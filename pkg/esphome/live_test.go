//go:build linux && integration

package esphome

// What only a real connection tells: Home Assistant's own library, at the other end of a link,
// between two network namespaces, that vanishes from it, stops reading, or can't get in for the
// clients that say nothing. It needs root, iproute2, and a Python with aioesphomeapi:
//
//	go test -tags integration -exec sudo -run '^TestLive' ./pkg/esphome
//
// device_test.go has the same limits against a client in Go, over loopback, where a connection
// always ends for both.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// serveAt serves d at an address of the machine's, on a port of its own, until the test ends.
func serveAt(t *testing.T, d *Device, address string) (port string) {
	t.Helper()
	d.Name = "ipv6ddns-live"
	d.MAC, _ = net.ParseMAC("02:00:5e:10:00:20")
	ln, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Error(err)
		}
	})
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}

// follow starts a client of testdata, which prints a JSON object per line, and gives them: the
// end of the test kills it.
func follow(t *testing.T, cmd *exec.Cmd) <-chan map[string]any {
	t.Helper()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	events := make(chan map[string]any, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(events)
		for lines := bufio.NewScanner(stdout); lines.Scan(); {
			var event map[string]any
			if err := json.Unmarshal(lines.Bytes(), &event); err != nil {
				t.Errorf("the client: %s: %v", lines.Text(), err)
				continue
			}
			events <- event
		}
	}()
	t.Cleanup(func() {
		// Stopped or not: SIGKILL ends both.
		cmd.Process.Kill()
		cmd.Wait()
		<-done
	})
	return events
}

// await is the client's next event with the key; one that says the connection ended, when that
// isn't what is waited for, fails the test.
func await(t *testing.T, events <-chan map[string]any, key string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case event, open := <-events:
			if !open {
				t.Fatalf("waiting for %q: the client ended", key)
			}
			if _, ok := event[key]; ok {
				return event
			}
			if _, ended := event["disconnected"]; ended {
				t.Fatalf("waiting for %q: Home Assistant was disconnected", key)
			}
		case <-deadline:
			t.Fatalf("waiting for %q: nothing in %s", key, timeout)
		}
	}
}

// Home Assistant, which pings, stays connected however long, and gets the states; one that
// vanishes from the network, as with its power cut, sends no end of its connection: the device
// drops it once it was silent for idleTimeout, and says Home Assistant isn't connected.
func TestLiveHomeAssistantVanishes(t *testing.T) {
	py := livetest.Python(t)
	link := livetest.NewLink(t, 1)
	shorten(t, &idleTimeout, 4*time.Second)
	key := GenerateKey()
	d := &Device{Key: first(ParseKey(key))}
	sensor := d.AddTextSensor(Entity{ID: "addresses", Name: "Addresses"})
	sensor.Set("2001:db8::1")
	port := serveAt(t, d, link.Address)

	// A ping a second: Home Assistant's are 20 seconds apart, for the 150 of the device's.
	events := follow(t, link.Command(py, "testdata/hold.py", link.Address, port, key, "1"))
	if name := await(t, events, "connected", 30*time.Second)["connected"]; name != d.Name {
		t.Errorf("connected to %v, want %s", name, d.Name)
	}
	if got := await(t, events, "state", 10*time.Second)["state"]; got != "2001:db8::1" {
		t.Errorf("the first state: %v", got)
	}
	awaitConnected(t, d)
	for end := time.Now().Add(3 * idleTimeout); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if !d.Connected() {
			t.Fatal("Home Assistant, which pings, was dropped")
		}
	}
	sensor.Set("2001:db8::2")
	if got := await(t, events, "state", 10*time.Second)["state"]; got != "2001:db8::2" {
		t.Errorf("a state after three times idleTimeout: %v", got)
	}

	link.Vanish(t)
	gone := time.Now()
	for d.Connected() {
		if time.Since(gone) > idleTimeout+20*time.Second {
			t.Fatalf("Home Assistant vanished %s ago, and the device still says it is connected", time.Since(gone).Round(time.Second))
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("dropped %s after it vanished", time.Since(gone).Round(100*time.Millisecond))
}

// awaitConnected waits until the device says Home Assistant is connected: once it asked for its
// states, which it does after the device's, so a moment after their first is seen. A test that
// read Connected at once could find it false, and take that for a drop.
func awaitConnected(t *testing.T, d *Device) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !d.Connected(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("Home Assistant never asked for its states")
		}
	}
}

// Home Assistant stopped, as a machine that hangs: its kernel still takes what it is sent, until
// its buffers are full. The device drops it once a state couldn't be written for writeTimeout,
// long before idleTimeout would.
func TestLiveHomeAssistantStopsReading(t *testing.T) {
	py := livetest.Python(t)
	link := livetest.NewLink(t, 1)
	shorten(t, &writeTimeout, time.Second)
	key := GenerateKey()
	d := &Device{Key: first(ParseKey(key))}
	sensor := d.AddTextSensor(Entity{ID: "addresses", Name: "Addresses"})
	sensor.Set("2001:db8::1")
	port := serveAt(t, d, link.Address)

	cmd := link.Command(py, "testdata/hold.py", link.Address, port, key, "20")
	events := follow(t, cmd)
	await(t, events, "connected", 30*time.Second)
	if got := await(t, events, "state", 10*time.Second)["state"]; got != "2001:db8::1" {
		t.Errorf("a state before it stopped: %v", got)
	}
	awaitConnected(t, d)

	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	stopped := time.Now()
	long := strings.Repeat("2001:db8::1 ", 1000)
	for n := 0; d.Connected(); n++ {
		if time.Since(stopped) > 60*time.Second {
			t.Fatalf("Home Assistant read nothing for %s, and the device still says it is connected", time.Since(stopped).Round(time.Second))
		}
		sensor.Set(fmt.Sprint(long, n))
		time.Sleep(50 * time.Microsecond)
	}
	t.Logf("dropped %s after it stopped reading", time.Since(stopped).Round(100*time.Millisecond))
}

// As many clients as the device serves at once connect and say nothing: Home Assistant can't get
// in while they hold every place, as nobody over maxConnections is served; and it does once they
// were silent for handshakeTimeout, and dropped.
func TestLiveSilentClients(t *testing.T) {
	py := livetest.Python(t)
	link := livetest.NewLink(t, 1)
	shorten(t, &handshakeTimeout, 6*time.Second)
	key := GenerateKey()
	d := &Device{Key: first(ParseKey(key))}
	port := serveAt(t, d, link.Address)

	events := follow(t, link.Command(py, "testdata/crowd.py", link.Address, port, key, strconv.Itoa(maxConnections), "30"))
	if got := await(t, events, "open", 30*time.Second)["open"]; got != float64(maxConnections) {
		t.Fatalf("%v connections opened, want %d", got, maxConnections)
	}
	if got := await(t, events, "among", 30*time.Second)["among"]; got != false {
		t.Errorf("with %d connections open, one more was served", maxConnections)
	}
	after := await(t, events, "after", 60*time.Second)
	if after["after"] != true {
		t.Fatalf("Home Assistant never got in: %v of the %d silent connections dropped", after["dropped"], maxConnections)
	}
	if after["name"] != d.Name || after["dropped"] != float64(maxConnections) {
		t.Errorf("Home Assistant got in, to %v, with %v of the %d silent connections dropped", after["name"], after["dropped"], maxConnections)
	}
}
