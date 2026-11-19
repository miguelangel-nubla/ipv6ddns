package esphome

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// python is the interpreter with aioesphomeapi: $ESPHOME_PYTHON, or python3.
func python(t *testing.T) string {
	p := os.Getenv("ESPHOME_PYTHON")
	if p == "" {
		p = "python3"
	}
	if err := exec.Command(p, "-c", "import aioesphomeapi").Run(); err != nil {
		if os.Getenv("ESPHOME_COMPAT_REQUIRED") != "" {
			t.Fatalf("%s has no aioesphomeapi: %v", p, err)
		}
		t.Skipf("%s has no aioesphomeapi; ESPHOME_PYTHON names one that has", p)
	}
	return p
}

// Home Assistant's ESPHome library, aioesphomeapi, connects to the device as to any ESPHome one:
// it is refused without the key and with another, then reads the device and its entities, follows
// their states, presses its button, and gives it the state of an entity it asks for.
func TestHomeAssistantConnects(t *testing.T) {
	py := python(t)
	key := GenerateKey()
	rawKey, _ := ParseKey(key)
	mac, _ := net.ParseMAC("02:00:5e:10:00:01")
	d := &Device{
		Name: "ipv6ddns-test", FriendlyName: "ipv6ddns test", MAC: mac, Key: rawKey,
		Manufacturer: "ipv6ddns", Model: "DDNS updater", Project: "miguelangel-nubla.ipv6ddns", ProjectVersion: "1.2.3",
	}
	addresses := d.AddTextSensor(Entity{ID: "addresses", Name: "Addresses", Icon: "mdi:ip-network"})
	hosts := d.AddSensor(Entity{ID: "hosts", Name: "Hosts", Unit: "hosts", Category: CategoryDiagnostic})
	pressed := d.AddBinarySensor(Entity{ID: "pressed", Name: "Pressed", DeviceClass: "problem"})
	echo := d.AddTextSensor(Entity{ID: "echo", Name: "Echo"})
	d.AddButton(Entity{ID: "update", Name: "Update"}, func() { pressed.Set(true) })
	d.SubscribeHomeAssistant("sensor.wan_ip", "", func(state string) { echo.Set("got:" + state) })
	addresses.Set("2001:db8::1")
	hosts.Set(3)
	pressed.Set(false)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx, ln) }()
	defer func() {
		cancel()
		if err := <-served; err != nil {
			t.Error(err)
		}
	}()

	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	cmd := exec.Command(py, "testdata/client.py", port, key)
	cmd.Stderr = os.Stderr
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(60*time.Second, func() { cmd.Process.Kill() })
	defer timer.Stop()

	events := map[string][]map[string]any{}
	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		var event map[string]any
		if err := json.Unmarshal(lines.Bytes(), &event); err != nil {
			t.Fatalf("%s: %v", lines.Text(), err)
		}
		for k := range event {
			events[k] = append(events[k], event)
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("the client: %v", err)
	}

	if got := events["no_key"]; len(got) != 1 || got[0]["no_key"] != "RequiresEncryptionAPIError" {
		t.Errorf("without the key: %v", got)
	}
	if got := events["wrong_key"]; len(got) != 1 || got[0]["wrong_key"] != "InvalidEncryptionKeyAPIError" {
		t.Errorf("with another key: %v", got)
	}
	if got := events["info"]; len(got) != 1 {
		t.Errorf("device info: %v", got)
	} else {
		info := got[0]["info"].(map[string]any)
		for k, want := range map[string]string{
			"name": "ipv6ddns-test", "friendly_name": "ipv6ddns test", "mac": "02:00:5E:10:00:01",
			"project_name": "miguelangel-nubla.ipv6ddns", "project_version": "1.2.3", "manufacturer": "ipv6ddns",
			"api_version": "APIVersion(major=1, minor=20)",
		} {
			if info[k] != want {
				t.Errorf("device info %s: %v, want %v", k, info[k], want)
			}
		}
	}
	if got := events["refused_new_key"]; len(got) != 1 || got[0]["refused_new_key"] != true {
		t.Errorf("a key given to a device with a fixed one: %v", got)
	}
	if got := events["capabilities"]; len(got) != 1 {
		t.Errorf("device capabilities: %v", got)
	}
	if got := events["entity"]; len(got) != 5 {
		t.Errorf("entities: %v", got)
	}
	if got := events["asked"]; len(got) != 1 || got[0]["asked"].(map[string]any)["entity_id"] != "sensor.wan_ip" {
		t.Errorf("the state the device asks: %v", got)
	}
	if got := events["done"]; len(got) != 1 || got[0]["done"] != true {
		t.Errorf("the button, and the echo of Home Assistant's state: %v", got)
	}
	initial := map[string]any{}
	for _, e := range events["state"] {
		s := e["state"].(map[string]any)
		if _, seen := initial[s["entity"].(string)]; !seen {
			initial[s["entity"].(string)] = s["value"]
		}
	}
	if initial["addresses"] != "2001:db8::1" || initial["hosts"] != 3.0 {
		t.Errorf("the first states: %v", initial)
	}
}

// Home Assistant gives the key to a device without one, as to ESPHome's: the device keeps it, and
// takes it at once; then only the key gets in.
func TestHomeAssistantGivesTheKey(t *testing.T) {
	py := python(t)
	mac, _ := net.ParseMAC("02:00:5e:10:00:02")
	var kept []byte
	d := &Device{Name: "ipv6ddns-test", FriendlyName: "test", MAC: mac, OnKey: func(key []byte) error {
		kept = key
		return nil
	}}
	d.AddSensor(Entity{ID: "hosts", Name: "Hosts"})
	var pressed, stated atomic.Bool
	d.AddButton(Entity{ID: "update", Name: "Update"}, func() { pressed.Store(true) })
	d.SubscribeHomeAssistant("sensor.wan_ip", "", func(string) { stated.Store(true) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx, ln) }()
	defer func() {
		cancel()
		<-served
	}()

	newKey := GenerateKey()
	out, err := exec.Command(py, "testdata/provision.py", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), newKey).Output()
	if err != nil {
		t.Fatalf("the client: %v\n%s", err, out)
	}
	events := map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		for k, v := range e {
			events[k] = v
		}
	}
	check := func(name string, want map[string]any) {
		got, _ := events[name].(map[string]any)
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s: %s %v, want %v (%v)", name, k, got[k], v, got)
			}
		}
	}
	check("before", map[string]any{"ok": true, "provisionable": true, "mac": "02:00:5E:10:00:02"})
	// Before the key, a client is anyone: it gets no subscription, and its states and button
	// presses are dropped.
	if untrusted, _ := events["untrusted"].(map[string]any); len(untrusted["asked"].([]any)) != 0 {
		t.Errorf("a client without the key was asked states: %v", untrusted)
	}
	if pressed.Load() || stated.Load() {
		t.Errorf("a client without the key: button pressed %v, state taken %v", pressed.Load(), stated.Load())
	}
	if events["set"] != true {
		t.Errorf("giving the key: %v", events["set"])
	}
	check("with_key", map[string]any{"ok": true, "mac": "02:00:5E:10:00:02"})
	check("without_key", map[string]any{"ok": false, "error": "RequiresEncryptionAPIError"})
	check("with_zero", map[string]any{"ok": false, "error": "InvalidEncryptionKeyAPIError"})
	if want, _ := ParseKey(newKey); string(kept) != string(want) || !d.HasKey() {
		t.Errorf("the key kept: %x, the device has one: %v", kept, d.HasKey())
	}
}

// Home Assistant discovers the device, with python-zeroconf, as its zeroconf integration does:
// listening only, without a query, so that the device must announce itself, as RFC 6762 has a
// new service do, to be found, as by a Home Assistant that queries an hour apart; then its
// announcement says it needs its key once Home Assistant gave it. On loopback only, so that the
// test announces nothing on the network it runs in: where loopback carries multicast, as in CI,
// which turns it on.
func TestHomeAssistantDiscovers(t *testing.T) {
	py := python(t)
	lo := multicastLoopback(t)
	mac, _ := net.ParseMAC("02:00:5e:10:00:03")
	d := &Device{Name: "ipv6ddns-discover-test", FriendlyName: "discover test", MAC: mac,
		Project: "miguelangel-nubla.ipv6ddns", ProjectVersion: "1.2.3", OnKey: func([]byte) error { return nil }}

	cmd := exec.Command(py, "testdata/discover.py", d.Name, "30")
	cmd.Stderr = os.Stderr
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() || lines.Text() != "ready" {
		t.Fatalf("the listener: %q", lines.Text())
	}
	type record struct {
		Port    int               `json:"port"`
		TXT     map[string]string `json:"txt"`
		Address string            `json:"address"`
	}
	var addresses sync.Map // every address heard
	records := make(chan record, 16)
	go func() {
		for lines.Scan() {
			var r record
			if json.Unmarshal(lines.Bytes(), &r) == nil {
				if r.Address != "" {
					addresses.Store(r.Address, true)
				}
				records <- r
			}
		}
		close(records)
	}()
	next := func(what string, ok func(record) bool) record {
		deadline := time.After(10 * time.Second)
		for {
			select {
			case r, open := <-records:
				if !open {
					t.Fatalf("%s: the listener ended", what)
				}
				if ok(r) {
					return r
				}
			case <-deadline:
				t.Fatalf("%s: not announced", what)
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	links := []Link{{Interface: *lo, IPs: []net.IP{net.IPv4(127, 0, 0, 1)}}}
	// Another network of the machine, which Home Assistant isn't on: announced there, with its own
	// address, never on loopback. CI makes one, a dummy interface.
	var other net.IP
	if name := os.Getenv("ESPHOME_MDNS_OTHER_INTERFACE"); name != "" {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			t.Fatal(err)
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ip := a.(*net.IPNet).IP.To4(); ip != nil {
				other = ip
			}
		}
		links = append(links, Link{Interface: *iface, IPs: []net.IP{other}})
	}
	go d.Advertise(ctx, 6053, links)

	next("the address", func(r record) bool { return r.Address == "127.0.0.1" })
	next("the port", func(r record) bool { return r.Port == 6053 })
	txt := next("the TXT records", func(r record) bool { return r.TXT != nil }).TXT
	if txt["mac"] != "02005e100003" || txt["friendly_name"] != "discover test" {
		t.Errorf("announced: %v", txt)
	}
	if _, needsKey := txt["api_encryption"]; needsKey {
		t.Errorf("without a key, the device says it needs one: %v", txt)
	}

	key, _ := ParseKey(GenerateKey())
	if err := d.setKey(key); err != nil {
		t.Fatal(err)
	}
	next("the key", func(r record) bool { return r.TXT["api_encryption"] == "Noise_NNpsk0_25519_ChaChaPoly_SHA256" })
	if other != nil {
		if _, heard := addresses.Load(other.String()); heard {
			t.Errorf("the other network's address, %s, announced on loopback", other)
		}
	}
}

// multicastLoopback is the loopback interface, where it carries IPv4 multicast: on Linux, with
// "ip link set lo multicast on" and a route of 224.0.0.0/4 to it, as CI does; macOS has no route.
func multicastLoopback(t *testing.T) *net.Interface {
	skip := func(why string) {
		if os.Getenv("ESPHOME_COMPAT_REQUIRED") != "" {
			t.Fatal(why)
		}
		t.Skip(why)
	}
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback == 0 {
			continue
		}
		if ifaces[i].Flags&net.FlagMulticast == 0 {
			skip("loopback carries no multicast: ip link set lo multicast on")
		}
		conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 9})
		if err == nil {
			_, err = conn.Write([]byte{0})
			conn.Close()
		}
		if err != nil {
			skip("no multicast route to loopback: ip route add 224.0.0.0/4 dev lo: " + err.Error())
		}
		return &ifaces[i]
	}
	skip("no loopback interface")
	return nil
}
