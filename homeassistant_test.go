package ipv6ddns

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
	"go.uber.org/zap"
)

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// Home Assistant, by its ESPHome integration's library, sees a name's entities, and the state it
// sends for a homeassistant source reaches the DNS provider, and the name's addresses entity.
func TestHomeAssistantIntegration(t *testing.T) {
	py := os.Getenv("ESPHOME_PYTHON")
	if py == "" {
		py = "python3"
	}
	if err := exec.Command(py, "-c", "import aioesphomeapi").Run(); err != nil {
		if os.Getenv("ESPHOME_COMPAT_REQUIRED") != "" {
			t.Fatalf("%s has no aioesphomeapi", py)
		}
		t.Skipf("%s has no aioesphomeapi; ESPHOME_PYTHON names one that has", py)
	}

	key := esphome.GenerateKey()
	port := freePort(t)
	wan := config.Source{Type: config.SourceHomeAssistant, Entity: "sensor.wan_ip"}
	wan.Interval.Duration, wan.Lifetime.Duration = time.Hour, 3*time.Hour
	cfg := config.Config{
		Tasks:         map[string]config.Task{"web": {Name: "web", Sources: []string{"wan"}, Endpoints: map[string][]string{"dns": {"web"}}}},
		Credentials:   map[string]config.Credential{"dns": fakeCredential("homeassistant", time.Millisecond, time.Hour)},
		Sources:       map[string]config.Source{"wan": wan},
		HomeAssistant: &config.HomeAssistant{Key: key, Name: "ipv6ddns-test", FriendlyName: "ipv6ddns test", Port: port, Announce: new(bool)},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["homeassistant"]
	fakeServicesMutex.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.homeAssistant.serve(ctx, nil, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	go w.homeAssistant.follow(ctx, func() Status { return w.Status(false) })
	w.sources["wan"].Start(ctx, zap.NewNop().Sugar(), w.askRematch)
	go func() {
		for ctx.Err() == nil {
			w.lookForChanges()
			select {
			case <-ctx.Done():
			case <-w.rematch:
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()

	cmd := exec.Command(py, "testdata/ha_client.py", strconv.Itoa(port), key)
	cmd.Stderr = os.Stderr
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(60*time.Second, func() { cmd.Process.Kill() })
	defer timer.Stop()
	entities := map[string]string{}
	done := false
	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		var event struct {
			Entity *struct {
				ObjectID string `json:"object_id"`
				Name     string `json:"name"`
			} `json:"entity"`
			Done *bool `json:"done"`
		}
		if err := json.Unmarshal(lines.Bytes(), &event); err != nil {
			t.Fatalf("%s: %v", lines.Text(), err)
		}
		if event.Entity != nil {
			entities[event.Entity.ObjectID] = event.Entity.Name
		}
		if event.Done != nil {
			done = *event.Done
		}
	}
	cmd.Wait()

	service.waitFor(t, "web", "203.0.113.50")
	for id, name := range map[string]string{
		"dns_web_addresses":   "web.fake addresses",
		"dns_web_last_update": "web.fake last update",
		"dns_web_problem":     "web.fake update",
		"discovered_hosts":    "Discovered hosts",
		"update_now":          "Update now",
	} {
		if entities[id] != name {
			t.Errorf("entity %s: %q, want %q (all: %v)", id, entities[id], name, entities)
		}
	}
	if !done {
		t.Error("the addresses entity never showed the state Home Assistant sent")
	}
}

// Without a key, the device keeps its identity, and the key Home Assistant gives, in its state file:
// the same device, with its key, after a restart.
func TestHomeAssistantState(t *testing.T) {
	dir := t.TempDir()
	cfg := config.HomeAssistant{Name: "ipv6ddns", FriendlyName: "ipv6ddns", Port: 6053, StateFile: "homeassistant.state"}
	h, err := newHomeAssistant(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	if h.device.HasKey() || h.device.OnKey == nil {
		t.Fatal("a new device: no key, and takes one")
	}
	info, err := os.Stat(filepath.Join(dir, "homeassistant.state"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the state file: %v, %v", info, err)
	}
	key, _ := esphome.ParseKey(esphome.GenerateKey())
	if err := h.device.OnKey(key); err != nil {
		t.Fatal(err)
	}

	again, err := newHomeAssistant(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.device.MAC.String() != h.device.MAC.String() || string(again.device.Key) != string(key) {
		t.Errorf("after a restart: MAC %s, was %s; key kept %v", again.device.MAC, h.device.MAC, string(again.device.Key) == string(key))
	}
	// Forgotten, as when Home Assistant deletes the device.
	if err := again.device.OnKey(nil); err != nil {
		t.Fatal(err)
	}
	if third, _ := newHomeAssistant(cfg, dir); third.device.HasKey() || third.device.MAC.String() != h.device.MAC.String() {
		t.Error("forgotten key: still kept, or another device")
	}

	// A state file it can't write is an error at the start.
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	if _, err := newHomeAssistant(config.HomeAssistant{StateFile: "other.state"}, dir); err == nil && os.Geteuid() != 0 {
		t.Error("an unwritable state file: no error")
	}
}

func TestAnnounced(t *testing.T) {
	ifaces, err := announced(nil, nil)
	if err != nil || len(ifaces) == 0 {
		t.Skipf("no interface with an address here: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagMulticast == 0 {
			t.Errorf("announced on %s, %v", iface.Name, iface.Flags)
		}
	}
	if _, err := announced(nil, []string{"*"}); err == nil {
		t.Error("every interface left out: want an error")
	}
	if _, err := announced([]string{"no-such-interface"}, nil); err == nil {
		t.Error("only an interface that isn't: want an error")
	}
}

// The device's announcement starts: without addresses, it failed at once, unable to resolve its
// own name. On loopback only: a test needn't announce a device on the network it runs in.
func TestDeviceAnnounces(t *testing.T) {
	var lo *net.Interface
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagLoopback != 0 && ifaces[i].Flags&net.FlagMulticast != 0 {
			lo = &ifaces[i]
		}
	}
	if lo == nil {
		t.Skip("no loopback interface with multicast")
	}
	h, err := newHomeAssistant(config.HomeAssistant{Name: "ipv6ddns-announce-test", FriendlyName: "test", Port: 16099, StateFile: "s"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- h.device.Advertise(ctx, 16099, []net.Interface{*lo})
	}()
	select {
	case err := <-done:
		t.Fatalf("the announcement ended at once: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	// The key given: the announcement follows, without ending.
	key, _ := esphome.ParseKey(esphome.GenerateKey())
	if err := h.device.OnKey(key); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("the announcement ended: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Error(err)
	}
}
