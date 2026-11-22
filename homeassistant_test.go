package ipv6ddns

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/miguelangel-nubla/ipv6ddns/source"
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
	if err := w.homeAssistant.serve(ctx, new(sync.WaitGroup), nil, nil, t.Logf); err != nil {
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

// With key provisioning, the device keeps its identity, and the key Home Assistant gives, in its state file:
// the same device, with its key, after a restart.
func TestHomeAssistantState(t *testing.T) {
	dir := t.TempDir()
	cfg := config.HomeAssistant{Name: "ipv6ddns", FriendlyName: "ipv6ddns", Port: 6053, KeyProvisioning: true, KeyProvisioningStateFile: "homeassistant.state"}
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
	if _, err := newHomeAssistant(config.HomeAssistant{KeyProvisioning: true, KeyProvisioningStateFile: "other.state"}, dir); err == nil && os.Geteuid() != 0 {
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
	h, err := newHomeAssistant(config.HomeAssistant{Name: "ipv6ddns-announce-test", FriendlyName: "test", Port: 16099, KeyProvisioning: true, KeyProvisioningStateFile: "s"}, t.TempDir())
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

// With listen, the device takes connections at those addresses only.
func TestHomeAssistantListens(t *testing.T) {
	port := freePort(t)
	h, err := newHomeAssistant(config.HomeAssistant{Name: "ipv6ddns-listen-test", FriendlyName: "test", Port: port, KeyProvisioning: true, KeyProvisioningStateFile: "s",
		Announce: new(bool), Entries: []listen.Entry{{Network: netip.MustParsePrefix("127.0.0.1/32"), Port: strconv.Itoa(port)}}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.serve(ctx, new(sync.WaitGroup), nil, nil, t.Logf); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatalf("at the address listened on: %v", err)
	}
	conn.Close()
	// Another address of the machine, where it doesn't listen: loopback's 127.0.0.2 on Linux, or
	// an interface's.
	others := []string{"127.0.0.2"}
	if ifaces, err := announced(nil, nil); err == nil {
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				if ip := a.(*net.IPNet).IP; ip.To4() != nil {
					others = append(others, ip.String())
				}
			}
		}
	}
	for _, other := range others {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort(other, strconv.Itoa(port)), time.Second); err == nil {
			conn.Close()
			t.Errorf("listened on %s too", other)
		}
	}
}

// The states are those of Home Assistant's connection of now: one of an earlier connection, which
// Home Assistant doesn't send again, its entity gone meanwhile, is none, and an error in time.
func TestHomeAssistantStatesOfAConnection(t *testing.T) {
	h, err := newHomeAssistant(config.HomeAssistant{Name: "ipv6ddns", FriendlyName: "test", Port: 6053, KeyProvisioning: true, KeyProvisioningStateFile: "s"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	since := time.Now()
	h.connectedSince = func() (time.Time, bool) { return since, true }
	changes := 0
	h.subscribe("sensor.wan", "", func() { changes++ })
	if h.device.OnStatesReset == nil {
		t.Fatal("the device doesn't tell when Home Assistant's states are none")
	}
	h.mutex.Lock()
	h.states[stateKey("sensor.wan", "")] = "203.0.113.7"
	h.mutex.Unlock()
	if state, err := h.State("sensor.wan", ""); err != nil || state != "203.0.113.7" {
		t.Fatalf("connected: %q, %v", state, err)
	}
	// Home Assistant reconnects, as the device tells, and sends nothing for the entity.
	h.device.OnStatesReset()
	since = time.Now()
	if state, err := h.State("sensor.wan", ""); !errors.Is(err, source.ErrWaiting) {
		t.Errorf("just reconnected, no state: %q, %v, want a wait", state, err)
	}
	since = time.Now().Add(-time.Minute)
	if state, err := h.State("sensor.wan", ""); err == nil || errors.Is(err, source.ErrWaiting) {
		t.Errorf("reconnected a minute, no state: %q, %v, want an error", state, err)
	}
}

// Names whose entities would have one id have each its own, with a hash; the others' ids are of
// the endpoint and the host name alone, as ever.
func TestEntityIDs(t *testing.T) {
	names := []haName{
		{"cf", "a-b", "a-b.example.com"}, {"cf", "a.b", "a.b.example.com"}, {"cf", "A_B", "a_b.example.com"},
		{"cf_x", "y", "y.example.com"}, {"cf", "x_y", "x_y.example.org"},
		{"dns", "web", "web.fake"},
	}
	bases := entityBases(names)
	seen := map[string]haName{}
	for _, n := range names {
		base := bases[n.key()]
		if other, ok := seen[base]; ok {
			t.Errorf("%v and %v: one id, %s", other, n, base)
		}
		seen[base] = n
	}
	if bases[haName{"dns", "web", ""}] != "dns_web" {
		t.Errorf("a name alone with its id: %s, want dns_web", bases[haName{"dns", "web", ""}])
	}
	if base := bases[haName{"cf", "a-b", ""}]; !strings.HasPrefix(base, "cf_a_b_") || len(base) != len("cf_a_b_")+8 {
		t.Errorf("a name sharing its id: %s, want cf_a_b_ and a hash", base)
	}
	// Whatever the order, and the other names.
	slices.Reverse(names)
	if again := entityBases(names[1:]); again[haName{"cf", "a-b", ""}] != bases[haName{"cf", "a-b", ""}] {
		t.Errorf("another order: %s, was %s", again[haName{"cf", "a-b", ""}], bases[haName{"cf", "a-b", ""}])
	}

	h, err := newHomeAssistant(config.HomeAssistant{Name: "ipv6ddns", FriendlyName: "test", Port: 6053, KeyProvisioning: true, KeyProvisioningStateFile: "s"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h.addEntities(names, func() {})
	if len(h.names) != len(names) {
		t.Errorf("%d names with entities, of %d", len(h.names), len(names))
	}
}

// The addresses entity's state fits Home Assistant's 255 characters, which a longer one is unknown
// to: the first addresses whole, and how many more.
func TestAddressesState(t *testing.T) {
	addresses := func(n int) []string {
		var list []string
		for i := range n {
			list = append(list, fmt.Sprintf("2001:0db8:1234:5678:9abc:def0:1234:%04x", i))
		}
		return list
	}
	if got := addressesState(addresses(6)); got != strings.Join(addresses(6), ", ") {
		t.Errorf("6 addresses: %s", got)
	}
	if got := addressesState(nil); got != "" {
		t.Errorf("no address: %q", got)
	}
	for n, more := range map[int]string{7: "+1 more", 20: "+14 more"} {
		got := addressesState(addresses(n))
		parts := strings.Split(got, ", ")
		if len(got) > stateMax || len(parts) != 7 || parts[6] != more || !slices.Equal(parts[:6], addresses(6)) {
			t.Errorf("%d addresses: %d characters, %s", n, len(got), got)
		}
	}
	// The count longer, an address fewer.
	if got := addressesState(addresses(2000)); len(got) > stateMax || !strings.HasSuffix(got, ":0004, +1995 more") {
		t.Errorf("2000 addresses: %d characters, %s", len(got), got)
	}
	if got := addressesState([]string{strings.Repeat("x", 300)}); got != "+1 more" {
		t.Errorf("one address too long: %s", got)
	}
}

// The device announces the port it listens on, which listen may give; and the worker's shutdown
// waits for the announcement to be taken back, and for the connections.
func TestHomeAssistantAnnouncesItsPort(t *testing.T) {
	port := freePort(t)
	h, err := newHomeAssistant(config.HomeAssistant{Name: "ipv6ddns-port-test", FriendlyName: "test", Port: 6053, KeyProvisioning: true, KeyProvisioningStateFile: "s",
		Entries: []listen.Entry{{Host: "127.0.0.1", Port: strconv.Itoa(port)}}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	announced := make(chan int, 1)
	var goodbye atomic.Bool
	h.advertise = func(ctx context.Context, port int, _ []net.Interface) error {
		announced <- port
		<-ctx.Done()
		time.Sleep(100 * time.Millisecond)
		goodbye.Store(true)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var running sync.WaitGroup
	if err := h.serve(ctx, &running, nil, nil, t.Errorf); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-announced:
		if got != port {
			t.Errorf("announced the port %d, listening on %d", got, port)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not announced")
	}
	// A connection, which the device serves until the end.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	running.Wait()
	if !goodbye.Load() {
		t.Error("the shutdown didn't wait for the announcement to be taken back")
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("the connection after the shutdown: %v, want it closed", err)
	}
}

// A state file that isn't one, as cut short, is an error, and stays as it is: a new identity
// would be a new device to Home Assistant.
func TestHomeAssistantStateFileCorrupt(t *testing.T) {
	for name, content := range map[string]string{
		"cut":              `{"identity":"q9b/BwP6Z3bLDXmeLY+bPQPDUcKV9FXLRJlTnm`,
		"empty":            "",
		"a short identity": `{"identity":"c2hvcnQ="}`,
		"a short key":      `{"identity":"q9b/BwP6Z3bLDXmeLY+bPQPDUcKV9FXLRJlTnmoLmLM=","key":"c2hvcnQ="}`,
		"no identity":      `{"key":"q9b/BwP6Z3bLDXmeLY+bPQPDUcKV9FXLRJlTnmoLmLM="}`,
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "homeassistant.state")
		os.WriteFile(path, []byte(content), 0o600)
		if _, err := newHomeAssistant(config.HomeAssistant{KeyProvisioning: true, KeyProvisioningStateFile: "homeassistant.state"}, dir); err == nil || !strings.Contains(err.Error(), "isn't a valid state file") {
			t.Errorf("%s: %v, want an error", name, err)
		}
		if after, _ := os.ReadFile(path); string(after) != content {
			t.Errorf("%s: the file was written: %s", name, after)
		}
	}
}

// A state Home Assistant hasn't sent: a wait while it isn't connected, or for a moment after it
// connects; then an error, the entity being none of Home Assistant's.
func TestHomeAssistantStateWaits(t *testing.T) {
	var since time.Time
	h := &homeAssistant{states: map[string]string{stateKey("sensor.wan", ""): "203.0.113.7"},
		connectedSince: func() (time.Time, bool) { return since, !since.IsZero() }}
	if _, err := h.State("sensor.wan", ""); !errors.Is(err, source.ErrWaiting) {
		t.Errorf("not connected: %v, want a wait", err)
	}
	since = time.Now()
	if state, err := h.State("sensor.wan", ""); err != nil || state != "203.0.113.7" {
		t.Errorf("connected: %q, %v", state, err)
	}
	if _, err := h.State("sensor.missing", ""); !errors.Is(err, source.ErrWaiting) {
		t.Errorf("just connected, no state: %v, want a wait", err)
	}
	since = time.Now().Add(-time.Minute)
	if _, err := h.State("sensor.missing", ""); err == nil || errors.Is(err, source.ErrWaiting) || !strings.Contains(err.Error(), "entity's id and attribute") {
		t.Errorf("connected a minute, no state: %v, want an error", err)
	}
}

// A device serves with its state file for itself alone: a second with the same one, as another
// instance configured beside the first with no state file named, doesn't start, and says which
// file. Once the first stopped, it does, and is that device. Those with a key of their own have
// no state file to share.
func TestHomeAssistantStateFileOfOne(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "lock")
	release, err := lockFile(lock)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := lockFile(lock); err == nil {
		again()
		t.Skip("no lock that ends with its process, on this system")
	}
	release()
	dir := t.TempDir()
	device := func(port int) *homeAssistant {
		announce := false
		h, err := newHomeAssistant(config.HomeAssistant{Name: "ipv6ddns", FriendlyName: "test", Port: port, KeyProvisioning: true, KeyProvisioningStateFile: "homeassistant.state", Announce: &announce,
			Entries: []listen.Entry{{Host: "127.0.0.1", Port: strconv.Itoa(port)}}}, dir)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	first, second := device(freePort(t)), device(freePort(t))
	if first.device.MAC.String() != second.device.MAC.String() {
		t.Fatal("two devices of one state file have two MACs")
	}
	var running sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := first.serve(ctx, &running, nil, nil, t.Errorf); err != nil {
		t.Fatal(err)
	}
	err = second.serve(context.Background(), &running, nil, nil, t.Errorf)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, "homeassistant.state")) || !strings.Contains(err.Error(), "another running ipv6ddns") {
		t.Fatalf("a second device of served: %v", err)
	}
	// It left nothing listening.
	if conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", second.config.Entries[0].Port)); err == nil {
		conn.Close()
		t.Error("the second device, which didn't serve, listens")
	}
	cancel()
	running.Wait()
	ctx, cancel = context.WithCancel(context.Background())
	if err := second.serve(ctx, &running, nil, nil, t.Errorf); err != nil {
		t.Errorf("the first stopped, and the second doesn't serve: %v", err)
	}
	cancel()
	running.Wait()
}

// A state file that is there, in a folder nothing can be written in, as a file system mounted
// read-only: no lock file to make, and the device serves all the same.
func TestHomeAssistantStateFileReadOnlyFolder(t *testing.T) {
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("a folder that can't be written needs a user that isn't root, and a system with such folders")
	}
	dir := t.TempDir()
	announce := false
	port := strconv.Itoa(freePort(t))
	cfg := config.HomeAssistant{Name: "ipv6ddns", FriendlyName: "test", KeyProvisioning: true, KeyProvisioningStateFile: "homeassistant.state", Announce: &announce,
		Entries: []listen.Entry{{Host: "127.0.0.1", Port: port}}}
	if _, err := newHomeAssistant(cfg, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	h, err := newHomeAssistant(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	var running sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	if err := h.serve(ctx, &running, nil, nil, t.Errorf); err != nil {
		t.Errorf("with its state file in a folder that can't be written, the device doesn't serve: %v", err)
	}
	cancel()
	running.Wait()
	if _, err := os.Stat(filepath.Join(dir, "homeassistant.state.lock")); err == nil {
		t.Error("a lock file was made in a folder that can't be written")
	}
}

// With a key of its own, the device writes nothing: it serves, and its folder, the configuration's,
// is as it was, with no state file and no lock file.
func TestHomeAssistantKeyWritesNothing(t *testing.T) {
	dir := t.TempDir()
	announce := false
	h, err := newHomeAssistant(config.HomeAssistant{Name: "ipv6ddns", FriendlyName: "test", Key: esphome.GenerateKey(), Announce: &announce,
		Entries: []listen.Entry{{Host: "127.0.0.1", Port: strconv.Itoa(freePort(t))}}}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var running sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	if err := h.serve(ctx, &running, nil, nil, t.Errorf); err != nil {
		t.Errorf("with a key, the device doesn't serve: %v", err)
	}
	cancel()
	running.Wait()
	if files, err := os.ReadDir(dir); err != nil || len(files) > 0 {
		t.Errorf("with a key, the device wrote in its folder: %v, %v", files, err)
	}
}
