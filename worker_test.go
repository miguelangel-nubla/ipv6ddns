package ipv6ddns

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6disc"
	disc "github.com/miguelangel-nubla/ipv6disc/pkg/config"
	"go.uber.org/zap"
)

// discoveryWith is the discovery of a configuration that says nothing of it, changed.
func discoveryWith(change func(*config.Discovery)) config.Discovery {
	d := config.DefaultDiscovery()
	change(&d)
	return d
}

// loadConfig reads a configuration, as the command does: a file.
func loadConfig(t *testing.T, content string) config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// The discovery the worker runs is the configuration's, its protocols too: a configuration that
// names none runs those ipv6disc has by default, not none, which is what a discovery made
// without them runs; and one that names them, those it says.
func TestWorkerRunsTheProtocolsOfTheConfiguration(t *testing.T) {
	// Those of the names, in the order of the protocols: with those that hear frames, on Linux,
	// where alone they are on by default.
	running := func(names ...string) []string {
		var out []string
		for _, name := range ipv6disc.ProtocolNames() {
			if slices.Contains(names, name) && (runtime.GOOS == "linux" || name != ipv6disc.ProtocolDHCP && name != ipv6disc.ProtocolLLDP && name != ipv6disc.ProtocolARPListen) {
				out = append(out, name)
			}
		}
		return out
	}
	ipv6 := []string{"ndp", "ping", "ssdp", "wsd", "mdns", "dhcp", "lldp", "llmnr"}
	for name, tt := range map[string]struct {
		config string
		want   []string
	}{
		"no discovery block": {"", running(ipv6...)},
		"no protocols key":   {"discovery:\n  exclude_interfaces:\n    - docker0\n", running(ipv6...)},
		"some of them": {"discovery:\n  protocols:\n    ssdp:\n      enabled: false\n    wsd:\n      enabled: false\n    llmnr:\n      enabled: false\n",
			running("ndp", "ping", "mdns", "dhcp", "lldp")},
		"IPv4, without its sweep": {"discovery:\n  ipv4:\n    enabled: true\n  protocols:\n    arp-sweep:\n      enabled: false\n    arp-listen:\n      enabled: false\n",
			running(append(ipv6, "arp", "netbios")...)},
		"a family that doesn't listen": {"discovery:\n  ipv6:\n    listen: false\n", []string{}},
		"the reverse DNS, with servers": {"discovery:\n  protocols:\n    dns:\n      servers: 192.0.2.53\n",
			running(append(ipv6, "dns")...)},
	} {
		w, err := NewWorker(zap.NewNop().Sugar(), loadConfig(t, tt.config+"tasks: {}\ncredentials: {}\n"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := w.Status(true).Protocols; !slices.Equal(got, tt.want) {
			t.Errorf("%s: the status has the protocols %v, want %v", name, got, tt.want)
		}
		line := "Protocols: none\n"
		if len(tt.want) > 0 {
			line = "Protocols: " + strings.Join(tt.want, ", ") + "\n"
		}
		if page := w.PrettyPrint("", true); !strings.Contains(page, line) {
			t.Errorf("%s: the page has no %q:\n%s", name, line, page)
		}
	}

	// As JSON: a list, empty with none.
	w, err := NewWorker(zap.NewNop().Sugar(), config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := json.Marshal(w.Status(true)); !strings.Contains(string(status), `"protocols":[]`) {
		t.Errorf("a discovery of nothing: %s", status)
	}
}

// A host's names are where the hosts are: the status, and the page, which -live shows too.
func TestStatusHasTheNamesOfTheHosts(t *testing.T) {
	hw, _ := net.ParseMAC(macA)
	for _, kept := range []bool{true} {
		cfg := loadConfig(t, "tasks: {}\ncredentials: {}\n")
		w, err := NewWorker(zap.NewNop().Sugar(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(w.discWorker.State.Close)
		register(t, w, macA, "2001:db8::a", time.Hour)
		w.discWorker.RegisterName(hw, "Printer.local.", "mdns", time.Hour)
		w.discWorker.RegisterName(hw, "printer", "router", time.Hour)
		w.discWorker.RegisterName(hw, "laserjet", "router", time.Hour)

		discovered := w.Status(true).Discovered
		if len(discovered) != 1 || discovered[0].MAC != macA {
			t.Fatalf("hostnames %t: discovered %+v", kept, discovered)
		}
		want := []DiscoveredName(nil)
		onPage := macA + "\n"
		if kept {
			want = []DiscoveredName{{Name: "laserjet", Sources: []string{"router"}}, {Name: "printer", Sources: []string{"mdns", "router"}}}
			onPage = macA + " laserjet (router), printer (mdns,router)\n"
		}
		if got := discovered[0].Names; !reflect.DeepEqual(got, want) {
			t.Errorf("hostnames %t: the names of the status are %+v, want %+v", kept, got, want)
		}
		if page := w.PrettyPrint("", true); !strings.Contains(page, onPage) {
			t.Errorf("hostnames %t: the page has no %q:\n%s", kept, onPage, page)
		}
		encoded, _ := json.Marshal(discovered[0])
		if has := strings.Contains(string(encoded), `"names":[{"name":"laserjet","sources":["router"]}`); has != kept {
			t.Errorf("hostnames %t: as JSON, %s", kept, encoded)
		}
	}
}

func addr(mac, ip string) *ipv6disc.Addr {
	hw, _ := net.ParseMAC(mac)
	return ipv6disc.NewAddr(hw, netip.MustParseAddr(ip), "eth0", time.Hour, nil)
}

func collection(addrs ...*ipv6disc.Addr) *ipv6disc.AddrCollection {
	c := ipv6disc.NewAddrCollection()
	for _, a := range addrs {
		c.Add(a)
	}
	return c
}

func TestHostnameDebouncesAndRetries(t *testing.T) {
	var mutex sync.Mutex
	var updates [][]string
	fail := true
	h := NewHostname(func(c *ipv6disc.AddrCollection) error {
		mutex.Lock()
		defer mutex.Unlock()
		updates = append(updates, c.Strings())
		if fail {
			fail = false
			return errors.New("down")
		}
		return nil
	}, 30*time.Millisecond, 30*time.Millisecond)

	a, b := addr("00:00:00:00:00:01", "2001:db8::1"), addr("00:00:00:00:00:01", "2001:db8::2")
	h.SetAddrCollection(collection(a))
	h.SetAddrCollection(collection(a, b)) // within the debounce time: one update
	h.SetAddrCollection(collection(a, b)) // no change

	deadline := time.Now().Add(2 * time.Second)
	for {
		mutex.Lock()
		n := len(updates)
		mutex.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(60 * time.Millisecond) // no more updates come

	mutex.Lock()
	defer mutex.Unlock()
	if len(updates) != 2 || len(updates[0]) != 2 || len(updates[1]) != 2 {
		t.Fatalf("got updates %v, want the failed one and its retry, both with two addresses", updates)
	}
	if s := h.status(); s.updateError != nil || s.updatedTime.IsZero() || s.updateRunning {
		t.Errorf("status after the retry: %+v", s)
	}
}

func filterTask(mac string) config.Task {
	var f config.Filters
	f.MAC.Address = mac
	return config.Task{Filters: []config.Filters{f}}
}

func TestMatchingMergesTasks(t *testing.T) {
	a, b, c := addr("00:00:00:00:00:01", "2001:db8::1"), addr("00:00:00:00:00:02", "2001:db8::2"), addr("00:00:00:00:00:03", "2001:db8::3")
	got := (&Worker{}).matching([]config.Task{filterTask("00:00:00:00:00:01"), filterTask("00:00:00:00:00:02")}, []*ipv6disc.Addr{a, b, c})
	if want := []string{"2001:db8::1", "2001:db8::2"}; !equal(got.Strings(), want) {
		t.Errorf("got %v, want %v", got.Strings(), want)
	}
	if got := (&Worker{}).matching([]config.Task{{}}, []*ipv6disc.Addr{a}); len(got.Get()) != 0 {
		t.Errorf("a task without filters: got %v, want nothing", got.Strings())
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNewWorker(t *testing.T) {
	cfg := config.Config{
		Discovery: config.DefaultDiscovery(),
		Tasks: map[string]config.Task{
			"a": {Name: "a", Endpoints: map[string][]string{"duck": {"home", "nas"}}},
			"b": {Name: "b", Endpoints: map[string][]string{"duck": {"nas"}}},
		},
		Credentials: map[string]config.Credential{
			"duck": {Provider: "duckdns", RawSettings: json.RawMessage(`{"api_token": "01234567-89ab-cdef-0123-456789abcdef"}`)},
		},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.targets) != 2 {
		t.Fatalf("got %d targets, want 2: home, and nas for both tasks", len(w.targets))
	}
	for _, target := range w.targets {
		if target.hostname == w.providers["duckdns"].endpoints["duck"].hostnames["nas"] && len(target.tasks) != 2 {
			t.Errorf("nas: got %d tasks, want 2", len(target.tasks))
		}
	}

	cfg.Credentials["duck"] = config.Credential{Provider: "duckdns", RawSettings: json.RawMessage(`{}`)}
	if _, err := NewWorker(zap.NewNop().Sugar(), cfg); err == nil {
		t.Error("invalid settings: want an error")
	}
}

// A credential no task names is checked at the start too.
func TestUnusedCredentialsAreChecked(t *testing.T) {
	cfg := config.Config{
		Discovery:   config.DefaultDiscovery(),
		Credentials: map[string]config.Credential{"unused": {Provider: "cloudflare", RawSettings: []byte(`{"zone": "example.com"}`)}},
	}
	if _, err := NewWorker(zap.NewNop().Sugar(), cfg); err == nil || !strings.Contains(err.Error(), "unused") {
		t.Errorf("got %v, want the unused credential's error", err)
	}
}

// With nothing to discover, the worker starts all the same: its names get their sources'.
func TestWorkerWithSourcesOnly(t *testing.T) {
	wan := config.Source{Type: config.SourceStatic, Addresses: []string{"203.0.113.7"}}
	wan.Interval.Duration, wan.Lifetime.Duration = time.Hour, 3*time.Hour
	cfg := config.Config{
		// Asking the hosts with no family listening starts no discovery either, and asks nobody.
		Discovery:   discoveryWith(func(d *config.Discovery) { d.IPv6, d.Solicit.IPv6 = disc.Family{Enabled: true}, true }),
		Tasks:       map[string]config.Task{"web": {Name: "web", Sources: []string{"wan"}, Endpoints: map[string][]string{"dns": {"www"}}}},
		Credentials: map[string]config.Credential{"dns": fakeCredential("sources-only", time.Millisecond, time.Hour)},
		Sources:     map[string]config.Source{"wan": wan},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatalf("no discovery, but sources: %v", err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["sources-only"]
	fakeServicesMutex.Unlock()
	service.waitFor(t, "www", "203.0.113.7")

	// A worker starts once: a second start would run its sources twice.
	if err := w.Start(ctx); err == nil {
		t.Error("a second start: want an error")
	}
	cancel()
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := w.Shutdown(shutdown); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// A name spelled in more ways than one is one name, with the addresses of all its tasks: two would
// each remove the other's records, and be the same series twice in the metrics.
func TestNewWorkerMergesSpellings(t *testing.T) {
	cfg := config.Config{
		Discovery: config.DefaultDiscovery(),
		Tasks: map[string]config.Task{
			"a": {Name: "a", Endpoints: map[string][]string{"duck": {"nas"}}},
			"b": {Name: "b", Endpoints: map[string][]string{"duck": {"nas.duckdns.org", "NAS.", "other"}}},
		},
		Credentials: map[string]config.Credential{
			"duck": {Provider: "duckdns", RawSettings: json.RawMessage(`{"api_token": "01234567-89ab-cdef-0123-456789abcdef"}`)},
		},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.targets) != 2 {
		t.Fatalf("got %d targets, want 2: nas, however spelled, and other", len(w.targets))
	}
	nas := w.providers["duckdns"].endpoints["duck"].hostnames["nas"]
	if w.targets[0].hostname != nas || len(w.targets[0].tasks) != 2 {
		t.Errorf("nas: got %d tasks, want both, the second once", len(w.targets[0].tasks))
	}

	var metrics strings.Builder
	if err := w.Status(true).WriteMetrics(&metrics); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(strings.ToLower(metrics.String()), `ipv6ddns_hostname_addresses{provider="duckdns",endpoint="duck",hostname="nas.duckdns.org"}`); got != 1 {
		t.Errorf("got the series of nas %d times, want once:\n%s", got, metrics.String())
	}
}

// Nothing found at the start leaves the records as they are; the last address gone removes them.
func TestHostnameUpdatesOnlyOnceItHadAddresses(t *testing.T) {
	updates := make(chan []string, 10)
	h := NewHostname(func(c *ipv6disc.AddrCollection) error {
		updates <- c.Strings()
		return nil
	}, time.Millisecond, time.Hour)

	h.SetAddrCollection(collection())
	select {
	case got := <-updates:
		t.Fatalf("updated with %v before any address", got)
	case <-time.After(50 * time.Millisecond):
	}

	for _, want := range [][]string{{"2001:db8::1"}, {}} {
		if len(want) > 0 {
			h.SetAddrCollection(collection(addr("00:00:00:00:00:01", want[0])))
		} else {
			h.SetAddrCollection(collection())
		}
		select {
		case got := <-updates:
			if !equal(got, want) {
				t.Errorf("got an update with %v, want %v", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no update with %v", want)
		}
	}
}

// The retry is above the debounce: after a failure the endpoint is left alone for the retry
// interval, whatever the addresses do meanwhile, during the update that fails or after it, and the
// retry sends the addresses of then.
func TestHostnameChangesWaitForTheRetry(t *testing.T) {
	const retry = 400 * time.Millisecond
	started, release := make(chan []string, 10), make(chan error)
	h := NewHostname(func(c *ipv6disc.AddrCollection) error {
		started <- c.Strings()
		return <-release
	}, 10*time.Millisecond, retry)
	defer h.Stop()

	a, b, c := addr("00:00:00:00:00:01", "2001:db8::1"), addr("00:00:00:00:00:01", "2001:db8::2"), addr("00:00:00:00:00:01", "2001:db8::3")
	h.SetAddrCollection(collection(a))
	<-started
	h.SetAddrCollection(collection(a, b)) // while the update that fails runs
	release <- errors.New("down")
	failed := time.Now()
	h.Wait()
	h.SetAddrCollection(collection(a, b, c)) // and after it failed

	select {
	case got := <-started:
		if waited := time.Since(failed); waited < retry-50*time.Millisecond {
			t.Errorf("updated %v after the failure, with %v: the retry interval is %v", waited, got, retry)
		}
		if len(got) != 3 {
			t.Errorf("the retry sent %v, want the three addresses of then", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no retry")
	}

	// Once an update succeeds, a change waits for the debounce time alone.
	release <- nil
	h.Wait()
	changed := time.Now()
	h.SetAddrCollection(collection(a))
	select {
	case <-started:
		if waited := time.Since(changed); waited > retry/2 {
			t.Errorf("after a success, the change waited %v: the debounce time is 10ms", waited)
		}
		release <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("no update after the success")
	}
}

// An update somebody asks for doesn't wait for the retry.
func TestHostnameScheduleUpdateGoesPastTheRetry(t *testing.T) {
	started := make(chan struct{}, 10)
	h := NewHostname(func(*ipv6disc.AddrCollection) error {
		started <- struct{}{}
		return errors.New("down")
	}, 0, time.Hour)
	defer h.Stop()
	h.SetAddrCollection(collection(addr("00:00:00:00:00:01", "2001:db8::1")))
	<-started
	h.Wait()
	h.ScheduleUpdate(0)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the update asked for waits for the retry")
	}
	h.Wait()
	if next := time.Until(h.status().nextUpdateTime); next < 30*time.Minute {
		t.Errorf("next update in %v, want the retry interval", next)
	}
}

// A timer that fires as the name is stopped starts no update, and neither does one scheduled
// after: "Update now" of Home Assistant comes when it comes.
func TestHostnameStoppedUpdatesNoMore(t *testing.T) {
	for range 200 {
		var mutex sync.Mutex
		stopped, after := false, false
		h := NewHostname(func(*ipv6disc.AddrCollection) error {
			mutex.Lock()
			defer mutex.Unlock()
			after = after || stopped
			return nil
		}, 0, time.Hour)
		h.SetAddrCollection(collection(addr("00:00:00:00:00:01", "2001:db8::1"))) // fires at once
		h.Stop()
		h.Wait()
		mutex.Lock()
		stopped = true
		mutex.Unlock()

		h.ScheduleUpdate(0)
		if !h.status().nextUpdateTime.IsZero() {
			t.Fatal("an update scheduled once stopped")
		}
		time.Sleep(time.Millisecond)
		mutex.Lock()
		if after {
			t.Fatal("an update started once stopped and waited for")
		}
		mutex.Unlock()
	}
}

// A retry interval of nothing would try a failing endpoint without a pause.
func TestHostnameRetryHasAFloor(t *testing.T) {
	var calls atomic.Int32
	h := NewHostname(func(*ipv6disc.AddrCollection) error {
		calls.Add(1)
		return errors.New("down")
	}, -time.Second, 0)
	defer h.Stop()
	h.SetAddrCollection(collection(addr("00:00:00:00:00:01", "2001:db8::1")))
	time.Sleep(200 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Errorf("%d updates in 200ms, want the one, and its retry a second after", n)
	}
}
