package ipv6ddns

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6disc"
	disc "github.com/miguelangel-nubla/ipv6disc/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// fakeService records the updates of a fake provider, made by its settings: {"id": "..."}.
type fakeService struct {
	mutex   sync.Mutex
	updates map[string][][]string
	fail    error
}

var (
	fakeServicesMutex sync.Mutex
	fakeServices      = map[string]*fakeService{}
)

func init() {
	ddns.RegisterProvider("fake", func(settings json.RawMessage) (ddns.Service, error) {
		var s struct{ ID string }
		if err := json.Unmarshal(settings, &s); err != nil || s.ID == "" {
			return nil, errors.New("fake: no id")
		}
		service := &fakeService{updates: map[string][][]string{}}
		fakeServicesMutex.Lock()
		fakeServices[s.ID] = service
		fakeServicesMutex.Unlock()
		return service, nil
	})
}

func (f *fakeService) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.updates[hostname] = append(f.updates[hostname], addresses.Strings())
	return f.fail
}

func (f *fakeService) Domain(hostname string) string { return hostname + ".fake" }

// updatesOf returns the updates of hostname so far.
func (f *fakeService) updatesOf(hostname string) [][]string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return slices.Clone(f.updates[hostname])
}

// waitFor waits until the last update of hostname is want.
func (f *fakeService) waitFor(t *testing.T, hostname string, want ...string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		f.mutex.Lock()
		updates := f.updates[hostname]
		var last []string
		if len(updates) > 0 {
			last = updates[len(updates)-1]
		}
		f.mutex.Unlock()
		if slices.Equal(last, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: got updates %v, want the last to be %v", hostname, updates, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func macFilter(mac string) config.Filters {
	var f config.Filters
	f.MAC.Address = mac
	return f
}

func fakeCredential(id string, debounce, retry time.Duration) config.Credential {
	c := config.Credential{Provider: "fake", RawSettings: json.RawMessage(`{"id": "` + id + `"}`)}
	c.Debounce.Duration = debounce
	c.Retry.Duration = retry
	return c
}

// register puts a discovered address in the state. The state leaves out, with no error and no
// address returned, one of a family that config.Discovery has off, as both are in a zero one: the
// test would then wait for nothing.
func register(t *testing.T, w *Worker, mac, ip string, lifetime time.Duration) {
	t.Helper()
	hw, _ := net.ParseMAC(mac)
	w.discWorker.State.Register(hw, netip.MustParseAddr(ip), "eth0", lifetime, nil)
	if !discovered(w, mac, ip) {
		t.Fatalf("%s of %s isn't in the state: is its family on in the test's config.Discovery?", ip, mac)
	}
}

// discovered tells whether the state has the address.
func discovered(w *Worker, mac, ip string) bool {
	collection, ok := w.discWorker.GetAll()[mac]
	return ok && slices.Contains(collection.Strings(), ip)
}

const (
	macA = "00:00:00:00:00:0a"
	macB = "00:00:00:00:00:0b"
	macC = "00:00:00:00:00:0c"
)

func TestWorkerUpdatesFromDiscovery(t *testing.T) {
	cfg := config.Config{
		Discovery: config.DefaultDiscovery(),
		Tasks: map[string]config.Task{
			"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Endpoints: map[string][]string{"dns": {"nas", "web"}}},
			"b": {Name: "b", Filters: []config.Filters{macFilter(macB)}, Endpoints: map[string][]string{"dns": {"nas"}}},
		},
		Credentials: map[string]config.Credential{"dns": fakeCredential("e2e", 150*time.Millisecond, time.Hour)},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["e2e"]
	fakeServicesMutex.Unlock()

	register(t, w, macA, "2001:db8::a", time.Hour)
	register(t, w, macB, "2001:db8::b", time.Hour)
	register(t, w, macC, "2001:db8::c", time.Hour) // no task's

	// Within the debounce time, the addresses keep coming: one update with all of them.
	w.lookForChanges()
	register(t, w, macB, "2001:db8::b2", time.Second)
	w.lookForChanges()
	service.waitFor(t, "nas", "2001:db8::a", "2001:db8::b", "2001:db8::b2")
	service.waitFor(t, "web", "2001:db8::a")
	service.mutex.Lock()
	if n := len(service.updates["nas"]); n != 1 {
		t.Errorf("nas: got %d updates, want 1 after the debounce", n)
	}
	service.mutex.Unlock()

	// An address that expires leaves the records.
	time.Sleep(time.Second)
	w.lookForChanges()
	service.waitFor(t, "nas", "2001:db8::a", "2001:db8::b")

	// No change, no update.
	service.mutex.Lock()
	n := len(service.updates["nas"])
	service.mutex.Unlock()
	w.lookForChanges()
	time.Sleep(300 * time.Millisecond)
	service.mutex.Lock()
	if len(service.updates["nas"]) != n {
		t.Errorf("nas: updated without a change")
	}
	service.mutex.Unlock()
}

func TestWorkerRetriesFailedUpdates(t *testing.T) {
	cfg := config.Config{
		Discovery:   config.DefaultDiscovery(),
		Tasks:       map[string]config.Task{"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Endpoints: map[string][]string{"dns": {"nas"}}}},
		Credentials: map[string]config.Credential{"dns": fakeCredential("retry", time.Millisecond, 20*time.Millisecond)},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["retry"]
	fakeServicesMutex.Unlock()
	service.fail = errors.New("down")

	register(t, w, macA, "2001:db8::a", time.Hour)
	w.lookForChanges()
	service.waitFor(t, "nas", "2001:db8::a")
	service.mutex.Lock()
	service.fail = nil
	service.mutex.Unlock()

	deadline := time.Now().Add(3 * time.Second)
	for {
		service.mutex.Lock()
		n := len(service.updates["nas"])
		service.mutex.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no retry after the failure")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if out := w.State.PrettyPrint("", false); !strings.Contains(out, "last update:") {
		t.Errorf("no last update after the retry:\n%s", out)
	}
}

// The status page hides what can be secret, even in the errors of providers.
func TestPrettyPrintHidesSensibleData(t *testing.T) {
	const secret = "SECRET-7f3a"
	wan := config.Source{Type: config.SourceCommand, Command: "curl", Args: []string{"https://example.com/ip?token=" + secret}}
	wan.Interval.Duration, wan.Lifetime.Duration = time.Hour, time.Hour
	// An echo service of one's own, with its token: no task names it, so it is never asked.
	echo := config.Source{Type: config.SourceHTTP, Family: []int{4}, URLs: []string{"https://user:" + secret + "@echo.example/ip/" + secret + "?token=" + secret}}
	echo.Interval.Duration, echo.Lifetime.Duration = time.Hour, time.Hour
	cfg := config.Config{
		Tasks:       map[string]config.Task{"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Sources: []string{"wan"}, Endpoints: map[string][]string{"dns": {"nas"}}}},
		Credentials: map[string]config.Credential{"dns": fakeCredential("hidden", time.Millisecond, time.Hour)},
		Discovery: discoveryWith(func(d *config.Discovery) {
			d.Plugins = map[string]disc.Plugin{"router": {Type: "mikrotik", Fields: map[string]string{"interval": "60s", "address": "192.0.2.1", "username": "admin", "password": secret}}}
		}),
		Sources: map[string]config.Source{"wan": wan, "echo": echo},
	}
	credential := cfg.Credentials["dns"]
	credential.RawSettings = json.RawMessage(`{"id": "hidden", "token": "` + secret + `"}`)
	cfg.Credentials["dns"] = credential
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["hidden"]
	fakeServicesMutex.Unlock()
	service.fail = errors.New("denied for token " + secret)

	register(t, w, macA, "2001:db8::a", time.Hour)
	w.lookForChanges()
	service.waitFor(t, "nas", "2001:db8::a")
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(w.PrettyPrint("", false), "last update error") {
		if time.Now().After(deadline) {
			t.Fatal("no update error")
		}
		time.Sleep(5 * time.Millisecond)
	}

	if shown := w.PrettyPrint("", false); strings.Count(shown, secret) < 4 {
		t.Errorf("the test expects the secret in the settings, the plugin, the IPv4 command and the error, shown:\n%s", shown)
	}
	hidden := w.PrettyPrint("", true)
	if strings.Contains(hidden, secret) {
		t.Errorf("the secret is on the page:\n%s", hidden)
	}
	// Which service an http source asks stays: its host.
	if !strings.Contains(hidden, "from https://echo.example,") {
		t.Errorf("the host of the http source's url isn't on the page:\n%s", hidden)
	}
}

// blockingService holds its updates until release is closed.
type blockingService struct {
	fakeService
	started chan struct{}
	release chan struct{}
}

func (b *blockingService) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	b.started <- struct{}{}
	<-b.release
	return b.fakeService.Update(hostname, addresses)
}

func TestShutdownWaitsForTheUpdateRunning(t *testing.T) {
	cfg := config.Config{
		Discovery:   config.DefaultDiscovery(),
		Tasks:       map[string]config.Task{"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Endpoints: map[string][]string{"dns": {"nas"}}}},
		Credentials: map[string]config.Credential{"dns": fakeCredential("shutdown", time.Millisecond, time.Millisecond)},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	blocking := &blockingService{fakeService: fakeService{updates: map[string][][]string{}}, started: make(chan struct{}, 1), release: make(chan struct{})}
	w.providers["fake"].endpoints["dns"].Service = blocking

	register(t, w, macA, "2001:db8::a", time.Hour)
	w.lookForChanges()
	select {
	case <-blocking.started:
	case <-time.After(3 * time.Second):
		t.Fatal("no update started")
	}

	// The update runs: a short shutdown gives up on it.
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := w.Shutdown(short); err == nil {
		t.Error("shutdown returned while an update runs")
	}

	// No update starts once stopping, though the addresses change.
	register(t, w, macA, "2001:db8::a2", time.Hour)
	w.lookForChanges()

	close(blocking.release)
	if err := w.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case <-blocking.started:
		t.Error("an update started after stopping")
	default:
	}
	blocking.mutex.Lock()
	defer blocking.mutex.Unlock()
	if got := blocking.updates["nas"]; len(got) != 1 {
		t.Errorf("got updates %v, want the one that was running", got)
	}
}

func TestStatusAndMetrics(t *testing.T) {
	cfg := config.Config{
		Discovery:   config.DefaultDiscovery(),
		Tasks:       map[string]config.Task{"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Endpoints: map[string][]string{"dns": {"nas", `we"ird`, "x\\y\nz"}}}},
		Credentials: map[string]config.Credential{"dns": fakeCredential("status", time.Millisecond, time.Hour)},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["status"]
	fakeServicesMutex.Unlock()
	service.fail = errors.New("denied for token SECRET")

	register(t, w, macA, "2001:db8::a", time.Hour)
	w.lookForChanges()
	service.waitFor(t, "nas", "2001:db8::a")
	deadline := time.Now().Add(3 * time.Second)
	for w.Status(false).Hostnames[0].Failures == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no failure counted")
		}
		time.Sleep(5 * time.Millisecond)
	}

	status := w.Status(true)
	if len(status.Hostnames) != 3 || len(status.Discovered) != 1 {
		t.Fatalf("status: %+v", status)
	}
	nas := status.Hostnames[0]
	if nas.Hostname != "nas" || nas.Domain != "nas.fake" || len(nas.Addresses) != 1 || nas.Failures != 1 || nas.LastError != "<sensible data hidden>" {
		t.Errorf("nas: %+v", nas)
	}
	if got := w.Status(false).Hostnames[0].LastError; !strings.Contains(got, "SECRET") {
		t.Errorf("the error shown: %q", got)
	}
	if d := status.Discovered[0]; d.MAC != macA || d.Addresses[0].Address != "2001:db8::a" || d.Addresses[0].Sources[0] != "eth0" {
		t.Errorf("discovered: %+v", d)
	}

	var metrics strings.Builder
	if err := status.WriteMetrics(&metrics); err != nil {
		t.Fatal(err)
	}
	out := metrics.String()
	for _, want := range []string{
		`ipv6ddns_hostname_addresses{provider="fake",endpoint="dns",hostname="nas.fake"} 1`,
		`ipv6ddns_hostname_updates_total{provider="fake",endpoint="dns",hostname="nas.fake",result="failure"} 1`,
		`ipv6ddns_hostname_last_update_failed{provider="fake",endpoint="dns",hostname="nas.fake"} 1`,
		`hostname="we\"ird.fake"`,
		`hostname="x\\y\nz.fake"`,
		"ipv6ddns_discovered_hosts 1\n",
		"ipv6ddns_discovered_addresses 1\n",
		"# TYPE ipv6ddns_hostname_updates_total counter\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %s in the metrics:\n%s", want, out)
		}
	}
	// Every sample line is a name, optional labels and a number.
	sample := regexp.MustCompile(`^[a-z0-9_]+(\{([a-z_]+="([^"\\]|\\.)*",?)+\})? -?[0-9.]+$`)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(line, "# ") && !sample.MatchString(line) {
			t.Errorf("not a sample: %q", line)
		}
	}
}

// warningService is a provider with a warning, once.
type warningService struct {
	fakeService
	warned bool
}

func (s *warningService) Warnings() []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.warned {
		return nil
	}
	s.warned = true
	return []string{"the host key is not verified"}
}

func TestProviderWarningsAreLogged(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	cfg := config.Config{
		Discovery:   config.DefaultDiscovery(),
		Tasks:       map[string]config.Task{"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Endpoints: map[string][]string{"dns": {"nas"}}}},
		Credentials: map[string]config.Credential{"dns": fakeCredential("warning", time.Millisecond, time.Hour)},
	}
	w, err := NewWorker(zap.New(core).Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	service := &warningService{fakeService: fakeService{updates: map[string][][]string{}}}
	w.providers["fake"].endpoints["dns"].Service = service

	register(t, w, macA, "2001:db8::a", time.Hour)
	w.lookForChanges()
	service.waitFor(t, "nas", "2001:db8::a")
	register(t, w, macA, "2001:db8::a2", time.Hour)
	w.lookForChanges()
	service.waitFor(t, "nas", "2001:db8::a", "2001:db8::a2")

	if got := logs.FilterMessageSnippet("host key is not verified").Len(); got != 1 {
		t.Errorf("got the warning %d times, want once", got)
	}
}

func TestWorkerAddsSourcesAndKeepsIPv4Out(t *testing.T) {
	wan := config.Source{Type: config.SourceStatic, Addresses: []string{"203.0.113.7"}}
	wan.Interval.Duration, wan.Lifetime.Duration = time.Hour, 3*time.Hour
	lan := macFilter(macB)
	lan.IP.Family = []int{4}
	cfg := config.Config{
		Tasks: map[string]config.Task{
			// A filter from before IPv4 discovery: the device's IPv6 only, plus the public IPv4.
			"web": {Name: "web", Filters: []config.Filters{macFilter(macA)}, Sources: []string{"wan"}, Endpoints: map[string][]string{"dns": {"www"}}},
			"api": {Name: "api", Sources: []string{"wan"}, Endpoints: map[string][]string{"dns": {"api"}}},
			"lan": {Name: "lan", Filters: []config.Filters{lan}, Endpoints: map[string][]string{"dns": {"nas"}}},
		},
		Credentials: map[string]config.Credential{"dns": fakeCredential("sources", time.Millisecond, time.Hour)},
		Sources:     map[string]config.Source{"wan": wan},
		// The IPv4 neighbors discovered: still, a filter without family leaves them out.
		Discovery: discoveryWith(func(d *config.Discovery) { d.IPv4 = disc.Family{Enabled: true} }),
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["sources"]
	fakeServicesMutex.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.sources["wan"].Start(ctx, zap.NewNop().Sugar(), nil)
	deadline := time.Now().Add(3 * time.Second)
	for len(w.sources["wan"].Addresses().Get()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the source gave nothing")
		}
		time.Sleep(time.Millisecond)
	}

	register(t, w, macA, "2001:db8::a", time.Hour)
	register(t, w, macA, "192.168.1.10", time.Hour) // its private IPv4, discovered
	register(t, w, macB, "192.168.1.20", time.Hour)
	register(t, w, macB, "2001:db8::b", time.Hour)
	w.lookForChanges()

	service.waitFor(t, "www", "203.0.113.7", "2001:db8::a")
	service.waitFor(t, "api", "203.0.113.7")
	service.waitFor(t, "nas", "192.168.1.20")

	status := w.Status(true)
	if len(status.Sources) != 1 || status.Sources[0].Name != "wan" || len(status.Sources[0].Addresses) != 1 {
		t.Errorf("sources status: %+v", status.Sources)
	}
	var metrics strings.Builder
	status.WriteMetrics(&metrics)
	if !strings.Contains(metrics.String(), `ipv6ddns_source_addresses{source="wan"} 1`) {
		t.Errorf("no source in the metrics:\n%s", metrics.String())
	}
	if page := w.State.PrettyPrint("", true); !strings.Contains(page, "203.0.113.7 from source wan") {
		t.Errorf("the source isn't on the page:\n%s", page)
	}
}

func TestDiscoveryIPv4(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := config.Config{Discovery: discoveryWith(func(d *config.Discovery) { d.IPv4 = disc.Family{Enabled: enabled} })}
		w, err := NewWorker(zap.NewNop().Sugar(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got := w.discWorker.State.IPv4(); got != enabled {
			t.Errorf("discovery.ipv4 %v: the state takes IPv4: %v", enabled, got)
		}
		hw, _ := net.ParseMAC(macA)
		// Left out with the family off: nothing is returned then, and nothing here reads it.
		w.discWorker.State.Register(hw, netip.MustParseAddr("192.168.1.10"), "eth0", time.Hour, nil)
		if _, registered := w.discWorker.GetAll()[macA]; registered != enabled {
			t.Errorf("discovery.ipv4 %v: an IPv4 neighbor registered: %v", enabled, registered)
		}
	}
}

func TestWorkerDiscoveryFamilies(t *testing.T) {
	cfg := config.Config{Discovery: discoveryWith(func(d *config.Discovery) { d.IPv6, d.IPv4 = disc.Family{}, disc.Family{Enabled: true} })}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if w.discWorker.State.IPv6() || !w.discWorker.State.IPv4() {
		t.Errorf("IPv6 off, IPv4 on: the state takes IPv6 %v, IPv4 %v", w.discWorker.State.IPv6(), w.discWorker.State.IPv4())
	}
}

// countingService tells how many of its updates ran at once.
type countingService struct {
	fakeService
	running, most int
}

func (c *countingService) Update(hostname string, addresses *ipv6disc.AddrCollection) error {
	c.mutex.Lock()
	c.running++
	c.most = max(c.most, c.running)
	c.mutex.Unlock()
	time.Sleep(30 * time.Millisecond)
	c.mutex.Lock()
	c.running--
	c.mutex.Unlock()
	return c.fakeService.Update(hostname, addresses)
}

// The names of a task change together: their updates of the one service run one after another.
func TestEndpointUpdatesOneAtATime(t *testing.T) {
	cfg := config.Config{
		Discovery:   config.DefaultDiscovery(),
		Tasks:       map[string]config.Task{"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Endpoints: map[string][]string{"dns": {"nas", "web", "www"}}}},
		Credentials: map[string]config.Credential{"dns": fakeCredential("one-at-a-time", time.Millisecond, time.Hour)},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	service := &countingService{fakeService: fakeService{updates: map[string][][]string{}}}
	w.providers["fake"].endpoints["dns"].Service = service

	register(t, w, macA, "2001:db8::a", time.Hour)
	w.lookForChanges()
	for _, name := range []string{"nas", "web", "www"} {
		service.waitFor(t, name, "2001:db8::a")
	}
	service.mutex.Lock()
	defer service.mutex.Unlock()
	if service.most != 1 {
		t.Errorf("got %d updates of the endpoint at once, want one at a time", service.most)
	}
}

// A worker started matches when the discovery's state changes, not at its next interval: so do the
// addresses of this machine that an interface lost leave the records. And Shutdown waits for the
// context of Start, then leaves the state with nothing running.
func TestWorkerFollowsTheStateAndShutdownClosesIt(t *testing.T) {
	cfg := config.Config{
		// IPv6 taken, but nothing listening: Start opens no socket.
		Discovery:   discoveryWith(func(d *config.Discovery) { d.IPv6 = disc.Family{Enabled: true} }),
		Tasks:       map[string]config.Task{"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Endpoints: map[string][]string{"dns": {"nas"}}}},
		Credentials: map[string]config.Credential{"dns": fakeCredential("follows", time.Millisecond, time.Hour)},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["follows"]
	fakeServicesMutex.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// Well within rematchInterval.
	register(t, w, macA, "2001:db8::a", time.Hour)
	service.waitFor(t, "nas", "2001:db8::a")

	short, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	if err := w.Shutdown(short); err == nil {
		t.Error("shutdown returned while the context of Start goes on")
	}

	const lifetime = 300 * time.Millisecond
	register(t, w, macB, "2001:db8::b", lifetime)
	cancel()
	if err := w.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Its expiration would take it out of the state.
	time.Sleep(2 * lifetime)
	if !discovered(w, macB, "2001:db8::b") {
		t.Error("an address expired after the shutdown: the state still watches them")
	}
}
