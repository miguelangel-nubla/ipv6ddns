package ipv6ddns

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
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
	c.DebounceTime.Duration = debounce
	c.RetryTime.Duration = retry
	return c
}

func register(w *Worker, mac, ip string, lifetime time.Duration) {
	hw, _ := net.ParseMAC(mac)
	w.discWorker.State.Register(hw, netip.MustParseAddr(ip), "eth0", lifetime, nil)
}

const (
	macA = "00:00:00:00:00:0a"
	macB = "00:00:00:00:00:0b"
	macC = "00:00:00:00:00:0c"
)

func TestWorkerUpdatesFromDiscovery(t *testing.T) {
	cfg := config.Config{
		Tasks: map[string]config.Task{
			"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Endpoints: map[string][]string{"dns": {"nas", "web"}}},
			"b": {Name: "b", Filters: []config.Filters{macFilter(macB)}, Endpoints: map[string][]string{"dns": {"nas"}}},
		},
		Credentials: map[string]config.Credential{"dns": fakeCredential("e2e", 150*time.Millisecond, time.Hour)},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), time.Minute, time.Hour, cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["e2e"]
	fakeServicesMutex.Unlock()

	register(w, macA, "2001:db8::a", time.Hour)
	register(w, macB, "2001:db8::b", time.Hour)
	register(w, macC, "2001:db8::c", time.Hour) // no task's

	// Within the debounce time, the addresses keep coming: one update with all of them.
	w.lookForChanges()
	register(w, macB, "2001:db8::b2", time.Second)
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
		Tasks:       map[string]config.Task{"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Endpoints: map[string][]string{"dns": {"nas"}}}},
		Credentials: map[string]config.Credential{"dns": fakeCredential("retry", time.Millisecond, 20*time.Millisecond)},
	}
	w, err := NewWorker(zap.NewNop().Sugar(), time.Minute, time.Hour, cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["retry"]
	fakeServicesMutex.Unlock()
	service.fail = errors.New("down")

	register(w, macA, "2001:db8::a", time.Hour)
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
	ipv4 := new(config.IPv4Handler)
	if err := ipv4.UnmarshalJSON([]byte(`{"interval": "1h", "lifetime": "1h", "command": "curl", "args": ["https://example.com/ip?token=` + secret + `"]}`)); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Tasks:       map[string]config.Task{"a": {Name: "a", Filters: []config.Filters{macFilter(macA)}, Endpoints: map[string][]string{"dns": {"nas"}}, IPv4: ipv4}},
		Credentials: map[string]config.Credential{"dns": fakeCredential("hidden", time.Millisecond, time.Hour)},
		Discovery:   config.Discovery{Plugins: map[string]config.PluginConfig{"router": {Type: "mikrotik", Params: "60s,192.0.2.1,admin," + secret}}},
	}
	credential := cfg.Credentials["dns"]
	credential.RawSettings = json.RawMessage(`{"id": "hidden", "token": "` + secret + `"}`)
	cfg.Credentials["dns"] = credential
	w, err := NewWorker(zap.NewNop().Sugar(), time.Minute, time.Hour, cfg)
	if err != nil {
		t.Fatal(err)
	}
	fakeServicesMutex.Lock()
	service := fakeServices["hidden"]
	fakeServicesMutex.Unlock()
	service.fail = errors.New("denied for token " + secret)

	register(w, macA, "2001:db8::a", time.Hour)
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
	if hidden := w.PrettyPrint("", true); strings.Contains(hidden, secret) {
		t.Errorf("the secret is on the page:\n%s", hidden)
	}
}
