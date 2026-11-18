package ipv6ddns

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
)

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
