package source

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
)

func pushSource(t *testing.T, dir string, lifetime time.Duration) *Source {
	t.Helper()
	cfg := config.Source{Type: config.SourcePush, Password: "secret"}
	cfg.Lifetime.Duration = lifetime
	if lifetime == 0 {
		cfg.Lifetime.Duration = config.PushForever
	}
	s, err := New("wan", cfg, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func pushed(ips ...string) []netip.Addr {
	var out []netip.Addr
	for _, ip := range ips {
		out = append(out, netip.MustParseAddr(ip))
	}
	return out
}

// Each family pushed replaces that family's addresses, and the other's stay; the same push again
// changes nothing; the matching is asked again each time; the password is the source's alone.
func TestPush(t *testing.T) {
	s := pushSource(t, t.TempDir(), 0)
	rematched := 0
	s.Start(t.Context(), nil, func() { rematched++ })
	have := func(want ...string) {
		t.Helper()
		got := slices.Sorted(slices.Values(s.Addresses().Strings()))
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("addresses %v, want %v", got, want)
		}
	}
	if changed, err := s.Push(pushed("203.0.113.9", "2001:db8::9"), netip.Prefix{}); !changed || err != nil {
		t.Fatalf("the first push: %v, %v", changed, err)
	}
	have("203.0.113.9", "2001:db8::9")
	if changed, _ := s.Push(pushed("203.0.113.9"), netip.Prefix{}); changed {
		t.Error("the same IPv4 again changed something")
	}
	have("203.0.113.9", "2001:db8::9")
	if changed, _ := s.Push(pushed("2001:db8::10"), netip.Prefix{}); !changed {
		t.Error("a new IPv6 changed nothing")
	}
	have("203.0.113.9", "2001:db8::10")
	if changed, _ := s.Push(pushed("::ffff:203.0.113.10"), netip.Prefix{}); !changed {
		t.Error("a new IPv4, mapped, changed nothing")
	}
	have("203.0.113.10", "2001:db8::10")
	if _, err := s.Push(nil, netip.Prefix{}); err == nil {
		t.Error("a push of nothing")
	}
	if rematched != 4 {
		t.Errorf("matched again %d times, want 4", rematched)
	}
	if !s.Accepts("secret") || s.Accepts("Secret") || s.Accepts("") {
		t.Error("the password")
	}
	if st := s.Status(false); st.Type != "push" || st.Runs != 4 || st.LastSuccess == nil {
		t.Errorf("the status: %+v", st)
	}
}

// What the router sent last is kept in the source's file, and taken again after a restart, for
// what is left of its lifetime: none, once that is over.
func TestPushKeptAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	s := pushSource(t, dir, time.Hour)
	if _, err := s.Push(pushed("203.0.113.9", "2001:db8::9"), netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "push-wan.json")); err != nil {
		t.Fatalf("the file: %v", err)
	}
	again := pushSource(t, dir, time.Hour)
	if got := slices.Sorted(slices.Values(again.Addresses().Strings())); !slices.Equal(got, []string{"2001:db8::9", "203.0.113.9"}) {
		t.Errorf("after a restart: %v", got)
	}
	// Its lifetime over, by the file's time.
	data := []byte(`{"addresses":["203.0.113.9"],"at":"2020-01-01T00:00:00Z"}`)
	os.WriteFile(filepath.Join(dir, "push-wan.json"), data, 0o600)
	if got := pushSource(t, dir, time.Hour).Addresses().Strings(); len(got) != 0 {
		t.Errorf("after its lifetime: %v", got)
	}
	// Without a lifetime, kept however long ago.
	if got := pushSource(t, dir, 0).Addresses().Strings(); !slices.Equal(got, []string{"203.0.113.9"}) {
		t.Errorf("without a lifetime: %v", got)
	}
	// A file that doesn't read stops the start, with the source and the file.
	os.WriteFile(filepath.Join(dir, "push-wan.json"), []byte("{"), 0o600)
	cfg := config.Source{Type: config.SourcePush, Password: "secret"}
	cfg.Lifetime.Duration = time.Hour
	if _, err := New("wan", cfg, dir, nil); err == nil {
		t.Error("a broken file read")
	}
}

// The file is state_file, relative to the configuration's folder, unless absolute.
func TestPushFile(t *testing.T) {
	for _, tc := range []struct{ stateFile, want string }{
		{"", "/etc/ipv6ddns/push-wan.json"},
		{"state/wan.json", "/etc/ipv6ddns/state/wan.json"},
		{"/var/lib/ipv6ddns/wan.json", "/var/lib/ipv6ddns/wan.json"},
	} {
		if got := pushFile("wan", config.Source{StateFile: tc.stateFile}, "/etc/ipv6ddns"); got != tc.want {
			t.Errorf("%q: %s, want %s", tc.stateFile, got, tc.want)
		}
	}
}

// The prefix a router sends replaces the one before, counts as a change, is kept in the file, and
// stays when an update sends none; one alone is an update too.
func TestPushPrefix(t *testing.T) {
	dir := t.TempDir()
	s := pushSource(t, dir, 0)
	if _, ok := s.Prefix(); ok {
		t.Fatal("a prefix before any push")
	}
	if changed, err := s.Push(pushed("203.0.113.9"), netip.MustParsePrefix("2001:db8:1:2::1/64")); !changed || err != nil {
		t.Fatalf("%v, %v", changed, err)
	}
	if p, _ := s.Prefix(); p.String() != "2001:db8:1:2::/64" {
		t.Errorf("the prefix: %s", p)
	}
	if changed, _ := s.Push(pushed("203.0.113.9"), netip.Prefix{}); changed {
		t.Error("an update without a prefix changed it")
	}
	if changed, err := s.Push(nil, netip.MustParsePrefix("2001:db8:9::/56")); !changed || err != nil {
		t.Errorf("a prefix alone: %v, %v", changed, err)
	}
	if st := s.Status(false); st.Prefix != "2001:db8:9::/56" {
		t.Errorf("the status: %+v", st)
	}
	again := pushSource(t, dir, 0)
	if p, ok := again.Prefix(); !ok || p.String() != "2001:db8:9::/56" {
		t.Errorf("after a restart: %s, %v", p, ok)
	}
	if got := again.Addresses().Strings(); !slices.Equal(got, []string{"203.0.113.9"}) {
		t.Errorf("the addresses after a restart: %v", got)
	}
}

// The prefix lasts the source's lifetime from when it was sent, as the addresses do, though later
// updates send none; after a restart, from the time in the file. The times are set, not waited.
func TestPushPrefixLifetime(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8:1:2::/64")
	sentAt := func(s *Source) time.Time {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		return s.prefixAt
	}
	dir := t.TempDir()
	s := pushSource(t, dir, time.Hour)
	if _, err := s.Push(nil, prefix); err != nil {
		t.Fatal(err)
	}
	first := sentAt(s)
	// An update without a prefix doesn't make the old one new.
	if _, err := s.Push(pushed("203.0.113.9"), netip.Prefix{}); err != nil {
		t.Fatal(err)
	}
	if !sentAt(s).Equal(first) {
		t.Error("an update without a prefix renewed it")
	}

	// Sent past its lifetime: gone, from the status too; sent again, new, and a change.
	s.mutex.Lock()
	s.prefixAt = time.Now().Add(-time.Hour - time.Second)
	s.mutex.Unlock()
	if p, ok := s.Prefix(); ok {
		t.Errorf("past its lifetime: %s", p)
	}
	if st := s.Status(false); st.Prefix != "" {
		t.Errorf("the status past its lifetime: %+v", st)
	}
	if changed, _ := s.Push(nil, prefix); !changed {
		t.Error("the prefix sent again past its lifetime is no change")
	}

	// After a restart: the prefix of the file, by the time it was sent, which isn't the file's.
	for name, c := range map[string]struct {
		prefixAt time.Duration
		want     bool
	}{"within its lifetime": {-30 * time.Minute, true}, "past it": {-2 * time.Hour, false}} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			at, prefixAt := time.Now().UTC().Format(time.RFC3339), time.Now().Add(c.prefixAt).UTC().Format(time.RFC3339)
			os.WriteFile(filepath.Join(dir, "push-wan.json"), []byte(`{"addresses":["203.0.113.9"],"at":"`+at+`","prefix":"2001:db8:1:2::/64","prefix_at":"`+prefixAt+`"}`), 0o600)
			s := pushSource(t, dir, time.Hour)
			if p, ok := s.Prefix(); ok != c.want || (ok && p != prefix) {
				t.Errorf("%s, %v", p, ok)
			}
			if got := s.Addresses().Strings(); !slices.Equal(got, []string{"203.0.113.9"}) {
				t.Errorf("the addresses: %v", got)
			}
		})
	}

	// A file without the prefix's time: the file's.
	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, "push-wan.json"), []byte(`{"addresses":[],"at":"`+time.Now().UTC().Format(time.RFC3339)+`","prefix":"2001:db8:1:2::/64"}`), 0o600)
	if p, ok := pushSource(t, dir, time.Hour).Prefix(); !ok || p != prefix {
		t.Errorf("without its time: %s, %v", p, ok)
	}
}

// Pushes at once, of each family: each takes the state of the one before, and the file has the
// last.
func TestPushConcurrent(t *testing.T) {
	dir := t.TempDir()
	s := pushSource(t, dir, 0)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			if _, err := s.Push(pushed(fmt.Sprintf("203.0.113.%d", i+1), fmt.Sprintf("2001:db8::%x", i+1)), netip.Prefix{}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	got := s.Addresses().Strings()
	if len(got) != 2 {
		t.Fatalf("after the pushes: %v", got)
	}
	again := pushSource(t, dir, 0).Addresses().Strings()
	if !slices.Equal(slices.Sorted(slices.Values(again)), slices.Sorted(slices.Values(got))) {
		t.Errorf("the file has %v, the source %v", again, got)
	}
}

// A file that doesn't read stops the source's making, with the file and what is wrong; one that
// isn't there is no error.
func TestPushFileErrors(t *testing.T) {
	recent := time.Now().UTC().Format(time.RFC3339)
	for _, c := range []struct{ name, content, want string }{
		{"not JSON", "{", "doesn't read"},
		{"a prefix that isn't one", `{"addresses":[],"at":"` + recent + `","prefix":"2001:db8::/129"}`, `has the prefix "2001:db8::/129"`},
		{"an address that isn't one", `{"addresses":["203.0.113.300"],"at":"` + recent + `"}`, `has "203.0.113.300", not an address`},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "push-wan.json"), []byte(c.content), 0o600)
			cfg := config.Source{Type: config.SourcePush, Password: "secret"}
			cfg.Lifetime.Duration = config.PushForever
			_, err := New("wan", cfg, dir, nil)
			if err == nil || !strings.Contains(err.Error(), "source wan: ") || !strings.Contains(err.Error(), c.want) {
				t.Errorf("got %v, want %q", err, c.want)
			}
		})
	}
	// A file that can't be read, as a folder in its place.
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "push-wan.json"), 0o700)
	cfg := config.Source{Type: config.SourcePush, Password: "secret"}
	cfg.Lifetime.Duration = config.PushForever
	if _, err := New("wan", cfg, dir, nil); err == nil || !strings.HasPrefix(err.Error(), "source wan: ") {
		t.Errorf("a folder for the file: %v", err)
	}
}

// A file that can't be written: the push is taken still, and changes the addresses, and the error
// says so, of the file's folder and of the file.
func TestPushSaveError(t *testing.T) {
	for name, block := range map[string]string{"its folder is a file": "state", "the file is a folder": "state/push-wan.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := config.Source{Type: config.SourcePush, Password: "secret", StateFile: "state/push-wan.json"}
			cfg.Lifetime.Duration = config.PushForever
			s, err := New("wan", cfg, dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			if block == "state" {
				os.WriteFile(filepath.Join(dir, "state"), nil, 0o600)
			} else {
				os.MkdirAll(filepath.Join(dir, block), 0o700)
			}
			changed, err := s.Push(pushed("203.0.113.9"), netip.Prefix{})
			if !changed || err == nil || !strings.Contains(err.Error(), "source wan: keeping the addresses: ") {
				t.Errorf("%v, %v", changed, err)
			}
			if got := s.Addresses().Strings(); !slices.Equal(got, []string{"203.0.113.9"}) {
				t.Errorf("the addresses: %v", got)
			}
		})
	}
}
