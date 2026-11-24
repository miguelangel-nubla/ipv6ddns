package source

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
	if changed, err := s.Push(pushed("203.0.113.9", "2001:db8::9")); !changed || err != nil {
		t.Fatalf("the first push: %v, %v", changed, err)
	}
	have("203.0.113.9", "2001:db8::9")
	if changed, _ := s.Push(pushed("203.0.113.9")); changed {
		t.Error("the same IPv4 again changed something")
	}
	have("203.0.113.9", "2001:db8::9")
	if changed, _ := s.Push(pushed("2001:db8::10")); !changed {
		t.Error("a new IPv6 changed nothing")
	}
	have("203.0.113.9", "2001:db8::10")
	if changed, _ := s.Push(pushed("::ffff:203.0.113.10")); !changed {
		t.Error("a new IPv4, mapped, changed nothing")
	}
	have("203.0.113.10", "2001:db8::10")
	if _, err := s.Push(nil); err == nil {
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
	if _, err := s.Push(pushed("203.0.113.9", "2001:db8::9")); err != nil {
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
