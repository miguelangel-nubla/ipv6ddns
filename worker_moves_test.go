package ipv6ddns

import (
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"go.uber.org/zap"
)

// An address that moves to another MAC, as a router's neighbor table tells it, leaves the names of
// the host it left at once, not when its lifetime ends: the name of the device that had it no
// longer gives the address of another. The host that took it has it under its own name.
func TestTemplatesFollowAMovedAddress(t *testing.T) {
	cfg := loadConfig(t, `
credentials:
  fake:
    provider: fake
    debounce: 1ms
    settings:
      id: moves
tasks:
  lan:
    filter:
      - ip:
          prefix: 2001:db8::/64
    endpoints:
      fake:
        - "{hostname}"
`)
	w, err := NewWorker(zap.NewNop().Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.discWorker.State.Close)
	fake := fakeServices["moves"]
	ip := netip.MustParseAddr("2001:db8::5")
	report := func(mac string) {
		hw, _ := net.ParseMAC(mac)
		w.discWorker.State.Report(hw, ip, "router", "mikrotik", "neighbors", time.Hour, nil)
	}
	name := func(mac, name string) {
		hw, _ := net.ParseMAC(mac)
		w.discWorker.RegisterName(hw, name, "test", time.Hour)
	}
	wait := func(hostname string, want ...string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			updates := fake.updatesOf(hostname)
			if len(updates) > 0 && slices.Equal(updates[len(updates)-1], want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: got updates %v, want the last to be %v", hostname, updates, want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	report(macA)
	name(macA, "tv")
	w.lookForChanges()
	wait("tv", ip.String())

	time.Sleep(2 * time.Millisecond)
	report(macB)
	name(macB, "laptop")
	w.lookForChanges()
	wait("laptop", ip.String())
	wait("tv")
	if discovered(w, macA, ip.String()) {
		t.Error("the address stays at the MAC it left")
	}
}
