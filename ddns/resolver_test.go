package ddns

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

// Update keeps the name's addresses for the resolver, under every spelling of the name, without
// a zone or a mapping; none leaves it with none. It needs nothing, and never fails.
func TestResolverUpdate(t *testing.T) {
	service, err := NewService("resolver", json.RawMessage(`{"zone": "Home.Arpa."}`))
	if err != nil {
		t.Fatal(err)
	}
	r := service.(*Resolver)
	addrs := ipv6disc.NewAddrCollection()
	for _, ip := range []string{"192.168.1.10", "fe80::1%eth0", "::ffff:192.168.1.11", "2001:db8::10"} {
		addrs.Add(ipv6disc.NewAddr(nil, netip.MustParseAddr(ip), "test", time.Hour, nil))
	}
	if err := r.Update("NAS", addrs); err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("192.168.1.11"), netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("fe80::1")}
	for _, spelling := range []string{"nas.home.arpa.", "NAS.home.arpa"} {
		if got := r.Addresses().Get(spelling); !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", spelling, got, want)
		}
	}
	if got := r.Domain("nas"); got != "nas.Home.Arpa" {
		t.Errorf("domain: %s", got)
	}
	if err := r.Update("nas.home.arpa", ipv6disc.NewAddrCollection()); err != nil {
		t.Fatal(err)
	}
	if got := r.Addresses().Get("nas.home.arpa."); got != nil {
		t.Errorf("none: got %v", got)
	}
}
