package config

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

func TestTaskMatch(t *testing.T) {
	hw, _ := net.ParseMAC("00:11:22:33:44:55")
	addr := ipv6disc.NewAddr(hw, netip.MustParseAddr("2001:db8::211:22ff:fe33:4455"), "router", time.Hour, nil)

	var byMAC, byPrefix, byOtherPrefix, bySource Filters
	byMAC.MAC.Address = "00:11:22:33:44:55"
	byPrefix.IP.Prefix = netip.MustParsePrefix("2001:db8::/64")
	byOtherPrefix.IP.Prefix = netip.MustParsePrefix("fd00::/8")
	bySource.Source = []string{"eth0"}
	macAndOtherPrefix := byMAC
	macAndOtherPrefix.IP.Prefix = byOtherPrefix.IP.Prefix
	eui64 := byMAC
	eui64.IP.Type = []string{"eui64", "global"}

	tests := []struct {
		name    string
		filters []Filters
		want    bool
	}{
		{"no filters", nil, false},
		{"an empty filter", []Filters{{}}, true},
		{"its MAC", []Filters{byMAC}, true},
		{"its MAC and EUI-64 global", []Filters{eui64}, true},
		{"its MAC, another prefix: every check of a filter must pass", []Filters{macAndOtherPrefix}, false},
		{"another prefix, or its prefix: any filter can match", []Filters{byOtherPrefix, byPrefix}, true},
		{"a source that didn't see it", []Filters{bySource}, false},
	}
	for _, tt := range tests {
		if got := (Task{Filters: tt.filters}).Match(addr); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}

// self takes this machine's own addresses, of whatever MAC; temporary and "!" take or leave its
// privacy addresses.
func TestSelfFilters(t *testing.T) {
	state := ipv6disc.NewState()
	state.SetFamilies(true, true)
	own, _ := net.ParseMAC("02:00:00:00:00:01")
	neighbor, _ := net.ParseMAC("02:00:00:00:00:02")
	register := func(self, temporary bool, mac net.HardwareAddr, ip string) *ipv6disc.Addr {
		var a *ipv6disc.Addr
		if self {
			a, _ = state.RegisterSelf(mac, netip.MustParseAddr(ip), "eth0", temporary, time.Hour, nil)
		} else {
			a, _ = state.Register(mac, netip.MustParseAddr(ip), "eth0", time.Hour, nil)
		}
		t.Cleanup(a.Unwatch)
		return a
	}
	stable := register(true, false, own, "2001:db8::1")
	temporary := register(true, true, own, "2001:db8::a1b2:c3d4:e5f6:708")
	local4 := register(true, false, own, "192.168.1.10")
	other := register(false, false, neighbor, "2001:db8::2")

	filter := func(yaml string) Filters {
		var f Filters
		if err := json.Unmarshal([]byte(yaml), &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	for _, c := range []struct {
		filter string
		want   map[*ipv6disc.Addr]bool
	}{
		{`{"self": true}`, map[*ipv6disc.Addr]bool{stable: true, temporary: true, local4: false, other: false}},
		{`{"self": true, "ip": {"type": ["global", "!temporary"]}}`, map[*ipv6disc.Addr]bool{stable: true, temporary: false, other: false}},
		{`{"self": true, "ip": {"type": ["temporary"]}}`, map[*ipv6disc.Addr]bool{stable: false, temporary: true}},
		{`{"self": true, "ip": {"family": [4], "type": ["private"]}}`, map[*ipv6disc.Addr]bool{local4: true, stable: false}},
		{`{"ip": {"type": ["!temporary"]}}`, map[*ipv6disc.Addr]bool{other: true, temporary: false}},
		{`{"mac": {"type": ["!multicast", "local"]}}`, map[*ipv6disc.Addr]bool{other: true}},
		{`{"mac": {"type": ["!local"]}}`, map[*ipv6disc.Addr]bool{other: false}},
	} {
		f := filter(c.filter)
		for addr, want := range c.want {
			if got := f.Match(addr); got != want {
				t.Errorf("%s, %s: %v, want %v", c.filter, addr.Addr, got, want)
			}
		}
	}
}
