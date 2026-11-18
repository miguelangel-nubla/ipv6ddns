package config

import (
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
