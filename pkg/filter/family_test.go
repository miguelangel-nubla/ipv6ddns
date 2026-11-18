package filter

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

func TestCheckFamily(t *testing.T) {
	v4, v6, mapped := netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("::ffff:192.168.1.10")
	for _, tt := range []struct {
		ip       netip.Addr
		families []int
		want     bool
	}{
		// Without families, IPv6 only: a filter from before IPv4 discovery.
		{v6, nil, true},
		{v4, nil, false},
		{mapped, nil, false},
		{v4, []int{4}, true},
		{v6, []int{4}, false},
		{v4, []int{4, 6}, true},
		{v6, []int{4, 6}, true},
		{mapped, []int{4}, true},
	} {
		if got := CheckFamily(tt.ip, tt.families); got != tt.want {
			t.Errorf("CheckFamily(%s, %v) = %v, want %v", tt.ip, tt.families, got, tt.want)
		}
	}
}

func TestCheckIPTypeIPv4(t *testing.T) {
	mac := parseMAC("00:11:22:33:44:55")
	addr := func(ip string) *ipv6disc.Addr {
		return ipv6disc.NewAddr(mac, netip.MustParseAddr(ip), "test", time.Hour, nil)
	}
	for _, tt := range []struct {
		ip    string
		types []string
		want  bool
	}{
		{"203.0.113.7", []string{"global"}, true},
		{"192.168.1.10", []string{"global"}, false},
		{"192.168.1.10", []string{"private"}, true},
		{"10.1.2.3", []string{"private"}, true},
		{"172.16.0.1", []string{"private"}, true},
		{"100.64.1.1", []string{"cgnat"}, true},
		{"100.64.1.1", []string{"global"}, false},
		{"169.254.1.1", []string{"link_local"}, true},
		{"169.254.1.1", []string{"global"}, false},
		// The IPv6 meanings stay.
		{"2001:db8::1", []string{"global"}, true},
		{"fd00::1", []string{"global"}, false},
		{"fd00::1", []string{"private"}, true},
		{"fd00::1", []string{"ula"}, true},
		{"fe80::1", []string{"link_local"}, true},
		// The interface ID types are IPv6's.
		{"192.168.1.10", []string{"random"}, false},
		{"192.168.1.10", []string{"eui64"}, false},
		{"2001:db8::1234", []string{"random"}, true},
	} {
		if got := CheckIPType(addr(tt.ip), tt.types); got != tt.want {
			t.Errorf("CheckIPType(%s, %v) = %v, want %v", tt.ip, tt.types, got, tt.want)
		}
	}
}
