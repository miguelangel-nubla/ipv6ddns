package ipv6ddns

import (
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/config"
)

func TestEUI64Address(t *testing.T) {
	mac, _ := net.ParseMAC("00:0c:e3:71:45:68")
	got, ok := eui64Address(netip.MustParsePrefix("2001:db8:1:2::/64"), mac)
	if want := netip.MustParseAddr("2001:db8:1:2:20c:e3ff:fe71:4568"); !ok || got != want {
		t.Errorf("got %s, %v, want %s", got, ok, want)
	}
	if _, ok := eui64Address(netip.MustParsePrefix("2001:db8::/48"), mac); ok {
		t.Error("a prefix that isn't a /64: want none")
	}
}

func task(mac string, prefix string, types ...string) config.Task {
	var f config.Filters
	f.MAC.Address = mac
	f.IP.Type = types
	if prefix != "" {
		f.IP.Prefix = netip.MustParsePrefix(prefix)
	}
	return config.Task{Filters: []config.Filters{f}}
}

func TestEUI64Targets(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("2001:db8:1:2::/64"), netip.MustParsePrefix("fd51:1:2:3::/64")}
	const mac = "00:0c:e3:71:45:68"
	const global = "2001:db8:1:2:20c:e3ff:fe71:4568"
	const ula = "fd51:1:2:3:20c:e3ff:fe71:4568"
	tests := []struct {
		name string
		task config.Task
		want []string
	}{
		{"global", task(mac, "", "global", "eui64"), []string{global}},
		{"ula", task(mac, "", "ula", "eui64"), []string{ula}},
		{"either", task(mac, "", "eui64"), []string{global, ula}},
		{"upper case type", task(mac, "", "EUI64"), []string{global, ula}},
		{"inside the prefix filter", task(mac, "fd51::/16", "eui64"), []string{ula}},
		{"no eui64", task(mac, "", "global"), nil},
		{"no MAC", task("", "", "global", "eui64"), nil},
		{"bad MAC", task("nope", "", "global", "eui64"), nil},
	}
	for _, tt := range tests {
		var got []string
		for _, a := range eui64Targets(map[string]config.Task{"t": tt.task}, prefixes) {
			got = append(got, a.String())
		}
		slices.Sort(got)
		want := slices.Clone(tt.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", tt.name, got, want)
		}
	}
	two := map[string]config.Task{"a": task(mac, "", "global", "eui64"), "b": task(mac, "", "global", "eui64")}
	if got := eui64Targets(two, prefixes); len(got) != 1 {
		t.Errorf("the same address in two tasks: got %v, want it once", got)
	}
}
