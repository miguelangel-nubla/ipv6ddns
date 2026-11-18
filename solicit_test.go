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

func TestIPv4SolicitTargets(t *testing.T) {
	filter := func(mac string, families ...int) config.Filters {
		var f config.Filters
		f.MAC.Address = mac
		f.IP.Family = families
		return f
	}
	tasks := map[string]config.Task{
		"a": {Filters: []config.Filters{filter("00:11:22:33:44:01", 4), filter("00:11:22:33:44:02")}}, // the second: IPv6 only
		"b": {Filters: []config.Filters{filter("00:11:22:33:44:03", 4, 6), filter("00:11:22:33:44:01", 4)}},
		"c": {Filters: []config.Filters{filter("", 4), filter("nope", 4)}},
	}
	var got []string
	for _, mac := range ipv4SolicitTargets(tasks) {
		got = append(got, mac.String())
	}
	if want := []string{"00:11:22:33:44:01", "00:11:22:33:44:03"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
