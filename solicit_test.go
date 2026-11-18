package ipv6ddns

import (
	"fmt"
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
		{"IPv4 only", ipv4Only(task(mac, "", "eui64")), nil},
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
	filter := func(mac, prefix string, families ...int) config.Filters {
		var f config.Filters
		f.MAC.Address = mac
		f.IP.Family = families
		if prefix != "" {
			f.IP.Prefix = netip.MustParsePrefix(prefix)
		}
		return f
	}
	tasks := map[string]config.Task{
		// The second: IPv6 only.
		"a": {Filters: []config.Filters{filter("00:11:22:33:44:01", "10.2.3.0/24", 4), filter("00:11:22:33:44:02", "")}},
		"b": {Filters: []config.Filters{
			filter("00:11:22:33:44:03", "", 4, 6),
			filter("00:11:22:33:44:01", "192.168.1.7/24", 4),
			filter("00:11:22:33:44:01", "10.2.3.0/24", 4),
		}},
		"c": {Filters: []config.Filters{filter("", "", 4), filter("nope", "", 4)}},
		// An IPv6 prefix takes no IPv4 address; a filter without a prefix asks everywhere.
		"d": {Filters: []config.Filters{filter("00:11:22:33:44:04", "2001:db8::/64", 4), filter("00:11:22:33:44:05", "10.0.0.0/8", 4), filter("00:11:22:33:44:05", "", 4)}},
	}
	var got []string
	for _, target := range ipv4SolicitTargets(tasks) {
		got = append(got, fmt.Sprint(target.MAC, target.Prefixes))
	}
	want := []string{
		"00:11:22:33:44:01 [10.2.3.0/24 192.168.1.0/24]",
		"00:11:22:33:44:03 []",
		"00:11:22:33:44:05 []",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func ipv4Only(t config.Task) config.Task {
	t.Filters[0].IP.Family = []int{4}
	return t
}
