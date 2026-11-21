package config

import (
	"encoding/json"
	"net"
	"net/netip"
	"strings"
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

func host(mac, address string) *ipv6disc.Addr {
	hw, _ := net.ParseMAC(mac)
	return ipv6disc.NewAddr(hw, netip.MustParseAddr(address), "eth0", time.Hour, nil)
}

func filterConfig(filter string) string {
	// A filter of several lines is one item: the lines after the first are under it.
	filter = strings.ReplaceAll(filter, "\n", "\n        ")
	return "tasks:\n  web:\n    filter:\n      - " + filter + "\n    endpoints:\n      duck:\n        - www\n" + duckCredential
}

// A mask that doesn't parse is an error, as it loads: skipped, the filter would match every host,
// and take the whole network to the task's names.
func TestInvalidMasksAreErrors(t *testing.T) {
	for filter, want := range map[string]string{
		`mac:
  mask:
    - "00:11:22:00:00:00/ff:ff:ff"`: `task web: filter 1: mac.mask "00:11:22:00:00:00/ff:ff:ff": the mask "ff:ff:ff" is not a MAC`,
		`mac:
  mask:
    - "00:11:22:00:00:00"`: "not VALUE/MASK",
		`mac:
  mask:
    - "00:11:22:00:00:00/ff:ff:ff:00:00:00/"`: "not VALUE/MASK",
		`mac:
  mask:
    - "nope/ff:ff:ff:00:00:00"`: `the value "nope" is not a MAC`,
		`mac:
  mask:
    - "00:11:22:33:44:55:66:77/ff:ff:ff:ff:ff:ff:ff:ff"`: "a MAC is 6 bytes",
		`ip:
  mask:
    - "::1/64"`: `task web: filter 1: ip.mask "::1/64": the mask "64" is not an address`,
		`ip:
  mask:
    - "::1/128"`: "not a prefix length",
		`ip:
  mask:
    - "::1"`: "not VALUE/MASK",
		`ip:
  mask:
    - "::1/::ffff/::1"`: "not VALUE/MASK",
		`ip:
  mask:
    - "one/::ffff"`: `the value "one" is not an address`,
		`ip:
  mask:
    - "::1/0.0.0.255"`: "not of the same family",
		`ip:
  mask:
    - "fe80::1%eth0/::ffff"`: "is not an address",
		`ip:
  mask:
    - "::1/::ffff"
    - "::1/64"`: `ip.mask "::1/64"`,
	} {
		_, err := loadConfig(t, filterConfig(filter))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error with %q", filter, err, want)
		}
	}

	// And one made in code, that no configuration checked, matches nothing.
	for _, f := range []Filters{
		{MAC: MACFilters{Mask: []string{"00:11:22:00:00:00/ff:ff:ff"}}},
		{IP: IPFilters{Mask: []string{"::1/64"}}},
		{MAC: MACFilters{Address: "00:11:22:33:44"}},
	} {
		if f.Match(host("de:ad:be:ef:00:01", "2001:db8::99")) {
			t.Errorf("%+v matches an unrelated host", f)
		}
	}
}

func TestMasksOfBothFamilies(t *testing.T) {
	cfg, err := loadConfig(t, filterConfig(`mac:
  mask:
    - "00-11-22-00-00-00/ff-ff-ff-00-00-00"
ip:
  family:
    - 4
    - 6
  mask:
    - "0.0.0.5/0.0.0.255"`))
	if err != nil {
		t.Fatal(err)
	}
	task := cfg.Tasks["web"]
	for address, want := range map[string]bool{"192.168.1.5": true, "192.168.1.6": false, "2001:db8::5": false} {
		if got := task.Match(host("00:11:22:33:44:55", address)); got != want {
			t.Errorf("%s: got %t, want %t", address, got, want)
		}
	}
	if task.Match(host("00:11:23:33:44:55", "192.168.1.5")) {
		t.Error("the MAC of another vendor matches")
	}
}

// A MAC in any form net.ParseMAC reads is kept in the canonical one, which is what the hosts'
// are compared with, and what soliciting asks for; what is no MAC is an error, not a task that
// never gets an address.
func TestMACAddressForms(t *testing.T) {
	for _, written := range []string{"00:11:22:AA:BB:CC", "00-11-22-aa-bb-cc", "0011.22aa.bbcc"} {
		cfg, err := loadConfig(t, filterConfig("mac:\n  address: \""+written+"\""))
		if err != nil {
			t.Errorf("%s: %v", written, err)
			continue
		}
		task := cfg.Tasks["web"]
		if got := task.Filters[0].MAC.Address; got != "00:11:22:aa:bb:cc" {
			t.Errorf("%s: kept as %q", written, got)
		}
		if !task.Match(host("00:11:22:aa:bb:cc", "2001:db8::1")) || task.Match(host("00:11:22:aa:bb:cd", "2001:db8::1")) {
			t.Errorf("%s: doesn't match its host alone", written)
		}
	}

	for _, wrong := range []string{"00:11:22:33:44", "00:11:22:33:44:5g", "00:11-22:33-44:55", "00:11:22:33:44:55:66:77", "001122334455", ""} {
		_, err := loadConfig(t, filterConfig("mac:\n  address: \""+wrong+"\""))
		if wrong == "" {
			// No address: no rule.
			if err != nil {
				t.Errorf("an empty address: %v", err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "not a MAC address, as 00:11:22:33:44:55") || !strings.Contains(err.Error(), "web") {
			t.Errorf("%s: got %v, want an error naming the task", wrong, err)
		}
	}

	// Unquoted and all digits, as the example writes it: a string, not a base 60 number of YAML 1.1.
	cfg, err := loadConfig(t, filterConfig("mac:\n  address: 12:34:56:18:10:12"))
	if err != nil || cfg.Tasks["web"].Filters[0].MAC.Address != "12:34:56:18:10:12" {
		t.Errorf("unquoted: %v, %+v", err, cfg.Tasks["web"].Filters)
	}
}
