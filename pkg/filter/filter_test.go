package filter

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
)

func parseMAC(s string) net.HardwareAddr {
	mac, _ := net.ParseMAC(s)
	return mac
}

func parseIP(s string) netip.Addr {
	ip, _ := netip.ParseAddr(s)
	return ip
}

func TestCheckMAC(t *testing.T) {
	tests := []struct {
		name   string
		mac    string
		filter string
		want   bool
	}{
		{"Empty filter", "00:11:22:33:44:55", "", true},
		{"Match", "00:11:22:33:44:55", "00:11:22:33:44:55", true},
		{"Mismatch", "00:11:22:33:44:55", "00:11:22:33:44:56", false},
		{"Case insensitive", "00:11:22:aa:bb:cc", "00:11:22:AA:BB:CC", true},
		// The forms net.ParseMAC reads, as Windows and Cisco write them.
		{"Dashes", "00:11:22:33:44:55", "00-11-22-33-44-55", true},
		{"Dots", "00:11:22:33:44:55", "0011.2233.4455", true},
		{"Dashes, mismatch", "00:11:22:33:44:55", "00-11-22-33-44-56", false},
		{"Not a MAC", "00:11:22:33:44:55", "00:11:22:33:44", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckMAC(parseMAC(tt.mac), tt.filter); got != tt.want {
				t.Errorf("CheckMAC() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckPrefix(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		subnet string
		want   bool
	}{
		{"Invalid subnet", "2001:db8::1", "", true},
		{"Match", "2001:db8::1", "2001:db8::/64", true},
		{"Mismatch", "2001:db9::1", "2001:db8::/64", false},
		{"Zone ignored", "fe80::1%eth0", "fe80::/64", true},
		{"IPv4", "192.168.1.5", "192.168.1.0/24", true},
		// An IPv4-mapped address is the IPv4 address it holds, as for family and mask.
		{"IPv4-mapped in an IPv4 prefix", "::ffff:192.168.1.5", "192.168.1.0/24", true},
		{"IPv4-mapped outside an IPv4 prefix", "::ffff:192.168.2.5", "192.168.1.0/24", false},
		{"IPv4 in no IPv6 prefix", "192.168.1.5", "2001:db8::/64", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, _ := netip.ParsePrefix(tt.subnet) // if error, IsValid() is false
			if got := CheckPrefix(parseIP(tt.ip), prefix); got != tt.want {
				t.Errorf("CheckPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckMACMask(t *testing.T) {
	tests := []struct {
		name   string
		mac    string
		filter string
		want   bool
	}{
		{
			name:   "Exact match via mask",
			mac:    "00:11:22:33:44:55",
			filter: "00:11:22:33:44:55/ff:ff:ff:ff:ff:ff",
			want:   true,
		},
		{
			name:   "OUI match",
			mac:    "00:11:22:33:44:55",
			filter: "00:11:22:00:00:00/ff:ff:ff:00:00:00",
			want:   true,
		},
		{
			name:   "OUI mismatch",
			mac:    "00:11:23:33:44:55",
			filter: "00:11:22:00:00:00/ff:ff:ff:00:00:00",
			want:   false,
		},
		{
			name:   "Local bit set (Virtual)",
			mac:    "02:00:00:00:00:00",
			filter: "02:00:00:00:00:00/02:00:00:00:00:00",
			want:   true,
		},
		// What doesn't parse matches nothing, rather than everything.
		{name: "Short mask", mac: "de:ad:be:ef:00:01", filter: "00:11:22:00:00:00/ff:ff:ff", want: false},
		{name: "No slash", mac: "00:11:22:33:44:55", filter: "00:11:22:33:44:55", want: false},
		{name: "Two slashes", mac: "00:11:22:33:44:55", filter: "00:11:22:33:44:55/ff:ff:ff:ff:ff:ff/00", want: false},
		{name: "Invalid value", mac: "00:11:22:33:44:55", filter: "nope/ff:ff:ff:ff:ff:ff", want: false},
		{name: "Longer than the MAC", mac: "00:11:22:33:44:55", filter: "00:00:00:00:00:00:00:00/00:00:00:00:00:00:00:00", want: false},
		{name: "Dashes", mac: "00:11:22:33:44:55", filter: "00-11-22-00-00-00/ff-ff-ff-00-00-00", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckMACMask(parseMAC(tt.mac), []string{tt.filter}); got != tt.want {
				t.Errorf("CheckMACMask() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckMACType(t *testing.T) {
	tests := []struct {
		name   string
		mac    string
		filter string
		want   bool
	}{
		{"Global UAA", "00:11:22:33:44:55", "global", true},
		{"Global LAA (fail)", "02:11:22:33:44:55", "global", false},
		{"Local LAA", "02:11:22:33:44:55", "local", true},
		{"Local UAA (fail)", "00:11:22:33:44:55", "local", false},
		{"Multicast", "01:00:5e:00:00:01", "multicast", true},
		{"Unicast", "00:11:22:33:44:55", "unicast", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckMACType(parseMAC(tt.mac), []string{tt.filter}); got != tt.want {
				t.Errorf("CheckMACType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckIPType(t *testing.T) {
	mac := parseMAC("00:11:22:33:44:55")
	// EUI-64 should be: 0211:22ff:fe33:4455
	validEUI64 := ipv6disc.NewAddr(mac, parseIP("2001:db8::211:22ff:fe33:4455"), "test", time.Hour, nil)
	randomIP := ipv6disc.NewAddr(mac, parseIP("2001:db8::1234"), "test", time.Hour, nil)
	ulaIP := ipv6disc.NewAddr(mac, parseIP("fc00::1"), "test", time.Hour, nil)
	linkLocalIP := ipv6disc.NewAddr(mac, parseIP("fe80::1"), "test", time.Hour, nil)

	tests := []struct {
		name   string
		addr   *ipv6disc.Addr
		filter string
		want   bool
	}{
		{"EUI64 match", validEUI64, "eui64", true},
		{"EUI64 non-match", randomIP, "eui64", false},
		{"Random match", randomIP, "random", true},
		{"Random non-match", validEUI64, "random", false},
		{"Global match", validEUI64, "global", true},
		{"ULA match", ulaIP, "ula", true},
		{"LinkLocal match", linkLocalIP, "link_local", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckIPType(tt.addr, []string{tt.filter}); got != tt.want {
				t.Errorf("CheckIPType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckMask(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		filter string
		want   bool
	}{
		{"Suffix ::1 match", "2001:db8::1", "::1/::ffff:ffff:ffff:ffff", true},
		{"Suffix ::1 mismatch", "2001:db8::2", "::1/::ffff:ffff:ffff:ffff", false},
		// The bits, whatever the text: a host part 2:0:0:5 is no ::5, though its text ends so.
		{"Host part ::5, written short", "2001:db8:1:1::5", "::5/::ffff:ffff:ffff:ffff", true},
		{"Host part 2:0:0:5 is not ::5", "2001:db8:1:1:2:0:0:5", "::5/::ffff:ffff:ffff:ffff", false},
		{"Host part ending 0:5", "2001:db8:1:1:2:0:0:5", "::5/::ffff:ffff", true},
		{"Last group 15 is not 5", "2001:db8:1:1::15", "::5/::ffff", false},
		{"Subnet and host, any prefix", "2001:db8:aaaa:42::5", "0:0:0:42::5/0:0:0:ffff:ffff:ffff:ffff:ffff", true},
		{"Match odd", "2001:db8::1", "::1/::1", true},
		{"Match odd (fail)", "2001:db8::2", "::1/::1", false},
		{"Match even", "2001:db8::2", "::0/::1", true},
		{"Zone ignored", "fe80::1%eth0", "::1/::ffff", true},
		// Within the address's family.
		{"IPv4 match", "192.168.1.5", "0.0.0.5/0.0.0.255", true},
		{"IPv4 mismatch", "192.168.1.6", "0.0.0.5/0.0.0.255", false},
		{"IPv4-mapped is IPv4", "::ffff:192.168.1.5", "0.0.0.5/0.0.0.255", true},
		// A pair written in IPv6 is IPv6, whatever its bytes: ::ffff:X:Y are those of an IPv4-mapped
		// address, and the mask of the last 48 bits is one.
		{"Last 48 bits", "2001:db8:1:1::1234:dead:beef", "::1234:dead:beef/::ffff:ffff:ffff", true},
		{"Last 48 bits mismatch", "2001:db8:1:1::1235:dead:beef", "::1234:dead:beef/::ffff:ffff:ffff", false},
		{"Last 48 bits, above them ignored", "2001:db8:1:7:9:1234:dead:beef", "::1234:dead:beef/::ffff:ffff:ffff", true},
		{"Last 48 bits ffff:dead:beef", "2001:db8:1:1::ffff:dead:beef", "::ffff:dead:beef/::ffff:ffff:ffff", true},
		{"Last 48 bits ffff:dead:beef mismatch", "2001:db8:1:1::fffe:dead:beef", "::ffff:dead:beef/::ffff:ffff:ffff", false},
		{"Interface ID 0:ffff:0:5", "2001:db8:1:1:0:ffff:0:5", "::ffff:0:5/::ffff:ffff:ffff:ffff", true},
		{"Interface ID 0:ffff:0:5 mismatch", "2001:db8:1:1:0:ffff:0:6", "::ffff:0:5/::ffff:ffff:ffff:ffff", false},
		{"A pair written in IPv6, with an IPv4 tail, is IPv6", "2001:db8::ffff:c0a8:105", "::ffff:192.168.1.5/::ffff:ffff:ffff", true},
		{"An IPv6 pair of a mapped address's bytes takes no IPv4 address", "192.168.1.5", "::ffff:c0a8:105/::ffff:ffff:ffff", false},
		{"Nor an IPv4-mapped one, which is IPv4", "::ffff:192.168.1.5", "::ffff:c0a8:105/::ffff:ffff:ffff", false},
		{"A value in IPv6 and a mask in IPv4", "192.168.1.5", "::ffff:192.168.1.5/255.255.255.255", false},
		{"IPv4 against an IPv6 mask", "192.168.1.5", "::5/::ff", false},
		{"IPv6 against an IPv4 mask", "2001:db8::5", "0.0.0.5/0.0.0.255", false},
		// What doesn't parse matches nothing, rather than everything.
		{"Prefix length for a mask", "2001:db8::1", "::1/64", false},
		{"Prefix length 128", "2001:db8::1", "::1/128", false},
		{"No slash", "2001:db8::1", "::1", false},
		{"Two slashes", "2001:db8::1", "::1/::1/::1", false},
		{"Invalid value", "2001:db8::1", "nope/::1", false},
		{"Mixed families", "2001:db8::1", "::1/0.0.0.255", false},
		{"Zone in the mask", "2001:db8::1", "::1/::1%eth0", false},
		{"Empty", "2001:db8::1", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckMask(parseIP(tt.ip), []string{tt.filter}); got != tt.want {
				t.Errorf("CheckMask() = %v, want %v", got, tt.want)
			}
		})
	}
}

// A pair's family is the one it is written in: the parts come back as written, an IPv6 one of an
// IPv4-mapped address's bytes too, and two of different families are refused.
func TestParseIPMask(t *testing.T) {
	for pair, want := range map[string]string{
		"::1/::ffff:ffff:ffff:ffff":           "",
		"0.0.0.5/0.0.0.255":                   "",
		"::1234:dead:beef/::ffff:ffff:ffff":   "",
		"::ffff:dead:beef/::ffff:ffff:ffff":   "",
		"::ffff:0:5/::ffff:ffff:ffff:ffff":    "",
		"::ffff:192.168.1.5/::ffff:ffff:ffff": "",
		"::1/0.0.0.255":                       "of different families",
		"0.0.0.5/::ffff":                      "of different families",
		"::ffff:192.168.1.5/255.255.255.255":  "of different families",
		"::1/64":                              "not an address",
		"::1":                                 "not VALUE/MASK",
		"fe80::1%eth0/::ffff":                 "not an address",
	} {
		value, mask, err := ParseIPMask(pair)
		if want != "" {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s: %v, want an error of %q", pair, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", pair, err)
			continue
		}
		if v, m, _ := strings.Cut(pair, "/"); value != netip.MustParseAddr(v) || mask != netip.MustParseAddr(m) || value.Is4() != !strings.Contains(v, ":") {
			t.Errorf("%s: read as %s/%s", pair, value, mask)
		}
	}
}
