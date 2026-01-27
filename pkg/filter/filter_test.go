package filter

import (
	"net"
	"net/netip"
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
		{"Case insensitive", "00:11:22:33:44:55", "00:11:22:33:44:55", true},
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

func TestCheckSuffix(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		suffix string
		want   bool
	}{
		{"Empty suffix", "2001:db8::1", "", true},
		{"Match", "2001:db8::1", "::1", true},
		{"Mismatch", "2001:db8::2", "::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckSuffix(parseIP(tt.ip), tt.suffix); got != tt.want {
				t.Errorf("CheckSuffix() = %v, want %v", got, tt.want)
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
		{"Match odd", "2001:db8::1", "::1/::1", true},
		{"Match odd (fail)", "2001:db8::2", "::1/::1", false},
		{"Match even", "2001:db8::2", "::0/::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckMask(parseIP(tt.ip), []string{tt.filter}); got != tt.want {
				t.Errorf("CheckMask() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckSource(t *testing.T) {
	addr := ipv6disc.NewAddr(nil, parseIP("::1"), "plugin-A", time.Hour, nil)
	addr.Seen("plugin-B")

	tests := []struct {
		name   string
		filter string
		want   bool
	}{
		{"Match A", "plugin-A", true},
		{"Match B", "plugin-B", true},
		{"Mismatch", "plugin-C", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckSource(addr, []string{tt.filter}); got != tt.want {
				t.Errorf("CheckSource() = %v, want %v", got, tt.want)
			}
		})
	}
}
