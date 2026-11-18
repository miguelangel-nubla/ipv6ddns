package config

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6disc"
	"go.uber.org/zap"
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

func TestIPv4Handler(t *testing.T) {
	var h IPv4Handler
	if err := h.UnmarshalJSON([]byte(`{"interval": "1h", "lifetime": "1h", "command": "printf", "args": ["192.0.2.1\n\nnot an address\n 192.0.2.2 \n"]}`)); err != nil {
		t.Fatal(err)
	}
	h.logger = zap.NewNop().Sugar()
	h.runCommand()
	got := h.AddrCollection.Strings()
	if len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "192.0.2.2" {
		t.Errorf("got %v, want the two addresses", got)
	}

	for _, bad := range []string{`{"interval": "0s", "lifetime": "1h", "command": "x"}`, `{"interval": "1m", "lifetime": "-1s", "command": "x"}`} {
		if err := new(IPv4Handler).UnmarshalJSON([]byte(bad)); err == nil {
			t.Errorf("%s: want an error", bad)
		}
	}
	if timeout := (&IPv4Handler{Interval: h.Interval}).commandTimeout(); timeout != time.Hour-time.Second {
		t.Errorf("timeout: %s", timeout)
	}
	short := IPv4Handler{}
	short.Interval.Duration = time.Second
	if timeout := short.commandTimeout(); timeout != 500*time.Millisecond {
		t.Errorf("timeout of a 1s interval: %s, want half of it", timeout)
	}
}
