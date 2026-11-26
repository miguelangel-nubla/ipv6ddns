package resolver

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// One zone of two resolvers, which differ in upstream and allow: both answer its names with the
// addresses given once, after both started, its records, its wildcards and the reverse of its
// addresses; and neither asks its upstream any of them.
func TestZoneOfTwoResolvers(t *testing.T) {
	lanUp, kidsUp := newUpstream(t), newUpstream(t)
	lanCfg, addresses := testConfig(t, lanUp.address)
	kidsCfg := lanCfg
	kidsCfg.Name, kidsCfg.Path, kidsCfg.Upstreams = "kids", "resolvers.kids", []string{kidsUp.address}
	kidsCfg.Allow = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	lan, kids := start(t, lanCfg), start(t, kidsCfg)
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.10")})
	addresses.Set("*.dev.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.50")})

	for _, c := range []struct {
		name  string
		qtype uint16
		want  string
	}{
		{"nas.home.arpa.", dns.TypeA, "nas.home.arpa. A 192.168.1.10"},
		{"printer.home.arpa.", dns.TypeTXT, `printer.home.arpa. TXT "color"`},
		{"x.dev.home.arpa.", dns.TypeA, "x.dev.home.arpa. A 192.168.1.50"},
		{"10.1.168.192.in-addr.arpa.", dns.TypePTR, "10.1.168.192.in-addr.arpa. PTR nas.home.arpa."},
	} {
		for _, s := range []*Server{lan, kids} {
			resp := query(t, s, "udp", c.name, c.qtype, nil)
			if got := answers(resp); len(got) != 1 || got[0] != c.want || !resp.Authoritative {
				t.Errorf("%s: %s %s: %v, want %s", s.config.Name, c.name, dns.TypeToString[c.qtype], got, c.want)
			}
		}
	}
	for _, s := range []*Server{lan, kids} {
		if got := s.Status().ZoneNames["home.arpa"]; got != 2 {
			t.Errorf("%s: zone names %d", s.config.Name, got)
		}
	}
	if n := lanUp.queries.Load() + kidsUp.queries.Load(); n != 0 {
		t.Errorf("%d queries of the zone's names upstream", n)
	}

	// A name gone is gone of both.
	addresses.Set("nas.home.arpa.", nil)
	for _, s := range []*Server{lan, kids} {
		if resp := query(t, s, "udp", "nas.home.arpa.", dns.TypeA, nil); len(resp.Answer) != 0 {
			t.Errorf("%s: nas once gone: %v", s.config.Name, resp)
		}
	}
}
