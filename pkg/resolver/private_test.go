package resolver

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

// The zones of RFC 6303 and RFC 7793, by their names: of whole octets, or whole nibbles.
func TestPrivateZones(t *testing.T) {
	zones := privateZones(nil)
	if len(zones) != 17+16+64 {
		t.Errorf("%d zones", len(zones))
	}
	for _, want := range []string{
		"10.in-addr.arpa.", "168.192.in-addr.arpa.", "16.172.in-addr.arpa.", "31.172.in-addr.arpa.",
		"64.100.in-addr.arpa.", "127.100.in-addr.arpa.", "0.in-addr.arpa.", "127.in-addr.arpa.",
		"254.169.in-addr.arpa.", "2.0.192.in-addr.arpa.", "100.51.198.in-addr.arpa.", "113.0.203.in-addr.arpa.",
		"255.255.255.255.in-addr.arpa.",
		"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		"d.f.ip6.arpa.", "8.e.f.ip6.arpa.", "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", "b.e.f.ip6.arpa.",
		"8.b.d.0.1.0.0.2.ip6.arpa.",
	} {
		found := false
		for _, z := range zones {
			found = found || z == want
		}
		if !found {
			t.Errorf("no zone %s", want)
		}
	}
	// An upstream server in a network: its zone is the server's to answer.
	if zones := privateZones([]*upstreamServer{{host: "192.168.1.1"}, {host: "fd00::1"}, {host: "dns.example"}}); len(zones) != 17+16+64-2 {
		t.Errorf("with upstream servers in two of them, %d zones", len(zones))
	}
}

// With private_reverse, the reverse of a private network's address that the resolver has no name
// of is no such name, answered as its own, of the zone's SOA, and the upstream server isn't asked;
// the reverse of an address it has a name of is that name, and of another type no data. The apex
// has its SOA and NS. The reverse of the network the upstream server is in is asked of it, and of
// any other address too. Without, all is asked.
func TestPrivateReverse(t *testing.T) {
	up := newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
	cfg.PrivateReverse = true
	s, _ := startCached(t, cfg, 0)
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.10")})

	ask := func(name string, qtype uint16) (*dns.Msg, bool) {
		t.Helper()
		before := up.queries.Load()
		resp := query(t, s, "udp", name, qtype, nil)
		return resp, up.queries.Load() != before
	}
	local := func(name string, qtype uint16, rcode int, zone string) *dns.Msg {
		t.Helper()
		resp, asked := ask(name, qtype)
		if asked || resp.Rcode != rcode || !resp.Authoritative {
			t.Errorf("%s %s: %s, authoritative %t, upstream asked %t; want %s of the resolver's own", name, dns.TypeToString[qtype],
				dns.RcodeToString[resp.Rcode], resp.Authoritative, asked, dns.RcodeToString[rcode])
		}
		if zone != "" {
			soa, ok := firstRR(resp.Ns).(*dns.SOA)
			if !ok || soa.Hdr.Name != zone || soa.Mbox != "nobody.invalid." || soa.Minttl != privateTTL {
				t.Errorf("%s: the authority %v, want the SOA of %s", name, resp.Ns, zone)
			}
		}
		return resp
	}
	for address, zone := range map[string]string{
		"192.168.1.99": "168.192.in-addr.arpa.",
		"10.0.0.1":     "10.in-addr.arpa.",
		"172.20.0.1":   "20.172.in-addr.arpa.",
		"100.64.0.1":   "64.100.in-addr.arpa.",
		"169.254.1.1":  "254.169.in-addr.arpa.",
		"fd00::99":     "d.f.ip6.arpa.",
		"fe90::1":      "9.e.f.ip6.arpa.",
		"2001:db8::1":  "8.b.d.0.1.0.0.2.ip6.arpa.",
	} {
		local(reverseName4(t, address), dns.TypePTR, dns.RcodeNameError, zone)
	}
	// The loopback's zone is of its one address: its name is the apex, which has no PTR.
	local(reverseName4(t, "::1"), dns.TypePTR, dns.RcodeSuccess, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.")
	// A name of the zone that is no address's, deeper or shallower.
	local("1.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError, "168.192.in-addr.arpa.")

	// The address of a name of the resolver's: its name; of another type, no data.
	if resp := local(reverseName4(t, "192.168.1.10"), dns.TypePTR, dns.RcodeSuccess, ""); len(resp.Answer) != 1 || resp.Answer[0].(*dns.PTR).Ptr != "nas.home.arpa." {
		t.Errorf("the named address: %v", resp.Answer)
	}
	if resp := local(reverseName4(t, "192.168.1.10"), dns.TypeTXT, dns.RcodeSuccess, "168.192.in-addr.arpa."); len(resp.Answer) != 0 {
		t.Errorf("the named address, of TXT: %v", resp.Answer)
	}

	// The apex.
	if resp := local("168.192.in-addr.arpa.", dns.TypeSOA, dns.RcodeSuccess, ""); len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != dns.TypeSOA {
		t.Errorf("the apex's SOA: %v", resp.Answer)
	}
	if resp := local("168.192.in-addr.arpa.", dns.TypeNS, dns.RcodeSuccess, ""); len(resp.Answer) != 1 || resp.Answer[0].(*dns.NS).Ns != "168.192.in-addr.arpa." {
		t.Errorf("the apex's NS: %v", resp.Answer)
	}
	local("168.192.in-addr.arpa.", dns.TypeA, dns.RcodeSuccess, "168.192.in-addr.arpa.")

	// Asked of the upstream server: of the loopback, its network, and of addresses of the
	// internet, or next to a private network.
	for _, address := range []string{"127.0.0.1", "8.8.8.8", "100.63.0.1", "172.32.0.1", "2a00::1"} {
		if _, asked := ask(reverseName4(t, address), dns.TypePTR); !asked {
			t.Errorf("%s: not asked of the upstream server", address)
		}
	}

	// Without private_reverse: asked.
	cfg.PrivateReverse = false
	off, _ := startCached(t, cfg, 0)
	before := up.queries.Load()
	query(t, off, "udp", reverseName4(t, "192.168.1.99"), dns.TypePTR, nil)
	if up.queries.Load() == before {
		t.Error("without private_reverse, the upstream server wasn't asked")
	}
}

func firstRR(rrs []dns.RR) dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	return rrs[0]
}
