package resolver

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The zones of RFC 6303 and RFC 7793, by their names: of whole octets, or whole nibbles.
func TestPrivateZones(t *testing.T) {
	zones := privateZones()
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
}

// By default, the reverse of a private network's address that the resolver has no name of is no
// such name, answered as its own, of the zone's SOA, and the upstream server isn't asked: whatever
// network the upstream server is in, here the loopback's. The reverse of an address it has a name
// of is that name, and of another type no data. The apex has its SOA and NS. The reverse of any
// other address is asked. With forward_unknown_private_reverse_queries, all it has no name of is asked, and
// what it names is its own all the same.
func TestPrivateReverse(t *testing.T) {
	up := newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
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
	// A name of the zone that isn't an address's: one with no name under it, and one deeper than
	// an address, are no such name; one above an address with a name has no data.
	local("2.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError, "168.192.in-addr.arpa.")
	local("x.10.1.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError, "168.192.in-addr.arpa.")
	if resp := local("1.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeSuccess, "168.192.in-addr.arpa."); len(resp.Answer) != 0 {
		t.Errorf("above the named address: %v", resp.Answer)
	}

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

	// The loopback's, though the upstream server is on it.
	local(reverseName4(t, "127.0.0.1"), dns.TypePTR, dns.RcodeNameError, "127.in-addr.arpa.")
	// Asked of the upstream server: of addresses of the internet, or next to a private network.
	for _, address := range []string{"8.8.8.8", "100.63.0.1", "172.32.0.1", "2a00::1"} {
		if _, asked := ask(reverseName4(t, address), dns.TypePTR); !asked {
			t.Errorf("%s: not asked of the upstream server", address)
		}
	}

	// With forward_unknown_private_reverse_queries: what it has no name of is asked; what it names, not.
	cfg.ForwardUnknownPrivateReverse = true
	forwarding, _ := startCached(t, cfg, 0)
	for _, address := range []string{"192.168.1.99", "fd00::99", "127.0.0.1"} {
		before := up.queries.Load()
		query(t, forwarding, "udp", reverseName4(t, address), dns.TypePTR, nil)
		if up.queries.Load() == before {
			t.Errorf("%s, forwarding: the upstream server wasn't asked", address)
		}
	}
	before := up.queries.Load()
	resp := query(t, forwarding, "udp", reverseName4(t, "192.168.1.10"), dns.TypePTR, nil)
	if up.queries.Load() != before || !resp.Authoritative || len(resp.Answer) != 1 || resp.Answer[0].(*dns.PTR).Ptr != "nas.home.arpa." {
		t.Errorf("the named address, forwarding: %v, asked upstream %t", resp.Answer, up.queries.Load() != before)
	}
}

// A name of a private reverse zone above one the resolver answers is there, with no data: no such
// name would deny the names under it, as RFC 8020 reads it. Above the address of a task's name, of
// a record's, of a PTR record written, and of a zone's of the reverse itself.
func TestPrivateEmptyNonTerminal(t *testing.T) {
	up := newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
	cfg.Records = append(cfg.Records, mustRecords(t, "", "7.3.2.10.in-addr.arpa. PTR host.example.com.")...)
	cfg.Zones = append(cfg.Zones, Zone{Credential: "reverse", Name: "5.10.in-addr.arpa.", TTL: time.Minute,
		Records: mustRecords(t, "5.10.in-addr.arpa", "1.2 PTR host.example.com.")})
	s := start(t, cfg)
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("172.16.5.10"), netip.MustParseAddr("fd00:1::10")})

	for _, name := range []string{"7.3.2.10.in-addr.arpa.", "1.2.5.10.in-addr.arpa.", reverseName4(t, "172.16.5.10"), reverseName4(t, "fd00:1::10"), reverseName4(t, "192.168.1.20")} {
		if resp := query(t, s, "udp", name, dns.TypePTR, nil); len(resp.Answer) != 1 {
			t.Fatalf("%s: %v", name, resp)
		}
	}
	for name, rcode := range map[string]int{
		// Above the task's name's addresses, which were given after the start.
		"5.16.172.in-addr.arpa.":    dns.RcodeSuccess,
		"6.16.172.in-addr.arpa.":    dns.RcodeNameError,
		"1.0.0.0.0.0.d.f.ip6.arpa.": dns.RcodeSuccess,
		"0.0.0.d.f.ip6.arpa.":       dns.RcodeSuccess,
		"2.0.0.0.0.0.d.f.ip6.arpa.": dns.RcodeNameError,
		"x.0.0.0.0.0.d.f.ip6.arpa.": dns.RcodeNameError,
		"10.0.0.0.0.d.f.ip6.arpa.":  dns.RcodeNameError,
		"1.168.192.in-addr.arpa.":   dns.RcodeSuccess, // printer.home.arpa's record
		"0.0.10.in-addr.arpa.":      dns.RcodeSuccess, // printer.lab.home.arpa's
		"0.10.in-addr.arpa.":        dns.RcodeSuccess,
		"1.10.in-addr.arpa.":        dns.RcodeNameError,
		"01.168.192.in-addr.arpa.":  dns.RcodeNameError,
		// Above the PTR record written, of the resolver's own.
		"3.2.10.in-addr.arpa.": dns.RcodeSuccess,
		"2.10.in-addr.arpa.":   dns.RcodeSuccess,
		"4.2.10.in-addr.arpa.": dns.RcodeNameError,
		// The zone of the reverse: its own name, a name above its record, and one beside it.
		"5.10.in-addr.arpa.":   dns.RcodeSuccess,
		"2.5.10.in-addr.arpa.": dns.RcodeSuccess,
		"3.5.10.in-addr.arpa.": dns.RcodeNameError,
	} {
		for _, qtype := range []uint16{dns.TypePTR, dns.TypeNS} {
			resp := query(t, s, "udp", name, qtype, nil)
			if _, ok := firstRR(resp.Ns).(*dns.SOA); resp.Rcode != rcode || len(resp.Answer) != 0 || !ok || !resp.Authoritative {
				t.Errorf("%s %s: %s, %d answers, authority %v; want %s with no data, of the resolver's own", name, dns.TypeToString[qtype],
					dns.RcodeToString[resp.Rcode], len(resp.Answer), resp.Ns, dns.RcodeToString[rcode])
			}
		}
	}
	if n := up.queries.Load(); n != 0 {
		t.Errorf("%d queries forwarded", n)
	}
}

func firstRR(rrs []dns.RR) dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	return rrs[0]
}
