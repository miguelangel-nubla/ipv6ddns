package resolver

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func reverseName4(t *testing.T, address string) string {
	t.Helper()
	name, err := dns.ReverseAddr(address)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestReverseAddr(t *testing.T) {
	for name, want := range map[string]string{
		"10.1.168.192.in-addr.arpa.": "192.168.1.10",
		"10.1.168.192.IN-ADDR.ARPA.": "192.168.1.10",
		"0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.": "fd00::10",
		"F.e.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.": "2001:db8::ef",
	} {
		if got, ok := reverseAddr(name); !ok || got.String() != want {
			t.Errorf("%s: %s, %t, want %s", name, got, ok, want)
		}
	}
	for _, name := range []string{
		"1.168.192.in-addr.arpa.", "1.10.1.168.192.in-addr.arpa.", "010.1.168.192.in-addr.arpa.", "256.1.168.192.in-addr.arpa.",
		"x.1.168.192.in-addr.arpa.", "in-addr.arpa.", "10.1.168.192.in-addr.example.",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
		"10.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
		"g.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.",
	} {
		if got, ok := reverseAddr(name); ok {
			t.Errorf("%s: %s, and it is no address's", name, got)
		}
	}
}

// The reverse of an address that a name of the resolver's has is answered with the name: a
// task's, as long as it has the address, and a record's; every name of it, sorted; not a
// wildcard's. Any other reverse goes upstream.
func TestReverse(t *testing.T) {
	up := newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
	// The private networks' reverse it has no name of goes upstream too: what it names is its own
	// all the same.
	cfg.ForwardUnknownPrivateReverse = true
	cfg.Records = append(cfg.Records, mustRecords(t, "",
		"7.2.0.192.in-addr.arpa. PTR written.example.com.",
		"seven.example.com. A 192.0.2.7",
		"six.example.com. 20 AAAA 2001:db8::6")...)
	cfg.Zones[0].Records = append(cfg.Zones[0].Records, mustRecords(t, "home.arpa",
		"also A 192.168.1.20",
		// A deeper zone's name: never answered from this one.
		"hidden.lab A 192.168.1.77")...)
	s, _ := startCached(t, cfg, 100)
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("fd00::10")})
	addresses.Set("*.dev.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.50")})

	// names are the names of the address, a local answer; none, when the upstream server is asked.
	check := func(address string, ttl uint32, names ...string) {
		t.Helper()
		before := up.queries.Load()
		// As a client spells it, to its liking.
		asked := strings.ToUpper(reverseName4(t, address))
		resp := query(t, s, "udp", asked, dns.TypePTR, nil)
		var got []string
		for _, rr := range resp.Answer {
			ptr, ok := rr.(*dns.PTR)
			if !ok || ptr.Hdr.Name != asked || ptr.Hdr.Ttl != ttl || ptr.Hdr.Class != dns.ClassINET {
				t.Errorf("%s: %v, want a PTR of %s with a TTL of %d", address, rr, asked, ttl)
				continue
			}
			got = append(got, ptr.Ptr)
		}
		if !slices.Equal(got, names) {
			t.Errorf("%s: the names %q, want %q", address, got, names)
		}
		local := len(names) > 0
		if forwarded := up.queries.Load() > before; forwarded == local || resp.Authoritative != local {
			t.Errorf("%s: the upstream server asked: %t, authoritative: %t, want local: %t", address, forwarded, resp.Authoritative, local)
		}
		if local && resp.Rcode != dns.RcodeSuccess || !local && resp.Rcode != dns.RcodeNameError {
			t.Errorf("%s: %s", address, dns.RcodeToString[resp.Rcode])
		}
	}
	// A task's addresses, with the zone's TTL.
	check("192.168.1.10", 30, "nas.home.arpa.")
	check("fd00::10", 30, "nas.home.arpa.")
	// Records: of a zone, two names of one address, sorted; of a deeper zone; of the resolver.
	check("192.168.1.20", 60, "also.home.arpa.", "printer.home.arpa.")
	check("192.168.1.21", 60, "printer.home.arpa.")
	check("10.0.0.20", 60, "printer.lab.home.arpa.")
	check("192.0.2.99", 60, "self.example.com.")
	check("2001:db8::6", 20, "six.example.com.")
	// Wildcards, a task's and a record's, are no host; a name that a deeper zone hides isn't
	// answered; an address of no name.
	check("192.168.1.50", 0)
	check("192.168.1.40", 0)
	check("192.168.1.77", 0)
	check("192.168.1.99", 0)
	check("fd00::99", 0)
	// An exact name under a wildcard is a host.
	check("192.168.1.41", 60, "exact.wild.home.arpa.")

	// It follows the task: the address it had goes upstream at once, though a moment ago it was
	// answered; the new one is answered; and one it shares with a record, with both names and the
	// shorter TTL.
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.11"), netip.MustParseAddr("fd00::11"), netip.MustParseAddr("192.168.1.21")})
	check("192.168.1.10", 0)
	check("fd00::10", 0)
	check("192.168.1.11", 30, "nas.home.arpa.")
	check("fd00::11", 30, "nas.home.arpa.")
	check("192.168.1.21", 30, "nas.home.arpa.", "printer.home.arpa.")
	// That an address has no name, the upstream server's answer, is kept; once a task has the
	// address, its name is answered all the same: the local names are before the cache.
	up.answerWith(func(req *dns.Msg) *dns.Msg {
		resp := zoned(30, 300, 300)(new(dns.Msg).SetQuestion("x.nx.test.", dns.TypeA))
		resp.SetRcode(req, dns.RcodeNameError)
		return resp
	})
	check("fd00::12", 0)
	before := up.queries.Load()
	query(t, s, "udp", reverseName4(t, "fd00::12"), dns.TypePTR, nil)
	if st := s.Status(); st.CacheEntries != 1 || up.queries.Load() != before {
		t.Errorf("%d answers kept, want the upstream server's, that fd00::12 has no name", st.CacheEntries)
	}
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("fd00::12")})
	check("fd00::12", 30, "nas.home.arpa.")
	up.answerWith(nil)

	// A PTR record written is answered as any record, and before the names of the address.
	resp := query(t, s, "udp", "7.2.0.192.in-addr.arpa.", dns.TypePTR, nil)
	if got := answers(resp); !slices.Equal(got, []string{"7.2.0.192.in-addr.arpa. PTR written.example.com."}) || resp.Authoritative {
		t.Errorf("a PTR record written: %v", resp)
	}
	// Of another type, a reverse name is as any other: forwarded.
	before = up.queries.Load()
	if resp := query(t, s, "udp", reverseName4(t, "192.168.1.20"), dns.TypeMX, nil); len(resp.Answer) != 0 || up.queries.Load() == before {
		t.Errorf("an MX of a reverse name: %v", resp)
	}
	if st := s.Status(); st.Queries[Local] == 0 || st.Queries[Forwarded] == 0 {
		t.Errorf("status: %+v", st)
	}
}

// A resolver answers the reverse of the names it answers itself, and no other's: two of one zone's
// name, each with its own.
func TestReverseSplitHorizon(t *testing.T) {
	up := newUpstream(t)
	lanConfig, lanAddresses := testConfig(t, up.address)
	labConfig, labAddresses := testConfig(t, up.address)
	labConfig.Name, labConfig.Path = "lab", "resolvers.lab"
	lan, lab := start(t, lanConfig), start(t, labConfig)
	lanAddresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.10")})
	labAddresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("10.0.0.10")})
	for _, c := range []struct {
		s       *Server
		address string
		local   bool
	}{{lan, "192.168.1.10", true}, {lan, "10.0.0.10", false}, {lab, "10.0.0.10", true}, {lab, "192.168.1.10", false}} {
		resp := query(t, c.s, "tcp", reverseName4(t, c.address), dns.TypePTR, nil)
		if got := answers(resp); c.local != (len(got) == 1 && strings.HasSuffix(got[0], " PTR nas.home.arpa.")) {
			t.Errorf("%s at %s: %v", c.address, c.s.config.Name, resp)
		}
	}
}
