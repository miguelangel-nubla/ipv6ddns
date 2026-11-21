package resolver

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/miekg/dns"
)

// A name a zone is given addresses for, that it didn't have when it was made, is a task's
// template's, of a host called so: it is answered while it has addresses. The names written, a
// task's and a record's, stay theirs; it comes before a wildcard above it; and a deeper zone's
// name isn't this zone's.
func TestGivenNames(t *testing.T) {
	up := newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
	s := start(t, cfg)
	a := func(addrs ...string) (out []netip.Addr) {
		for _, addr := range addrs {
			out = append(out, netip.MustParseAddr(addr))
		}
		return out
	}
	addresses.Set("laptop.home.arpa.", a("192.168.1.60", "192.168.1.61", "fd00::60"))
	addresses.Set("1.laptop.home.arpa.", a("192.168.1.60"))
	// Under a wildcard record, *.wild: the name given is its own.
	addresses.Set("given.wild.home.arpa.", a("192.168.1.62"))
	// A record's name, and a deeper zone's: not this one's to give.
	addresses.Set("printer.home.arpa.", a("192.168.1.63"))
	addresses.Set("pc.lab.home.arpa.", a("192.168.1.64"))
	addresses.Set("nas.home.arpa.", a("192.168.1.10"))

	for _, c := range []struct {
		name  string
		qtype uint16
		rcode int
		aa    bool
		want  []string
	}{
		{"laptop.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"laptop.home.arpa. A 192.168.1.60", "laptop.home.arpa. A 192.168.1.61"}},
		{"LAPTOP.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, true, []string{"LAPTOP.home.arpa. AAAA fd00::60"}},
		{"1.laptop.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"1.laptop.home.arpa. A 192.168.1.60"}},
		// Another type of a name it has: no data, not upstream's answer.
		{"1.laptop.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, true, nil},
		{"laptop.home.arpa.", dns.TypeTXT, dns.RcodeSuccess, true, nil},
		{"given.wild.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"given.wild.home.arpa. A 192.168.1.62"}},
		{"other.wild.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"other.wild.home.arpa. A 192.168.1.40"}},
		// The record's, both of them, and not the address given.
		{"printer.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"printer.home.arpa. A 192.168.1.20", "printer.home.arpa. A 192.168.1.21"}},
		{"nas.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"nas.home.arpa. A 192.168.1.10"}},
		// The deeper zone's name: that zone has no such name, and upstream is asked.
		{"pc.lab.home.arpa.", dns.TypeA, dns.RcodeSuccess, false, []string{"pc.lab.home.arpa. A 192.0.2.53"}},
		// A name never given: upstream's.
		{"2.laptop.home.arpa.", dns.TypeA, dns.RcodeSuccess, false, []string{"2.laptop.home.arpa. A 192.0.2.53"}},
	} {
		resp := query(t, s, "udp", c.name, c.qtype, nil)
		got := answers(resp)
		slices.Sort(got)
		if resp.Rcode != c.rcode || resp.Authoritative != c.aa || !slices.Equal(got, c.want) {
			t.Errorf("%s %s: rcode %s, aa %t, %v; want %v, aa %t", c.name, dns.TypeToString[c.qtype], dns.RcodeToString[resp.Rcode], resp.Authoritative, got, c.want, c.aa)
		}
		if c.want == nil && (len(resp.Ns) != 1 || resp.Ns[0].Header().Rrtype != dns.TypeSOA) {
			t.Errorf("%s %s: no data, without the zone's SOA: %v", c.name, dns.TypeToString[c.qtype], resp.Ns)
		}
	}

	// Its reverse: the names given that have the address, not the one a record has.
	ptr := func(addr string) []string {
		reverse, _ := dns.ReverseAddr(addr)
		var names []string
		for _, rr := range query(t, s, "udp", reverse, dns.TypePTR, nil).Answer {
			if p, ok := rr.(*dns.PTR); ok {
				names = append(names, p.Ptr)
			}
		}
		return names
	}
	if got := ptr("192.168.1.60"); !slices.Equal(got, []string{"1.laptop.home.arpa.", "laptop.home.arpa."}) {
		t.Errorf("the reverse of 192.168.1.60: %v", got)
	}
	if got := ptr("192.168.1.63"); len(got) != 0 {
		t.Errorf("the reverse of the address given to a record's name: %v", got)
	}
	if got := ptr("192.168.1.64"); len(got) != 0 {
		t.Errorf("the reverse of the address given to a deeper zone's name: %v", got)
	}

	// The host leaves: its names are upstream's again, at once.
	addresses.Set("laptop.home.arpa.", a("192.168.1.61"))
	addresses.Set("1.laptop.home.arpa.", nil)
	if got := answers(query(t, s, "udp", "laptop.home.arpa.", dns.TypeA, nil)); !slices.Equal(got, []string{"laptop.home.arpa. A 192.168.1.61"}) {
		t.Errorf("the name of both, one gone: %v", got)
	}
	if resp := query(t, s, "udp", "1.laptop.home.arpa.", dns.TypeA, nil); resp.Authoritative || !slices.Equal(answers(resp), []string{"1.laptop.home.arpa. A 192.0.2.53"}) {
		t.Errorf("the name of the host that left: %v", resp)
	}
	if got := ptr("192.168.1.60"); len(got) != 0 {
		t.Errorf("the reverse of the host that left: %v", got)
	}
}
