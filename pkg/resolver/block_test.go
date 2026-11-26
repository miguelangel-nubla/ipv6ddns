package resolver

import (
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/blocklist"
)

// listOf is a blocklist of those lines.
func listOf(t *testing.T, lines ...string) Blocklist {
	t.Helper()
	p, err := blocklist.Parse(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return p.Set
}

// blockConfig is testConfig, of a block of two lists, which have names of its own too, and one of
// allow.
func blockConfig(t *testing.T, upstream, answer string) Config {
	cfg, _ := testConfig(t, upstream)
	cfg.Block = &Block{
		Lists: []string{"ads", "local"},
		Sets: []Blocklist{
			listOf(t, "ads.test", "upstream.test", "resolver.arpa"),
			listOf(t, "example.com", "home.arpa", "168.192.in-addr.arpa"),
		},
		Allow:  []string{"ok.ads.test."},
		Answer: answer,
		TTL:    30 * time.Second,
	}
	return cfg
}

// A name of a list, and below it, is NXDOMAIN, of an SOA of the TTL, and isn't asked upstream; a
// name of allow, and below it, is; the resolver's own names, its zones' and reverse names never
// are blocked, whatever the lists say; a CNAME of its own to a target blocked is the CNAME and
// NXDOMAIN.
func TestBlockNXDomain(t *testing.T) {
	up := newUpstream(t)
	s := start(t, blockConfig(t, up.address, BlockNXDomain))
	ask := func(name string, qtype uint16) (*dns.Msg, bool) {
		t.Helper()
		before := up.queries.Load()
		resp := query(t, s, "udp", name, qtype, nil)
		return resp, up.queries.Load() != before
	}
	for _, c := range []struct {
		name  string
		qtype uint16
	}{
		{"ads.test.", dns.TypeA},
		{"x.y.ADS.test.", dns.TypeAAAA},
		{"www.upstream.test.", dns.TypeTXT},
	} {
		resp, asked := ask(c.name, c.qtype)
		soa, ok := firstRR(resp.Ns).(*dns.SOA)
		if resp.Rcode != dns.RcodeNameError || asked || len(resp.Answer) != 0 || !ok || soa.Hdr.Ttl != 30 || soa.Minttl != 30 || soa.Hdr.Name != strings.ToLower(c.name) {
			t.Errorf("%s: %s, asked %t, authority %v; want NXDOMAIN of the resolver's, of an SOA of 30s", c.name, resp, asked, resp.Ns)
		}
	}
	for _, name := range []string{"ok.ads.test.", "a.ok.ads.test.", "other.test.", "ads.test.example.", "_dns.resolver.arpa."} {
		if resp, asked := ask(name, dns.TypeA); !asked || resp.Rcode != dns.RcodeSuccess {
			t.Errorf("%s: %s, asked %t; want forwarded", name, dns.RcodeToString[resp.Rcode], asked)
		}
	}
	for _, c := range []struct {
		name  string
		qtype uint16
		want  int
	}{
		{"self.example.com.", dns.TypeA, dns.RcodeSuccess},
		{"www.example.com.", dns.TypeA, dns.RcodeSuccess},
		{"printer.home.arpa.", dns.TypeA, dns.RcodeSuccess},
		{"99.1.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError},
	} {
		resp, asked := ask(c.name, c.qtype)
		if asked || resp.Rcode != c.want || !resp.Authoritative && c.name != "self.example.com." && c.name != "www.example.com." {
			t.Errorf("%s: %s, asked %t; want %s of its own", c.name, resp, asked, dns.RcodeToString[c.want])
		}
	}
	if got := s.Status().Queries[Blocked]; got != 3 {
		t.Errorf("%d blocked before the CNAMEs, want 3", got)
	}

	// A CNAME of the zone's, and of the resolver's records, to a target blocked.
	for _, name := range []string{"out.home.arpa.", "ext.example.com."} {
		resp, asked := ask(name, dns.TypeA)
		if want := []string{name + " CNAME www.upstream.test."}; resp.Rcode != dns.RcodeNameError || asked || !slices.Equal(answers(resp), want) {
			t.Errorf("%s: %s, asked %t; want the CNAME, and NXDOMAIN", name, resp, asked)
		}
	}
	status := s.Status()
	if got := status.Queries[Blocked]; got != 5 {
		t.Errorf("%d blocked, want 5", got)
	}
	if b := status.Block; b == nil || !slices.Equal(b.Lists, []string{"ads", "local"}) || !slices.Equal(b.Allow, []string{"ok.ads.test"}) || b.Answer != BlockNXDomain || b.TTL != 30 {
		t.Errorf("status %+v", status.Block)
	}
}

// Of null: 0.0.0.0 of A, :: of AAAA, and no data of another type, with the SOA.
func TestBlockNull(t *testing.T) {
	up := newUpstream(t)
	s := start(t, blockConfig(t, up.address, BlockNull))
	for _, c := range []struct {
		name  string
		qtype uint16
		want  []string
	}{
		{"ads.test.", dns.TypeA, []string{"ads.test. A 0.0.0.0"}},
		{"x.ads.test.", dns.TypeAAAA, []string{"x.ads.test. AAAA ::"}},
		{"ads.test.", dns.TypeTXT, nil},
		{"out.home.arpa.", dns.TypeAAAA, []string{"out.home.arpa. CNAME www.upstream.test.", "www.upstream.test. AAAA ::"}},
	} {
		resp := query(t, s, "udp", c.name, c.qtype, nil)
		if resp.Rcode != dns.RcodeSuccess || !slices.Equal(answers(resp), c.want) {
			t.Errorf("%s %s: %s; want %q", c.name, dns.TypeToString[c.qtype], resp, c.want)
		}
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype != dns.TypeCNAME && rr.Header().Ttl != 30 {
				t.Errorf("%s: TTL %d, want 30", c.name, rr.Header().Ttl)
			}
		}
		if c.want == nil {
			if _, ok := firstRR(resp.Ns).(*dns.SOA); !ok {
				t.Errorf("%s: no data, of no SOA", c.name)
			}
		}
	}
	if got := s.Status().Queries[Blocked]; got != 4 {
		t.Errorf("%d blocked, want 4", got)
	}
}

// A list that changes, as one downloaded again, is blocked as it is now; one of no names yet blocks
// nothing.
func TestBlockListChanges(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	list := &swapped{}
	cfg.Block = &Block{Lists: []string{"ads"}, Sets: []Blocklist{list}, Answer: BlockNXDomain}
	s := start(t, cfg)
	if resp := query(t, s, "udp", "ads.test.", dns.TypeA, nil); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("of a list of no names yet: %s", dns.RcodeToString[resp.Rcode])
	}
	list.set.Store(listOf(t, "ads.test").(*blocklist.Set))
	resp := query(t, s, "udp", "ads.test.", dns.TypeA, nil)
	if resp.Rcode != dns.RcodeNameError {
		t.Errorf("of the list given: %s", dns.RcodeToString[resp.Rcode])
	}
	if soa, ok := firstRR(resp.Ns).(*dns.SOA); !ok || soa.Hdr.Ttl != uint32(DefaultBlockTTL.Seconds()) {
		t.Errorf("the authority %v, want an SOA of the default TTL", resp.Ns)
	}
}

func TestBlockCheck(t *testing.T) {
	cfg, _ := testConfig(t, "127.0.0.1:53")
	cfg.Block = &Block{Lists: []string{"ads"}}
	if _, err := New(cfg, nil); err == nil {
		t.Error("a list without its names was taken")
	}
	cfg.Block = &Block{Lists: []string{"ads"}, Sets: []Blocklist{listOf(t, "a.test")}, Answer: "refused"}
	if _, err := New(cfg, nil); err == nil || !strings.Contains(err.Error(), "resolvers.lan.block.answer") {
		t.Errorf("error %v", err)
	}
}

// swapped is a list whose names are replaced, as a download replaces them.
type swapped struct {
	set atomic.Pointer[blocklist.Set]
}

func (s *swapped) Match(name string) (string, bool) { return s.set.Load().Match(name) }
