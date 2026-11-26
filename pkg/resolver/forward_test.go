package resolver

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// asker asks s a name, and tells which of the upstream servers were asked it.
func asker(t *testing.T, s *Server, ups ...*upstream) func(name string, qtype uint16) (*dns.Msg, []bool) {
	return func(name string, qtype uint16) (*dns.Msg, []bool) {
		t.Helper()
		before := make([]int64, len(ups))
		for i, u := range ups {
			before[i] = u.queries.Load()
		}
		resp := query(t, s, "udp", name, qtype, nil)
		asked := make([]bool, len(ups))
		for i, u := range ups {
			asked[i] = u.queries.Load() != before[i]
		}
		return resp, asked
	}
}

// A name of a domain forwarded, of those the resolver would ask upstream, is asked of the
// domain's servers, of the deepest domain that holds it; any other of the upstream servers. The
// names of its zones and its records are its own first: a zone's name it hasn't is forwarded, as
// MAAS's names of a zone the resolver has some of. The answers are kept, as the upstream's.
func TestForward(t *testing.T) {
	up, maas, deep := newUpstream(t), newUpstream(t), newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	cfg.Forwards = []Forward{
		{Domain: "home.arpa.", Upstreams: []string{maas.address}},
		{Domain: "deep.home.arpa.", Upstreams: []string{deep.address}},
		{Domain: "example.com.", Upstreams: []string{maas.address}},
	}
	cfg.Records = append(cfg.Records, mustRecords(t, "", "alias.example.org. CNAME node.deep.home.arpa.")...)
	s, _ := startCached(t, cfg, 100)
	ask := asker(t, s, up, maas, deep)
	for _, c := range []struct {
		name string
		// Which was asked: up, maas, deep; none, of the resolver's own.
		want int
	}{
		{"printer.home.arpa.", -1},
		{"files.home.arpa.", -1},
		{"self.example.com.", -1},
		{"printer.lab.home.arpa.", -1},
		{"missing.home.arpa.", 1},
		{"MISSING.Other.home.arpa.", 1},
		{"x.lab.home.arpa.", 1},
		{"deep.home.arpa.", 2},
		{"a.b.deep.home.arpa.", 2},
		{"nodeep.home.arpa.", 1},
		{"other.example.com.", 1},
		{"www.upstream.test.", 0},
		{"home.arpa.example.", 0},
	} {
		resp, asked := ask(c.name, dns.TypeA)
		for i, a := range asked {
			if a != (i == c.want) {
				t.Errorf("%s: asked %v, want only %d of up, maas, deep (-1: none)", c.name, asked, c.want)
				break
			}
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
			t.Errorf("%s: %s", c.name, resp)
		}
	}
	// A CNAME of its own to a name of its own is answered of its own, though under a domain
	// forwarded.
	if _, asked := ask("www.example.com.", dns.TypeA); asked[1] || asked[0] {
		t.Errorf("www.example.com., a CNAME to a task's name, asked %v", asked)
	}
	// A CNAME of its own to a name forwarded, not its own, is followed to the domain's servers.
	resp, asked := ask("alias.example.org.", dns.TypeA)
	if !asked[2] || asked[0] || asked[1] || len(resp.Answer) != 2 {
		t.Errorf("alias.example.org., a CNAME to node.deep.home.arpa.: %s, asked %v; want the CNAME and deep's answer, of deep alone", resp, asked)
	}

	// Kept: asked again, of none.
	if resp, asked := ask("missing.home.arpa.", dns.TypeA); asked[1] || len(resp.Answer) != 1 {
		t.Errorf("missing.home.arpa. again: asked %v, %s; want it of the cache", asked, resp)
	}
	if n := s.Status().Queries[Cached]; n != 1 {
		t.Errorf("cached %d, want 1", n)
	}
}

// A domain's server given by host name is found by the bootstrap servers, and asked; its addresses
// are the forward's in the status, not the upstream servers'.
func TestForwardByName(t *testing.T) {
	up, maas, b := newUpstream(t), newUpstream(t), newBootstrap(t)
	cfg, _ := testConfig(t, up.address)
	cfg.Bootstrap = []string{b.address}
	cfg.Forwards = []Forward{{Domain: "lan.example.", Upstreams: []string{named(t, maas)}}}
	s := start(t, cfg)
	ask := asker(t, s, up, maas)
	if resp, asked := ask("node.lan.example.", dns.TypeA); resp.Rcode != dns.RcodeSuccess || !asked[1] || asked[0] {
		t.Errorf("node.lan.example.: %s, asked %v; want of maas, by name", resp, asked)
	}
	status := s.Status()
	if len(status.Forwards) != 1 {
		t.Fatalf("forwards: %+v", status.Forwards)
	}
	if got := status.Forwards[0].UpstreamAddresses[named(t, maas)]; len(got) != 1 || got[0] != maas.address {
		t.Errorf("the forward's addresses %v, want [%s]", status.Forwards[0].UpstreamAddresses, maas.address)
	}
	if len(status.UpstreamAddresses) != 0 {
		t.Errorf("the upstream servers' addresses %v, want none: none is given by name", status.UpstreamAddresses)
	}
}

// A domain forwarded whose servers don't answer is SERVFAIL, of its servers' failures: the upstream
// servers aren't asked in their place.
func TestForwardFailures(t *testing.T) {
	up := newUpstream(t)
	dead := deadAddress(t)
	cfg, _ := testConfig(t, up.address)
	cfg.Forwards = []Forward{{Domain: "lan.example.", Upstreams: []string{dead}}}
	s := start(t, cfg)
	ask := asker(t, s, up)
	if resp, asked := ask("maas.lan.example.", dns.TypeA); resp.Rcode != dns.RcodeServerFailure || asked[0] {
		t.Errorf("%s, upstream asked %t; want SERVFAIL, of the forward's server alone", dns.RcodeToString[resp.Rcode], asked[0])
	}
	status := s.Status()
	if len(status.Forwards) != 1 {
		t.Fatalf("forwards: %+v", status.Forwards)
	}
	f := status.Forwards[0]
	if f.Domain != "lan.example" || len(f.Upstreams) != 1 || f.Upstreams[0] != dead || f.UpstreamFailures[dead] != 1 {
		t.Errorf("forward: %+v; want lan.example, of %s, failed once", f, dead)
	}
	if status.UpstreamFailures[up.address] != 0 || len(status.UpstreamFailures) != 1 {
		t.Errorf("upstream failures: %v; want of the upstream alone, none", status.UpstreamFailures)
	}
	if status.Queries[ServFail] != 1 {
		t.Errorf("servfail %d", status.Queries[ServFail])
	}
}

// A domain forwarded under a private network's reverse zone, as a network's that MAAS names, is
// asked of its servers, not answered as no such name; the rest of the private zone is still the
// resolver's own, and so is the reverse of an address it has a name of.
func TestForwardPrivateReverse(t *testing.T) {
	up, maas := newUpstream(t), newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
	cfg.Forwards = []Forward{{Domain: "3.2.10.in-addr.arpa.", Upstreams: []string{maas.address}}}
	s, _ := startCached(t, cfg, 0)
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("10.2.3.10")})
	ask := asker(t, s, up, maas)

	if _, asked := ask("204.3.2.10.in-addr.arpa.", dns.TypePTR); !asked[1] || asked[0] {
		t.Errorf("204.3.2.10.in-addr.arpa.: asked %v, want of maas", asked)
	}
	if _, asked := ask("3.2.10.in-addr.arpa.", dns.TypeSOA); !asked[1] || asked[0] {
		t.Errorf("3.2.10.in-addr.arpa. SOA: asked %v, want of maas", asked)
	}
	resp, asked := ask("10.3.2.10.in-addr.arpa.", dns.TypePTR)
	if asked[0] || asked[1] || len(resp.Answer) != 1 || !strings.HasSuffix(resp.Answer[0].String(), "nas.home.arpa.") {
		t.Errorf("10.3.2.10.in-addr.arpa.: %s, asked %v; want nas's, of its own", resp, asked)
	}
	resp, asked = ask("1.4.2.10.in-addr.arpa.", dns.TypePTR)
	if asked[0] || asked[1] || resp.Rcode != dns.RcodeNameError {
		t.Errorf("1.4.2.10.in-addr.arpa.: %s, asked %v; want no such name, of its own", dns.RcodeToString[resp.Rcode], asked)
	}
}

// A name of a block is blocked under a domain forwarded too: the block comes before.
func TestForwardBlocked(t *testing.T) {
	maas := newUpstream(t)
	up := newUpstream(t)
	cfg := blockConfig(t, up.address, BlockNXDomain)
	cfg.Forwards = []Forward{{Domain: "test.", Upstreams: []string{maas.address}}}
	s := start(t, cfg)
	ask := asker(t, s, up, maas)
	if resp, asked := ask("x.ads.test.", dns.TypeA); resp.Rcode != dns.RcodeNameError || asked[0] || asked[1] {
		t.Errorf("x.ads.test.: %s, asked %v; want blocked", dns.RcodeToString[resp.Rcode], asked)
	}
	if _, asked := ask("ok.ads.test.", dns.TypeA); asked[0] || !asked[1] {
		t.Errorf("ok.ads.test., of allow: asked %v; want of maas", asked)
	}
}

// New tells of a domain forwarded twice, of one that is none, and of one without servers.
func TestForwardErrors(t *testing.T) {
	for _, c := range []struct {
		forwards []Forward
		want     string
	}{
		{[]Forward{{Domain: "lan.example.", Upstreams: []string{"10.2.3.204:53"}}, {Domain: "LAN.example", Upstreams: []string{"10.2.3.205:53"}}},
			"resolvers.lan.forward[1].domain: lan.example is forwarded twice"},
		{[]Forward{{Domain: ".", Upstreams: []string{"10.2.3.204:53"}}}, `resolvers.lan.forward[0].domain: "." is not a domain`},
		{[]Forward{{Domain: "lan.example."}}, "resolvers.lan.forward[0].upstream is empty"},
		{[]Forward{{Domain: "lan.example.", Upstreams: []string{"maas.example:53"}}},
			`resolvers.lan.forward[0].upstream: "maas.example:53" is a host name, and there's no bootstrap to look it up`},
	} {
		cfg, _ := testConfig(t, "192.0.2.1:53")
		cfg.Forwards = c.forwards
		if _, err := New(cfg, nil); err == nil || err.Error() != c.want {
			t.Errorf("%+v: %v, want %s", c.forwards, err, c.want)
		}
	}
}
