package resolver

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeGrant is a grant of the tests': its records in memory, and each Apply noted.
type fakeGrant struct {
	kind  string
	zone  string
	names []string
	types []uint16

	mutex    sync.Mutex
	records  map[string][]dns.RR
	applied  []map[string][]dns.RR
	applyErr error
	scopeErr error
}

func newFakeGrant(zone string, names []string, types ...uint16) *fakeGrant {
	return &fakeGrant{kind: "fake", zone: zone, names: names, types: types, records: make(map[string][]dns.RR)}
}

func (g *fakeGrant) Kind() string { return g.kind }
func (g *fakeGrant) Scope() (string, []string, error) {
	return g.zone, g.names, g.scopeErr
}
func (g *fakeGrant) Types() []uint16 { return g.types }
func (g *fakeGrant) Records(name string) []dns.RR {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return slices.Clone(g.records[name])
}
func (g *fakeGrant) Apply(changes map[string][]dns.RR) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if g.applyErr != nil {
		return g.applyErr
	}
	g.applied = append(g.applied, changes)
	for name, rrs := range changes {
		g.records[name] = rrs
	}
	return nil
}

// has is the records of name, as "TYPE data", sorted.
func (g *fakeGrant) has(name string) []string {
	var out []string
	for _, rr := range g.Records(name) {
		h := rr.Header()
		out = append(out, dns.TypeToString[h.Rrtype]+" "+strings.TrimPrefix(rr.String(), h.String()))
	}
	slices.Sort(out)
	return out
}

func (g *fakeGrant) applies() int {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	return len(g.applied)
}

// testSecret is a key's secret, of 32 bytes, as tsig-keygen makes for hmac-sha256.
var testSecret = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// updateConfig is testConfig with the key nas, of hmac-sha256, of the grants given.
func updateConfig(t *testing.T, grants ...Grant) Config {
	cfg, _ := testConfig(t)
	cfg.UpdateKeys = []UpdateKey{{Name: "nas", Secret: testSecret, Algorithm: dns.HmacSHA256, Grants: grants}}
	return cfg
}

// signedExchange sends m signed with the key, of its algorithm and secret, at time signed, and
// returns the response, and the error of its signature.
func signedExchange(t *testing.T, s *Server, network string, m *dns.Msg, key, algorithm, secret string, signed time.Time) (*dns.Msg, error) {
	t.Helper()
	m.SetTsig(dns.Fqdn(key), algorithm, 300, signed.Unix())
	c := &dns.Client{Net: network, Timeout: 3 * time.Second, TsigSecret: map[string]string{dns.Fqdn(key): secret}}
	resp, _, err := c.Exchange(m, s.Addresses()[0])
	if resp == nil {
		t.Fatalf("no response: %v", err)
	}
	return resp, err
}

// send is a message signed with the key nas, over UDP, whose response must be signed right too.
func send(t *testing.T, s *Server, m *dns.Msg) *dns.Msg {
	t.Helper()
	resp, err := signedExchange(t, s, "udp", m, "nas", dns.HmacSHA256, testSecret, time.Now())
	if err != nil {
		t.Fatalf("the response's signature: %v: %v", err, resp)
	}
	return resp
}

func rr(t *testing.T, line string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(line)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func updateOf(zone string) *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(zone))
	return m
}

// tsigError is the error of the response's TSIG record: 0 for none.
func tsigError(resp *dns.Msg) uint16 {
	if t := resp.IsTsig(); t != nil {
		return t.Error
	}
	return 0
}

func TestUpdateSignatures(t *testing.T) {
	g := newFakeGrant("example.com.", []string{"_acme-challenge.nas.example.com."}, dns.TypeTXT)
	s := start(t, updateConfig(t, g))
	add := func() *dns.Msg {
		m := updateOf("example.com")
		m.Insert([]dns.RR{rr(t, `_acme-challenge.nas.example.com. 60 IN TXT "a"`)})
		return m
	}

	for _, network := range []string{"udp", "tcp"} {
		resp, err := signedExchange(t, s, network, add(), "nas", dns.HmacSHA256, testSecret, time.Now())
		if err != nil || resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("over %s: %s, %v", network, dns.RcodeToString[resp.Rcode], err)
		}
	}
	if got := g.has("_acme-challenge.nas.example.com."); !slices.Equal(got, []string{`TXT "a"`}) {
		t.Fatalf("the records: %v", got)
	}

	other := base64.StdEncoding.EncodeToString([]byte("another secret, of 32 bytes ...."))
	for _, c := range []struct {
		what                   string
		key, algorithm, secret string
		at                     time.Time
		want                   uint16
	}{
		{"a key it doesn't know", "other", dns.HmacSHA256, testSecret, time.Now(), dns.RcodeBadKey},
		{"another algorithm", "nas", dns.HmacSHA512, testSecret, time.Now(), dns.RcodeBadKey},
		{"a wrong secret", "nas", dns.HmacSHA256, other, time.Now(), dns.RcodeBadSig},
		{"an hour ago", "nas", dns.HmacSHA256, testSecret, time.Now().Add(-time.Hour), dns.RcodeBadTime},
		{"in an hour", "nas", dns.HmacSHA256, testSecret, time.Now().Add(time.Hour), dns.RcodeBadTime},
	} {
		resp, _ := signedExchange(t, s, "udp", add(), c.key, c.algorithm, c.secret, c.at)
		if resp.Rcode != dns.RcodeNotAuth || tsigError(resp) != c.want {
			t.Errorf("%s: %s, TSIG error %d, want NOTAUTH, %d", c.what, dns.RcodeToString[resp.Rcode], tsigError(resp), c.want)
		}
		// BADTIME is signed, with the server's time, as RFC 8945 has it; the others, unsigned.
		sig := resp.IsTsig()
		switch {
		case sig == nil:
			t.Errorf("%s: no TSIG error said", c.what)
		case c.want == dns.RcodeBadTime && (sig.MAC == "" || sig.OtherLen != 6):
			t.Errorf("%s: BADTIME must be signed, with the time: %v", c.what, sig)
		case c.want != dns.RcodeBadTime && sig.MAC != "":
			t.Errorf("%s: the response must say the TSIG error, unsigned: %v", c.what, sig)
		}
	}

	// Unsigned: refused, and nothing changed.
	m := add()
	m.Insert([]dns.RR{rr(t, `_acme-challenge.nas.example.com. 60 IN TXT "unsigned"`)})
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, s.Addresses()[0])
	if err != nil || resp.Rcode != dns.RcodeRefused {
		t.Errorf("unsigned: %v, %v", resp, err)
	}
	if got := g.has("_acme-challenge.nas.example.com."); !slices.Equal(got, []string{`TXT "a"`}) {
		t.Errorf("after the refused: %v", got)
	}
	if n := g.applies(); n != 1 {
		t.Errorf("applied %d times, want once: the second add changed nothing", n)
	}
}

func TestUpdateAllow(t *testing.T) {
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	elsewhere := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for _, c := range []struct {
		what                      string
		resolver, updates, keyNet []netip.Prefix
		want                      int
	}{
		{"the resolver's, by default", nil, nil, nil, dns.RcodeSuccess},
		{"the resolver's, elsewhere", elsewhere, nil, nil, dns.RcodeRefused},
		{"the updates' over the resolver's", elsewhere, loopback, nil, dns.RcodeSuccess},
		{"the updates', elsewhere", loopback, elsewhere, nil, dns.RcodeRefused},
		{"the key's over the updates'", loopback, elsewhere, loopback, dns.RcodeSuccess},
		{"the key's, elsewhere", loopback, loopback, elsewhere, dns.RcodeRefused},
	} {
		t.Run(c.what, func(t *testing.T) {
			g := newFakeGrant("example.com.", []string{"vps.example.com."}, dns.TypeA)
			cfg := updateConfig(t, g)
			cfg.Allow, cfg.UpdateAllow, cfg.UpdateKeys[0].Allow = c.resolver, c.updates, c.keyNet
			s := start(t, cfg)
			m := updateOf("example.com")
			m.Insert([]dns.RR{rr(t, "vps.example.com. 60 IN A 192.0.2.7")})
			if resp := send(t, s, m); resp.Rcode != c.want {
				t.Errorf("%s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[c.want])
			}
		})
	}
}

func TestUpdateChanges(t *testing.T) {
	name := "_acme-challenge.apps.example.com."
	g := newFakeGrant("example.com.", []string{name, "_acme-challenge.nas.example.com."}, dns.TypeTXT)
	s := start(t, updateConfig(t, g))
	step := func(what string, change func(m *dns.Msg), rcode int, want ...string) {
		t.Helper()
		m := updateOf("example.com")
		change(m)
		if resp := send(t, s, m); resp.Rcode != rcode {
			t.Errorf("%s: %s, want %s", what, dns.RcodeToString[resp.Rcode], dns.RcodeToString[rcode])
		}
		if got := g.has(name); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", what, got, want)
		}
	}
	txt := func(v string) dns.RR { return rr(t, name+` 60 IN TXT "`+v+`"`) }

	// A certificate for apps and *.apps: two values at once, one removed as the other stays.
	step("added", func(m *dns.Msg) { m.Insert([]dns.RR{txt("apps")}) }, dns.RcodeSuccess, `TXT "apps"`)
	step("another beside", func(m *dns.Msg) { m.Insert([]dns.RR{txt("wildcard")}) }, dns.RcodeSuccess, `TXT "apps"`, `TXT "wildcard"`)
	step("the same again", func(m *dns.Msg) { m.Insert([]dns.RR{txt("apps")}) }, dns.RcodeSuccess, `TXT "apps"`, `TXT "wildcard"`)
	step("one removed", func(m *dns.Msg) { m.Remove([]dns.RR{txt("apps")}) }, dns.RcodeSuccess, `TXT "wildcard"`)
	step("one removed that isn't there", func(m *dns.Msg) { m.Remove([]dns.RR{txt("apps")}) }, dns.RcodeSuccess, `TXT "wildcard"`)
	step("two in one", func(m *dns.Msg) { m.Insert([]dns.RR{txt("b"), txt("c")}) }, dns.RcodeSuccess, `TXT "b"`, `TXT "c"`, `TXT "wildcard"`)
	step("the set removed", func(m *dns.Msg) { m.RemoveRRset([]dns.RR{txt("")}) }, dns.RcodeSuccess)
	step("again", func(m *dns.Msg) { m.Insert([]dns.RR{txt("d")}) }, dns.RcodeSuccess, `TXT "d"`)
	step("the name removed", func(m *dns.Msg) { m.RemoveName([]dns.RR{txt("")}) }, dns.RcodeSuccess)
	step("removed and added in one", func(m *dns.Msg) {
		m.Insert([]dns.RR{txt("old")})
		m.RemoveRRset([]dns.RR{txt("")})
		m.Insert([]dns.RR{txt("new")})
	}, dns.RcodeSuccess, `TXT "new"`)

	// What Apply was given: every record of each name changed, and only those names.
	g.mutex.Lock()
	last := g.applied[len(g.applied)-1]
	g.mutex.Unlock()
	if len(last) != 1 || len(last[name]) != 1 {
		t.Errorf("the last apply: %v", last)
	}

	// Refused, and nothing changed.
	step("of another zone", func(m *dns.Msg) {
		m.SetUpdate("example.net.")
		m.Insert([]dns.RR{rr(t, `_acme-challenge.nas.example.net. 60 IN TXT "x"`)})
	}, dns.RcodeRefused, `TXT "new"`)
	step("a name out of the zone", func(m *dns.Msg) {
		m.Insert([]dns.RR{rr(t, `_acme-challenge.nas.example.net. 60 IN TXT "x"`)})
	}, dns.RcodeNotZone, `TXT "new"`)
	step("a name out of its scope", func(m *dns.Msg) {
		m.Insert([]dns.RR{rr(t, `_acme-challenge.www.example.com. 60 IN TXT "x"`)})
	}, dns.RcodeRefused, `TXT "new"`)
	step("a type out of its scope", func(m *dns.Msg) {
		m.Insert([]dns.RR{rr(t, name+` 60 IN A 192.0.2.1`)})
	}, dns.RcodeRefused, `TXT "new"`)
	step("one of two out of its scope: none applied", func(m *dns.Msg) {
		m.Insert([]dns.RR{txt("in"), rr(t, `www.example.com. 60 IN A 192.0.2.1`)})
	}, dns.RcodeRefused, `TXT "new"`)
	step("the zone section isn't a zone", func(m *dns.Msg) {
		m.Question[0].Qtype = dns.TypeA
		m.Insert([]dns.RR{txt("x")})
	}, dns.RcodeFormatError, `TXT "new"`)
	step("a deletion with a TTL", func(m *dns.Msg) {
		d := txt("new")
		d.Header().Class = dns.ClassNONE
		m.Ns = append(m.Ns, d)
	}, dns.RcodeFormatError, `TXT "new"`)
	step("a zone above the grant's", func(m *dns.Msg) {
		m.SetUpdate("com.")
		m.Insert([]dns.RR{txt("x")})
	}, dns.RcodeRefused, `TXT "new"`)

	// A zone below the grant's, as a client that thinks the name its own zone: taken.
	step("a zone below the grant's", func(m *dns.Msg) {
		m.SetUpdate(name)
		m.Insert([]dns.RR{txt("below")})
	}, dns.RcodeSuccess, `TXT "below"`, `TXT "new"`)

	// The grant fails: SERVFAIL, and its records as they were.
	g.mutex.Lock()
	g.applyErr = errors.New("the provider is down")
	g.mutex.Unlock()
	step("failed", func(m *dns.Msg) { m.Insert([]dns.RR{txt("lost")}) }, dns.RcodeServerFailure, `TXT "below"`, `TXT "new"`)
	g.mutex.Lock()
	g.applyErr, g.scopeErr = nil, errors.New("the zone can't be found")
	g.mutex.Unlock()
	step("its scope can't be read", func(m *dns.Msg) { m.Insert([]dns.RR{txt("lost")}) }, dns.RcodeServerFailure, `TXT "below"`, `TXT "new"`)
}

// Two grants: an update goes to the first that holds all of it.
func TestUpdateGrants(t *testing.T) {
	challenges := newFakeGrant("example.com.", []string{"_acme-challenge.vps.example.com."}, dns.TypeTXT)
	addresses := newFakeGrant("example.com.", []string{"vps.example.com."}, dns.TypeA, dns.TypeAAAA)
	s := start(t, updateConfig(t, challenges, addresses))
	m := updateOf("example.com")
	m.Insert([]dns.RR{rr(t, "vps.example.com. 60 IN A 192.0.2.7")})
	if resp := send(t, s, m); resp.Rcode != dns.RcodeSuccess {
		t.Fatal(dns.RcodeToString[resp.Rcode])
	}
	m = updateOf("example.com")
	m.Insert([]dns.RR{rr(t, `_acme-challenge.vps.example.com. 60 IN TXT "x"`)})
	if resp := send(t, s, m); resp.Rcode != dns.RcodeSuccess {
		t.Fatal(dns.RcodeToString[resp.Rcode])
	}
	if challenges.applies() != 1 || addresses.applies() != 1 {
		t.Errorf("applied: challenges %d, addresses %d", challenges.applies(), addresses.applies())
	}
	// Both in one message: of no one grant, refused.
	m = updateOf("example.com")
	m.Insert([]dns.RR{rr(t, "vps.example.com. 60 IN A 192.0.2.8"), rr(t, `_acme-challenge.vps.example.com. 60 IN TXT "y"`)})
	if resp := send(t, s, m); resp.Rcode != dns.RcodeRefused {
		t.Error(dns.RcodeToString[resp.Rcode])
	}
}

// The prerequisites, each holding and not, and the conflict resolution of RFC 4703, as Kea's
// DHCP-DDNS sends it.
func TestUpdatePrerequisites(t *testing.T) {
	g := newFakeGrant("lan.example.com.", nil, dns.TypeA, dns.TypeAAAA, dns.TypeDHCID)
	s := start(t, updateConfig(t, g))
	name := "printer.lan.example.com."
	a := func(ip string) dns.RR { return rr(t, name+" 1200 IN A "+ip) }
	dhcid := func(v string) dns.RR { return rr(t, name+" 1200 IN DHCID "+v) }
	ours, theirs := "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=", "AAEBOSD+XR3Os/0LozeXVqcNc7FwCfQdWL3b/NaiUDlW2No="
	step := func(what string, change func(m *dns.Msg), rcode int, want ...string) {
		t.Helper()
		m := updateOf("lan.example.com")
		change(m)
		if resp := send(t, s, m); resp.Rcode != rcode {
			t.Errorf("%s: %s, want %s", what, dns.RcodeToString[resp.Rcode], dns.RcodeToString[rcode])
		}
		if got := g.has(name); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", what, got, want)
		}
	}

	// The lease: the name is free, so it is added with its DHCID.
	step("added, the name free", func(m *dns.Msg) {
		m.NameNotUsed([]dns.RR{a("0.0.0.0")})
		m.Insert([]dns.RR{a("192.168.1.20"), dhcid(ours)})
	}, dns.RcodeSuccess, "A 192.168.1.20", "DHCID "+ours)
	step("again: the name is in use", func(m *dns.Msg) {
		m.NameNotUsed([]dns.RR{a("0.0.0.0")})
		m.Insert([]dns.RR{a("192.168.1.21")})
	}, dns.RcodeYXDomain, "A 192.168.1.20", "DHCID "+ours)
	// Its DHCID proves it the client's: the address moves.
	step("moved, the DHCID ours", func(m *dns.Msg) {
		m.Used([]dns.RR{dhcid(ours)})
		m.RemoveRRset([]dns.RR{a("0.0.0.0")})
		m.Insert([]dns.RR{a("192.168.1.21")})
	}, dns.RcodeSuccess, "A 192.168.1.21", "DHCID "+ours)
	// Another client's DHCID: the name stays the first's.
	step("another client", func(m *dns.Msg) {
		m.Used([]dns.RR{dhcid(theirs)})
		m.RemoveRRset([]dns.RR{a("0.0.0.0")})
		m.Insert([]dns.RR{a("192.168.1.99")})
	}, dns.RcodeNXRrset, "A 192.168.1.21", "DHCID "+ours)
	// The lease ends: the address, then the DHCID once no address is left.
	step("released", func(m *dns.Msg) {
		m.Used([]dns.RR{dhcid(ours)})
		m.Remove([]dns.RR{a("192.168.1.21")})
	}, dns.RcodeSuccess, "DHCID "+ours)
	step("its DHCID, no address left", func(m *dns.Msg) {
		m.RRsetNotUsed([]dns.RR{a("0.0.0.0"), rr(t, name+" 0 IN AAAA ::")})
		m.Remove([]dns.RR{dhcid(ours)})
	}, dns.RcodeSuccess)

	// Each prerequisite, holding and not.
	step("set up", func(m *dns.Msg) { m.Insert([]dns.RR{a("192.168.1.30")}) }, dns.RcodeSuccess, "A 192.168.1.30")
	for _, c := range []struct {
		what   string
		prereq func(m *dns.Msg)
		rcode  int
	}{
		{"in use, it is", func(m *dns.Msg) { m.NameUsed([]dns.RR{a("0.0.0.0")}) }, dns.RcodeSuccess},
		{"in use, another isn't", func(m *dns.Msg) { m.NameUsed([]dns.RR{rr(t, "other.lan.example.com. 0 IN A 0.0.0.0")}) }, dns.RcodeNameError},
		{"not in use, it is", func(m *dns.Msg) { m.NameNotUsed([]dns.RR{a("0.0.0.0")}) }, dns.RcodeYXDomain},
		{"has A records, it has", func(m *dns.Msg) { m.RRsetUsed([]dns.RR{a("0.0.0.0")}) }, dns.RcodeSuccess},
		{"has AAAA records, it hasn't", func(m *dns.Msg) { m.RRsetUsed([]dns.RR{rr(t, name+" 0 IN AAAA ::")}) }, dns.RcodeNXRrset},
		{"has no AAAA records, it hasn't", func(m *dns.Msg) { m.RRsetNotUsed([]dns.RR{rr(t, name+" 0 IN AAAA ::")}) }, dns.RcodeSuccess},
		{"has no A records, it has", func(m *dns.Msg) { m.RRsetNotUsed([]dns.RR{a("0.0.0.0")}) }, dns.RcodeYXRrset},
		{"has exactly that A, it has", func(m *dns.Msg) { m.Used([]dns.RR{a("192.168.1.30")}) }, dns.RcodeSuccess},
		{"has exactly those two, it has one", func(m *dns.Msg) { m.Used([]dns.RR{a("192.168.1.30"), a("192.168.1.31")}) }, dns.RcodeNXRrset},
		{"has exactly another, it hasn't", func(m *dns.Msg) { m.Used([]dns.RR{a("192.168.1.31")}) }, dns.RcodeNXRrset},
		{"with a TTL", func(m *dns.Msg) {
			m.RRsetUsed([]dns.RR{a("0.0.0.0")})
			m.Answer[len(m.Answer)-1].Header().Ttl = 60
		}, dns.RcodeFormatError},
	} {
		step(c.what, func(m *dns.Msg) {
			c.prereq(m)
			m.Insert([]dns.RR{rr(t, name+" 60 IN AAAA 2001:db8::30")})
		}, c.rcode, append([]string{"A 192.168.1.30"}, map[bool][]string{true: {"AAAA 2001:db8::30"}}[c.rcode == dns.RcodeSuccess]...)...)
		step("undone", func(m *dns.Msg) { m.RemoveRRset([]dns.RR{rr(t, name+" 0 IN AAAA ::")}) }, dns.RcodeSuccess, "A 192.168.1.30")
	}
}

// A query signed with a key is answered with authority, from its grant, of the names of its
// scope alone: the same query unsigned, or of another key, is any client's.
func TestSignedQueries(t *testing.T) {
	g := newFakeGrant("home.arpa.", []string{"_acme-challenge.nas.home.arpa."}, dns.TypeTXT)
	g.records["_acme-challenge.nas.home.arpa."] = []dns.RR{rr(t, `_acme-challenge.nas.home.arpa. 60 IN TXT "token"`)}
	cfg := updateConfig(t, g)
	other := newFakeGrant("home.arpa.", []string{"_acme-challenge.www.home.arpa."}, dns.TypeTXT)
	cfg.UpdateKeys = append(cfg.UpdateKeys, UpdateKey{Name: "www", Secret: testSecret, Algorithm: dns.HmacSHA256, Grants: []Grant{other}})
	s := start(t, cfg)
	signed := func(key, name string, qtype uint16) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		resp, err := signedExchange(t, s, "udp", m, key, dns.HmacSHA256, testSecret, time.Now())
		if err != nil {
			t.Fatalf("%s %s: the response's signature: %v", name, dns.TypeToString[qtype], err)
		}
		return resp
	}
	soaOwner := func(rrs []dns.RR) string {
		for _, r := range rrs {
			if soa, ok := r.(*dns.SOA); ok {
				return soa.Hdr.Name
			}
		}
		return ""
	}

	// The zone apex: its SOA, with authority, as certbot finds the zone.
	resp := signed("nas", "home.arpa.", dns.TypeSOA)
	if !resp.Authoritative || soaOwner(resp.Answer) != "home.arpa." {
		t.Errorf("the apex: %v", resp)
	}
	// The names between: no data, with the SOA in the authority section, as nsupdate finds it.
	for _, name := range []string{"nas.home.arpa.", "_acme-challenge.nas.home.arpa."} {
		resp := signed("nas", name, dns.TypeSOA)
		if !resp.Authoritative || len(resp.Answer) != 0 || soaOwner(resp.Ns) != "home.arpa." || resp.Rcode != dns.RcodeSuccess {
			t.Errorf("%s: %v", name, resp)
		}
	}
	// The challenge's record, as the grant has it.
	if resp := signed("nas", "_acme-challenge.nas.home.arpa.", dns.TypeTXT); !slices.Equal(answers(resp), []string{`_acme-challenge.nas.home.arpa. TXT "token"`}) {
		t.Errorf("the TXT: %v", answers(resp))
	}

	// Outside its scope, of the resolver's own zone: as any client is answered.
	resp = signed("nas", "printer.home.arpa.", dns.TypeA)
	if got := answers(resp); !slices.Equal(got, []string{"printer.home.arpa. A 192.168.1.20", "printer.home.arpa. A 192.168.1.21"}) {
		t.Errorf("printer, signed: %v", got)
	}
	// The same names unsigned, and of another key: the resolver's answers, not the grant's.
	for _, c := range []struct {
		what string
		resp *dns.Msg
	}{
		{"unsigned", query(t, s, "udp", "_acme-challenge.nas.home.arpa.", dns.TypeTXT, nil)},
		{"of another key", signed("www", "_acme-challenge.nas.home.arpa.", dns.TypeTXT)},
	} {
		// The resolver has no upstream here: the name is asked of none, and fails. What matters
		// is that the grant's record isn't what it answers.
		if len(c.resp.Answer) != 0 {
			t.Errorf("%s: %v", c.what, c.resp)
		}
	}
}

// An update, or a signed query, where signatures aren't checked, as over DNS over HTTPS: refused.
func TestSignedOverEncryptedRefused(t *testing.T) {
	s := start(t, updateConfig(t, newFakeGrant("example.com.", nil, dns.TypeA)))
	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	m := updateOf("example.com")
	m.Insert([]dns.RR{rr(t, "vps.example.com. 60 IN A 192.0.2.7")})
	m.SetTsig("nas.", dns.HmacSHA256, 300, time.Now().Unix())
	if resp := s.respond(m, remote); resp.Rcode != dns.RcodeRefused {
		t.Errorf("an update: %s", dns.RcodeToString[resp.Rcode])
	}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeSOA)
	q.SetTsig("nas.", dns.HmacSHA256, 300, time.Now().Unix())
	if resp := s.respond(q, remote); resp.Rcode != dns.RcodeRefused {
		t.Errorf("a signed query: %s", dns.RcodeToString[resp.Rcode])
	}
}

// Without keys, an update is refused unread, as miekg/dns does: not implemented.
func TestUpdateWithoutKeys(t *testing.T) {
	cfg, _ := testConfig(t)
	s := start(t, cfg)
	m := updateOf("home.arpa")
	m.Insert([]dns.RR{rr(t, "nas.home.arpa. 60 IN A 192.0.2.7")})
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, s.Addresses()[0])
	if err != nil || resp.Rcode != dns.RcodeNotImplemented {
		t.Errorf("%v, %v", resp, err)
	}
}

// An update past the bounds of its sections is refused unread.
func TestUpdateTooBig(t *testing.T) {
	g := newFakeGrant("example.com.", nil, dns.TypeTXT)
	s := start(t, updateConfig(t, g))
	m := updateOf("example.com")
	for i := range maxUpdates + 1 {
		m.Insert([]dns.RR{rr(t, fmt.Sprintf(`n%d.example.com. 60 IN TXT "x"`, i))})
	}
	resp, _ := signedExchange(t, s, "tcp", m, "nas", dns.HmacSHA256, testSecret, time.Now())
	if resp.Rcode != dns.RcodeFormatError || g.applies() != 0 {
		t.Errorf("%s, applied %d", dns.RcodeToString[resp.Rcode], g.applies())
	}
}

// Updates of one name at once, each adding a value: all kept, none lost to another.
func TestUpdatesConcurrent(t *testing.T) {
	name := "_acme-challenge.apps.example.com."
	g := newFakeGrant("example.com.", []string{name}, dns.TypeTXT)
	s := start(t, updateConfig(t, g))
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := updateOf("example.com")
			m.Insert([]dns.RR{rr(t, fmt.Sprintf(`%s 60 IN TXT "v%d"`, name, i))})
			resp, err := signedExchange(t, s, "tcp", m, "nas", dns.HmacSHA256, testSecret, time.Now())
			if err != nil || resp.Rcode != dns.RcodeSuccess {
				t.Errorf("%d: %v, %v", i, resp.Rcode, err)
			}
		}()
	}
	wg.Wait()
	if got := g.has(name); len(got) != 20 {
		t.Errorf("%d values, want 20: %v", len(got), got)
	}
}

func TestUpdateStatus(t *testing.T) {
	g := newFakeGrant("example.com.", []string{"vps.example.com."}, dns.TypeA)
	var logged []string
	var mutex sync.Mutex
	cfg := updateConfig(t, g)
	cfg.Infof = func(f string, a ...any) {
		mutex.Lock()
		logged = append(logged, "info: "+fmt.Sprintf(f, a...))
		mutex.Unlock()
	}
	cfg.Warnf = func(f string, a ...any) {
		mutex.Lock()
		logged = append(logged, "warn: "+fmt.Sprintf(f, a...))
		mutex.Unlock()
	}
	s := start(t, cfg)
	m := updateOf("example.com")
	m.Insert([]dns.RR{rr(t, "vps.example.com. 60 IN A 192.0.2.7")})
	send(t, s, m)
	m = updateOf("example.com")
	m.Insert([]dns.RR{rr(t, "www.example.com. 60 IN A 192.0.2.7")})
	send(t, s, m)

	st := s.Status().Keys
	if len(st) != 1 || st[0].Name != "nas" || !slices.Equal(st[0].Permissions, []string{"fake"}) ||
		st[0].Updates[UpdateApplied] != 1 || st[0].Updates[UpdateRefused] != 1 || st[0].LastResult != UpdateRefused ||
		st[0].LastMessage != "www.example.com A is outside its permissions" || st[0].Last == nil {
		t.Errorf("%+v", st)
	}
	mutex.Lock()
	defer mutex.Unlock()
	want := []string{
		"info: resolver lan: key nas: updated fake: vps.example.com",
		"warn: resolver lan: key nas: update refused: www.example.com A is outside its permissions",
	}
	if !slices.Equal(logged, want) {
		t.Errorf("logged %q", logged)
	}
}

func TestUpdateKeysChecked(t *testing.T) {
	g := newFakeGrant("example.com.", nil, dns.TypeA)
	for _, c := range []struct {
		key  UpdateKey
		want string
	}{
		{UpdateKey{Name: "nas", Secret: testSecret, Algorithm: dns.HmacSHA1, Grants: []Grant{g}}, "resolvers.lan.updates.keys.nas: the algorithm hmac-sha1. isn't one of hmac-sha256, hmac-sha384 and hmac-sha512"},
		{UpdateKey{Name: "nas", Secret: "not base64!", Algorithm: dns.HmacSHA256, Grants: []Grant{g}}, "resolvers.lan.updates.keys.nas.secret is not base64, as tsig-keygen writes it"},
		{UpdateKey{Name: "nas", Secret: testSecret, Algorithm: dns.HmacSHA256}, "resolvers.lan.updates.keys.nas has no permissions"},
		{UpdateKey{Name: "a b", Secret: testSecret, Algorithm: dns.HmacSHA256, Grants: []Grant{g}}, `resolvers.lan.updates.keys: "a b" is not a name a TSIG key can have`},
	} {
		cfg, _ := testConfig(t)
		cfg.UpdateKeys = []UpdateKey{c.key}
		if _, err := New(cfg, nil); err == nil || err.Error() != c.want {
			t.Errorf("%+v: %v, want %s", c.key, err, c.want)
		}
	}
	cfg, _ := testConfig(t)
	k := UpdateKey{Name: "nas", Secret: testSecret, Algorithm: dns.HmacSHA256, Grants: []Grant{g}}
	cfg.UpdateKeys = []UpdateKey{k, k}
	if _, err := New(cfg, nil); err == nil || err.Error() != "resolvers.lan.updates.keys: nas is there twice" {
		t.Error(err)
	}
}

// Any update, read from bytes, applied straight: the server never fails, and the grant's
// records stay of its scope.
func FuzzUpdate(f *testing.F) {
	seed := func(change func(m *dns.Msg)) {
		m := updateOf("example.com")
		change(m)
		if b, err := m.Pack(); err == nil {
			f.Add(b)
		}
	}
	txt, _ := dns.NewRR(`_acme-challenge.nas.example.com. 60 IN TXT "x"`)
	seed(func(m *dns.Msg) { m.Insert([]dns.RR{txt}) })
	seed(func(m *dns.Msg) { m.Remove([]dns.RR{txt}) })
	seed(func(m *dns.Msg) { m.RemoveRRset([]dns.RR{txt}) })
	seed(func(m *dns.Msg) { m.RemoveName([]dns.RR{txt}) })
	seed(func(m *dns.Msg) { m.NameNotUsed([]dns.RR{txt}); m.Insert([]dns.RR{txt}) })
	seed(func(m *dns.Msg) { m.Used([]dns.RR{txt}); m.RRsetNotUsed([]dns.RR{txt}) })
	f.Fuzz(func(t *testing.T, data []byte) {
		m := new(dns.Msg)
		if m.Unpack(data) != nil {
			return
		}
		g := newFakeGrant("example.com.", []string{"_acme-challenge.nas.example.com."}, dns.TypeTXT)
		cfg, _ := testConfig(t)
		cfg.UpdateKeys = []UpdateKey{{Name: "nas", Secret: testSecret, Algorithm: dns.HmacSHA256, Grants: []Grant{g}}}
		s, err := New(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp := s.update(m, s.keys["nas."])
		if resp == nil || resp.Id != m.Id {
			t.Fatalf("no response of the update: %v", resp)
		}
		for name, rrs := range g.records {
			if name != "_acme-challenge.nas.example.com." && len(rrs) > 0 {
				t.Fatalf("a record out of the scope: %s", name)
			}
			for _, r := range rrs {
				if r.Header().Rrtype != dns.TypeTXT || r.Header().Class != dns.ClassINET {
					t.Fatalf("a record out of the scope: %s", r)
				}
			}
		}
	})
}

// Signatures refused, of a client no allow has: refused unsaid, and never logged; of one an allow
// has, logged once a minute, however many it sends.
func TestUpdateRefusedSignaturesLogged(t *testing.T) {
	var mutex sync.Mutex
	var warned []string
	for _, c := range []struct {
		what  string
		allow []netip.Prefix
		rcode int
		warns int
	}{
		{"of no allow", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, dns.RcodeRefused, 0},
		{"of the resolver's allow", nil, dns.RcodeNotAuth, 1},
	} {
		t.Run(c.what, func(t *testing.T) {
			warned = nil
			cfg := updateConfig(t, newFakeGrant("example.com.", nil, dns.TypeA))
			cfg.Allow, cfg.UpdateKeys[0].Allow = c.allow, c.allow
			cfg.Warnf = func(f string, a ...any) { mutex.Lock(); warned = append(warned, fmt.Sprintf(f, a...)); mutex.Unlock() }
			s := start(t, cfg)
			for range 3 {
				m := updateOf("example.com")
				m.Insert([]dns.RR{rr(t, "vps.example.com. 60 IN A 192.0.2.7")})
				resp, _ := signedExchange(t, s, "udp", m, "intruder", dns.HmacSHA256, testSecret, time.Now())
				if resp.Rcode != c.rcode {
					t.Errorf("%s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[c.rcode])
				}
			}
			mutex.Lock()
			defer mutex.Unlock()
			if len(warned) != c.warns {
				t.Errorf("warned %q, want %d", warned, c.warns)
			}
		})
	}
}

// A signed answer over UDP fits its size with its signature, of the longest key names and
// algorithm: truncated, never larger.
func TestSignedAnswerFits(t *testing.T) {
	long := strings.Repeat("k", 60) + "." + strings.Repeat("e", 60) + "." + strings.Repeat("y", 60)
	name := "_acme-challenge.nas.example.com."
	g := newFakeGrant("example.com.", []string{name}, dns.TypeTXT)
	for i := range 40 {
		g.records[name] = append(g.records[name], rr(t, fmt.Sprintf(`%s 60 IN TXT "value number %d, long enough"`, name, i)))
	}
	cfg, _ := testConfig(t)
	cfg.UpdateKeys = []UpdateKey{{Name: long, Secret: testSecret, Algorithm: dns.HmacSHA512, Grants: []Grant{g}}}
	s := start(t, cfg)
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	resp, err := signedExchange(t, s, "udp", m, long, dns.HmacSHA512, testSecret, time.Now())
	if err != nil {
		t.Fatalf("the signature: %v", err)
	}
	// The client read it into 512 bytes; and so it measures, compressed as it was sent.
	resp.Compress = true
	if !resp.Truncated || resp.Len() > dns.MinMsgSize {
		t.Errorf("truncated %v, %d bytes, of %d at most", resp.Truncated, resp.Len(), dns.MinMsgSize)
	}
}

// A signed query of a name between a permission and its zone, of another type than SOA, is the
// world's: forwarded, as any client's.
func TestSignedQueryBetweenIsForwarded(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	g := newFakeGrant("example.com.", []string{"_acme-challenge.shop.example.com."}, dns.TypeTXT)
	cfg.UpdateKeys = []UpdateKey{{Name: "nas", Secret: testSecret, Algorithm: dns.HmacSHA256, Grants: []Grant{g}}}
	s := start(t, cfg)
	m := new(dns.Msg)
	m.SetQuestion("shop.example.com.", dns.TypeA)
	resp := send(t, s, m)
	if a, ok := firstA(resp); !ok || a != "192.0.2.53" {
		t.Errorf("shop, signed: %v", resp)
	}
	m = new(dns.Msg)
	m.SetQuestion("shop.example.com.", dns.TypeSOA)
	if resp := send(t, s, m); !resp.Authoritative || len(resp.Answer) != 0 || len(resp.Ns) != 1 {
		t.Errorf("shop's SOA, signed: %v", resp)
	}
}

// firstA is the first A record's address of resp.
func firstA(resp *dns.Msg) (string, bool) {
	for _, r := range resp.Answer {
		if a, ok := r.(*dns.A); ok {
			return a.A.String(), true
		}
	}
	return "", false
}

// holdingGrant is a fake grant that holds the names one label below its zone alone, and no
// wildcard.
type holdingGrant struct{ *fakeGrant }

func (g holdingGrant) Holds(name string) bool {
	label, ok := strings.CutSuffix(name, "."+g.zone)
	return ok && label != "*" && !strings.Contains(label, ".")
}

func TestUpdateGrantHolds(t *testing.T) {
	g := holdingGrant{newFakeGrant("lan.example.com.", nil, dns.TypeA)}
	s := start(t, updateConfig(t, g))
	for _, c := range []struct {
		name  string
		rcode int
	}{
		{"printer.lan.example.com.", dns.RcodeSuccess},
		{"*.lan.example.com.", dns.RcodeRefused},
		{"a.b.lan.example.com.", dns.RcodeRefused},
	} {
		m := updateOf("lan.example.com")
		m.Insert([]dns.RR{rr(t, c.name+" 60 IN A 192.0.2.7")})
		if resp := send(t, s, m); resp.Rcode != c.rcode {
			t.Errorf("%s: %s, want %s", c.name, dns.RcodeToString[resp.Rcode], dns.RcodeToString[c.rcode])
		}
	}
}

// limitedGrant is a fake grant whose updates are limited, as a provider's writes.
type limitedGrant struct{ *fakeGrant }

func (limitedGrant) Limited() bool { return true }

// A key's updates of a limited grant: updateLimit at once, refused past them, and allowed again as
// the minute goes, logged once; those of another grant, not limited.
func TestUpdateLimit(t *testing.T) {
	name := "_acme-challenge.nas.example.com."
	g := limitedGrant{newFakeGrant("example.com.", []string{name}, dns.TypeTXT)}
	free := newFakeGrant("example.com.", []string{"vps.example.com."}, dns.TypeA)
	cfg := updateConfig(t, g, free)
	var warned []string
	var mutex sync.Mutex
	cfg.Warnf = func(f string, a ...any) { mutex.Lock(); warned = append(warned, fmt.Sprintf(f, a...)); mutex.Unlock() }
	now := time.Now()
	var clock sync.Mutex
	s := startWith(t, cfg, func(s *Server) {
		s.now = func() time.Time { clock.Lock(); defer clock.Unlock(); return now }
	})
	challenge := func(i int) int {
		m := updateOf("example.com")
		m.Insert([]dns.RR{rr(t, fmt.Sprintf(`%s 60 IN TXT "v%d"`, name, i))})
		// Signed of the real time: the server's clock is the test's, for the limit alone.
		resp, err := signedExchange(t, s, "tcp", m, "nas", dns.HmacSHA256, testSecret, time.Now())
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		return resp.Rcode
	}
	for i := range updateLimit {
		if rcode := challenge(i); rcode != dns.RcodeSuccess {
			t.Fatalf("update %d of %d: %s", i+1, updateLimit, dns.RcodeToString[rcode])
		}
	}
	for i := range 3 {
		if rcode := challenge(100 + i); rcode != dns.RcodeRefused {
			t.Errorf("past the limit: %s", dns.RcodeToString[rcode])
		}
	}
	// Another grant's, of the same key: not limited.
	m := updateOf("example.com")
	m.Insert([]dns.RR{rr(t, "vps.example.com. 60 IN A 192.0.2.7")})
	if resp := send(t, s, m); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("an update not limited: %s", dns.RcodeToString[resp.Rcode])
	}
	// Two seconds on, two more.
	clock.Lock()
	now = now.Add(2 * time.Second)
	clock.Unlock()
	for i := range 2 {
		if rcode := challenge(200 + i); rcode != dns.RcodeSuccess {
			t.Errorf("after two seconds, %d: %s", i+1, dns.RcodeToString[rcode])
		}
	}
	if rcode := challenge(300); rcode != dns.RcodeRefused {
		t.Errorf("then past it again: %s", dns.RcodeToString[rcode])
	}
	if st := s.Status().Keys[0]; st.Updates[UpdateRefused] != 4 {
		t.Errorf("refused %d, want 4", st.Updates[UpdateRefused])
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(warned) != 1 || !strings.Contains(warned[0], "more than 60 updates of fake a minute") {
		t.Errorf("warned %q, want once", warned)
	}
}
