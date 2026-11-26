package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

func mustRecords(t testing.TB, origin string, lines ...string) []dns.RR {
	t.Helper()
	var records []dns.RR
	for _, line := range lines {
		rr, err := ParseRecord(line, origin, DefaultTTL)
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		records = append(records, rr)
	}
	return records
}

func TestParseRecord(t *testing.T) {
	for _, c := range []struct{ line, origin, want string }{
		{"printer A 192.168.1.20", "home.arpa", "printer.home.arpa.\t60\tIN\tA\t192.168.1.20"},
		{"Printer 30 IN AAAA fd00::20", "home.arpa.", "printer.home.arpa.\t30\tIN\tAAAA\tfd00::20"},
		{"@ MX 10 mail", "home.arpa", "home.arpa.\t60\tIN\tMX\t10 mail.home.arpa."},
		{"files.home.arpa. CNAME nas", "home.arpa", "files.home.arpa.\t60\tIN\tCNAME\tnas.home.arpa."},
		{`txt TXT "a, b" "c"`, "home.arpa", "txt.home.arpa.\t60\tIN\tTXT\t\"a, b\" \"c\""},
		{"www.example.com. CNAME nas.home.arpa.", "", "www.example.com.\t60\tIN\tCNAME\tnas.home.arpa."},
	} {
		rr, err := ParseRecord(c.line, c.origin, DefaultTTL)
		if err != nil || rr.String() != c.want {
			t.Errorf("%q: got %v, %v, want %q", c.line, rr, err, c.want)
		}
	}
	for _, c := range []struct{ line, origin, want string }{
		{"www CNAME nas.home.arpa.", "", "the name www must be absolute, ending in a dot, as www.: these records belong to no zone"},
		{"www.example.com. CNAME nas", "", `bad CNAME Target: "nas": every name in these records must be absolute, ending in a dot`},
		{"printer A 192.168.1.300", "home.arpa", `bad A A: "192.168.1.300"`},
		{"printer A", "home.arpa", "a A record with no data"},
		{"printer CH A 1.2.3.4", "home.arpa", "class CH isn't supported: only IN"},
		{"@ SOA a b 1 2 3 4 5", "home.arpa", "SOA records aren't allowed: the resolver makes its zones' own"},
		{"$TTL 5", "home.arpa", "zone file directives aren't records: give only the records"},
		{"a A 1.1.1.1\nb A 2.2.2.2", "home.arpa", "more than one line: give each record as its own entry"},
		{"", "home.arpa", "empty record: give a name, a type and its data, as printer A 192.168.1.20"},
	} {
		if _, err := ParseRecord(c.line, c.origin, DefaultTTL); err == nil || err.Error() != c.want {
			t.Errorf("%q: got %v, want %s", c.line, err, c.want)
		}
	}
	if got := Name("NAS", "Home.Arpa."); got != "nas.home.arpa." {
		t.Error(got)
	}
	if got := Name("", "home.arpa"); got != "home.arpa." {
		t.Error(got)
	}
	if got := Name("nas.home.arpa.", "home.arpa"); got != "nas.home.arpa." {
		t.Error(got)
	}
}

// upstream is a DNS server of the test's, on 127.0.0.1: it answers every A query with 192.0.2.53
// and a TXT of what it was asked, unless told to be slow, or to truncate over UDP; and of long TXT
// records, told to, of an answer past 8 KB, as a name's signed with ML-DSA-44.
type upstream struct {
	address  string
	queries  atomic.Int64
	slow     atomic.Bool
	truncate atomic.Bool
	long     atomic.Bool
	// The last query, as received.
	mutex sync.Mutex
	last  *dns.Msg
	// The answer to a query, in place of the usual, when it gives one.
	handle func(req *dns.Msg) *dns.Msg
}

// answerWith makes handle the upstream's answers.
func (u *upstream) answerWith(handle func(req *dns.Msg) *dns.Msg) {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	u.handle = handle
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	pc, l := listenBoth(t)
	u.address = pc.LocalAddr().String()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		u.queries.Add(1)
		u.mutex.Lock()
		u.last = req.Copy()
		handle := u.handle
		u.mutex.Unlock()
		if u.slow.Load() {
			time.Sleep(time.Second)
		}
		if handle != nil {
			if resp := handle(req); resp != nil {
				w.WriteMsg(resp)
				return
			}
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		_, overUDP := w.RemoteAddr().(*net.UDPAddr)
		if u.truncate.Load() && overUDP {
			resp.Truncated = true
			w.WriteMsg(resp)
			return
		}
		q := req.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.53")})
		case dns.TypeTXT:
			// Many, so that over UDP without EDNS they don't fit.
			for i := range 40 {
				text := fmt.Sprintf("upstream record %02d", i)
				if u.long.Load() {
					text += " " + strings.Repeat("x", 200)
				}
				resp.Answer = append(resp.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 30}, Txt: []string{text}})
			}
		default:
			resp.Rcode = dns.RcodeNameError
		}
		if opt := req.IsEdns0(); opt != nil {
			resp.SetEdns0(opt.UDPSize(), opt.Do())
		}
		w.WriteMsg(resp)
	})
	servers := []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: l, Handler: handler}}
	for _, s := range servers {
		go s.ActivateAndServe()
	}
	t.Cleanup(func() {
		for _, s := range servers {
			s.Shutdown()
		}
	})
	return u
}

// listenBoth listens on a port of 127.0.0.1 that is free over UDP and over TCP: the one the system
// gives for UDP can be taken over TCP, as by a connection of a test before that has just closed,
// and then another is asked.
func listenBoth(t testing.TB) (net.PacketConn, net.Listener) {
	t.Helper()
	for try := 0; ; try++ {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp4", pc.LocalAddr().String())
		if err == nil {
			return pc, l
		}
		pc.Close()
		if try == 50 {
			t.Fatal(err)
		}
	}
}

func (u *upstream) lastQuery() *dns.Msg {
	u.mutex.Lock()
	defer u.mutex.Unlock()
	return u.last
}

// deadAddress is a UDP address nothing answers at: a server that is down.
func deadAddress(t testing.TB) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := pc.LocalAddr().String()
	pc.Close()
	return a
}

// testConfig is a resolver on 127.0.0.1, at a port of its own, with zones home.arpa, with the
// task names nas and *.dev, and lab.home.arpa, and records of its own.
func testConfig(t testing.TB, upstreams ...string) (Config, *Addresses) {
	addresses := NewAddresses()
	return Config{
		Name:      "lan",
		Path:      "resolvers.lan",
		Listen:    []listen.Entry{{Host: "127.0.0.1", Port: "0"}},
		Upstreams: upstreams,
		Records: mustRecords(t, "",
			"www.example.com. CNAME nas.home.arpa.",
			"ext.example.com. CNAME www.upstream.test.",
			"self.example.com. A 192.0.2.99"),
		Zones: []Zone{{
			Credential: "home", Name: "home.arpa.", TTL: 30 * time.Second, Addresses: addresses,
			Tasks: map[string]string{"nas.home.arpa.": "nas", "*.dev.home.arpa.": "dev", "empty.home.arpa.": "empty"},
			Records: mustRecords(t, "home.arpa",
				"printer A 192.168.1.20",
				"printer A 192.168.1.21",
				"printer TXT \"color\"",
				"files CNAME nas",
				"chain CNAME files",
				"out CNAME www.upstream.test.",
				"_ipp._tcp SRV 0 0 631 printer",
				"*.wild A 192.168.1.40",
				"exact.wild A 192.168.1.41",
				"deep.ent.wild TXT \"x\""),
		}, {
			Credential: "lab", Name: "lab.home.arpa.", TTL: time.Minute,
			Records: mustRecords(t, "lab.home.arpa", "printer A 10.0.0.20"),
		}},
	}, addresses
}

func start(t *testing.T, cfg Config) *Server {
	t.Helper()
	return startWith(t, cfg, nil)
}

// startWith is start, of a server that prepare changes before it listens: its clock, its roots.
func startWith(t *testing.T, cfg Config, prepare func(*Server)) *Server {
	t.Helper()
	var s *Server
	// The port of the test's, any free one over UDP, can be another server's over TCP, of the
	// tests that run: then another.
	for try := 0; ; try++ {
		var err error
		if s, err = New(cfg, t.Errorf); err != nil {
			t.Fatal(err)
		}
		s.timeout = 300 * time.Millisecond
		if prepare != nil {
			prepare(s)
		}
		if err = s.Start(); err == nil {
			break
		}
		if try == 5 || !strings.Contains(err.Error(), "address already in use") {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	return s
}

func query(t *testing.T, s *Server, network, name string, qtype uint16, edns func(*dns.Msg)) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	if edns != nil {
		edns(m)
	}
	c := &dns.Client{Net: network, Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, s.Addresses()[0])
	if err != nil {
		t.Fatalf("%s %s over %s: %v", name, dns.TypeToString[qtype], network, err)
	}
	if resp.Id != m.Id {
		t.Errorf("%s: the id %d, not the query's %d", name, resp.Id, m.Id)
	}
	return resp
}

// answers are the data of the answer section, each as "name type data".
func answers(resp *dns.Msg) []string {
	var out []string
	for _, rr := range resp.Answer {
		h := rr.Header()
		out = append(out, h.Name+" "+dns.TypeToString[h.Rrtype]+" "+strings.TrimPrefix(rr.String(), h.String()))
	}
	return out
}

func TestAnswers(t *testing.T) {
	up := newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
	s := start(t, cfg)
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("fd00::10")})
	addresses.Set("*.dev.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.50")})

	for _, c := range []struct {
		name          string
		qtype         uint16
		rcode         int
		authoritative bool
		want          []string
		// A NODATA's SOA, in authority.
		soa string
		// Whether the upstream server was asked.
		upstream bool
	}{
		{"nas.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"nas.home.arpa. A 192.168.1.10"}, "", false},
		{"NAS.Home.Arpa.", dns.TypeAAAA, dns.RcodeSuccess, true, []string{"NAS.Home.Arpa. AAAA fd00::10"}, "", false},
		// Of no task with an address yet, and a type a name doesn't have.
		{"empty.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, nil, "home.arpa.", false},
		{"nas.home.arpa.", dns.TypeMX, dns.RcodeSuccess, true, nil, "home.arpa.", false},
		{"printer.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, true, nil, "home.arpa.", false},
		// Several records of a name and type, together.
		{"printer.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"printer.home.arpa. A 192.168.1.20", "printer.home.arpa. A 192.168.1.21"}, "", false},
		{"printer.home.arpa.", dns.TypeTXT, dns.RcodeSuccess, true, []string{`printer.home.arpa. TXT "color"`}, "", false},
		{"_ipp._tcp.home.arpa.", dns.TypeSRV, dns.RcodeSuccess, true, []string{"_ipp._tcp.home.arpa. SRV 0 0 631 printer.home.arpa."}, "", false},
		// The longest zone: lab.home.arpa's printer, not home.arpa's.
		{"printer.lab.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"printer.lab.home.arpa. A 10.0.0.20"}, "", false},
		{"printer.lab.home.arpa.", dns.TypeTXT, dns.RcodeSuccess, true, nil, "lab.home.arpa.", false},
		// Wildcards: of a task, and of records, for what has nothing more specific.
		{"anything.dev.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"anything.dev.home.arpa. A 192.168.1.50"}, "", false},
		{"a.b.dev.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"a.b.dev.home.arpa. A 192.168.1.50"}, "", false},
		{"other.wild.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"other.wild.home.arpa. A 192.168.1.40"}, "", false},
		{"exact.wild.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"exact.wild.home.arpa. A 192.168.1.41"}, "", false},
		// Under a name that exists, with no data of its own: no wildcard, as in DNS.
		{"x.ent.wild.home.arpa.", dns.TypeA, dns.RcodeSuccess, false, []string{"x.ent.wild.home.arpa. A 192.0.2.53"}, "", true},
		// CNAMEs, followed among the local names, and to the upstream server past them.
		{"files.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"files.home.arpa. CNAME nas.home.arpa.", "nas.home.arpa. A 192.168.1.10"}, "", false},
		{"chain.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, true, []string{"chain.home.arpa. CNAME files.home.arpa.", "files.home.arpa. CNAME nas.home.arpa.", "nas.home.arpa. AAAA fd00::10"}, "", false},
		{"files.home.arpa.", dns.TypeCNAME, dns.RcodeSuccess, true, []string{"files.home.arpa. CNAME nas.home.arpa."}, "", false},
		{"files.home.arpa.", dns.TypeMX, dns.RcodeSuccess, true, []string{"files.home.arpa. CNAME nas.home.arpa."}, "home.arpa.", false},
		{"out.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, []string{"out.home.arpa. CNAME www.upstream.test.", "www.upstream.test. A 192.0.2.53"}, "", true},
		// The resolver's own, not authoritative, and its CNAME into a zone.
		{"self.example.com.", dns.TypeA, dns.RcodeSuccess, false, []string{"self.example.com. A 192.0.2.99"}, "", false},
		{"www.example.com.", dns.TypeA, dns.RcodeSuccess, false, []string{"www.example.com. CNAME nas.home.arpa.", "nas.home.arpa. A 192.168.1.10"}, "", false},
		{"ext.example.com.", dns.TypeA, dns.RcodeSuccess, false, []string{"ext.example.com. CNAME www.upstream.test.", "www.upstream.test. A 192.0.2.53"}, "", true},
		// Not the zone's, though in it, and outside every zone: forwarded, and relayed.
		{"tv.home.arpa.", dns.TypeA, dns.RcodeSuccess, false, []string{"tv.home.arpa. A 192.0.2.53"}, "", true},
		{"example.org.", dns.TypeA, dns.RcodeSuccess, false, []string{"example.org. A 192.0.2.53"}, "", true},
		{"example.org.", dns.TypeMX, dns.RcodeNameError, false, nil, "", true},
	} {
		before := up.queries.Load()
		for _, network := range []string{"udp", "tcp"} {
			resp := query(t, s, network, c.name, c.qtype, nil)
			what := fmt.Sprintf("%s %s over %s", c.name, dns.TypeToString[c.qtype], network)
			// The upstream server's answers are relayed as they are: its own sets no RA.
			if resp.Rcode != c.rcode || resp.Authoritative != c.authoritative || resp.RecursionAvailable == (c.upstream && len(c.want) < 2) {
				t.Errorf("%s: rcode %s, aa %t, ra %t", what, dns.RcodeToString[resp.Rcode], resp.Authoritative, resp.RecursionAvailable)
			}
			if got := answers(resp); !slices.Equal(got, c.want) {
				t.Errorf("%s: got %q, want %q", what, got, c.want)
			}
			if c.soa != "" {
				if len(resp.Ns) != 1 || resp.Ns[0].Header().Name != c.soa || resp.Ns[0].Header().Ttl != uint32(NegativeTTL.Seconds()) {
					t.Errorf("%s: the authority %v, want the SOA of %s", what, resp.Ns, c.soa)
				} else if soa := resp.Ns[0].(*dns.SOA); soa.Minttl != uint32(NegativeTTL.Seconds()) {
					t.Errorf("%s: the SOA's minimum %d", what, soa.Minttl)
				}
			}
			if c.qtype == dns.TypeA && c.name == "nas.home.arpa." && resp.Answer[0].Header().Ttl != 30 {
				t.Errorf("%s: the zone's TTL, 30s: %d", what, resp.Answer[0].Header().Ttl)
			}
		}
		if asked := up.queries.Load() > before; asked != c.upstream {
			t.Errorf("%s: the upstream server asked: %t", c.name, asked)
		}
	}

	// The provider's updates, at once: a new address, and none.
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.11")})
	if got := answers(query(t, s, "udp", "nas.home.arpa.", dns.TypeA, nil)); !slices.Equal(got, []string{"nas.home.arpa. A 192.168.1.11"}) {
		t.Errorf("after the change: %q", got)
	}
	addresses.Set("nas.home.arpa.", nil)
	if resp := query(t, s, "udp", "nas.home.arpa.", dns.TypeA, nil); len(resp.Answer) != 0 || resp.Rcode != dns.RcodeSuccess || len(resp.Ns) != 1 {
		t.Errorf("after the host left: %v", resp)
	}

	st := s.Status()
	if !st.Serving || st.Queries[Local] == 0 || st.Queries[NoData] == 0 || st.Queries[Forwarded] == 0 || st.Queries[Refused] != 0 {
		t.Errorf("status: %+v", st)
	}
	// Allow is, by default, the network of 127.0.0.1.
	if !slices.Contains(st.Allow, "127.0.0.0/8") || !slices.Equal(st.Zones, []string{"home.arpa", "lab.home.arpa"}) {
		t.Errorf("status: %+v", st)
	}
}

// The client's EDNS goes upstream as it is: its size and its DO bit; and a local answer has EDNS
// when the query has, with the DO bit, and its records unsigned.
func TestEDNS(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	s := start(t, cfg)

	resp := query(t, s, "udp", "example.org.", dns.TypeA, func(m *dns.Msg) { m.SetEdns0(3000, true) })
	last := up.lastQuery()
	if opt := last.IsEdns0(); opt == nil || opt.UDPSize() != 3000 || !opt.Do() {
		t.Errorf("upstream got %v", last)
	}
	if opt := resp.IsEdns0(); opt == nil || !opt.Do() {
		t.Errorf("the relayed answer: %v", resp)
	}
	resp = query(t, s, "udp", "example.org.", dns.TypeA, nil)
	if up.lastQuery().IsEdns0() != nil || resp.IsEdns0() != nil {
		t.Errorf("without EDNS: upstream got %v, the client %v", up.lastQuery(), resp)
	}

	resp = query(t, s, "udp", "printer.home.arpa.", dns.TypeA, func(m *dns.Msg) { m.SetEdns0(1400, true) })
	if opt := resp.IsEdns0(); opt == nil || !opt.Do() || opt.UDPSize() != ednsSize {
		t.Errorf("local, with EDNS: %v", resp)
	}
	resp = query(t, s, "udp", "printer.home.arpa.", dns.TypeA, nil)
	if resp.IsEdns0() != nil {
		t.Errorf("local, without EDNS: %v", resp)
	}
}

// An answer that doesn't fit the client's UDP size has TC set, and comes whole over TCP: a local
// one, and one the upstream server sent over TCP after a truncated one over UDP.
func TestTruncation(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	var lines []string
	for i := range 40 {
		lines = append(lines, fmt.Sprintf(`big TXT "local record %02d, long enough to fill a message soon"`, i))
	}
	cfg.Zones[0].Records = append(cfg.Zones[0].Records, mustRecords(t, "home.arpa", lines...)...)
	s := start(t, cfg)

	for _, name := range []string{"big.home.arpa.", "big.example.org."} {
		resp := query(t, s, "udp", name, dns.TypeTXT, nil)
		if !resp.Truncated || len(resp.Answer) >= 40 {
			t.Errorf("%s over UDP: truncated %t, %d records", name, resp.Truncated, len(resp.Answer))
		}
		// As sent: compressed.
		resp.Compress = true
		if resp.Len() > dns.MinMsgSize {
			t.Errorf("%s over UDP: %d bytes", name, resp.Len())
		}
		resp = query(t, s, "udp", name, dns.TypeTXT, func(m *dns.Msg) { m.SetEdns0(4096, false) })
		if resp.Truncated && len(resp.Answer) == 40 {
			t.Errorf("%s over UDP of 4096: truncated", name)
		}
		resp = query(t, s, "tcp", name, dns.TypeTXT, nil)
		if resp.Truncated || len(resp.Answer) != 40 {
			t.Errorf("%s over TCP: truncated %t, %d records", name, resp.Truncated, len(resp.Answer))
		}
		// An EDNS size smaller than what the upstream server sends over UDP anyway: it is read
		// whole, and comes whole over TCP.
		resp = query(t, s, "tcp", name, dns.TypeTXT, func(m *dns.Msg) { m.SetEdns0(600, false) })
		if resp.Truncated || len(resp.Answer) != 40 {
			t.Errorf("%s over TCP: truncated %t, %d records", name, resp.Truncated, len(resp.Answer))
		}
	}

	// Upstream truncates over UDP: asked again over TCP.
	up.truncate.Store(true)
	resp := query(t, s, "tcp", "example.org.", dns.TypeA, nil)
	if got := answers(resp); resp.Truncated || !slices.Equal(got, []string{"example.org. A 192.0.2.53"}) {
		t.Errorf("after a truncated upstream answer: %v", resp)
	}
	resp = query(t, s, "udp", "out.home.arpa.", dns.TypeA, nil)
	if got := answers(resp); !slices.Equal(got, []string{"out.home.arpa. CNAME www.upstream.test.", "www.upstream.test. A 192.0.2.53"}) {
		t.Errorf("a CNAME's target, after a truncated upstream answer: %q", got)
	}
}

// The upstream servers are asked in order, the next when one doesn't answer in time; none
// answering is SERVFAIL. Each failure counts.
func TestUpstreamFailover(t *testing.T) {
	slow, good := newUpstream(t), newUpstream(t)
	slow.slow.Store(true)
	dead := deadAddress(t)
	cfg, _ := testConfig(t, dead, slow.address, good.address)
	s := start(t, cfg)

	resp := query(t, s, "udp", "example.org.", dns.TypeA, nil)
	if got := answers(resp); resp.Rcode != dns.RcodeSuccess || !slices.Equal(got, []string{"example.org. A 192.0.2.53"}) || good.queries.Load() != 1 {
		t.Errorf("past two failing: %v", resp)
	}
	st := s.Status()
	if st.UpstreamFailures[dead] != 1 || st.UpstreamFailures[slow.address] != 1 || st.UpstreamFailures[good.address] != 0 {
		t.Errorf("failures: %v", st.UpstreamFailures)
	}

	cfg, _ = testConfig(t, dead, slow.address)
	s = start(t, cfg)
	for _, name := range []string{"example.org.", "out.home.arpa."} {
		resp := query(t, s, "udp", name, dns.TypeA, nil)
		if resp.Rcode != dns.RcodeServerFailure || len(resp.Answer) != 0 {
			t.Errorf("%s, none answering: %v", name, resp)
		}
	}
	if st := s.Status(); st.Queries[ServFail] != 2 || st.UpstreamFailures[dead] != 2 {
		t.Errorf("status: %+v", st)
	}
}

// A client outside allow is refused: of a local name too, and nothing goes upstream.
func TestRefused(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	cfg.Allow = []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd00::/64")}
	s := start(t, cfg)
	for _, name := range []string{"printer.home.arpa.", "example.org."} {
		for _, network := range []string{"udp", "tcp"} {
			if resp := query(t, s, network, name, dns.TypeA, nil); resp.Rcode != dns.RcodeRefused || len(resp.Answer) != 0 {
				t.Errorf("%s over %s: %v", name, network, resp)
			}
		}
	}
	if up.queries.Load() != 0 || s.Status().Queries[Refused] != 4 {
		t.Errorf("upstream asked %d, status %+v", up.queries.Load(), s.Status())
	}

	cfg.Allow = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	s = start(t, cfg)
	if resp := query(t, s, "udp", "printer.home.arpa.", dns.TypeA, nil); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("allowed: %v", resp)
	}
}

// A second server on the same address doesn't start, and leaves nothing open; the first goes on.
func TestStartTaken(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	first := start(t, cfg)
	_, port, _ := net.SplitHostPort(first.Addresses()[0])
	// Free over UDP and over TCP both: it is listened on, and then to be free again.
	pc, l := listenBoth(t)
	_, free, _ := net.SplitHostPort(pc.LocalAddr().String())
	pc.Close()
	l.Close()
	cfg2, _ := testConfig(t, up.address)
	cfg2.Listen = []listen.Entry{{Host: "127.0.0.1", Port: free}, {Host: "127.0.0.1", Port: port}}
	second, err := New(cfg2, t.Errorf)
	if err != nil {
		t.Fatal(err)
	}
	err = second.Start()
	if err == nil || !strings.Contains(err.Error(), "address already in use") || !strings.HasPrefix(err.Error(), "resolvers.lan: ") {
		second.Shutdown(context.Background())
		t.Fatalf("got %v", err)
	}
	if st := second.Status(); st.Serving {
		t.Errorf("serving: %+v", st)
	}
	// The address it could listen on was closed again.
	for _, network := range []string{"udp4", "tcp4"} {
		var err error
		if network == "udp4" {
			var pc net.PacketConn
			if pc, err = net.ListenPacket(network, net.JoinHostPort("127.0.0.1", free)); err == nil {
				pc.Close()
			}
		} else {
			var l net.Listener
			if l, err = net.Listen(network, net.JoinHostPort("127.0.0.1", free)); err == nil {
				l.Close()
			}
		}
		if err != nil {
			t.Errorf("%s left open: %v", network, err)
		}
	}
	if resp := query(t, first, "udp", "printer.home.arpa.", dns.TypeA, nil); resp.Rcode != dns.RcodeSuccess {
		t.Errorf("the first: %v", resp)
	}
}

func TestCheck(t *testing.T) {
	cfg, _ := testConfig(t)
	if err := Check(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Zones[0].Addresses == nil {
		t.Error("Check changed the zones")
	}
	for _, c := range []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"one zone twice", func(c *Config) {
			c.Zones = append(c.Zones, Zone{Credential: "office", Name: "HOME.arpa"})
		}, "credentials home and office are both the zone home.arpa of resolver lan: a zone can belong to only one credential"},
		{"a record outside", func(c *Config) {
			c.Zones[1].Path = "credentials.lab.settings.records"
			c.Zones[1].Records = mustRecords(t, "", "printer.home.arpa. A 10.0.0.1")
			c.Zones[1].Lines = []string{"printer.home.arpa. A 10.0.0.1"}
		}, `credentials.lab.settings.records: "printer.home.arpa. A 10.0.0.1": printer.home.arpa. isn't in the zone lab.home.arpa: a zone's records must be for its names, relative to it or absolute within it`},
		{"a resolver record in a zone", func(c *Config) {
			c.Records = mustRecords(t, "", "x.lab.home.arpa. A 10.0.0.1")
		}, "resolvers.lan.records: \"x.lab.home.arpa.\\t60\\tIN\\tA\\t10.0.0.1\": x.lab.home.arpa. is in the zone lab.home.arpa, of credential lab: give it in that credential's records"},
		{"a wildcard record of a task's wildcard", func(c *Config) {
			c.Zones[0].Path = "credentials.home.settings.records"
			c.Zones[0].Records = mustRecords(t, "home.arpa", "*.dev TXT x")
		}, "credentials.home.settings.records: \"*.dev.home.arpa.\\t60\\tIN\\tTXT\\t\\\"x\\\"\": *.dev.home.arpa. is published by task dev, which gives its addresses: records are for other names"},
		{"a CNAME beside data, of the resolver", func(c *Config) {
			c.Records = append(c.Records, mustRecords(t, "", "www.example.com. TXT x")...)
		}, "resolvers.lan.records: www.example.com. has a CNAME and other records: a name with a CNAME can't have others, since its data is the target's"},
		{"a loop of one", func(c *Config) {
			c.Records = mustRecords(t, "", "me.example.com. CNAME ME.example.com.")
		}, "resolvers.lan: the CNAMEs me.example.com. -> me.example.com. are a loop"},
		{"a loop across zones", func(c *Config) {
			c.Zones[1].Records = mustRecords(t, "lab.home.arpa", "back CNAME chain.home.arpa.")
			c.Zones[0].Records = append(c.Zones[0].Records, mustRecords(t, "home.arpa", "to-lab CNAME back.lab")...)
			c.Zones[0].Records[4] = mustRecords(t, "home.arpa", "chain CNAME to-lab")[0]
		}, "resolvers.lan: the CNAMEs chain.home.arpa. -> to-lab.home.arpa. -> back.lab.home.arpa. -> chain.home.arpa. are a loop"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, _ := testConfig(t)
			c.change(&cfg)
			if err := Check(cfg); err == nil || err.Error() != c.want {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
}

// A chain longer than MaxChain stops there: what was followed is the answer.
func TestLongChain(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	var lines []string
	for i := range 12 {
		lines = append(lines, fmt.Sprintf("c%d CNAME c%d", i, i+1))
	}
	lines = append(lines, "c12 A 192.168.1.99")
	cfg.Zones[0].Records = append(cfg.Zones[0].Records, mustRecords(t, "home.arpa", lines...)...)
	s := start(t, cfg)
	resp := query(t, s, "udp", "c0.home.arpa.", dns.TypeA, nil)
	if len(resp.Answer) != MaxChain+1 || resp.Rcode != dns.RcodeSuccess || up.queries.Load() != 0 {
		t.Errorf("got %d records: %v", len(resp.Answer), resp)
	}
}

// Queries and updates at once, as clients and the worker do: under -race.
func TestConcurrent(t *testing.T) {
	up := newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
	s := start(t, cfg)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			addresses.Set("nas.home.arpa.", []netip.Addr{netip.AddrFrom4([4]byte{192, 168, 1, byte(i)})})
			if i%7 == 0 {
				addresses.Set("nas.home.arpa.", nil)
			}
		}
	}()
	var queriers sync.WaitGroup
	for range 8 {
		queriers.Add(1)
		go func() {
			defer queriers.Done()
			c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
			for _, name := range []string{"nas.home.arpa.", "files.home.arpa.", "example.org.", "printer.home.arpa."} {
				for range 10 {
					m := new(dns.Msg)
					m.SetQuestion(name, dns.TypeA)
					resp, _, err := c.Exchange(m, s.Addresses()[0])
					if err != nil || resp.Rcode != dns.RcodeSuccess {
						t.Errorf("%s: %v %v", name, resp, err)
						return
					}
				}
			}
			_ = s.Status()
		}()
	}
	queriers.Wait()
	close(stop)
	wg.Wait()
}
