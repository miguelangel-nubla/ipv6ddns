package resolver

import (
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

// clock is the time of a test, which it moves.
type clock struct {
	mutex sync.Mutex
	now   time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.now = c.now.Add(d)
}

// startCached is start, of a resolver that keeps size answers, at the test's time.
func startCached(t *testing.T, cfg Config, size int) (*Server, *clock) {
	t.Helper()
	c := newClock()
	cfg.CacheSize = size
	return startWith(t, cfg, func(s *Server) { s.now = c.Now }), c
}

// zoned is an upstream's answers as a real one's: an A of its TTL for any name, but those under
// nx.test., which don't exist, and under empty.test., which have no data, each with the SOA; under
// bare.test., which don't exist either, with no SOA; and fail.test. and refused.test., its codes.
func zoned(ttl, soaTTL, minimum uint32) func(req *dns.Msg) *dns.Msg {
	return func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		q := req.Question[0]
		name := strings.ToLower(q.Name)
		soa := func(zone string) {
			resp.Ns = append(resp.Ns, &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
				Ns: "ns." + zone, Mbox: "hostmaster." + zone, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: minimum})
		}
		switch {
		case dns.IsSubDomain("nx.test.", name):
			resp.Rcode = dns.RcodeNameError
			soa("nx.test.")
		case dns.IsSubDomain("empty.test.", name):
			soa("empty.test.")
		case dns.IsSubDomain("bare.test.", name):
			resp.Rcode = dns.RcodeNameError
		case dns.IsSubDomain("fail.test.", name):
			resp.Rcode = dns.RcodeServerFailure
		case dns.IsSubDomain("refused.test.", name):
			resp.Rcode = dns.RcodeRefused
		case q.Qtype == dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP("192.0.2.53")})
		default:
			return nil
		}
		if opt := req.IsEdns0(); opt != nil {
			resp.SetEdns0(opt.UDPSize(), opt.Do())
		}
		return resp
	}
}

// A forwarded answer is kept for its TTL: asked again, it comes from the cache, with the
// client's id, its spelling of the name and its EDNS, and the TTL less the time it was kept; its
// time over, the upstream server is asked again. The DO and CD bits are other answers.
func TestCache(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	s, clock := startCached(t, cfg, 100)

	asked := func(want int64, what string) {
		t.Helper()
		if got := up.queries.Load(); got != want {
			t.Errorf("%s: the upstream server was asked %d times, want %d", what, got, want)
		}
	}
	ttl := func(resp *dns.Msg) uint32 {
		t.Helper()
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("no answer: %v", resp)
		}
		return resp.Answer[0].Header().Ttl
	}

	if got := ttl(query(t, s, "udp", "a.example.org.", dns.TypeA, nil)); got != 30 {
		t.Errorf("forwarded: a TTL of %d, want 30", got)
	}
	asked(1, "a miss")
	// query tells an id that isn't the client's.
	resp := query(t, s, "udp", "A.Example.ORG.", dns.TypeA, nil)
	if got := answers(resp); !slices.Equal(got, []string{"A.Example.ORG. A 192.0.2.53"}) || resp.Question[0].Name != "A.Example.ORG." {
		t.Errorf("from the cache, as the client spells it: %v", resp)
	}
	if got := ttl(resp); got != 30 {
		t.Errorf("from the cache, at once: a TTL of %d, want 30", got)
	}
	if resp.IsEdns0() != nil {
		t.Errorf("from the cache, to a client without EDNS: %v", resp)
	}
	asked(1, "a hit")

	clock.advance(10*time.Second + 500*time.Millisecond)
	if got := ttl(query(t, s, "tcp", "a.example.org.", dns.TypeA, nil)); got != 20 {
		t.Errorf("after 10.5s: a TTL of %d, want 20", got)
	}
	// The client's EDNS, not the one of the query that was kept.
	resp = query(t, s, "udp", "a.example.org.", dns.TypeA, func(m *dns.Msg) { m.SetEdns0(1400, false) })
	if opt := resp.IsEdns0(); opt == nil || opt.Do() || opt.UDPSize() != ednsSize || ttl(resp) != 20 {
		t.Errorf("from the cache, to a client with EDNS: %v", resp)
	}
	asked(1, "hits")

	// The DO bit, and CD, are answers of their own.
	resp = query(t, s, "udp", "a.example.org.", dns.TypeA, func(m *dns.Msg) { m.SetEdns0(1400, true) })
	if opt := resp.IsEdns0(); opt == nil || !opt.Do() || ttl(resp) != 30 {
		t.Errorf("with DO: %v", resp)
	}
	asked(2, "with DO")
	query(t, s, "udp", "a.example.org.", dns.TypeA, func(m *dns.Msg) { m.CheckingDisabled = true })
	asked(3, "with CD")
	resp = query(t, s, "udp", "a.example.org.", dns.TypeA, func(m *dns.Msg) { m.SetEdns0(4096, true) })
	if opt := resp.IsEdns0(); opt == nil || !opt.Do() || ttl(resp) != 30 {
		t.Errorf("with DO, from the cache: %v", resp)
	}
	asked(3, "with DO, again")

	// The last second: a TTL of 1, never 0.
	clock.advance(19 * time.Second)
	if got := ttl(query(t, s, "udp", "a.example.org.", dns.TypeA, nil)); got != 1 {
		t.Errorf("after 29.5s: a TTL of %d, want 1", got)
	}
	asked(3, "the last second")
	if st := s.Status(); st.CacheEntries != 3 || st.CacheSize != 100 || st.Queries[Cached] != 5 || st.Queries[Forwarded] != 3 {
		t.Errorf("status: %+v", st)
	}
	clock.advance(500 * time.Millisecond)
	if got := ttl(query(t, s, "udp", "a.example.org.", dns.TypeA, nil)); got != 30 {
		t.Errorf("its time over: a TTL of %d, want 30, asked again", got)
	}
	asked(4, "its time over")
	// The two others, of DO and CD, kept 19.5s of their 30.
	clock.advance(11 * time.Second)
	if st := s.Status(); st.CacheEntries != 1 {
		t.Errorf("%d answers kept, want the one whose time isn't over", st.CacheEntries)
	}
}

// An answer too big for the client over UDP is truncated from the cache as any, and whole over TCP.
func TestCacheTruncation(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	s, _ := startCached(t, cfg, 100)
	for i := range 2 {
		resp := query(t, s, "udp", "big.example.org.", dns.TypeTXT, nil)
		if !resp.Truncated || len(resp.Answer) >= 40 {
			t.Errorf("query %d over UDP: truncated %t, %d records", i, resp.Truncated, len(resp.Answer))
		}
		resp = query(t, s, "tcp", "big.example.org.", dns.TypeTXT, nil)
		if resp.Truncated || len(resp.Answer) != 40 {
			t.Errorf("query %d over TCP: truncated %t, %d records", i, resp.Truncated, len(resp.Answer))
		}
	}
	if got := up.queries.Load(); got != 1 {
		t.Errorf("the upstream server was asked %d times, want 1", got)
	}

	// A truncated answer of the upstream server, with none over TCP, isn't kept.
	up.answerWith(func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Truncated = true
		resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.53")})
		return resp
	})
	before := up.queries.Load()
	for range 2 {
		query(t, s, "tcp", "cut.example.org.", dns.TypeA, nil)
	}
	// Over UDP and over TCP, twice.
	if got := up.queries.Load() - before; got != 4 {
		t.Errorf("a truncated answer: the upstream server was asked %d times, want 4", got)
	}
}

// That a name doesn't exist, or has no data, is kept as RFC 2308 has it: for the SOA's minimum,
// or its TTL, the lower, an hour at most; and an answer with data a day at most. Never without an
// SOA, nor a failure, nor a TTL of 0.
func TestCacheNegative(t *testing.T) {
	for _, c := range []struct {
		name                 string
		qtype                uint16
		ttl, soaTTL, minimum uint32
		rcode                int
		// How long it is kept: 0, not at all.
		kept time.Duration
	}{
		{"gone.nx.test.", dns.TypeA, 30, 300, 60, dns.RcodeNameError, time.Minute},
		{"gone.nx.test.", dns.TypeA, 30, 20, 60, dns.RcodeNameError, 20 * time.Second},
		{"host.empty.test.", dns.TypeAAAA, 30, 300, 5, dns.RcodeSuccess, 5 * time.Second},
		{"gone.nx.test.", dns.TypeA, 30, 86400, 7200, dns.RcodeNameError, time.Hour},
		{"host.empty.test.", dns.TypeA, 30, 86400, 86400, dns.RcodeSuccess, time.Hour},
		{"gone.nx.test.", dns.TypeA, 30, 300, 0, dns.RcodeNameError, 0},
		{"gone.bare.test.", dns.TypeA, 30, 300, 60, dns.RcodeNameError, 0},
		{"x.fail.test.", dns.TypeA, 30, 300, 60, dns.RcodeServerFailure, 0},
		{"x.refused.test.", dns.TypeA, 30, 300, 60, dns.RcodeRefused, 0},
		{"long.example.org.", dns.TypeA, 7 * 86400, 300, 60, dns.RcodeSuccess, 24 * time.Hour},
		{"short.example.org.", dns.TypeA, 2, 300, 60, dns.RcodeSuccess, 2 * time.Second},
		{"none.example.org.", dns.TypeA, 0, 300, 60, dns.RcodeSuccess, 0},
	} {
		t.Run(fmt.Sprintf("%s %s %d %d %d", c.name, dns.TypeToString[c.qtype], c.ttl, c.soaTTL, c.minimum), func(t *testing.T) {
			up := newUpstream(t)
			up.answerWith(zoned(c.ttl, c.soaTTL, c.minimum))
			cfg, _ := testConfig(t, up.address)
			s, clock := startCached(t, cfg, 100)
			ask := func(what string, upstream bool) *dns.Msg {
				t.Helper()
				before := up.queries.Load()
				resp := query(t, s, "udp", c.name, c.qtype, nil)
				if resp.Rcode != c.rcode {
					t.Errorf("%s: %v", what, resp)
				}
				if got := up.queries.Load() > before; got != upstream {
					t.Errorf("%s: the upstream server asked: %t, want %t", what, got, upstream)
				}
				return resp
			}
			ask("the first", true)
			if c.kept == 0 {
				ask("again, of an answer not to keep", true)
				if n := s.Status().CacheEntries; n != 0 {
					t.Errorf("%d answers kept", n)
				}
				return
			}
			resp := ask("again", false)
			// The SOA tells how long: all of it, then what is left.
			if len(resp.Answer) == 0 {
				if len(resp.Ns) != 1 || resp.Ns[0].Header().Ttl != uint32(c.kept.Seconds()) {
					t.Errorf("the SOA from the cache: %v, want a TTL of %s", resp.Ns, c.kept)
				}
			}
			clock.advance(c.kept - time.Second)
			resp = ask("in its last second", false)
			for _, rr := range append(resp.Answer, resp.Ns...) {
				if c.ttl <= 86400 && rr.Header().Ttl != 1 {
					t.Errorf("in its last second: a TTL of %d: %v", rr.Header().Ttl, rr)
				}
			}
			clock.advance(time.Second)
			ask("its time over", true)
		})
	}
}

// The cache holds its size, and no more: the least recently asked goes first.
func TestCacheEviction(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	s, _ := startCached(t, cfg, 3)
	hit := func(name string, want bool) {
		t.Helper()
		before := up.queries.Load()
		query(t, s, "udp", name, dns.TypeA, nil)
		if got := up.queries.Load() == before; got != want {
			t.Errorf("%s from the cache: %t, want %t", name, got, want)
		}
	}
	for _, name := range []string{"a.test.", "b.test.", "c.test."} {
		hit(name, false)
	}
	// a is asked, so b is the one asked the longest ago: d takes its place.
	hit("a.test.", true)
	hit("d.test.", false)
	if n := s.Status().CacheEntries; n != 3 {
		t.Errorf("%d answers kept, want 3", n)
	}
	hit("a.test.", true)
	hit("c.test.", true)
	hit("d.test.", true)
	hit("b.test.", false)
	// Which took a's place, the one asked the longest ago then.
	hit("a.test.", false)
	if n := s.Status().CacheEntries; n != 3 {
		t.Errorf("%d answers kept, want 3", n)
	}
}

// The local names are never kept: they follow the tasks' addresses at once, with a cache too. A
// CNAME's target outside is, as any forwarded.
func TestCacheLocal(t *testing.T) {
	up := newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
	s, clock := startCached(t, cfg, 100)
	for i := range 3 {
		addr := netip.AddrFrom4([4]byte{192, 168, 1, byte(10 + i)})
		addresses.Set("nas.home.arpa.", []netip.Addr{addr})
		for _, name := range []string{"nas.home.arpa.", "files.home.arpa.", "www.example.com."} {
			resp := query(t, s, "udp", name, dns.TypeA, nil)
			if last := resp.Answer[len(resp.Answer)-1]; last.(*dns.A).A.String() != addr.String() || last.Header().Ttl != 30 {
				t.Errorf("%s, with nas at %s: %v", name, addr, resp)
			}
		}
		query(t, s, "udp", "printer.home.arpa.", dns.TypeA, nil)
		query(t, s, "udp", "printer.home.arpa.", dns.TypeAAAA, nil)
	}
	if st := s.Status(); st.CacheEntries != 0 || st.Queries[Cached] != 0 || up.queries.Load() != 0 {
		t.Errorf("local names: %d kept, %d from the cache, the upstream server asked %d times", st.CacheEntries, st.Queries[Cached], up.queries.Load())
	}

	want := []string{"out.home.arpa. CNAME www.upstream.test.", "www.upstream.test. A 192.0.2.53"}
	for i := range 2 {
		clock.advance(4 * time.Second)
		resp := query(t, s, "udp", "out.home.arpa.", dns.TypeA, nil)
		if got := answers(resp); !slices.Equal(got, want) || !resp.Authoritative {
			t.Errorf("query %d: %v", i, resp)
		}
		// The CNAME is local, and has its TTL whole; its target's counts down.
		if resp.Answer[0].Header().Ttl != 60 || resp.Answer[1].Header().Ttl != uint32(30-4*i) {
			t.Errorf("query %d: the TTLs %d and %d", i, resp.Answer[0].Header().Ttl, resp.Answer[1].Header().Ttl)
		}
	}
	// And the target, asked for itself, is the same answer kept.
	query(t, s, "udp", "www.upstream.test.", dns.TypeA, nil)
	if st := s.Status(); up.queries.Load() != 1 || st.CacheEntries != 1 || st.Queries[Cached] != 1 {
		t.Errorf("a CNAME's target: the upstream server asked %d times, status %+v", up.queries.Load(), st)
	}
}

// Without a cache, every query goes upstream.
func TestNoCache(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	s := start(t, cfg)
	for range 3 {
		query(t, s, "udp", "example.org.", dns.TypeA, nil)
	}
	if st := s.Status(); up.queries.Load() != 3 || st.CacheEntries != 0 || st.CacheSize != 0 || st.Queries[Cached] != 0 {
		t.Errorf("the upstream server asked %d times, status %+v", up.queries.Load(), st)
	}
}

// Queries at once, of few names, with a cache smaller than them: under -race.
func TestCacheConcurrent(t *testing.T) {
	up := newUpstream(t)
	cfg, _ := testConfig(t, up.address)
	s, clock := startCached(t, cfg, 4)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
			for i := range 40 {
				m := new(dns.Msg)
				m.SetQuestion(fmt.Sprintf("n%d.example.org.", (g+i)%6), dns.TypeA)
				resp, _, err := c.Exchange(m, s.Addresses()[0])
				if err != nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 || resp.Answer[0].Header().Ttl == 0 {
					t.Errorf("%v %v", resp, err)
					return
				}
				if i%10 == 0 {
					clock.advance(7 * time.Second)
					_ = s.Status()
				}
			}
		}()
	}
	wg.Wait()
	if st := s.Status(); st.CacheEntries > 4 || st.Queries[Cached] == 0 {
		t.Errorf("status: %+v", st)
	}
}
