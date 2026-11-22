package resolver

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// bootstrap is a DNS server of the test's that tells the address of one host name, up.test., as
// 127.0.0.1 with the TTL ttl; and nothing else. Down, it answers nothing.
type bootstrap struct {
	address string
	ttl     atomic.Uint32
	down    atomic.Bool
	queries atomic.Int64
}

func newBootstrap(t *testing.T) *bootstrap {
	t.Helper()
	b := &bootstrap{}
	b.ttl.Store(300)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b.address = pc.LocalAddr().String()
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		b.queries.Add(1)
		if b.down.Load() {
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		q := req.Question[0]
		switch {
		case !strings.EqualFold(q.Name, "up.test."):
			resp.Rcode = dns.RcodeNameError
		case q.Qtype == dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: b.ttl.Load()}, A: net.ParseIP("127.0.0.1")})
		}
		w.WriteMsg(resp)
	})}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return b
}

// named is the upstream u given by host name, up.test, at its port.
func named(t *testing.T, u *upstream) string {
	t.Helper()
	_, port, err := net.SplitHostPort(u.address)
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort("up.test", port)
}

// An upstream server given by host name: the bootstrap servers find it, once for as long as their
// answer says, and it is asked as any.
func TestUpstreamByName(t *testing.T) {
	up, b := newUpstream(t), newBootstrap(t)
	cfg, _ := testConfig(t, named(t, up))
	cfg.Bootstrap = []string{deadAddress(t), b.address}
	s := start(t, cfg)

	for range 3 {
		resp := query(t, s, "udp", "example.org.", dns.TypeA, nil)
		if got := answers(resp); resp.Rcode != dns.RcodeSuccess || len(got) != 1 || got[0] != "example.org. A 192.0.2.53" {
			t.Fatalf("by name: %v", resp)
		}
	}
	if got := up.queries.Load(); got != 3 {
		t.Errorf("the upstream was asked %d times, want 3", got)
	}
	// A and AAAA, once, past the bootstrap server that is down.
	if got := b.queries.Load(); got != 2 {
		t.Errorf("the bootstrap server was asked %d times, want 2: the addresses are kept for their TTL", got)
	}
	st := s.Status()
	if got := st.UpstreamAddresses[named(t, up)]; len(got) != 1 || got[0] != up.address {
		t.Errorf("status: the upstream's addresses %v, want [%s]", got, up.address)
	}
	if st.UpstreamFailures[named(t, up)] != 0 {
		t.Errorf("failures: %v", st.UpstreamFailures)
	}
}

// A TTL shorter than a minute is kept a minute; and when the bootstrap servers stop answering, the
// addresses found stay, asked again a little later.
func TestUpstreamByNameKept(t *testing.T) {
	up, b := newUpstream(t), newBootstrap(t)
	b.ttl.Store(1)
	cfg, _ := testConfig(t, named(t, up))
	cfg.Bootstrap = []string{b.address}
	s := start(t, cfg)

	query(t, s, "udp", "example.org.", dns.TypeA, nil)
	n := s.named[named(t, up)]
	n.mutex.Lock()
	kept := time.Until(n.refresh)
	n.mutex.Unlock()
	if kept < minUpstreamTTL-time.Second || kept > minUpstreamTTL {
		t.Errorf("a TTL of 1s is kept %s, want %s", kept.Round(time.Second), minUpstreamTTL)
	}

	// Their time over, the bootstrap server down: still answered, at the addresses there were.
	b.down.Store(true)
	n.mutex.Lock()
	n.refresh = time.Now().Add(-time.Second)
	n.mutex.Unlock()
	before := b.queries.Load()
	resp := query(t, s, "udp", "example.org.", dns.TypeA, nil)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("the bootstrap server down: %v", resp)
	}
	if b.queries.Load() == before {
		t.Error("the bootstrap server wasn't asked again once the time was over")
	}
	n.mutex.Lock()
	again := time.Until(n.refresh)
	n.mutex.Unlock()
	if again < bootstrapRetryWait-time.Second || again > bootstrapRetryWait {
		t.Errorf("asked again in %s, want %s", again.Round(time.Second), bootstrapRetryWait)
	}
}

// One the bootstrap servers never found is skipped, as a server down: the next is asked, and with
// no other, SERVFAIL.
func TestUpstreamByNameNotFound(t *testing.T) {
	up, b := newUpstream(t), newBootstrap(t)
	b.down.Store(true)
	cfg, _ := testConfig(t, named(t, up), up.address)
	cfg.Bootstrap = []string{b.address}
	s := start(t, cfg)
	resp := query(t, s, "udp", "example.org.", dns.TypeA, nil)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("past the one not found: %v", resp)
	}
	if st := s.Status(); st.UpstreamFailures[named(t, up)] != 1 || st.UpstreamFailures[up.address] != 0 {
		t.Errorf("failures: %v", st.UpstreamFailures)
	}

	cfg, _ = testConfig(t, named(t, up))
	cfg.Bootstrap = []string{b.address}
	s = start(t, cfg)
	if resp := query(t, s, "udp", "example.org.", dns.TypeA, nil); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("none other: %v", resp)
	}
}

// A host name with no bootstrap server to find it is an error, as the configuration says.
func TestUpstreamByNameNeedsBootstrap(t *testing.T) {
	cfg, _ := testConfig(t, "up.test:53")
	if _, err := New(cfg, nil); err == nil || !strings.Contains(err.Error(), "no bootstrap") {
		t.Errorf("got %v", err)
	}
}

// The status doesn't wait for the bootstrap servers: /healthz and the metrics read it while an
// upstream given by host name is being looked up, and a bootstrap server that doesn't answer
// would hold them for its timeout, of each type and each server.
func TestUpstreamByNameStatusDoesNotWait(t *testing.T) {
	up, b := newUpstream(t), newBootstrap(t)
	b.down.Store(true)
	cfg, _ := testConfig(t, named(t, up))
	cfg.Bootstrap = []string{b.address}
	s := start(t, cfg)

	done := make(chan struct{})
	go func() {
		defer close(done)
		m := new(dns.Msg)
		m.SetQuestion("example.org.", dns.TypeA)
		c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
		c.Exchange(m, s.Addresses()[0])
	}()
	deadline := time.Now().Add(2 * time.Second)
	for b.queries.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the bootstrap server was never asked")
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	s.Status()
	if took := time.Since(start); took > s.timeout/2 {
		t.Errorf("the status took %s, while the bootstrap servers were asked: it waited for them", took.Round(time.Millisecond))
	}
	<-done
}
