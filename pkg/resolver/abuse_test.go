package resolver

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Many clients at once, over UDP and TCP, asking what is local, what has no data, what is
// forwarded and what is kept: each has the answer to its own question, and the counts add up.
func TestManyClients(t *testing.T) {
	up := newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
	s, _ := startCached(t, cfg, 1000)
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.10")})

	const clients, each = 40, 100
	var wrong atomic.Int64
	var first sync.Once
	fail := func(format string, args ...any) {
		wrong.Add(1)
		first.Do(func() { t.Errorf(format, args...) })
	}
	var wg sync.WaitGroup
	for c := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			network := []string{"udp", "tcp"}[c%2]
			client := &dns.Client{Net: network, Timeout: 5 * time.Second}
			for i := range each {
				m := new(dns.Msg)
				var want string
				qtype := dns.TypeA
				switch i % 4 {
				case 0:
					m.SetQuestion("nas.home.arpa.", qtype)
					want = "nas.home.arpa. A 192.168.1.10"
				case 1:
					qtype = dns.TypeAAAA
					m.SetQuestion("nas.home.arpa.", qtype)
				case 2:
					// Its own name: asked upstream.
					name := fmt.Sprintf("c%d-q%d.example.org.", c, i)
					m.SetQuestion(name, qtype)
					want = name + " A 192.0.2.53"
				case 3:
					// One name of all: from the cache, but for the first to ask.
					m.SetQuestion("shared.example.org.", qtype)
					want = "shared.example.org. A 192.0.2.53"
				}
				resp, _, err := client.Exchange(m, s.Addresses()[0])
				if err != nil {
					fail("client %d over %s, query %d: %v", c, network, i, err)
					continue
				}
				got := answers(resp)
				if resp.Id != m.Id || resp.Rcode != dns.RcodeSuccess || len(resp.Question) != 1 || resp.Question[0].Name != m.Question[0].Name ||
					want == "" && len(got) != 0 || want != "" && !slices.Equal(got, []string{want}) {
					fail("client %d over %s, query %d, %s: %v", c, network, i, m.Question[0].Name, resp)
				}
			}
		}()
	}
	wg.Wait()
	if n := wrong.Load(); n > 0 {
		t.Fatalf("%d of %d answers were wrong, or missing", n, clients*each)
	}

	st := s.Status()
	total := uint64(clients * each)
	if st.Queries[Local] != total/4 || st.Queries[NoData] != total/4 {
		t.Errorf("local %d, no data %d, want %d each", st.Queries[Local], st.Queries[NoData], total/4)
	}
	if got := st.Queries[Forwarded] + st.Queries[Cached]; got != total/2 || st.Queries[ServFail] != 0 || st.Queries[Refused] != 0 {
		t.Errorf("forwarded %d and cached %d, want %d together; failed %d, refused %d", st.Queries[Forwarded], st.Queries[Cached], total/2, st.Queries[ServFail], st.Queries[Refused])
	}
	// The name of all is asked upstream by those that came before its answer was kept, and by
	// none after: most are from the cache.
	if st.Queries[Cached] < total/4-clients {
		t.Errorf("cached %d of the %d of the shared name", st.Queries[Cached], total/4)
	}
}

// Clients that connect over TCP and say nothing, or half a message, hold nothing up: the others
// are answered meanwhile, over UDP and TCP, and the silent ones are dropped in the end.
func TestSilentTCPClients(t *testing.T) {
	up := newUpstream(t)
	cfg, addresses := testConfig(t, up.address)
	s := start(t, cfg)
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.10")})

	var silent []net.Conn
	for i := range 200 {
		conn, err := net.Dial("tcp", s.Addresses()[0])
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		defer conn.Close()
		if i%2 == 1 {
			// The length of a message of 300 bytes, and 3 of them.
			conn.Write([]byte{1, 44, 0, 0, 0})
		}
		silent = append(silent, conn)
	}

	for _, network := range []string{"udp", "tcp"} {
		begun := time.Now()
		for range 20 {
			if got := answers(query(t, s, network, "nas.home.arpa.", dns.TypeA, nil)); !slices.Equal(got, []string{"nas.home.arpa. A 192.168.1.10"}) {
				t.Fatalf("over %s, beside the silent ones: %v", network, got)
			}
		}
		if took := time.Since(begun); took > 2*time.Second {
			t.Errorf("20 queries over %s took %s beside the silent ones", network, took)
		}
	}

	if testing.Short() {
		return
	}
	// Dropped: within the 10s a client has to send its query, and a little.
	silent[0].SetReadDeadline(time.Now().Add(13 * time.Second))
	silent[1].SetReadDeadline(time.Now().Add(13 * time.Second))
	for i, conn := range silent[:2] {
		if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
			if n, ok := err.(net.Error); ok && n.Timeout() {
				t.Errorf("silent connection %d is still open after 13s", i)
			}
		}
	}
}

// What an upstream server says of a name that wasn't asked is not kept for that name: it answers
// the question it came for, and the other name is asked for itself.
func TestAnswerIsOfItsQuestionOnly(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var asked sync.Map
	upstream := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		q := req.Question[0]
		count, _ := asked.LoadOrStore(q.Name, new(atomic.Int64))
		count.(*atomic.Int64).Add(1)
		resp := new(dns.Msg)
		resp.SetReply(req)
		a := func(name, addr string) dns.RR {
			return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP(addr)}
		}
		if q.Name == "bait.example.org." {
			// With records of a name nobody asked, in every section.
			resp.Answer = []dns.RR{a(q.Name, "192.0.2.1"), a("bank.example.", "203.0.113.66")}
			resp.Ns = []dns.RR{&dns.NS{Hdr: dns.RR_Header{Name: "bank.example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns.evil.example."}}
			resp.Extra = []dns.RR{a("bank.example.", "203.0.113.66"), a("nas.home.arpa.", "203.0.113.66")}
		} else {
			resp.Answer = []dns.RR{a(q.Name, "198.51.100.7")}
		}
		w.WriteMsg(resp)
	})}
	go upstream.ActivateAndServe()
	t.Cleanup(func() { upstream.Shutdown() })

	cfg, addresses := testConfig(t, pc.LocalAddr().String())
	s, _ := startCached(t, cfg, 100)
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.10")})

	for range 2 {
		query(t, s, "udp", "bait.example.org.", dns.TypeA, nil)
	}
	for range 2 {
		if got := answers(query(t, s, "udp", "bank.example.", dns.TypeA, nil)); !slices.Equal(got, []string{"bank.example. A 198.51.100.7"}) {
			t.Errorf("bank.example., after an answer that had another address for it: %v", got)
		}
		// And a local name is the resolver's own, whatever upstream said of it.
		if got := answers(query(t, s, "udp", "nas.home.arpa.", dns.TypeA, nil)); !slices.Equal(got, []string{"nas.home.arpa. A 192.168.1.10"}) {
			t.Errorf("nas.home.arpa., after an answer that had another address for it: %v", got)
		}
	}
	for name, want := range map[string]int64{"bait.example.org.": 1, "bank.example.": 1} {
		count, _ := asked.Load(name)
		if count == nil || count.(*atomic.Int64).Load() != want {
			t.Errorf("%s was asked upstream %v times, want %d: the second is from the cache, and the first its own", name, count, want)
		}
	}
	if _, ok := asked.Load("nas.home.arpa."); ok {
		t.Error("the local name was asked upstream")
	}
}

// A query that comes back as it was sent is no answer to it: of a server that echoes what it is
// sent, the next is asked, and with no other the query fails.
func TestQueryEchoedIsNoAnswer(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	echo := pc.LocalAddr().String()

	cfg, _ := testConfig(t, echo)
	s := start(t, cfg)
	if resp := query(t, s, "udp", "example.org.", dns.TypeA, nil); resp.Rcode != dns.RcodeServerFailure || len(resp.Answer) != 0 {
		t.Errorf("of a server that echoes alone: %v", resp)
	}

	up := newUpstream(t)
	cfg, _ = testConfig(t, echo, up.address)
	s = start(t, cfg)
	resp := query(t, s, "udp", "example.org.", dns.TypeA, nil)
	if got := answers(resp); resp.Rcode != dns.RcodeSuccess || !slices.Equal(got, []string{"example.org. A 192.0.2.53"}) {
		t.Errorf("past a server that echoes: %v", resp)
	}
	if st := s.Status(); st.UpstreamFailures[echo] != 1 {
		t.Errorf("the echoing server's failures: %v", st.UpstreamFailures)
	}
}

// FuzzAnswer gives the resolver any message a client can send: it answers or it doesn't, without
// a panic, and what it answers can be sent, with the query's id.
func FuzzAnswer(f *testing.F) {
	for _, q := range []struct {
		name  string
		qtype uint16
	}{
		{"nas.home.arpa.", dns.TypeA}, {"printer.home.arpa.", dns.TypeANY}, {"files.home.arpa.", dns.TypeAAAA},
		{"x.wild.home.arpa.", dns.TypeA}, {"20.1.168.192.in-addr.arpa.", dns.TypePTR}, {"example.org.", dns.TypeTXT},
		{".", dns.TypeNS}, {"www.example.com.", dns.TypeCNAME},
	} {
		m := new(dns.Msg)
		m.SetQuestion(q.name, q.qtype)
		m.SetEdns0(1232, true)
		packed, _ := m.Pack()
		f.Add(packed)
	}
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})

	// No upstream server there: what is forwarded fails at once, which is an answer too.
	cfg, addresses := testConfig(f, deadAddress(f))
	s, err := New(cfg, nil)
	if err != nil {
		f.Fatal(err)
	}
	s.timeout = 20 * time.Millisecond
	s.allow = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	addresses.Set("nas.home.arpa.", []netip.Addr{netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("fd00::10")})
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}

	f.Fuzz(func(t *testing.T, data []byte) {
		req := new(dns.Msg)
		if req.Unpack(data) != nil {
			return
		}
		resp, _ := s.answer(req, remote)
		if resp == nil {
			if !req.Response {
				t.Errorf("no answer to a query: %v", req)
			}
			return
		}
		if resp.Id != req.Id || !resp.Response {
			t.Errorf("the answer isn't one to the query: %v", resp)
		}
		resp.Truncate(dns.MinMsgSize)
		if _, err := resp.Pack(); err != nil {
			t.Errorf("an answer that can't be sent: %v\n%v", err, resp)
		}
	})
}
