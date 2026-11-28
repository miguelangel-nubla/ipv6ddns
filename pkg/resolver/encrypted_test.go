package resolver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testCA is a certificate authority of the test's, which the servers' certificates are of.
type testCA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &testCA{cert: cert, key: key, roots: roots}
}

// leaf is a certificate of the CA for names and addresses.
func (ca *testCA) leaf(t *testing.T, names []string, ips ...net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: names, IPAddresses: ips, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// encryptedAnswer answers req as the fake encrypted servers do: an A of 192.0.2.80, or none.
func encryptedAnswer(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	q := req.Question[0]
	if q.Qtype == dns.TypeA {
		resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.80")})
	} else {
		resp.Rcode = dns.RcodeNameError
	}
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
		resp.IsEdns0().Option = append(resp.IsEdns0().Option, &dns.EDNS0_PADDING{Padding: make([]byte, 7)})
	}
	return resp
}

// dotServer is a server of DNS over TLS on 127.0.0.1, with a certificate for cert.
type dotServer struct {
	address string
	queries atomic.Int64
	conns   atomic.Int64
	// The length of each query as received, for the padding.
	lengths chan int
}

// countingListener counts the connections accepted.
type countingListener struct {
	net.Listener
	n *atomic.Int64
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func newDoT(t *testing.T, cert tls.Certificate) *dotServer {
	t.Helper()
	d := &dotServer{lengths: make(chan int, 100)}
	inner, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.address = inner.Addr().String()
	l := tls.NewListener(countingListener{inner, &d.conns}, &tls.Config{Certificates: []tls.Certificate{cert}})
	server := &dns.Server{Listener: l, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		d.queries.Add(1)
		if packed, err := req.Pack(); err == nil {
			select {
			case d.lengths <- len(packed):
			default:
			}
		}
		w.WriteMsg(encryptedAnswer(req))
	}), IdleTimeout: func() time.Duration { return time.Minute }}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return d
}

// dohServer is a server of DNS over HTTPS, over HTTP/2, on 127.0.0.1 at /dns-query.
type dohServer struct {
	*httptest.Server
	queries atomic.Int64
	conns   atomic.Int64
	proto   atomic.Value
}

func newDoH(t *testing.T, cert tls.Certificate) *dohServer {
	t.Helper()
	d := &dohServer{}
	d.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.proto.Store(r.Proto)
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil || req.Id != 0 {
			http.Error(w, "bad message", http.StatusBadRequest)
			return
		}
		d.queries.Add(1)
		packed, _ := encryptedAnswer(req).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}))
	d.EnableHTTP2 = true
	// Of the handshakes that fail, as the tests of wrong certificates mean them to.
	d.Config.ErrorLog = log.New(io.Discard, "", 0)
	d.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	d.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			d.conns.Add(1)
		}
	}
	d.StartTLS()
	t.Cleanup(d.Close)
	return d
}

// startWithRoots is start, of a server that trusts the CA.
func startWithRoots(t *testing.T, cfg Config, ca *testCA) *Server {
	t.Helper()
	return startWith(t, cfg, func(s *Server) {
		s.timeout = 500 * time.Millisecond
		s.roots = ca.roots
	})
}

// DNS over TLS, at an address whose certificate holds it, and at a host name the bootstrap server
// finds: the answer relayed, one connection for many queries, the queries padded.
func TestDoT(t *testing.T) {
	ca := newTestCA(t)
	dot := newDoT(t, ca.leaf(t, []string{"up.test"}, net.ParseIP("127.0.0.1")))
	_, port, _ := net.SplitHostPort(dot.address)
	boot := newBootstrap(t)
	for _, upstream := range []string{"tls://127.0.0.1:" + port, "tls://up.test:" + port} {
		t.Run(upstream, func(t *testing.T) {
			before := dot.conns.Load()
			cfg, _ := testConfig(t, upstream)
			cfg.Bootstrap = []string{boot.address}
			s := startWithRoots(t, cfg, ca)
			for i, name := range []string{"a.example.org.", "b.example.org.", "a-much-longer-name.example.org."} {
				resp := query(t, s, "udp", name, dns.TypeA, nil)
				if got := answers(resp); resp.Rcode != dns.RcodeSuccess || !slices.Equal(got, []string{name + " A 192.0.2.80"}) {
					t.Fatalf("query %d: %v", i, resp)
				}
				// No EDNS asked, none answered: the padding's is taken off.
				if resp.IsEdns0() != nil {
					t.Errorf("an OPT the client didn't ask: %v", resp)
				}
			}
			resp := query(t, s, "udp", "c.example.org.", dns.TypeA, func(m *dns.Msg) { m.SetEdns0(1232, true) })
			if opt := resp.IsEdns0(); opt == nil || !opt.Do() || slices.ContainsFunc(opt.Option, func(o dns.EDNS0) bool { return o.Option() == dns.EDNS0PADDING }) {
				t.Errorf("the client's EDNS, without the padding: %v", resp)
			}
			if got := dot.conns.Load() - before; got != 1 {
				t.Errorf("%d connections for 4 queries, want 1, kept open", got)
			}
			if st := s.Status(); st.Queries[Forwarded] != 4 || st.UpstreamFailures[upstream] != 0 || !slices.Equal(st.Upstreams, []string{upstream}) {
				t.Errorf("status: %+v", st)
			}
		})
	}
	for range len(dot.lengths) {
		if n := <-dot.lengths; n%paddingBlock != 0 {
			t.Errorf("a query of %d bytes, not padded to %d", n, paddingBlock)
		}
	}
}

// A connection the server closed, kept, is tried again on a new one: no query fails.
func TestDoTReconnect(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.leaf(t, nil, net.ParseIP("127.0.0.1"))
	dot := newDoT(t, cert)
	cfg, _ := testConfig(t, "tls://"+dot.address)
	s := startWithRoots(t, cfg, ca)
	query(t, s, "udp", "a.example.org.", dns.TypeA, nil)
	// The kept connection closed under it, as by a server's idle timeout.
	srv := s.upstreams[0]
	c := srv.dot.take(dot.address)
	if c == nil {
		t.Fatal("no connection kept")
	}
	c.Conn.Conn.(*tls.Conn).NetConn().Close()
	srv.dot.put(dot.address, c)
	if resp := query(t, s, "udp", "b.example.org.", dns.TypeA, nil); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("past a closed connection: %v", resp)
	}
	if got := dot.conns.Load(); got != 2 {
		t.Errorf("%d connections, want 2", got)
	}
	if st := s.Status(); st.UpstreamFailures["tls://"+dot.address] != 0 {
		t.Errorf("failures: %v", st.UpstreamFailures)
	}
}

// DNS over HTTPS, over HTTP/2, one connection for many queries; at a host name too, which the
// bootstrap server finds, and which no system resolver knows.
func TestDoH(t *testing.T) {
	ca := newTestCA(t)
	doh := newDoH(t, ca.leaf(t, []string{"up.test"}, net.ParseIP("127.0.0.1")))
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(doh.URL, "https://"))
	boot := newBootstrap(t)
	for _, upstream := range []string{"https://127.0.0.1:" + port + "/dns-query", "https://up.test:" + port + "/dns-query"} {
		t.Run(upstream, func(t *testing.T) {
			before := doh.conns.Load()
			cfg, _ := testConfig(t, upstream)
			cfg.Bootstrap = []string{boot.address}
			s := startWithRoots(t, cfg, ca)
			for i, name := range []string{"a.example.org.", "b.example.org.", "c.example.org."} {
				resp := query(t, s, "udp", name, dns.TypeA, nil)
				if got := answers(resp); resp.Rcode != dns.RcodeSuccess || !slices.Equal(got, []string{name + " A 192.0.2.80"}) || resp.IsEdns0() != nil {
					t.Fatalf("query %d: %v", i, resp)
				}
			}
			if resp := query(t, s, "tcp", "none.example.org.", dns.TypeTXT, nil); resp.Rcode != dns.RcodeNameError {
				t.Errorf("NXDOMAIN, relayed: %v", resp)
			}
			if got := doh.conns.Load() - before; got != 1 {
				t.Errorf("%d connections for 4 queries, want 1", got)
			}
			if p, _ := doh.proto.Load().(string); p != "HTTP/2.0" {
				t.Errorf("over %s, not HTTP/2", p)
			}
			if st := s.Status(); st.Queries[Forwarded] != 4 || st.UpstreamFailures[upstream] != 0 {
				t.Errorf("status: %+v", st)
			}
		})
	}
}

// A certificate of another name, or of a CA the resolver doesn't trust, fails the server, as one
// that is down: the next upstream answers, and none answering is SERVFAIL.
func TestEncryptedWrongCertificate(t *testing.T) {
	ca := newTestCA(t)
	other := ca.leaf(t, []string{"other.test"})
	dot, doh := newDoT(t, other), newDoH(t, other)
	_, dotPort, _ := net.SplitHostPort(dot.address)
	_, dohPort, _ := net.SplitHostPort(strings.TrimPrefix(doh.URL, "https://"))
	good := newUpstream(t)
	boot := newBootstrap(t)
	wrong := []string{"tls://up.test:" + dotPort, "https://up.test:" + dohPort + "/dns-query", "tls://127.0.0.1:" + dotPort}
	cfg, _ := testConfig(t, append(slices.Clone(wrong), good.address)...)
	cfg.Bootstrap = []string{boot.address}
	s := startWithRoots(t, cfg, ca)
	resp := query(t, s, "udp", "example.org.", dns.TypeA, nil)
	if got := answers(resp); resp.Rcode != dns.RcodeSuccess || !slices.Equal(got, []string{"example.org. A 192.0.2.53"}) {
		t.Errorf("past the wrong certificates: %v", resp)
	}
	st := s.Status()
	for _, u := range wrong {
		if st.UpstreamFailures[u] != 1 {
			t.Errorf("%s failed %d times, want 1", u, st.UpstreamFailures[u])
		}
	}
	if dot.queries.Load() != 0 || doh.queries.Load() != 0 {
		t.Error("a query was sent to a server of the wrong certificate")
	}

	// The right address, of a CA not trusted: the system's roots don't have it.
	untrusted := newDoT(t, ca.leaf(t, nil, net.ParseIP("127.0.0.1")))
	cfg, _ = testConfig(t, "tls://"+untrusted.address)
	s2 := start(t, cfg)
	if resp := query(t, s2, "udp", "example.org.", dns.TypeA, nil); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("of a CA not trusted: %v", resp)
	}
	if untrusted.queries.Load() != 0 {
		t.Error("a query was sent to a server of a CA not trusted")
	}
}

// An encrypted server that fails, as any: one of DNS over HTTPS that answers with an error, one
// of DNS over TLS that never answers; the next is asked, and each failure counts.
func TestEncryptedFailover(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.leaf(t, nil, net.ParseIP("127.0.0.1"))
	failing := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	failing.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	failing.StartTLS()
	t.Cleanup(failing.Close)
	redirecting := httptest.NewUnstartedServer(http.RedirectHandler("/elsewhere", http.StatusFound))
	redirecting.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	redirecting.StartTLS()
	t.Cleanup(redirecting.Close)
	// It takes the connection, and the query, and says nothing.
	silent, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { silent.Close() })
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(io.Discard, c)
			}()
		}
	}()
	good := newDoT(t, cert)
	upstreams := []string{failing.URL + "/dns-query", redirecting.URL + "/dns-query", "tls://" + silent.Addr().String(), "tls://" + good.address}
	cfg, _ := testConfig(t, upstreams...)
	s := startWithRoots(t, cfg, ca)
	began := time.Now()
	resp := query(t, s, "udp", "example.org.", dns.TypeA, nil)
	if got := answers(resp); resp.Rcode != dns.RcodeSuccess || !slices.Equal(got, []string{"example.org. A 192.0.2.80"}) {
		t.Errorf("past three failing: %v", resp)
	}
	// The silent one had its time, and no more.
	if took := time.Since(began); took < 400*time.Millisecond || took > 2*time.Second {
		t.Errorf("answered in %s, want the 500ms of the one that never answers", took.Round(time.Millisecond))
	}
	st := s.Status()
	for i, u := range upstreams {
		if want := uint64(1); st.UpstreamFailures[u] != want && i < 3 || i == 3 && st.UpstreamFailures[u] != 0 {
			t.Errorf("%s failed %d times", u, st.UpstreamFailures[u])
		}
	}
}

// Shutdown closes the connections kept to the upstream servers.
func TestEncryptedShutdownCloses(t *testing.T) {
	ca := newTestCA(t)
	dot := newDoT(t, ca.leaf(t, nil, net.ParseIP("127.0.0.1")))
	cfg, _ := testConfig(t, "tls://"+dot.address)
	s := startWithRoots(t, cfg, ca)
	query(t, s, "udp", "a.example.org.", dns.TypeA, nil)
	pool := s.upstreams[0].dot
	pool.mutex.Lock()
	kept := len(pool.idle[dot.address])
	pool.mutex.Unlock()
	if kept != 1 {
		t.Fatalf("%d connections kept, want 1", kept)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	pool.mutex.Lock()
	defer pool.mutex.Unlock()
	if len(pool.idle) != 0 || !pool.closed {
		t.Errorf("connections kept after the shutdown: %v", pool.idle)
	}
}

func TestPadded(t *testing.T) {
	for _, name := range []string{"a.", "example.org.", strings.Repeat("abcdefghij.", 20)} {
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		p := padded(m)
		if p.Len()%paddingBlock != 0 {
			t.Errorf("%s: %d bytes", name, p.Len())
		}
		if m.IsEdns0() != nil {
			t.Error("the query given was changed")
		}
	}
}

func TestParseServer(t *testing.T) {
	for _, c := range []struct{ in, transport, host, port, url string }{
		{"1.1.1.1:53", plainDNS, "1.1.1.1", "53", ""},
		{"tls://1.1.1.1", dnsOverTLS, "1.1.1.1", "853", ""},
		{"TLS://Dns.Example.NET:8853", dnsOverTLS, "dns.example.net", "8853", ""},
		{"https://[2606:4700::1111]/dns-query", dnsOverHTTPS, "2606:4700::1111", "443", "https://[2606:4700::1111]:443/dns-query"},
		{"https://dns.example.net:8443/a/b", dnsOverHTTPS, "dns.example.net", "8443", "https://dns.example.net:8443/a/b"},
	} {
		srv, err := parseServer(c.in)
		if err != nil || srv.transport != c.transport || srv.host != c.host || srv.port != c.port || srv.url != c.url || srv.label != c.in {
			t.Errorf("%s: %+v %v", c.in, srv, err)
		}
	}
}

// A connection kept that has gone silent, as one a firewall forgot, takes the time of its try,
// and the query is asked again on a new one, with a time of its own: it is answered.
func TestDoTSilentKeptConnection(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.leaf(t, nil, net.ParseIP("127.0.0.1"))
	inner, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inner.Close() })
	l := tls.NewListener(inner, &tls.Config{Certificates: []tls.Certificate{cert}})
	var conns atomic.Int64
	go func() {
		for {
			raw, err := l.Accept()
			if err != nil {
				return
			}
			first := conns.Add(1) == 1
			go func() {
				defer raw.Close()
				c := &dns.Conn{Conn: raw}
				for n := 0; ; n++ {
					req, err := c.ReadMsg()
					if err != nil {
						return
					}
					// The first connection answers one query, and is silent after.
					if first && n > 0 {
						continue
					}
					c.WriteMsg(encryptedAnswer(req))
				}
			}()
		}
	}()
	upstream := "tls://" + inner.Addr().String()
	cfg, _ := testConfig(t, upstream)
	s := startWithRoots(t, cfg, ca)
	if resp := query(t, s, "udp", "a.example.org.", dns.TypeA, nil); len(resp.Answer) != 1 {
		t.Fatalf("the first: %v", resp)
	}
	if resp := query(t, s, "udp", "b.example.org.", dns.TypeA, nil); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Errorf("past a kept connection gone silent: %s, after %d connections", dns.RcodeToString[resp.Rcode], conns.Load())
	}
	if st := s.Status(); st.UpstreamFailures[upstream] != 0 {
		t.Errorf("failures: %v", st.UpstreamFailures)
	}
}

// A server that takes the connection and never answers the TLS handshake is given up within the
// server's time: the dial's deadline is the handshake's too.
func TestDoTSilentHandshake(t *testing.T) {
	ca := newTestCA(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	cfg, _ := testConfig(t, "tls://"+l.Addr().String())
	s := startWithRoots(t, cfg, ca)
	began := time.Now()
	if resp := query(t, s, "udp", "a.example.org.", dns.TypeA, nil); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("of a server silent in the handshake: %s", dns.RcodeToString[resp.Rcode])
	}
	if took := time.Since(began); took > 4*s.timeout {
		t.Errorf("given up after %s, of a time of %s", took, s.timeout)
	}
}

// The clients of the encrypted upstream servers are there from New: a query that reaches a
// resolver not started, as by a socket another opened, finds them, and fails as any other.
func TestEncryptedUpstreamBeforeStart(t *testing.T) {
	for _, upstream := range []string{"tls://127.0.0.1:1", "https://127.0.0.1:1/dns-query"} {
		cfg, _ := testConfig(t, upstream)
		s, err := New(cfg, t.Errorf)
		if err != nil {
			t.Fatal(err)
		}
		s.timeout = 100 * time.Millisecond
		m := new(dns.Msg)
		m.SetQuestion("example.org.", dns.TypeA)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: a query before Start: panic: %v", upstream, r)
				}
			}()
			resp := s.respond(m, client{Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}, allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
			if resp == nil || resp.Rcode != dns.RcodeServerFailure {
				t.Errorf("%s: %v, want SERVFAIL", upstream, resp)
			}
		}()
	}
}

// An answer of DNS over HTTPS larger than a DNS message is none: it isn't read cut short.
func TestDoHAnswerTooLarge(t *testing.T) {
	ca := newTestCA(t)
	doh := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req := new(dns.Msg)
		if req.Unpack(body) != nil {
			http.Error(w, "bad message", http.StatusBadRequest)
			return
		}
		// A whole answer, and more after it, past the size.
		packed, _ := encryptedAnswer(req).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(append(packed, make([]byte, dns.MaxMsgSize)...))
	}))
	doh.EnableHTTP2 = true
	doh.TLS = &tls.Config{Certificates: []tls.Certificate{ca.leaf(t, nil, net.ParseIP("127.0.0.1"))}}
	doh.StartTLS()
	t.Cleanup(doh.Close)
	upstream := "https://" + doh.Listener.Addr().String() + "/dns-query"
	cfg, _ := testConfig(t, upstream)
	s := startWithRoots(t, cfg, ca)
	if resp := query(t, s, "udp", "a.example.org.", dns.TypeA, nil); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("an answer past %d bytes: %s, %v", dns.MaxMsgSize, dns.RcodeToString[resp.Rcode], answers(resp))
	}
	if st := s.Status(); st.UpstreamFailures[upstream] != 1 {
		t.Errorf("failures: %v", st.UpstreamFailures)
	}
}
