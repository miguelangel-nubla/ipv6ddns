package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/quic-go/quic-go"
)

// freePort is a port of 127.0.0.1 free over TCP and UDP, now.
func freePort(t *testing.T) string {
	t.Helper()
	for range 20 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(l.Addr().String())
		c, err := net.ListenPacket("udp", "127.0.0.1:"+port)
		l.Close()
		if err == nil {
			c.Close()
			return port
		}
	}
	t.Fatal("no port free over both TCP and UDP")
	return ""
}

// sharedServer is a resolver, name, with the record who.test TXT of its name, whose listener of
// its name, of the rank given, shares port over TLS and QUIC, and httpsPort over HTTPS, with a certificate of the CA
// for names. allow is of each transport's entry.
func sharedServer(t *testing.T, ca *testCA, name string, rank int, port, httpsPort, serverName string, names []string, allow map[string][]netip.Prefix) *Server {
	t.Helper()
	cfg, _ := testConfig(t)
	cfg.Name, cfg.Path = name, "resolvers."+name
	// Its plain DNS on a port free over both: a port of the system's, 0, is UDP's, and the shared
	// HTTPS port, of TCP alone, can be one.
	cfg.Listen = []listen.Entry{{Host: "127.0.0.1", Port: freePort(t)}}
	cfg.Records = append(cfg.Records, mustRecords(t, "", `who.test. TXT "`+name+`"`)...)
	certFile, keyFile := writeCertificate(t, t.TempDir(), ca.leaf(t, names))
	cert, err := certfile.Load(certFile, keyFile, false, t.Errorf)
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{TransportTLS, TransportHTTPS, TransportQUIC} {
		port := port
		if transport == TransportHTTPS {
			port = httpsPort
		}
		a := allow[transport]
		if a == nil {
			a = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
		}
		cfg.Encrypted = append(cfg.Encrypted, EncryptedListen{Transport: transport, Entry: listen.Entry{Host: "127.0.0.1", Port: port},
			Line: transport + "://127.0.0.1:" + port, Certificate: cert, CertificateName: name, Allow: a,
			Listener: name, Rank: rank, ServerName: serverName, Shared: true})
	}
	s, err := New(cfg, t.Errorf)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// sharedClient is the configuration of TLS of a client that asks name, or, of none, no name, as
// a client by address alone: which checks no certificate, as Android's opportunistic DNS.
func sharedClient(ca *testCA, name string, protocols ...string) *tls.Config {
	if name == "" {
		return &tls.Config{ServerName: "127.0.0.1", InsecureSkipVerify: true, NextProtos: protocols}
	}
	return &tls.Config{RootCAs: ca.roots, ServerName: name, NextProtos: protocols}
}

// whoOver is the TXT of who.test answered over transport at address to a client that asks name:
// the resolver's name; or, of an answer refused, "REFUSED".
func whoOver(t *testing.T, ca *testCA, transport, address, name string) string {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("who.test.", dns.TypeTXT)
	var resp *dns.Msg
	var err error
	switch transport {
	case TransportTLS:
		c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: sharedClient(ca, name, alpnTLS)}
		resp, _, err = c.Exchange(m, address)
	case TransportHTTPS:
		m.Id = 0
		wire, _ := m.Pack()
		req, _ := http.NewRequest(http.MethodPost, "https://"+address+DoHPath, bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/dns-message")
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: sharedClient(ca, name), ForceAttemptHTTP2: true}}
		var r *http.Response
		if r, err = client.Do(req); err == nil {
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			resp = new(dns.Msg)
			err = resp.Unpack(body)
		}
	case TransportQUIC:
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var conn *quic.Conn
		if conn, err = quic.DialAddr(ctx, address, sharedClient(ca, name, alpnQUIC), nil); err == nil {
			defer conn.CloseWithError(0, "")
			resp, err = queryQUIC(conn, "who.test.", dns.TypeTXT, 0)
		}
	}
	if err != nil {
		return "error: " + err.Error()
	}
	if resp.Rcode != dns.RcodeSuccess {
		return dns.RcodeToString[resp.Rcode]
	}
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			return strings.Join(txt.Txt, "")
		}
	}
	return "no answer"
}

// Two resolvers' listeners share a port over TLS, HTTPS and QUIC: a client gets the resolver of the
// listener whose certificate, or server name, is for the name it asks, with that listener's
// allow; one that asks none, or a name of neither, the first listener's. Each resolver's DDR
// tells its own name, and its status the socket it shares. Shut down, the second is no longer
// answered, and the first still is.
func TestServeShared(t *testing.T) {
	ca := newTestCA(t)
	port, httpsPort := freePort(t), freePort(t)
	// kids's HTTPS takes no client of 127.0.0.1: its allow, not lan's, answers it.
	lan := sharedServer(t, ca, "lan", 0, port, httpsPort, "", []string{"dns.lan.test"}, nil)
	kids := sharedServer(t, ca, "kids", 1, port, httpsPort, "kids.dns.local.test", []string{"dns.local.test", "*.dns.local.test"},
		map[string][]netip.Prefix{TransportHTTPS: {netip.MustParsePrefix("10.0.0.0/8")}})
	servers := []*Server{kids, lan}
	if err := Share(servers); err != nil {
		t.Fatal(err)
	}
	if err := CheckListen(servers); err != nil {
		t.Fatalf("the shared entries collide: %v", err)
	}
	// kids first, as the worker starts them by name: lan opens the sockets.
	for _, s := range servers {
		if err := s.Start(); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, s := range servers {
			s.Shutdown(context.Background())
		}
	})
	address := "127.0.0.1:" + port
	at := func(transport string) string {
		if transport == TransportHTTPS {
			return "127.0.0.1:" + httpsPort
		}
		return address
	}

	for _, c := range []struct {
		name string
		want map[string]string
	}{
		{"kids.dns.local.test", map[string]string{TransportTLS: "kids", TransportHTTPS: "REFUSED", TransportQUIC: "kids"}},
		{"KIDS.dns.local.test.", map[string]string{TransportTLS: "kids", TransportHTTPS: "REFUSED", TransportQUIC: "kids"}},
		{"dns.local.test", map[string]string{TransportTLS: "kids", TransportHTTPS: "REFUSED", TransportQUIC: "kids"}},
		{"dns.lan.test", map[string]string{TransportTLS: "lan", TransportHTTPS: "lan", TransportQUIC: "lan"}},
		{"", map[string]string{TransportTLS: "lan", TransportHTTPS: "lan", TransportQUIC: "lan"}},
	} {
		for _, transport := range []string{TransportTLS, TransportHTTPS, TransportQUIC} {
			if got := whoOver(t, ca, transport, at(transport), c.name); got != c.want[transport] {
				t.Errorf("%s, asking %q: %s, want %s", transport, c.name, got, c.want[transport])
			}
		}
	}

	// A name of neither: the first's certificate, which the client doesn't take.
	if got := whoOver(t, ca, TransportTLS, address, "other.test"); !strings.HasPrefix(got, "error: ") {
		t.Errorf("TLS, asking a name of neither: %s, want the first's certificate, refused", got)
	}

	// Each resolver's DDR, over its plain DNS: its own name, of each transport, on the port shared.
	for _, c := range []struct {
		s    *Server
		want string
	}{{lan, "dns.lan.test."}, {kids, "kids.dns.local.test."}} {
		m := new(dns.Msg)
		m.SetQuestion(ddrName, dns.TypeSVCB)
		resp, err := dns.Exchange(m, c.s.Addresses()[0])
		if err != nil {
			t.Fatal(err)
		}
		var targets []string
		for _, rr := range resp.Answer {
			svcb := rr.(*dns.SVCB)
			targets = append(targets, svcb.Target)
			if text := svcb.String(); !strings.Contains(text, `port="`+port+`"`) && !strings.Contains(text, `port="`+httpsPort+`"`) {
				t.Errorf("%s: DDR: %s without the port shared", c.s.Name(), svcb)
			}
		}
		// kids's HTTPS isn't for a client of 127.0.0.1.
		want := []string{c.want, c.want, c.want}
		if c.s == kids {
			want = want[:2]
		}
		if !slices.Equal(targets, want) {
			t.Errorf("%s: DDR targets %v, want %v", c.s.Name(), targets, want)
		}
	}

	// Each status: the sockets, which kids, too, listens on, and what it shares them with.
	for _, c := range []struct {
		s             *Server
		name, with    string
		defaultListen bool
	}{{lan, "dns.lan.test", "kids", true}, {kids, "kids.dns.local.test", "lan", false}} {
		st := c.s.Status()
		if !slices.Contains(st.Listening, "tls://"+address) || !slices.Contains(st.Listening, "quic://"+address) {
			t.Errorf("%s: listening on %v", c.s.Name(), st.Listening)
		}
		if len(st.Shared) != 3 {
			t.Fatalf("%s: shared %v, want 3", c.s.Name(), st.Shared)
		}
		for _, sh := range st.Shared {
			if sh.Listener != c.s.Name() || sh.Name != c.name || sh.Default != c.defaultListen || !slices.Equal(sh.With, []string{c.with}) {
				t.Errorf("%s: shared %+v", c.s.Name(), sh)
			}
		}
	}

	if err := kids.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{TransportTLS, TransportQUIC} {
		if got := whoOver(t, ca, transport, address, "kids.dns.local.test"); !strings.HasPrefix(got, "error: ") {
			t.Errorf("%s, of kids shut down: %s", transport, got)
		}
		if got := whoOver(t, ca, transport, address, "dns.lan.test"); got != "lan" {
			t.Errorf("%s, of lan, with kids shut down: %s", transport, got)
		}
	}
}

// The listener chosen: of a name its server name or certificate is for, the first; else the
// first of all.
func TestChoose(t *testing.T) {
	ca := newTestCA(t)
	load := func(names ...string) *certfile.Certificate {
		certFile, keyFile := writeCertificate(t, t.TempDir(), ca.leaf(t, names))
		c, err := certfile.Load(certFile, keyFile, false, t.Errorf)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	s := &Server{}
	routes := []route{
		{s, EncryptedListen{Listener: "lan", Certificate: load("dns.lan.test")}},
		{s, EncryptedListen{Listener: "kids", Certificate: load("*.kids.test"), ServerName: "a.kids.test"}},
		{s, EncryptedListen{Listener: "more", Certificate: load("*.kids.test", "more.test")}},
	}
	for _, c := range []struct{ name, want string }{
		{"", "lan"},
		{"dns.lan.test", "lan"},
		{"DNS.LAN.TEST.", "lan"},
		{"a.kids.test", "kids"},
		{"b.kids.test", "kids"},
		{"a.b.kids.test", "lan"},
		{"more.test", "more"},
		{"other.test", "lan"},
	} {
		if got := choose(routes, c.name).e.Listener; got != c.want {
			t.Errorf("%q: %s, want %s", c.name, got, c.want)
		}
	}
}

// stateWriter is a writer of DNS over TLS whose client asked a name, that keeps what is written.
type stateWriter struct {
	name string
	got  *dns.Msg
}

func (w *stateWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 853}
}
func (w *stateWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}
func (w *stateWriter) WriteMsg(m *dns.Msg) error   { w.got = m; return nil }
func (w *stateWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *stateWriter) Close() error                { return nil }
func (w *stateWriter) TsigStatus() error           { return nil }
func (w *stateWriter) TsigTimersOnly(bool)         {}
func (w *stateWriter) Hijack()                     {}
func (w *stateWriter) ConnectionState() *tls.ConnectionState {
	return &tls.ConnectionState{ServerName: w.name}
}

// A signed message or an update to a listener of a shared socket of DNS over TLS other than the
// first's is refused: the server checked its signature with the first's keys, if any.
func TestServeSharedSigned(t *testing.T) {
	ca := newTestCA(t)
	port, httpsPort := freePort(t), freePort(t)
	lan := sharedServer(t, ca, "lan", 0, port, httpsPort, "", []string{"dns.lan.test"}, nil)
	kids := sharedServer(t, ca, "kids", 1, port, httpsPort, "kids.dns.local.test", []string{"dns.local.test", "*.dns.local.test"}, nil)
	if err := Share([]*Server{lan, kids}); err != nil {
		t.Fatal(err)
	}
	h := sharedSocket(lan.shared[sharedKey(TransportTLS, "127.0.0.1:"+port)])
	if len(h) != 2 {
		t.Fatalf("got %d routes, want 2", len(h))
	}
	signed := new(dns.Msg).SetQuestion("nas.home.arpa.", dns.TypeA)
	signed.SetTsig("kids.", dns.HmacSHA256, 300, time.Now().Unix())
	signed.Extra[len(signed.Extra)-1].(*dns.TSIG).MAC = "00"
	update := new(dns.Msg).SetUpdate("home.arpa.")
	for _, c := range []struct {
		name string
		req  *dns.Msg
	}{
		{"a signed query", signed},
		{"an update", update},
	} {
		t.Run(c.name, func(t *testing.T) {
			before := kids.queries[Refused].Load()
			w := &stateWriter{name: "kids.dns.local.test"}
			h.ServeDNS(w, c.req)
			if w.got == nil || w.got.Rcode != dns.RcodeRefused {
				t.Fatalf("got %v, want REFUSED", w.got)
			}
			if kids.queries[Refused].Load() != before+1 {
				t.Error("the refusal isn't counted")
			}
		})
	}
}
