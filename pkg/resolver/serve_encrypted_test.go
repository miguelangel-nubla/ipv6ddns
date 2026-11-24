package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/quic-go/quic-go"
)

const encryptedName = "dns.home.arpa"

// writeCertificate writes the certificate and its key as PEM files in dir, and returns their paths.
func writeCertificate(t *testing.T, dir string, cert tls.Certificate) (certFile, keyFile string) {
	t.Helper()
	certFile, keyFile = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// encryptedConfig is testConfig, answering also over TLS, HTTPS and QUIC on 127.0.0.1, with a
// certificate of the CA for encryptedName.
func encryptedConfig(t *testing.T, ca *testCA) Config {
	t.Helper()
	cfg, _ := testConfig(t)
	for _, transport := range []string{TransportTLS, TransportHTTPS, TransportQUIC} {
		cfg.Encrypted = append(cfg.Encrypted, EncryptedListen{Transport: transport, Entry: listen.Entry{Host: "127.0.0.1", Port: "0"}, Line: transport + "://127.0.0.1:0"})
	}
	cfg.CertFile, cfg.KeyFile = writeCertificate(t, t.TempDir(), ca.leaf(t, []string{encryptedName}))
	return cfg
}

// addressOf is the address s listens on over transport, host:port, without its scheme.
func addressOf(t *testing.T, s *Server, transport string) string {
	t.Helper()
	for _, a := range s.Addresses() {
		if after, ok := strings.CutPrefix(a, transport+"://"); ok {
			return after
		}
	}
	t.Fatalf("no address over %s in %v", transport, s.Addresses())
	return ""
}

func clientTLS(ca *testCA, protocols ...string) *tls.Config {
	return &tls.Config{RootCAs: ca.roots, ServerName: encryptedName, NextProtos: protocols}
}

// queryTLS asks over DNS over TLS.
func queryTLS(t *testing.T, ca *testCA, address, name string, qtype uint16) (*dns.Msg, error) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	c := &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: clientTLS(ca, alpnTLS)}
	resp, _, err := c.Exchange(m, address)
	return resp, err
}

// httpsClient is a client of HTTP/2 that trusts the CA.
func httpsClient(ca *testCA) *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS(ca), ForceAttemptHTTP2: true}}
}

// queryHTTPS asks over DNS over HTTPS, by POST or by GET, and returns the response with its answer.
func queryHTTPS(t *testing.T, ca *testCA, address, method, name string, qtype uint16) (*http.Response, *dns.Msg) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Id = 0
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	url := "https://" + address + DoHPath
	var req *http.Request
	if method == http.MethodGet {
		req, _ = http.NewRequest(method, url+"?dns="+base64.RawURLEncoding.EncodeToString(wire), nil)
	} else {
		req, _ = http.NewRequest(method, url, bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/dns-message")
	}
	resp, err := httpsClient(ca).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, name, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: %s: %s", method, name, resp.Status, body)
	}
	answer := new(dns.Msg)
	if err := answer.Unpack(body); err != nil {
		t.Fatalf("%s %s: the body isn't a DNS message: %v", method, name, err)
	}
	return resp, answer
}

// dialQUIC connects to the server over DNS over QUIC.
func dialQUIC(t *testing.T, ca *testCA, address string) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, address, clientTLS(ca, alpnQUIC), nil)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	return conn
}

// queryQUIC asks on a stream of its own of conn, with the ID given.
func queryQUIC(conn *quic.Conn, name string, qtype uint16, id uint16) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Id = id
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
	if _, err := stream.Write(append(out, wire...)); err != nil {
		return nil, err
	}
	stream.Close()
	var length [2]byte
	if _, err := io.ReadFull(stream, length[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(stream, body); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	return resp, resp.Unpack(body)
}

// The resolver answers over DNS over TLS, over HTTPS, by GET and by POST over HTTP/2, and over
// QUIC, what it answers over plain DNS, of its zones, and DNS over HTTPS lets it be kept for its
// TTL, a minute for these records. Each transport says
// its application protocol, and the status has its addresses, with their scheme, and the
// certificate.
func TestServeEncrypted(t *testing.T) {
	ca := newTestCA(t)
	s := start(t, encryptedConfig(t, ca))
	want := []string{"printer.home.arpa. A 192.168.1.20", "printer.home.arpa. A 192.168.1.21"}
	sorted := func(resp *dns.Msg) []string { return slices.Sorted(slices.Values(answers(resp))) }

	resp, err := queryTLS(t, ca, addressOf(t, s, TransportTLS), "printer.home.arpa.", dns.TypeA)
	if err != nil {
		t.Fatalf("DNS over TLS: %v", err)
	}
	if got := sorted(resp); !slices.Equal(got, want) {
		t.Errorf("DNS over TLS: %v", got)
	}

	for _, method := range []string{http.MethodPost, http.MethodGet} {
		r, answer := queryHTTPS(t, ca, addressOf(t, s, TransportHTTPS), method, "printer.home.arpa.", dns.TypeA)
		if got := sorted(answer); !slices.Equal(got, want) {
			t.Errorf("DNS over HTTPS, %s: %v", method, got)
		}
		if r.ProtoMajor != 2 || r.Header.Get("Content-Type") != "application/dns-message" || r.Header.Get("Cache-Control") != "max-age=60" {
			t.Errorf("DNS over HTTPS, %s: %s, %q, %q", method, r.Proto, r.Header.Get("Content-Type"), r.Header.Get("Cache-Control"))
		}
	}

	conn := dialQUIC(t, ca, addressOf(t, s, TransportQUIC))
	if p := conn.ConnectionState().TLS.NegotiatedProtocol; p != alpnQUIC {
		t.Errorf("DNS over QUIC: the protocol %q", p)
	}
	// Two queries at once, each on its stream, of one connection.
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			resp, err := queryQUIC(conn, "printer.home.arpa.", dns.TypeA, 0)
			if err != nil {
				t.Errorf("DNS over QUIC: %v", err)
				return
			}
			if got := sorted(resp); !slices.Equal(got, want) {
				t.Errorf("DNS over QUIC: %v", got)
			}
		})
	}
	wg.Wait()

	st := s.Status()
	for _, transport := range []string{TransportTLS, TransportHTTPS, TransportQUIC} {
		if !slices.ContainsFunc(st.Listening, func(a string) bool { return strings.HasPrefix(a, transport+"://127.0.0.1:") }) {
			t.Errorf("the status listens on %v, without %s", st.Listening, transport)
		}
	}
	if st.Certificate == nil || !slices.Equal(st.Certificate.Names, []string{encryptedName}) || st.Certificate.NotAfter.Before(time.Now()) {
		t.Errorf("the certificate in the status: %+v", st.Certificate)
	}
	if n := st.Queries[Local]; n < 5 {
		t.Errorf("%d local answers counted, want the 5 of the encrypted transports at least", n)
	}
}

// What isn't a query of DNS over HTTPS is answered with the status of HTTP that tells why.
func TestServeHTTPSErrors(t *testing.T) {
	ca := newTestCA(t)
	s := start(t, encryptedConfig(t, ca))
	base := "https://" + addressOf(t, s, TransportHTTPS)
	client := httpsClient(ca)
	for _, tc := range []struct {
		name, method, url, contentType, body string
		want                                 int
	}{
		{"another path", http.MethodGet, base + "/other?dns=AAAB", "", "", http.StatusNotFound},
		{"no dns parameter", http.MethodGet, base + DoHPath, "", "", http.StatusBadRequest},
		{"not base64url", http.MethodGet, base + DoHPath + "?dns=!!", "", "", http.StatusBadRequest},
		{"not a message", http.MethodPost, base + DoHPath, "application/dns-message", "nonsense", http.StatusBadRequest},
		{"another content type", http.MethodPost, base + DoHPath, "application/json", "{}", http.StatusUnsupportedMediaType},
		{"another method", http.MethodPut, base + DoHPath, "application/dns-message", "", http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("%s, want %d", resp.Status, tc.want)
			}
		})
	}
}

// A query of DNS over QUIC with an ID other than 0 breaks RFC 9250: the connection is closed, with
// the protocol's error.
func TestServeQUICProtocolError(t *testing.T) {
	ca := newTestCA(t)
	s := start(t, encryptedConfig(t, ca))
	conn := dialQUIC(t, ca, addressOf(t, s, TransportQUIC))
	if _, err := queryQUIC(conn, "printer.home.arpa.", dns.TypeA, 7); err == nil {
		t.Fatal("answered a query with the ID 7")
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the connection is still open")
	}
	var appErr *quic.ApplicationError
	if err := context.Cause(conn.Context()); !errors.As(err, &appErr) || appErr.ErrorCode != quic.ApplicationErrorCode(doqProtocolError) {
		t.Errorf("closed with %v, want the protocol error of DNS over QUIC", err)
	}
}

// A client of no network it allows is refused over every transport, as over plain DNS.
func TestServeEncryptedRefused(t *testing.T) {
	ca := newTestCA(t)
	cfg := encryptedConfig(t, ca)
	cfg.Allow = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	s := start(t, cfg)
	resp, err := queryTLS(t, ca, addressOf(t, s, TransportTLS), "printer.home.arpa.", dns.TypeA)
	if err != nil || resp.Rcode != dns.RcodeRefused {
		t.Errorf("DNS over TLS: %v, %v", resp, err)
	}
	if _, answer := queryHTTPS(t, ca, addressOf(t, s, TransportHTTPS), http.MethodPost, "printer.home.arpa.", dns.TypeA); answer.Rcode != dns.RcodeRefused {
		t.Errorf("DNS over HTTPS: %s", dns.RcodeToString[answer.Rcode])
	}
	conn := dialQUIC(t, ca, addressOf(t, s, TransportQUIC))
	if resp, err := queryQUIC(conn, "printer.home.arpa.", dns.TypeA, 0); err != nil || resp.Rcode != dns.RcodeRefused {
		t.Errorf("DNS over QUIC: %v, %v", resp, err)
	}
}

// The DoH answer of a name that doesn't exist is kept as long as the SOA says; a refusal, not.
func TestFreshness(t *testing.T) {
	m := new(dns.Msg)
	m.SetRcode(new(dns.Msg), dns.RcodeNameError)
	m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Rrtype: dns.TypeSOA, Ttl: 300}, Minttl: 60}}
	if got := freshness(m); got != 60 {
		t.Errorf("no such name: %d, want the SOA's minimum, 60", got)
	}
	m.Rcode = dns.RcodeRefused
	if got := freshness(m); got != 0 {
		t.Errorf("refused: %d", got)
	}
}

// A renewed certificate, written over the files, is shown to the next client without a restart.
// Files that don't read keep the one before, and the log says it once.
func TestEncryptedCertificateReload(t *testing.T) {
	saved := certificateCheck
	certificateCheck = 10 * time.Millisecond
	t.Cleanup(func() { certificateCheck = saved })
	ca := newTestCA(t)
	cfg := encryptedConfig(t, ca)
	var mutex sync.Mutex
	var logged []string
	var s *Server
	for try := 0; ; try++ {
		var err error
		s, err = New(cfg, func(format string, args ...any) {
			mutex.Lock()
			defer mutex.Unlock()
			logged = append(logged, format)
		})
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Start(); err == nil {
			break
		}
		if try == 5 {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { s.Shutdown(context.Background()) })
	address := addressOf(t, s, TransportTLS)
	shown := func(name string) []string {
		t.Helper()
		conn, err := tls.Dial("tcp", address, &tls.Config{RootCAs: ca.roots, ServerName: name})
		if err != nil {
			t.Fatalf("dial for %s: %v", name, err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].DNSNames
	}
	if got := shown(encryptedName); !slices.Equal(got, []string{encryptedName}) {
		t.Fatalf("shown %v", got)
	}

	renewed := ca.leaf(t, []string{"renewed.home.arpa"})
	writeCertificate(t, filepath.Dir(cfg.CertFile), renewed)
	later := time.Now().Add(time.Second)
	os.Chtimes(cfg.CertFile, later, later)
	time.Sleep(30 * time.Millisecond)
	if got := shown("renewed.home.arpa"); !slices.Equal(got, []string{"renewed.home.arpa"}) {
		t.Fatalf("after renewal, shown %v", got)
	}
	if st := s.Status().Certificate; st == nil || !slices.Equal(st.Names, []string{"renewed.home.arpa"}) {
		t.Errorf("the status: %+v", st)
	}

	os.WriteFile(cfg.CertFile, []byte("not a certificate"), 0o600)
	later = later.Add(time.Second)
	os.Chtimes(cfg.CertFile, later, later)
	for range 3 {
		time.Sleep(30 * time.Millisecond)
		if got := shown("renewed.home.arpa"); !slices.Equal(got, []string{"renewed.home.arpa"}) {
			t.Fatalf("after a broken file, shown %v", got)
		}
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(logged) != 1 || !strings.Contains(logged[0], "doesn't read again") {
		t.Errorf("logged %q, want once", logged)
	}
	if st := s.Status().Certificate; st == nil || st.Error == "" {
		t.Errorf("the status doesn't tell the error: %+v", st)
	}
}

// A certificate that doesn't read stops the start, with the setting to fix.
func TestEncryptedStartWithoutCertificate(t *testing.T) {
	cfg := encryptedConfig(t, newTestCA(t))
	cfg.CertFile = filepath.Join(t.TempDir(), "missing.pem")
	s, err := New(cfg, t.Errorf)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err == nil || !strings.Contains(err.Error(), "resolvers.lan.tls_certificate") {
		t.Errorf("started: %v", err)
	}
}

// After Shutdown, nothing answers over the encrypted transports.
func TestEncryptedShutdown(t *testing.T) {
	ca := newTestCA(t)
	s := start(t, encryptedConfig(t, ca))
	conn := dialQUIC(t, ca, addressOf(t, s, TransportQUIC))
	tlsAddress, httpsAddress := addressOf(t, s, TransportTLS), addressOf(t, s, TransportHTTPS)
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{tlsAddress, httpsAddress} {
		if c, err := net.DialTimeout("tcp", a, time.Second); err == nil {
			c.Close()
			t.Errorf("%s still listens", a)
		}
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Error("the connection of DNS over QUIC stays open")
	}
}

// Two resolvers can share an address and port over different protocols, not over the same.
func TestCheckListenProtocols(t *testing.T) {
	server := func(name string, plain []listen.Entry, encrypted ...EncryptedListen) *Server {
		return &Server{config: Config{Name: name, Path: "resolvers." + name, Listen: plain, Encrypted: encrypted}}
	}
	at := listen.Entry{Host: "127.0.0.1", Port: "853"}
	tlsAt := EncryptedListen{Transport: TransportTLS, Entry: at, Line: "tls://127.0.0.1"}
	quicAt := EncryptedListen{Transport: TransportQUIC, Entry: at, Line: "quic://127.0.0.1"}
	httpsAt := EncryptedListen{Transport: TransportHTTPS, Entry: at, Line: "https://127.0.0.1:853"}
	if err := CheckListen([]*Server{server("a", nil, tlsAt), server("b", nil, quicAt)}); err != nil {
		t.Errorf("TLS and QUIC on one port: %v", err)
	}
	if err := CheckListen([]*Server{server("a", nil, tlsAt), server("b", nil, httpsAt)}); err == nil || !strings.Contains(err.Error(), "tls://127.0.0.1") {
		t.Errorf("TLS and HTTPS, both TCP, on one port: %v", err)
	}
	if err := CheckListen([]*Server{server("a", []listen.Entry{at}), server("b", nil, quicAt)}); err == nil {
		t.Error("plain DNS and QUIC, both UDP, on one port")
	}
}

// A resolver is the upstream of another over DNS over TLS and over HTTPS: the client this package
// has for its own upstream servers agrees with the server.
func TestServeEncryptedAsUpstream(t *testing.T) {
	ca := newTestCA(t)
	cfg := encryptedConfig(t, ca)
	cfg.CertFile, cfg.KeyFile = writeCertificate(t, t.TempDir(), ca.leaf(t, []string{encryptedName}, net.ParseIP("127.0.0.1")))
	upstream := start(t, cfg)
	for _, via := range []string{
		"tls://" + addressOf(t, upstream, TransportTLS),
		"https://" + addressOf(t, upstream, TransportHTTPS) + DoHPath,
	} {
		t.Run(strings.SplitN(via, ":", 2)[0], func(t *testing.T) {
			downstream, _ := testConfig(t, via)
			downstream.Zones = nil
			downstream.Records = nil
			s := startWith(t, downstream, func(s *Server) { s.roots = ca.roots })
			resp := query(t, s, "udp", "printer.home.arpa.", dns.TypeA, nil)
			if got := slices.Sorted(slices.Values(answers(resp))); !slices.Equal(got, []string{"printer.home.arpa. A 192.168.1.20", "printer.home.arpa. A 192.168.1.21"}) {
				t.Errorf("through %s: %v, %s", via, got, dns.RcodeToString[resp.Rcode])
			}
		})
	}
}
