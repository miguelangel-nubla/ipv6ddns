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
	"fmt"
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
	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
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
func encryptedConfig(t *testing.T, ca *testCA, upstreams ...string) Config {
	t.Helper()
	cfg, _ := testConfig(t, upstreams...)
	for _, transport := range []string{TransportTLS, TransportHTTPS, TransportQUIC} {
		cfg.Encrypted = append(cfg.Encrypted, EncryptedListen{Transport: transport, Entry: listen.Entry{Host: "127.0.0.1", Port: "0"}, Line: transport + "://127.0.0.1:0"})
	}
	certFile, keyFile := writeCertificate(t, t.TempDir(), ca.leaf(t, []string{encryptedName}))
	setCertificate(t, &cfg, t.Errorf, false, certFile, keyFile)
	return cfg
}

// setCertificate gives cfg the certificate of the files, as the program loads one of its
// certificates: of something else's, as ACME, with managed.
func setCertificate(t *testing.T, cfg *Config, errorf func(string, ...any), managed bool, certFile, keyFile string) {
	t.Helper()
	cert, err := certfile.Load(certFile, keyFile, managed, errorf)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Certificate, cfg.CertificateName = cert, "home"
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
	if st.Certificate != "home" {
		t.Errorf("the certificate in the status: %q", st.Certificate)
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
	saved := certfile.CheckInterval
	certfile.CheckInterval = 10 * time.Millisecond
	t.Cleanup(func() { certfile.CheckInterval = saved })
	ca := newTestCA(t)
	cfg := encryptedConfig(t, ca)
	var mutex sync.Mutex
	var logged []string
	logf := func(format string, args ...any) {
		mutex.Lock()
		defer mutex.Unlock()
		logged = append(logged, format)
	}
	certFile, keyFile := writeCertificate(t, t.TempDir(), ca.leaf(t, []string{encryptedName}))
	setCertificate(t, &cfg, logf, false, certFile, keyFile)
	var s *Server
	for try := 0; ; try++ {
		var err error
		s, err = New(cfg, logf)
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
	writeCertificate(t, filepath.Dir(certFile), renewed)
	later := time.Now().Add(time.Second)
	os.Chtimes(certFile, later, later)
	time.Sleep(30 * time.Millisecond)
	if got := shown("renewed.home.arpa"); !slices.Equal(got, []string{"renewed.home.arpa"}) {
		t.Fatalf("after renewal, shown %v", got)
	}
	if st := cfg.Certificate.Status(); !slices.Equal(st.Names, []string{"renewed.home.arpa"}) {
		t.Errorf("the status: %+v", st)
	}

	os.WriteFile(certFile, []byte("not a certificate"), 0o600)
	later = later.Add(time.Second)
	os.Chtimes(certFile, later, later)
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
	if st := cfg.Certificate.Status(); st.Error == "" {
		t.Errorf("the status doesn't tell the error: %+v", st)
	}
}

// Encrypted entries without a certificate stop the start, with the setting to fix.
func TestEncryptedStartWithoutCertificate(t *testing.T) {
	cfg := encryptedConfig(t, newTestCA(t))
	cfg.Certificate = nil
	s, err := New(cfg, t.Errorf)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err == nil || !strings.Contains(err.Error(), "resolvers.lan: no certificate for ") {
		t.Errorf("started: %v", err)
	}
}

// After Shutdown, nothing answers over the encrypted transports, and their sockets are closed:
// the UDP one of DNS over QUIC too, which another can then listen on.
func TestEncryptedShutdown(t *testing.T) {
	ca := newTestCA(t)
	s := start(t, encryptedConfig(t, ca))
	quicAddress := addressOf(t, s, TransportQUIC)
	conn := dialQUIC(t, ca, quicAddress)
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
	pc, err := net.ListenPacket("udp4", quicAddress)
	if err != nil {
		t.Fatalf("the UDP socket of DNS over QUIC is still open: %v", err)
	}
	pc.Close()
}

// An answer past 65535 bytes, the most its two bytes of length can say, is truncated over DNS over
// QUIC, as over TCP and DNS over TLS: not sent with a length that isn't its own.
func TestServeQUICAnswerTooLarge(t *testing.T) {
	ca := newTestCA(t)
	cfg := encryptedConfig(t, ca)
	for i := range 330 {
		cfg.Records = append(cfg.Records, mustRecords(t, "", fmt.Sprintf(`huge.example.com. TXT "%03d %s"`, i, strings.Repeat("x", 200)))...)
	}
	s := start(t, cfg)
	conn := dialQUIC(t, ca, addressOf(t, s, TransportQUIC))
	resp, err := queryQUIC(conn, "huge.example.com.", dns.TypeTXT, 0)
	if err != nil {
		t.Fatalf("DNS over QUIC: %v", err)
	}
	if !resp.Truncated || len(resp.Answer) == 0 || len(resp.Answer) >= 330 {
		t.Errorf("DNS over QUIC: truncated %t, %d records of 330", resp.Truncated, len(resp.Answer))
	}
	if resp, err := queryTLS(t, ca, addressOf(t, s, TransportTLS), "huge.example.com.", dns.TypeTXT); err != nil || !resp.Truncated {
		t.Errorf("DNS over TLS: %v, %v", resp, err)
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
	certFile, keyFile := writeCertificate(t, t.TempDir(), ca.leaf(t, []string{encryptedName}, net.ParseIP("127.0.0.1")))
	setCertificate(t, &cfg, t.Errorf, false, certFile, keyFile)
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

// A certificate that something else writes, as ACME: the resolver starts without it, refusing
// the encrypted connections, and shows it once its files are written.
func TestEncryptedManagedCertificate(t *testing.T) {
	saved := certfile.CheckInterval
	certfile.CheckInterval = 10 * time.Millisecond
	t.Cleanup(func() { certfile.CheckInterval = saved })
	ca := newTestCA(t)
	cfg := encryptedConfig(t, ca)
	dir := t.TempDir()
	setCertificate(t, &cfg, t.Errorf, true, filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"))
	s := start(t, cfg)
	address := addressOf(t, s, TransportTLS)
	if _, err := queryTLS(t, ca, address, "printer.home.arpa.", dns.TypeA); err == nil {
		t.Fatal("answered over TLS without a certificate")
	}
	if st := cfg.Certificate.Status(); !st.Managed || len(st.Names) != 0 || st.Error != "" {
		t.Errorf("the status without a certificate: %+v", st)
	}
	writeCertificate(t, dir, ca.leaf(t, []string{encryptedName}))
	time.Sleep(30 * time.Millisecond)
	if resp, err := queryTLS(t, ca, address, "printer.home.arpa.", dns.TypeA); err != nil || len(resp.Answer) != 2 {
		t.Fatalf("once written: %v, %v", resp, err)
	}
	if st := cfg.Certificate.Status(); !slices.Equal(st.Names, []string{encryptedName}) {
		t.Errorf("the status once written: %+v", st)
	}
}

// More of DNS over HTTPS: a body past the largest message is 413; a response, which is no query,
// 400; and a GET with the padding of base64, which RFC 8484 leaves out, is answered still.
func TestServeHTTPSMessages(t *testing.T) {
	ca := newTestCA(t)
	s := start(t, encryptedConfig(t, ca))
	url := "https://" + addressOf(t, s, TransportHTTPS) + DoHPath
	client := httpsClient(ca)
	do := func(req *http.Request) (int, []byte) {
		t.Helper()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}
	post := func(body []byte) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/dns-message")
		code, _ := do(req)
		return code
	}
	if code := post(make([]byte, dns.MaxMsgSize+1)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("a body too large: %d", code)
	}
	response := new(dns.Msg)
	response.SetQuestion("printer.home.arpa.", dns.TypeA)
	response.Response = true
	wire, _ := response.Pack()
	if code := post(wire); code != http.StatusBadRequest {
		t.Errorf("a response: %d", code)
	}

	query := new(dns.Msg)
	query.SetQuestion("printer.home.arpa.", dns.TypeA)
	query.Id = 0
	// A header of 12 bytes and a question of 23: 35, which base64 pads with "=".
	wire, _ = query.Pack()
	padded := base64.URLEncoding.EncodeToString(wire)
	if !strings.HasSuffix(padded, "=") {
		t.Fatalf("no padding: %s", padded)
	}
	req, _ := http.NewRequest(http.MethodGet, url+"?dns="+padded, nil)
	code, body := do(req)
	answer := new(dns.Msg)
	if code != http.StatusOK || answer.Unpack(body) != nil || len(answer.Answer) != 2 {
		t.Errorf("a GET with padding: %d, %v", code, answer)
	}
}

// More of DNS over QUIC: a response, which is no query, closes the connection with the protocol's
// error; a stream that ends before the length it gave is reset, and the connection answers on.
func TestServeQUICMessages(t *testing.T) {
	ca := newTestCA(t)
	s := start(t, encryptedConfig(t, ca))
	address := addressOf(t, s, TransportQUIC)

	conn := dialQUIC(t, ca, address)
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	// 100 bytes said, 10 sent.
	stream.Write(append([]byte{0, 100}, make([]byte, 10)...))
	stream.Close()
	if _, err := io.ReadAll(stream); err == nil {
		t.Error("a short stream was answered")
	}
	if resp, err := queryQUIC(conn, "printer.home.arpa.", dns.TypeA, 0); err != nil || len(resp.Answer) != 2 {
		t.Errorf("the connection after a short stream: %v, %v", resp, err)
	}

	conn = dialQUIC(t, ca, address)
	stream, err = conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	response := new(dns.Msg)
	response.SetQuestion("printer.home.arpa.", dns.TypeA)
	response.Id, response.Response = 0, true
	wire, _ := response.Pack()
	stream.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...))
	stream.Close()
	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the connection is still open after a response")
	}
	var appErr *quic.ApplicationError
	if err := context.Cause(conn.Context()); !errors.As(err, &appErr) || appErr.ErrorCode != quic.ApplicationErrorCode(doqProtocolError) {
		t.Errorf("closed with %v, want the protocol error of DNS over QUIC", err)
	}
}

// A resolver without upstream servers, which the configuration doesn't allow, still answers a
// name not its own: SERVFAIL, over every transport, rather than nothing.
func TestServeWithoutUpstream(t *testing.T) {
	ca := newTestCA(t)
	s := start(t, encryptedConfig(t, ca))
	if _, answer := queryHTTPS(t, ca, addressOf(t, s, TransportHTTPS), http.MethodPost, "elsewhere.example.", dns.TypeA); answer.Rcode != dns.RcodeServerFailure {
		t.Errorf("DNS over HTTPS: %s", dns.RcodeToString[answer.Rcode])
	}
	if resp := query(t, s, "udp", "elsewhere.example.", dns.TypeA, nil); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("plain DNS: %s", dns.RcodeToString[resp.Rcode])
	}
}

// An answer larger than the HTTP server's buffer, of 4 KB, as a name signed with ML-DSA-44 has:
// its length is said, which clients read the body by, as dig: without it, Go streams the body,
// and dig took it for a message shorter than its header.
func TestServeHTTPSLargeAnswer(t *testing.T) {
	ca := newTestCA(t)
	cfg := encryptedConfig(t, ca)
	for i := range 40 {
		cfg.Records = append(cfg.Records, mustRecords(t, "", fmt.Sprintf(`big.example.com. TXT "%03d %s"`, i, strings.Repeat("x", 200)))...)
	}
	s := start(t, cfg)
	checkLargeHTTPS(t, ca, addressOf(t, s, TransportHTTPS), "big.example.com.", 40)
}

// checkLargeHTTPS asks name's TXT records of DNS over HTTPS, by GET and by POST, over HTTP/2 and
// HTTP/1.1, and checks each answer: records of it, its body past 4 KB, and its length said, the
// body's exactly.
func checkLargeHTTPS(t *testing.T, ca *testCA, address, name string, records int) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)
	m.SetEdns0(1232, true)
	m.Id = 0
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	url := "https://" + address + DoHPath
	for _, protocol := range []string{"h2", "http/1.1"} {
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS(ca, protocol), ForceAttemptHTTP2: protocol == "h2"}}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			var req *http.Request
			if method == http.MethodGet {
				req, _ = http.NewRequest(method, url+"?dns="+base64.RawURLEncoding.EncodeToString(wire), nil)
			} else {
				req, _ = http.NewRequest(method, url, bytes.NewReader(wire))
				req.Header.Set("Content-Type", "application/dns-message")
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s, %s: %v", protocol, method, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			what := fmt.Sprintf("%s, %s", resp.Proto, method)
			answer := new(dns.Msg)
			switch {
			case resp.StatusCode != http.StatusOK:
				t.Errorf("%s: %s", what, resp.Status)
			case answer.Unpack(body) != nil || len(answer.Answer) != records:
				t.Errorf("%s: %d records of %d bytes, want %d", what, len(answer.Answer), len(body), records)
			case len(body) <= 4096:
				t.Errorf("%s: a body of %d bytes, which the test wants past 4096", what, len(body))
			case resp.ContentLength != int64(len(body)):
				t.Errorf("%s: the length said is %d, the body's %d", what, resp.ContentLength, len(body))
			}
		}
	}
}

// An answer of the upstream past 8 KB, as of a name signed with ML-DSA-44, which the upstream
// truncates over UDP and gives over TCP: the resolver asks it again over TCP, and gives it whole
// over each transport that carries it, DNS over HTTPS with its length; over UDP, it is truncated,
// for the client to ask over TCP. As dnscheck.tools found, of DNS over HTTPS.
func TestServeLargeForwardedAnswer(t *testing.T) {
	up := newUpstream(t)
	up.truncate.Store(true)
	up.long.Store(true)
	ca := newTestCA(t)
	s := start(t, encryptedConfig(t, ca, up.address))
	const name = "pq.example.net."

	checkLargeHTTPS(t, ca, addressOf(t, s, TransportHTTPS), name, 40)

	resp, err := queryTLS(t, ca, addressOf(t, s, TransportTLS), name, dns.TypeTXT)
	if err != nil || len(resp.Answer) != 40 {
		t.Errorf("DNS over TLS: %v, %v", resp, err)
	}
	conn := dialQUIC(t, ca, addressOf(t, s, TransportQUIC))
	if resp, err := queryQUIC(conn, name, dns.TypeTXT, 0); err != nil || len(resp.Answer) != 40 {
		t.Errorf("DNS over QUIC: %v, %v", resp, err)
	}
	if resp := query(t, s, "tcp", name, dns.TypeTXT, nil); len(resp.Answer) != 40 {
		t.Errorf("over TCP: %d records", len(resp.Answer))
	}
	// Measured compressed, as it was sent: the client's copy isn't.
	if resp := query(t, s, "udp", name, dns.TypeTXT, func(m *dns.Msg) { m.SetEdns0(1232, true) }); !resp.Truncated || func() int { resp.Compress = true; return resp.Len() }() > 1232 {
		t.Errorf("over UDP: truncated %v, %d bytes", resp.Truncated, resp.Len())
	}
}

// An HTTPS entry with a web server: /dns-query is DNS, by GET and by POST, and every other path
// the web server's that SetWeb gave by the entry's Web; an entry without one answers those 404.
func TestServeHTTPSShared(t *testing.T) {
	ca := newTestCA(t)
	web := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "web: %s", r.URL.Path) })
	for _, c := range []struct {
		what, web string
		want      int
	}{
		{"shared", "main", http.StatusOK},
		{"not shared", "", http.StatusNotFound},
		{"of a web server not given", "other", http.StatusNotFound},
	} {
		t.Run(c.what, func(t *testing.T) {
			cfg := encryptedConfig(t, ca)
			for i := range cfg.Encrypted {
				if cfg.Encrypted[i].Transport == TransportHTTPS {
					cfg.Encrypted[i].Web = c.web
				}
			}
			s := startWith(t, cfg, func(s *Server) { s.SetWeb("main", web) })
			address := addressOf(t, s, TransportHTTPS)
			for _, path := range []string{"/", "/status.json"} {
				resp, err := httpsClient(ca).Get("https://" + address + path)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != c.want || c.want == http.StatusOK && string(body) != "web: "+path {
					t.Errorf("%s: %d %q, want %d", path, resp.StatusCode, body, c.want)
				}
			}
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				if _, answer := queryHTTPS(t, ca, address, method, "printer.home.arpa.", dns.TypeA); len(answer.Answer) != 2 {
					t.Errorf("DNS over HTTPS, %s: %v", method, answer)
				}
			}
		})
	}
}

// Each socket answers the clients of its entry's allow, a listener's: the resolver's own allow,
// when given, replaces it; without either, the networks listened on. Over every transport.
func TestServeSocketAllow(t *testing.T) {
	ca := newTestCA(t)
	elsewhere := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	here := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	for _, c := range []struct {
		what         string
		entry, own   []netip.Prefix
		wantAnswered bool
	}{
		{"the entry's allow lets the client in", here, nil, true},
		{"the entry's allow keeps the client out", elsewhere, nil, false},
		{"the resolver's own replaces the entry's", elsewhere, here, true},
		{"the resolver's own keeps out whom the entry's lets in", here, elsewhere, false},
	} {
		t.Run(c.what, func(t *testing.T) {
			cfg := encryptedConfig(t, ca)
			cfg.Allow = c.own
			cfg.ListenAllow = make([][]netip.Prefix, len(cfg.Listen))
			for i := range cfg.Listen {
				cfg.ListenAllow[i] = c.entry
			}
			for i := range cfg.Encrypted {
				cfg.Encrypted[i].Allow = c.entry
			}
			s := start(t, cfg)
			check := func(transport string, resp *dns.Msg) {
				t.Helper()
				if answered := resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 2; answered != c.wantAnswered {
					t.Errorf("%s: %s with %d answers, want answered %t", transport, dns.RcodeToString[resp.Rcode], len(resp.Answer), c.wantAnswered)
				}
			}
			for _, network := range []string{"udp", "tcp"} {
				check(network, query(t, s, network, "printer.home.arpa.", dns.TypeA, nil))
			}
			resp, err := queryTLS(t, ca, addressOf(t, s, TransportTLS), "printer.home.arpa.", dns.TypeA)
			if err != nil {
				t.Fatal(err)
			}
			check(TransportTLS, resp)
			_, resp = queryHTTPS(t, ca, addressOf(t, s, TransportHTTPS), http.MethodPost, "printer.home.arpa.", dns.TypeA)
			check(TransportHTTPS, resp)
		})
	}
}
