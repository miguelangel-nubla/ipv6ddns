//go:build linux && integration

package main

// The resolver's encrypted upstream servers, its cache, and two on one address, as the command
// runs them, asked by dig.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// liveCA is a certificate authority of the test's: the command trusts it when SSL_CERT_FILE names
// its file.
type liveCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	// Its certificate, in PEM, in a file.
	file string
}

func newLiveCA(t *testing.T, name string) *liveCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), name+".pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return &liveCA{cert: cert, key: key, file: file}
}

// leaf is a server's certificate of the authority, for host names and addresses.
func (ca *liveCA) leaf(t *testing.T, names []string, ips ...net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "a server of the test's"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: names, IPAddresses: ips, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// encryptedUpstream is a server of DNS over TLS and one of DNS over HTTPS, at /dns-query, of the
// test's on a machine, with one certificate: each answers every A query with its own address.
type encryptedUpstream struct {
	// The queries each answered, and the connections each took.
	dot, doh           atomic.Int64
	dotConns, dohConns atomic.Int64
	// The protocol of the last request over HTTPS.
	proto atomic.Value
	// A query that came without its padding.
	unpadded atomic.Int64
}

// The answers of the encrypted servers: over TLS, and over HTTPS.
const (
	dotAnswer = "192.0.2.61"
	dohAnswer = "192.0.2.62"
)

// countedListener counts the connections taken.
type countedListener struct {
	net.Listener
	n *atomic.Int64
}

func (l countedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func startEncrypted(t *testing.T, m *livetest.Machine, cert tls.Certificate, dotPort, dohPort string) *encryptedUpstream {
	t.Helper()
	e := &encryptedUpstream{}
	answer := func(req *dns.Msg, address string) *dns.Msg {
		// Padded to 128 bytes, as it came.
		if req.Len()%128 != 0 {
			e.unpadded.Add(1)
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		if q := req.Question[0]; q.Qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP(address)})
		}
		if opt := req.IsEdns0(); opt != nil {
			resp.SetEdns0(opt.UDPSize(), opt.Do())
		}
		return resp
	}

	l, err := m.Listen("tcp4", net.JoinHostPort(m.IPv4.String(), dotPort))
	if err != nil {
		t.Fatal(err)
	}
	overTLS := &dns.Server{
		Listener: tls.NewListener(countedListener{l, &e.dotConns}, &tls.Config{Certificates: []tls.Certificate{cert}}),
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			e.dot.Add(1)
			w.WriteMsg(answer(req, dotAnswer))
		}),
		IdleTimeout: func() time.Duration { return time.Minute },
	}
	go overTLS.ActivateAndServe()
	t.Cleanup(func() { overTLS.Shutdown() })

	l, err = m.Listen("tcp4", net.JoinHostPort(m.IPv4.String(), dohPort))
	if err != nil {
		t.Fatal(err)
	}
	overHTTPS := &http.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		ErrorLog:  log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e.proto.Store(r.Proto)
			if r.Method != http.MethodPost || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != "application/dns-message" {
				http.Error(w, "a POST of application/dns-message at /dns-query", http.StatusBadRequest)
				return
			}
			body, _ := io.ReadAll(r.Body)
			req := new(dns.Msg)
			if err := req.Unpack(body); err != nil || len(req.Question) != 1 {
				http.Error(w, "no DNS message", http.StatusBadRequest)
				return
			}
			e.doh.Add(1)
			packed, _ := answer(req, dohAnswer).Pack()
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(packed)
		}),
	}
	go overHTTPS.ServeTLS(countedListener{l, &e.dohConns}, "", "")
	t.Cleanup(func() { overHTTPS.Close() })
	return e
}

// Upstream servers of DNS over TLS and over HTTPS, on another machine, with a certificate of an
// authority the command is told to trust, for a host name that the bootstrap server gives, and
// for the machine's address: the queries go there, on one connection, and nowhere else. One with
// a certificate of another name, or of an authority not trusted, is passed over, for the next.
func TestLiveResolverEncrypted(t *testing.T) {
	if _, err := exec.LookPath("dig"); err != nil {
		t.Fatal("the live tests of the resolver ask it with dig, of bind9-dnsutils: not found")
	}
	lan := livetest.NewLAN(t, 17)
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	wrong := lan.Machine(t, "wrong", 41)
	plain := lan.Machine(t, "plain", 42)
	boot := lan.Machine(t, "boot", 43)

	ca, other := newLiveCA(t, "trusted"), newLiveCA(t, "untrusted")
	good := startEncrypted(t, up, ca.leaf(t, []string{"dns.upstream.test"}, up.IPv4.AsSlice()), "853", "443")
	// The trusted authority's, of another name than the one asked for.
	misnamed := startEncrypted(t, wrong, ca.leaf(t, []string{"other.upstream.test"}), "853", "443")
	// The name asked for, of an authority the command doesn't trust.
	untrusted := startEncrypted(t, wrong, other.leaf(t, []string{"untrusted.upstream.test"}), "8853", "8443")
	fallback := startUpstream(t, plain, "192.0.2.53")
	bootstrap := startUpstream(t, boot, "192.0.2.1")
	bootstrap.host("dns.upstream.test.", up.IPv4.String())
	bootstrap.host("wrong.upstream.test.", wrong.IPv4.String())
	bootstrap.host("untrusted.upstream.test.", wrong.IPv4.String())

	server := srv.IPv4.String()
	config := fmt.Sprintf(`
webservers:
  main:
    listen:
      - 8053
resolvers:
  dot:
    listen: "%[1]s:5301"
    upstream: tls://dns.upstream.test
    bootstrap: %[2]s
  dotaddr:
    listen: "%[1]s:5302"
    upstream: tls://%[3]s
  doh:
    listen: "%[1]s:5303"
    upstream: https://dns.upstream.test/dns-query
    bootstrap: %[2]s
  wrongdot:
    listen: "%[1]s:5304"
    upstream:
      - "tls://wrong.upstream.test"
      - "tls://untrusted.upstream.test:8853"
      - %[4]s
    bootstrap: %[2]s
  wrongdoh:
    listen: "%[1]s:5305"
    upstream:
      - "https://wrong.upstream.test/dns-query"
      - "https://untrusted.upstream.test:8443/dns-query"
      - %[4]s
    bootstrap: %[2]s
credentials: {}
tasks: {}
`, server, boot.IPv4, up.IPv4, plain.IPv4)
	instance := configure(t, srv, lan.Router, "srv", 8053, config)
	instance.env = []string{"SSL_CERT_FILE=" + ca.file, "SSL_CERT_DIR=" + t.TempDir()}
	instance.start().serving()

	ask := func(port, name, want string) {
		t.Helper()
		if d := dig(t, client, server, "-p", port, name, "A"); d.status != "NOERROR" || !slices.Equal(d.data("A"), []string{want}) {
			t.Errorf("%s at port %s: %s\nwant %s", name, port, d, want)
		}
	}
	// Over TLS, at the host name the bootstrap server gives: three queries, one connection.
	for i := range 3 {
		ask("5301", fmt.Sprintf("t%d.example.org", i), dotAnswer)
	}
	if q, c := good.dot.Load(), good.dotConns.Load(); q != 3 || c != 1 {
		t.Errorf("over TLS: %d queries on %d connections, want 3 on 1", q, c)
	}
	// At the address, which the certificate holds: no bootstrap.
	ask("5302", "address.example.org", dotAnswer)
	if q := good.dot.Load(); q != 4 {
		t.Errorf("over TLS, at the address: %d queries, want 4", q)
	}
	// Over HTTPS: three queries, one connection, of HTTP/2.
	for i := range 3 {
		ask("5303", fmt.Sprintf("h%d.example.org", i), dohAnswer)
	}
	if q, c := good.doh.Load(), good.dohConns.Load(); q != 3 || c != 1 {
		t.Errorf("over HTTPS: %d queries on %d connections, want 3 on 1", q, c)
	}
	if proto, _ := good.proto.Load().(string); proto != "HTTP/2.0" {
		t.Errorf("over HTTPS: %q, want HTTP/2.0", proto)
	}
	if n := good.unpadded.Load(); n != 0 {
		t.Errorf("%d encrypted queries without padding", n)
	}
	// Nothing of them in the clear: the plain server, and the bootstrap server, never had the names.
	for _, name := range []string{"t0.example.org.", "address.example.org.", "h0.example.org."} {
		if fallback.times(name) != 0 || bootstrap.times(name) != 0 {
			t.Errorf("%s was asked in the clear", name)
		}
	}

	// A certificate of another name, and one of an authority not trusted: passed over, for the
	// plain server after them, and never sent the query.
	ask("5304", "wrong-tls.example.org", "192.0.2.53")
	ask("5305", "wrong-https.example.org", "192.0.2.53")
	if fallback.times("wrong-tls.example.org.") != 1 || fallback.times("wrong-https.example.org.") != 1 {
		t.Error("the plain server after the wrong certificates wasn't asked")
	}
	for what, e := range map[string]*encryptedUpstream{"of another name": misnamed, "of an authority not trusted": untrusted} {
		if e.dot.Load() != 0 || e.doh.Load() != 0 {
			t.Errorf("a server with a certificate %s was sent queries: %d over TLS, %d over HTTPS", what, e.dot.Load(), e.doh.Load())
		}
		if e.dotConns.Load() == 0 || e.dohConns.Load() == 0 {
			t.Errorf("a server with a certificate %s was never connected to: the test didn't reach it", what)
		}
	}

	// Named as written, in the metrics and the status, with the addresses found.
	metrics := instance.page("/metrics")
	for _, want := range []string{
		`ipv6ddns_resolver_upstream_failures_total{resolver="dot",upstream="tls://dns.upstream.test"} 0`,
		fmt.Sprintf(`ipv6ddns_resolver_upstream_failures_total{resolver="dotaddr",upstream="tls://%s"} 0`, up.IPv4),
		`ipv6ddns_resolver_upstream_failures_total{resolver="doh",upstream="https://dns.upstream.test/dns-query"} 0`,
		`ipv6ddns_resolver_upstream_failures_total{resolver="wrongdot",upstream="tls://wrong.upstream.test"} 1`,
		`ipv6ddns_resolver_upstream_failures_total{resolver="wrongdot",upstream="tls://untrusted.upstream.test:8853"} 1`,
		`ipv6ddns_resolver_upstream_failures_total{resolver="wrongdoh",upstream="https://wrong.upstream.test/dns-query"} 1`,
		`ipv6ddns_resolver_upstream_failures_total{resolver="wrongdoh",upstream="https://untrusted.upstream.test:8443/dns-query"} 1`,
		`ipv6ddns_resolver_queries_total{resolver="dot",kind="forwarded"} 3`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics without %s:\n%s", want, metrics)
		}
	}
	for _, r := range instance.status().Resolvers {
		if r.Name == "dot" && !slices.Equal(r.UpstreamAddresses["tls://dns.upstream.test"], []string{net.JoinHostPort(up.IPv4.String(), "853")}) {
			t.Errorf("status: the addresses of the upstream over TLS: %v", r.UpstreamAddresses)
		}
	}
}

// The answers of the upstream server are kept for their TTL: a name asked again doesn't reach it,
// however spelled, and its TTL counts down; its time over, it is asked again. That a name doesn't
// exist, or has no data, is kept too, for the SOA's time. With cache_size: 0, nothing is.
func TestLiveResolverCache(t *testing.T) {
	if _, err := exec.LookPath("dig"); err != nil {
		t.Fatal("the live tests of the resolver ask it with dig, of bind9-dnsutils: not found")
	}
	lan := livetest.NewLAN(t, 18)
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	upstream := startUpstream(t, up, "192.0.2.53")
	const ttl, negative = 6, 4
	upstream.ttl.Store(ttl)
	upstream.negative.Store(negative)

	server := srv.IPv4.String()
	instance := configure(t, srv, lan.Router, "srv", 8053, fmt.Sprintf(`
webservers:
  main:
    listen:
      - 8053
resolvers:
  lan:
    listen: 198.18.18.0/24
    upstream: %[1]s
  nocache:
    listen: "%[2]s:5300"
    upstream: %[1]s
    cache_size: 0
credentials: {}
tasks: {}
`, up.IPv4, server)).start().serving()

	// asked tells that the upstream server was asked the name that many times.
	asked := func(name string, want int, what string) {
		t.Helper()
		if got := upstream.times(name); got != want {
			t.Errorf("%s: the upstream server was asked %s %d times, want %d", what, name, got, want)
		}
	}

	began := time.Now()
	d := dig(t, client, server, "kept.example.org", "A")
	if d.status != "NOERROR" || !slices.Equal(d.answers, []string{"kept.example.org. A 192.0.2.53"}) || d.ttl() != ttl {
		t.Fatalf("the first: %s", d)
	}
	asked("kept.example.org.", 1, "the first")
	// Again, as another client spells it: from the cache.
	d = dig(t, client, server, "KEPT.Example.org", "A")
	if d.status != "NOERROR" || !slices.Equal(d.answers, []string{"KEPT.Example.org. A 192.0.2.53"}) || d.ttl() < 1 || d.ttl() > ttl {
		t.Errorf("again: %s", d)
	}
	asked("kept.example.org.", 1, "again")
	time.Sleep(2500 * time.Millisecond)
	d = dig(t, client, server, "kept.example.org", "A")
	if !slices.Equal(d.data("A"), []string{"192.0.2.53"}) || d.ttl() < 1 || d.ttl() > ttl-2 {
		t.Errorf("2.5s later: a TTL of %v, want what is left of %d, from 1 to %d: %s", d.ttls, ttl, ttl-2, d)
	}
	// Over TCP, the same answer kept.
	if d := dig(t, client, server, "+tcp", "kept.example.org", "A"); !slices.Equal(d.data("A"), []string{"192.0.2.53"}) {
		t.Errorf("over TCP: %s", d)
	}
	asked("kept.example.org.", 1, "2.5s later")

	// With the DO bit, another answer, kept beside.
	for _, c := range []struct {
		flag string
		want int
	}{{"+nodnssec", 1}, {"+dnssec", 2}, {"+dnssec", 2}, {"+nodnssec", 2}} {
		dig(t, client, server, c.flag, "signed.example.org", "A")
		asked("signed.example.org.", c.want, "with "+c.flag)
	}

	// That there is none: a name that doesn't exist, and one without data of the type.
	negativeBegan := time.Now()
	for _, what := range []string{"the first", "again"} {
		d := dig(t, client, server, "x.gone.test", "A")
		if d.status != "NXDOMAIN" || len(d.authority) != 1 || !strings.HasPrefix(d.authority[0], "gone.test. SOA ") || d.ttl() < 1 || d.ttl() > negative {
			t.Errorf("a name that doesn't exist, %s: %s", what, d)
		}
		d = dig(t, client, server, "host.empty.test", "AAAA")
		if d.status != "NOERROR" || len(d.answers) != 0 || len(d.authority) != 1 || !strings.HasPrefix(d.authority[0], "empty.test. SOA ") {
			t.Errorf("a name without data, %s: %s", what, d)
		}
		asked("x.gone.test.", 1, what)
		asked("host.empty.test.", 1, what)
	}

	// Without a cache, every query is asked.
	for i := range 3 {
		if d := dig(t, client, server, "-p", "5300", "every.example.org", "A"); !slices.Equal(d.data("A"), []string{"192.0.2.53"}) || d.ttl() != ttl {
			t.Errorf("without a cache: %s", d)
		}
		asked("every.example.org.", i+1, "without a cache")
	}

	metrics := instance.page("/metrics")
	for _, want := range []string{
		`ipv6ddns_resolver_queries_total{resolver="lan",kind="cached"} 7`,
		`ipv6ddns_resolver_queries_total{resolver="lan",kind="forwarded"} 5`,
		`ipv6ddns_resolver_queries_total{resolver="nocache",kind="cached"} 0`,
		`ipv6ddns_resolver_queries_total{resolver="nocache",kind="forwarded"} 3`,
		`ipv6ddns_resolver_cache_entries{resolver="nocache"} 0`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics without %s:\n%s", want, metrics)
		}
	}

	// Their time over, each is asked again: the TTL whole.
	time.Sleep(time.Until(began.Add((ttl + 1) * time.Second)))
	d = dig(t, client, server, "kept.example.org", "A")
	if !slices.Equal(d.data("A"), []string{"192.0.2.53"}) || d.ttl() != ttl {
		t.Errorf("its time over: %s", d)
	}
	asked("kept.example.org.", 2, "its time over")
	time.Sleep(time.Until(negativeBegan.Add((negative + 2) * time.Second)))
	if d := dig(t, client, server, "x.gone.test", "A"); d.status != "NXDOMAIN" || d.ttl() != negative {
		t.Errorf("a name that doesn't exist, its time over: %s", d)
	}
	dig(t, client, server, "host.empty.test", "AAAA")
	asked("x.gone.test.", 2, "its time over")
	asked("host.empty.test.", 2, "its time over")
}

// Two resolvers on one address and port, which the entries spell two ways, don't start: the
// error names both, and each one's entry, before anything listens. Apart, they do.
func TestLiveResolverCollision(t *testing.T) {
	lan := livetest.NewLAN(t, 19)
	srv := lan.Machine(t, "srv", 10)
	config := func(lab, lan string) string {
		return fmt.Sprintf(`
webservers:
  main:
    listen:
      - 8053
resolvers:
  lab:
    listen: %s
    upstream: 192.0.2.1
  lan:
    listen: %s
    upstream: 192.0.2.1
credentials: {}
tasks: {}
`, lab, lan)
	}
	address6 := "[" + srv.IPv6.String() + "]"
	for i, c := range []struct{ lab, lan, want string }{
		// A network, and the machine's address in it.
		{"198.18.19.0/24", srv.IPv4.String(), fmt.Sprintf("resolvers lab and lan both listen on %[1]s:53: lab as 198.18.19.0/24, lan as %[1]s: an address and port can belong to only one resolver", srv.IPv4)},
		// A port alone, every address, and one of them.
		{`"` + address6 + `"`, "53", fmt.Sprintf("resolvers lab and lan both listen on %[1]s:53: lab as %[1]s, lan as 53: an address and port can belong to only one resolver", address6)},
		// Every IPv4 address, and one of them, the second of its resolver's entries.
		{"0.0.0.0:5353", `["127.0.0.1", "` + srv.IPv4.String() + `:5353"]`, fmt.Sprintf("resolvers lab and lan both listen on %[1]s:5353: lab as 0.0.0.0:5353, lan as %[1]s:5353: an address and port can belong to only one resolver", srv.IPv4)},
	} {
		wrote := configure(t, srv, lan.Router, fmt.Sprintf("colliding-%d", i), 8053, config(c.lab, c.lan)).start().fails()
		if !strings.Contains(wrote, c.want) {
			t.Errorf("%s and %s: it wrote:\n%s\nwant %s", c.lab, c.lan, wrote, c.want)
		}
		if strings.Contains(wrote, "address already in use") || strings.Contains(wrote, "listening on") {
			t.Errorf("%s and %s: one listened before the other was told:\n%s", c.lab, c.lan, wrote)
		}
	}
	// One address each: both start.
	configure(t, srv, lan.Router, "apart", 8053, config("198.18.19.0/24", `"`+address6+`"`)).start().serving()
}
