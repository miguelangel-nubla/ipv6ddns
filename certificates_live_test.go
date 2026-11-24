//go:build live

package ipv6ddns

// The program, as the configuration has it, gets the certificate of a resolver's encrypted
// transports from a real authority, Pebble, whose challenge it writes at a real DNS server, BIND:
// tools/live-providers.sh starts both, and runs this.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap/zaptest"
)

func liveEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s is not set: see tools/live-providers.sh", name)
	}
	return v
}

// A resolver with tls.acme: it starts without a certificate, its encrypted transport refusing,
// gets one for the name in the zone of an rfc2136 credential, and answers over TLS with it; the
// report tells it, and its files are where the configuration's folder has them by default.
func TestLiveACME(t *testing.T) {
	var settings map[string]any
	if err := json.Unmarshal([]byte(liveEnv(t, "IPV6DDNS_LIVE_RFC2136")), &settings); err != nil {
		t.Fatal(err)
	}
	directory := liveEnv(t, "IPV6DDNS_LIVE_PEBBLE")
	pebbleCA, err := os.ReadFile(liveEnv(t, "IPV6DDNS_LIVE_PEBBLE_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pebbleCA)
	saved := acmeHTTPClient
	acmeHTTPClient = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	t.Cleanup(func() { acmeHTTPClient = saved })

	zone := fmt.Sprint(settings["zone"])
	// Ports that are free now: the configuration takes no port 0.
	free := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	cfg := loadConfig(t, fmt.Sprintf(`
webserver:
  listen: "https://127.0.0.1:%d"
  tls:
    acme:
      names: web
      credential: public
      directory: %s
resolvers:
  lan:
    listen:
      - 127.0.0.1:%d
      - "tls://127.0.0.1:%d"
    upstream: 192.0.2.1
    tls:
      acme:
        names: dot
        credential: public
        directory: %s
credentials:
  public:
    provider: rfc2136
    settings:
      server: %q
      zone: %s
      ttl: 1m
      tsig_key: %s
      tsig_secret: %q
  home:
    provider: resolver
    settings:
      resolver: lan
      zone: home.arpa
      records:
        - printer A 192.0.2.20
tasks: {}
`, free(), directory, free(), free(), directory, settings["server"], zone, settings["tsig_key"], settings["tsig_secret"]))
	w, err := NewWorker(zaptest.NewLogger(t).Sugar(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		w.Shutdown(context.Background())
	}()
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	var address string
	for _, a := range w.resolvers[0].Addresses() {
		if after, ok := strings.CutPrefix(a, "tls://"); ok {
			address = after
		}
	}
	// A name of its own: the manager's live test has dns.
	name := "dot." + zone

	// Pebble signs with a root of its own, which the client trusts: of no name but the one asked.
	ask := func() (*dns.Msg, *x509.Certificate, error) {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: []string{"dot"}})
		if err != nil {
			return nil, nil, err
		}
		defer conn.Close()
		leaf := conn.ConnectionState().PeerCertificates[0]
		if err := leaf.VerifyHostname(name); err != nil {
			return nil, leaf, err
		}
		m := new(dns.Msg)
		m.SetQuestion("printer.home.arpa.", dns.TypeA)
		c := &dns.Conn{Conn: conn}
		if err := c.WriteMsg(m); err != nil {
			return nil, leaf, err
		}
		resp, err := c.ReadMsg()
		return resp, leaf, err
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		resp, leaf, err := ask()
		if err == nil {
			if len(resp.Answer) != 1 {
				t.Fatalf("the answer over TLS: %v", resp)
			}
			t.Logf("answered over TLS with the certificate for %v, until %s", leaf.DNSNames, leaf.NotAfter)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no certificate after 2 minutes: %v; the status: %+v", err, w.resolverStatus(w.resolvers[0]).Certificate)
		}
		time.Sleep(time.Second)
	}
	st := w.resolverStatus(w.resolvers[0]).Certificate
	if st == nil || !st.Managed || len(st.Names) != 1 || st.Names[0] != name || st.Renewal != "" {
		t.Errorf("the status: %+v", st)
	}
	if _, err := os.Stat(cfg.Resolvers["lan"].TLS.AccountKeyFile); err != nil || !strings.HasPrefix(cfg.Resolvers["lan"].TLS.CertFile, cfg.BaseDir) {
		t.Errorf("the files: %+v, %v", cfg.Resolvers["lan"].TLS, err)
	}
	if page := w.Page("", false).String(); !strings.Contains(page, "Certificate: "+name+", until ") {
		t.Errorf("the report:\n%s", page)
	}

	// The web server's own, of tls.acme too: its TLS shows it, once got.
	web := "web." + zone
	l, err := tls.Listen("tcp", "127.0.0.1:0", w.WebserverTLS("http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(time.Second) {
		conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{ServerName: web, InsecureSkipVerify: true})
		if err == nil {
			leaf := conn.ConnectionState().PeerCertificates[0]
			conn.Close()
			if leaf.VerifyHostname(web) != nil {
				t.Fatalf("the web server's certificate is for %v", leaf.DNSNames)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no certificate of the web server after 2 minutes: %v; the status: %+v", err, w.webserverCertificate())
		}
	}
	if page := w.Page("", false).String(); !strings.Contains(page, "Webserver:\n    Certificate: "+web+", until ") {
		t.Errorf("the report of the web server:\n%s", page)
	}
}
