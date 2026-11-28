//go:build live

// The manager against a real authority, Pebble, Let's Encrypt's server for tests, which checks
// the challenges at a real DNS server, BIND, where the provider of RFC 2136 writes them.
// tools/live-providers.sh starts both, and runs this: without their variables, it is skipped.

package acme_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/acme"
)

// liveEnv is a variable of the script's, or the test is skipped.
func liveEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Skipf("%s is not set: see tools/live-providers.sh", name)
	}
	return v
}

// pebbleClient trusts the certificate of Pebble's API.
func pebbleClient(t *testing.T) *http.Client {
	t.Helper()
	pemData, err := os.ReadFile(liveEnv(t, "IPV6DDNS_LIVE_PEBBLE_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemData)
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
}

// issuers are the root and intermediate certificates Pebble signs with: new at each start of it.
func issuers(t *testing.T, client *http.Client) (roots, intermediates *x509.CertPool) {
	t.Helper()
	get := func(path string) []byte {
		resp, err := client.Get(liveEnv(t, "IPV6DDNS_LIVE_PEBBLE_MANAGEMENT") + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return body
	}
	roots, intermediates = x509.NewCertPool(), x509.NewCertPool()
	roots.AppendCertsFromPEM(get("/roots/0"))
	intermediates.AppendCertsFromPEM(get("/intermediates/0"))
	return roots, intermediates
}

// readChain is the certificates of the file, the leaf first.
func readChain(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	return chain
}

// A certificate for a name, and for another name with its wildcard, which share a record of the
// challenge: the manager writes the records at BIND, Pebble checks them there, and the certificate
// it signs is written with its key, which are a pair. The records are gone after. Checked again,
// it is kept; due for renewal, another is got, with the account's key of the first time.
func TestLiveCertificate(t *testing.T) {
	settings := liveEnv(t, "IPV6DDNS_LIVE_RFC2136")
	bind := liveEnv(t, "IPV6DDNS_LIVE_RFC2136_DNS")
	directory := liveEnv(t, "IPV6DDNS_LIVE_PEBBLE")
	service, err := ddns.NewService("rfc2136", []byte(settings))
	if err != nil {
		t.Fatal(err)
	}
	writer := service.(ddns.TXTWriter)
	zone := strings.TrimSuffix(service.Domain(""), ".")
	names := []string{"dns." + zone, "w." + zone, "*.w." + zone}
	dir := t.TempDir()
	client := pebbleClient(t)
	cfg := acme.Config{
		Directory: directory, Email: "test@example.test", Names: names,
		CertFile: filepath.Join(dir, "tls", "fullchain.pem"), KeyFile: filepath.Join(dir, "tls", "privkey.pem"),
		AccountKeyFile: filepath.Join(dir, "tls", "account.key"),
		Challenge:      writer, Propagation: 100 * time.Millisecond, HTTPClient: client,
		Errorf: t.Errorf,
	}
	// What it logs, each step of the order.
	var logged []string
	var logMutex sync.Mutex
	cfg.Logf = func(f string, args ...any) {
		t.Logf(f, args...)
		logMutex.Lock()
		logged = append(logged, fmt.Sprintf(f, args...))
		logMutex.Unlock()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	m := acme.New(cfg)
	wait := m.Check(ctx)
	if st := m.Status(); st.LastError != "" {
		t.Fatalf("the certificate: %s", st.LastError)
	}
	logMutex.Lock()
	steps := []string{"getting a certificate for ", "wrote the challenge's records, _acme-challenge.", "the authority is checking the records",
		"the authority checked the names: asking for the certificate", "removed the challenge's records", "got a certificate for "}
	i := 0
	for _, line := range logged {
		if i < len(steps) && strings.HasPrefix(line, steps[i]) {
			i++
		}
	}
	if i != len(steps) {
		t.Errorf("logged %q: missing, in order, %q", logged, steps[i:])
	}
	logMutex.Unlock()
	pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		t.Fatalf("the certificate and its key: %v", err)
	}
	chain := readChain(t, cfg.CertFile)
	if !slices.Equal(slices.Sorted(slices.Values(chain[0].DNSNames)), slices.Sorted(slices.Values(names))) {
		t.Errorf("the certificate is for %v, want %v", chain[0].DNSNames, names)
	}
	roots, intermediates := issuers(t, client)
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	for _, name := range []string{"dns." + zone, "x.w." + zone} {
		if _, err := chain[0].Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: intermediates}); err != nil {
			t.Errorf("for %s, it doesn't verify: %v", name, err)
		}
	}
	if wait < time.Minute || wait > 24*time.Hour {
		t.Errorf("looked at again in %s", wait)
	}
	if pair.Leaf == nil && len(pair.Certificate) == 0 {
		t.Error("an empty pair")
	}

	// The challenge's records are gone.
	for _, name := range []string{"_acme-challenge.dns." + zone, "_acme-challenge.w." + zone} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
		resp, err := dns.Exchange(m, bind)
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Answer) != 0 {
			t.Errorf("%s has %v", name, resp.Answer)
		}
	}

	// Checked again: kept, the same. So too with a RenewBefore of more than its lifetime, which
	// made one just got due at once, and another ordered at every look.
	before, _ := os.Stat(cfg.CertFile)
	account, _ := os.ReadFile(cfg.AccountKeyFile)
	for _, renewBefore := range []time.Duration{0, 365 * 24 * time.Hour} {
		cfg.RenewBefore = renewBefore
		acme.New(cfg).Check(ctx)
		if after, _ := os.Stat(cfg.CertFile); !after.ModTime().Equal(before.ModTime()) {
			t.Errorf("RenewBefore %s: a certificate that is fine was got again", renewBefore)
		}
	}
	cfg.RenewBefore = 0

	// Two thirds of its lifetime later, it is due: another, with the same account. No RenewBefore
	// makes one just got due: one of its whole lifetime or more is taken as two thirds.
	lifetime := chain[0].NotAfter.Sub(chain[0].NotBefore)
	later := chain[0].NotBefore.Add(lifetime / 3 * 2).Add(time.Minute)
	renewed := acme.New(cfg)
	renewed.SetNow(func() time.Time { return later })
	renewed.Check(ctx)
	if st := renewed.Status(); st.LastError != "" {
		t.Fatalf("the renewal: %s", st.LastError)
	}
	if again := readChain(t, cfg.CertFile)[0]; again.SerialNumber.Cmp(chain[0].SerialNumber) == 0 {
		t.Error("renewed, the certificate is the same")
	}
	if now, _ := os.ReadFile(cfg.AccountKeyFile); string(now) != string(account) {
		t.Error("the account's key changed")
	}
}

// A name the provider can't write the record of fails the attempt, which says why, and is tried
// again in an hour; the files stay as they were.
func TestLiveCertificateFailure(t *testing.T) {
	settings := liveEnv(t, "IPV6DDNS_LIVE_RFC2136")
	service, err := ddns.NewService("rfc2136", []byte(settings))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := acme.Config{
		Directory: liveEnv(t, "IPV6DDNS_LIVE_PEBBLE"), Names: []string{"outside.example.org"},
		CertFile: filepath.Join(dir, "fullchain.pem"), KeyFile: filepath.Join(dir, "privkey.pem"), AccountKeyFile: filepath.Join(dir, "account.key"),
		Challenge: service.(ddns.TXTWriter), Propagation: 100 * time.Millisecond, HTTPClient: pebbleClient(t),
		Logf: t.Logf, Errorf: t.Logf,
	}
	m := acme.New(cfg)
	if wait := m.Check(context.Background()); wait != time.Hour {
		t.Errorf("tried again in %s", wait)
	}
	st := m.Status()
	if !strings.Contains(st.LastError, "_acme-challenge.outside.example.org") {
		t.Errorf("the error: %q", st.LastError)
	}
	if _, err := os.Stat(cfg.CertFile); err == nil {
		t.Error("a certificate was written")
	}
}
