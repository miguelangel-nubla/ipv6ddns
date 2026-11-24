//go:build linux && integration

package main

// The resolver's encrypted transports, as the command runs them, asked by real clients of DNS
// over TLS, HTTPS and QUIC: BIND's dig and Knot's kdig.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

const encryptedHost = "dns.home.arpa"

// writeTestCA writes a certificate authority, and a certificate it signed for encryptedHost with
// its key, as PEM files in dir: the authority's for the clients, the others for the resolver.
func writeTestCA(t *testing.T, dir string) (caFile, certFile, keyFile string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "live test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: encryptedHost},
		DNSNames: []string{encryptedHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	caFile, certFile, keyFile = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	for file, block := range map[string]*pem.Block{
		caFile:   {Type: "CERTIFICATE", Bytes: caDER},
		certFile: {Type: "CERTIFICATE", Bytes: der},
		keyFile:  {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(file, pem.EncodeToMemory(block), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return caFile, certFile, keyFile
}

// kdig asks server with Knot's kdig, from the machine: the addresses of its short answer.
func kdig(t *testing.T, m *livetest.Machine, server string, args ...string) (string, error) {
	t.Helper()
	cmd := m.Command("kdig", append([]string{"@" + server, "+short", "+timeout=6", "+retry=0"}, args...)...)
	cmd.Stderr = nil
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// A machine runs ipv6ddns with a resolver that answers over plain DNS, and over TLS, HTTPS and
// QUIC, with a certificate of the test's authority. A client asks a name of its zone over each,
// with dig and with kdig, the latter trusting that authority, and gets its address; a client that expects
// another name is refused the connection; and the report tells the transports and the
// certificate.
func TestLiveResolverServesEncrypted(t *testing.T) {
	for _, tool := range []string{"dig", "kdig"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("the live test of the encrypted resolver asks it with %s, of bind9-dnsutils and knot-dnsutils: not found", tool)
		}
	}
	lan := livetest.NewLAN(t, 27)
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	caFile, certFile, keyFile := writeTestCA(t, t.TempDir())
	address := srv.IPv4.String()

	config := fmt.Sprintf(`
webserver:
  listen:
    - 8053
resolvers:
  lan:
    listen:
      - %[1]s
      - "tls://%[1]s"
      - "https://%[1]s"
      - "quic://%[1]s"
    tls:
      certificate: %[2]s
      key: %[3]s
    # Nothing is forwarded in this test: a server that doesn't answer.
    upstream: 192.0.2.1
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - printer A 198.18.27.50
        - dns A %[1]s
tasks:
  nobody:
    filter:
      - mac:
          address: "02:00:00:00:00:99"
    endpoints:
      home:
        - nobody
`, address, certFile, keyFile)
	one := configure(t, srv, lan.Router, "srv", 8053, config).start().serving()
	const want = "198.18.27.50"
	trust := []string{"+tls-ca=" + caFile, "+tls-hostname=" + encryptedHost}

	plain := dig(t, client, address, "printer.home.arpa", "A")
	if plain.status != "NOERROR" || len(plain.answers) != 1 || !strings.HasSuffix(plain.answers[0], want) {
		t.Errorf("plain DNS: %s", plain.output)
	}
	// dig as a second client of TLS and HTTPS, which doesn't check the certificate: BIND 9.18's,
	// of CI's Ubuntu, says its TLS context can't be created when given +tls-ca there, though not
	// in a container of the same Ubuntu. kdig, below, checks it, over every transport.
	for name, args := range map[string][]string{
		"dig, over TLS":         {"+tls", "-p", "853"},
		"dig, over HTTPS":       {"+https"},
		"dig, over HTTPS (GET)": {"+https-get"},
	} {
		d := dig(t, client, address, append(args, "printer.home.arpa", "A")...)
		if d.status != "NOERROR" || len(d.answers) != 1 || !strings.HasSuffix(d.answers[0], want) {
			t.Errorf("%s: %s", name, d.output)
		}
	}
	for name, args := range map[string][]string{
		"kdig, over TLS":   append([]string{"+tls"}, trust...),
		"kdig, over HTTPS": append([]string{"+https"}, trust...),
		"kdig, over QUIC":  append([]string{"+quic"}, trust...),
	} {
		got, err := kdig(t, client, address, append(args, "printer.home.arpa", "A")...)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}

	// A client that expects another name doesn't take the certificate.
	if got, err := kdig(t, client, address, "+tls", "+tls-ca="+caFile, "+tls-hostname=other.home.arpa", "printer.home.arpa", "A"); err == nil && got == want {
		t.Error("a client expecting other.home.arpa took the certificate of " + encryptedHost)
	}

	report := one.page("/status.txt")
	for _, has := range []string{"tls://" + address + ":853", "https://" + address + ":443", "quic://" + address + ":853", "Certificate: " + encryptedHost + ", until "} {
		if !strings.Contains(report, has) {
			t.Errorf("the report has no %q:\n%s", has, report)
		}
	}
}
