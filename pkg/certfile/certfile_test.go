package certfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// write writes a certificate signed by itself, of the template's names, and its key, in dir.
func write(t *testing.T, dir string, template *x509.Certificate) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = big.NewInt(1)
	template.NotBefore, template.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certFile, keyFile = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile
}

// Files of one's own must read as a pair: missing, or a key of another, is an error that names
// them. Managed files may be missing: the handshake then fails with ErrNone, and the status says
// there is none.
func TestLoad(t *testing.T) {
	certFile, keyFile := write(t, t.TempDir(), &x509.Certificate{DNSNames: []string{"dns.example.com"}})
	_, otherKey := write(t, t.TempDir(), &x509.Certificate{DNSNames: []string{"other.example.com"}})
	missing := filepath.Join(t.TempDir(), "missing.pem")
	for name, files := range map[string][2]string{"missing": {missing, keyFile}, "the key of another": {certFile, otherKey}} {
		if _, err := Load(files[0], files[1], false, t.Errorf); err == nil || !strings.Contains(err.Error(), files[0]) {
			t.Errorf("%s: %v", name, err)
		}
	}

	c, err := Load(missing, filepath.Join(filepath.Dir(missing), "key.pem"), true, t.Errorf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(&tls.ClientHelloInfo{}); !errors.Is(err, ErrNone) {
		t.Errorf("the handshake without a certificate: %v", err)
	}
	if st := c.Status(); !st.Managed || st.Names != nil || !st.NotAfter.IsZero() || st.Error != "" {
		t.Errorf("the status without a certificate: %+v", st)
	}
}

// The status's names: the DNS names, then the addresses; the common name only without either.
// Each status is its own, not the certificate's: changing one, or reading many at once, leaves
// the others.
func TestStatusNames(t *testing.T) {
	for _, c := range []struct {
		name     string
		template x509.Certificate
		want     []string
	}{
		{"names alone", x509.Certificate{DNSNames: []string{"a.example.com", "b.example.com"}}, []string{"a.example.com", "b.example.com"}},
		{"names and addresses", x509.Certificate{DNSNames: []string{"dns.example.com"}, IPAddresses: []net.IP{net.ParseIP("192.168.1.2"), net.ParseIP("fd00::2")}}, []string{"dns.example.com", "192.168.1.2", "fd00::2"}},
		{"addresses alone", x509.Certificate{IPAddresses: []net.IP{net.ParseIP("192.168.1.2")}}, []string{"192.168.1.2"}},
		{"a common name alone", x509.Certificate{Subject: pkix.Name{CommonName: "dns.example.com"}}, []string{"dns.example.com"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			certFile, keyFile := write(t, t.TempDir(), &c.template)
			cert, err := Load(certFile, keyFile, false, t.Errorf)
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					if got := cert.Status().Names; !slices.Equal(got, c.want) {
						t.Errorf("names %v, want %v", got, c.want)
					}
				})
			}
			wg.Wait()
			first := cert.Status()
			first.Names[0] = "changed"
			if got := cert.Status().Names; !slices.Equal(got, c.want) {
				t.Errorf("after a change of another status: %v", got)
			}
		})
	}
}

// A name of a certificate is for the same name, in any case and with its final dot or without;
// a wildcard, for one label more, as RFC 6125 has it.
func TestMatches(t *testing.T) {
	for _, c := range []struct {
		pattern, name string
		want          bool
	}{
		{"dns.lan.example.com", "dns.lan.example.com", true},
		{"DNS.lan.example.com", "dns.LAN.example.com.", true},
		{"dns.lan.example.com", "lan.example.com", false},
		{"*.lan.example.com", "kids.lan.example.com", true},
		{"*.lan.example.com", "KIDS.lan.example.com.", true},
		{"*.lan.example.com", "a.kids.lan.example.com", false},
		{"*.lan.example.com", "lan.example.com", false},
		{"*.lan.example.com", ".lan.example.com", false},
		{"", "", false},
	} {
		if got := Matches(c.pattern, c.name); got != c.want {
			t.Errorf("%q, %q: %t, want %t", c.pattern, c.name, got, c.want)
		}
	}
}

// A renewed certificate is shown without a restart; and while its files are half written, as
// between the key and the certificate, which acme writes one after the other, or truncated, the
// one before stays, the failure is logged once, and it is read again at each look until it reads.
func TestReload(t *testing.T) {
	old := CheckInterval
	CheckInterval = 0
	defer func() { CheckInterval = old }()
	dir := t.TempDir()
	certFile, keyFile := write(t, dir, &x509.Certificate{DNSNames: []string{"a.example"}})
	// Each change at a time of its own, whatever the file system keeps of them.
	changed := time.Now()
	touch := func(file string) {
		t.Helper()
		changed = changed.Add(time.Second)
		if err := os.Chtimes(file, changed, changed); err != nil {
			t.Fatal(err)
		}
	}
	var errs int
	c, err := Load(certFile, keyFile, false, func(string, ...any) { errs++ })
	if err != nil {
		t.Fatal(err)
	}
	if !c.Covers("a.example") {
		t.Fatal("not for a.example")
	}

	newCert, newKey := write(t, t.TempDir(), &x509.Certificate{DNSNames: []string{"b.example"}})
	if err := os.Rename(newKey, keyFile); err != nil { // the key first, as acme writes
		t.Fatal(err)
	}
	touch(keyFile)
	if !c.Covers("a.example") || c.Status().Error == "" {
		t.Errorf("half a renewal: for a.example %v, error %q", c.Covers("a.example"), c.Status().Error)
	}
	if err := os.Rename(newCert, certFile); err != nil {
		t.Fatal(err)
	}
	touch(certFile)
	if !c.Covers("b.example") || c.Status().Error != "" {
		t.Errorf("the renewal isn't shown: %+v", c.Status())
	}

	whole, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, whole[:len(whole)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	touch(certFile)
	if !c.Covers("b.example") || c.Status().Error == "" {
		t.Errorf("a truncated file: %+v", c.Status())
	}
	if err := os.WriteFile(certFile, whole, 0o600); err != nil {
		t.Fatal(err)
	}
	touch(certFile)
	if !c.Covers("b.example") || c.Status().Error != "" {
		t.Errorf("whole again: %+v", c.Status())
	}
	if errs != 2 {
		t.Errorf("%d errors logged, want 2: one of each failure, however many looks", errs)
	}
}
