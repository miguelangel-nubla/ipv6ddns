package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert writes a certificate signed by itself for names, valid from notBefore to notAfter,
// with its key.
func writeCert(t *testing.T, dir string, names []string, notBefore, notAfter time.Time) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: names, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	if err := write(certFile, keyFile, [][]byte{der}, key); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// A certificate is due when there is none, its key is missing, it isn't for every name, or two
// thirds of its lifetime have passed; or RenewBefore its end, when given.
func TestDue(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	for _, tc := range []struct {
		name        string
		names       []string
		from, to    time.Time
		renewBefore time.Duration
		want        time.Time
		removeKey   bool
	}{
		{"90 days, 10 in", []string{"dns.example.com"}, now.Add(-10 * day), now.Add(80 * day), 0, now.Add(50 * day), false},
		{"6 days", []string{"dns.example.com"}, now, now.Add(6 * day), 0, now.Add(4 * day), false},
		{"RenewBefore", []string{"dns.example.com"}, now, now.Add(90 * day), 7 * day, now.Add(83 * day), false},
		{"another name", []string{"other.example.com"}, now, now.Add(90 * day), 0, now, false},
		{"a wildcard of the name", []string{"*.example.com"}, now, now.Add(90 * day), 0, now.Add(60 * day), false},
		{"no key", []string{"dns.example.com"}, now, now.Add(90 * day), 0, now, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := writeCert(t, dir, tc.names, tc.from, tc.to)
			if tc.removeKey {
				os.Remove(keyFile)
			}
			m := New(Config{Names: []string{"dns.example.com"}, CertFile: certFile, KeyFile: keyFile, RenewBefore: tc.renewBefore})
			m.now = func() time.Time { return now }
			if got, reason := m.due(); !got.Equal(tc.want) {
				t.Errorf("due %s (%s), want %s", got, reason, tc.want)
			}
		})
	}
	m := New(Config{Names: []string{"dns.example.com"}, CertFile: filepath.Join(t.TempDir(), "none.pem")})
	m.now = func() time.Time { return now }
	if got, reason := m.due(); !got.Equal(now) || reason != "there is none yet" {
		t.Errorf("without a file: %s, %s", got, reason)
	}
}

// The account's key is made once, and read after.
func TestAccountKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "account.key")
	first, err := loadOrMakeKey(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the key's file: %v, %v", info, err)
	}
	again, err := loadOrMakeKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Public().(*ecdsa.PublicKey).Equal(first.Public()) {
		t.Error("another key, read again")
	}
}
