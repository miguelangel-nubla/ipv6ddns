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

// A certificate is due when there is none, its key is missing or another's, it isn't for every
// name, or two
// thirds of its lifetime have passed; or RenewBefore its end, when given, and less than its
// lifetime.
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
		otherKey    bool
	}{
		{"90 days, 10 in", []string{"dns.example.com"}, now.Add(-10 * day), now.Add(80 * day), 0, now.Add(50 * day), false, false},
		{"6 days", []string{"dns.example.com"}, now, now.Add(6 * day), 0, now.Add(4 * day), false, false},
		{"RenewBefore", []string{"dns.example.com"}, now, now.Add(90 * day), 7 * day, now.Add(83 * day), false, false},
		{"another name", []string{"other.example.com"}, now, now.Add(90 * day), 0, now, false, false},
		{"a wildcard of the name", []string{"*.example.com"}, now, now.Add(90 * day), 0, now.Add(60 * day), false, false},
		// RenewBefore of the lifetime or more would have a certificate just got due at once, and
		// another ordered at every look: two thirds, as without it.
		{"RenewBefore, a day less than the lifetime", []string{"dns.example.com"}, now, now.Add(6 * day), 5 * day, now.Add(1 * day), false, false},
		{"RenewBefore, the lifetime", []string{"dns.example.com"}, now, now.Add(6 * day), 6 * day, now.Add(4 * day), false, false},
		{"RenewBefore, more than the lifetime", []string{"dns.example.com"}, now, now.Add(6 * day), 30 * day, now.Add(4 * day), false, false},
		// A lifetime twice which a Duration doesn't hold.
		{"200 years", []string{"dns.example.com"}, now, now.Add(73000 * day), 0, now.Add(73000 * day / 3 * 2), false, false},
		{"no key", []string{"dns.example.com"}, now, now.Add(90 * day), 0, now, true, false},
		{"the key of another", []string{"dns.example.com"}, now, now.Add(90 * day), 0, now, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certFile, keyFile := writeCert(t, dir, tc.names, tc.from, tc.to)
			if tc.removeKey {
				os.Remove(keyFile)
			}
			if tc.otherKey {
				// Another certificate's key, written over this one's: as two writers would leave it.
				_, other := writeCert(t, t.TempDir(), tc.names, tc.from, tc.to)
				data, _ := os.ReadFile(other)
				os.WriteFile(keyFile, data, 0o600)
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

// A certificate just got is never due at once, whatever RenewBefore: Check would order another at
// every look, a minute apart.
func TestDueAfterObtain(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	for _, renewBefore := range []time.Duration{0, time.Hour, 6 * day, 30 * day, 1 << 62} {
		certFile, keyFile := writeCert(t, t.TempDir(), []string{"dns.example.com"}, now, now.Add(6*day))
		m := New(Config{Names: []string{"dns.example.com"}, CertFile: certFile, KeyFile: keyFile, RenewBefore: renewBefore})
		m.now = func() time.Time { return now }
		if got, _ := m.due(); !got.After(now) {
			t.Errorf("RenewBefore %s: a certificate of 6 days, just got, is due on %s", renewBefore, got.Format(time.DateOnly))
		}
	}
}

// The names of Names are matched to the certificate's as a client would match them: a wildcard is
// the certificate's own wildcard, in any case, and not the name above it.
func TestDueNames(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	fine := now.Add(60 * 24 * time.Hour)
	for _, tc := range []struct {
		name          string
		cert, names   []string
		want          time.Time
		wantReasonFor string
	}{
		{"a name and its wildcard", []string{"*.example.com", "example.com"}, []string{"*.example.com", "example.com"}, fine, ""},
		{"a wildcard, in another case", []string{"*.example.com"}, []string{"*.Example.com"}, fine, ""},
		{"a name, in another case", []string{"dns.example.com"}, []string{"DNS.example.com"}, fine, ""},
		{"a name of the wildcard", []string{"*.example.com"}, []string{"dns.example.com"}, fine, ""},
		{"a wildcard alone isn't the name above", []string{"*.example.com"}, []string{"example.com"}, now, "example.com"},
		{"a name isn't its wildcard", []string{"a.example.com"}, []string{"*.example.com"}, now, "*.example.com"},
		{"one of two missing", []string{"*.example.com"}, []string{"*.example.com", "example.com"}, now, "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certFile, keyFile := writeCert(t, t.TempDir(), tc.cert, now, now.Add(90*24*time.Hour))
			m := New(Config{Names: tc.names, CertFile: certFile, KeyFile: keyFile})
			m.now = func() time.Time { return now }
			got, reason := m.due()
			if !got.Equal(tc.want) {
				t.Errorf("the certificate for %q, wanted for %q: due %s (%s), want %s", tc.cert, tc.names, got, reason, tc.want)
			}
			if tc.wantReasonFor != "" && reason != "the one there isn't for "+tc.wantReasonFor {
				t.Errorf("the reason: %q, want that it isn't for %s", reason, tc.wantReasonFor)
			}
		})
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
