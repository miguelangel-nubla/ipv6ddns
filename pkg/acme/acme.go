// Package acme keeps a certificate from an ACME authority, as Let's Encrypt, by its DNS
// challenge: it writes the TXT record the authority checks through a DNS provider, and the
// certificate and its key to files, which the program reads. It gets one when there is none, or
// none for the names, and renews it before it ends.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// LetsEncrypt is the directory of Let's Encrypt, the default authority.
const LetsEncrypt = "https://acme-v02.api.letsencrypt.org/directory"

// TXT writes the TXT records the DNS challenge needs, as a DNS provider does.
type TXT interface {
	// SetTXT makes the TXT records of name, absolute or not, the values: none removes them. It
	// returns once the provider's servers answer with them.
	SetTXT(name string, values []string) error
}

// Config is a certificate to keep.
type Config struct {
	// The authority's directory: LetsEncrypt by default.
	Directory string
	// The address the authority can write to about the account: none, for none.
	Email string
	// The names the certificate is for, absolute, without the final dot.
	Names []string
	// Where the certificate, with its chain, and its key are kept, in PEM; and the key of the
	// account at the authority.
	CertFile, KeyFile, AccountKeyFile string
	// What writes the challenge's records.
	Challenge TXT
	// How long before its end a certificate is renewed: by default, once two thirds of its
	// lifetime have passed, as Let's Encrypt advises, which is 30 days before the end of one of 90
	// days, and 2 before the end of one of 6.
	RenewBefore time.Duration
	// How long after its records are written the authority is told to check them, for the
	// provider's servers that have them yet to give them to the others: 15 seconds by default.
	Propagation time.Duration
	// The client of the authority's API: the default one, with the system's authorities.
	HTTPClient *http.Client
	// Where it says what it did, and what failed.
	Logf, Errorf func(format string, args ...any)
}

// Status is what the manager did last.
type Status struct {
	// When it last tried to get a certificate, and what failed then: none, when it got one.
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	// When it looks again.
	NextAttempt time.Time `json:"next_attempt,omitzero"`
}

// Manager keeps a certificate: Run does it, until its context ends.
type Manager struct {
	config Config
	now    func() time.Time

	mutex  sync.Mutex
	status Status
}

// The times between the attempts: after a failure, an hour, so that an authority's limits aren't
// reached; and a certificate that is fine is looked at again within a day, in case its files
// change.
var (
	retryAfterFailure = time.Hour
	lookAgain         = 24 * time.Hour
)

// New makes the manager of a certificate.
func New(cfg Config) *Manager {
	if cfg.Directory == "" {
		cfg.Directory = LetsEncrypt
	}
	if cfg.Propagation == 0 {
		cfg.Propagation = 15 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Errorf == nil {
		cfg.Errorf = cfg.Logf
	}
	return &Manager{config: cfg, now: time.Now}
}

// Status is what the manager did last.
func (m *Manager) Status() Status {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.status
}

// Run keeps the certificate until ctx ends: it gets one now if it must, and then when the one it
// has is to be renewed, or an hour after a failure.
func (m *Manager) Run(ctx context.Context) {
	for {
		wait := m.Check(ctx)
		m.mutex.Lock()
		m.status.NextAttempt = m.now().Add(wait)
		m.mutex.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Check gets a certificate if the one in the files is missing, isn't for the names, or is to be
// renewed, and tells how long until it is to be looked at again.
func (m *Manager) Check(ctx context.Context) time.Duration {
	renew, reason := m.due()
	if !renew.After(m.now()) {
		m.config.Logf("getting a certificate for %s from %s: %s", strings.Join(m.config.Names, ", "), m.config.Directory, reason)
		err := m.obtain(ctx)
		m.mutex.Lock()
		m.status.LastAttempt, m.status.LastError = m.now(), ""
		if err != nil {
			m.status.LastError = err.Error()
		}
		m.mutex.Unlock()
		if err != nil {
			m.config.Errorf("the certificate for %s: %s; trying again in %s", strings.Join(m.config.Names, ", "), err, retryAfterFailure)
			return retryAfterFailure
		}
		m.config.Logf("got a certificate for %s, written to %s", strings.Join(m.config.Names, ", "), m.config.CertFile)
		renew, _ = m.due()
	}
	return min(max(renew.Sub(m.now()), time.Minute), lookAgain)
}

// due is when the certificate in the files is to be renewed, and why: now, for none, or one that
// isn't for every name.
func (m *Manager) due() (time.Time, string) {
	data, err := os.ReadFile(m.config.CertFile)
	if err != nil {
		return m.now(), "there is none yet"
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return m.now(), "its file isn't PEM"
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return m.now(), "its file doesn't read"
	}
	if _, err := os.Stat(m.config.KeyFile); err != nil {
		return m.now(), "its key is missing"
	}
	for _, name := range m.config.Names {
		if cert.VerifyHostname(name) != nil {
			return m.now(), "the one there isn't for " + name
		}
	}
	renew := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) * 2 / 3)
	if m.config.RenewBefore > 0 {
		renew = cert.NotAfter.Add(-m.config.RenewBefore)
	}
	return renew, "it ends on " + cert.NotAfter.UTC().Format(time.DateOnly)
}

// obtain gets a certificate for the names, and writes it, with its key.
func (m *Manager) obtain(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	accountKey, err := loadOrMakeKey(m.config.AccountKeyFile)
	if err != nil {
		return fmt.Errorf("the account's key: %w", err)
	}
	client := &acme.Client{Key: accountKey, DirectoryURL: m.config.Directory, HTTPClient: m.config.HTTPClient, UserAgent: "ipv6ddns"}
	account := &acme.Account{}
	if m.config.Email != "" {
		account.Contact = []string{"mailto:" + m.config.Email}
	}
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("registering with %s: %w", m.config.Directory, err)
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(m.config.Names...))
	if err != nil {
		return fmt.Errorf("ordering: %w", err)
	}

	// The challenges, and the value of each record: a name and its wildcard share one.
	var challenges []*acme.Challenge
	var authzURLs []string
	records := make(map[string][]string)
	for _, u := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, u)
		if err != nil {
			return fmt.Errorf("the authorization %s: %w", u, err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
			}
		}
		if chal == nil {
			return fmt.Errorf("%s offers no DNS challenge for %s", m.config.Directory, authz.Identifier.Value)
		}
		value, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}
		name := "_acme-challenge." + strings.TrimPrefix(authz.Identifier.Value, "*.")
		records[name] = append(records[name], value)
		challenges = append(challenges, chal)
		authzURLs = append(authzURLs, authz.URI)
	}
	names := slices.Sorted(maps.Keys(records))
	defer func() {
		for _, name := range names {
			if err := m.config.Challenge.SetTXT(name, nil); err != nil {
				m.config.Errorf("removing the challenge's record %s: %s", name, err)
			}
		}
	}()
	for _, name := range names {
		if err := m.config.Challenge.SetTXT(name, records[name]); err != nil {
			return fmt.Errorf("writing the challenge's record %s: %w", name, err)
		}
	}
	if len(challenges) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.config.Propagation):
		}
	}
	for _, chal := range challenges {
		if _, err := client.Accept(ctx, chal); err != nil {
			return fmt.Errorf("asking for the check of %s: %w", chal.URI, err)
		}
	}
	for _, u := range authzURLs {
		if _, err := client.WaitAuthorization(ctx, u); err != nil {
			return fmt.Errorf("the check: %w", err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("the order: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: m.config.Names}, key)
	if err != nil {
		return err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("the certificate: %w", err)
	}
	return write(m.config.CertFile, m.config.KeyFile, chain, key)
}

// write writes the certificate's chain and its key, each to a file beside it first, and then in
// its place, the key first: whatever reads them never reads half a file.
func write(certFile, keyFile string, chain [][]byte, key crypto.Signer) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	var certPEM []byte
	for _, der := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600},
		{certFile, certPEM, 0o644},
	} {
		if err := writeAtomic(f.path, f.data, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// writeAtomic writes data to path through a file beside it, renamed: its folder made if missing.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// loadOrMakeKey reads the account's key, or makes it and writes it, the first time.
func loadOrMakeKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		return key, writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s isn't PEM", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s isn't a key that signs", path)
	}
	return signer, nil
}
