package ipv6ddns

import (
	"context"
	"crypto/tls"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/acme"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"go.uber.org/zap"
)

// certificate is one of certificates: loaded once, and shown by each server that gives it as its
// tls, a renewal too. With acme, ipv6ddns keeps it: it writes the challenge's TXT records through
// a credential's provider, and the certificate to its files; one manager, whatever shows it.
type certificate struct {
	name   string
	usedBy []string
	file   *certfile.Certificate
	// Without acme, none.
	acme   *acmeSettings
	writer ddns.TXTWriter
	logger *zap.SugaredLogger

	mutex sync.Mutex
	// Its manager, once the names are known; until then, why they aren't.
	manager  *acme.Manager
	namesErr string
}

// acmeSettings are the settings of a certificate, read.
type acmeSettings struct {
	names                             []string
	credential, email, directory      string
	certFile, keyFile, accountKeyFile string
}

// certificates are the certificates of the configuration, by name's order, loaded: of acme, each
// with the provider of its credential, which must write TXT records.
func (w *Worker) certificates() ([]*certificate, error) {
	var out []*certificate
	for _, name := range slices.Sorted(maps.Keys(w.config.Certificates)) {
		t := w.config.Certificates[name]
		c := &certificate{name: name, usedBy: t.UsedBy, logger: w.logger}
		file, err := certfile.Load(t.CertFile, t.KeyFile, t.ACME != nil, func(f string, args ...any) { w.logger.Errorf(c.label()+": "+f, args...) })
		if err != nil {
			return nil, fmt.Errorf("certificates.%s: %w", name, err)
		}
		c.file = file
		if t.ACME != nil {
			endpoint, err := w.endpoint(t.ACME.Credential)
			if err != nil {
				return nil, err
			}
			writer, ok := endpoint.Service.(ddns.TXTWriter)
			if !ok {
				return nil, fmt.Errorf("certificates.%s.acme.credential: the provider of %s, %s, can't write the TXT records of the DNS challenge: give a credential of cloudflare, route53, rfc2136 or duckdns", name, t.ACME.Credential, w.config.Credentials[t.ACME.Credential].Provider)
			}
			c.writer = writer
			c.acme = &acmeSettings{
				names: t.ACME.Names, credential: t.ACME.Credential, email: t.ACME.Email, directory: t.ACME.Directory,
				certFile: t.CertFile, keyFile: t.KeyFile, accountKeyFile: t.AccountKeyFile,
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// certificate is the loaded certificate of that name: nil for none.
func (w *Worker) certificate(name string) *certfile.Certificate {
	for _, c := range w.certs {
		if c.name == name {
			return c.file
		}
	}
	return nil
}

// namesRetry is how long until the names are asked again of a provider that couldn't tell them.
var namesRetry = time.Minute

// acmeHTTPClient is the client of the authority's API: nil, the default, but in tests, of an
// authority of theirs.
var acmeHTTPClient *http.Client

// run keeps the certificate of acme until ctx ends: first the names, in full, which Route 53 asks AWS for;
// then the manager.
func (c *certificate) run(ctx context.Context) {
	var names []string
	for {
		var err error
		if names, err = c.fullNames(); err == nil {
			break
		}
		c.mutex.Lock()
		c.namesErr = err.Error()
		c.mutex.Unlock()
		c.logger.Errorf("%s: the names of its certificate: %s", c.label(), err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(namesRetry):
		}
	}
	m := acme.New(acme.Config{
		Directory: c.acme.directory, Email: c.acme.email, Names: names,
		CertFile: c.acme.certFile, KeyFile: c.acme.keyFile, AccountKeyFile: c.acme.accountKeyFile,
		Challenge: c.writer, HTTPClient: acmeHTTPClient,
		Logf:   func(f string, args ...any) { c.logger.Infof(c.label()+": "+f, args...) },
		Errorf: func(f string, args ...any) { c.logger.Errorf(c.label()+": "+f, args...) },
	})
	c.mutex.Lock()
	c.manager, c.namesErr = m, ""
	c.mutex.Unlock()
	m.Run(ctx)
}

// fullNames are the names, each in full, by the zone of the credential.
func (c *certificate) fullNames() ([]string, error) {
	var names []string
	for _, n := range c.acme.names {
		full, err := c.writer.FullName(n)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		names = append(names, full)
	}
	return names, nil
}

// label is what the log calls the certificate: certificate home.
func (c *certificate) label() string { return "certificate " + c.name }

// CertificateStatus is a certificate of the configuration: its name, what shows it, and its
// status, with what its manager did.
type CertificateStatus struct {
	Name string `json:"name"`
	// resolvers.lan, webserver.
	UsedBy []string `json:"used_by"`
	*certfile.Status
}

// status is the certificate's status, with what its manager did, of acme.
func (c *certificate) status() CertificateStatus {
	st := c.file.Status()
	if c.acme != nil {
		c.mutex.Lock()
		m, namesErr := c.manager, c.namesErr
		c.mutex.Unlock()
		if m == nil {
			st.Renewal = namesErr
		} else {
			s := m.Status()
			st.Renewal, st.NextAttempt = s.LastError, s.NextAttempt
		}
	}
	return CertificateStatus{Name: c.name, UsedBy: slices.Clone(c.usedBy), Status: st}
}

// certificateStatuses are the certificates' statuses, by name's order.
func (w *Worker) certificateStatuses() []CertificateStatus {
	out := make([]CertificateStatus, 0, len(w.certs))
	for _, c := range w.certs {
		out = append(out, c.status())
	}
	return out
}

// WebserverTLS is the TLS of the web server's HTTPS entries, which speak the protocols given:
// nil without them.
func (w *Worker) WebserverTLS(protocols ...string) *tls.Config {
	if w.webCert == nil {
		return nil
	}
	return w.webCert.Config(protocols...)
}
