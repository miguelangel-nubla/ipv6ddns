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

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/acme"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/certfile"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"go.uber.org/zap"
)

// certificate is the certificate of a resolver's encrypted transports, or of the web server's
// HTTPS, that an ACME authority signs, which ipv6ddns keeps: it writes the challenge's TXT
// records through a credential's provider, and the certificate to the files the server reads.
type certificate struct {
	// The resolver's name, or webserver; and where its settings are, for the log.
	owner, path string
	tls         acmeSettings
	writer      ddns.TXTWriter
	logger      *zap.SugaredLogger

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

// certificates are the certificates of tls.acme, of the resolvers and of the web server, each
// with the provider of its credential, which must write TXT records.
func (w *Worker) certificates() ([]*certificate, error) {
	type owned struct {
		owner, path string
		tls         *config.TLS
	}
	var all []owned
	for _, name := range slices.Sorted(maps.Keys(w.config.Resolvers)) {
		all = append(all, owned{name, "resolvers." + name, w.config.Resolvers[name].TLS})
	}
	all = append(all, owned{"webserver", "webserver", w.config.Webserver.TLS})
	var out []*certificate
	for _, o := range all {
		t := o.tls
		if t == nil || t.ACME == nil {
			continue
		}
		endpoint, err := w.endpoint(t.ACME.Credential)
		if err != nil {
			return nil, err
		}
		writer, ok := endpoint.Service.(ddns.TXTWriter)
		if !ok {
			return nil, fmt.Errorf("%s.tls.acme.credential: the provider of %s, %s, can't write the TXT records of the DNS challenge: give a credential of cloudflare, route53, rfc2136 or duckdns", o.path, t.ACME.Credential, w.config.Credentials[t.ACME.Credential].Provider)
		}
		out = append(out, &certificate{owner: o.owner, path: o.path, writer: writer, logger: w.logger, tls: acmeSettings{
			names: t.ACME.Names, credential: t.ACME.Credential, email: t.ACME.Email, directory: t.ACME.Directory,
			certFile: t.CertFile, keyFile: t.KeyFile, accountKeyFile: t.AccountKeyFile,
		}})
	}
	return out, nil
}

// namesRetry is how long until the names are asked again of a provider that couldn't tell them.
var namesRetry = time.Minute

// acmeHTTPClient is the client of the authority's API: nil, the default, but in tests, of an
// authority of theirs.
var acmeHTTPClient *http.Client

// run keeps the certificate until ctx ends: first the names, in full, which Route 53 asks AWS for;
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
		Directory: c.tls.directory, Email: c.tls.email, Names: names,
		CertFile: c.tls.certFile, KeyFile: c.tls.keyFile, AccountKeyFile: c.tls.accountKeyFile,
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
	for _, n := range c.tls.names {
		full, err := c.writer.FullName(n)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		names = append(names, full)
	}
	return names, nil
}

// label is what the log calls the certificate's server: resolver lan, or webserver.
func (c *certificate) label() string {
	if c.owner == "webserver" {
		return "webserver"
	}
	return "resolver " + c.owner
}

// fill tells, in the status of its server's certificate, why the last attempt failed, and when
// the next is.
func (c *certificate) fill(st *certfile.Status) {
	c.mutex.Lock()
	m, namesErr := c.manager, c.namesErr
	c.mutex.Unlock()
	if m == nil {
		st.Renewal = namesErr
		return
	}
	s := m.Status()
	st.Renewal, st.NextAttempt = s.LastError, s.NextAttempt
}

// resolverStatus is a resolver's status, with what its certificate's manager did.
func (w *Worker) resolverStatus(r *resolver.Server) resolver.Status {
	st := r.Status()
	if st.Certificate == nil {
		return st
	}
	for _, c := range w.certs {
		if c.owner == st.Name && c.path != "webserver" {
			c.fill(st.Certificate)
		}
	}
	return st
}

// WebserverTLS is the TLS of the web server's HTTPS entries, which speak the protocols given:
// nil without them.
func (w *Worker) WebserverTLS(protocols ...string) *tls.Config {
	if w.webCert == nil {
		return nil
	}
	return w.webCert.Config(protocols...)
}

// webserverCertificate is the status of the web server's certificate, with what its manager did:
// nil without HTTPS entries.
func (w *Worker) webserverCertificate() *certfile.Status {
	if w.webCert == nil {
		return nil
	}
	st := w.webCert.Status()
	for _, c := range w.certs {
		if c.path == "webserver" {
			c.fill(st)
		}
	}
	return st
}
