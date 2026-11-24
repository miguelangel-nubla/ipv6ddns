package ipv6ddns

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/ddns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/acme"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
	"go.uber.org/zap"
)

// certificate is the certificate of a resolver's encrypted transports that an ACME authority
// signs, which ipv6ddns keeps: it writes the challenge's TXT records through a credential's
// provider, and the certificate to the files the resolver reads.
type certificate struct {
	resolver string
	tls      acmeSettings
	writer   ddns.TXTWriter
	logger   *zap.SugaredLogger

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

// certificates are the certificates of the resolvers with tls.acme, each with the provider of its
// credential, which must write TXT records.
func (w *Worker) certificates() ([]*certificate, error) {
	var out []*certificate
	for _, name := range slices.Sorted(maps.Keys(w.config.Resolvers)) {
		t := w.config.Resolvers[name].TLS
		if t == nil || t.ACME == nil {
			continue
		}
		endpoint, err := w.endpoint(t.ACME.Credential)
		if err != nil {
			return nil, err
		}
		writer, ok := endpoint.Service.(ddns.TXTWriter)
		if !ok {
			return nil, fmt.Errorf("resolvers.%s.tls.acme.credential: the provider of %s, %s, can't write the TXT records of the DNS challenge: give a credential of cloudflare, route53, rfc2136 or duckdns", name, t.ACME.Credential, w.config.Credentials[t.ACME.Credential].Provider)
		}
		out = append(out, &certificate{resolver: name, writer: writer, logger: w.logger, tls: acmeSettings{
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
		c.logger.Errorf("resolver %s: the names of its certificate: %s", c.resolver, err)
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
		Logf:   func(f string, args ...any) { c.logger.Infof("resolver "+c.resolver+": "+f, args...) },
		Errorf: func(f string, args ...any) { c.logger.Errorf("resolver "+c.resolver+": "+f, args...) },
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

// fill tells, in the status of its resolver's certificate, why the last attempt failed, and when
// the next is.
func (c *certificate) fill(st *resolver.CertificateStatus) {
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
		if c.resolver == st.Name {
			c.fill(st.Certificate)
		}
	}
	return st
}
