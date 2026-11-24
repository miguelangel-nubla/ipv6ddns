// Package certfile is a certificate that TLS servers show, read from its files in PEM, and read
// again when they change: a renewal is shown without a restart.
package certfile

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Certificate is a certificate that TLS servers show, read from its files, and read again when
// they change: a renewed certificate is shown without a restart. One that doesn't read
// keeps the one before, and the log says why.
type Certificate struct {
	certFile, keyFile string
	errorf            func(string, ...any)
	// Whether something else writes the files, as ACME: until it does, there is no certificate,
	// and that is no error.
	managed bool

	mutex           sync.Mutex
	cert            *tls.Certificate
	certMod, keyMod time.Time
	checked         time.Time
	failed          string
}

// CheckInterval is how often the files are looked at, at most: when a client connects. A
// variable, for the tests to shorten.
var CheckInterval = 5 * time.Second

// Load reads the certificate and its key, which must be a pair: of managed files, there may be
// none yet, which is no error. errorf logs files that don't read again, once.
func Load(certFile, keyFile string, managed bool, errorf func(string, ...any)) (*Certificate, error) {
	c := &Certificate{certFile: certFile, keyFile: keyFile, errorf: errorf, managed: managed}
	if err := c.load(); err != nil && !managed {
		return nil, err
	}
	return c, nil
}

// ErrNone is the handshake's error while managed files aren't written yet.
var ErrNone = errors.New("no certificate yet")

// load reads the files, with the mutex held or before anything else has the certificate.
func (c *Certificate) load() error {
	certMod, keyMod, err := modTimes(c.certFile, c.keyFile)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("%s and %s: %w", c.certFile, c.keyFile, err)
	}
	c.cert, c.certMod, c.keyMod, c.checked = &pair, certMod, keyMod, time.Now()
	return nil
}

// modTimes are when the files changed last.
func modTimes(certFile, keyFile string) (certMod, keyMod time.Time, err error) {
	ci, err := os.Stat(certFile)
	if err != nil {
		return certMod, keyMod, err
	}
	ki, err := os.Stat(keyFile)
	if err != nil {
		return certMod, keyMod, err
	}
	return ci.ModTime(), ki.ModTime(), nil
}

// Get is the certificate to show a client, as tls.Config.GetCertificate: read again first, if
// its files changed.
func (c *Certificate) Get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if time.Since(c.checked) >= CheckInterval {
		c.checked = time.Now()
		certMod, keyMod, err := modTimes(c.certFile, c.keyFile)
		if err == nil && (!certMod.Equal(c.certMod) || !keyMod.Equal(c.keyMod)) {
			err = c.load()
		}
		if err != nil && c.managed && c.cert == nil && errors.Is(err, os.ErrNotExist) {
			// Not written yet: the status says so, and the manager why.
			err = nil
		}
		if err != nil {
			if err.Error() != c.failed {
				c.failed = err.Error()
				c.errorf("the certificate %s doesn't read again, and the one before is shown: %s", c.certFile, err)
			}
		} else {
			c.failed = ""
		}
	}
	if c.cert == nil {
		return nil, ErrNone
	}
	return c.cert, nil
}

// Config is the TLS configuration of a server that speaks the protocols given.
func (c *Certificate) Config(protocols ...string) *tls.Config {
	return &tls.Config{GetCertificate: c.Get, MinVersion: tls.VersionTLS12, NextProtos: protocols}
}

// Status is the certificate a server shows: the names it is for, and until when.
type Status struct {
	Names    []string  `json:"names"`
	NotAfter time.Time `json:"not_after"`
	// Why the files didn't read again, while the one before is shown.
	Error string `json:"error,omitempty"`
	// Whether an ACME authority signs it, which ipv6ddns asks: and, then, why the last attempt
	// to get one failed, and when the next is.
	Managed     bool      `json:"acme,omitempty"`
	Renewal     string    `json:"renewal_error,omitempty"`
	NextAttempt time.Time `json:"next_attempt,omitzero"`
}

// Status is the certificate's status.
func (c *Certificate) Status() *Status {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	st := &Status{Error: c.failed, Managed: c.managed}
	if c.cert == nil {
		return st
	}
	leaf := c.cert.Leaf
	if leaf == nil && len(c.cert.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(c.cert.Certificate[0])
	}
	if leaf != nil {
		st.Names = leaf.DNSNames
		for _, ip := range leaf.IPAddresses {
			st.Names = append(st.Names, ip.String())
		}
		if len(st.Names) == 0 && leaf.Subject.CommonName != "" {
			st.Names = []string{leaf.Subject.CommonName}
		}
		st.NotAfter = leaf.NotAfter
	}
	return st
}
