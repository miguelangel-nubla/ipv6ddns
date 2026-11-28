package config

import (
	"crypto/tls"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"slices"
)

// TLS is a certificate that TLS servers show: a resolver's encrypted transports and the web
// server's HTTPS, which give its name. Its files, or ACME, which gets and renews them.
type TLS struct {
	// The files of the certificate, in PEM, with its chain, and of its key: relative to the
	// configuration's folder, unless absolute. With ACME, where it writes them, relative to the
	// state folder: by default tls/<name>/fullchain.pem and privkey.pem there.
	Certificate string `json:"certificate,omitempty"`
	Key         string `json:"key,omitempty"`
	// The certificate from an ACME authority, as Let's Encrypt, by its DNS challenge: kept and
	// renewed by ipv6ddns.
	ACME *ACME `json:"acme,omitempty"`

	// The files, read: in the configuration's folder, or with ACME in the state folder; and, with
	// ACME, the account's key, beside the certificate.
	CertFile, KeyFile, AccountKeyFile string `json:"-"`
	// What shows it: resolvers.lan, webserver; in that order.
	UsedBy []string `json:"-"`
}

// ACME is a certificate an ACME authority signs.
type ACME struct {
	// The names it is for, relative to the credential's zone, as an endpoint's: dns.lan of
	// example.com is dns.lan.example.com. A full name is taken as it is.
	Names StringList `json:"names,omitempty"`
	// The credential that writes the TXT records of the DNS challenge: of the public zone of the
	// names.
	Credential string `json:"credential,omitempty"`
	// The address the authority can write to about the account: none by default.
	Email string `json:"email,omitempty"`
	// The authority's directory: Let's Encrypt's by default.
	Directory string `json:"directory,omitempty"`
}

// The files of an ACME certificate, in the state folder by default.
const (
	acmeFolder      = "tls"
	acmeCertificate = "fullchain.pem"
	acmeKey         = "privkey.pem"
	acmeAccountKey  = "acme-account.key"
)

// setUpCertificates checks each certificate, and sets its files: its own, a certificate and its
// key that read as a pair; or, with ACME, names and a credential that can write their challenge.
// No two certificates share a file: each would write, or read, the other's.
func (c *Config) setUpCertificates() error {
	owner := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(c.Certificates)) {
		// Never nil: the schema takes an object alone.
		t := c.Certificates[name]
		t.UsedBy = nil
		if err := c.setUpCertificate(name, t); err != nil {
			return err
		}
		for _, file := range []string{t.CertFile, t.KeyFile, t.AccountKeyFile} {
			if file == "" {
				continue
			}
			if other, ok := owner[file]; ok && other != name {
				return fmt.Errorf("certificates %s and %s both use the file %s: each certificate needs files of its own. A certificate for both servers is one entry, with all their names, that both give as tls", other, name, file)
			}
			owner[file] = name
		}
	}
	return nil
}

// setUpCertificate checks one certificate, and sets its files.
func (c *Config) setUpCertificate(name string, t *TLS) error {
	path := "certificates." + name
	if t.ACME == nil {
		if t.Certificate == "" || t.Key == "" {
			return fmt.Errorf("%s: give certificate and key, the files of the certificate and of its key, in PEM, or acme, for ipv6ddns to get one", path)
		}
		t.CertFile, t.KeyFile, t.AccountKeyFile = inFolder(c.BaseDir, t.Certificate), inFolder(c.BaseDir, t.Key), ""
		if _, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile); err != nil {
			return fmt.Errorf("%s: %s and %s: %w", path, t.CertFile, t.KeyFile, err)
		}
		return nil
	}
	a := t.ACME
	switch credential, ok := c.Credentials[a.Credential]; {
	case len(a.Names) == 0:
		return fmt.Errorf("%s.acme.names is missing: give the names the clients use, relative to the zone of the credential, as dns.lan", path)
	case a.Credential == "":
		return fmt.Errorf("%s.acme.credential is missing: give the credential of the public zone of the names, which writes the TXT record that the authority checks", path)
	case !ok:
		return fmt.Errorf("%s.acme.credential: there is no credential %s", path, a.Credential)
	case credential.Provider == ResolverProvider:
		return fmt.Errorf("%s.acme.credential: %s is a zone of the resolver, which the authority can't ask: give the credential of the public zone of the names", path, a.Credential)
	case (t.Certificate == "") != (t.Key == ""):
		return fmt.Errorf("%s: give both certificate and key, where ipv6ddns writes them, or neither, for %s/%s/", path, acmeFolder, name)
	}
	if a.Directory != "" {
		if u, err := url.Parse(a.Directory); err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("%s.acme.directory: %q is not a URL of http:// or https://: give the authority's directory, as https://acme-v02.api.letsencrypt.org/directory, or leave it out for Let's Encrypt's", path, a.Directory)
		}
	}
	certificate, key := t.Certificate, t.Key
	if certificate == "" {
		certificate, key = filepath.Join(acmeFolder, name, acmeCertificate), filepath.Join(acmeFolder, name, acmeKey)
	}
	// What ACME writes is state: in the state folder.
	t.CertFile, t.KeyFile = inFolder(c.StateFolder, certificate), inFolder(c.StateFolder, key)
	t.AccountKeyFile = filepath.Join(filepath.Dir(t.CertFile), acmeAccountKey)
	// Each is written apart: one file for two would keep the last written alone.
	switch {
	case t.CertFile == t.KeyFile:
		return fmt.Errorf("%s: certificate and key are one file, %s, and ipv6ddns writes each to its own: give two, as certificate: %s and key: %s, or neither, for %s/%s/", path, t.CertFile, acmeCertificate, acmeKey, acmeFolder, name)
	case t.CertFile == t.AccountKeyFile || t.KeyFile == t.AccountKeyFile:
		return fmt.Errorf("%s: %s is where ipv6ddns keeps the key of the ACME account, beside the certificate: give the certificate and its key other names, as certificate: %s and key: %s", path, t.AccountKeyFile, acmeCertificate, acmeKey)
	}
	return nil
}

// useCertificate tells of a server, resolvers.lan or webserver, that has encrypted entries and
// no certificate, or one without the other, or a certificate that isn't of certificates; and
// notes the server as one that shows it. schemes are its encrypted ones, and example an entry of
// them, for the errors.
func (c *Config) useCertificate(path, name string, encrypted bool, schemes, example string) error {
	switch {
	case encrypted && name == "":
		return fmt.Errorf("%s.tls is missing: an entry of listen is encrypted, %s, and the clients must be shown a certificate: give the name of one of certificates, as tls: home", path, schemes)
	case !encrypted && name != "":
		return fmt.Errorf("%s.tls is for the encrypted entries of listen, and there is none: add one, as %s, or leave tls out", path, example)
	case !encrypted:
		return nil
	}
	t, ok := c.Certificates[name]
	if !ok {
		return fmt.Errorf("%s.tls: there is no certificate %s: add it under certificates, or fix its name", path, name)
	}
	t.UsedBy = append(t.UsedBy, path)
	return nil
}

// checkCertificatesUsed tells of a certificate that no server shows: a name mistyped would
// otherwise leave it ordered and renewed for nothing.
func (c *Config) checkCertificatesUsed() error {
	for _, name := range slices.Sorted(maps.Keys(c.Certificates)) {
		if len(c.Certificates[name].UsedBy) == 0 {
			return fmt.Errorf("certificates.%s: no server shows it: give it as the tls of a resolver, a web server or a listener, or leave it out", name)
		}
	}
	return nil
}
