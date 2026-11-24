package config

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// Resolver is a DNS server for the clients of a network: it answers the zones of its resolver
// credentials and its own records, and asks its upstream servers the rest. See docs/resolver.md.
type Resolver struct {
	// Required. Where it answers, as listen takes it; without a port, 53. An entry that starts with
	// tls://, https:// or quic:// answers over that encrypted transport, on its port by default.
	Listen StringList `json:"listen,omitempty"`
	// The certificate the encrypted transports show. Required with an encrypted entry, and only
	// then.
	TLS *TLS `json:"tls,omitempty"`
	// The networks, or addresses, of the clients it answers; any other is refused. Default: the
	// networks of the machine's addresses it listens on.
	Allow StringList `json:"allow,omitempty"`
	// Required. The servers it asks what isn't its own, in order: addresses or host names, with a
	// port or not.
	Upstream StringList `json:"upstream,omitempty"`
	// The servers that find the addresses of the upstream servers given by host name, and nothing
	// else: addresses, with a port or not. Required with a host name in Upstream, and only then.
	Bootstrap StringList `json:"bootstrap,omitempty"`
	// Records of names of no zone of its credentials, absolute, in the syntax of a zone file.
	Records []string `json:"records,omitempty"`
	// The answers forwarded that it keeps, for their TTL: entries. Default: DefaultCacheSize; 0,
	// none.
	CacheSize *int `json:"cache_size,omitempty"`
	// Whether the reverse of the private networks' addresses that it has no name of is asked of the
	// upstream servers, out of RFC 6303, as of a local server that knows more of their names.
	// Default: false, no such name, its own.
	ForwardUnknownPrivateReverseQueries bool `json:"forward_unknown_private_reverse_queries,omitempty"`

	// The resolver, checked, with its zones.
	Spec resolver.Config `json:"-"`
}

// TLS is the certificate of a resolver's encrypted transports, or of the web server's HTTPS.
type TLS struct {
	// The files of the certificate, in PEM, with its chain, and of its key: relative to the
	// configuration's folder, unless absolute. With ACME, where it writes them, by default
	// tls/<resolver>/fullchain.pem and privkey.pem.
	Certificate string `json:"certificate,omitempty"`
	Key         string `json:"key,omitempty"`
	// The certificate from an ACME authority, as Let's Encrypt, by its DNS challenge: kept and
	// renewed by ipv6ddns.
	ACME *ACME `json:"acme,omitempty"`

	// The files, read: in the configuration's folder; and, with ACME, the account's key, beside
	// the certificate.
	CertFile, KeyFile, AccountKeyFile string `json:"-"`
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

// The files of an ACME certificate, in the configuration's folder by default.
const (
	acmeFolder      = "tls"
	acmeCertificate = "fullchain.pem"
	acmeKey         = "privkey.pem"
	acmeAccountKey  = "acme-account.key"
)

// ResolverProvider is the provider of a zone a resolver answers.
const ResolverProvider = "resolver"

// resolverSettings are the settings of a resolver credential that the configuration reads: the
// provider checks them all, at start.
type resolverSettings struct {
	Resolver string            `json:"resolver"`
	Zone     string            `json:"zone"`
	Records  []string          `json:"records"`
	TTL      duration.Duration `json:"ttl"`
}

// checkResolvers tells, of a configuration not yet checked by the schema, that a resolver is to
// say where it listens and which servers it asks: in words, where the schema would only say that
// a key is missing.
func checkResolvers(configData []byte) error {
	var c struct {
		Resolvers map[string]map[string]json.RawMessage `json:"resolvers"`
	}
	if json.Unmarshal(configData, &c) != nil {
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(c.Resolvers)) {
		r := c.Resolvers[name]
		if _, ok := r["listen"]; !ok {
			return fmt.Errorf("resolvers.%s.listen is missing: give where the resolver answers. That's the clients' network, as 192.168.1.0/24, for this machine's address in it, or the address itself. Without a port, 53", name)
		}
		if _, ok := r["upstream"]; !ok {
			return fmt.Errorf("resolvers.%s.upstream is missing: give one or more servers to ask about the names that aren't the resolver's own, as 192.168.1.1 or 1.1.1.1:53. Without them, it answers no other name", name)
		}
	}
	return nil
}

// setUpResolvers reads the resolvers, and their credentials' zones, and checks them: once the
// tasks are read, whose names the zones have.
func (c *Config) setUpResolvers() error {
	names := slices.Sorted(maps.Keys(c.Resolvers))
	// Every resolver's entries, to tell those two share.
	listening := make(map[string]string)
	for _, name := range names {
		r := c.Resolvers[name]
		path := "resolvers." + name
		spec := resolver.Config{Name: name, Path: path}
		if len(r.Listen) == 0 {
			return fmt.Errorf("%s.listen is missing: give where the resolver answers", path)
		}
		// One by one: each entry with its text, as written, which the errors at start quote.
		for _, line := range r.Listen {
			transport, rest := listenTransport(line)
			entries, err := listen.Parse([]string{rest}, resolver.DefaultPortOf(transport))
			if err != nil {
				return fmt.Errorf("%s.listen: %w", path, err)
			}
			e := entries[0]
			if transport != "" {
				enc := resolver.EncryptedListen{Transport: transport, Entry: e, Line: strings.TrimSpace(line)}
				if !slices.ContainsFunc(spec.Encrypted, func(o resolver.EncryptedListen) bool { return o.Transport == transport && o.Entry == e }) {
					spec.Encrypted = append(spec.Encrypted, enc)
				}
				continue
			}
			if !slices.Contains(spec.Listen, e) {
				spec.Listen = append(spec.Listen, e)
				spec.ListenLines = append(spec.ListenLines, strings.TrimSpace(line))
			}
		}
		if err := c.checkCertificate(path, name, r.TLS, len(spec.Encrypted) > 0); err != nil {
			return err
		}
		if r.TLS != nil {
			spec.CertFile, spec.KeyFile, spec.CertManaged = r.TLS.CertFile, r.TLS.KeyFile, r.TLS.ACME != nil
		}
		// By protocol: plain DNS has UDP and TCP, DNS over TLS and over HTTPS TCP, over QUIC UDP.
		claim := func(protocol, shown string, e fmt.Stringer) error {
			key := protocol + " " + e.String()
			if other, ok := listening[key]; ok && other != name {
				return fmt.Errorf("resolvers %s and %s both listen on %s: an address and port can belong to only one resolver", other, name, shown)
			}
			listening[key] = name
			return nil
		}
		for _, e := range spec.Listen {
			for _, protocol := range []string{"udp", "tcp"} {
				if err := claim(protocol, e.String(), e); err != nil {
					return err
				}
			}
		}
		for _, e := range spec.Encrypted {
			if err := claim(resolver.Protocol(e.Transport), e.Line, e.Entry); err != nil {
				return err
			}
		}
		spec.CacheSize = resolver.DefaultCacheSize
		if r.CacheSize != nil {
			spec.CacheSize = *r.CacheSize
		}
		spec.ForwardUnknownPrivateReverse = r.ForwardUnknownPrivateReverseQueries
		for _, a := range r.Allow {
			p, err := parseNetwork(a)
			if err != nil {
				return fmt.Errorf("%s.allow: %w", path, err)
			}
			spec.Allow = append(spec.Allow, p)
		}
		if len(r.Upstream) == 0 {
			return fmt.Errorf("%s.upstream is missing: give one or more servers to ask about the names that aren't the resolver's own", path)
		}
		named := ""
		for _, u := range r.Upstream {
			address, name, err := parseUpstream(u)
			if err != nil {
				return fmt.Errorf("%s.upstream: %w", path, err)
			}
			if name && named == "" {
				named = u
			}
			spec.Upstreams = append(spec.Upstreams, address)
		}
		for _, b := range r.Bootstrap {
			address, err := parseServerAddress(b)
			if err != nil {
				return fmt.Errorf("%s.bootstrap: %w", path, err)
			}
			spec.Bootstrap = append(spec.Bootstrap, address)
		}
		switch {
		case named != "" && len(spec.Bootstrap) == 0:
			is := "is a host name"
			if strings.Contains(named, "://") {
				is = "is at a host name"
			}
			return fmt.Errorf("%s.upstream: %q %s, and there's no bootstrap to look it up. Add bootstrap, servers used for that lookup only, as bootstrap: 9.9.9.9. The system's resolver isn't used, as it may be this one", path, named, is)
		case named == "" && len(spec.Bootstrap) > 0:
			return fmt.Errorf("%s.bootstrap only looks up upstream servers given by host name, and every upstream here is an address: leave it out", path)
		}
		for _, line := range r.Records {
			rr, err := resolver.ParseRecord(line, "", resolver.DefaultTTL)
			if err != nil {
				return fmt.Errorf("%s.records: %q: %w", path, line, err)
			}
			spec.Records = append(spec.Records, rr)
			spec.Lines = append(spec.Lines, line)
		}
		r.Spec = spec
		c.Resolvers[name] = r
	}

	for _, credential := range slices.Sorted(maps.Keys(c.Credentials)) {
		cred := c.Credentials[credential]
		if cred.Provider != ResolverProvider {
			continue
		}
		path := "credentials." + credential
		var settings resolverSettings
		if err := json.Unmarshal(cred.RawSettings, &settings); err != nil {
			return fmt.Errorf("%s.settings: %w", path, err)
		}
		name := settings.Resolver
		switch {
		case name == "" && len(names) == 0:
			return fmt.Errorf("%s: the resolver provider is a zone that one of the resolvers answers, and there are none: add one under resolvers, with its listen and upstream", path)
		case name == "" && len(names) > 1:
			return fmt.Errorf("%s.settings.resolver is missing: say which of %s answers the zone", path, strings.Join(names, ", "))
		case name == "":
			name = names[0]
		}
		r, ok := c.Resolvers[name]
		if !ok {
			if len(names) == 0 {
				return fmt.Errorf("%s.settings.resolver: there's no resolver %s: resolvers is empty", path, name)
			}
			return fmt.Errorf("%s.settings.resolver: there's no resolver %s: the resolvers are %s", path, name, strings.Join(names, ", "))
		}
		zone := strings.Trim(settings.Zone, ".")
		if zone == "" {
			return fmt.Errorf("%s.settings.zone is missing: give the zone the resolver answers, as home.arpa", path)
		}
		ttl := settings.TTL.Duration
		if ttl <= 0 {
			ttl = resolver.DefaultTTL
		}
		z := resolver.Zone{Credential: credential, Name: resolver.Name("", zone), Path: path + ".settings.records", TTL: ttl, Tasks: make(map[string]string)}
		for _, line := range settings.Records {
			rr, err := resolver.ParseRecord(line, zone, ttl)
			if err != nil {
				return fmt.Errorf("%s.settings.records: %q: %w", path, line, err)
			}
			z.Records = append(z.Records, rr)
			z.Lines = append(z.Lines, line)
		}
		for _, task := range slices.Sorted(maps.Keys(c.Tasks)) {
			for _, hostname := range c.Tasks[task].Endpoints[credential] {
				// A template's names come and go with the hosts: the resolver has them as they are
				// given addresses.
				if IsTemplate(hostname) {
					continue
				}
				if n := resolver.Name(hostname, zone); z.Tasks[n] == "" {
					z.Tasks[n] = task
				}
			}
		}
		r.Spec.Zones = append(r.Spec.Zones, z)
		c.Resolvers[name] = r
	}

	for _, name := range names {
		if err := resolver.Check(c.Resolvers[name].Spec); err != nil {
			return err
		}
	}
	return nil
}

// parseNetwork reads a network of allow, or an address, which is a network of one.
func parseNetwork(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("%q is not a network, as 192.168.1.0/24 or fd00::/64, nor an address", s)
}

// parseUpstream reads an upstream server, as host:port: an address, or a host name, with a port
// or not; or a URL of DNS over TLS or over HTTPS, as written. It tells whether its host is a host
// name.
func parseUpstream(s string) (string, bool, error) {
	if strings.Contains(s, "://") {
		return parseEncrypted(s)
	}
	if address, err := parseServerAddress(s); err == nil {
		return address, false, nil
	}
	invalid := fmt.Errorf("%q is not an address or a host name, with or without a port, as 192.168.1.1, 1.1.1.1:53, [2001:db8::1]:53 or dns.example.net", s)
	host, port := s, resolver.DefaultPort
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", false, invalid
		}
	}
	host = strings.TrimSuffix(host, ".")
	if _, ok := dns.IsDomainName(host); !ok || !strings.Contains(host, ".") || strings.ContainsAny(host, "[]:/ ") {
		return "", false, invalid
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false, invalid
	}
	return net.JoinHostPort(strings.ToLower(host), port), true, nil
}

// parseEncrypted reads an upstream server of DNS over TLS, tls://host[:port], or over HTTPS,
// https://host[:port]/path: the host an address, or a host name, which bootstrap finds. It is
// kept as written, which the status and the metrics name it by. It tells whether its host is a
// host name.
func parseEncrypted(s string) (string, bool, error) {
	scheme, _, _ := strings.Cut(s, "://")
	scheme = strings.ToLower(scheme)
	if scheme != "tls" && scheme != "https" {
		return "", false, fmt.Errorf("%q: unknown scheme %s: use plain DNS, as 1.1.1.1 or dns.example.net; tls:// for DNS over TLS, as tls://1.1.1.1; or https:// for DNS over HTTPS, as https://dns.example.net/dns-query", s, scheme)
	}
	example := "tls://1.1.1.1, tls://[2606:4700:4700::1111]:853 or tls://dns.example.net"
	if scheme == "https" {
		example = "https://1.1.1.1/dns-query, https://[2606:4700:4700::1111]/dns-query or https://dns.example.net/dns-query"
	}
	invalid := fmt.Errorf("%q: the host must be an address or a host name, with or without a port, as %s", s, example)
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" {
		return "", false, invalid
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
		if scheme == "tls" {
			return "", false, fmt.Errorf("%q: DNS over TLS takes a host, with or without a port: no user, query or fragment", s)
		}
		return "", false, fmt.Errorf("%q: DNS over HTTPS takes a host, with or without a port, and a path: no user, query or fragment", s)
	}
	switch {
	case scheme == "tls" && u.Path != "":
		return "", false, fmt.Errorf("%q: DNS over TLS takes a host, with or without a port, and no path: paths are for https://", s)
	case scheme == "https" && (u.Path == "" || u.Path == "/"):
		return "", false, fmt.Errorf("%q: DNS over HTTPS needs a path, as %s/dns-query", s, strings.TrimSuffix(s, "/"))
	}
	host, port := u.Hostname(), u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", false, invalid
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", false, fmt.Errorf("%q: the port %s is out of range: ports go from 1 to 65535", s, port)
		}
	}
	if a, err := netip.ParseAddr(host); err == nil {
		// An IPv6 address in brackets, as a URL has it, and of no zone.
		if a.Zone() != "" || a.Is6() && !strings.Contains(u.Host, "[") {
			return "", false, invalid
		}
		return strings.TrimSpace(s), false, nil
	}
	name := strings.TrimSuffix(host, ".")
	if _, ok := dns.IsDomainName(name); !ok || !strings.Contains(name, ".") || strings.ContainsAny(name, "[]:/ %") {
		return "", false, invalid
	}
	return strings.TrimSpace(s), true, nil
}

// parseServerAddress reads a server's address, with a port or not, as host:port.
func parseServerAddress(s string) (string, error) {
	invalid := fmt.Errorf("%q is not an address, with or without a port, as 192.168.1.1, 1.1.1.1:53 or [2001:db8::1]:53", s)
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil && a.Zone() == "" {
		return net.JoinHostPort(a.Unmap().String(), resolver.DefaultPort), nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil || ap.Port() == 0 {
		return "", invalid
	}
	return ap.String(), nil
}

// DefaultResolverDebounce is the debounce of a resolver credential that gives none: nothing is
// sent anywhere, so a change is answered at once.
const DefaultResolverDebounce = time.Duration(0)

// listenTransport reads the scheme of a listen entry: tls://, https:// or quic://, the encrypted
// transport it answers over, and the rest of the entry; none, for plain DNS. A path after an
// https:// entry can only be /dns-query, where DNS over HTTPS answers.
func listenTransport(line string) (transport, rest string) {
	line = strings.TrimSpace(line)
	for _, t := range []string{resolver.TransportTLS, resolver.TransportHTTPS, resolver.TransportQUIC} {
		if after, ok := strings.CutPrefix(strings.ToLower(line), t+"://"); ok {
			rest = line[len(line)-len(after):]
			if t == resolver.TransportHTTPS {
				rest = strings.TrimSuffix(rest, resolver.DoHPath)
			}
			return t, rest
		}
	}
	return "", line
}

// checkCertificate tells of a resolver that has encrypted entries and no certificate, or one
// without the other, or a certificate and its key that don't read as a pair; or, with ACME, no
// name, or a credential that isn't there to write its challenge. It sets the files of t.
func (c *Config) checkCertificate(path, name string, t *TLS, encrypted bool) error {
	schemes, example := "tls://, https:// or quic://", "tls://192.168.1.0/24"
	if path == "webserver" {
		schemes, example = "https://", "https://192.168.1.2"
	}
	switch {
	case encrypted && t == nil:
		return fmt.Errorf("%s.tls is missing: an entry of listen is encrypted, %s, and the clients must be shown a certificate: give tls.certificate and tls.key, the files of the certificate and of its key, in PEM, or tls.acme, for ipv6ddns to get one", path, schemes)
	case !encrypted && t != nil:
		return fmt.Errorf("%s.tls is for the encrypted entries of listen, and there is none: add one, as %s, or leave tls out", path, example)
	case !encrypted:
		return nil
	}
	if t.ACME == nil {
		if t.Certificate == "" || t.Key == "" {
			return fmt.Errorf("%s.tls: give tls.certificate and tls.key, the files of the certificate and of its key, in PEM, or tls.acme, for ipv6ddns to get one", path)
		}
		t.CertFile, t.KeyFile = inFolder(c.BaseDir, t.Certificate), inFolder(c.BaseDir, t.Key)
		if _, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile); err != nil {
			return fmt.Errorf("%s.tls: %s and %s: %w", path, t.CertFile, t.KeyFile, err)
		}
		return nil
	}
	a := t.ACME
	switch credential, ok := c.Credentials[a.Credential]; {
	case len(a.Names) == 0:
		return fmt.Errorf("%s.tls.acme.names is missing: give the names the clients use, relative to the zone of the credential, as dns.lan", path)
	case a.Credential == "":
		return fmt.Errorf("%s.tls.acme.credential is missing: give the credential of the public zone of the names, which writes the TXT record that the authority checks", path)
	case !ok:
		return fmt.Errorf("%s.tls.acme.credential: there is no credential %s", path, a.Credential)
	case credential.Provider == ResolverProvider:
		return fmt.Errorf("%s.tls.acme.credential: %s is a zone of the resolver, which the authority can't ask: give the credential of the public zone of the names", path, a.Credential)
	case (t.Certificate == "") != (t.Key == ""):
		return fmt.Errorf("%s.tls: give both certificate and key, where ipv6ddns writes them, or neither, for %s/%s/", path, acmeFolder, name)
	}
	certificate, key := t.Certificate, t.Key
	if certificate == "" {
		certificate, key = filepath.Join(acmeFolder, name, acmeCertificate), filepath.Join(acmeFolder, name, acmeKey)
	}
	t.CertFile, t.KeyFile = inFolder(c.BaseDir, certificate), inFolder(c.BaseDir, key)
	t.AccountKeyFile = filepath.Join(filepath.Dir(t.CertFile), acmeAccountKey)
	return nil
}

// inFolder is the path of a file, relative to the folder unless absolute.
func inFolder(folder, file string) string {
	if file == "" || filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(folder, file)
}
