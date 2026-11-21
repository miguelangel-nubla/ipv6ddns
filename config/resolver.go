package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
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
	// Required. Where it answers, as listen takes it; without a port, 53.
	Listen StringList `json:"listen,omitempty"`
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
	// Whether it answers itself the reverse of the private networks' addresses that it has no name
	// of, with no such name, as RFC 6303 asks: but of a network an upstream server is in. Default:
	// true.
	PrivateReverse *bool `json:"private_reverse,omitempty"`

	// The resolver, checked, with its zones.
	Spec resolver.Config `json:"-"`
}

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
			return fmt.Errorf("resolvers.%s.listen: where the resolver answers is to be given: the network of its clients, as 192.168.1.0/24, for the machine's address in it, or that address; without a port, 53", name)
		}
		if _, ok := r["upstream"]; !ok {
			return fmt.Errorf("resolvers.%s.upstream: the servers the resolver asks what isn't its own are to be given, one or more, as 192.168.1.1 or 1.1.1.1:53: without them, it would answer no other name", name)
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
			return fmt.Errorf("%s.listen: where the resolver answers is to be given", path)
		}
		// One by one: each entry with its text, as written, which the errors at start quote.
		for _, line := range r.Listen {
			entries, err := listen.Parse([]string{line}, resolver.DefaultPort)
			if err != nil {
				return fmt.Errorf("%s.listen: %w", path, err)
			}
			if e := entries[0]; !slices.Contains(spec.Listen, e) {
				spec.Listen = append(spec.Listen, e)
				spec.ListenLines = append(spec.ListenLines, strings.TrimSpace(line))
			}
		}
		for _, e := range spec.Listen {
			if other, ok := listening[e.String()]; ok {
				return fmt.Errorf("resolvers %s and %s both listen on %s: an address and port is one resolver's", other, name, e)
			}
			listening[e.String()] = name
		}
		spec.CacheSize = resolver.DefaultCacheSize
		if r.CacheSize != nil {
			spec.CacheSize = *r.CacheSize
		}
		spec.PrivateReverse = r.PrivateReverse == nil || *r.PrivateReverse
		for _, a := range r.Allow {
			p, err := parseNetwork(a)
			if err != nil {
				return fmt.Errorf("%s.allow: %w", path, err)
			}
			spec.Allow = append(spec.Allow, p)
		}
		if len(r.Upstream) == 0 {
			return fmt.Errorf("%s.upstream: the servers the resolver asks what isn't its own are to be given, one or more", path)
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
			return fmt.Errorf("%s.upstream: %q %s: its addresses are asked of bootstrap, the servers for that alone, which is to be given, as bootstrap: 9.9.9.9; not the system's resolver, which can be this one", path, named, is)
		case named == "" && len(spec.Bootstrap) > 0:
			return fmt.Errorf("%s.bootstrap: the servers that find the upstream servers given by host name, and every upstream is an address: leave it out", path)
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
			return fmt.Errorf("%s: the provider resolver is a zone that a resolver answers, and there is none: add one to resolvers, with where it listens and the servers it asks", path)
		case name == "" && len(names) > 1:
			return fmt.Errorf("%s.settings.resolver: which resolver answers the zone is to be said, of %s", path, strings.Join(names, ", "))
		case name == "":
			name = names[0]
		}
		r, ok := c.Resolvers[name]
		if !ok {
			if len(names) == 0 {
				return fmt.Errorf("%s.settings.resolver: %s is no resolver: resolvers has none", path, name)
			}
			return fmt.Errorf("%s.settings.resolver: %s is no resolver: they are %s", path, name, strings.Join(names, ", "))
		}
		zone := strings.Trim(settings.Zone, ".")
		if zone == "" {
			return fmt.Errorf("%s.settings.zone: the zone the resolver answers is to be given, as home.arpa", path)
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
	return netip.Prefix{}, fmt.Errorf("%q: a network, as 192.168.1.0/24 or fd00::/64, or an address", s)
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
	invalid := fmt.Errorf("%q: an address or a host name, with a port or not, as 192.168.1.1, 1.1.1.1:53, [2001:db8::1]:53 or dns.example.net", s)
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
		return "", false, fmt.Errorf("%q: the scheme %s: an upstream is plain DNS, as 1.1.1.1 or dns.example.net, tls:// for DNS over TLS, as tls://1.1.1.1, or https:// for DNS over HTTPS, as https://dns.example.net/dns-query", s, scheme)
	}
	example := "tls://1.1.1.1, tls://[2606:4700:4700::1111]:853 or tls://dns.example.net"
	if scheme == "https" {
		example = "https://1.1.1.1/dns-query, https://[2606:4700:4700::1111]/dns-query or https://dns.example.net/dns-query"
	}
	invalid := fmt.Errorf("%q: the host is an address or a host name, with a port or not, as %s", s, example)
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" {
		return "", false, invalid
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
		if scheme == "tls" {
			return "", false, fmt.Errorf("%q: DNS over TLS is a host, with a port or not: no user, query or fragment", s)
		}
		return "", false, fmt.Errorf("%q: DNS over HTTPS is a host, with a port or not, and a path: no user, query or fragment", s)
	}
	switch {
	case scheme == "tls" && u.Path != "":
		return "", false, fmt.Errorf("%q: DNS over TLS is a host, with a port or not: no path, which is of https://", s)
	case scheme == "https" && (u.Path == "" || u.Path == "/"):
		return "", false, fmt.Errorf("%q: DNS over HTTPS is asked at a path, which is to be given, as %s/dns-query", s, strings.TrimSuffix(s, "/"))
	}
	host, port := u.Hostname(), u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", false, invalid
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", false, fmt.Errorf("%q: the port %s: a port is from 1 to 65535", s, port)
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
	invalid := fmt.Errorf("%q: an address, with a port or not, as 192.168.1.1, 1.1.1.1:53 or [2001:db8::1]:53", s)
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
