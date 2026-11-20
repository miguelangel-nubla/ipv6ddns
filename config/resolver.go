package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/netip"
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
		var err error
		if len(r.Listen) == 0 {
			return fmt.Errorf("%s.listen: where the resolver answers is to be given", path)
		}
		if spec.Listen, err = listen.Parse(r.Listen, resolver.DefaultPort); err != nil {
			return fmt.Errorf("%s.listen: %w", path, err)
		}
		for _, e := range spec.Listen {
			if other, ok := listening[e.String()]; ok {
				return fmt.Errorf("resolvers %s and %s both listen on %s: an address and port is one resolver's", other, name, e)
			}
			listening[e.String()] = name
		}
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
			return fmt.Errorf("%s.upstream: %q is a host name: its addresses are asked of bootstrap, the servers for that alone, which is to be given, as bootstrap: [9.9.9.9]; not the system's resolver, which can be this one", path, named)
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
// or not. It tells whether it is a host name.
func parseUpstream(s string) (string, bool, error) {
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
