package config

import (
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
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// Resolver is a DNS server for the clients of a network: it answers the zones of its resolver
// credentials and its own records, and asks its upstream servers the rest. See docs/resolver.md.
type Resolver struct {
	// Required. The listeners it answers on, by name: their DNS entries, plain, of TLS and of
	// QUIC, and /dns-query of their HTTPS ones.
	Listeners StringList `json:"listeners,omitempty"`
	// The networks, or addresses, of the clients it answers; any other is refused. Default: the
	// networks of the machine's addresses it listens on.
	Allow AllowList `json:"allow,omitempty"`
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
	// The dynamic updates it takes, by RFC 2136, of the clients that hold a key.
	Updates *Updates `json:"updates,omitempty"`
	// What it answers as blocked, of the names it would forward: of blocklists, by name.
	Block *Block `json:"block,omitempty"`
	// The domains whose names, of those it would forward, are asked of servers of their own.
	Forward []Forward `json:"forward,omitempty"`

	// The resolver, checked, with its zones.
	Spec resolver.Config `json:"-"`
}

// ResolverProvider is the provider of a zone a resolver answers.
const ResolverProvider = "resolver"

// resolverSettings are the settings of a resolver credential that the configuration reads: the
// provider checks them all, at start.
type resolverSettings struct {
	Resolver  string            `json:"resolver"`
	Resolvers []string          `json:"resolvers"`
	Zone      string            `json:"zone"`
	Records   []string          `json:"records"`
	TTL       duration.Duration `json:"ttl"`
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
		for _, key := range []string{"listen", "tls"} {
			if _, ok := r[key]; ok {
				return fmt.Errorf("resolvers.%s.%s is a listener's now: move the resolver's listen and tls to one under listeners, its plain entries as dns://, and name it in the resolver's listeners, as\n\nlisteners:\n  %s:\n    listen:\n      - dns://192.168.1.2\n      - tls://192.168.1.2\n    tls: home\nresolvers:\n  %s:\n    listeners:\n      - %s", name, key, name, name, name)
			}
		}
		if _, ok := r["listeners"]; !ok {
			return fmt.Errorf("resolvers.%s.listeners is missing: give the listeners where the resolver answers, under listeners, as dns://192.168.1.2 for this machine's address on the clients' network. Without a port, 53", name)
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
	// What the keys of every resolver may change.
	claimed := make(claims)
	for _, name := range names {
		r := c.Resolvers[name]
		path := "resolvers." + name
		spec := resolver.Config{Name: name, Path: path}
		c.listenOnListeners(&spec, r.Listeners)
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
			// Of listeners that share it, which their set up checked.
			if e.Shared {
				continue
			}
			if err := claim(resolver.Protocol(e.Transport), e.Line, e.Entry); err != nil {
				return err
			}
		}
		spec.CacheSize = resolver.DefaultCacheSize
		if r.CacheSize != nil {
			spec.CacheSize = *r.CacheSize
		}
		spec.ForwardUnknownPrivateReverse = r.ForwardUnknownPrivateReverseQueries
		allow, err := parseAllow(path, r.Allow)
		if err != nil {
			return err
		}
		spec.Allow = allow
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
		forwardNamed, err := setUpForwards(path, r, &spec)
		if err != nil {
			return err
		}
		for _, b := range r.Bootstrap {
			address, err := parseServerAddress(b)
			if err != nil {
				return fmt.Errorf("%s.bootstrap: %w", path, err)
			}
			spec.Bootstrap = append(spec.Bootstrap, address)
		}
		// Of the upstream, or of a domain forwarded, whose servers the same bootstrap looks up.
		at := path + ".upstream"
		if named == "" && forwardNamed != "" {
			named, at = forwardNamed, path+".forward"
		}
		switch {
		case named != "" && len(spec.Bootstrap) == 0:
			is := "is a host name"
			if strings.Contains(named, "://") {
				is = "is at a host name"
			}
			return fmt.Errorf("%s: %q %s, and there's no bootstrap to look it up. Add bootstrap, servers used for that lookup only, as bootstrap: 9.9.9.9. The system's resolver isn't used, as it may be this one", at, named, is)
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
		if err := c.setUpUpdates(path, &r, &spec, claimed); err != nil {
			return err
		}
		if err := c.setUpBlock(path, r, &spec); err != nil {
			return err
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
		answering, err := zoneResolvers(path, settings, cred.RawSettings, names)
		if err != nil {
			return err
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
		// One zone of each resolver, and the same: its names' addresses, the provider's, are
		// shared by them all, which answer the same at once.
		for _, name := range answering {
			r := c.Resolvers[name]
			r.Spec.Zones = append(r.Spec.Zones, z)
			c.Resolvers[name] = r
		}
	}

	for _, name := range names {
		if err := resolver.Check(c.Resolvers[name].Spec); err != nil {
			return err
		}
	}
	return c.checkPushSources()
}

// zoneResolvers are the resolvers that answer the zone of a credential, at path: those its
// settings name, by resolver or resolvers, or the only one there is.
func zoneResolvers(path string, settings resolverSettings, raw json.RawMessage, names []string) ([]string, error) {
	var given struct {
		Resolvers json.RawMessage `json:"resolvers"`
	}
	_ = json.Unmarshal(raw, &given)
	listed := given.Resolvers != nil && string(given.Resolvers) != "null"
	unknown := func(key, name string) error {
		if len(names) == 0 {
			return fmt.Errorf("%s.settings.%s: there's no resolver %s: resolvers is empty", path, key, name)
		}
		return fmt.Errorf("%s.settings.%s: there's no resolver %s: the resolvers are %s", path, key, name, strings.Join(names, ", "))
	}
	switch {
	case listed && settings.Resolver != "":
		return nil, fmt.Errorf("%s.settings has both resolver and resolvers: give resolvers alone, with %s among them", path, settings.Resolver)
	case listed && len(settings.Resolvers) == 0 && len(names) == 0:
		return nil, fmt.Errorf("%s: the resolver provider is a zone that one of the resolvers answers, and there are none: add one under resolvers, with its listeners and upstream", path)
	case listed && len(settings.Resolvers) == 0:
		return nil, fmt.Errorf("%s.settings.resolvers is empty: give the resolvers that answer the zone, one or more of %s", path, strings.Join(names, ", "))
	case listed:
		for i, name := range settings.Resolvers {
			if slices.Contains(settings.Resolvers[:i], name) {
				return nil, fmt.Errorf("%s.settings.resolvers: %s is given twice: give each resolver once", path, name)
			}
			if !slices.Contains(names, name) {
				return nil, unknown("resolvers", name)
			}
		}
		return settings.Resolvers, nil
	}
	name := settings.Resolver
	switch {
	case name == "" && len(names) == 0:
		return nil, fmt.Errorf("%s: the resolver provider is a zone that one of the resolvers answers, and there are none: add one under resolvers, with its listeners and upstream", path)
	case name == "" && len(names) > 1:
		return nil, fmt.Errorf("%s.settings.resolver is missing: say which of %s answers the zone", path, strings.Join(names, ", "))
	case name == "":
		name = names[0]
	}
	if !slices.Contains(names, name) {
		return nil, unknown("resolver", name)
	}
	return []string{name}, nil
}

// listenOnListeners adds to spec the DNS entries of the listeners named, each with the listener's
// certificate and allow: plain DNS, DNS over TLS, over QUIC, and over HTTPS, whose other paths are
// the web server's that uses the listener too, if one does.
func (c *Config) listenOnListeners(spec *resolver.Config, names []string) {
	for _, name := range names {
		l := c.Listeners[name]
		for _, le := range l.Entries {
			switch le.Scheme {
			case SchemeHTTP:
				// The web server's.
			case SchemeDNS:
				if !slices.Contains(spec.Listen, le.Entry) {
					spec.Listen = append(spec.Listen, le.Entry)
					spec.ListenLines = append(spec.ListenLines, le.Line)
					spec.ListenAllow = append(spec.ListenAllow, l.Allowed)
					spec.ListenListeners = append(spec.ListenListeners, name)
				}
			default:
				enc := resolver.EncryptedListen{Transport: le.Scheme, Entry: le.Entry, Line: le.Line, CertificateName: l.TLS, Allow: l.Allowed,
					Listener: name, Rank: l.Rank, ServerName: l.ServerName, Shared: le.Shared}
				if le.Scheme == SchemeHTTPS && l.Web != "" {
					enc.Web = name
				}
				// Of two listeners that share it, both: each with its own certificate and allow.
				if !slices.ContainsFunc(spec.Encrypted, func(o resolver.EncryptedListen) bool {
					return o.Transport == enc.Transport && o.Entry == enc.Entry && (o.Listener == enc.Listener || !enc.Shared)
				}) {
					spec.Encrypted = append(spec.Encrypted, enc)
				}
			}
		}
	}
}

// checkPushSources tells of a push source without a password that no key sends addresses to: it
// would never have any.
func (c *Config) checkPushSources() error {
	fed := map[string]bool{}
	for _, r := range c.Resolvers {
		if r.Updates == nil {
			continue
		}
		for _, k := range r.Updates.Keys {
			for _, p := range k.Permissions {
				if p.Addresses != nil {
					fed[p.Addresses.Source] = true
				}
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Sources)) {
		if s := c.Sources[name]; s.Type == SourcePush && s.Password == "" && !fed[name] {
			return fmt.Errorf("source %s: a push source needs a password, which a router sends with its updates, or a key of a resolver's updates whose permission of addresses sends them", name)
		}
	}
	return nil
}

// parseNetwork reads a network of allow, or an address, which is a network of one.
// parseAllow reads an allow, of path: nil when it isn't given, for the default. One given that
// names nobody is refused, as the default it would be taken for lets more clients in than any
// list: for a web server, everyone.
func parseAllow(path string, allow AllowList) ([]netip.Prefix, error) {
	if allow != nil && len(allow) == 0 {
		return nil, fmt.Errorf("%s.allow is empty: give the clients, as 192.168.1.0/24, or leave allow out for the default. A variable that is empty, as in allow: ${ALLOWED}, gives an empty one", path)
	}
	var result []netip.Prefix
	for _, a := range allow {
		p, err := parseNetwork(a)
		if err != nil {
			return nil, fmt.Errorf("%s.allow: %w", path, err)
		}
		result = append(result, p)
	}
	return result, nil
}

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

// inFolder is the path of a file, relative to the folder unless absolute.
func inFolder(folder, file string) string {
	if file == "" || filepath.IsAbs(file) {
		return file
	}
	return filepath.Join(folder, file)
}
