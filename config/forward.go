package config

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// Forward is a domain whose names, of those a resolver would forward, it asks servers of their own
// instead of its upstream servers. See docs/resolver.md.
type Forward struct {
	// Required. The domain, with every name below it: lan.example.com, or 3.2.10.in-addr.arpa.
	Domain string `json:"domain,omitempty"`
	// Required. Its servers, in order, as the resolver's upstream.
	Upstream StringList `json:"upstream,omitempty"`
}

// setUpForwards reads the domains forwarded of a resolver, at path, into spec. It tells the first
// of their servers given by host name, which needs the resolver's bootstrap: "" for none.
func setUpForwards(path string, r Resolver, spec *resolver.Config) (string, error) {
	named := ""
	seen := map[string]int{}
	for i, f := range r.Forward {
		at := fmt.Sprintf("%s.forward[%d]", path, i)
		given := strings.TrimSpace(f.Domain)
		domain := strings.ToLower(strings.TrimSuffix(given, "."))
		switch {
		case given == "":
			return "", fmt.Errorf("%s.domain is missing: give the domain whose names its upstream servers are asked, as lan.example.com", at)
		case domain == "":
			return "", fmt.Errorf("%s.domain: %q is not a domain: the root would forward every name: give its servers as the resolver's upstream instead", at, f.Domain)
		case strings.Contains(domain, "://") || strings.ContainsAny(domain, " /:@*"):
			return "", fmt.Errorf("%s.domain: %q is not a domain: give the name alone, as lan.example.com or 3.2.10.in-addr.arpa, with no scheme, port, path or wildcard", at, f.Domain)
		}
		if _, ok := dns.IsDomainName(domain); !ok {
			return "", fmt.Errorf("%s.domain: %q is not a domain: give the name alone, as lan.example.com or 3.2.10.in-addr.arpa", at, f.Domain)
		}
		if j, ok := seen[domain]; ok {
			return "", fmt.Errorf("%s.domain: %s is forwarded already, by %s.forward[%d]: give each domain once, with all of its servers in its upstream", at, domain, path, j)
		}
		seen[domain] = i
		if len(f.Upstream) == 0 {
			return "", fmt.Errorf("%s.upstream is missing: give one or more servers to ask about the names of %s, as 10.2.3.204 or dns.%s. Without them, leave the domain out: its names are asked of the resolver's upstream", at, domain, domain)
		}
		forward := resolver.Forward{Domain: dns.Fqdn(domain)}
		for _, u := range f.Upstream {
			address, name, err := parseUpstream(u)
			if err != nil {
				return "", fmt.Errorf("%s.upstream: %w", at, err)
			}
			if name && named == "" {
				named = u
			}
			forward.Upstreams = append(forward.Upstreams, address)
		}
		spec.Forwards = append(spec.Forwards, forward)
	}
	return named, nil
}
