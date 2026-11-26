package resolver

import (
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// Forward is a domain whose names, of those the resolver would forward, are asked of servers of its
// own rather than of its upstream servers: a local server that knows them, as of a zone that has
// more names than the resolver's, or of a network's reverse.
type Forward struct {
	// Absolute, in lower case.
	Domain string
	// As Config.Upstreams: in order, host:port, tls://host[:port] or https://host[:port]/path, the
	// host an address, or a host name, which the resolver's Bootstrap finds.
	Upstreams []string
}

// forwardZone is a domain forwarded at work, with its servers, which are its own: their failures
// and the addresses found for those given by host name apart from the upstream servers', of the
// same server or not.
type forwardZone struct {
	domain    string
	upstreams []*upstreamServer
	failures  map[string]*atomic.Uint64
	named     map[string]*namedUpstream
}

// parseUpstreams reads the servers of an upstream list, at path, as the configuration checked
// them: each counted in failures, and, given by host name, kept in named.
func (s *Server) parseUpstreams(path string, upstreams []string, failures map[string]*atomic.Uint64, named map[string]*namedUpstream) ([]*upstreamServer, error) {
	var servers []*upstreamServer
	for _, u := range upstreams {
		failures[u] = new(atomic.Uint64)
		srv, err := parseServer(u)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", path, u, err)
		}
		if srv.isName() {
			if len(s.config.Bootstrap) == 0 {
				return nil, fmt.Errorf("%s: %q is a host name, and there's no bootstrap to look it up", path, u)
			}
			srv.named = &namedUpstream{host: dns.Fqdn(srv.host), port: srv.port}
			named[u] = srv.named
		}
		servers = append(servers, srv)
	}
	return servers, nil
}

// newForwards reads the domains forwarded of cfg, each once and with its servers.
func (s *Server) newForwards() error {
	for i, f := range s.config.Forwards {
		path := fmt.Sprintf("%s.forward[%d]", s.config.Path, i)
		domain := strings.ToLower(dns.Fqdn(f.Domain))
		if _, ok := dns.IsDomainName(domain); !ok || domain == "." {
			return fmt.Errorf("%s.domain: %q is not a domain", path, f.Domain)
		}
		if slices.ContainsFunc(s.forwards, func(o *forwardZone) bool { return o.domain == domain }) {
			return fmt.Errorf("%s.domain: %s is forwarded twice", path, strings.TrimSuffix(domain, "."))
		}
		if len(f.Upstreams) == 0 {
			return fmt.Errorf("%s.upstream is empty", path)
		}
		z := &forwardZone{domain: domain, failures: make(map[string]*atomic.Uint64), named: make(map[string]*namedUpstream)}
		servers, err := s.parseUpstreams(path+".upstream", f.Upstreams, z.failures, z.named)
		if err != nil {
			return err
		}
		z.upstreams = servers
		s.forwards = append(s.forwards, z)
	}
	return nil
}

// forwardOf is the domain forwarded that name, absolute, is at or under, the deepest of those
// that hold it: nil for none, whose name the upstream servers are asked.
func (s *Server) forwardOf(name string) *forwardZone {
	name = strings.ToLower(dns.Fqdn(name))
	var deepest *forwardZone
	for _, z := range s.forwards {
		if dns.IsSubDomain(z.domain, name) && (deepest == nil || dns.CountLabel(z.domain) > dns.CountLabel(deepest.domain)) {
			deepest = z
		}
	}
	return deepest
}

// ForwardStatus is a domain a resolver forwards to servers of its own, for the report,
// /status.json and the metrics.
type ForwardStatus struct {
	Domain    string   `json:"domain"`
	Upstreams []string `json:"upstreams"`
	// The addresses the bootstrap servers found for its servers given by host name.
	UpstreamAddresses map[string][]string `json:"upstream_addresses,omitempty"`
	// The queries one of its servers didn't answer, by server.
	UpstreamFailures map[string]uint64 `json:"upstream_failures"`
}

// forwardsStatus is the domains forwarded, in the configuration's order: nil for none.
func (s *Server) forwardsStatus() []ForwardStatus {
	var statuses []ForwardStatus
	for _, z := range s.forwards {
		status := ForwardStatus{Domain: strings.TrimSuffix(z.domain, "."), UpstreamFailures: make(map[string]uint64),
			UpstreamAddresses: namedAddresses(z.named)}
		for _, srv := range z.upstreams {
			status.Upstreams = append(status.Upstreams, srv.label)
			status.UpstreamFailures[srv.label] = z.failures[srv.label].Load()
		}
		statuses = append(statuses, status)
	}
	return statuses
}

// namedAddresses are the addresses found of each server given by host name, by its text as
// configured: nil, when none has any yet.
func namedAddresses(named map[string]*namedUpstream) map[string][]string {
	var found map[string][]string
	for upstream, n := range named {
		n.mutex.Lock()
		if len(n.addresses) > 0 {
			if found == nil {
				found = make(map[string][]string)
			}
			found[upstream] = append([]string{}, n.addresses...)
		}
		n.mutex.Unlock()
	}
	return found
}
