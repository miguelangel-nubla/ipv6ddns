package config

import (
	"slices"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/resolver"
)

// A resolver's domains forwarded are read in order, absolute and in lower case, each with its
// servers as the upstream's: of a port, encrypted, by host name with the resolver's bootstrap.
func TestResolverConfigForward(t *testing.T) {
	cfg, err := resolverConfig(t, `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    bootstrap: 9.9.9.9
    forward:
      - domain: Lan.Example.com.
        upstream:
          - 10.2.3.204
          - "10.2.3.205:5353"
      - domain: 3.2.10.in-addr.arpa
        upstream:
          - "tls://dns.example.net"
          - dns.example.net`, homeCredential, nasTask)
	if err != nil {
		t.Fatal(err)
	}
	want := []resolver.Forward{
		{Domain: "lan.example.com.", Upstreams: []string{"10.2.3.204:53", "10.2.3.205:5353"}},
		{Domain: "3.2.10.in-addr.arpa.", Upstreams: []string{"tls://dns.example.net", "dns.example.net:53"}},
	}
	got := cfg.Resolvers["lan"].Spec.Forwards
	if !slices.EqualFunc(got, want, func(a, b resolver.Forward) bool {
		return a.Domain == b.Domain && slices.Equal(a.Upstreams, b.Upstreams)
	}) {
		t.Errorf("forwards: %+v, want %+v", got, want)
	}
}

func TestResolverConfigForwardErrors(t *testing.T) {
	for _, c := range []struct{ name, resolvers, want string }{
		{"a domain twice", `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    forward:
      - domain: lan.example.com
        upstream: 10.2.3.204
      - domain: LAN.example.com.
        upstream: 10.2.3.205`,
			"resolvers.lan.forward[1].domain: lan.example.com is forwarded already, by resolvers.lan.forward[0]: give each domain once, with all of its servers in its upstream"},
		{"no domain", `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    forward:
      - upstream: 10.2.3.204`,
			"resolvers.lan.forward[0].domain is missing: give the domain whose names its upstream servers are asked, as lan.example.com"},
		{"the root", `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    forward:
      - domain: "."
        upstream: 10.2.3.204`,
			`resolvers.lan.forward[0].domain: "." is not a domain: the root would forward every name: give its servers as the resolver's upstream instead`},
		{"a domain of a URL", `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    forward:
      - domain: "dns://lan.example.com"
        upstream: 10.2.3.204`,
			`resolvers.lan.forward[0].domain: "dns://lan.example.com" is not a domain: give the name alone, as lan.example.com or 3.2.10.in-addr.arpa, with no scheme, port, path or wildcard`},
		{"a domain of an empty label", `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    forward:
      - domain: lan..example.com
        upstream: 10.2.3.204`,
			`resolvers.lan.forward[0].domain: "lan..example.com" is not a domain: give the name alone, as lan.example.com or 3.2.10.in-addr.arpa`},
		{"no upstream", `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    forward:
      - domain: lan.example.com`,
			"resolvers.lan.forward[0].upstream is missing: give one or more servers to ask about the names of lan.example.com, as 10.2.3.204 or dns.lan.example.com. Without them, leave the domain out: its names are asked of the resolver's upstream"},
		{"an empty upstream", `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    forward:
      - domain: lan.example.com
        upstream: []`,
			"resolvers.lan.forward[0].upstream is missing: give one or more servers to ask about the names of lan.example.com, as 10.2.3.204 or dns.lan.example.com. Without them, leave the domain out: its names are asked of the resolver's upstream"},
		{"an invalid upstream", `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    forward:
      - domain: lan.example.com
        upstream: "maas dns"`,
			`resolvers.lan.forward[0].upstream: "maas dns" is not an address or a host name, with or without a port, as 192.168.1.1, 1.1.1.1:53, [2001:db8::1]:53 or dns.example.net`},
		{"a host name without bootstrap", `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    forward:
      - domain: lan.example.com
        upstream: maas.example.com`,
			`resolvers.lan.forward: "maas.example.com" is a host name, and there's no bootstrap to look it up. Add bootstrap, servers used for that lookup only, as bootstrap: 9.9.9.9. The system's resolver isn't used, as it may be this one`},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := resolverConfig(t, c.resolvers, homeCredential, nasTask)
			if err == nil || err.Error() != c.want {
				t.Errorf("got %v\nwant %s", err, c.want)
			}
		})
	}
	// A bootstrap is wanted of a domain forwarded's host name alone.
	if _, err := resolverConfig(t, `
  lan:
    listeners:
      - lan
    upstream: 1.1.1.1
    bootstrap: 9.9.9.9
    forward:
      - domain: lan.example.com
        upstream: maas.example.com`, homeCredential, nasTask); err != nil {
		t.Errorf("a bootstrap of a forward's host name: %v", err)
	}
}
