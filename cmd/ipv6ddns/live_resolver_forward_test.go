//go:build linux && integration

package main

// A domain forwarded to a server of its own, as the command runs it, asked by dig, on machines of
// one link.

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// A machine runs ipv6ddns with a resolver of a zone, lan.example.com, whose domain and a private
// network's reverse zone it forwards to a server of their own, as MAAS's, on another machine; its
// upstream is a third. A client asks it: the zone's record is its own, a name of the zone it
// hasn't is asked of the domain's server, and a name outside of the upstream; the reverse of an
// address of the network forwarded is the domain's server's, and of another private address no
// such name, of its own. The report, /status.json and /metrics have the domain forwarded with its
// server, and the failures of a second one that is down.
func TestLiveResolverForward(t *testing.T) {
	if _, err := exec.LookPath("dig"); err != nil {
		t.Fatal("the live tests of the resolver ask it with dig, of bind9-dnsutils: not found")
	}
	lan := livetest.NewLAN(t, 34)
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	maas := lan.Machine(t, "maas", 41)
	upstream := startUpstream(t, up, "192.0.2.53")
	forwarded := startUpstream(t, maas, "192.0.2.204")
	// A server of the reverse domain that never answers: the next is asked.
	down := lan.Machine(t, "down", 42)
	startUpstream(t, down, "192.0.2.1").mode.Store("down")

	config := fmt.Sprintf(`
listeners:
  web:
    listen:
      - http://8053
  lan:
    listen:
      - dns://%[1]s
webservers:
  main:
    listeners:
      - web
discovery:
  ipv6:
    enabled: false
resolvers:
  lan:
    listeners:
      - lan
    upstream: %[2]s
    forward:
      - domain: lan.example.com
        upstream:
          - %[3]s
      - domain: 3.2.10.in-addr.arpa
        upstream:
          - %[4]s
          - %[3]s
credentials:
  home:
    provider: resolver
    settings:
      zone: lan.example.com
      records:
        - printer A 198.18.34.50
tasks: {}
`, srv.IPv4, up.IPv4, maas.IPv4, down.IPv4)
	one := configure(t, srv, lan.Router, "srv", 8053, config).start().serving()
	server := srv.IPv4.String()

	for _, c := range []struct {
		args   []string
		status string
		// The data of the answers of a type.
		rrtype string
		want   []string
	}{
		{[]string{"printer.lan.example.com", "A"}, "NOERROR", "A", []string{"198.18.34.50"}},
		{[]string{"node1.lan.example.com", "A"}, "NOERROR", "A", []string{"192.0.2.204"}},
		{[]string{"www.example.com", "A"}, "NOERROR", "A", []string{"192.0.2.53"}},
		{[]string{"-x", "10.2.3.204"}, "NOERROR", "PTR", []string{reverseName}},
		{[]string{"-x", "10.2.4.1"}, "NXDOMAIN", "PTR", nil},
	} {
		d := dig(t, client, server, c.args...)
		if d.status != c.status || !slices.Equal(d.data(c.rrtype), c.want) {
			t.Errorf("%v: %s, want %s %q", c.args, d, c.status, c.want)
		}
	}
	for _, c := range []struct {
		name string
		// Of the domain's server, and of the upstream.
		forwarded, upstream int
	}{
		{"printer.lan.example.com.", 0, 0},
		{"node1.lan.example.com.", 1, 0},
		{"www.example.com.", 0, 1},
		{"204.3.2.10.in-addr.arpa.", 1, 0},
		{"1.4.2.10.in-addr.arpa.", 0, 0},
	} {
		if f, u := forwarded.times(c.name), upstream.times(c.name); f != c.forwarded || u != c.upstream {
			t.Errorf("%s: asked %d times of the domain's server, %d of the upstream; want %d and %d", c.name, f, u, c.forwarded, c.upstream)
		}
	}
	// Kept: asked again, of the cache.
	if d := dig(t, client, server, "node1.lan.example.com", "A"); !slices.Equal(d.data("A"), []string{"192.0.2.204"}) || forwarded.times("node1.lan.example.com.") != 1 {
		t.Errorf("node1.lan.example.com again: %s, asked %d times", d, forwarded.times("node1.lan.example.com."))
	}

	// The reports: of each domain, its servers, and of the one down, its failure.
	downServer := down.IPv4.String() + ":53"
	report := one.page("/")
	for _, want := range []string{
		fmt.Sprintf("        Forward: lan.example.com to %s:53 (0 failed)\n", maas.IPv4),
		fmt.Sprintf("        Forward: 3.2.10.in-addr.arpa to %s (1 failed), %s:53 (0 failed)\n", downServer, maas.IPv4),
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the report without %q:\n%s", want, report)
		}
	}
	metrics := one.page("/metrics")
	for _, want := range []string{
		fmt.Sprintf(`ipv6ddns_resolver_forward_failures_total{resolver="lan",domain="3.2.10.in-addr.arpa",upstream="%s"} 1`, downServer),
		fmt.Sprintf(`ipv6ddns_resolver_forward_failures_total{resolver="lan",domain="lan.example.com",upstream="%s:53"} 0`, maas.IPv4),
		fmt.Sprintf(`ipv6ddns_resolver_upstream_failures_total{resolver="lan",upstream="%s:53"} 0`, up.IPv4),
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics without %s:\n%s", want, metrics)
		}
	}
	status := one.status()
	if len(status.Resolvers) != 1 || len(status.Resolvers[0].Forwards) != 2 {
		t.Fatalf("/status.json: %+v", status.Resolvers)
	}
	if f := status.Resolvers[0].Forwards[0]; f.Domain != "lan.example.com" || !slices.Equal(f.Upstreams, []string{maas.IPv4.String() + ":53"}) || len(f.UpstreamFailures) != 1 || f.UpstreamFailures[maas.IPv4.String()+":53"] != 0 {
		t.Errorf("/status.json: the domain forwarded: %+v", f)
	}
	if failures := status.Resolvers[0].UpstreamFailures; len(failures) != 1 || failures[up.IPv4.String()+":53"] != 0 {
		t.Errorf("/status.json: the upstream's failures %v, want of %s:53 alone, none", failures, up.IPv4)
	}
	f := status.Resolvers[0].Forwards[1]
	if f.Domain != "3.2.10.in-addr.arpa" || !slices.Equal(f.Upstreams, []string{downServer, maas.IPv4.String() + ":53"}) || f.UpstreamFailures[downServer] != 1 {
		t.Errorf("/status.json: the reverse domain forwarded: %+v", f)
	}
}
