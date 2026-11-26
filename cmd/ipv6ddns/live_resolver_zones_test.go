//go:build linux && integration

package main

// One zone of two resolvers, as the command runs them, asked by dig, on machines of one link.

import (
	"fmt"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// A machine runs ipv6ddns with two resolvers, lan and kids, on two addresses of its own, which
// differ in upstream and allow, and one credential whose zone both answer. A client asks each the
// name of the zone's task, with the address discovered, its written record and the reverse of
// the address: each gives the same, with authority, and neither asks its upstream any of them.
func TestLiveResolverZoneOfTwo(t *testing.T) {
	if _, err := exec.LookPath("dig"); err != nil {
		t.Fatal("the live tests of the resolver ask it with dig, of bind9-dnsutils: not found")
	}
	lan := livetest.NewLAN(t, 32)
	srv := lan.Machine(t, "srv", 10)
	peer := lan.Machine(t, "peer", 20)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	up2 := lan.Machine(t, "up2", 41)
	// The kids' resolver's address, of the same machine.
	kids := "198.18.32.11"
	srv.IP(t, "addr", "add", kids+"/24", "dev", srv.Interface)
	lanUpstream := startUpstream(t, up, "192.0.2.53")
	kidsUpstream := startUpstream(t, up2, "192.0.2.54")

	config := fmt.Sprintf(`
listeners:
  web:
    listen:
      - http://8053
  lan:
    listen:
      - dns://%[1]s
  kids:
    listen:
      - dns://%[2]s
webservers:
  main:
    listeners:
      - web
discovery:
  lifetime: 9s
  rediscover: 3s
  solicit:
    ipv6: true
resolvers:
  lan:
    listeners:
      - lan
    upstream: %[3]s
  kids:
    listeners:
      - kids
    allow:
      - 198.18.32.0/26
    upstream: %[4]s
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
      resolvers:
        - lan
        - kids
      records:
        - printer A 198.18.32.50
tasks:
  peer:
    filter:
      - mac:
          address: "%[5]s"
        ip:
          prefix: "%[6]s"
    endpoints:
      home:
        - peer
`, srv.IPv4, kids, up.IPv4, up2.IPv4, peer.MAC, lan.Prefix())
	one := configure(t, srv, lan.Router, "srv", 8053, config).start().serving()

	servers := []string{srv.IPv4.String(), kids}
	for _, server := range servers {
		waitFor(t, 60*time.Second, "the peer's address, answered at "+server, func() bool {
			return slices.Equal(dig(t, client, server, "peer.home.arpa", "AAAA").data("AAAA"), []string{peer.IPv6.String()})
		}, one.tells)
	}
	for _, server := range servers {
		for _, c := range []struct {
			args []string
			// The data of the answers of a type, or with none, the answers.
			rrtype string
			want   []string
		}{
			{[]string{"peer.home.arpa", "AAAA"}, "", []string{"peer.home.arpa. AAAA " + peer.IPv6.String()}},
			{[]string{"printer.home.arpa", "A"}, "", []string{"printer.home.arpa. A 198.18.32.50"}},
			{[]string{"-x", peer.IPv6.String()}, "PTR", []string{"peer.home.arpa."}},
			{[]string{"-x", "198.18.32.50"}, "PTR", []string{"printer.home.arpa."}},
		} {
			d := dig(t, client, server, c.args...)
			got := d.answers
			if c.rrtype != "" {
				got = d.data(c.rrtype)
			}
			if d.status != "NOERROR" || !slices.Equal(got, c.want) || !d.has("aa") {
				t.Errorf("%v at %s: %s, want %q, with authority", c.args, server, d, c.want)
			}
		}
	}
	// The zone's names are its own, at each: never forwarded.
	for _, name := range []string{"peer.home.arpa.", "printer.home.arpa."} {
		if n, m := lanUpstream.times(name), kidsUpstream.times(name); n != 0 || m != 0 {
			t.Errorf("%s forwarded: %d times by lan, %d by kids", name, n, m)
		}
	}
}
