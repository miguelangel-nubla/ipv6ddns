//go:build linux && integration

package main

import (
	"fmt"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// A filter by how an address was seen, of the command as it is built: a host that announces its
// address with a real avahi-daemon, and one that runs none. The name of what was announced over
// mDNS has the first's address alone; the name of what nothing announced, the other's; and the
// status says how each was seen.
func TestLiveSeen(t *testing.T) {
	if _, err := exec.LookPath("dig"); err != nil {
		t.Fatal("the live tests of the resolver ask it with dig, of bind9-dnsutils: not found")
	}
	lan := livetest.NewLAN(t, 26)
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	loud, quiet := lan.Machine(t, "loud", 20), lan.Machine(t, "quiet", 21)
	loud.Avahi(t, "loud")
	startUpstream(t, up, "192.0.2.53")

	one := configure(t, srv, lan.Router, "srv", 8053, fmt.Sprintf(`
listeners:
  web:
    listen:
      - http://8053
  lan:
    listen:
      - dns://198.18.26.0/24
webservers:
  main:
    listeners:
      - web
discovery:
  rediscover: 3s
  protocols:
    mdns:
      enabled: true
resolvers:
  lan:
    listeners:
      - lan
    upstream: %s
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
tasks:
  announced:
    filter:
      - ip:
          prefix: "%[2]s"
          seen:
            - protocol: mdns
              way: announced
    endpoints:
      home:
        - announced
  unannounced:
    filter:
      # loud and quiet: every other machine of the link answers the ping too, and announces nothing.
      - mac:
          address: "%[3]s"
        ip:
          prefix: "%[2]s"
          seen:
            - protocol: ping
          not_seen:
            - protocol: mdns
              way: announced
      - mac:
          address: "%[4]s"
        ip:
          prefix: "%[2]s"
          seen:
            - protocol: ping
          not_seen:
            - protocol: mdns
              way: announced
    endpoints:
      home:
        - unannounced
`, up.IPv4, lan.Prefix(), loud.MAC, quiet.MAC)).start().serving()
	server := srv.IPv4.String()
	aaaa := func(name string) []string { return dig(t, client, server, name, "AAAA").data("AAAA") }

	waitFor(t, 60*time.Second, "the announced name, with loud's address alone", func() bool {
		return slices.Equal(aaaa("announced.home.arpa"), []string{loud.IPv6.String()})
	}, one.tells, func() string { return dig(t, client, server, "announced.home.arpa", "AAAA").String() })
	// loud's address can be there a moment, before its announcement comes: not_seen judges the
	// records there are. Once announced, it is left.
	waitFor(t, 30*time.Second, "the unannounced name, with quiet's address alone", func() bool {
		return slices.Equal(aaaa("unannounced.home.arpa"), []string{quiet.IPv6.String()})
	}, one.tells, func() string { return dig(t, client, server, "unannounced.home.arpa", "AAAA").String() })
	// It stays so: loud never comes to the second, nor quiet to the first.
	time.Sleep(5 * time.Second)
	if got := aaaa("announced.home.arpa"); !slices.Equal(got, []string{loud.IPv6.String()}) {
		t.Errorf("announced: %v", got)
	}
	if got := aaaa("unannounced.home.arpa"); !slices.Equal(got, []string{quiet.IPv6.String()}) {
		t.Errorf("unannounced: %v", got)
	}

	// The status says how each was seen.
	seen := func(mac, address string) []string {
		for _, h := range one.status().Discovered {
			if h.MAC != mac {
				continue
			}
			for _, a := range h.Addresses {
				if a.Address != address {
					continue
				}
				var out []string
				for _, r := range a.Seen {
					out = append(out, r.Protocol+":"+r.Way)
				}
				return out
			}
		}
		return nil
	}
	if got := seen(loud.MAC, loud.IPv6.String()); !slices.Contains(got, "mdns:announced") || !slices.Contains(got, "ping:answered") {
		t.Errorf("loud's address in the status: %v", got)
	}
	if got := seen(quiet.MAC, quiet.IPv6.String()); slices.Contains(got, "mdns:announced") || !slices.Contains(got, "ping:answered") {
		t.Errorf("quiet's address in the status: %v", got)
	}
}
