//go:build linux && integration

package main

// The discovery of the resolver's encrypted transports, RFC 9462, as the command answers it on a
// real link: the SVCB records of _dns.resolver.arpa, asked with dig over IPv4 and IPv6.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// A machine runs ipv6ddns with a resolver over plain DNS, TLS, HTTPS and QUIC, its entries once
// of its addresses and once of ports alone, every address. A client asks _dns.resolver.arpa over
// each family and gets a record of each transport, for the certificate's name, with the address
// it asked as a hint, and no hint a client can't use: an unspecified or link-local one.
func TestLiveResolverDDR(t *testing.T) {
	const everyone = `
    allow:
      - 0.0.0.0/0
      - ::/0`
	for _, c := range []struct {
		name   string
		allow  string
		listen func(m *livetest.Machine) string
	}{
		{"its addresses", everyone, func(m *livetest.Machine) string {
			return fmt.Sprintf(`
      - dns://%[1]s
      - dns://[%[2]s]
      - "tls://%[1]s"
      - "tls://[%[2]s]"
      - "https://%[1]s"
      - "https://[%[2]s]"
      - "quic://%[1]s"
      - "quic://[%[2]s]"`, m.IPv4, m.IPv6)
		}},
		{"ports alone", everyone, func(*livetest.Machine) string {
			return `
      - dns://53
      - tls://853
      - https://443
      - quic://853`
		}},
		// Without allow, a port alone answers every network of the machine, of both families: its
		// socket is one of IPv6 that takes IPv4 too, and was once read as of IPv6 alone, so that
		// the client's query over IPv4 was refused.
		{"ports alone, without allow", "", func(*livetest.Machine) string {
			return `
      - dns://53
      - tls://853
      - https://443
      - quic://853`
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			lan := livetest.NewLAN(t, 30)
			srv := lan.Machine(t, "srv", 10)
			client := lan.Machine(t, "client", 30)
			_, certFile, keyFile := writeTestCA(t, t.TempDir())
			config := fmt.Sprintf(`
listeners:
  web:
    listen:
      - http://8053
  lan:
    listen:%s
    tls: home%s
webservers:
  main:
    listeners:
      - web
resolvers:
  lan:
    listeners:
      - lan
    # Nothing is forwarded in this test: a server that doesn't answer.
    upstream: 192.0.2.1
certificates:
  home:
    certificate: %s
    key: %s
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
tasks:
  nobody:
    filter:
      - mac:
          address: "02:00:00:00:00:99"
    endpoints:
      home:
        - nobody
`, c.listen(srv), c.allow, certFile, keyFile)
			configure(t, srv, lan.Router, "srv", 8053, config).start().serving()

			for _, asked := range []string{srv.IPv4.String(), srv.IPv6.String()} {
				d := dig(t, client, asked, "_dns.resolver.arpa", "SVCB")
				// A record of each entry: of each transport, and of each address an entry has one of.
				if d.status != "NOERROR" || len(d.answers) < 3 {
					t.Errorf("asked at %s: a record of each transport wanted:\n%s", asked, d.output)
					continue
				}
				// dig of BIND 9.18 writes dohpath by its number, key7.
				all := strings.ReplaceAll(strings.Join(d.answers, "\n"), "key7=", "dohpath=")
				for _, has := range []string{" " + encryptedHost + ". ", `alpn="dot"`, `alpn="h2"`, `alpn="doq"`, `dohpath="/dns-query{?dns}"`, "hint=" + asked} {
					if !strings.Contains(all, has) {
						t.Errorf("asked at %s: no %q in\n%s", asked, has, all)
					}
				}
				for _, hasnt := range []string{"hint=0.0.0.0", "::,", "hint=::\n", "fe80:", "port="} {
					if strings.Contains(all+"\n", hasnt) {
						t.Errorf("asked at %s: %q in\n%s", asked, hasnt, all)
					}
				}
				for _, a := range d.answers {
					if !strings.Contains(a, "hint=") {
						t.Errorf("asked at %s: a record without hints: %s", asked, a)
					}
				}
			}
			// Another name of resolver.arpa is the resolver's, not forwarded.
			if d := dig(t, client, srv.IPv4.String(), "other.resolver.arpa", "A"); d.status != "NXDOMAIN" {
				t.Errorf("other.resolver.arpa: %s", d.output)
			}
		})
	}
}
