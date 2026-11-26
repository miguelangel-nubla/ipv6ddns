//go:build linux && integration

package main

// Two resolvers' listeners on one address and port of each encrypted transport, as the command
// serves them on a real link: kdig, asking each name, gets each resolver's answer, and asking
// none, as a client by address alone, the first listener's.

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// The names of the two listeners' certificates: lan's, and kids', with its wildcard.
const (
	sharedLanHost  = "dns.lan.home.arpa"
	sharedKidsHost = "kids.dns.local.home.arpa"
)

// A machine runs ipv6ddns with two resolvers, lan and kids, whose listeners share the address's
// ports of TLS, HTTPS and QUIC, each with a certificate of its own names and a record of its
// own for one name. A client asks that name with kdig over each transport, by each listener's
// name, checking its certificate, and gets that resolver's address; by no name, the first
// listener's, lan's. Each resolver's DDR tells its own name, and the report the sockets shared.
func TestLiveResolverShared(t *testing.T) {
	for _, tool := range []string{"dig", "kdig"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("the live test of shared listeners asks with %s, of bind9-dnsutils and knot-dnsutils: not found", tool)
		}
	}
	lan := livetest.NewLAN(t, 31)
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	lanCA, lanCert, lanKey := writeTestCAFor(t, t.TempDir(), sharedLanHost)
	kidsCA, kidsCert, kidsKey := writeTestCAFor(t, t.TempDir(), "dns.local.home.arpa", "*.dns.local.home.arpa")
	address := srv.IPv4.String()

	config := fmt.Sprintf(`
listeners:
  web:
    listen:
      - http://8053
  lan:
    listen:
      - dns://%[1]s
      - "tls://%[1]s"
      - "https://%[1]s"
      - "quic://%[1]s"
    tls: lan
    allow:
      - 0.0.0.0/0
  kids:
    listen:
      - dns://%[1]s:5300
      - "tls://%[1]s:853"
      - "https://%[1]s/dns-query"
      - "quic://%[1]s"
    tls: kids
    server_name: %[6]s
    allow:
      - 0.0.0.0/0
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
    records:
      - who.home.example. A 198.18.31.1
  kids:
    listeners:
      - kids
    upstream: 192.0.2.1
    records:
      - who.home.example. A 198.18.31.2
certificates:
  lan:
    certificate: %[2]s
    key: %[3]s
  kids:
    certificate: %[4]s
    key: %[5]s
credentials:
  home:
    provider: resolver
    settings:
      resolver: lan
      zone: home.arpa
tasks:
  nobody:
    filter:
      - mac:
          address: "02:00:00:00:00:99"
    endpoints:
      home:
        - nobody
`, address, lanCert, lanKey, kidsCert, kidsKey, sharedKidsHost)
	one := configure(t, srv, lan.Router, "srv", 8053, config).start().serving()

	for _, transport := range []string{"+tls", "+https", "+quic"} {
		for _, c := range []struct {
			name, ca, want string
		}{
			{sharedLanHost, lanCA, "198.18.31.1"},
			{sharedKidsHost, kidsCA, "198.18.31.2"},
		} {
			got, err := kdig(t, client, address, transport, "+tls-ca="+c.ca, "+tls-hostname="+c.name, "who.home.example", "A")
			if err != nil || got != c.want {
				t.Errorf("kdig %s, asking %s: %q, %v; want %s", transport, c.name, got, err, c.want)
			}
		}
		// No name, and no certificate checked, as Android's opportunistic DNS asks by address.
		if got, err := kdig(t, client, address, transport, "who.home.example", "A"); err != nil || got != "198.18.31.1" {
			t.Errorf("kdig %s, asking no name: %q, %v; want lan's, 198.18.31.1", transport, got, err)
		}
	}

	// Each resolver's DDR, at its plain address: its own name, of every transport.
	for _, c := range []struct {
		port, want, other string
	}{{"53", sharedLanHost, sharedKidsHost}, {"5300", sharedKidsHost, sharedLanHost}} {
		d := dig(t, client, address, "-p", c.port, "_dns.resolver.arpa", "SVCB")
		all := strings.ReplaceAll(strings.Join(d.answers, "\n"), "key7=", "dohpath=")
		if d.status != "NOERROR" || len(d.answers) != 3 {
			t.Errorf("DDR at port %s: a record of each transport wanted:\n%s", c.port, d.output)
		}
		for _, has := range []string{" " + c.want + ". ", `alpn="dot"`, `alpn="h2"`, `alpn="doq"`, "hint=" + address} {
			if !strings.Contains(all, has) {
				t.Errorf("DDR at port %s: no %q in\n%s", c.port, has, all)
			}
		}
		if strings.Contains(all, c.other) {
			t.Errorf("DDR at port %s: the other's name, %s, in\n%s", c.port, c.other, all)
		}
	}

	report := one.page("/status.txt")
	for _, has := range []string{
		"Shared: tls://" + address + ":853, listener lan, with kids: the clients that ask " + sharedLanHost + ", or another name, or none",
		"Shared: quic://" + address + ":853, listener kids, with lan: the clients that ask " + sharedKidsHost + "\n",
		"Shared: https://" + address + ":443, listener kids, with lan",
	} {
		if !strings.Contains(report, has) {
			t.Errorf("the report has no %q:\n%s", has, report)
		}
	}
}
