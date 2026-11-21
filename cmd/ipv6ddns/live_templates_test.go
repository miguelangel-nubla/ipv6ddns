//go:build linux && integration

package main

import (
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// The names of a task's templates, of the command as it is built, on a link whose hosts say what
// they are called with a real mDNS responder, avahi-daemon: printer, laptop and nas.
//
// A resolver's zone and a DNS provider both have a name for each host, by its name; the zone has
// the numbered one and the one of its MAC too, and their reverse. A name written in the
// configuration, and a record of the zone, stay what they are written to be, whatever host is
// called so. A host that leaves loses its names at both, and has them again when it is back.
func TestLiveHostnameTemplates(t *testing.T) {
	if _, err := exec.LookPath("dig"); err != nil {
		t.Fatal("the live tests of the resolver ask it with dig, of bind9-dnsutils: not found")
	}
	lan := livetest.NewLAN(t, 22)
	router := lan.Router
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	printer, laptop, nas := lan.Machine(t, "printer", 20), lan.Machine(t, "laptop", 21), lan.Machine(t, "nas", 22)
	printer.Avahi(t, "printer")
	laptop.Avahi(t, "laptop")
	nas.Avahi(t, "nas")
	startUpstream(t, up, "192.0.2.53")
	dns := startProvider(t, router, 5390, "token-templates", "lan.example")

	one := configure(t, srv, router, "srv", 8053, fmt.Sprintf(`
webserver:
  listen:
    - 8053
discovery:
  lifetime: 9s
  rediscover: 3s
  protocols:
    mdns:
      enabled: true
resolvers:
  lan:
    listen: 198.18.22.0/24
    upstream: %[1]s
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - laptop A 192.0.2.77
%[4]stasks:
  hosts:
    filter:
      - ip:
          prefix: "%[2]s"
    endpoints:
      home:
        - "{hostname}"
        - "{n}.{hostname}"
        - "{mac}.by-mac"
      dns:
        - "{hostname}"
  written:
    filter:
      - mac:
          address: "%[3]s"
        ip:
          prefix: "%[2]s"
    endpoints:
      home:
        - nas
      dns:
        - nas
`, up.IPv4, lan.Prefix(), printer.MAC, dns.credential("dns", "1s"))).start().serving()
	server := srv.IPv4.String()
	aaaa := func(name string) []string { return dig(t, client, server, name, "AAAA").data("AAAA") }
	is := func(name string, m *livetest.Machine) func() bool {
		return func() bool { return slices.Equal(aaaa(name), []string{m.IPv6.String()}) }
	}
	tells := func(name string) func() string {
		return func() string { return dig(t, client, server, name, "AAAA").String() }
	}
	byMAC := func(m *livetest.Machine) string {
		return strings.ReplaceAll(m.MAC, ":", "") + ".by-mac.home.arpa"
	}

	// Each host, by its name, its place among those of the name, and its MAC.
	for _, c := range []struct {
		name string
		m    *livetest.Machine
	}{
		{"printer.home.arpa", printer}, {"1.printer.home.arpa", printer}, {byMAC(printer), printer},
		{"1.laptop.home.arpa", laptop}, {byMAC(laptop), laptop},
		{"1.nas.home.arpa", nas}, {byMAC(nas), nas},
	} {
		waitFor(t, 60*time.Second, c.name+", answered with its host's address", is(c.name, c.m), one.tells, tells(c.name))
	}
	if d := dig(t, client, server, "printer.home.arpa", "AAAA"); d.status != "NOERROR" || !d.has("aa") {
		t.Errorf("the name of a template isn't answered as the zone's own: %s", d)
	}
	// A second of the name there is none of: the upstream server's to answer.
	if d := dig(t, client, server, "2.printer.home.arpa", "A"); d.has("aa") || !slices.Equal(d.data("A"), []string{"192.0.2.53"}) {
		t.Errorf("the second printer, which there is none of: %s", d)
	}

	// The name written is its task's, the printer's addresses, and not of the host called nas; the
	// zone's record is the record, and not of the host called laptop.
	waitFor(t, 30*time.Second, "nas, the name written, with the addresses its task matches", is("nas.home.arpa", printer), one.tells, tells("nas.home.arpa"))
	if d := dig(t, client, server, "laptop.home.arpa", "A"); !slices.Equal(d.data("A"), []string{"192.0.2.77"}) {
		t.Errorf("laptop, the zone's record: %s", d)
	}
	if got := aaaa("laptop.home.arpa"); len(got) != 0 {
		t.Errorf("laptop, a record's name, has the address of the host called so: %v", got)
	}
	if told := one.logged("warn"); !slices.ContainsFunc(told, func(l string) bool {
		return strings.Contains(l, "nas.home.arpa is a name written in the configuration")
	}) {
		t.Errorf("the name written, which a host is called too, isn't told: %v", told)
	}

	// The reverse of the printer's address: every name of the zone that has it.
	reverse := dig(t, client, server, "-x", printer.IPv6.String()).data("PTR")
	for _, want := range []string{"printer.home.arpa.", "1.printer.home.arpa.", byMAC(printer) + ".", "nas.home.arpa."} {
		if !slices.Contains(reverse, want) {
			t.Errorf("the reverse of the printer's address has no %s: %v", want, reverse)
		}
	}

	// The reverse of an address of the LAN, a unique local one, that no name has: no such name, of
	// the resolver's own, as RFC 6303 has it, not asked of the upstream server.
	unnamed := strings.TrimSuffix(printer.IPv6.String(), "20") + "99"
	if d := dig(t, client, server, "-x", unnamed); d.status != "NXDOMAIN" || !d.has("aa") {
		t.Errorf("the reverse of %s, which no name has: %s", unnamed, d)
	}

	// The provider has a name for each, and the name written with its own addresses.
	for name, m := range map[string]*livetest.Machine{"printer.lan.example": printer, "laptop.lan.example": laptop, "nas.lan.example": printer} {
		waitFor(t, 30*time.Second, name+" at the provider", func() bool { return dns.has(name, m.IPv6) }, one.tells, dns.tells)
	}

	// The printer leaves: its names are gone from the zone, asked upstream now, and from the
	// provider; the others stay.
	printer.Leave(t)
	left := time.Now()
	waitFor(t, 40*time.Second, "the printer's name to go from the zone", func() bool {
		d := dig(t, client, server, "printer.home.arpa", "A")
		return !d.has("aa") && slices.Equal(d.data("A"), []string{"192.0.2.53"})
	}, one.tells)
	t.Logf("the printer's name went %s after it left, with a lifetime of 9s", time.Since(left).Round(100*time.Millisecond))
	// Its names by its name go with the name; the one of its MAC, with its address, which lasts
	// its lifetime after the last record of it: within the lifetime of its leaving, both.
	if got := aaaa("1.printer.home.arpa"); len(got) != 0 {
		t.Errorf("1.printer.home.arpa, of the printer that left: %v", got)
	}
	waitFor(t, time.Until(left.Add(9*time.Second+5*time.Second)), byMAC(printer)+" to go, a lifetime after the printer left", func() bool {
		return len(aaaa(byMAC(printer))) == 0
	}, one.tells)
	waitFor(t, 30*time.Second, "the printer's name to go from the provider", func() bool { return dns.has("printer.lan.example") }, one.tells, dns.tells)
	if !is("1.laptop.home.arpa", laptop)() || !dns.has("laptop.lan.example", laptop.IPv6) {
		t.Errorf("the laptop, which stays: %s; at the provider %v", tells("1.laptop.home.arpa")(), dns.addresses("laptop.lan.example"))
	}

	// And back: named again, at both.
	printer.Return(t)
	waitFor(t, 60*time.Second, "the printer's name, back in the zone", is("printer.home.arpa", printer), one.tells, tells("printer.home.arpa"))
	waitFor(t, 30*time.Second, "the printer's name, back at the provider", func() bool { return dns.has("printer.lan.example", printer.IPv6) }, one.tells, dns.tells)
}

// Two hosts that say the same name, each in its own way: one by mDNS, with a real avahi-daemon,
// and the other in the DHCP requests it broadcasts, with a real udhcpc, which mDNS on the link
// would have renamed otherwise. The name has the addresses of both; and each has its own
// numbered name, in the order of their MACs.
func TestLiveSharedHostname(t *testing.T) {
	if _, err := exec.LookPath("udhcpc"); err != nil {
		t.Fatal("the test asks for an address with udhcpc, as a host does that names itself so: not found")
	}
	lan := livetest.NewLAN(t, 25)
	srv := lan.Machine(t, "srv", 10)
	client := lan.Machine(t, "client", 30)
	up := lan.Machine(t, "up", 40)
	// By MAC, b before a: the order of the numbers isn't the order they came in.
	a, b := lan.Machine(t, "a", 21), lan.Machine(t, "b", 20)
	a.Avahi(t, "printer")
	dhcp := b.Command("udhcpc", "-f", "-i", b.Interface, "-x", "hostname:printer", "-s", "/bin/true")
	if err := dhcp.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dhcp.Process.Kill()
		dhcp.Wait()
	})
	startUpstream(t, up, "192.0.2.53")

	one := configure(t, srv, lan.Router, "srv", 8053, fmt.Sprintf(`
webserver:
  listen:
    - 8053
discovery:
  protocols:
    mdns:
      enabled: true
    dhcp:
      enabled: true
resolvers:
  lan:
    listen: 198.18.25.0/24
    upstream: %s
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
tasks:
  hosts:
    filter:
      - ip:
          prefix: "%s"
    endpoints:
      home:
        - "{hostname}"
        - "{n}.{hostname}"
`, up.IPv4, lan.Prefix())).start().serving()
	server := srv.IPv4.String()
	aaaa := func(name string) []string { return dig(t, client, server, name, "AAAA").data("AAAA") }
	both := []string{a.IPv6.String(), b.IPv6.String()}
	slices.Sort(both)
	waitFor(t, 60*time.Second, "printer, with the addresses of both", func() bool { return slices.Equal(aaaa("printer.home.arpa"), both) }, one.tells, func() string {
		return dig(t, client, server, "printer.home.arpa", "AAAA").String()
	})
	if got := aaaa("1.printer.home.arpa"); !slices.Equal(got, []string{b.IPv6.String()}) {
		t.Errorf("1.printer, the first by MAC: %v, want b's, %s", got, b.IPv6)
	}
	if got := aaaa("2.printer.home.arpa"); !slices.Equal(got, []string{a.IPv6.String()}) {
		t.Errorf("2.printer, the second by MAC: %v, want a's, %s", got, a.IPv6)
	}
	// Each by what said its name: a by mDNS, b by DHCP.
	for _, h := range one.status().Discovered {
		for _, n := range h.Names {
			if n.Name != "printer" {
				continue
			}
			want := map[string]string{a.MAC: "mdns", b.MAC: "dhcp"}[h.MAC]
			if !slices.Contains(n.Sources, want) {
				t.Errorf("%s is printer by %v, want %s", h.MAC, n.Sources, want)
			}
		}
	}
}
