//go:build linux && integration

package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns"
	"github.com/miguelangel-nubla/ipv6ddns/internal/livetest"
)

// The protocols and the names of the configuration, of the command as it is built, on a link
// with a host that a real mDNS responder names: avahi-daemon says it is printer.local.
//
// Three instances, each on its machine, with the discovery each asks for:
//
//   - names: mDNS and the names, and no SSDP;
//   - plain: a discovery block that names no protocol, so ipv6disc's defaults: SSDP, and no mDNS;
//   - quiet: mDNS, and no names kept.
//
// A protocol that is disabled sends nothing on the wire, and one that is enabled does, counted
// of each machine's MAC as its frames come in to the bridge. And the host's name is in
// /status.json, and on the page, of the instance that keeps names, and of no other: all three
// find the host itself.
func TestLiveProtocolsAndNames(t *testing.T) {
	lan := livetest.NewLAN(t, 20)
	router := lan.Router
	names, plain, quiet := lan.Machine(t, "names", 10), lan.Machine(t, "plain", 11), lan.Machine(t, "quiet", 12)
	peer := lan.Machine(t, "peer", 20)
	peer.Avahi(t, "printer")
	sent := lan.Capture(t)

	config := func(discovery string) string {
		return fmt.Sprintf(`
webserver:
  listen: [8053]
discovery:
  lifetime: 30s
  rediscover: 3s
%s
tasks: {}
credentials: {}
`, discovery)
	}
	withNames := configure(t, names, router, "names", 8053, config(`  hostnames:
    enabled: true
  protocols:
    mdns: {enabled: true}
    ssdp: {enabled: false}`)).start().serving()
	// No protocol named: the defaults, which the worker has to run, not none.
	withDefaults := configure(t, plain, router, "plain", 8053, config("")).start().serving()
	withoutNames := configure(t, quiet, router, "quiet", 8053, config(`  protocols:
    mdns: {enabled: true}`)).start().serving()

	// The protocols each says it runs, as its configuration has them.
	for _, c := range []struct {
		i    *instance
		want []string
	}{
		{withNames, []string{"ndp", "ping", "wsd", "mdns"}},
		{withDefaults, []string{"ndp", "ping", "ssdp", "wsd"}},
		{withoutNames, []string{"ndp", "ping", "ssdp", "wsd", "mdns"}},
	} {
		if got := c.i.status().Protocols; !slices.Equal(got, c.want) {
			t.Errorf("%s says it runs %v, want %v", c.i.name, got, c.want)
		}
		if page, line := c.i.page("/"), "Protocols: "+strings.Join(c.want, ", ")+"\n"; !strings.Contains(page, line) {
			t.Errorf("the page of %s has no %q:\n%s", c.i.name, line, page)
		}
	}

	// All three find the host: discovery runs through each, whatever its protocols.
	host := func(i *instance) *ipv6ddns.DiscoveredHost {
		for _, h := range i.status().Discovered {
			if h.MAC == peer.MAC {
				return &h
			}
		}
		return nil
	}
	for _, i := range []*instance{withNames, withDefaults, withoutNames} {
		waitFor(t, 30*time.Second, "peer's address at "+i.name, func() bool { return i.knows(peer.MAC, peer.IPv6) }, i.tells)
	}

	// Its name, learned by mDNS, where names are kept.
	named := func(i *instance) []string {
		var said []string
		if h := host(i); h != nil {
			for _, n := range h.Names {
				said = append(said, n.Name+" by "+strings.Join(n.Sources, ","))
			}
		}
		return said
	}
	waitFor(t, 30*time.Second, "peer's name at names, by mDNS", func() bool { return slices.Equal(named(withNames), []string{"printer by mdns"}) }, withNames.tells,
		func() string { return fmt.Sprintf("names has the names %v", named(withNames)) })
	if page, line := withNames.page("/"), peer.MAC+" printer (mdns)\n"; !strings.Contains(page, line) {
		t.Errorf("the page of names has no %q:\n%s", line, page)
	}

	// What each sends in a while, of several rounds of the active discovery: the search of SSDP,
	// and the questions of mDNS, to the group and to the host.
	sent.Reset()
	const while = 12 * time.Second
	time.Sleep(while)
	for _, c := range []struct {
		i          *instance
		m          *livetest.Machine
		mdns, ssdp bool
	}{
		{withNames, names, true, false},
		{withDefaults, plain, false, true},
		{withoutNames, quiet, true, true},
	} {
		of := sent.From(c.m.MAC)
		t.Logf("%s sent in %s: %v", c.i.name, while, of)
		for protocol, enabled := range map[string]bool{"mdns": c.mdns, "ssdp": c.ssdp} {
			switch {
			case enabled && of[protocol] == 0:
				t.Errorf("%s has %s enabled, and sent none of it in %s: %v\n%s", c.i.name, protocol, while, of, c.i.tells())
			case !enabled && of[protocol] != 0:
				t.Errorf("%s has %s disabled, and sent %d of it in %s: %v", c.i.name, protocol, of[protocol], while, of)
			}
		}
		// What no configuration here turns off runs in all.
		if of["multicast ping"] == 0 || of["wsd"] == 0 {
			t.Errorf("%s sent no multicast ping, or no WS-Discovery probe, in %s: %v", c.i.name, while, of)
		}
	}

	// And after all that time the name is still at the one that keeps names, and at no other:
	// not at the one that hears mDNS and keeps none, nor at the one that doesn't hear it.
	if got := named(withNames); !slices.Equal(got, []string{"printer by mdns"}) {
		t.Errorf("names has the names %v of the peer", got)
	}
	for _, i := range []*instance{withDefaults, withoutNames} {
		if !i.knows(peer.MAC, peer.IPv6) {
			t.Errorf("%s lost the peer", i.name)
		}
		if got := named(i); len(got) != 0 {
			t.Errorf("%s keeps no names, and has %v of the peer", i.name, got)
		}
		if page := i.page("/"); !strings.Contains(page, peer.MAC+"\n") || strings.Contains(page, "printer") {
			t.Errorf("the page of %s has the peer's name, or not the peer:\n%s", i.name, page)
		}
	}
	for _, i := range []*instance{withNames, withDefaults, withoutNames} {
		if errors := i.logged("error"); len(errors) > 0 {
			t.Errorf("%s logged errors: %v", i.name, errors)
		}
		i.terminate()
	}
}
