package config

import (
	"strings"
	"testing"
)

// A rule of seen or not_seen that can't match is an error at start, that says why: and source, which
// they replace, says what it is now.
func TestSeenErrors(t *testing.T) {
	filter := func(rules string) string {
		return `
discovery:
  plugins:
    router:
      type: mikrotik
      interval: 60s
      address: 192.168.88.1
      username: admin
      password: x
tasks:
  web:
    filter:
      - ip:
` + rules + `
    endpoints:
      duck:
        - www
` + duckCredential
	}
	good := []string{
		"          seen:\n            - protocol: ndp\n",
		"          seen:\n            - protocol: mdns\n              way: announced\n              interfaces:\n                - eth0\n",
		"          seen:\n            - reported: {}\n",
		"          seen:\n            - reported:\n                by:\n                  - router\n                  - mikrotik\n                  - kernel\n                from:\n                  - neighbors\n",
		"          not_seen:\n            - reported:\n                from:\n                  - leases\n",
	}
	for _, rules := range good {
		if _, err := loadConfig(t, filter(rules)); err != nil {
			t.Errorf("%s: %v", rules, err)
		}
	}
	for name, c := range map[string]struct{ rules, want string }{
		"no protocol nor report":      {"          seen:\n            - interfaces:\n                - eth0\n", ""},
		"a protocol there is none of": {"          seen:\n            - protocol: bonjour\n", ""},
		"a way there is none of":      {"          seen:\n            - protocol: ndp\n              way: shouted\n", ""},
		"a way a protocol never sees": {"          seen:\n            - protocol: ping\n              way: announced\n",
			"task web: filter 1: ip.seen[0].way: ping never sees an address announced, only answered"},
		"a reporter there is none of": {"          seen:\n            - reported:\n                by:\n                  - switch\n",
			`task web: filter 1: ip.seen[0].reported.by: "switch" isn't a plugin under discovery.plugins, a plugin type, or kernel: use one of kernel, freebsd, linux, mikrotik, router`},
		"a table there is none of": {"          not_seen:\n            - reported:\n                from:\n                  - arp\n", ""},
		"both kinds in one rule":   {"          seen:\n            - protocol: ndp\n              reported: {}\n", ""},
		"a report with a way":      {"          seen:\n            - reported: {}\n              way: heard\n", ""},
	} {
		_, err := loadConfig(t, filter(c.rules))
		if err == nil || c.want != "" && err.Error() != c.want {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// A filter that takes no address is an error at start: a rule of seen of a protocol that is
// disabled, or one of not_seen that leaves out every record a rule of seen wants. One that leaves
// out only some of them is no error.
func TestSeenThatTakesNothing(t *testing.T) {
	config := func(protocols, rules string) string {
		return "discovery:\n  protocols:\n" + protocols + `  plugins:
    router:
      type: mikrotik
      interval: 60s
      address: 192.168.88.1
      username: admin
      password: x
tasks:
  web:
    filter:
      - ip:
` + rules + `
    endpoints:
      duck:
        - www
` + duckCredential
	}
	const mdnsOn, mdnsOff = "    mdns:\n      enabled: true\n", "    mdns:\n      enabled: false\n"
	for name, c := range map[string]struct{ protocols, rules, want string }{
		"a protocol disabled": {mdnsOff, "          seen:\n            - protocol: mdns\n",
			"task web: filter 1: ip.seen[0].protocol: mdns is disabled under discovery.protocols, so no address has a record of it"},
		"the same way left out": {mdnsOn, "          seen:\n            - protocol: mdns\n              way: announced\n          not_seen:\n            - protocol: mdns\n",
			"task web: filter 1: ip.not_seen[0]: it excludes every record ip.seen[0] requires, mdns:announced, so the filter matches no address"},
		"the one way of a protocol": {mdnsOn, "          seen:\n            - protocol: ping\n          not_seen:\n            - protocol: ping\n              way: answered\n",
			"task web: filter 1: ip.not_seen[0]: it excludes every record ip.seen[0] requires, ping, so the filter matches no address"},
		"a plugin, left out by its type": {mdnsOn, "          seen:\n            - reported:\n                by:\n                  - router\n          not_seen:\n            - reported:\n                by:\n                  - mikrotik\n",
			"task web: filter 1: ip.not_seen[0]: it excludes every record ip.seen[0] requires, reported by router, so the filter matches no address"},
		"any report, left out": {mdnsOn, "          seen:\n            - reported:\n                from:\n                  - leases\n          not_seen:\n            - reported: {}\n",
			"task web: filter 1: ip.not_seen[0]: it excludes every record ip.seen[0] requires, reported from leases, so the filter matches no address"},
	} {
		if _, err := loadConfig(t, config(c.protocols, c.rules)); err == nil || err.Error() != c.want {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
	for name, rules := range map[string]string{
		"some ways left out":      "          seen:\n            - protocol: mdns\n          not_seen:\n            - protocol: mdns\n              way: announced\n",
		"another protocol":        "          seen:\n            - protocol: mdns\n          not_seen:\n            - protocol: ndp\n",
		"one interface left out":  "          seen:\n            - protocol: ndp\n          not_seen:\n            - protocol: ndp\n              interfaces:\n                - eth1\n",
		"another table":           "          seen:\n            - reported:\n                from:\n                  - neighbors\n          not_seen:\n            - reported:\n                from:\n                  - leases\n",
		"a report and a protocol": "          seen:\n            - protocol: ndp\n          not_seen:\n            - reported: {}\n",
		"of a disabled one, none": "          not_seen:\n            - protocol: lldp\n",
	} {
		if _, err := loadConfig(t, config(mdnsOn+"    lldp:\n      enabled: false\n", rules)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Each error the schema doesn't give is the check's own, and reads as it should.
func TestSeenCheckMessages(t *testing.T) {
	for name, c := range map[string]struct {
		s    Seen
		want string
	}{
		"neither":  {Seen{}, "p: give a protocol or reported: what saw the address"},
		"both":     {Seen{Protocol: "ndp", Reported: &Reported{}}, "p: give a protocol or reported, not both: each is a record of its own"},
		"a way":    {Seen{Reported: &Reported{}, Way: "heard"}, "p.way: a report has no way, as it's what something else tells from its tables: leave way out"},
		"no such":  {Seen{Protocol: "bonjour"}, `p.protocol: "bonjour" isn't a protocol that sees addresses: use one of arp, dhcp, lldp, llmnr, mdns, ndp, netbios, ping, ssdp, wsd`},
		"no way":   {Seen{Protocol: "ndp", Way: "shouted"}, `p.way: "shouted" isn't a way: use one of announced, answered, heard`},
		"no table": {Seen{Reported: &Reported{From: []string{"arp"}}}, `p.reported.from: "arp" isn't a table: use one of neighbors, leases, interfaces`},
		"empty on": {Seen{Protocol: "ndp", On: []string{" "}}, "p.interfaces[0] is empty: give an interface's name"},
	} {
		if err := c.s.check("p", nil); err == nil || err.Error() != c.want {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
	if !strings.Contains((Seen{Protocol: "mdns", Way: "announced", On: []string{"eth0"}}).describe(), "mdns:announced on eth0") {
		t.Error("describe")
	}
}
