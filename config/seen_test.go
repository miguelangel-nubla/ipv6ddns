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
			"task web: filter 1: ip.seen[0].way: ping never sees an address announced: it sees it answered"},
		"a reporter there is none of": {"          seen:\n            - reported:\n                by:\n                  - switch\n",
			`task web: filter 1: ip.seen[0].reported.by: "switch" is no plugin of discovery.plugins, nor a type of them, nor kernel: they are kernel, freebsd, linux, mikrotik, router`},
		"a table there is none of": {"          not_seen:\n            - reported:\n                from:\n                  - arp\n", ""},
		"both kinds in one rule":   {"          seen:\n            - protocol: ndp\n              reported: {}\n", ""},
		"a report with a way":      {"          seen:\n            - reported: {}\n              way: heard\n", ""},
		"source, of before": {"          type:\n            - global\n      - source:\n          - router\n",
			"task web: filter 2: source is ip.seen now, with a rule for each record the address is to have: reported, with by, for a plugin; interfaces, for an interface"},
	} {
		_, err := loadConfig(t, filter(c.rules))
		if err == nil || c.want != "" && err.Error() != c.want {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// Each error the schema doesn't give is the check's own, and reads as it should.
func TestSeenCheckMessages(t *testing.T) {
	for name, c := range map[string]struct {
		s    Seen
		want string
	}{
		"neither":  {Seen{}, "p: a protocol, or reported, is to be given: what saw the address"},
		"both":     {Seen{Protocol: "ndp", Reported: &Reported{}}, "p: a protocol, or reported: one or the other, as each is a record of its own"},
		"a way":    {Seen{Reported: &Reported{}, Way: "heard"}, "p.way: a report has no way: it is of what something else tells, from its tables"},
		"no such":  {Seen{Protocol: "bonjour"}, `p.protocol: "bonjour" is no protocol that sees an address: they are arp, dhcp, lldp, llmnr, mdns, ndp, netbios, ping, ssdp, wsd`},
		"no way":   {Seen{Protocol: "ndp", Way: "shouted"}, `p.way: "shouted" is no way: they are announced, answered, heard`},
		"no table": {Seen{Reported: &Reported{From: []string{"arp"}}}, `p.reported.from: "arp" is no table: they are neighbors, leases, interfaces`},
		"empty on": {Seen{Protocol: "ndp", On: []string{" "}}, "p.interfaces[0]: an interface's name"},
	} {
		if err := c.s.check("p", nil); err == nil || err.Error() != c.want {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
	if !strings.Contains((Seen{Protocol: "mdns", Way: "announced", On: []string{"eth0"}}).describe(), "mdns:announced on eth0") {
		t.Error("describe")
	}
}
