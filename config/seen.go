package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/miguelangel-nubla/ipv6disc"
)

// Seen is a rule on how an address was seen, of its records: by a protocol of the local
// discovery, and how; or reported by something, from one of its tables. One of Protocol or
// Reported.
type Seen struct {
	// A protocol of the local discovery, as ndp or mdns; and how it saw the address: announced,
	// answered or heard. Without Way, any way.
	Protocol string `json:"protocol,omitempty"`
	Way      string `json:"way,omitempty"`
	// Reported by something: a plugin, or this machine's kernel.
	Reported *Reported `json:"reported,omitempty"`
	// On these local interfaces only. Without, on any.
	On []string `json:"interfaces,omitempty"`
}

// Reported is a rule on what reported an address: by whom, and from which of their tables. Either
// left out is any.
type Reported struct {
	// Plugins by name, or by type, as mikrotik; or kernel, this machine's own.
	By []string `json:"by,omitempty"`
	// Tables: neighbors, leases, interfaces.
	From []string `json:"from,omitempty"`
}

// Match tells whether any of the records is of the rule.
func (s Seen) Match(records []ipv6disc.Record) bool {
	return slices.ContainsFunc(records, s.matches)
}

func (s Seen) matches(r ipv6disc.Record) bool {
	if len(s.On) > 0 && !slices.Contains(s.On, r.On) {
		return false
	}
	if s.Reported != nil {
		if !r.Reported() {
			return false
		}
		by := s.Reported.By
		return (len(by) == 0 || slices.Contains(by, r.By) || r.Type != "" && slices.Contains(by, r.Type)) &&
			(len(s.Reported.From) == 0 || slices.Contains(s.Reported.From, r.From))
	}
	return r.Protocol == s.Protocol && (s.Way == "" || string(r.Way) == s.Way)
}

// The ways a protocol can see an address, as it does: what isn't here is a rule that never matches.
var protocolWays = map[string][]ipv6disc.Way{
	ipv6disc.ProtocolNDP:     {ipv6disc.Announced, ipv6disc.Answered, ipv6disc.Heard},
	ipv6disc.ProtocolPing:    {ipv6disc.Answered},
	ipv6disc.ProtocolSSDP:    {ipv6disc.Answered},
	ipv6disc.ProtocolWSD:     {ipv6disc.Answered},
	ipv6disc.ProtocolMDNS:    {ipv6disc.Announced, ipv6disc.Heard},
	ipv6disc.ProtocolARP:     {ipv6disc.Announced, ipv6disc.Answered, ipv6disc.Heard},
	ipv6disc.ProtocolDHCP:    {ipv6disc.Announced, ipv6disc.Heard},
	ipv6disc.ProtocolLLDP:    {ipv6disc.Announced},
	ipv6disc.ProtocolNetBIOS: {ipv6disc.Answered},
	ipv6disc.ProtocolLLMNR:   {ipv6disc.Answered},
}

// The tables a report is of, and the types of plugins that report.
var (
	reportTables = []string{ipv6disc.FromNeighbors, ipv6disc.FromLeases, ipv6disc.FromInterfaces}
	pluginTypes  = []string{"freebsd", "linux", "mikrotik"}
)

func wayNames(ways []ipv6disc.Way) string {
	var names []string
	for _, w := range ways {
		names = append(names, string(w))
	}
	return strings.Join(names, ", ")
}

// check tells what is wrong with the rule, at path: plugins are the names of the configuration's.
func (s Seen) check(path string, plugins []string) error {
	switch {
	case s.Protocol == "" && s.Reported == nil:
		return fmt.Errorf("%s: a protocol, or reported, is to be given: what saw the address", path)
	case s.Protocol != "" && s.Reported != nil:
		return fmt.Errorf("%s: a protocol, or reported: one or the other, as each is a record of its own", path)
	case s.Reported != nil && s.Way != "":
		return fmt.Errorf("%s.way: a report has no way: it is of what something else tells, from its tables", path)
	}
	for i, on := range s.On {
		if strings.TrimSpace(on) == "" {
			return fmt.Errorf("%s.interfaces[%d]: an interface's name", path, i)
		}
	}
	if s.Reported != nil {
		for _, by := range s.Reported.By {
			if by != ipv6disc.ReportedByKernel && !slices.Contains(pluginTypes, by) && !slices.Contains(plugins, by) {
				known := append([]string{ipv6disc.ReportedByKernel}, pluginTypes...)
				known = append(known, plugins...)
				return fmt.Errorf("%s.reported.by: %q is no plugin of discovery.plugins, nor a type of them, nor kernel: they are %s", path, by, strings.Join(known, ", "))
			}
		}
		for _, from := range s.Reported.From {
			if !slices.Contains(reportTables, from) {
				return fmt.Errorf("%s.reported.from: %q is no table: they are %s", path, from, strings.Join(reportTables, ", "))
			}
		}
		return nil
	}
	ways, ok := protocolWays[s.Protocol]
	if !ok {
		return fmt.Errorf("%s.protocol: %q is no protocol that sees an address: they are %s", path, s.Protocol, strings.Join(slices.Sorted(maps.Keys(protocolWays)), ", "))
	}
	if s.Way != "" && !slices.Contains(ways, ipv6disc.Way(s.Way)) {
		if !slices.Contains(ipv6disc.Ways, ipv6disc.Way(s.Way)) {
			return fmt.Errorf("%s.way: %q is no way: they are %s", path, s.Way, wayNames(ipv6disc.Ways))
		}
		return fmt.Errorf("%s.way: %s never sees an address %s: it sees it %s", path, s.Protocol, s.Way, wayNames(ways))
	}
	return nil
}

// describe is the rule, as the configuration's page says it.
func (s Seen) describe() string {
	var b strings.Builder
	if s.Reported != nil {
		b.WriteString("reported")
		if len(s.Reported.By) > 0 {
			b.WriteString(" by " + strings.Join(s.Reported.By, ", "))
		}
		if len(s.Reported.From) > 0 {
			b.WriteString(" from " + strings.Join(s.Reported.From, ", "))
		}
	} else {
		b.WriteString(s.Protocol)
		if s.Way != "" {
			b.WriteString(":" + s.Way)
		}
	}
	if len(s.On) > 0 {
		b.WriteString(" on " + strings.Join(s.On, ", "))
	}
	return b.String()
}

// covers tells whether every record s matches would match n too: as a rule of not_seen, n then
// leaves out every address s, of seen, takes. A plugin named in s is of the type n names.
func (n Seen) covers(s Seen, d Discovery) bool {
	within := func(some, all []string) bool {
		return len(all) == 0 || len(some) > 0 && !slices.ContainsFunc(some, func(x string) bool { return !slices.Contains(all, x) })
	}
	if !within(s.On, n.On) || (n.Reported == nil) != (s.Reported == nil) {
		return false
	}
	if n.Reported != nil {
		if !within(s.Reported.From, n.Reported.From) {
			return false
		}
		if len(n.Reported.By) == 0 {
			return true
		}
		return len(s.Reported.By) > 0 && !slices.ContainsFunc(s.Reported.By, func(by string) bool {
			p, plugin := d.Plugins[by]
			return !slices.Contains(n.Reported.By, by) && !(plugin && slices.Contains(n.Reported.By, p.Type))
		})
	}
	if n.Protocol != s.Protocol {
		return false
	}
	ways := protocolWays[s.Protocol]
	if s.Way != "" {
		ways = []ipv6disc.Way{ipv6disc.Way(s.Way)}
	}
	return n.Way == "" || !slices.ContainsFunc(ways, func(w ipv6disc.Way) bool { return w != ipv6disc.Way(n.Way) })
}

// records tells whether the discovery runs what makes the protocol's records: its switch, of
// discovery.protocols; of arp, the ARP heard, or a sweep's or a solicitation's answers.
func (d Discovery) records(protocol string) bool {
	p := d.Protocols
	switch protocol {
	case ipv6disc.ProtocolNDP:
		return p.NDP.Enabled
	case ipv6disc.ProtocolPing:
		return p.Ping.Enabled
	case ipv6disc.ProtocolSSDP:
		return p.SSDP.Enabled
	case ipv6disc.ProtocolWSD:
		return p.WSD.Enabled
	case ipv6disc.ProtocolMDNS:
		return p.MDNS.Enabled
	case ipv6disc.ProtocolARP:
		return p.ARP.Enabled || p.ARPSweep.Enabled || p.ARPListen.Enabled || d.Solicit.IPv4
	case ipv6disc.ProtocolDHCP:
		return p.DHCP.Enabled
	case ipv6disc.ProtocolLLDP:
		return p.LLDP.Enabled
	case ipv6disc.ProtocolNetBIOS:
		return p.NetBIOS.Enabled
	case ipv6disc.ProtocolLLMNR:
		return p.LLMNR.Enabled
	}
	return false
}
