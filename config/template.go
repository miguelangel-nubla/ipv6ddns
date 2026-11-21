package config

import (
	"fmt"
	"maps"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The placeholders of a task's host name that is a template: one name for each host the task's
// filters match, by what the host is called.
const (
	// A name of the host, as discovery learns them: alone in the template, the name is
	// of every host called so, with the addresses of all of them.
	PlaceholderHostname = "{hostname}"
	// The place of the host among those of its name, by MAC, from 1: with {hostname}, a name for
	// each of them. It is the place among those there now: it moves when one comes or leaves.
	PlaceholderN = "{n}"
	// The host's MAC, its twelve digits: a name for each host, which stays its own.
	PlaceholderMAC = "{mac}"
)

var placeholder = regexp.MustCompile(`\{[^{}]*\}`)

// Template is a task's host name with placeholders.
type Template struct {
	// As written.
	Text string
	// Which it has.
	Hostname, N, MAC bool
}

// IsTemplate tells whether a task's host name has a placeholder, or what looks like one.
func IsTemplate(name string) bool {
	return strings.ContainsAny(name, "{}")
}

// ParseTemplate reads a task's host name that has placeholders.
func ParseTemplate(name string) (Template, error) {
	t := Template{Text: name}
	for _, p := range placeholder.FindAllString(name, -1) {
		switch p {
		case PlaceholderHostname:
			t.Hostname = true
		case PlaceholderN:
			t.N = true
		case PlaceholderMAC:
			t.MAC = true
		default:
			return t, fmt.Errorf("%s is no placeholder: they are {hostname}, {n} and {mac}", p)
		}
	}
	if strings.ContainsAny(placeholder.ReplaceAllString(name, ""), "{}") {
		return t, fmt.Errorf("a brace that is of no placeholder: they are {hostname}, {n} and {mac}")
	}
	if t.N && !t.Hostname {
		return t, fmt.Errorf("{n} is the place of a host among those of one name: it needs {hostname} beside it, as {n}.{hostname}")
	}
	return t, nil
}

// PerHost tells whether the template is a name of one host: with {n} or {mac}. Without, it is the
// name of every host called the same.
func (t Template) PerHost() bool {
	return t.N || t.MAC
}

// Expand is the name of the template for a host: its name, its place among those of the name,
// and its MAC.
func (t Template) Expand(hostname string, n int, mac net.HardwareAddr) string {
	return strings.NewReplacer(
		PlaceholderHostname, hostname,
		PlaceholderN, strconv.Itoa(n),
		PlaceholderMAC, strings.ReplaceAll(mac.String(), ":", ""),
	).Replace(t.Text)
}

// checkTemplates checks the tasks' host names that are templates: their placeholders, and that
// the names of the hosts are learned, for those that take them.
func (c *Config) checkTemplates() error {
	for _, taskName := range slices.Sorted(maps.Keys(c.Tasks)) {
		task := c.Tasks[taskName]
		for _, endpoint := range slices.Sorted(maps.Keys(task.Endpoints)) {
			for _, name := range task.Endpoints[endpoint] {
				if !IsTemplate(name) {
					continue
				}
				t, err := ParseTemplate(name)
				if err != nil {
					return fmt.Errorf("task %s: endpoint %s: the name %q: %w", taskName, endpoint, name, err)
				}
				if t.Hostname && !c.Discovery.learnsNames() {
					return fmt.Errorf("task %s: endpoint %s: the name %q is of the hosts' names, which nothing learns: it needs a protocol of discovery.protocols that does, as mdns, or a plugin", taskName, endpoint, name)
				}
			}
		}
	}
	return nil
}

// learnsNames tells whether anything of the discovery learns the hosts' names: a plugin, of its
// router's leases, or a protocol that runs for them.
func (d Discovery) learnsNames() bool {
	p := d.Protocols
	return len(d.Plugins) > 0 || p.MDNS.Enabled || p.DHCP.Enabled || p.LLDP.Enabled || p.NetBIOS.Enabled || p.LLMNR.Enabled ||
		p.DNS.Enabled && len(p.DNS.Servers) > 0 || p.SSDP.Enabled && p.SSDP.Names || p.WSD.Enabled && p.WSD.Names
}
