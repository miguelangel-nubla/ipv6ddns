package config

import (
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
)

// The types of source.
const (
	// SourceHTTP asks echo services, over HTTPS, the address they see: the public address of the
	// network, behind NAT too.
	SourceHTTP = "http"
	// SourceDNS asks DNS resolvers that answer with the address they see.
	SourceDNS = "dns"
	// SourceCommand runs a command that prints addresses, one per line.
	SourceCommand = "command"
	// SourceStatic is a fixed list of addresses.
	SourceStatic = "static"
	// SourceHomeAssistant is the state of a Home Assistant entity, or of its attribute: the
	// addresses in it. It needs the homeassistant block, through which Home Assistant sends it.
	SourceHomeAssistant = "homeassistant"
)

// Source is a named source of addresses that have no MAC, for the tasks that name it: the public
// address of the network, the output of a command, a fixed list. The addresses it gives are kept
// for their lifetime after it last gave them.
type Source struct {
	Type string `json:"type"`
	// http and dns: the families of the addresses to find, 4 and 6. Default: 4.
	Family []int `json:"family,omitempty"`
	// How often it runs, and how long an address stays after the last run that gave it.
	// Defaults: 5m, and 3 intervals.
	Interval duration.Duration `json:"interval,omitempty"`
	Lifetime duration.Duration `json:"lifetime,omitempty"`
	// http: the echo services to ask, in order, instead of the defaults.
	URLs []string `json:"urls,omitempty"`
	// command.
	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	// static.
	Addresses []string `json:"addresses,omitempty"`
	// homeassistant: the entity, as "sensor.wan_ip", and its attribute, or its state when empty.
	Entity    string `json:"entity,omitempty"`
	Attribute string `json:"attribute,omitempty"`
}

const (
	defaultSourceInterval = 5 * time.Minute
	staticSourceInterval  = time.Hour
)

// withDefaults returns the source with its defaults set, or an error for an invalid one.
func (s Source) withDefaults() (Source, error) {
	switch s.Type {
	case SourceHTTP, SourceDNS:
		if len(s.Family) == 0 {
			s.Family = []int{4}
		}
		for _, family := range s.Family {
			if family != 4 && family != 6 {
				return s, fmt.Errorf("family %d: use 4 or 6", family)
			}
		}
		if s.Type == SourceDNS && len(s.URLs) > 0 {
			return s, fmt.Errorf("urls is only for http sources")
		}
	case SourceCommand:
		if s.Command == "" {
			return s, fmt.Errorf("a command source needs a command")
		}
	case SourceStatic:
		if len(s.Addresses) == 0 {
			return s, fmt.Errorf("a static source needs addresses")
		}
		for _, a := range s.Addresses {
			if _, err := netip.ParseAddr(a); err != nil {
				return s, fmt.Errorf("invalid address %q: %w", a, err)
			}
		}
		// It gives the same addresses at every run: they never expire.
		s.Interval.Duration = staticSourceInterval
		s.Lifetime.Duration = 3 * staticSourceInterval
	case SourceHomeAssistant:
		if s.Entity == "" {
			return s, fmt.Errorf("a homeassistant source needs an entity")
		}
	default:
		return s, fmt.Errorf("unknown source type %q", s.Type)
	}
	if s.Type != SourceHTTP && s.Type != SourceDNS && len(s.Family) > 0 {
		return s, fmt.Errorf("family is only for http and dns sources: a %s source gives whatever addresses it has", s.Type)
	}
	if s.Interval.Duration == 0 {
		s.Interval.Duration = defaultSourceInterval
	}
	if s.Lifetime.Duration == 0 {
		s.Lifetime.Duration = 3 * s.Interval.Duration
	}
	if s.Interval.Duration < time.Second {
		return s, fmt.Errorf("interval %s is too short: the least is 1s", s.Interval)
	}
	if s.Lifetime.Duration < s.Interval.Duration {
		return s, fmt.Errorf("lifetime %s is shorter than the interval, %s: the addresses would expire between runs", s.Lifetime, s.Interval)
	}
	return s, nil
}

// describe tells what the source is, in a line. hideSensible hides the arguments of a command,
// and the urls of an http source but their host, which can hold a token.
func (s Source) describe(hideSensible bool) string {
	var b strings.Builder
	b.WriteString(s.Type)
	switch s.Type {
	case SourceHTTP, SourceDNS:
		var families []string
		for _, family := range s.Family {
			families = append(families, fmt.Sprintf("IPv%d", family))
		}
		b.WriteString(", " + strings.Join(families, " and "))
		if len(s.URLs) > 0 {
			urls := s.URLs
			if hideSensible {
				urls = make([]string, len(s.URLs))
				for i, u := range s.URLs {
					urls[i] = hideURL(u)
				}
			}
			b.WriteString(", from " + strings.Join(urls, ", "))
		}
	case SourceCommand:
		b.WriteString(": " + s.Command)
		if hideSensible && len(s.Args) > 0 {
			b.WriteString(" <sensible data hidden>")
		} else {
			for _, arg := range s.Args {
				fmt.Fprintf(&b, " %q", arg)
			}
		}
	case SourceStatic:
		b.WriteString(": " + strings.Join(s.Addresses, ", "))
		return b.String()
	}
	fmt.Fprintf(&b, ", every %s, kept %s", s.Interval, s.Lifetime)
	return b.String()
}

// hideURL returns the scheme and host of the URL alone: its user, path and query can hold a token.
func hideURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<sensible data hidden>"
	}
	return u.Scheme + "://" + u.Host
}

// setUpSources checks the sources, and gives them their defaults; and that the tasks name ones
// there are.
func (c *Config) setUpSources() error {
	if c.Sources == nil {
		c.Sources = make(map[string]Source)
	}
	for _, name := range slices.Sorted(maps.Keys(c.Sources)) {
		source, err := c.Sources[name].withDefaults()
		if err != nil {
			return fmt.Errorf("source %s: %w", name, err)
		}
		c.Sources[name] = source
	}
	for _, name := range slices.Sorted(maps.Keys(c.Tasks)) {
		for _, source := range c.Tasks[name].Sources {
			if _, ok := c.Sources[source]; !ok {
				return fmt.Errorf("task %s: there's no source %s under sources", name, source)
			}
		}
	}
	return nil
}
