package config

import (
	"fmt"
	"maps"
	"net/netip"
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
				return s, fmt.Errorf("invalid family %d: 4 or 6", family)
			}
		}
		if s.Type == SourceDNS && len(s.URLs) > 0 {
			return s, fmt.Errorf("urls are for http sources")
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
	default:
		return s, fmt.Errorf("unknown source type %q", s.Type)
	}
	if s.Type != SourceHTTP && s.Type != SourceDNS && len(s.Family) > 0 {
		return s, fmt.Errorf("family is for http and dns sources: a %s source gives what it has", s.Type)
	}
	if s.Interval.Duration == 0 {
		s.Interval.Duration = defaultSourceInterval
	}
	if s.Lifetime.Duration == 0 {
		s.Lifetime.Duration = 3 * s.Interval.Duration
	}
	if s.Interval.Duration < time.Second {
		return s, fmt.Errorf("invalid interval %s: at least 1s", s.Interval)
	}
	if s.Lifetime.Duration < s.Interval.Duration {
		return s, fmt.Errorf("invalid lifetime %s: at least the interval, %s, or the addresses expire between runs", s.Lifetime, s.Interval)
	}
	return s, nil
}

// describe tells what the source is, in a line. hideSensible hides the arguments of a command,
// which can hold a token.
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
			b.WriteString(", from " + strings.Join(s.URLs, ", "))
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

// IPv4Command is the ipv4 block of a task, from before sources: a command source, which it
// becomes.
type IPv4Command struct {
	Interval duration.Duration `json:"interval"`
	Command  string            `json:"command"`
	Args     []string          `json:"args"`
	Lifetime duration.Duration `json:"lifetime"`
}

// setUpSources checks the sources, and turns the ipv4 block of a task into a source of its own,
// named <task>.ipv4. It returns warnings for the configuration to change.
func (c *Config) setUpSources() ([]string, error) {
	var warnings []string
	if c.Sources == nil {
		c.Sources = make(map[string]Source)
	}
	for _, name := range slices.Sorted(maps.Keys(c.Tasks)) {
		task := c.Tasks[name]
		if task.IPv4 == nil {
			continue
		}
		sourceName := name + ".ipv4"
		if _, exists := c.Sources[sourceName]; exists {
			return nil, fmt.Errorf("task %s: its ipv4 block becomes the source %s, which exists", name, sourceName)
		}
		c.Sources[sourceName] = Source{Type: SourceCommand, Interval: task.IPv4.Interval, Lifetime: task.IPv4.Lifetime, Command: task.IPv4.Command, Args: task.IPv4.Args}
		task.Sources = append(task.Sources, sourceName)
		task.IPv4 = nil
		c.Tasks[name] = task
		warnings = append(warnings, fmt.Sprintf("task %s: the ipv4 block is deprecated: move it to sources, as a command source, and name it in the task's sources", name))
	}

	for name, source := range c.Sources {
		source, err := source.withDefaults()
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", name, err)
		}
		c.Sources[name] = source
	}
	for name, task := range c.Tasks {
		for _, source := range task.Sources {
			if _, ok := c.Sources[source]; !ok {
				return nil, fmt.Errorf("task %s: no source %s", name, source)
			}
		}
	}
	return warnings, nil
}
