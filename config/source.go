package config

import (
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"path/filepath"
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
	// SourcePush is the addresses a router sends, as to a DynDNS service: through the web
	// server, at /nic/update, with its password.
	SourcePush = "push"
)

// PushForever is the lifetime of the addresses of a push source that gives none: until the next
// push, however far.
const PushForever = 100 * 365 * 24 * time.Hour

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
	// push: the password a router sends with its updates; and the file the addresses it sent last
	// are kept in, for a restart: relative to the state folder, by default push-<source>.json
	// there.
	Password  string `json:"password,omitempty"`
	StateFile string `json:"state_file,omitempty"`
}

const (
	defaultSourceInterval = 5 * time.Minute
	staticSourceInterval  = time.Hour
)

// sourceKeys are the keys of each type of source, besides type.
var sourceKeys = map[string][]string{
	SourceHTTP:          {"family", "interval", "lifetime", "urls"},
	SourceDNS:           {"family", "interval", "lifetime"},
	SourceCommand:       {"interval", "lifetime", "command", "args"},
	SourceStatic:        {"addresses"},
	SourceHomeAssistant: {"interval", "lifetime", "entity", "attribute"},
	SourcePush:          {"lifetime", "password", "state_file"},
}

// checkKeys tells of a key of the source that is another type's, as the addresses of an http
// source: it would be ignored without a word, and the source give something else than was meant.
// The keys that have an error of their own, in withDefaults, are told there.
func (s Source) checkKeys() error {
	for _, key := range []struct {
		name  string
		given bool
	}{
		{"urls", len(s.URLs) > 0},
		{"command", s.Command != ""},
		{"args", len(s.Args) > 0},
		{"addresses", len(s.Addresses) > 0},
		{"entity", s.Entity != ""},
		{"attribute", s.Attribute != ""},
	} {
		if !key.given || slices.Contains(sourceKeys[s.Type], key.name) {
			continue
		}
		var types []string
		for _, t := range []string{SourceHTTP, SourceDNS, SourceCommand, SourceStatic, SourceHomeAssistant, SourcePush} {
			if slices.Contains(sourceKeys[t], key.name) {
				types = append(types, t)
			}
		}
		return fmt.Errorf("%s is only for %s sources, and this one's type is %s, which doesn't read it: leave it out, or make the type %s", key.name, strings.Join(types, " and "), s.Type, types[0])
	}
	return nil
}

// withDefaults returns the source with its defaults set, or an error for an invalid one.
func (s Source) withDefaults() (Source, error) {
	if _, ok := sourceKeys[s.Type]; ok {
		if err := s.checkKeys(); err != nil {
			return s, err
		}
	}
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
		if s.Interval.Duration != 0 || s.Lifetime.Duration != 0 {
			return s, fmt.Errorf("a static source has no interval nor lifetime: its addresses are always those written. Leave both out")
		}
		// It gives the same addresses at every run: they never expire.
		s.Interval.Duration = staticSourceInterval
		s.Lifetime.Duration = 3 * staticSourceInterval
	case SourceHomeAssistant:
		if s.Entity == "" {
			return s, fmt.Errorf("a homeassistant source needs an entity")
		}
	case SourcePush:
		// Without a password, it takes the dynamic updates of a key alone: setUpResolvers checks
		// that one sends them.
		if len(s.Family) > 0 || s.Interval.Duration != 0 {
			return s, fmt.Errorf("a push source has no family nor interval: it has the addresses the router sends, when it sends them")
		}
		// It runs when the router sends: its addresses stay until then, unless it has a lifetime.
		if s.Lifetime.Duration == 0 {
			s.Lifetime.Duration = PushForever
		}
		if s.Lifetime.Duration < time.Second {
			return s, fmt.Errorf("lifetime %s is too short: the least is 1s. Give more than the time between two updates of the router, as 1h, or leave it out to keep the addresses until the next", s.Lifetime)
		}
		s.Interval.Duration = s.Lifetime.Duration
		return s, nil
	default:
		return s, fmt.Errorf("unknown source type %q", s.Type)
	}
	if s.Password != "" || s.StateFile != "" {
		return s, fmt.Errorf("password and state_file are only for push sources")
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
	case SourcePush:
		b.WriteString(", at /nic/update")
		if s.Lifetime.Duration == PushForever {
			b.WriteString(", kept until the next push")
		} else {
			fmt.Fprintf(&b, ", kept %s", s.Lifetime)
		}
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

// checkPushName checks the name of a push source, which is the hostname a router sends, where a
// comma separates several and the spaces around each are left out, and in the name of its file,
// push-<source>.json in the state folder.
func checkPushName(name string) error {
	switch {
	case name == "." || name == "..", strings.ContainsAny(name, `,/\`), strings.TrimSpace(name) != name, name == "":
		return fmt.Errorf("sources: the name %q of a push source is the hostname its router sends, and in the name of its file: use one without a comma, a slash or a space around it, as wan", name)
	}
	return nil
}

// setUpSources checks the sources, and gives them their defaults; and that the tasks name ones
// there are. That a router's updates have a web server to come through, checkWebserversServe checks.
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
	// The file of each push source, by its path without its case, which some file systems don't
	// tell apart.
	files := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(c.Sources)) {
		source := c.Sources[name]
		if source.Type != SourcePush {
			continue
		}
		if err := checkPushName(name); err != nil {
			return err
		}
		file, what := source.StateFile, fmt.Sprintf("sources.%s.state_file: %s", name, source.StateFile)
		if file == "" {
			file = "push-" + name + ".json"
			what = fmt.Sprintf("sources.%s: its file, %s,", name, file)
		}
		file = strings.ToLower(filepath.Clean(inFolder(c.StateFolder, file)))
		if other, ok := files[file]; ok {
			return fmt.Errorf("%s is the file of the push source %s too, and each would read the other's addresses at a restart: give one of them a file of its own, as state_file: push-%s-2.json", what, other, name)
		}
		files[file] = name
	}
	for _, name := range slices.Sorted(maps.Keys(c.Tasks)) {
		for _, f := range c.Tasks[name].Filters {
			if p := f.IP.PrefixSource; p != "" && c.Sources[p].Type != SourcePush {
				return fmt.Errorf("task %s: ip.prefix_source %s is no push source: give the push source whose router sends the IPv6 prefix", name, p)
			}
		}
		for _, source := range c.Tasks[name].Sources {
			if _, ok := c.Sources[source]; !ok {
				return fmt.Errorf("task %s: there's no source %s under sources", name, source)
			}
		}
	}
	return nil
}
