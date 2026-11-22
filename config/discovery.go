package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	disc "github.com/miguelangel-nubla/ipv6disc/pkg/config"
)

// DefaultLifetime is how long a discovered address stays after it was last seen, by default:
// discovery.lifetime. ipv6disc's own is longer.
const DefaultLifetime = time.Hour

// StringList is a list of strings: in the configuration, a list, or one string of comma separated
// values. A number, as a port, is taken as written.
type StringList []string

func (l *StringList) UnmarshalJSON(b []byte) error {
	var values []json.RawMessage
	if err := json.Unmarshal(b, &values); err != nil {
		values = []json.RawMessage{b}
	}
	*l = nil
	for _, raw := range values {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			var number json.Number
			if err := json.Unmarshal(raw, &number); err != nil {
				return fmt.Errorf("not a string or a list of them: %s", b)
			}
			value = number.String()
		}
		for _, v := range strings.Split(value, ",") {
			if v = strings.TrimSpace(v); v != "" {
				*l = append(*l, v)
			}
		}
	}
	return nil
}

// Discovery is how hosts are discovered: ipv6disc's own configuration, the same keys its command
// takes in its file, read by its decoder; and what is ipv6ddns's, the solicitation of the hosts
// the filters want. A Discovery's zero value discovers nothing: DefaultDiscovery is what a
// configuration that says nothing has.
type Discovery struct {
	// lifetime, rediscover, interfaces, exclude_interfaces, ipv6, ipv4, hostnames, protocols and
	// plugins: ipv6disc says what each is.
	disc.Discovery
	// Asking the hosts the filters want, which aren't otherwise found: ipv6ddns's, as the targets
	// are the filters'.
	Solicit Solicit `json:"solicit"`
}

// Solicit is which family's hosts are asked for, of those the filters name by their MAC. A
// family that is off is not asked.
type Solicit struct {
	// A neighbor solicitation for the EUI-64 address of their MAC, on each /64 listened on.
	IPv6 bool `json:"ipv6"`
	// ARP requests to their MAC alone.
	IPv4 bool `json:"ipv4"`
}

// DefaultDiscovery is the discovery of a configuration that doesn't say: ipv6disc's, IPv6 by the
// protocols that find hosts, no IPv4 and no names, with the lifetime of ipv6ddns; and nothing
// solicited.
func DefaultDiscovery() Discovery {
	d := Discovery{Discovery: disc.DefaultDiscovery()}
	d.Lifetime = disc.Duration(DefaultLifetime)
	return d
}

// discoveryKeys are the keys of the discovery block, in their order: ipv6disc's, then ipv6ddns's.
func discoveryKeys() []string {
	var keys []string
	for _, typ := range []reflect.Type{reflect.TypeFor[disc.Discovery](), reflect.TypeFor[Discovery]()} {
		for i := range typ.NumField() {
			if name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
				keys = append(keys, name)
			}
		}
	}
	return keys
}

// UnmarshalJSON reads the discovery block over what d has, strictly: solicit, which is
// ipv6ddns's, is taken off, and the rest is ipv6disc's to read. Every error is told, each with
// its path from the top of the configuration.
func (d *Discovery) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if string(b) == "null" {
		return nil
	}
	var block map[string]json.RawMessage
	if err := json.Unmarshal(b, &block); err != nil {
		return fmt.Errorf("discovery: %s is not a mapping of its keys", b)
	}

	var errs []error
	known := discoveryKeys()
	rest := make(map[string]json.RawMessage)
	for _, key := range slices.Sorted(maps.Keys(block)) {
		switch {
		case key == "solicit":
			errs = append(errs, d.Solicit.read(block[key]))
		case !slices.Contains(known, key):
			errs = append(errs, fmt.Errorf("discovery.%s: no such key: discovery has %s", key, strings.Join(known, ", ")))
		default:
			rest[key] = block[key]
		}
	}
	library, err := json.Marshal(rest)
	if err != nil {
		return err
	}
	errs = append(errs, prefixed(d.Discovery.UnmarshalJSON(library), func(string) string { return "discovery." }))
	return errors.Join(errs...)
}

// read reads discovery.solicit, strictly.
func (s *Solicit) read(raw json.RawMessage) error {
	raw = bytes.TrimSpace(raw)
	if string(raw) == "null" {
		return nil
	}
	var block map[string]json.RawMessage
	if err := json.Unmarshal(raw, &block); err != nil {
		var on bool
		if json.Unmarshal(raw, &on) == nil {
			return fmt.Errorf("discovery.solicit: %s is not its settings: it is written as solicit, with ipv6: %t under it, and ipv4 beside that for IPv4", raw, on)
		}
		return fmt.Errorf("discovery.solicit: %s is not a mapping of its keys", raw)
	}
	var errs []error
	for _, key := range slices.Sorted(maps.Keys(block)) {
		var family *bool
		switch key {
		case "ipv6":
			family = &s.IPv6
		case "ipv4":
			family = &s.IPv4
		default:
			errs = append(errs, fmt.Errorf("discovery.solicit.%s: no such key: discovery.solicit has ipv6, ipv4", key))
			continue
		}
		if value := bytes.TrimSpace(block[key]); string(value) != "null" && json.Unmarshal(value, family) != nil {
			errs = append(errs, fmt.Errorf("discovery.solicit.%s: %s is not true or false", key, value))
		}
	}
	return errors.Join(errs...)
}

// prefixed returns every error of err, which ipv6disc joined, with what prefix says before it:
// theirs start at the keys of the discovery, and a configuration has those under discovery.
func prefixed(err error, prefix func(message string) string) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var errs []error
		for _, e := range joined.Unwrap() {
			errs = append(errs, prefixed(e, prefix))
		}
		return errors.Join(errs...)
	}
	return fmt.Errorf("%s%w", prefix(err.Error()), err)
}

// validate tells what of the discovery can't run, as ipv6disc tells it: the protocols enabled
// that can't be, the lifetimes, the interfaces' patterns, and the plugins, each made and dropped
// to know. And what runs, but does nothing: warnings.
func (d Discovery) validate() (warnings []string, err error) {
	err = prefixed(d.Discovery.Validate(), func(message string) string {
		// A plugin's error has its path; the others are of the discovery as a whole.
		if strings.HasPrefix(message, "plugins.") {
			return "discovery."
		}
		return "discovery: "
	})
	// The answers to the IPv6 solicitations are read listening.
	if d.Solicit.IPv6 && d.IPv6.Enabled && !d.IPv6.Listen {
		warnings = append(warnings, "discovery.solicit.ipv6 does nothing without discovery.ipv6.listen, which reads the answers")
	}
	for _, family := range []struct {
		name          string
		solicit, runs bool
	}{{"ipv6", d.Solicit.IPv6, d.IPv6.Enabled}, {"ipv4", d.Solicit.IPv4, d.IPv4.Enabled}} {
		if family.solicit && !family.runs {
			warnings = append(warnings, fmt.Sprintf("discovery.solicit.%[1]s does nothing without discovery.%[1]s.enabled", family.name))
		}
	}
	return warnings, err
}

// checkDiscovery reads the discovery block of the configuration before the schema does: the
// errors are ipv6disc's, in words, each with its path, where the schema would tell of its
// combinations.
func checkDiscovery(configData []byte) error {
	var top map[string]json.RawMessage
	if json.Unmarshal(configData, &top) != nil {
		// Not a mapping: the schema's to say.
		return nil
	}
	block, ok := top["discovery"]
	if !ok {
		return nil
	}
	d := DefaultDiscovery()
	if err := d.UnmarshalJSON(block); err != nil {
		return err
	}
	_, err := d.validate()
	return err
}

// familyWarnings tells the IPv4 block that has settings, and no enabled, which is off by default:
// it runs, and what it says does nothing.
func familyWarnings(configData []byte) []string {
	var top struct {
		Discovery struct {
			IPv4 map[string]json.RawMessage `json:"ipv4"`
		} `json:"discovery"`
	}
	if json.Unmarshal(configData, &top) != nil || len(top.Discovery.IPv4) == 0 {
		return nil
	}
	if _, ok := top.Discovery.IPv4["enabled"]; ok {
		return nil
	}
	return []string{fmt.Sprintf("discovery.ipv4 has %s, and no enabled: IPv4 is off, and they do nothing, until it has enabled: true", strings.Join(slices.Sorted(maps.Keys(top.Discovery.IPv4)), ", "))}
}
