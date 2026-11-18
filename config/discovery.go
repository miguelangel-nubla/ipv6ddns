package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
)

// DefaultLifetime is how long a discovered address stays after it was last seen, by default.
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

// Family is how a family's addresses are discovered: the same for IPv6 and IPv4. It is true,
// false, or an object of the ways, each defaulting as in true.
type Family struct {
	// Whether the family is discovered at all: its addresses, and the plugins reading them.
	Enabled bool `json:"enabled"`
	// Passive local discovery. IPv6: NDP, and the answers of the protocols. IPv4: the kernel's
	// neighbor table.
	Listen bool `json:"listen"`
	// Probing every host of the local links. IPv6: multicast ping, SSDP and WS-Discovery. IPv4: a
	// sweep of the subnets, which broadcasts an ARP request for each address.
	Active bool `json:"active"`
	// Asking the hosts the filters want, which aren't otherwise found. IPv6: a neighbor
	// solicitation for the EUI-64 address of their MAC. IPv4: ARP requests to their MAC alone.
	Solicit bool `json:"solicit"`
	// How long the family's addresses stay after they were last seen, the plugins' too: the
	// lifetime of the configuration when not given.
	Lifetime duration.Duration `json:"lifetime"`

	// Whether the configuration has it, rather than the default.
	set bool
}

// familyOn is a family as true sets it.
var familyOn = Family{Enabled: true, Listen: true, Active: true}

// DefaultDiscovery is the discovery of a configuration that doesn't say: IPv6 by listening and
// active probes, no IPv4. A Discovery's zero value discovers nothing.
func DefaultDiscovery() Discovery {
	return Discovery{IPv6: familyOn}
}

func (f *Family) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	var on bool
	if err := json.Unmarshal(b, &on); err == nil {
		*f = Family{}
		if on {
			*f = familyOn
		}
		f.set = true
		return nil
	}
	type plain Family
	family := plain(familyOn)
	if err := json.Unmarshal(b, &family); err != nil {
		return err
	}
	*f = Family(family)
	f.set = true
	return nil
}

// setUpDiscovery turns the discovery settings from before the families, listen, active and
// solicit_eui64, into the IPv6 ones, with warnings to move them.
func (d *Discovery) setUpDiscovery() ([]string, error) {
	var warnings []string
	old := map[string]*bool{"listen": d.Listen, "active": d.Active, "solicit_eui64": d.SolicitEUI64}
	for _, key := range []string{"listen", "active", "solicit_eui64"} {
		value := old[key]
		if value == nil {
			continue
		}
		if d.IPv6.set {
			return nil, fmt.Errorf("discovery.%s is the deprecated form of discovery.ipv6: give one of them", key)
		}
		switch key {
		case "listen":
			d.IPv6.Listen = *value
		case "active":
			d.IPv6.Active = *value
		case "solicit_eui64":
			d.IPv6.Solicit = *value
		}
		newKey := map[string]string{"listen": "listen", "active": "active", "solicit_eui64": "solicit"}[key]
		warnings = append(warnings, fmt.Sprintf("discovery.%s is deprecated, and goes in v1.0: it is discovery.ipv6.%s", key, newKey))
	}
	d.Listen, d.Active, d.SolicitEUI64 = nil, nil, nil

	var errs []error
	for name, f := range map[string]Family{"ipv6": d.IPv6, "ipv4": d.IPv4} {
		if f.Enabled && f.Active && !f.Listen {
			errs = append(errs, fmt.Errorf("discovery.%s: active needs listen, which reads its answers", name))
		}
		if f.Lifetime.Duration < 0 {
			errs = append(errs, fmt.Errorf("discovery.%s: a negative lifetime", name))
		}
	}
	for _, pattern := range slices.Concat(d.Interfaces, d.ExcludeInterfaces) {
		if _, err := path.Match(pattern, ""); err != nil {
			errs = append(errs, fmt.Errorf("discovery: invalid interface pattern %q", pattern))
		}
	}
	return warnings, errors.Join(errs...)
}
