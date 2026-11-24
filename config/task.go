package config

import (
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/filter"
	"github.com/miguelangel-nubla/ipv6disc"
)

type Task struct {
	// The key of the task in the configuration.
	Name    string    `json:"-"`
	Filters []Filters `json:"filter"`
	// The names of the sources whose addresses the task's names get too.
	Sources   []string            `json:"sources,omitempty"`
	Endpoints map[string][]string `json:"endpoints"`
}

type Filters struct {
	// The addresses of the machine ipv6ddns runs on, on the interfaces discovery runs on, rather
	// than of a MAC: a Home Assistant host, a server.
	Self bool       `json:"self"`
	MAC  MACFilters `json:"mac"`
	IP   IPFilters  `json:"ip"`
}

type MACFilters struct {
	Address string   `json:"address"`
	Mask    []string `json:"mask"`
	Type    []string `json:"type"`
}

type IPFilters struct {
	// 4, 6, or both. Default: 6, so a filter written before IPv4 discovery doesn't take the
	// private IPv4 addresses of a device to a public DNS.
	Family []int        `json:"family"`
	Type   []string     `json:"type"`
	Prefix netip.Prefix `json:"prefix"`
	// VALUE/MASK pairs, both whole addresses: the bits the mask has are the value's.
	Mask []string `json:"mask"`
	// How the address was seen, of its records: every rule of Seen by one of them, and no record
	// of any rule of NotSeen.
	Seen    []Seen `json:"seen,omitempty"`
	NotSeen []Seen `json:"not_seen,omitempty"`
	// A push source: an IPv6 address must be in the IPv6 prefix its router sent last, as a
	// Fritz!Box sends the prefix of its LAN. IPv4 addresses pass. Until the router sent one, every
	// address passes.
	PrefixSource string `json:"prefix_source,omitempty"`
}

// Prefixes are the IPv6 prefixes of their LAN that the routers of push sources sent, by source,
// as one round of matching takes them: what prefix_source compares with. A source that has none
// is left out.
type Prefixes map[string]netip.Prefix

// Match tells whether any of the task's filters matches the address, with the push sources'
// prefixes.
func (t Task) Match(addr *ipv6disc.Addr, prefixes Prefixes) bool {
	for _, f := range t.Filters {
		if f.Match(addr, prefixes) {
			return true
		}
	}
	return false
}

// Match tells whether the address passes every check of the filter, with the push sources'
// prefixes.
func (f Filters) Match(addr *ipv6disc.Addr, prefixes Prefixes) bool {
	return (!f.Self || addr.Self()) &&
		filter.CheckFamily(addr.Addr, f.IP.Family) &&
		filter.CheckMAC(addr.Hw, f.MAC.Address) &&
		filter.CheckMACMask(addr.Hw, f.MAC.Mask) &&
		filter.CheckMACType(addr.Hw, f.MAC.Type) &&
		filter.CheckIPType(addr, f.IP.Type) &&
		filter.CheckPrefix(addr.Addr, f.IP.Prefix) &&
		filter.CheckMask(addr.Addr, f.IP.Mask) &&
		f.IP.checkPrefixSource(addr.Addr, prefixes) &&
		f.IP.checkSeen(addr)
}

// checkPrefixSource tells whether an IPv6 address is in the prefix of PrefixSource: every address
// is, without the rule, without a prefix yet, or of IPv4.
func (f IPFilters) checkPrefixSource(ip netip.Addr, prefixes Prefixes) bool {
	if f.PrefixSource == "" || !ip.Is6() || ip.Is4In6() {
		return true
	}
	prefix, ok := prefixes[f.PrefixSource]
	if !ok {
		return true
	}
	return prefix.Contains(ip.WithZone(""))
}

// checkSeen tells whether the address's records are as the rules say: one for each of Seen, and
// none of NotSeen.
func (f IPFilters) checkSeen(addr *ipv6disc.Addr) bool {
	if len(f.Seen) == 0 && len(f.NotSeen) == 0 {
		return true
	}
	records := addr.Records()
	for _, s := range f.Seen {
		if !s.Match(records) {
			return false
		}
	}
	for _, s := range f.NotSeen {
		if s.Match(records) {
			return false
		}
	}
	return true
}

// checkFilters checks what the schema can't of the task's filters, and writes their MAC in its
// canonical form, 00:11:22:33:44:55, which is what matches and what the report shows. A rule
// that doesn't parse is an error: skipped, the filter would take every host.
func (t *Task) checkFilters(d Discovery) error {
	plugins := slices.Sorted(maps.Keys(d.Plugins))
	for i := range t.Filters {
		f := &t.Filters[i]
		for j, s := range f.IP.Seen {
			path := fmt.Sprintf("filter %d: ip.seen[%d]", i+1, j)
			if err := s.check(path, plugins); err != nil {
				return err
			}
			if s.Protocol != "" && !d.records(s.Protocol) {
				return fmt.Errorf("%s.protocol: %s is disabled under discovery.protocols, so no address has a record of it", path, s.Protocol)
			}
		}
		for j, s := range f.IP.NotSeen {
			path := fmt.Sprintf("filter %d: ip.not_seen[%d]", i+1, j)
			if err := s.check(path, plugins); err != nil {
				return err
			}
			for k, wanted := range f.IP.Seen {
				if s.covers(wanted, d) {
					return fmt.Errorf("%s: it excludes every record ip.seen[%d] requires, %s, so the filter matches no address", path, k, wanted.describe())
				}
			}
		}
		if f.MAC.Address != "" {
			mac, err := net.ParseMAC(f.MAC.Address)
			if err != nil || len(mac) != 6 {
				return fmt.Errorf("filter %d: mac.address %q: not a MAC address: write it as 00:11:22:33:44:55", i+1, f.MAC.Address)
			}
			f.MAC.Address = mac.String()
		}
		for _, m := range f.MAC.Mask {
			value, _, err := filter.ParseMACMask(m)
			if err == nil && len(value) != 6 {
				err = fmt.Errorf("a MAC is 6 bytes, not %d", len(value))
			}
			if err != nil {
				return fmt.Errorf("filter %d: mac.mask %q: %w", i+1, m, err)
			}
		}
		for _, m := range f.IP.Mask {
			if _, _, err := filter.ParseIPMask(m); err != nil {
				return fmt.Errorf("filter %d: ip.mask %q: %w", i+1, m, err)
			}
		}
	}
	return nil
}
