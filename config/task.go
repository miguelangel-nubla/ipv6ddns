package config

import (
	"net/netip"

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
	// Deprecated: a command source, in Sources. NewConfig turns it into one.
	IPv4 *IPv4Command `json:"ipv4,omitempty"`
}

type Filters struct {
	MAC    MACFilters `json:"mac"`
	IP     IPFilters  `json:"ip"`
	Source []string   `json:"source"`
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
	Suffix string       `json:"suffix"`
	Mask   []string     `json:"mask"`
}

// Match tells whether any of the task's filters matches the address.
func (t Task) Match(addr *ipv6disc.Addr) bool {
	for _, f := range t.Filters {
		if f.Match(addr) {
			return true
		}
	}
	return false
}

// Match tells whether the address passes every check of the filter.
func (f Filters) Match(addr *ipv6disc.Addr) bool {
	return filter.CheckFamily(addr.Addr, f.IP.Family) &&
		filter.CheckMAC(addr.Hw, f.MAC.Address) &&
		filter.CheckMACMask(addr.Hw, f.MAC.Mask) &&
		filter.CheckMACType(addr.Hw, f.MAC.Type) &&
		filter.CheckIPType(addr, f.IP.Type) &&
		filter.CheckPrefix(addr.Addr, f.IP.Prefix) &&
		filter.CheckSuffix(addr.Addr, f.IP.Suffix) &&
		filter.CheckMask(addr.Addr, f.IP.Mask) &&
		filter.CheckSource(addr, f.Source)
}
