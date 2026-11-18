package config

import (
	"net/netip"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/filter"
	"github.com/miguelangel-nubla/ipv6disc"
)

type Task struct {
	// The key of the task in the configuration.
	Name      string              `json:"-"`
	Filters   []Filters           `json:"filter"`
	Endpoints map[string][]string `json:"endpoints"`
	IPv4      *IPv4Handler        `json:"ipv4,omitempty"`
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
	return filter.CheckMAC(addr.Hw, f.MAC.Address) &&
		filter.CheckMACMask(addr.Hw, f.MAC.Mask) &&
		filter.CheckMACType(addr.Hw, f.MAC.Type) &&
		filter.CheckIPType(addr, f.IP.Type) &&
		filter.CheckPrefix(addr.Addr, f.IP.Prefix) &&
		filter.CheckSuffix(addr.Addr, f.IP.Suffix) &&
		filter.CheckMask(addr.Addr, f.IP.Mask) &&
		filter.CheckSource(addr, f.Source)
}
