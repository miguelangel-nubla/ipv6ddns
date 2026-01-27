package config

import (
	"net/netip"
)

type Task struct {
	Name      string              `json:"name"`
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
