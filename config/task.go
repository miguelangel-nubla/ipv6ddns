package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
)

type Task struct {
	Name         string              `json:"name"`
	Subnets      []netip.Prefix      `json:"subnets"`
	MACAddresses []net.HardwareAddr  `json:"mac_address"`
	Endpoints    map[string][]string `json:"endpoints"`
	IPv4         *IPv4Handler        `json:"ipv4,omitempty"`
}

func (t *Task) UnmarshalJSON(data []byte) error {
	type Alias Task
	aux := &struct {
		MACAddresses []string `json:"mac_address"`
		*Alias
	}{
		Alias: (*Alias)(t),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	t.MACAddresses = make([]net.HardwareAddr, len(aux.MACAddresses))
	for i, macAddress := range aux.MACAddresses {
		parsedMAC, err := net.ParseMAC(macAddress)
		if err != nil {
			return fmt.Errorf("error parsing MAC address: %v", err)
		}
		t.MACAddresses[i] = parsedMAC
	}

	return nil
}
