package config

import (
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
)

// HomeAssistant makes ipv6ddns a device of Home Assistant's ESPHome integration: Home Assistant
// finds it by mDNS, and shows each name's addresses and update problems, and the hosts discovered,
// with a button to update now; and it sends ipv6ddns the states that homeassistant sources ask.
type HomeAssistant struct {
	// The encryption key, the base64 of 32 bytes, which the user gives Home Assistant. Without
	// it, Home Assistant makes one and gives it, as to ESPHome's devices: it is kept in StateFile.
	Key string `json:"key,omitempty"`
	// Without a key, where the device keeps its identity, and the key Home Assistant gave: a file
	// ipv6ddns can write. Default: homeassistant.state, beside the configuration.
	StateFile string `json:"state_file,omitempty"`
	// The device's name in the network, and the one Home Assistant shows. Defaults: ipv6ddns.
	Name         string `json:"name,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	// The port Home Assistant connects to. Default: ESPHome's, 6053.
	Port int `json:"port,omitempty"`
	// Whether the device announces itself by mDNS, for Home Assistant to find it. Default: true.
	Announce *bool `json:"announce,omitempty"`
}

// Announces tells whether the device announces itself by mDNS.
func (h HomeAssistant) Announces() bool { return h.Announce == nil || *h.Announce }

var deviceName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,29}[a-z0-9])?$`)

// setUpHomeAssistant checks the block and gives its defaults; and that the homeassistant sources
// have it.
func (c *Config) setUpHomeAssistant() error {
	if c.HomeAssistant == nil {
		for _, name := range slices.Sorted(maps.Keys(c.Sources)) {
			if c.Sources[name].Type == SourceHomeAssistant {
				return fmt.Errorf("source %s: a homeassistant source needs the homeassistant block, through which Home Assistant sends it the state", name)
			}
		}
		return nil
	}
	h := c.HomeAssistant
	if h.Key != "" {
		if _, err := esphome.ParseKey(h.Key); err != nil {
			return fmt.Errorf("homeassistant.key: %w", err)
		}
		if h.StateFile != "" {
			return fmt.Errorf("homeassistant: a key, or a state_file for the key Home Assistant gives, not both")
		}
	} else if h.StateFile == "" {
		h.StateFile = "homeassistant.state"
	}
	if h.Name == "" {
		h.Name = "ipv6ddns"
	}
	if !deviceName.MatchString(h.Name) {
		return fmt.Errorf("homeassistant.name %q: lower case letters, digits and hyphens, as a host name", h.Name)
	}
	if h.FriendlyName == "" {
		h.FriendlyName = h.Name
	}
	if h.Port == 0 {
		h.Port = 6053
	}
	return nil
}
