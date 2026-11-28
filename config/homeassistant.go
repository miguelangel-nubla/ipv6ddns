package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
)

// HomeAssistant makes ipv6ddns a device of Home Assistant's ESPHome integration: Home Assistant
// finds it by mDNS, and shows each name's addresses and update problems, and the hosts discovered,
// with a button to update now; and it sends ipv6ddns the states that homeassistant sources ask.
type HomeAssistant struct {
	// The encryption key, the base64 of 32 bytes, which the user gives Home Assistant: fixed, and
	// nothing is written. This, or KeyProvisioning.
	Key string `json:"key,omitempty"`
	// Whether Home Assistant makes the key and gives it, as to ESPHome's devices: it is kept in
	// KeyProvisioningStateFile. Default: false.
	KeyProvisioning bool `json:"key_provisioning,omitempty"`
	// With KeyProvisioning, where the device keeps its identity, and the key Home Assistant gave:
	// a file ipv6ddns can write, relative to the state folder. Default: homeassistant.state there.
	KeyProvisioningStateFile string `json:"key_provisioning_state_file,omitempty"`
	// The device's name in the network, and the one Home Assistant shows. Defaults: ipv6ddns.
	Name         string `json:"name,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	// The port Home Assistant connects to, which the device announces. Default: ESPHome's, 6053.
	Port int `json:"port,omitempty"`
	// Whether the device announces itself by mDNS, for Home Assistant to find it. Default: true.
	Announce *bool `json:"announce,omitempty"`
	// Required. Where Home Assistant can connect to the device: networks, addresses, host names
	// or ports, as listen takes them. A network means this machine's addresses in it; an entry
	// without a port uses Port. A port alone means every address of this machine, a public one on
	// a router too. The device announces itself only on the interfaces of these addresses, and one
	// port, so entries with different ports need Announce false.
	Listen StringList `json:"listen,omitempty"`
	// Listen, parsed.
	Entries []listen.Entry `json:"-"`
}

// Announces tells whether the device announces itself by mDNS.
func (h HomeAssistant) Announces() bool { return h.Announce == nil || *h.Announce }

var deviceName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,29}[a-z0-9])?$`)

// checkHomeAssistant tells, of a configuration not yet checked by the schema, how the block is
// to have the device's key, when it doesn't say, or says it twice, and that it is to say where the
// device listens: in words, where the schema, which has the same rules, would only say that it
// doesn't match. And what state_file, a key from before, is now. A block that is no block is the
// schema's to refuse.
func checkHomeAssistant(configData []byte) error {
	var c struct {
		HomeAssistant map[string]json.RawMessage `json:"homeassistant"`
	}
	if json.Unmarshal(configData, &c) != nil || c.HomeAssistant == nil {
		return nil
	}
	has := func(key string) bool {
		_, ok := c.HomeAssistant[key]
		return ok
	}
	provisioning := false
	if has("key_provisioning") && json.Unmarshal(c.HomeAssistant["key_provisioning"], &provisioning) != nil {
		// Not true or false: the schema's to say, rather than that the block has neither.
		return nil
	}
	switch {
	case has("key") && provisioning:
		return errors.New("homeassistant: give a key or key_provisioning: true, not both")
	case has("key_provisioning_state_file") && has("key"):
		return errors.New("homeassistant.key_provisioning_state_file stores the key Home Assistant gives, with key_provisioning: true. With your own key nothing is stored, so leave it out")
	case has("key_provisioning_state_file") && !provisioning:
		return errors.New("homeassistant.key_provisioning_state_file stores the key Home Assistant gives: it needs key_provisioning: true")
	case !has("key") && !provisioning:
		return errors.New(`homeassistant: the device needs an encryption key, in one of two ways. key: your own, made with "openssl rand -base64 32", written there or read from a file or the environment, as ${file:homeassistant.key}. Or key_provisioning: true: Home Assistant gives the key when it adds the device, and it's stored in key_provisioning_state_file`)
	case !has("listen"):
		return errors.New(`homeassistant.listen is missing: give where Home Assistant can connect to the device. That's the network Home Assistant is on, as 192.168.1.0/24, or this machine's address on it. A port alone, as 6053, means every address of the machine, including the internet-facing one on a router`)
	}
	return nil
}

// setUpHomeAssistant checks the block and gives its defaults; and that the homeassistant sources
// have it.
func (c *Config) setUpHomeAssistant() error {
	if c.HomeAssistant == nil {
		for _, name := range slices.Sorted(maps.Keys(c.Sources)) {
			if c.Sources[name].Type == SourceHomeAssistant {
				return fmt.Errorf("source %s: a homeassistant source needs the homeassistant block: that's how Home Assistant sends it the state", name)
			}
		}
		return nil
	}
	h := c.HomeAssistant
	if h.KeyProvisioning {
		if h.KeyProvisioningStateFile == "" {
			h.KeyProvisioningStateFile = "homeassistant.state"
		}
	} else if _, err := esphome.ParseKey(h.Key); err != nil {
		return fmt.Errorf("homeassistant.key: %w", err)
	}
	if h.Name == "" {
		h.Name = "ipv6ddns"
	}
	if !deviceName.MatchString(h.Name) {
		return fmt.Errorf("homeassistant.name %q: use only lower-case letters, digits and hyphens, as in a host name", h.Name)
	}
	if h.FriendlyName == "" {
		h.FriendlyName = h.Name
	}
	if h.Port == 0 {
		h.Port = 6053
	}
	if len(h.Listen) == 0 {
		return errors.New("homeassistant.listen is missing: give where the device listens")
	}
	entries, err := listen.Parse(h.Listen, strconv.Itoa(h.Port))
	if err != nil {
		return fmt.Errorf("homeassistant.listen: %w", err)
	}
	// Home Assistant connects to the port announced, which is one.
	if h.Announces() {
		for _, e := range entries {
			if e.Port != entries[0].Port {
				return fmt.Errorf("homeassistant.listen: ports %s and %s: the device can announce only one port. Use one port, or set announce: false", entries[0].Port, e.Port)
			}
		}
	}
	h.Entries = entries
	return nil
}
