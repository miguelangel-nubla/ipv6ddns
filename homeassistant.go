package ipv6ddns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
)

// Version is the version of ipv6ddns, which Home Assistant shows: the command sets it.
var Version = "dev"

// homeAssistantSync is how often the entities follow the worker's state. A state goes to Home
// Assistant only when it changes.
const homeAssistantSync = 5 * time.Second

// homeAssistant is ipv6ddns as a device of Home Assistant's ESPHome integration: the names'
// addresses, last updates and problems, the hosts discovered, a button to update now; and the
// states of Home Assistant's entities that homeassistant sources read.
type homeAssistant struct {
	config config.HomeAssistant
	device *esphome.Device

	mutex  sync.Mutex
	states map[string]string // by entity and attribute

	names map[haName]nameEntities // by endpoint and hostname
	hosts *esphome.Sensor
}

// haName is a name the entities are of: its endpoint and hostname, which stay, and its domain
// when the entities were made, for their names. A provider can learn its zone at the first update.
type haName struct{ endpoint, hostname, domain string }

func (n haName) key() haName { return haName{n.endpoint, n.hostname, ""} }

type nameEntities struct {
	addresses, lastUpdate *esphome.TextSensor
	problem               *esphome.BinarySensor
}

func newHomeAssistant(cfg config.HomeAssistant) (*homeAssistant, error) {
	key, err := esphome.ParseKey(cfg.Key)
	if err != nil {
		return nil, err
	}
	return &homeAssistant{
		config: cfg,
		device: &esphome.Device{
			Name: cfg.Name, FriendlyName: cfg.FriendlyName, MAC: esphome.MACFromKey(key), Key: key,
			Manufacturer: "ipv6ddns", Model: "Network wide DDNS updater",
			Project: "miguelangel-nubla.ipv6ddns", ProjectVersion: Version,
		},
		states: make(map[string]string),
		names:  make(map[haName]nameEntities),
	}, nil
}

func stateKey(entity, attribute string) string { return entity + "\x00" + attribute }

// State is a homeassistant source's: the latest state Home Assistant sent, while it is connected.
func (h *homeAssistant) State(entity, attribute string) (string, bool) {
	if !h.device.Connected() {
		return "", false
	}
	h.mutex.Lock()
	defer h.mutex.Unlock()
	state, ok := h.states[stateKey(entity, attribute)]
	return state, ok
}

// subscribe asks Home Assistant for an entity's state, for a source: changed runs the source.
func (h *homeAssistant) subscribe(entity, attribute string, changed func()) {
	h.device.SubscribeHomeAssistant(entity, attribute, func(state string) {
		h.mutex.Lock()
		h.states[stateKey(entity, attribute)] = state
		h.mutex.Unlock()
		changed()
	})
}

// entityID makes an entity's id of a name and what it is: "cloudflare_ha_addresses".
func entityID(n haName, what string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(n.endpoint + "_" + n.hostname) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String() + "_" + what
}

// addEntities adds the entities of the worker's names, and the others. updateNow is the button's.
func (h *homeAssistant) addEntities(names []haName, updateNow func()) {
	for _, n := range names {
		if _, ok := h.names[n.key()]; ok {
			continue
		}
		h.names[n.key()] = nameEntities{
			addresses: h.device.AddTextSensor(esphome.Entity{
				ID: entityID(n, "addresses"), Name: n.domain + " addresses", Icon: "mdi:ip-network",
			}),
			lastUpdate: h.device.AddTextSensor(esphome.Entity{
				ID: entityID(n, "last_update"), Name: n.domain + " last update", DeviceClass: "timestamp",
				Category: esphome.CategoryDiagnostic,
			}),
			problem: h.device.AddBinarySensor(esphome.Entity{
				ID: entityID(n, "problem"), Name: n.domain + " update", DeviceClass: "problem",
				Category: esphome.CategoryDiagnostic,
			}),
		}
	}
	h.hosts = h.device.AddSensor(esphome.Entity{
		ID: "discovered_hosts", Name: "Discovered hosts", Icon: "mdi:lan", Unit: "hosts",
		Category: esphome.CategoryDiagnostic,
	})
	h.device.AddButton(esphome.Entity{ID: "update_now", Name: "Update now", Icon: "mdi:refresh"}, updateNow)
}

// follow sets the entities to the worker's state, now and every homeAssistantSync, until ctx is
// done.
func (h *homeAssistant) follow(ctx context.Context, status func() Status) {
	ticker := time.NewTicker(homeAssistantSync)
	defer ticker.Stop()
	for {
		s := status()
		for _, name := range s.Hostnames {
			e, ok := h.names[haName{name.Endpoint, name.Hostname, ""}]
			if !ok {
				continue
			}
			e.addresses.Set(strings.Join(name.Addresses, ", "))
			if name.LastUpdate != nil {
				e.lastUpdate.Set(name.LastUpdate.UTC().Format(time.RFC3339))
			}
			e.problem.Set(name.LastError != "")
		}
		h.hosts.Set(float32(len(s.Discovered)))
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// serve listens for Home Assistant on the port, and announces the device by mDNS, until ctx is
// done.
func (h *homeAssistant) serve(ctx context.Context, errorf func(string, ...any)) error {
	ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(h.config.Port)))
	if err != nil {
		return fmt.Errorf("homeassistant: %w", err)
	}
	go func() {
		if err := h.device.Advertise(ctx, h.config.Port, nil); err != nil {
			errorf("homeassistant: %s: Home Assistant won't discover it, add it by its address", err)
		}
	}()
	go func() {
		if err := h.device.Serve(ctx, ln); err != nil {
			errorf("homeassistant: %s", err)
		}
	}()
	return nil
}
