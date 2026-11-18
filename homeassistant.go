package ipv6ddns

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
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

// newHomeAssistant makes the device: with the configuration's key, fixed, its MAC from it; or with
// the state file, its MAC from the identity kept there, and the key Home Assistant gives kept there.
// baseDir is the configuration's folder, which a relative state file is in.
func newHomeAssistant(cfg config.HomeAssistant, baseDir string) (*homeAssistant, error) {
	device := &esphome.Device{
		Name: cfg.Name, FriendlyName: cfg.FriendlyName,
		Manufacturer: "ipv6ddns", Model: "Network wide DDNS updater",
		Project: "miguelangel-nubla.ipv6ddns", ProjectVersion: Version,
	}
	if cfg.Key != "" {
		key, err := esphome.ParseKey(cfg.Key)
		if err != nil {
			return nil, err
		}
		device.Key, device.MAC = key, esphome.MACFrom(key)
	} else {
		path := cfg.StateFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		state, err := loadDeviceState(path)
		if err != nil {
			return nil, fmt.Errorf("homeassistant: %w", err)
		}
		device.MAC, device.Key = esphome.MACFrom(state.Identity), state.Key
		device.OnKey = func(key []byte) error {
			state.Key = key
			return state.save(path)
		}
	}
	return &homeAssistant{
		config: cfg,
		device: device,
		states: make(map[string]string),
		names:  make(map[haName]nameEntities),
	}, nil
}

// deviceState is what a device whose key Home Assistant gives keeps: its identity, which its MAC
// comes from, so that Home Assistant knows it whatever its key; and the key, once given.
type deviceState struct {
	Identity []byte `json:"identity"`
	Key      []byte `json:"key,omitempty"`
}

// loadDeviceState reads the state file, or makes a new identity and writes it, the first time: a
// state file ipv6ddns can't write is an error at the start, rather than when Home Assistant gives
// the key.
func loadDeviceState(path string) (*deviceState, error) {
	var state deviceState
	content, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(content, &state); err != nil || len(state.Identity) != 32 || state.Key != nil && len(state.Key) != 32 {
			return nil, fmt.Errorf("the state file %s isn't one: delete it, and Home Assistant sees a new device", path)
		}
		return &state, nil
	case errors.Is(err, fs.ErrNotExist):
		state.Identity = make([]byte, 32)
		rand.Read(state.Identity)
		if err := state.save(path); err != nil {
			return nil, fmt.Errorf("%w: without a key in the configuration, the key Home Assistant gives is kept there; set state_file to a file ipv6ddns can write", err)
		}
		return &state, nil
	default:
		return nil, err
	}
}

// save writes the state, readable by its owner only, whole or not at all.
func (s *deviceState) save(path string) error {
	content, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
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

// announced are the interfaces the device announces itself on by mDNS, and the addresses it
// announces, for Home Assistant to connect to: those of the interfaces up, with multicast, but
// loopback, and those discovery leaves out, as the bridges of containers, which Home Assistant
// can't reach the device at.
func announced(include, exclude []string) ([]net.Interface, []net.IP, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	matches := func(patterns []string, name string) bool {
		for _, p := range patterns {
			if ok, _ := path.Match(p, name); ok {
				return true
			}
		}
		return false
	}
	var ifaces []net.Interface
	var ips []net.IP
	for _, iface := range all {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagMulticast == 0 ||
			len(include) > 0 && !matches(include, iface.Name) || matches(exclude, iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		before := len(ips)
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLinkLocalUnicast() {
				ips = append(ips, ipNet.IP)
			}
		}
		if len(ips) > before {
			ifaces = append(ifaces, iface)
		}
	}
	if len(ips) == 0 {
		return nil, nil, errors.New("no address to announce")
	}
	return ifaces, ips, nil
}

// serve listens for Home Assistant on the port, and announces the device by mDNS at the addresses
// of the interfaces discovery runs on, until ctx is done.
func (h *homeAssistant) serve(ctx context.Context, interfaces, exclude []string, errorf func(string, ...any)) error {
	ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(h.config.Port)))
	if err != nil {
		return fmt.Errorf("homeassistant: %w", err)
	}
	if h.config.Announces() {
		go func() {
			ifaces, ips, err := announced(interfaces, exclude)
			if err == nil {
				err = h.device.Advertise(ctx, h.config.Port, ips, ifaces)
			}
			if err != nil {
				errorf("homeassistant: %s: Home Assistant won't discover it, add it by its address", err)
			}
		}()
	}
	go func() {
		if err := h.device.Serve(ctx, ln); err != nil {
			errorf("homeassistant: %s", err)
		}
	}()
	return nil
}
