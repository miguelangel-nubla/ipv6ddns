package ipv6ddns

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/config"
	"github.com/miguelangel-nubla/ipv6ddns/internal/atomicfile"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/esphome"
	"github.com/miguelangel-nubla/ipv6ddns/pkg/listen"
	"github.com/miguelangel-nubla/ipv6ddns/source"
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
	// The state file, of a device whose key Home Assistant gives: empty with a key of its own.
	stateFile string

	mutex  sync.Mutex
	states map[string]string // by entity and attribute
	// Since when Home Assistant has been connected: the device's, but in tests.
	connectedSince func() (time.Time, bool)

	names map[haName]nameEntities // by endpoint and hostname
	hosts *esphome.Sensor

	// Why the device isn't announced, when it isn't: with the mutex.
	announceError string

	// The announcement: the device's, but in tests.
	advertise func(ctx context.Context, port int, ifaces []net.Interface) error
}

// haName is a name the entities are of: its endpoint and hostname, which stay, and its domain
// when the entities were made, for their names. A provider can learn its zone at the first update.
type haName struct{ endpoint, hostname, domain string }

func (n haName) key() haName { return haName{n.endpoint, n.hostname, ""} }

type nameEntities struct {
	addresses, lastUpdate *esphome.TextSensor
	problem               *esphome.BinarySensor
}

// newHomeAssistant makes the device: with the configuration's key, fixed, its MAC from it; or, with
// key provisioning, its MAC from the identity kept in the state file, and the key Home Assistant
// gives kept there. baseDir is the state folder, which a relative state file is in.
func newHomeAssistant(cfg config.HomeAssistant, baseDir string) (*homeAssistant, error) {
	device := &esphome.Device{
		Name: cfg.Name, FriendlyName: cfg.FriendlyName,
		Manufacturer: "ipv6ddns", Model: "Network wide DDNS updater",
		Project: "miguelangel-nubla.ipv6ddns", ProjectVersion: Version,
	}
	stateFile := ""
	if !cfg.KeyProvisioning {
		key, err := esphome.ParseKey(cfg.Key)
		if err != nil {
			return nil, err
		}
		device.Key, device.MAC = key, esphome.MACFrom(key)
	} else {
		path := cfg.KeyProvisioningStateFile
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
		stateFile = path
	}
	h := &homeAssistant{
		config:    cfg,
		device:    device,
		stateFile: stateFile,
		advertise: device.Advertise,
		states:    make(map[string]string),
		names:     make(map[haName]nameEntities),
	}
	// The states are a connection's: Home Assistant sends them all when it connects, so one it
	// doesn't send again, its entity gone or renamed meanwhile, is none, and not the last it sent.
	device.OnStatesReset = func() {
		h.mutex.Lock()
		clear(h.states)
		h.mutex.Unlock()
	}
	return h, nil
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
			return nil, fmt.Errorf("%s isn't a valid state file: delete it, and Home Assistant will see a new device", path)
		}
		return &state, nil
	case errors.Is(err, fs.ErrNotExist):
		state.Identity = make([]byte, 32)
		// It never fails: without randomness the process ends.
		_, _ = rand.Read(state.Identity)
		if err := state.save(path); err != nil {
			return nil, fmt.Errorf("%w: with key_provisioning, the key Home Assistant gives is stored there. Set key_provisioning_state_file to a file ipv6ddns can write, or give a key instead", err)
		}
		return &state, nil
	default:
		return nil, err
	}
}

// errLocked is lockFile's, of a lock another holds.
var errLocked = errors.New("locked")

// lockState takes the state file for this device alone, while it serves: a second instance with
// the same one, as two configurations in one folder that name none, would be the same device to
// Home Assistant, with the same MAC, and each would lose the key the other was given. The lock is
// a file beside it, <state file>.lock, as the state file itself is replaced when written.
func (h *homeAssistant) lockState() (release func(), err error) {
	if h.stateFile == "" {
		return func() {}, nil
	}
	release, err = lockFile(h.stateFile + ".lock")
	if errors.Is(err, errLocked) {
		return nil, fmt.Errorf("homeassistant: the state file %s is in use by another running ipv6ddns. Each instance is its own device, and needs its own key_provisioning_state_file and name", h.stateFile)
	}
	if err != nil {
		// No lock to take, as beside a state file that is there in a folder that can't be
		// written: it serves as before there was one.
		return func() {}, nil
	}
	return release, nil
}

// save writes the state, readable by its owner only, whole or not at all.
func (s *deviceState) save(path string) error {
	content, err := json.Marshal(s)
	if err != nil {
		return err
	}
	// Synced: the key Home Assistant gave, lost to a power cut, would leave the device unknown
	// to it, to be added again.
	return atomicfile.Write(path, content, 0o600)
}

func stateKey(entity, attribute string) string { return entity + "\x00" + attribute }

// State is a homeassistant source's: the latest state Home Assistant sent, in its connection of
// now.
func (h *homeAssistant) State(entity, attribute string) (string, error) {
	connectedSince := h.connectedSince
	if connectedSince == nil {
		connectedSince = h.device.ConnectedSince
	}
	since, connected := connectedSince()
	if !connected {
		return "", fmt.Errorf("%w for Home Assistant to connect", source.ErrWaiting)
	}
	h.mutex.Lock()
	state, ok := h.states[stateKey(entity, attribute)]
	h.mutex.Unlock()
	switch {
	case ok:
		return state, nil
	case time.Since(since) < stateGrace:
		return "", fmt.Errorf("%w for Home Assistant to send the state", source.ErrWaiting)
	default:
		// Home Assistant sends the state of an entity that is at once: none, an entity it hasn't,
		// or an attribute the entity hasn't.
		return "", fmt.Errorf("no state from Home Assistant, connected for %s: are the entity's id and attribute right?", time.Since(since).Round(time.Second))
	}
}

// stateGrace is how long a state may take after Home Assistant connects, before its absence is an
// error: the entity is none of Home Assistant's.
var stateGrace = 30 * time.Second

// subscribe asks Home Assistant for an entity's state, for a source: changed runs the source.
func (h *homeAssistant) subscribe(entity, attribute string, changed func()) {
	h.device.SubscribeHomeAssistant(entity, attribute, func(state string) {
		h.mutex.Lock()
		h.states[stateKey(entity, attribute)] = state
		h.mutex.Unlock()
		changed()
	})
}

// entityBase makes the id of a name's entities, but what each is: "cloudflare_ha", of the endpoint
// cloudflare and the host name ha. Names that differ only in case, or in what isn't a letter or a
// digit, have the same.
func entityBase(n haName) string {
	var b strings.Builder
	for _, r := range strings.ToLower(n.endpoint + "_" + n.hostname) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// entityBases gives each name the id of its entities: entityBase's, or, for those of names that
// share it, as the host names a-b and a.b of an endpoint, each with the hash of its own endpoint
// and host name besides, so that no two names are one entity to Home Assistant, whatever their
// order. The others keep theirs, whatever names come or go.
func entityBases(names []haName) map[haName]string {
	shared := map[string][]haName{}
	for _, n := range names {
		if base := entityBase(n); !slices.Contains(shared[base], n.key()) {
			shared[base] = append(shared[base], n.key())
		}
	}
	bases := map[haName]string{}
	for base, of := range shared {
		for _, n := range of {
			bases[n] = base
			if len(of) > 1 {
				hash := fnv.New32a()
				hash.Write([]byte(n.endpoint + "\x00" + n.hostname))
				bases[n] = fmt.Sprintf("%s_%08x", base, hash.Sum32())
			}
		}
	}
	return bases
}

// addEntities adds the entities of the worker's names, and the others, once. updateNow is the
// button's.
func (h *homeAssistant) addEntities(names []haName, updateNow func()) {
	bases := entityBases(names)
	for _, n := range names {
		if _, ok := h.names[n.key()]; ok {
			continue
		}
		base := bases[n.key()]
		if base != entityBase(n) && h.device.Logger != nil {
			h.device.Logger.Warnf("homeassistant: %s of %s: its entity ID, %s, is the same as another name's, so its entities are %s", n.hostname, n.endpoint, entityBase(n), base)
		}
		h.names[n.key()] = nameEntities{
			addresses: h.device.AddTextSensor(esphome.Entity{
				ID: base + "_addresses", Name: n.domain + " addresses", Icon: "mdi:ip-network",
			}),
			lastUpdate: h.device.AddTextSensor(esphome.Entity{
				ID: base + "_last_update", Name: n.domain + " last update", DeviceClass: "timestamp",
				Category: esphome.CategoryDiagnostic,
			}),
			problem: h.device.AddBinarySensor(esphome.Entity{
				ID: base + "_problem", Name: n.domain + " update", DeviceClass: "problem",
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

// stateMax is the longest state Home Assistant takes: a longer one is unknown to it.
const stateMax = 255

// addressesState is the state of a name's addresses entity: the addresses, comma separated, and,
// when they are more than Home Assistant's state holds, the first ones whole and how many more.
func addressesState(addresses []string) string {
	state := strings.Join(addresses, ", ")
	if len(state) <= stateMax {
		return state
	}
	state = fmt.Sprintf("+%d more", len(addresses))
	for n := 1; n < len(addresses); n++ {
		longer := fmt.Sprintf("%s, +%d more", strings.Join(addresses[:n], ", "), len(addresses)-n)
		if len(longer) > stateMax {
			break
		}
		state = longer
	}
	return state
}

// follow sets the entities to the worker's state, now and every homeAssistantSync, until ctx is
// done. It takes the whole status each time, for the little of it that it reads: that costs a
// little, and is simple. An entity is sent only when its state changed.
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
			e.addresses.Set(addressesState(name.Addresses))
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

// announced are the interfaces the device announces itself on by mDNS, each with its own
// addresses, for Home Assistant to connect to: those up, with multicast and an address but
// link-local, but loopback and those discovery leaves out.
func announced(include, exclude []string) ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
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
	for _, iface := range all {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagMulticast == 0 ||
			len(include) > 0 && !matches(include, iface.Name) || matches(exclude, iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLinkLocalUnicast() {
				ifaces = append(ifaces, iface)
				break
			}
		}
	}
	if len(ifaces) == 0 {
		return nil, errors.New("no address to announce")
	}
	return ifaces, nil
}

// serve listens for Home Assistant where listen says, with the state file for itself alone, and
// announces the device by mDNS, with the port it listens on, until ctx is done: on the interfaces
// that hold the addresses it listens on, or, listening on all, those discovery runs on, as they
// are now. running then waits for the connections to end, and for the announcement to be taken
// back, which tells Home Assistant the device is gone.
func (h *homeAssistant) serve(ctx context.Context, running *sync.WaitGroup, interfaces, exclude []string, errorf func(string, ...any)) error {
	entries := h.config.Entries
	if len(entries) == 0 {
		entries = []listen.Entry{{Port: strconv.Itoa(h.config.Port)}}
	}
	release, err := h.lockState()
	if err != nil {
		return err
	}
	lns, err := listen.Listen(entries)
	if err != nil {
		release()
		return fmt.Errorf("homeassistant.listen: %w", err)
	}
	running.Add(1)
	go func() {
		defer running.Done()
		<-ctx.Done()
		release()
	}()
	if h.config.Announces() {
		// The configuration takes one port to announce.
		port := h.config.Port
		if tcp, ok := lns[0].Addr().(*net.TCPAddr); ok {
			port = tcp.Port
		}
		running.Add(1)
		go func() {
			defer running.Done()
			ifaces, all, err := listen.Interfaces(lns)
			if err == nil && all {
				ifaces, err = announced(interfaces, exclude)
			}
			if err == nil {
				err = h.advertise(ctx, port, ifaces)
			}
			if err != nil {
				h.mutex.Lock()
				h.announceError = err.Error()
				h.mutex.Unlock()
				errorf("homeassistant: %s: Home Assistant won't discover it, add it by its address", err)
			}
		}()
	}
	for _, ln := range lns {
		running.Add(1)
		go func() {
			defer running.Done()
			if err := h.device.Serve(ctx, ln); err != nil {
				errorf("homeassistant: %s", err)
			}
		}()
	}
	return nil
}
