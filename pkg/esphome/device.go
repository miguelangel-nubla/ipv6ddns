// Package esphome is a device of the ESPHome native API: Home Assistant's ESPHome integration
// connects to it as to any ESPHome device, finds it by mDNS, lists its entities, follows their
// states, presses its buttons, and sends it the states of Home Assistant's entities it asks for.
// The connection is encrypted with the device's key, which the user gives Home Assistant once.
//
// It speaks the part of the protocol a device of sensors and buttons needs, as ESPHome 2026.11
// does: the protocol is ESPHome's, in esphome/components/api.
package esphome

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Device is what Home Assistant sees. Set its fields, add its entities and its subscriptions to
// Home Assistant's states, then Serve.
type Device struct {
	// Name is the device's name in the network, as a host name: lower case, digits and hyphens.
	Name string
	// FriendlyName is the one Home Assistant shows.
	FriendlyName string
	// MAC identifies the device to Home Assistant: keep it the same, or Home Assistant sees
	// another device.
	MAC net.HardwareAddr
	// Key is the encryption key: 32 bytes, which the user gives Home Assistant in base64. Without
	// one, and with OnKey, Home Assistant gives it, as to ESPHome's devices: it connects without,
	// makes a key, and gives it over Noise with the zero key; OnKey keeps it, and the device takes
	// it at once.
	Key []byte
	// OnKey keeps a key Home Assistant gives, or forgets it when nil: the device's next start must
	// have it. Without OnKey, the device's key is fixed, and one Home Assistant gives is refused.
	OnKey func(key []byte) error
	// Who made it, and what: project is "author.name", as ESPHome's project_name.
	Manufacturer, Model, Project, ProjectVersion string

	Logger *zap.SugaredLogger

	mutex         sync.Mutex
	keyChanged    chan struct{} // closed and replaced when the key changes
	entities      []*entity
	subscriptions []subscription
	conns         map[*connection]struct{}
}

// EntityCategory groups an entity in Home Assistant's device page.
type EntityCategory int

const (
	CategoryNone       EntityCategory = 0
	CategoryConfig     EntityCategory = 1
	CategoryDiagnostic EntityCategory = 2
)

// Entity says what an entity is: its id, unique on the device, as "wan_address", its name, as
// "WAN address", and how Home Assistant shows it.
type Entity struct {
	ID          string
	Name        string
	Icon        string // as "mdi:dns"
	DeviceClass string // Home Assistant's, as "timestamp" or "problem"
	Unit        string // sensors: as "hosts"
	Category    EntityCategory
}

type kind int

const (
	kindTextSensor kind = iota
	kindSensor
	kindBinarySensor
	kindButton
)

type entity struct {
	Entity
	kind    kind
	key     uint32
	onPress func()

	// The state, and whether there is one yet.
	text    string
	number  float32
	on      bool
	hasData bool
}

// TextSensor is an entity whose state is text.
type TextSensor struct {
	device *Device
	entity *entity
}

// Sensor is an entity whose state is a number.
type Sensor struct {
	device *Device
	entity *entity
}

// BinarySensor is an entity that is on or off.
type BinarySensor struct {
	device *Device
	entity *entity
}

type subscription struct {
	entityID, attribute string
	onState             func(state string)
}

// GenerateKey returns a new encryption key, in the base64 Home Assistant takes.
func GenerateKey() string {
	key := make([]byte, 32)
	rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

// ParseKey reads a key as Home Assistant takes it: the base64 of 32 bytes.
func ParseKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(key) != 32 {
		return nil, errors.New("not an encryption key: the base64 of 32 bytes, as ESPHome's")
	}
	return key, nil
}

func (d *Device) add(e Entity, k kind) *entity {
	h := fnv.New32a()
	h.Write([]byte(e.ID))
	en := &entity{Entity: e, kind: k, key: h.Sum32()}
	d.mutex.Lock()
	d.entities = append(d.entities, en)
	d.mutex.Unlock()
	return en
}

// AddTextSensor adds an entity whose state is text. Add the entities before Serve.
func (d *Device) AddTextSensor(e Entity) *TextSensor {
	return &TextSensor{d, d.add(e, kindTextSensor)}
}

// AddSensor adds an entity whose state is a number.
func (d *Device) AddSensor(e Entity) *Sensor {
	return &Sensor{d, d.add(e, kindSensor)}
}

// AddBinarySensor adds an entity that is on or off.
func (d *Device) AddBinarySensor(e Entity) *BinarySensor {
	return &BinarySensor{d, d.add(e, kindBinarySensor)}
}

// AddButton adds a button; onPress runs when Home Assistant presses it.
func (d *Device) AddButton(e Entity, onPress func()) {
	en := d.add(e, kindButton)
	en.onPress = onPress
}

// SubscribeHomeAssistant asks Home Assistant for the state of an entity, or of its attribute when
// not empty; onState is called with it when Home Assistant connects and at every change.
func (d *Device) SubscribeHomeAssistant(entityID, attribute string, onState func(state string)) {
	d.mutex.Lock()
	d.subscriptions = append(d.subscriptions, subscription{entityID, attribute, onState})
	d.mutex.Unlock()
}

// Set makes the sensor's state text, and tells Home Assistant.
func (s *TextSensor) Set(text string) {
	s.device.update(s.entity, func(e *entity) bool {
		changed := !e.hasData || e.text != text
		e.text = text
		return changed
	})
}

// Set makes the sensor's state the number, and tells Home Assistant.
func (s *Sensor) Set(v float32) {
	s.device.update(s.entity, func(e *entity) bool {
		changed := !e.hasData || e.number != v
		e.number = v
		return changed
	})
}

// Set turns the sensor on or off, and tells Home Assistant.
func (s *BinarySensor) Set(on bool) {
	s.device.update(s.entity, func(e *entity) bool {
		changed := !e.hasData || e.on != on
		e.on = on
		return changed
	})
}

func (d *Device) update(e *entity, set func(*entity) bool) {
	d.mutex.Lock()
	changed := set(e)
	e.hasData = true
	state := stateMessage(e)
	conns := make([]*connection, 0, len(d.conns))
	for c := range d.conns {
		if c.statesSubscribed() {
			conns = append(conns, c)
		}
	}
	d.mutex.Unlock()
	if !changed {
		return
	}
	for _, c := range conns {
		c.write(state.msgType, state.data)
	}
}

// key returns the device's key: nil without one.
func (d *Device) key() []byte {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.Key
}

// HasKey tells whether the device has its key, set or given by Home Assistant.
func (d *Device) HasKey() bool { return d.key() != nil }

// keyChange returns a channel closed at the next change of the key.
func (d *Device) keyChange() <-chan struct{} {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.keyChanged == nil {
		d.keyChanged = make(chan struct{})
	}
	return d.keyChanged
}

// setKey takes a key Home Assistant gave, or forgets it: OnKey keeps it first.
func (d *Device) setKey(key []byte) error {
	if err := d.OnKey(key); err != nil {
		return err
	}
	d.mutex.Lock()
	d.Key = key
	if d.keyChanged != nil {
		close(d.keyChanged)
	}
	d.keyChanged = make(chan struct{})
	d.mutex.Unlock()
	return nil
}

// closeUntrusted ends the connections without the key, after it changed: Home Assistant's own
// reconnects with it.
func (d *Device) closeUntrusted() {
	d.mutex.Lock()
	var untrusted []*connection
	for c := range d.conns {
		if !c.trusted {
			untrusted = append(untrusted, c)
		}
	}
	d.mutex.Unlock()
	for _, c := range untrusted {
		c.close()
	}
}

// Connected tells whether Home Assistant is connected, and follows the device's states.
func (d *Device) Connected() bool {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	for c := range d.conns {
		if c.statesSubscribed() {
			return true
		}
	}
	return false
}

// Serve answers Home Assistant's connections on ln, until ctx is done.
func (d *Device) Serve(ctx context.Context, ln net.Listener) error {
	if d.Key != nil && len(d.Key) != 32 {
		return errors.New("the device's key must be of 32 bytes")
	}
	if d.Key == nil && d.OnKey == nil {
		return errors.New("the device needs a key, or OnKey for Home Assistant to give it one")
	}
	if len(d.MAC) != 6 {
		return errors.New("the device needs a MAC of 6 bytes")
	}
	d.mutex.Lock()
	if d.conns == nil {
		d.conns = make(map[*connection]struct{})
	}
	d.mutex.Unlock()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.serveConn(ctx, conn)
		}()
	}
}

type outgoing struct {
	msgType uint16
	data    []byte
}

type connection struct {
	sc      msgConn
	conn    net.Conn
	mutex   sync.Mutex
	states  bool
	trusted bool // with the device's key: only then are Home Assistant's states and commands taken
}

func (c *connection) close() { c.conn.Close() }

func (c *connection) statesSubscribed() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.states
}

func (c *connection) write(msgType uint16, data []byte) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.sc.WriteMessage(msgType, data)
}

func (d *Device) logf(format string, args ...any) {
	if d.Logger != nil {
		d.Logger.Debugf("esphome: "+format, args...)
	}
}

func (d *Device) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	sc, trusted, err := accept(conn, d.Name, d.MAC, d.key())
	if err != nil {
		d.logf("%s: %s", conn.RemoteAddr(), err)
		return
	}
	c := &connection{sc: sc, conn: conn, trusted: trusted}
	d.mutex.Lock()
	d.conns[c] = struct{}{}
	d.mutex.Unlock()
	defer func() {
		d.mutex.Lock()
		delete(d.conns, c)
		d.mutex.Unlock()
	}()

	for {
		msgType, data, err := sc.ReadMessage()
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				d.logf("%s: %s", conn.RemoteAddr(), err)
			}
			return
		}
		if done, err := d.handle(c, msgType, data); err != nil || done {
			if err != nil {
				d.logf("%s: %s", conn.RemoteAddr(), err)
			}
			return
		}
	}
}

// handle answers a message; done says the connection ends.
func (d *Device) handle(c *connection, msgType uint16, data []byte) (bool, error) {
	switch msgType {
	case msgHelloRequest:
		return false, c.write(msgHelloResponse, message{}.
			uint(1, apiVersionMajor).uint(2, apiVersionMinor).
			string(3, d.Project+" "+d.ProjectVersion).string(4, d.Name))
	case msgAuthenticationRequest:
		// There is no password: the key authenticates.
		return false, c.write(msgAuthenticationResponse, nil)
	case msgPingRequest:
		return false, c.write(msgPingResponse, nil)
	case msgDisconnectRequest:
		c.write(msgDisconnectResponse, nil)
		return true, nil
	case msgDeviceInfoRequest:
		return false, c.write(msgDeviceInfoResponse, d.deviceInfo())
	case msgDeviceCapabilitiesRequest:
		// None: no Bluetooth proxy, voice assistant, Z-Wave proxy or wizard. Home Assistant waits
		// for it, from devices of API 1.15 on.
		return false, c.write(msgDeviceCapabilitiesResponse, nil)
	case msgListEntitiesRequest:
		d.mutex.Lock()
		list := make([]outgoing, 0, len(d.entities))
		for _, e := range d.entities {
			list = append(list, listMessage(e))
		}
		d.mutex.Unlock()
		for _, m := range list {
			if err := c.write(m.msgType, m.data); err != nil {
				return false, err
			}
		}
		return false, c.write(msgListEntitiesDoneResponse, nil)
	case msgSubscribeStatesRequest:
		d.mutex.Lock()
		var states []outgoing
		for _, e := range d.entities {
			if e.kind != kindButton {
				states = append(states, stateMessage(e))
			}
		}
		d.mutex.Unlock()
		c.mutex.Lock()
		c.states = true
		c.mutex.Unlock()
		for _, m := range states {
			if err := c.write(m.msgType, m.data); err != nil {
				return false, err
			}
		}
		return false, nil
	case msgSubscribeHomeAssistantStatesRequest:
		if !c.trusted {
			// States from a client without the key would be anyone's: not asked.
			return false, nil
		}
		d.mutex.Lock()
		subs := append([]subscription(nil), d.subscriptions...)
		d.mutex.Unlock()
		for _, s := range subs {
			if err := c.write(msgSubscribeHomeAssistantStateResponse, message{}.string(1, s.entityID).string(2, s.attribute)); err != nil {
				return false, err
			}
		}
		return false, nil
	case msgHomeAssistantStateResponse:
		if !c.trusted {
			return false, nil
		}
		f, err := parse(data)
		if err != nil {
			return false, err
		}
		entityID, state, attribute := f.strings[1], f.strings[2], f.strings[3]
		d.mutex.Lock()
		subs := append([]subscription(nil), d.subscriptions...)
		d.mutex.Unlock()
		for _, s := range subs {
			if s.entityID == entityID && s.attribute == attribute {
				s.onState(state)
			}
		}
		return false, nil
	case msgButtonCommandRequest:
		if !c.trusted {
			d.logf("a button pressed without the key: ignored")
			return false, nil
		}
		f, err := parse(data)
		if err != nil {
			return false, err
		}
		key := uint32(f.numbers[1])
		d.mutex.Lock()
		var press func()
		for _, e := range d.entities {
			if e.kind == kindButton && e.key == key {
				press = e.onPress
			}
		}
		d.mutex.Unlock()
		if press != nil {
			go press()
		}
		return false, nil
	case msgNoiseEncryptionSetKeyRequest:
		f, err := parse(data)
		if err != nil {
			return false, err
		}
		ok := d.takeKey(c, f.strings[1])
		if err := c.write(msgNoiseEncryptionSetKeyResponse, message{}.bool(1, ok)); err != nil {
			return false, err
		}
		if ok {
			d.closeUntrusted()
		}
		return false, nil
	}
	// The rest, as the logs and services subscriptions: nothing to do.
	return false, nil
}

// takeKey takes the key Home Assistant gives: over Noise, with the zero key while the device has
// none, or with the key, to change it; never in plaintext. An empty one forgets it, with the key
// only. It tells whether the key was taken.
func (d *Device) takeKey(c *connection, encoded string) bool {
	if d.OnKey == nil {
		d.logf("a key given, but the device's is fixed: refused")
		return false
	}
	_, plain := c.sc.(*plainConn)
	if plain || !c.trusted && d.HasKey() {
		d.logf("a key given without encryption, or without the key: refused")
		return false
	}
	if encoded == "" {
		if !c.trusted {
			return false
		}
		if err := d.setKey(nil); err != nil {
			d.logf("forgetting the key: %s", err)
			return false
		}
		return true
	}
	key, err := ParseKey(encoded)
	if err != nil || string(key) == string(zeroKey) {
		d.logf("a key given that isn't one: refused")
		return false
	}
	if err := d.setKey(key); err != nil {
		d.logf("keeping the key: %s", err)
		return false
	}
	return true
}

func (d *Device) deviceInfo() []byte {
	mac := strings.ToUpper(d.MAC.String())
	return message{}.
		string(2, d.Name).
		string(3, mac).
		string(4, esphomeVersion).
		string(6, d.Model).
		string(8, d.Project).
		string(9, d.ProjectVersion).
		string(12, d.Manufacturer).
		string(13, d.FriendlyName).
		bool(19, true).          // api_encryption_supported
		bool(26, d.OnKey != nil) // api_encryption_provisionable: Home Assistant gives the key
}

func listMessage(e *entity) outgoing {
	m := message{}.string(1, e.ID).fixed32(2, e.key).string(3, e.Name)
	switch e.kind {
	case kindBinarySensor:
		return outgoing{msgListEntitiesBinarySensorResponse, m.string(5, e.DeviceClass).string(8, e.Icon).uint(9, uint64(e.Category))}
	case kindSensor:
		// accuracy_decimals 0, state_class measurement.
		return outgoing{msgListEntitiesSensorResponse, m.string(5, e.Icon).string(6, e.Unit).string(9, e.DeviceClass).uint(10, 1).uint(13, uint64(e.Category))}
	case kindTextSensor:
		return outgoing{msgListEntitiesTextSensorResponse, m.string(5, e.Icon).uint(7, uint64(e.Category)).string(8, e.DeviceClass)}
	default:
		return outgoing{msgListEntitiesButtonResponse, m.string(5, e.Icon).uint(7, uint64(e.Category)).string(8, e.DeviceClass)}
	}
}

func stateMessage(e *entity) outgoing {
	m := message{}.fixed32(1, e.key)
	missing := !e.hasData
	switch e.kind {
	case kindBinarySensor:
		return outgoing{msgBinarySensorStateResponse, m.bool(2, e.on).bool(3, missing)}
	case kindSensor:
		return outgoing{msgSensorStateResponse, m.float(2, e.number).bool(3, missing)}
	default:
		return outgoing{msgTextSensorStateResponse, m.string(2, e.text).bool(3, missing)}
	}
}

// String tells the device, for logs.
func (d *Device) String() string {
	return fmt.Sprintf("%s (%s)", d.Name, d.MAC)
}
