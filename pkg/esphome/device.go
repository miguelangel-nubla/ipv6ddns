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
	"slices"
	"strings"
	"sync"
	"time"

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
	// OnStatesReset, when set, is called when the states Home Assistant sent are none any more:
	// when a connection asks which to follow, as Home Assistant sends them all anew then, and when
	// the last such connection ends. So a state of an earlier connection, of an entity Home
	// Assistant has no more, isn't taken for the present one. It runs with the device locked,
	// before any state of the new connection: it must not call the device.
	OnStatesReset func()
	// Who made it, and what: project is "author.name", as ESPHome's project_name.
	Manufacturer, Model, Project, ProjectVersion string

	Logger *zap.SugaredLogger

	keying        sync.Mutex // one key given at a time: held while it is checked, kept and taken
	mutex         sync.Mutex
	keyChanged    chan struct{} // closed and replaced when the key changes
	entities      []*entity
	subscriptions []subscription
	conns         map[*connection]struct{}
}

// What a connection may take: a variable each, for the tests.
var (
	// handshakeTimeout is how long a client has to say which protocol it speaks, and to prove the
	// key: one that connects and says nothing holds no descriptor longer.
	handshakeTimeout = 30 * time.Second
	// idleTimeout is how long a connection may send nothing: Home Assistant pings every 20
	// seconds, and ESPHome's devices drop a client silent for 150.
	idleTimeout = 150 * time.Second
	// writeTimeout is how long a message may take to be written: a client that reads nothing for
	// that long is dropped.
	writeTimeout = 10 * time.Second
	// maxConnections is how many connections a listener serves at once, the ones over it closed
	// at once: Home Assistant makes one, or two while it adds the device.
	maxConnections = 32
)

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
		return nil, errors.New("not an encryption key: it must be base64 of 32 bytes, as ESPHome's")
	}
	return key, nil
}

// add adds an entity, with its key, by which Home Assistant tells the entities of a connection
// apart: the hash of its id, as ESPHome's, or the next free one when another entity has it, as two
// ids of the same hash would, since two entities with one key are one to Home Assistant.
func (d *Device) add(e Entity, k kind) *entity {
	h := fnv.New32a()
	h.Write([]byte(e.ID))
	en := &entity{Entity: e, kind: k, key: h.Sum32()}
	d.mutex.Lock()
	for slices.ContainsFunc(d.entities, func(other *entity) bool { return other.key == en.key }) {
		en.key++
	}
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

// update sets an entity's state, and has each connection that follows the states send it: it
// waits for none of them.
func (d *Device) update(e *entity, set func(*entity) bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	changed := set(e)
	e.hasData = true
	if !changed {
		return
	}
	for c := range d.conns {
		if c.states {
			c.queue(e)
		}
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

// setKey takes a key Home Assistant gave, or forgets it: OnKey keeps it first. With keying held.
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
// reconnects with it. But the one that gave it, which ends itself once it is answered.
func (d *Device) closeUntrusted(but *connection) {
	d.mutex.Lock()
	var untrusted []*connection
	for c := range d.conns {
		if !c.trusted && c != but {
			untrusted = append(untrusted, c)
		}
	}
	d.mutex.Unlock()
	for _, c := range untrusted {
		c.close()
	}
}

// Connected tells whether Home Assistant is connected: with the device's key, and asked for the
// states the device follows. A connection without the key is anyone's, and sends none.
func (d *Device) Connected() bool {
	_, ok := d.ConnectedSince()
	return ok
}

// ConnectedSince tells since when Home Assistant has been connected, with the device's key, and
// sending the states the device asked for: since the latest of its connections asked which, as
// the states are those sent from then on.
func (d *Device) ConnectedSince() (time.Time, bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	var since time.Time
	for c := range d.conns {
		if c.asked.After(since) {
			since = c.asked
		}
	}
	return since, !since.IsZero()
}

// Serve answers Home Assistant's connections on ln, until ctx is done: maxConnections at once. A
// failure to accept one, as with no file descriptor left, is tried again, ever later up to a
// second: only the listener closed ends it.
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
	slots := make(chan struct{}, maxConnections)
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if delay == 0 && d.Logger != nil {
				d.Logger.Warnf("esphome: accepting a connection: %s: trying again", err)
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(delay):
			}
			continue
		}
		delay = 0
		select {
		case slots <- struct{}{}:
		default:
			d.logf("%s: %d connections already: closed", conn.RemoteAddr(), maxConnections)
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			d.serveConn(ctx, conn)
		}()
	}
}

type outgoing struct {
	msgType uint16
	data    []byte
}

// connection is a client past its handshake. Its handler reads, and only its writer writes, each
// message within writeTimeout: nothing that holds a lock waits for a client to read.
type connection struct {
	sc      msgConn
	conn    net.Conn
	trusted bool // with the device's key: only then are Home Assistant's states and commands taken

	out  chan outgoing // the answers, for the writer: closed when the handler ends
	wake chan struct{} // there are states to send
	done chan struct{} // closed when the writer ends

	// With the device's mutex.
	states  bool                 // it follows the device's states
	asked   time.Time            // when it asked which of Home Assistant's states to send: trusted only
	pending []*entity            // those whose state it has yet to send, in order
	queued  map[*entity]struct{} // the same
}

func (c *connection) close() { c.conn.Close() }

// queue has the writer send the entity's state, as it is when it does: once, however many changes
// before that. With the device's mutex.
func (c *connection) queue(e *entity) {
	if _, ok := c.queued[e]; ok {
		return
	}
	c.queued[e] = struct{}{}
	c.pending = append(c.pending, e)
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// write gives the writer a message, waiting while it has many to send: an error when it ended.
func (c *connection) write(msgType uint16, data []byte) error {
	select {
	case c.out <- outgoing{msgType, data}:
		return nil
	case <-c.done:
		return errors.New("the connection is closed")
	}
}

// writer sends the connection's messages, until its handler ends or a write fails, as when the
// client reads nothing for writeTimeout: it closes the connection then, since part of a frame may
// have gone, which ends the handler.
func (d *Device) writer(c *connection) {
	defer close(c.done)
	send := func(m outgoing) bool {
		// Without its deadline, a write to a client that reads nothing would wait for ever.
		err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err == nil {
			err = c.sc.WriteMessage(m.msgType, m.data)
		}
		if err != nil {
			d.logf("%s: writing: %s", c.conn.RemoteAddr(), err)
			c.conn.Close()
			return false
		}
		return true
	}
	for {
		select {
		case m, ok := <-c.out:
			if !ok || !send(m) {
				return
			}
		case <-c.wake:
			d.mutex.Lock()
			states := make([]outgoing, 0, len(c.pending))
			for _, e := range c.pending {
				states = append(states, stateMessage(e))
			}
			c.pending = c.pending[:0]
			clear(c.queued)
			d.mutex.Unlock()
			for _, m := range states {
				if !send(m) {
					return
				}
			}
		}
	}
}

func (d *Device) logf(format string, args ...any) {
	if d.Logger != nil {
		d.Logger.Debugf("esphome: "+format, args...)
	}
}

// connected tells whether a connection has been asked for Home Assistant's states. With the mutex.
func (d *Device) connected() bool {
	for c := range d.conns {
		if !c.asked.IsZero() {
			return true
		}
	}
	return false
}

func (d *Device) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	// A connection whose deadlines can't be set could hold its slot for ever: it ends.
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		d.logf("%s: %s", conn.RemoteAddr(), err)
		return
	}
	sc, trusted, err := accept(conn, d.Name, d.MAC, d.key)
	if err != nil {
		d.logf("%s: %s", conn.RemoteAddr(), err)
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		d.logf("%s: %s", conn.RemoteAddr(), err)
		return
	}
	c := &connection{sc: sc, conn: conn, trusted: trusted,
		out: make(chan outgoing, 16), wake: make(chan struct{}, 1), done: make(chan struct{}),
		queued: make(map[*entity]struct{})}
	// The key may have been given since the handshake began: setKey sets it with the mutex, before
	// closeUntrusted, so a connection without it is either among conns for that, or sees it here.
	d.mutex.Lock()
	if !trusted && d.Key != nil {
		d.mutex.Unlock()
		d.logf("%s: connected without the key, which the device has now: closed", conn.RemoteAddr())
		return
	}
	d.conns[c] = struct{}{}
	d.mutex.Unlock()
	go d.writer(c)
	defer func() {
		d.mutex.Lock()
		delete(d.conns, c)
		if !c.asked.IsZero() && !d.connected() && d.OnStatesReset != nil {
			d.OnStatesReset()
		}
		d.mutex.Unlock()
		// The writer sends what the handler left it, as the answer to a disconnection, and ends.
		close(c.out)
		<-c.done
	}()

	for {
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			d.logf("%s: %s", conn.RemoteAddr(), err)
			return
		}
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
		// The connection ends, answered or not.
		_ = c.write(msgDisconnectResponse, nil)
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
		// Every state now, and each change from now on.
		d.mutex.Lock()
		c.states = true
		for _, e := range d.entities {
			if e.kind != kindButton {
				c.queue(e)
			}
		}
		d.mutex.Unlock()
		return false, nil
	case msgSubscribeHomeAssistantStatesRequest:
		if !c.trusted {
			// States from a client without the key would be anyone's: not asked.
			return false, nil
		}
		// Home Assistant sends each state asked here, now and at its changes: those of before, of
		// another connection or this one, are none.
		d.mutex.Lock()
		subs := append([]subscription(nil), d.subscriptions...)
		c.asked = time.Now()
		if d.OnStatesReset != nil {
			d.OnStatesReset()
		}
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
			d.closeUntrusted(c)
		}
		// Without the key the device has now, this one ends too, its answer written first.
		return ok && !c.trusted, nil
	}
	// The rest, as the logs and services subscriptions: nothing to do.
	return false, nil
}

// takeKey takes the key Home Assistant gives: over Noise, with the zero key while the device has
// none, or with the key, to change it; never in plaintext. An empty one forgets it, with the key
// only. It tells whether the key was taken. One at a time: of two clients that give a device
// without a key one each, the second finds it has one, and is refused.
func (d *Device) takeKey(c *connection, encoded string) bool {
	if d.OnKey == nil {
		d.logf("a key given, but the device's is fixed: refused")
		return false
	}
	d.keying.Lock()
	defer d.keying.Unlock()
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
