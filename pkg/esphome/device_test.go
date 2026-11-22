package esphome

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
)

// These tests are a client in Go, with the device's own framing, so that they run where Python's
// aioesphomeapi isn't: compat_test.go has Home Assistant's library itself.

// testClient is a client past its handshake.
type testClient struct {
	net.Conn
	msgConn
}

// serveDevice serves d at an address of loopback's, until the test ends.
func serveDevice(t *testing.T, d *Device) string {
	t.Helper()
	if d.MAC == nil {
		d.MAC, _ = net.ParseMAC("02:00:5e:10:00:10")
	}
	if d.Name == "" {
		d.Name = "ipv6ddns-test"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Error(err)
		}
	})
	return ln.Addr().String()
}

// shorten gives a limit of the connections another value, for the test.
func shorten[T any](t *testing.T, limit *T, value T) {
	t.Helper()
	old := *limit
	*limit = value
	// After the device of the test stopped, which reads it: the cleanups run last first.
	t.Cleanup(func() { *limit = old })
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	return conn
}

// dialPlain connects in the plaintext protocol.
func dialPlain(t *testing.T, addr string) *testClient {
	t.Helper()
	conn := dial(t, addr)
	return &testClient{conn, &plainConn{conn: conn, r: bufio.NewReader(conn)}}
}

// dialNoise connects with key, as aioesphomeapi does: its hello and its handshake at once. It
// returns the device's reason when it refuses the handshake.
func dialNoise(t *testing.T, addr string, key []byte) (*testClient, string) {
	t.Helper()
	conn := dial(t, addr)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Pattern: noise.HandshakeNN, Initiator: true,
		Prologue: append(append([]byte{}, prologue...), 0, 0), PresharedKey: key, PresharedKeyPlacement: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(conn, nil)
	writeFrame(conn, append([]byte{handshakeOK}, first...))
	r := bufio.NewReader(conn)
	hello, err := readFrame(r, maxHandshakeFrame)
	if err != nil {
		return nil, err.Error()
	}
	if len(hello) == 0 || hello[0] != protocolNNpsk0 {
		return nil, string(hello[1:])
	}
	reply, err := readFrame(r, maxHandshakeFrame)
	if err != nil {
		return nil, err.Error()
	}
	if len(reply) == 0 || reply[0] != handshakeOK {
		return nil, string(reply[1:])
	}
	_, send, recv, err := hs.ReadMessage(nil, reply[1:])
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{conn, &secureConn{conn: conn, r: r, send: send, recv: recv}}, ""
}

// expect reads to the next message of the type.
func (c *testClient) expect(t *testing.T, msgType uint16) []byte {
	t.Helper()
	for {
		got, data, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("waiting for a message of type %d: %v", msgType, err)
		}
		if got == msgType {
			return data
		}
	}
}

// ping waits for the device to have handled what was sent before.
func (c *testClient) ping(t *testing.T) {
	t.Helper()
	c.WriteMessage(msgPingRequest, nil)
	c.expect(t, msgPingResponse)
}

// closed tells whether the device closed the connection, without a message of the type before.
func (c *testClient) closed(without uint16) bool {
	for {
		got, _, err := c.ReadMessage()
		if err != nil {
			var timeout net.Error
			return !errors.As(err, &timeout) || !timeout.Timeout()
		}
		if got == without {
			return false
		}
	}
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
	}
}

func testKey() []byte {
	key, _ := ParseKey(GenerateKey())
	return key
}

// A client that follows the states and reads nothing, while it goes on asking, stops nobody else:
// the states are set, the device answers who asks whether Home Assistant is connected and whether
// it has its key, others connect; and it is dropped once nothing could be written to it for
// writeTimeout.
func TestClientThatStopsReading(t *testing.T) {
	shorten(t, &writeTimeout, 500*time.Millisecond)
	d := &Device{FriendlyName: strings.Repeat("a long name ", 20), OnKey: func([]byte) error { return nil }}
	sensor := d.AddTextSensor(Entity{ID: "addresses", Name: "Addresses"})
	sensor.Set("2001:db8::1")
	addr := serveDevice(t, d)

	stalled := dialPlain(t, addr)
	stalled.WriteMessage(msgSubscribeStatesRequest, nil)
	dropped := make(chan struct{})
	go func() {
		defer close(dropped)
		stalled.SetWriteDeadline(time.Now().Add(30 * time.Second))
		for {
			if err := stalled.WriteMessage(msgDeviceInfoRequest, nil); err != nil {
				return
			}
		}
	}()

	within := func(what string, f func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			f()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: blocked by a client that reads nothing", what)
		}
	}
	for n, end := 0, time.Now().Add(time.Second); time.Now().Before(end); n++ {
		within("setting a state", func() { sensor.Set(strings.Repeat("x", n%200)) })
		within("ConnectedSince", func() { d.ConnectedSince() })
		within("HasKey", func() { d.HasKey() })
	}
	within("another client", func() {
		other := dialPlain(t, addr)
		other.ping(t)
		other.Close()
	})
	select {
	case <-dropped:
	case <-time.After(20 * time.Second):
		t.Fatal("the client that reads nothing was never dropped")
	}
	eventually(t, "the connection gone from the device's", func() bool {
		d.mutex.Lock()
		defer d.mutex.Unlock()
		return len(d.conns) == 0
	})
}

// A state set many times before a client reads goes once, as it is then, and the latest last.
func TestStatesFollowed(t *testing.T) {
	d := &Device{OnKey: func([]byte) error { return nil }}
	sensor := d.AddTextSensor(Entity{ID: "addresses", Name: "Addresses"})
	hosts := d.AddSensor(Entity{ID: "hosts", Name: "Hosts"})
	d.AddButton(Entity{ID: "update", Name: "Update"}, func() {})
	hosts.Set(3)
	c := dialPlain(t, serveDevice(t, d))
	c.WriteMessage(msgSubscribeStatesRequest, nil)
	// No state yet: told so.
	if f, _ := parse(c.expect(t, msgTextSensorStateResponse)); f.numbers[3] != 1 || f.strings[2] != "" {
		t.Errorf("a sensor without a state: %v", f)
	}
	if f, _ := parse(c.expect(t, msgSensorStateResponse)); f.numbers[3] != 0 {
		t.Errorf("a sensor with a state: %v", f)
	}
	for _, state := range []string{"a", "b", "c", "last"} {
		sensor.Set(state)
	}
	for {
		f, _ := parse(c.expect(t, msgTextSensorStateResponse))
		if f.strings[2] == "last" {
			break
		}
	}
	// The same again is no change: the ping's answer comes with no state before it.
	sensor.Set("last")
	c.WriteMessage(msgPingRequest, nil)
	if got, _, err := c.ReadMessage(); err != nil || got != msgPingResponse {
		t.Errorf("after a state set to the same: a message of type %d, %v", got, err)
	}
}

// A client that connected while the device had no key, and waited to speak until Home Assistant
// gave it, gets in no more than one that connects then.
func TestKeyGivenWhileConnecting(t *testing.T) {
	d := &Device{OnKey: func([]byte) error { return nil }}
	d.AddTextSensor(Entity{ID: "addresses", Name: "Addresses"}).Set("2001:db8::1")
	addr := serveDevice(t, d)

	early := dialPlain(t, addr)
	// Let the device take the connection, and wait for its first byte.
	other := dialPlain(t, addr)
	other.ping(t)
	if err := d.setKey(testKey()); err != nil {
		t.Fatal(err)
	}
	d.closeUntrusted(nil)
	if !other.closed(0) {
		t.Error("a connection without the key outlived the key")
	}

	early.WriteMessage(msgSubscribeStatesRequest, nil)
	rest, _ := io.ReadAll(early.Conn)
	if bytes.Contains(rest, []byte("2001:db8::1")) {
		t.Errorf("served without the key: %q", rest)
	}
	if !bytes.Contains(rest, []byte(rejectBadIndicator)) {
		t.Errorf("not told it needs the key: %q", rest)
	}
	if d.Connected() {
		t.Error("Home Assistant connected, by a client without the key")
	}
}

// A client whose handshake began while the device had no key, and ended once Home Assistant had
// given it, is past both the key's check and the closing of the connections without it: it is
// closed when its handshake ends.
func TestKeyGivenDuringHandshake(t *testing.T) {
	d := &Device{OnKey: func([]byte) error { return nil }}
	d.AddTextSensor(Entity{ID: "addresses", Name: "Addresses"}).Set("2001:db8::1")
	addr := serveDevice(t, d)

	// The client's hello alone: the device answers it with the zero key, since it has none, and
	// waits for the rest of the handshake.
	conn := dial(t, addr)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite, Pattern: noise.HandshakeNN, Initiator: true,
		Prologue: append(append([]byte{}, prologue...), 0, 0), PresharedKey: zeroKey, PresharedKeyPlacement: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeFrame(conn, nil)
	r := bufio.NewReader(conn)
	if hello, err := readFrame(r, maxHandshakeFrame); err != nil || len(hello) == 0 || hello[0] != protocolNNpsk0 {
		t.Fatalf("the device's hello: %x, %v", hello, err)
	}

	if err := d.setKey(testKey()); err != nil {
		t.Fatal(err)
	}
	d.closeUntrusted(nil)

	// The handshake ends, with the zero key the device began it with.
	writeFrame(conn, append([]byte{handshakeOK}, first...))
	reply, err := readFrame(r, maxHandshakeFrame)
	if err != nil || len(reply) == 0 || reply[0] != handshakeOK {
		t.Fatalf("the device's handshake: %x, %v", reply, err)
	}
	_, send, recv, err := hs.ReadMessage(nil, reply[1:])
	if err != nil {
		t.Fatal(err)
	}
	c := &testClient{conn, &secureConn{conn: conn, r: r, send: send, recv: recv}}
	c.WriteMessage(msgSubscribeStatesRequest, nil)
	if !c.closed(msgTextSensorStateResponse) {
		t.Error("served without the key the device has, by a handshake that began before it")
	}
}

// closeRecorder is a connection that tells whether it was closed.
type closeRecorder struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeRecorder) Close() error {
	c.closed.Store(true)
	return nil
}

// Of the connections without the key, the one that gave it is not closed with the others: its
// answer, that the key was taken, may not be written yet, and it ends itself after it.
func TestKeyGiverNotClosedWithTheUntrusted(t *testing.T) {
	d := &Device{conns: make(map[*connection]struct{})}
	add := func(trusted bool) *closeRecorder {
		conn := &closeRecorder{}
		d.conns[&connection{conn: conn, trusted: trusted}] = struct{}{}
		return conn
	}
	giver, other, homeAssistant := add(false), add(false), add(true)
	for c := range d.conns {
		if c.conn == giver {
			d.closeUntrusted(c)
		}
	}
	if giver.closed.Load() {
		t.Error("the connection that gave the key was closed, before its answer")
	}
	if !other.closed.Load() {
		t.Error("another connection without the key was not closed")
	}
	if homeAssistant.closed.Load() {
		t.Error("a connection with the key was closed")
	}
}

// Home Assistant is connected when a client with the key was asked for the states: one without
// the key, which a device without one takes, is anyone, and is asked none. The states of before
// are none when a connection asks which to send, and when the last ends.
func TestConnected(t *testing.T) {
	var resets atomic.Int32
	d := &Device{OnKey: func([]byte) error { return nil }, OnStatesReset: func() { resets.Add(1) }}
	d.AddTextSensor(Entity{ID: "addresses", Name: "Addresses"}).Set("2001:db8::1")
	d.SubscribeHomeAssistant("sensor.wan_ip", "", func(string) {})
	addr := serveDevice(t, d)

	for name, anyone := range map[string]*testClient{"plaintext": dialPlain(t, addr), "the zero key": first(dialNoise(t, addr, zeroKey))} {
		anyone.WriteMessage(msgSubscribeStatesRequest, nil)
		anyone.WriteMessage(msgSubscribeHomeAssistantStatesRequest, nil)
		anyone.expect(t, msgTextSensorStateResponse)
		anyone.ping(t)
		if d.Connected() || resets.Load() != 0 {
			t.Errorf("%s: Home Assistant connected, by a client without the key; %d resets", name, resets.Load())
		}
	}

	key := testKey()
	if err := d.setKey(key); err != nil {
		t.Fatal(err)
	}
	d.closeUntrusted(nil)
	ha, reason := dialNoise(t, addr, key)
	if ha == nil {
		t.Fatal(reason)
	}
	ha.WriteMessage(msgSubscribeStatesRequest, nil)
	ha.ping(t)
	if d.Connected() {
		t.Error("Home Assistant connected, before it was asked for states")
	}
	before := time.Now()
	ha.WriteMessage(msgSubscribeHomeAssistantStatesRequest, nil)
	if f, _ := parse(ha.expect(t, msgSubscribeHomeAssistantStateResponse)); f.strings[1] != "sensor.wan_ip" {
		t.Errorf("the state asked: %v", f)
	}
	if since, ok := d.ConnectedSince(); !ok || since.Before(before) || resets.Load() != 1 {
		t.Errorf("with the key, asked for states: connected %v since %v, %d resets", ok, since, resets.Load())
	}

	// Another connection: the states are its own, from when it is asked; and the first ending
	// leaves them.
	again, _ := dialNoise(t, addr, key)
	again.WriteMessage(msgSubscribeHomeAssistantStatesRequest, nil)
	again.expect(t, msgSubscribeHomeAssistantStateResponse)
	if resets.Load() != 2 {
		t.Errorf("a second connection asked for states: %d resets", resets.Load())
	}
	ha.WriteMessage(msgDisconnectRequest, nil)
	ha.expect(t, msgDisconnectResponse)
	if !ha.closed(0) {
		t.Error("not closed after a disconnection")
	}
	again.ping(t)
	if !d.Connected() || resets.Load() != 2 {
		t.Errorf("one of two connections ended: connected %v, %d resets", d.Connected(), resets.Load())
	}
	again.Close()
	eventually(t, "Home Assistant disconnected, its states none", func() bool { return !d.Connected() && resets.Load() == 3 })
}

func first[T, U any](v T, _ U) T { return v }

// A client that connects and says nothing, or that stops talking, is dropped; and no more
// connections are served at once than maxConnections.
func TestConnectionLimits(t *testing.T) {
	t.Run("silent before the handshake", func(t *testing.T) {
		shorten(t, &handshakeTimeout, 200*time.Millisecond)
		d := &Device{Key: testKey()}
		conn := dial(t, serveDevice(t, d))
		start := time.Now()
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) || time.Since(start) > 10*time.Second {
			t.Errorf("a silent connection: %v after %s, want it closed", err, time.Since(start))
		}
	})
	t.Run("silent in the handshake", func(t *testing.T) {
		shorten(t, &handshakeTimeout, 200*time.Millisecond)
		d := &Device{Key: testKey()}
		conn := dial(t, serveDevice(t, d))
		writeFrame(conn, nil)
		if rest, err := io.ReadAll(conn); err != nil || len(rest) == 0 {
			t.Errorf("a client that stops in the handshake: %q, %v, want the device's hello, and closed", rest, err)
		}
	})
	t.Run("silent after", func(t *testing.T) {
		shorten(t, &idleTimeout, 300*time.Millisecond)
		d := &Device{OnKey: func([]byte) error { return nil }}
		c := dialPlain(t, serveDevice(t, d))
		c.ping(t)
		if !c.closed(0) {
			t.Error("a client that stopped talking wasn't dropped")
		}
	})
	t.Run("too many", func(t *testing.T) {
		shorten(t, &maxConnections, 2)
		d := &Device{OnKey: func([]byte) error { return nil }}
		addr := serveDevice(t, d)
		one, two := dialPlain(t, addr), dialPlain(t, addr)
		one.ping(t)
		two.ping(t)
		over := dialPlain(t, addr)
		over.WriteMessage(msgPingRequest, nil)
		if !over.closed(msgPingResponse) {
			t.Error("a third connection of two was served")
		}
		// One ends: its place is another's.
		one.Close()
		eventually(t, "a place freed", func() bool {
			c := dialPlain(t, addr)
			defer c.Close()
			c.WriteMessage(msgPingRequest, nil)
			return !c.closed(msgPingResponse)
		})
	})
}

// failingListener fails to accept the first times, as with no file descriptor left.
type failingListener struct {
	net.Listener
	failures atomic.Int32
}

func (l *failingListener) Accept() (net.Conn, error) {
	if l.failures.Add(-1) >= 0 {
		return nil, errors.New("accept: too many open files")
	}
	return l.Listener.Accept()
}

// A failure to accept a connection doesn't end the listener: the next ones are served.
func TestServeAcceptsAgain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	failing := &failingListener{Listener: ln}
	failing.failures.Store(3)
	mac, _ := net.ParseMAC("02:00:5e:10:00:11")
	d := &Device{Name: "ipv6ddns-test", MAC: mac, OnKey: func([]byte) error { return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx, failing) }()
	dialPlain(t, ln.Addr().String()).ping(t)
	if failing.failures.Load() >= 0 {
		t.Error("the listener didn't fail first")
	}
	cancel()
	if err := <-served; err != nil {
		t.Errorf("Serve, its context done: %v", err)
	}

	// The listener closed by another is the end.
	ln, _ = net.Listen("tcp", "127.0.0.1:0")
	go func() { served <- d.Serve(context.Background(), ln) }()
	ln.Close()
	select {
	case err := <-served:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve, its listener closed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve, its listener closed, goes on")
	}
}

// Who may do what: the key is given over Noise only, with the zero key while the device has none
// and with the key after; forgotten with the key only; and a client without the key presses no
// button and gives no state.
func TestTrust(t *testing.T) {
	var kept [][]byte
	var keptMutex sync.Mutex
	var pressed, stated atomic.Int32
	d := &Device{OnKey: func(key []byte) error {
		keptMutex.Lock()
		defer keptMutex.Unlock()
		kept = append(kept, key)
		return nil
	}}
	d.AddButton(Entity{ID: "update", Name: "Update"}, func() { pressed.Add(1) })
	d.SubscribeHomeAssistant("sensor.wan_ip", "", func(string) { stated.Add(1) })
	addr := serveDevice(t, d)
	var button *entity
	for _, e := range d.entities {
		button = e
	}
	setKey := func(c *testClient, key []byte) bool {
		t.Helper()
		var encoded string
		if key != nil {
			encoded = base64.StdEncoding.EncodeToString(key)
		}
		c.WriteMessage(msgNoiseEncryptionSetKeyRequest, message{}.string(1, encoded))
		f, err := parse(c.expect(t, msgNoiseEncryptionSetKeyResponse))
		if err != nil {
			t.Fatal(err)
		}
		return f.numbers[1] == 1
	}
	act := func(c *testClient) {
		t.Helper()
		c.WriteMessage(msgButtonCommandRequest, message{}.fixed32(1, button.key))
		c.WriteMessage(msgHomeAssistantStateResponse, message{}.string(1, "sensor.wan_ip").string(2, "203.0.113.9"))
		c.ping(t)
	}
	keyA, keyB := testKey(), testKey()

	// Without a key yet.
	plain := dialPlain(t, addr)
	if setKey(plain, keyA) || d.HasKey() {
		t.Error("a key taken in plaintext")
	}
	act(plain)
	zero, _ := dialNoise(t, addr, zeroKey)
	second, _ := dialNoise(t, addr, zeroKey)
	act(zero)
	time.Sleep(50 * time.Millisecond) // a press runs apart
	if pressed.Load() != 0 || stated.Load() != 0 {
		t.Errorf("without the key: %d presses, %d states taken", pressed.Load(), stated.Load())
	}
	if setKey(zero, nil) {
		t.Error("the key forgotten by a client without it")
	}
	if setKey(zero, zeroKey) || setKey(zero, []byte("short")) || d.HasKey() {
		t.Error("the zero key, or a short one, taken")
	}
	if !setKey(zero, keyA) || string(d.key()) != string(keyA) {
		t.Error("a key given over Noise to a device without one: not taken")
	}
	// The connections without it end; the other who meant to give one is too late.
	second.WriteMessage(msgNoiseEncryptionSetKeyRequest, message{}.string(1, base64.StdEncoding.EncodeToString(keyB)))
	for name, c := range map[string]*testClient{"plaintext": plain, "the zero key": zero, "a second giver": second} {
		if !c.closed(0) {
			t.Errorf("%s: not closed once the device had its key", name)
		}
	}
	if string(d.key()) != string(keyA) {
		t.Error("a second key taken from a client without the first")
	}

	// With its key.
	if c, reason := dialNoise(t, addr, zeroKey); c != nil || reason != rejectMACFailure {
		t.Errorf("the zero key, to a device with its key: %q, want %q", reason, rejectMACFailure)
	}
	if c, reason := dialNoise(t, addr, keyB); c != nil || reason != rejectMACFailure {
		t.Errorf("another key: %q, want %q", reason, rejectMACFailure)
	}
	refused := dial(t, addr)
	(&plainConn{conn: refused}).WriteMessage(msgHelloRequest, nil)
	if rest, _ := io.ReadAll(refused); !bytes.Equal(rest, append([]byte{frameIndicator, 0, byte(1 + len(rejectBadIndicator)), handshakeReject}, rejectBadIndicator...)) {
		t.Errorf("plaintext, to a device with its key: %q", rest)
	}
	ha, reason := dialNoise(t, addr, keyA)
	if ha == nil {
		t.Fatal(reason)
	}
	act(ha)
	eventually(t, "the button pressed and the state taken, with the key", func() bool { return pressed.Load() == 1 && stated.Load() == 1 })
	if !setKey(ha, keyB) || string(d.key()) != string(keyB) {
		t.Error("the key changed with the key: not taken")
	}
	if !setKey(ha, nil) || d.HasKey() {
		t.Error("the key forgotten with the key: kept")
	}
	keptMutex.Lock()
	defer keptMutex.Unlock()
	if len(kept) != 3 || string(kept[0]) != string(keyA) || string(kept[1]) != string(keyB) || kept[2] != nil {
		t.Errorf("the keys kept: %x", kept)
	}
}

// Of two clients that give a device without a key one each at once, one is taken: the device
// keeps that one.
func TestOneKeyTaken(t *testing.T) {
	var kept atomic.Int32
	d := &Device{OnKey: func([]byte) error {
		kept.Add(1)
		time.Sleep(20 * time.Millisecond)
		return nil
	}}
	addr := serveDevice(t, d)
	var clients []*testClient
	for range 4 {
		c, _ := dialNoise(t, addr, zeroKey)
		c.ping(t)
		clients = append(clients, c)
	}
	var givers sync.WaitGroup
	for _, c := range clients {
		givers.Add(1)
		go func() {
			defer givers.Done()
			c.WriteMessage(msgNoiseEncryptionSetKeyRequest, message{}.string(1, GenerateKey()))
			c.closed(0)
		}()
	}
	givers.Wait()
	if kept.Load() != 1 || !d.HasKey() {
		t.Errorf("%d keys kept, of clients without one", kept.Load())
	}
}

// The messages the device writes, byte by byte, as api.proto has their fields: a number that
// slips shows here, without Home Assistant's library.
func TestMessagesGolden(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:5e:10:00:01")
	d := &Device{Name: "ddns", FriendlyName: "DDNS", MAC: mac, Manufacturer: "mf", Model: "md", Project: "a.b", ProjectVersion: "1.2",
		OnKey: func([]byte) error { return nil }}
	e := Entity{ID: "id", Name: "Nm", Icon: "mdi:x", DeviceClass: "dc", Unit: "u", Category: CategoryDiagnostic}
	text := &entity{Entity: e, kind: kindTextSensor, key: 0x04030201, text: "ab", hasData: true}
	number := &entity{Entity: e, kind: kindSensor, key: 0x04030201, number: 3, hasData: true}
	binary := &entity{Entity: e, kind: kindBinarySensor, key: 0x04030201, on: true, hasData: true}
	button := &entity{Entity: e, kind: kindButton, key: 0x04030201}
	missing := &entity{Entity: e, kind: kindTextSensor, key: 0x04030201}
	// name 1, key 2 (fixed32), name 3.
	const head = "0a026964" + "1501020304" + "1a024e6d"
	for name, c := range map[string]struct {
		got     outgoing
		msgType uint16
		want    string
	}{
		"device info": {outgoing{msgDeviceInfoResponse, d.deviceInfo()}, 10,
			"120464646e73" + "1a1130323a30303a35453a31303a30303a3031" + "2209323032362e31312e30" + "32026d64" +
				"4203612e62" + "4a03312e32" + "62026d66" + "6a0444444e53" + "9801" + "01" + "d001" + "01"},
		"a text sensor":   {listMessage(text), 18, head + "2a056d64693a78" + "3802" + "42026463"},
		"a sensor":        {listMessage(number), 16, head + "2a056d64693a78" + "320175" + "4a026463" + "5001" + "6802"},
		"a binary sensor": {listMessage(binary), 12, head + "2a026463" + "42056d64693a78" + "4802"},
		"a button":        {listMessage(button), 61, head + "2a056d64693a78" + "3802" + "42026463"},
		"a text state":    {stateMessage(text), 27, "0d01020304" + "12026162"},
		"a number state":  {stateMessage(number), 25, "0d01020304" + "1500004040"},
		"a binary state":  {stateMessage(binary), 21, "0d01020304" + "1001"},
		"no state":        {stateMessage(missing), 27, "0d01020304" + "1801"},
	} {
		if c.got.msgType != c.msgType || hex.EncodeToString(c.got.data) != c.want {
			t.Errorf("%s: type %d, %x\nwant type %d, %s", name, c.got.msgType, c.got.data, c.msgType, c.want)
		}
	}
}

// Two entities have no key in common, whatever their ids: Home Assistant would take them for one.
func TestEntityKeys(t *testing.T) {
	d := &Device{}
	a := d.AddTextSensor(Entity{ID: "addresses"})
	b := d.AddSensor(Entity{ID: "hosts"})
	same := d.AddBinarySensor(Entity{ID: "addresses"})
	if a.entity.key != 0x949b51e3 {
		t.Errorf("the key of an entity: %#x, want the FNV-1a hash of its id, as ESPHome's", a.entity.key)
	}
	if a.entity.key == b.entity.key || same.entity.key == a.entity.key || same.entity.key == b.entity.key {
		t.Errorf("keys in common: %#x, %#x, %#x", a.entity.key, b.entity.key, same.entity.key)
	}
}
