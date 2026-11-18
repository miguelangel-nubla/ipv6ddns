package esphome

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/flynn/noise"
)

// The encrypted transport of the ESPHome native API, as a device answers it
// (esphome/components/api/api_frame_helper_noise.cpp):
//
//   - Every frame is 0x01, the payload's length on two bytes, big endian, and the payload.
//   - The client opens with a hello frame, empty. The prologue of the handshake is "NoiseAPIInit",
//     that frame's length on two bytes, and its payload.
//   - The device answers with its hello: 0x01, the protocol it chose (Noise_NNpsk0_25519_ChaChaPoly_SHA256),
//     its name, 0, its MAC in hex, 0.
//   - Then Noise_NNpsk0 with the key: the client's message, the device's, each frame led by 0x00.
//     A failure is a frame of 0x01 and the reason: "Handshake MAC failure" for a wrong key.
//   - Then data frames: each encrypted, of the message's type and length on two bytes each, and
//     the protobuf message.

const (
	frameIndicator     = 0x01
	handshakeOK        = 0x00
	handshakeReject    = 0x01
	protocolNNpsk0     = 0x01
	maxHandshakeFrame  = 128
	maxDataFrame       = 32768
	rejectBadIndicator = "Bad indicator byte"
	rejectMACFailure   = "Handshake MAC failure"
	rejectHandshake    = "Handshake error"
)

var prologue = []byte("NoiseAPIInit")

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// errUnencrypted is a client speaking the plaintext protocol to a device that needs the key: it
// is told so, and asks the user for the key.
var errUnencrypted = errors.New("the client spoke unencrypted, and the device needs its key")

// secureConn is a connection past the handshake.
type secureConn struct {
	conn net.Conn
	r    *bufio.Reader
	send *noise.CipherState
	recv *noise.CipherState
}

func readFrame(r *bufio.Reader, limit int) ([]byte, error) {
	var header [3]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if header[0] != frameIndicator {
		return nil, errUnencrypted
	}
	size := int(binary.BigEndian.Uint16(header[1:]))
	if size > limit {
		return nil, fmt.Errorf("a frame of %d bytes, more than %d", size, limit)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeFrame(w io.Writer, payload []byte) error {
	frame := make([]byte, 3+len(payload))
	frame[0] = frameIndicator
	binary.BigEndian.PutUint16(frame[1:], uint16(len(payload)))
	copy(frame[3:], payload)
	_, err := w.Write(frame)
	return err
}

func reject(w io.Writer, reason string) {
	writeFrame(w, append([]byte{handshakeReject}, reason...))
}

// handshake answers a client's handshake as the device of name and mac, with key: the 32 bytes of
// the encryption key, the base64 of which the user gives Home Assistant.
func handshake(conn net.Conn, name string, mac net.HardwareAddr, key []byte) (*secureConn, error) {
	r := bufio.NewReader(conn)
	hello, err := readFrame(r, maxHandshakeFrame)
	if errors.Is(err, errUnencrypted) {
		reject(conn, rejectBadIndicator)
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("the client's hello: %w", err)
	}

	p := append([]byte{}, prologue...)
	p = binary.BigEndian.AppendUint16(p, uint16(len(hello)))
	p = append(p, hello...)

	serverHello := []byte{protocolNNpsk0}
	serverHello = append(serverHello, name...)
	serverHello = append(serverHello, 0)
	serverHello = append(serverHello, strings.ReplaceAll(mac.String(), ":", "")...)
	serverHello = append(serverHello, 0)
	if err := writeFrame(conn, serverHello); err != nil {
		return nil, err
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:           cipherSuite,
		Pattern:               noise.HandshakeNN,
		Initiator:             false,
		Prologue:              p,
		PresharedKey:          key,
		PresharedKeyPlacement: 0,
	})
	if err != nil {
		return nil, err
	}

	first, err := readFrame(r, maxHandshakeFrame)
	if err != nil {
		return nil, fmt.Errorf("the client's handshake: %w", err)
	}
	if len(first) == 0 || first[0] != handshakeOK {
		reject(conn, rejectHandshake)
		return nil, errors.New("the client's handshake: no status byte")
	}
	if _, _, _, err := hs.ReadMessage(nil, first[1:]); err != nil {
		// A wrong key fails the message's authentication: the client asks the user for another.
		reject(conn, rejectMACFailure)
		return nil, fmt.Errorf("the client's handshake, another key: %w", err)
	}
	reply, clientToDevice, deviceToClient, err := hs.WriteMessage(nil, nil)
	if err != nil {
		reject(conn, rejectHandshake)
		return nil, err
	}
	if err := writeFrame(conn, append([]byte{handshakeOK}, reply...)); err != nil {
		return nil, err
	}
	// The first cipher state is the initiator's, the client's, which the device decrypts.
	return &secureConn{conn: conn, r: r, send: deviceToClient, recv: clientToDevice}, nil
}

// ReadMessage returns the next message: its type and protobuf.
func (c *secureConn) ReadMessage() (uint16, []byte, error) {
	frame, err := readFrame(c.r, maxDataFrame)
	if err != nil {
		return 0, nil, err
	}
	plain, err := c.recv.Decrypt(nil, nil, frame)
	if err != nil {
		return 0, nil, fmt.Errorf("decrypting: %w", err)
	}
	if len(plain) < 4 {
		return 0, nil, errors.New("a message too short")
	}
	msgType := binary.BigEndian.Uint16(plain[0:])
	size := int(binary.BigEndian.Uint16(plain[2:]))
	if size > len(plain)-4 {
		return 0, nil, errors.New("a message longer than its frame")
	}
	return msgType, plain[4 : 4+size], nil
}

// WriteMessage sends a message of the type. It isn't safe for concurrent use.
func (c *secureConn) WriteMessage(msgType uint16, data []byte) error {
	plain := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint16(plain[0:], msgType)
	binary.BigEndian.PutUint16(plain[2:], uint16(len(data)))
	plain = append(plain, data...)
	encrypted, err := c.send.Encrypt(nil, nil, plain)
	if err != nil {
		return err
	}
	return writeFrame(c.conn, encrypted)
}
