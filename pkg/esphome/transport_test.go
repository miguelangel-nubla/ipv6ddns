package esphome

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func frame(indicator byte, payload []byte) []byte {
	return append(binary.BigEndian.AppendUint16([]byte{indicator}, uint16(len(payload))), payload...)
}

// A frame is read whole or not at all: within its limit, with its indicator, and all of it.
func TestReadFrame(t *testing.T) {
	read := func(b []byte, limit int) ([]byte, error) {
		return readFrame(bufio.NewReader(bytes.NewReader(b)), limit)
	}
	if got, err := read(frame(frameIndicator, bytes.Repeat([]byte{7}, maxHandshakeFrame)), maxHandshakeFrame); err != nil || len(got) != maxHandshakeFrame {
		t.Errorf("a frame of the limit: %d bytes, %v", len(got), err)
	}
	if got, err := read(frame(frameIndicator, nil), maxHandshakeFrame); err != nil || len(got) != 0 {
		t.Errorf("an empty frame: %v, %v", got, err)
	}
	for name, c := range map[string]struct {
		frame []byte
		limit int
		want  string
	}{
		"a handshake frame over the limit": {frame(frameIndicator, make([]byte, maxHandshakeFrame+1)), maxHandshakeFrame, "more than 128"},
		"a data frame over the limit":      {frame(frameIndicator, make([]byte, maxDataFrame+1)), maxDataFrame, "more than 32768"},
		"the plaintext indicator":          {frame(plaintextIndicator, []byte{1}), maxDataFrame, errUnencrypted.Error()},
		"a header cut":                     {[]byte{frameIndicator, 0}, maxDataFrame, io.ErrUnexpectedEOF.Error()},
		"a payload cut":                    {frame(frameIndicator, []byte{1, 2, 3})[:5], maxDataFrame, io.ErrUnexpectedEOF.Error()},
		"nothing":                          {nil, maxDataFrame, io.EOF.Error()},
	} {
		if _, err := read(c.frame, c.limit); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error with %q", name, err, c.want)
		}
	}
}

// A message longer than the two bytes of a frame's length tell is an error, not a frame of
// another length, after which the client would read anything.
func TestWriteFrameLimit(t *testing.T) {
	var written bytes.Buffer
	if err := writeFrame(&written, make([]byte, maxFrame)); err != nil || written.Len() != 3+maxFrame {
		t.Errorf("the longest frame: %v, %d bytes", err, written.Len())
	}
	written.Reset()
	if err := writeFrame(&written, make([]byte, maxFrame+1)); err == nil || written.Len() != 0 {
		t.Errorf("a frame too long: %v, %d bytes written", err, written.Len())
	}
	if err := (&secureConn{}).WriteMessage(msgTextSensorStateResponse, make([]byte, maxFrame-4-16+1)); err == nil {
		t.Error("an encrypted message too long for its frame: no error")
	}
}

// writerConn is a connection that only writes, to w.
type writerConn struct {
	net.Conn
	w io.Writer
}

func (c writerConn) Write(b []byte) (int, error) { return c.w.Write(b) }

func plainMessage(size, msgType uint64, data []byte) []byte {
	b := binary.AppendUvarint([]byte{plaintextIndicator}, size)
	return append(binary.AppendUvarint(b, msgType), data...)
}

// The plaintext protocol's messages: their length and type within bounds, and whole.
func TestPlainRead(t *testing.T) {
	read := func(b []byte) (uint16, []byte, error) {
		return (&plainConn{r: bufio.NewReader(bytes.NewReader(b))}).ReadMessage()
	}
	if msgType, data, err := read(plainMessage(2, 300, []byte{8, 1})); err != nil || msgType != 300 || !bytes.Equal(data, []byte{8, 1}) {
		t.Errorf("a message: type %d, %v, %v", msgType, data, err)
	}
	// What it writes, it reads.
	var written bytes.Buffer
	(&plainConn{conn: writerConn{w: &written}}).WriteMessage(msgButtonCommandRequest, []byte{1, 2, 3})
	if msgType, data, err := read(written.Bytes()); err != nil || msgType != msgButtonCommandRequest || !bytes.Equal(data, []byte{1, 2, 3}) {
		t.Errorf("a message written: type %d, %v, %v", msgType, data, err)
	}
	for name, b := range map[string][]byte{
		"another indicator": frame(frameIndicator, nil),
		"too long":          plainMessage(maxDataFrame+1, 1, nil),
		"a type too high":   plainMessage(0, 0x10000, nil),
		"a length cut":      {plaintextIndicator, 0x80},
		"no type":           {plaintextIndicator, 1},
		"data cut":          plainMessage(4, 1, []byte{1, 2}),
		"a varint too long": append([]byte{plaintextIndicator}, bytes.Repeat([]byte{0xff}, 11)...),
	} {
		if _, _, err := read(b); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if _, _, err := read(nil); !errors.Is(err, io.EOF) {
		t.Errorf("nothing: %v, want the end", err)
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add(frame(frameIndicator, []byte("hello")))
	f.Add(frame(plaintextIndicator, nil))
	f.Add([]byte{frameIndicator, 0xff, 0xff, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		payload, err := readFrame(bufio.NewReader(bytes.NewReader(b)), maxDataFrame)
		if err == nil && (len(payload) > maxDataFrame || len(payload) > len(b)-3) {
			t.Errorf("a frame of %d bytes read of %d", len(payload), len(b))
		}
	})
}

func FuzzPlainRead(f *testing.F) {
	f.Add(plainMessage(2, 300, []byte{8, 1}))
	f.Add([]byte{plaintextIndicator, 0xff, 0xff, 0xff, 0xff, 0x0f, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		c := &plainConn{r: bufio.NewReader(bytes.NewReader(b))}
		for {
			_, data, err := c.ReadMessage()
			if err != nil {
				return
			}
			if len(data) > maxDataFrame || len(data) > len(b) {
				t.Fatalf("a message of %d bytes read of %d", len(data), len(b))
			}
		}
	})
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(message{}.string(1, "sensor.wan_ip").string(2, "203.0.113.9").fixed32(3, 7).uint(4, 9).float(5, 1.5)))
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Add([]byte{0x0b, 0x0c}) // a group, which api.proto has none of
	f.Fuzz(func(t *testing.T, b []byte) {
		fields, _ := parse(b)
		for _, s := range fields.strings {
			if len(s) > len(b) {
				t.Errorf("a string of %d bytes read of %d", len(s), len(b))
			}
		}
	})
}
