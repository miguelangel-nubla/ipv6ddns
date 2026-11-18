package esphome

import (
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

// The messages of the native API a device needs, with their ids and field numbers as
// esphome/components/api/api.proto has them (ESPHome 2026.11). Only these are encoded and
// decoded; a device ignores the others.
const (
	msgHelloRequest                        = 1
	msgHelloResponse                       = 2
	msgAuthenticationRequest               = 3
	msgAuthenticationResponse              = 4
	msgDisconnectRequest                   = 5
	msgDisconnectResponse                  = 6
	msgPingRequest                         = 7
	msgPingResponse                        = 8
	msgDeviceInfoRequest                   = 9
	msgDeviceInfoResponse                  = 10
	msgListEntitiesRequest                 = 11
	msgListEntitiesBinarySensorResponse    = 12
	msgListEntitiesSensorResponse          = 16
	msgListEntitiesTextSensorResponse      = 18
	msgListEntitiesDoneResponse            = 19
	msgSubscribeStatesRequest              = 20
	msgBinarySensorStateResponse           = 21
	msgSensorStateResponse                 = 25
	msgTextSensorStateResponse             = 27
	msgSubscribeHomeAssistantStatesRequest = 38
	msgSubscribeHomeAssistantStateResponse = 39
	msgHomeAssistantStateResponse          = 40
	msgListEntitiesButtonResponse          = 61
	msgButtonCommandRequest                = 62
	msgNoiseEncryptionSetKeyRequest        = 124
	msgNoiseEncryptionSetKeyResponse       = 125
	msgDeviceCapabilitiesRequest           = 149
	msgDeviceCapabilitiesResponse          = 150
)

// The API version a device of ESPHome 2026.11 says it speaks, and that release.
const (
	apiVersionMajor = 1
	apiVersionMinor = 20
	esphomeVersion  = "2026.11.0"
)

// message is a protobuf being written.
type message []byte

func (m message) string(field protowire.Number, s string) message {
	if s == "" {
		return m
	}
	m = protowire.AppendTag(m, field, protowire.BytesType)
	return protowire.AppendString(m, s)
}

func (m message) uint(field protowire.Number, v uint64) message {
	if v == 0 {
		return m
	}
	m = protowire.AppendTag(m, field, protowire.VarintType)
	return protowire.AppendVarint(m, v)
}

func (m message) bool(field protowire.Number, v bool) message {
	if !v {
		return m
	}
	return m.uint(field, 1)
}

func (m message) fixed32(field protowire.Number, v uint32) message {
	m = protowire.AppendTag(m, field, protowire.Fixed32Type)
	return protowire.AppendFixed32(m, v)
}

func (m message) float(field protowire.Number, v float32) message {
	m = protowire.AppendTag(m, field, protowire.Fixed32Type)
	return protowire.AppendFixed32(m, math.Float32bits(v))
}

// fields reads a protobuf's fields: the strings and the numbers, by field number. It is enough for
// the few the device reads.
type fields struct {
	strings map[protowire.Number]string
	numbers map[protowire.Number]uint64
}

func parse(b []byte) (fields, error) {
	f := fields{strings: map[protowire.Number]string{}, numbers: map[protowire.Number]uint64{}}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return f, protowire.ParseError(n)
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return f, protowire.ParseError(n)
			}
			f.numbers[num] = v
			b = b[n:]
		case protowire.Fixed32Type:
			v, n := protowire.ConsumeFixed32(b)
			if n < 0 {
				return f, protowire.ParseError(n)
			}
			f.numbers[num] = uint64(v)
			b = b[n:]
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return f, protowire.ParseError(n)
			}
			f.strings[num] = string(v)
			b = b[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return f, protowire.ParseError(n)
			}
			b = b[n:]
		}
	}
	return f, nil
}
