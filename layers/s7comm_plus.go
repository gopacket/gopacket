// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// S7comm-plus is the protocol of S7-1200 and S7-1500 PLCs and TIA
// Portal, carried in COTP DT TPDUs:
//
//	+-----------------+-----------+-----------------------+---------+
//	| 0x72 ver len(2) | integrity | data header | items   | trailer |
//	+-----------------+-----------+-----------------------+---------+
//	                   (V3 only)  <------ DataLength ----->  0x72 ver 0
//
// Request data header:  opcode, reserved(2), function(2), reserved(2),
// sequence(2), session ID(4), transport flags.
// Response data header: the same without the session ID.
//
// Decoded: frame header, V3 integrity part (opaque), request and
// response data headers, trailer. The item tree after the data header
// (objects, attributes, values in VLQ encoding) stays raw in Data;
// DecodeBody decodes it on request, and the exported VLQ readers its
// integers. A PDU too large for one
// TPDU is sent as several frames that each repeat the frame header and
// only the last of which has the trailer; a continuation frame does not
// start with an opcode, so its body stays raw too. S7CommPlusAssembler
// joins such frames. A frame of version 0xFE is a system event, which
// DecodeSysEvent decodes.
//
// Not decoded: the keep-alive of version 0xFF, whose third and fourth
// octets are a sequence number and not a length. It is not recognised
// as S7comm-plus.

// LayerTypeS7CommPlus is the layer type of a Siemens S7comm-plus frame.
var LayerTypeS7CommPlus = gopacket.RegisterLayerType(163, gopacket.LayerTypeMetadata{Name: "S7comm-plus", Decoder: gopacket.DecodeFunc(decodeS7CommPlus)})

const (
	// S7CommPlusProtocolID is the first octet of every S7comm-plus frame
	// and of its trailer.
	S7CommPlusProtocolID uint8 = 0x72

	s7plusHeaderLen  = 4
	s7plusTrailerLen = 4

	// Data header sizes: opcode, reserved, function, reserved, sequence,
	// then session ID (requests only) and transport flags.
	s7plusRespHeadLen = 10
	s7plusReqHeadLen  = 14

	// VLQ: 7 value bits per octet, high bit set while more follow.
	vlqMore     = 0x80
	vlqValue    = 0x7F
	vlqSign     = 0x40
	vlqBits     = 7
	vlqMax32Len = 5
	// A 64-bit VLQ has eight 7-bit octets, then one full 8-bit octet.
	vlqMax64Septets = 8
	vlqLastOctetBit = 8
	// One's complement preload of a negative int32 VLQ: the first octet
	// holds 6 value bits below the sign bit.
	vlqNeg32Preload = 0xFFFFFFC0
	vlqNeg64Preload = 0xFFFFFFFFFFFFFFC0
)

var (
	// ErrS7CommPlusTooShort is returned when data is shorter than the
	// frame header or than the data length it announces.
	ErrS7CommPlusTooShort = errors.New("S7comm-plus frame truncated")
	// ErrS7CommPlusBadProtocol is returned when the first octet is not
	// 0x72.
	ErrS7CommPlusBadProtocol = errors.New("S7comm-plus protocol ID is not 0x72")
	// ErrS7CommPlusMalformed is returned when the integrity part
	// overruns the frame.
	ErrS7CommPlusMalformed = errors.New("S7comm-plus malformed frame")
	// ErrVLQTruncated is returned when a VLQ integer runs past its data.
	ErrVLQTruncated = errors.New("S7comm-plus VLQ truncated")
	// ErrVLQTooLong is returned when a 32-bit VLQ integer has more than
	// five octets.
	ErrVLQTooLong = errors.New("S7comm-plus VLQ too long")
)

// S7CommPlusVersion is the protocol version octet of the frame header.
type S7CommPlusVersion uint8

// S7comm-plus protocol versions.
const (
	S7CommPlusV1        S7CommPlusVersion = 0x01
	S7CommPlusV2        S7CommPlusVersion = 0x02
	S7CommPlusV3        S7CommPlusVersion = 0x03
	S7CommPlusKeepAlive S7CommPlusVersion = 0xFE // extended keep-alive
)

// String returns a human-readable name of the version.
func (v S7CommPlusVersion) String() string {
	switch v {
	case S7CommPlusV1:
		return "V1"
	case S7CommPlusV2:
		return "V2"
	case S7CommPlusV3:
		return "V3"
	case S7CommPlusKeepAlive:
		return "Extended Keep Alive"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(v))
	}
}

// valid reports whether v is a version this package knows.
func (v S7CommPlusVersion) valid() bool {
	switch v {
	case S7CommPlusV1, S7CommPlusV2, S7CommPlusV3, S7CommPlusKeepAlive:
		return true
	}
	return false
}

// S7CommPlusOpcode is the first octet of the data header.
type S7CommPlusOpcode uint8

// S7comm-plus opcodes.
const (
	S7CommPlusOpResponse2    S7CommPlusOpcode = 0x02
	S7CommPlusOpRequest      S7CommPlusOpcode = 0x31
	S7CommPlusOpResponse     S7CommPlusOpcode = 0x32
	S7CommPlusOpNotification S7CommPlusOpcode = 0x33
)

// String returns a human-readable name of the opcode.
func (o S7CommPlusOpcode) String() string {
	switch o {
	case S7CommPlusOpResponse2:
		return "Response2"
	case S7CommPlusOpRequest:
		return "Request"
	case S7CommPlusOpResponse:
		return "Response"
	case S7CommPlusOpNotification:
		return "Notification"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(o))
	}
}

// valid reports whether o is an opcode this package knows.
func (o S7CommPlusOpcode) valid() bool {
	switch o {
	case S7CommPlusOpResponse2, S7CommPlusOpRequest, S7CommPlusOpResponse, S7CommPlusOpNotification:
		return true
	}
	return false
}

// S7CommPlusFunction is the function code of a request or response.
type S7CommPlusFunction uint16

// S7comm-plus function codes.
const (
	S7CommPlusFuncError             S7CommPlusFunction = 0x04B1
	S7CommPlusFuncExplore           S7CommPlusFunction = 0x04BB
	S7CommPlusFuncCreateObject      S7CommPlusFunction = 0x04CA
	S7CommPlusFuncDeleteObject      S7CommPlusFunction = 0x04D4
	S7CommPlusFuncSetVariable       S7CommPlusFunction = 0x04F2
	S7CommPlusFuncGetVariable       S7CommPlusFunction = 0x04FC
	S7CommPlusFuncAddLink           S7CommPlusFunction = 0x0506
	S7CommPlusFuncRemoveLink        S7CommPlusFunction = 0x051A
	S7CommPlusFuncGetLink           S7CommPlusFunction = 0x0524
	S7CommPlusFuncSetMultiVariables S7CommPlusFunction = 0x0542
	S7CommPlusFuncGetMultiVariables S7CommPlusFunction = 0x054C
	S7CommPlusFuncBeginSequence     S7CommPlusFunction = 0x0556
	S7CommPlusFuncEndSequence       S7CommPlusFunction = 0x0560
	S7CommPlusFuncInvoke            S7CommPlusFunction = 0x056B
	S7CommPlusFuncSetVarSubStreamed S7CommPlusFunction = 0x057C
	S7CommPlusFuncGetVarSubStreamed S7CommPlusFunction = 0x0586
	S7CommPlusFuncGetVariablesAddr  S7CommPlusFunction = 0x0590
	S7CommPlusFuncAbort             S7CommPlusFunction = 0x059A
	S7CommPlusFuncError2            S7CommPlusFunction = 0x05A9
	S7CommPlusFuncInitSSL           S7CommPlusFunction = 0x05B3
)

// String returns the function name.
func (f S7CommPlusFunction) String() string {
	switch f {
	case S7CommPlusFuncError:
		return "Error"
	case S7CommPlusFuncExplore:
		return "Explore"
	case S7CommPlusFuncCreateObject:
		return "CreateObject"
	case S7CommPlusFuncDeleteObject:
		return "DeleteObject"
	case S7CommPlusFuncSetVariable:
		return "SetVariable"
	case S7CommPlusFuncGetVariable:
		return "GetVariable"
	case S7CommPlusFuncAddLink:
		return "AddLink"
	case S7CommPlusFuncRemoveLink:
		return "RemoveLink"
	case S7CommPlusFuncGetLink:
		return "GetLink"
	case S7CommPlusFuncSetMultiVariables:
		return "SetMultiVariables"
	case S7CommPlusFuncGetMultiVariables:
		return "GetMultiVariables"
	case S7CommPlusFuncBeginSequence:
		return "BeginSequence"
	case S7CommPlusFuncEndSequence:
		return "EndSequence"
	case S7CommPlusFuncInvoke:
		return "Invoke"
	case S7CommPlusFuncSetVarSubStreamed:
		return "SetVarSubStreamed"
	case S7CommPlusFuncGetVarSubStreamed:
		return "GetVarSubStreamed"
	case S7CommPlusFuncGetVariablesAddr:
		return "GetVariablesAddress"
	case S7CommPlusFuncAbort:
		return "Abort"
	case S7CommPlusFuncError2:
		return "Error2"
	case S7CommPlusFuncInitSSL:
		return "InitSsl"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", uint16(f))
	}
}

// S7CommPlus is one S7comm-plus frame. HasDataHeader tells whether the
// body started with a known opcode and the request or response header
// fields are set; Data holds the body after that header (or the whole
// body when HasDataHeader is false). Notifications keep their body raw
// in Data after Opcode.
type S7CommPlus struct {
	BaseLayer
	ProtocolID uint8
	Version    S7CommPlusVersion
	DataLength uint16
	Integrity  []byte // V3: digest after its length octet, opaque

	HasDataHeader  bool
	Opcode         S7CommPlusOpcode
	Reserved1      uint16
	Function       S7CommPlusFunction
	Reserved2      uint16
	Sequence       uint16
	SessionID      uint32 // requests only
	TransportFlags uint8
	Data           []byte

	HasTrailer     bool
	TrailerVersion S7CommPlusVersion
	TrailerLength  uint16
}

// LayerType returns LayerTypeS7CommPlus.
func (s *S7CommPlus) LayerType() gopacket.LayerType { return LayerTypeS7CommPlus }

// CanDecode returns LayerTypeS7CommPlus.
func (s *S7CommPlus) CanDecode() gopacket.LayerClass { return LayerTypeS7CommPlus }

// NextLayerType returns LayerTypePayload for octets after the frame,
// else LayerTypeZero.
func (s *S7CommPlus) NextLayerType() gopacket.LayerType {
	if len(s.Payload) > 0 {
		return gopacket.LayerTypePayload
	}
	return gopacket.LayerTypeZero
}

// isS7CommPlus reports whether b starts like an S7comm-plus frame.
func isS7CommPlus(b []byte) bool {
	if len(b) < s7plusHeaderLen || b[0] != S7CommPlusProtocolID {
		return false
	}
	return S7CommPlusVersion(b[1]).valid()
}

// DecodeFromBytes decodes an S7comm-plus frame from data.
func (s *S7CommPlus) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*s = S7CommPlus{}
	if len(data) < s7plusHeaderLen {
		df.SetTruncated()
		return ErrS7CommPlusTooShort
	}

	s.ProtocolID = data[0]
	s.Version = S7CommPlusVersion(data[1])
	s.DataLength = binary.BigEndian.Uint16(data[2:4])
	if s.ProtocolID != S7CommPlusProtocolID {
		return ErrS7CommPlusBadProtocol
	}
	end := s7plusHeaderLen + int(s.DataLength)
	if end > len(data) {
		df.SetTruncated()
		return ErrS7CommPlusTooShort
	}

	body := data[s7plusHeaderLen:end]
	rest := data[end:]
	if s.Version == S7CommPlusV3 {
		var err error
		if body, err = s.decodeIntegrity(body); err != nil {
			return err
		}
	}

	if s.Version != S7CommPlusKeepAlive {
		s.decodeDataHeader(body)
	} else {
		s.Data = body
	}

	if len(rest) >= s7plusTrailerLen && rest[0] == S7CommPlusProtocolID {
		s.HasTrailer = true
		s.TrailerVersion = S7CommPlusVersion(rest[1])
		s.TrailerLength = binary.BigEndian.Uint16(rest[2:4])
		end += s7plusTrailerLen
	}

	s.Contents = data[:end]
	s.Payload = data[end:]
	return nil
}

// decodeIntegrity splits the V3 integrity part (length octet, digest)
// off the body and returns what follows it.
func (s *S7CommPlus) decodeIntegrity(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	n := int(body[0])
	if 1+n > len(body) {
		return nil, fmt.Errorf("%w: integrity length %d in %d octets", ErrS7CommPlusMalformed, n, len(body))
	}
	s.Integrity = body[1 : 1+n]
	return body[1+n:], nil
}

// decodeDataHeader reads the request or response header when body
// starts with a known opcode; anything else (a continuation frame,
// or a header cut short) stays raw in Data.
func (s *S7CommPlus) decodeDataHeader(body []byte) {
	s.Data = body
	if len(body) == 0 {
		return
	}

	op := S7CommPlusOpcode(body[0])
	if !op.valid() {
		return
	}
	if op == S7CommPlusOpNotification {
		s.HasDataHeader = true
		s.Opcode = op
		s.Data = body[1:]
		return
	}

	headLen := s7plusRespHeadLen
	if op == S7CommPlusOpRequest {
		headLen = s7plusReqHeadLen
	}
	if len(body) < headLen {
		return
	}

	s.HasDataHeader = true
	s.Opcode = op
	s.Reserved1 = binary.BigEndian.Uint16(body[1:3])
	s.Function = S7CommPlusFunction(binary.BigEndian.Uint16(body[3:5]))
	s.Reserved2 = binary.BigEndian.Uint16(body[5:7])
	s.Sequence = binary.BigEndian.Uint16(body[7:9])
	if op == S7CommPlusOpRequest {
		s.SessionID = binary.BigEndian.Uint32(body[9:13])
	}
	s.TransportFlags = body[headLen-1]
	s.Data = body[headLen:]
}

// ReturnValue reads the VLQ return value most responses start their
// data with. It is a convenience: the item layout is function-specific
// and not validated here.
func (s *S7CommPlus) ReturnValue() (uint64, error) {
	v, _, err := S7CommPlusVarUint64(s.Data)
	return v, err
}

// S7CommPlusVarUint32 reads an unsigned VLQ integer of at most five
// octets from b and returns it with the octets consumed.
func S7CommPlusVarUint32(b []byte) (uint32, int, error) {
	var v uint32
	for i := 0; i < vlqMax32Len; i++ {
		if i >= len(b) {
			return 0, 0, ErrVLQTruncated
		}

		v = v<<vlqBits | uint32(b[i]&vlqValue)
		if b[i]&vlqMore == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, ErrVLQTooLong
}

// S7CommPlusVarInt32 reads a signed VLQ integer of at most five octets.
// Bit 6 of the first octet is the sign.
func S7CommPlusVarInt32(b []byte) (int32, int, error) {
	if len(b) == 0 {
		return 0, 0, ErrVLQTruncated
	}

	var v uint32
	if b[0]&vlqSign != 0 {
		v = vlqNeg32Preload
	}
	v |= uint32(b[0] & vlqValue &^ vlqSign)
	if b[0]&vlqMore == 0 {
		return int32(v), 1, nil
	}

	for i := 1; i < vlqMax32Len; i++ {
		if i >= len(b) {
			return 0, 0, ErrVLQTruncated
		}

		v = v<<vlqBits | uint32(b[i]&vlqValue)
		if b[i]&vlqMore == 0 {
			return int32(v), i + 1, nil
		}
	}
	return 0, 0, ErrVLQTooLong
}

// S7CommPlusVarUint64 reads an unsigned VLQ integer of at most nine
// octets: eight carry 7 value bits each, a ninth carries a full 8.
func S7CommPlusVarUint64(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < vlqMax64Septets; i++ {
		if i >= len(b) {
			return 0, 0, ErrVLQTruncated
		}

		v = v<<vlqBits | uint64(b[i]&vlqValue)
		if b[i]&vlqMore == 0 {
			return v, i + 1, nil
		}
	}

	if len(b) <= vlqMax64Septets {
		return 0, 0, ErrVLQTruncated
	}
	v = v<<vlqLastOctetBit | uint64(b[vlqMax64Septets])
	return v, vlqMax64Septets + 1, nil
}

// S7CommPlusVarInt64 reads a signed VLQ integer of at most nine octets.
// Bit 6 of the first octet is the sign.
func S7CommPlusVarInt64(b []byte) (int64, int, error) {
	if len(b) == 0 {
		return 0, 0, ErrVLQTruncated
	}

	var v uint64
	if b[0]&vlqSign != 0 {
		v = vlqNeg64Preload
	}
	v |= uint64(b[0] & vlqValue &^ vlqSign)
	if b[0]&vlqMore == 0 {
		return int64(v), 1, nil
	}

	for i := 1; i < vlqMax64Septets; i++ {
		if i >= len(b) {
			return 0, 0, ErrVLQTruncated
		}

		v = v<<vlqBits | uint64(b[i]&vlqValue)
		if b[i]&vlqMore == 0 {
			return int64(v), i + 1, nil
		}
	}

	if len(b) <= vlqMax64Septets {
		return 0, 0, ErrVLQTruncated
	}
	v = v<<vlqLastOctetBit | uint64(b[vlqMax64Septets])
	return int64(v), vlqMax64Septets + 1, nil
}

func decodeS7CommPlus(data []byte, p gopacket.PacketBuilder) error {
	s := &S7CommPlus{}
	if err := s.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(s)

	if len(s.Payload) == 0 {
		return nil
	}
	return p.NextDecoder(gopacket.LayerTypePayload)
}
