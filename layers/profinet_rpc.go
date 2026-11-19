// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO connection management (PNIO-CM) support.
//
// Connect, Release, Read, Write and Control run over connectionless
// DCE/RPC on UDP port 34964 (IEC 61158-6-10, DCE 1.1 RPC chapter 12,
// Wireshark packet-dcerpc.c and packet-dcerpc-pn-io.c):
//
//	+----------------+-----------------+--------------+
//	| DCE/RPC header | PNIO NDR header | Blocks       |
//	| 80             | 20              | n            |
//	+----------------+-----------------+--------------+
//
// DCE/RPC header (multi-byte fields in the sender's byte order, given by
// the first DataRep byte: 0x10 is little-endian):
//
//	0   Version (1) = 4      24  InterfaceUUID (16)    70  InterfaceHint (2)
//	1   PacketType (1)       40  ActivityUUID (16)     72  ActivityHint (2)
//	2   Flags1 (1)           56  ServerBootTime (4)    74  FragmentLength (2)
//	3   Flags2 (1)           60  InterfaceVersion (4)  76  FragmentNumber (2)
//	4   DataRep (3)          64  SequenceNumber (4)    78  AuthProto (1)
//	7   SerialHigh (1)       68  Opnum (2)             79  SerialLow (1)
//	8   ObjectUUID (16)
//
// PNIO NDR header, in the same byte order. A request opens with
// ArgsMaximum, a response with the PNIO status:
//
//	ArgsMaximum | PNIOStatus (4), ArgsLength (4),
//	MaximumCount (4), Offset (4), ActualCount (4)
//
// The blocks that follow are always big-endian; see profinet_block.go.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// UDPPortProfinetIO is the UDP port of the PROFINET IO RPC endpoint mapper
// and, on most devices, of the PNIO-CM server itself.
const UDPPortProfinetIO UDPPort = 34964

const (
	profinetRPCHeaderLen = 80
	profinetNDRHeaderLen = 20
	profinetRPCVersion   = 4

	// profinetRPCLittleEndian is the integer byte order nibble of the
	// first DataRep byte.
	profinetRPCLittleEndian = 0x10
	profinetRPCOrderMask    = 0xF0

	// Offsets in the DCE/RPC header.
	profinetRPCObjectOff   = 8
	profinetRPCIfaceOff    = 24
	profinetRPCActivityOff = 40
	profinetRPCBootOff     = 56
	profinetRPCIfVersOff   = 60
	profinetRPCSeqOff      = 64
	profinetRPCOpnumOff    = 68
	profinetRPCIHintOff    = 70
	profinetRPCAHintOff    = 72
	profinetRPCFragLenOff  = 74
	profinetRPCFragNumOff  = 76
	profinetRPCAuthOff     = 78
	profinetRPCSerialLoOff = 79

	profinetRPCFaultLen = 4
)

var (
	// ErrProfinetRPCTooShort is returned when the DCE/RPC header is
	// truncated.
	ErrProfinetRPCTooShort = errors.New("PROFINET IO RPC header too short")
	// ErrProfinetRPCVersion is returned when the data is not a
	// connectionless DCE/RPC version 4 PDU.
	ErrProfinetRPCVersion = errors.New("PROFINET IO RPC: not DCE/RPC version 4")
)

// ProfinetRPCPacketType is the DCE/RPC packet type.
type ProfinetRPCPacketType uint8

// Connectionless DCE/RPC packet types.
const (
	ProfinetRPCRequest   ProfinetRPCPacketType = 0
	ProfinetRPCPing      ProfinetRPCPacketType = 1
	ProfinetRPCResponse  ProfinetRPCPacketType = 2
	ProfinetRPCFault     ProfinetRPCPacketType = 3
	ProfinetRPCWorking   ProfinetRPCPacketType = 4
	ProfinetRPCNoCall    ProfinetRPCPacketType = 5
	ProfinetRPCReject    ProfinetRPCPacketType = 6
	ProfinetRPCAck       ProfinetRPCPacketType = 7
	ProfinetRPCCancel    ProfinetRPCPacketType = 8
	ProfinetRPCFack      ProfinetRPCPacketType = 9
	ProfinetRPCCancelAck ProfinetRPCPacketType = 10
)

// String returns the packet type name.
func (t ProfinetRPCPacketType) String() string {
	names := [...]string{"Request", "Ping", "Response", "Fault", "Working", "Nocall", "Reject", "Ack", "Cl_cancel", "Fack", "Cancel_ack"}
	if int(t) < len(names) {
		return names[t]
	}
	return fmt.Sprintf("Unknown(%d)", uint8(t))
}

// DCE/RPC Flags1 bits.
const (
	ProfinetRPCFlagLastFragment uint8 = 0x02
	ProfinetRPCFlagFragment     uint8 = 0x04
	ProfinetRPCFlagNoFack       uint8 = 0x08
	ProfinetRPCFlagMaybe        uint8 = 0x10
	ProfinetRPCFlagIdempotent   uint8 = 0x20
	ProfinetRPCFlagBroadcast    uint8 = 0x40
)

// ProfinetRPCOpnum is the PNIO-CM operation.
type ProfinetRPCOpnum uint16

// PNIO-CM operations.
const (
	ProfinetRPCConnect      ProfinetRPCOpnum = 0
	ProfinetRPCRelease      ProfinetRPCOpnum = 1
	ProfinetRPCRead         ProfinetRPCOpnum = 2
	ProfinetRPCWrite        ProfinetRPCOpnum = 3
	ProfinetRPCControl      ProfinetRPCOpnum = 4
	ProfinetRPCReadImplicit ProfinetRPCOpnum = 5
)

// String returns the operation name.
func (o ProfinetRPCOpnum) String() string {
	names := [...]string{"Connect", "Release", "Read", "Write", "Control", "Read Implicit"}
	if int(o) < len(names) {
		return names[o]
	}
	return fmt.Sprintf("Unknown(%d)", uint16(o))
}

// ProfinetRPCInterface says which PNIO interface an RPC addresses.
type ProfinetRPCInterface uint8

// PNIO interfaces. Their UUIDs are DEA0000x-6C97-11D1-8271-00A02442DF7D
// with x from 1 to 4.
const (
	ProfinetRPCInterfaceOther ProfinetRPCInterface = iota // not PNIO, e.g. the endpoint mapper
	ProfinetRPCInterfaceDevice
	ProfinetRPCInterfaceController
	ProfinetRPCInterfaceSupervisor
	ProfinetRPCInterfaceParameterServer
)

// String returns the interface name.
func (i ProfinetRPCInterface) String() string {
	switch i {
	case ProfinetRPCInterfaceOther:
		return "Other"
	case ProfinetRPCInterfaceDevice:
		return "Device"
	case ProfinetRPCInterfaceController:
		return "Controller"
	case ProfinetRPCInterfaceSupervisor:
		return "Supervisor"
	case ProfinetRPCInterfaceParameterServer:
		return "Parameter Server"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(i))
}

// profinetRPCInterfaceUUID is the device interface UUID; byte 3 selects
// the interface (1 device .. 4 parameter server).
var profinetRPCInterfaceUUID = ProfinetUUID{
	0xDE, 0xA0, 0x00, 0x01, 0x6C, 0x97, 0x11, 0xD1, 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D,
}

// profinetRPCInterfaceByte is the UUID byte that numbers the interface.
const profinetRPCInterfaceByte = 3

// ProfinetIORPC is a PROFINET IO RPC PDU: the connectionless DCE/RPC
// header and, for PNIO requests and responses, the NDR header and the
// block list.
//
// The body is decoded when the PDU is an unfragmented request or response
// on a PNIO interface; HasNDR tells. Everything else leaves the body after
// the DCE/RPC header as the payload: other interfaces (the endpoint
// mapper), other packet types and fragments, which are not reassembled.
//
// UUIDs are stored in canonical order whatever the sender's byte order.
type ProfinetIORPC struct {
	BaseLayer

	// DCE/RPC header.
	PacketType       ProfinetRPCPacketType
	Flags1           uint8
	Flags2           uint8
	DataRep          [3]byte
	SerialHigh       uint8
	ObjectUUID       ProfinetUUID
	InterfaceUUID    ProfinetUUID
	ActivityUUID     ProfinetUUID
	ServerBootTime   uint32
	InterfaceVersion uint32
	SequenceNumber   uint32
	Opnum            ProfinetRPCOpnum
	InterfaceHint    uint16
	ActivityHint     uint16
	FragmentLength   uint16
	FragmentNumber   uint16
	AuthProto        uint8
	SerialLow        uint8

	// FaultStatus is the status of a Fault or Reject PDU.
	FaultStatus uint32

	// PNIO NDR header. ArgsMaximum exists in requests, Status in
	// responses.
	HasNDR       bool
	ArgsMaximum  uint32
	Status       ProfinetPNIOStatus
	ArgsLength   uint32
	MaximumCount uint32
	Offset       uint32
	ActualCount  uint32

	Blocks []ProfinetBlock
}

// LayerType returns LayerTypeProfinetIORPC.
func (r *ProfinetIORPC) LayerType() gopacket.LayerType { return LayerTypeProfinetIORPC }

// CanDecode returns LayerTypeProfinetIORPC.
func (r *ProfinetIORPC) CanDecode() gopacket.LayerClass { return LayerTypeProfinetIORPC }

// NextLayerType returns LayerTypePayload for a body left undecoded.
func (r *ProfinetIORPC) NextLayerType() gopacket.LayerType {
	if len(r.BaseLayer.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	return gopacket.LayerTypePayload
}

// LittleEndian reports whether the sender's integers are little-endian.
func (r *ProfinetIORPC) LittleEndian() bool {
	return r.DataRep[0]&profinetRPCOrderMask == profinetRPCLittleEndian
}

// Interface classifies the interface UUID.
func (r *ProfinetIORPC) Interface() ProfinetRPCInterface {
	u := r.InterfaceUUID
	n := u[profinetRPCInterfaceByte]
	u[profinetRPCInterfaceByte] = profinetRPCInterfaceUUID[profinetRPCInterfaceByte]

	if u != profinetRPCInterfaceUUID || n < uint8(ProfinetRPCInterfaceDevice) || n > uint8(ProfinetRPCInterfaceParameterServer) {
		return ProfinetRPCInterfaceOther
	}
	return ProfinetRPCInterface(n)
}

// Fragmented reports whether the PDU is one fragment of a larger one.
func (r *ProfinetIORPC) Fragmented() bool {
	return r.Flags1&ProfinetRPCFlagFragment != 0 || r.FragmentNumber != 0
}

// order returns the sender's byte order.
func (r *ProfinetIORPC) order() binary.ByteOrder {
	if r.LittleEndian() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// rpcUUID reads a DCE UUID. Its first three fields are integers in the
// sender's byte order; the last eight bytes are plain.
func rpcUUID(b []byte, order binary.ByteOrder) (u ProfinetUUID) {
	binary.BigEndian.PutUint32(u[0:], order.Uint32(b[0:]))
	binary.BigEndian.PutUint16(u[4:], order.Uint16(b[4:]))
	binary.BigEndian.PutUint16(u[6:], order.Uint16(b[6:]))
	copy(u[8:], b[8:profinetUUIDLen])
	return u
}

// DecodeFromBytes decodes a PROFINET IO RPC PDU, starting at the DCE/RPC
// version byte.
func (r *ProfinetIORPC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < profinetRPCHeaderLen {
		df.SetTruncated()
		return ErrProfinetRPCTooShort
	}
	if data[0] != profinetRPCVersion {
		return ErrProfinetRPCVersion
	}

	*r = ProfinetIORPC{Blocks: r.Blocks[:0]}
	r.PacketType = ProfinetRPCPacketType(data[1])
	r.Flags1 = data[2]
	r.Flags2 = data[3]
	copy(r.DataRep[:], data[4:7])
	r.SerialHigh = data[7]

	order := r.order()
	r.ObjectUUID = rpcUUID(data[profinetRPCObjectOff:], order)
	r.InterfaceUUID = rpcUUID(data[profinetRPCIfaceOff:], order)
	r.ActivityUUID = rpcUUID(data[profinetRPCActivityOff:], order)
	r.ServerBootTime = order.Uint32(data[profinetRPCBootOff:])
	r.InterfaceVersion = order.Uint32(data[profinetRPCIfVersOff:])
	r.SequenceNumber = order.Uint32(data[profinetRPCSeqOff:])
	r.Opnum = ProfinetRPCOpnum(order.Uint16(data[profinetRPCOpnumOff:]))
	r.InterfaceHint = order.Uint16(data[profinetRPCIHintOff:])
	r.ActivityHint = order.Uint16(data[profinetRPCAHintOff:])
	r.FragmentLength = order.Uint16(data[profinetRPCFragLenOff:])
	r.FragmentNumber = order.Uint16(data[profinetRPCFragNumOff:])
	r.AuthProto = data[profinetRPCAuthOff]
	r.SerialLow = data[profinetRPCSerialLoOff]

	// The body ends at FragmentLength; an authentication trailer or
	// padding may follow it.
	end := profinetRPCHeaderLen + int(r.FragmentLength)
	if end > len(data) {
		df.SetTruncated()
		end = len(data)
	}
	body := data[profinetRPCHeaderLen:end]
	r.BaseLayer = BaseLayer{Contents: data[:profinetRPCHeaderLen], Payload: body}

	switch r.PacketType {
	case ProfinetRPCFault, ProfinetRPCReject:
		if len(body) >= profinetRPCFaultLen {
			r.FaultStatus = order.Uint32(body)
		}
		return nil
	case ProfinetRPCRequest, ProfinetRPCResponse:
	default:
		return nil
	}

	if r.Fragmented() || r.Interface() == ProfinetRPCInterfaceOther {
		return nil
	}
	return r.decodeBody(body, df)
}

// decodeBody reads the NDR header and the blocks. Once the NDR header is
// in, the whole body counts as decoded and there is no payload.
func (r *ProfinetIORPC) decodeBody(body []byte, df gopacket.DecodeFeedback) error {
	if len(body) < profinetNDRHeaderLen {
		// Too short for PNIO: leave it as payload.
		return nil
	}

	order := r.order()
	if r.PacketType == ProfinetRPCRequest {
		r.ArgsMaximum = order.Uint32(body)
	} else {
		r.Status = rpcStatus(body, r.LittleEndian())
	}
	r.ArgsLength = order.Uint32(body[4:])
	r.MaximumCount = order.Uint32(body[8:])
	r.Offset = order.Uint32(body[12:])
	r.ActualCount = order.Uint32(body[16:])
	r.HasNDR = true

	r.BaseLayer.Contents = r.BaseLayer.Contents[:profinetRPCHeaderLen+len(body)]
	r.BaseLayer.Payload = nil

	blocks, err := appendProfinetBlocks(r.Blocks, body[profinetNDRHeaderLen:], profinetBlockTop)
	r.Blocks = blocks
	if err != nil {
		return err
	}

	for i := range r.Blocks {
		if r.Blocks[i].Clipped() {
			df.SetTruncated()
		}
	}
	return nil
}

// rpcStatus reads the PNIO status of a response. It travels as one NDR
// integer, so a little-endian sender puts ErrorCode last.
func rpcStatus(b []byte, littleEndian bool) ProfinetPNIOStatus {
	if littleEndian {
		return ProfinetPNIOStatus{ProfinetErrorCode(b[3]), ProfinetErrorDecode(b[2]), b[1], b[0]}
	}
	return ProfinetPNIOStatus{ProfinetErrorCode(b[0]), ProfinetErrorDecode(b[1]), b[2], b[3]}
}

func decodeProfinetIORPC(data []byte, p gopacket.PacketBuilder) error {
	r := &ProfinetIORPC{}
	err := r.DecodeFromBytes(data, p)

	// A bad block comes after a good header: keep the layer, then report.
	if err != nil && !r.HasNDR {
		return err
	}

	p.AddLayer(r)
	p.SetApplicationLayer(r)
	if err != nil {
		return err
	}

	next := r.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}

// Payload returns the body left undecoded; it makes the layer an
// application layer.
func (r *ProfinetIORPC) Payload() []byte { return r.BaseLayer.Payload }
