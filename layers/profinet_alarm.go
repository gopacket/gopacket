// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO alarm (RTA, acyclic real-time) support.
//
// Alarm frames (Frame ID 0xFC01 high, 0xFE01 low priority) carry an
// RTA-PDU (IEC 61158-6-10, Wireshark packet-dcerpc-pn-io.c
// dissect_PNIO_RTA):
//
//	+--------+--------+---------+----------+---------+--------+------------+---------+
//	| DstEP  | SrcEP  | PDUType | AddFlags | SendSeq | AckSeq | VarPartLen | VarPart |
//	| 2      | 2      | 1       | 1        | 2       | 2      | 2          | n       |
//	+--------+--------+---------+----------+---------+--------+------------+---------+
//
// PDUType holds the type in its low nibble and the version in its high
// nibble; AddFlags holds WindowSize (low nibble) and TACK (high nibble).
//
// The VarPart of a DATA-RTA is one block (see profinet_block.go): an alarm
// notification or an alarm acknowledge. ERR-RTA carries a PNIO status.
//
// Frame IDs 0xFC41 and 0xFE41 are the same PDU behind a SecurityMetaData
// header, which the Profinet layer decodes and strips.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

const (
	profinetAlarmHeaderLen = 12
	profinetPNIOStatusLen  = 4
	profinetNibbleMask     = 0x0F
	profinetNibbleShift    = 4
)

// ErrProfinetAlarmTooShort is returned when an RTA-PDU header is truncated.
var ErrProfinetAlarmTooShort = errors.New("PROFINET alarm header too short")

// ProfinetAlarmPDUType is the RTA-PDU type.
type ProfinetAlarmPDUType uint8

// RTA-PDU types.
const (
	ProfinetAlarmData ProfinetAlarmPDUType = 0x01
	ProfinetAlarmNACK ProfinetAlarmPDUType = 0x02
	ProfinetAlarmACK  ProfinetAlarmPDUType = 0x03
	ProfinetAlarmERR  ProfinetAlarmPDUType = 0x04
)

// String returns the PDU type name.
func (t ProfinetAlarmPDUType) String() string {
	switch t {
	case ProfinetAlarmData:
		return "DATA-RTA"
	case ProfinetAlarmNACK:
		return "NACK-RTA"
	case ProfinetAlarmACK:
		return "ACK-RTA"
	case ProfinetAlarmERR:
		return "ERR-RTA"
	}
	return fmt.Sprintf("Unknown(0x%x)", uint8(t))
}

// ProfinetAlarm is a PROFINET IO RTA-PDU.
//
// The payload is the raw VarPart; Ethernet padding past VarPartLen is
// dropped. It is also decoded: the block of a DATA-RTA into Block, the
// PNIO status of an ERR-RTA into the four error fields.
type ProfinetAlarm struct {
	BaseLayer

	DstEndpoint   uint16
	SrcEndpoint   uint16
	PDUType       ProfinetAlarmPDUType
	Version       uint8
	WindowSize    uint8
	TACK          uint8
	SendSeqNum    uint16
	AckSeqNum     uint16
	VarPartLength uint16

	// ERR-RTA PNIO status.
	ErrorCode   uint8
	ErrorDecode uint8
	ErrorCode1  uint8
	ErrorCode2  uint8

	// Block is the DATA-RTA block, with Block.Alarm or Block.AlarmAck set
	// for the alarm block types. It is nil for other PDU types and when
	// the VarPart holds no whole block header.
	Block *ProfinetBlock
}

// Status returns the ERR-RTA PNIO status as one value.
func (a *ProfinetAlarm) Status() ProfinetPNIOStatus {
	return ProfinetPNIOStatus{
		ErrorCode:   ProfinetErrorCode(a.ErrorCode),
		ErrorDecode: ProfinetErrorDecode(a.ErrorDecode),
		ErrorCode1:  a.ErrorCode1,
		ErrorCode2:  a.ErrorCode2,
	}
}

// LayerType returns LayerTypeProfinetAlarm.
func (a *ProfinetAlarm) LayerType() gopacket.LayerType { return LayerTypeProfinetAlarm }

// CanDecode returns LayerTypeProfinetAlarm.
func (a *ProfinetAlarm) CanDecode() gopacket.LayerClass { return LayerTypeProfinetAlarm }

// NextLayerType returns LayerTypePayload when there is a VarPart.
func (a *ProfinetAlarm) NextLayerType() gopacket.LayerType {
	if len(a.BaseLayer.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes an RTA-PDU, starting at the destination endpoint.
func (a *ProfinetAlarm) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < profinetAlarmHeaderLen {
		df.SetTruncated()
		return ErrProfinetAlarmTooShort
	}

	a.DstEndpoint = binary.BigEndian.Uint16(data[0:2])
	a.SrcEndpoint = binary.BigEndian.Uint16(data[2:4])
	a.PDUType = ProfinetAlarmPDUType(data[4] & profinetNibbleMask)
	a.Version = data[4] >> profinetNibbleShift
	a.WindowSize = data[5] & profinetNibbleMask
	a.TACK = data[5] >> profinetNibbleShift
	a.SendSeqNum = binary.BigEndian.Uint16(data[6:8])
	a.AckSeqNum = binary.BigEndian.Uint16(data[8:10])
	a.VarPartLength = binary.BigEndian.Uint16(data[10:12])
	a.ErrorCode, a.ErrorDecode, a.ErrorCode1, a.ErrorCode2 = 0, 0, 0, 0
	a.Block = nil

	// The VarPart ends at VarPartLen; anything after it is padding.
	end := profinetAlarmHeaderLen + int(a.VarPartLength)
	if end > len(data) {
		df.SetTruncated()
		end = len(data)
	}
	a.BaseLayer = BaseLayer{Contents: data[:profinetAlarmHeaderLen], Payload: data[profinetAlarmHeaderLen:end]}

	// ERR-RTA carries a PNIO status: ErrorCode, ErrorDecode, ErrorCode1, ErrorCode2.
	status := a.BaseLayer.Payload
	if a.PDUType == ProfinetAlarmERR && len(status) >= profinetPNIOStatusLen {
		a.ErrorCode, a.ErrorDecode, a.ErrorCode1, a.ErrorCode2 = status[0], status[1], status[2], status[3]
	}

	// DATA-RTA carries one block. A VarPart too short or too odd for a
	// block header stays raw in the payload.
	if a.PDUType != ProfinetAlarmData {
		return nil
	}

	b, _, err := decodeProfinetBlock(a.BaseLayer.Payload, profinetBlockTop)
	if err != nil {
		return nil
	}

	if b.Clipped() {
		df.SetTruncated()
	}
	a.Block = &b
	return nil
}

func decodeProfinetAlarm(data []byte, p gopacket.PacketBuilder) error {
	a := &ProfinetAlarm{}
	if err := a.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(a)
	next := a.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}
