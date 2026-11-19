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
// The payload is the VarPart: alarm notification or acknowledge blocks for
// DATA-RTA, the PNIO status for ERR-RTA. Ethernet padding past VarPartLen
// is dropped. For ERR-RTA the PNIO status is also decoded below.
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
