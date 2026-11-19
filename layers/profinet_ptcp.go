// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET PTCP (Precision Transparent Clock Protocol) support.
//
// Every PTCP PDU has a 20-byte header after the Frame ID, followed by TLV
// blocks up to an End block (IEC 61158-6-10, Wireshark packet-pn-ptcp.c):
//
//	offset  RTSync (0x0020-0x0081)   Announce/FollowUp/Delay (0xFFxx)
//	0       Reserved_1 (4)           Padding (12)
//	4       Reserved_2 (4)
//	8       Delay10ns (4)
//	12      SequenceID (2)           SequenceID (2)
//	14      Delay1ns (1), pad (1)    Padding (2)
//	16      Delay1ns (4)             Delay1ns / Delay1ns_FUP (4), or padding
//
// Both layouts put the sequence ID and the 4-byte delay at the same
// offsets and the RTSync-only fields over padding, so one decoder serves
// all PTCP frames without the Frame ID.
//
// A TLV header is 2 bytes: Type (7 bits) and Length (9 bits).

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
)

const (
	profinetPTCPHeaderLen    = 20
	profinetPTCPTLVHeaderLen = 2
	profinetPTCPTypeShift    = 9
	profinetPTCPLengthMask   = 0x01FF
	profinetPTCPUUIDLen      = 16
	profinetPTCPTimeLen      = 10
	profinetNsPer10ns        = 10
)

var (
	// ErrProfinetPTCPTooShort is returned when a PTCP header is truncated.
	ErrProfinetPTCPTooShort = errors.New("PROFINET PTCP header too short")
	// ErrProfinetPTCPTLV is returned when a PTCP TLV runs past the data.
	ErrProfinetPTCPTLV = errors.New("PROFINET PTCP TLV exceeds data")
)

// ProfinetPTCPTLVType is a PTCP TLV block type.
type ProfinetPTCPTLVType uint8

// PTCP TLV types.
const (
	ProfinetPTCPTLVEnd            ProfinetPTCPTLVType = 0x00
	ProfinetPTCPTLVSubdomain      ProfinetPTCPTLVType = 0x01
	ProfinetPTCPTLVTime           ProfinetPTCPTLVType = 0x02
	ProfinetPTCPTLVTimeExtension  ProfinetPTCPTLVType = 0x03
	ProfinetPTCPTLVMaster         ProfinetPTCPTLVType = 0x04
	ProfinetPTCPTLVPortParameter  ProfinetPTCPTLVType = 0x05
	ProfinetPTCPTLVDelayParameter ProfinetPTCPTLVType = 0x06
	ProfinetPTCPTLVPortTime       ProfinetPTCPTLVType = 0x07
	ProfinetPTCPTLVOrgSpecific    ProfinetPTCPTLVType = 0x7F
)

// String returns the TLV type name.
func (t ProfinetPTCPTLVType) String() string {
	switch t {
	case ProfinetPTCPTLVEnd:
		return "End"
	case ProfinetPTCPTLVSubdomain:
		return "Subdomain"
	case ProfinetPTCPTLVTime:
		return "Time"
	case ProfinetPTCPTLVTimeExtension:
		return "TimeExtension"
	case ProfinetPTCPTLVMaster:
		return "Master"
	case ProfinetPTCPTLVPortParameter:
		return "PortParameter"
	case ProfinetPTCPTLVDelayParameter:
		return "DelayParameter"
	case ProfinetPTCPTLVPortTime:
		return "PortTime"
	case ProfinetPTCPTLVOrgSpecific:
		return "Organizationally Specific"
	}
	return fmt.Sprintf("Reserved(0x%02x)", uint8(t))
}

// ProfinetPTCPTLV is one PTCP TLV block; Value aliases the packet data.
type ProfinetPTCPTLV struct {
	Type   ProfinetPTCPTLVType
	Length uint16
	Value  []byte
}

// ProfinetPTCP is a PROFINET PTCP PDU (RTSync, announce, follow up, delay).
//
// The Subdomain and Time blocks are decoded into fields; all blocks are
// also listed raw in TLVs. Padding after the End block is ignored.
type ProfinetPTCP struct {
	BaseLayer

	Delay10ns   uint32 // RTSync only
	SequenceID  uint16
	Delay1nsLow uint8 // RTSync only
	Delay1ns    int32 // Integer32 Delay1ns_FUP in follow up PDUs
	TLVs        []ProfinetPTCPTLV

	// Subdomain block.
	MasterSourceAddress net.HardwareAddr
	SubdomainUUID       []byte

	// Time block.
	EpochNumber uint16
	Seconds     uint32
	NanoSeconds uint32
}

// LayerType returns LayerTypeProfinetPTCP.
func (t *ProfinetPTCP) LayerType() gopacket.LayerType { return LayerTypeProfinetPTCP }

// CanDecode returns LayerTypeProfinetPTCP.
func (t *ProfinetPTCP) CanDecode() gopacket.LayerClass { return LayerTypeProfinetPTCP }

// NextLayerType returns LayerTypeZero: PTCP carries no further layer.
func (t *ProfinetPTCP) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// DelayNs returns the delay in nanoseconds as Wireshark computes it:
// Delay10ns*10 + Delay1ns(byte) + Delay1ns. A follow up's Delay1ns_FUP
// is signed, so the result can be negative.
func (t *ProfinetPTCP) DelayNs() int64 {
	return int64(t.Delay10ns)*profinetNsPer10ns + int64(t.Delay1nsLow) + int64(t.Delay1ns)
}

// DecodeFromBytes decodes a PTCP PDU, starting after the Frame ID.
func (t *ProfinetPTCP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < profinetPTCPHeaderLen {
		df.SetTruncated()
		return ErrProfinetPTCPTooShort
	}

	*t = ProfinetPTCP{TLVs: t.TLVs[:0]}
	t.Delay10ns = binary.BigEndian.Uint32(data[8:12])
	t.SequenceID = binary.BigEndian.Uint16(data[12:14])
	t.Delay1nsLow = data[14]
	t.Delay1ns = int32(binary.BigEndian.Uint32(data[16:20]))

	// TLVs until End. Each consumes at least its 2-byte header.
	off := profinetPTCPHeaderLen
	for off < len(data) {
		if off+profinetPTCPTLVHeaderLen > len(data) {
			df.SetTruncated()
			return ErrProfinetPTCPTLV
		}

		tl := binary.BigEndian.Uint16(data[off:])
		tlv := ProfinetPTCPTLV{
			Type:   ProfinetPTCPTLVType(tl >> profinetPTCPTypeShift),
			Length: tl & profinetPTCPLengthMask,
		}
		start := off + profinetPTCPTLVHeaderLen
		end := start + int(tlv.Length)
		if end > len(data) {
			df.SetTruncated()
			return ErrProfinetPTCPTLV
		}

		tlv.Value = data[start:end]
		t.TLVs = append(t.TLVs, tlv)
		t.decodeTLV(tlv)
		off = end

		if tlv.Type == ProfinetPTCPTLVEnd {
			break
		}
	}

	t.BaseLayer = BaseLayer{Contents: data[:off]}
	return nil
}

// decodeTLV fills the typed fields of the blocks we know.
func (t *ProfinetPTCP) decodeTLV(tlv ProfinetPTCPTLV) {
	v := tlv.Value
	switch tlv.Type {
	case ProfinetPTCPTLVSubdomain:
		if len(v) < 6+profinetPTCPUUIDLen {
			return
		}
		t.MasterSourceAddress = net.HardwareAddr(v[:6])
		t.SubdomainUUID = v[6 : 6+profinetPTCPUUIDLen]
	case ProfinetPTCPTLVTime:
		if len(v) < profinetPTCPTimeLen {
			return
		}
		t.EpochNumber = binary.BigEndian.Uint16(v)
		t.Seconds = binary.BigEndian.Uint32(v[2:])
		t.NanoSeconds = binary.BigEndian.Uint32(v[6:])
	}
}

func decodeProfinetPTCP(data []byte, p gopacket.PacketBuilder) error {
	t := &ProfinetPTCP{}
	if err := t.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(t)
	return nil
}
