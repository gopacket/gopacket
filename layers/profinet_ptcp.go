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
// A TLV header is 2 bytes: Type (7 bits) and Length (9 bits). Several
// blocks pad their fields to a multiple of four bytes counted from the
// start of the PDU, so a block's layout depends on where it sits:
//
//	Subdomain       MasterSourceAddress (6), SubdomainUUID (16)
//	Time            EpochNumber (2), Seconds (4), NanoSeconds (4)
//	TimeExtension   Flags (2), CurrentUTCOffset (2), padding
//	Master          MasterPriority1 (1), MasterPriority2 (1), ClockClass (1),
//	                ClockAccuracy (1), ClockVariance (2), padding
//	PortParameter   padding, T2PortRxDelay (4), T3PortTxDelay (4)
//	DelayParameter  PortMACAddress (6), padding
//	PortTime        padding, T2TimeStamp (4)
//	Option          OUI (3), SubType (1), then for PROFINET RTData:
//	                padding, IRDataUUID (16)

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
	profinetPTCPAlign        = 4
	profinetPTCPMasterLen    = 6
	profinetPTCPTimeExtLen   = 4
	profinetPTCPPortParamLen = 8
	profinetPTCPPortTimeLen  = 4
	profinetPTCPOptionHead   = 4 // OUI and subtype
	profinetPTCPOUILen       = 3

	// MasterPriority1 layout: priority (bits 0-2), level (3-5), active (7).
	profinetPTCPPrioMask    = 0x07
	profinetPTCPLevelShift  = 3
	profinetPTCPActiveBit   = 0x80
	profinetPTCPSubtypeData = 1 // PROFINET option subtype RTData
)

// PROFINET OUIs that mark a PROFINET PTCP option.
const (
	profinetOUI          uint32 = 0x000ECF
	profinetOUIMulticast uint32 = 0x010ECF
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

// ProfinetPTCPPriority1 is the MasterPriority1 byte of a Master block.
type ProfinetPTCPPriority1 uint8

// Priority returns bits 0-2: 0 sync slave, 1 primary master, 2 secondary
// master.
func (p ProfinetPTCPPriority1) Priority() uint8 { return uint8(p) & profinetPTCPPrioMask }

// Level returns bits 3-5: 0 is the highest level, 7 the lowest.
func (p ProfinetPTCPPriority1) Level() uint8 {
	return uint8(p) >> profinetPTCPLevelShift & profinetPTCPPrioMask
}

// Active reports whether the master is active (bit 7).
func (p ProfinetPTCPPriority1) Active() bool { return p&profinetPTCPActiveBit != 0 }

// String names the priority as Wireshark does.
func (p ProfinetPTCPPriority1) String() string {
	switch p.Priority() {
	case 0:
		return "Sync slave"
	case 1:
		return "Primary master"
	case 2:
		return "Secondary master"
	}
	return fmt.Sprintf("(Reserved: 0x%x)", p.Priority())
}

// ProfinetPTCPClockAccuracy is the ClockAccuracy byte of a Master block.
type ProfinetPTCPClockAccuracy uint8

// profinetPTCPAccuracyFirst is the first named clock accuracy (25 ns).
const profinetPTCPAccuracyFirst ProfinetPTCPClockAccuracy = 0x20

// ProfinetPTCPAccuracyUnknown is the "unknown" clock accuracy.
const ProfinetPTCPAccuracyUnknown ProfinetPTCPClockAccuracy = 0xFE

// profinetPTCPAccuracies names the accuracies from 0x20 up.
var profinetPTCPAccuracies = [...]string{
	"25ns", "100ns (Default)", "250ns", "1us", "2.5us", "10us", "25us", "100us", "250us", "1ms",
}

// String returns the accuracy name used by Wireshark.
func (a ProfinetPTCPClockAccuracy) String() string {
	if a == ProfinetPTCPAccuracyUnknown {
		return "Unknown"
	}
	if i := int(a) - int(profinetPTCPAccuracyFirst); i >= 0 && i < len(profinetPTCPAccuracies) {
		return profinetPTCPAccuracies[i]
	}
	return fmt.Sprintf("(Reserved: 0x%x)", uint8(a))
}

// ProfinetPTCPTLV is one PTCP TLV block; Value aliases the packet data.
type ProfinetPTCPTLV struct {
	Type   ProfinetPTCPTLVType
	Length uint16
	Value  []byte
}

// ProfinetPTCP is a PROFINET PTCP PDU (RTSync, announce, follow up, delay).
//
// Every block is listed raw in TLVs and decoded into the fields below;
// TLVs tells which blocks the PDU carries. Padding after the End block is
// ignored.
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

	// TimeExtension block.
	Flags            uint16
	CurrentUTCOffset uint16

	// Master block.
	MasterPriority1 ProfinetPTCPPriority1
	MasterPriority2 uint8
	ClockClass      uint8
	ClockAccuracy   ProfinetPTCPClockAccuracy
	ClockVariance   int16

	// PortParameter block, in nanoseconds.
	T2PortRxDelay uint32
	T3PortTxDelay uint32

	// DelayParameter block.
	PortMACAddress net.HardwareAddr

	// PortTime block, in nanoseconds.
	T2TimeStamp uint32

	// Organizationally specific block. OptionData is what follows the
	// subtype; IRDataUUID is set for the PROFINET RTData option.
	OUI           uint32
	OptionSubType uint8
	OptionData    []byte
	IRDataUUID    ProfinetUUID
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
		t.decodeTLV(tlv, start)
		off = end

		if tlv.Type == ProfinetPTCPTLVEnd {
			break
		}
	}

	t.BaseLayer = BaseLayer{Contents: data[:off]}
	return nil
}

// ptcpPad returns the padding needed at off, an offset from the start of
// the PDU, to reach the next multiple of four.
func ptcpPad(off int) int {
	return (profinetPTCPAlign - off%profinetPTCPAlign) % profinetPTCPAlign
}

// decodeTLV fills the typed fields of the blocks we know. start is the
// offset of the value in the PDU, which fixes the padding. A value too
// short for its fields stays raw in TLVs.
func (t *ProfinetPTCP) decodeTLV(tlv ProfinetPTCPTLV, start int) {
	v := tlv.Value
	pad := ptcpPad(start)

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
	case ProfinetPTCPTLVTimeExtension:
		if len(v) < profinetPTCPTimeExtLen {
			return
		}
		t.Flags = binary.BigEndian.Uint16(v)
		t.CurrentUTCOffset = binary.BigEndian.Uint16(v[2:])
	case ProfinetPTCPTLVMaster:
		if len(v) < profinetPTCPMasterLen {
			return
		}
		t.MasterPriority1 = ProfinetPTCPPriority1(v[0])
		t.MasterPriority2 = v[1]
		t.ClockClass = v[2]
		t.ClockAccuracy = ProfinetPTCPClockAccuracy(v[3])
		t.ClockVariance = int16(binary.BigEndian.Uint16(v[4:]))
	case ProfinetPTCPTLVPortParameter:
		if len(v) < pad+profinetPTCPPortParamLen {
			return
		}
		t.T2PortRxDelay = binary.BigEndian.Uint32(v[pad:])
		t.T3PortTxDelay = binary.BigEndian.Uint32(v[pad+4:])
	case ProfinetPTCPTLVDelayParameter:
		if len(v) < 6 {
			return
		}
		t.PortMACAddress = net.HardwareAddr(v[:6])
	case ProfinetPTCPTLVPortTime:
		if len(v) < pad+profinetPTCPPortTimeLen {
			return
		}
		t.T2TimeStamp = binary.BigEndian.Uint32(v[pad:])
	case ProfinetPTCPTLVOrgSpecific:
		t.decodeOption(v, start)
	}
}

// decodeOption reads an organizationally specific block: a 3-byte OUI and
// a subtype, then data only the organization defines.
func (t *ProfinetPTCP) decodeOption(v []byte, start int) {
	if len(v) < profinetPTCPOptionHead {
		return
	}

	t.OUI = uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2])
	t.OptionSubType = v[profinetPTCPOUILen]
	t.OptionData = v[profinetPTCPOptionHead:]

	// PROFINET RTData: padding, then the IRDataUUID.
	if t.OUI != profinetOUI && t.OUI != profinetOUIMulticast {
		return
	}
	if t.OptionSubType != profinetPTCPSubtypeData {
		return
	}

	off := profinetPTCPOptionHead + ptcpPad(start+profinetPTCPOptionHead)
	if len(v) < off+profinetPTCPUUIDLen {
		return
	}
	copy(t.IRDataUUID[:], v[off:])
}

func decodeProfinetPTCP(data []byte, p gopacket.PacketBuilder) error {
	t := &ProfinetPTCP{}
	if err := t.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(t)
	return nil
}
