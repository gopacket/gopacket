// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET real-time (PN-RT) support for gopacket.
//
// PROFINET IO frames ride directly on Ethernet (EtherType 0x8892), usually
// inside an 802.1Q tag carrying priority 6. Every frame starts with a 2-byte
// Frame ID whose range selects the frame class (IEC 61158-6-10, Wireshark
// packet-pn-rt.c):
//
//	0x0020-0x0021  PTCP RTSync with follow up   0xFC01  alarm high
//	0x0080-0x0081  PTCP RTSync                  0xFE01  alarm low
//	0x0100-0x0FFF  RT_CLASS_3 cyclic            0xFEFC  DCP hello
//	0x8000-0xBFFF  RT_CLASS_1 cyclic            0xFEFD  DCP get/set
//	0xC000-0xFBFF  RT_CLASS_1 legacy / UDP      0xFEFE  DCP identify request
//	0xFF00-0xFF01  PTCP announce                0xFEFF  DCP identify response
//	0xFF20-0xFF21  PTCP follow up               0xFF80-0xFF8F fragmentation
//	0xFF40-0xFF43  PTCP delay
//
// Cyclic frames end with a 4-byte APDU status trailer:
//
//	+----------+---------------------+---------------+------------+-----------+
//	| FrameID  | IO data (C_SDU) ... | CycleCounter  | DataStatus | Transfer  |
//	| 2 bytes  | n bytes             | 2 bytes       | 1 byte     | 1 byte    |
//	+----------+---------------------+---------------+------------+-----------+
//
// Acyclic frames (DCP, alarms, PTCP) carry a PDU right after the Frame ID,
// decoded by the ProfinetDCP, ProfinetAlarm and ProfinetPTCP layers.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// EthernetTypeProfinet is the EtherType of PROFINET real-time frames.
const EthernetTypeProfinet EthernetType = 0x8892

// PROFINET layer types, registered in the 185-194 block.
var (
	// LayerTypeProfinet is the PROFINET real-time (PN-RT) frame layer.
	LayerTypeProfinet = gopacket.RegisterLayerType(185, gopacket.LayerTypeMetadata{Name: "Profinet", Decoder: gopacket.DecodeFunc(decodeProfinet)})
	// LayerTypeProfinetDCP is the PROFINET Discovery and basic Configuration Protocol layer.
	LayerTypeProfinetDCP = gopacket.RegisterLayerType(186, gopacket.LayerTypeMetadata{Name: "ProfinetDCP", Decoder: gopacket.DecodeFunc(decodeProfinetDCP)})
	// LayerTypeProfinetAlarm is the PROFINET IO alarm (RTA) layer.
	LayerTypeProfinetAlarm = gopacket.RegisterLayerType(187, gopacket.LayerTypeMetadata{Name: "ProfinetAlarm", Decoder: gopacket.DecodeFunc(decodeProfinetAlarm)})
	// LayerTypeProfinetPTCP is the PROFINET Precision Transparent Clock Protocol layer.
	LayerTypeProfinetPTCP = gopacket.RegisterLayerType(188, gopacket.LayerTypeMetadata{Name: "ProfinetPTCP", Decoder: gopacket.DecodeFunc(decodeProfinetPTCP)})
)

const (
	profinetFrameIDLen = 2

	// profinetTrailerLen is the APDU status at the end of cyclic frames:
	// cycle counter (2), data status (1), transfer status (1).
	profinetTrailerLen = 4
)

// ErrProfinetTooShort is returned when a PROFINET frame is shorter than its
// fixed header or trailer.
var ErrProfinetTooShort = errors.New("PROFINET frame too short")

// ProfinetFrameID is the 2-byte Frame ID that opens every PROFINET RT frame.
type ProfinetFrameID uint16

// Frame IDs with a fixed meaning.
const (
	ProfinetFrameIDAlarmHigh  ProfinetFrameID = 0xFC01
	ProfinetFrameIDAlarmLow   ProfinetFrameID = 0xFE01
	ProfinetFrameIDDCPHello   ProfinetFrameID = 0xFEFC
	ProfinetFrameIDDCPGetSet  ProfinetFrameID = 0xFEFD
	ProfinetFrameIDDCPIdentRq ProfinetFrameID = 0xFEFE
	ProfinetFrameIDDCPIdentRs ProfinetFrameID = 0xFEFF
)

// Frame ID range bounds, inclusive (Wireshark packet-pn-rt.c).
const (
	profinetRTSyncFUFirst   ProfinetFrameID = 0x0020
	profinetRTSyncFULast    ProfinetFrameID = 0x0021
	profinetRTSyncFirst     ProfinetFrameID = 0x0080
	profinetRTSyncLast      ProfinetFrameID = 0x0081
	profinetRTC3First       ProfinetFrameID = 0x0100
	profinetRTC3Last        ProfinetFrameID = 0x0FFF
	profinetRTC1First       ProfinetFrameID = 0x8000
	profinetRTC1Last        ProfinetFrameID = 0xBFFF
	profinetRTC1LegacyFirst ProfinetFrameID = 0xC000
	profinetRTC1LegacyLast  ProfinetFrameID = 0xFBFF
	profinetAcyclicFirst    ProfinetFrameID = 0xFC00
	profinetAcyclicLast     ProfinetFrameID = 0xFEFF
	profinetAnnounceFirst   ProfinetFrameID = 0xFF00
	profinetAnnounceLast    ProfinetFrameID = 0xFF01
	profinetFollowUpFirst   ProfinetFrameID = 0xFF20
	profinetFollowUpLast    ProfinetFrameID = 0xFF21
	profinetDelayFirst      ProfinetFrameID = 0xFF40
	profinetDelayLast       ProfinetFrameID = 0xFF43
	profinetFragFirst       ProfinetFrameID = 0xFF80
	profinetFragLast        ProfinetFrameID = 0xFF8F
)

// ProfinetFrameClass is the kind of frame a Frame ID range stands for.
type ProfinetFrameClass uint8

// PROFINET frame classes.
//
// 0x8000-0xBFFF was RT_CLASS_2 in early editions of IEC 61158-6-10; current
// editions and Wireshark treat it as RT_CLASS_1, which is what controllers
// such as the S7-1500 send there. RT_CLASS_STREAM (0x1000-0x3FFF on
// time-aware networks) needs connection state to tell apart from reserved
// IDs, so it is reported as reserved, as Wireshark does by default.
const (
	ProfinetFrameClassReserved ProfinetFrameClass = iota
	ProfinetFrameClassPTCPSync
	ProfinetFrameClassRTClass3
	ProfinetFrameClassRTClass1
	ProfinetFrameClassRTClass1Legacy
	ProfinetFrameClassAlarmHigh
	ProfinetFrameClassAlarmLow
	ProfinetFrameClassAcyclic
	ProfinetFrameClassDCP
	ProfinetFrameClassPTCPAnnounce
	ProfinetFrameClassPTCPFollowUp
	ProfinetFrameClassPTCPDelay
	ProfinetFrameClassFragment
)

// String returns the frame class name.
func (c ProfinetFrameClass) String() string {
	switch c {
	case ProfinetFrameClassReserved:
		return "Reserved"
	case ProfinetFrameClassPTCPSync:
		return "PTCP RTSync"
	case ProfinetFrameClassRTClass3:
		return "RT_CLASS_3"
	case ProfinetFrameClassRTClass1:
		return "RT_CLASS_1"
	case ProfinetFrameClassRTClass1Legacy:
		return "RT_CLASS_1 legacy"
	case ProfinetFrameClassAlarmHigh:
		return "Alarm high"
	case ProfinetFrameClassAlarmLow:
		return "Alarm low"
	case ProfinetFrameClassAcyclic:
		return "Acyclic"
	case ProfinetFrameClassDCP:
		return "DCP"
	case ProfinetFrameClassPTCPAnnounce:
		return "PTCP announce"
	case ProfinetFrameClassPTCPFollowUp:
		return "PTCP follow up"
	case ProfinetFrameClassPTCPDelay:
		return "PTCP delay"
	case ProfinetFrameClassFragment:
		return "Fragment"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(c))
}

// IsCyclic reports whether frames of this class carry IO data and the
// APDU status trailer.
func (c ProfinetFrameClass) IsCyclic() bool {
	switch c {
	case ProfinetFrameClassRTClass3, ProfinetFrameClassRTClass1, ProfinetFrameClassRTClass1Legacy:
		return true
	}
	return false
}

// IsPTCP reports whether frames of this class carry a PTCP PDU.
func (c ProfinetFrameClass) IsPTCP() bool {
	switch c {
	case ProfinetFrameClassPTCPSync, ProfinetFrameClassPTCPAnnounce,
		ProfinetFrameClassPTCPFollowUp, ProfinetFrameClassPTCPDelay:
		return true
	}
	return false
}

// inRange reports whether id lies in [first, last].
func (id ProfinetFrameID) inRange(first, last ProfinetFrameID) bool {
	return id >= first && id <= last
}

// Class maps the Frame ID to its frame class.
func (id ProfinetFrameID) Class() ProfinetFrameClass {
	switch {
	case id.inRange(profinetRTSyncFUFirst, profinetRTSyncFULast),
		id.inRange(profinetRTSyncFirst, profinetRTSyncLast):
		return ProfinetFrameClassPTCPSync
	case id.inRange(profinetRTC3First, profinetRTC3Last):
		return ProfinetFrameClassRTClass3
	case id.inRange(profinetRTC1First, profinetRTC1Last):
		return ProfinetFrameClassRTClass1
	case id.inRange(profinetRTC1LegacyFirst, profinetRTC1LegacyLast):
		return ProfinetFrameClassRTClass1Legacy
	case id == ProfinetFrameIDAlarmHigh:
		return ProfinetFrameClassAlarmHigh
	case id == ProfinetFrameIDAlarmLow:
		return ProfinetFrameClassAlarmLow
	case id.inRange(ProfinetFrameIDDCPHello, ProfinetFrameIDDCPIdentRs):
		return ProfinetFrameClassDCP
	case id.inRange(profinetAcyclicFirst, profinetAcyclicLast):
		return ProfinetFrameClassAcyclic
	case id.inRange(profinetAnnounceFirst, profinetAnnounceLast):
		return ProfinetFrameClassPTCPAnnounce
	case id.inRange(profinetFollowUpFirst, profinetFollowUpLast):
		return ProfinetFrameClassPTCPFollowUp
	case id.inRange(profinetDelayFirst, profinetDelayLast):
		return ProfinetFrameClassPTCPDelay
	case id.inRange(profinetFragFirst, profinetFragLast):
		return ProfinetFrameClassFragment
	}
	return ProfinetFrameClassReserved
}

// String returns the Frame ID in hex with its class.
func (id ProfinetFrameID) String() string {
	return fmt.Sprintf("0x%04x(%v)", uint16(id), id.Class())
}

// ProfinetDataStatus is the DataStatus byte of the APDU status trailer.
type ProfinetDataStatus uint8

// DataStatus bits (IEC 61158-6-10, Wireshark pn_rt.ds_*).
const (
	ProfinetDataStatusPrimary    ProfinetDataStatus = 0x01 // 1 primary, 0 backup
	ProfinetDataStatusRedundancy ProfinetDataStatus = 0x02
	ProfinetDataStatusDataValid  ProfinetDataStatus = 0x04
	ProfinetDataStatusRun        ProfinetDataStatus = 0x10 // provider state: 1 run, 0 stop
	ProfinetDataStatusStationOK  ProfinetDataStatus = 0x20 // station problem indicator: 1 ok
	ProfinetDataStatusIgnore     ProfinetDataStatus = 0x80
)

// Primary reports whether the provider is the primary (not backup) one.
func (s ProfinetDataStatus) Primary() bool { return s&ProfinetDataStatusPrimary != 0 }

// Redundancy returns the redundancy bit; its meaning depends on the IOCR.
func (s ProfinetDataStatus) Redundancy() bool { return s&ProfinetDataStatusRedundancy != 0 }

// DataValid reports whether the IO data is valid.
func (s ProfinetDataStatus) DataValid() bool { return s&ProfinetDataStatusDataValid != 0 }

// Run reports whether the provider is in RUN (not STOP).
func (s ProfinetDataStatus) Run() bool { return s&ProfinetDataStatusRun != 0 }

// StationProblem reports whether the station signals a problem.
func (s ProfinetDataStatus) StationProblem() bool { return s&ProfinetDataStatusStationOK == 0 }

// Ignore reports whether the consumer must ignore this frame.
func (s ProfinetDataStatus) Ignore() bool { return s&ProfinetDataStatusIgnore != 0 }

// String summarises the bits like Wireshark's info column.
func (s ProfinetDataStatus) String() string {
	pick := func(set bool, yes, no string) string {
		if set {
			return yes
		}
		return no
	}

	return fmt.Sprintf("0x%02x(%s,%s,%s,%s)", uint8(s),
		pick(s.DataValid(), "Valid", "Invalid"),
		pick(s.Primary(), "Primary", "Backup"),
		pick(s.StationProblem(), "Problem", "Ok"),
		pick(s.Run(), "Run", "Stop"))
}

// Profinet is a PROFINET real-time frame.
//
// For cyclic classes (see ProfinetFrameClass.IsCyclic) the IO data and the
// APDU status trailer are decoded here and there is no payload. The IO data
// layout comes from the device's GSDML file, so it stays raw.
//
// Ethernet pads frames to 64 bytes. The cyclic trailer always sits at the
// end of the frame, so the padding needed by short IO data is part of
// IOData: without the connection's configuration the padding cannot be told
// apart from data. Wireshark behaves the same way.
//
// For acyclic classes the PDU after the Frame ID is the payload. Padding is
// left in the payload; the DCP, alarm and PTCP layers drop it using their
// own length fields.
type Profinet struct {
	BaseLayer

	FrameID ProfinetFrameID

	// Cyclic frames only.
	IOData         []byte
	CycleCounter   uint16
	DataStatus     ProfinetDataStatus
	TransferStatus uint8
}

// LayerType returns LayerTypeProfinet.
func (p *Profinet) LayerType() gopacket.LayerType { return LayerTypeProfinet }

// CanDecode returns LayerTypeProfinet.
func (p *Profinet) CanDecode() gopacket.LayerClass { return LayerTypeProfinet }

// NextLayerType picks the decoder for the PDU after the Frame ID.
func (p *Profinet) NextLayerType() gopacket.LayerType {
	class := p.FrameID.Class()
	switch {
	case class.IsCyclic():
		return gopacket.LayerTypeZero
	case class == ProfinetFrameClassDCP:
		return LayerTypeProfinetDCP
	case class == ProfinetFrameClassAlarmHigh, class == ProfinetFrameClassAlarmLow:
		return LayerTypeProfinetAlarm
	case class.IsPTCP():
		return LayerTypeProfinetPTCP
	}
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes a PROFINET RT frame, starting at the Frame ID.
func (p *Profinet) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < profinetFrameIDLen {
		df.SetTruncated()
		return ErrProfinetTooShort
	}

	p.FrameID = ProfinetFrameID(binary.BigEndian.Uint16(data))
	p.IOData = nil
	p.CycleCounter = 0
	p.DataStatus = 0
	p.TransferStatus = 0

	// Acyclic: everything after the Frame ID is the next PDU.
	if !p.FrameID.Class().IsCyclic() {
		p.BaseLayer = BaseLayer{Contents: data[:profinetFrameIDLen], Payload: data[profinetFrameIDLen:]}
		return nil
	}

	// Cyclic: IO data, then the APDU status trailer at the frame end.
	if len(data) < profinetFrameIDLen+profinetTrailerLen {
		df.SetTruncated()
		return ErrProfinetTooShort
	}

	trailer := len(data) - profinetTrailerLen
	p.IOData = data[profinetFrameIDLen:trailer]
	p.CycleCounter = binary.BigEndian.Uint16(data[trailer:])
	p.DataStatus = ProfinetDataStatus(data[trailer+2])
	p.TransferStatus = data[trailer+3]
	p.BaseLayer = BaseLayer{Contents: data}
	return nil
}

func decodeProfinet(data []byte, p gopacket.PacketBuilder) error {
	pn := &Profinet{}
	if err := pn.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(pn)
	next := pn.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}

// registerProfinetDecoders maps EtherType 0x8892 to the PROFINET decoder.
// It is opt-in because existing callers would otherwise start seeing new
// layers. Calling it more than once is harmless.
func registerProfinetDecoders() {
	EthernetTypeMetadata[EthernetTypeProfinet] = EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeProfinet),
		Name:       "Profinet",
		LayerType:  LayerTypeProfinet,
	}
}
