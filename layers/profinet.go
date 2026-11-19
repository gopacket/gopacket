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
//
// Three more layouts are decoded here, each found the way Wireshark finds
// it (packet-pn-rt.c, packet-pn.c):
//
//   - Fragments (0xFF80-0xFF8F) open with FragDataLength and FragStatus;
//     ProfinetFragAssembler puts the fragments back together.
//   - Secured frames put an 8-byte SecurityMetaData header after the Frame
//     ID. Alarm IDs 0xFC41 and 0xFE41 always have it. Cyclic frames have
//     no flag for it, so it is recognised by its reserved bits being zero
//     and its SecurityLength matching the frame length exactly.
//   - RT_CLASS_3 frames may pack several subframes (Dynamic Frame
//     Packing); see Profinet.Subframes for the heuristic.
//
// PROFINET IO connection management runs over DCE/RPC on UDP port 34964
// and is decoded by the ProfinetIORPC layer.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

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
	// LayerTypeProfinetIORPC is the PROFINET IO connection management layer (DCE/RPC over UDP).
	LayerTypeProfinetIORPC = gopacket.RegisterLayerType(190, gopacket.LayerTypeMetadata{Name: "ProfinetIORPC", Decoder: gopacket.DecodeFunc(decodeProfinetIORPC)})
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
	ProfinetFrameIDRSI        ProfinetFrameID = 0xFE02 // Remote Service Interface
	ProfinetFrameIDSXP        ProfinetFrameID = 0xFE03 // SXP via RTAv3
	ProfinetFrameIDDCPHello   ProfinetFrameID = 0xFEFC
	ProfinetFrameIDDCPGetSet  ProfinetFrameID = 0xFEFD
	ProfinetFrameIDDCPIdentRq ProfinetFrameID = 0xFEFE
	ProfinetFrameIDDCPIdentRs ProfinetFrameID = 0xFEFF
)

// Frame IDs of the secured variants: the same PDU behind a
// SecurityMetaData header.
const (
	ProfinetFrameIDAlarmHighSec ProfinetFrameID = 0xFC41
	ProfinetFrameIDAlarmLowSec  ProfinetFrameID = 0xFE41
	ProfinetFrameIDRSISec       ProfinetFrameID = 0xFE42
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

	// RT_CLASS_STREAM ranges, used on time-aware (TSN) networks only.
	profinetStreamFirst    ProfinetFrameID = 0x1000
	profinetStreamLast     ProfinetFrameID = 0x2FFF
	profinetStreamSecFirst ProfinetFrameID = 0x3800
	profinetStreamSecLast  ProfinetFrameID = 0x3FFF
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
	ProfinetFrameClassRTStream
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
	case ProfinetFrameClassRTStream:
		return "RT_CLASS_STREAM"
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
	case id == ProfinetFrameIDAlarmHigh, id == ProfinetFrameIDAlarmHighSec:
		return ProfinetFrameClassAlarmHigh
	case id == ProfinetFrameIDAlarmLow, id == ProfinetFrameIDAlarmLowSec:
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

// StreamClass maps the Frame ID to its class on a time-aware (TSN)
// network, where 0x1000-0x2FFF and 0x3800-0x3FFF carry RT_CLASS_STREAM
// and the RT_CLASS_3 range is reserved. Whether a network is time-aware
// is negotiated at connection set-up (ARProperties), which a single frame
// does not show; Class assumes it is not, as Wireshark does by default.
func (id ProfinetFrameID) StreamClass() ProfinetFrameClass {
	switch {
	case id.inRange(profinetStreamFirst, profinetStreamLast),
		id.inRange(profinetStreamSecFirst, profinetStreamSecLast):
		return ProfinetFrameClassRTStream
	case id.inRange(profinetRTC3First, profinetRTC3Last):
		return ProfinetFrameClassReserved
	}
	return id.Class()
}

// profinetFrameRange names one Frame ID range.
type profinetFrameRange struct {
	last ProfinetFrameID
	name string
}

// profinetFrameRanges lists the ranges in ascending order with the names
// of IEC 61158-6-10 as Wireshark prints them, for networks that are not
// time-aware.
var profinetFrameRanges = [...]profinetFrameRange{
	{0x001F, "0x0000-0x001F: Reserved ID"},
	{0x0021, "0x0020-0x0021: Real-Time: Sync (with follow up)"},
	{0x007F, "0x0022-0x007F: Reserved ID"},
	{0x0081, "0x0080-0x0081: Real-Time: Sync (without follow up)"},
	{0x00FF, "0x0082-0x00FF: Reserved ID"},
	{0x06FF, "0x0100-0x06FF: RED: Real-Time(class=3): non redundant, normal or DFP"},
	{0x0FFF, "0x0700-0x0FFF: RED: Real-Time(class=3): redundant, normal or DFP"},
	{0x7FFF, "0x1000-0x7FFF: Reserved ID"},
	{0xBBFF, "0x8000-0xBBFF: Real-Time(class=1 unicast): non redundant, normal"},
	{0xBFFF, "0xBC00-0xBFFF: Real-Time(class=1 multicast): non redundant, normal"},
	{0xF7FF, "0xC000-0xF7FF: Real-Time(class=1 unicast): Cyclic"},
	{0xFBFF, "0xF800-0xFBFF: Real-Time(class=1 multicast): Cyclic"},
	{0xFDFF, "0xFC00-0xFDFF: Reserved"},
	{0xFEFF, "0xFE00-0xFEFF: Real-Time: Reserved"},
	{0xFF01, "0xFF00-0xFF01: PTCP Announce"},
	{0xFF1F, "0xFF02-0xFF1F: Reserved"},
	{0xFF21, "0xFF20-0xFF21: PTCP Follow Up"},
	{0xFF3F, "0xFF22-0xFF3F: Reserved"},
	{0xFF43, "0xFF40-0xFF43: Acyclic Real-Time: Delay"},
	{0xFF7F, "0xFF44-0xFF7F: reserved ID"},
	{0xFF8F, "0xFF80-0xFF8F: Fragmentation"},
	{0xFFFF, "0xFF90-0xFFFF: reserved ID"},
}

// profinetStreamRanges replaces 0x0100-0x3FFF on time-aware networks.
var profinetStreamRanges = [...]profinetFrameRange{
	{0x0FFF, "0x0100-0x0FFF: Reserved ID"},
	{0x2FFF, "0x1000-0x2FFF: RT_CLASS_STREAM"},
	{0x37FF, "0x3000-0x37FF: Reserved ID"},
	{0x3FFF, "0x3800-0x3FFF: RT_CLASS_STREAM with security"},
}

// Name describes the Frame ID: the fixed meaning of the IDs that have
// one, otherwise the range it lies in.
func (id ProfinetFrameID) Name() string {
	switch id {
	case ProfinetFrameIDAlarmHigh:
		return "Real-Time: Acyclic PN-IO Alarm high priority"
	case ProfinetFrameIDAlarmHighSec:
		return "Real-Time: Acyclic PN-IO Alarm high priority with security"
	case ProfinetFrameIDAlarmLow:
		return "Real-Time: Acyclic PN-IO Alarm low priority"
	case ProfinetFrameIDAlarmLowSec:
		return "Real-Time: Acyclic PN-IO Alarm low priority with security"
	case ProfinetFrameIDRSI:
		return "Real-Time: Acyclic PN-IO RSI"
	case ProfinetFrameIDRSISec:
		return "Real-Time: Acyclic PN-IO RSI with security"
	case ProfinetFrameIDSXP:
		return "Real-Time: Acyclic PN-IO SXP via RTAv3"
	case ProfinetFrameIDDCPHello:
		return "Real-Time: DCP (Discovery and basic Configuration Protocol) hello"
	case ProfinetFrameIDDCPGetSet:
		return "Real-Time: DCP (Discovery and basic Configuration Protocol) get/set"
	case ProfinetFrameIDDCPIdentRq:
		return "Real-Time: DCP (Discovery and basic Configuration Protocol) identify multicast request"
	case ProfinetFrameIDDCPIdentRs:
		return "Real-Time: DCP (Discovery and basic Configuration Protocol) identify response"
	}

	for _, r := range profinetFrameRanges {
		if id <= r.last {
			return r.name
		}
	}
	return ""
}

// StreamName is Name for a time-aware network (see StreamClass).
func (id ProfinetFrameID) StreamName() string {
	if !id.inRange(profinetRTC3First, profinetStreamSecLast) {
		return id.Name()
	}

	for _, r := range profinetStreamRanges {
		if id <= r.last {
			return r.name
		}
	}
	return ""
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

	// Cyclic frames only. A frame with authenticated encryption (see
	// Security) hides the trailer: IOData is then the ciphertext and the
	// three status fields are zero.
	IOData         []byte
	CycleCounter   uint16
	DataStatus     ProfinetDataStatus
	TransferStatus uint8

	// Security is the SecurityMetaData of a secured cyclic or alarm frame,
	// nil for plain frames.
	Security *ProfinetSecurity

	// Subframes are the DFP subframes of an RT_CLASS_3 frame, nil when the
	// frame is not packed. They alias IOData, which stays whole.
	//
	// A frame is taken as packed when, as in Wireshark's IsDFP_Frame, its
	// IO data opens with a header CRC that is zero or matches, the next
	// two bytes are not zero, and a chain of subframes (position, length,
	// cycle counter, data status, data, CRC) leads to a terminating
	// zero-length subframe, each non-zero CRC of a subframe with position
	// bit 7 set matching. The header CRC covers the Ethernet addresses, so
	// it can only be checked when the frame is decoded from the Ethernet
	// layer down; a bare DecodeFromBytes accepts a zero header CRC only.
	// Use DecodeSubframes to supply the addresses in that case.
	SubframeHeaderCRC uint16
	Subframes         []ProfinetSubframe

	// Fragment frames only (0xFF80-0xFF8F); the payload is the fragment.
	FragDataLength uint8 // in units of 8 octets
	FragStatus     ProfinetFragStatus
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
		// An encrypted alarm PDU cannot be decoded.
		if p.Security != nil && p.Security.Encrypted() {
			return gopacket.LayerTypePayload
		}
		return LayerTypeProfinetAlarm
	case class.IsPTCP():
		return LayerTypeProfinetPTCP
	}
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes a PROFINET RT frame, starting at the Frame ID.
func (p *Profinet) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	return p.decode(data, df, nil, nil)
}

// decode is DecodeFromBytes with the Ethernet addresses, when known, for
// the DFP header CRC.
func (p *Profinet) decode(data []byte, df gopacket.DecodeFeedback, dst, src net.HardwareAddr) error {
	if len(data) < profinetFrameIDLen {
		df.SetTruncated()
		return ErrProfinetTooShort
	}

	*p = Profinet{FrameID: ProfinetFrameID(binary.BigEndian.Uint16(data))}
	body := data[profinetFrameIDLen:]

	switch class := p.FrameID.Class(); {
	case class.IsCyclic():
		return p.decodeCyclic(data, df, dst, src)
	case class == ProfinetFrameClassFragment:
		return p.decodeFragment(data, df)
	case p.FrameID == ProfinetFrameIDAlarmHighSec, p.FrameID == ProfinetFrameIDAlarmLowSec:
		return p.decodeSecuredAlarm(data, df)
	}

	// Acyclic: everything after the Frame ID is the next PDU.
	p.BaseLayer = BaseLayer{Contents: data[:profinetFrameIDLen], Payload: body}
	return nil
}

// decodeCyclic reads the IO data and the APDU status trailer at the frame
// end, behind the SecurityMetaData of a secured frame.
func (p *Profinet) decodeCyclic(data []byte, df gopacket.DecodeFeedback, dst, src net.HardwareAddr) error {
	if len(data) < profinetFrameIDLen+profinetTrailerLen {
		df.SetTruncated()
		return ErrProfinetTooShort
	}
	p.BaseLayer = BaseLayer{Contents: data}

	// Secured: metadata, then either data, trailer and checksum or
	// ciphertext and checksum.
	end := len(data)
	start := profinetFrameIDLen
	if sec := cyclicSecurity(data); sec != nil {
		p.Security = sec
		start += profinetSecurityMetaLen
		end -= profinetSecurityChecksumLen

		if sec.Encrypted() {
			p.IOData = data[start:end]
			return nil
		}
	}

	trailer := end - profinetTrailerLen
	p.IOData = data[start:trailer]
	p.CycleCounter = binary.BigEndian.Uint16(data[trailer:])
	p.DataStatus = ProfinetDataStatus(data[trailer+2])
	p.TransferStatus = data[trailer+3]

	// Wireshark looks for subframes in plain RT_CLASS_3 frames only.
	if p.Security == nil && p.FrameID.Class() == ProfinetFrameClassRTClass3 {
		p.DecodeSubframes(dst, src)
	}
	return nil
}

// decodeSecuredAlarm strips the SecurityMetaData that opens the alarm
// frames 0xFC41 and 0xFE41. SecurityLength bounds the alarm PDU; the
// SecurityChecksum follows it.
func (p *Profinet) decodeSecuredAlarm(data []byte, df gopacket.DecodeFeedback) error {
	head := profinetFrameIDLen + profinetSecurityMetaLen
	if len(data) < head {
		df.SetTruncated()
		return ErrProfinetTooShort
	}

	sec := decodeProfinetSecurity(data[profinetFrameIDLen:])
	p.Security = &sec

	end := head + int(sec.Length)
	if end > len(data) {
		df.SetTruncated()
		end = len(data)
	}
	if rest := data[end:]; len(rest) >= profinetSecurityChecksumLen {
		sec.Checksum = rest[:profinetSecurityChecksumLen]
	} else {
		df.SetTruncated()
	}

	p.BaseLayer = BaseLayer{Contents: data[:head], Payload: data[head:end]}
	return nil
}

func decodeProfinet(data []byte, p gopacket.PacketBuilder) error {
	pn := &Profinet{}
	dst, src := profinetLinkAddrs(p)
	if err := pn.decode(data, p, dst, src); err != nil {
		return err
	}

	p.AddLayer(pn)
	next := pn.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}

// profinetLinkAddrs returns the Ethernet addresses of the frame being
// built, or nil when the packet has no Ethernet layer yet. The link layer
// is set before its payload is decoded, so asking for it decodes nothing.
func profinetLinkAddrs(p gopacket.PacketBuilder) (dst, src net.HardwareAddr) {
	linked, ok := p.(interface{ LinkLayer() gopacket.LinkLayer })
	if !ok {
		return nil, nil
	}

	eth, ok := linked.LinkLayer().(*Ethernet)
	if !ok {
		return nil, nil
	}
	return eth.DstMAC, eth.SrcMAC
}

// registerProfinetDecoders maps EtherType 0x8892 to the PROFINET decoder
// and UDP port 34964 to the PROFINET IO RPC decoder. It is opt-in because
// existing callers would otherwise start seeing new layers. Calling it
// more than once is harmless.
func registerProfinetDecoders() {
	RegisterUDPPortLayerType(UDPPortProfinetIO, LayerTypeProfinetIORPC)
	EthernetTypeMetadata[EthernetTypeProfinet] = EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeProfinet),
		Name:       "Profinet",
		LayerType:  LayerTypeProfinet,
	}
}
