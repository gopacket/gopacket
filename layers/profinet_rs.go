// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO reporting system (IEC 61158-6-10, "Coding section related
// to the Reporting System"): time stamped events a device buffers until
// its controller fetches and acknowledges them.
//
// The RS records count blocks of their own kind. Those have the usual
// block header, but their types are a separate number space:
//
//	RS_EventBlock   BlockHeader, Padding (2), ARUUID (16), API (4),
//	                SlotNumber (2), SubslotNumber (2), ChannelNumber (2),
//	                RS_Specifier (2), RS_TimeStamp (12), RS_MinusError (2),
//	                RS_PlusError (2), RS_EventDataExtension*
//	RS_AdjustBlock  BlockHeader, Padding (2), settings of the observer
//
// The settings of an observer have no layout Wireshark knows; they stay
// raw. The first extension of an event is read by the observer that made
// it, as Wireshark does:
//
//	Stop observer            observer (2), RS_ReasonCode (4), user data
//	Time status observer     Padding (2), RS_DomainIdentification (16),
//	                         RS_MasterIdentification (8), RS_TimeStamp (12)
//	Source identification    AM_DeviceIdentification (8),
//	                         IM_Tag_Function (32), IM_Tag_Location (22)
//	Digital input observer   SoE_DigitalInputCurrentValue (2)

package layers

import "fmt"

// Reporting system block types and the type of their ProfinetBlock.Value.
const (
	ProfinetBlockRSAdjustObserver ProfinetBlockType = 0x0900 // *ProfinetRSAdjustInfo
	ProfinetBlockRSGetEvent       ProfinetBlockType = 0x0901 // *ProfinetRSEventInfo
	ProfinetBlockRSAckEvent       ProfinetBlockType = 0x0902 // *ProfinetRSAckInfo
)

const (
	profinetRSEventFixedLen = 46 // padding .. RS_PlusError
	profinetRSEventMinLen   = profinetBlockHeaderLen + profinetRSEventFixedLen
	profinetRSExtHeadLen    = 2
	profinetRSAdjustMinLen  = profinetBlockHeaderLen + 2

	profinetRSObserverFirst ProfinetRSBlockType = 0x4000
)

// ProfinetRSBlockType is the block type of a reporting system block: the
// observer that made the event. Types below 0x4000 are manufacturer
// specific.
type ProfinetRSBlockType uint16

// Observers of the standard.
const (
	ProfinetRSStopObserver         ProfinetRSBlockType = 0x4000
	ProfinetRSBufferObserver       ProfinetRSBlockType = 0x4001
	ProfinetRSTimeStatusObserver   ProfinetRSBlockType = 0x4002
	ProfinetRSSRLObserver          ProfinetRSBlockType = 0x4003
	ProfinetRSSourceIdentObserver  ProfinetRSBlockType = 0x4004
	ProfinetRSDigitalInputObserver ProfinetRSBlockType = 0x4010
)

// String names the observer.
func (t ProfinetRSBlockType) String() string {
	switch t {
	case ProfinetRSStopObserver:
		return "Stop observer"
	case ProfinetRSBufferObserver:
		return "Buffer observer"
	case ProfinetRSTimeStatusObserver:
		return "Time status observer"
	case ProfinetRSSRLObserver:
		return "System redundancy layer observer"
	case ProfinetRSSourceIdentObserver:
		return "Source identification observer"
	case ProfinetRSDigitalInputObserver:
		return "Digital input observer"
	}
	if t != 0 && t < profinetRSObserverFirst {
		return fmt.Sprintf("Manufacturer specific(0x%04x)", uint16(t))
	}
	return fmt.Sprintf("Reserved(0x%04x)", uint16(t))
}

// ProfinetRSSpecifier is RS_Specifier.
type ProfinetRSSpecifier uint16

// SequenceNumber returns the event sequence number (bits 0-10).
func (s ProfinetRSSpecifier) SequenceNumber() uint16 { return uint16(s) & profinetRSSeqMask }

// Specifier returns bits 14-15: 0 current value, 1 appears, 2 disappears.
func (s ProfinetRSSpecifier) Specifier() uint8 { return uint8(s >> profinetRSSpecifierShift) }

// ProfinetRSTimeStamp is RS_TimeStamp: a status word and a PTP style
// time. Bits 0-1 of Status tell the time scale: 0 global synchronized
// time, 1 the working clock, 2 local arbitrary time.
type ProfinetRSTimeStamp struct {
	Status      uint16
	SecondsHigh uint16
	Seconds     uint32
	Nanoseconds uint32
}

// ProfinetRSExtension is one RS_EventDataExtension. Value is set on the
// first extension of an event of a standard observer: a pointer to
// ProfinetRSStop, ProfinetRSTimeStatus, ProfinetRSSourceIdent or
// ProfinetRSDigitalInput.
type ProfinetRSExtension struct {
	Type  uint8
	Data  []byte
	Value interface{}
}

// ProfinetRSStop is the extension of a stop observer event: the observer
// that stopped and why.
type ProfinetRSStop struct {
	Observer ProfinetRSBlockType
	Reason   uint16 // RS_ReasonCode bits 0-15
	Detail   uint16 // RS_ReasonCode bits 16-31
	Data     []byte
}

// ProfinetRSTimeStatus is the extension of a time status observer event.
type ProfinetRSTimeStatus struct {
	DomainIdentification []byte // RS_DomainIdentification, 16 bytes
	MasterIdentification []byte // RS_MasterIdentification, 8 bytes
	TimeStamp            ProfinetRSTimeStamp
}

// ProfinetRSSourceIdent is the extension of a source identification
// observer event. The tags keep their padding.
type ProfinetRSSourceIdent struct {
	Organization uint16 // AM_DeviceIdentification
	VendorID     uint16
	DeviceID     uint16
	DeviceSubID  uint16
	TagFunction  string // IM_Tag_Function
	TagLocation  string // IM_Tag_Location
}

// ProfinetRSDigitalInput is the extension of a digital input observer
// event.
type ProfinetRSDigitalInput struct {
	CurrentValue uint16 // SoE_DigitalInputCurrentValue
}

// One reports whether the digital input is one (bit 0).
func (d *ProfinetRSDigitalInput) One() bool { return d.CurrentValue&1 != 0 }

// Sizes of the typed extensions.
const (
	profinetRSStopLen         = 6
	profinetRSDomainIdentLen  = 16
	profinetRSMasterIdentLen  = 8
	profinetRSTimeStampLen    = 12
	profinetRSTimeStatusLen   = 2 + profinetRSDomainIdentLen + profinetRSMasterIdentLen + profinetRSTimeStampLen
	profinetRSSourceIdentLen  = 8 + profinetIMTagFunctionLen + profinetIMTagLocationLen
	profinetRSDigitalInputLen = 2
)

// timeStamp reads an RS_TimeStamp.
func (r *profinetReader) timeStamp() ProfinetRSTimeStamp {
	return ProfinetRSTimeStamp{Status: r.u16(), SecondsHigh: r.u16(), Seconds: r.u32(), Nanoseconds: r.u32()}
}

// decodeProfinetRSExt reads the data of the first extension of an event
// by the observer that made it. It returns nil for other observers and
// for data shorter than the fields.
func decodeProfinetRSExt(observer ProfinetRSBlockType, data []byte) interface{} {
	r := &profinetReader{data: data}

	switch observer {
	case ProfinetRSStopObserver:
		if len(data) >= profinetRSStopLen {
			s := &ProfinetRSStop{Observer: ProfinetRSBlockType(r.u16())}
			s.Detail, s.Reason, s.Data = r.u16(), r.u16(), r.rest()
			return s
		}
	case ProfinetRSTimeStatusObserver:
		if len(data) >= profinetRSTimeStatusLen {
			r.skip(2)
			return &ProfinetRSTimeStatus{r.bytes(profinetRSDomainIdentLen), r.bytes(profinetRSMasterIdentLen), r.timeStamp()}
		}
	case ProfinetRSSourceIdentObserver:
		if len(data) >= profinetRSSourceIdentLen {
			return &ProfinetRSSourceIdent{r.u16(), r.u16(), r.u16(), r.u16(),
				r.str(profinetIMTagFunctionLen), r.str(profinetIMTagLocationLen)}
		}
	case ProfinetRSDigitalInputObserver:
		if len(data) >= profinetRSDigitalInputLen {
			return &ProfinetRSDigitalInput{CurrentValue: r.u16()}
		}
	}
	return nil
}

// ProfinetRSBlockHead is the header of a reporting system block.
type ProfinetRSBlockHead struct {
	BlockType   ProfinetRSBlockType
	Length      uint16
	VersionHigh uint8
	VersionLow  uint8
}

// ProfinetRSEvent is one RS_EventBlock.
type ProfinetRSEvent struct {
	ProfinetRSBlockHead
	ARUUID        ProfinetUUID
	API           uint32
	Slot          uint16
	Subslot       uint16
	ChannelNumber uint16
	Specifier     ProfinetRSSpecifier
	TimeStamp     ProfinetRSTimeStamp
	MinusError    uint16
	PlusError     uint16
	Extensions    []ProfinetRSExtension
}

// ProfinetRSEventInfo is RS_EventInfo: the body of RS_GetEvent and of the
// RS_Event alarm item.
type ProfinetRSEventInfo struct {
	NumberOfEntries uint16
	Events          []ProfinetRSEvent
}

// rsBlock reads the header of a reporting system block and returns a
// reader over its body, or nil when no whole header is left.
func (r *profinetReader) rsBlock() (ProfinetRSBlockHead, *profinetReader) {
	if r.left() < profinetBlockHeaderLen {
		r.rest()
		return ProfinetRSBlockHead{}, nil
	}

	h := ProfinetRSBlockHead{BlockType: ProfinetRSBlockType(r.u16()), Length: r.u16(), VersionHigh: r.u8(), VersionLow: r.u8()}

	n := int(h.Length) - profinetBlockVersionLen
	if n < 0 {
		n = 0
	}
	return h, &profinetReader{data: r.clipBytes(n), base: profinetBlockHeaderLen, depth: r.depth}
}

// decodeProfinetRSEvents reads RS_EventInfo. A cut event is dropped.
func decodeProfinetRSEvents(r *profinetReader) *ProfinetRSEventInfo {
	if r.left() < 2 {
		return nil
	}

	info := &ProfinetRSEventInfo{NumberOfEntries: r.u16()}
	n := int(info.NumberOfEntries)
	if max := r.left() / profinetRSEventMinLen; n > max {
		n = max
	}

	info.Events = make([]ProfinetRSEvent, 0, n)
	for len(info.Events) < n {
		head, body := r.rsBlock()
		if body == nil || body.left() < profinetRSEventFixedLen {
			break
		}

		e := ProfinetRSEvent{ProfinetRSBlockHead: head}
		body.skip(2)
		e.ARUUID = body.uuid()
		e.API = body.u32()
		e.Slot = body.u16()
		e.Subslot = body.u16()
		e.ChannelNumber = body.u16()
		e.Specifier = ProfinetRSSpecifier(body.u16())
		e.TimeStamp = body.timeStamp()
		e.MinusError = body.u16()
		e.PlusError = body.u16()
		e.Extensions = body.rsExtensions()
		if len(e.Extensions) > 0 {
			e.Extensions[0].Value = decodeProfinetRSExt(head.BlockType, e.Extensions[0].Data)
		}
		info.Events = append(info.Events, e)
	}
	return info
}

// rsExtensions reads the extensions that fill the rest of an event: a
// type, a length and that many bytes each.
func (r *profinetReader) rsExtensions() []ProfinetRSExtension {
	// Count before allocating; an extension takes at least two bytes.
	n := 0
	for off := r.off; off+profinetRSExtHeadLen <= len(r.data); n++ {
		off += profinetRSExtHeadLen + int(r.data[off+1])
	}
	if n == 0 {
		return nil
	}

	exts := make([]ProfinetRSExtension, n)
	for i := range exts {
		exts[i].Type = r.u8()
		exts[i].Data = r.clipBytes(int(r.u8()))
	}
	return exts
}

// ProfinetRSAdjustBlock is one RS_AdjustBlock: the settings of one
// observer, raw (Wireshark shows them as user data for every observer).
type ProfinetRSAdjustBlock struct {
	ProfinetRSBlockHead
	Data []byte
}

// ProfinetRSAdjustInfo is RS_AdjustInfo, the body of RS_AdjustObserver.
type ProfinetRSAdjustInfo struct {
	NumberOfEntries uint16
	Blocks          []ProfinetRSAdjustBlock
}

func decodeProfinetRSAdjust(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	info := &ProfinetRSAdjustInfo{NumberOfEntries: r.u16()}
	n := int(info.NumberOfEntries)
	if max := r.left() / profinetRSAdjustMinLen; n > max {
		n = max
	}

	info.Blocks = make([]ProfinetRSAdjustBlock, 0, n)
	for len(info.Blocks) < n {
		head, body := r.rsBlock()
		if body == nil || body.left() < 2 {
			break
		}

		body.skip(2)
		info.Blocks = append(info.Blocks, ProfinetRSAdjustBlock{head, body.rest()})
	}
	return info
}

// ProfinetRSAckInfo is RS_AckInfo, the body of RS_AckEvent: the last
// event the controller has seen.
type ProfinetRSAckInfo struct {
	Specifier ProfinetRSSpecifier
}

// decodeRSValue decodes the reporting system blocks.
func (b *ProfinetBlock) decodeRSValue(r *profinetReader, low uint8) interface{} {
	if low != 0 {
		return nil
	}

	switch b.Type {
	case ProfinetBlockRSAdjustObserver:
		return decodeProfinetRSAdjust(r)
	case ProfinetBlockRSGetEvent:
		if info := decodeProfinetRSEvents(r); info != nil {
			return info
		}
	case ProfinetBlockRSAckEvent:
		if r.left() >= 2 {
			return &ProfinetRSAckInfo{Specifier: ProfinetRSSpecifier(r.u16())}
		}
	}
	return nil
}
