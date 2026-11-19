// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Ethernet over EtherCAT (EoE) mailbox bodies (ETG.1000.6, Wireshark
// packet-ecatmb.c). Fields are little endian.
//
//	EoE header (4 bytes):
//	    word 0: Type (4 bits) | Port (4) | LastFragment (1) |
//	            TimeAppended (1) | TimeRequested (1) | reserved (5)
//	    word 1: FragmentNo (6 bits) | Offset (6) | FrameNo (4)
//	            or a 16-bit result for the response types
//
//	Fragment:           header | Ethernet frame bytes | [Timestamp (4)]
//	Timestamp response: header | Timestamp (4)
//	Set IP request:     header | Flags (4) | MAC (6) | IP (4) | Mask (4) |
//	                    Gateway (4) | DNS (4) | DNS name (32)
//	MAC filter request: header | Options (2) | 16 MACs | 4 masks
//	Get IP request, get address filter request: header only
//	Get IP response:    header | body of a set IP request
//	Get address filter response: header | body of a MAC filter request
//
// Wireshark decodes neither the get services nor their responses.
//
// The Offset field counts 32-byte blocks: the position of the fragment
// in the frame, or for fragment 0 the size of the whole frame.

package layers

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	ethercatEoEHeaderLen     = 4
	ethercatEoETypeMask      = 0x000F
	ethercatEoEPortShift     = 4
	ethercatEoEPortMask      = 0x0F
	ethercatEoELastBit       = 0x0100
	ethercatEoETimeAppBit    = 0x0200
	ethercatEoETimeReqBit    = 0x0400
	ethercatEoEFragMask      = 0x003F
	ethercatEoEOffsetShift   = 6
	ethercatEoEOffsetMask    = 0x3F
	ethercatEoEFrameNoShift  = 12
	ethercatEoEOffsetUnit    = 32
	ethercatEoETimestampLen  = 4
	ethercatEoEInitLen       = 58 // the full set IP request body
	ethercatEoEInitFlagsLen  = 4
	ethercatEoEDNSNameLen    = 32
	ethercatEoEFilterLen     = 122 // options, 16 filters, 4 masks
	ethercatEoEFilterOptLen  = 2
	ethercatEoEMaxFilters    = 16
	ethercatEoEMaxMasks      = 4
	ethercatEoEFilterCntMask = 0x000F
	ethercatEoEMaskCntShift  = 4
	ethercatEoEMaskCntMask   = 0x03
	ethercatEoENoBroadcast   = 0x0080
	ethercatMACLen           = 6
	ethercatIPv4Len          = 4
)

// EtherCATEoEType is the EoE frame type.
type EtherCATEoEType uint8

// EoE frame types.
const (
	EtherCATEoEFragment         EtherCATEoEType = 0
	EtherCATEoETimestamp        EtherCATEoEType = 1
	EtherCATEoESetIPRequest     EtherCATEoEType = 2
	EtherCATEoESetIPResponse    EtherCATEoEType = 3
	EtherCATEoEMACFilterRequest EtherCATEoEType = 4
	EtherCATEoEMACFilterReply   EtherCATEoEType = 5
	EtherCATEoEGetIPRequest     EtherCATEoEType = 6
	EtherCATEoEGetIPResponse    EtherCATEoEType = 7
	EtherCATEoEGetFilterRequest EtherCATEoEType = 8
	EtherCATEoEGetFilterReply   EtherCATEoEType = 9
)

// String returns the frame type name.
func (t EtherCATEoEType) String() string {
	switch t {
	case EtherCATEoEFragment:
		return "Fragment"
	case EtherCATEoETimestamp:
		return "TimeStamp"
	case EtherCATEoESetIPRequest:
		return "Init Req"
	case EtherCATEoESetIPResponse:
		return "Init Res"
	case EtherCATEoEMACFilterRequest:
		return "MAC Req"
	case EtherCATEoEMACFilterReply:
		return "MAC Res"
	case EtherCATEoEGetIPRequest:
		return "Get IP Req"
	case EtherCATEoEGetIPResponse:
		return "Get IP Res"
	case EtherCATEoEGetFilterRequest:
		return "Get MAC Req"
	case EtherCATEoEGetFilterReply:
		return "Get MAC Res"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(t))
}

// EtherCATEoEResult is the result word of the EoE responses.
type EtherCATEoEResult uint16

// EoE results (ETG.1000.6).
const (
	EtherCATEoESuccess          EtherCATEoEResult = 0x0000
	EtherCATEoEUnspecifiedError EtherCATEoEResult = 0x0001
	EtherCATEoEUnsupportedType  EtherCATEoEResult = 0x0002
	EtherCATEoENoIPSupport      EtherCATEoEResult = 0x0201
	EtherCATEoENoDHCPSupport    EtherCATEoEResult = 0x0202
	EtherCATEoENoFilterSupport  EtherCATEoEResult = 0x0401
)

// String returns the result name.
func (r EtherCATEoEResult) String() string {
	switch r {
	case EtherCATEoESuccess:
		return "Success"
	case EtherCATEoEUnspecifiedError:
		return "Unspecified error"
	case EtherCATEoEUnsupportedType:
		return "Unsupported frame type"
	case EtherCATEoENoIPSupport:
		return "No IP support"
	case EtherCATEoENoDHCPSupport:
		return "DHCP not supported"
	case EtherCATEoENoFilterSupport:
		return "No filter support"
	}
	return fmt.Sprintf("Unknown(0x%04x)", uint16(r))
}

// EtherCATEoEIPFlags says which parameters a set IP request carries.
type EtherCATEoEIPFlags uint32

// Set IP request flags.
const (
	EtherCATEoEHasMAC          EtherCATEoEIPFlags = 0x00000001
	EtherCATEoEHasIP           EtherCATEoEIPFlags = 0x00000002
	EtherCATEoEHasSubnetMask   EtherCATEoEIPFlags = 0x00000004
	EtherCATEoEHasGateway      EtherCATEoEIPFlags = 0x00000008
	EtherCATEoEHasDNSServer    EtherCATEoEIPFlags = 0x00000010
	EtherCATEoEHasDNSName      EtherCATEoEIPFlags = 0x00000020
	EtherCATEoEAppendTimestamp EtherCATEoEIPFlags = 0x00010000
)

// EtherCATEoESetIP is the body of an EoE set IP parameter request.
//
// ETG.1000.6 gives the body a fixed layout: every field has its place
// whether or not its flag is set, and only the flagged ones mean
// anything. Some masters (SOEM) instead send only the flagged fields,
// back to back; such a body is recognised by its exact length, Packed is
// set and the fields that were not sent stay nil. Wireshark rejects the
// packed form as too short.
//
// The four addresses travel in reversed byte order and are returned in
// the usual one. DNSName is the 32-byte field without its NUL padding.
type EtherCATEoESetIP struct {
	Flags      EtherCATEoEIPFlags
	Packed     bool
	MAC        net.HardwareAddr
	IP         net.IP
	SubnetMask net.IP
	Gateway    net.IP
	DNSServer  net.IP
	DNSName    []byte
}

// Has reports whether the request carries the parameter flag names.
func (s *EtherCATEoESetIP) Has(flag EtherCATEoEIPFlags) bool { return s.Flags&flag != 0 }

// EtherCATEoEMACFilter is the body of an EoE MAC filter request. Filters
// and Masks hold the entries the option counts announce.
type EtherCATEoEMACFilter struct {
	NoBroadcasts bool
	Filters      []net.HardwareAddr
	Masks        []net.HardwareAddr
}

// EtherCATEoE is an Ethernet over EtherCAT message.
//
// For a fragment, Data holds the Ethernet frame bytes without the
// appended timestamp, and Offset is the byte offset of the fragment or,
// for fragment 0, the size of the whole frame, both in steps of 32.
// Fragments are reassembled by EtherCATMailboxAssembler.
type EtherCATEoE struct {
	Type          EtherCATEoEType
	Port          uint8
	LastFragment  bool
	TimeAppended  bool
	TimeRequested bool

	// Fragment and timestamp response.
	FragmentNo uint8
	Offset     uint16
	FrameNo    uint8

	// Result of the set and get IP and MAC filter responses.
	Result EtherCATEoEResult

	// Timestamp is set when HasTimestamp is: by a timestamp response, or
	// by a fragment with TimeAppended that is long enough to hold it.
	Timestamp    uint32
	HasTimestamp bool

	// SetIP holds the parameters of a set IP request or get IP
	// response, MACFilter those of a set address filter request or get
	// address filter response. The get requests have no body.
	Data      []byte
	SetIP     *EtherCATEoESetIP
	MACFilter *EtherCATEoEMACFilter
}

// decodeEtherCATEoE decodes an EoE body, nil when the header is cut.
func decodeEtherCATEoE(data []byte) *EtherCATEoE {
	if len(data) < ethercatEoEHeaderLen {
		return nil
	}

	info := binary.LittleEndian.Uint16(data[0:2])
	word := binary.LittleEndian.Uint16(data[2:4])
	e := &EtherCATEoE{
		Type:          EtherCATEoEType(info & ethercatEoETypeMask),
		Port:          uint8(info>>ethercatEoEPortShift) & ethercatEoEPortMask,
		LastFragment:  info&ethercatEoELastBit != 0,
		TimeAppended:  info&ethercatEoETimeAppBit != 0,
		TimeRequested: info&ethercatEoETimeReqBit != 0,
		Data:          data[ethercatEoEHeaderLen:],
	}

	switch e.Type {
	case EtherCATEoEFragment:
		e.decodeFragment(word)
	case EtherCATEoETimestamp:
		e.splitFragmentWord(word)
		if len(e.Data) >= ethercatEoETimestampLen {
			e.Timestamp = binary.LittleEndian.Uint32(e.Data)
			e.HasTimestamp = true
		}
	case EtherCATEoESetIPRequest:
		e.SetIP = decodeEtherCATSetIP(e.Data)
	case EtherCATEoEMACFilterRequest:
		e.MACFilter = decodeEtherCATMACFilter(e.Data)
	case EtherCATEoESetIPResponse, EtherCATEoEMACFilterReply:
		e.Result = EtherCATEoEResult(word)
	case EtherCATEoEGetIPResponse:
		// The parameters read back, in the layout of a set IP request.
		e.Result = EtherCATEoEResult(word)
		e.SetIP = decodeEtherCATSetIP(e.Data)
	case EtherCATEoEGetFilterReply:
		e.Result = EtherCATEoEResult(word)
		e.MACFilter = decodeEtherCATMACFilter(e.Data)
	}
	return e
}

// splitFragmentWord splits the second header word of fragment frames.
func (e *EtherCATEoE) splitFragmentWord(word uint16) {
	e.FragmentNo = uint8(word & ethercatEoEFragMask)
	e.Offset = (word >> ethercatEoEOffsetShift & ethercatEoEOffsetMask) * ethercatEoEOffsetUnit
	e.FrameNo = uint8(word >> ethercatEoEFrameNoShift)
}

// decodeFragment reads a fragment and cuts the appended timestamp off
// the frame bytes.
func (e *EtherCATEoE) decodeFragment(word uint16) {
	e.splitFragmentWord(word)
	if !e.TimeAppended || len(e.Data) < ethercatEoETimestampLen {
		return
	}

	cut := len(e.Data) - ethercatEoETimestampLen
	e.Timestamp = binary.LittleEndian.Uint32(e.Data[cut:])
	e.HasTimestamp = true
	e.Data = e.Data[:cut]
}

// ethercatReverseIP returns the 4 address bytes of data in network order.
func ethercatReverseIP(data []byte) net.IP {
	return net.IPv4(data[3], data[2], data[1], data[0]).To4()
}

// decodeEtherCATSetIP decodes a set IP request body: the fixed layout
// when the body is long enough for it, else the packed one when the
// flags account for every byte. It returns nil for anything else.
func decodeEtherCATSetIP(data []byte) *EtherCATEoESetIP {
	if len(data) < ethercatEoEInitFlagsLen {
		return nil
	}

	s := &EtherCATEoESetIP{Flags: EtherCATEoEIPFlags(binary.LittleEndian.Uint32(data))}
	fields := [...]struct {
		flag EtherCATEoEIPFlags
		size int
		set  func(v []byte)
	}{
		{EtherCATEoEHasMAC, ethercatMACLen, func(v []byte) { s.MAC = net.HardwareAddr(v) }},
		{EtherCATEoEHasIP, ethercatIPv4Len, func(v []byte) { s.IP = ethercatReverseIP(v) }},
		{EtherCATEoEHasSubnetMask, ethercatIPv4Len, func(v []byte) { s.SubnetMask = ethercatReverseIP(v) }},
		{EtherCATEoEHasGateway, ethercatIPv4Len, func(v []byte) { s.Gateway = ethercatReverseIP(v) }},
		{EtherCATEoEHasDNSServer, ethercatIPv4Len, func(v []byte) { s.DNSServer = ethercatReverseIP(v) }},
		{EtherCATEoEHasDNSName, ethercatEoEDNSNameLen, func(v []byte) { s.DNSName = trimEtherCATNUL(v) }},
	}

	// Packed bodies hold the flagged fields only.
	packedLen := ethercatEoEInitFlagsLen
	for _, f := range fields {
		if s.Has(f.flag) {
			packedLen += f.size
		}
	}

	switch {
	case len(data) >= ethercatEoEInitLen:
	case len(data) == packedLen:
		s.Packed = true
	default:
		return nil
	}

	off := ethercatEoEInitFlagsLen
	for _, f := range fields {
		if s.Packed && !s.Has(f.flag) {
			continue
		}

		f.set(data[off : off+f.size])
		off += f.size
	}
	return s
}

// trimEtherCATNUL cuts a fixed-size string field at its first NUL.
func trimEtherCATNUL(data []byte) []byte {
	for i, b := range data {
		if b == 0 {
			return data[:i]
		}
	}
	return data
}

// decodeEtherCATMACFilter decodes a MAC filter request body, nil when it
// is shorter than the fixed layout. The counts are 4 and 2 bits wide, so
// at most 15 filters and 3 masks are listed.
func decodeEtherCATMACFilter(data []byte) *EtherCATEoEMACFilter {
	if len(data) < ethercatEoEFilterLen {
		return nil
	}

	opts := binary.LittleEndian.Uint16(data)
	f := &EtherCATEoEMACFilter{NoBroadcasts: opts&ethercatEoENoBroadcast != 0}
	filters := int(opts & ethercatEoEFilterCntMask)
	masks := int(opts >> ethercatEoEMaskCntShift & ethercatEoEMaskCntMask)

	list := func(off, n int) []net.HardwareAddr {
		if n == 0 {
			return nil
		}

		out := make([]net.HardwareAddr, n)
		for i := range out {
			start := off + i*ethercatMACLen
			out[i] = net.HardwareAddr(data[start : start+ethercatMACLen])
		}
		return out
	}

	f.Filters = list(ethercatEoEFilterOptLen, filters)
	f.Masks = list(ethercatEoEFilterOptLen+ethercatEoEMaxFilters*ethercatMACLen, masks)
	return f
}
