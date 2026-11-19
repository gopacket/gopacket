// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET fragmentation, security metadata and Dynamic Frame Packing.
//
// These are the three PN-RT layouts that wrap or split the usual PDU
// (IEC 61158-6-10, Wireshark packet-pn-rt.c and packet-pn.c).
//
// Fragment (Frame ID 0xFF80-0xFF8F; the low nibble is the fragment ID):
//
//	+---------+----------------+------------+----------+
//	| FrameID | FragDataLength | FragStatus | FragData |
//	| 2       | 1 (x 8 octets) | 1          | n        |
//	+---------+----------------+------------+----------+
//
// FragStatus holds the fragment number (bits 0-5) and MoreFollows (bit 7).
// The fragments put together are an EtherType followed by its payload.
//
// SecurityMetaData (8 bytes after the Frame ID of a secured frame):
//
//	+---------------------+-----------------+-------------------------+----------------+
//	| SecurityInformation | SecurityControl | SecuritySequenceCounter | SecurityLength |
//	| 1 (bit 0: mode)     | 1 (low nibble:  | 4                       | 2 (11 bits)    |
//	|                     |  generation)    |                         |                |
//	+---------------------+-----------------+-------------------------+----------------+
//
// Mode 0 authenticates only: the PDU follows in clear, then a 16-byte
// SecurityChecksum. Mode 1 encrypts: ciphertext, then the checksum.
//
// DFP (RT_CLASS_3 frames packing the data of several devices):
//
//	+---------+----------+----------+-----+------------+-------------+
//	| FrameID | HeaderCRC| Subframe | ... | 0x?? 0x00  | APDU status |
//	| 2       | 2 (LE)   |          |     | terminator | 4           |
//	+---------+----------+----------+-----+------------+-------------+
//
//	Subframe: Position (1), DataLength (1), CycleCounter (1),
//	          DataStatus (1), Data (DataLength), CRC16 (2, LE)

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
)

const (
	profinetFragHeaderLen = 2

	// profinetFragUnit is the unit of FragDataLength, in octets.
	profinetFragUnit = 8

	profinetSecurityMetaLen     = 8
	profinetSecurityChecksumLen = 16

	// SecurityMetaData bits. The reserved ones must be zero.
	profinetSecModeBit        = 0x01
	profinetSecInfoReserved   = 0xFE
	profinetSecGenerationMask = 0x0F
	profinetSecCtrlReserved   = 0xF0
	profinetSecLengthMask     = 0x07FF
	profinetSecLenReserved    = 0xF800

	// DFP layout.
	profinetDFPCRCLen        = 2
	profinetSubframeHeadLen  = 4 // position, length, cycle counter, data status
	profinetSubframeEndLen   = 2 // position, zero length
	profinetSubframePosMask  = 0x7F
	profinetSubframeCRCBit   = 0x80
	profinetDFPVirtualHdrLen = 16 // dst, src, EtherType, Frame ID
	profinetCRC16ARCPoly     = 0xA001

	// Fragment reassembly.
	profinetFragNumberMask    = 0x3F
	profinetFragIDMask        = 0x000F
	profinetFragDefaultMax    = 9216 // a jumbo frame
	profinetFragMaxReassembly = 64   // concurrent reassemblies kept
)

// ProfinetFragMoreFollows is the FragStatus bit set on every fragment but
// the last.
const ProfinetFragMoreFollows ProfinetFragStatus = 0x80

var (
	// ErrProfinetFragOrder is returned when a fragment does not continue
	// the reassembly in progress; that reassembly is dropped.
	ErrProfinetFragOrder = errors.New("PROFINET fragment out of order")
	// ErrProfinetFragTooBig is returned when a reassembly would exceed the
	// assembler's size cap; it is dropped.
	ErrProfinetFragTooBig = errors.New("PROFINET reassembly exceeds size cap")
	// ErrProfinetFragShort is returned when a fragment holds fewer bytes
	// than its FragDataLength says.
	ErrProfinetFragShort = errors.New("PROFINET fragment shorter than FragDataLength")
	// ErrProfinetNotFragment is returned when a frame handed to the
	// assembler is not a fragment.
	ErrProfinetNotFragment = errors.New("not a PROFINET fragment")
)

// ProfinetFragStatus is the FragStatus byte of a fragment.
type ProfinetFragStatus uint8

// Number returns the zero-based fragment number (bits 0-5).
func (s ProfinetFragStatus) Number() uint8 { return uint8(s) & profinetFragNumberMask }

// MoreFollows reports whether more fragments follow this one.
func (s ProfinetFragStatus) MoreFollows() bool { return s&ProfinetFragMoreFollows != 0 }

// String formats the status as Wireshark does.
func (s ProfinetFragStatus) String() string {
	if s.MoreFollows() {
		return fmt.Sprintf("Number: %d, More Fragments follow", s.Number())
	}
	return fmt.Sprintf("Number: %d, Last Fragment", s.Number())
}

// decodeFragment reads the fragment header; the fragment is the payload.
func (p *Profinet) decodeFragment(data []byte, df gopacket.DecodeFeedback) error {
	head := profinetFrameIDLen + profinetFragHeaderLen
	if len(data) < head {
		df.SetTruncated()
		return ErrProfinetTooShort
	}

	p.FragDataLength = data[profinetFrameIDLen]
	p.FragStatus = ProfinetFragStatus(data[profinetFrameIDLen+1])
	p.BaseLayer = BaseLayer{Contents: data[:head], Payload: data[head:]}
	return nil
}

// ProfinetSecurity is the SecurityMetaData of a secured frame.
type ProfinetSecurity struct {
	Information     uint8  // bit 0 is the protection mode
	Control         uint8  // low nibble is the generation number
	SequenceCounter uint32 // SecuritySequenceCounter
	Length          uint16 // SecurityLength: protected bytes after the metadata

	// Checksum is the 16-byte SecurityChecksum behind the protected bytes,
	// nil when the capture ends before it.
	Checksum []byte
}

// Encrypted reports whether the protection mode is authenticated
// encryption (1) rather than authentication only (0).
func (s *ProfinetSecurity) Encrypted() bool { return s.Information&profinetSecModeBit != 0 }

// GenerationNumber returns the key generation (SecurityControl bits 0-3).
func (s *ProfinetSecurity) GenerationNumber() uint8 { return s.Control & profinetSecGenerationMask }

// decodeProfinetSecurity reads SecurityMetaData; data holds at least 8
// bytes.
func decodeProfinetSecurity(data []byte) ProfinetSecurity {
	return ProfinetSecurity{
		Information:     data[0],
		Control:         data[1],
		SequenceCounter: binary.BigEndian.Uint32(data[2:]),
		Length:          binary.BigEndian.Uint16(data[6:]) & profinetSecLengthMask,
	}
}

// cyclicSecurity returns the SecurityMetaData of a secured cyclic frame,
// or nil for a plain one. data starts at the Frame ID.
//
// Nothing flags a secured cyclic frame, so this is Wireshark's test
// (pn_is_valid_security_metadata): the reserved bits are zero, the counter
// and the length are not, and SecurityLength is exactly what the frame
// holds between the metadata and the 16-byte checksum. IO data that
// happens to pass is read as secured; the length match makes that rare.
func cyclicSecurity(data []byte) *ProfinetSecurity {
	head := profinetFrameIDLen + profinetSecurityMetaLen
	if len(data) < head+profinetSecurityChecksumLen {
		return nil
	}

	meta := data[profinetFrameIDLen:head]
	rawLen := binary.BigEndian.Uint16(meta[6:])
	if meta[0]&profinetSecInfoReserved != 0 || meta[1]&profinetSecCtrlReserved != 0 || rawLen&profinetSecLenReserved != 0 {
		return nil
	}

	sec := decodeProfinetSecurity(meta)
	protected := len(data) - head - profinetSecurityChecksumLen
	if sec.SequenceCounter == 0 || sec.Length == 0 || int(sec.Length) != protected {
		return nil
	}

	// Authentication only protects at least the APDU status.
	if !sec.Encrypted() && protected < profinetTrailerLen {
		return nil
	}

	sec.Checksum = data[len(data)-profinetSecurityChecksumLen:]
	return &sec
}

// ProfinetSubframe is one DFP subframe.
type ProfinetSubframe struct {
	Position     uint8 // bits 0-6 of the position byte
	CRCFlag      bool  // bit 7 of the position byte: the CRC is checked
	DataLength   uint8
	CycleCounter uint8
	DataStatus   ProfinetDataStatus
	Data         []byte
	CRC          uint16 // SFCRC16, zero when not used
}

// profinetCRC16 continues a CRC-16/ARC (polynomial 0x8005 reflected, no
// final XOR) over data. Wireshark calls it crc16_plain.
func profinetCRC16(crc uint16, data []byte) uint16 {
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ profinetCRC16ARCPoly
				continue
			}
			crc >>= 1
		}
	}
	return crc
}

// ProfinetDFPHeaderCRC computes the header CRC of a DFP frame: a CRC-16
// over the destination and source addresses, the PROFINET EtherType and
// the Frame ID.
func ProfinetDFPHeaderCRC(dst, src net.HardwareAddr, id ProfinetFrameID) uint16 {
	var hdr [profinetDFPVirtualHdrLen]byte
	copy(hdr[0:6], dst)
	copy(hdr[6:12], src)
	binary.BigEndian.PutUint16(hdr[12:], uint16(EthernetTypeProfinet))
	binary.BigEndian.PutUint16(hdr[14:], uint16(id))
	return profinetCRC16(0, hdr[:])
}

// DecodeSubframes looks for DFP subframes in IOData and fills Subframes,
// reporting whether the frame is packed. dst and src are the Ethernet
// addresses of the frame; without them (nil) only a zero header CRC is
// accepted, since a non-zero one cannot be checked.
//
// Decoding a packet from the Ethernet layer calls this for RT_CLASS_3
// frames. Callers that use DecodeFromBytes directly, such as a
// DecodingLayerParser, can call it with the addresses of their Ethernet
// layer.
func (p *Profinet) DecodeSubframes(dst, src net.HardwareAddr) bool {
	p.Subframes = nil
	p.SubframeHeaderCRC = 0

	d := p.IOData
	if len(d) < profinetDFPCRCLen+profinetSubframeHeadLen {
		return false
	}

	// Header CRC: zero means unused, anything else must match.
	hdrCRC := binary.LittleEndian.Uint16(d)
	if hdrCRC != 0 {
		if len(dst) != profinetMACLen || len(src) != profinetMACLen {
			return false
		}
		if hdrCRC != ProfinetDFPHeaderCRC(dst, src, p.FrameID) {
			return false
		}
	}

	// A first subframe of position 0 and length 0 is no DFP frame.
	if binary.LittleEndian.Uint16(d[profinetDFPCRCLen:]) == 0 {
		return false
	}

	// Walk the chain once to validate and count it, then fill the list.
	n := countSubframes(d)
	if n < 0 {
		return false
	}

	p.SubframeHeaderCRC = hdrCRC
	p.Subframes = make([]ProfinetSubframe, n)
	off := profinetDFPCRCLen
	for i := range p.Subframes {
		sf := &p.Subframes[i]
		sf.Position = d[off] & profinetSubframePosMask
		sf.CRCFlag = d[off]&profinetSubframeCRCBit != 0
		sf.DataLength = d[off+1]
		sf.CycleCounter = d[off+2]
		sf.DataStatus = ProfinetDataStatus(d[off+3])

		end := off + profinetSubframeHeadLen + int(sf.DataLength)
		sf.Data = d[off+profinetSubframeHeadLen : end]
		sf.CRC = binary.LittleEndian.Uint16(d[end:])
		off = end + profinetDFPCRCLen
	}
	return true
}

// countSubframes validates the subframe chain behind the header CRC and
// returns the number of subframes before the terminator, or -1 when d is
// not a DFP frame. Each subframe takes at least 6 bytes, so the walk is
// bounded by len(d).
func countSubframes(d []byte) int {
	n := 0
	off := profinetDFPCRCLen
	for {
		if off+profinetSubframeEndLen > len(d) {
			return -1
		}

		start := off
		position, length := d[off], int(d[off+1])
		if length == 0 {
			return n
		}

		off += profinetSubframeHeadLen + length
		if off+profinetDFPCRCLen > len(d) {
			return -1
		}

		// A non-zero CRC counts only when the position byte asks for it.
		crc := binary.LittleEndian.Uint16(d[off:])
		if crc != 0 && position&profinetSubframeCRCBit != 0 && crc != profinetCRC16(0, d[start:off]) {
			return -1
		}

		off += profinetDFPCRCLen
		n++
	}
}

// profinetFragKey identifies a reassembly: the two stations and the
// fragment ID in the low nibble of the Frame ID.
type profinetFragKey struct {
	src, dst [profinetMACLen]byte
	id       uint8
}

// profinetFragState is a reassembly in progress.
type profinetFragState struct {
	data []byte
	next uint8  // fragment number expected next
	seq  uint64 // when the reassembly started, for eviction
}

// ProfinetFragAssembler reassembles fragmented PROFINET frames.
//
// It keeps one reassembly per source, destination and fragment ID. A
// reassembly starts at fragment number 0 and takes fragments in order;
// anything else drops it. Memory is bounded: each reassembly holds at most
// MaxSize bytes and at most 64 run at once, the oldest making room for a
// new one. There are no timers; a reassembly that never completes stays
// until it is evicted or its key starts over.
//
// An assembler is not safe for concurrent use.
type ProfinetFragAssembler struct {
	// MaxSize caps the bytes of one reassembled frame.
	MaxSize int

	states map[profinetFragKey]*profinetFragState
	seq    uint64
}

// NewProfinetFragAssembler returns an assembler that caps each reassembled
// frame at maxSize bytes; a value of zero or less selects 9216.
func NewProfinetFragAssembler(maxSize int) *ProfinetFragAssembler {
	if maxSize <= 0 {
		maxSize = profinetFragDefaultMax
	}
	return &ProfinetFragAssembler{MaxSize: maxSize, states: map[profinetFragKey]*profinetFragState{}}
}

// Add feeds one fragment frame, given the Ethernet addresses it travelled
// between. It returns nil while fragments are missing and, with the last
// fragment, the reassembled bytes: a 2-byte EtherType followed by that
// protocol's payload, in a buffer the caller owns. To decode it:
//
//	etherType := EthernetType(binary.BigEndian.Uint16(frame))
//	pkt := gopacket.NewPacket(frame[2:], etherType.LayerType(), gopacket.Default)
//
// Like Wireshark, the fragment is taken to be everything after the
// header, and must be at least FragDataLength*8 bytes.
func (a *ProfinetFragAssembler) Add(src, dst net.HardwareAddr, pn *Profinet) ([]byte, error) {
	if pn.FrameID.Class() != ProfinetFrameClassFragment {
		return nil, ErrProfinetNotFragment
	}

	key := profinetFragKey{id: uint8(pn.FrameID & profinetFragIDMask)}
	copy(key.src[:], src)
	copy(key.dst[:], dst)

	frag := pn.LayerPayload()
	if len(frag) < int(pn.FragDataLength)*profinetFragUnit {
		delete(a.states, key)
		return nil, ErrProfinetFragShort
	}

	st := a.state(key, pn.FragStatus.Number())
	if st == nil {
		return nil, ErrProfinetFragOrder
	}

	if len(st.data)+len(frag) > a.MaxSize {
		delete(a.states, key)
		return nil, ErrProfinetFragTooBig
	}
	st.data = append(st.data, frag...)
	st.next++

	if pn.FragStatus.MoreFollows() {
		return nil, nil
	}

	delete(a.states, key)
	return st.data, nil
}

// state returns the reassembly a fragment with the given number belongs
// to, or nil when the fragment does not fit. Number 0 always starts over.
func (a *ProfinetFragAssembler) state(key profinetFragKey, number uint8) *profinetFragState {
	if a.states == nil {
		a.states = map[profinetFragKey]*profinetFragState{}
	}
	if a.MaxSize <= 0 {
		a.MaxSize = profinetFragDefaultMax
	}

	st := a.states[key]
	if number != 0 {
		if st != nil && st.next == number {
			return st
		}
		delete(a.states, key)
		return nil
	}

	if st == nil && len(a.states) >= profinetFragMaxReassembly {
		a.evict()
	}

	a.seq++
	st = &profinetFragState{seq: a.seq}
	a.states[key] = st
	return st
}

// evict drops the oldest reassembly.
func (a *ProfinetFragAssembler) evict() {
	var oldest profinetFragKey
	first := true
	for key, st := range a.states {
		if first || st.seq < a.states[oldest].seq {
			oldest, first = key, false
		}
	}
	delete(a.states, oldest)
}

// Pending returns the number of reassemblies in progress.
func (a *ProfinetFragAssembler) Pending() int { return len(a.states) }
