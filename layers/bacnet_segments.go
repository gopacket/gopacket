// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// Reassembly of segmented BACnet APDUs (ASHRAE 135 Clause 5.2, 20.1.2).

package layers

import (
	"bytes"
	"errors"

	"github.com/gopacket/gopacket"
)

// Limits of a BACnetSegmentAssembler left at its zero value.
const (
	// BACnetSegmentDefaultMaxSize caps one reassembled APDU, in octets.
	BACnetSegmentDefaultMaxSize = 1 << 20
	// BACnetSegmentDefaultMaxPending caps the messages in reassembly.
	BACnetSegmentDefaultMaxPending = 64

	// bacnetSegmentAhead is how far ahead of the next expected sequence
	// number a segment may be and still be kept; the largest window
	// (Clause 20.1.2.8). Anything further is a duplicate.
	bacnetSegmentAhead = 127
)

// ErrBACnetSegmentsTooLarge is returned when a segmented message outgrows
// the MaxSize of its assembler; the message is dropped.
var ErrBACnetSegmentsTooLarge = errors.New("BACnet segmented message exceeds the size cap")

// bacnetSegmentKey names one segmented message: the sender, the invoke
// ID, and the direction, which the PDU type gives (a request goes to the
// server, a ComplexACK comes from it).
type bacnetSegmentKey struct {
	source   string
	invokeID uint8
	pduType  BACnetPDUType
}

// bacnetSegments is a message in reassembly.
type bacnetSegments struct {
	// buf is the unsegmented header followed by the in-order data.
	buf []byte
	// held are the segments that arrived ahead of next.
	held map[uint8][]byte
	// size counts the data octets in buf and held.
	size int
	next uint8
	// zeroAt is where the data of the latest segment numbered 0 starts
	// in buf: segment 0, 256, 512 and so on.
	zeroAt int
	// last is the sequence number of the final segment, once seen.
	last     uint8
	sawLast  bool
	lastSeen uint64
}

// BACnetSegmentAssembler joins the segments of segmented BACnet APDUs
// into whole ones. Messages are told apart by source address, invoke ID
// and direction; their segments are joined in sequence number order,
// duplicates are ignored, and segments that overtake others are held
// until the gap closes.
//
// Memory is bounded: a message that would exceed MaxSize is dropped, and
// starting one more than MaxPending messages drops the one that has been
// silent the longest, so at most MaxSize*MaxPending octets are held. The
// zero value is ready to use. An assembler is not safe for concurrent use.
type BACnetSegmentAssembler struct {
	// MaxSize caps the service data of one message, in octets; 0 means
	// BACnetSegmentDefaultMaxSize.
	MaxSize int
	// MaxPending caps the messages in reassembly; 0 means
	// BACnetSegmentDefaultMaxPending.
	MaxPending int

	pending map[bacnetSegmentKey]*bacnetSegments
	clock   uint64
}

// NewBACnetSegmentAssembler returns an assembler with the default limits.
func NewBACnetSegmentAssembler() *BACnetSegmentAssembler {
	return &BACnetSegmentAssembler{}
}

// Pending returns the number of messages in reassembly.
func (s *BACnetSegmentAssembler) Pending() int { return len(s.pending) }

// Add takes one decoded APDU sent from the source address (the octets of
// the IP, MAC or NPDU source address, as long as it is the same choice
// for every call). An unsegmented APDU is returned as it is. A segment
// returns nil until it completes its message, and then the whole APDU,
// decoded as if it had been sent unsegmented, in memory of its own.
//
// The error is ErrBACnetSegmentsTooLarge, or what decoding the joined
// message gave.
func (s *BACnetSegmentAssembler) Add(source []byte, a *BACnetAPDU) (*BACnetAPDU, error) {
	if a == nil || !a.Segmented {
		return a, nil
	}

	key := bacnetSegmentKey{source: string(source), invokeID: a.InvokeID, pduType: a.PDUType}
	m := s.message(key, a)
	if m == nil {
		return nil, nil
	}
	s.clock++
	m.lastSeen = s.clock

	// 0 is the segment awaited; up to bacnetSegmentAhead is one that
	// overtook it; the rest of the octet wraps around to the past.
	ahead := a.SequenceNumber - m.next
	if ahead > bacnetSegmentAhead {
		return nil, nil
	}
	if _, dup := m.held[a.SequenceNumber]; dup {
		return nil, nil
	}

	if m.size+len(a.Parameters) > s.maxSize() {
		delete(s.pending, key)
		return nil, ErrBACnetSegmentsTooLarge
	}
	m.size += len(a.Parameters)

	if !a.MoreFollows {
		m.last, m.sawLast = a.SequenceNumber, true
	}
	if ahead != 0 {
		m.hold(a)
		return nil, nil
	}
	m.join(a.Parameters)
	m.drain()

	if !m.sawLast || m.next != m.last+1 {
		return nil, nil
	}
	delete(s.pending, key)

	whole := &BACnetAPDU{}
	if err := whole.DecodeFromBytes(m.buf, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}
	return whole, nil
}

// message returns the message the segment belongs to, starting one for a
// first segment. It returns nil for a segment of a message whose start
// was not seen.
func (s *BACnetSegmentAssembler) message(key bacnetSegmentKey, a *BACnetAPDU) *bacnetSegments {
	m := s.pending[key]

	restart := a.SequenceNumber == 0 && (m == nil || m.abandonedBy(a))
	if !restart {
		return m
	}

	if s.pending == nil {
		s.pending = make(map[bacnetSegmentKey]*bacnetSegments)
	}
	if m == nil && len(s.pending) >= s.maxPending() {
		s.evict()
	}
	m = &bacnetSegments{buf: bacnetWholeHeader(a)}
	m.zeroAt = len(m.buf)
	s.pending[key] = m
	return m
}

// evict drops the message that has been silent the longest.
func (s *BACnetSegmentAssembler) evict() {
	var oldest bacnetSegmentKey
	found := false

	for key, m := range s.pending {
		if !found || m.lastSeen < s.pending[oldest].lastSeen {
			oldest, found = key, true
		}
	}
	if found {
		delete(s.pending, oldest)
	}
}

func (s *BACnetSegmentAssembler) maxSize() int {
	if s.MaxSize > 0 {
		return s.MaxSize
	}
	return BACnetSegmentDefaultMaxSize
}

func (s *BACnetSegmentAssembler) maxPending() int {
	if s.MaxPending > 0 {
		return s.MaxPending
	}
	return BACnetSegmentDefaultMaxPending
}

// abandonedBy reports whether a segment numbered 0 starts a new message
// in place of m, the invoke ID being in use again. It does not when the
// sequence number has wrapped (segment 256 is numbered 0 too) or when the
// segment is one already joined, sent again.
//
//	next 0, 129..255: 0 is awaited or overtook others    -> same message
//	next 1..128:      0 is past; data equal to that kept -> sent again
//	                                 other data          -> new message
func (m *bacnetSegments) abandonedBy(a *BACnetAPDU) bool {
	if ahead := -m.next; ahead <= bacnetSegmentAhead {
		return false
	}
	return !bytes.HasPrefix(m.buf[m.zeroAt:], a.Parameters)
}

// join appends the data of the segment awaited.
func (m *bacnetSegments) join(data []byte) {
	if m.next == 0 {
		m.zeroAt = len(m.buf)
	}
	m.buf = append(m.buf, data...)
	m.next++
}

// hold keeps a copy of a segment that arrived early.
func (m *bacnetSegments) hold(a *BACnetAPDU) {
	if m.held == nil {
		m.held = make(map[uint8][]byte)
	}
	m.held[a.SequenceNumber] = append([]byte(nil), a.Parameters...)
}

// drain appends the held segments that now follow in sequence.
func (m *bacnetSegments) drain() {
	for len(m.held) > 0 {
		data, ok := m.held[m.next]
		if !ok {
			return
		}
		delete(m.held, m.next)
		m.join(data)
	}
}

// bacnetWholeHeader returns the header the segmented message would have
// had unsegmented: the segment flags cleared, the sequence number and
// window size left out.
//
//	segmented:   type|SEG|MOR|SA  [max]  invoke  seq  window  service
//	unsegmented: type|SA          [max]  invoke               service
func bacnetWholeHeader(a *BACnetAPDU) []byte {
	const segmentFlags = bacnetPDUFlagSEG | bacnetPDUFlagMOR

	hdr := a.Contents
	fixed := len(hdr) - bacnetSegmentHeaderLen - 1
	if fixed < 1 {
		return nil
	}

	buf := make([]byte, 0, len(hdr)-bacnetSegmentHeaderLen+len(a.Parameters))
	buf = append(buf, hdr[0]&^segmentFlags)
	buf = append(buf, hdr[1:fixed]...)
	return append(buf, hdr[len(hdr)-1])
}
