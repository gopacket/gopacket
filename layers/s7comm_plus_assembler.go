// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"fmt"
)

// A PDU too large for one TPDU is sent as several frames. Each repeats
// the frame header (and, in V3, has its own integrity part); only the
// first has the data header and only the last the trailer. Nothing
// else marks a fragment, so the trailer alone drives the joining:
//
//	72 v len|head|part 1   72 v len|part 2   72 v len|part 3|72 v 0
//	          \______________ S7CommPlusAssembler.Feed ____________/
//	                     head|part 1 part 2 part 3| -> DecodeBody
//
// A SetVarSubStreamed request differs: its first frame holds a whole
// body, and each later frame a length-prefixed piece of the stream,
// the last one followed by the integrity part.
//
//	72 v len|head|body   72 v len|n|piece 1   72 v len|n|piece 2|tail|72 v 0

// S7CommPlusDefaultMaxPDU is the PDU size cap of an
// S7CommPlusAssembler whose MaxSize is zero: 1 MiB.
const S7CommPlusDefaultMaxPDU = 1 << 20

var (
	// ErrS7CommPlusPDUTooLong is returned by S7CommPlusAssembler.Feed
	// when the frames of a PDU exceed the assembler's size cap.
	ErrS7CommPlusPDUTooLong = errors.New("S7comm-plus PDU above the assembler size cap")

	// ErrS7CommPlusNoStart is returned by S7CommPlusAssembler.Feed for a
	// frame that continues a PDU whose first frame was not fed.
	ErrS7CommPlusNoStart = errors.New("S7comm-plus fragment without a first frame")
)

// S7CommPlusPDU is a whole PDU: the header fields of its first frame,
// the trailer of its last, and in Data the joined body after the data
// header, which DecodeBody decodes.
type S7CommPlusPDU struct {
	S7CommPlus

	// Frames counts the frames the PDU came in.
	Frames int

	// Stream holds the pieces a SetVarSubStreamed request sent after its
	// first frame, StreamTail what followed the last piece (integrity
	// part and fill). They are not part of Data.
	Stream     []byte
	StreamTail []byte
}

// s7plusJoin is what an S7CommPlusAssembler is doing between frames.
type s7plusJoin uint8

const (
	s7plusJoinIdle s7plusJoin = iota
	// s7plusJoinBody appends frame bodies to Data.
	s7plusJoinBody
	// s7plusJoinStream appends length-prefixed pieces to Stream.
	s7plusJoinStream
	// s7plusJoinSkip drops frames up to the next trailer: the PDU was
	// too long, malformed, or had no first frame.
	s7plusJoinSkip
)

// S7CommPlusAssembler joins the frames of one direction of a
// connection into PDUs. The zero value is ready to use. It holds at
// most MaxSize octets and is not safe for concurrent use.
//
// Frames must be fed in order; the protocol numbers PDUs, not frames,
// so a frame out of order cannot be told from one in order. Feed the
// S7comm-plus layer of every TPDU of the direction, after TCP
// reassembly.
type S7CommPlusAssembler struct {
	// MaxSize caps the body and stream of a PDU in octets. Zero or less
	// means S7CommPlusDefaultMaxPDU.
	MaxSize int

	state s7plusJoin
	pdu   *S7CommPlusPDU
}

// Feed takes the next frame of the direction. When s completes a PDU,
// Feed returns it; otherwise it returns nil.
//
// A PDU that came in one frame aliases s. A joined PDU owns its Data
// and Stream. System events (version S7CommPlusKeepAlive) are whole by
// themselves and do not disturb an unfinished PDU.
//
// A PDU above the size cap returns ErrS7CommPlusPDUTooLong once, and a
// frame without a data header where a first frame is due returns
// ErrS7CommPlusNoStart once; the frames up to the next trailer are
// then skipped.
func (a *S7CommPlusAssembler) Feed(s *S7CommPlus) (*S7CommPlusPDU, error) {
	if s == nil {
		return nil, nil
	}
	if s.Version == S7CommPlusKeepAlive {
		return &S7CommPlusPDU{S7CommPlus: *s, Frames: 1}, nil
	}

	switch a.state {
	case s7plusJoinBody, s7plusJoinStream:
		return a.next(s)
	case s7plusJoinSkip:
		if s.HasTrailer {
			a.Reset()
		}
		return nil, nil
	}
	return a.first(s)
}

// Pending returns the octets held for an unfinished PDU.
func (a *S7CommPlusAssembler) Pending() int {
	if a.pdu == nil {
		return 0
	}
	return len(a.pdu.Data) + len(a.pdu.Stream)
}

// Reset drops an unfinished PDU.
func (a *S7CommPlusAssembler) Reset() {
	a.state, a.pdu = s7plusJoinIdle, nil
}

// limit returns the size cap in effect.
func (a *S7CommPlusAssembler) limit() int {
	if a.MaxSize <= 0 {
		return S7CommPlusDefaultMaxPDU
	}
	return a.MaxSize
}

// skip drops the unfinished PDU and, unless s ends it, the frames up
// to the next trailer.
func (a *S7CommPlusAssembler) skip(s *S7CommPlus, err error) (*S7CommPlusPDU, error) {
	a.Reset()
	if !s.HasTrailer {
		a.state = s7plusJoinSkip
	}
	return nil, err
}

// first handles a frame fed while no PDU is unfinished.
func (a *S7CommPlusAssembler) first(s *S7CommPlus) (*S7CommPlusPDU, error) {
	if !s.HasDataHeader {
		return a.skip(s, ErrS7CommPlusNoStart)
	}
	if s.HasTrailer {
		return &S7CommPlusPDU{S7CommPlus: *s, Frames: 1}, nil
	}
	if len(s.Data) > a.limit() {
		return a.skip(s, fmt.Errorf("%w: %d octets, limit %d", ErrS7CommPlusPDUTooLong, len(s.Data), a.limit()))
	}

	// The frame's buffer may be reused before the PDU is whole.
	a.pdu = &S7CommPlusPDU{S7CommPlus: *s, Frames: 1}
	a.pdu.Data = append([]byte(nil), s.Data...)
	a.pdu.BaseLayer = BaseLayer{}

	a.state = s7plusJoinBody
	if s.Opcode == S7CommPlusOpRequest && s.Function == S7CommPlusFuncSetVarSubStreamed {
		a.state = s7plusJoinStream
	}
	return nil, nil
}

// next adds a frame to the unfinished PDU and returns the PDU when the
// frame has the trailer.
func (a *S7CommPlusAssembler) next(s *S7CommPlus) (*S7CommPlusPDU, error) {
	p := a.pdu
	part := s.rawBody()

	var tail []byte
	if a.state == s7plusJoinStream {
		n, used, err := S7CommPlusVarUint32(part)
		if err != nil || uint64(n) > uint64(len(part)-used) {
			return a.skip(s, fmt.Errorf("%w: stream piece of %d octets in %d", ErrS7CommPlusMalformed, n, len(part)))
		}
		part, tail = part[used:used+int(n)], part[used+int(n):]
	}

	if len(part) > a.limit()-a.Pending() {
		return a.skip(s, fmt.Errorf("%w: %d octets, limit %d", ErrS7CommPlusPDUTooLong, a.Pending()+len(part), a.limit()))
	}
	if a.state == s7plusJoinStream {
		p.Stream = append(p.Stream, part...)
	} else {
		p.Data = append(p.Data, part...)
	}
	p.Frames++

	if !s.HasTrailer {
		return nil, nil
	}

	p.StreamTail = append([]byte(nil), tail...)
	p.HasTrailer, p.TrailerVersion, p.TrailerLength = true, s.TrailerVersion, s.TrailerLength
	a.Reset()
	return p, nil
}

// rawBody returns the frame body after the V3 integrity part, with the
// octets a data header was read from: in a continuation frame those
// are data. A frame that was not decoded from bytes has only Data.
func (s *S7CommPlus) rawBody() []byte {
	end := s7plusHeaderLen + int(s.DataLength)
	if len(s.Contents) < end {
		return s.Data
	}

	body := s.Contents[s7plusHeaderLen:end]
	if s.Version != S7CommPlusV3 || len(body) == 0 {
		return body
	}

	// Length octet and digest, as decodeIntegrity split them off.
	skip := 1 + len(s.Integrity)
	if skip > len(body) {
		return s.Data
	}
	return body[skip:]
}
