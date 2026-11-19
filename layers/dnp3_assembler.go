// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"container/list"
	"errors"
	"fmt"
)

// A DNP3Assembler joins the transport segments of application fragments
// and decodes each fragment whole, so objects that cross a link frame
// decode:
//
//	link frames, one stream per source, destination and DIR bit
//	+-----------------+  +-----------------+  +-----------------+
//	| TH FIR seq 5    |  | TH seq 6        |  | TH FIN seq 7    |
//	| AC FC objects.. |  | ..objects..     |  | ..objects       |
//	+-----------------+  +-----------------+  +-----------------+
//	         \                   |                   /
//	          +------ DNP3Fragment.Data: AC FC objects ------+
//	                             |
//	          DNP3Fragment.Application, decoded as one fragment
//
// A response too long for one fragment is sent as several, each a
// complete fragment of its own (IEEE 1815-2012 clause 4.2.2.5): no
// object crosses a fragment. The assembler does not join their bytes;
// it lists the fragments of such a message in order in
// DNP3Fragment.Message when the last one arrives.

// Default limits of a DNP3Assembler.
const (
	// DNP3MaxFragment is the largest application fragment devices are
	// required to accept (IEEE 1815-2012 clause 4.2.2.5).
	DNP3MaxFragment = 2048
	// DNP3MaxStreams is the default number of streams tracked at once.
	DNP3MaxStreams = 256
	// DNP3MaxMessage is the default number of fragments kept of one
	// application message.
	DNP3MaxMessage = 16
)

// Errors returned by DNP3Assembler.Add. Each names why a frame, and the
// fragment it belonged to, was dropped.
var (
	ErrDNP3AsmBadCRC   = errors.New("DNP3 assembler: frame fails its CRC")
	ErrDNP3AsmNoStart  = errors.New("DNP3 assembler: segment without a fragment in progress")
	ErrDNP3AsmSequence = errors.New("DNP3 assembler: transport sequence number out of order")
	ErrDNP3AsmTooLong  = errors.New("DNP3 assembler: fragment exceeds the size limit")
	ErrDNP3AsmMessage  = errors.New("DNP3 assembler: application fragment out of order or past the message limit")
)

// DNP3CRCPolicy says what a DNP3Assembler does with a frame that fails
// a CRC.
type DNP3CRCPolicy uint8

// DNP3CRCPolicy values.
const (
	// DNP3CRCDrop drops the frame and the fragment in progress, as a
	// device does. It is the default.
	DNP3CRCDrop DNP3CRCPolicy = iota
	// DNP3CRCKeep assembles the frame all the same, e.g. for captures
	// whose checksums were rewritten.
	DNP3CRCKeep
)

// DNP3Fragment is one application fragment, assembled.
//
// Application is the fragment decoded whole. Err is the error of that
// decode: the fragment is still returned, with the part that decoded.
//
// Message is set on the fragment that ends an application message
// (application FIN): the decoded fragments of the message in order,
// this one last, also when the message is this fragment alone. It is
// nil when the start of the message was not seen or its fragments
// arrived out of order. Objects of one fragment never continue in the
// next, so nothing is joined across them.
type DNP3Fragment struct {
	Source      uint16
	Destination uint16
	Dir         bool // sent by a master
	Segments    int  // link frames the fragment came in
	Data        []byte
	Application *DNP3Application
	Err         error
	Message     []*DNP3Application
}

// dnp3StreamKey names one direction of one link.
type dnp3StreamKey struct {
	src, dst uint16
	dir      bool
}

// dnp3Message collects the fragments of one application message.
type dnp3Message struct {
	apps []*DNP3Application
	seq  uint8 // application sequence number of the last fragment
}

// dnp3Stream is the state of one direction of one link.
type dnp3Stream struct {
	key      dnp3StreamKey
	buf      []byte
	segments int
	seq      uint8 // transport sequence number of the last segment
	active   bool  // a fragment is in progress
	last     []byte

	// Solicited and unsolicited responses interleave, each with its
	// own sequence numbers.
	msgs [2]dnp3Message
}

// DNP3Assembler assembles the application fragments of any number of
// DNP3 links. The zero value is ready to use with the default limits.
// It is not safe for concurrent use.
//
// Memory is bounded: at most MaxStreams streams, each holding one
// fragment of at most MaxFragment bytes in progress and at most
// MaxMessage decoded fragments of a message. The stream idle the
// longest is dropped to make room for a new one.
type DNP3Assembler struct {
	// MaxFragment caps the bytes of one fragment. 0 means
	// DNP3MaxFragment.
	MaxFragment int
	// MaxStreams caps the streams tracked at once. 0 means
	// DNP3MaxStreams.
	MaxStreams int
	// MaxMessage caps the fragments kept of one application message. 0
	// means DNP3MaxMessage.
	MaxMessage int
	// CRC says what to do with frames that fail a CRC.
	CRC DNP3CRCPolicy

	streams map[dnp3StreamKey]*list.Element
	order   list.List // of *dnp3Stream, most recently used first
}

// dnp3Limit returns v, or def when v is not positive.
func dnp3Limit(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// Streams returns how many streams the assembler tracks.
func (a *DNP3Assembler) Streams() int {
	return len(a.streams)
}

// Add takes the next link frame of a capture, in order, and returns the
// fragment it completes. It returns nil, nil for a frame that completes
// none: a link control frame, or a segment of a fragment still in
// progress. It returns an error when the frame is dropped; the
// assembler then waits for the next start of a fragment on that stream.
//
// d may be reused after Add returns: its user data is copied.
func (a *DNP3Assembler) Add(d *DNP3) (*DNP3Fragment, error) {
	if d == nil || !d.Link.Function.carriesData() || len(d.UserData) == 0 {
		return nil, nil
	}

	s := a.stream(dnp3StreamKey{src: d.Link.Source, dst: d.Link.Destination, dir: d.Link.Dir})
	if a.CRC == DNP3CRCDrop && !d.CRCValid() {
		s.reset()
		return nil, ErrDNP3AsmBadCRC
	}

	if err := s.add(d, dnp3Limit(a.MaxFragment, DNP3MaxFragment)); err != nil {
		return nil, err
	}

	if !d.Transport.FIN {
		return nil, nil
	}

	f := &DNP3Fragment{Source: s.key.src, Destination: s.key.dst, Dir: s.key.dir, Segments: s.segments, Data: s.buf}
	s.buf, s.active, s.last = nil, false, nil

	f.Application = &DNP3Application{}
	f.Err = f.Application.decode(f.Data, dnp3LastSegment)
	if len(f.Data) < dnp3AppHeaderLen {
		return f, nil
	}

	msg, err := s.track(f.Application, dnp3Limit(a.MaxMessage, DNP3MaxMessage))
	f.Message = msg
	if f.Err == nil {
		f.Err = err
	}
	return f, nil
}

// stream returns the state of key, most recently used first, dropping
// the stream idle the longest when a new one would pass the cap.
func (a *DNP3Assembler) stream(key dnp3StreamKey) *dnp3Stream {
	if e, ok := a.streams[key]; ok {
		a.order.MoveToFront(e)
		return e.Value.(*dnp3Stream)
	}

	if a.streams == nil {
		a.streams = make(map[dnp3StreamKey]*list.Element)
	}

	for limit := dnp3Limit(a.MaxStreams, DNP3MaxStreams); len(a.streams) >= limit; {
		oldest := a.order.Back()
		delete(a.streams, oldest.Value.(*dnp3Stream).key)
		a.order.Remove(oldest)
	}

	s := &dnp3Stream{key: key}
	a.streams[key] = a.order.PushFront(s)
	return s
}

// reset drops the fragment in progress.
func (s *dnp3Stream) reset() {
	s.buf, s.active, s.segments, s.last = nil, false, 0, nil
}

// add appends the segment of d to the fragment in progress, following
// the reception rules of IEEE 1815-2012 clause 8.2.3: FIR starts a
// fragment and drops one in progress, any other segment must carry the
// next sequence number, modulo 64, and a repeat of the last segment is
// ignored.
func (s *dnp3Stream) add(d *DNP3, limit int) error {
	seg := d.UserData[1:]
	th := d.Transport

	switch {
	case th.FIR:
		s.reset()
		s.active = true
	case !s.active:
		return ErrDNP3AsmNoStart
	case th.Seq == s.seq && string(seg) == string(s.last):
		return nil
	case th.Seq != (s.seq+1)&dnp3TrSeq:
		got, want := th.Seq, (s.seq+1)&dnp3TrSeq
		s.reset()
		return fmt.Errorf("%w: got %d, want %d", ErrDNP3AsmSequence, got, want)
	}

	if len(s.buf)+len(seg) > limit {
		s.reset()
		return fmt.Errorf("%w: %d bytes", ErrDNP3AsmTooLong, limit)
	}

	// The copy outlives d, whose buffer the next decode reuses.
	start := len(s.buf)
	s.buf = append(s.buf, seg...)
	s.last = s.buf[start:]
	s.seq = th.Seq
	s.segments++
	return nil
}

// track files app with the message it belongs to and returns the
// message once app ends it. Requests are one fragment each. A response
// that starts a message replaces one left unfinished.
func (s *dnp3Stream) track(app *DNP3Application, limit int) ([]*DNP3Application, error) {
	slot := 0
	if app.Control.UNS {
		slot = 1
	}
	m := &s.msgs[slot]

	switch {
	case app.Control.FIR:
		m.apps = nil
	case len(m.apps) == 0:
		return nil, ErrDNP3AsmMessage
	case app.Control.Seq != (m.seq+1)&dnp3AcSeq || len(m.apps) >= limit:
		m.apps = nil
		return nil, ErrDNP3AsmMessage
	}

	m.apps = append(m.apps, app)
	m.seq = app.Control.Seq
	if !app.Control.FIN {
		return nil, nil
	}

	out := m.apps
	m.apps = nil
	return out, nil
}
