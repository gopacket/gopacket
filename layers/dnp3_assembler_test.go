// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gopacket/gopacket"
)

// Transport header bits of the test segments.
const (
	testDNP3FIR = 0x40
	testDNP3FIN = 0x80
)

// dnp3Outstation builds an unconfirmed user data frame from outstation
// 4 to master 3 with transport header th and user data seg.
func dnp3Outstation(th byte, seg []byte) []byte {
	return dnp3Frame(0x44, 3, 4, append([]byte{th}, seg...))
}

// dnp3Split cuts an application fragment into transport segments of at
// most size bytes, numbered from seq, each in its own link frame.
func dnp3Split(app []byte, size int, seq byte) [][]byte {
	var out [][]byte
	for off := 0; off < len(app); off += size {
		end := min(off+size, len(app))
		th := seq & dnp3TrSeq
		if off == 0 {
			th |= testDNP3FIR
		}
		if end == len(app) {
			th |= testDNP3FIN
		}

		out = append(out, dnp3Outstation(th, app[off:end]))
		seq++
	}
	return out
}

// testDNP3BigResponse is a response with 60 g30v1 analog inputs, 305
// bytes, then one g1v2 binary input: more than one link frame holds.
func testDNP3BigResponse(ac byte) []byte {
	app := []byte{ac, 0x81, 0x00, 0x00, 30, 1, 0x00, 0, 59}
	for i := 0; i < 60; i++ {
		app = append(app, 0x01, byte(i), 0, 0, 0)
	}
	return append(app, 1, 2, 0x00, 7, 7, 0x81)
}

// dnp3AddAll feeds frames to a and returns the fragments and errors.
func dnp3AddAll(t *testing.T, a *DNP3Assembler, frames [][]byte) ([]*DNP3Fragment, []error) {
	t.Helper()

	var frags []*DNP3Fragment
	var errs []error
	var d DNP3
	for _, frame := range frames {
		if err := d.decodeFrame(frame, gopacket.NilDecodeFeedback); err != nil {
			t.Fatalf("frame %x: %v", frame, err)
		}

		f, err := a.Add(&d)
		if f != nil {
			frags = append(frags, f)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return frags, errs
}

// Objects that cross a link frame stop the parse of the frame and
// decode once the fragment is assembled. tshark 4.7 reassembles these
// frames to the same 61 points.
func TestDNP3Assemble(t *testing.T) {
	app := testDNP3BigResponse(0xc0)
	frames := dnp3Split(app, 100, 62)
	if len(frames) != 4 {
		t.Fatalf("%d frames", len(frames))
	}

	// Frame by frame: only the first has an application layer, and its
	// one header is cut.
	var d DNP3
	if err := d.DecodeFromBytes(frames[0], gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if a := d.Application; len(a.Objects) != 1 || a.Objects[0].State != DNP3HeaderTruncated || len(a.Objects[0].Objects) != 0 {
		t.Errorf("first frame alone: %+v", a.Objects)
	}

	var asm DNP3Assembler
	frags, errs := dnp3AddAll(t, &asm, frames)
	if len(frags) != 1 || len(errs) != 0 {
		t.Fatalf("fragments %d errors %v", len(frags), errs)
	}

	f := frags[0]
	if f.Source != 4 || f.Destination != 3 || f.Dir || f.Segments != 4 || !bytes.Equal(f.Data, app) || f.Err != nil {
		t.Fatalf("%+v", f)
	}

	a := f.Application
	if dnp3ObjectList(a) != "0x1e01,0x0102" || len(a.Objects[0].Objects) != 60 || len(a.Unparsed) != 0 {
		t.Fatalf("objects %q, %d points, unparsed %x", dnp3ObjectList(a), len(a.Objects[0].Objects), a.Unparsed)
	}

	// Point 21 sits astride frames 1 and 2 (bytes 100 and 200 of app).
	v, err := a.Objects[0].Value(21)
	if err != nil || v != (DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogInput, 1), Value: 21, Format: DNP3NumInt32}) {
		t.Errorf("point 21: %+v, %v", v, err)
	}

	if len(f.Message) != 1 || f.Message[0] != a {
		t.Errorf("message %v", f.Message)
	}

	// The decoder's buffer is reused: the fragment must not alias it.
	_ = d.DecodeFromBytes(dnp3Master(0xc0, bytes.Repeat([]byte{0xff}, 200)...), gopacket.NilDecodeFeedback)
	if !bytes.Equal(f.Data, app) {
		t.Error("fragment data changed by a later decode")
	}
}

func TestDNP3AssembleErrors(t *testing.T) {
	app := testDNP3BigResponse(0xc0)
	fr := dnp3Split(app, 100, 62)
	ack := dnp3Frame(0x00, 3, 4, nil)

	tests := []struct {
		name   string
		frames [][]byte
		frags  int
		errs   []error
	}{
		{"in order, sequence wraps 63 to 0", fr, 1, nil},
		{"link control frames between", [][]byte{fr[0], ack, fr[1], ack, fr[2], fr[3]}, 1, nil},
		{"repeated segment ignored", [][]byte{fr[0], fr[1], fr[1], fr[2], fr[3]}, 1, nil},
		{"no start", fr[1:], 0, []error{ErrDNP3AsmNoStart, ErrDNP3AsmNoStart, ErrDNP3AsmNoStart}},
		{"gap", [][]byte{fr[0], fr[2], fr[3]}, 0, []error{ErrDNP3AsmSequence, ErrDNP3AsmNoStart}},
		{"reordered", [][]byte{fr[0], fr[2], fr[1], fr[3]}, 0, []error{ErrDNP3AsmSequence, ErrDNP3AsmNoStart, ErrDNP3AsmNoStart}},
		{"restart drops the fragment in progress", [][]byte{fr[0], fr[1], fr[0], fr[1], fr[2], fr[3]}, 1, nil},
		{"after an error the next fragment assembles", [][]byte{fr[1], fr[0], fr[1], fr[2], fr[3]}, 1, []error{ErrDNP3AsmNoStart}},
		{"last segment repeated", append(fr[:4:4], fr[3]), 1, []error{ErrDNP3AsmNoStart}},
	}

	for _, tc := range tests {
		var asm DNP3Assembler
		frags, errs := dnp3AddAll(t, &asm, tc.frames)
		if len(frags) != tc.frags || len(errs) != len(tc.errs) {
			t.Errorf("%s: %d fragments, errors %v", tc.name, len(frags), errs)
			continue
		}

		for i, err := range errs {
			if !errors.Is(err, tc.errs[i]) {
				t.Errorf("%s: error %d: %v, want %v", tc.name, i, err, tc.errs[i])
			}
		}

		for _, f := range frags {
			if !bytes.Equal(f.Data, app) || f.Err != nil {
				t.Errorf("%s: data %x, %v", tc.name, f.Data, f.Err)
			}
		}
	}

	if f, err := (&DNP3Assembler{}).Add(nil); f != nil || err != nil {
		t.Errorf("nil frame: %v, %v", f, err)
	}
}

// A fragment past MaxFragment is dropped before its bytes are kept.
func TestDNP3AssembleLimits(t *testing.T) {
	app := testDNP3BigResponse(0xc0)
	fr := dnp3Split(app, 100, 0)

	asm := DNP3Assembler{MaxFragment: 250}
	frags, errs := dnp3AddAll(t, &asm, fr)
	if len(frags) != 0 || len(errs) != 2 || !errors.Is(errs[0], ErrDNP3AsmTooLong) || !errors.Is(errs[1], ErrDNP3AsmNoStart) {
		t.Errorf("limit 250: %d fragments, errors %v", len(frags), errs)
	}

	asm = DNP3Assembler{MaxFragment: len(app)}
	if frags, errs = dnp3AddAll(t, &asm, fr); len(frags) != 1 || len(errs) != 0 {
		t.Errorf("limit %d: %d fragments, errors %v", len(app), len(frags), errs)
	}

	// The default: 2048 bytes pass, 2049 do not.
	for size, want := range map[int]int{DNP3MaxFragment: 1, DNP3MaxFragment + 1: 0} {
		big := append([]byte{0xc0, 0x81, 0x00, 0x00, 110, 0xff}, make([]byte, size-6)...)
		var def DNP3Assembler
		if frags, _ = dnp3AddAll(t, &def, dnp3Split(big, 249, 0)); len(frags) != want {
			t.Errorf("%d bytes: %d fragments", size, len(frags))
		}
	}

	// Streams: one per source, destination and direction, the idle
	// one dropped at the cap.
	asm = DNP3Assembler{MaxStreams: 3}
	var d DNP3
	for src := uint16(1); src <= 100; src++ {
		_ = d.decodeFrame(dnp3Frame(0x44, 3, src, append([]byte{testDNP3FIR}, app[:50]...)), gopacket.NilDecodeFeedback)
		if f, err := asm.Add(&d); f != nil || err != nil || asm.Streams() > 3 {
			t.Fatalf("source %d: %v, %v, %d streams", src, f, err, asm.Streams())
		}
	}

	// Sources 98 to 100 are kept, 97 was dropped with its fragment.
	for src, want := range map[uint16]error{100: nil, 97: ErrDNP3AsmNoStart} {
		_ = d.decodeFrame(dnp3Frame(0x44, 3, src, append([]byte{testDNP3FIN | 1}, app[50:60]...)), gopacket.NilDecodeFeedback)
		if _, err := asm.Add(&d); !errors.Is(err, want) {
			t.Errorf("source %d: %v, want %v", src, err, want)
		}
	}

	// The two directions of a link do not mix.
	asm = DNP3Assembler{}
	_ = d.decodeFrame(dnp3Frame(0x44, 3, 4, append([]byte{testDNP3FIR}, app[:50]...)), gopacket.NilDecodeFeedback)
	_, _ = asm.Add(&d)
	_ = d.decodeFrame(dnp3Frame(0xc4, 3, 4, append([]byte{testDNP3FIN | 1}, app[50:60]...)), gopacket.NilDecodeFeedback)
	if _, err := asm.Add(&d); !errors.Is(err, ErrDNP3AsmNoStart) || asm.Streams() != 2 {
		t.Errorf("other direction: %v, %d streams", err, asm.Streams())
	}
}

func TestDNP3AssembleCRC(t *testing.T) {
	fr := dnp3Split(testDNP3BigResponse(0xc0), 100, 0)
	bad := bytes.Clone(fr[1])
	bad[dnp3HeaderLen+3] ^= 0xff

	var asm DNP3Assembler
	frags, errs := dnp3AddAll(t, &asm, [][]byte{fr[0], bad, fr[2], fr[3]})
	if len(frags) != 0 || len(errs) != 3 || !errors.Is(errs[0], ErrDNP3AsmBadCRC) {
		t.Errorf("drop: %d fragments, errors %v", len(frags), errs)
	}

	asm = DNP3Assembler{CRC: DNP3CRCKeep}
	if frags, errs = dnp3AddAll(t, &asm, [][]byte{fr[0], bad, fr[2], fr[3]}); len(frags) != 1 || len(errs) != 0 {
		t.Errorf("keep: %d fragments, errors %v", len(frags), errs)
	}
}

// A response in several fragments: each decodes alone, and the last
// lists them all in order.
func TestDNP3AssembleMessage(t *testing.T) {
	// Application control: FIR 0x80, FIN 0x40, UNS 0x10, sequence.
	first := dnp3Split(testDNP3BigResponse(0x80|5), 100, 0)
	mid := dnp3Split([]byte{0x00 | 6, 0x81, 0x00, 0x00, 1, 2, 0x00, 1, 1, 0x01}, 100, 4)
	last := dnp3Split([]byte{0x40 | 7, 0x81, 0x00, 0x00, 1, 2, 0x00, 2, 2, 0x81}, 100, 5)
	uns := dnp3Split([]byte{0xd0 | 2, 0x82, 0x00, 0x00, 2, 1, 0x17, 1, 9, 0x81}, 100, 9)

	var asm DNP3Assembler
	var frames [][]byte
	frames = append(frames, first...)
	frames = append(frames, uns...)
	frames = append(frames, mid...)
	frames = append(frames, last...)

	frags, errs := dnp3AddAll(t, &asm, frames)
	if len(frags) != 4 || len(errs) != 0 {
		t.Fatalf("%d fragments, errors %v", len(frags), errs)
	}

	// The unsolicited response is a message of its own.
	for i, want := range []int{0, 1, 0, 3} {
		if frags[i].Err != nil || len(frags[i].Message) != want {
			t.Errorf("fragment %d: %v, message of %d", i, frags[i].Err, len(frags[i].Message))
		}
	}

	msg := frags[3].Message
	if msg[0] != frags[0].Application || msg[1] != frags[2].Application || msg[2] != frags[3].Application {
		t.Error("message out of order")
	}

	points := 0
	for _, a := range msg {
		for _, h := range a.Objects {
			points += len(h.Objects)
		}
	}
	if points != 63 {
		t.Errorf("%d points in the message", points)
	}

	// Without its first fragment, out of order, or past the cap, a
	// message is not listed and Err says so.
	frags, _ = dnp3AddAll(t, &DNP3Assembler{}, append(mid[:1:1], last...))
	if len(frags) != 2 || !errors.Is(frags[0].Err, ErrDNP3AsmMessage) || !errors.Is(frags[1].Err, ErrDNP3AsmMessage) || frags[1].Message != nil {
		t.Errorf("no start: %+v", frags)
	}

	frags, _ = dnp3AddAll(t, &DNP3Assembler{}, append(first[:len(first):len(first)], last...))
	if len(frags) != 2 || frags[0].Err != nil || !errors.Is(frags[1].Err, ErrDNP3AsmMessage) || frags[1].Message != nil {
		t.Errorf("gap: %+v", frags)
	}

	frames = first[:len(first):len(first)]
	frames = append(frames, mid...)
	frames = append(frames, last...)
	frags, _ = dnp3AddAll(t, &DNP3Assembler{MaxMessage: 2}, frames)
	if len(frags) != 3 || frags[1].Err != nil || !errors.Is(frags[2].Err, ErrDNP3AsmMessage) || frags[2].Message != nil {
		t.Errorf("cap: %+v", frags)
	}

	// A malformed fragment is returned with what decoded and its error.
	frags, _ = dnp3AddAll(t, &DNP3Assembler{}, dnp3Split([]byte{0xc0, 0x81, 0x00, 0x00, 30, 1, 0x00, 0, 5, 1, 2}, 100, 0))
	if len(frags) != 1 || !errors.Is(frags[0].Err, ErrDNP3ObjTruncated) || len(frags[0].Application.Objects) != 1 {
		t.Errorf("malformed: %+v", frags)
	}

	frags, _ = dnp3AddAll(t, &DNP3Assembler{}, dnp3Split([]byte{0xc0}, 100, 0))
	if len(frags) != 1 || !errors.Is(frags[0].Err, ErrDNP3AppTooShort) || frags[0].Message != nil {
		t.Errorf("short: %+v", frags)
	}
}

// Every frame of the test captures is a whole fragment: the assembler
// must return the objects the frame decode shows, for each of them.
// tshark 4.7 lists 88 and 18 object headers; the 12 more of dnp3.pcap
// are in four STOP_APPL requests, whose objects it does not parse.
func TestDNP3AssemblePcap(t *testing.T) {
	registerDNP3Decoders()
	for path, want := range map[string]int{"testdata/dnp3.pcap": 100, "testdata/dnp3-2.pcap": 18} {
		var asm DNP3Assembler
		headers := 0
		for i, pkt := range mbReadPcap(t, path) {
			p := gopacket.NewPacket(pkt, LinkTypeEthernet, testDNP3Opts)
			for _, l := range p.Layers() {
				d, ok := l.(*DNP3)
				if !ok {
					continue
				}

				f, err := asm.Add(d)
				if err != nil || (f == nil) != (d.Application == nil) {
					t.Fatalf("%s frame %d: %v, %v", path, i+1, f, err)
				}
				if f == nil {
					continue
				}

				if dnp3ObjectList(f.Application) != dnp3ObjectList(d.Application) || len(f.Message) != 1 {
					t.Errorf("%s frame %d: assembled %q, frame %q, message %d", path, i+1, dnp3ObjectList(f.Application), dnp3ObjectList(d.Application), len(f.Message))
				}
				headers += len(f.Application.Objects)
			}
		}

		if headers != want {
			t.Errorf("%s: %d object headers, want %d", path, headers, want)
		}
	}
}

// dnp3AddStream cuts stream into link frames and feeds them to a.
func dnp3AddStream(t *testing.T, a *DNP3Assembler, stream []byte) {
	var d DNP3
	for len(stream) > 0 {
		if err := d.decodeFrame(stream, gopacket.NilDecodeFeedback); err != nil {
			return
		}
		stream = d.BaseLayer.Payload

		f, _ := a.Add(&d)
		if f == nil {
			continue
		}

		if len(f.Data) > dnp3Limit(a.MaxFragment, DNP3MaxFragment) || len(f.Message) > dnp3Limit(a.MaxMessage, DNP3MaxMessage) || f.Application == nil {
			t.Fatalf("fragment of %d bytes, message of %d", len(f.Data), len(f.Message))
		}
		dnp3ExerciseApp(t, f.Application)
	}

	if a.Streams() > dnp3Limit(a.MaxStreams, DNP3MaxStreams) {
		t.Fatalf("%d streams", a.Streams())
	}
}

// testDNP3Stream is a multi-fragment response, an unsolicited response
// and a request, as one byte stream.
func testDNP3Stream() []byte {
	var out []byte
	for _, frames := range [][][]byte{
		dnp3Split(testDNP3BigResponse(0x80|5), 100, 0),
		dnp3Split([]byte{0xd0 | 2, 0x82, 0x00, 0x00, 2, 1, 0x17, 1, 9, 0x81}, 100, 9),
		dnp3Split([]byte{0x40 | 6, 0x81, 0x00, 0x00, 1, 2, 0x00, 2, 2, 0x81}, 3, 5),
		{dnp3Master(0xc0, 0xc0, 0x01, 0x3c, 0x02, 0x06)},
	} {
		for _, frame := range frames {
			out = append(out, frame...)
		}
	}
	return out
}

// A stream cut at any offset, or with any byte changed, never panics.
func TestDNP3AssembleTruncated(t *testing.T) {
	stream := testDNP3Stream()
	for n := 0; n <= len(stream); n++ {
		dnp3AddStream(t, &DNP3Assembler{}, stream[:n])
	}

	for i := range stream {
		lie := bytes.Clone(stream)
		lie[i] ^= 0xff
		dnp3AddStream(t, &DNP3Assembler{CRC: DNP3CRCKeep}, lie)
	}
}

func FuzzDNP3Assembler(f *testing.F) {
	f.Add(testDNP3Stream(), uint8(0), uint8(0), uint8(0))
	f.Add(testDNP3Stream(), uint8(200), uint8(1), uint8(2))
	for _, frame := range testDNP3Frames() {
		f.Add(frame, uint8(0), uint8(1), uint8(1))
	}

	f.Fuzz(func(t *testing.T, stream []byte, maxFrag, maxStreams, maxMsg uint8) {
		for _, crc := range []DNP3CRCPolicy{DNP3CRCDrop, DNP3CRCKeep} {
			a := DNP3Assembler{MaxFragment: int(maxFrag), MaxStreams: int(maxStreams), MaxMessage: int(maxMsg), CRC: crc}
			dnp3AddStream(t, &a, stream)
		}
	})
}
