// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// testDNP3Time is the time of the hand-built vectors.
var testDNP3Time = time.Date(2026, time.November, 19, 12, 0, 0, 123e6, time.UTC)

// dnp3T encodes t as a 48 bit DNP3 time.
func dnp3T(t time.Time) []byte {
	b := binary.LittleEndian.AppendUint64(nil, uint64(t.UnixMilli()))
	return b[:dnp3TimeLen]
}

// dnp3Cat joins byte slices and single bytes.
func dnp3Cat(parts ...any) []byte {
	var out []byte
	for _, p := range parts {
		switch v := p.(type) {
		case int:
			out = append(out, byte(v))
		case []byte:
			out = append(out, v...)
		case string:
			out = append(out, v...)
		}
	}
	return out
}

func dnp3LE16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
func dnp3LE32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
func dnp3LEF32(v float32) []byte {
	return binary.LittleEndian.AppendUint32(nil, math.Float32bits(v))
}
func dnp3LEF64(v float64) []byte {
	return binary.LittleEndian.AppendUint64(nil, math.Float64bits(v))
}

// testDNP3Abs and testDNP3Rel are timestamps of the vectors.
var (
	testDNP3Abs = DNP3Timestamp{Kind: DNP3TimeAbsolute, Time: testDNP3Time}
	testDNP3Rel = DNP3Timestamp{Kind: DNP3TimeRelative, Relative: 1011 * time.Millisecond}
)

// dnp3Fl is a flags octet of family f.
func dnp3Fl(f DNP3FlagFamily, raw uint8) DNP3Flags {
	return DNP3Flags{Family: f, Raw: raw}
}

// testDNP3Vector is one object built from IEEE 1815-2012 annex A. Cuts
// of data shorter than fixed must fail; past it the object has a free
// format tail. fixed 0 means all of data.
type testDNP3Vector struct {
	g     DNP3Group
	v     uint8
	data  []byte
	want  DNP3Value
	fixed int
}

// testDNP3Vectors are hand built from the spec: the captures hold none of
// these types, so tshark cannot check them.
var testDNP3Vectors = []testDNP3Vector{
	{1, 2, []byte{0x81}, DNP3Binary{Flags: dnp3Fl(DNP3FlagsBinaryInput, 0x81), State: true}, 0},
	{2, 1, []byte{0x23}, DNP3Binary{Flags: dnp3Fl(DNP3FlagsBinaryInput, 0x23)}, 0},
	{2, 2, dnp3Cat(0x81, dnp3T(testDNP3Time)), DNP3Binary{Flags: dnp3Fl(DNP3FlagsBinaryInput, 0x81), State: true, Time: testDNP3Abs}, 0},
	{2, 3, dnp3Cat(0x01, dnp3LE16(1011)), DNP3Binary{Flags: dnp3Fl(DNP3FlagsBinaryInput, 0x01), Time: testDNP3Rel}, 0},

	{3, 2, []byte{0x81}, DNP3DoubleBitInput{Flags: dnp3Fl(DNP3FlagsDoubleBit, 0x81), State: DNP3DoubleBitOn}, 0},
	{4, 1, []byte{0xc1}, DNP3DoubleBitInput{Flags: dnp3Fl(DNP3FlagsDoubleBit, 0xc1), State: DNP3DoubleBitIndeterminate}, 0},
	{4, 2, dnp3Cat(0x41, dnp3T(testDNP3Time)), DNP3DoubleBitInput{Flags: dnp3Fl(DNP3FlagsDoubleBit, 0x41), State: DNP3DoubleBitOff, Time: testDNP3Abs}, 0},
	{4, 3, dnp3Cat(0x01, dnp3LE16(1011)), DNP3DoubleBitInput{Flags: dnp3Fl(DNP3FlagsDoubleBit, 0x01), State: DNP3DoubleBitIntermediate, Time: testDNP3Rel}, 0},

	{10, 2, []byte{0x81}, DNP3Binary{Flags: dnp3Fl(DNP3FlagsBinaryOutput, 0x81), State: true}, 0},
	{11, 1, []byte{0x02}, DNP3Binary{Flags: dnp3Fl(DNP3FlagsBinaryOutput, 0x02)}, 0},
	{11, 2, dnp3Cat(0x81, dnp3T(testDNP3Time)), DNP3Binary{Flags: dnp3Fl(DNP3FlagsBinaryOutput, 0x81), State: true, Time: testDNP3Abs}, 0},

	// CROB: PULSE_ON with CLOSE, once, 1000 ms on, 500 ms off.
	{12, 1, dnp3Cat(0x41, 1, dnp3LE32(1000), dnp3LE32(500), 0), DNP3CROB{Code: 0x41, Count: 1, OnTime: 1000, OffTime: 500}, 0},
	// PCB: LATCH_OFF with clear, status NOT_SUPPORTED with bit 7 set.
	{12, 2, dnp3Cat(0x24, 2, dnp3LE32(0), dnp3LE32(0), 0x84), DNP3CROB{Code: 0x24, Count: 2, Status: DNP3StatusNotSupported}, 0},

	{13, 1, []byte{0x81}, DNP3BinaryCommandEvent{State: true, Status: DNP3StatusTimeout}, 0},
	{13, 2, dnp3Cat(0x04, dnp3T(testDNP3Time)), DNP3BinaryCommandEvent{Status: DNP3StatusNotSupported, Time: testDNP3Abs}, 0},

	{20, 1, dnp3Cat(0x41, dnp3LE32(0x12345678)), DNP3Counter{Flags: dnp3Fl(DNP3FlagsCounter, 0x41), Value: 0x12345678, Format: DNP3NumUint32}, 0},
	{20, 2, dnp3Cat(0x21, dnp3LE16(0xffff)), DNP3Counter{Flags: dnp3Fl(DNP3FlagsCounter, 0x21), Value: 0xffff, Format: DNP3NumUint16}, 0},
	{20, 6, dnp3LE16(7), DNP3Counter{Value: 7, Format: DNP3NumUint16}, 0},
	{21, 5, dnp3Cat(0x01, dnp3LE32(9), dnp3T(testDNP3Time)), DNP3Counter{Flags: dnp3Fl(DNP3FlagsCounter, 1), Value: 9, Format: DNP3NumUint32, Time: testDNP3Abs}, 0},
	{21, 6, dnp3Cat(0x01, dnp3LE16(9), dnp3T(testDNP3Time)), DNP3Counter{Flags: dnp3Fl(DNP3FlagsCounter, 1), Value: 9, Format: DNP3NumUint16, Time: testDNP3Abs}, 0},
	{21, 10, dnp3LE16(3), DNP3Counter{Value: 3, Format: DNP3NumUint16}, 0},
	{22, 1, dnp3Cat(0x01, dnp3LE32(4)), DNP3Counter{Flags: dnp3Fl(DNP3FlagsCounter, 1), Value: 4, Format: DNP3NumUint32}, 0},
	{22, 6, dnp3Cat(0x01, dnp3LE16(4), dnp3T(testDNP3Time)), DNP3Counter{Flags: dnp3Fl(DNP3FlagsCounter, 1), Value: 4, Format: DNP3NumUint16, Time: testDNP3Abs}, 0},
	{23, 5, dnp3Cat(0x03, dnp3LE32(5), dnp3T(testDNP3Time)), DNP3Counter{Flags: dnp3Fl(DNP3FlagsCounter, 3), Value: 5, Format: DNP3NumUint32, Time: testDNP3Abs}, 0},

	{30, 1, dnp3Cat(0x21, dnp3LE32(0xfffe7960)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogInput, 0x21), Value: -100000, Format: DNP3NumInt32}, 0},
	{30, 2, dnp3Cat(0x41, dnp3LE16(0xfffe)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogInput, 0x41), Value: -2, Format: DNP3NumInt16}, 0},
	{30, 4, dnp3LE16(0x8000), DNP3Analog{Value: -32768, Format: DNP3NumInt16}, 0},
	{30, 5, dnp3Cat(0x01, dnp3LEF32(1.5)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogInput, 1), Value: 1.5, Format: DNP3NumFloat32}, 0},
	{30, 6, dnp3Cat(0x01, dnp3LEF64(-2.25)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogInput, 1), Value: -2.25, Format: DNP3NumFloat64}, 0},
	{31, 3, dnp3Cat(0x01, dnp3LE32(10), dnp3T(testDNP3Time)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogInput, 1), Value: 10, Format: DNP3NumInt32, Time: testDNP3Abs}, 0},
	{31, 5, dnp3LE32(11), DNP3Analog{Value: 11, Format: DNP3NumInt32}, 0},
	{31, 8, dnp3Cat(0x01, dnp3LEF64(0.1)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogInput, 1), Value: 0.1, Format: DNP3NumFloat64}, 0},
	{32, 4, dnp3Cat(0x01, dnp3LE16(12), dnp3T(testDNP3Time)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogInput, 1), Value: 12, Format: DNP3NumInt16, Time: testDNP3Abs}, 0},
	{32, 7, dnp3Cat(0x01, dnp3LEF32(-0.5), dnp3T(testDNP3Time)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogInput, 1), Value: -0.5, Format: DNP3NumFloat32, Time: testDNP3Abs}, 0},
	{33, 8, dnp3Cat(0x01, dnp3LEF64(3), dnp3T(testDNP3Time)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogInput, 1), Value: 3, Format: DNP3NumFloat64, Time: testDNP3Abs}, 0},
	{34, 1, dnp3LE16(0xffff), DNP3Analog{Value: 65535, Format: DNP3NumUint16}, 0},
	{34, 2, dnp3LE32(0xffffffff), DNP3Analog{Value: 4294967295, Format: DNP3NumUint32}, 0},
	{34, 3, dnp3LEF32(0.5), DNP3Analog{Value: 0.5, Format: DNP3NumFloat32}, 0},

	{40, 1, dnp3Cat(0x01, dnp3LE32(1000)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogOutput, 1), Value: 1000, Format: DNP3NumInt32}, 0},
	{40, 4, dnp3Cat(0x01, dnp3LEF64(2)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogOutput, 1), Value: 2, Format: DNP3NumFloat64}, 0},
	{41, 1, dnp3Cat(dnp3LE32(1000), 0), DNP3AnalogCommand{Value: 1000, Format: DNP3NumInt32}, 0},
	{41, 2, dnp3Cat(dnp3LE16(0xfffb), 7), DNP3AnalogCommand{Value: -5, Format: DNP3NumInt16, Status: DNP3StatusLocal}, 0},
	{41, 3, dnp3Cat(dnp3LEF32(12.5), 2), DNP3AnalogCommand{Value: 12.5, Format: DNP3NumFloat32, Status: DNP3StatusNoSelect}, 0},
	{41, 4, dnp3Cat(dnp3LEF64(1), 12), DNP3AnalogCommand{Value: 1, Format: DNP3NumFloat64, Status: DNP3StatusOutOfRange}, 0},
	{42, 3, dnp3Cat(0x01, dnp3LE32(1), dnp3T(testDNP3Time)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogOutput, 1), Value: 1, Format: DNP3NumInt32, Time: testDNP3Abs}, 0},
	{42, 8, dnp3Cat(0x01, dnp3LEF64(1), dnp3T(testDNP3Time)), DNP3Analog{Flags: dnp3Fl(DNP3FlagsAnalogOutput, 1), Value: 1, Format: DNP3NumFloat64, Time: testDNP3Abs}, 0},
	{43, 1, dnp3Cat(0, dnp3LE32(5)), DNP3AnalogCommand{Value: 5, Format: DNP3NumInt32}, 0},
	{43, 7, dnp3Cat(1, dnp3LEF32(1.5), dnp3T(testDNP3Time)), DNP3AnalogCommand{Value: 1.5, Format: DNP3NumFloat32, Status: DNP3StatusTimeout, Time: testDNP3Abs}, 0},

	{50, 1, dnp3T(testDNP3Time), DNP3TimeDate{Time: testDNP3Time}, 0},
	{50, 2, dnp3Cat(dnp3T(testDNP3Time), dnp3LE32(60000)), DNP3TimeDate{Time: testDNP3Time, Interval: 60000, Units: DNP3IntervalMilliseconds}, 0},
	{50, 3, dnp3T(testDNP3Time), DNP3TimeDate{Time: testDNP3Time}, 0},
	{50, 4, dnp3Cat(dnp3T(testDNP3Time), dnp3LE32(15), 3), DNP3TimeDate{Time: testDNP3Time, Interval: 15, Units: DNP3IntervalMinutes}, 0},
	{51, 2, dnp3T(testDNP3Time), DNP3TimeDate{Time: testDNP3Time}, 0},
	{52, 1, dnp3LE16(10), DNP3TimeDelay{Delay: 10 * time.Second}, 0},

	{110, 3, []byte("abc"), DNP3OctetString("abc"), 0},
	{113, 2, []byte("hi"), DNP3OctetString("hi"), 0},

	// Device attributes: data type code, length, value.
	{0, 252, dnp3Cat(1, 4, "ACME"), DNP3Attribute{Type: DNP3AttrVString, Data: []byte("ACME")}, 0},
	{0, 240, dnp3Cat(2, 2, dnp3LE16(2048)), DNP3Attribute{Type: DNP3AttrUint, Data: dnp3LE16(2048)}, 0},
	{0, 255, dnp3Cat(0xfe, 4, 240, 0, 252, 1), DNP3Attribute{Type: DNP3AttrList, Data: []byte{240, 0, 252, 1}}, 0},

	// File objects: names follow the fixed fields.
	{70, 2, dnp3Cat(dnp3LE16(12), dnp3LE16(2), dnp3LE16(14), dnp3LE16(3), dnp3LE32(0x0a0b0c0d), "me", "pwd"),
		DNP3FileAuth{AuthKey: 0x0a0b0c0d, UserName: "me", Password: "pwd"}, 0},
	{70, 3, dnp3Cat(dnp3LE16(26), dnp3LE16(3), dnp3T(testDNP3Time), dnp3LE16(0x01a4), dnp3LE32(0x11223344), dnp3LE32(1024), dnp3LE16(1), dnp3LE16(512), dnp3LE16(7), "a.b"),
		DNP3FileCommand{Created: testDNP3Time, Permissions: 0x01a4, AuthKey: 0x11223344, Size: 1024, Mode: 1, MaxBlock: 512, RequestID: 7, Name: "a.b"}, 0},
	{70, 4, dnp3Cat(dnp3LE32(0x01020304), dnp3LE32(1024), dnp3LE16(512), dnp3LE16(7), 0, "ok"),
		DNP3FileStatus{Handle: 0x01020304, Size: 1024, MaxBlock: 512, RequestID: 7, Text: []byte("ok")}, 13},
	{70, 5, dnp3Cat(dnp3LE32(9), dnp3LE32(0x80000002), "xyz"), DNP3FileTransport{Handle: 9, Block: 2, Last: true, Data: []byte("xyz")}, 8},
	{70, 6, dnp3Cat(dnp3LE32(9), dnp3LE32(5), 3), DNP3FileTransportStatus{Handle: 9, Block: 5, Status: 3, Text: []byte{}}, 0},
	{70, 7, dnp3Cat(dnp3LE16(20), dnp3LE16(1), dnp3LE16(1), dnp3LE32(99), dnp3T(testDNP3Time), dnp3LE16(0x1ff), dnp3LE16(2), "f"),
		DNP3FileDescriptor{FileType: 1, Size: 99, Created: testDNP3Time, Permissions: 0x1ff, RequestID: 2, Name: "f"}, 0},
	{70, 8, []byte("/tmp/x"), DNP3FileSpec{Name: "/tmp/x"}, 1},

	// Secure authentication (IEEE 1815-2012 clause 7.6, A.45).
	{120, 1, dnp3Cat(dnp3LE32(1), dnp3LE16(1), 4, 1, 0xde, 0xad, 0xbe, 0xef),
		DNP3AuthChallenge{Seq: 1, User: 1, MACAlgorithm: 4, Reason: 1, Data: []byte{0xde, 0xad, 0xbe, 0xef}}, 8},
	{120, 2, dnp3Cat(dnp3LE32(1), dnp3LE16(1), 1, 2, 3, 4), DNP3AuthReply{Seq: 1, User: 1, MAC: []byte{1, 2, 3, 4}}, 6},
	{120, 3, dnp3Cat(dnp3LE32(2), dnp3LE16(1)), DNP3AuthAggressive{Seq: 2, User: 1}, 0},
	{120, 4, dnp3LE16(3), DNP3AuthKeyStatusReq{User: 3}, 0},
	{120, 5, dnp3Cat(dnp3LE32(5), dnp3LE16(1), 1, 1, 4, dnp3LE16(4), 1, 2, 3, 4, 9, 9, 9, 9),
		DNP3AuthKeyStatus{Seq: 5, User: 1, KeyWrap: 1, KeyStatus: 1, MACAlgorithm: 4, Challenge: []byte{1, 2, 3, 4}, MAC: []byte{9, 9, 9, 9}}, 15},
	{120, 6, dnp3Cat(dnp3LE32(5), dnp3LE16(1), 7, 7, 7), DNP3AuthKeyChange{Seq: 5, User: 1, KeyData: []byte{7, 7, 7}}, 6},
	{120, 7, dnp3Cat(dnp3LE32(1), dnp3LE16(1), dnp3LE16(2), 1, dnp3T(testDNP3Time), "bad"),
		DNP3AuthError{Seq: 1, User: 1, Association: 2, Code: 1, Time: testDNP3Time, Text: []byte("bad")}, 15},
	{120, 9, []byte{1, 2, 3, 4}, DNP3AuthMAC{MAC: []byte{1, 2, 3, 4}}, 1},
}

func TestDNP3ValueVectors(t *testing.T) {
	for _, tc := range testDNP3Vectors {
		h := DNP3ObjectHeader{Group: tc.g, Variation: tc.v, Objects: []DNP3Object{{Data: tc.data}}}
		got, err := h.Value(0)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("g%dv%d: %+v, %v; want %+v", tc.g, tc.v, got, err, tc.want)
		}

		// Every cut into the fixed part errors, never panics.
		fixed := tc.fixed
		if fixed == 0 {
			fixed = len(tc.data)
		}
		for n := 0; n < fixed; n++ {
			h.Objects[0].Data = tc.data[:n]
			if v, err := h.Value(0); err == nil {
				t.Errorf("g%dv%d cut to %d bytes: %+v", tc.g, tc.v, n, v)
			}
		}
	}
}

// testDNP3PcapValue is one object value as tshark 4.7 shows it.
type testDNP3PcapValue struct {
	path   string
	frame  int
	header int
	object int
	index  uint32
	want   DNP3Value
}

// Online and Online|State flags of the captures.
var (
	dnp3BIOnline = dnp3Fl(DNP3FlagsBinaryInput, 0x01)
	dnp3BIOn     = dnp3Fl(DNP3FlagsBinaryInput, 0x81)
	dnp3BOOnline = dnp3Fl(DNP3FlagsBinaryOutput, 0x01)
	dnp3BOOn     = dnp3Fl(DNP3FlagsBinaryOutput, 0x81)
	dnp3AIOnline = dnp3Fl(DNP3FlagsAnalogInput, 0x01)
)

// testDNP3PcapValues are representative values of the test captures. A
// throwaway script compared all 570 values tshark shows for them, and for
// the other ICS-pcap DNP3 captures, with Value: all matched.
var testDNP3PcapValues = []testDNP3PcapValue{
	// Frame 7: WRITE of g50v1, 2004-10-11 09:39:01.483 UTC.
	{"testdata/dnp3.pcap", 7, 0, 0, 0, DNP3TimeDate{Time: time.UnixMilli(1097487541483).UTC()}},

	// Frame 40: CTO, g2v3 events relative to it, g32v1 events.
	{"testdata/dnp3.pcap", 40, 0, 0, 0, DNP3TimeDate{Time: time.UnixMilli(1097489794018).UTC()}},
	{"testdata/dnp3.pcap", 40, 1, 0, 0, DNP3Binary{Flags: dnp3BIOnline, Time: DNP3Timestamp{Kind: DNP3TimeRelative}}},
	{"testdata/dnp3.pcap", 40, 1, 1, 1, DNP3Binary{Flags: dnp3BIOn, State: true, Time: DNP3Timestamp{Kind: DNP3TimeRelative}}},
	{"testdata/dnp3.pcap", 40, 1, 3, 0, DNP3Binary{Flags: dnp3BIOn, State: true, Time: testDNP3Rel}},
	{"testdata/dnp3.pcap", 40, 1, 4, 1, DNP3Binary{Flags: dnp3BIOnline, Time: testDNP3Rel}},
	{"testdata/dnp3.pcap", 40, 2, 2, 2, DNP3Analog{Flags: dnp3AIOnline, Format: DNP3NumInt32}},

	// Frame 46: g32v1 events.
	{"testdata/dnp3.pcap", 46, 2, 0, 0, DNP3Analog{Flags: dnp3AIOnline, Value: 198, Format: DNP3NumInt32}},
	{"testdata/dnp3.pcap", 46, 2, 1, 1, DNP3Analog{Flags: dnp3AIOnline, Value: 202, Format: DNP3NumInt32}},

	// Frame 71: g52v2 fine time delay, 5000 ms.
	{"testdata/dnp3.pcap", 71, 0, 0, 0, DNP3TimeDelay{Delay: 5 * time.Second}},

	// Frame 88: WRITE g80v1 index 7 (DEVICE_RESTART) off.
	{"testdata/dnp3.pcap", 88, 0, 0, 7, DNP3Binary{}},

	// Frame 141: static response.
	{"testdata/dnp3.pcap", 141, 0, 0, 0, DNP3Binary{State: true}},
	{"testdata/dnp3.pcap", 141, 0, 1, 1, DNP3Binary{}},
	{"testdata/dnp3.pcap", 141, 0, 4, 4, DNP3Binary{State: true}},
	{"testdata/dnp3.pcap", 141, 1, 0, 0, DNP3Binary{Flags: dnp3BOOn, State: true}},
	{"testdata/dnp3.pcap", 141, 1, 1, 1, DNP3Binary{Flags: dnp3BOOnline}},
	{"testdata/dnp3.pcap", 141, 2, 0, 0, DNP3Counter{Value: 32, Format: DNP3NumUint32}},
	{"testdata/dnp3.pcap", 141, 3, 0, 0, DNP3Counter{Format: DNP3NumUint32}},
	{"testdata/dnp3.pcap", 141, 4, 0, 0, DNP3Analog{Value: 202, Format: DNP3NumInt32}},
	{"testdata/dnp3.pcap", 141, 4, 3, 3, DNP3Analog{Value: -1, Format: DNP3NumInt32}},
	{"testdata/dnp3.pcap", 141, 4, 6, 6, DNP3Analog{Value: 8523, Format: DNP3NumInt32}},

	// dnp3-2.pcap frames 4 and 5: SELECT of a CROB and its response,
	// NOT_SUPPORTED.
	{"testdata/dnp3-2.pcap", 4, 0, 0, 34463, DNP3CROB{Code: 0x03, Count: 1, OnTime: 100, OffTime: 100}},
	{"testdata/dnp3-2.pcap", 5, 0, 0, 34463, DNP3CROB{Code: 0x03, Count: 1, OnTime: 100, OffTime: 100, Status: DNP3StatusNotSupported}},
}

func TestDNP3ValuePcap(t *testing.T) {
	registerDNP3Decoders()
	pcaps := map[string][][]byte{}
	for _, tc := range testDNP3PcapValues {
		if pcaps[tc.path] == nil {
			pcaps[tc.path] = mbReadPcap(t, tc.path)
		}

		p := gopacket.NewPacket(pcaps[tc.path][tc.frame-1], LinkTypeEthernet, testDNP3Opts)
		d, ok := p.Layer(LayerTypeDNP3).(*DNP3)
		if !ok || d.Application == nil || tc.header >= len(d.Application.Objects) {
			t.Errorf("%s frame %d: no header %d", tc.path, tc.frame, tc.header)
			continue
		}

		h := &d.Application.Objects[tc.header]
		got, err := h.Value(tc.object)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s frame %d header %d object %d: %+v, %v; want %+v", tc.path, tc.frame, tc.header, tc.object, got, err, tc.want)
		}

		idx := h.Start + uint32(tc.object)
		if tc.object < len(h.Objects) {
			idx = h.Objects[tc.object].Index
		}
		if idx != tc.index {
			t.Errorf("%s frame %d header %d object %d: index %d, want %d", tc.path, tc.frame, tc.header, tc.object, idx, tc.index)
		}
	}
}

func TestDNP3ResolveTime(t *testing.T) {
	registerDNP3Decoders()
	p := gopacket.NewPacket(testPacketDNP3Unsolicited, LinkTypeEthernet, testDNP3Opts)
	a := p.Layer(LayerTypeDNP3).(*DNP3).Application

	// Wireshark: CTO 10:16:34.018 plus 1011 ms.
	ev := &a.Objects[1]
	v, err := ev.Value(3)
	if err != nil {
		t.Fatal(err)
	}

	got, err := a.ResolveTime(1, v.(DNP3Binary).Time)
	want := time.Date(2004, time.October, 11, 10, 16, 35, 29e6, time.UTC)
	if err != nil || !got.Equal(want) {
		t.Errorf("resolved %v, %v; want %v", got, err, want)
	}

	// The CTO header itself has none before it.
	if _, err := a.CTO(0); !errors.Is(err, ErrDNP3NoCTO) {
		t.Errorf("CTO(0): %v", err)
	}

	if _, err := a.CTO(len(a.Objects)); !errors.Is(err, ErrDNP3BadObject) {
		t.Errorf("CTO past the end: %v", err)
	}

	if _, err := a.ResolveTime(2, DNP3Timestamp{}); !errors.Is(err, ErrDNP3NoTime) {
		t.Errorf("no time: %v", err)
	}

	if got, err := a.ResolveTime(0, testDNP3Abs); err != nil || !got.Equal(testDNP3Time) {
		t.Errorf("absolute: %v, %v", got, err)
	}

	// A relative time with no CTO before it.
	if _, err := a.ResolveTime(0, testDNP3Rel); !errors.Is(err, ErrDNP3NoCTO) {
		t.Errorf("relative before the CTO: %v", err)
	}

	// A CTO cut short.
	short := DNP3Application{Objects: []DNP3ObjectHeader{
		{Group: DNP3GroupCTO, Variation: 1, Objects: []DNP3Object{{Data: []byte{1, 2}}}},
		{Group: DNP3GroupBinaryInputEvent, Variation: 3},
	}}
	if _, err := short.CTO(1); !errors.Is(err, ErrDNP3ValueShort) {
		t.Errorf("short CTO: %v", err)
	}
}

func TestDNP3ValueErrors(t *testing.T) {
	tests := []struct {
		name string
		h    DNP3ObjectHeader
		i    int
		err  error
	}{
		{"index list of a READ", DNP3ObjectHeader{Group: 30, Variation: 1, Objects: []DNP3Object{{Index: 5, Data: []byte{}}}}, 0, ErrDNP3NoValue},
		{"class data", DNP3ObjectHeader{Group: DNP3GroupClassData, Variation: 1}, 0, ErrDNP3BadObject},
		{"negative", DNP3ObjectHeader{Group: 30, Variation: 1, Objects: []DNP3Object{{Data: []byte{1}}}}, -1, ErrDNP3BadObject},
		{"past the end", DNP3ObjectHeader{Group: 30, Variation: 1, Objects: []DNP3Object{{Data: []byte{1}}}}, 1, ErrDNP3BadObject},
		{"unknown group", DNP3ObjectHeader{Group: 99, Variation: 1, Objects: []DNP3Object{{Data: []byte{1}}}}, 0, ErrDNP3UnknownValue},
		{"unknown variation", DNP3ObjectHeader{Group: 30, Variation: 99, Objects: []DNP3Object{{Data: []byte{1}}}}, 0, ErrDNP3UnknownValue},
		{"g51v3", DNP3ObjectHeader{Group: 51, Variation: 3, Objects: []DNP3Object{{Data: []byte{1}}}}, 0, ErrDNP3UnknownValue},
		{"g70v1 obsolete", DNP3ObjectHeader{Group: 70, Variation: 1, Objects: []DNP3Object{{Data: []byte{1}}}}, 0, ErrDNP3UnknownValue},
		{"packed past count", DNP3ObjectHeader{Group: 1, Variation: 1, Count: 2, BitsPerObject: 1, Data: []byte{3}}, 2, ErrDNP3BadObject},
		{"packed past data", DNP3ObjectHeader{Group: 3, Variation: 1, Count: 5, BitsPerObject: 2, Data: []byte{3}}, 4, ErrDNP3ValueShort},
	}

	for _, tc := range tests {
		if v, err := tc.h.Value(tc.i); !errors.Is(err, tc.err) {
			t.Errorf("%s: %+v, %v; want %v", tc.name, v, err, tc.err)
		}
	}

	// Packed double-bit inputs 2..6 of TestDNP3ObjectValues: 01 10 11 00 | 01.
	h := DNP3ObjectHeader{Group: 3, Variation: 1, Start: 2, Count: 5, BitsPerObject: 2, Data: []byte{0x39, 0x01}}
	for i, want := range []DNP3DoubleBit{DNP3DoubleBitOff, DNP3DoubleBitOn, DNP3DoubleBitIndeterminate, DNP3DoubleBitIntermediate, DNP3DoubleBitOff} {
		if v, err := h.Value(i); err != nil || v != (DNP3DoubleBitInput{State: want}) {
			t.Errorf("double-bit %d: %+v, %v", i, v, err)
		}
	}
}

func TestDNP3Attribute(t *testing.T) {
	tests := []struct {
		a    DNP3Attribute
		uint uint64
		int  int64
		flt  float64
		ok   string // the accessors expected to succeed: u, i, f, t, l
	}{
		{DNP3Attribute{Type: DNP3AttrUint, Data: dnp3LE16(2048)}, 2048, 0, 0, "u"},
		{DNP3Attribute{Type: DNP3AttrUint, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}, 0x0807060504030201, 0, 0, "u"},
		{DNP3Attribute{Type: DNP3AttrInt, Data: []byte{0xff}}, 0, -1, 0, "i"},
		{DNP3Attribute{Type: DNP3AttrInt, Data: dnp3LE16(0x8000)}, 0, -32768, 0, "i"},
		{DNP3Attribute{Type: DNP3AttrInt, Data: dnp3LE32(5)}, 0, 5, 0, "i"},
		{DNP3Attribute{Type: DNP3AttrFloat, Data: dnp3LEF32(1.5)}, 0, 0, 1.5, "f"},
		{DNP3Attribute{Type: DNP3AttrFloat, Data: dnp3LEF64(-3.25)}, 0, 0, -3.25, "f"},
		{DNP3Attribute{Type: DNP3AttrTime, Data: dnp3T(testDNP3Time)}, 0, 0, 0, "t"},
		{DNP3Attribute{Type: DNP3AttrList, Data: []byte{240, 0, 252, 1}}, 0, 0, 0, "l"},
		{DNP3Attribute{Type: DNP3AttrUint}, 0, 0, 0, ""},
		{DNP3Attribute{Type: DNP3AttrUint, Data: make([]byte, 9)}, 0, 0, 0, ""},
		{DNP3Attribute{Type: DNP3AttrFloat, Data: []byte{1, 2}}, 0, 0, 0, ""},
		{DNP3Attribute{Type: DNP3AttrList, Data: []byte{240}}, 0, 0, 0, ""},
		{DNP3Attribute{Type: DNP3AttrVString, Data: []byte("x")}, 0, 0, 0, ""},
	}

	for _, tc := range tests {
		u, errU := tc.a.Uint()
		i, errI := tc.a.Int()
		f, errF := tc.a.Float()
		tm, errT := tc.a.Time()
		l, errL := tc.a.List()

		got := ""
		for _, r := range []struct {
			c   string
			err error
		}{{"u", errU}, {"i", errI}, {"f", errF}, {"t", errT}, {"l", errL}} {
			if r.err == nil {
				got += r.c
			} else if !errors.Is(r.err, ErrDNP3AttrType) {
				t.Errorf("%+v: %v", tc.a, r.err)
			}
		}

		if got != tc.ok || u != tc.uint || i != tc.int || f != tc.flt {
			t.Errorf("%+v: ok %q u %d i %d f %v", tc.a, got, u, i, f)
		}

		if tc.ok == "t" && !tm.Equal(testDNP3Time) {
			t.Errorf("time %v", tm)
		}

		if tc.ok == "l" && !reflect.DeepEqual(l, []DNP3AttrEntry{{240, 0}, {252, 1}}) {
			t.Errorf("list %+v", l)
		}
	}

	if got := (DNP3Attribute{Type: DNP3AttrVString, Data: []byte("ACME")}).Text(); got != "ACME" {
		t.Errorf("text %q", got)
	}
}

// dnp3Resp builds a final response frame around objects.
func dnp3Resp(objs ...byte) []byte {
	return dnp3Frame(0x44, 3, 4, append([]byte{0xc0, 0xc0, 0x81, 0x00, 0x00}, objs...))
}

func TestDNP3LateSized(t *testing.T) {
	// g0v252 VSTR "ACME" and g0v240 UINT 2048, one each (qualifier 0x00,
	// range 0..0), then g30v3: all three decode.
	attrs := []byte{
		0x00, 0xfc, 0x00, 0x00, 0x00, 0x01, 0x04, 'A', 'C', 'M', 'E',
		0x00, 0xf0, 0x17, 0x01, 0x00, 0x02, 0x02, 0x00, 0x08,
		0x1e, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
	}

	var d DNP3
	if err := d.DecodeFromBytes(dnp3Resp(attrs...), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}

	a := d.Application
	if got := dnp3ObjectList(a); got != "0x00fc,0x00f0,0x1e03" || len(a.Unparsed) != 0 {
		t.Fatalf("objects %s unparsed %x", got, a.Unparsed)
	}

	v, err := a.Objects[0].Value(0)
	if err != nil || v.(DNP3Attribute).Text() != "ACME" {
		t.Errorf("g0v252: %+v, %v", v, err)
	}

	v, err = a.Objects[1].Value(0)
	if u, _ := v.(DNP3Attribute).Uint(); err != nil || u != 2048 {
		t.Errorf("g0v240: %+v, %v", v, err)
	}

	// Aggressive mode: g120v3 then a CROB then the g120v9 MAC.
	op := []byte{0xc0, 0x05,
		0x78, 0x03, 0x07, 0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x0c, 0x01, 0x28, 0x01, 0x00, 0x07, 0x00, 0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00,
		0x78, 0x09, 0x5b, 0x01, 0x04, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
	}
	if err := d.DecodeFromBytes(dnp3Master(0xc0, op...), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}

	if got := dnp3ObjectList(d.Application); got != "0x7803,0x0c01,0x7809" {
		t.Errorf("aggressive mode objects %s", got)
	}

	if v, err := d.Application.Objects[0].Value(0); err != nil || v != (DNP3AuthAggressive{Seq: 2, User: 1}) {
		t.Errorf("g120v3: %+v, %v", v, err)
	}

	// Where the first release stopped (no error, Unparsed), it still
	// does: a cut attribute, or bad bytes past a late sized object.
	tests := []struct {
		name     string
		objs     []byte
		objects  string
		unparsed int
	}{
		{"attribute cut", []byte{0x00, 0xfc, 0x00, 0x00, 0x00, 0x01, 0x09, 'A'}, "", 8},
		{"two attributes, one byte", []byte{0x00, 0xfc, 0x07, 0x02, 0x01}, "", 5},
		{"bad range after", append(attrs[:11:11], 0x1e, 0x01, 0x00, 0x05, 0x04), "0x00fc", 5},
		{"cut header after", append(attrs[:11:11], 0x1e, 0x01, 0x07, 0x03, 0x00), "0x00fc", 5},
		{"g120v4 cut", []byte{0x78, 0x04, 0x07, 0x01, 0x01}, "", 5},
		{"free format attribute", []byte{0x00, 0xfc, 0x0b, 0x01, 0x01, 0x01, 'A'}, "", 7},
		{"all attributes", []byte{0x00, 0xfe, 0x00, 0x00, 0x00}, "", 5},
	}

	for _, tc := range tests {
		err := d.DecodeFromBytes(dnp3Resp(tc.objs...), gopacket.NilDecodeFeedback)
		if err != nil || dnp3ObjectList(d.Application) != tc.objects || len(d.Application.Unparsed) != tc.unparsed {
			t.Errorf("%s: %v, objects %q unparsed %x", tc.name, err, dnp3ObjectList(d.Application), d.Application.Unparsed)
		}
	}

	// A READ of all attributes is header only, as before.
	read := []byte{0xc0, 0x01, 0x00, 0xfe, 0x06, 0x00, 0xfc, 0x06}
	if err := d.DecodeFromBytes(dnp3Master(0xc0, read...), gopacket.NilDecodeFeedback); err != nil || dnp3ObjectList(d.Application) != "0x00fe,0x00fc" {
		t.Errorf("read attributes: %v, %s", err, dnp3ObjectList(d.Application))
	}
}

func TestDNP3ValueStrings(t *testing.T) {
	tests := []struct {
		got, want string
	}{
		{dnp3Fl(DNP3FlagsBinaryInput, 0xa1).String(), "Online|ChatterFilter|State"},
		{dnp3Fl(DNP3FlagsBinaryInput, 0x40).String(), "Reserved(0x40)"},
		{dnp3Fl(DNP3FlagsDoubleBit, 0xbf).String(), "Online|Restart|CommLost|RemoteForced|LocalForced|ChatterFilter"},
		{dnp3Fl(DNP3FlagsBinaryOutput, 0x8c).String(), "CommLost|RemoteForced|State"},
		{dnp3Fl(DNP3FlagsCounter, 0x61).String(), "Online|Rollover|Discontinuity"},
		{dnp3Fl(DNP3FlagsAnalogInput, 0xe2).String(), "Restart|OverRange|ReferenceErr|Reserved(0x80)"},
		{dnp3Fl(DNP3FlagsAnalogOutput, 0x31).String(), "Online|LocalForced|Reserved(0x20)"},
		{DNP3Flags{Raw: 0xff}.String(), ""},
		{DNP3DoubleBitOn.String(), "Determined On"},
		{DNP3DoubleBit(4).String(), "Unknown(4)"},
		{DNP3StatusNotSupported.String(), "NOT_SUPPORTED"},
		{DNP3StatusNonParticipating.String(), "NON_PARTICIPATING"},
		{DNP3ControlStatus(50).String(), "Reserved(50)"},
		{DNP3ControlCode(0x41).String(), "PULSE_ON|CLOSE"},
		{DNP3ControlCode(0xb3).String(), "LATCH_ON|TRIP|Queue|Clear"},
		{DNP3ControlCode(0xc5).String(), "Reserved(5)|RESERVED"},
		{DNP3OpPulseOff.String(), "PULSE_OFF"},
		{DNP3OpLatchOff.String(), "LATCH_OFF"},
		{DNP3OpNul.String(), "NUL"},
		{DNP3TripCloseNul.String(), "NUL"},
		{DNP3IntervalMinutes.String(), "Minutes"},
		{DNP3IntervalUnit(200).String(), "Reserved(200)"},
		{DNP3AttrList.String(), "U8BS8LIST"},
		{DNP3AttrType(100).String(), "Reserved(100)"},
	}

	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}

	f := dnp3Fl(DNP3FlagsCounter, 0x41)
	if !f.Has(DNP3FlagOnline|DNP3FlagDiscontinuity) || f.Has(DNP3FlagRestart) || (DNP3Flags{Raw: 1}).Has(DNP3FlagOnline) {
		t.Error("DNP3Flags.Has")
	}

	c := DNP3ControlCode(0xb3)
	if c.Op() != DNP3OpLatchOn || !c.Queue() || !c.Clear() || c.TripClose() != DNP3TripCloseTrip {
		t.Errorf("control code %#x: %v %v %v %v", uint8(c), c.Op(), c.Queue(), c.Clear(), c.TripClose())
	}
}

// dnp3Exercise calls every accessor of v, as the fuzz target needs.
func dnp3Exercise(a *DNP3Application, h int, v DNP3Value) {
	var ts DNP3Timestamp
	switch x := v.(type) {
	case DNP3Binary:
		_, ts = x.Flags.String(), x.Time
	case DNP3DoubleBitInput:
		_, _, ts = x.Flags.String(), x.State.String(), x.Time
	case DNP3Counter:
		_, ts = x.Flags.String(), x.Time
	case DNP3Analog:
		_, ts = x.Flags.String(), x.Time
	case DNP3AnalogCommand:
		_, ts = x.Status.String(), x.Time
	case DNP3BinaryCommandEvent:
		_, ts = x.Status.String(), x.Time
	case DNP3CROB:
		_, _ = x.Code.String(), x.Status.String()
	case DNP3TimeDate:
		_ = x.Units.String()
	case DNP3Attribute:
		_, _ = x.Type.String(), x.Text()
		_, _ = x.Uint()
		_, _ = x.Int()
		_, _ = x.Float()
		_, _ = x.Time()
		_, _ = x.List()
	}

	if a != nil {
		_, _ = a.ResolveTime(h, ts)
	}
}

// dnp3ExerciseApp calls Value on every object of every header.
func dnp3ExerciseApp(t *testing.T, a *DNP3Application) {
	for hi := range a.Objects {
		h := &a.Objects[hi]
		_, _ = a.CTO(hi)

		n := len(h.Objects)
		if h.BitsPerObject != 0 {
			n = int(min(h.Count, uint64(len(h.Data))*dnp3BitsPerByte))
		}

		for i := -1; i <= n; i++ {
			v, err := h.Value(i)
			if err == nil && v == nil {
				t.Fatalf("header %d object %d: nil value without error", hi, i)
			}
			dnp3Exercise(a, hi, v)
		}
	}
}

func FuzzDNP3Values(f *testing.F) {
	for _, frame := range testDNP3Frames() {
		f.Add(frame)
	}
	for _, v := range testDNP3Vectors {
		f.Add(dnp3Resp(append([]byte{byte(v.g), v.v, 0x5b, 0x01, byte(len(v.data))}, v.data...)...))
		f.Add(append([]byte{byte(v.g), v.v}, v.data...))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// As a frame: decode, then every value of every object.
		var d DNP3
		_ = d.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
		if d.Application != nil {
			dnp3ExerciseApp(t, d.Application)
		}

		// As one object: group, variation, value bytes.
		if len(data) < 2 {
			return
		}
		h := DNP3ObjectHeader{Group: DNP3Group(data[0]), Variation: data[1], Objects: []DNP3Object{{Data: data[2:]}}}
		v, err := h.Value(0)
		if err == nil && v == nil {
			t.Fatal("nil value without error")
		}
		dnp3Exercise(nil, 0, v)
	})
}
