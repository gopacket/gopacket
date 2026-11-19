// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// testDNP3SecStatData is a g121v1 object: online, association 2, 77.
var testDNP3SecStatData = dnp3Cat(0x01, dnp3LE16(2), dnp3LE32(77))

// testDNP3MoreVectors are objects of dnp3_values.go. tshark 4.7 shows
// the same fields for g120v11, v12, v13, v15, g121 and g122 (see
// TestDNP3SecStatFrame for the bytes it was given); it has no dissector
// for the others, which follow the Zeek and Suricata parsers.
var testDNP3MoreVectors = []testDNP3Vector{
	{70, 1, dnp3Cat(dnp3LE16(1), 1, 2, dnp3LE16(3), dnp3LE16(4), dnp3LE32(5), dnp3T(testDNP3Time), dnp3LE16(0x1ff),
		dnp3LE32(6), dnp3LE32(7), dnp3LE32(8), 1, 0, "f", 2, 0, 9, 9),
		DNP3FileID{FileType: 1, Attributes: 2, StartRecord: 3, EndRecord: 4, Size: 5, Created: testDNP3Time, Permissions: 0x1ff,
			FileID: 6, OwnerID: 7, GroupID: 8, Function: 1, Name: "f", Data: []byte{2, 0, 9, 9}}, 35},

	{81, 1, []byte{0x85, 30, 1}, DNP3BufferFill{Overflow: true, Percent: 5, Group: 30, Variation: 1}, 0},
	{82, 1, dnp3Cat(dnp3LE32(0x06), dnp3LE32(1), dnp3LE16(2), 1, 2, 0x00, 7, 30, 1, 0x01, 0),
		DNP3DeviceProfile{Functions: 1<<32 | 0x06, Headers: []DNP3ProfileHeader{{1, 2, 0x00, 7}, {30, 1, 0x01, 0}}}, 0},
	{83, 1, dnp3Cat("ACME", dnp3LE16(7), dnp3LE16(2), 1, 2), DNP3PrivateObject{Vendor: "ACME", ObjectID: 7, Data: []byte{1, 2}}, 0},
	{83, 2, dnp3Cat("ACME", dnp3LE16(7), dnp3LE16(1), dnp3LE16(3), 30, 1),
		DNP3PrivateDescriptor{Vendor: "ACME", ObjectID: 7, Specs: []DNP3PrivateSpec{{3, 30, 1}}}, 0},

	// Data sets: a NAME "ABC" and a 4 octet UINT data element.
	{85, 1, dnp3Cat(6, 4, 1, 0, "ABC", 3, 5, 2, 4), DNP3DataSetDescriptor{Elements: []DNP3DescriptorElement{
		{Code: DNP3DescriptorName, Type: DNP3AttrVString, Ancillary: []byte("ABC")},
		{Code: DNP3DescriptorDataElement, Type: DNP3AttrUint, MaxLength: 4, Ancillary: []byte{}}}}, 7},
	{86, 1, dnp3Cat(4, 1, 2, 2, 9), DNP3DataSetDescriptor{Elements: []DNP3DescriptorElement{
		{Code: DNP3DescriptorID, Type: DNP3AttrUint, MaxLength: 2, Ancillary: []byte{9}}}}, 0},
	{86, 2, []byte{0x0d}, DNP3DataSetReadable | DNP3DataSetStatic | DNP3DataSetEvents, 0},
	{87, 1, []byte{1, 5, 2, 0x34, 0x12}, DNP3DataSet{Elements: [][]byte{{5}, {0x34, 0x12}}}, 2},
	{88, 1, dnp3Cat(1, 5, 6, dnp3T(testDNP3Time)), DNP3DataSet{Elements: [][]byte{{5}, dnp3T(testDNP3Time)}}, 2},

	{90, 1, []byte("app"), DNP3AppID{Name: "app"}, 1},
	{91, 1, dnp3Cat(dnp3LE32(1000), 2, 1, 0, 3, 2, "ok"),
		DNP3ActivateStatus{Delay: time.Second, Statuses: []DNP3OperationStatus{{0, []byte{}}, {2, []byte("ok")}}}, 0},

	{101, 1, dnp3LE16(0x1234), DNP3BCD{Raw: 0x1234, Digits: 4}, 0},
	{101, 2, dnp3LE32(0x12345678), DNP3BCD{Raw: 0x12345678, Digits: 8}, 0},
	{101, 3, dnp3Cat(dnp3LE32(0x90123456), dnp3LE32(0x12345678)), DNP3BCD{Raw: 0x1234567890123456, Digits: 16}, 0},
	{102, 1, []byte{200}, DNP3Analog{Value: 200, Format: DNP3NumUint8}, 0},

	{120, 8, []byte{1, 2, 0x30, 0x82}, DNP3AuthUserCert{Method: 1, CertType: 2, Certificate: []byte{0x30, 0x82}}, 2},
	{120, 10, dnp3Cat(1, 2, dnp3LE32(3), dnp3LE16(4), dnp3LE16(5), dnp3LE16(2), dnp3LE16(1), dnp3LE16(1), "ab", 9, 8),
		DNP3AuthUserStatus{Method: 1, Operation: 2, Seq: 3, Role: 4, RoleExpiry: 5, UserName: "ab", PublicKey: []byte{9}, CertData: []byte{8}}, 0},
	{120, 11, dnp3Cat(1, dnp3LE16(2), dnp3LE16(2), "ab", 1, 2), DNP3AuthUpdateKeyReq{Method: 1, UserName: "ab", Challenge: []byte{1, 2}}, 0},
	{120, 12, dnp3Cat(dnp3LE32(1), dnp3LE16(2), dnp3LE16(2), 1, 2), DNP3AuthUpdateKeyReply{Seq: 1, User: 2, Challenge: []byte{1, 2}}, 0},
	{120, 13, dnp3Cat(dnp3LE32(1), dnp3LE16(2), dnp3LE16(2), 1, 2), DNP3AuthUpdateKey{Seq: 1, User: 2, KeyData: []byte{1, 2}}, 0},
	{120, 14, []byte{1, 2, 3}, DNP3AuthSignature{Signature: []byte{1, 2, 3}}, 1},
	{120, 15, []byte{1, 2, 3}, DNP3AuthMAC{MAC: []byte{1, 2, 3}}, 1},

	{121, 1, testDNP3SecStatData, DNP3SecurityStat{Flags: dnp3Fl(DNP3FlagsCounter, 1), Association: 2, Value: 77}, 0},
	{122, 1, testDNP3SecStatData, DNP3SecurityStat{Flags: dnp3Fl(DNP3FlagsCounter, 1), Association: 2, Value: 77}, 0},
	{122, 2, dnp3Cat(testDNP3SecStatData, dnp3T(testDNP3Time)),
		DNP3SecurityStat{Flags: dnp3Fl(DNP3FlagsCounter, 1), Association: 2, Value: 77, Time: testDNP3Abs}, 0},
}

func TestDNP3MoreVectors(t *testing.T) {
	for _, tc := range testDNP3MoreVectors {
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

// Counts inside an object must fit what is left of it before anything
// is allocated for them.
func TestDNP3ValueCounts(t *testing.T) {
	tests := []struct {
		name string
		g    DNP3Group
		v    uint8
		data []byte
	}{
		{"profile headers", 82, 1, dnp3Cat(dnp3LE32(0), dnp3LE32(0), dnp3LE16(0xffff), 1, 2, 3, 4)},
		{"private specs", 83, 2, dnp3Cat("ACME", dnp3LE16(7), dnp3LE16(0xffff), 1, 2, 3, 4)},
		{"private data", 83, 1, dnp3Cat("ACME", dnp3LE16(7), dnp3LE16(0xffff), 1)},
		{"statuses", 91, 1, dnp3Cat(dnp3LE32(0), 0xff, 1, 0)},
		{"status length 0", 91, 1, dnp3Cat(dnp3LE32(0), 1, 0, 0)},
		{"descriptor length 2", 85, 1, []byte{2, 4, 1}},
		{"descriptor past end", 86, 1, []byte{9, 4, 1, 0, 1}},
		{"data set past end", 87, 1, []byte{1, 5, 9, 1}},
		{"user name past end", 120, 10, dnp3Cat(1, 2, dnp3LE32(3), dnp3LE16(4), dnp3LE16(5), dnp3LE16(0xffff), dnp3LE16(0), dnp3LE16(0), "ab")},
		{"key past end", 120, 13, dnp3Cat(dnp3LE32(1), dnp3LE16(2), dnp3LE16(0xffff), 1, 2)},
	}

	for _, tc := range tests {
		h := DNP3ObjectHeader{Group: tc.g, Variation: tc.v, Objects: []DNP3Object{{Data: tc.data}}}
		allocs := testing.AllocsPerRun(10, func() {
			if v, err := h.Value(0); !errors.Is(err, ErrDNP3ValueShort) {
				t.Errorf("%s: %+v, %v", tc.name, v, err)
			}
		})

		if allocs > 4 {
			t.Errorf("%s: %v allocations", tc.name, allocs)
		}
	}

	// Variations without a decoder.
	for _, gv := range [][2]uint8{{81, 2}, {82, 2}, {83, 3}, {85, 2}, {86, 3}, {87, 2}, {90, 2}, {91, 2}, {101, 4}, {121, 2}, {122, 3}, {120, 16}, {100, 1}} {
		h := DNP3ObjectHeader{Group: DNP3Group(gv[0]), Variation: gv[1], Objects: []DNP3Object{{Data: make([]byte, 32)}}}
		if v, err := h.Value(0); !errors.Is(err, ErrDNP3UnknownValue) {
			t.Errorf("g%dv%d: %+v, %v", gv[0], gv[1], v, err)
		}
	}
}

// The fixed size objects added here decode in a response without a
// size prefix, as tshark 4.7 shows this frame: two g121v1 statistics by
// range, then a g122v2 event by index.
func TestDNP3SecStatFrame(t *testing.T) {
	a, err := dnp3App(t, dnp3Cat(0xc0, 0x81, 0x00, 0x00,
		121, 1, 0x00, 0, 1, testDNP3SecStatData, 0x41, dnp3LE16(3), dnp3LE32(9),
		122, 2, 0x17, 1, 5, testDNP3SecStatData, dnp3T(testDNP3Time),
		86, 2, 0x00, 4, 4, 0x03, 101, 1, 0x00, 0, 0, dnp3LE16(0x0042), 102, 1, 0x00, 1, 1, 7, 81, 1, 0x07, 1, 0x32, 2, 0)...)
	if err != nil || dnp3ObjectList(a) != "0x7901,0x7a02,0x5602,0x6501,0x6601,0x5101" || len(a.Unparsed) != 0 {
		t.Fatalf("%v, objects %q unparsed %x", err, dnp3ObjectList(a), a.Unparsed)
	}

	want := []struct {
		h, i  int
		index uint32
		v     DNP3Value
	}{
		{0, 0, 0, DNP3SecurityStat{Flags: dnp3Fl(DNP3FlagsCounter, 0x01), Association: 2, Value: 77}},
		{0, 1, 1, DNP3SecurityStat{Flags: dnp3Fl(DNP3FlagsCounter, 0x41), Association: 3, Value: 9}},
		{1, 0, 5, DNP3SecurityStat{Flags: dnp3Fl(DNP3FlagsCounter, 0x01), Association: 2, Value: 77, Time: testDNP3Abs}},
		{2, 0, 4, DNP3DataSetReadable | DNP3DataSetWritable},
		{3, 0, 0, DNP3BCD{Raw: 0x42, Digits: 4}},
		{4, 0, 1, DNP3Analog{Value: 7, Format: DNP3NumUint8}},
		{5, 0, 0, DNP3BufferFill{Percent: 0x32, Group: 2}},
	}

	for _, tc := range want {
		h := &a.Objects[tc.h]
		v, err := h.Value(tc.i)
		if err != nil || !reflect.DeepEqual(v, tc.v) || h.Objects[tc.i].Index != tc.index {
			t.Errorf("header %d object %d: %+v, %v, index %d", tc.h, tc.i, v, err, h.Objects[tc.i].Index)
		}
	}
}

// A flag is only reported for a family that defines its bit.
func TestDNP3FlagFamilies(t *testing.T) {
	tests := []struct {
		family DNP3FlagFamily
		flag   DNP3Flag
		want   bool
	}{
		{DNP3FlagsBinaryInput, DNP3FlagState, true},
		{DNP3FlagsBinaryInput, DNP3FlagChatterFilter, true},
		{DNP3FlagsBinaryInput, DNP3FlagDiscontinuity, false},
		{DNP3FlagsDoubleBit, DNP3FlagChatterFilter, true},
		{DNP3FlagsDoubleBit, DNP3FlagState, false},
		{DNP3FlagsDoubleBit, DNP3FlagDiscontinuity, false},
		{DNP3FlagsBinaryOutput, DNP3FlagState, true},
		{DNP3FlagsBinaryOutput, DNP3FlagChatterFilter, false},
		{DNP3FlagsCounter, DNP3FlagRollover, true},
		{DNP3FlagsCounter, DNP3FlagDiscontinuity, true},
		{DNP3FlagsCounter, DNP3FlagState, false},
		{DNP3FlagsAnalogInput, DNP3FlagOverRange, true},
		{DNP3FlagsAnalogInput, DNP3FlagReferenceErr, true},
		{DNP3FlagsAnalogInput, DNP3FlagState, false},
		{DNP3FlagsAnalogOutput, DNP3FlagLocalForced, true},
		{DNP3FlagsAnalogOutput, DNP3FlagOverRange, false},
		{DNP3FlagsAnalogOutput, DNP3FlagOnline | DNP3FlagState, false},
		{DNP3FlagsAnalogOutput, 0, false},
		{DNP3FlagsAbsent, DNP3FlagOnline, false},
	}

	for _, tc := range tests {
		if got := dnp3Fl(tc.family, 0xff).Has(tc.flag); got != tc.want {
			t.Errorf("family %d flag %#02x: %v", tc.family, uint8(tc.flag), got)
		}

		if dnp3Fl(tc.family, 0x00).Has(tc.flag) {
			t.Errorf("family %d flag %#02x: set in a zero octet", tc.family, uint8(tc.flag))
		}
	}
}

func TestDNP3AttributeTypes(t *testing.T) {
	ostr := DNP3Attribute{Type: DNP3AttrOctets, Data: []byte{1, 2}}
	if b, err := ostr.Octets(); err != nil || !reflect.DeepEqual(b, []byte{1, 2}) {
		t.Errorf("octets %x, %v", b, err)
	}

	// Bit 0 is the low bit of the first octet, bit 9 bit 1 of the second.
	bstr := DNP3Attribute{Type: DNP3AttrBits, Data: []byte{0x01, 0x02}}
	for n, want := range map[int]bool{0: true, 1: false, 8: false, 9: true} {
		if got, err := bstr.Bit(n); err != nil || got != want {
			t.Errorf("bit %d: %v, %v", n, got, err)
		}
	}
	if b, err := bstr.Bits(); err != nil || len(b) != 2 {
		t.Errorf("bits %x, %v", b, err)
	}

	uncd := DNP3Attribute{Type: DNP3AttrUnicode, Data: []byte{0x41, 0x00, 0xe9, 0x00, 0x3d, 0xd8, 0x00, 0xde}}
	if s, err := uncd.Unicode(); err != nil || s != "Aé\U0001f600" {
		t.Errorf("unicode %q, %v", s, err)
	}

	ext := DNP3Attribute{Type: DNP3AttrListExtend, Data: []byte{240, 0, 252, 1}}
	if l, err := ext.List(); err != nil || !reflect.DeepEqual(l, []DNP3AttrEntry{{240, 0}, {252, 1}}) {
		t.Errorf("extended list %+v, %v", l, err)
	}

	// Another type, an odd UNCD length and a bit past the end all error.
	for name, err := range map[string]error{
		"octets of BSTR":  func() error { _, err := bstr.Octets(); return err }(),
		"bits of OSTR":    func() error { _, err := ostr.Bits(); return err }(),
		"bit of OSTR":     func() error { _, err := ostr.Bit(0); return err }(),
		"bit 16":          func() error { _, err := bstr.Bit(16); return err }(),
		"bit -1":          func() error { _, err := bstr.Bit(-1); return err }(),
		"unicode of OSTR": func() error { _, err := ostr.Unicode(); return err }(),
		"odd unicode": func() error {
			_, err := DNP3Attribute{Type: DNP3AttrUnicode, Data: []byte{0x41}}.Unicode()
			return err
		}(),
	} {
		if !errors.Is(err, ErrDNP3AttrType) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A NONE attribute still has its length octet (IEEE 1815-2012 A.2), so
// the header after it decodes. Wireshark reads no length octet there.
func TestDNP3AttributeNone(t *testing.T) {
	a, err := dnp3App(t, 0xc0, 0x81, 0x00, 0x00, 0, 240, 0x00, 0, 0, 0x00, 0x00, 30, 2, 0x00, 1, 1, 0x01, 0x05, 0x00)
	if err != nil || dnp3ObjectList(a) != "0x00f0,0x1e02" || len(a.Unparsed) != 0 {
		t.Fatalf("%v, objects %q unparsed %x", err, dnp3ObjectList(a), a.Unparsed)
	}

	v, err := a.Objects[0].Value(0)
	if err != nil || !reflect.DeepEqual(v, DNP3Attribute{Type: DNP3AttrNone, Data: []byte{}}) {
		t.Errorf("%+v, %v", v, err)
	}
}

func TestDNP3ValueNames(t *testing.T) {
	if got := (DNP3DataSetReadable | DNP3DataSetStatic | 0x40).String(); got != "RD|ST|Reserved(0x40)" {
		t.Errorf("traits %q", got)
	}

	if !DNP3DataSetTraits(0x03).Has(DNP3DataSetWritable) || DNP3DataSetTraits(0x01).Has(DNP3DataSetWritable) {
		t.Error("traits Has")
	}

	if DNP3DescriptorDataElement.String() != "DAEL" || DNP3DescriptorCode(99).String() != "Reserved(99)" {
		t.Error("descriptor code names")
	}

	if DNP3GroupDataSet.String() != "Data Set" || DNP3GroupSecurityStat.String() != "Security Statistic" {
		t.Error("group names")
	}

	if v, err := (DNP3BCD{Raw: 0x1234567890123456, Digits: 16}).Uint(); err != nil || v != 1234567890123456 {
		t.Errorf("bcd %d, %v", v, err)
	}

	if _, err := (DNP3BCD{Raw: 0x12a4, Digits: 4}).Uint(); !errors.Is(err, ErrDNP3BadBCD) {
		t.Errorf("bcd digit above 9: %v", err)
	}
}

// START_APPL, STOP_APPL and INITIALIZE_APPL name applications with
// g90v1 objects, each sized by its prefix (IEEE 1815-2012 A.39;
// AN2013-004b table 3). Wireshark does not parse the objects of these
// requests.
func TestDNP3AppIDRequest(t *testing.T) {
	for _, fc := range []byte{16, 17, 18} {
		a, err := dnp3App(t, dnp3Cat(0xc0, int(fc), 90, 1, 0x5b, 2, dnp3LE16(3), "app", dnp3LE16(2), "hi")...)
		if err != nil || dnp3ObjectList(a) != "0x5a01" || len(a.Unparsed) != 0 {
			t.Fatalf("function %d: %v, objects %q unparsed %x", fc, err, dnp3ObjectList(a), a.Unparsed)
		}

		for i, want := range []string{"app", "hi"} {
			if v, err := a.Objects[0].Value(i); err != nil || v != (DNP3AppID{Name: want}) {
				t.Errorf("function %d object %d: %+v, %v", fc, i, v, err)
			}
		}

		// All applications: no object follows the header.
		a, err = dnp3App(t, 0xc0, fc, 90, 1, 0x06)
		if err != nil || dnp3ObjectList(a) != "0x5a01" || len(a.Objects[0].Objects) != 0 {
			t.Errorf("function %d, all: %v, %+v", fc, err, a.Objects)
		}
	}
}

func TestDNP3LinkIssues(t *testing.T) {
	read := []byte{0xc0, 0xc0, 0x01, 0x3c, 0x02, 0x06}
	resp := []byte{0xc0, 0xc0, 0x81, 0x00, 0x00}

	tests := []struct {
		name  string
		frame []byte
		want  DNP3LinkIssue
	}{
		{"unconfirmed user data from a master", dnp3Frame(0xc4, 4, 3, read), 0},
		{"confirmed user data, FCV set", dnp3Frame(0xf3, 4, 3, read), 0},
		{"response from an outstation", dnp3Frame(0x44, 3, 4, resp), 0},
		{"reset link states", dnp3Frame(0xc0, 4, 3, nil), 0},
		{"test link states", dnp3Frame(0xf2, 4, 3, nil), 0},
		{"request link status", dnp3Frame(0xc9, 4, 3, nil), 0},
		{"ACK", dnp3Frame(0x00, 3, 4, nil), 0},
		{"NACK with DFC", dnp3Frame(0x11, 3, 4, nil), 0},
		{"link status", dnp3Frame(0x0b, 3, 4, nil), 0},
		{"not supported", dnp3Frame(0x0f, 3, 4, nil), 0},
		{"broadcast user data", dnp3Frame(0xc4, 0xffff, 3, read), 0},
		{"self address", dnp3Frame(0xc9, 0xfffc, 3, nil), 0},

		{"ACK with user data", dnp3Frame(0x00, 3, 4, []byte{1, 2, 3}), DNP3LinkUnexpectedData},
		{"request link status with user data", dnp3Frame(0xc9, 4, 3, read), DNP3LinkUnexpectedData},
		{"user data function without data", dnp3Frame(0xc4, 4, 3, nil), DNP3LinkMissingData},
		{"confirmed user data, FCV clear", dnp3Frame(0xc3, 4, 3, read), DNP3LinkBadFCV},
		{"unconfirmed user data, FCV set", dnp3Frame(0xd4, 4, 3, read), DNP3LinkBadFCV},
		{"reset link states, FCV set", dnp3Frame(0xd0, 4, 3, nil), DNP3LinkBadFCV},
		{"undefined primary function 5", dnp3Frame(0xc5, 4, 3, nil), DNP3LinkBadFunction},
		{"obsolete primary function 1", dnp3Frame(0xc1, 4, 3, nil), DNP3LinkBadFunction},
		{"undefined secondary function 2", dnp3Frame(0x02, 3, 4, nil), DNP3LinkBadFunction},
		{"ACK with bit 5 set", dnp3Frame(0x20, 3, 4, nil), DNP3LinkReservedBit},
		{"reserved destination", dnp3Frame(0xc4, 0xfff0, 3, read), DNP3LinkBadDestination},
		{"broadcast source", dnp3Frame(0xc4, 4, 0xffff, read), DNP3LinkBadSource},
		{"reserved source", dnp3Frame(0xc4, 4, 0xfff0, read), DNP3LinkBadSource},
		{"broadcast link status request", dnp3Frame(0xc9, 0xfffd, 3, nil), DNP3LinkBadBroadcast},
		{"request with DIR clear", dnp3Frame(0x44, 4, 3, read), DNP3LinkBadDirection},
		{"response with DIR set", dnp3Frame(0xc4, 3, 4, resp), DNP3LinkBadDirection},
		{"several", dnp3Frame(0xc3, 0xfff1, 0xfffe, nil), DNP3LinkBadFCV | DNP3LinkMissingData | DNP3LinkBadDestination | DNP3LinkBadSource},
	}

	for _, tc := range tests {
		var d DNP3
		if err := d.DecodeFromBytes(tc.frame, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}

		if d.LinkIssues != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, d.LinkIssues, tc.want)
		}
	}

	// A later decode into the same layer clears the issues.
	var d DNP3
	_ = d.DecodeFromBytes(dnp3Frame(0x00, 3, 4, []byte{1}), gopacket.NilDecodeFeedback)
	_ = d.DecodeFromBytes(dnp3Frame(0x00, 3, 4, nil), gopacket.NilDecodeFeedback)
	if d.LinkIssues != 0 {
		t.Errorf("reused layer: %v", d.LinkIssues)
	}

	issues := DNP3LinkBadFCV | DNP3LinkUnexpectedData
	if issues.String() != "BadFCV|UnexpectedData" || !issues.Has(DNP3LinkBadFCV) || issues.Has(DNP3LinkBadSource) || DNP3LinkIssue(0).String() != "" {
		t.Errorf("issue names: %q", issues.String())
	}

	if got := (DNP3LinkBadDirection | 0x8000).String(); got != "BadDirection|Unknown(0x8000)" {
		t.Errorf("unknown issue: %q", got)
	}
}
