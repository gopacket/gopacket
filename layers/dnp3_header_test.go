// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// dnp3App decodes application bytes sent in one frame by master 3.
func dnp3App(t *testing.T, app ...byte) (*DNP3Application, error) {
	t.Helper()

	var d DNP3
	err := d.DecodeFromBytes(dnp3Master(0xc0, app...), gopacket.NilDecodeFeedback)
	if d.Application == nil {
		t.Fatalf("%x: no application: %v", app, err)
	}
	return d.Application, err
}

func TestDNP3RequestValues(t *testing.T) {
	// An aggressive mode READ: g120v3 with its sequence and user, the
	// class 0 header that is read, then the g120v9 MAC.
	a, err := dnp3App(t, 0xc0, 0x01,
		0x78, 0x03, 0x07, 0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x3c, 0x01, 0x06,
		0x78, 0x09, 0x5b, 0x01, 0x04, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
	)
	if err != nil {
		t.Fatal(err)
	}

	if got := dnp3ObjectList(a); got != "0x7803,0x3c01,0x7809" || len(a.Unparsed) != 0 {
		t.Fatalf("aggressive mode read: objects %s unparsed %x", got, a.Unparsed)
	}

	if v, err := a.Objects[0].Value(0); err != nil || v != (DNP3AuthAggressive{Seq: 2, User: 1}) {
		t.Errorf("g120v3: %+v, %v", v, err)
	}

	if v, err := a.Objects[2].Value(0); err != nil || !bytes.Equal(v.(DNP3AuthMAC).MAC, []byte{0xaa, 0xbb, 0xcc, 0xdd}) {
		t.Errorf("g120v9: %+v, %v", v, err)
	}

	// The same objects lead a freeze, which also lists headers only.
	a, err = dnp3App(t, 0xc0, 0x07,
		0x78, 0x03, 0x07, 0x01, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
		0x14, 0x00, 0x06,
	)
	if got := dnp3ObjectList(a); err != nil || got != "0x7803,0x1400" {
		t.Errorf("aggressive mode freeze: %v, objects %s", err, got)
	}

	// A file READ names the block it wants in a sized g70v5: handle
	// 0x12345678, block 3.
	a, err = dnp3App(t, 0xc0, 0x01,
		0x46, 0x05, 0x5b, 0x01, 0x08, 0x00, 0x78, 0x56, 0x34, 0x12, 0x03, 0x00, 0x00, 0x00,
		0x3c, 0x02, 0x06,
	)
	if err != nil {
		t.Fatal(err)
	}

	if got := dnp3ObjectList(a); got != "0x4605,0x3c02" || len(a.Unparsed) != 0 {
		t.Fatalf("file read: objects %s unparsed %x", got, a.Unparsed)
	}

	v, err := a.Objects[0].Value(0)
	if ft, ok := v.(DNP3FileTransport); err != nil || !ok || ft.Handle != 0x12345678 || ft.Block != 3 || ft.Last || len(ft.Data) != 0 {
		t.Errorf("g70v5: %+v, %v", v, err)
	}

	// Index lists of a READ still carry no values.
	a, err = dnp3App(t, 0xc0, 0x01, 0x1e, 0x01, 0x17, 0x02, 0x05, 0x09, 0x3c, 0x01, 0x06)
	if got := dnp3ObjectList(a); err != nil || got != "0x1e01,0x3c01" || a.Objects[0].Objects[1].Index != 9 {
		t.Errorf("index list: %v, objects %s", err, got)
	}

	// A sized object cut short in a READ is malformed.
	a, err = dnp3App(t, 0xc0, 0x01, 0x46, 0x05, 0x5b, 0x01, 0x08, 0x00, 0x78, 0x56)
	if !errors.Is(err, ErrDNP3ObjTruncated) || len(a.Unparsed) != 8 {
		t.Errorf("cut g70v5: %v, unparsed %x", err, a.Unparsed)
	}
}

func TestDNP3HeaderStates(t *testing.T) {
	tests := []struct {
		name     string
		app      []byte
		objects  string
		state    DNP3HeaderState
		count    uint64
		unparsed int
	}{
		// Frame 154 of testdata/dnp3.pcap ends in g60v4 with qualifier
		// 0xed: range code 0xd is reserved.
		{"reserved range", []byte{0xc1, 0x15, 0x3c, 0x02, 0x06, 0x3c, 0x03, 0x06, 0x3c, 0x04, 0xed}, "0x3c02,0x3c03,0x3c04", DNP3HeaderReserved, 0, 3},
		{"reserved range, more follows", []byte{0xc1, 0x15, 0x3c, 0x04, 0xed, 0x3c, 0x02, 0x06}, "0x3c04", DNP3HeaderReserved, 0, 6},
		{"reserved prefix", []byte{0xc0, 0x81, 0x00, 0x00, 0x1e, 0x02, 0x70, 0x00, 0x00}, "0x1e02", DNP3HeaderReserved, 0, 5},
		{"unknown variation", []byte{0xc0, 0x81, 0x00, 0x00, 0x1e, 0x63, 0x00, 0x02, 0x04, 0xaa}, "0x1e63", DNP3HeaderUnsized, 3, 6},
		{"free format without size", []byte{0xc0, 0x81, 0x00, 0x00, 0x1e, 0x01, 0x0b, 0x01, 0x00}, "0x1e01", DNP3HeaderUnsized, 1, 5},
		{"packed with index", []byte{0xc0, 0x81, 0x00, 0x00, 0x01, 0x01, 0x17, 0x01, 0x00, 0x01}, "0x0101", DNP3HeaderUnsized, 1, 6},

		// Bit 7 of the qualifier is reserved, but the codes are defined:
		// the header reads as with 0x07.
		{"reserved bit", []byte{0xc0, 0x81, 0x00, 0x00, 0x1e, 0x04, 0x87, 0x01, 0x05, 0x00}, "0x1e04", DNP3HeaderDecoded, 1, 0},
	}

	for _, tc := range tests {
		a, err := dnp3App(t, tc.app...)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}

		if got := dnp3ObjectList(a); got != tc.objects || len(a.Unparsed) != tc.unparsed {
			t.Errorf("%s: objects %q unparsed %x, want %q and %d bytes", tc.name, got, a.Unparsed, tc.objects, tc.unparsed)
			continue
		}

		last := a.Objects[len(a.Objects)-1]
		if last.State != tc.state || last.Count != tc.count {
			t.Errorf("%s: state %v count %d, want %v and %d", tc.name, last.State, last.Count, tc.state, tc.count)
		}

		if _, err := last.Value(0); tc.state != DNP3HeaderDecoded && !errors.Is(err, ErrDNP3BadObject) {
			t.Errorf("%s: value of an undecoded header: %v", tc.name, err)
		}
	}

	a, err := dnp3App(t, 0xc0, 0x81, 0x00, 0x00, 0x1e, 0x04, 0x87, 0x01, 0x05, 0x00)
	if err != nil {
		t.Fatal(err)
	}

	h := a.Objects[0]
	if !h.ReservedBit() || h.Prefix != DNP3PrefixNone || h.Range != DNP3RangeCount1 {
		t.Errorf("reserved bit header %+v", h)
	}

	if v, err := h.Value(0); err != nil || v.(DNP3Analog).Value != 5 {
		t.Errorf("reserved bit value %+v, %v", v, err)
	}

	for _, tc := range []struct {
		got, want string
	}{
		{DNP3HeaderDecoded.String(), "Decoded"},
		{DNP3HeaderReserved.String(), "Reserved Qualifier"},
		{DNP3HeaderUnsized.String(), "Unsized Objects"},
		{DNP3HeaderState(9).String(), "Unknown(9)"},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}

func TestDNP3VirtualRange(t *testing.T) {
	// Range codes 3 to 5 hold start and stop virtual addresses (IEEE
	// 1815-2012 table 4-6), so g30v4 at addresses 2..3 is two objects.
	// Wireshark reads one address and one object here.
	a, err := dnp3App(t, 0xc0, 0x81, 0x00, 0x00, 0x1e, 0x04, 0x03, 0x02, 0x03, 0x05, 0x00, 0x06, 0x00, 0x3c, 0x01, 0x06)
	if err != nil {
		t.Fatal(err)
	}

	if got := dnp3ObjectList(a); got != "0x1e04,0x3c01" {
		t.Fatalf("objects %s", got)
	}

	h := a.Objects[0]
	want := []DNP3Object{{Index: 2, Data: []byte{0x05, 0x00}}, {Index: 3, Data: []byte{0x06, 0x00}}}
	if h.Range != DNP3RangeVirtual1 || h.Start != 2 || h.Stop != 3 || h.Count != 2 || !reflect.DeepEqual(h.Objects, want) {
		t.Errorf("virtual range header %+v", h)
	}

	if !h.Range.IsVirtual() || !h.Range.IsStartStop() || DNP3RangeStartStop1.IsVirtual() || DNP3RangeCount1.IsVirtual() {
		t.Error("DNP3RangeCode.IsVirtual")
	}

	// Each width, a range cut short and a stop below the start.
	for _, tc := range []struct {
		app []byte
		err error
	}{
		{[]byte{0xc0, 0x01, 0x1e, 0x04, 0x04, 0x02, 0x00, 0x03, 0x00}, nil},
		{[]byte{0xc0, 0x01, 0x1e, 0x04, 0x05, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}, nil},
		{[]byte{0xc0, 0x01, 0x1e, 0x04, 0x05, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00}, ErrDNP3ObjTruncated},
		{[]byte{0xc0, 0x01, 0x1e, 0x04, 0x03, 0x03, 0x02}, ErrDNP3BadRange},
	} {
		a, err := dnp3App(t, tc.app...)
		if !errors.Is(err, tc.err) {
			t.Errorf("%x: %v, want %v", tc.app, err, tc.err)
		}

		if tc.err == nil && (len(a.Objects) != 1 || a.Objects[0].Count != 2) {
			t.Errorf("%x: objects %+v", tc.app, a.Objects)
		}
	}
}
