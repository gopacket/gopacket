// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// s7SZLCase is one SZL ID and index with a record of its layout.
type s7SZLCase struct {
	id, index uint16
	rec       []byte
}

// value returns the SZL response value holding the record.
func (c s7SZLCase) value() []byte {
	head := make([]byte, s7commSZLRespLen)
	binary.BigEndian.PutUint16(head[0:2], c.id)
	binary.BigEndian.PutUint16(head[2:4], c.index)
	binary.BigEndian.PutUint16(head[4:6], uint16(len(c.rec)))
	binary.BigEndian.PutUint16(head[6:8], 1)
	return append(head, c.rec...)
}

// fields decodes the response and splits its record.
func (c s7SZLCase) fields(t *testing.T) []S7CommField {
	t.Helper()
	u := s7Decode(t, s7UDPDU(s7TGCPURes, byte(S7CommCPUReadSZL), c.value())).Userdata
	if u.SZL == nil || len(u.SZL.Records) != 1 {
		t.Fatalf("SZL %04x index %04x: %+v", c.id, c.index, u.SZL)
	}
	return u.SZL.Fields(0)
}

// s7SZLFixedCases returns one record for every SZL ID and index with a
// fixed layout, found by asking the lookup about every ID.
func s7SZLFixedCases() []s7SZLCase {
	var cases []s7SZLCase
	add := func(id, index uint16, first []byte) {
		z := &S7CommSZL{ID: id, Index: index}
		defs := z.fieldDefs(first)
		if defs == nil {
			return
		}

		size := 0
		for _, d := range defs {
			size += int(d.size)
		}
		rec := s7Seq(size, 0x10)
		copy(rec, first)
		cases = append(cases, s7SZLCase{id, index, rec})
	}

	for id := 0; id <= 0xFFFF; id++ {
		if id&0xFF == 0x1C {
			// Component identification picks by the record's index.
			for idx := uint16(1); idx <= 0x0C; idx++ {
				add(uint16(id), idx, []byte{0, byte(idx)})
			}
			continue
		}
		for idx := uint16(0); idx <= 0x10; idx++ {
			add(uint16(id), idx, nil)
		}
	}
	return cases
}

// s7SZLRelRecord is a 0x0077 record: 2 parents, no child, 1 redundancy
// link, 1 IO device agent link.
var s7SZLRelRecord = s7Hex("0100" + "0200" + "1100" + "1200" + "0000" + "0100" + "2100" + "0100" + "3100")

// s7SZLDNNRecord builds a 0x0078 record of version 5 with one
// diagnostic entry and, if asked, two TLVs.
func s7SZLDNNRecord(tlvs string) []byte {
	return s7Cat("0500", s7Seq(10, 1), s7Seq(32, 0x41), s7Seq(32, 0x61), "0100",
		"0100", s7Seq(28, 0x80),
		s7Seq(26, 0xc0), "002a", s7Seq(20, 0x30), s7Seq(32, 0x41), s7Seq(22, 0x61), s7Seq(32, 0x41), tlvs)
}

func TestS7CommSZLFieldLayouts(t *testing.T) {
	cases := s7SZLFixedCases()

	// 57 IDs with a layout for each of the 17 indexes tried, 4 IDs for
	// index 0 only, 18 indexes of 0131 and 0132, and 12 component
	// indexes for each of the four xy1C IDs.
	if want := 57*17 + 4 + 18 + 4*12; len(cases) != want {
		t.Errorf("%d fixed SZL layouts, want %d", len(cases), want)
	}

	for _, c := range cases {
		fields := c.fields(t)
		var raw []byte
		for _, f := range fields {
			if f.Name == "" || len(f.Raw) == 0 {
				t.Errorf("SZL %04x index %04x: field %+v", c.id, c.index, f)
			}
			raw = append(raw, f.Raw...)
		}
		if !bytes.Equal(raw, c.rec) {
			t.Errorf("SZL %04x index %04x: fields cover %x of %x", c.id, c.index, raw, c.rec)
		}

		// One octet short has no layout; one more is ignored.
		short := s7SZLCase{c.id, c.index, c.rec[:len(c.rec)-1]}
		if got := short.fields(t); got != nil && c.id&0xFF != 0x1C {
			t.Errorf("SZL %04x index %04x short: %v", c.id, c.index, got)
		}
	}
}

func TestS7CommSZLFieldValues(t *testing.T) {
	for _, c := range []struct {
		name string
		szl  s7SZLCase
		want string
	}{
		{"module identification", s7SZLCase{0x0111, 1, s7TestSZLValue[s7commSZLRespLen:]},
			`[index=1 mlfb="6ES7 315-2EH14-0AB0 " bgtyp=192 ausbg=4 ausbe=1]`},
		{"component name", s7SZLCase{0x001C, 0, s7Cat("0001", []byte("PLC_1"), make([]byte, 27))},
			`[index=1 name="PLC_1" res=0000000000000000]`},
		{"component of an H CPU", s7SZLCase{0x001C, 0, s7Cat("0105", []byte("S C-1"), make([]byte, 27))},
			`[index=261 serialn="S C-1" res=0000000000000000]`},
		{"user memory, other index", s7SZLCase{0x0113, 1, s7Seq(36, 0)}, `[]`},
		{"DNN relations", s7SZLCase{0x0077, 0, s7SZLRelRecord},
			"[version=1 num_parent=2 obj_parent=17 obj_parent=18 num_child=0 num_redundancy_links=1 " +
				"obj_redundancy=33 num_iodevice_agent_links=1 obj_iodevice_agent=49]"},
		{"DNN relations, count lie", s7SZLCase{0x0077, 0, s7Hex("0100" + "ffff" + "1100")}, `[]`},
		{"DNN diagnostics, other version", s7SZLCase{0x0078, 0, s7Hex("0400aabbcc")},
			`[version=4 unknown_version_data=aabbcc]`},
		{"DNN diagnostics, count lie", s7SZLCase{0x0078, 0, s7Cat("0500", s7Seq(76, 1), "ffff", s7Seq(40, 0))}, `[]`},
		{"station status", s7SZLCase{0x0092, 0, s7Seq(16, 1)}, `[status=0102030405060708090a0b0c0d0e0f10]`},
		{"diagnostic buffer", s7SZLCase{0x00A0, 0, s7Hex("4302ff68c70000000b107710" + s7TestStamp)},
			`[eventid=17154 prioclass=255 obnumber=104 datid=50944 info1=0 info2=185628432 time=1408201159337464]`},
	} {
		if got := fmt.Sprint(c.szl.fields(t)); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}

	// A version 5 DNN record with and without the optional TLVs.
	plain := s7SZLCase{0x0078, 0, s7SZLDNNRecord("")}.fields(t)
	tlv := s7SZLCase{0x0078, 0, s7SZLDNNRecord("0200" + "0103aabbcc" + "0200")}.fields(t)
	if len(plain) != 39 || len(tlv) != len(plain)+6 {
		t.Fatalf("DNN diagnostics: %d and %d fields", len(plain), len(tlv))
	}
	if got := fmt.Sprint(tlv[len(plain):]); got != "[tlv_num=2 tlv_type=1 tlv_len=3 tlv_data=aabbcc tlv_type=2 tlv_len=0]" {
		t.Errorf("DNN TLVs: %s", got)
	}
	if plain[6].Name != "name" || plain[6].Text != string(s7Seq(32, 0x41)) || plain[9].Name != "num_cdiag" {
		t.Errorf("DNN fields: %v", plain[:10])
	}

	// A TLV running past the record leaves no fields.
	if got := (s7SZLCase{0x0078, 0, s7SZLDNNRecord("0100" + "01ffaa")}).fields(t); got != nil {
		t.Errorf("DNN TLV overrun: %v", got)
	}
}

func TestS7CommSZLFieldsRange(t *testing.T) {
	z := s7Decode(t, s7UDPDU(s7TGCPURes, byte(S7CommCPUReadSZL), s7TestSZLValue)).Userdata.SZL
	for _, i := range []int{-1, 1, 1 << 20} {
		if got := z.Fields(i); got != nil {
			t.Errorf("Fields(%d) = %v", i, got)
		}
	}
	if (S7CommField{Name: "x", Kind: S7CommFieldKind(9), Raw: []byte{1}}).String() != "x=01" {
		t.Error("unknown kind does not print its octets")
	}
}

// TestS7CommSZLFieldsCut splits records of the variable layouts cut at
// every offset and with every octet changed: no panic, and the fields
// never cover more than the record.
func TestS7CommSZLFieldsCut(t *testing.T) {
	check := func(id uint16, rec []byte) {
		z := &S7CommSZL{ID: id, Records: [][]byte{rec}}
		n := 0
		for _, f := range z.Fields(0) {
			n += len(f.Raw)
		}
		if n > len(rec) {
			t.Fatalf("SZL %04x: fields cover %d of %d octets", id, n, len(rec))
		}
	}

	for id, rec := range map[uint16][]byte{
		0x0077: s7SZLRelRecord,
		0x0078: s7SZLDNNRecord("0200" + "0103aabbcc" + "0200"),
		0x001C: s7Seq(34, 0),
		0x0194: s7Seq(258, 0),
	} {
		for n := 0; n <= len(rec); n++ {
			check(id, rec[:n])
		}
		for i := range rec {
			for _, x := range []byte{0x01, 0x80, 0xff} {
				mod := append([]byte{}, rec...)
				mod[i] ^= x
				check(id, mod)
			}
		}
	}
}

// TestS7CommSZLFieldsAlloc bounds what splitting a record allocates
// when its counts lie: nothing is sized by a count before the count is
// checked against the record.
func TestS7CommSZLFieldsAlloc(t *testing.T) {
	lie := &S7CommSZL{ID: 0x0077, Records: [][]byte{s7Hex("0100" + "ffff" + "1100")}}
	avg := testing.AllocsPerRun(100, func() {
		if lie.Fields(0) != nil {
			t.Fatal("count lie yields fields")
		}
	})
	if avg > 4 {
		t.Errorf("count lie: %.0f allocations", avg)
	}

	rec := s7SZLDNNRecord("")
	bytesPer := testing.Benchmark(func(b *testing.B) {
		z := &S7CommSZL{ID: 0x0078, Records: [][]byte{rec}}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			z.Fields(0)
		}
	}).AllocedBytesPerOp()
	if limit := int64(len(rec)) * 64; bytesPer > limit {
		t.Errorf("DNN record of %d octets: %d octets allocated, limit %d", len(rec), bytesPer, limit)
	}
}
