// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// s7PlusFrame decodes one frame from its octets.
func s7PlusFrame(t *testing.T, b []byte) *S7CommPlus {
	t.Helper()
	s := &S7CommPlus{}
	if err := s.DecodeFromBytes(b, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("frame %x: %v", b, err)
	}
	return s
}

// s7PlusRawFrame builds a frame of version ver around body. The frame
// gets a trailer when last is set.
func s7PlusRawFrame(ver S7CommPlusVersion, body []byte, last bool) []byte {
	f := []byte{S7CommPlusProtocolID, byte(ver), byte(len(body) >> 8), byte(len(body))}
	f = append(f, body...)
	if last {
		f = append(f, S7CommPlusProtocolID, byte(ver), 0, 0)
	}
	return f
}

// System events. No capture has one: the vectors follow the plugin.

const (
	s7PlusEventHead = "00000000" + "000001f4" + "00000000" + "00000000"

	// A STRUCT 0xABC with a member of each type that loses its VLQ, an
	// array, a sparse array and a nested struct.
	s7PlusEventStruct = "0000" + "0017" + "00000abc" +
		"00000001" + "0000" + "0004" + "000000ff" +
		"00000002" + "0000" + "0005" + "0000000100000002" +
		"00000003" + "0000" + "0008" + "fffffffe" +
		"00000004" + "0000" + "0009" + "fffffffffffffffd" +
		"00000005" + "0010" + "0004" + "00000002" + "00000007" + "00000008" +
		"00000006" + "0040" + "0002" + "00000009" + "2a" + "00000000" +
		"00000007" + "0000" + "0017" + "00000def" + "00000008" + "0000" + "0001" + "01" + "00000000" +
		"00000000"
)

func TestS7CommPlusSysEvent(t *testing.T) {
	short, err := DecodeS7CommPlusSysEvent(s7Hex(s7PlusEventHead))
	if err != nil || short.ConfirmedBytes != 500 || short.Message != "" || short.Value != nil {
		t.Errorf("16-octet event: %+v, %v", short, err)
	}

	text, err := DecodeS7CommPlusSysEvent(append(s7Hex(s7PlusEventHead), "LOGOUT"...))
	if err != nil || text.Message != "LOGOUT" || text.Value != nil {
		t.Errorf("text event: %+v, %v", text, err)
	}

	// Through the frame decoder: version 0xFE, no trailer.
	s := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusKeepAlive, s7Hex(s7PlusEventHead+s7PlusEventStruct), false))
	if _, err := s.DecodeBody(); !errors.Is(err, ErrS7CommPlusFragment) {
		t.Errorf("DecodeBody of a system event: %v", err)
	}
	e, err := s.DecodeSysEvent()
	if err != nil || e.Value == nil || len(e.Rest) != 0 {
		t.Fatalf("binary event: %+v, %v", e, err)
	}

	v := e.Value
	if v.Type != S7CommPlusTypeStruct || v.Elements[0].Uint() != 0xabc || len(v.Members) != 7 {
		t.Fatalf("struct: %+v", v)
	}
	m := v.Members
	for i, want := range []uint64{0xff, 0x100000002} {
		if m[i].ID != uint32(i+1) || m[i].Value.Elements[0].Uint() != want {
			t.Errorf("member %d: %+v", i+1, m[i])
		}
	}
	if m[2].Value.Elements[0].Int() != -2 || m[3].Value.Elements[0].Int() != -3 {
		t.Errorf("signed members: %+v %+v", m[2], m[3])
	}
	if a := m[4].Value.Elements; len(a) != 2 || a[0].Uint() != 7 || a[1].Uint() != 8 {
		t.Errorf("array: %+v", a)
	}
	if a := m[5].Value.Elements; len(a) != 1 || a[0].Key != 9 || a[0].Uint() != 0x2a {
		t.Errorf("sparse array: %+v", a)
	}
	if in := m[6].Value; in.Elements[0].Uint() != 0xdef || len(in.Members) != 1 || in.Members[0].ID != 8 {
		t.Errorf("nested struct: %+v", in)
	}
}

func TestS7CommPlusSysEventBad(t *testing.T) {
	whole := s7Hex(s7PlusEventHead + s7PlusEventStruct)
	for n := 0; n < len(whole); n++ {
		e, err := DecodeS7CommPlusSysEvent(whole[:n])
		switch {
		case n < s7plusEventHeadLen:
			if e != nil || !errors.Is(err, ErrS7CommPlusMalformed) {
				t.Errorf("cut at %d: %+v, %v", n, e, err)
			}
		case n < s7plusEventHeadLen+s7plusEventMarkLen:
			// Too short for a struct: read as text.
			if err != nil || e.Value != nil {
				t.Errorf("cut at %d: %+v, %v", n, e, err)
			}
		default:
			if e == nil || !errors.Is(err, ErrS7CommPlusMalformed) {
				t.Errorf("cut at %d: %+v, %v", n, e, err)
			}
		}
	}

	if _, err := (&S7CommPlus{Version: S7CommPlusV2}).DecodeSysEvent(); !errors.Is(err, ErrS7CommPlusUnsupported) {
		t.Errorf("V2 frame: %v", err)
	}

	// Structs nested past the cap.
	deep := s7PlusEventHead + "0000" + "0017" + "00000001" +
		strings.Repeat("00000001"+"0000"+"0017"+"00000001", s7plusMaxDepth+1)
	if _, err := DecodeS7CommPlusSysEvent(s7Hex(deep)); !errors.Is(err, ErrS7CommPlusTooDeep) {
		t.Errorf("deep event: %v", err)
	}

	// An array size the event cannot hold allocates nothing.
	lie := s7Hex(s7PlusEventHead + "0000" + "0017" + "00000001" + "00000001" + "0010" + "0004" + "ffffffff")
	avg := testing.AllocsPerRun(20, func() {
		if _, err := DecodeS7CommPlusSysEvent(lie); !errors.Is(err, ErrS7CommPlusMalformed) {
			t.Fatalf("array size lie: %v", err)
		}
	})
	if avg > 20 {
		t.Errorf("array size lie: %.0f allocations", avg)
	}
}

// Subscription reference lists.

// Frames 32 and 35 of the ICS-pcap capture V13_1200_TP1200sim_..._
// Timer_sync: a V13 HMI subscribes to two memory words, and the PLC's
// first notification names them by reference number.
const (
	s7PlusSubscribeFrame = "720200bf" + "31000004ca000000040000039834" +
		"000003af00040000000000a17fffc00187690000a38169001517537562736372697074696f6e5f32313437343637323635" +
		"a3883a000200a3876a00030000a3876b000900a38810000205a38811000101" +
		"a388182004118880848000000288809080028fffffff7e00528ae28fb7009d1809" +
		"88809080028fffffff7f00528a8ee5ef369d180a" +
		"a3881900048768a3881a000400a3881b000200a3881c000200a3881d00070003a3881e0003ffffa200000000" + "72020000"
	s7PlusNotifyFrame = "72020024" + "331000006a040000000000010192ffffffff000703e992fffffffe0007000200" + "00000000" + "72020000"
)

// s7PlusUDInts builds the value of a UDInt address array.
func s7PlusUDInts(words ...uint32) *S7CommPlusValue {
	v := &S7CommPlusValue{Flags: S7CommPlusFlagAddressArray, Type: S7CommPlusTypeUDInt}
	for _, w := range words {
		v.Elements = append(v.Elements, S7CommPlusElement{Type: S7CommPlusTypeUDInt, Bits: uint64(w)})
	}
	return v
}

func TestS7CommPlusSubRefs(t *testing.T) {
	b, err := s7PlusFrame(t, s7Hex(s7PlusSubscribeFrame)).DecodeBody()
	if err != nil || b.Elements == nil || len(b.Elements.Objects) != 1 {
		t.Fatalf("subscribe: %+v, %v", b, err)
	}

	var refs *S7CommPlusSubscriptionRefs
	for i := range b.Elements.Objects[0].Attributes {
		if a := &b.Elements.Objects[0].Attributes[i]; a.ID == S7CommPlusIDSubscriptionRefs {
			if refs, err = a.Value.SubscriptionRefs(); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Two memory words (area 82, ControllerArea.ValueActual 3736) by
	// symbol CRC and one LID each; every array element is used.
	want := &S7CommPlusSubscriptionRefs{Header: 0x80010000, Subscribed: []S7CommPlusSubscriptionRef{
		{Head: 0x80040002, RefNumber: 0xfffffffe, Address: S7CommPlusAddress{SymbolCRC: 0xac43db80, AccessArea: 82, LIDCount: 2, AccessSubArea: 3736, LIDs: []uint32{9}}},
		{Head: 0x80040002, RefNumber: 0xffffffff, Address: S7CommPlusAddress{SymbolCRC: 0xa1d977b6, AccessArea: 82, LIDCount: 2, AccessSubArea: 3736, LIDs: []uint32{10}}},
	}}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("refs:\n got %+v\nwant %+v", refs, want)
	}
	if !refs.New() || refs.ChangeCounter() != 1 {
		t.Errorf("header: new %v, change counter %d", refs.New(), refs.ChangeCounter())
	}

	// The notification's items are the subscribed reference numbers.
	nb, err := s7PlusFrame(t, s7Hex(s7PlusNotifyFrame)).DecodeBody()
	if err != nil || nb.Notification == nil || len(nb.Notification.Items) != 2 {
		t.Fatalf("notification: %+v, %v", nb, err)
	}
	known := map[uint32]bool{}
	for _, r := range refs.Subscribed {
		known[r.RefNumber] = true
	}
	for _, it := range nb.Notification.Items {
		if !known[it.ItemRef] {
			t.Errorf("notification item %#x was not subscribed", it.ItemRef)
		}
	}
}

func TestS7CommPlusSubRefsBuilt(t *testing.T) {
	// Two to drop; a DB word by classic blob access (CRC 0, LID 3,
	// offset, count: three LIDs although the head says one); a bit with
	// four LIDs; a plain ID without LIDs; one element left over.
	words := []uint32{0x00020000, 2, 3, 11, 12,
		2, 21, 0, 0x8a0e0001, 0, 2550, 3, 4, 2,
		5, 22, 0, 0x8a0e0002, 0, 2550, 3, 8, 1, 6,
		1, 23, 7, 300, 0xdead, 2000,
		99}
	l, err := s7PlusUDInts(words...).SubscriptionRefs()
	if err != nil {
		t.Fatal(err)
	}

	want := &S7CommPlusSubscriptionRefs{Header: 0x00020000, Unsubscribed: []uint32{11, 12}, Rest: []uint32{99},
		Subscribed: []S7CommPlusSubscriptionRef{
			{Head: 2, RefNumber: 21, Address: S7CommPlusAddress{AccessArea: 0x8a0e0001, LIDCount: 2, AccessSubArea: 2550, LIDs: []uint32{3, 4, 2}}},
			{Head: 5, RefNumber: 22, Address: S7CommPlusAddress{AccessArea: 0x8a0e0002, LIDCount: 5, AccessSubArea: 2550, LIDs: []uint32{3, 8, 1, 6}}},
			{Head: 1, RefNumber: 23, Unknown: 7, Address: S7CommPlusAddress{SymbolCRC: 0xdead, AccessArea: 300, LIDCount: 1, AccessSubArea: 2000}},
		}}
	if !reflect.DeepEqual(l, want) {
		t.Errorf("refs:\n got %+v\nwant %+v", l, want)
	}
	if l.New() || l.ChangeCounter() != 2 {
		t.Errorf("header: new %v, change counter %d", l.New(), l.ChangeCounter())
	}

	// Every shorter array fails or decodes fewer words; none panics.
	for n := 0; n < len(words)-1; n++ {
		l, err := s7PlusUDInts(words[:n]...).SubscriptionRefs()
		if err == nil {
			t.Errorf("%d of %d words: %+v", n, len(words), l)
		}
		if !errors.Is(err, ErrS7CommPlusMalformed) {
			t.Errorf("%d words: %v", n, err)
		}
	}

	// Counts above the array are refused before anything is sized by them.
	for _, lie := range [][]uint32{{0, 0xffffffff, 0}, {0, 0, 0xffffffff}, {0, 1, 1, 5, 6}, {0, 0, 1, 0xffff, 1, 0, 300, 1, 2, 3}} {
		v := s7PlusUDInts(lie...)
		avg := testing.AllocsPerRun(20, func() {
			if _, err := v.SubscriptionRefs(); !errors.Is(err, ErrS7CommPlusMalformed) {
				t.Fatalf("%v: %v", lie, err)
			}
		})
		if avg > 6 {
			t.Errorf("%v: %.0f allocations", lie, avg)
		}
	}

	// Only an address array of UDInt is a list.
	for _, v := range []*S7CommPlusValue{
		{Flags: S7CommPlusFlagArray, Type: S7CommPlusTypeUDInt, Elements: make([]S7CommPlusElement, 3)},
		{Flags: S7CommPlusFlagAddressArray, Type: S7CommPlusTypeDInt, Elements: make([]S7CommPlusElement, 3)},
		{},
	} {
		if _, err := v.SubscriptionRefs(); !errors.Is(err, ErrS7CommPlusMalformed) {
			t.Errorf("%+v: %v", v, err)
		}
	}
}

// Type list offsets. No capture has a type list: the layout follows
// the plugin.

// s7PlusOffsetInfo builds the offset part of offset info type t: the
// legacy pair 0x0101, 0x0202, then the 32-bit words 1, 2, 3, ...
func s7PlusOffsetInfo(t uint8) []byte {
	b := s7Hex("0101" + "0202")
	for w := uint32(1); len(b) < s7plusOffsetLen(t); w++ {
		b = binary.LittleEndian.AppendUint32(b, w)
	}
	return b
}

func TestS7CommPlusVarOffsets(t *testing.T) {
	const pair1, pair2 = 0x0101, 0x0202
	info := func(first uint32) [4]uint32 { return [4]uint32{first, first + 1, first + 2, first + 3} }
	bounds := func(first int32) (b [6]int32) {
		for i := range b {
			b[i] = first + int32(i)
		}
		return b
	}
	counts := func(first uint32) (c [6]uint32) {
		for i := range c {
			c[i] = first + uint32(i)
		}
		return c
	}

	for _, c := range []struct {
		name string
		typ  uint8
		soft uint8
		want S7CommPlusVarOffsets
	}{
		{"standard", s7plusOffStd, 5, S7CommPlusVarOffsets{OptimizedAddr: pair1, NonOptimizedAddr: pair2}},
		{"struct element, standard", s7plusOffElemStd, 5, S7CommPlusVarOffsets{NonOptimizedAddr: pair1, OptimizedAddr: pair2}},
		{"string", s7plusOffString, s7plusSoftString,
			S7CommPlusVarOffsets{StringLength: pair1, Unspecified2: pair2, OptimizedAddr: 1, NonOptimizedAddr: 2}},
		{"string type, not a string", s7plusOffString, 5,
			S7CommPlusVarOffsets{Unspecified1: pair1, Unspecified2: pair2, OptimizedAddr: 1, NonOptimizedAddr: 2}},
		{"array of wstring", s7plusOffArray1, s7plusSoftWString,
			S7CommPlusVarOffsets{StringLength: pair1, Unspecified2: pair2, OptimizedAddr: 1, NonOptimizedAddr: 2,
				ArrayLowerBound: 3, ArrayElementCount: 4}},
		{"multi-dimensional array", s7plusOffElemArrayM, 5,
			S7CommPlusVarOffsets{Unspecified1: pair1, Unspecified2: pair2, OptimizedAddr: 1, NonOptimizedAddr: 2,
				ArrayLowerBound: 3, ArrayElementCount: 4, DimLowerBounds: bounds(5), DimElementCounts: counts(11)}},
		{"struct", s7plusOffStruct, 17,
			S7CommPlusVarOffsets{Unspecified1: pair1, Unspecified2: pair2, OptimizedAddr: 1, NonOptimizedAddr: 2,
				StructRelationID: 3, StructInfo: info(4)}},
		{"array of struct", s7plusOffElemStruct1, 17,
			S7CommPlusVarOffsets{Unspecified1: pair1, Unspecified2: pair2, OptimizedAddr: 1, NonOptimizedAddr: 2,
				ArrayLowerBound: 3, ArrayElementCount: 4, NonOptimizedStructSize: 5, OptimizedStructSize: 6,
				StructRelationID: 7, StructInfo: info(8)}},
		{"multi-dimensional array of struct", s7plusOffStructM, 17,
			S7CommPlusVarOffsets{Unspecified1: pair1, Unspecified2: pair2, OptimizedAddr: 1, NonOptimizedAddr: 2,
				ArrayLowerBound: 3, ArrayElementCount: 4, DimLowerBounds: bounds(5), DimElementCounts: counts(11),
				NonOptimizedStructSize: 17, OptimizedStructSize: 18, StructRelationID: 19, StructInfo: info(20)}},
		{"FB", s7plusOffFBSFB, 0,
			S7CommPlusVarOffsets{Unspecified1: pair1, Unspecified2: pair2, OptimizedAddr: 1, NonOptimizedAddr: 2,
				FBRelationID: 3, FBInfo: info(4), FBRetainOffset: 8, FBVolatileOffset: 9}},
		{"FB array", s7plusOffFBArray, 0,
			S7CommPlusVarOffsets{Unspecified1: pair1, Unspecified2: pair2, OptimizedAddr: 1, NonOptimizedAddr: 2,
				FBRelationID: 3, FBInfo: info(4), FBRetainOffset: 8, FBVolatileOffset: 9,
				ArrayElementCount: 10, FBClassicSize: 11, FBRetainSize: 12, FBVolatileSize: 13,
				DimLowerBounds: bounds(14), DimElementCounts: counts(20)}},
	} {
		v := S7CommPlusVarType{SoftDatatype: c.soft, AttributeFlags: uint16(c.typ) << s7plusOffsetTypeShift, OffsetInfo: s7PlusOffsetInfo(c.typ)}
		got, ok := v.Offsets()
		if !ok || got != c.want {
			t.Errorf("%s:\n got %+v (%v)\nwant %+v", c.name, got, ok, c.want)
		}
	}

	// Every type takes exactly its size and nothing else.
	for typ := uint8(0); typ < 16; typ++ {
		v := S7CommPlusVarType{AttributeFlags: uint16(typ) << s7plusOffsetTypeShift, OffsetInfo: s7PlusOffsetInfo(typ)}
		if _, ok := v.Offsets(); !ok {
			t.Errorf("type %d: not decoded", typ)
		}
		for _, info := range [][]byte{nil, v.OffsetInfo[:len(v.OffsetInfo)-1], append(v.OffsetInfo[:len(v.OffsetInfo):len(v.OffsetInfo)], 0)} {
			v.OffsetInfo = info
			if o, ok := v.Offsets(); ok || o != (S7CommPlusVarOffsets{}) {
				t.Errorf("type %d with %d octets: %+v", typ, len(info), o)
			}
		}
	}

	// Through the decoder: the type list of the object tree vector.
	for _, c := range s7PlusFuncCases {
		b, _ := DecodeS7CommPlusBody(c.ver, c.op, c.fn, s7Hex(c.data))
		s7PlusWalk(b, nil, func(v *S7CommPlusVarType) {
			if _, ok := v.Offsets(); !ok {
				t.Errorf("%s: offsets of %+v", c.name, v)
			}
		})
	}
}

// s7PlusWalk calls value for every ID/value of a body and varType for
// every type list entry, at any depth.
func s7PlusWalk(b *S7CommPlusBody, value func(*S7CommPlusIDValue), varType func(*S7CommPlusVarType)) {
	if b == nil {
		return
	}

	var values func(vals []S7CommPlusIDValue)
	values = func(vals []S7CommPlusIDValue) {
		for i := range vals {
			if value != nil {
				value(&vals[i])
			}
			values(vals[i].Value.Members)
			for _, m := range vals[i].Value.StructArray {
				values(m)
			}
			for _, e := range vals[i].Value.Elements {
				if e.Blob != nil {
					values(e.Blob.Values)
				}
			}
		}
	}

	var elements func(es *S7CommPlusElements)
	elements = func(es *S7CommPlusElements) {
		if es == nil {
			return
		}
		values(es.Attributes)
		for i := range es.VarTypes {
			if varType != nil {
				varType(&es.VarTypes[i])
			}
		}
		for i := range es.Objects {
			elements(&es.Objects[i].S7CommPlusElements)
		}
	}

	values(b.Values)
	elements(b.Elements)
	if b.Qualifier != nil {
		values(b.Qualifier.Values)
	}
	if b.Notification == nil {
		return
	}
	for _, it := range append(append([]S7CommPlusNotifyItem{}, b.Notification.Items...), b.Notification.Items2...) {
		elements(it.Elements)
	}
}

// The functions nobody has described stay undecoded: no layout is
// guessed for them.
func TestS7CommPlusUnknownFuncs(t *testing.T) {
	data := s7Hex("00" + "0102030405" + "00000000")
	for _, fn := range []S7CommPlusFunction{S7CommPlusFuncAddLink, S7CommPlusFuncRemoveLink, S7CommPlusFuncGetVariablesAddr, S7CommPlusFuncAbort} {
		for _, op := range []S7CommPlusOpcode{S7CommPlusOpRequest, S7CommPlusOpResponse} {
			b, err := DecodeS7CommPlusBody(S7CommPlusV2, op, fn, data)
			if !errors.Is(err, ErrS7CommPlusUnsupported) || b == nil || !bytes.Equal(b.Rest, data) {
				t.Errorf("%v %v: %+v, %v", op, fn, b, err)
			}
			if !reflect.DeepEqual(b, &S7CommPlusBody{Rest: data}) {
				t.Errorf("%v %v: fields set: %+v", op, fn, b)
			}
		}
	}
}

// Dry runs. A body decodes to the same tree whether its lists were
// counted first or grown by appending.

func TestS7CommPlusDryRun(t *testing.T) {
	for _, v := range append(s7PlusBodyVectors(t), s7PlusAllocCases()...) {
		data := []byte(v.data)
		b, err := DecodeS7CommPlusBody(v.ver, v.op, v.fn, data)

		// The lists hold exactly their entries: counted, not grown.
		s7PlusWalk(b, func(iv *S7CommPlusIDValue) {
			if m := iv.Value.Members; cap(m) != len(m) {
				t.Fatalf("%s: member list of %d has room for %d", v.name, len(m), cap(m))
			}
		}, nil)
		if b != nil && cap(b.Values) != len(b.Values) && v.fn != S7CommPlusFuncSetMultiVariables {
			t.Errorf("%s: value list of %d has room for %d", v.name, len(b.Values), cap(b.Values))
		}

		// Decoding again gives the same tree: no state leaks from a run.
		again, err2 := DecodeS7CommPlusBody(v.ver, v.op, v.fn, data)
		if !reflect.DeepEqual(b, again) || (err == nil) != (err2 == nil) {
			t.Errorf("%s: second decode differs", v.name)
		}
	}
}

// TestS7CommPlusDryRunCost bounds the work of a body nested to the
// cap: the dry run of the outermost list covers the lists inside, so
// each level is not walked once per level above it.
func TestS7CommPlusDryRunCost(t *testing.T) {
	const levels = s7plusMaxDepth - 2
	item := "01" + "0017" + "00000001"
	nest := "00" + strings.Repeat(item, levels) + strings.Repeat("010000", 2000) + strings.Repeat("00", levels+1) + "00"
	data := s7Hex(nest)

	b, err := DecodeS7CommPlusBody(S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetMultiVariables, data)
	if err != nil || len(b.Values) != 1 {
		t.Fatalf("nested body: %v", err)
	}

	got := allocPerByte(len(data), func() {
		_, _ = DecodeS7CommPlusBody(S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetMultiVariables, data)
	})
	if got > 60 {
		t.Errorf("nested body allocates %.1f bytes per input byte", got)
	}

	// One dry run for the whole nest.
	r := &s7plusReader{b: data[1:]}
	if list := r.itemList(); r.err != nil || len(list) != 1 || r.dryRuns != 1 {
		t.Errorf("nested list: %d dry runs, %d items, err %v", r.dryRuns, len(list), r.err)
	}

	// Empty lists have no hint and look for themselves: one terminator
	// each, however many there are.
	r = &s7plusReader{b: s7Hex(strings.Repeat("01"+"0017"+"00000001"+"00", 100) + "00")}
	if list := r.itemList(); r.err != nil || len(list) != 100 || r.dryRuns != 101 || len(r.b) != 0 {
		t.Errorf("empty structs: %d dry runs, %d items, err %v", r.dryRuns, len(list), r.err)
	}
}
