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
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// tshark has no S7comm-plus dissector, so the body tests check
// structure instead: every whole PDU of the captures decodes with only
// zero fill left over, responses repeat what their request asked for,
// and the spot-checked values are visible in the frame bytes (symbol
// names, CPU order number, DB number of the address).

// s7PlusQualifier is the object qualifier the captures' variable
// requests end with: ID 1256, then RID 1257, AID 1258, UDInt 1259.
const s7PlusQualifier = "000004e8" + "89690012" + "00000000" + "896a001300" + "896b000400" + "00"

// s7PlusBodies decodes the body of every whole PDU in frames, keyed by
// 1-based frame number. It fails on any decode error and on fill that
// is not zero.
func s7PlusBodies(t *testing.T, name string, frames map[int]*S7CommPlus) map[int]*S7CommPlusBody {
	t.Helper()
	out := map[int]*S7CommPlusBody{}
	for f, s := range frames {
		if !s.HasDataHeader || !s.HasTrailer {
			continue
		}

		b, err := s.DecodeBody()
		if err != nil {
			t.Errorf("%s frame %d (%v %v): %v", name, f, s.Opcode, s.Function, err)
			continue
		}
		if len(b.Rest) > 10 || strings.Trim(string(b.Rest), "\x00") != "" {
			t.Errorf("%s frame %d: rest %x", name, f, b.Rest)
		}
		out[f] = b
	}
	return out
}

func TestS7CommPlusBodyOPC(t *testing.T) {
	frames := s7PlusLayers(s7Packets(t, "s7commplus-1511-opc.pcap"))
	bodies := s7PlusBodies(t, "1511", frames)
	if len(bodies) != 27 {
		t.Errorf("decoded %d bodies, want 27", len(bodies))
	}

	// The integrity ID of a response is its request's plus the
	// sequence number.
	reqID := map[uint16]uint32{}
	pairs := 0
	for f := 1; f <= 70; f++ {
		b, s := bodies[f], frames[f]
		if b == nil || !b.HasIntegrityID {
			continue
		}

		if s.Opcode == S7CommPlusOpRequest {
			reqID[s.Sequence] = b.IntegrityID
			continue
		}

		// The session setup response (seq 2) answers a request
		// without an ID.
		id, ok := reqID[s.Sequence]
		if !ok {
			continue
		}
		pairs++
		if b.IntegrityID != id+uint32(s.Sequence) {
			t.Errorf("frame %d: integrity ID %d, request %d + seq %d", f, b.IntegrityID, id, s.Sequence)
		}
	}
	if pairs != 7 {
		t.Errorf("checked %d integrity pairs, want 7", pairs)
	}

	s7PlusCheckOPCSession(t, bodies)
	s7PlusCheckOPCValues(t, bodies)
}

// s7PlusCheckOPCSession checks the session setup of the 1511 capture.
func s7PlusCheckOPCSession(t *testing.T, bodies map[int]*S7CommPlusBody) {
	t.Helper()
	req := bodies[9]
	if req.ObjectID != 0x11d || req.Elements == nil || len(req.Elements.Objects) != 1 {
		t.Fatalf("CreateObject request = %+v", req)
	}
	sess := req.Elements.Objects[0]
	if sess.RelationID != 0xd3 || sess.ClassID != 287 || len(sess.Attributes) != 8 || len(sess.Objects) != 1 {
		t.Errorf("session object = %+v", sess)
	}
	if a := sess.Attributes[0]; a.ID != 233 || string(a.Value.Elements[0].Bytes) != "ServerSession_10000002" {
		t.Errorf("session name = %+v", a)
	}
	if sub := sess.Objects[0]; sub.ClassID != 255 || string(sub.Attributes[0].Value.Elements[0].Bytes) != "SubscriptionContainer" {
		t.Errorf("subscription container = %+v", sub)
	}

	resp := bodies[11]
	if resp.Return != 0 || !reflect.DeepEqual(resp.ObjectIDs, []uint32{0x386, 0x387}) {
		t.Errorf("CreateObject response = %+v", resp)
	}
	srv := resp.Elements.Objects[0]
	cpu := srv.Attributes[4].Value
	if cpu.Type != S7CommPlusTypeStruct || cpu.Elements[0].Bits != 0x13a || len(cpu.Members) != 7 ||
		string(cpu.Members[4].Value.Elements[0].Bytes) != "1;6ES7 511-1AK00-0AB0;V1.0" {
		t.Errorf("server info struct = %+v", cpu)
	}
}

// s7PlusCheckOPCValues checks addresses and values of the 1511 capture.
func s7PlusCheckOPCValues(t *testing.T, bodies map[int]*S7CommPlusBody) {
	t.Helper()
	get := bodies[29]
	want := S7CommPlusAddress{SymbolCRC: 0x8db7863, AccessArea: 0x8a0e0006, LIDCount: 2, AccessSubArea: 2550, LIDs: []uint32{22}}
	want.SymbolCRC = get.Addresses[0].SymbolCRC
	if len(get.Addresses) != 1 || !reflect.DeepEqual(get.Addresses[0], want) || get.FieldCount != 5 {
		t.Errorf("GetMultiVariables address = %+v", get.Addresses)
	}
	if db, ok := get.Addresses[0].DBNumber(); !ok || db != 6 {
		t.Errorf("DB number = %d, %v", db, ok)
	}
	if q := get.Qualifier; q == nil || q.ID != 1256 || len(q.Values) != 3 || q.Values[0].Value.Type != S7CommPlusTypeRID {
		t.Errorf("qualifier = %+v", q)
	}

	// 40 variables of every type: request addresses, response values.
	if n := len(bodies[62].Addresses); n != 40 {
		t.Errorf("request has %d addresses", n)
	}
	vals := bodies[64].Values
	if len(vals) != 40 {
		t.Fatalf("response has %d values", len(vals))
	}
	checks := []struct {
		item  int
		typ   S7CommPlusDatatype
		count int
	}{
		{1, S7CommPlusTypeByte, 11}, {2, S7CommPlusTypeBool, 1}, {12, S7CommPlusTypeUInt, 1},
		{22, S7CommPlusTypeTimestamp, 1}, {24, S7CommPlusTypeLReal, 1}, {25, S7CommPlusTypeTimespan, 1},
		{28, S7CommPlusTypeReal, 1}, {30, S7CommPlusTypeSInt, 1}, {31, S7CommPlusTypeUSInt, 256},
	}
	for _, c := range checks {
		v := vals[c.item-1]
		if v.ID != uint32(c.item) || v.Value.Type != c.typ || len(v.Value.Elements) != c.count {
			t.Errorf("item %d = %v x%d, want %v x%d", v.ID, v.Value.Type, len(v.Value.Elements), c.typ, c.count)
		}
	}

	// Item 12 is a DTL year (1970); item 31 an S7 STRING[254], whose
	// first octet is the maximum length.
	if y := vals[11].Value.Elements[0].Uint(); y != 1970 {
		t.Errorf("year = %d", y)
	}
	if m := vals[30].Value.Elements[0].Uint(); m != 254 {
		t.Errorf("string max length = %d", m)
	}

	sub := bodies[22].Value
	if sub.Type != S7CommPlusTypeDInt || sub.Elements[0].Int() != 250 {
		t.Errorf("GetVarSubStreamed value = %+v", sub)
	}
}

func TestS7CommPlusBodyUpload(t *testing.T) {
	frames := s7PlusLayers(s7Packets(t, "s7commplus-1200-upload.pcap"))
	bodies := s7PlusBodies(t, "1200", frames)
	if len(bodies) != 85 {
		t.Errorf("decoded %d bodies, want 85", len(bodies))
	}

	// Every GetMultiVariables response has a value or an error per
	// requested item.
	asked := map[uint16]uint32{}
	pairs := 0
	for f := 1; f <= len(frames)+200; f++ {
		b, s := bodies[f], frames[f]
		if b == nil || s.Function != S7CommPlusFuncGetMultiVariables {
			continue
		}

		if s.Opcode == S7CommPlusOpRequest {
			asked[s.Sequence] = b.ItemCount
			continue
		}
		pairs++
		if got := uint32(len(b.Values) + len(b.Errors)); got != asked[s.Sequence] {
			t.Errorf("frame %d: %d results for %d items", f, got, asked[s.Sequence])
		}
	}
	if pairs != 22 {
		t.Errorf("checked %d GetMultiVariables pairs, want 22", pairs)
	}

	areas := map[string]bool{}
	for _, o := range bodies[93].Elements.Objects[0].Objects[0].Objects {
		if len(o.Attributes) > 0 {
			areas[string(o.Attributes[0].Value.Elements[0].Bytes)] = true
		}
	}
	for _, n := range []string{"ProgramCyclePI", "IArea", "QArea", "MArea"} {
		if !areas[n] {
			t.Errorf("Explore response lacks %s: %v", n, areas)
		}
	}

	if e := bodies[57].Explore; e == nil || e.ChildsRecursive != 1 || len(e.Sets) != 1 || len(e.Sets[0].IDs) != 38 {
		t.Errorf("Explore request = %+v", e)
	}
	if l := bodies[37].ObjectIDs; len(l) != 16 || l[0] != 0x88e10102 {
		t.Errorf("GetLink link IDs = %x", l)
	}
	seq := bodies[121]
	if seq.Sequence == nil || seq.Sequence.ValueType != 1 || seq.Elements == nil ||
		string(seq.Elements.Objects[0].Attributes[0].Value.Elements[0].Bytes) != "DLTransaction" {
		t.Errorf("BeginSequence request = %+v", seq)
	}

	s7PlusCheckUpload(t, frames)
}

// s7PlusCheckUpload decodes the CreateObject request split over
// frames 127-129 from the concatenated Data.
func s7PlusCheckUpload(t *testing.T, frames map[int]*S7CommPlus) {
	t.Helper()
	first := frames[127]
	if _, err := first.DecodeBody(); !errors.Is(err, ErrS7CommPlusFragment) {
		t.Errorf("fragment DecodeBody: %v", err)
	}

	data := bytes.Join([][]byte{first.Data, frames[128].Data, frames[129].Data}, nil)
	b, err := DecodeS7CommPlusBody(first.Version, first.Opcode, first.Function, data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Rest, make([]byte, 4)) || b.Elements == nil || len(b.Elements.Objects) != 1 {
		t.Fatalf("reassembled CreateObject: rest %x, %+v", b.Rest, b.Elements)
	}
	if ob := b.Elements.Objects[0]; string(ob.Attributes[0].Value.Elements[0].Bytes) != "Main" {
		t.Errorf("uploaded block = %+v", ob.Attributes[0])
	}
}

// Frames of github.com/automayt/ICS-pcap captures not kept in testdata.
var (
	// S7-1511_db2_var1_HMI frame 37: DeleteObject response ending in a
	// bare digest, which the plugin misreads as an integrity ID.
	s7PlusDeleteResp1511 = "00" + "00000388" + "20" + "58a62600649a22eeb5be53920fe687176f698afa1e9be8547abd42bc83afd1e4"
	// V13_1200_TP1200sim_..._Timer_sync frame 35: notification of two
	// INT values (1001 and 2).
	s7PlusNotify1200 = "1000006a" + "0400" + "0000" + "0000" + "01" + "01" +
		"92" + "ffffffff" + "0007" + "03e9" + "92" + "fffffffe" + "0007" + "0002" + "00" + "00" + "00000000"
	// Same capture, frame 43: SetVariable request writing INT 6.
	s7PlusSetVar1200 = "1000006a" + "01" + "881d" + "0007" + "0006" + s7PlusQualifier + "00" + "00000000"
)

// s7PlusCase is a body decoding vector.
type s7PlusCase struct {
	name  string
	ver   S7CommPlusVersion
	op    S7CommPlusOpcode
	fn    S7CommPlusFunction
	data  string
	check func(t *testing.T, b *S7CommPlusBody)
}

// s7PlusValue returns the single value of a body, or fails.
func s7PlusValue(t *testing.T, b *S7CommPlusBody) *S7CommPlusValue {
	t.Helper()
	if b.Value == nil {
		t.Fatal("no value")
	}
	return b.Value
}

// s7PlusValueCases are GetVariable responses (return value, value)
// built from the plugin's datatype layouts; no capture has them all.
var s7PlusValueCases = []s7PlusCase{
	{"real", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "000e3fc00000" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if f := s7PlusValue(t, b).Elements[0].Float(); f != 1.5 {
				t.Errorf("real = %g", f)
			}
		}},
	{"signed", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "00137f" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if e := s7PlusValue(t, b).Elements[0]; e.Type != S7CommPlusTypeAID || e.Uint() != 127 {
				t.Errorf("AID = %+v", e)
			}
		}},
	{"dint array", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "1008" + "03" + "7f" + "41" + "8100" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			v := s7PlusValue(t, b)
			if len(v.Elements) != 3 || v.Elements[0].Int() != -1 || v.Elements[1].Int() != -63 || v.Elements[2].Int() != 128 {
				t.Errorf("DInt array = %+v", v.Elements)
			}
		}},
	{"int sint lword", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetMultiVariables,
		"00" + "010007fffe" + "020006ff" + "03000d0102030405060708" + "00" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if v := b.Values; len(v) != 3 || v[0].Value.Elements[0].Int() != -2 || v[1].Value.Elements[0].Int() != -1 ||
				v[2].Value.Elements[0].Uint() != 0x0102030405060708 {
				t.Errorf("values = %+v", v)
			}
		}},
	{"timestamp timespan", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetMultiVariables,
		"00" + "010010" + "16b8e5e2ff7a1800" + "0200117f" + "00" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			ts := b.Values[0].Value.Elements[0].Time()
			if ts.Year() != 2021 || b.Values[1].Value.Elements[0].Duration() != -time.Nanosecond {
				t.Errorf("time = %v, span = %v", ts, b.Values[1].Value.Elements[0].Duration())
			}
		}},
	{"wstring", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "00150568656c6c6f" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if s := string(s7PlusValue(t, b).Elements[0].Bytes); s != "hello" {
				t.Errorf("wstring = %q", s)
			}
		}},
	{"sparse", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "4004" + "0105" + "028100" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			v := s7PlusValue(t, b)
			if len(v.Elements) != 2 || v.Elements[1].Key != 2 || v.Elements[1].Uint() != 128 {
				t.Errorf("sparse = %+v", v.Elements)
			}
		}},
	{"variant", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "1016" + "02" + "00070102" + "0015026869" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			v := s7PlusValue(t, b)
			if v.Elements[0].Type != S7CommPlusTypeInt || v.Elements[0].Int() != 0x102 || string(v.Elements[1].Bytes) != "hi" {
				t.Errorf("variant = %+v", v.Elements)
			}
		}},
	{"struct array", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "2017" + "00000123" + "02" + "0100020500" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			v := s7PlusValue(t, b)
			if len(v.StructArray) != 2 || len(v.StructArray[0]) != 1 || v.StructArray[0][0].Value.Elements[0].Uint() != 5 {
				t.Errorf("struct array = %+v", v.StructArray)
			}
		}},
	{"packed struct", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "001702000010" + "0000000000000001" + "00" + "03" + "aabbcc" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if p := s7PlusValue(t, b).Packed; p == nil || !bytes.Equal(p.Data, s7Hex("aabbcc")) || p.InterfaceTimestamp != 1 {
				t.Errorf("packed = %+v", p)
			}
		}},
	{"blob", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "0014" + "01" + "03" + "010203" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if e := s7PlusValue(t, b).Elements[0]; e.Blob != nil || !bytes.Equal(e.Bytes, s7Hex("010203")) {
				t.Errorf("blob = %+v", e)
			}
		}},
	{"blob raw", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "0014" + "02" + "0000000000000000" + "02" + "02" + "abcd" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if e := s7PlusValue(t, b).Elements[0]; e.Blob == nil || e.Blob.Type != 2 || !bytes.Equal(e.Bytes, s7Hex("abcd")) {
				t.Errorf("blob = %+v", e)
			}
		}},
	{"blob list", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "0014" + "05" + "0000000000000000" + "00" + "05000101" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			bl := s7PlusValue(t, b).Elements[0].Blob
			if bl == nil || bl.RootID != 5 || len(bl.Values) != 1 || bl.Values[0].ID != 5 || bl.Values[0].Value.Elements[0].Uint() != 1 {
				t.Errorf("blob = %+v", bl)
			}
		}},
}

// s7PlusFuncCases cover functions and layouts absent from testdata:
// some from other ICS-pcap captures, the rest built from the plugin.
var s7PlusFuncCases = []s7PlusCase{
	{"delete response bare digest", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncDeleteObject, s7PlusDeleteResp1511,
		func(t *testing.T, b *S7CommPlusBody) {
			if b.ObjectID != 0x388 || b.HasIntegrityID || len(b.Digest) != 32 || len(b.Rest) != 0 {
				t.Errorf("body = %+v", b)
			}
		}},
	{"notification", S7CommPlusV2, S7CommPlusOpNotification, 0, s7PlusNotify1200,
		func(t *testing.T, b *S7CommPlusBody) {
			n := b.Notification
			if n == nil || n.SubscriptionID != 0x1000006a || n.Sequence != 1 || n.ChangeCounter != 1 || len(n.Items) != 2 {
				t.Fatalf("notification = %+v", n)
			}
			if it := n.Items[0]; it.Code != 0x92 || it.ItemRef != 0xffffffff || it.Value.Elements[0].Int() != 1001 {
				t.Errorf("item = %+v", it)
			}
		}},
	{"set variable", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncSetVariable, s7PlusSetVar1200,
		func(t *testing.T, b *S7CommPlusBody) {
			if b.ObjectID != 0x1000006a || !reflect.DeepEqual(b.IDs, []uint32{1053}) || b.Value.Elements[0].Int() != 6 || b.Qualifier == nil {
				t.Errorf("body = %+v", b)
			}
		}},
	{"set variable raw length", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncSetVariable, "00000005" + "03" + "0008" + "05" + "00070102" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if !reflect.DeepEqual(b.IDs, []uint32{0, 8, 5}) || b.Value.Elements[0].Uint() != 0x102 {
				t.Errorf("body = %+v", b)
			}
		}},
	{"notification VLQ sequence", S7CommPlusV2, S7CommPlusOpNotification, 0,
		"70000001" + "0400" + "0000" + "0000" + "05" + "8100" + "000600000000000a" + "03" +
			"9b" + "05" + "00030102" + "13" + "00000007" + "00" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			n := b.Notification
			if n.CreditTick != 5 || n.Sequence != 128 || !n.HasTimestamp || n.Timestamp != 0x000600000000000a || n.ChangeCounter != 3 {
				t.Errorf("notification = %+v", n)
			}
			if len(n.Items) != 2 || n.Items[0].ItemRef != 5 || n.Items[0].Value.Elements[0].Uint() != 0x102 || n.Items[1].ItemRef != 7 {
				t.Errorf("items = %+v", n.Items)
			}
		}},
	{"notification part 2", S7CommPlusV2, S7CommPlusOpNotification, 0,
		"70000001" + "0400" + "0000" + "0000" + "05" + "01" + "02" + "00" + "70000002" + "0000" + "83000201" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			n := b.Notification
			if n.SubscriptionID2 != 0x70000002 || len(n.Items2) != 1 || n.Items2[0].Value.Elements[0].Uint() != 1 {
				t.Errorf("notification = %+v", n)
			}
		}},
	{"notification V1", S7CommPlusV1, S7CommPlusOpNotification, 0,
		"00000010" + "00000000" + "00000005" + "0000" + "92" + "00000001" + "000209" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			n := b.Notification
			if n.V1Unknown3 != 5 || len(n.Items) != 1 || n.Items[0].Value.Elements[0].Uint() != 9 {
				t.Errorf("notification = %+v", n)
			}
		}},
	{"get variable", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncGetVariable, "00000123" + "02" + "8100" + "05" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if b.ObjectID != 0x123 || !reflect.DeepEqual(b.IDs, []uint32{128, 5}) || b.Qualifier != nil {
				t.Errorf("body = %+v", b)
			}
		}},
	{"classic blob address", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncGetMultiVariables,
		"00000000" + "02" + "0c" + "00" + "52" + "04" + "9d18" + "03" + "7a" + "01" + "00" + "88d0b88001" + "02" + "9376" + "03" + "02" + "02" + s7PlusQualifier + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if len(b.Addresses) != 2 || !reflect.DeepEqual(b.Addresses[0].LIDs, []uint32{3, 122, 1}) {
				t.Fatalf("addresses = %+v", b.Addresses)
			}
			// LID count 2, but classic blob access reads three LIDs.
			if a := b.Addresses[1]; !reflect.DeepEqual(a.LIDs, []uint32{3, 2, 2}) || a.AccessSubArea != 2550 {
				t.Errorf("DB address = %+v", a)
			}
			if db, ok := b.Addresses[1].DBNumber(); !ok || db != 1 {
				t.Errorf("DB number = %d", db)
			}
		}},
	{"set multi by ID", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncSetMultiVariables,
		"00000386" + "02" + "02" + "8100" + "05" + "01000201" + "02000307d0" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if !reflect.DeepEqual(b.IDs, []uint32{128, 5}) || len(b.Values) != 2 || b.Values[1].Value.Elements[0].Uint() != 0x7d0 {
				t.Errorf("body = %+v", b)
			}
		}},
	{"set multi errors", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncSetMultiVariables, "00" + "02" + "8a00" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if len(b.Errors) != 1 || b.Errors[0].Item != 2 || b.Errors[0].Return.ErrorCode() != 0x500 {
				t.Errorf("errors = %+v", b.Errors)
			}
		}},
	{"substreamed struct", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncGetVarSubStreamed,
		"00000002" + "001700000100" + "00000003" + "000207" + "00000000" + "0000" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if len(b.Values) != 1 || len(b.Values[0].Value.Members) != 1 || b.Values[0].Value.Members[0].ID != 3 {
				t.Errorf("values = %+v", b.Values)
			}
		}},
	{"set substreamed", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncSetVarSubStreamed,
		"00000001" + "0015026869" + s7PlusQualifier + "0000" + "000405" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if b.Stream == nil || b.Stream.Elements[0].Uint() != 5 || b.Qualifier == nil || string(b.Values[0].Value.Elements[0].Bytes) != "hi" {
				t.Errorf("body = %+v", b)
			}
		}},
	{"invoke", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncInvoke, "00000005" + "00000000" + "01000407" + "00" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if b.ObjectID != 5 || len(b.Values) != 1 || b.Values[0].Value.Elements[0].Uint() != 7 {
				t.Errorf("body = %+v", b)
			}
		}},
	{"invoke response", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncInvoke, "00" + "00" + "00" + "05" + "01000209" + "00" + "00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if len(b.Returns) != 4 || b.Returns[3] != 5 || len(b.Values) != 1 {
				t.Errorf("body = %+v", b)
			}
		}},
	{"error", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncError, "8a00" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if b.Return.ErrorCode() != 0x500 {
				t.Errorf("return = %x", uint64(b.Return))
			}
		}},
	{"end sequence", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncEndSequence, "0000" + "00000000", nil},
	{"begin sequence ID", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncBeginSequence, "01" + "0012" + "00000099" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if *b.Sequence != (S7CommPlusSequence{TransactionType: 1, ValueType: 0x12, RequestID: 0x99}) {
				t.Errorf("sequence = %+v", b.Sequence)
			}
		}},
	{"begin sequence V1", S7CommPlusV1, S7CommPlusOpRequest, S7CommPlusFuncBeginSequence, "01" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if b.Sequence.TransactionType != 1 || len(b.Rest) != 4 {
				t.Errorf("body = %+v", b)
			}
		}},
	{"delete extension", S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncDeleteObject,
		"a08080808080808000" + "00000005" + "a1" + "00000006" + "070000" + "a2" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if !b.Return.Extension() || b.ObjectID != 5 || len(b.Elements.Objects) != 1 || b.HasIntegrityID {
				t.Errorf("body = %+v", b)
			}
		}},
	{"explore V3", S7CommPlusV3, S7CommPlusOpResponse, S7CommPlusFuncExplore,
		"00" + "00000001" + "05" + "a1" + "00000002" + "030000" + "a2" + "07" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if !b.Explore.HasSeqIntegrity || b.Explore.SequenceIntegrity != 5 || len(b.Elements.Objects) != 1 || b.IntegrityID != 7 {
				t.Errorf("body = %+v", b)
			}
		}},
	{"create object tree", S7CommPlusV1, S7CommPlusOpRequest, S7CommPlusFuncCreateObject,
		"00000123" + "000400" + "00000000" +
			"a1" + "00000001" + "05" + "00" + "00" +
			"a3" + "816900" + "15026869" +
			"a4" + "07" + "00000000" +
			"ac" + "0007" + "02616200" + "016300" + "0000" +
			"ab" + "0014" + "00000000" + "01000000" + "02000000" + "05" + "8a40" + "00" + "00000000" + "0000" +
			"a7" + "01" + "026869" + "00" + "01" + "01" + "00000000" + "05" + "00" + "02" + "03" + "04" + "05" + "a8" +
			"a1" + "00000002" + "06" + "00" + "8100" + "07" + "a2" +
			"a2" + "00000000",
		s7PlusCheckTree},
	{"create object V2 inner ID", S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncCreateObject,
		"00000123" + "000400" + "00000000" + "05" + "a1" + "00000001" + "050000" + "a2" + "00000000",
		func(t *testing.T, b *S7CommPlusBody) {
			if !b.HasInnerID || b.InnerIntegrityID != 5 || len(b.Elements.Objects) != 1 {
				t.Errorf("body = %+v", b)
			}
		}},
}

// s7PlusCheckTree checks the hand-built object of "create object tree".
func s7PlusCheckTree(t *testing.T, b *S7CommPlusBody) {
	t.Helper()
	if len(b.Elements.Objects) != 1 {
		t.Fatalf("elements = %+v", b.Elements)
	}

	o := b.Elements.Objects[0]
	if len(o.Attributes) != 1 || o.Attributes[0].ID != 233 || len(o.Relations) != 1 || o.Relations[0].RelationID != 7 {
		t.Errorf("object = %+v", o)
	}
	if !reflect.DeepEqual(o.VarNames, []string{"ab", "c"}) {
		t.Errorf("names = %q", o.VarNames)
	}
	if len(o.VarTypes) != 1 || o.VarTypes[0].LID != 1 || o.VarTypes[0].SymbolCRC != 2 || o.VarTypes[0].OffsetInfoType() != 8 || len(o.VarTypes[0].OffsetInfo) != 4 {
		t.Errorf("types = %+v", o.VarTypes)
	}
	want := S7CommPlusTagDesc{OffsetInfoType: 1, Name: "hi", Datatype: S7CommPlusTypeBool, SoftDatatype: 1, LID: 5,
		OffsetType1: 2, OffsetType2: 3, BitOffset1: 4, BitOffset2: 5}
	if len(o.TagDescs) != 1 || !reflect.DeepEqual(o.TagDescs[0], want) {
		t.Errorf("tag = %+v", o.TagDescs)
	}
	if len(o.Objects) != 1 || o.Objects[0].AttributeID != 128 || o.Objects[0].AttributeIDFlags != 7 {
		t.Errorf("child = %+v", o.Objects)
	}
}

func TestS7CommPlusBodyCases(t *testing.T) {
	for _, c := range append(append([]s7PlusCase{}, s7PlusValueCases...), s7PlusFuncCases...) {
		b, err := DecodeS7CommPlusBody(c.ver, c.op, c.fn, s7Hex(c.data))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if strings.Trim(string(b.Rest), "\x00") != "" {
			t.Errorf("%s: rest %x", c.name, b.Rest)
		}
		if c.check != nil {
			c.check(t, b)
		}
	}
}

// TestS7CommPlusBodyMalformed feeds count and length lies, unknown
// types and unsupported functions.
func TestS7CommPlusBodyMalformed(t *testing.T) {
	cases := []struct {
		name string
		op   S7CommPlusOpcode
		fn   S7CommPlusFunction
		data string
		want error
	}{
		{"array count lie", S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "1001" + "8fffffff7f" + "01", ErrS7CommPlusMalformed},
		{"string length lie", S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "0015" + "8fffffff7f" + "41", ErrS7CommPlusMalformed},
		{"blob length lie", S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "0014" + "00" + "ff7f", ErrS7CommPlusMalformed},
		{"address count lie", S7CommPlusOpRequest, S7CommPlusFuncGetMultiVariables, "00000000" + "8fffffff7f" + "01" + "00000000", ErrS7CommPlusMalformed},
		{"LID count lie", S7CommPlusOpRequest, S7CommPlusFuncGetMultiVariables, "00000000" + "01" + "01" + "00" + "52" + "8fffffff7f" + "00", ErrS7CommPlusMalformed},
		{"ID count lie", S7CommPlusOpRequest, S7CommPlusFuncGetVariable, "00000001" + "8fffffff7f" + "00", ErrS7CommPlusMalformed},
		{"dimension count lie", S7CommPlusOpResponse, S7CommPlusFuncExplore, "00" + "00000001" + "a1" + "00000002" + "000000" +
			"a7" + "03" + "00" + "00" + "01" + "01" + "00000000" + "00" + "00" + "00" + "00" + "00" + "00" + "8fffffff7f", ErrS7CommPlusMalformed},
		{"unknown datatype", S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "0018" + "00000000", ErrS7CommPlusUnknownType},
		{"unknown blob type", S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "0014" + "02" + "0000000000000000" + "07" + "00000000", ErrS7CommPlusUnknownType},
		{"unknown notification item", S7CommPlusOpNotification, 0, "70000001" + "0400" + "0000" + "0000" + "00" + "00" + "01" + "55" + "00000000", ErrS7CommPlusUnknownType},
		{"bad digest", S7CommPlusOpResponse, S7CommPlusFuncSetVariable, "00" + "00" + "21" + strings.Repeat("00", 32), ErrS7CommPlusMalformed},
		{"truncated VLQ", S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "0004" + "ff", ErrS7CommPlusMalformed},
		{"unsupported function", S7CommPlusOpRequest, S7CommPlusFuncAddLink, "00000000", ErrS7CommPlusUnsupported},
		{"unsupported opcode", 0x44, 0, "00000000", ErrS7CommPlusUnsupported},
	}

	for _, c := range cases {
		b, err := DecodeS7CommPlusBody(S7CommPlusV2, c.op, c.fn, s7Hex(c.data))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if b == nil {
			t.Errorf("%s: no partial body", c.name)
		}
	}

	var keep S7CommPlus
	if err := keep.DecodeFromBytes(s7Hex("72fe0002"+"0000"), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if _, err := keep.DecodeBody(); !errors.Is(err, ErrS7CommPlusFragment) {
		t.Errorf("keep-alive DecodeBody: %v", err)
	}
}

// TestS7CommPlusBodyDeep nests 10000 levels of every recursive form;
// each must stop at the depth limit instead of exhausting the stack.
func TestS7CommPlusBodyDeep(t *testing.T) {
	const levels = 10000
	cases := []struct {
		name string
		op   S7CommPlusOpcode
		fn   S7CommPlusFunction
		head string
		unit string
	}{
		{"struct members", S7CommPlusOpResponse, S7CommPlusFuncGetMultiVariables, "00", "01001700000001"},
		{"objects", S7CommPlusOpResponse, S7CommPlusFuncExplore, "00" + "00000001", "a1" + "00000001" + "010000"},
		{"blob lists", S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00" + "0014" + "02" + "0000000000000000" + "00", "01" + "0014" + "02" + "0000000000000000" + "00"},
		{"substreamed", S7CommPlusOpRequest, S7CommPlusFuncGetVarSubStreamed, "", "00000001" + "001700000001"},
		{"notification objects", S7CommPlusOpNotification, 0, "70000001" + "0400" + "0000" + "0000" + "00" + "00" + "01" + "81", "a1" + "00000001" + "010000"},
		{"struct arrays", S7CommPlusOpResponse, S7CommPlusFuncGetVariable, "00", "2017" + "00000001" + "01" + "01"},
	}

	for _, c := range cases {
		data := s7Hex(c.head + strings.Repeat(c.unit, levels))
		_, err := DecodeS7CommPlusBody(S7CommPlusV2, c.op, c.fn, data)
		if !errors.Is(err, ErrS7CommPlusTooDeep) {
			t.Errorf("%s: err = %v, want %v", c.name, err, ErrS7CommPlusTooDeep)
		}
	}
}

// s7PlusBodyVectors returns every body vector: capture PDUs and the
// hand-built cases.
func s7PlusBodyVectors(t *testing.T) []s7PlusCase {
	t.Helper()
	var out []s7PlusCase
	for _, name := range []string{"s7commplus-1511-opc.pcap", "s7commplus-1200-upload.pcap"} {
		for _, s := range s7PlusLayers(s7Packets(t, name)) {
			if s.HasDataHeader && s.HasTrailer {
				out = append(out, s7PlusCase{name: name, ver: s.Version, op: s.Opcode, fn: s.Function, data: string(s.Data)})
			}
		}
	}

	for _, c := range append(append([]s7PlusCase{}, s7PlusValueCases...), s7PlusFuncCases...) {
		c.data = string(s7Hex(c.data))
		out = append(out, c)
	}
	return out
}

// TestS7CommPlusBodyTruncation cuts every body vector at every offset.
// Nothing may panic; a cut inside the decoded fields may still decode
// when what is left looks like a shorter body, so only Rest is checked.
func TestS7CommPlusBodyTruncation(t *testing.T) {
	for _, v := range s7PlusBodyVectors(t) {
		data := []byte(v.data)
		for n := 0; n < len(data); n++ {
			b, _ := DecodeS7CommPlusBody(v.ver, v.op, v.fn, data[:n])
			if b != nil && len(b.Rest) > n {
				t.Fatalf("%s cut at %d: rest %d octets", v.name, n, len(b.Rest))
			}
		}
	}
}

// A body of one 60000-element BOOL array, or of 20000 three-octet NULL
// items, must cost a small multiple of its structs. The array is
// counted and allocated once (48 bytes per element). The item list ends
// at a terminator and grows by doubling: 144 bytes of structs per item,
// plus up to twice the list in spare and discarded capacity.
func TestS7CommPlusAllocBound(t *testing.T) {
	const maxPerByte = 150
	bools := append(s7Hex("00"+"1001"+"83d460"), make([]byte, 60000)...)
	nulls := append(s7Hex("00"), bytes.Repeat(s7Hex("010000"), 20000)...)

	for _, c := range []struct {
		name string
		fn   S7CommPlusFunction
		data []byte
	}{{"bool array", S7CommPlusFuncGetVariable, bools}, {"null items", S7CommPlusFuncGetMultiVariables, append(nulls, 0, 0)}} {
		got := allocPerByte(len(c.data), func() {
			_, _ = DecodeS7CommPlusBody(S7CommPlusV2, S7CommPlusOpResponse, c.fn, c.data)
		})
		t.Logf("%s: %.0f bytes per input byte", c.name, got)
		if got > maxPerByte {
			t.Errorf("%s allocates %.0f bytes per input byte, want <= %d", c.name, got, maxPerByte)
		}
	}
}

// s7PlusFuzzFuncs are the functions FuzzS7CommPlusItems picks from.
var s7PlusFuzzFuncs = []S7CommPlusFunction{
	S7CommPlusFuncError, S7CommPlusFuncExplore, S7CommPlusFuncCreateObject, S7CommPlusFuncDeleteObject,
	S7CommPlusFuncSetVariable, S7CommPlusFuncGetVariable, S7CommPlusFuncGetLink, S7CommPlusFuncSetMultiVariables,
	S7CommPlusFuncGetMultiVariables, S7CommPlusFuncBeginSequence, S7CommPlusFuncEndSequence, S7CommPlusFuncInvoke,
	S7CommPlusFuncSetVarSubStreamed, S7CommPlusFuncGetVarSubStreamed, S7CommPlusFuncInitSSL, S7CommPlusFuncAbort,
}

var s7PlusFuzzOps = []S7CommPlusOpcode{S7CommPlusOpRequest, S7CommPlusOpResponse, S7CommPlusOpNotification, S7CommPlusOpResponse2}

// FuzzS7CommPlusItems decodes arbitrary bodies. The first octet picks
// version, opcode and function; the rest is the body.
func FuzzS7CommPlusItems(f *testing.F) {
	for i, c := range append(append([]s7PlusCase{}, s7PlusValueCases...), s7PlusFuncCases...) {
		sel := byte(i)
		for j, fn := range s7PlusFuzzFuncs {
			if fn == c.fn {
				sel = byte(j)
			}
		}
		for j, op := range s7PlusFuzzOps {
			if op == c.op {
				sel |= byte(j) << 4
			}
		}
		sel |= byte(c.ver-1) << 6
		f.Add(append([]byte{sel}, s7Hex(c.data)...))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		sel := data[0]
		fn := s7PlusFuzzFuncs[int(sel)%len(s7PlusFuzzFuncs)]
		op := s7PlusFuzzOps[int(sel>>4)%len(s7PlusFuzzOps)]
		ver := S7CommPlusVersion(sel>>6) + S7CommPlusV1
		b, err := DecodeS7CommPlusBody(ver, op, fn, data[1:])
		if b == nil {
			t.Fatalf("no body, err %v", err)
		}
		if len(b.Rest) > len(data)-1 {
			t.Fatalf("rest %d of %d octets", len(b.Rest), len(data)-1)
		}

		for _, v := range b.Values {
			for i := range v.Value.Elements {
				e := &v.Value.Elements[i]
				_, _, _, _ = e.Float(), e.Time(), e.Duration(), e.Int()
			}
		}
		if b.Notification != nil {
			_ = b.Notification.Time()
		}
	})
}
