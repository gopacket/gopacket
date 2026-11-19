// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// s7PlusExpect is the expected data header of one S7comm-plus frame.
// Wireshark ships no S7comm-plus dissector, so these come from this
// decoder and were checked by hand against the frame bytes and the
// request/response pairing (sequence numbers, functions).
type s7PlusExpect struct {
	frame    int
	version  S7CommPlusVersion
	opcode   S7CommPlusOpcode
	function S7CommPlusFunction
	sequence uint16
	session  uint32
	flags    uint8
}

var s7PlusExpect1511 = []s7PlusExpect{
	{9, S7CommPlusV1, S7CommPlusOpRequest, S7CommPlusFuncCreateObject, 1, 0x120, 0x36},
	{11, S7CommPlusV1, S7CommPlusOpResponse, S7CommPlusFuncCreateObject, 1, 0, 0x36},
	{14, S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncSetMultiVariables, 2, 0x386, 0x34},
	{16, S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncSetMultiVariables, 2, 0, 0x34},
	{20, S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncGetVarSubStreamed, 3, 0x386, 0x34},
	{22, S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetVarSubStreamed, 3, 0, 0x34},
	{29, S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncGetMultiVariables, 4, 0x386, 0x34},
	{31, S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetMultiVariables, 4, 0, 0x34},
	{62, S7CommPlusV2, S7CommPlusOpRequest, S7CommPlusFuncGetMultiVariables, 9, 0x386, 0x34},
	{64, S7CommPlusV2, S7CommPlusOpResponse, S7CommPlusFuncGetMultiVariables, 9, 0, 0x34},
}

// s7PlusLayers returns the S7comm-plus layer of every packet that has
// one, keyed by 1-based frame number.
func s7PlusLayers(pkts []gopacket.Packet) map[int]*S7CommPlus {
	out := map[int]*S7CommPlus{}
	for i, p := range pkts {
		if s, ok := p.Layer(LayerTypeS7CommPlus).(*S7CommPlus); ok {
			out[i+1] = s
		}
	}
	return out
}

// s7PlusCheckPairs checks that every response answers an earlier
// request with the same sequence number and function.
func s7PlusCheckPairs(t *testing.T, name string, frames map[int]*S7CommPlus, n int) {
	t.Helper()
	reqs := map[uint16]S7CommPlusFunction{}
	for f := 1; f <= n; f++ {
		s := frames[f]
		if s == nil || !s.HasDataHeader {
			continue
		}

		switch s.Opcode {
		case S7CommPlusOpRequest:
			reqs[s.Sequence] = s.Function
		case S7CommPlusOpResponse:
			if fn, ok := reqs[s.Sequence]; !ok || fn != s.Function {
				t.Errorf("%s frame %d: response %v seq %d has no matching request", name, f, s.Function, s.Sequence)
			}
		}
	}
}

func TestS7CommPlusOPCPcap(t *testing.T) {
	pkts := s7CheckCapture(t, "s7commplus-1511-opc.pcap", s7ExpectPlus1511)
	frames := s7PlusLayers(pkts)
	s7PlusCheckPairs(t, "1511", frames, len(pkts))

	for _, w := range s7PlusExpect1511 {
		s := frames[w.frame]
		if s == nil {
			t.Errorf("frame %d: no S7comm-plus layer", w.frame)
			continue
		}

		got := s7PlusExpect{w.frame, s.Version, s.Opcode, s.Function, s.Sequence, s.SessionID, s.TransportFlags}
		if got != w || !s.HasDataHeader || !s.HasTrailer || s.TrailerVersion != s.Version {
			t.Errorf("frame %d:\n got %+v (trailer %v)\nwant %+v", w.frame, got, s.HasTrailer, w)
		}
	}

	ok := frames[16]
	if v, err := ok.ReturnValue(); err != nil || v != 0 || len(ok.Data) != 7 {
		t.Errorf("SetMultiVariables response: return %d, %v, data %x", v, err, ok.Data)
	}
}

// TestS7CommPlusUploadPcap covers a PDU sent as three frames: only the
// first has a data header, only the last a trailer.
func TestS7CommPlusUploadPcap(t *testing.T) {
	pkts := s7Packets(t, "s7commplus-1200-upload.pcap")
	frames := s7PlusLayers(pkts)
	s7PlusCheckPairs(t, "1200", frames, len(pkts))

	for i, p := range pkts {
		if el := p.ErrorLayer(); el != nil {
			t.Errorf("frame %d: %v", i+1, el.Error())
		}
	}

	first, mid, last := frames[127], frames[128], frames[129]
	if first == nil || mid == nil || last == nil {
		t.Fatal("fragment frames not decoded")
	}
	if !first.HasDataHeader || first.Function != S7CommPlusFuncCreateObject || first.HasTrailer || first.DataLength != 1008 {
		t.Errorf("first fragment = %+v", first)
	}
	if mid.HasDataHeader || mid.HasTrailer || len(mid.Data) != int(mid.DataLength) {
		t.Errorf("middle fragment: header %v trailer %v", mid.HasDataHeader, mid.HasTrailer)
	}
	if last.HasDataHeader || !last.HasTrailer {
		t.Errorf("last fragment: header %v trailer %v", last.HasDataHeader, last.HasTrailer)
	}
}

func TestS7CommPlusFrames(t *testing.T) {
	digest := "20" + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	cases := []struct {
		name  string
		data  string
		want  S7CommPlus
		data2 int // len(Data)
	}{
		{"V3 request with integrity", "72030030" + digest + "31000004f200000005000003863401" + "72030000",
			S7CommPlus{ProtocolID: 0x72, Version: S7CommPlusV3, DataLength: 0x30, HasDataHeader: true,
				Opcode: S7CommPlusOpRequest, Function: S7CommPlusFuncSetVariable, Sequence: 5, SessionID: 0x386,
				TransportFlags: 0x34, HasTrailer: true, TrailerVersion: S7CommPlusV3}, 1},
		{"response2", "7202000b" + "02000005600000000a3400" + "72020000",
			S7CommPlus{ProtocolID: 0x72, Version: S7CommPlusV2, DataLength: 11, HasDataHeader: true,
				Opcode: S7CommPlusOpResponse2, Function: S7CommPlusFuncEndSequence, Sequence: 10,
				TransportFlags: 0x34, HasTrailer: true, TrailerVersion: S7CommPlusV2}, 1},
		{"notification", "72020005" + "3301020304" + "72020000",
			S7CommPlus{ProtocolID: 0x72, Version: S7CommPlusV2, DataLength: 5, HasDataHeader: true,
				Opcode: S7CommPlusOpNotification, HasTrailer: true, TrailerVersion: S7CommPlusV2}, 4},
		{"keep-alive", "72fe0002" + "0000",
			S7CommPlus{ProtocolID: 0x72, Version: S7CommPlusKeepAlive, DataLength: 2}, 2},
		{"short request header", "72020005" + "3100000542",
			S7CommPlus{ProtocolID: 0x72, Version: S7CommPlusV2, DataLength: 5}, 5},
	}

	for _, c := range cases {
		var s S7CommPlus
		if err := s.DecodeFromBytes(s7Hex(c.data), gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}

		if len(s.Data) != c.data2 {
			t.Errorf("%s: data %x, want %d octets", c.name, s.Data, c.data2)
		}
		if c.want.Version == S7CommPlusV3 && len(s.Integrity) != 32 {
			t.Errorf("%s: integrity %x", c.name, s.Integrity)
		}
		s.BaseLayer, s.Data, s.Integrity = BaseLayer{}, nil, nil
		if !reflect.DeepEqual(s, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, s, c.want)
		}
	}
}

func TestS7CommPlusMalformed(t *testing.T) {
	cases := []struct {
		name string
		data string
		want error
	}{
		{"short header", "7202", ErrS7CommPlusTooShort},
		{"bad protocol", "73020000", ErrS7CommPlusBadProtocol},
		{"length lie", "7202ffff31", ErrS7CommPlusTooShort},
		{"integrity lie", "72030002" + "2000", ErrS7CommPlusMalformed},
	}

	for _, c := range cases {
		var s S7CommPlus
		if err := s.DecodeFromBytes(s7Hex(c.data), gopacket.NilDecodeFeedback); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestS7CommPlusVLQ(t *testing.T) {
	u32 := []struct {
		in   string
		want uint32
		n    int
		err  error
	}{
		{"00", 0, 1, nil},
		{"7f", 127, 1, nil},
		{"8100", 128, 2, nil},
		{"8fffffff7f", math.MaxUint32, 5, nil},
		{"", 0, 0, ErrVLQTruncated},
		{"80", 0, 0, ErrVLQTruncated},
		{"8080808080", 0, 0, ErrVLQTooLong},
	}
	for _, c := range u32 {
		v, n, err := S7CommPlusVarUint32(s7Hex(c.in))
		if v != c.want || n != c.n || !errors.Is(err, c.err) {
			t.Errorf("VarUint32(%s) = %d, %d, %v", c.in, v, n, err)
		}
	}

	i32 := []struct {
		in   string
		want int32
		n    int
	}{
		{"3f", 63, 1},
		{"7f", -1, 1},
		{"40", -64, 1},
		{"c000", -8192, 2},
		{"8100", 128, 2},
	}
	for _, c := range i32 {
		v, n, err := S7CommPlusVarInt32(s7Hex(c.in))
		if v != c.want || n != c.n || err != nil {
			t.Errorf("VarInt32(%s) = %d, %d, %v", c.in, v, n, err)
		}
	}

	u64 := []struct {
		in   string
		want uint64
		n    int
		err  error
	}{
		{"7f", 127, 1, nil},
		{"818080808080808001", 1<<57 | 1, 9, nil},
		{"ffffffffffffffffff", math.MaxUint64, 9, nil},
		{"8080808080808080", 0, 0, ErrVLQTruncated},
	}
	for _, c := range u64 {
		v, n, err := S7CommPlusVarUint64(s7Hex(c.in))
		if v != c.want || n != c.n || !errors.Is(err, c.err) {
			t.Errorf("VarUint64(%s) = %d, %d, %v", c.in, v, n, err)
		}
	}

	if v, n, err := S7CommPlusVarInt64(s7Hex("7f")); v != -1 || n != 1 || err != nil {
		t.Errorf("VarInt64(7f) = %d, %d, %v", v, n, err)
	}
	if v, n, err := S7CommPlusVarInt64(s7Hex("ffffffffffffffffff")); v != -1 || n != 9 || err != nil {
		t.Errorf("VarInt64(ff x9) = %d, %d, %v", v, n, err)
	}
}

// TestS7CommPlusTruncation cuts every S7comm-plus TPKT frame of the
// captures at every offset; nothing may panic and every cut must error.
func TestS7CommPlusTruncation(t *testing.T) {
	for _, name := range []string{"s7commplus-1511-opc.pcap", "s7commplus-1200-upload.pcap"} {
		for _, p := range s7Packets(t, name) {
			tp, ok := p.Layer(LayerTypeTPKT).(*TPKT)
			if !ok {
				continue
			}

			v := append(tp.Contents, tp.Payload...)
			for n := 0; n < len(v); n++ {
				if gopacket.NewPacket(v[:n], LayerTypeTPKT, s7NoRecover).ErrorLayer() == nil {
					t.Fatalf("%s: frame %x cut at %d: no error", name, v, n)
				}
			}
		}
	}
}

// FuzzS7CommPlus decodes arbitrary S7comm-plus frames and VLQ integers.
func FuzzS7CommPlus(f *testing.F) {
	f.Add(s7Hex("720100e431000004ca0000000100000120360000011d0004"))
	f.Add(s7Hex("7202001132000005420000000234000000000000007202 0000"))
	f.Add(s7Hex("72030030" + "20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + "31000004f200000005000003863401" + "72030000"))
	f.Add(s7Hex("72020005" + "3301020304" + "72020000"))
	f.Add(s7Hex("818080808080808001"))

	f.Fuzz(func(t *testing.T, data []byte) {
		p := gopacket.NewPacket(data, LayerTypeS7CommPlus, s7NoRecover)
		for _, l := range p.Layers() {
			_ = gopacket.LayerString(l)
		}

		var s S7CommPlus
		if s.DecodeFromBytes(data, gopacket.NilDecodeFeedback) == nil {
			if len(s.Contents)+len(s.Payload) != len(data) {
				t.Fatalf("Contents %d + Payload %d != %d", len(s.Contents), len(s.Payload), len(data))
			}
			_, _ = s.ReturnValue()
		}

		if _, n, err := S7CommPlusVarUint32(data); err == nil && (n < 1 || n > 5) {
			t.Fatalf("VarUint32 consumed %d", n)
		}
		if _, n, err := S7CommPlusVarInt32(data); err == nil && (n < 1 || n > 5) {
			t.Fatalf("VarInt32 consumed %d", n)
		}
		if _, n, err := S7CommPlusVarUint64(data); err == nil && (n < 1 || n > 9) {
			t.Fatalf("VarUint64 consumed %d", n)
		}
		if _, n, err := S7CommPlusVarInt64(data); err == nil && (n < 1 || n > 9) {
			t.Fatalf("VarInt64 consumed %d", n)
		}
	})
}

// s7ExpectPlus1511 is tshark's COTP view of s7commplus-1511-opc.pcap.
var s7ExpectPlus1511 = []s7Expect{
	{6, 0xE0, 0, 0, 0, 0, 0, 0, 0},
	{8, 0xD0, 0, 0, 0, 0, 0, 0, 0},
	{9, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{11, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{12, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{14, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{16, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{17, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{20, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{22, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{23, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{29, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{31, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{32, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{35, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{37, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{38, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{41, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{43, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{44, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{47, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{49, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{50, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{53, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{55, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{56, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{62, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{64, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{65, 0xF0, 0, 0, 0, 0, 0, 0, 0},
}
