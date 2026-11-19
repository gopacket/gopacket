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
	"math"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// Test captures, all public:
//
//	iec61850_goose_ge_f650.pcap  GE F650 GOOSE, untagged (cutaway-security/goosestalker)
//	iec61850_goose_vlan.pcap     GOOSE demo frame, 802.1Q VLAN 10 (goosestalker)
//	iec61850_goose_abb.pcap      ABB GOOSE, first 120 frames of Sample_File_GOOSE.pcap (goosestalker)
//	iec61850_goose_gooseind.pcap GOOSE frames of gooseind1_7.pcap (EmreEkin/ICS-Pcaps)
//	iec61850_goose_iedscout.pcap GOOSE frames of iedscout.pcap (EmreEkin/ICS-Pcaps)
//	iec61850_sv_92le.pcap        9-2LE SV, first 80 frames of SV_Normal_Traffic.cap (mgadelha/Sampled_Values)
//	iec61850_sv_multi_asdu.pcap  SV with 5 ASDUs per frame (EmreEkin/ICS-Pcaps 9-2-sv.pcap)
//	iec61850_sv_bad_length.pcap  SV whose length field is 4 short (EmreEkin/ICS-Pcaps IEC61850_SV.pcap)
//
// Expected values come from tshark 4.7.

const (
	iecPcapMagicLE   = 0xa1b2c3d4
	iecPcapMagicNsLE = 0xa1b23c4d
	iecPcapHeaderLen = 24
	iecPcapRecordLen = 16
	iecPcapMaxRecord = 1 << 18

	// iecTimeLayout prints times the way tshark does.
	iecTimeLayout = "Jan 2, 2006 15:04:05.000000000"
)

// iecReadPcap returns every frame of a classic pcap file. pcapgo cannot be
// used from package layers (import cycle).
func iecReadPcap(t testing.TB, path string) [][]byte {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < iecPcapHeaderLen {
		t.Fatalf("%s: short pcap header", path)
	}

	// The magic tells the byte order of every header field.
	var order binary.ByteOrder = binary.LittleEndian
	switch binary.LittleEndian.Uint32(raw) {
	case iecPcapMagicLE, iecPcapMagicNsLE:
	default:
		order = binary.BigEndian
	}
	if lt := order.Uint32(raw[20:]); lt != uint32(LinkTypeEthernet) {
		t.Fatalf("%s: link type %d, want Ethernet", path, lt)
	}

	var frames [][]byte
	for b := raw[iecPcapHeaderLen:]; len(b) >= iecPcapRecordLen; {
		n := int(order.Uint32(b[8:]))
		if n > iecPcapMaxRecord || n > len(b)-iecPcapRecordLen {
			t.Fatalf("%s: bad record length %d", path, n)
		}
		frames = append(frames, b[iecPcapRecordLen:iecPcapRecordLen+n])
		b = b[iecPcapRecordLen+n:]
	}
	return frames
}

// iecTLV encodes one BER TLV with a single octet identifier.
func iecTLV(id byte, parts ...[]byte) []byte {
	v := bytes.Join(parts, nil)
	out := []byte{id}
	switch {
	case len(v) < 0x80:
		out = append(out, byte(len(v)))
	case len(v) <= 0xff:
		out = append(out, 0x81, byte(len(v)))
	case len(v) <= 0xffff:
		out = append(out, 0x82, byte(len(v)>>8), byte(len(v)))
	default:
		out = append(out, 0x83, byte(len(v)>>16), byte(len(v)>>8), byte(len(v)))
	}
	return append(out, v...)
}

// iecFrame wraps an APDU in an 802.1Q tagged (priority 4) Ethernet frame
// with the GOOSE/SV header.
func iecFrame(etype EthernetType, appID uint16, apdu []byte) []byte {
	f := []byte{
		0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x81, 0x00, 0x80, 0x00,
		byte(etype >> 8), byte(etype),
	}
	n := iec61850HeaderLen + len(apdu)
	f = append(f, byte(appID>>8), byte(appID), byte(n>>8), byte(n), 0, 0, 0, 0)
	return append(f, apdu...)
}

func iecDecode(frame []byte) gopacket.Packet {
	registerIEC61850Decoders()
	return gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)
}

func iecDataTypes(ds []MMSData) []MMSDataType {
	var out []MMSDataType
	for _, d := range ds {
		out = append(out, d.Type)
		out = append(out, iecDataTypes(d.Items)...)
	}
	return out
}

func TestGOOSEPcaps(t *testing.T) {
	type want struct {
		frames            int
		appID             uint16
		gocbRef, datSet   string
		goID, timestamp   string
		tal, stNum, sqNum uint32
		confRev, entries  uint32
		simulation        bool
		types             []MMSDataType
	}
	b, bs := MMSDataBoolean, MMSDataBitString
	tests := map[string]want{
		"iec61850_goose_ge_f650.pcap": {8, 0x0001, "GEDeviceF650/LLN0$GO$gcb01", "GEDeviceF650/LLN0$GOOSE1",
			"F650_GOOSE1", "Jan 2, 2000 02:46:11.258165836", 40000, 1, 10, 1, 8, false,
			[]MMSDataType{b, bs, b, bs, b, bs, b, bs}},
		"iec61850_goose_iedscout.pcap": {63, 0x0150, "OG_TRALD0/LLN0$GO$gcbTRdevrede", "OG_TRALD0/LLN0$TRdevrede",
			"OG_TRALD0/LLN0.gcbTRdevrede", "Jan 28, 2019 09:51:40.119407415", 20000, 3, 495, 100, 4, true,
			[]MMSDataType{bs, bs, b, b}},
		"iec61850_goose_abb.pcap": {120, 0x3001, "AA1C1Q01A1LD0/LLN0$GO$gcb_A", "AA1C1Q01A1LD0/LLN0$InterlockingA",
			"InterlockingA", "Jul 24, 2008 14:25:05.140625000", 15000, 36705, 0, 1, 25, false,
			[]MMSDataType{b, b, b, b, b, b, b, bs, bs, bs, bs, bs, bs, bs, bs, bs, bs, bs, bs, bs, bs, bs, bs, bs, bs}},
		"iec61850_goose_gooseind.pcap": {40, 0x0150, "OG_TRALD0/LLN0$GO$gcbTRdevrede", "OG_TRALD0/LLN0$TRdevrede",
			"OG_TRALD0/LLN0.gcbTRdevrede", "Feb 22, 2019 09:00:39.827228307", 20000, 13, 14, 100, 4, true,
			[]MMSDataType{bs, bs, b, b}},
	}

	for name, w := range tests {
		frames := iecReadPcap(t, "testdata/"+name)
		if len(frames) != w.frames {
			t.Fatalf("%s: %d frames, want %d", name, len(frames), w.frames)
		}

		// Every frame must decode cleanly with matching entry counts.
		for i, f := range frames {
			p := iecDecode(f)
			g, ok := p.Layer(LayerTypeGOOSE).(*GOOSE)
			if !ok || p.ErrorLayer() != nil {
				t.Fatalf("%s frame %d: no GOOSE layer: %v", name, i+1, p.ErrorLayer())
			}
			if !g.EntriesMatch() {
				t.Errorf("%s frame %d: %d entries, %d data", name, i+1, g.NumDatSetEntries, len(g.AllData))
			}
		}

		g := iecDecode(frames[0]).Layer(LayerTypeGOOSE).(*GOOSE)
		got := want{w.frames, g.AppID, g.GocbRef, g.DatSet, g.GoID, g.Timestamp.Time().Format(iecTimeLayout),
			g.TimeAllowedToLive, g.StNum, g.SqNum, g.ConfRev, g.NumDatSetEntries, g.Simulation, iecDataTypes(g.AllData)}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("%s frame 1:\n got %+v\nwant %+v", name, got, w)
		}
	}
}

// TestGOOSEDot1Q checks a VLAN tagged frame reaches GOOSE through Dot1Q.
func TestGOOSEDot1Q(t *testing.T) {
	frames := iecReadPcap(t, "testdata/iec61850_goose_vlan.pcap")
	p := iecDecode(frames[0])
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeDot1Q, LayerTypeGOOSE}, t)

	q := p.Layer(LayerTypeDot1Q).(*Dot1Q)
	if q.Priority != 4 || q.VLANIdentifier != 10 {
		t.Errorf("Dot1Q priority %d VLAN %d, want 4 and 10", q.Priority, q.VLANIdentifier)
	}

	g := p.Layer(LayerTypeGOOSE).(*GOOSE)
	if p.ApplicationLayer() != g {
		t.Error("GOOSE is not the application layer")
	}
	if g.AppID != 0x2000 || g.Length != 108 || g.GocbRef != "111" || g.DatSet != "222" || g.GoID != "333" ||
		g.TimeAllowedToLive != 10000 || g.StNum != 1 || g.SqNum != 1 || g.NumDatSetEntries != 10 || g.Simulated() {
		t.Errorf("unexpected GOOSE %+v", g)
	}
	if got := g.Timestamp.Time().Format(iecTimeLayout); got != "May 26, 2011 00:55:54.859000027" {
		t.Errorf("t = %s", got)
	}
	for _, d := range g.AllData {
		if d.Type != MMSDataBoolean || d.Bool {
			t.Errorf("allData member %+v, want boolean false", d)
		}
	}
}

// TestGOOSEDataTypes decodes a hand built goosePdu (IEC 61850-8-1 Annex A)
// carrying every Data alternative: no capture had floats or structures.
func TestGOOSEDataTypes(t *testing.T) {
	data := bytes.Join([][]byte{
		iecTLV(0x83, []byte{0xff}),                                                 // boolean true
		iecTLV(0x84, []byte{0x06, 0x40}),                                           // bit-string "01"
		iecTLV(0x85, []byte{0xfe, 0x0c}),                                           // integer -500
		iecTLV(0x86, []byte{0x00, 0xff, 0xff, 0xff, 0xff}),                         // unsigned 2^32-1
		iecTLV(0x87, []byte{0x08, 0x3f, 0xc0, 0x00, 0x00}),                         // float32 1.5
		iecTLV(0x87, []byte{0x0b, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18}), // float64 pi
		iecTLV(0x89, []byte{0xde, 0xad}),                                           // octet-string
		iecTLV(0x8a, []byte("abc")),                                                // visible-string
		iecTLV(0x8c, []byte{0x00, 0x00, 0x03, 0xe8, 0x00, 0x01}),                   // binary-time 1s, day 1
		iecTLV(0x8f, []byte{0x28, 0xca, 0x22, 0x02, 0x01}),                         // objId
		iecTLV(0x90, []byte("é")),                                                  // mMSString
		iecTLV(0x91, []byte{0, 0, 0, 1, 0x80, 0, 0, 0x0a}),                         // utc-time 1.5s
		iecTLV(0xa2, iecTLV(0xa1, iecTLV(0x85, []byte{7}))),                        // {[7]}
	}, nil)
	pdu := iecTLV(0x61,
		iecTLV(0x80, []byte("gcb")), iecTLV(0x81, []byte{0x07, 0xd0}), iecTLV(0x82, []byte("ds")),
		iecTLV(0x84, make([]byte, 8)), iecTLV(0x85, []byte{1}), iecTLV(0x86, []byte{2}),
		iecTLV(0x87, []byte{0}), iecTLV(0x88, []byte{3}), iecTLV(0x89, []byte{0}),
		iecTLV(0x8a, []byte{13}), iecTLV(0xab, data))

	p := iecDecode(iecFrame(EthernetTypeGOOSE, 0x0001, pdu))
	g, ok := p.Layer(LayerTypeGOOSE).(*GOOSE)
	if !ok {
		t.Fatal("no GOOSE layer:", p.ErrorLayer())
	}
	if g.GoID != "" || g.TimeAllowedToLive != 2000 || !g.EntriesMatch() {
		t.Errorf("unexpected header fields %+v", g)
	}

	d := g.AllData
	switch {
	case !d[0].Bool:
		t.Error("boolean")
	case d[1].BitLen() != 2 || d[1].Bit(0) || !d[1].Bit(1) || d[1].Bit(2):
		t.Errorf("bit-string %+v", d[1])
	case d[2].Int != -500:
		t.Errorf("integer %d", d[2].Int)
	case d[3].Uint != math.MaxUint32:
		t.Errorf("unsigned %d", d[3].Uint)
	case d[4].Float != 1.5 || d[5].Float != math.Pi:
		t.Errorf("floats %v %v", d[4].Float, d[5].Float)
	case !bytes.Equal(d[6].Raw, []byte{0xde, 0xad}) || d[7].String != "abc":
		t.Error("strings")
	case !d[8].Time.Equal(time.Date(1984, 1, 2, 0, 0, 1, 0, time.UTC)):
		t.Errorf("binary-time %v", d[8].Time)
	case d[9].String != "1.0.9506.2.1" || d[10].String != "é":
		t.Errorf("objId %q mMSString %q", d[9].String, d[10].String)
	case d[11].UTC.Time() != time.Unix(1, 5e8).UTC() || d[11].UTC.Quality != 0x0a:
		t.Errorf("utc-time %+v", d[11].UTC)
	case d[12].Type != MMSDataStructure || d[12].Items[0].Type != MMSDataArray || d[12].Items[0].Items[0].Int != 7:
		t.Errorf("structure %+v", d[12])
	}
}

func TestGOOSEMalformed(t *testing.T) {
	base := func(fields ...[]byte) []byte {
		return iecFrame(EthernetTypeGOOSE, 1, iecTLV(0x61, fields...))
	}
	required := [][]byte{
		iecTLV(0x80, []byte("g")), iecTLV(0x81, []byte{1}), iecTLV(0x82, []byte("d")),
		iecTLV(0x84, make([]byte, 8)), iecTLV(0x85, []byte{1}), iecTLV(0x86, []byte{1}),
		iecTLV(0x88, []byte{1}), iecTLV(0x8a, []byte{0}), iecTLV(0xab),
	}
	if p := iecDecode(base(required...)); p.ErrorLayer() != nil {
		t.Fatal("minimal goosePdu failed:", p.ErrorLayer().Error())
	}

	tests := map[string][]byte{
		"missing field":  base(required[1:]...),
		"out of order":   base(append([][]byte{required[1], required[0]}, required[2:]...)...),
		"bad utc length": base(append(append([][]byte{}, required[:3]...), append([][]byte{iecTLV(0x84, make([]byte, 7))}, required[4:]...)...)...),
		"stNum > 32 bit": base(append(append([][]byte{}, required[:4]...), append([][]byte{iecTLV(0x85, []byte{1, 0, 0, 0, 0})}, required[5:]...)...)...),
		"negative sqNum": base(append(append([][]byte{}, required[:5]...), append([][]byte{iecTLV(0x86, []byte{0xff})}, required[6:]...)...)...),
		"bad data float": base(append(append([][]byte{}, required[:8]...), iecTLV(0xab, iecTLV(0x87, []byte{8, 0, 0})))...),
		"gseMngtPdu":     iecFrame(EthernetTypeGOOSE, 1, iecTLV(0x60)),
		"indefinite len": iecFrame(EthernetTypeGOOSE, 1, []byte{0x61, 0x80, 0, 0}),
	}
	for name, f := range tests {
		if p := iecDecode(f); p.ErrorLayer() == nil {
			t.Errorf("%s: decoded without error", name)
		}
	}
}

func TestSVPcaps(t *testing.T) {
	frames := iecReadPcap(t, "testdata/iec61850_sv_92le.pcap")
	for i, f := range frames {
		p := iecDecode(f)
		s, ok := p.Layer(LayerTypeSV).(*SV)
		if !ok || p.ErrorLayer() != nil || !s.ASDUCountMatch() {
			t.Fatalf("frame %d: no SV layer: %v", i+1, p.ErrorLayer())
		}
	}

	p := iecDecode(frames[0])
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeDot1Q, LayerTypeSV}, t)
	s := p.Layer(LayerTypeSV).(*SV)
	a := s.ASDUs[0]
	if s.AppID != 0x4001 || s.NoASDU != 1 || a.SvID != "4001" || a.SmpCnt != 280 || a.ConfRev != 1 ||
		a.SmpSynch != SVSmpSynchGlobal || a.HasRefrTm || a.HasSmpRate {
		t.Errorf("unexpected SV %+v", s)
	}

	le, err := a.Samples92LE()
	if err != nil {
		t.Fatal(err)
	}
	wantValues := []int32{-108158, 277980, -168100, 1722, -7474176, 18742210, -11182068, 85966}
	wantQuality := []uint32{0, 0, 0, 0x2000, 0, 0, 0, 0x2000}
	for i, x := range le {
		if x.Value != wantValues[i] || x.Quality != wantQuality[i] {
			t.Errorf("channel %d = %+v", i, x)
		}
	}
}

func TestSVMultiASDU(t *testing.T) {
	frames := iecReadPcap(t, "testdata/iec61850_sv_multi_asdu.pcap")
	for i, f := range frames {
		p := iecDecode(f)
		s, ok := p.Layer(LayerTypeSV).(*SV)
		if !ok || len(s.ASDUs) != 5 || !s.ASDUCountMatch() {
			t.Fatalf("frame %d: %v", i+1, p.ErrorLayer())
		}
	}

	s := iecDecode(frames[0]).Layer(LayerTypeSV).(*SV)
	for i, a := range s.ASDUs {
		if s.AppID != 0x4000 || a.SvID != "XJPA_MU0001" || a.SmpCnt != uint16(27220+i) || a.ConfRev != 1 || a.SmpSynch != SVSmpSynchNone {
			t.Errorf("ASDU %d = %+v", i, a)
		}
		// 12 channels: not the 9-2LE dataset.
		if _, err := a.Samples92LE(); err == nil || len(a.Sample) != 96 {
			t.Errorf("ASDU %d: sample of %d octets decoded as 9-2LE", i, len(a.Sample))
		}
	}
}

// TestSVLengthLie checks frames whose length field is 4 octets short
// fail cleanly, as tshark reports them malformed.
func TestSVLengthLie(t *testing.T) {
	for i, f := range iecReadPcap(t, "testdata/iec61850_sv_bad_length.pcap") {
		p := iecDecode(f)
		if p.Layer(LayerTypeSV) != nil || p.ErrorLayer() == nil {
			t.Errorf("frame %d decoded", i+1)
		}
	}
}

func TestSVHandBuilt(t *testing.T) {
	asdu := iecTLV(0x30,
		iecTLV(0x80, []byte("MU01")), iecTLV(0x81, []byte("LD/LLN0$DS")), iecTLV(0x82, []byte{0x0f, 0x9f}),
		iecTLV(0x83, []byte{0, 0, 0, 2}), iecTLV(0x84, []byte{0, 0, 0, 10, 0, 0, 0, 0}),
		iecTLV(0x85, []byte{1}), iecTLV(0x86, []byte{0x0f, 0xa0}), iecTLV(0x87, make([]byte, 64)),
		iecTLV(0x88, []byte{0, 1}))
	pdu := iecTLV(0x60, iecTLV(0x80, []byte{1}), iecTLV(0x81, []byte{0xaa}), iecTLV(0xa2, asdu))

	p := iecDecode(iecFrame(EthernetTypeSV, 0x4000, pdu))
	s, ok := p.Layer(LayerTypeSV).(*SV)
	if !ok {
		t.Fatal(p.ErrorLayer())
	}
	a := s.ASDUs[0]
	if a.DatSet != "LD/LLN0$DS" || a.SmpCnt != 3999 || !a.HasRefrTm || a.RefrTm.Seconds != 10 ||
		a.SmpSynch != SVSmpSynchLocal || a.SmpRate != 4000 || a.SmpMod != 1 || !bytes.Equal(s.Security, []byte{0xaa}) {
		t.Errorf("unexpected ASDU %+v", a)
	}
}

// TestIEC61850Truncation cuts every frame at every offset: decoding must
// fail or succeed, never panic.
func TestIEC61850Truncation(t *testing.T) {
	files := []string{"iec61850_goose_ge_f650.pcap", "iec61850_goose_iedscout.pcap", "iec61850_sv_92le.pcap", "iec61850_sv_multi_asdu.pcap"}
	for _, name := range files {
		frame := iecReadPcap(t, "testdata/"+name)[0]
		for i := range frame {
			iecDecode(frame[:i])
		}
	}
}

func TestIEC61850LengthField(t *testing.T) {
	frame := iecReadPcap(t, "testdata/iec61850_goose_vlan.pcap")[0]
	const lenOff = 20
	for _, n := range []uint16{0, 7, 109, 0xffff} {
		f := append([]byte(nil), frame...)
		binary.BigEndian.PutUint16(f[lenOff:], n)
		if p := iecDecode(f); p.Layer(LayerTypeGOOSE) != nil {
			t.Errorf("length %d accepted", n)
		}
	}

	// Ethernet padding past the length is ignored.
	f := append(append([]byte(nil), frame...), 0, 0, 0, 0)
	g, ok := iecDecode(f).Layer(LayerTypeGOOSE).(*GOOSE)
	if !ok || len(g.Contents) != 108 {
		t.Error("padding not ignored")
	}
}

// iecNested returns a boolean inside depth nested structures, built from
// the inside out in one buffer: a2 len (a2 len (... (83 01 00))).
func iecNested(depth int) []byte {
	const maxHdr = 5
	core := []byte{0x83, 0x01, 0x00}
	buf := make([]byte, depth*maxHdr+len(core))
	start := len(buf) - len(core)
	copy(buf[start:], core)

	for range depth {
		n := len(buf) - start
		hdr := []byte{0xa2}
		switch {
		case n < 0x80:
			hdr = append(hdr, byte(n))
		case n <= 0xffff:
			hdr = append(hdr, 0x82, byte(n>>8), byte(n))
		default:
			hdr = append(hdr, 0x83, byte(n>>16), byte(n>>8), byte(n))
		}
		start -= len(hdr)
		copy(buf[start:], hdr)
	}
	return buf[start:]
}

// TestMMSDataDeepNesting checks 10k nested structures are rejected
// without exhausting the stack.
func TestMMSDataDeepNesting(t *testing.T) {
	_, err := decodeMMSDataList(iecNested(10000), 0)
	if !errors.Is(err, errOSIBERDepth) {
		t.Fatalf("got %v, want %v", err, errOSIBERDepth)
	}

	// The limit itself is accepted.
	if _, err := decodeMMSDataList(iecNested(osiBERMaxDepth), 0); err != nil {
		t.Errorf("depth %d: %v", osiBERMaxDepth, err)
	}
	if _, err := decodeMMSDataList(iecNested(osiBERMaxDepth+1), 0); err == nil {
		t.Errorf("depth %d accepted", osiBERMaxDepth+1)
	}
}

func TestOSIBERNext(t *testing.T) {
	tests := []struct {
		in    []byte
		class osiBERClass
		form  osiBERForm
		tag   uint32
		value []byte
		err   error
	}{
		{[]byte{0x02, 0x01, 0x05}, osiBERUniversal, osiBERPrimitive, 2, []byte{5}, nil},
		{[]byte{0xbf, 0x4f, 0x00}, osiBERContext, osiBERConstructed, 79, []byte{}, nil},
		{[]byte{0x9f, 0x81, 0x00, 0x00}, osiBERContext, osiBERPrimitive, 128, []byte{}, nil},
		{[]byte{0x61, 0x81, 0x01, 0xaa}, osiBERApplication, osiBERConstructed, 1, []byte{0xaa}, nil},
		{[]byte{0x04, 0x82, 0x00, 0x01, 0xaa}, osiBERUniversal, osiBERPrimitive, 4, []byte{0xaa}, nil},
		{[]byte{0x04}, 0, 0, 0, nil, errOSIBERTruncated},
		{[]byte{0x04, 0x02, 0x00}, 0, 0, 0, nil, errOSIBERTruncated},
		{[]byte{0x30, 0x80, 0x00, 0x00}, 0, 0, 0, nil, errOSIBERIndefinite},
		{[]byte{0x04, 0x85, 0, 0, 0, 0, 1}, 0, 0, 0, nil, errOSIBERLength},
		{[]byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xff}, 0, 0, 0, nil, errOSIBERTruncated},
		{[]byte{0x04, 0x82, 0x01}, 0, 0, 0, nil, errOSIBERTruncated},
		{[]byte{0x1f, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00}, 0, 0, 0, nil, errOSIBERTag},
		{[]byte{0x1f, 0x81}, 0, 0, 0, nil, errOSIBERTruncated},
	}
	for _, tc := range tests {
		tlv, _, err := osiBERNext(tc.in)
		if err != tc.err {
			t.Errorf("% x: err %v, want %v", tc.in, err, tc.err)
			continue
		}
		if err == nil && (tlv.Class != tc.class || tlv.Form != tc.form || tlv.Tag != tc.tag || !bytes.Equal(tlv.Value, tc.value)) {
			t.Errorf("% x: got %+v", tc.in, tlv)
		}
	}
}

func TestOSIBERValues(t *testing.T) {
	ints := map[string]int64{"\x00": 0, "\x7f": 127, "\x80": -128, "\xff\x7f": -129, "\x01\x00": 256,
		"\x7f\xff\xff\xff\xff\xff\xff\xff": math.MaxInt64}
	for in, want := range ints {
		if got, err := osiBERInt([]byte(in)); err != nil || got != want {
			t.Errorf("int % x = %d, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "\x01\x02\x03\x04\x05\x06\x07\x08\x09"} {
		if _, err := osiBERInt([]byte(bad)); err == nil {
			t.Errorf("int % x accepted", bad)
		}
	}

	if n, err := osiBERUint([]byte("\x00\xff\xff\xff\xff\xff\xff\xff\xff")); err != nil || n != math.MaxUint64 {
		t.Errorf("uint max = %d, %v", n, err)
	}
	for _, bad := range []string{"", "\x80", "\x01\x00\x00\x00\x00\x00\x00\x00\x00"} {
		if _, err := osiBERUint([]byte(bad)); err == nil {
			t.Errorf("uint % x accepted", bad)
		}
	}

	oids := map[string]string{"\x28\xca\x22\x02\x01": "1.0.9506.2.1", "\x52\x01\x00\x01": "2.2.1.0.1",
		"\x51\x01": "2.1.1", "\x2b\xce\x0f\x02": "1.3.9999.2", "\x88\x37\x01": "2.999.1"}
	for in, want := range oids {
		if got, err := osiBEROID([]byte(in)); err != nil || got != want {
			t.Errorf("oid % x = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "\x81", "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"} {
		if _, err := osiBEROID([]byte(bad)); err == nil {
			t.Errorf("oid % x accepted", bad)
		}
	}

	for _, bad := range []string{"", "\x08\x00", "\x01"} {
		if _, _, err := osiBERBits([]byte(bad)); err == nil {
			t.Errorf("bits % x accepted", bad)
		}
	}
}

func TestIEC61850Register(t *testing.T) {
	registerIEC61850Decoders()
	first := EthernetTypeMetadata[EthernetTypeSV]
	registerIEC61850Decoders()
	if EthernetTypeMetadata[EthernetTypeSV].LayerType != first.LayerType || EthernetTypeGOOSE.LayerType() != LayerTypeGOOSE {
		t.Error("registration not idempotent")
	}
}

// iecFuzzSeeds returns the APDUs (from APPID on) of the test captures.
func iecFuzzSeeds(f *testing.F, files ...string) {
	for _, name := range files {
		for _, frame := range iecReadPcap(f, "testdata/"+name) {
			off := 14
			if EthernetType(binary.BigEndian.Uint16(frame[12:])) == EthernetTypeDot1Q {
				off += 4
			}
			f.Add(frame[off:])
		}
	}
}

// iecFuzzOne decodes data both as a DecodingLayer and through a packet.
func iecFuzzOne(t *testing.T, l gopacket.DecodingLayer, lt gopacket.LayerType, data []byte) {
	if err := l.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
		if len(l.(gopacket.Layer).LayerContents()) > len(data) {
			t.Fatal("contents longer than input")
		}
	}
	gopacket.NewPacket(data, lt, gopacket.Default)
}

func FuzzGOOSE(f *testing.F) {
	iecFuzzSeeds(f, "iec61850_goose_ge_f650.pcap", "iec61850_goose_vlan.pcap", "iec61850_goose_iedscout.pcap")
	f.Fuzz(func(t *testing.T, data []byte) {
		iecFuzzOne(t, &GOOSE{}, LayerTypeGOOSE, data)
	})
}

func FuzzSV(f *testing.F) {
	iecFuzzSeeds(f, "iec61850_sv_multi_asdu.pcap", "iec61850_sv_bad_length.pcap", "iec61850_sv_92le.pcap")
	f.Fuzz(func(t *testing.T, data []byte) {
		iecFuzzOne(t, &SV{}, LayerTypeSV, data)
	})
}

// A 4-octet BER length of 0x80000000 is negative in a 32-bit int, which
// used to pass the bounds check and panic when slicing.
func TestOSIBERLengthOverflow(t *testing.T) {
	cases := map[string][]byte{
		"mms":   {0xa0, 0x84, 0x80, 0x00, 0x00, 0x00},
		"goose": {0x00, 0x01, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x61, 0x84, 0x80, 0x00, 0x00, 0x00},
	}

	if _, _, err := osiBERNext(cases["mms"]); err == nil {
		t.Fatal("osiBERNext accepted a 2 GiB length")
	}

	g := &GOOSE{}
	if err := g.DecodeFromBytes(cases["goose"], gopacket.NilDecodeFeedback); err == nil {
		t.Fatal("GOOSE accepted a 2 GiB length")
	}
}
