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
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

var (
	_ gopacket.DecodingLayer    = &DNP3{}
	_ gopacket.ApplicationLayer = &DNP3{}
)

// Frame 4 of testdata/dnp3-2.pcap (ICS-pcap DNP3-TestDataPart2): a SELECT
// of one CROB, latch on, index 34463.
var testPacketDNP3Select = []byte{
	0x00, 0x42, 0x15, 0x69, 0x87, 0x25, 0x00, 0x16, 0xcb, 0x8e, 0x3f, 0x0b, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x4b, 0x08, 0x8c, 0x40, 0x00, 0x80, 0x06, 0xec, 0x8c, 0xc0, 0xa8, 0x42, 0x21, 0xc0, 0xa8,
	0x42, 0x22, 0x04, 0x8f, 0x4e, 0x20, 0xde, 0x6e, 0xf3, 0xc0, 0xa2, 0x46, 0xda, 0x01, 0x50, 0x18,
	0xfe, 0x76, 0x96, 0xa5, 0x00, 0x00, 0x05, 0x64, 0x1a, 0xc4, 0x04, 0x00, 0x03, 0x00, 0xc2, 0xe6,
	0xd2, 0xc3, 0x03, 0x0c, 0x01, 0x28, 0x01, 0x00, 0x9f, 0x86, 0x03, 0x01, 0x64, 0x00, 0x00, 0x00,
	0xec, 0x41, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b,
}

// Frame 40 of testdata/dnp3.pcap (ICS-pcap DNP3-TestDataPart1): an
// unsolicited response with a CTO, binary input events with relative time
// and analog events.
var testPacketDNP3Unsolicited = []byte{
	0x00, 0x50, 0x04, 0x93, 0x70, 0x67, 0x00, 0x02, 0xb3, 0xce, 0x70, 0x51, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x83, 0x93, 0xd3, 0x40, 0x00, 0x80, 0x06, 0x52, 0x97, 0x0a, 0x00, 0x00, 0x03, 0x0a, 0x00,
	0x00, 0x08, 0x4e, 0x20, 0x0b, 0x0c, 0x73, 0x07, 0x54, 0xc4, 0x8f, 0x05, 0xdb, 0xed, 0x50, 0x18,
	0xff, 0xbf, 0x5a, 0x21, 0x00, 0x00, 0x05, 0x64, 0x4c, 0x44, 0x03, 0x00, 0x04, 0x00, 0xd8, 0x6b,
	0xcc, 0xf3, 0x82, 0x00, 0x00, 0x33, 0x01, 0x07, 0x01, 0xe2, 0x43, 0x7d, 0x87, 0xff, 0x00, 0x02,
	0xf8, 0xc3, 0x03, 0x28, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x81, 0x00, 0x00,
	0x02, 0x00, 0x59, 0x89, 0x81, 0x00, 0x00, 0x00, 0x00, 0x81, 0xf3, 0x03, 0x01, 0x00, 0x01, 0xf3,
	0x03, 0x20, 0x01, 0x28, 0x3b, 0x46, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xe8, 0xb9, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3d,
	0x62,
}

// Frame 91 of testdata/dnp3.pcap: a response with packed binary inputs,
// binary output status, a counter, a frozen counter and analog inputs.
var testPacketDNP3Static = []byte{
	0x00, 0x50, 0x04, 0x93, 0x70, 0x67, 0x00, 0x02, 0xb3, 0xce, 0x70, 0x51, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x85, 0xc6, 0x01, 0x40, 0x00, 0x80, 0x06, 0x20, 0x66, 0x0a, 0x00, 0x00, 0x03, 0x0a, 0x00,
	0x00, 0x09, 0x4e, 0x20, 0x04, 0x38, 0x96, 0x6c, 0x7a, 0x74, 0x19, 0x6a, 0x18, 0x86, 0x50, 0x18,
	0xff, 0x96, 0x7c, 0x24, 0x00, 0x00, 0x05, 0x64, 0x4e, 0x44, 0x03, 0x00, 0x04, 0x00, 0x6f, 0x4d,
	0xd8, 0xc5, 0x81, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x05, 0x02, 0x0a, 0x02, 0x00, 0x00, 0x05,
	0xac, 0x11, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x14, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x15, 0x4e, 0x0d, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x03, 0x00, 0x00,
	0x06, 0xc5, 0x00, 0x00, 0xf0, 0xff, 0x00, 0xc7, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x25, 0x1c, 0x00, 0x68, 0xac, 0x00, 0x0e, 0x1c, 0x00, 0x00, 0x10, 0x1c, 0x00,
	0x00, 0x2a, 0x73,
}

// Frame 2 of ICS-pcap DNP3-Malformed: an OPERATE claiming two CROBs with
// room for one. Wireshark: malformed, CRCs good.
var testPacketDNP3Malformed = []byte{
	0x00, 0x30, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x21, 0x07, 0x3e, 0x6a, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x4a, 0x19, 0x75, 0x40, 0x00, 0x40, 0x06, 0x9f, 0xe5, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8,
	0x00, 0x02, 0xd0, 0x39, 0x4e, 0x20, 0xdd, 0x97, 0x4b, 0xd6, 0x99, 0x74, 0x99, 0xc9, 0x50, 0x18,
	0x16, 0xd0, 0x6b, 0x93, 0x00, 0x00, 0x05, 0x64, 0x19, 0xc4, 0x0a, 0x00, 0x01, 0x00, 0xda, 0x8f,
	0xc1, 0xc2, 0x04, 0x0c, 0x01, 0x00, 0x00, 0x01, 0x00, 0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64,
	0x63, 0x9a, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
}

// Frame 157 of ICS-pcap DNP3-Malformed: a header whose range stops before
// it starts.
var testPacketDNP3BadRange = []byte{
	0x00, 0x30, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x21, 0x07, 0x3e, 0x6a, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x4d, 0x4e, 0xa2, 0x40, 0x00, 0x40, 0x06, 0x6a, 0xb5, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8,
	0x00, 0x02, 0xd1, 0x57, 0x4e, 0x20, 0xde, 0xb7, 0x89, 0xa8, 0xa6, 0xe9, 0xb9, 0xc6, 0x50, 0x18,
	0x16, 0xd0, 0xd6, 0xc3, 0x00, 0x00, 0x05, 0x64, 0x1c, 0xc4, 0x0a, 0x00, 0x01, 0x00, 0x53, 0x77,
	0xc1, 0xc2, 0x04, 0x0c, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x01, 0x64, 0x00,
	0xe9, 0xbf, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b,
}

// testDNP3LinkStatus is the TCP payload of ICS-pcap DNP3-RequestLinkStatus:
// a link frame with no user data.
var testDNP3LinkStatus = []byte{0x05, 0x64, 0x05, 0xc9, 0x03, 0x00, 0x04, 0x00, 0xbd, 0x71}

// testDNP3Opts decodes TCP payloads by port, as DNP3 needs.
var testDNP3Opts = gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true}

// testDNP3EthHeaderLen is the Ethernet+IPv4+TCP header size of the
// embedded packets, all without IP or TCP options.
const testDNP3EthHeaderLen = 54

// dnp3Frame builds a link frame with valid CRCs around user data.
func dnp3Frame(ctl byte, dst, src uint16, user []byte) []byte {
	hdr := []byte{dnp3Start0, dnp3Start1, byte(dnp3MinLength + len(user)), ctl, byte(dst), byte(dst >> 8), byte(src), byte(src >> 8)}
	frame := binary.LittleEndian.AppendUint16(hdr, DNP3CRC(hdr))
	for len(user) > 0 {
		n := min(dnp3BlockLen, len(user))
		frame = append(frame, user[:n]...)
		frame = binary.LittleEndian.AppendUint16(frame, DNP3CRC(user[:n]))
		user = user[n:]
	}
	return frame
}

// dnp3Master builds an unconfirmed user data frame from master 3 to
// outstation 4 with transport header th and application bytes app.
func dnp3Master(th byte, app ...byte) []byte {
	return dnp3Frame(0xc4, 4, 3, append([]byte{th}, app...))
}

// decodeDNP3Packet decodes data as DNP3 and returns its DNP3 layers.
func decodeDNP3Packet(t *testing.T, data []byte) (gopacket.Packet, []*DNP3) {
	t.Helper()
	p := gopacket.NewPacket(data, LayerTypeDNP3, gopacket.Default)
	var out []*DNP3
	for _, l := range p.Layers() {
		if d, ok := l.(*DNP3); ok {
			out = append(out, d)
		}
	}
	return p, out
}

func TestDNP3CRC(t *testing.T) {
	// Check value of CRC-16/DNP from the CRC catalogue.
	if got := DNP3CRC([]byte("123456789")); got != 0xEA82 {
		t.Errorf("DNP3CRC(123456789) = %#04x, want 0xea82", got)
	}

	// Header CRC of a captured frame, sent little endian.
	if got := DNP3CRC(testDNP3LinkStatus[:8]); got != 0x71bd {
		t.Errorf("DNP3CRC(link status header) = %#04x, want 0x71bd", got)
	}
}

func TestDNP3Select(t *testing.T) {
	registerDNP3Decoders()
	p := gopacket.NewPacket(testPacketDNP3Select, LinkTypeEthernet, testDNP3Opts)
	if p.ErrorLayer() != nil {
		t.Fatal("decode failed:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeDNP3}, t)

	d := p.Layer(LayerTypeDNP3).(*DNP3)
	wantLink := DNP3Link{
		Length: 26, Control: 0xc4, Dir: true, Primary: true,
		Function: DNP3LinkUnconfirmedData, Destination: 4, Source: 3, CRC: 0xe6c2,
	}
	if d.Link != wantLink {
		t.Errorf("link = %+v, want %+v", d.Link, wantLink)
	}

	if !d.CRCValid() {
		t.Errorf("CRCs flagged bad: header ok %v, bad blocks %d", d.HeaderCRCOK, d.BadBlocks)
	}

	// Transport 0xd2: FIN, FIR, sequence 18.
	if want := (DNP3Transport{FIN: true, FIR: true, Seq: 18}); d.Transport != want {
		t.Errorf("transport = %+v, want %+v", d.Transport, want)
	}

	if p.ApplicationLayer() != gopacket.ApplicationLayer(d) {
		t.Error("DNP3 is not the application layer")
	}

	if !bytes.Equal(d.Payload(), d.UserData[1:]) || len(d.UserData) != 21 {
		t.Errorf("user data %x, payload %x", d.UserData, d.Payload())
	}

	a := d.Application
	if a == nil {
		t.Fatal("no application layer")
	}

	if want := (DNP3AppControl{FIR: true, FIN: true, Seq: 3}); a.Control != want || a.Function != DNP3FuncSelect {
		t.Errorf("app control %+v function %v", a.Control, a.Function)
	}

	want := []DNP3ObjectHeader{{
		Group: DNP3GroupBinaryCommand, Variation: 1, Qualifier: 0x28,
		Prefix: DNP3PrefixIndex2, Range: DNP3RangeCount2, Count: 1,
		Data: []byte{0x9f, 0x86, 0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00},
		Objects: []DNP3Object{{
			Index: 34463,
			Data:  []byte{0x03, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00},
		}},
	}}
	if !reflect.DeepEqual(a.Objects, want) {
		t.Errorf("objects = %+v, want %+v", a.Objects, want)
	}

	// CROB per Wireshark: latch on, count 1, on 100 ms, off 100 ms.
	crob := a.Objects[0].Objects[0].Data
	if crob[0] != 3 || crob[1] != 1 || binary.LittleEndian.Uint32(crob[2:]) != 100 || binary.LittleEndian.Uint32(crob[6:]) != 100 {
		t.Errorf("CROB %x", crob)
	}
}

func TestDNP3Unsolicited(t *testing.T) {
	registerDNP3Decoders()
	p := gopacket.NewPacket(testPacketDNP3Unsolicited, LinkTypeEthernet, testDNP3Opts)
	if p.ErrorLayer() != nil {
		t.Fatal("decode failed:", p.ErrorLayer().Error())
	}

	d := p.Layer(LayerTypeDNP3).(*DNP3)
	if d.Link.Dir || !d.Link.Primary || d.Link.Function != DNP3LinkUnconfirmedData || !d.CRCValid() {
		t.Errorf("link %+v crc %v", d.Link, d.CRCValid())
	}

	a := d.Application
	if want := (DNP3AppControl{FIR: true, FIN: true, CON: true, UNS: true, Seq: 3}); a.Control != want {
		t.Errorf("app control %+v, want %+v", a.Control, want)
	}

	if a.Function != DNP3FuncUnsolicited || a.IIN != 0 || len(a.Objects) != 3 || len(a.Unparsed) != 0 {
		t.Fatalf("function %v IIN %v objects %d unparsed %x", a.Function, a.IIN, len(a.Objects), a.Unparsed)
	}

	// g51v1 CTO, as Wireshark shows it.
	cto := a.Objects[0]
	wantTime := time.Date(2004, time.October, 11, 10, 16, 34, 18e6, time.UTC)
	if cto.Group != DNP3GroupCTO || cto.Range != DNP3RangeCount1 || len(cto.Objects) != 1 || !DNP3Time(cto.Objects[0].Data).Equal(wantTime) {
		t.Errorf("CTO %+v time %v", cto, DNP3Time(cto.Objects[0].Data))
	}

	// g2v3 events: index, state (flags bit 7) and relative time in ms.
	ev := a.Objects[1]
	wantIdx := []uint32{0, 1, 2, 0, 1}
	wantState := []byte{0, 1, 1, 1, 0}
	wantRel := []uint16{0, 0, 0, 1011, 1011}
	if ev.Group != DNP3GroupBinaryInputEvent || ev.Variation != 3 || ev.Prefix != DNP3PrefixIndex2 || len(ev.Objects) != len(wantIdx) {
		t.Fatalf("g2v3 header %+v", ev)
	}
	for i, o := range ev.Objects {
		if o.Index != wantIdx[i] || o.Data[0]>>7 != wantState[i] || binary.LittleEndian.Uint16(o.Data[1:]) != wantRel[i] {
			t.Errorf("g2v3 object %d = %+v", i, o)
		}
	}

	// g32v1 events: three zero values at indexes 0..2.
	ai := a.Objects[2]
	if ai.Group != DNP3GroupAnalogInputEvent || ai.Variation != 1 || len(ai.Objects) != 3 {
		t.Fatalf("g32v1 header %+v", ai)
	}
	for i, o := range ai.Objects {
		if o.Index != uint32(i) || binary.LittleEndian.Uint32(o.Data[1:]) != 0 {
			t.Errorf("g32v1 object %d = %+v", i, o)
		}
	}
}

func TestDNP3StaticResponse(t *testing.T) {
	registerDNP3Decoders()
	p := gopacket.NewPacket(testPacketDNP3Static, LinkTypeEthernet, testDNP3Opts)
	if p.ErrorLayer() != nil {
		t.Fatal("decode failed:", p.ErrorLayer().Error())
	}

	a := p.Layer(LayerTypeDNP3).(*DNP3).Application
	if a.Function != DNP3FuncResponse || len(a.Objects) != 5 {
		t.Fatalf("function %v, %d objects", a.Function, len(a.Objects))
	}

	// g1v1 points 0..5, packed: only point 1 is on.
	bi := a.Objects[0]
	if bi.Group != DNP3GroupBinaryInput || bi.BitsPerObject != 1 || bi.Count != 6 || bi.Objects != nil {
		t.Fatalf("g1v1 header %+v", bi)
	}
	for i := uint64(0); i < bi.Count; i++ {
		want := uint8(0)
		if i == 1 {
			want = 1
		}
		if got := bi.PackedValue(i); got != want {
			t.Errorf("g1v1 point %d = %d, want %d", i, got, want)
		}
	}

	if bi.PackedValue(bi.Count) != 0 {
		t.Error("PackedValue past Count is not 0")
	}

	// g10v2 points 0..5, one flags octet each.
	if bo := a.Objects[1]; bo.Group != DNP3GroupBinaryOutput || len(bo.Objects) != 6 || bo.Objects[5].Index != 5 {
		t.Errorf("g10v2 header %+v", bo)
	}

	// g20v5 and g21v9: one 32 bit counter each, value 0.
	for i, g := range []DNP3Group{DNP3GroupCounter, DNP3GroupFrozenCounter} {
		h := a.Objects[2+i]
		if h.Group != g || len(h.Objects) != 1 || binary.LittleEndian.Uint32(h.Objects[0].Data) != 0 {
			t.Errorf("%v header %+v", g, h)
		}
	}

	// g30v3 points 0..6, values per Wireshark.
	wantAI := []int32{197, 199, 200, 1, 7205, 7182, 7184}
	ai := a.Objects[4]
	if ai.Group != DNP3GroupAnalogInput || ai.Variation != 3 || len(ai.Objects) != len(wantAI) {
		t.Fatalf("g30v3 header %+v", ai)
	}
	for i, o := range ai.Objects {
		if got := int32(binary.LittleEndian.Uint32(o.Data)); got != wantAI[i] || o.Index != uint32(i) {
			t.Errorf("g30v3 point %d = %d index %d, want %d", i, got, o.Index, wantAI[i])
		}
	}
}

func TestDNP3LinkOnly(t *testing.T) {
	p, ds := decodeDNP3Packet(t, testDNP3LinkStatus)
	if p.ErrorLayer() != nil || len(ds) != 1 {
		t.Fatalf("error %v, %d layers", p.ErrorLayer(), len(ds))
	}

	d := ds[0]
	if d.Link.Function != DNP3LinkRequestStatus || !d.Link.Dir || !d.Link.Primary || d.Link.Destination != 3 || d.Link.Source != 4 {
		t.Errorf("link %+v", d.Link)
	}

	if len(d.UserData) != 0 || d.Application != nil || d.Payload() != nil || !d.CRCValid() {
		t.Errorf("user data %x application %v", d.UserData, d.Application)
	}
}

// dnp3PcapFrame is the Wireshark view of one frame of a test pcap.
type dnp3PcapFrame struct {
	frame   int
	length  uint8
	control uint8
	dst     uint16
	src     uint16
	th      uint8
	alFunc  int // -1 when there is no application header
	iin     DNP3IIN
	objects string
}

// testDNP3PcapFrames is what tshark 4.7 reports for each DNP3 frame of
// testdata/dnp3.pcap and testdata/dnp3-2.pcap.
var testDNP3PcapFrames = map[string][]dnp3PcapFrame{
	"testdata/dnp3.pcap": {
		{4, 10, 0x44, 3, 4, 0xe6, 130, 0x1000, ""},
		{6, 8, 0xc4, 4, 3, 0xc0, 0, 0, ""},
		{7, 18, 0xc4, 4, 3, 0xc1, 2, 0, "0x3201"},
		{9, 10, 0x44, 3, 4, 0xe7, 129, 0x0000, ""},
		{11, 17, 0xc4, 4, 3, 0xc2, 21, 0, "0x3c02,0x3c03,0x3c04"},
		{12, 10, 0x44, 3, 4, 0xe8, 129, 0x0000, ""},
		{17, 10, 0x44, 3, 4, 0xea, 130, 0x0000, ""},
		{30, 10, 0x44, 3, 4, 0xc9, 130, 0x1000, ""},
		{32, 8, 0xc4, 4, 3, 0xc0, 0, 0, ""},
		{33, 18, 0xc4, 4, 3, 0xc1, 2, 0, "0x3201"},
		{35, 10, 0x44, 3, 4, 0xca, 129, 0x0000, ""},
		{37, 17, 0xc4, 4, 3, 0xc2, 20, 0, "0x3c02,0x3c03,0x3c04"},
		{38, 10, 0x44, 3, 4, 0xcb, 129, 0x0000, ""},
		{40, 76, 0x44, 3, 4, 0xcc, 130, 0x0000, "0x3301,0x0203,0x2001"},
		{41, 8, 0xc4, 4, 3, 0xc3, 0, 0, ""},
		{43, 71, 0x44, 3, 4, 0xcd, 130, 0x0000, "0x3301,0x0203,0x2001"},
		{44, 8, 0xc4, 4, 3, 0xc4, 0, 0, ""},
		{46, 76, 0x44, 3, 4, 0xce, 130, 0x0000, "0x3301,0x0203,0x2001"},
		{47, 8, 0xc4, 4, 3, 0xc5, 0, 0, ""},
		{49, 71, 0x44, 3, 4, 0xcf, 130, 0x0000, "0x3301,0x0203,0x2001"},
		{50, 8, 0xc4, 4, 3, 0xc6, 0, 0, ""},
		{52, 76, 0x44, 3, 4, 0xd0, 130, 0x0000, "0x3301,0x0203,0x2001"},
		{53, 8, 0xc4, 4, 3, 0xc7, 0, 0, ""},
		{55, 50, 0x44, 3, 4, 0xd1, 130, 0x0000, "0x3301,0x0203"},
		{56, 8, 0xc4, 4, 3, 0xc8, 0, 0, ""},
		{58, 76, 0x44, 3, 4, 0xd2, 130, 0x0000, "0x3301,0x0203,0x2001"},
		{59, 8, 0xc4, 4, 3, 0xc9, 0, 0, ""},
		{61, 66, 0x44, 3, 4, 0xd3, 130, 0x0000, "0x3301,0x0203,0x2001"},
		{62, 8, 0xc4, 4, 3, 0xca, 0, 0, ""},
		{64, 76, 0x44, 3, 4, 0xd4, 130, 0x0000, "0x3301,0x0203,0x2001"},
		{65, 8, 0xc4, 4, 3, 0xcb, 0, 0, ""},
		{67, 56, 0x44, 3, 4, 0xd5, 130, 0x0000, "0x3301,0x0203,0x2001"},
		{68, 8, 0xc4, 4, 3, 0xcc, 0, 0, ""},
		{70, 8, 0xc4, 4, 3, 0xcd, 13, 0, ""},
		{71, 16, 0x44, 3, 4, 0xd6, 129, 0x0000, "0x3402"},
		{76, 8, 0xc4, 4, 3, 0xc0, 13, 0, ""},
		{77, 10, 0x44, 6, 4, 0xd1, 130, 0x0000, ""},
		{78, 10, 0x44, 6, 4, 0xd2, 130, 0x0000, ""},
		{80, 16, 0x44, 3, 4, 0xd3, 129, 0x0000, "0x3402"},
		{82, 11, 0xc4, 4, 3, 0xc1, 1, 0, "0x0200"},
		{83, 10, 0x44, 3, 4, 0xd4, 129, 0x8000, ""},
		{84, 10, 0x44, 6, 4, 0xd5, 130, 0x8000, ""},
		{86, 17, 0xc4, 4, 3, 0xc2, 21, 0, "0x3c02,0x3c03,0x3c04"},
		{87, 10, 0x44, 3, 4, 0xd6, 129, 0x8000, ""},
		{88, 14, 0xc4, 4, 3, 0xc3, 2, 0, "0x5001"},
		{89, 10, 0x44, 3, 4, 0xd7, 129, 0x0000, ""},
		{90, 20, 0xc4, 4, 3, 0xc4, 1, 0, "0x3c02,0x3c03,0x3c04,0x3c01"},
		{91, 78, 0x44, 3, 4, 0xd8, 129, 0x0000, "0x0101,0x0a02,0x1405,0x1509,0x1e03"},
		{93, 10, 0x44, 6, 4, 0xd9, 130, 0x0000, ""},
		{95, 10, 0x44, 6, 4, 0xda, 130, 0x0000, ""},
		{97, 10, 0x44, 6, 4, 0xdb, 130, 0x0000, ""},
		{99, 10, 0x44, 6, 4, 0xdc, 130, 0x0000, ""},
		{101, 10, 0x44, 6, 4, 0xdd, 130, 0x0000, ""},
		{103, 10, 0x44, 6, 4, 0xde, 130, 0x0000, ""},
		{105, 10, 0x44, 6, 4, 0xdf, 130, 0x0000, ""},
		{107, 10, 0x44, 6, 4, 0xe0, 130, 0x0000, ""},
		{109, 17, 0xc4, 4, 3, 0xc5, 20, 0, "0x3c02,0x3c03,0x3c04"},
		{110, 10, 0x44, 3, 4, 0xe1, 129, 0x0000, ""},
		{111, 10, 0x44, 6, 4, 0xe2, 130, 0x0000, ""},
		{113, 17, 0xc4, 4, 3, 0xc6, 20, 0, "0x3c02,0x3c03,0x3c04"},
		{114, 10, 0x44, 3, 4, 0xe3, 129, 0x0000, ""},
		{116, 10, 0x44, 6, 4, 0xe4, 130, 0x0000, ""},
		{121, 10, 0x44, 3, 4, 0xc0, 130, 0x9000, ""},
		{123, 8, 0xc4, 4, 3, 0xc0, 0, 0, ""},
		{124, 17, 0xc4, 4, 3, 0xc1, 21, 0, "0x3c02,0x3c03,0x3c04"},
		{126, 10, 0x44, 3, 4, 0xc1, 129, 0x9000, ""},
		{128, 18, 0xc4, 4, 3, 0xc2, 2, 0, "0x3201"},
		{129, 10, 0x44, 3, 4, 0xc2, 129, 0x8000, ""},
		{130, 17, 0xc4, 4, 3, 0xc3, 21, 0, "0x3c02,0x3c03,0x3c04"},
		{131, 10, 0x44, 3, 4, 0xc3, 129, 0x8000, ""},
		{133, 18, 0xc4, 4, 3, 0xc4, 2, 0, "0x3201"},
		{134, 10, 0x44, 3, 4, 0xc4, 129, 0x8000, ""},
		{135, 17, 0xc4, 4, 3, 0xc5, 21, 0, "0x3c02,0x3c03,0x3c04"},
		{136, 10, 0x44, 3, 4, 0xc5, 129, 0x8000, ""},
		{137, 14, 0xc4, 4, 3, 0xc6, 2, 0, "0x5001"},
		{138, 10, 0x44, 3, 4, 0xc6, 129, 0x0000, ""},
		{140, 20, 0xc4, 4, 3, 0xc7, 1, 0, "0x3c02,0x3c03,0x3c04,0x3c01"},
		{141, 78, 0x44, 3, 4, 0xc7, 129, 0x0000, "0x0101,0x0a02,0x1405,0x1509,0x1e03"},
		{143, 8, 0xc4, 4, 3, 0xc8, 14, 0, ""},
		{144, 16, 0x44, 3, 4, 0xc8, 129, 0x0000, "0x3402"},
		{146, 8, 0xc4, 4, 3, 0xc9, 14, 0, ""},
		{147, 16, 0x44, 3, 4, 0xc9, 129, 0x0000, "0x3402"},
		{152, 10, 0x44, 3, 4, 0xd6, 130, 0x0100, ""},
		{154, 17, 0xc4, 65535, 3, 0xc1, 21, 0, "0x3c02,0x3c03,0x3c04"},
		{156, 17, 0xc4, 65535, 3, 0xc1, 21, 0, "0x3c02,0x3c03,0x3c04"},
		{161, 10, 0x44, 3, 4, 0xdb, 130, 0x1000, ""},
		{163, 17, 0xc4, 4, 3, 0xc1, 18, 0, ""},
		{164, 10, 0x44, 3, 4, 0xdc, 129, 0x1001, ""},
		{166, 17, 0xc4, 4, 3, 0xc1, 18, 0, ""},
		{167, 10, 0x44, 3, 4, 0xdd, 129, 0x1001, ""},
		{172, 10, 0x44, 3, 6, 0xc6, 130, 0x9501, ""},
		{174, 17, 0xc4, 65535, 3, 0xc1, 18, 0, ""},
		{176, 17, 0xc4, 65535, 3, 0xc1, 18, 0, ""},
	},
	"testdata/dnp3-2.pcap": {
		{1, 17, 0xc4, 4, 3, 0xd1, 1, 0, "0x3c02,0x3c03,0x3c04"},
		{2, 10, 0x44, 3, 4, 0xf8, 129, 0x0000, ""},
		{4, 26, 0xc4, 4, 3, 0xd2, 3, 0, "0x0c01"},
		{5, 28, 0x44, 3, 4, 0xf9, 129, 0x0004, "0x0c01"},
		{7, 26, 0xc4, 4, 3, 0xd3, 3, 0, "0x0c01"},
		{8, 28, 0x44, 3, 4, 0xfa, 129, 0x0004, "0x0c01"},
		{10, 26, 0xc4, 4, 3, 0xd4, 3, 0, "0x0c01"},
		{11, 28, 0x44, 3, 4, 0xfb, 129, 0x0004, "0x0c01"},
		{13, 26, 0xc4, 4, 3, 0xd5, 3, 0, "0x0c01"},
		{14, 28, 0x44, 3, 4, 0xfc, 129, 0x0004, "0x0c01"},
		{16, 26, 0xc4, 4, 3, 0xd6, 3, 0, "0x0c01"},
		{17, 28, 0x44, 3, 4, 0xfd, 129, 0x0004, "0x0c01"},
		{19, 11, 0xc4, 4, 3, 0xd7, 1, 0, "0xff00"},
		{20, 10, 0x44, 3, 4, 0xfe, 129, 0x0006, ""},
		{22, 11, 0xc4, 4, 3, 0xd8, 1, 0, "0xff00"},
		{23, 10, 0x44, 3, 4, 0xff, 129, 0x0006, ""},
		{25, 11, 0xc4, 4, 3, 0xd9, 1, 0, "0xff00"},
		{26, 10, 0x44, 3, 4, 0xc0, 129, 0x0006, ""},
		{28, 11, 0xc4, 4, 3, 0xda, 1, 0, "0xff00"},
		{29, 10, 0x44, 3, 4, 0xc1, 129, 0x0006, ""},
		{31, 11, 0xc4, 4, 3, 0xdb, 1, 0, "0xff00"},
		{32, 10, 0x44, 3, 4, 0xc2, 129, 0x0006, ""},
	},
}

// testDNP3PcapDiffs lists frames where this decoder and Wireshark list
// different object headers, with the headers decoded here. Wireshark does
// not parse STOP_APPL objects (163 to 176) at all. Their last header, as
// that of frames 154 and 156, has the reserved qualifier 0xed: it is
// listed, as Wireshark does, with State DNP3HeaderReserved.
var testDNP3PcapDiffs = map[string]map[int]string{
	"testdata/dnp3.pcap": {
		163: "0x3c02,0x0107,0x3c04",
		166: "0x3c02,0x0107,0x3c04",
		174: "0x3c02,0x0107,0x3c04",
		176: "0x3c02,0x0107,0x3c04",
	},
}

// dnp3ObjectList renders object headers as Wireshark's dnp3.al.obj does.
func dnp3ObjectList(a *DNP3Application) string {
	if a == nil {
		return ""
	}

	var objs []string
	for _, h := range a.Objects {
		objs = append(objs, fmt.Sprintf("0x%02x%02x", uint8(h.Group), h.Variation))
	}
	return strings.Join(objs, ",")
}

func TestDNP3Pcap(t *testing.T) {
	registerDNP3Decoders()
	for path, frames := range testDNP3PcapFrames {
		packets := mbReadPcap(t, path)
		for _, want := range frames {
			p := gopacket.NewPacket(packets[want.frame-1], LinkTypeEthernet, testDNP3Opts)
			if p.ErrorLayer() != nil {
				t.Errorf("%s frame %d: %v", path, want.frame, p.ErrorLayer().Error())
				continue
			}

			d, ok := p.Layer(LayerTypeDNP3).(*DNP3)
			if !ok {
				t.Errorf("%s frame %d: no DNP3 layer", path, want.frame)
				continue
			}

			got := dnp3PcapFrame{
				frame: want.frame, length: d.Link.Length, control: d.Link.Control,
				dst: d.Link.Destination, src: d.Link.Source, alFunc: -1,
				objects: dnp3ObjectList(d.Application),
			}
			if len(d.UserData) > 0 {
				got.th = d.UserData[0]
			}
			if d.Application != nil {
				got.alFunc = int(d.Application.Function)
				got.iin = d.Application.IIN
			}

			if objs, ok := testDNP3PcapDiffs[path][want.frame]; ok {
				want.objects = objs
				if len(d.Application.Unparsed) == 0 {
					t.Errorf("%s frame %d: nothing left unparsed", path, want.frame)
				}
			}

			if got != want {
				t.Errorf("%s frame %d:\n got %+v\nwant %+v", path, want.frame, got, want)
			}

			if !d.CRCValid() {
				t.Errorf("%s frame %d: CRC flagged bad", path, want.frame)
			}
		}
	}
}

// testDNP3Frames returns the DNP3 bytes of every embedded test vector.
func testDNP3Frames() [][]byte {
	out := [][]byte{testDNP3LinkStatus}
	for _, pkt := range [][]byte{testPacketDNP3Select, testPacketDNP3Unsolicited, testPacketDNP3Static, testPacketDNP3Malformed, testPacketDNP3BadRange} {
		out = append(out, pkt[testDNP3EthHeaderLen:])
	}
	return out
}

func TestDNP3Malformed(t *testing.T) {
	registerDNP3Decoders()
	tests := []struct {
		name string
		pkt  []byte
		err  error
	}{
		{"objects past the data", testPacketDNP3Malformed, ErrDNP3ObjTruncated},
		{"stop below start", testPacketDNP3BadRange, ErrDNP3BadRange},
	}

	for _, tc := range tests {
		p := gopacket.NewPacket(tc.pkt, LinkTypeEthernet, testDNP3Opts)
		checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeDNP3, gopacket.LayerTypeDecodeFailure}, t)

		el := p.ErrorLayer()
		if el == nil || !errors.Is(el.Error(), tc.err) {
			t.Errorf("%s: error %v, want %v", tc.name, el, tc.err)
		}

		// The link layer and the application header still decode.
		d := p.Layer(LayerTypeDNP3).(*DNP3)
		if d.Application == nil || d.Application.Function != DNP3FuncOperate || len(d.Application.Unparsed) == 0 {
			t.Errorf("%s: application %+v", tc.name, d.Application)
		}
	}

	// DecodeFromBytes fills in the frame along with the error.
	var d DNP3
	err := d.DecodeFromBytes(testPacketDNP3Malformed[testDNP3EthHeaderLen:], gopacket.NilDecodeFeedback)
	if !errors.Is(err, ErrDNP3ObjTruncated) || !d.CRCValid() || d.Link.Destination != 10 || d.Application.Function != DNP3FuncOperate {
		t.Errorf("err %v header CRC ok %v bad blocks %d", err, d.HeaderCRCOK, d.BadBlocks)
	}
}

func TestDNP3Truncated(t *testing.T) {
	for _, frame := range testDNP3Frames() {
		for i := 0; i < len(frame); i++ {
			cut := frame[:i]

			var d DNP3
			df := &dnp3TestFeedback{}
			if err := d.DecodeFromBytes(cut, df); err == nil {
				t.Errorf("frame %x cut to %d bytes decoded", frame, i)
			} else if !df.truncated {
				t.Errorf("frame cut to %d bytes: %v, not flagged truncated", i, err)
			}

			p, _ := decodeDNP3Packet(t, cut)
			if p.ErrorLayer() == nil {
				t.Errorf("packet cut to %d bytes decoded", i)
			}
		}
	}
}

// dnp3TestFeedback records SetTruncated.
type dnp3TestFeedback struct {
	truncated bool
}

func (f *dnp3TestFeedback) SetTruncated() {
	f.truncated = true
}

func TestDNP3LengthLies(t *testing.T) {
	// LEN below 5 cannot hold control, destination and source.
	short := dnp3Frame(0xc4, 4, 3, nil)
	short[2] = 4
	var d DNP3
	if err := d.DecodeFromBytes(short, gopacket.NilDecodeFeedback); !errors.Is(err, ErrDNP3BadLength) {
		t.Errorf("LEN 4: %v", err)
	}

	// LEN 255 claims 250 user data bytes on a 10 byte frame.
	long := dnp3Frame(0xc4, 4, 3, nil)
	long[2] = 0xff
	df := &dnp3TestFeedback{}
	if err := d.DecodeFromBytes(long, df); !errors.Is(err, ErrDNP3Truncated) || !df.truncated {
		t.Errorf("LEN 255: %v truncated %v", err, df.truncated)
	}

	// A wrong start is not DNP3.
	bad := dnp3Frame(0xc4, 4, 3, nil)
	bad[1] = 0x65
	if err := d.DecodeFromBytes(bad, gopacket.NilDecodeFeedback); !errors.Is(err, ErrDNP3BadStart) {
		t.Errorf("start 0x0565: %v", err)
	}
}

func TestDNP3BadCRC(t *testing.T) {
	// A READ of class 1, 2 and 3 data spans two blocks.
	frame := dnp3Master(0xc0, 0xc0, 0x01, 0x3c, 0x02, 0x06, 0x3c, 0x03, 0x06, 0x3c, 0x04, 0x06, 0x3c, 0x01, 0x06, 0x50, 0x01, 0x00, 0x07, 0x07)

	var d DNP3
	if err := d.DecodeFromBytes(frame, gopacket.NilDecodeFeedback); err != nil || !d.CRCValid() {
		t.Fatalf("clean frame: %v, CRC valid %v", err, d.CRCValid())
	}

	// Corrupt the header CRC and a byte of the first block: both are
	// flagged and the frame still decodes as far as the bytes allow.
	bad := append([]byte(nil), frame...)
	bad[dnp3HeaderCRCOff] ^= 0xff
	bad[dnp3HeaderLen+dnp3BlockLen-1] ^= 0x01 // last byte of block 1: the g80 group, now 0x51
	if err := d.DecodeFromBytes(bad, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("corrupt frame: %v", err)
	}

	if d.HeaderCRCOK || d.BadBlocks != 1 || d.CRCValid() {
		t.Errorf("header CRC ok %v, bad blocks %d", d.HeaderCRCOK, d.BadBlocks)
	}

	if got := dnp3ObjectList(d.Application); got != "0x3c02,0x3c03,0x3c04,0x3c01,0x5101" {
		t.Errorf("objects %s", got)
	}
}

func TestDNP3MultipleFrames(t *testing.T) {
	// Two frames back to back, then a third cut short: two layers, and
	// the cut frame stays the payload of the second.
	first := dnp3Master(0xc0, 0xc0, 0x01, 0x3c, 0x01, 0x06)
	second := dnp3Frame(0x44, 3, 4, []byte{0xc0, 0xc0, 0x81, 0x00, 0x00})
	cut := dnp3Master(0xc1, 0xc1, 0x01, 0x3c, 0x02, 0x06)[:12]
	data := append(append(append([]byte(nil), first...), second...), cut...)

	p, ds := decodeDNP3Packet(t, data)
	if p.ErrorLayer() != nil || len(ds) != 2 {
		t.Fatalf("error %v, %d layers", p.ErrorLayer(), len(ds))
	}

	if ds[0].Application.Function != DNP3FuncRead || ds[1].Application.Function != DNP3FuncResponse {
		t.Errorf("functions %v, %v", ds[0].Application.Function, ds[1].Application.Function)
	}

	if !bytes.Equal(ds[1].LayerPayload(), cut) {
		t.Errorf("trailing payload %x, want %x", ds[1].LayerPayload(), cut)
	}

	// Many frames in one buffer decode without recursion.
	var many []byte
	for i := 0; i < 1000; i++ {
		many = append(many, first...)
	}
	if _, ds := decodeDNP3Packet(t, many); len(ds) != 1000 {
		t.Errorf("%d layers from 1000 frames", len(ds))
	}
}

func TestDNP3Fragments(t *testing.T) {
	// g30v1 count 3 needs 15 bytes; only 5 are here.
	objs := []byte{0x1e, 0x01, 0x07, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00}

	// More segments follow (transport FIN clear): not an error.
	var d DNP3
	frame := dnp3Frame(0x44, 3, 4, append([]byte{0x40, 0xc0, 0x81, 0x00, 0x00}, objs...))
	if err := d.DecodeFromBytes(frame, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("first segment: %v", err)
	}

	// The header that continues is listed, its objects are not.
	a := d.Application
	if len(a.Objects) != 1 || a.Objects[0].State != DNP3HeaderTruncated || a.Objects[0].Count != 3 || a.Objects[0].Objects != nil || !bytes.Equal(a.Unparsed, objs) {
		t.Errorf("objects %v unparsed %x", a.Objects, a.Unparsed)
	}

	// Last segment: the same shortfall is malformed.
	frame = dnp3Frame(0x44, 3, 4, append([]byte{0xc0, 0xc0, 0x81, 0x00, 0x00}, objs...))
	if err := d.DecodeFromBytes(frame, gopacket.NilDecodeFeedback); !errors.Is(err, ErrDNP3ObjTruncated) {
		t.Errorf("last segment: %v", err)
	}

	// A later segment (FIR clear) has no application header to decode.
	frame = dnp3Frame(0x44, 3, 4, append([]byte{0x81}, objs...))
	if err := d.DecodeFromBytes(frame, gopacket.NilDecodeFeedback); err != nil || d.Application != nil {
		t.Fatalf("middle segment: %v, application %v", err, d.Application)
	}

	if want := (DNP3Transport{FIN: true, Seq: 1}); d.Transport != want || !bytes.Equal(d.Payload(), objs) {
		t.Errorf("transport %+v payload %x", d.Transport, d.Payload())
	}
}

func TestDNP3Objects(t *testing.T) {
	tests := []struct {
		name     string
		app      []byte
		objects  string
		unparsed int
		err      error
	}{
		{"read class 0123 header only", []byte{0xc0, 0x01, 0x3c, 0x02, 0x06, 0x3c, 0x03, 0x06, 0x3c, 0x04, 0x06, 0x3c, 0x01, 0x06}, "0x3c02,0x3c03,0x3c04,0x3c01", 0, nil},
		{"read huge range header only", []byte{0xc0, 0x01, 0x01, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}, "0x0102", 0, nil},
		{"read index list", []byte{0xc0, 0x01, 0x1e, 0x01, 0x17, 0x02, 0x05, 0x09}, "0x1e01", 0, nil},
		{"read index list cut", []byte{0xc0, 0x01, 0x1e, 0x01, 0x39, 0xff, 0xff, 0xff, 0xff, 0x05, 0x00, 0x00, 0x00}, "0x1e01", 11, ErrDNP3ObjTruncated},
		{"write time", []byte{0xc0, 0x02, 0x32, 0x01, 0x07, 0x01, 1, 2, 3, 4, 5, 6}, "0x3201", 0, nil},
		{"write IIN restart bit", []byte{0xc0, 0x02, 0x50, 0x01, 0x00, 0x07, 0x07, 0x00}, "0x5001", 0, nil},
		{"huge count", []byte{0xc0, 0x81, 0x00, 0x00, 0x1e, 0x01, 0x09, 0xff, 0xff, 0xff, 0xff, 0x00}, "0x1e01", 8, ErrDNP3ObjTruncated},
		{"huge packed range", []byte{0xc0, 0x81, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00}, "0x0101", 12, ErrDNP3ObjTruncated},
		{"stop below start", []byte{0xc0, 0x81, 0x00, 0x00, 0x1e, 0x01, 0x00, 0x05, 0x04}, "0x1e01", 5, ErrDNP3BadRange},
		{"unknown object stops", []byte{0xc0, 0x81, 0x00, 0x00, 0x1e, 0x02, 0x00, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0xaa}, "0x1e02,0x00fe", 6, nil},
		{"reserved qualifier stops", []byte{0xc0, 0x81, 0x00, 0x00, 0x1e, 0x02, 0x0a, 0x00}, "0x1e02", 4, nil},
		{"octet string", []byte{0xc0, 0x81, 0x00, 0x00, 0x6e, 0x03, 0x00, 0x00, 0x01, 'a', 'b', 'c', 'd', 'e', 'f'}, "0x6e03", 0, nil},
		{"size prefixed free format", []byte{0xc0, 0x81, 0x00, 0x00, 0x46, 0x05, 0x5b, 0x02, 0x03, 0x00, 1, 2, 3, 0x01, 0x00, 9}, "0x4605", 0, nil},
		{"size prefix past data", []byte{0xc0, 0x81, 0x00, 0x00, 0x46, 0x05, 0x5b, 0x01, 0xff, 0xff, 1}, "0x4605", 7, ErrDNP3ObjTruncated},
		{"count zero", []byte{0xc0, 0x81, 0x00, 0x00, 0x1e, 0x01, 0x07, 0x00, 0x3c, 0x01, 0x06}, "0x1e01,0x3c01", 0, nil},
		{"free format no size", []byte{0xc0, 0x81, 0x00, 0x00, 0x1e, 0x01, 0x0b, 0x01, 0x00}, "0x1e01", 5, nil},
		{"response IIN cut", []byte{0xc0, 0x81, 0x00}, "", 0, ErrDNP3AppTooShort},
		{"header cut", []byte{0xc0}, "", 0, ErrDNP3AppTooShort},
	}

	// A header that fails is listed last, its State saying why.
	for _, tc := range tests {
		var d DNP3
		err := d.DecodeFromBytes(dnp3Master(0xc0, tc.app...), gopacket.NilDecodeFeedback)
		if !errors.Is(err, tc.err) {
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.err)
		}

		if d.Application == nil {
			t.Errorf("%s: no application", tc.name)
			continue
		}

		if got := dnp3ObjectList(d.Application); got != tc.objects || len(d.Application.Unparsed) != tc.unparsed {
			t.Errorf("%s: objects %q unparsed %x, want %q and %d bytes", tc.name, got, d.Application.Unparsed, tc.objects, tc.unparsed)
		}
	}
}

func TestDNP3ObjectValues(t *testing.T) {
	// Free format: two file objects of 3 and 1 bytes, sizes 2 bytes wide.
	var d DNP3
	app := []byte{0xc0, 0x81, 0x00, 0x00, 0x46, 0x05, 0x5b, 0x02, 0x03, 0x00, 1, 2, 3, 0x01, 0x00, 9}
	if err := d.DecodeFromBytes(dnp3Master(0xc0, app...), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}

	want := []DNP3Object{{Index: 0, Data: []byte{1, 2, 3}}, {Index: 1, Data: []byte{9}}}
	if got := d.Application.Objects[0].Objects; !reflect.DeepEqual(got, want) {
		t.Errorf("free format objects %+v, want %+v", got, want)
	}

	// Index list of a READ: indexes, no values.
	app = []byte{0xc0, 0x01, 0x1e, 0x01, 0x17, 0x02, 0x05, 0x09}
	if err := d.DecodeFromBytes(dnp3Master(0xc0, app...), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}

	want = []DNP3Object{{Index: 5, Data: []byte{}}, {Index: 9, Data: []byte{}}}
	if got := d.Application.Objects[0].Objects; !reflect.DeepEqual(got, want) {
		t.Errorf("index list %+v, want %+v", got, want)
	}

	// Double-bit inputs 2..6 packed two bits each: 01 10 11 00 | 01.
	app = []byte{0xc0, 0x81, 0x00, 0x00, 0x03, 0x01, 0x00, 0x02, 0x06, 0x39, 0x01}
	if err := d.DecodeFromBytes(dnp3Master(0xc0, app...), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}

	h := d.Application.Objects[0]
	for i, want := range []uint8{1, 2, 3, 0, 1} {
		if got := h.PackedValue(uint64(i)); got != want || h.BitsPerObject != 2 {
			t.Errorf("double-bit %d = %d, want %d", i, got, want)
		}
	}
}

func TestDNP3UDPAndParser(t *testing.T) {
	registerDNP3Decoders()
	registerDNP3Decoders() // idempotent

	frame := dnp3Master(0xc0, 0xc0, 0x01, 0x3c, 0x01, 0x06)
	buf := gopacket.NewSerializeBuffer()
	ip := &IPv4{Version: 4, TTL: 64, Protocol: IPProtocolUDP, SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}}
	udp := &UDP{SrcPort: 1234, DstPort: UDPPort(DNP3Port)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(frame)); err != nil {
		t.Fatal(err)
	}

	p := gopacket.NewPacket(buf.Bytes(), LayerTypeIPv4, gopacket.Default)
	checkLayers(p, []gopacket.LayerType{LayerTypeIPv4, LayerTypeUDP, LayerTypeDNP3}, t)

	// DecodingLayerParser over TCP.
	var (
		eth   Ethernet
		ip4   IPv4
		tcp   TCP
		dnp3  DNP3
		found []gopacket.LayerType
	)
	parser := gopacket.NewDecodingLayerParser(LayerTypeEthernet, &eth, &ip4, &tcp, &dnp3)
	if err := parser.DecodeLayers(testPacketDNP3Select, &found); err != nil {
		t.Fatal(err)
	}

	if len(found) != 4 || found[3] != LayerTypeDNP3 || dnp3.Application.Function != DNP3FuncSelect {
		t.Errorf("parser found %v", found)
	}
}

func TestDNP3Strings(t *testing.T) {
	tests := []struct {
		got, want string
	}{
		{DNP3LinkUnconfirmedData.String(), "Unconfirmed User Data"},
		{DNP3LinkStatus.String(), "Status of Link"},
		{DNP3LinkFunc(0x45).String(), "Unknown Primary(5)"},
		{DNP3LinkFunc(0x05).String(), "Unknown Secondary(5)"},
		{DNP3FuncDirectOperateNR.String(), "Direct Operate No Ack"},
		{DNP3AppFunc(200).String(), "Unknown(200)"},
		{(DNP3IINDeviceRestart | DNP3IINNeedTime | DNP3IINObjectUnknown).String(), "NeedTime|DeviceRestart|ObjectUnknown"},
		{DNP3GroupAnalogInput.String(), "Analog Input"},
		{DNP3Group(99).String(), "Group(99)"},
		{DNP3PrefixIndex2.String(), "2-Octet Index"},
		{DNP3PrefixSize4.String(), "4-Octet Object Size"},
		{DNP3PrefixCode(7).String(), "Reserved(7)"},
		{DNP3RangeCount2.String(), "2-Octet Count of Objects"},
		{DNP3RangeVirtual4.String(), "4-Octet Start/Stop Virtual Addresses"},
		{DNP3RangeCode(0xc).String(), "Reserved(12)"},
	}

	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}

	if !DNP3IIN(0x9002).Has(DNP3IINDeviceRestart) || DNP3IIN(0x9002).Has(DNP3IINLocalControl) {
		t.Error("DNP3IIN.Has")
	}

	if !DNP3Time([]byte{1}).IsZero() {
		t.Error("DNP3Time of a short slice is not zero")
	}
}

func FuzzDNP3(f *testing.F) {
	for _, frame := range testDNP3Frames() {
		f.Add(frame)
	}
	f.Add(dnp3Master(0xc0, 0xc0, 0x01, 0x3c, 0x02, 0x06, 0x3c, 0x03, 0x06, 0x3c, 0x04, 0x06, 0x3c, 0x01, 0x06))
	f.Add(dnp3Frame(0x44, 3, 4, []byte{0xc0, 0xc0, 0x81, 0x00, 0x00, 0x46, 0x05, 0x5b, 0x02, 0x03, 0x00, 1, 2, 3, 0x01, 0x00, 9}))
	f.Add(dnp3Frame(0x44, 3, 4, []byte{0xc0, 0xc0, 0x81, 0x00, 0x00, 0x03, 0x01, 0x00, 0x02, 0x06, 0x39, 0x01}))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, ds := decodeDNP3Packet(t, data)
		for _, d := range ds {
			dnp3CheckBounds(t, d)
		}

		var d DNP3
		if d.DecodeFromBytes(data, gopacket.NilDecodeFeedback) == nil {
			dnp3CheckBounds(t, &d)
		}
	})
}

// dnp3CheckBounds checks what a decode produced stays within its frame.
func dnp3CheckBounds(t *testing.T, d *DNP3) {
	if len(d.UserData) > int(d.Link.Length) || len(d.Contents) > len(d.UserData)+dnp3HeaderLen+dnp3CRCLen*16 {
		t.Fatalf("user data %d bytes, contents %d, link length %d", len(d.UserData), len(d.Contents), d.Link.Length)
	}

	if d.Application == nil {
		return
	}

	for _, h := range d.Application.Objects {
		if len(h.Objects) > len(d.UserData) || len(h.Data) > len(d.UserData) {
			t.Fatalf("header %+v larger than its %d byte frame", h, len(d.UserData))
		}
	}
}
