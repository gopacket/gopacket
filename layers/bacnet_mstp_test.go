// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"testing"

	"github.com/gopacket/gopacket"
)

// MS/TP frames of the public captures at kargs.net/captures, link type
// 165. The expectations are what tshark 4.7 shows for the same frames.
var bacnetMSTPVectors = []struct {
	name  string
	frame string
	want  string
}{
	{"mstp_20090227094623.cap #1", "55ff01691b000078",
		"Poll For Master 27>105 len=0 hdr=ok"},
	{"mstp_20090227094623.cap #3", "55ff050c00000f0101040203f10c0c02000002194c2921204b",
		"BACnet Data Expecting Reply 0>12 len=15 hdr=ok data=ok next=BACnetNPDU"},
	{"mstp_20091014112427.cap #1171", "55ff060a51001c220120037806ac10110abac0ff30850e0c02014ff11e29704e91004f1ff502",
		"BACnet Data Not Expecting Reply 81>10 len=28 hdr=ok data=ok next=BACnetNPDU"},
	{"mstp_20091014112427.cap #1375", "55ff020f51000062",
		"Reply To Poll For Master 81>15 len=0 hdr=ok"},
	{"mstp_20091014112427.cap #1446", "55ff070a51000051",
		"Reply Postponed 81>10 len=0 hdr=ok"},
	{"mstp_wtap.cap #310", "55ff06000a001fe0010030db0e0c00c000161e29554e91004f29674e91004f296f4e8204004f1f6647",
		"BACnet Data Not Expecting Reply 10>0 len=31 hdr=ok data=ok next=BACnetNPDU"},
	// Line noise: tshark flags both CRCs bad and stops there.
	{"mstp_20091014112427.cap #3810", "55ff80d5ff000feb0120037806ac10110abac0ff30410e8b8e",
		"Unknown(128) 255>213 len=15 hdr=bad data=bad vendor=288"},
	{"MSTP_Malformed_Packets.pcap #1494", "55ff000606000015",
		"Token 6>6 len=0 hdr=bad"},
	// The header CRC of Annex G.1 and, as data, the octets of Annex G.2.
	{"Annex G token", "55ff00100500008c",
		"Token 5>16 len=0 hdr=ok"},
	{"Annex G data", "55ff0310050003" + "04" + "012230" + "10bd",
		"Test_Request 5>16 len=3 hdr=ok data=ok"},
	// The optional pad after a frame is not part of it.
	{"padded", "55ff00100500008cff", "Token 5>16 len=0 hdr=ok"},
}

// bacnetMSTPSummary renders the fields of a frame on one line.
func bacnetMSTPSummary(m *BACnetMSTP) string {
	flag := func(ok bool) string {
		if ok {
			return "ok"
		}
		return "bad"
	}

	s := fmt.Sprintf("%v %d>%d len=%d hdr=%s", m.FrameType, m.Source, m.Destination, m.Length, flag(m.HeaderCRCValid))
	if m.Length > 0 {
		s += " data=" + flag(m.DataCRCValid)
	}
	if m.FrameType.Proprietary() {
		s += fmt.Sprintf(" vendor=%d", m.VendorID)
	}
	if next := m.NextLayerType(); next != gopacket.LayerTypeZero {
		s += fmt.Sprintf(" next=%v", next)
	}
	return s
}

func TestBACnetMSTP(t *testing.T) {
	for _, tt := range bacnetMSTPVectors {
		var m BACnetMSTP
		if err := m.DecodeFromBytes(mustHex(t, tt.frame), gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if got := bacnetMSTPSummary(&m); got != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", tt.name, got, tt.want)
		}
	}

	// Data and CRC of a data frame: the CRC-16 is sent low octet first.
	var m BACnetMSTP
	if err := m.DecodeFromBytes(mustHex(t, bacnetMSTPVectors[1].frame), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if m.DataCRC != 0x4B20 || m.HeaderCRC != 0x01 || !bytes.Equal(m.Data, mustHex(t, "01040203f10c0c02000002194c2921")) {
		t.Errorf("data %x crc %#x header crc %#x", m.Data, m.DataCRC, m.HeaderCRC)
	}
	if !bytes.Equal(m.Payload, m.Data) || len(m.Contents) != bacnetMSTPHeaderLen || m.Broadcast() {
		t.Errorf("payload %x contents %x", m.Payload, m.Contents)
	}

	bad := []struct {
		frame string
		want  error
	}{
		{"", ErrBACnetTruncated},
		{"55ff0010050000", ErrBACnetTruncated},
		{"55fe00100500008c", ErrBACnetMalformed},
		{"54ff00100500008c", ErrBACnetMalformed},
		// 15 octets of data announced, 14 and the CRC present.
		{"55ff050c00000f0101040203f10c0c02000002194c29204b", ErrBACnetTruncated},
		// A length that lies: 46528 octets (mstp_20091014112427.cap #5222).
		{"55ff0051afb5c00f0120037806ac10562abac0ff306d0c", ErrBACnetTruncated},
		// An extended frame too short for its encoded CRC-32K.
		{"55ff20100500028c" + "00000000", ErrBACnetMalformed},
	}
	for _, tt := range bad {
		if err := m.DecodeFromBytes(mustHex(t, tt.frame), gopacket.NilDecodeFeedback); err != tt.want {
			t.Errorf("%s: got %v, want %v", tt.frame, err, tt.want)
		}
	}
}

// TestBACnetMSTPStack decodes a capture frame from the link type down,
// which only works once the BACnet decoders are registered.
func TestBACnetMSTPStack(t *testing.T) {
	registerBACnetDecoders()

	p := gopacket.NewPacket(mustHex(t, bacnetMSTPVectors[1].frame), LinkTypeBACnetMSTP, gopacket.Default)
	if e := p.ErrorLayer(); e != nil {
		t.Fatal(e.Error())
	}
	var got []string
	for _, l := range p.Layers() {
		got = append(got, l.LayerType().String())
	}
	if want := "[BACnetMSTP BACnetNPDU BACnetAPDU]"; fmt.Sprint(got) != want {
		t.Fatalf("layers %v, want %s", got, want)
	}

	a := p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU)
	if got, want := bacnetValuesText(a), "object-identifier=device,2 property-identifier=object-list property-array-index=33"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if LinkTypeBACnetMSTP.String() != "BACnetMSTP" || LinkTypeBACnetMSTP.LayerType() != LayerTypeBACnetMSTP {
		t.Errorf("link type %v, layer type %v", LinkTypeBACnetMSTP, LinkTypeBACnetMSTP.LayerType())
	}

	// A data frame with a wrong CRC stops at the MS/TP layer.
	frame := mustHex(t, bacnetMSTPVectors[1].frame)
	frame[len(frame)-1] ^= 0x01
	p = gopacket.NewPacket(frame, LinkTypeBACnetMSTP, gopacket.Default)
	m, ok := p.Layer(LayerTypeBACnetMSTP).(*BACnetMSTP)
	if !ok || m.DataCRCValid || len(m.Data) != 15 || len(p.Layers()) != 1 || p.ErrorLayer() != nil {
		t.Errorf("corrupt frame: %v", p)
	}
}

// bacnetCOBSEncode is the encoder of Clause 9.10.3, written for the tests
// from the description of the encoding, not from the decoder.
func bacnetCOBSEncode(data []byte) []byte {
	const mask = 0x55

	out := []byte{0}
	code := 0 // index of the code octet of the block being built
	for _, b := range data {
		if b != 0 {
			out = append(out, b)
		}
		if b == 0 || len(out)-code == 0xFF {
			out[code] = uint8(len(out) - code)
			if b != 0 {
				// A full block: no zero is implied after it.
				out[code] = 0xFF
			}
			code = len(out)
			out = append(out, 0)
		}
	}
	out[code] = uint8(len(out) - code)

	// A full block that ends the data needs no empty block after it.
	if len(data) > 0 && data[len(data)-1] != 0 && out[code] == 1 && code > 0 && out[code-0xFF] == 0xFF {
		out = out[:code]
	}
	for i := range out {
		out[i] ^= mask
	}
	return out
}

// bacnetExtendedFrame builds an extended MS/TP frame around npdu.
func bacnetExtendedFrame(frameType BACnetMSTPFrameType, npdu []byte) []byte {
	encoded := bacnetCOBSEncode(npdu)

	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], crc32.Checksum(encoded, crc32.MakeTable(crc32.Koopman)))
	body := append(encoded, bacnetCOBSEncode(crc[:])...)

	frame := []byte{0x55, 0xFF, uint8(frameType), 0x10, 0x05, 0, 0}
	binary.BigEndian.PutUint16(frame[5:], uint16(len(body)-2))
	frame = append(frame, bacnetCRC8(frame[2:]))
	return append(frame, body...)
}

// TestBACnetMSTPExtended decodes COBS encoded frames built from Clause
// 9.10: data with zeros, with preamble octets, and longer than one block.
func TestBACnetMSTPExtended(t *testing.T) {
	// A Who-Is, global broadcast.
	whoIs := mustHex(t, "0120ffff00ff1008")
	long := append([]byte{0x01, 0x00, 0x10, 0x04, 0x09, 0x07, 0x19, 0x01, 0x2E, 0x65, 0xFE, 0x02, 0x58}, bytes.Repeat([]byte{0x55}, 600)...)
	long = append(long, 0x2F)

	inputs := [][]byte{
		whoIs,
		{0x00},
		{0x00, 0x00, 0x55, 0x00},
		{0x55, 0xFF, 0x55, 0xFF},
		bytes.Repeat([]byte{0xAA}, 253),
		bytes.Repeat([]byte{0xAA}, 254),
		bytes.Repeat([]byte{0xAA}, 255),
		append(bytes.Repeat([]byte{0xAA}, 254), 0x00),
		bytes.Repeat([]byte{0x00}, 300),
		long,
	}
	for i, data := range inputs {
		frame := bacnetExtendedFrame(BACnetMSTPExtendedDataNoReply, data)
		if bytes.Contains(frame[bacnetMSTPHeaderLen:], []byte{0x55}) {
			t.Fatalf("input %d: encoder left a preamble octet in the frame", i)
		}

		var m BACnetMSTP
		if err := m.DecodeFromBytes(frame, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("input %d: %v", i, err)
			continue
		}
		if !bytes.Equal(m.Data, data) || !m.HeaderCRCValid || !m.DataCRCValid || !m.FrameType.Extended() {
			t.Errorf("input %d: data %x, header %v, data crc %v", i, m.Data, m.HeaderCRCValid, m.DataCRCValid)
		}
		if int(m.Length) != len(frame)-bacnetMSTPHeaderLen-2 || len(m.Contents) != bacnetMSTPHeaderLen {
			t.Errorf("input %d: length %d of %d, contents %d", i, m.Length, len(frame), len(m.Contents))
		}

		// One flipped bit anywhere in the body is caught by the CRC-32K.
		for _, at := range []int{bacnetMSTPHeaderLen, bacnetMSTPHeaderLen + (len(frame)-bacnetMSTPHeaderLen)/2, len(frame) - 1} {
			bad := append([]byte(nil), frame...)
			bad[at] ^= 0x04
			if err := m.DecodeFromBytes(bad, gopacket.NilDecodeFeedback); err == nil && m.DataCRCValid {
				t.Errorf("input %d: flipped bit at %d not caught", i, at)
			}
			if m.NextLayerType() != gopacket.LayerTypeZero {
				t.Errorf("input %d: corrupt frame handed on", i)
			}
		}
	}

	// The whole stack: MS/TP, NPDU, APDU.
	registerBACnetDecoders()
	p := gopacket.NewPacket(bacnetExtendedFrame(BACnetMSTPExtendedDataNoReply, whoIs), LinkTypeBACnetMSTP, gopacket.Default)
	a, ok := p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU)
	if !ok || a.UnconfirmedService != BACnetUnconfirmedServiceWhoIs {
		t.Fatalf("extended Who-Is: %v", p)
	}
	p = gopacket.NewPacket(bacnetExtendedFrame(BACnetMSTPExtendedDataExpectingReply, long), LinkTypeBACnetMSTP, gopacket.Default)
	a, ok = p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU)
	if !ok || a.UnconfirmedService != BACnetUnconfirmedServiceUnconfirmedPrivateTransfer || len(a.Tags) != 5 {
		t.Fatalf("extended private transfer: %v", p.ErrorLayer())
	}

	// IPv6 over MS/TP is COBS decoded, and not BACnet.
	var m BACnetMSTP
	if err := m.DecodeFromBytes(bacnetExtendedFrame(BACnetMSTPIPv6Encapsulation, whoIs), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Data, whoIs) || !m.DataCRCValid || m.NextLayerType() != gopacket.LayerTypeZero {
		t.Errorf("IPv6 encapsulation: %x %v %v", m.Data, m.DataCRCValid, m.NextLayerType())
	}
}

// TestBACnetMSTPCRC checks the three CRCs against independent values.
func TestBACnetMSTPCRC(t *testing.T) {
	// Annex G.1 and G.2: the worked examples of the standard.
	if got := bacnetCRC8([]byte{0x00, 0x10, 0x05, 0x00, 0x00}); got != 0x8C {
		t.Errorf("header CRC %#x", got)
	}
	if got := bacnetCRC16([]byte{0x01, 0x22, 0x30}); got != 0xBD10 {
		t.Errorf("data CRC %#x", got)
	}

	// CRC-32K against the table driven implementation of hash/crc32.
	table := crc32.MakeTable(crc32.Koopman)
	for _, s := range []string{"", "\x00", "123456789", string(bytes.Repeat([]byte{0xFF, 0x55}, 700))} {
		if got, want := bacnetCRC32K([]byte(s)), crc32.Checksum([]byte(s), table); got != want {
			t.Errorf("CRC-32K of %d octets: %#x, want %#x", len(s), got, want)
		}
	}
}

// TestBACnetMSTPTruncation cuts every vector at every offset and lies in
// every octet. Nothing may panic, and decoding costs no more memory than
// the frame is long.
func TestBACnetMSTPTruncation(t *testing.T) {
	var frames [][]byte
	for _, tt := range bacnetMSTPVectors {
		frames = append(frames, mustHex(t, tt.frame))
	}
	frames = append(frames,
		bacnetExtendedFrame(BACnetMSTPExtendedDataNoReply, mustHex(t, "0120ffff00ff1008")),
		bacnetExtendedFrame(BACnetMSTPExtendedDataExpectingReply, bytes.Repeat([]byte{0x00, 0xAA}, 140)),
	)
	lies := []byte{0x00, 0x01, 0x20, 0x21, 0x54, 0x55, 0x56, 0xAA, 0xAB, 0xFE, 0xFF}

	for _, frame := range frames {
		for i := 0; i <= len(frame); i++ {
			decodeBACnetMSTPAll(frame[:i:i])
		}

		buf := make([]byte, len(frame))
		for i := range frame {
			for _, lie := range lies {
				copy(buf, frame)
				buf[i] = lie
				decodeBACnetMSTPAll(buf)
			}
		}

		var m BACnetMSTP
		allocs := testing.AllocsPerRun(4, func() {
			_ = m.DecodeFromBytes(frame, gopacket.NilDecodeFeedback)
		})
		if allocs > 1 {
			t.Errorf("%d allocations for a frame of %d octets", int(allocs), len(frame))
		}
		if len(m.Data) > len(frame) {
			t.Errorf("%d octets of data from a frame of %d", len(m.Data), len(frame))
		}
	}
}

// decodeBACnetMSTPAll decodes data from the MS/TP layer down and touches
// what a caller could.
func decodeBACnetMSTPAll(data []byte) {
	p := gopacket.NewPacket(data, LayerTypeBACnetMSTP, gopacket.Default)
	for _, l := range p.Layers() {
		_ = fmt.Sprint(l)
	}
	if m, ok := p.Layer(LayerTypeBACnetMSTP).(*BACnetMSTP); ok {
		_ = fmt.Sprint(m.FrameType, m.FrameType.Extended(), m.FrameType.Proprietary(), m.Broadcast())
	}
	if a, ok := p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU); ok {
		bacnetTouchValues(a.Values())
	}
}
