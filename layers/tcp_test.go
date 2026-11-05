// Copyright 2016, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

func TestTCPOptionKindString(t *testing.T) {
	testData := []struct {
		o *TCPOption
		s string
	}{
		{&TCPOption{
			OptionType:   TCPOptionKindNop,
			OptionLength: 1,
		},
			"TCPOption(NOP:)"},
		{&TCPOption{
			OptionType:   TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x12, 0x34},
		},
			"TCPOption(MSS:4660 0x1234)"},
		{&TCPOption{
			OptionType:   TCPOptionKindTimestamps,
			OptionLength: 10,
			OptionData:   []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01},
		},
			"TCPOption(Timestamps:2/1 0x0000000200000001)"},
		{&TCPOption{
			OptionType:   TCPOptionKindMultipathTCP,
			OptionLength: 4,
			OptionMPTCPMpCapable: &MPCapable{
				Version: 1,
			},
		},
			"MPTCPOption(MP_CAPABLE Version 1)"},
		// An MPTCP option whose subtype is set but whose per-subtype pointer
		// is not, as a hand-built option can be, must print the generic line
		// rather than dereference nil.
		{&TCPOption{
			OptionType:      TCPOptionKindMultipathTCP,
			OptionLength:    3,
			OptionMultipath: MPTCPSubtypeMPCAPABLE,
		},
			"TCPOption(MultipathTCP:)"},
		{&TCPOption{
			OptionType:      TCPOptionKindMultipathTCP,
			OptionLength:    8,
			OptionMultipath: MPTCPSubtypeMPJOIN,
		},
			"TCPOption(MultipathTCP:)"},
		{&TCPOption{
			OptionType:      TCPOptionKindMultipathTCP,
			OptionLength:    8,
			OptionMultipath: MPTCPSubtypeMPPRIO,
		},
			"TCPOption(MultipathTCP:)"},
		{&TCPOption{
			OptionType:      TCPOptionKindMultipathTCP,
			OptionLength:    8,
			OptionMultipath: MPTCPSubtypeADDADDR,
		},
			"TCPOption(MultipathTCP:)"},
		{&TCPOption{
			OptionType:      TCPOptionKindMultipathTCP,
			OptionLength:    3,
			OptionMultipath: MPTCPSubtypeREMOVEADDR,
		},
			"TCPOption(MultipathTCP:)"},
		{&TCPOption{
			OptionType:      TCPOptionKindMultipathTCP,
			OptionLength:    8,
			OptionMultipath: MPTCPSubtypeMPTCPRST,
		},
			"TCPOption(MultipathTCP:)"}}

	for _, tc := range testData {
		if s := tc.o.String(); s != tc.s {
			t.Errorf("expected %#v string to be %s, got %s", tc.o, tc.s, s)
		}
	}
}

func TestTCPSerializePadding(t *testing.T) {
	tcp := &TCP{}
	tcp.Options = append(tcp.Options, TCPOption{
		OptionType:   TCPOptionKindNop,
		OptionLength: 1,
	})
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, tcp)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf.Bytes())%4 != 0 {
		t.Errorf("TCP data of len %d not padding to 32 bit boundary", len(buf.Bytes()))
	}
}

// testPacketTCPOptionDecode is the packet:
//
//	16:17:26.239051 IP 192.168.0.1.12345 > 192.168.0.2.54321: Flags [S], seq 3735928559:3735928563, win 0, options [mss 8192,eol], length 4
//		0x0000:  0000 0000 0001 0000 0000 0001 0800 4500  ..............E.
//		0x0010:  0034 0000 0000 8006 b970 c0a8 0001 c0a8  .4.......p......
//		0x0020:  0002 3039 d431 dead beef 0000 0000 7002  ..09.1........p.
//		0x0030:  0000 829c 0000 0204 2000 0000 0000 5465  ..............Te
//		0x0040:  7374                                     st
var testPacketTCPOptionDecode = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x80, 0x06, 0xb9, 0x70, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8,
	0x00, 0x02, 0x30, 0x39, 0xd4, 0x31, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02,
	0x00, 0x00, 0x82, 0x9c, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x65,
	0x73, 0x74,
}

func TestPacketTCPOptionDecode(t *testing.T) {
	p := gopacket.NewPacket(testPacketTCPOptionDecode, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	tcp := p.Layer(LayerTypeTCP).(*TCP)
	if tcp == nil {
		t.Error("Expected TCP layer, but got none")
	}

	expected := []TCPOption{
		{
			OptionType:   TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{32, 00},
		},
		{
			OptionType:   TCPOptionKindEndList,
			OptionLength: 1,
		},
	}

	if !reflect.DeepEqual(expected, tcp.Options) {
		t.Errorf("expected options to be %#v, but got %#v", expected, tcp.Options)
	}
}

// testPacketMPTCPOptionDecode is the packet:
//
//	16:17:26.239051 IP 192.168.0.1.12345 > 192.168.0.2.54321: Flags [S], seq 3735928559:3735928563, win 0, options [mss 8192,mpcapable,eol], length 8
//		0x0000:  0000 0000 0001 0000  0000 0001 0800 4500  ..............E.
//		0x0010:  0038 0000 0000 8006  0000 c0a8 0001 c0a8  .8..............
//		0x0020:  0002 3039 d431 dead  beef 0000 0000 8002  ..09.1..........
//		0x0030:  0000 0000 0000 0204  2000 1e04 0100 0000  ........ .......
//		0x0040:  0000 5465 7374                            ..Test
var testPacketMPTCPOptionDecode = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x80, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8,
	0x00, 0x02, 0x30, 0x39, 0xD4, 0x31, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x1E, 0x04, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x54, 0x65, 0x73, 0x74,
}

func TestPacketMPTCPOptionDecode(t *testing.T) {
	p := gopacket.NewPacket(testPacketMPTCPOptionDecode, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode MPTCP packet:", p.ErrorLayer().Error())
	}
	tcp := p.Layer(LayerTypeTCP).(*TCP)
	if tcp == nil {
		t.Error("Expected TCP layer, but got none")
	}

	expected := []TCPOption{
		{
			OptionType:   TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{32, 00},
		},
		{
			OptionType:   TCPOptionKindMultipathTCP,
			OptionLength: 4,
			OptionData:   []byte{0x01, 0x00},
			OptionMPTCPMpCapable: &MPCapable{
				Version: 1,
			},
		},
		{
			OptionType:   TCPOptionKindEndList,
			OptionLength: 1,
		},
	}

	if !reflect.DeepEqual(expected, tcp.Options) {
		t.Errorf("expected options to be %#v, but got %#v", expected, tcp.Options)
	}
}

// testMPTCPInvalidLengthAndSubtype is the packet:
//
//	00:00:00.000000 IP 192.168.0.2.49220 > 192.68.0.3.443: Flags [A], seq 1, win=343, options [nop,unknown,mptls], length 0
//	        0x0000:  0800 0000 0000 0001 0001 0006 0011 2233   .............."3
//	        0x0010:  4455 ee33 4528 0034 c339 4000 2c06 0000   DU.3E(.4.9@.,...
//	        0x0020:  c0a8 0002 c0a8 0003 c044 01bb 41db 076a   .........D..A..j
//	        0x0030:  e385 9837 8010 0157 b67f 0000 0121 080a   ...7...W.....!..
//	        0x0040:  164b d4ca f81e 00a0                       .K......
var testMPTCPInvalidLengthAndSubtype = []byte{
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0x00, 0x11, 0x22, 0x33,
	0x44, 0x55, 0xee, 0x33, 0x45, 0x28, 0x00, 0x34, 0xc3, 0x39, 0x40, 0x00, 0x2c, 0x06, 0x00, 0x00,
	0xc0, 0xa8, 0x00, 0x02, 0xc0, 0xa8, 0x00, 0x03, 0xc0, 0x44, 0x01, 0xbb, 0x41, 0xdb, 0x07, 0x6a,
	0xe3, 0x85, 0x98, 0x37, 0x80, 0x10, 0x01, 0x57, 0xb6, 0x7f, 0x00, 0x00, 0x01, 0x21, 0x08, 0x0a,
	0x16, 0x4b, 0xd4, 0xca, 0xf8, 0x1e, 0x00, 0xa0,
}

func TestMPTCPInvalidLengthAndSubtype(t *testing.T) {
	t.Log("Starting packet decoding")
	p := gopacket.NewPacket(testMPTCPInvalidLengthAndSubtype, LinkTypeLinuxSLL2, gopacket.Default)

	// A receiver stops reading options at the zero length and keeps the
	// segment, so the layer decodes with the NOP and the unknown option
	// before it, and the MPTCP bytes left as Padding.
	if p.ErrorLayer() != nil {
		t.Fatalf("Failed to decode packet: %v", p.ErrorLayer().Error())
	}
	tcp := p.Layer(LayerTypeTCP).(*TCP)
	if len(tcp.Options) != 2 || tcp.Options[0].OptionType != TCPOptionKindNop || tcp.Options[1].OptionType != 0x21 {
		t.Errorf("expected NOP and kind 33 options, got %v", tcp.Options)
	}
	if !bytes.Equal(tcp.Padding, []byte{0x1e, 0x00, 0xa0}) {
		t.Errorf("expected the MPTCP bytes as padding, got %x", tcp.Padding)
	}
	// Stringifying the packet runs outside decode recovery and must not
	// panic.
	p.Dump()
}

// TestMPTCPOptionSerialize checks that a decoded segment with an MPTCP option
// serializes back to the bytes it was decoded from, both as is and with
// FixLengths, so that the sender's padding never ends up behind DataOffset.
func TestMPTCPOptionSerialize(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []byte
	}{
		{"MP_CAPABLE", []byte{30, 12, 0x00, 0x81, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}},
		{"MP_PRIO, nop, eol and padding", []byte{30, 3, 0x50, 1, 0, 0, 0, 0}},
		{"unknown subtype", []byte{30, 4, 0xf0, 0xaa}},
	} {
		seg := make([]byte, 20)
		seg[12] = byte((20+len(tc.options))/4) << 4
		seg = append(append(seg, tc.options...), "Test"...)
		for _, opts := range []gopacket.SerializeOptions{{}, {FixLengths: true}} {
			p := gopacket.NewPacket(seg, LayerTypeTCP, gopacket.Default)
			if p.ErrorLayer() != nil {
				t.Fatalf("%s: failed to decode packet: %v", tc.name, p.ErrorLayer().Error())
			}
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializePacket(buf, opts, p); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if !bytes.Equal(buf.Bytes(), seg) {
				t.Errorf("%s: %+v: expected %x, but got %x", tc.name, opts, seg, buf.Bytes())
			}
		}
	}
}

// TestTCPBadOptionLengthKeepsPayload checks that an option the decoder cannot
// follow (length byte missing, below the minimum, past the option area, or
// not what its MPTCP subtype allows) stops option parsing without failing
// the segment. A receiving host stops reading options there and still
// delivers the data, so both decode paths must hand the payload on, keep the
// options decoded before it and leave the rest of the option area in Padding.
func TestTCPBadOptionLengthKeepsPayload(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []byte
		kept    int // options decoded before the bad one
		padding int // offset of the first unparsed byte
	}{
		{"length 1", []byte{0xfd, 0x01, 0x01, 0x01}, 0, 0},
		{"length 0", []byte{0xfd, 0x00, 0x01, 0x01}, 0, 0},
		{"length past option area", []byte{0xfd, 0x08, 0x01, 0x01}, 0, 0},
		{"kind byte without length", []byte{0x01, 0x01, 0x01, 0xfd}, 3, 3},
		{"MPTCP length 0", []byte{0x1e, 0x00, 0x01, 0x01}, 0, 0},
		{"MPTCP length past option area", []byte{0x1e, 0x08, 0x01, 0x01}, 0, 0},
		{"MPTCP kind byte without subtype", []byte{0x01, 0x01, 0x1e, 0x03}, 2, 2},
		{"MP_CAPABLE bad length", []byte{0x1e, 0x03, 0x00, 0x01}, 0, 0},
		{"MP_JOIN bad length", []byte{0x1e, 0x04, 0x10, 0x00}, 0, 0},
		{"DSS bad length", []byte{0x1e, 0x05, 0x20, 0x00, 0x00, 0x01, 0x01, 0x01}, 0, 0},
		{"ADD_ADDR bad length", []byte{0x1e, 0x03, 0x30, 0x01}, 0, 0},
		{"REMOVE_ADDR bad length", []byte{0x1e, 0x03, 0x40, 0x01}, 0, 0},
		{"MP_PRIO bad length", []byte{0x1e, 0x05, 0x50, 0x01, 0x01, 0x01, 0x01, 0x01}, 0, 0},
		{"MP_FAIL bad length", []byte{0x1e, 0x03, 0x60, 0x01}, 0, 0},
		{"MP_FASTCLOSE bad length", []byte{0x1e, 0x03, 0x70, 0x01}, 0, 0},
		{"MP_TCPRST bad length", []byte{0x1e, 0x03, 0x80, 0x01}, 0, 0},
	} {
		seg := make([]byte, 20)
		seg[12] = byte((20+len(tc.options))/4) << 4
		seg = append(append(seg, tc.options...), "Test"...)

		p := gopacket.NewPacket(seg, LayerTypeTCP, gopacket.Default)
		if p.ErrorLayer() != nil {
			t.Errorf("%s: NewPacket: %v", tc.name, p.ErrorLayer().Error())
			continue
		}
		tcp := p.Layer(LayerTypeTCP).(*TCP)
		if string(tcp.Payload) != "Test" {
			t.Errorf("%s: payload %q, want %q", tc.name, tcp.Payload, "Test")
		}
		if len(tcp.Options) != tc.kept {
			t.Errorf("%s: kept %d options, want %d", tc.name, len(tcp.Options), tc.kept)
		}
		if !bytes.Equal(tcp.Padding, tc.options[tc.padding:]) {
			t.Errorf("%s: padding %x, want %x", tc.name, tcp.Padding, tc.options[tc.padding:])
		}
		// No case keeps an MPTCP option, so the flag must not survive the
		// dropped one.
		if tcp.Multipath {
			t.Errorf("%s: Multipath set with no MPTCP option kept", tc.name)
		}
		if p.ApplicationLayer() == nil || string(p.ApplicationLayer().Payload()) != "Test" {
			t.Errorf("%s: application layer %v, want payload %q", tc.name, p.ApplicationLayer(), "Test")
		}
		// Printing runs outside decode recovery: it must not panic.
		_ = p.String()

		var dlpTCP TCP
		var payload gopacket.Payload
		parser := gopacket.NewDecodingLayerParser(LayerTypeTCP, &dlpTCP, &payload)
		decoded := []gopacket.LayerType{}
		if err := parser.DecodeLayers(seg, &decoded); err != nil {
			t.Errorf("%s: DecodeLayers: %v", tc.name, err)
			continue
		}
		if len(decoded) != 2 || decoded[1] != gopacket.LayerTypePayload || string(payload) != "Test" {
			t.Errorf("%s: DecodeLayers decoded %v, payload %q", tc.name, decoded, payload)
		}
	}
}
