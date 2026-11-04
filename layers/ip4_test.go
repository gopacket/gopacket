// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// This file tests some of the functionality provided in the ip4.go

package layers

import (
	"bytes"
	"encoding/hex"
	"net"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// Test the function getIPv4OptionSize when the ipv4 has no options
func TestGetIPOptLengthNoOpt(t *testing.T) {
	ip := IPv4{}
	length := ip.getIPv4OptionSize()
	if length != 0 {
		t.Fatalf("Empty option list should have 0 length.  Actual %d", length)
	}
}

// Test the function getIPv4OptionSize when the ipv4 has end of list option
func TestGetIPOptLengthEndOfList(t *testing.T) {
	ip := IPv4{}
	ip.Options = append(ip.Options, IPv4Option{OptionType: 0, OptionLength: 1})
	length := ip.getIPv4OptionSize()
	if length != 4 {
		t.Fatalf("After padding, the list should have 4 length.  Actual %d", length)
	}
}

// Test the function getIPv4OptionSize when the ipv4 has padding and end of list option
func TestGetIPOptLengthPaddingEndOfList(t *testing.T) {
	ip := IPv4{}
	ip.Options = append(ip.Options, IPv4Option{OptionType: 1, OptionLength: 1})
	ip.Options = append(ip.Options, IPv4Option{OptionType: 0, OptionLength: 1})
	length := ip.getIPv4OptionSize()
	if length != 4 {
		t.Fatalf("After padding, the list should have 4 length.  Actual %d", length)
	}
}

// Test the function getIPv4OptionSize when the ipv4 has some non-trivial option and end of list option
func TestGetIPOptLengthOptionEndOfList(t *testing.T) {
	ip := IPv4{}
	someByte := make([]byte, 8)
	ip.Options = append(ip.Options, IPv4Option{OptionType: 2, OptionLength: 10, OptionData: someByte})
	ip.Options = append(ip.Options, IPv4Option{OptionType: 0, OptionLength: 1})
	length := ip.getIPv4OptionSize()
	if length != 12 {
		t.Fatalf("The list should have 12 length.  Actual %d", length)
	}
}

// Tests that the Options slice is properly reset before parsing new data
func TestIPOptResetDuringDecoding(t *testing.T) {
	ip := &IPv4{
		Options: []IPv4Option{{OptionType: 42, OptionLength: 4, OptionData: make([]byte, 2)}},
	}

	ipWithoutOptions := &IPv4{
		SrcIP:    net.IPv4(192, 168, 1, 1),
		DstIP:    net.IPv4(192, 168, 1, 1),
		Protocol: IPProtocolTCP,
	}

	ipBytes, err := serialize(ipWithoutOptions)

	if err != nil {
		t.Fatalf("Failed to serialize ip layer: %v", err)
	}

	err = ip.DecodeFromBytes(ipBytes, gopacket.NilDecodeFeedback)

	if err != nil {
		t.Fatalf("Failed to deserialize ip layer: %v", err)
	}

	if len(ip.Options) > 0 {
		t.Fatalf("Options slice has stale data from previous packet")
	}

}

func serialize(ip *IPv4) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	})
	return buffer.Bytes(), err
}

func TestIPv4InvalidOptionLength(t *testing.T) {
	// ip4 Packet with option 136 length set to zero
	b, err := hex.DecodeString("460000705f5b0000ff114e02af2db00295ab7e0f88001234")
	if err != nil {
		t.Fatalf("Failed to Decode header: %v", err)
	}
	var ip4 IPv4
	err = ip4.DecodeFromBytes(b, gopacket.NilDecodeFeedback)
	if err == nil {
		t.Fatal("Expected 'invalid IP option length' error, but got none.")
	}
}

// An option of length 2 is the type and length bytes with no data. RFC 791
// allows it and Linux delivers such packets, so the decoder must accept it.
func TestIPv4EmptyOption(t *testing.T) {
	// IHL 6, options: type 30 length 2, NOP, NOP
	b, err := hex.DecodeString("460000180000400040061cdb7f0000017f0000011e020101")
	if err != nil {
		t.Fatal(err)
	}
	var ip4 IPv4
	if err := ip4.DecodeFromBytes(b, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("Failed to decode option of length 2: %v", err)
	}
	if len(ip4.Options) != 3 || ip4.Options[0].OptionType != 30 || ip4.Options[0].OptionLength != 2 || len(ip4.Options[0].OptionData) != 0 {
		t.Fatalf("Unexpected options: %v", ip4.Options)
	}
}

func TestIPv4SerializeShortOptionLength(t *testing.T) {
	ip := &IPv4{
		SrcIP:   make([]byte, 4),
		DstIP:   make([]byte, 4),
		Options: []IPv4Option{{OptionType: 2, OptionLength: 1}},
	}
	if _, err := serialize(ip); err == nil {
		t.Fatal("Expected an error for an option length below 2, but got none.")
	}
}

func TestIPv4Options(t *testing.T) {
	for _, test := range []struct {
		packet  string
		options []IPv4Option
		padding []byte
	}{
		{
			packet: "4800002803040000fe01c1e0af2db00095ab7e0b820b00000000000000000000",
			options: []IPv4Option{
				{
					OptionType:   130,
					OptionData:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0},
					OptionLength: 11,
				},
				{
					OptionType:   0,
					OptionLength: 1,
				},
			},
		},
		{
			packet: "4900002803040000fe01c1e0af2db00095ab7e0b01820b00000000000000000000010203",
			options: []IPv4Option{
				{
					OptionType:   1,
					OptionLength: 1,
				},
				{
					OptionType:   130,
					OptionData:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0},
					OptionLength: 11,
				},
				{
					OptionType:   0,
					OptionLength: 1,
				},
			},
			padding: []byte{1, 2, 3},
		},
		{
			packet: "4800002803040000fe01c1e0af2db00095ab7e0b820c00000000000000000000",
			options: []IPv4Option{
				{
					OptionType:   130,
					OptionData:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					OptionLength: 12,
				},
			},
		},
		{
			packet: "4900002803040000fe01c1e0af2db00095ab7e0b00820b00000000000000000000010203",
			options: []IPv4Option{
				{
					OptionType:   0,
					OptionLength: 1,
				},
			},
			padding: []byte{0x82, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3},
		},
		{
			packet: "4800002803040000fe01c1e0af2db00095ab7e0b070704000000000100000000",
			options: []IPv4Option{
				{
					OptionType:   7,
					OptionLength: 7,
					OptionData:   []byte{4, 0, 0, 0, 0},
				},
				{
					OptionType:   1,
					OptionLength: 1,
				},
				{
					OptionType:   0,
					OptionLength: 1,
				},
			},
			padding: []byte{0, 0, 0},
		},
	} {
		t.Run(test.packet, func(t *testing.T) {
			var ip4 IPv4 // reuse ip4 to test reset
			b, err := hex.DecodeString(test.packet)
			if err != nil {
				t.Fatalf("Failed to Decode header: %v", err)
			}
			err = ip4.DecodeFromBytes(b, gopacket.NilDecodeFeedback)
			if err != nil {
				t.Fatal("Unexpected error during decoding:", err)
			}
			if !reflect.DeepEqual(ip4.Options, test.options) {
				t.Fatalf("Options mismatch.\nGot:\n%#v\nExpected:\n%#v\n", ip4.Options, test.options)
			}
			if !bytes.Equal(ip4.Padding, test.padding) {
				t.Fatalf("Padding mismatch.\nGot:\n%#v\nExpected:\n%#v\n", ip4.Padding, test.padding)
			}
		})
	}
}

// TestIPv4ZeroLengthUsesDataLength decodes a TSO packet (total length 0)
// whose IP part is longer than the 16-bit Length field can hold.
func TestIPv4ZeroLengthUsesDataLength(t *testing.T) {
	for _, payloadLen := range []int{65495, 65496, 65536, 65541, 131077} {
		data := []byte{0x45, 0, 0, 0, 0, 1, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
			0x9c, 0x40, 0x9c, 0x41, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0}
		data = append(data, make([]byte, payloadLen)...)
		p := gopacket.NewPacket(data, LayerTypeIPv4, gopacket.Default)
		if p.ErrorLayer() != nil {
			t.Errorf("%d payload bytes: %v", payloadLen, p.ErrorLayer().Error())
			continue
		}
		if p.Metadata().Truncated {
			t.Errorf("%d payload bytes: marked truncated", payloadLen)
		}
		tcp, ok := p.Layer(LayerTypeTCP).(*TCP)
		if !ok {
			t.Errorf("%d payload bytes: no TCP layer", payloadLen)
			continue
		}
		if len(tcp.Payload) != payloadLen {
			t.Errorf("%d payload bytes: TCP payload has %d", payloadLen, len(tcp.Payload))
		}
		if ip := p.Layer(LayerTypeIPv4).(*IPv4); int(ip.Length) != min(len(data), 65535) {
			t.Errorf("%d payload bytes: Length %d", payloadLen, ip.Length)
		}
	}
}
