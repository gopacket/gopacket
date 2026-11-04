// Copyright 2018, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/gopacket/gopacket"
)

func TestDHCPv6EncodeRequest(t *testing.T) {
	dhcpv6 := &DHCPv6{MsgType: DHCPv6MsgTypeRequest, HopCount: 0, TransactionID: []byte{87, 25, 88}}

	client := &DHCPv6DUID{Type: DHCPv6DUIDTypeLLT, HardwareType: []byte{0, 1}, Time: []byte{28, 56, 38, 45}, LinkLayerAddress: []byte{8, 0, 39, 254, 143, 149}}
	dhcpv6.Options = append(dhcpv6.Options, NewDHCPv6Option(DHCPv6OptClientID, client.Encode()))

	server := &DHCPv6DUID{Type: DHCPv6DUIDTypeLLT, HardwareType: []byte{0, 1}, Time: []byte{28, 56, 37, 232}, LinkLayerAddress: []byte{8, 0, 39, 212, 16, 187}}
	dhcpv6.Options = append(dhcpv6.Options, NewDHCPv6Option(DHCPv6OptServerID, server.Encode()))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, dhcpv6)
	if err != nil {
		t.Fatal(err)
	}

	p2 := gopacket.NewPacket(buf.Bytes(), LayerTypeDHCPv6, testDecodeOptions)
	dhcpv62 := p2.Layer(LayerTypeDHCPv6).(*DHCPv6)
	testDHCPv6Equal(t, dhcpv6, dhcpv62)
}

func TestDHCPv6EncodeReply(t *testing.T) {
	dhcpv6 := &DHCPv6{MsgType: DHCPv6MsgTypeReply, HopCount: 0, TransactionID: []byte{87, 25, 88}}

	client := &DHCPv6DUID{Type: DHCPv6DUIDTypeLLT, HardwareType: []byte{0, 1}, Time: []byte{28, 56, 38, 45}, LinkLayerAddress: []byte{8, 0, 39, 254, 143, 149}}
	dhcpv6.Options = append(dhcpv6.Options, NewDHCPv6Option(DHCPv6OptClientID, client.Encode()))

	server := &DHCPv6DUID{Type: DHCPv6DUIDTypeLLT, HardwareType: []byte{0, 1}, Time: []byte{28, 56, 37, 232}, LinkLayerAddress: []byte{8, 0, 39, 212, 16, 187}}
	dhcpv6.Options = append(dhcpv6.Options, NewDHCPv6Option(DHCPv6OptServerID, server.Encode()))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, dhcpv6)
	if err != nil {
		t.Fatal(err)
	}

	p2 := gopacket.NewPacket(buf.Bytes(), LayerTypeDHCPv6, testDecodeOptions)
	dhcpv62 := p2.Layer(LayerTypeDHCPv6).(*DHCPv6)
	testDHCPv6Equal(t, dhcpv6, dhcpv62)
}

// TestDHCPv6DecodeMaxLengthOption: 4+Length used to be computed in uint16, so
// an option of 0xfffc..0xffff bytes (reachable in an IPv6 jumbogram) sliced
// data[4:0]..data[4:3] and panicked.
func TestDHCPv6DecodeMaxLengthOption(t *testing.T) {
	for _, length := range []int{0xfffb, 0xfffc, 0xffff} {
		msg := make([]byte, 8+length)
		msg[0] = byte(DHCPv6MsgTypeSolicit)
		msg[5] = byte(DHCPv6OptVendorClass)
		msg[6], msg[7] = byte(length>>8), byte(length)

		dhcpv6 := &DHCPv6{}
		if err := dhcpv6.DecodeFromBytes(msg, gopacket.NilDecodeFeedback); err != nil {
			t.Fatalf("length %#x: %v", length, err)
		}
		if len(dhcpv6.Options) != 1 || len(dhcpv6.Options[0].Data) != length {
			t.Errorf("length %#x: got options %d, want one with %d bytes of data", length, len(dhcpv6.Options), length)
		}

		if err := dhcpv6.DecodeFromBytes(msg[:len(msg)-1], gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("length %#x: expected an error for a truncated option", length)
		}
	}
}

// TestDHCPv6OptionOroString pins the ORO rendering and checks that it is
// linear: the list used to be built with string concatenation, which copied
// everything so far for each of the up to 32767 codes in the option.
func TestDHCPv6OptionOroString(t *testing.T) {
	for _, test := range []struct {
		data []byte
		want string
	}{
		{nil, "Option(Oro:[])"},
		{[]byte{0}, "Option(Oro:[])"},
		{[]byte{0, 3}, "Option(Oro:[IA_NA])"},
		{[]byte{0, 3, 0, 23, 0xff, 0xff, 0}, "Option(Oro:[IA_NA,DNSRecursiveNameServer,Unknown(65535)])"},
	} {
		got := NewDHCPv6Option(DHCPv6OptOro, test.data).String()
		if got != test.want {
			t.Errorf("ORO %v: expected %q, got %q", test.data, test.want, got)
		}
	}

	oro := NewDHCPv6Option(DHCPv6OptOro, bytes.Repeat([]byte{0xff, 0xff}, 4000))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	s := oro.String()
	runtime.ReadMemStats(&after)

	// the quadratic version allocated thousands of bytes per output byte;
	// the bound leaves room for the race detector's own allocations
	grew := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(len(s)) * 64; grew > limit {
		t.Fatalf("rendering %d bytes allocated %d bytes, limit %d", len(s), grew, limit)
	}
}

func testDHCPv6Equal(t *testing.T, d1, d2 *DHCPv6) {
	if d1.MsgType != d2.MsgType {
		t.Errorf("expected MsgType=%s, got %s", d1.MsgType, d2.MsgType)
	}
	if d1.HopCount != d2.HopCount {
		t.Errorf("expected HopCount=%d, got %d", d1.HopCount, d2.HopCount)
	}
	if !d1.LinkAddr.Equal(d2.LinkAddr) {
		t.Errorf("expected LinkAddr=%v, got %v", d1.LinkAddr, d2.LinkAddr)
	}
	if !d1.PeerAddr.Equal(d2.PeerAddr) {
		t.Errorf("expected PeerAddr=%v, got %v", d1.PeerAddr, d2.PeerAddr)
	}
	if !bytes.Equal(d1.TransactionID, d2.TransactionID) {
		t.Errorf("expected TransactionID=%v, got %v", d1.TransactionID, d2.TransactionID)
	}
	if len(d1.Options) != len(d2.Options) {
		t.Errorf("expected %d options, got %d", len(d1.Options), len(d2.Options))
	}

	for i, o := range d1.Options {
		testDHCPv6OptionEqual(t, i, o, d2.Options[i])
	}
}

func testDHCPv6OptionEqual(t *testing.T, idx int, d1, d2 DHCPv6Option) {
	if d1.Code != d2.Code {
		t.Errorf("expection Options[%d].Code = %s, got %s", idx, d1.Code, d2.Code)
	}
	if d1.Length != d2.Length {
		t.Errorf("expection Options[%d].Length = %d, got %d", idx, d1.Length, d2.Length)
	}
	if !bytes.Equal(d1.Data, d2.Data) {
		t.Errorf("expection Options[%d].Data to be = %v, got %v", idx, d1.Data, d2.Data)
	}
}

// TestDHCPv6DUIDRoundTrip decodes and re-encodes one DUID of each type and
// expects the wire bytes back, including the two bytes after the type of a
// DUID the decoder has no branch for (DUID-UUID).
func TestDHCPv6DUIDRoundTrip(t *testing.T) {
	for _, in := range [][]byte{
		{0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x26, 0x2d, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95},
		{0x00, 0x02, 0x00, 0x00, 0x00, 0x09, 0x0c, 0xc0, 0x84, 0xd3, 0x03, 0x00, 0x09, 0x12},
		{0x00, 0x03, 0x00, 0x01, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95},
		{0x00, 0x04, 0xaa, 0xaa, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab},
	} {
		duid := &DHCPv6DUID{}
		if err := duid.DecodeFromBytes(in); err != nil {
			t.Errorf("%x: %v", in, err)
			continue
		}
		if out := duid.Encode(); !bytes.Equal(out, in) {
			t.Errorf("%x re-encoded as %x", in, out)
		}
	}
}
