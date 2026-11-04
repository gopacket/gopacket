// Copyright 2014, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
)

const (
	ipv4UDPChecksum                = uint16(0xbc5f) // Wireshark
	ipv6UDPChecksumWithIPv6DstOpts = uint16(0x4d21) // Wireshark
	ipv6UDPChecksumJumbogram       = uint16(0xcda8)
)

func createIPv4ChecksumTestLayer() (ip4 *IPv4) {
	ip4 = &IPv4{}
	ip4.Version = 4
	ip4.TTL = 64
	ip4.SrcIP = net.ParseIP("192.0.2.1")
	ip4.DstIP = net.ParseIP("198.51.100.1")
	return
}

func createIPv6ChecksumTestLayer() (ip6 *IPv6) {
	ip6 = &IPv6{}
	ip6.Version = 6
	ip6.NextHeader = IPProtocolNoNextHeader
	ip6.HopLimit = 64
	ip6.SrcIP = net.ParseIP("2001:db8::1")
	ip6.DstIP = net.ParseIP("2001:db8::2")
	return
}

func createIPv6DestinationChecksumTestLayer() (dst *IPv6Destination) {
	tlv := &IPv6DestinationOption{}
	tlv.OptionType = 0x01 //PadN
	tlv.OptionData = []byte{0x00, 0x00, 0x00, 0x00}
	dst = &IPv6Destination{}
	dst.Options = append(dst.Options, tlv)
	dst.NextHeader = IPProtocolNoNextHeader
	return
}

func createUDPChecksumTestLayer() (udp *UDP) {
	udp = &UDP{}
	udp.SrcPort = UDPPort(12345)
	udp.DstPort = UDPPort(9999)
	return
}

func TestIPv4UDPChecksum(t *testing.T) {
	var serialize = make([]gopacket.SerializableLayer, 0, 2)
	var u *UDP
	var err error

	ip4 := createIPv4ChecksumTestLayer()
	ip4.Protocol = IPProtocolUDP
	serialize = append(serialize, ip4)

	udp := createUDPChecksumTestLayer()
	udp.SetNetworkLayerForChecksum(ip4)
	serialize = append(serialize, udp)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		t.Fatal(err)
	}

	p := gopacket.NewPacket(buf.Bytes(), LinkTypeRaw, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeIPv4, LayerTypeUDP}, t)

	if l, ok := p.Layer(LayerTypeUDP).(*UDP); !ok {
		t.Fatal("No UDP layer type found in packet")
	} else {
		u = l
	}
	got := u.Checksum
	want := ipv4UDPChecksum
	if got != want {
		t.Errorf("Bad checksum:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
	}
}

func TestIPv6UDPChecksumWithIPv6DstOpts(t *testing.T) {
	var serialize = make([]gopacket.SerializableLayer, 0, 3)
	var u *UDP
	var err error

	ip6 := createIPv6ChecksumTestLayer()
	ip6.NextHeader = IPProtocolIPv6Destination
	serialize = append(serialize, ip6)

	dst := createIPv6DestinationChecksumTestLayer()
	dst.NextHeader = IPProtocolUDP
	serialize = append(serialize, dst)

	udp := createUDPChecksumTestLayer()
	udp.SetNetworkLayerForChecksum(ip6)
	serialize = append(serialize, udp)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		t.Fatal(err)
	}

	p := gopacket.NewPacket(buf.Bytes(), LinkTypeRaw, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeIPv6, LayerTypeIPv6Destination, LayerTypeUDP}, t)

	if l, ok := p.Layer(LayerTypeUDP).(*UDP); !ok {
		t.Fatal("No UDP layer type found in packet")
	} else {
		u = l
	}
	got := u.Checksum
	want := ipv6UDPChecksumWithIPv6DstOpts
	if got != want {
		t.Errorf("Bad checksum:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
	}
}

func TestIPv6JumbogramUDPChecksum(t *testing.T) {
	var serialize = make([]gopacket.SerializableLayer, 0, 4)
	var u *UDP
	var err error

	ip6 := &IPv6{}
	ip6.Version = 6
	ip6.NextHeader = IPProtocolUDP
	ip6.HopLimit = 64
	ip6.SrcIP = net.ParseIP("2001:db8::1")
	ip6.DstIP = net.ParseIP("2001:db8::2")
	serialize = append(serialize, ip6)

	udp := &UDP{}
	udp.SrcPort = UDPPort(12345)
	udp.DstPort = UDPPort(9999)
	udp.SetNetworkLayerForChecksum(ip6)
	serialize = append(serialize, udp)

	payload := make([]byte, ipv6MaxPayloadLength+1)
	for i := range payload {
		payload[i] = 0xfe
	}
	serialize = append(serialize, gopacket.Payload(payload))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		t.Fatal(err)
	}

	p := gopacket.NewPacket(buf.Bytes(), LinkTypeRaw, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeIPv6, LayerTypeIPv6HopByHop, LayerTypeUDP, gopacket.LayerTypePayload}, t)

	if l, ok := p.Layer(LayerTypeUDP).(*UDP); !ok {
		t.Fatal("No UDP layer type found in packet")
	} else {
		u = l
	}
	got := u.Checksum
	want := ipv6UDPChecksumJumbogram
	if got != want {
		t.Errorf("Bad checksum:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
	}
}

// TestIPv6LargeJumbogramUDPChecksum serializes a UDP jumbogram of more than
// 128 KiB, where the checksum sum overflows 32 bits.
func TestIPv6LargeJumbogramUDPChecksum(t *testing.T) {
	ip6 := &IPv6{Version: 6, NextHeader: IPProtocolUDP, HopLimit: 64,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	udp := &UDP{SrcPort: 40000, DstPort: 40001}
	udp.SetNetworkLayerForChecksum(ip6)
	payload := make([]byte, 131200)
	for i := range payload {
		payload[i] = 0xff
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip6, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	if udp.Checksum != 0x6b6d {
		t.Errorf("checksum %#x, want 0x6b6d", udp.Checksum)
	}

	p := gopacket.NewPacket(buf.Bytes(), LayerTypeIPv6, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer().Error())
	}
	p.Layer(LayerTypeUDP).(*UDP).SetNetworkLayerForChecksum(p.NetworkLayer())
	if err, mismatches := p.VerifyChecksums(); err != nil || len(mismatches) != 0 {
		t.Errorf("verify: err %v, mismatches %v", err, mismatches)
	}
}

// TestVerifyChecksumAllOnes checks every VerifyChecksum with a packet whose
// computed checksum is 0x0000: a field of 0xffff is then equally valid
// (RFC 1071), 0x1234 is not.
func TestVerifyChecksumAllOnes(t *testing.T) {
	ip4 := createIPv4ChecksumTestLayer()
	ip6 := createIPv6ChecksumTestLayer()
	decode := func(l gopacket.DecodingLayer, data []byte) {
		if err := l.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Fatalf("%T: %v", l, err)
		}
	}
	cases := []struct {
		layer   gopacket.LayerWithChecksum
		data    []byte
		free    int // offset of a 16-bit word the sender may choose
		csum    int // offset of the checksum field
		prepare func()
	}{
		{&IPv4{}, []byte{0x45, 0, 0, 0x2a, 0, 0, 0, 0, 0x40, 0x11, 0, 0, 0xcb, 0, 0x71, 0x42, 0xc0, 0, 2, 1}, 4, 10, nil},
		{&TCP{}, []byte{0x9c, 0x40, 0x9c, 0x41, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0, 0, 0}, 20, 16, nil},
		{&UDP{}, []byte{0x9c, 0x40, 0x9c, 0x41, 0, 10, 0, 0, 0, 0}, 8, 6, nil},
		{&ICMPv4{}, []byte{8, 0, 0, 0, 0, 1, 0, 1, 0, 0}, 8, 2, nil},
		{&ICMPv6{}, []byte{0x80, 0, 0, 0, 0, 1, 0, 1, 0, 0}, 8, 2, nil},
		{&GRE{}, []byte{0x80, 0, 0x08, 0, 0, 0, 0, 0, 0, 0}, 8, 4, nil},
	}
	cases[1].prepare = func() { cases[1].layer.(*TCP).SetNetworkLayerForChecksum(ip4) }
	cases[2].prepare = func() { cases[2].layer.(*UDP).SetNetworkLayerForChecksum(ip4) }
	cases[4].prepare = func() { cases[4].layer.(*ICMPv6).SetNetworkLayerForChecksum(ip6) }

	for _, c := range cases {
		dl := c.layer.(gopacket.DecodingLayer)
		if c.prepare != nil {
			c.prepare()
		}
		// With the free word 0, Correct is ^S for sum S; writing it into the
		// free word makes the sum all ones and the computed checksum 0.
		decode(dl, c.data)
		err, res := c.layer.VerifyChecksum()
		if err != nil {
			t.Fatalf("%T: %v", c.layer, err)
		}
		c.data[c.free], c.data[c.free+1] = byte(res.Correct>>8), byte(res.Correct)

		for field, valid := range map[uint16]bool{0x0000: true, 0xffff: true, 0x1234: false} {
			c.data[c.csum], c.data[c.csum+1] = byte(field>>8), byte(field)
			decode(dl, c.data)
			err, res := c.layer.VerifyChecksum()
			if err != nil {
				t.Fatalf("%T: %v", c.layer, err)
			}
			if res.Valid != valid {
				t.Errorf("%T: checksum %#04x: got %+v, want Valid:%v", c.layer, field, res, valid)
			}
		}
	}
}

// TestChecksumSourceRoute computes the pseudo-header over the final
// destination of a source-routed packet, which is in the option or the
// routing header while the route is not used up (RFC 791, RFC 8200 8.1).
func TestChecksumSourceRoute(t *testing.T) {
	// IPv4 with LSRR to 192.0.2.11 via 192.0.2.10, UDP checksum over .11
	ip4Data := []byte{
		0x47, 0x00, 0x00, 0x27, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x61, 0xf0, 0xc0, 0x00, 0x02, 0x01, 0xc0, 0x00, 0x02, 0x0a,
		0x83, 0x07, 0x04, 0xc0, 0x00, 0x02, 0x0b, 0x00,
		0x9c, 0x40, 0x9c, 0x41, 0x00, 0x0b, 0x5f, 0xd1, 0x74, 0x77, 0x6f,
	}
	p := gopacket.NewPacket(ip4Data, LayerTypeIPv4, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer().Error())
	}
	udp := p.Layer(LayerTypeUDP).(*UDP)
	udp.SetNetworkLayerForChecksum(p.NetworkLayer())
	if err, res := udp.VerifyChecksum(); err != nil || !res.Valid {
		t.Errorf("IPv4 LSRR: err %v, result %+v, want valid", err, res)
	}
	ip4Data[35] = 0xd2 // checksum over the waypoint
	p = gopacket.NewPacket(ip4Data, LayerTypeIPv4, gopacket.Default)
	udp = p.Layer(LayerTypeUDP).(*UDP)
	udp.SetNetworkLayerForChecksum(p.NetworkLayer())
	if err, res := udp.VerifyChecksum(); err != nil || res.Valid {
		t.Errorf("IPv4 LSRR: err %v, result %+v, want invalid", err, res)
	}

	// IPv6 echo request for ::b via ::a, ICMPv6 checksum over ::b
	hdr := []byte{0x60, 0, 0, 0, 0, 0x3c, 43, 64}
	hdr = append(hdr, net.ParseIP("2001:db8::1").To16()...)
	hdr = append(hdr, net.ParseIP("2001:db8::a").To16()...)
	icmp := []byte{0x80, 0x00, 0x21, 0xf7, 0x12, 0x34, 0x00, 0x02, 'p', 'i', 'n', 'g', ' ', 'd', 'a', 't', 'a', '.', '.', '.'}
	for _, c := range []struct {
		name    string
		routing []byte
	}{
		{"type 4 segment list", append(append([]byte{0x3a, 0x04, 0x04, 0x01, 0x01, 0x00, 0x00, 0x00},
			net.ParseIP("2001:db8::b").To16()...), net.ParseIP("2001:db8::a").To16()...)},
		{"type 0 address list", append(append([]byte{0x3a, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
			net.ParseIP("2001:db8::a").To16()...), net.ParseIP("2001:db8::b").To16()...)},
	} {
		data := append(append(append([]byte{}, hdr...), c.routing...), icmp...)
		ip6 := &IPv6{}
		if err := ip6.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		i := &ICMPv6{}
		if err := i.DecodeFromBytes(data[80:], gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		i.SetNetworkLayerForChecksum(ip6)
		if err, res := i.VerifyChecksum(); err != nil || !res.Valid {
			t.Errorf("%s: err %v, result %+v, want valid", c.name, err, res)
		}

		// With no segments left, DstIP is the final destination.
		data[43] = 0
		if err := ip6.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		if err, res := i.VerifyChecksum(); err != nil || res.Valid {
			t.Errorf("%s, segments left 0: err %v, result %+v, want invalid", c.name, err, res)
		}
	}
}
