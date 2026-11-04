// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
package layers

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// test harness to ensure the dot1q layer can be encoded/decoded properly
// return error if decoded data not match.
func testEncodeDecodeDot1Q(dot1Q *Dot1Q) error {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	expectedDot1Q := dot1Q

	err := dot1Q.SerializeTo(buf, opts)
	if err != nil {
		return err
	}

	newDot1q := &Dot1Q{}
	err = newDot1q.DecodeFromBytes(buf.Bytes(), gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}
	newDot1q.BaseLayer = BaseLayer{}

	if !reflect.DeepEqual(expectedDot1Q, newDot1q) {
		return fmt.Errorf("Expect %v actual %v", expectedDot1Q, newDot1q)
	}
	return nil

}

// Test to ensure what has been encode can be decoded
func TestEncodeDecodeDot1Q(t *testing.T) {
	dot1Qs := []*Dot1Q{
		&Dot1Q{
			Priority:       uint8(3),
			VLANIdentifier: uint16(30),
		},
		&Dot1Q{
			Priority:       uint8(0x07),
			DropEligible:   true,
			VLANIdentifier: uint16(0xFFF),
		},
	}

	for i, curTest := range dot1Qs {
		err := testEncodeDecodeDot1Q(curTest)
		if err != nil {
			t.Error("Error with item ", i, " with error message :", err)
		}
	}
}

// testPacketDot1QSTP is an 802.1D configuration BPDU in an 802.3/LLC frame
// tagged for VLAN 10, padded to 60 bytes:
//
//	02:aa:bb:cc:dd:ee > 01:80:c2:00:00:00, ethertype 802.1Q (0x8100), length 60: vlan 10, p 0, 802.3LLC, dsap STP (0x42) Individual, ssap STP (0x42) Command, ctrl 0x03: STP 802.1d, Config
var testPacketDot1QSTP = []byte{
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x81, 0x00, 0x00, 0x0a,
	0x00, 0x26, 0x42, 0x42, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb, 0xcc,
	0xdd, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x80, 0x01,
	0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00,
}

// An 802.3 length behind the tag is followed by LLC, as in an untagged frame.
func TestPacketDot1QLLC(t *testing.T) {
	p := gopacket.NewPacket(testPacketDot1QSTP, LinkTypeEthernet, testDecodeOptions)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeDot1Q, LayerTypeLLC, LayerTypeSTP}, t)
	d := p.Layer(LayerTypeDot1Q).(*Dot1Q)
	if d.Type != 0x26 || len(d.Payload) != 0x26 {
		t.Errorf("want type/length 38, payload 38, got %v, %d", d.Type, len(d.Payload))
	}

	// The frame must serialize back to the same bytes.
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, p.Layer(LayerTypeEthernet).(*Ethernet), d, gopacket.Payload(d.Payload)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(buf.Bytes(), testPacketDot1QSTP) {
		t.Errorf("want %x got %x", testPacketDot1QSTP, buf.Bytes())
	}
}
