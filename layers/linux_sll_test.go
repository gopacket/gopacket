// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// testPacketLinuxSLLLLC is a spanning tree BPDU in a Linux cooked v1 record.
// The captured frame had an 802.3 length field, so the protocol type is
// 0x0004 (802.2 LLC) rather than an ethernet type.
var testPacketLinuxSLLLLC = []byte{
	// sll
	0x00, 0x02, 0x00, 0x01, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04,
	// llc
	0x42, 0x42, 0x03,
	// stp
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x14, 0x00, 0x02,
	0x00, 0x0f, 0x00,
}

func TestDecodeLinuxSLLLLC(t *testing.T) {
	want := []gopacket.LayerType{LayerTypeLinuxSLL, LayerTypeLLC, LayerTypeSTP}

	p := gopacket.NewPacket(testPacketLinuxSLLLLC, LinkTypeLinuxSLL, testDecodeOptions)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, want, t)

	parser := gopacket.NewDecodingLayerParser(LayerTypeLinuxSLL, &LinuxSLL{}, &LLC{}, &STP{})
	var decoded []gopacket.LayerType
	if err := parser.DecodeLayers(testPacketLinuxSLLLLC, &decoded); err != nil {
		t.Fatal("Failed to decode layers:", err)
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Errorf("decoded layers = %v, want %v", decoded, want)
	}
}
