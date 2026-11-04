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

// testPacketEAPIdentityPadded is an EAP Response/Identity for "mallory"
// (Length 12) followed by the zero bytes an Ethernet sender pads a short
// frame with. RFC 3748 section 4: octets outside the range of the Length
// field are data link layer padding and must be ignored.
var testPacketEAPIdentityPadded = []byte{
	0x02, 0x01, 0x00, 0x0c, 0x01, 0x6d, 0x61, 0x6c,
	0x6c, 0x6f, 0x72, 0x79, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestPacketEAPIdentityPadded(t *testing.T) {
	p := gopacket.NewPacket(testPacketEAPIdentityPadded, LayerTypeEAP, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEAP}, t)

	got := p.Layer(LayerTypeEAP).(*EAP)
	want := &EAP{
		BaseLayer: BaseLayer{
			Contents: testPacketEAPIdentityPadded[:12],
			Payload:  testPacketEAPIdentityPadded[12:],
		},
		Code:     EAPCodeResponse,
		Id:       1,
		Length:   12,
		Type:     EAPTypeIdentity,
		TypeData: []byte("mallory"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EAP packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
	}
}
