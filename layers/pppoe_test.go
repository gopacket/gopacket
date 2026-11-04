// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"

	"github.com/gopacket/gopacket"
)

// A PPPoE session frame (EtherType 0x8864) carries PPP whatever its Code
// byte says: the receiver goes by EtherType and session id, not by Code.
func TestPPPoESessionIgnoresCode(t *testing.T) {
	for _, code := range []PPPoECode{PPPoECodeSession, 0x01, PPPoECodePADT} {
		data := append([]byte(nil), testPPPoEICMPv6...)
		data[15] = byte(code)
		p := gopacket.NewPacket(data, LinkTypeEthernet, testDecodeOptions)
		checkLayers(p, []gopacket.LayerType{
			LayerTypeEthernet,
			LayerTypePPPoE,
			LayerTypePPP,
			LayerTypeIPv6,
			LayerTypeICMPv6,
			gopacket.LayerTypePayload,
		}, t)
		if got := p.Layer(LayerTypePPPoE).(*PPPoE).Code; got != code {
			t.Errorf("code %d: decoded code %d", code, got)
		}
	}
}
