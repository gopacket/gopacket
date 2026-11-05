// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"

	"github.com/gopacket/gopacket"
)

// ethernetCTPFrame returns a loopback frame (EtherType 0x9000) whose payload
// is the little-endian skipCount followed by messages.
func ethernetCTPFrame(skipCount uint16, messages ...[]byte) []byte {
	frame := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x90, 0x00,
		byte(skipCount), byte(skipCount >> 8),
	}
	for _, m := range messages {
		frame = append(frame, m...)
	}
	return frame
}

// TestEthernetCTPSkipCount checks that SkipCount is even and inside the
// payload before the message chain is decoded, and that valid values decode
// the whole chain as before.
func TestEthernetCTPSkipCount(t *testing.T) {
	forward := []byte{0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xbb}
	reply := []byte{0x01, 0x00, 0x09, 0x00, 'p', 'i', 'n', 'g'}
	valid := []gopacket.LayerType{LayerTypeEthernet, LayerTypeEthernetCTP, LayerTypeEthernetCTPForwardData, LayerTypeEthernetCTPReply}
	rejected := []gopacket.LayerType{LayerTypeEthernet, gopacket.LayerTypeDecodeFailure}

	for _, test := range []struct {
		name      string
		skipCount uint16
		want      []gopacket.LayerType
	}{
		{"Zero", 0, valid},
		{"ForwardDataSkipped", 8, valid},
		{"Odd", 7, rejected},
		{"AtEnd", 16, rejected},
		{"PastEnd", 1000, rejected},
	} {
		p := gopacket.NewPacket(ethernetCTPFrame(test.skipCount, forward, reply), LinkTypeEthernet, testDecodeOptions)
		t.Run(test.name, func(t *testing.T) { checkLayers(p, test.want, t) })
	}
}
