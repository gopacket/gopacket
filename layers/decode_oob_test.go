// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"

	"github.com/gopacket/gopacket"
)

// TestDecodeOOBRegression verifies that crafted, truncated packets which
// previously triggered out-of-bounds panics (GHSA-8mcr-459q-5mx2) are now
// rejected with an error instead of crashing. Each decoder is driven through
// the direct DecodeFromBytes path, which does not recover panics (unlike
// gopacket.NewPacket with default options), mirroring how DecodingLayerParser
// invokes decoders.
func TestDecodeOOBRegression(t *testing.T) {
	dhcp := make([]byte, 240)
	dhcp[2] = 0xFF // HardwareLen: 28+0xFF wraps in uint8
	dhcp[236], dhcp[237], dhcp[238], dhcp[239] = 0x63, 0x82, 0x53, 0x63

	cases := []struct {
		name  string
		layer func() gopacket.DecodingLayer
		data  []byte
	}{
		{"TLS/empty-handshake", func() gopacket.DecodingLayer { return &TLS{} }, []byte{0x16, 0x03, 0x01, 0x00, 0x00}},
		{"TLS/short-clienthello", func() gopacket.DecodingLayer { return &TLS{} }, []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}},
		{"DHCPv4/hwlen-overflow", func() gopacket.DecodingLayer { return &DHCPv4{} }, dhcp},
		{"SFlow/short-header", func() gopacket.DecodingLayer { return &SFlowDatagram{} }, []byte{0x00, 0x00, 0x00}},
		{"IPSecAH/short-actuallen", func() gopacket.DecodingLayer { return &IPSecAH{} }, make([]byte, 12)},
		{"VRRPv2/count-overrun", func() gopacket.DecodingLayer { return &VRRPv2{} }, []byte{0x21, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00}},
		{"Diameter/short-msglen", func() gopacket.DecodingLayer { return &Diameter{} }, func() []byte { b := make([]byte, 20); b[0] = 0x01; return b }()},
		{"GTPv1U/ext-header-overrun", func() gopacket.DecodingLayer { return &GTPv1U{} }, []byte{0x04, 0xFF, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0x01}},
		{"ERSPANII/short", func() gopacket.DecodingLayer { return &ERSPANII{} }, make([]byte, 6)},
		{"LCM/short-fragmented", func() gopacket.DecodingLayer { return &LCM{} }, []byte{0x4c, 0x43, 0x30, 0x33, 0x00, 0x00, 0x00, 0x00}},
		{"RadioTap/present-ext-overrun", func() gopacket.DecodingLayer { return &RadioTap{} }, []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x80}},
		{"Dot11IE/ext-id-overrun", func() gopacket.DecodingLayer { return &Dot11InformationElement{} }, []byte{0xFF, 0x00}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decoder panicked on crafted input: %v", r)
				}
			}()
			// A returned error is expected and fine; the point is that it must
			// not panic.
			_ = c.layer().DecodeFromBytes(c.data, gopacket.NilDecodeFeedback)
		})
	}
}
