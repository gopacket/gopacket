// Copyright 2014, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	_ "fmt"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// packet samples from Wireshark sample set: https://wiki.wireshark.org/Lightweight_User_Datagram_Protocol.md
var udpLiteTestData = map[string]struct {
	data       []byte
	wantLayers []gopacket.LayerType
	want       *UDPLite
	shouldErr  bool
}{
	"udp-lite - valid - full checksum coverage": {
		data: []byte{
			// UDP-Lite header
			0x80, 0x00, 0x04, 0xd2, 0x00, 0x00, 0x38, 0x45,
			// Payload
			0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0a,
		},
		wantLayers: []gopacket.LayerType{LayerTypeUDPLite, gopacket.LayerTypePayload},
		want: &UDPLite{
			BaseLayer: BaseLayer{
				Contents: []uint8{0x80, 0x00, 0x04, 0xd2, 0x00, 0x00, 0x38, 0x45},
				Payload:  []uint8{0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0xa},
			},
			SrcPort:          32768,
			DstPort:          1234,
			ChecksumCoverage: 0, // 0 = entire packet
			Checksum:         14405,
			sPort:            []uint8{0x80, 0x0},
			dPort:            []uint8{0x4, 0xd2},
		},
	},
	"udp-lite - valid - 20 byte checksum coverage": {
		data: []byte{
			// UDP-Lite header
			0x80, 0x00, 0x04, 0xd2, 0x00, 0x14, 0x38, 0x31,
			// Payload
			0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0a,
		},
		wantLayers: []gopacket.LayerType{LayerTypeUDPLite, gopacket.LayerTypePayload},
		want: &UDPLite{
			BaseLayer: BaseLayer{
				Contents: []uint8{0x80, 0x00, 0x04, 0xd2, 0x00, 0x14, 0x38, 0x31},
				Payload:  []uint8{0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0xa},
			},
			SrcPort:          32768,
			DstPort:          1234,
			ChecksumCoverage: 20, //
			Checksum:         0x3831,
			sPort:            []uint8{0x80, 0x0},
			dPort:            []uint8{0x4, 0xd2},
		},
	},
	"udp-lite - invalid - checksum coverage exceeds size of data": {
		data: []byte{
			// UDP-Lite header
			0x80, 0x00, 0x04, 0xd2, 0x00, 0x15, 0x38, 0x30,
			// Payload
			0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0a,
		},
		wantLayers: []gopacket.LayerType{},
		want:       &UDPLite{},
		shouldErr:  true,
	},
	"udp-lite - invalid - checksum coverage doesn't meet minimum req of 8 bytes": {
		data: []byte{
			// UDP-Lite header
			0x80, 0x00, 0x04, 0xd2, 0x00, 0x01, 0xce, 0xef,
			// Payload
			0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x0a,
		},
		wantLayers: []gopacket.LayerType{},
		want:       &UDPLite{},
		shouldErr:  true,
	},
}

func TestDecodeUDPLite(t *testing.T) {
	for label, td := range udpLiteTestData {
		t.Run(label, func(t *testing.T) {
			p := gopacket.NewPacket(td.data, LayerTypeUDPLite, gopacket.Default)
			if p.ErrorLayer() != nil && !td.shouldErr {
				t.Error("Failed to decode packet:", p.ErrorLayer().Error())
			} else if p.ErrorLayer() == nil && td.shouldErr {
				t.Error("expected an error, but got nil")
			}

			if p.ErrorLayer() != nil || td.shouldErr {
				return
			}

			checkLayers(p, td.wantLayers, t)

			if got, ok := p.Layer(LayerTypeUDPLite).(*UDPLite); ok {
				if !reflect.DeepEqual(got, td.want) {
					t.Errorf("UDP-Lite packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, td.want)
				}
			}
		})
	}
}

func BenchmarkDecodeUDPLite(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, td := range udpLiteTestData {
			gopacket.NewPacket(td.data, LayerTypeUDPLite, gopacket.Default)
		}
	}
}
