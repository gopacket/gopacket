// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// testPacketOSPF2Hello is the packet:
// 13:19:20.008765 IP 192.168.170.8 > 224.0.0.5: OSPFv2, Hello, length 44
//
//	0x0000:  0100 5e00 0005 00e0 18b1 0cad 0800 45c0  ..^...........E.
//	0x0010:  0040 0812 0000 0159 65dd c0a8 aa08 e000  .@.....Ye.......
//	0x0020:  0005 0201 002c c0a8 aa08 0000 0001 273b  .....,........';
//	0x0030:  0000 0000 0000 0000 0000 ffff ff00 000a  ................
//	0x0040:  0201 0000 0028 c0a8 aa08 0000 0000       .....(........
var testPacketOSPF2Hello = []byte{
	0x01, 0x00, 0x5e, 0x00, 0x00, 0x05, 0x00, 0xe0, 0x18, 0xb1, 0x0c, 0xad, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x40, 0x08, 0x12, 0x00, 0x00, 0x01, 0x59, 0x65, 0xdd, 0xc0, 0xa8, 0xaa, 0x08, 0xe0, 0x00,
	0x00, 0x05, 0x02, 0x01, 0x00, 0x2c, 0xc0, 0xa8, 0xaa, 0x08, 0x00, 0x00, 0x00, 0x01, 0x27, 0x3b,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x0a,
	0x02, 0x01, 0x00, 0x00, 0x00, 0x28, 0xc0, 0xa8, 0xaa, 0x08, 0x00, 0x00, 0x00, 0x00,
}

func TestPacketOSPF2Hello(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF2Hello, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeOSPF}, t)

	ospf := p.Layer(LayerTypeOSPF).(*OSPFv2)
	if ospf.Version != 2 {
		t.Fatal("Invalid OSPF version")
	}
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv2); ok {
		want := &OSPFv2{
			OSPF: OSPF{
				Version:      2,
				Type:         OSPFHello,
				PacketLength: 44,
				RouterID:     0xc0a8aa08,
				AreaID:       1,
				Checksum:     0x273b,
				Content: HelloPkgV2{
					NetworkMask: 0xffffff00,
					HelloPkg: HelloPkg{
						RtrPriority:              0x1,
						Options:                  0x2,
						HelloInterval:            0xa,
						RouterDeadInterval:       0x28,
						DesignatedRouterID:       0xc0a8aa08,
						BackupDesignatedRouterID: 0x0,
					},
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}
func BenchmarkDecodePacketPacket5(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketOSPF2Hello, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketOSPF3Hello is the packet:
//
//	14:43:11.663317 IP6 fe80::1 > ff02::5: OSPFv3, Hello, length 36
//		0x0000:  3333 0000 0005 c200 1ffa 0001 86dd 6e00  33............n.
//		0x0010:  0000 0024 5901 fe80 0000 0000 0000 0000  ...$Y...........
//		0x0020:  0000 0000 0001 ff02 0000 0000 0000 0000  ................
//		0x0030:  0000 0000 0005 0301 0024 0101 0101 0000  .........$......
//		0x0040:  0001 fb86 0000 0000 0005 0100 0013 000a  ................
//		0x0050:  0028 0000 0000 0000 0000                 .(........
var testPacketOSPF3Hello = []byte{
	0x33, 0x33, 0x00, 0x00, 0x00, 0x05, 0xc2, 0x00, 0x1f, 0xfa, 0x00, 0x01, 0x86, 0xdd, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x24, 0x59, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x24, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x01, 0xfb, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x13, 0x00, 0x0a,
	0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestPacketOSPF3Hello(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF3Hello, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv6, LayerTypeOSPF}, t)

	ospf := p.Layer(LayerTypeOSPF).(*OSPFv3)
	if ospf.Version != 3 {
		t.Fatal("Invalid OSPF version")
	}
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv3); ok {
		want := &OSPFv3{
			OSPF: OSPF{
				Version:      3,
				Type:         OSPFHello,
				PacketLength: 36,
				RouterID:     0x1010101,
				AreaID:       1,
				Checksum:     0xfb86,
				Content: HelloPkg{
					InterfaceID:              5,
					RtrPriority:              1,
					Options:                  0x000013,
					HelloInterval:            10,
					RouterDeadInterval:       40,
					DesignatedRouterID:       0,
					BackupDesignatedRouterID: 0,
				},
			},
			Instance: 0,
			Reserved: 0,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}
func BenchmarkDecodePacketPacket0(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketOSPF3Hello, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketOSPF2DBDesc is the packet:
// 13:20:14.414477 IP 192.168.170.8 > 192.168.170.2: OSPFv2, Database Description, length 32
//
//	0x0000:  0060 0881 7a70 00e0 18b1 0cad 0800 45c0  .`..zp........E.
//	0x0010:  0034 2be5 0000 0159 b770 c0a8 aa08 c0a8  .4+....Y.p......
//	0x0020:  aa02 0202 0020 c0a8 aa08 0000 0001 a052  ...............R
//	0x0030:  0000 0000 0000 0000 0000 05dc 0207 4177  ..............Aw
//	0x0040:  a97e                                     .~
var testPacketOSPF2DBDesc = []byte{
	0x00, 0x60, 0x08, 0x81, 0x7a, 0x70, 0x00, 0xe0, 0x18, 0xb1, 0x0c, 0xad, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x34, 0x2b, 0xe5, 0x00, 0x00, 0x01, 0x59, 0xb7, 0x70, 0xc0, 0xa8, 0xaa, 0x08, 0xc0, 0xa8,
	0xaa, 0x02, 0x02, 0x02, 0x00, 0x20, 0xc0, 0xa8, 0xaa, 0x08, 0x00, 0x00, 0x00, 0x01, 0xa0, 0x52,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, 0x02, 0x07, 0x41, 0x77,
	0xa9, 0x7e,
}

func TestPacketOSPF2DBDesc(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF2DBDesc, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv2); ok {
		want := &OSPFv2{
			OSPF: OSPF{
				Version:      2,
				Type:         OSPFDatabaseDescription,
				PacketLength: 32,
				RouterID:     0xc0a8aa08,
				AreaID:       1,
				Checksum:     0xa052,
				Content: DbDescPkg{
					Options:      0x02,
					InterfaceMTU: 1500,
					Flags:        0x7,
					DDSeqNumber:  1098361214,
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}

// 192.168.87.1 > 192.168.87.9: OSPFv2, Database Description, length 52
//
//	Router-ID 192.168.87.1, Backbone Area, Authentication Type: none (0)
//	Options [External, Opaque], DD Flags [none], MTU: 1500, Sequence: 0x00006904
//	  Advertising Router 192.168.87.1, seq 0x8000029d, age 1456s, length 16
//	    Router LSA (1), LSA-ID: 192.168.87.1
//	    Options: [External]
//	0x0000:  000c 29f1 e465 2ec8 1b56 b71d 0800 45c0  ..)..e...V....E.
//	0x0010:  0048 55f8 0000 0159 334a c0a8 5701 c0a8  .HU....Y3J..W...
//	0x0020:  5709 0202 0034 c0a8 5701 0000 0000 90fc  W....4..W.......
//	0x0030:  0000 0000 0000 0000 0000 05dc 4200 0000  ............B...
//	0x0040:  6904 05b0 0201 c0a8 5701 c0a8 5701 8000  i.......W...W...
//	0x0050:  029d ea7b 0024	                          ...{.$
var testPacketOSPF2DBDescWithLSAheader = []byte{
	0x00, 0x0c, 0x29, 0xf1, 0xe4, 0x65, 0x2e, 0xc8, 0x1b, 0x56, 0xb7, 0x1d, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x48, 0x55, 0xf8, 0x00, 0x00, 0x01, 0x59, 0x33, 0x4a, 0xc0, 0xa8, 0x57, 0x01, 0xc0, 0xa8,
	0x57, 0x09, 0x02, 0x02, 0x00, 0x34, 0xc0, 0xa8, 0x57, 0x01, 0x00, 0x00, 0x00, 0x00, 0x90, 0xfc,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc, 0x42, 0x00, 0x00, 0x00,
	0x69, 0x04, 0x05, 0xb0, 0x02, 0x01, 0xc0, 0xa8, 0x57, 0x01, 0xc0, 0xa8, 0x57, 0x01, 0x80, 0x00,
	0x02, 0x9d, 0xea, 0x7b, 0x00, 0x24,
}

func TestPacketOSPF2DBDescWithLSAheader(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF2DBDescWithLSAheader, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv2); ok {
		want := &OSPFv2{
			OSPF: OSPF{
				Version:      2,
				Type:         OSPFDatabaseDescription,
				PacketLength: 52,
				RouterID:     binary.BigEndian.Uint32(net.ParseIP("192.168.87.1").To4()),
				AreaID:       0,
				Checksum:     0x90fc,
				Content: DbDescPkg{
					Options:      0x42,
					InterfaceMTU: 1500,
					Flags:        0x0,
					DDSeqNumber:  26884,
					LSAinfo: []LSAheader{
						{
							LSAge:       1456,
							LSType:      1,
							LinkStateID: 3232257793,
							AdvRouter:   3232257793,
							LSSeqNumber: 0x8000029d,
							LSChecksum:  60027,
							Length:      36,
							LSOptions:   0x2,
						},
					},
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}

func BenchmarkDecodePacketPacket6(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketOSPF2DBDesc, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketOSPF3DBDesc is the packet:
//
//	14:43:51.657571 IP6 fe80::2 > fe80::1: OSPFv3, Database Description, length 28
//		0x0000:  c200 1ffa 0001 c201 1ffa 0001 86dd 6e00  ..............n.
//		0x0010:  0000 001c 5901 fe80 0000 0000 0000 0000  ....Y...........
//		0x0020:  0000 0000 0002 fe80 0000 0000 0000 0000  ................
//		0x0030:  0000 0000 0001 0302 001c 0202 0202 0000  ................
//		0x0040:  0001 d826 0000 0000 0013 05dc 0007 0000  ...&............
//		0x0050:  1d46                                     .F
var testPacketOSPF3DBDesc = []byte{
	0xc2, 0x00, 0x1f, 0xfa, 0x00, 0x01, 0xc2, 0x01, 0x1f, 0xfa, 0x00, 0x01, 0x86, 0xdd, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x1c, 0x59, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x02, 0x00, 0x1c, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
	0x00, 0x01, 0xd8, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x05, 0xdc, 0x00, 0x07, 0x00, 0x00,
	0x1d, 0x46,
}

func TestPacketOSPF3DBDesc(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF3DBDesc, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv6, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv3); ok {
		want := &OSPFv3{
			OSPF: OSPF{
				Version:      3,
				Type:         OSPFDatabaseDescription,
				PacketLength: 28,
				RouterID:     0x2020202,
				AreaID:       1,
				Checksum:     0xd826,
				Content: DbDescPkg{
					Options:      0x000013,
					InterfaceMTU: 1500,
					Flags:        0x7,
					DDSeqNumber:  7494,
				},
			},
			Instance: 0,
			Reserved: 0,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}
func BenchmarkDecodePacketPacket1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketOSPF3DBDesc, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketOSPF2LSRequest is the packet:
// 13:20:14.418003 IP 192.168.170.2 > 192.168.170.8: OSPFv2, LS-Request, length 36
//
//	0x0000:  00e0 18b1 0cad 0060 0881 7a70 0800 45c0  .......`..zp..E.
//	0x0010:  0038 88c6 0000 0159 5a8b c0a8 aa02 c0a8  .8.....YZ.......
//	0x0020:  aa08 0203 0024 c0a8 aa03 0000 0001 bdc7  .....$..........
//	0x0030:  0000 0000 0000 0000 0000 0000 0001 c0a8  ................
//	0x0040:  aa08 c0a8 aa08                           ......
var testPacketOSPF2LSRequest = []byte{
	0x00, 0xe0, 0x18, 0xb1, 0x0c, 0xad, 0x00, 0x60, 0x08, 0x81, 0x7a, 0x70, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x38, 0x88, 0xc6, 0x00, 0x00, 0x01, 0x59, 0x5a, 0x8b, 0xc0, 0xa8, 0xaa, 0x02, 0xc0, 0xa8,
	0xaa, 0x08, 0x02, 0x03, 0x00, 0x24, 0xc0, 0xa8, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x01, 0xbd, 0xc7,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0, 0xa8,
	0xaa, 0x08, 0xc0, 0xa8, 0xaa, 0x08,
}

func TestPacketOSPF2LSRequest(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF2LSRequest, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv2); ok {
		want := &OSPFv2{
			OSPF: OSPF{
				Version:      2,
				Type:         OSPFLinkStateRequest,
				PacketLength: 36,
				RouterID:     0xc0a8aa03,
				AreaID:       1,
				Checksum:     0xbdc7,
				Content: []LSReq{
					LSReq{
						LSType:    0x1,
						LSID:      0xc0a8aa08,
						AdvRouter: 0xc0a8aa08,
					},
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}
func BenchmarkDecodePacketPacket7(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketOSPF2LSRequest, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketOSPF3LSRequest is the packet:
//
//	14:43:51.673584 IP6 fe80::2 > fe80::1: OSPFv3, LS-Request, length 100
//		0x0000:  c200 1ffa 0001 c201 1ffa 0001 86dd 6e00  ..............n.
//		0x0010:  0000 0064 5901 fe80 0000 0000 0000 0000  ...dY...........
//		0x0020:  0000 0000 0002 fe80 0000 0000 0000 0000  ................
//		0x0030:  0000 0000 0001 0303 0064 0202 0202 0000  .........d......
//		0x0040:  0001 2c9a 0000 0000 2001 0000 0000 0101  ..,.............
//		0x0050:  0101 0000 2003 0000 0003 0101 0101 0000  ................
//		0x0060:  2003 0000 0002 0101 0101 0000 2003 0000  ................
//		0x0070:  0001 0101 0101 0000 2003 0000 0000 0101  ................
//		0x0080:  0101 0000 0008 0000 0005 0101 0101 0000  ................
//		0x0090:  2009 0000 0000 0101 0101                 ..........
var testPacketOSPF3LSRequest = []byte{
	0xc2, 0x00, 0x1f, 0xfa, 0x00, 0x01, 0xc2, 0x01, 0x1f, 0xfa, 0x00, 0x01, 0x86, 0xdd, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x64, 0x59, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x00, 0x64, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
	0x00, 0x01, 0x2c, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
	0x01, 0x01, 0x00, 0x00, 0x20, 0x03, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
	0x20, 0x03, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x20, 0x03, 0x00, 0x00,
	0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x20, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x05, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
	0x20, 0x09, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
}

func TestPacketOSPF3LSRequest(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF3LSRequest, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv6, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv3); ok {
		want := &OSPFv3{
			OSPF: OSPF{
				Version:      3,
				Type:         OSPFLinkStateRequest,
				PacketLength: 100,
				RouterID:     0x2020202,
				AreaID:       1,
				Checksum:     0x2c9a,
				Content: []LSReq{
					LSReq{
						LSType:    0x2001,
						LSID:      0x00000000,
						AdvRouter: 0x01010101,
					},
					LSReq{
						LSType:    0x2003,
						LSID:      0x00000003,
						AdvRouter: 0x01010101,
					},
					LSReq{
						LSType:    0x2003,
						LSID:      0x00000002,
						AdvRouter: 0x01010101,
					},
					LSReq{
						LSType:    0x2003,
						LSID:      0x00000001,
						AdvRouter: 0x01010101,
					},
					LSReq{
						LSType:    0x2003,
						LSID:      0x00000000,
						AdvRouter: 0x01010101,
					},
					LSReq{
						LSType:    0x0008,
						LSID:      0x00000005,
						AdvRouter: 0x01010101,
					},
					LSReq{
						LSType:    0x2009,
						LSID:      0x00000000,
						AdvRouter: 0x01010101,
					},
				},
			},
			Instance: 0,
			Reserved: 0,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}
func BenchmarkDecodePacketPacket2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketOSPF3LSRequest, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketOSPF2LSUpdate is the packet:
// 13:20:14.420459 IP 192.168.170.2 > 224.0.0.6: OSPFv2, LS-Update, length 292
//
//	0x0000:  0100 5e00 0006 0060 0881 7a70 0800 45c0  ..^....`..zp..E.
//	0x0010:  0138 3025 0000 0159 3cd7 c0a8 aa02 e000  .80%...Y<.......
//	0x0020:  0006 0204 0124 c0a8 aa03 0000 0001 366b  .....$........6k
//	0x0030:  0000 0000 0000 0000 0000 0000 0007 0002  ................
//	0x0040:  0201 c0a8 aa03 c0a8 aa03 8000 0001 3a9c  ..............:.
//	0x0050:  0030 0200 0002 c0a8 aa00 ffff ff00 0300  .0..............
//	0x0060:  000a c0a8 aa00 ffff ff00 0300 000a 0003  ................
//	0x0070:  0205 50d4 1000 c0a8 aa02 8000 0001 2a49  ..P...........*I
//	0x0080:  0024 ffff ffff 8000 0014 0000 0000 0000  .$..............
//	0x0090:  0000 0003 0205 9479 ab00 c0a8 aa02 8000  .......y........
//	0x00a0:  0001 34a5 0024 ffff ff00 8000 0014 c0a8  ..4..$..........
//	0x00b0:  aa01 0000 0000 0003 0205 c082 7800 c0a8  ............x...
//	0x00c0:  aa02 8000 0001 d319 0024 ffff ff00 8000  .........$......
//	0x00d0:  0014 0000 0000 0000 0000 0003 0205 c0a8  ................
//	0x00e0:  0000 c0a8 aa02 8000 0001 3708 0024 ffff  ..........7..$..
//	0x00f0:  ff00 8000 0014 0000 0000 0000 0000 0003  ................
//	0x0100:  0205 c0a8 0100 c0a8 aa02 8000 0001 2c12  ..............,.
//	0x0110:  0024 ffff ff00 8000 0014 0000 0000 0000  .$..............
//	0x0120:  0000 0003 0205 c0a8 ac00 c0a8 aa02 8000  ................
//	0x0130:  0001 3341 0024 ffff ff00 8000 0014 c0a8  ..3A.$..........
//	0x0140:  aa0a 0000 0000                           ......
var testPacketOSPF2LSUpdate = []byte{
	0x01, 0x00, 0x5e, 0x00, 0x00, 0x06, 0x00, 0x60, 0x08, 0x81, 0x7a, 0x70, 0x08, 0x00, 0x45, 0xc0,
	0x01, 0x38, 0x30, 0x25, 0x00, 0x00, 0x01, 0x59, 0x3c, 0xd7, 0xc0, 0xa8, 0xaa, 0x02, 0xe0, 0x00,
	0x00, 0x06, 0x02, 0x04, 0x01, 0x24, 0xc0, 0xa8, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x01, 0x36, 0x6b,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x02,
	0x02, 0x01, 0xc0, 0xa8, 0xaa, 0x03, 0xc0, 0xa8, 0xaa, 0x03, 0x80, 0x00, 0x00, 0x01, 0x3a, 0x9c,
	0x00, 0x30, 0x02, 0x00, 0x00, 0x02, 0xc0, 0xa8, 0xaa, 0x00, 0xff, 0xff, 0xff, 0x00, 0x03, 0x00,
	0x00, 0x0a, 0xc0, 0xa8, 0xaa, 0x00, 0xff, 0xff, 0xff, 0x00, 0x03, 0x00, 0x00, 0x0a, 0x00, 0x03,
	0x02, 0x05, 0x50, 0xd4, 0x10, 0x00, 0xc0, 0xa8, 0xaa, 0x02, 0x80, 0x00, 0x00, 0x01, 0x2a, 0x49,
	0x00, 0x24, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03, 0x02, 0x05, 0x94, 0x79, 0xab, 0x00, 0xc0, 0xa8, 0xaa, 0x02, 0x80, 0x00,
	0x00, 0x01, 0x34, 0xa5, 0x00, 0x24, 0xff, 0xff, 0xff, 0x00, 0x80, 0x00, 0x00, 0x14, 0xc0, 0xa8,
	0xaa, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x02, 0x05, 0xc0, 0x82, 0x78, 0x00, 0xc0, 0xa8,
	0xaa, 0x02, 0x80, 0x00, 0x00, 0x01, 0xd3, 0x19, 0x00, 0x24, 0xff, 0xff, 0xff, 0x00, 0x80, 0x00,
	0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x02, 0x05, 0xc0, 0xa8,
	0x00, 0x00, 0xc0, 0xa8, 0xaa, 0x02, 0x80, 0x00, 0x00, 0x01, 0x37, 0x08, 0x00, 0x24, 0xff, 0xff,
	0xff, 0x00, 0x80, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
	0x02, 0x05, 0xc0, 0xa8, 0x01, 0x00, 0xc0, 0xa8, 0xaa, 0x02, 0x80, 0x00, 0x00, 0x01, 0x2c, 0x12,
	0x00, 0x24, 0xff, 0xff, 0xff, 0x00, 0x80, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03, 0x02, 0x05, 0xc0, 0xa8, 0xac, 0x00, 0xc0, 0xa8, 0xaa, 0x02, 0x80, 0x00,
	0x00, 0x01, 0x33, 0x41, 0x00, 0x24, 0xff, 0xff, 0xff, 0x00, 0x80, 0x00, 0x00, 0x14, 0xc0, 0xa8,
	0xaa, 0x0a, 0x00, 0x00, 0x00, 0x00,
}

func TestPacketOSPF2LSUpdate(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF2LSUpdate, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv2); ok {
		want := &OSPFv2{
			OSPF: OSPF{
				Version:      2,
				Type:         OSPFLinkStateUpdate,
				PacketLength: 292,
				RouterID:     0xc0a8aa03,
				AreaID:       1,
				Checksum:     0x366b,
				Content: LSUpdate{
					NumOfLSAs: 7,
					LSAs: []LSA{
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x2,
								LSType:      0x1,
								LinkStateID: 0xc0a8aa03,
								AdvRouter:   0xc0a8aa03,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0x3a9c,
								Length:      0x30,
								LSOptions:   0x2,
							},
							Content: RouterLSAV2{
								Flags: 0x2,
								Links: 0x2,
								Routers: []RouterV2{
									RouterV2{
										LinkID:   0xc0a8aa00,
										LinkData: 0xffffff00,
										Type:     0x03,
										Metric:   0x0a,
									},
									RouterV2{
										LinkID:   0xc0a8aa00,
										LinkData: 0xffffff00,
										Type:     0x03,
										Metric:   0x0a,
									},
								},
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x3,
								LSType:      0x5,
								LinkStateID: 0x50d41000,
								AdvRouter:   0xc0a8aa02,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0x2a49,
								Length:      0x24,
								LSOptions:   0x2,
							},
							Content: ASExternalLSAV2{
								NetworkMask:       0xffffffff,
								ExternalBit:       0x80,
								Metric:            0x14,
								ForwardingAddress: 0x0,
								ExternalRouteTag:  0x0,
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x3,
								LSType:      0x5,
								LinkStateID: 0x9479ab00,
								AdvRouter:   0xc0a8aa02,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0x34a5,
								Length:      0x24,
								LSOptions:   0x2,
							},
							Content: ASExternalLSAV2{
								NetworkMask:       0xffffff00,
								ExternalBit:       0x80,
								Metric:            0x14,
								ForwardingAddress: 0xc0a8aa01,
								ExternalRouteTag:  0x0,
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x3,
								LSType:      0x5,
								LinkStateID: 0xc0827800,
								AdvRouter:   0xc0a8aa02,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0xd319,
								Length:      0x24,
								LSOptions:   0x2,
							},
							Content: ASExternalLSAV2{
								NetworkMask:       0xffffff00,
								ExternalBit:       0x80,
								Metric:            0x14,
								ForwardingAddress: 0x0,
								ExternalRouteTag:  0x0,
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x3,
								LSType:      0x5,
								LinkStateID: 0xc0a80000,
								AdvRouter:   0xc0a8aa02,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0x3708,
								Length:      0x24,
								LSOptions:   0x2,
							},
							Content: ASExternalLSAV2{
								NetworkMask:       0xffffff00,
								ExternalBit:       0x80,
								Metric:            0x14,
								ForwardingAddress: 0x0,
								ExternalRouteTag:  0x0,
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x3,
								LSType:      0x5,
								LinkStateID: 0xc0a80100,
								AdvRouter:   0xc0a8aa02,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0x2c12,
								Length:      0x24,
								LSOptions:   0x2,
							},
							Content: ASExternalLSAV2{
								NetworkMask:       0xffffff00,
								ExternalBit:       0x80,
								Metric:            0x14,
								ForwardingAddress: 0x0,
								ExternalRouteTag:  0x0,
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x3,
								LSType:      0x5,
								LinkStateID: 0xc0a8ac00,
								AdvRouter:   0xc0a8aa02,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0x3341,
								Length:      0x24,
								LSOptions:   0x2,
							},
							Content: ASExternalLSAV2{
								NetworkMask:       0xffffff00,
								ExternalBit:       0x80,
								Metric:            0x14,
								ForwardingAddress: 0xc0a8aa0a,
								ExternalRouteTag:  0x0,
							},
						},
					},
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}
func BenchmarkDecodePacketPacket8(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketOSPF2LSUpdate, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketOSPF2LSUpdateLSA2 is the packet:
// 00:50:17.836469 IP 172.24.27.86 > ospf-all.mcast.net: OSPFv2, LS-Update, length 104
//
//	0x0000:  0100 5e00 0005 d4e8 80c2 b1c9 8100 017f
//	0x0010:  0800 45c0 008c f7e4 0000 0159 1901 ac18
//	0x0020:  1b56 e000 0005 0204 0058 ac18 0446 0000
//	0x0030:  000c 0000 0000 0000 0000 0000 0000 0000
//	0x0040:  0002 0001 2801 ac18 0446 ac18 0446 8000
//	0x0050:  041a 6025 0024 0000 0001 ac18 1b56 ac18
//	0x0060:  1b56 0200 0001 0001 2802 ac18 1b56 ac18
//	0x0070:  0446 8000 041f 390e 0028 ffff fff8 ac18
//	0x0080:  0446 ac18 0445 ac18 1b53 ac18 1b54
var testPacketOSPF2LSUpdateLSA2 = []byte{
	0x01, 0x00, 0x5e, 0x00, 0x00, 0x05, 0xd4, 0xe8, 0x80, 0xc2, 0xb1, 0xc9, 0x81, 0x00, 0x01, 0x7f,
	0x08, 0x00, 0x45, 0xc0, 0x00, 0x8c, 0xf7, 0xe4, 0x00, 0x00, 0x01, 0x59, 0x19, 0x01, 0xac, 0x18,
	0x1b, 0x56, 0xe0, 0x00, 0x00, 0x05, 0x02, 0x04, 0x00, 0x58, 0xac, 0x18, 0x04, 0x46, 0x00, 0x00,
	0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x01, 0x28, 0x01, 0xac, 0x18, 0x04, 0x46, 0xac, 0x18, 0x04, 0x46, 0x80, 0x00,
	0x04, 0x1a, 0x60, 0x25, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0xac, 0x18, 0x1b, 0x56, 0xac, 0x18,
	0x1b, 0x56, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x28, 0x02, 0xac, 0x18, 0x1b, 0x56, 0xac, 0x18,
	0x04, 0x46, 0x80, 0x00, 0x04, 0x1f, 0x39, 0x0e, 0x00, 0x28, 0xff, 0xff, 0xff, 0xf8, 0xac, 0x18,
	0x04, 0x46, 0xac, 0x18, 0x04, 0x45, 0xac, 0x18, 0x1b, 0x53, 0xac, 0x18, 0x1b, 0x54,
}

func TestPacketOSPF2LSUpdateLSA2(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF2LSUpdateLSA2, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeDot1Q, LayerTypeIPv4, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv2); ok {
		want := &OSPFv2{
			OSPF: OSPF{
				Version:      2,
				Type:         OSPFLinkStateUpdate,
				PacketLength: 88,
				RouterID:     0xac180446,
				AreaID:       12,
				Checksum:     0x0000,
				Content: LSUpdate{
					NumOfLSAs: 2,
					LSAs: []LSA{
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x1,
								LSType:      0x1,
								LinkStateID: 0xac180446,
								AdvRouter:   0xac180446,
								LSSeqNumber: 0x8000041a,
								LSChecksum:  0x6025,
								Length:      0x24,
								LSOptions:   0x28,
							},
							Content: RouterLSAV2{
								Flags: 0x0,
								Links: 0x1,
								Routers: []RouterV2{
									RouterV2{
										LinkID:   0xac181b56,
										LinkData: 0xac181b56,
										Type:     0x02,
										Metric:   0x01,
									},
								},
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x1,
								LSType:      0x2,
								LinkStateID: 0xac181b56,
								AdvRouter:   0xac180446,
								LSSeqNumber: 0x8000041f,
								LSChecksum:  0x390e,
								Length:      0x28,
								LSOptions:   0x28,
							},
							Content: NetworkLSAV2{
								NetworkMask: 0xfffffff8,
								AttachedRouter: []uint32{
									0xac180446,
									0xac180445,
									0xac181b53,
									0xac181b54,
								},
							},
						},
					},
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}

// testPacketOSPF2LSUpdateLSA7 is the packet:
// 00:00:00.337386 IP 172.24.27.84 > ospf-dsig.mcast.net: OSPFv2, LS-Update, length 100
//
//	0x0000:  0100 5e00 0006 001a 1e02 81a8 8100 017f
//	0x0010:  0800 45c0 0088 0000 4000 0159 d0ea ac18
//	0x0020:  1b54 e000 0006 0204 0054 ac18 1b54 0000
//	0x0030:  000c 0000 0000 0000 0000 0000 0000 0000
//	0x0040:  0002 0001 0807 0ac8 4f60 ac18 1b54 8000
//	0x0050:  03a6 4d08 0024 ffff ffe0 8000 0100 ac18
//	0x0060:  1b54 0000 0000 0001 0807 0a80 9300 ac18
//	0x0070:  1b54 8000 03a6 43d6 0024 ffff ff80 8000
//	0x0080:  0100 ac18 1b54 0000 0000
var testPacketOSPF2LSUpdateLSA7 = []byte{
	0x01, 0x00, 0x5e, 0x00, 0x00, 0x06, 0x00, 0x1a, 0x1e, 0x02, 0x81, 0xa8, 0x81, 0x00, 0x01, 0x7f,
	0x08, 0x00, 0x45, 0xc0, 0x00, 0x88, 0x00, 0x00, 0x40, 0x00, 0x01, 0x59, 0xd0, 0xea, 0xac, 0x18,
	0x1b, 0x54, 0xe0, 0x00, 0x00, 0x06, 0x02, 0x04, 0x00, 0x54, 0xac, 0x18, 0x1b, 0x54, 0x00, 0x00,
	0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x01, 0x08, 0x07, 0x0a, 0xc8, 0x4f, 0x60, 0xac, 0x18, 0x1b, 0x54, 0x80, 0x00,
	0x03, 0xa6, 0x4d, 0x08, 0x00, 0x24, 0xff, 0xff, 0xff, 0xe0, 0x80, 0x00, 0x01, 0x00, 0xac, 0x18,
	0x1b, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x07, 0x0a, 0x80, 0x93, 0x00, 0xac, 0x18,
	0x1b, 0x54, 0x80, 0x00, 0x03, 0xa6, 0x43, 0xd6, 0x00, 0x24, 0xff, 0xff, 0xff, 0x80, 0x80, 0x00,
	0x01, 0x00, 0xac, 0x18, 0x1b, 0x54, 0x00, 0x00, 0x00, 0x00,
}

func TestPacketOSPF2LSUpdateLSA7(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF2LSUpdateLSA7, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeDot1Q, LayerTypeIPv4, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv2); ok {
		want := &OSPFv2{
			OSPF: OSPF{
				Version:      2,
				Type:         OSPFLinkStateUpdate,
				PacketLength: 84,
				RouterID:     0xac181b54,
				AreaID:       12,
				Checksum:     0x0,
				Content: LSUpdate{
					NumOfLSAs: 2,
					LSAs: []LSA{
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x1,
								LSType:      0x7,
								LinkStateID: 0x0ac84f60,
								AdvRouter:   0xac181b54,
								LSSeqNumber: 0x800003a6,
								LSChecksum:  0x4d08,
								Length:      0x24,
								LSOptions:   0x08,
							},
							Content: ASExternalLSAV2{
								NetworkMask:       0xffffffe0,
								ExternalBit:       0x80,
								Metric:            0x0100,
								ForwardingAddress: 0xac181b54,
								ExternalRouteTag:  0x0,
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       0x1,
								LSType:      0x7,
								LinkStateID: 0x0a809300,
								AdvRouter:   0xac181b54,
								LSSeqNumber: 0x800003a6,
								LSChecksum:  0x43d6,
								Length:      0x24,
								LSOptions:   0x08,
							},
							Content: ASExternalLSAV2{
								NetworkMask:       0xffffff80,
								ExternalBit:       0x80,
								Metric:            0x0100,
								ForwardingAddress: 0xac181b54,
								ExternalRouteTag:  0x0,
							},
						},
					},
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}

// testPacketOSPF3LSUpdate is the packet:
//
//	14:43:51.681554 IP6 fe80::1 > fe80::2: OSPFv3, LS-Update, length 288
//		0x0000:  c201 1ffa 0001 c200 1ffa 0001 86dd 6e00  ..............n.
//		0x0010:  0000 0120 5901 fe80 0000 0000 0000 0000  ....Y...........
//		0x0020:  0000 0000 0001 fe80 0000 0000 0000 0000  ................
//		0x0030:  0000 0000 0002 0304 0120 0101 0101 0000  ................
//		0x0040:  0001 e556 0000 0000 0007 0028 2001 0000  ...V.......(....
//		0x0050:  0000 0101 0101 8000 0002 d13a 0018 0100  ...........:....
//		0x0060:  0033 0029 2003 0000 0003 0101 0101 8000  .3.)............
//		0x0070:  0001 6259 0024 0000 004a 4000 0000 2001  ..bY.$...J@.....
//		0x0080:  0db8 0000 0003 0029 2003 0000 0002 0101  .......)........
//		0x0090:  0101 8000 0001 baf6 0024 0000 0054 4000  .........$...T@.
//		0x00a0:  0000 2001 0db8 0000 0004 0029 2003 0000  ...........)....
//		0x00b0:  0001 0101 0101 8000 0001 eba0 0024 0000  .............$..
//		0x00c0:  004a 4000 0000 2001 0db8 0000 0034 0029  .J@..........4.)
//		0x00d0:  2003 0000 0000 0101 0101 8000 0001 0ebd  ................
//		0x00e0:  0024 0000 0040 4000 0000 2001 0db8 0000  .$...@@.........
//		0x00f0:  0000 0023 0008 0000 0005 0101 0101 8000  ...#............
//		0x0100:  0002 3d08 0038 0100 0033 fe80 0000 0000  ..=..8...3......
//		0x0110:  0000 0000 0000 0000 0001 0000 0001 4000  ..............@.
//		0x0120:  0000 2001 0db8 0000 0012 0023 2009 0000  ...........#....
//		0x0130:  0000 0101 0101 8000 0001 e8d2 002c 0001  .............,..
//		0x0140:  2001 0000 0000 0101 0101 4000 000a 2001  ..........@.....
//		0x0150:  0db8 0000 0012                           ......
var testPacketOSPF3LSUpdate = []byte{
	0xc2, 0x01, 0x1f, 0xfa, 0x00, 0x01, 0xc2, 0x00, 0x1f, 0xfa, 0x00, 0x01, 0x86, 0xdd, 0x6e, 0x00,
	0x00, 0x00, 0x01, 0x20, 0x59, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x04, 0x01, 0x20, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x01, 0xe5, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x28, 0x20, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00, 0x02, 0xd1, 0x3a, 0x00, 0x18, 0x01, 0x00,
	0x00, 0x33, 0x00, 0x29, 0x20, 0x03, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
	0x00, 0x01, 0x62, 0x59, 0x00, 0x24, 0x00, 0x00, 0x00, 0x4a, 0x40, 0x00, 0x00, 0x00, 0x20, 0x01,
	0x0d, 0xb8, 0x00, 0x00, 0x00, 0x03, 0x00, 0x29, 0x20, 0x03, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01,
	0x01, 0x01, 0x80, 0x00, 0x00, 0x01, 0xba, 0xf6, 0x00, 0x24, 0x00, 0x00, 0x00, 0x54, 0x40, 0x00,
	0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x04, 0x00, 0x29, 0x20, 0x03, 0x00, 0x00,
	0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00, 0x01, 0xeb, 0xa0, 0x00, 0x24, 0x00, 0x00,
	0x00, 0x4a, 0x40, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x34, 0x00, 0x29,
	0x20, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00, 0x01, 0x0e, 0xbd,
	0x00, 0x24, 0x00, 0x00, 0x00, 0x40, 0x40, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x23, 0x00, 0x08, 0x00, 0x00, 0x00, 0x05, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00,
	0x00, 0x02, 0x3d, 0x08, 0x00, 0x38, 0x01, 0x00, 0x00, 0x33, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x40, 0x00,
	0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x12, 0x00, 0x23, 0x20, 0x09, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x80, 0x00, 0x00, 0x01, 0xe8, 0xd2, 0x00, 0x2c, 0x00, 0x01,
	0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x40, 0x00, 0x00, 0x0a, 0x20, 0x01,
	0x0d, 0xb8, 0x00, 0x00, 0x00, 0x12,
}

func TestPacketOSPF3LSUpdate(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF3LSUpdate, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv6, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv3); ok {
		want := &OSPFv3{
			OSPF: OSPF{
				Version:      3,
				Type:         OSPFLinkStateUpdate,
				PacketLength: 288,
				RouterID:     0x1010101,
				AreaID:       1,
				Checksum:     0xe556,
				Content: LSUpdate{
					NumOfLSAs: 7,
					LSAs: []LSA{
						LSA{
							LSAheader: LSAheader{
								LSAge:       40,
								LSType:      0x2001,
								LinkStateID: 0x00000000,
								AdvRouter:   0x01010101,
								LSSeqNumber: 0x80000002,
								LSChecksum:  0xd13a,
								Length:      24,
							},
							Content: RouterLSA{
								Flags:   0x1,
								Options: 0x33,
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       41,
								LSType:      0x2003,
								LinkStateID: 0x00000003,
								AdvRouter:   0x01010101,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0x6259,
								Length:      36,
							},
							Content: InterAreaPrefixLSA{
								Metric:        74,
								PrefixLength:  64,
								PrefixOptions: 0,
								AddressPrefix: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x03},
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       41,
								LSType:      0x2003,
								LinkStateID: 0x00000002,
								AdvRouter:   0x01010101,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0xbaf6,
								Length:      36,
							},
							Content: InterAreaPrefixLSA{
								Metric:        84,
								PrefixLength:  64,
								PrefixOptions: 0,
								AddressPrefix: []byte{0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x4},
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       41,
								LSType:      0x2003,
								LinkStateID: 0x00000001,
								AdvRouter:   0x01010101,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0xeba0,
								Length:      36,
							},
							Content: InterAreaPrefixLSA{
								Metric:        74,
								PrefixLength:  64,
								PrefixOptions: 0,
								AddressPrefix: []byte{0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x34},
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       41,
								LSType:      0x2003,
								LinkStateID: 0x00000000,
								AdvRouter:   0x01010101,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0xebd,
								Length:      36,
							},
							Content: InterAreaPrefixLSA{
								Metric:        64,
								PrefixLength:  64,
								PrefixOptions: 0,
								AddressPrefix: []byte{0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x0},
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       35,
								LSType:      0x8,
								LinkStateID: 0x00000005,
								AdvRouter:   0x01010101,
								LSSeqNumber: 0x80000002,
								LSChecksum:  0x3d08,
								Length:      56,
							},
							Content: LinkLSA{
								RtrPriority:      1,
								Options:          0x33,
								LinkLocalAddress: []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
								NumOfPrefixes:    1,
								Prefixes: []Prefix{
									Prefix{
										PrefixLength:  64,
										PrefixOptions: 0,
										AddressPrefix: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x12},
									},
								},
							},
						},
						LSA{
							LSAheader: LSAheader{
								LSAge:       35,
								LSType:      0x2009,
								LinkStateID: 0x00000000,
								AdvRouter:   0x01010101,
								LSSeqNumber: 0x80000001,
								LSChecksum:  0xe8d2,
								Length:      44,
							},
							Content: IntraAreaPrefixLSA{
								NumOfPrefixes: 1,
								RefLSType:     0x2001,
								RefAdvRouter:  0x01010101,
								Prefixes: []Prefix{
									Prefix{
										PrefixLength:  64,
										PrefixOptions: 0,
										Metric:        10,
										AddressPrefix: []byte{0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x12},
									},
								},
							},
						},
					},
				},
			},
			Instance: 0,
			Reserved: 0,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}
func BenchmarkDecodePacketPacket3(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketOSPF3LSUpdate, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketOSPF2LSAck is the packet:
// 13:20:20.858322 IP 192.168.170.8 > 192.168.170.2: OSPFv2, LS-Ack, length 44
//
//	0x0000:  0060 0881 7a70 00e0 18b1 0cad 0800 45c0  .`..zp........E.
//	0x0010:  0040 2bea 0000 0159 b75f c0a8 aa08 c0a8  .@+....Y._......
//	0x0020:  aa02 0205 002c c0a8 aa08 0000 0001 e2f4  .....,..........
//	0x0030:  0000 0000 0000 0000 0000 0e10 0201 c0a8  ................
//	0x0040:  aa02 c0a8 aa02 8000 0001 4a8e 0030       ..........J..0
var testPacketOSPF2LSAck = []byte{
	0x00, 0x60, 0x08, 0x81, 0x7a, 0x70, 0x00, 0xe0, 0x18, 0xb1, 0x0c, 0xad, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x40, 0x2b, 0xea, 0x00, 0x00, 0x01, 0x59, 0xb7, 0x5f, 0xc0, 0xa8, 0xaa, 0x08, 0xc0, 0xa8,
	0xaa, 0x02, 0x02, 0x05, 0x00, 0x2c, 0xc0, 0xa8, 0xaa, 0x08, 0x00, 0x00, 0x00, 0x01, 0xe2, 0xf4,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x10, 0x02, 0x01, 0xc0, 0xa8,
	0xaa, 0x02, 0xc0, 0xa8, 0xaa, 0x02, 0x80, 0x00, 0x00, 0x01, 0x4a, 0x8e, 0x00, 0x30,
}

func TestPacketOSPF2LSAck(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF2LSAck, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv2); ok {
		want := &OSPFv2{
			OSPF: OSPF{
				Version:      2,
				Type:         OSPFLinkStateAcknowledgment,
				PacketLength: 44,
				RouterID:     0xc0a8aa08,
				AreaID:       1,
				Checksum:     0xe2f4,
				Content: []LSAheader{
					LSAheader{
						LSAge:       0xe10,
						LSType:      0x1,
						LinkStateID: 0xc0a8aa02,
						AdvRouter:   0xc0a8aa02,
						LSSeqNumber: 0x80000001,
						LSChecksum:  0x4a8e,
						Length:      0x30,
						LSOptions:   0x2,
					},
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}
func BenchmarkDecodePacketPacket9(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketOSPF3LSAck, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// testPacketOSPF3LSAck is the packet:
//
//	14:43:54.185384 IP6 fe80::1 > ff02::5: OSPFv3, LS-Ack, length 136
//		0x0000:  3333 0000 0005 c200 1ffa 0001 86dd 6e00  33............n.
//		0x0010:  0000 0088 5901 fe80 0000 0000 0000 0000  ....Y...........
//		0x0020:  0000 0000 0001 ff02 0000 0000 0000 0000  ................
//		0x0030:  0000 0000 0005 0305 0088 0101 0101 0000  ................
//		0x0040:  0001 9d2c 0000 0005 2001 0000 0000 0202  ...,............
//		0x0050:  0202 8000 0002 b354 0018 0006 2003 0000  .......T........
//		0x0060:  0003 0202 0202 8000 0001 4473 0024 0006  ..........Ds.$..
//		0x0070:  2003 0000 0002 0202 0202 8000 0001 9c11  ................
//		0x0080:  0024 0006 2003 0000 0001 0202 0202 8000  .$..............
//		0x0090:  0001 cdba 0024 0006 2003 0000 0000 0202  .....$..........
//		0x00a0:  0202 8000 0001 efd7 0024 0005 0008 0000  .........$......
//		0x00b0:  0005 0202 0202 8000 0001 5433 002c       ..........T3.,
var testPacketOSPF3LSAck = []byte{
	0x33, 0x33, 0x00, 0x00, 0x00, 0x05, 0xc2, 0x00, 0x1f, 0xfa, 0x00, 0x01, 0x86, 0xdd, 0x6e, 0x00,
	0x00, 0x00, 0x00, 0x88, 0x59, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x03, 0x05, 0x00, 0x88, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x01, 0x9d, 0x2c, 0x00, 0x00, 0x00, 0x05, 0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02,
	0x02, 0x02, 0x80, 0x00, 0x00, 0x02, 0xb3, 0x54, 0x00, 0x18, 0x00, 0x06, 0x20, 0x03, 0x00, 0x00,
	0x00, 0x03, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01, 0x44, 0x73, 0x00, 0x24, 0x00, 0x06,
	0x20, 0x03, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01, 0x9c, 0x11,
	0x00, 0x24, 0x00, 0x06, 0x20, 0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00,
	0x00, 0x01, 0xcd, 0xba, 0x00, 0x24, 0x00, 0x06, 0x20, 0x03, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02,
	0x02, 0x02, 0x80, 0x00, 0x00, 0x01, 0xef, 0xd7, 0x00, 0x24, 0x00, 0x05, 0x00, 0x08, 0x00, 0x00,
	0x00, 0x05, 0x02, 0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x01, 0x54, 0x33, 0x00, 0x2c,
}

func TestPacketOSPF3LSAck(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPF3LSAck, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv6, LayerTypeOSPF}, t)
	if got, ok := p.Layer(LayerTypeOSPF).(*OSPFv3); ok {
		want := &OSPFv3{
			OSPF: OSPF{
				Version:      3,
				Type:         OSPFLinkStateAcknowledgment,
				PacketLength: 136,
				RouterID:     0x1010101,
				AreaID:       1,
				Checksum:     0x9d2c,
				Content: []LSAheader{
					LSAheader{
						LSAge:       5,
						LSType:      0x2001,
						LinkStateID: 0x00000000,
						AdvRouter:   0x02020202,
						LSSeqNumber: 0x80000002,
						LSChecksum:  0xb354,
						Length:      24,
					},
					LSAheader{
						LSAge:       6,
						LSType:      0x2003,
						LinkStateID: 0x00000003,
						AdvRouter:   0x02020202,
						LSSeqNumber: 0x80000001,
						LSChecksum:  0x4473,
						Length:      36,
					},
					LSAheader{
						LSAge:       6,
						LSType:      0x2003,
						LinkStateID: 0x00000002,
						AdvRouter:   0x02020202,
						LSSeqNumber: 0x80000001,
						LSChecksum:  0x9c11,
						Length:      36,
					},
					LSAheader{
						LSAge:       6,
						LSType:      0x2003,
						LinkStateID: 0x00000001,
						AdvRouter:   0x02020202,
						LSSeqNumber: 0x80000001,
						LSChecksum:  0xcdba,
						Length:      36,
					},
					LSAheader{
						LSAge:       6,
						LSType:      0x2003,
						LinkStateID: 0x00000000,
						AdvRouter:   0x02020202,
						LSSeqNumber: 0x80000001,
						LSChecksum:  0xefd7,
						Length:      36,
					},
					LSAheader{
						LSAge:       5,
						LSType:      0x0008,
						LinkStateID: 0x00000005,
						AdvRouter:   0x02020202,
						LSSeqNumber: 0x80000001,
						LSChecksum:  0x5433,
						Length:      44,
					},
				},
			},
			Instance: 0,
			Reserved: 0,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("OSPF packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No OSPF layer type found in packet")
	}
}

var testPacketOSPFInvalidLSA = []byte{
	0x5c, 0xfa, 0x00, 0x00, 0xfa, 0x6c, 0xbd, 0xe4, 0x19, 0x72, 0x1d, 0x1f,
	0x08, 0x00, 0x45, 0x00, 0x00, 0xad, 0x00, 0x00, 0x40, 0x00, 0x40, 0x59,
	0x6e, 0xef, 0x6b, 0x96, 0x61, 0x11, 0xb4, 0x96, 0xc0, 0xa8, 0x02, 0x04,
	0x00, 0xa2, 0x80, 0x00, 0x01, 0x1f, 0x08, 0x00, 0x45, 0x00, 0x6f, 0x76,
	0x65, 0x72, 0x66, 0x6c, 0x7f, 0xff, 0x12, 0x12, 0x00, 0x5a, 0xf6, 0x73,
	0xa2, 0xba, 0x81, 0x90, 0x00, 0x01, 0x40, 0x6f, 0x77, 0x20, 0x6f, 0x6e,
	0x20, 0x63, 0x68, 0x61, 0x72, 0x61, 0x63, 0x74, 0x00, 0x00, 0x00, 0x01,
	0x96, 0x20, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x20, 0x00, 0x6e, 0x00, 0x6f,
	0x77,
}

func TestPacketOSPFInvalidLSA(t *testing.T) {
	p := gopacket.NewPacket(testPacketOSPFInvalidLSA, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() == nil {
		t.Error("Bad packet decoded successfully")
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, gopacket.LayerTypeDecodeFailure}, t)
}

// TestOSPFShortLSABody checks that an LSA whose length covers the header but not
// the body of its type is rejected, both at the end of the packet and in front
// of further bytes. DecodeFromBytes is called directly, so a panic fails the test.
func TestOSPFShortLSABody(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint8
		lstype  uint16
		minLen  int
	}{
		{"RouterLSAV2", 2, RouterLSAtypeV2, 24},
		{"NetworkLSAV2", 2, NetworkLSAtypeV2, 24},
		{"ASExternalLSAV2", 2, ASExternalLSAtypeV2, 36},
		{"NSSALSAV2", 2, NSSALSAtypeV2, 36},
		{"RouterLSA", 3, RouterLSAtype, 24},
		{"NetworkLSA", 3, NetworkLSAtype, 24},
		{"InterAreaPrefixLSA", 3, InterAreaPrefixLSAtype, 28},
		{"InterAreaRouterLSA", 3, InterAreaRouterLSAtype, 32},
		{"ASExternalLSA", 3, ASExternalLSAtype, 28},
		{"NSSALSA", 3, NSSALSAtype, 28},
		{"LinkLSA", 3, LinkLSAtype, 44},
		{"IntraAreaPrefixLSA", 3, IntraAreaPrefixLSAtype, 32},
	} {
		decode := func(lsalength, trailing int, fill byte) error {
			hdrLen := 20 // OSPFv3 header and number of LSAs
			var layer gopacket.DecodingLayer = &OSPFv3{}
			if tc.version == 2 {
				hdrLen = 28
				layer = &OSPFv2{}
			}
			data := make([]byte, hdrLen+lsalength+trailing)
			data[0], data[1] = tc.version, uint8(OSPFLinkStateUpdate)
			binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
			binary.BigEndian.PutUint32(data[hdrLen-4:hdrLen], 1)
			lsa := data[hdrLen:]
			binary.BigEndian.PutUint16(lsa[2:4], tc.lstype)
			binary.BigEndian.PutUint16(lsa[18:20], uint16(lsalength))
			for i := 20; i < len(lsa); i++ {
				lsa[i] = fill
			}
			return layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
		}
		for _, trailing := range []int{0, 100} {
			for lsalength := 20; lsalength < tc.minLen; lsalength++ {
				if err := decode(lsalength, trailing, 0); err == nil {
					t.Errorf("%s: length %d with %d trailing bytes decoded successfully", tc.name, lsalength, trailing)
				}
			}
			if err := decode(tc.minLen, trailing, 0); err != nil {
				t.Errorf("%s: length %d with %d trailing bytes: %v", tc.name, tc.minLen, trailing, err)
			}
			// Every flag set and the largest counts and prefix lengths.
			for lsalength := 20; lsalength < 128; lsalength++ {
				decode(lsalength, trailing, 0xff)
			}
		}
	}
}

func BenchmarkDecodePacketPacket4(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketOSPF3LSAck, LinkTypeEthernet, gopacket.NoCopy)
	}
}

// TestOSPFIntraAreaPrefixTwoPrefixes checks that every prefix of a valid
// Intra-Area-Prefix LSA is decoded: each takes 4 bytes plus its address
// prefix in 32 bit words (RFC 5340 A.4.1), not 4 bytes plus its bit length.
func TestOSPFIntraAreaPrefixTwoPrefixes(t *testing.T) {
	const lsaLength = 20 + 12 + 2*(4+8)

	data := make([]byte, lsaLength)
	binary.BigEndian.PutUint16(data[18:20], lsaLength)
	binary.BigEndian.PutUint16(data[20:22], 2) // number of prefixes
	for i, off := range []int{32, 44} {
		data[off] = 64 // prefix length in bits
		binary.BigEndian.PutUint16(data[off+2:off+4], uint16(10+i))
		for j := 0; j < 8; j++ {
			data[off+4+j] = byte(i + 1)
		}
	}

	content, err := extractLSAInformation(IntraAreaPrefixLSAtype, lsaLength, data)
	if err != nil {
		t.Fatal("Unexpected error:", err)
	}
	prefixes := content.(IntraAreaPrefixLSA).Prefixes
	if len(prefixes) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(prefixes))
	}
	for i, p := range prefixes {
		want := []byte{byte(i + 1), byte(i + 1), byte(i + 1), byte(i + 1), byte(i + 1), byte(i + 1), byte(i + 1), byte(i + 1)}
		if p.Metric != uint16(10+i) || !reflect.DeepEqual(p.AddressPrefix, want) {
			t.Errorf("prefix %d: got metric %d, address %v", i, p.Metric, p.AddressPrefix)
		}
	}
}

// ospfv3LSA returns an OSPFv3 LSA header of the given type and length,
// followed by body.
func ospfv3LSA(lstype uint16, body []byte) []byte {
	lsa := make([]byte, 20, 20+len(body))
	binary.BigEndian.PutUint16(lsa[2:4], lstype)
	binary.BigEndian.PutUint16(lsa[18:20], uint16(20+len(body)))
	return append(lsa, body...)
}

// TestOSPFLinkLSATwoPrefixes checks that every prefix of a Link-LSA is
// decoded: each takes 4 bytes plus its address prefix in 32 bit words
// (RFC 5340 A.4.9), not 4 bytes plus its byte length.
func TestOSPFLinkLSATwoPrefixes(t *testing.T) {
	body := make([]byte, 24)                                 // priority/options, link local address
	binary.BigEndian.PutUint32(body[20:24], 2)               // number of prefixes
	body = append(body, 48, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0) // /48, 6 bytes padded to 8
	body = append(body, 64, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2) // /64

	lsa := ospfv3LSA(LinkLSAtype, body)
	content, err := extractLSAInformation(LinkLSAtype, uint16(len(lsa)), lsa)
	if err != nil {
		t.Fatal("Unexpected error:", err)
	}
	prefixes := content.(LinkLSA).Prefixes
	if len(prefixes) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(prefixes))
	}
	if prefixes[0].PrefixLength != 48 || !bytes.Equal(prefixes[0].AddressPrefix, []byte{1, 1, 1, 1, 1, 1}) {
		t.Errorf("prefix 0: got /%d %v", prefixes[0].PrefixLength, prefixes[0].AddressPrefix)
	}
	if prefixes[1].PrefixLength != 64 || !bytes.Equal(prefixes[1].AddressPrefix, []byte{2, 2, 2, 2, 2, 2, 2, 2}) {
		t.Errorf("prefix 1: got /%d %v", prefixes[1].PrefixLength, prefixes[1].AddressPrefix)
	}
}

// TestOSPFASExternalLSAForwardingAddress checks that the forwarding address
// of an AS-External-LSA follows the address prefix padded to 32 bits
// (RFC 5340 A.4.7).
func TestOSPFASExternalLSAForwardingAddress(t *testing.T) {
	body := []byte{0x02, 0, 0, 10} // F bit, metric 10
	body = append(body, 48, 0, 0, 0)
	body = append(body, 1, 1, 1, 1, 1, 1, 0, 0) // /48 prefix, padded
	fwd := bytes.Repeat([]byte{0xfe}, 16)
	body = append(body, fwd...)

	lsa := ospfv3LSA(ASExternalLSAtype, body)
	content, err := extractLSAInformation(ASExternalLSAtype, uint16(len(lsa)), lsa)
	if err != nil {
		t.Fatal("Unexpected error:", err)
	}
	got := content.(ASExternalLSA)
	if !bytes.Equal(got.AddressPrefix, []byte{1, 1, 1, 1, 1, 1}) {
		t.Errorf("address prefix: got %v", got.AddressPrefix)
	}
	if !bytes.Equal(got.ForwardingAddress, fwd) {
		t.Errorf("forwarding address: got %v, want %v", got.ForwardingAddress, fwd)
	}
}

// TestOSPFRouterLSAV2TOSMetrics checks that a Router-LSA link carrying TOS
// metrics (RFC 2328 A.4.2) is stepped over, so the links after it decode and
// the LSA is not rejected as short.
func TestOSPFRouterLSAV2TOSMetrics(t *testing.T) {
	body := []byte{0, 0, 0, 2}                                     // flags, 2 links
	body = append(body, 10, 0, 0, 1, 255, 255, 255, 0, 3, 1, 0, 5) // link 1, 1 TOS entry, metric 5
	body = append(body, 2, 0, 0, 20)                               // TOS 2 metric 20
	body = append(body, 10, 0, 0, 2, 255, 255, 255, 0, 3, 0, 0, 7) // link 2, metric 7

	lsa := make([]byte, 20, 20+len(body))
	lsa[3] = RouterLSAtypeV2
	binary.BigEndian.PutUint16(lsa[18:20], uint16(20+len(body)))
	lsa = append(lsa, body...)

	content, err := extractLSAInformation(RouterLSAtypeV2, uint16(len(lsa)), lsa)
	if err != nil {
		t.Fatal("Unexpected error:", err)
	}
	routers := content.(RouterLSAV2).Routers
	if len(routers) != 2 {
		t.Fatalf("got %d links, want 2: %+v", len(routers), routers)
	}
	if routers[0].Metric != 5 || routers[1].Metric != 7 || routers[1].LinkID != 0x0a000002 {
		t.Errorf("links decoded wrong: %+v", routers)
	}
}

// TestOSPFPacketLengthPastData: OSPFv2/v3 bounded their neighbour, LSA header
// and LS request loops with the wire PacketLength field without comparing it
// to the buffer, compared it in uint16 so 0xFFFF never ended the loop, and
// read the per-type fixed fields behind only the common header check.
func TestOSPFPacketLengthPastData(t *testing.T) {
	// version, type, PacketLength over a buffer of size bytes
	mk := func(version, typ uint8, pktLen uint16, size int) []byte {
		b := make([]byte, size)
		b[0], b[1] = version, typ
		binary.BigEndian.PutUint16(b[2:4], pktLen)
		return b
	}

	cases := []struct {
		name string
		data []byte
	}{
		// Complete Hello with no neighbours whose PacketLength claims one.
		{"OSPFv2/hello-length-past-data", mk(2, uint8(OSPFHello), 48, 44)},
		// 24-byte header only, PacketLength honest, fixed fields missing.
		{"OSPFv2/hello-header-only", mk(2, uint8(OSPFHello), 24, 24)},
		{"OSPFv2/dbdesc-header-only", mk(2, uint8(OSPFDatabaseDescription), 24, 24)},
		{"OSPFv2/lsu-header-only", mk(2, uint8(OSPFLinkStateUpdate), 24, 24)},
		// PacketLength 0xFFFF wraps the uint16 loop comparison.
		{"OSPFv2/lsr-length-wrap", mk(2, uint8(OSPFLinkStateRequest), 0xFFFF, 24)},
		{"OSPFv2/lsack-length-wrap", mk(2, uint8(OSPFLinkStateAcknowledgment), 0xFFFF, 0xFFFF)},
		{"OSPFv3/hello-length-past-data", mk(3, uint8(OSPFHello), 40, 36)},
		{"OSPFv3/hello-header-only", mk(3, uint8(OSPFHello), 16, 16)},
		{"OSPFv3/dbdesc-header-only", mk(3, uint8(OSPFDatabaseDescription), 16, 16)},
		{"OSPFv3/lsu-header-only", mk(3, uint8(OSPFLinkStateUpdate), 16, 16)},
		{"OSPFv3/lsr-length-wrap", mk(3, uint8(OSPFLinkStateRequest), 0xFFFF, 16)},
		{"OSPFv3/lsack-length-wrap", mk(3, uint8(OSPFLinkStateAcknowledgment), 0xFFFF, 0xFFFF)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decoder panicked on crafted input: %v", r)
				}
			}()
			var l gopacket.DecodingLayer = &OSPFv2{}
			if c.data[0] == 3 {
				l = &OSPFv3{}
			}
			_ = l.DecodeFromBytes(c.data, gopacket.NilDecodeFeedback)
		})
	}

	// A Hello cut short by the snap length decodes what is there and is
	// marked truncated.
	hello := mk(2, uint8(OSPFHello), 52, 48)
	var ospf OSPFv2
	df := &testDecodeFeedback{}
	if err := ospf.DecodeFromBytes(hello, df); err != nil {
		t.Fatalf("truncated Hello: %v", err)
	}
	if n := len(ospf.Content.(HelloPkgV2).NeighborID); n != 1 || !df.truncated {
		t.Errorf("truncated Hello: got %d neighbours, truncated %v; want 1, true", n, df.truncated)
	}
}

// testDecodeFeedback records whether SetTruncated was called.
type testDecodeFeedback struct{ truncated bool }

func (d *testDecodeFeedback) SetTruncated() { d.truncated = true }
