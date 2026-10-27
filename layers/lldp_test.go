// Copyright 2020 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.
package layers

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// testPacketLLDP is the packet:
//
//	13:03:20.982430 LLDP, length 222: Switch1
//		0x0000:  0180 c200 000e 001b 1b02 e61f 88cc 0208  ................
//		0x0010:  0773 7769 7463 6831 0409 0770 6f72 742d  .switch1...port-
//		0x0020:  3030 3106 0200 1408 2d53 6965 6d65 6e73  001.....-Siemens
//		0x0030:  2c20 5349 4d41 5449 4320 4e45 542c 2045  ,.SIMATIC.NET,.E
//		0x0040:  7468 6572 6e65 7420 5377 6974 6368 2050  thernet.Switch.P
//		0x0050:  6f72 7420 3031 0a07 5377 6974 6368 310c  ort.01..Switch1.
//		0x0060:  4c53 6965 6d65 6e73 2c20 5349 4d41 5449  LSiemens,.SIMATI
//		0x0070:  4320 4e45 542c 2053 4341 4c41 4e43 4520  C.NET,.SCALANCE.
//		0x0080:  5832 3132 2d32 2c20 3647 4b35 2032 3132  X212-2,.6GK5.212
//		0x0090:  2d32 4242 3030 2d32 4141 332c 2048 573a  -2BB00-2AA3,.HW:
//		0x00a0:  2037 2c20 4657 3a20 5634 2e30 320e 0400  .7,.FW:.V4.02...
//		0x00b0:  8000 8010 1405 018d 5100 be02 0000 0001  ........Q.......
//		0x00c0:  082b 0601 0401 81c0 6efe 0800 0ecf 0200  .+......n.......
//		0x00d0:  0000 00fe 0a00 0ecf 0500 1b1b 02e6 1efe  ................
//		0x00e0:  0900 120f 0103 6c00 0010 0000            ......l.....
var testPacketLLDP = []byte{
	0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, 0x00, 0x1b, 0x1b, 0x02, 0xe6, 0x1f, 0x88, 0xcc, 0x02, 0x08,
	0x07, 0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x31, 0x04, 0x09, 0x07, 0x70, 0x6f, 0x72, 0x74, 0x2d,
	0x30, 0x30, 0x31, 0x06, 0x02, 0x00, 0x14, 0x08, 0x2d, 0x53, 0x69, 0x65, 0x6d, 0x65, 0x6e, 0x73,
	0x2c, 0x20, 0x53, 0x49, 0x4d, 0x41, 0x54, 0x49, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x2c, 0x20, 0x45,
	0x74, 0x68, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x20, 0x50,
	0x6f, 0x72, 0x74, 0x20, 0x30, 0x31, 0x0a, 0x07, 0x53, 0x77, 0x69, 0x74, 0x63, 0x68, 0x31, 0x0c,
	0x4c, 0x53, 0x69, 0x65, 0x6d, 0x65, 0x6e, 0x73, 0x2c, 0x20, 0x53, 0x49, 0x4d, 0x41, 0x54, 0x49,
	0x43, 0x20, 0x4e, 0x45, 0x54, 0x2c, 0x20, 0x53, 0x43, 0x41, 0x4c, 0x41, 0x4e, 0x43, 0x45, 0x20,
	0x58, 0x32, 0x31, 0x32, 0x2d, 0x32, 0x2c, 0x20, 0x36, 0x47, 0x4b, 0x35, 0x20, 0x32, 0x31, 0x32,
	0x2d, 0x32, 0x42, 0x42, 0x30, 0x30, 0x2d, 0x32, 0x41, 0x41, 0x33, 0x2c, 0x20, 0x48, 0x57, 0x3a,
	0x20, 0x37, 0x2c, 0x20, 0x46, 0x57, 0x3a, 0x20, 0x56, 0x34, 0x2e, 0x30, 0x32, 0x0e, 0x04, 0x00,
	0x80, 0x00, 0x80, 0x10, 0x14, 0x05, 0x01, 0x8d, 0x51, 0x00, 0xbe, 0x02, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xc0, 0x6e, 0xfe, 0x08, 0x00, 0x0e, 0xcf, 0x02, 0x00,
	0x00, 0x00, 0x00, 0xfe, 0x0a, 0x00, 0x0e, 0xcf, 0x05, 0x00, 0x1b, 0x1b, 0x02, 0xe6, 0x1e, 0xfe,
	0x09, 0x00, 0x12, 0x0f, 0x01, 0x03, 0x6c, 0x00, 0x00, 0x10, 0x00, 0x00,
}

func TestPacketLLDP(t *testing.T) {
	p := gopacket.NewPacket(testPacketLLDP, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeLinkLayerDiscovery, LayerTypeLinkLayerDiscoveryInfo}, t)
	if got, ok := p.Layer(LayerTypeLinkLayerDiscoveryInfo).(*LinkLayerDiscoveryInfo); ok {
		want := &LinkLayerDiscoveryInfo{
			PortDescription: "Siemens, SIMATIC NET, Ethernet Switch Port 01",
			SysName:         "Switch1",
			SysDescription:  "Siemens, SIMATIC NET, SCALANCE X212-2, 6GK5 212-2BB00-2AA3, HW: 7, FW: V4.02",
			SysCapabilities: LLDPSysCapabilities{
				SystemCap:  LLDPCapabilities{StationOnly: true},
				EnabledCap: LLDPCapabilities{StationOnly: true},
			},
			MgmtAddress: LLDPMgmtAddress{
				Subtype:          0x1,
				Address:          []uint8{0x8d, 0x51, 0x0, 0xbe},
				InterfaceSubtype: 0x2,
				InterfaceNumber:  0x1,
				OID:              "+\x06\x01\x04\x01\x81\xc0n",
			},
			OrgTLVs: []LLDPOrgSpecificTLV{
				{OUI: 0xecf, SubType: 0x2, Info: []uint8{0x0, 0x0, 0x0, 0x0}},
				{OUI: 0xecf, SubType: 0x5, Info: []uint8{0x0, 0x1b, 0x1b, 0x2, 0xe6, 0x1e}},
				{OUI: 0x120f, SubType: 0x1, Info: []uint8{0x3, 0x6c, 0x0, 0x0, 0x10}},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("LLDP Info packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No LLDP Info layer type found in packet")
	}
}

func TestLLDPMandatoryTLVs(t *testing.T) {
	tlv := func(typ LLDPTLVType, value ...byte) []byte {
		header := uint16(typ)<<9 | uint16(len(value))
		return append([]byte{byte(header >> 8), byte(header)}, value...)
	}
	chassis := tlv(LLDPTLVChassisID, byte(LLDPChassisIDSubTypeMACAddr), 0, 0x11, 0x22, 0x33, 0x44, 0x55)
	port := tlv(LLDPTLVPortID, byte(LLDPPortIDSubtypeIfaceName), 'E', 't', 'h', '1')
	ttl := tlv(LLDPTLVTTL, 0, 120)
	shutdown := tlv(LLDPTLVTTL, 0, 0)
	name := tlv(LLDPTLVSysName, 's', 'w', '1')
	end := tlv(LLDPTLVEnd)

	tests := []struct {
		name          string
		tlvs          [][]byte
		wantError     bool
		wantTruncated bool
		wantTTL       uint16
		wantSysName   string
	}{
		{name: "mandatory TLVs with End", tlvs: [][]byte{chassis, port, ttl, end}, wantTTL: 120},
		{name: "optional TLV with End", tlvs: [][]byte{chassis, port, ttl, name, end}, wantTTL: 120, wantSysName: "sw1"},
		{name: "mandatory TLVs without End", tlvs: [][]byte{chassis, port, ttl}, wantTTL: 120},
		{name: "optional TLV without End", tlvs: [][]byte{chassis, port, ttl, name}, wantTTL: 120, wantSysName: "sw1"},
		{name: "shutdown with End", tlvs: [][]byte{chassis, port, shutdown, end}},
		{name: "shutdown without End", tlvs: [][]byte{chassis, port, shutdown}},
		{name: "data after End", tlvs: [][]byte{chassis, port, ttl, end, shutdown, {0xff}}, wantTTL: 120},
		{name: "port before chassis", tlvs: [][]byte{port, chassis, ttl, end}, wantError: true},
		{name: "TTL before port", tlvs: [][]byte{chassis, ttl, port, end}, wantError: true},
		{name: "port and TTL before chassis", tlvs: [][]byte{port, ttl, chassis, end}, wantError: true},
		{name: "TTL before chassis", tlvs: [][]byte{ttl, chassis, port, end}, wantError: true},
		{name: "mandatory TLVs reversed", tlvs: [][]byte{ttl, port, chassis, end}, wantError: true},
		{name: "optional TLV before chassis", tlvs: [][]byte{name, chassis, port, ttl, end}, wantError: true},
		{name: "optional TLV before port", tlvs: [][]byte{chassis, name, port, ttl, end}, wantError: true},
		{name: "optional TLV before TTL", tlvs: [][]byte{chassis, port, name, ttl, end}, wantError: true},
		{name: "missing chassis", tlvs: [][]byte{port, ttl, name, end}, wantError: true},
		{name: "missing port", tlvs: [][]byte{chassis, ttl, name, end}, wantError: true},
		{name: "missing TTL", tlvs: [][]byte{chassis, port, name, end}, wantError: true},
		{name: "missing TTL without End", tlvs: [][]byte{chassis, port}, wantError: true},
		{name: "empty packet", wantError: true},
		{name: "End before TTL", tlvs: [][]byte{chassis, port, end, ttl}, wantError: true},
		{name: "duplicate chassis", tlvs: [][]byte{chassis, port, ttl, chassis, end}, wantError: true},
		{name: "duplicate port", tlvs: [][]byte{chassis, port, ttl, port, end}, wantError: true},
		{name: "duplicate TTL", tlvs: [][]byte{chassis, port, ttl, shutdown, end}, wantError: true},
		{name: "duplicate chassis after optional TLV", tlvs: [][]byte{chassis, port, ttl, name, chassis, end}, wantError: true},
		{name: "duplicate port after optional TLV", tlvs: [][]byte{chassis, port, ttl, name, port, end}, wantError: true},
		{name: "duplicate TTL after optional TLV", tlvs: [][]byte{chassis, port, ttl, name, shutdown, end}, wantError: true},
		{name: "duplicate TTL without End", tlvs: [][]byte{chassis, port, ttl, shutdown}, wantError: true},
		{name: "short TTL", tlvs: [][]byte{chassis, port, tlv(LLDPTLVTTL, 0), end}, wantError: true},
		{name: "truncated TLV header", tlvs: [][]byte{chassis, port, ttl, {0x0a}}, wantError: true, wantTruncated: true},
		{name: "truncated TLV value", tlvs: [][]byte{chassis, port, ttl, name[:len(name)-1]}, wantError: true, wantTruncated: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Join(tt.tlvs, nil)
			p := gopacket.NewPacket(data, LayerTypeLinkLayerDiscovery, gopacket.Default)
			if got := p.Metadata().Truncated; got != tt.wantTruncated {
				t.Errorf("Truncated = %v, want %v", got, tt.wantTruncated)
			}
			if tt.wantError {
				if p.ErrorLayer() == nil {
					t.Fatal("Malformed LLDPDU decoded without an error")
				}
				if p.Layer(LayerTypeLinkLayerDiscovery) != nil {
					t.Error("Malformed mandatory TLVs produced an LLDP layer")
				}
				return
			}
			if p.ErrorLayer() != nil {
				t.Fatal("Failed to decode LLDPDU:", p.ErrorLayer().Error())
			}
			checkLayers(p, []gopacket.LayerType{LayerTypeLinkLayerDiscovery, LayerTypeLinkLayerDiscoveryInfo}, t)
			lldp := p.Layer(LayerTypeLinkLayerDiscovery).(*LinkLayerDiscovery)
			if lldp.ChassisID.Subtype != LLDPChassisIDSubTypeMACAddr || !bytes.Equal(lldp.ChassisID.ID, chassis[3:]) {
				t.Errorf("Unexpected chassis ID: %+v", lldp.ChassisID)
			}
			if lldp.PortID.Subtype != LLDPPortIDSubtypeIfaceName || string(lldp.PortID.ID) != "Eth1" {
				t.Errorf("Unexpected port ID: %+v", lldp.PortID)
			}
			if lldp.TTL != tt.wantTTL {
				t.Errorf("TTL = %d, want %d", lldp.TTL, tt.wantTTL)
			}
			info := p.Layer(LayerTypeLinkLayerDiscoveryInfo).(*LinkLayerDiscoveryInfo)
			if info.SysName != tt.wantSysName {
				t.Errorf("SysName = %q, want %q", info.SysName, tt.wantSysName)
			}
		})
	}
}

func BenchmarkDecodePacketLLDP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketLLDP, LinkTypeEthernet, gopacket.NoCopy)
	}
}
