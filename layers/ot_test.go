// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"io"
	"os"
	"testing"

	"github.com/gopacket/gopacket"
)

// otEtherTypes are the EtherTypes RegisterOTDecoders claims.
var otEtherTypes = []EthernetType{
	EthernetTypeProfinet,
	EthernetTypeEtherCAT,
	EthernetTypeGOOSE,
	EthernetTypeSV,
	EthernetTypePTP,
}

// otCapture is a committed capture and the layer every frame of it, or
// at least one, must reach once RegisterOTDecoders has run.
type otCapture struct {
	file  string
	layer gopacket.LayerType
}

// otCaptures holds one or more real captures per protocol. Captures
// whose peers split a TPKT header from its body across TCP segments
// (iec61850_mms.pcap) are left out: those need stream reassembly.
var otCaptures = []otCapture{
	{"dnp3.pcap", LayerTypeDNP3},
	{"iec104.pcap", LayerTypeIEC104},
	{"s7comm-read-var.pcap", LayerTypeS7Comm},
	{"s7commplus-1511-opc.pcap", LayerTypeS7CommPlus},
	{"bacnet-bbmd.pcap", LayerTypeBACnetAPDU},
	{"opcua-mainloop.pcap", LayerTypeOPCUA},
	{"ptpv2.pcap", LayerTypePTP},
	{"profinet-dcp.pcap", LayerTypeProfinetDCP},
	{"ethercat.pcap", LayerTypeEtherCAT},
	{"iec61850_goose_vlan.pcap", LayerTypeGOOSE},
	{"iec61850_goose_abb.pcap", LayerTypeGOOSE},
	{"iec61850_sv_92le.pcap", LayerTypeSV},
	{"iec61850_mms_libiec61850.pcap", LayerTypeMMS},
	{"iec61850_mms_reports_goose.pcap", LayerTypeMMS},
	{"iec61850_mms_siemens.pcap", LayerTypeMMS},
}

// withOTDecoders runs RegisterOTDecoders for one test and puts the port
// and EtherType tables back afterwards, so tests that check the default
// (unregistered) state keep passing whatever order tests run in.
func withOTDecoders(t *testing.T) {
	t.Helper()

	tcpOverride, udpOverride := tcpPortLayerTypeOverride, udpPortLayerTypeOverride
	tcpTypes := copyTCPPortTypes()
	udpTypes := copyUDPPortTypes()
	ether := make(map[EthernetType]EnumMetadata, len(otEtherTypes))
	for _, et := range otEtherTypes {
		ether[et] = EthernetTypeMetadata[et]
	}

	t.Cleanup(func() {
		tcpPortLayerTypeOverride, udpPortLayerTypeOverride = tcpOverride, udpOverride
		tcpPortLayerType, udpPortLayerType = tcpTypes, udpTypes
		for et, md := range ether {
			EthernetTypeMetadata[et] = md
		}
	})

	RegisterOTDecoders()
	RegisterOTDecoders()
}

func copyTCPPortTypes() map[TCPPort]gopacket.LayerType {
	m := make(map[TCPPort]gopacket.LayerType, len(tcpPortLayerType))
	for k, v := range tcpPortLayerType {
		m[k] = v
	}
	return m
}

func copyUDPPortTypes() map[UDPPort]gopacket.LayerType {
	m := make(map[UDPPort]gopacket.LayerType, len(udpPortLayerType))
	for k, v := range udpPortLayerType {
		m[k] = v
	}
	return m
}

// readOTFrames returns every frame of a classic pcap in testdata and
// the file's link type.
func readOTFrames(t *testing.T, name string) ([][]byte, LinkType) {
	t.Helper()

	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	r, err := newSimplePcapReader(f)
	if err != nil {
		t.Fatal(err)
	}

	var frames [][]byte
	for {
		data, err := r.readPacketData()
		if err == io.EOF {
			return frames, r.linkType
		}
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, data)
	}
}

// TestRegisterOTDecoders decodes real captures from the Ethernet header
// down through the public entry point alone: no test-only registration.
func TestRegisterOTDecoders(t *testing.T) {
	withOTDecoders(t)

	opts := gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true}
	for _, c := range otCaptures {
		frames, link := readOTFrames(t, c.file)
		hits := 0
		for _, data := range frames {
			p := gopacket.NewPacket(data, link, opts)
			if p.Layer(c.layer) != nil {
				hits++
			}
		}

		if hits == 0 {
			t.Errorf("%s: no frame reached %v", c.file, c.layer)
			continue
		}
		t.Logf("%s: %d/%d frames reached %v", c.file, hits, len(frames), c.layer)
	}
}

// TestOTDecodersRestored checks withOTDecoders really puts the tables
// back, which the default-state tests of each protocol depend on.
func TestOTDecodersRestored(t *testing.T) {
	// DecodeWith holds a func, which can't be compared; nil-ness is
	// what the default-state tests look at.
	wasSet := EthernetTypeMetadata[EthernetTypeProfinet].DecodeWith != nil
	t.Run("registered", func(t *testing.T) {
		withOTDecoders(t)
		if EthernetTypeMetadata[EthernetTypeProfinet].DecodeWith == nil {
			t.Fatal("PROFINET not registered")
		}
	})

	if isSet := EthernetTypeMetadata[EthernetTypeProfinet].DecodeWith != nil; isSet != wasSet {
		t.Fatal("EtherType table not restored")
	}
}
