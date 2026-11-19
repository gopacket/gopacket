// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const testdataDir = "../../layers/testdata"

// captureCase is a committed capture, a layer and how many PDUs of it
// tshark 4.x decodes, counted as <proto name="..."> elements of
// `tshark -r FILE -T pdml`. That counts PDUs, not frames: one frame may
// carry several (iec104.pcap: 115 APDUs in 64 frames). want differs from
// tshark only where the decoders disagree, never the framing; why says
// how.
type captureCase struct {
	file   string
	layer  gopacket.LayerType
	tshark int
	want   int
	why    string
}

var captureCases = []captureCase{
	// The client sends each TPKT header and body in separate segments.
	{"iec61850_mms.pcap", layers.LayerTypeMMS, 163, 163, ""},
	{"iec61850_mms.pcap", layers.LayerTypeTPKT, 165, 165, ""},
	{"iec61850_mms_libiec61850.pcap", layers.LayerTypeMMS, 5, 5, ""},
	{"iec61850_mms_libiec61850.pcap", layers.LayerTypeTPKT, 8, 8, ""},
	{"iec61850_mms_reports_goose.pcap", layers.LayerTypeMMS, 8, 36,
		"tshark decodes MMS only after seeing the association; 36 is its 38 PRES PDUs less 2 release PDUs"},
	{"iec61850_mms_reports_goose.pcap", layers.LayerTypeTPKT, 42, 40,
		"tshark counts two one-octet keep-alive probes (frames 96, 281) as TPKT continuations"},
	// Large responses span COTP DT segments, joined by otStream.tpkt.
	{"iec61850_mms_siemens.pcap", layers.LayerTypeMMS, 134, 134, ""},
	{"iec61850_mms_siemens.pcap", layers.LayerTypeTPKT, 174, 174, ""},
	{"s7comm-read-var.pcap", layers.LayerTypeS7Comm, 17, 17, ""},
	{"s7comm-download-db1.pcap", layers.LayerTypeS7Comm, 30, 30, ""},
	{"s7comm-blocklist.pcap", layers.LayerTypeS7Comm, 70, 70, ""},
	{"s7comm-blocklist.pcap", layers.LayerTypeTPKT, 115, 115, ""},
	// tshark has no S7comm-plus dissector built in; compare TPKT.
	{"s7commplus-1200-upload.pcap", layers.LayerTypeTPKT, 133, 133, ""},
	{"s7commplus-1511-opc.pcap", layers.LayerTypeTPKT, 29, 29, ""},
	{"dnp3.pcap", layers.LayerTypeDNP3, 93, 93, ""},
	{"dnp3-2.pcap", layers.LayerTypeDNP3, 22, 22, ""},
	{"iec104.pcap", layers.LayerTypeIEC104, 115, 115, ""},
	{"iec104_sq.pcap", layers.LayerTypeIEC104, 4, 4, ""},
	// NULL (loopback) link type.
	{"opcua-mainloop.pcap", layers.LayerTypeOPCUA, 47, 47, ""},
	{"opcua-read.pcap", layers.LayerTypeOPCUA, 18, 18, ""},
	{"opcua-minimal.pcap", layers.LayerTypeOPCUA, 17, 17, ""},
	{"opcua-getendpoints.pcap", layers.LayerTypeOPCUA, 7, 7, ""},
	{"opcua-encrypted.pcap", layers.LayerTypeOPCUA, 14, 14, ""},
	{"opcua-signed.pcap", layers.LayerTypeOPCUA, 10, 10, ""},
	{"modbus.pcap", layers.LayerTypeModbus, 102, 102, ""},
	{"modbus-2.pcap", layers.LayerTypeModbus, 34, 39,
		"frames 91-99: tshark skips 5 exception ADUs sent from port 502 on a connection port 502 opened"},
	{"modbus-3.pcap", layers.LayerTypeModbus, 281, 281, ""},
}

// openTestCapture opens a committed capture.
func openTestCapture(t *testing.T, name string) captureSource {
	t.Helper()
	f, err := os.Open(filepath.Join(testdataDir, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })

	src, err := openFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// reassembledCounts runs the dumper over a capture.
func reassembledCounts(t *testing.T, name string) map[gopacket.LayerType]int {
	t.Helper()
	d := newDumper(io.Discard)
	if err := d.run(openTestCapture(t, name)); err != nil {
		t.Fatal(err)
	}
	return d.counts
}

// perPacketCounts decodes every packet of a capture on its own, TCP
// payload included, as a caller without reassembly would.
func perPacketCounts(t *testing.T, name string) map[gopacket.LayerType]int {
	t.Helper()
	src := openTestCapture(t, name)
	ps := gopacket.NewPacketSource(src, src.LinkType())
	ps.DecodeStreamsAsDatagrams = true
	counts := map[gopacket.LayerType]int{}
	for {
		p, err := ps.NextPacket()
		if errors.Is(err, io.EOF) {
			return counts
		}
		if err != nil {
			t.Fatal(err)
		}

		for _, l := range p.Layers() {
			counts[l.LayerType()]++
		}
	}
}

func TestReassembledPDUCounts(t *testing.T) {
	layers.RegisterOTDecoders()
	for _, tc := range captureCases {
		t.Run(tc.file+"/"+tc.layer.String(), func(t *testing.T) {
			got := reassembledCounts(t, tc.file)[tc.layer]
			per := perPacketCounts(t, tc.file)[tc.layer]
			t.Logf("%-32s %-8v reassembled=%d per-packet=%d tshark=%d %s", tc.file, tc.layer, got, per, tc.tshark, tc.why)
			if got != tc.want {
				t.Errorf("reassembled %d %v PDUs, want %d (tshark %d)", got, tc.layer, tc.want, tc.tshark)
			}
		})
	}
}

func TestNonTCPPerPacket(t *testing.T) {
	layers.RegisterOTDecoders()
	tests := []struct {
		file  string
		layer gopacket.LayerType
	}{
		{"iec61850_goose_abb.pcap", layers.LayerTypeGOOSE},
		{"iec61850_sv_92le.pcap", layers.LayerTypeSV},
		{"ptpv2.pcap", layers.LayerTypePTP},
		{"profinet-dcp.pcap", layers.LayerTypeProfinet},
		{"ethercat.pcap", layers.LayerTypeEtherCAT},
		{"bacnet-vectors.pcap", layers.LayerTypeBACnetAPDU},
	}

	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			got := reassembledCounts(t, tc.file)[tc.layer]
			want := perPacketCounts(t, tc.file)[tc.layer]
			if got == 0 || got != want {
				t.Errorf("dumper decoded %d %v, per packet %d", got, tc.layer, want)
			}
		})
	}
}
