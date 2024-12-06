// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapgo

import (
	"bytes"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestNgWriteSimple(t *testing.T) {
	buffer := &bytes.Buffer{}

	w, err := NewNgWriter(buffer, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal("Opening file failed with: ", err)
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Unix(0, 0).UTC(),
		Length:         len(ngPacketSource[0]),
		CaptureLength:  len(ngPacketSource[0]),
		InterfaceIndex: 0,
	}
	err = w.WritePacket(ci, ngPacketSource[0])
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.Flush()
	if err != nil {
		t.Fatal("Couldn't flush buffer", err)
	}

	interf := DefaultNgInterface
	interf.LinkType = layers.LinkTypeEthernet

	test := ngFileReadTest{
		testContents: bytes.NewReader(buffer.Bytes()),
		linkType:     layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: DefaultNgWriterOptions.SectionInfo,
				ifaces: []NgInterface{
					interf,
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci:   ci,
			},
		},
	}

	ngRunFileReadTest(test, "", false, t)
}

func TestNgWriteComplex(t *testing.T) {
	test := ngFileReadTest{
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Comment: "A test",
				},
				ifaces: []NgInterface{
					{
						Name:                "in0",
						Comment:             "test0",
						Description:         "some test interface",
						LinkType:            layers.LinkTypeEthernet,
						TimestampResolution: 3,
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(1519128000, 195312500).UTC(),
							StartTime:       time.Unix(1519128000-100, 195312500).UTC(),
							EndTime:         time.Unix(1519128000, 195312500).UTC(),
							PacketsReceived: 100,
							PacketsDropped:  1,
						},
					},
					{
						Name:            "null0",
						Description:     "some test interface",
						Filter:          "none",
						OS:              "not needed",
						LinkType:        layers.LinkTypeEthernet,
						TimestampOffset: 100,
						Statistics: NgInterfaceStatistics{
							LastUpdate: time.Unix(1519128000, 195312500).UTC(),
						},
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-900, 195312500).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[4],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-800, 195312500).UTC(),
					Length:         len(ngPacketSource[4]),
					CaptureLength:  len(ngPacketSource[4]),
					InterfaceIndex: 1,
				},
			},
			{
				data: ngPacketSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-500, 195312500).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  len(ngPacketSource[1]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-300, 195312500).UTC(),
					Length:         len(ngPacketSource[2]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-200, 195312500).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  len(ngPacketSource[3]),
					InterfaceIndex: 0,
				},
			},
		},
	}

	buffer := &bytes.Buffer{}

	options := NgWriterOptions{
		SectionInfo: test.sections[0].sectionInfo,
	}

	w, err := NewNgWriterInterface(buffer, test.sections[0].ifaces[0], options)
	if err != nil {
		t.Fatal("Opening file failed with: ", err)
	}

	packets := test.packets
	err = w.WritePacket(packets[0].ci, packets[0].data)
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	id, err := w.AddInterface(test.sections[0].ifaces[1])
	if err != nil {
		t.Fatal("Couldn't add interface", err)
	}
	if id != 1 {
		t.Fatalf("Expected interface id 1, but got %d", id)
	}
	err = w.WritePacket(packets[1].ci, packets[1].data)
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.WriteInterfaceStats(1, test.sections[0].ifaces[1].Statistics)
	if err != nil {
		t.Fatal("Couldn't write interface stats", err)
	}
	err = w.WritePacket(packets[2].ci, packets[2].data)
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.WritePacket(packets[3].ci, packets[3].data)
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.WritePacket(packets[4].ci, packets[4].data)
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.WriteInterfaceStats(0, test.sections[0].ifaces[0].Statistics)
	if err != nil {
		t.Fatal("Couldn't write interface stats", err)
	}

	err = w.Flush()
	if err != nil {
		t.Fatal("Couldn't flush buffer", err)
	}

	// writer fixes resolution to 9
	test.sections[0].ifaces[0].TimestampResolution = 9
	test.sections[0].ifaces[1].TimestampResolution = 9

	// compensate for offset on interface 1
	test.sections[0].ifaces[1].Statistics.LastUpdate = test.sections[0].ifaces[1].Statistics.LastUpdate.Add(100 * time.Second)
	test.packets[1].ci.Timestamp = test.packets[1].ci.Timestamp.Add(100 * time.Second)

	test.testContents = bytes.NewReader(buffer.Bytes())

	ngRunFileReadTest(test, "", false, t)
}

func TestNgWritePacketWithOptions(t *testing.T) {
	buffer := &bytes.Buffer{}

	w, err := NewNgWriter(buffer, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("init writer failed: %+v", err)
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Unix(0, 0).UTC(),
		Length:         len(ngPacketSource[0]),
		CaptureLength:  len(ngPacketSource[0]),
		InterfaceIndex: 0,
	}
	uint64V := func(v uint64) *uint64 { return &v }
	uint32V := func(v uint32) *uint32 { return &v }

	wOpts := NgPacketOptions{
		Comments: []string{
			"this is a comment",
			"foobar",
		},
		Flags: &NgEpbFlags{
			Direction: NgEpbFlagDirectionInbound,
			Reception: NgEpbFlagReceptionTypeBroadcast,
			FCSLen:    NewNgEpbFlagFCSLength(10),
			LinkLayerErr: NgEpbFlagLinkLayerDependentErrorSymbol | NgEpbFlagLinkLayerDependentErrorPreamble |
				NgEpbFlagLinkLayerDependentErrorStartFrameDelimiter | NgEpbFlagLinkLayerDependentErrorUnalignedFrame |
				NgEpbFlagLinkLayerDependentErrorInterFrameGap | NgEpbFlagLinkLayerDependentErrorPacketTooShort |
				NgEpbFlagLinkLayerDependentErrorPacketTooLong | NgEpbFlagLinkLayerDependentErrorCRC,
		},
		Hashes: []NgEpbHash{
			{
				Algorithm: NgEpbHashAlgorithmMD5,
				Hash:      []byte{0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72},
			},
			{
				Algorithm: NgEpbHashAlgorithmCRC32,
				Hash:      []byte{0x90, 0x01, 0x50, 0x98},
			},
		},
		DropCount: uint64V(0x02),
		PacketID:  uint64V(0x1234567890abcdef),
		Queue:     uint32V(0x01),
		Verdicts: []NgEpbVerdict{
			{
				Type: NgEpbVerdictTypeLinuxeBPFXDP,
				Data: []byte{0, 0, 0, 0, 0, 0, 0, 0x01},
			},
			{
				Type: NgEpbVerdictTypeLinuxeBPFTC,
				Data: []byte{0, 0, 0, 0, 0, 0, 0, 0x02},
			},
		},
	}

	err = w.WritePacketWithOptions(ci, ngPacketSource[0], wOpts)
	if err != nil {
		t.Fatalf("Couldn't write packet: %+v", err)
	}
	err = w.Flush()
	if err != nil {
		t.Fatalf("Couldn't flush buffer: %+v", err)
	}
}

type ngDevNull struct{}

func (w *ngDevNull) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func BenchmarkNgWritePacket(b *testing.B) {
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(0x01020304, 0xAA*1000),
		Length:        0xABCD,
		CaptureLength: 10,
	}
	data := []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	w, err := NewNgWriter(&ngDevNull{}, layers.LinkTypeEthernet)
	if err != nil {
		b.Fatal("Failed creating writer:", err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w.WritePacket(ci, data)
	}
}
