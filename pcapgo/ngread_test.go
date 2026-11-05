// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapgo

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func ngMustDecode(s string) []byte {
	ret, err := hex.DecodeString(s)
	if err != nil {
		log.Panic("Initialization failed")
	}
	return ret
}

var ngPacketSource = [...][]byte{
	ngMustDecode("ffffffffffff000b8201fc4208004500012ca8360000fa11178b00000000ffffffff004400430118591f0101060000003d1d0000000000000000000000000000000000000000000b8201fc4200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501013d0701000b8201fc4232040000000037040103062aff00000000000000"),
	ngMustDecode("000b8201fc42000874adf19b0800450001480445000080110000c0a80001c0a8000a00430044013422330201060000003d1d0000000000000000c0a8000ac0a8000100000000000b8201fc4200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501020104ffffff003a04000007083b0400000c4e330400000e103604c0a80001ff0000000000000000000000000000000000000000000000000000"),
	ngMustDecode("ffffffffffff000b8201fc4208004500012ca8370000fa11178a00000000ffffffff0044004301189fbd0101060000003d1e0000000000000000000000000000000000000000000b8201fc4200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501033d0701000b8201fc423204c0a8000a3604c0a8000137040103062aff00"),
	ngMustDecode("000b8201fc42000874adf19b0800450001480446000080110000c0a80001c0a8000a004300440134dfdb0201060000003d1e0000000000000000c0a8000a0000000000000000000b8201fc4200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501053a04000007083b0400000c4e330400000e103604c0a800010104ffffff00ff0000000000000000000000000000000000000000000000000000"),
	ngMustDecode("02000000450000a4c6ce00004011f147c0a8018bffffffff445c445c0090ba037b22686f73745f696e74223a20343039343531343438332c202276657273696f6e223a205b312c20385d2c2022646973706c61796e616d65223a2022222c2022706f7274223a2031373530302c20226e616d65737061636573223a205b32303532343235372c203633393533393037322c203633393533393333372c203633393533393535355d7d"),
}

type ngFileReadTestPacket struct {
	data []byte
	ci   gopacket.CaptureInfo
	err  error
}

type ngFileReadTestSection struct {
	sectionInfo NgSectionInfo
	ifaces      []NgInterface
}

type ngFileReadTest struct {
	testName                   string
	testContents               io.Reader
	testType                   string
	wantMixedLinkType          bool
	errorOnMismatchingLinkType bool
	skipUnknownVersion         bool

	linkType layers.LinkType
	sections []ngFileReadTestSection
	packets  []ngFileReadTestPacket
}

func ngRunFileReadTest(test ngFileReadTest, be string, zerocopy bool, t *testing.T) {
	var err error
	var f io.Reader
	if test.testContents == nil {
		testf, err := os.Open(filepath.Join("tests", be, test.testName+".pcapng"))
		if err != nil {
			t.Fatal("Couldn't open file:", err)
		}
		defer testf.Close()
		f = testf
	} else {
		f = test.testContents
	}

	var r *NgReader

	section := 0
	checkInterface := func(intf NgInterface, i int) {
		currentInterface := test.sections[section].ifaces[i]

		// fix non-zero defaults
		if currentInterface.TimestampResolution == 0 {
			currentInterface.TimestampResolution = 6
		}
		// clear private values
		intf.scaleDown = 0
		intf.scaleUp = 0
		intf.secondMask = 0

		if !reflect.DeepEqual(intf, currentInterface) {
			t.Fatalf("[section %d] interface %d mismatches:\ngot:\n%#v\nwant:\n%#v\n\n", section, i, intf, currentInterface)
		}
	}
	testSection := func(intf []NgInterface, sectionInfo NgSectionInfo) {
		currentSection := test.sections[section]

		if !reflect.DeepEqual(sectionInfo, currentSection.sectionInfo) {
			t.Fatalf("[section header %d] section info mismatch:\ngot:\n%#v\nwant:\n%#v\n\n", section, sectionInfo, currentSection.sectionInfo)
		}

		if intf == nil {
			if r.NInterfaces() != len(test.sections[section].ifaces) {
				t.Fatalf("[section %d] Expected at least %d interfaces, but got only %d", section, len(test.sections[section].ifaces), r.NInterfaces())
			}
			for i := 0; i < r.NInterfaces(); i++ {
				in, err := r.Interface(i)
				if err != nil {
					t.Fatalf("Unexpected error querying interface %d", i)
				}
				checkInterface(in, i)
			}
		} else {
			if len(intf) != len(test.sections[section].ifaces) {
				t.Fatalf("[section %d] Expected at least %d interfaces, but got only %d", section, len(test.sections[section].ifaces), len(intf))
			}
			for i, in := range intf {
				checkInterface(in, i)
			}
		}

		section++
	}

	options := DefaultNgReaderOptions
	options.ErrorOnMismatchingLinkType = test.errorOnMismatchingLinkType
	options.WantMixedLinkType = test.wantMixedLinkType
	options.SkipUnknownVersion = test.skipUnknownVersion
	if len(test.sections) > 1 {
		options.SectionEndCallback = testSection
	}

	r, err = NewNgReader(f, options)
	if err != nil {
		t.Fatal("Couldn't read start of file:", err)
	}

	if test.wantMixedLinkType {
		if r.LinkType() != 0 {
			t.Fatalf("[first interface (section %d)] LinkType should be 0 with WantMixedLinkType, but is %s", section, r.LinkType())
		}
	} else {
		if r.LinkType() != test.linkType {
			t.Fatalf("[first interface (section %d)] LinkType mismatch: Should be %s but is %s", section, test.linkType, r.LinkType())
		}
	}

	for i, packet := range test.packets {
		var data []byte
		var ci gopacket.CaptureInfo
		var err error

		if zerocopy {
			data, ci, err = r.ZeroCopyReadPacketData()
		} else {
			data, ci, err = r.ReadPacketData()
		}
		if err == io.EOF {
			t.Fatalf("[packets] Expected %d packets, but got only %d", len(test.packets), i)
		}
		if err != nil {
			if err != packet.err {
				t.Fatalf("[packet %d] Expected error %s, but got %s", i, packet.err, err)
			}
			if err != ErrNgVersionMismatch {
				testSection(nil, r.SectionInfo())
			}
			return
		}

		if bytes.Compare(data, packet.data) != 0 {
			t.Log(data)
			t.Log(packet.data)
			t.Fatalf("[packet %d] data mismatch", i)
		}

		if !reflect.DeepEqual(ci, packet.ci) {
			t.Fatalf("[packet %d] ci mismatch:\ngot:\n%#v\nwant:\n%#v\n\n", i, ci, packet.ci)
		}
	}

	if zerocopy {
		_, _, err = r.ZeroCopyReadPacketData()
	} else {
		_, _, err = r.ReadPacketData()
	}
	if err != io.EOF {
		t.Fatalf("[packets] Expected only %d packet(s), but got at least one more!", len(test.packets))
	}

	testSection(nil, r.SectionInfo())

	if section != len(test.sections) {
		t.Fatalf("File should have %d sections, but has %d", len(test.sections), section)
	}
}

var tests = []ngFileReadTest{
	{
		testName: "test001",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test001",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "silly ethernet interface",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  len(ngPacketSource[1]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0).UTC(),
					Length:         len(ngPacketSource[2]),
					CaptureLength:  len(ngPacketSource[2]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  len(ngPacketSource[3]),
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName:          "test002",
		wantMixedLinkType: true,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test002",
				},
			},
		},
	},
	{
		testName: "test003",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test003",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "silly ethernet interface",
					},
				},
			},
		},
	},
	{
		testName: "test004",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test004",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
					},
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 128,
						Name:       "en1",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  128,
					InterfaceIndex: 1,
				},
			},
			{
				data: ngPacketSource[2][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+2000*1000).UTC(),
					Length:         len(ngPacketSource[2]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+3000*1000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  128,
					InterfaceIndex: 1,
				},
			},
		},
	},
	{
		testName: "test005",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test005",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
					},
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 128,
						Name:       "en1",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  128,
					InterfaceIndex: 1,
				},
			},
			{
				data: ngPacketSource[2][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+2000*1000).UTC(),
					Length:         len(ngPacketSource[2]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+3000*1000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  128,
					InterfaceIndex: 1,
				},
			},
		},
	},
	{
		testName: "test006",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test006",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
					},
					{
						LinkType: layers.LinkTypeNull,
						Name:     "en1",
					},
				},
			},
		},

		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+2000*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+3000*1000).UTC(),
					Length:         len(ngPacketSource[2]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+4000*1000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName:                   "test006",
		testType:                   "/ErrorOnMismatchingLink",
		errorOnMismatchingLinkType: true,
		linkType:                   layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test006",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
					},
					{
						LinkType: layers.LinkTypeNull,
						Name:     "en1",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{err: ErrNgLinkTypeMismatch},
		},
	},
	{
		testName:          "test006",
		testType:          "/WantMixedLinkType",
		wantMixedLinkType: true,
		linkType:          layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test006",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
					},
					{
						LinkType: layers.LinkTypeNull,
						Name:     "en1",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
					AncillaryData:  []interface{}{layers.LinkTypeEthernet},
				},
			},
			{
				data: ngPacketSource[4],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
					Length:         len(ngPacketSource[4]),
					CaptureLength:  len(ngPacketSource[4]),
					InterfaceIndex: 1,
					AncillaryData:  []interface{}{layers.LinkTypeNull},
				},
			},
			{
				data: ngPacketSource[1][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+2000*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  96,
					InterfaceIndex: 0,
					AncillaryData:  []interface{}{layers.LinkTypeEthernet},
				},
			},
			{
				data: ngPacketSource[2][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+3000*1000).UTC(),
					Length:         len(ngPacketSource[2]),
					CaptureLength:  96,
					InterfaceIndex: 0,
					AncillaryData:  []interface{}{layers.LinkTypeEthernet},
				},
			},
			{
				data: ngPacketSource[3][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+4000*1000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  96,
					InterfaceIndex: 0,
					AncillaryData:  []interface{}{layers.LinkTypeEthernet},
				},
			},
		},
	},
	{
		testName: "test007",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test007",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test008",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test008",
				},
				ifaces: []NgInterface{
					{
						LinkType:            layers.LinkTypeEthernet,
						SnapLength:          96,
						Name:                "eth-_0 foo",
						Comment:             "test008, and more\nfoo\r\nbar",
						Description:         "silly ethernet interface",
						Filter:              "tcp port 23 and host 192.0.2.5",
						OS:                  "Microsoft Windows for Workgroups 3.11b\npatch 42",
						TimestampResolution: 9,
					},
					{
						LinkType:            layers.LinkTypeEthernet,
						SnapLength:          128,
						Name:                "en1",
						Comment:             "test008",
						Description:         "silly ethernet interface 2",
						Filter:              "tcp port 23 and host 192.0.2.5",
						OS:                  "Novell NetWare 4.11\nbut not using IPX",
						TimestampResolution: 9,
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa+1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  128,
					InterfaceIndex: 1,
				},
			},
			{
				data: ngPacketSource[2][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa+2000).UTC(),
					Length:         len(ngPacketSource[2]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa+3000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  128,
					InterfaceIndex: 1,
				},
			},
		},
	},
	{
		testName: "test009",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test009",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "eth0",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  len(ngPacketSource[1]),
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test010",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test010",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "eth0",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[1]),
					CaptureLength:  len(ngPacketSource[1]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[2]),
					CaptureLength:  len(ngPacketSource[2]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[3]),
					CaptureLength:  len(ngPacketSource[3]),
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test011",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test011",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "eth0",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  len(ngPacketSource[1]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[2]),
					CaptureLength:  len(ngPacketSource[2]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+1000*2000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  len(ngPacketSource[3]),
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test012",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test012",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 315,
						Name:       "eth0",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1][:315],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[1]),
					CaptureLength:  315,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0).UTC(),
					Length:         len(ngPacketSource[2]),
					CaptureLength:  len(ngPacketSource[2]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3][:315],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  315,
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test013",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test013",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "silly ethernet interface",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0).UTC(),
							StartTime:       time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							EndTime:         time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							PacketsDropped:  10,
							PacketsReceived: NgNoValue64,
						},
					},
				},
			},
		},
	},
	{
		testName:          "test014",
		wantMixedLinkType: true,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test014",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							StartTime:       time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							EndTime:         time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							PacketsDropped:  10,
							PacketsReceived: NgNoValue64,
						},
					},
					{
						LinkType:   layers.LinkTypeNull,
						SnapLength: 0,
						Name:       "null1",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							StartTime:       time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							EndTime:         time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							PacketsDropped:  10,
							PacketsReceived: NgNoValue64,
						},
					},
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 128,
						Name:       "silly ethernet interface 2",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							StartTime:       time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							EndTime:         time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							PacketsDropped:  10,
							PacketsReceived: NgNoValue64,
							Comment:         "test014 ISB",
						},
					},
				},
			},
		},
	},
	{
		testName: "test015",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test015",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "silly ethernet interface",
						Comment:    "test015 IDB",
					},
				},
			},
		},
	},
	{
		testName: "test016",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test016",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "eth0",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  len(ngPacketSource[1]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[2]),
					CaptureLength:  len(ngPacketSource[2]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+1000*2000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  len(ngPacketSource[3]),
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName:          "test017",
		wantMixedLinkType: true,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test017",
				},
			},
		},
	},
	{
		testName: "test018",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test018",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "eth0",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  len(ngPacketSource[1]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[2]),
					CaptureLength:  len(ngPacketSource[2]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+1000*2000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  len(ngPacketSource[3]),
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test100",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test100",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "eth0",
					},
					{
						LinkType:   layers.LinkTypeNull,
						SnapLength: 0,
						Name:       "null1",
					},
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 128,
						Name:       "wifi2?",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  len(ngPacketSource[1]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[2]),
					CaptureLength:  len(ngPacketSource[2]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+1000*2000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  len(ngPacketSource[3]),
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test101",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test101",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0).UTC(),
							PacketsDropped:  NgNoValue64,
							PacketsReceived: NgNoValue64,
						},
					},
					{
						LinkType:   layers.LinkTypeNull,
						SnapLength: 0,
						Name:       "null1",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000-1000*1000).UTC(),
							PacketsDropped:  NgNoValue64,
							PacketsReceived: NgNoValue64,
						},
					},
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 128,
						Name:       "silly ethernet interface 2",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							StartTime:       time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							EndTime:         time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							PacketsDropped:  10,
							PacketsReceived: NgNoValue64,
							Comment:         "test101 ISB-2",
						},
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  128,
					InterfaceIndex: 2,
				},
			},
			{
				data: ngPacketSource[2][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[2]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test102",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test102",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0).UTC(),
							PacketsDropped:  NgNoValue64,
							PacketsReceived: NgNoValue64,
						},
					},
					{
						LinkType:   layers.LinkTypeNull,
						SnapLength: 0,
						Name:       "null1",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000-1000*1000).UTC(),
							PacketsDropped:  NgNoValue64,
							PacketsReceived: NgNoValue64,
						},
					},
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "silly!\r\nethernet interface 2",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							StartTime:       time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							EndTime:         time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							PacketsDropped:  10,
							PacketsReceived: NgNoValue64,
							Comment:         "test102 ISB-2",
						},
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  len(ngPacketSource[1]),
					InterfaceIndex: 2,
				},
			},
			{
				data: ngPacketSource[2][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[2]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000+2000*1000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test200",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test200",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
					},
				},
			},
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test200",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "eth0",
					},
				},
			},
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test200",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeNull,
						SnapLength: 128,
						Name:       "null1",
					},
				},
			},
		},
	},
	{
		testName: "test201",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test201 SHB-0",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
					},
					{
						LinkType:   layers.LinkTypeNull,
						SnapLength: 0,
						Name:       "null1",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							PacketsDropped:  NgNoValue64,
							PacketsReceived: NgNoValue64,
						},
					},
				},
			},
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test201 SHB-1",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 128,
						Name:       "silly ethernet interface 2",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							StartTime:       time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							EndTime:         time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							PacketsDropped:  10,
							PacketsReceived: NgNoValue64,
							Comment:         "test201 ISB-2",
						},
					},
				},
			},
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test201 SHB-2",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0).UTC(),
							PacketsDropped:  NgNoValue64,
							PacketsReceived: NgNoValue64,
						},
					},
					{
						LinkType:   layers.LinkTypeNull,
						SnapLength: 0,
						Name:       "null1",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  128,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[2]),
					CaptureLength:  128,
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test202",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test202 SHB-0",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
					},
					{
						LinkType:   layers.LinkTypeNull,
						SnapLength: 0,
						Name:       "null1",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							PacketsDropped:  NgNoValue64,
							PacketsReceived: NgNoValue64,
						},
					},
				},
			},
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test202 SHB-1",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 128,
						Name:       "silly ethernet interface 2",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							StartTime:       time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							EndTime:         time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							PacketsDropped:  10,
							PacketsReceived: NgNoValue64,
							Comment:         "test202 ISB-2",
						},
					},
				},
			},
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "Apple MBP",
					OS:          "OS-X 10.10.5",
					Application: "pcap_writer.lua",
					Comment:     "test202 SHB-2",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 96,
						Name:       "eth0",
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(0, 0).UTC(),
							StartTime:       time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
							EndTime:         time.Unix(0, 0x4c39764ca47aa*1000+1000*1000).UTC(),
							PacketsReceived: 100,
							PacketsDropped:  1,
							Comment:         "test202 ISB-0",
						},
					},
					{
						LinkType:   layers.LinkTypeNull,
						SnapLength: 0,
						Name:       "null1",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[0][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[0]),
					CaptureLength:  128,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[1][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  128,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Time{},
					Length:         len(ngPacketSource[2]),
					CaptureLength:  128,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3][:128],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  128,
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test901",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "my computer",
					OS:          "linux",
					Application: "pcap_writer.lua",
					Comment:     "test901 SHB-0",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "eth0",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{err: ErrNgVersionMismatch},
		},
	},
	{
		testName:           "test901",
		skipUnknownVersion: true,
		linkType:           layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "my computer",
					OS:          "linux",
					Application: "pcap_writer.lua",
					Comment:     "test901 SHB-0",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "eth0",
					},
				},
			},
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "my computer",
					OS:          "linux",
					Application: "pcap_writer.lua",
					Comment:     "test901 SHB-2",
				},
				ifaces: []NgInterface{
					{
						LinkType:   layers.LinkTypeEthernet,
						SnapLength: 0,
						Name:       "eth0",
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(0, 0x4c39764ca47aa*1000).UTC(),
					Length:         len(ngPacketSource[2]),
					CaptureLength:  len(ngPacketSource[2]),
					InterfaceIndex: 0,
				},
			},
		},
	},
	{
		testName: "test902",
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Hardware:    "my computer",
					OS:          "linux",
					Application: "pcap_writer.lua",
					Comment:     "test902",
				},
				ifaces: []NgInterface{
					{
						LinkType:            layers.LinkTypeEthernet,
						SnapLength:          0,
						Name:                "eth0",
						TimestampResolution: 0x88,
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000, 195312500).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
		},
	},
}

func TestNgFileReadBE(t *testing.T) {
	for _, test := range tests {
		ngRunFileReadTest(test, "be", false, t)
	}
}

func TestNgFileReadLE(t *testing.T) {
	for _, test := range tests {
		ngRunFileReadTest(test, "le", false, t)
	}
}

func TestNgFileReadBEZero(t *testing.T) {
	for _, test := range tests {
		ngRunFileReadTest(test, "be", true, t)
	}
}

func TestNgFileReadLEZero(t *testing.T) {
	for _, test := range tests {
		ngRunFileReadTest(test, "le", true, t)
	}
}

func TestNgFileReadGzipPacket(t *testing.T) {
	test := []byte{
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x13, 0xe3, 0xe2, 0xe5, 0xe5, 0x92, 0x61,
		0x60, 0x60, 0xf0, 0xb5, 0xd1, 0x96, 0x62, 0x04,
		0xd2, 0xff, 0xa1, 0x00, 0x24, 0x06, 0xe2, 0x8b,
		0x40, 0xe9, 0xff, 0xff, 0x21, 0x6c, 0x36, 0x20,
		0x56, 0x61, 0x80, 0x80, 0x50, 0x66, 0x56, 0x86,
		0x46, 0xaf, 0x15, 0x2f, 0x58, 0x80, 0x6c, 0x0e,
		0x90, 0x3a, 0x26, 0x66, 0x16, 0x90, 0x1c, 0x00,
		0xf5, 0xb2, 0x32, 0x08, 0x54, 0x00, 0x00, 0x00,
	}

	buf := bytes.NewBuffer(test)
	r, err := NewNgReader(buf, DefaultNgReaderOptions)
	if err != nil {
		t.Error("Unexpected error returned:", err)
		t.FailNow()
	}

	data, ci, err := r.ReadPacketData()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if !ci.Timestamp.Equal(time.Date(2014, 9, 18, 12, 13, 14, 1000, time.UTC)) {
		t.Error("Invalid time read")
		t.FailNow()
	}
	if ci.CaptureLength != 4 || ci.Length != 8 {
		t.Error("Invalid CapLen or Len")
	}
	want := []byte{1, 2, 3, 4}
	if !bytes.Equal(data, want) {
		t.Errorf("buf mismatch:\nwant: %+v\ngot:  %+v", want, data)
	}
}

func TestNgFileReadTruncatedGzipPacket(t *testing.T) {
	type ngGzipTruncTest struct {
		data        []byte
		expectErr   error
		description string
	}

	tests := []ngGzipTruncTest{
		{
			data:        []byte{},
			expectErr:   io.EOF,
			description: "Empty data",
		},
		{
			data:        []byte{0x1f},
			expectErr:   io.ErrUnexpectedEOF,
			description: "Partial GZIP Header",
		},
		{
			data:        []byte{0x1f, 0x8b, 0x08},
			expectErr:   io.ErrUnexpectedEOF,
			description: "3 bytes of gzip header, missing rest",
		},
	}
	for _, test := range tests {
		buf := bytes.NewBuffer(test.data)
		_, err := NewNgReader(buf, DefaultNgReaderOptions)
		if err != test.expectErr {
			t.Errorf("Test '%s' failed: expected error %v, got %v", test.description, test.expectErr, err)
		}
	}
}

// A gzip stream that fails must fail once and then end in io.EOF, as a
// damaged plain file does, or read loops that stop on io.EOF never stop.
func TestNgGzipErrorThenEOF(t *testing.T) {
	var file bytes.Buffer
	zw := gzip.NewWriter(&file)
	if _, err := zw.Write(getBasicOnePacketPcap(t).Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	// Damage the CRC of the gzip trailer (the 4 bytes before the size).
	badCRC := file.Bytes()
	badCRC[len(badCRC)-8]++

	r, err := NewNgReader(bytes.NewReader(badCRC), DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ReadPacketData(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ReadPacketData(); err != gzip.ErrChecksum {
		t.Errorf("got %v after the last packet, want %v", err, gzip.ErrChecksum)
	}
	if _, _, err := r.ReadPacketData(); err != io.EOF {
		t.Errorf("got %v after the error, want io.EOF", err)
	}
}

func getBasicOnePacketPcap(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Error("Unexpected error returned:", err)
		t.FailNow()
	}
	err = w.WritePacket(gopacket.CaptureInfo{CaptureLength: 2, Length: 2}, []byte{1, 2})
	if err != nil {
		t.Error("Unexpected error returned:", err)
		t.FailNow()
	}
	err = w.Flush()
	if err != nil {
		t.Error("Unexpected error returned:", err)
		t.FailNow()
	}
	return &buf
}

// Tests that NgReader buffer discard passes along UnexpectedEOF to callers
func TestTruncatedDiscard(t *testing.T) {
	buf := getBasicOnePacketPcap(t)
	buf.Truncate(buf.Len() - 1) // truncate last byte to simulate incomplete file
	r, err := NewNgReader(buf, DefaultNgReaderOptions)
	if err != nil {
		t.Error("Unexpected error returned:", err)
		t.FailNow()
	}
	_, _, err = r.ReadPacketData()
	if err == io.ErrUnexpectedEOF {
		return
	} else {
		t.Error("Expected io.ErrUnexpectedEOF, got:", err)
		t.FailNow()
	}
}

// Tests that truncated block headers return UnexpectedEOF
func TestTruncatedBlockHeader(t *testing.T) {
	buf := getBasicOnePacketPcap(t)
	buf.Truncate(4) // truncate to half of the block header
	_, err := NewNgReader(buf, DefaultNgReaderOptions)
	if err != io.ErrUnexpectedEOF {
		t.Error("Expected io.ErrUnexpectedEOF, got:", err)
		t.FailNow()
	}
}

// Tests that Resolution does not panic after a file ends in a section header without an interface
func TestResolutionAfterTrailingSectionHeader(t *testing.T) {
	buf := getBasicOnePacketPcap(t)
	buf.Write([]byte{
		0x0A, 0x0D, 0x0D, 0x0A, // Section Header
		28, 0, 0, 0, // block total length
		0x4D, 0x3C, 0x2B, 0x1A, // BOM
		1, 0, 0, 0, // Version
		0xFF, 0xFF, 0xFF, 0xFF, // Section length
		0xFF, 0xFF, 0xFF, 0xFF, // Section length
		28, 0, 0, 0, // block total length
	})
	r, err := NewNgReader(buf, DefaultNgReaderOptions)
	if err != nil {
		t.Error("Unexpected error returned:", err)
		t.FailNow()
	}
	if _, _, err = r.ReadPacketData(); err != nil {
		t.Error("Unexpected error returned:", err)
		t.FailNow()
	}
	if _, _, err = r.ReadPacketData(); err != io.EOF {
		t.Error("Expected io.EOF, got:", err)
		t.FailNow()
	}
	if res := r.Resolution(); res != (gopacket.TimestampResolution{}) {
		t.Error("Expected zero resolution without an interface, got:", res)
		t.FailNow()
	}
}

// Tests that an if_tsresol option whose divisor does not fit in 64 bits is rejected instead of dividing by zero
func TestNgInvalidTimestampResolution(t *testing.T) {
	for _, test := range []struct {
		tsresol uint8
		ok      bool
	}{
		{0x80 | 63, true},  // 2^-63: largest representable power of two
		{0x80 | 64, false}, // 2^-64: 1<<64 wraps to 0
		{0x80 | 127, false},
		{19, true}, // 10^-19: largest representable power of ten
		// 10^-20 to 10^-63 overflow secondMask but never to 0; they read
		// before the fix, so they must keep reading.
		{20, true},
		{63, true},
		{64, false}, // 10^64 has 2^64 as a factor: wraps to 0
		{127, false},
	} {
		// SHB + IDB with a single if_tsresol option and no packets
		file := ngMustDecode("0a0d0d0a1c0000004d3c2b1a01000000ffffffffffffffff1c000000" +
			"010000002000000001000000000000000900010000000000000000000020000000")
		file[48] = test.tsresol
		_, err := NewNgReader(bytes.NewReader(file), DefaultNgReaderOptions)
		if test.ok && err != nil {
			t.Errorf("tsresol 0x%02x: unexpected error returned: %v", test.tsresol, err)
		} else if !test.ok && err == nil {
			t.Errorf("tsresol 0x%02x: expected an error, got none", test.tsresol)
		}
	}
}

type endlessNgPacketReader struct {
	packet []byte
}

func (e endlessNgPacketReader) Read(p []byte) (n int, err error) {
	n = copy(p, e.packet)
	return
}

func setupNgReadBenchmark(b *testing.B) *NgReader {
	header := bytes.NewBuffer([]byte{
		0x0A, 0x0D, 0x0D, 0x0A, // Section Header
		0, 0, 0, 28, // block total length
		0x1A, 0x2B, 0x3C, 0x4D, // BOM
		0, 1, 0, 0, //Version
		0, 0, 0, 0, //Section length
		0, 0, 0, 0, //Section length
		0, 0, 0, 28, //block total length

		0, 0, 0, 1, // IDB
		0, 0, 0, 20, // block total length
		0, 1, 0, 0, // Ethernet
		0, 0, 0, 0, // Snap length
		0, 0, 0, 20, // block total length
	})

	packet := endlessNgPacketReader{
		[]byte{
			0, 0, 0, 6, // EPB
			0, 0, 0, 48, // block total length
			0, 0, 0, 0, // interface ID
			0, 0, 0, 0, // time (high)
			0, 0, 0, 0, // time (low)
			0, 0, 0, 16, // capture packet length
			0, 0, 0, 16, // original packet length
			1, 2, 3, 4,
			5, 6, 7, 8,
			9, 10, 11, 12,
			13, 14, 15, 16,
			0, 0, 0, 48, // block total length
			0, 0, 0, 6, // EPB
			0, 0, 0, 40, // block total length
			0, 0, 0, 0, // interface ID
			0, 0, 0, 0, // time (high)
			0, 0, 0, 0, // time (low)
			0, 0, 0, 8, // capture packet length
			0, 0, 0, 8, // original packet length
			8, 7, 6, 5,
			4, 3, 2, 1,
			0, 0, 0, 40, // block total length
		},
	}
	packetReader := bufio.NewReaderSize(packet, len(packet.packet))

	r, err := NewNgReader(header, DefaultNgReaderOptions)

	if err != nil {
		b.Fatal("Couldn't read header + IDB:", err)
	}
	r.r = packetReader
	return r
}

func TestNgReadPacketDataWithOptions(t *testing.T) {
	data, err := os.ReadFile("tests/epb.pcapng")
	if err != nil {
		t.Fatalf("read file failed: %+v", err)
	}
	r, err := NewNgReader(bytes.NewReader(data), DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("init reader failed: %+v", err)
	}

	uint64V := func(v uint64) *uint64 { return &v }
	uint32V := func(v uint32) *uint32 { return &v }
	wantOpts := NgPacketOptions{
		Comments: []string{
			"this is a comment",
			"foobar",
		},
		Flags: &NgEpbFlags{
			Direction: NgEpbFlagDirectionOutbound,
			Reception: NgEpbFlagReceptionTypeBroadcast,
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

	_, _, opts, err := r.ReadPacketDataWithOptions()
	if err != nil {
		t.Fatalf("read packets failed: %+v", err)
	}

	if !reflect.DeepEqual(opts.Comments, wantOpts.Comments) {
		t.Fatalf("comments mismatch:\nwant: %+v\ngot:  %+v", wantOpts.Comments, opts.Comments)
	}
	if !reflect.DeepEqual(*opts.Flags, *wantOpts.Flags) {
		t.Fatalf("flags mismatch:\nwant: %+v\ngot:  %+v", *wantOpts.Flags, *opts.Flags)
	}
	if !reflect.DeepEqual(opts.Hashes, wantOpts.Hashes) {
		t.Fatalf("hashes mismatch:\nwant: %+v\ngot:  %+v", wantOpts.Hashes, opts.Hashes)
	}
	if !reflect.DeepEqual(*opts.DropCount, *wantOpts.DropCount) {
		t.Fatalf("drop count mismatch:\nwant: %+v\ngot:  %+v", *wantOpts.DropCount, *opts.DropCount)
	}
	if !reflect.DeepEqual(*opts.PacketID, *wantOpts.PacketID) {
		t.Fatalf("packet ID mismatch:\nwant: %+v\ngot:  %+v", *wantOpts.PacketID, *opts.PacketID)
	}
	if !reflect.DeepEqual(*opts.Queue, *wantOpts.Queue) {
		t.Fatalf("queue mismatch:\nwant: %+v\ngot:  %+v", *wantOpts.Queue, *opts.Queue)
	}
	if !reflect.DeepEqual(opts.Verdicts, wantOpts.Verdicts) {
		t.Fatalf("verdicts mismatch:\nwant: %+v\ngot:  %+v", wantOpts.Verdicts, opts.Verdicts)
	}
}

// Tests that an empty option is returned empty instead of with the value of the option read before it
func TestNgReadEmptyOption(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	wantComments := []string{"this is a comment", ""}
	err = w.WritePacketWithOptions(gopacket.CaptureInfo{CaptureLength: 2, Length: 2}, []byte{1, 2}, NgPacketOptions{Comments: wantComments})
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	if err = w.Flush(); err != nil {
		t.Fatal("Unexpected error returned:", err)
	}

	r, err := NewNgReader(&buf, DefaultNgReaderOptions)
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	_, _, opts, err := r.ReadPacketDataWithOptions()
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	if !reflect.DeepEqual(opts.Comments, wantComments) {
		t.Fatalf("comments mismatch:\nwant: %q\ngot:  %q", wantComments, opts.Comments)
	}
}

// Tests that a fixed size option that is too short is skipped instead of read out of bounds
func TestNgReadShortOption(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	if err = w.Flush(); err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	// enhanced packet block with a 2 byte packet and a 2 byte epb_flags option (must be 4 bytes)
	buf.Write([]byte{
		0x06, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, // type, length
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // interface, timestamp
		0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // captured length, original length
		0x01, 0x02, 0x00, 0x00, // packet data + padding
		0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, // epb_flags, length 2, padded
		0x00, 0x00, 0x00, 0x00, // end of options
		0x2c, 0x00, 0x00, 0x00, // length
	})

	r, err := NewNgReader(&buf, DefaultNgReaderOptions)
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	data, _, opts, err := r.ReadPacketDataWithOptions()
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	if !bytes.Equal(data, []byte{1, 2}) || opts.Flags != nil {
		t.Fatalf("got packet %v, flags %v; want [1 2] and the short epb_flags skipped", data, opts.Flags)
	}
}

// epb_dropcount is 8 bytes; a 4 byte one is skipped the same way.
func TestNgReadShortDropCount(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	if err = w.Flush(); err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	buf.Write([]byte{
		0x06, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, // type, length
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // interface, timestamp
		0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // captured length, original length
		0x01, 0x02, 0x00, 0x00, // packet data + padding
		0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // epb_dropcount, length 4
		0x00, 0x00, 0x00, 0x00, // end of options
		0x2c, 0x00, 0x00, 0x00, // length
	})

	r, err := NewNgReader(&buf, DefaultNgReaderOptions)
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	data, _, opts, err := r.ReadPacketDataWithOptions()
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	if !bytes.Equal(data, []byte{1, 2}) || opts.DropCount != nil {
		t.Fatalf("got packet %v, drop count %v; want [1 2] and the short epb_dropcount skipped", data, opts.DropCount)
	}
}

func BenchmarkNgReadPacketData(b *testing.B) {
	r := setupNgReadBenchmark(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = r.ReadPacketData()
	}
}

func BenchmarkNgZeroCopyReadPacketData(b *testing.B) {
	r := setupNgReadBenchmark(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = r.ZeroCopyReadPacketData()
	}
}
