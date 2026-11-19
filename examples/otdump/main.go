// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The otdump binary prints one line per industrial (OT) protocol PDU of
// a capture file or a live interface.
//
// TCP protocols (S7comm, S7comm-plus and MMS over TPKT, Modbus/TCP,
// IEC 60870-5-104, OPC UA, DNP3) are reassembled, then cut into PDUs by
// the layers stream splitters, so PDUs split over segments decode too.
// Other OT traffic (GOOSE, SV, PTP, PROFINET, EtherCAT, BACnet/IP) is
// decoded per packet.
//
//	packet -> TCP on an OT port? -- yes --> reassembly -> SplitFunc -> PDU
//	              |                                                    |
//	              no -> per packet decode                     NewPacket(PDU)
//
// Usage:
//
//	otdump -r capture.pcap
//	otdump -i eth0
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var (
	fname   = flag.String("r", "", "Capture file (pcap or pcapng) to read")
	iface   = flag.String("i", "", "Interface to capture from when -r is not given")
	snaplen = flag.Int("s", 65536, "Snap length for live capture")
)

// captureSource is a packet source that knows its link type.
type captureSource interface {
	gopacket.PacketDataSource
	LinkType() layers.LinkType
}

func main() {
	flag.Parse()
	if *fname == "" && *iface == "" {
		flag.Usage()
		os.Exit(2)
	}

	src, closeSrc, err := openSource()
	if err != nil {
		log.Fatal(err)
	}
	defer closeSrc()

	// Decode non-TCP OT traffic, which is opt-in.
	layers.RegisterOTDecoders()

	d := newDumper(os.Stdout)
	if err := d.run(src); err != nil {
		log.Fatal(err)
	}
}

// openSource opens the capture file, or the interface without -r.
func openSource() (captureSource, func(), error) {
	if *fname == "" {
		return openLive(*iface, *snaplen)
	}

	f, err := os.Open(*fname)
	if err != nil {
		return nil, nil, err
	}

	src, err := openFile(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return src, func() { f.Close() }, nil
}

// openFile reads f as pcap, or as pcapng when it is not pcap.
func openFile(f io.ReadSeeker) (captureSource, error) {
	if r, err := pcapgo.NewReader(f); err == nil {
		return r, nil
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	r, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err != nil {
		return nil, fmt.Errorf("neither pcap nor pcapng: %w", err)
	}
	return r, nil
}

// run decodes every packet of src until it ends, then flushes the
// streams still open.
func (d *dumper) run(src captureSource) error {
	ps := gopacket.NewPacketSource(src, src.LinkType())
	defer d.flush()

	for {
		p, err := ps.NextPacket()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		d.packet(p)
	}
}
