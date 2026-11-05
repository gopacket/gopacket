// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestPcapNonexistentFile(t *testing.T) {
	handle, err := OpenOffline("/path/to/nonexistent/file")
	if err == nil {
		t.Error("No error returned for nonexistent file open")
	} else {
		t.Logf("Error returned for nonexistent file: %v", err)
	}
	if handle != nil {
		t.Error("Non-nil handle returned for nonexistent file open")
	}
}

func TestPcapFileRead(t *testing.T) {
	invalidData := []byte{
		0xAB, 0xAD, 0x1D, 0xEA,
	}

	invalidPcap, err := ioutil.TempFile("", "invalid.pcap")
	if err != nil {
		t.Fatal(err)
	}
	invalidPcap.Close() // if the file is still open later, the invalid test fails with permission denied on windows
	defer os.Remove(invalidPcap.Name())

	err = ioutil.WriteFile(invalidPcap.Name(), invalidData, 0644)
	if err != nil {
		t.Fatal(err)
	}

	for _, file := range []struct {
		filename       string
		num            int
		expectedLayers []gopacket.LayerType
		err            string
	}{
		{filename: "test_loopback.pcap",
			num: 24,
			expectedLayers: []gopacket.LayerType{
				layers.LayerTypeLoopback,
				layers.LayerTypeIPv6,
				layers.LayerTypeTCP,
			},
		},
		{filename: "test_ethernet.pcap",
			num: 10,
			expectedLayers: []gopacket.LayerType{
				layers.LayerTypeEthernet,
				layers.LayerTypeIPv4,
				layers.LayerTypeTCP,
			},
		},
		{filename: "test_dns.pcap",
			num: 10,
			expectedLayers: []gopacket.LayerType{
				layers.LayerTypeEthernet,
				layers.LayerTypeIPv4,
				layers.LayerTypeUDP,
				layers.LayerTypeDNS,
			},
		},
		{filename: invalidPcap.Name(),
			num: 0,
			err: "unknown file format",
		},
	} {
		t.Logf("\n\n\n\nProcessing file %s\n\n\n\n", file.filename)

		packets := []gopacket.Packet{}
		if handle, err := OpenOffline(file.filename); err != nil {
			if file.err != "" {
				if err.Error() != file.err {
					t.Errorf("expected message %q; got %q", file.err, err.Error())
				}
			} else {
				t.Fatal(err)
			}
		} else {
			if file.err != "" {
				t.Fatalf("Expected error, got none")
			}
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				packets = append(packets, packet)
			}
		}
		if len(packets) != file.num {
			t.Fatal("Incorrect number of packets, want", file.num, "got", len(packets))
		}
		for i, p := range packets {
			t.Log(p.Dump())
			for _, layertype := range file.expectedLayers {
				if p.Layer(layertype) == nil {
					t.Fatal("Packet", i, "has no layer type\n%s", layertype, p.Dump())
				}
			}
		}
	}
}

func TestBPF(t *testing.T) {
	handle, err := OpenOffline("test_ethernet.pcap")
	if err != nil {
		t.Fatal(err)
	}

	for _, expected := range []struct {
		expr   string
		Error  bool
		Result bool
	}{
		{"foobar", true, false},
		{"tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)", false, true},
		{"tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-ack", false, true},
		{"udp", false, false},
		{string([]byte("udp")), false, false}, // test for #664
	} {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		t.Log("Testing filter", expected.expr)
		if bpf, err := handle.NewBPF(expected.expr); err != nil {
			if !expected.Error {
				t.Error(err, "while compiling filter was unexpected")
			}
		} else if expected.Error {
			t.Error("expected error but didn't see one")
		} else if matches := bpf.Matches(ci, data); matches != expected.Result {
			t.Error("Filter result was", matches, "but should be", expected.Result)
		}
	}
}

// A capture file may contain a record with a captured length of 0, which
// ReadPacketData returns as an empty slice. Matches must not panic on it.
func TestBPFEmptyPacket(t *testing.T) {
	for _, expected := range []struct {
		expr   string
		Result bool
	}{
		{"tcp", false},
		{"less 10", true},
	} {
		bpf, err := NewBPF(layers.LinkTypeEthernet, 65535, expected.expr)
		if err != nil {
			t.Fatal(err)
		}
		for _, data := range [][]byte{nil, {}} {
			if matches := bpf.Matches(gopacket.CaptureInfo{}, data); matches != expected.Result {
				t.Errorf("Filter %q result on %#v was %v but should be %v", expected.expr, data, matches, expected.Result)
			}
		}
	}
}

// Matches reads like a query on an immutable program, so callers share one
// BPF between goroutines. The packet lengths must then not pass through the
// BPF itself, or one goroutine's packet is matched with another's length.
func TestBPFMatchesConcurrent(t *testing.T) {
	bpf, err := NewBPF(layers.LinkTypeEthernet, 65535, "less 100")
	if err != nil {
		t.Fatal(err)
	}
	short := make([]byte, 42)
	long := make([]byte, 242)

	var wg sync.WaitGroup
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				if !bpf.Matches(gopacket.CaptureInfo{Length: len(short)}, short) {
					t.Error("short packet not matched")
					return
				}
				if bpf.Matches(gopacket.CaptureInfo{Length: len(long)}, long) {
					t.Error("long packet matched")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// The *os.File stays the caller's: closing the handle must not close its
// descriptor, which the caller closes again, by then another file's.
func TestOpenOfflineFileLeavesFileOpen(t *testing.T) {
	file, err := os.Open("test_ethernet.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	handle, err := OpenOfflineFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := handle.ReadPacketData(); err != nil {
		t.Fatal(err)
	}
	handle.Close()

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Errorf("file unusable after handle.Close: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Errorf("file.Close after handle.Close: %v", err)
	}

	// A file libpcap rejects is the caller's too.
	empty, err := os.CreateTemp(t.TempDir(), "empty")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOfflineFile(empty); err == nil {
		t.Error("opened an empty file")
	}
	if err := empty.Close(); err != nil {
		t.Errorf("file.Close after a rejected open: %v", err)
	}
}

// badOptionPcapng is a pcapng file with a section header, interface 0,
// interface 1 with an if_tsresol option of length 2 (only 1 is valid) and
// one packet on interface 1. libpcap rejects the second interface block.
func badOptionPcapng() []byte {
	const (
		sectionHeaderBlock = 0x0A0D0D0A
		interfaceBlock     = 1
		packetBlock        = 6
		linkTypeEthernet   = 1
		optEndOfOpt        = 0
		optIfTsresol       = 9
		tsresolMicro       = 6
	)
	le := binary.LittleEndian
	block := func(blockType uint32, body []byte) []byte {
		total := uint32(4 + 4 + len(body) + 4)
		out := le.AppendUint32(nil, blockType)
		out = le.AppendUint32(out, total)
		out = append(out, body...)
		return le.AppendUint32(out, total)
	}

	// byte-order magic, version 1.0, section length unknown
	section := le.AppendUint32(nil, 0x1A2B3C4D)
	section = le.AppendUint16(section, 1)
	section = le.AppendUint16(section, 0)
	section = le.AppendUint64(section, ^uint64(0))

	// link type, reserved, snap length
	iface := le.AppendUint16(nil, linkTypeEthernet)
	iface = le.AppendUint16(iface, 0)
	iface = le.AppendUint32(iface, 65535)

	// the one byte value is padded to 4 whatever the length field says
	tsresol := le.AppendUint16(nil, optIfTsresol)
	tsresol = le.AppendUint16(tsresol, 2)
	tsresol = append(tsresol, tsresolMicro, 0, 0, 0)
	tsresol = le.AppendUint16(tsresol, optEndOfOpt)
	tsresol = le.AppendUint16(tsresol, 0)

	// interface 1, timestamp 0, 60 byte frame
	frame := make([]byte, 60)
	packet := le.AppendUint32(nil, 1)
	packet = le.AppendUint32(packet, 0)
	packet = le.AppendUint32(packet, 0)
	packet = le.AppendUint32(packet, uint32(len(frame)))
	packet = le.AppendUint32(packet, uint32(len(frame)))
	packet = append(packet, frame...)

	var file []byte
	file = append(file, block(sectionHeaderBlock, section)...)
	file = append(file, block(interfaceBlock, iface)...)
	file = append(file, block(interfaceBlock, append(iface, tsresol...))...)
	return append(file, block(packetBlock, packet)...)
}

// A read error on a capture file is final for libpcap; reading on returns
// garbage or, with libpcap 1.10.3 and 1.11.0, divides by zero. Report it
// once and io.EOF after that, so Packets() stops instead of retrying.
func TestPcapFileReadErrorIsFinal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad_option.pcapng")
	if err := os.WriteFile(path, badOptionPcapng(), 0o600); err != nil {
		t.Fatal(err)
	}
	handle, err := OpenOffline(path)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	if _, _, err := handle.ReadPacketData(); err != NextErrorReadError {
		t.Fatalf("first read: got %v, want %v", err, NextErrorReadError)
	}
	if _, _, err := handle.ReadPacketData(); err != io.EOF {
		t.Errorf("read after the error: got %v, want io.EOF", err)
	}
	if _, _, err := handle.ZeroCopyReadPacketData(); err != io.EOF {
		t.Errorf("zero copy read after the error: got %v, want io.EOF", err)
	}
}

func TestWritePacketDataEmptyPacket(t *testing.T) {
	handle, err := OpenOffline("test_ethernet.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	for _, data := range [][]byte{nil, {}} {
		// Savefiles cannot be written to; the point is that libpcap reports
		// that rather than WritePacketData panicking on the empty slice.
		if err := handle.WritePacketData(data); err == nil {
			t.Errorf("expected error writing %#v to a savefile but didn't see one", data)
		}
	}
}

func TestBPFInstruction(t *testing.T) {
	handle, err := OpenOffline("test_ethernet.pcap")
	if err != nil {
		t.Fatal(err)
	}

	cntr := 0
	oversizedBpfInstructionBuffer := [MaxBpfInstructions + 1]BPFInstruction{}

	for _, expected := range []struct {
		Filter         string
		BpfInstruction []BPFInstruction
		Error          bool
		Result         bool
	}{
		// {"foobar", true, false},
		{"foobar", []BPFInstruction{}, true, false},

		// tcpdump -dd 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'
		{"tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)",
			[]BPFInstruction{
				{0x28, 0, 0, 0x0000000c},
				{0x15, 0, 9, 0x00000800},
				{0x30, 0, 0, 0x00000017},
				{0x15, 0, 7, 0x00000006},
				{0x28, 0, 0, 0x00000014},
				{0x45, 5, 0, 0x00001fff},
				{0xb1, 0, 0, 0x0000000e},
				{0x50, 0, 0, 0x0000001b},
				{0x54, 0, 0, 0x00000012},
				{0x15, 0, 1, 0x00000012},
				{0x6, 0, 0, 0x0000ffff},
				{0x6, 0, 0, 0x00000000},
			}, false, true},

		// tcpdump -dd 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-ack'
		{"tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-ack",
			[]BPFInstruction{
				{0x28, 0, 0, 0x0000000c},
				{0x15, 0, 9, 0x00000800},
				{0x30, 0, 0, 0x00000017},
				{0x15, 0, 7, 0x00000006},
				{0x28, 0, 0, 0x00000014},
				{0x45, 5, 0, 0x00001fff},
				{0xb1, 0, 0, 0x0000000e},
				{0x50, 0, 0, 0x0000001b},
				{0x54, 0, 0, 0x00000012},
				{0x15, 0, 1, 0x00000010},
				{0x6, 0, 0, 0x0000ffff},
				{0x6, 0, 0, 0x00000000},
			}, false, true},

		// tcpdump -dd '(ip or ip6) and udp'
		{"(ip or ip6) and udp",
			[]BPFInstruction{
				{0x28, 0, 0, 0x0000000c},
				{0x15, 0, 2, 0x00000800},
				{0x30, 0, 0, 0x00000017},
				{0x15, 6, 7, 0x00000011},
				{0x15, 0, 6, 0x000086dd},
				{0x30, 0, 0, 0x00000014},
				{0x15, 3, 0, 0x00000011},
				{0x15, 0, 3, 0x0000002c},
				{0x30, 0, 0, 0x00000036},
				{0x15, 0, 1, 0x00000011},
				{0x6, 0, 0, 0x0000ffff},
				{0x6, 0, 0, 0x00000000},
			}, false, false},

		{"", oversizedBpfInstructionBuffer[:], true, false},
	} {
		cntr++
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}

		t.Log("Testing BpfInstruction filter", cntr)
		if bpf, err := handle.NewBPFInstructionFilter(expected.BpfInstruction); err != nil {
			if !expected.Error {
				t.Error(err, "while compiling filter was unexpected")
			}
		} else if expected.Error {
			t.Error("expected error but didn't see one")
		} else if matches := bpf.Matches(ci, data); matches != expected.Result {
			t.Error("Filter result was", matches, "but should be", expected.Result)
		}

		if expected.Filter != "" {
			t.Log("Testing dead bpf filter", cntr)
			if bpf, err := CompileBPFFilter(layers.LinkTypeEthernet, 65535, expected.Filter); err != nil {
				if !expected.Error {
					t.Error(err, "while compiling filter was unexpected")
				}
			} else if expected.Error {
				t.Error("expected error but didn't see one")
			} else {
				if len(bpf) != len(expected.BpfInstruction) {
					t.Errorf("expected %d instructions, got %d", len(expected.BpfInstruction), len(bpf))
				}
				for i := 0; i < len(bpf); i++ {
					if bpf[i] != expected.BpfInstruction[i] {
						t.Errorf("expected instruction %d = %x, got %x", i, expected.BpfInstruction[i], bpf[i])
					}
				}
			}
		}
	}
}

func ExampleBPF() {
	handle, err := OpenOffline("test_ethernet.pcap")
	if err != nil {
		log.Fatal(err)
	}
	synack, err := handle.NewBPF("tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)")
	if err != nil {
		log.Fatal(err)
	}
	syn, err := handle.NewBPF("tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn")
	if err != nil {
		log.Fatal(err)
	}
	for {
		data, ci, err := handle.ReadPacketData()
		switch {
		case err == io.EOF:
			return
		case err != nil:
			log.Fatal(err)
		case synack.Matches(ci, data):
			fmt.Println("SYN/ACK packet")
		case syn.Matches(ci, data):
			fmt.Println("SYN packet")
		default:
			fmt.Println("SYN flag not set")
		}
	}
	// Output:
	// SYN packet
	// SYN/ACK packet
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
	// SYN flag not set
}
