// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapgo

import (
	"bytes"
	"encoding/binary"
	"io"
	"runtime"
	"testing"
)

// declaredLen is the length a crafted file claims for data it does not hold.
const declaredLen = 1 << 30

// maxTestAlloc is the most a reader may allocate for one of the tiny files below.
const maxTestAlloc = 16 << 20

// largeLen is a valid record length above eagerReadMax, to cover the slow path.
const largeLen = 300000

// allocated returns the bytes allocated while f runs.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// le appends little endian uint32 values to b.
func le(b []byte, v ...uint32) []byte {
	for _, x := range v {
		b = binary.LittleEndian.AppendUint32(b, x)
	}
	return b
}

// ngFile returns a pcapng section header and an Ethernet interface with the given snaplen.
func ngFile(snaplen uint32) []byte {
	b := le(nil, 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0xffffffff, 0xffffffff, 28)
	return le(b, 1, 20, 1, snaplen, 20)
}

// ngEPB returns an enhanced packet block holding data.
func ngEPB(data []byte) []byte {
	padded := (len(data) + 3) &^ 3
	total := uint32(32 + padded)
	b := le(nil, 6, total, 0, 0, 0, uint32(len(data)), uint32(len(data)))
	b = append(b, data...)
	b = append(b, make([]byte, padded-len(data))...)
	return le(b, total)
}

// pcapFile returns a classic pcap header with the given snaplen and one record header.
func pcapFile(snaplen, capLen uint32) []byte {
	b := le(nil, magicMicroseconds)
	b = binary.LittleEndian.AppendUint16(b, versionMajor)
	b = binary.LittleEndian.AppendUint16(b, versionMinor)
	b = le(b, 0, 0, snaplen, 1)
	return le(b, 0, 0, capLen, capLen)
}

func TestReadDeclaredLengthAlloc(t *testing.T) {
	// EPB claiming a 1 GiB packet in a 92 byte file
	ngPacket := le(ngFile(0), 6, 32, 0, 0, 0, declaredLen, declaredLen)

	// DSB claiming 1 GiB of secrets, read by NewNgReader
	ngSecrets := le(nil, 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0xffffffff, 0xffffffff, 28)
	ngSecrets = le(ngSecrets, 0x0A, 32, 0x544c534b, declaredLen)

	// interface snaplen of 1 GiB, packet of 4 bytes
	ngSnap := append(ngFile(declaredLen), ngEPB([]byte{1, 2, 3, 4})...)

	// pcap snaplen of 1 GiB, packet of 4 bytes
	pcapSnap := append(pcapFile(declaredLen, 4), 1, 2, 3, 4)

	for _, test := range []struct {
		name string
		read func() error
	}{
		{"NgReader packet", func() error {
			r, err := NewNgReader(bytes.NewReader(ngPacket), DefaultNgReaderOptions)
			if err != nil {
				return err
			}
			_, _, err = r.ReadPacketData()
			return err
		}},
		{"NgReader secrets", func() error {
			_, err := NewNgReader(bytes.NewReader(ngSecrets), DefaultNgReaderOptions)
			return err
		}},
		{"NgReader zero copy snaplen", func() error {
			r, err := NewNgReader(bytes.NewReader(ngSnap), DefaultNgReaderOptions)
			if err != nil {
				return err
			}
			_, _, err = r.ZeroCopyReadPacketData()
			return err
		}},
		{"Reader packet", func() error {
			r, err := NewReader(bytes.NewReader(pcapFile(0xffffffff, declaredLen)))
			if err != nil {
				return err
			}
			_, _, err = r.ReadPacketData()
			return err
		}},
		{"Reader zero copy snaplen", func() error {
			r, err := NewReader(bytes.NewReader(pcapSnap))
			if err != nil {
				return err
			}
			_, _, err = r.ZeroCopyReadPacketData()
			return err
		}},
	} {
		n := allocated(func() { _ = test.read() })
		if n > maxTestAlloc {
			t.Errorf("%s: allocated %d bytes, want at most %d", test.name, n, maxTestAlloc)
		}
	}
}

func TestReadLargePacket(t *testing.T) {
	want := make([]byte, largeLen)
	for i := range want {
		want[i] = byte(i)
	}
	ng := append(ngFile(0), ngEPB(want)...)
	pcap := append(pcapFile(largeLen, largeLen), want...)

	for _, test := range []struct {
		name string
		read func() ([]byte, error)
	}{
		{"NgReader", func() ([]byte, error) {
			r, err := NewNgReader(bytes.NewReader(ng), DefaultNgReaderOptions)
			if err != nil {
				return nil, err
			}
			data, _, err := r.ReadPacketData()
			return data, err
		}},
		{"NgReader zero copy", func() ([]byte, error) {
			r, err := NewNgReader(bytes.NewReader(ng), DefaultNgReaderOptions)
			if err != nil {
				return nil, err
			}
			data, _, err := r.ZeroCopyReadPacketData()
			return data, err
		}},
		{"Reader", func() ([]byte, error) {
			r, err := NewReader(bytes.NewReader(pcap))
			if err != nil {
				return nil, err
			}
			data, _, err := r.ReadPacketData()
			return data, err
		}},
		{"Reader zero copy", func() ([]byte, error) {
			r, err := NewReader(bytes.NewReader(pcap))
			if err != nil {
				return nil, err
			}
			data, _, err := r.ZeroCopyReadPacketData()
			return data, err
		}},
	} {
		got, err := test.read()
		if err != nil {
			t.Errorf("%s: unexpected error: %v", test.name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: packet data differs, got %d bytes", test.name, len(got))
		}
	}
}

// TestNgReadShortOptionIgnored checks that short fixed size options which were
// always read without error, from the bytes left over in the option buffer,
// are now skipped rather than failing the file.
func TestNgReadShortOptionIgnored(t *testing.T) {
	b := le(nil, 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0xffffffff, 0xffffffff, 28)

	// IDB: if_tsoffset of 2 bytes, then empty if_tsresol and if_filter
	b = le(b, 1, 40, 1, 0)
	b = le(b, 14|2<<16, 6)
	b = le(b, 9, 11, 0)
	b = le(b, 40)

	// ISB: isb_ifrecv of 2 bytes
	b = le(b, 5, 36, 0, 0, 0)
	b = le(b, 4|2<<16, 0, 0)
	b = le(b, 36)

	b = append(b, ngEPB([]byte{1, 2, 3, 4})...)

	r, err := NewNgReader(bytes.NewReader(b), DefaultNgReaderOptions)
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	data, _, err := r.ReadPacketData()
	if err != nil {
		t.Fatal("Unexpected error returned:", err)
	}
	if !bytes.Equal(data, []byte{1, 2, 3, 4}) {
		t.Errorf("got packet %v, want [1 2 3 4]", data)
	}
}

// TestNgReadSectionLimits checks that the reader keeps no more of a section,
// or of the options of a packet, than its limits allow, however many blocks
// and options the file has, and that it reads on after what it dropped.
func TestNgReadSectionLimits(t *testing.T) {
	shb := le(nil, 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0xffffffff, 0xffffffff, 28)
	idb := le(nil, 1, 20, 1, 0, 20)
	packet := ngEPB([]byte{1, 2, 3, 4})
	nextSection := append(ngFile(0), packet...)

	// read returns a reader that is past the next packet of file
	read := func(t *testing.T, r *NgReader, file []byte) *NgReader {
		t.Helper()
		var err error
		if r == nil {
			if r, err = NewNgReader(bytes.NewReader(file), DefaultNgReaderOptions); err != nil {
				t.Fatal("Unexpected error returned:", err)
			}
		}
		data, _, err := r.ReadPacketData()
		if err != nil {
			t.Fatal("Unexpected error returned:", err)
		}
		if !bytes.Equal(data, []byte{1, 2, 3, 4}) {
			t.Fatalf("got packet %v, want [1 2 3 4]", data)
		}
		return r
	}

	t.Run("interfaces", func(t *testing.T) {
		const want = ngMaxInterfaceBytes / ngInterfaceSize
		file := append(bytes.Clone(shb), bytes.Repeat(idb, want+1000)...)
		file = append(file, packet...)
		file = append(file, nextSection...)

		r := read(t, nil, file)
		if r.NInterfaces() != want {
			t.Errorf("kept %d interfaces, want %d", r.NInterfaces(), want)
		}
		if read(t, r, nil); r.NInterfaces() != 1 {
			t.Errorf("next section has %d interfaces, want 1", r.NInterfaces())
		}
	})

	t.Run("names", func(t *testing.T) {
		// an IPv4 record of 65528 empty names, in a block of its own
		const names, blocks = 65528, 64
		nrb := le(nil, 4, 16+4+names+4, 1|(4+names)<<16, 0x010200c0)
		nrb = append(nrb, make([]byte, names)...)
		nrb = le(nrb, 0, 16+4+names+4)
		file := append(ngFile(0), bytes.Repeat(nrb, blocks)...)
		file = append(file, packet...)
		// the next section has one record of one name
		file = append(file, ngFile(0)...)
		file = le(file, 4, 28, 1|6<<16, 0x010200c0, 'a', 0, 28)
		file = append(file, packet...)

		r := read(t, nil, file)
		if n := r.NNames(); n == 0 || n*names*ngNameSize > ngMaxNameBytes {
			t.Errorf("kept %d records of %d names", n, names)
		}
		if read(t, r, nil); r.NNames() != 1 {
			t.Errorf("next section has %d name records, want 1", r.NNames())
		}
	})

	t.Run("decryption secrets", func(t *testing.T) {
		const want = ngMaxSecretBytes / ngSecretSize
		dsb := le(nil, 0x0A, 20, 0x544c534b, 0, 20)
		file := append(bytes.Clone(shb), bytes.Repeat(dsb, want+1000)...)
		file = append(file, idb...)
		file = append(file, packet...)

		r := read(t, nil, file)
		if len(r.decryptionSecrets) != want {
			t.Errorf("kept %d decryption secrets, want %d", len(r.decryptionSecrets), want)
		}
	})

	t.Run("statistics comments", func(t *testing.T) {
		// a comment of 64 KiB for each interface, then a short one for the first
		const interfaces, length = 300, 65532
		file := append(bytes.Clone(shb), bytes.Repeat(idb, interfaces)...)
		for i := uint32(0); i <= interfaces; i++ {
			comment := bytes.Repeat([]byte{'c'}, length)
			if i == interfaces {
				comment = []byte("last")
			}
			total := uint32(8 + 12 + 4 + len(comment) + 4)
			file = le(file, 5, total, i%interfaces, 0, 0, 1|uint32(len(comment))<<16)
			file = append(file, comment...)
			file = le(file, total)
		}
		file = append(file, packet...)

		r := read(t, nil, file)
		kept, comments := r.NInterfaces()*ngInterfaceSize, 0
		for i := 0; i < r.NInterfaces(); i++ {
			intf, _ := r.Interface(i)
			kept += len(intf.Statistics.Comment)
			if intf.Statistics.Comment != "" {
				comments++
			}
		}
		if r.NInterfaces() != interfaces || comments < 2 || kept > ngMaxInterfaceBytes {
			t.Errorf("kept %d interfaces and %d comments in %d bytes, want %d interfaces in at most %d bytes", r.NInterfaces(), comments, kept, interfaces, ngMaxInterfaceBytes)
		}
		if kept != r.ifaceBytes {
			t.Errorf("charged %d bytes for interfaces that hold %d", r.ifaceBytes, kept)
		}
		if intf, _ := r.Interface(0); intf.Statistics.Comment != "last" {
			t.Errorf("first interface has a comment of %d bytes, want the last one read", len(intf.Statistics.Comment))
		}
	})

	t.Run("packet options", func(t *testing.T) {
		// each option ngMaxPacketOptions+100 times: empty comments, one byte hashes and verdicts
		const n = ngMaxPacketOptions + 100
		total := uint32(32 + n*(4+8+8) + 4)
		file := le(ngFile(0), 6, total, 0, 0, 0, 4, 4, 0x04030201)
		for i := 0; i < n; i++ {
			file = le(file, uint32(ngOptionCodeComment))
			file = le(file, uint32(ngOptionCodeEpbHash)|1<<16, 0)
			file = le(file, uint32(ngOptionCodeEpbVerdict)|1<<16, 0)
		}
		file = le(file, total)
		file = append(file, packet...)

		r, err := NewNgReader(bytes.NewReader(file), DefaultNgReaderOptions)
		if err != nil {
			t.Fatal("Unexpected error returned:", err)
		}
		_, _, opts, err := r.ReadPacketDataWithOptions()
		if err != nil {
			t.Fatal("Unexpected error returned:", err)
		}
		if len(opts.Comments) != ngMaxPacketOptions || len(opts.Hashes) != ngMaxPacketOptions || len(opts.Verdicts) != ngMaxPacketOptions {
			t.Errorf("got %d comments, %d hashes and %d verdicts, want %d of each", len(opts.Comments), len(opts.Hashes), len(opts.Verdicts), ngMaxPacketOptions)
		}
		read(t, r, nil)
	})
}

// TestNgReadUnknownInterface checks that a block which names an interface the
// section doesn't have is skipped whole, so the packets after it are read.
// Interfaces over the section limit are dropped, which makes this reachable
// from a well-formed file.
func TestNgReadUnknownInterface(t *testing.T) {
	const unknown = 7

	for _, test := range []struct {
		name  string
		block []byte
	}{
		{"enhanced packet", le(nil, 6, 36, unknown, 0, 0, 4, 4, 0x04030201, 36)},
		{"packet", le(nil, 2, 36, unknown, 0, 0, 4, 4, 0x04030201, 36)},
		{"interface statistics", le(nil, 5, 24, unknown, 0, 0, 24)},
	} {
		file := append(ngFile(0), test.block...)
		file = append(file, ngEPB([]byte{5, 6, 7, 8})...)

		r, err := NewNgReader(bytes.NewReader(file), DefaultNgReaderOptions)
		if err != nil {
			t.Fatalf("%s: unexpected error returned: %v", test.name, err)
		}
		if _, _, err := r.ReadPacketData(); err == nil || err == io.EOF || err == io.ErrUnexpectedEOF {
			t.Errorf("%s: got error %v, want an error for the block", test.name, err)
		}
		if data, _, err := r.ReadPacketData(); err != nil || !bytes.Equal(data, []byte{5, 6, 7, 8}) {
			t.Errorf("%s: got packet %v, error %v; want [5 6 7 8]", test.name, data, err)
		}
	}
}
