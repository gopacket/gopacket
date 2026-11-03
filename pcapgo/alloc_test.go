// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapgo

import (
	"bytes"
	"encoding/binary"
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
