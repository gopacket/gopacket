// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build linux
// +build linux

package afpacket

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestParseOptions(t *testing.T) {
	wanted1 := defaultOpts
	wanted1.frameSize = 1 << 10
	wanted1.framesPerBlock = wanted1.blockSize / wanted1.frameSize
	for i, test := range []struct {
		opts []interface{}
		want options
		err  bool
	}{
		{opts: []interface{}{OptBlockSize(2)}, err: true},
		{opts: []interface{}{OptFrameSize(333)}, err: true},
		{opts: []interface{}{OptTPacketVersion(-3)}, err: true},
		{opts: []interface{}{OptTPacketVersion(5)}, err: true},
		{opts: []interface{}{OptFrameSize(1 << 10)}, want: wanted1},
	} {
		got, err := parseOptions(test.opts...)
		t.Logf("got: %#v\nerr: %v", got, err)
		if test.err && err == nil || !test.err && err != nil {
			t.Errorf("%d error mismatch, want error? %v.  error: %v", i, test.err, err)
		}
		if !test.err && !reflect.DeepEqual(test.want, got) {
			t.Errorf("%d opts mismatch, want\n%#v", i, test.want)
		}
	}
}

// v3TestPacket is one packet laid out in a fake TPACKET_V3 block.
type v3TestPacket struct {
	data []byte
	tci  int
	tpid int
}

const (
	v3TestFirstPkt = 48 // sizeof(tpacketBlockDesc)
	v3TestMac      = 68 // tpacket3_hdr (48) + sockaddr_ll (20)
)

// v3TestRing builds a one block TPACKET_V3 ring in anonymous memory, filled
// in as the kernel hands a block over, and a TPacket reading from it without
// a socket, so the read path runs unprivileged. numPkts goes into the block
// header as given, so it may differ from the packets laid out.
func v3TestRing(t *testing.T, numPkts uint32, packets ...v3TestPacket) *TPacket {
	t.Helper()
	ring, err := unix.Mmap(-1, 0, unix.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Munmap(ring) })

	base := unsafe.Pointer(&ring[0])
	blockhdr := (*tpacket_hdr_v1)(unsafe.Pointer(&(*tpacketBlockDesc)(base).hdr[0]))
	*blockhdr = tpacket_hdr_v1{
		block_status:        unix.TP_STATUS_USER,
		num_pkts:            numPkts,
		offset_to_first_pkt: v3TestFirstPkt,
	}

	off := v3TestFirstPkt
	for i, p := range packets {
		hdr := (*tpacket3_hdr)(unsafe.Add(base, off))
		size := tpAlign(v3TestMac + len(p.data))
		*hdr = tpacket3_hdr{
			tp_snaplen: uint32(len(p.data)),
			tp_len:     uint32(len(p.data)),
			tp_mac:     v3TestMac,
		}
		if i < len(packets)-1 {
			hdr.tp_next_offset = uint32(size)
		}
		if p.tci != 0 {
			hdr.tp_status = unix.TP_STATUS_VLAN_VALID | unix.TP_STATUS_VLAN_TPID_VALID
			hv1 := (*tpacketHdrVarient1)(unsafe.Pointer(&hdr.anon0[0]))
			hv1.vlanTCI = uint32(p.tci)
			hv1.vlanTPID = uint16(p.tpid)
		}
		copy(ring[off+v3TestMac:], p.data)
		off += size
	}

	return &TPacket{
		fd:        -1,
		rawring:   base,
		opts:      options{frameSize: len(ring), framesPerBlock: 1, numBlocks: 1},
		tpVersion: TPacketVersion3,
	}
}

// An empty packet at the start of a TPACKET_V3 block (a SocketDgram socket
// with a filter attached lets a header-only frame through as a packet of
// length 0) must not make the rest of the block go back to the kernel unread.
func TestV3BlockStartingWithEmptyPacket(t *testing.T) {
	want := []byte{1, 2, 3, 4}
	h := v3TestRing(t, 2, v3TestPacket{data: nil}, v3TestPacket{data: want})

	got, _, err := h.ZeroCopyReadPacketData()
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("got %v, %v want %v", got, err, want)
	}
	// The block is used up and, with a poll timeout of 0, nothing follows it.
	if _, _, err = h.ZeroCopyReadPacketData(); err != ErrTimeout {
		t.Errorf("got error %v at the end of the block, want %v", err, ErrTimeout)
	}
}

// The kernel does not clear the packet area of a block it hands over empty,
// so the first slot may still hold a packet from an earlier pass over the
// ring. num_pkts says the block is empty, and that must win.
func TestV3EmptyBlockWithStalePacket(t *testing.T) {
	h := v3TestRing(t, 0, v3TestPacket{data: []byte{9, 9, 9, 9}})

	if got, _, err := h.ZeroCopyReadPacketData(); err != ErrTimeout {
		t.Errorf("got %v, %v from an empty block, want %v", got, err, ErrTimeout)
	}
}

// With OptAddVLANHeader the tag goes back into the data, so Length has to
// count it too: the frame on the wire carried it, and CaptureInfo requires
// Length >= CaptureLength.
func TestVlanHeaderCountedInLength(t *testing.T) {
	eth := []byte{1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 0x08, 0x00}
	h := v3TestRing(t, 1, v3TestPacket{data: eth, tci: 5, tpid: 0x88a8})
	h.opts.addVLANHeader = true

	data, ci, err := h.ZeroCopyReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 0x88, 0xa8, 0x00, 0x05, 0x08, 0x00}
	if !bytes.Equal(data, want) {
		t.Errorf("got data %x, want %x", data, want)
	}
	if ci.CaptureLength != len(want) || ci.Length != len(want) {
		t.Errorf("got CaptureLength %d, Length %d, want both %d", ci.CaptureLength, ci.Length, len(want))
	}
	if len(ci.AncillaryData) != 1 || ci.AncillaryData[0] != (AncillaryVLAN{5}) {
		t.Errorf("got AncillaryData %v, want [{5}]", ci.AncillaryData)
	}
}

func TestInsertVlanHeader(t *testing.T) {
	eth := []byte{1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 0x08, 0x00, 3}
	tagged := func(tpid ...byte) []byte {
		return append(append(append([]byte{}, eth[:12]...), tpid...), 0x60, 0x05, 0x08, 0x00, 3)
	}
	for i, test := range []struct {
		data      []byte
		tci, tpid int
		add       bool
		want      []byte
	}{
		{data: eth, tci: 5, tpid: 0x8100, add: false, want: eth},
		{data: eth, tci: 0, tpid: 0, add: true, want: eth},
		// no TPID from the kernel: assume 802.1Q
		{data: eth, tci: 0x6005, tpid: 0, add: true, want: tagged(0x81, 0x00)},
		{data: eth, tci: 0x6005, tpid: 0x8100, add: true, want: tagged(0x81, 0x00)},
		// 802.1ad service tag
		{data: eth, tci: 0x6005, tpid: 0x88a8, add: true, want: tagged(0x88, 0xa8)},
		// too short to hold both MAC addresses: returned as is
		{data: eth[:12:12], tci: 0x6005, tpid: 0x8100, add: true, want: tagged(0x81, 0x00)[:16]},
		{data: eth[:11:11], tci: 5, tpid: 0x8100, add: true, want: eth[:11]},
		{data: eth[:0:0], tci: 5, tpid: 0x8100, add: true, want: eth[:0]},
	} {
		got := insertVlanHeader(test.data, test.tci, test.tpid, &options{addVLANHeader: test.add})
		if !bytes.Equal(test.want, got) {
			t.Errorf("%d data mismatch, want\n%x\ngot\n%x", i, test.want, got)
		}
	}
}
