// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/gopacket/gopacket"
)

// allocPerByte returns the bytes f allocates per input byte. Lists grown
// by append from empty spend about twice the final size on the way, so
// a packet of minimal items costs far more than the items themselves.
func allocPerByte(n int, f func()) float64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return float64(after.TotalAlloc-before.TotalAlloc) / float64(n)
}

// A 64 KB GOOSE of empty octet strings (89 00) must not cost more than
// its item structs: one MMSData per two input bytes.
func TestGOOSEAllocBound(t *testing.T) {
	const items = 32000
	const maxPerByte = 100

	all := bytes.Repeat([]byte{0x89, 0x00}, items)
	pdu := append([]byte{0xab, 0x83}, byte(len(all)>>16), byte(len(all)>>8), byte(len(all)))
	pdu = append(pdu, all...)
	body := append([]byte{0x61, 0x83}, byte(len(pdu)>>16), byte(len(pdu)>>8), byte(len(pdu)))
	body = append(body, pdu...)

	frame := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint16(frame[2:4], uint16(8+len(body)))
	frame = append(frame, body...)

	got := allocPerByte(len(frame), func() {
		g := &GOOSE{}
		_ = g.DecodeFromBytes(frame, gopacket.NilDecodeFeedback)
	})
	t.Logf("GOOSE: %.0f bytes per input byte", got)
	if got > maxPerByte {
		t.Fatalf("GOOSE allocates %.0f bytes per input byte, want <= %d", got, maxPerByte)
	}
}

// A BVLC full of one-octet Null tags must not cost more than the tag
// structs themselves.
func TestBACnetTagAllocBound(t *testing.T) {
	const tags = 60000
	const maxPerByte = 60

	tagData := bytes.Repeat([]byte{0x00}, tags)
	got := allocPerByte(len(tagData), func() {
		_, _ = decodeBACnetTags(tagData)
	})
	t.Logf("BACnet: %.0f bytes per input byte", got)
	if got > maxPerByte {
		t.Fatalf("BACnet tags allocate %.0f bytes per input byte, want <= %d", got, maxPerByte)
	}
}

// A DCP Get request lists two-octet selectors; their count is known up
// front, so the list must not be grown by append.
func TestProfinetDCPAllocBound(t *testing.T) {
	const selectors = 744
	const maxPerByte = 120

	data := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x05, 0xd0}
	data = append(data, make([]byte, 2*selectors)...)
	got := allocPerByte(len(data), func() {
		d := &ProfinetDCP{}
		_ = d.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	})
	t.Logf("PROFINET DCP: %.0f bytes per input byte", got)
	if got > maxPerByte {
		t.Fatalf("DCP allocates %.0f bytes per input byte, want <= %d", got, maxPerByte)
	}
}
