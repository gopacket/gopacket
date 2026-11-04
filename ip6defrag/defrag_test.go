// SPDX-FileCopyrightText: 2013 Google, Inc
// SPDX-FileCopyrightText: 2022 Cloud <cloud@txthinking.com>
// SPDX-License-Identifier: BSD-3-Clause
//
// The `ip6defrag` package was created by txthinking to provide IPv6 fragment reassembly (defragmentation) support.
// This feature was originally submitted as PR #943 to the google/gopacket repository: https://github.com/google/gopacket/pull/943  // Since google/gopacket has infrequent maintenance, I've ported the implementation to the active community fork: gopacket/gopacket.

package ip6defrag

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

func TestFrag(t *testing.T) {
	d := NewIPv6Defragmenter()

	l := &layers.IPv6{
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		NextHeader:   layers.IPProtocolIPv6Fragment,
		HopLimit:     0,
		SrcIP:        net.IPv6zero,
		DstIP:        net.IPv6zero,
	}

	l1 := &layers.IPv6Fragment{
		NextHeader:     layers.IPProtocolIPv6Fragment,
		FragmentOffset: 0,
		MoreFragments:  true,
		Identification: 1,
	}
	l1.Payload = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	l2 := &layers.IPv6Fragment{
		NextHeader:     layers.IPProtocolIPv6Fragment,
		FragmentOffset: 1,
		MoreFragments:  true,
		Identification: 1,
	}
	l2.Payload = []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	l3 := &layers.IPv6Fragment{
		NextHeader:     layers.IPProtocolTCP,
		FragmentOffset: 2,
		MoreFragments:  false,
		Identification: 1,
	}
	l3.Payload = []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}

	ipv6 := d.DefragIPv6(l, l1)
	if ipv6 != nil {
		t.Fatal("input: l1, output shoud be: nil")
	}
	ipv6 = d.DefragIPv6(l, l3)
	if ipv6 != nil {
		t.Fatal("input: l1+l3, output shoud be: nil")
	}
	ipv6 = d.DefragIPv6(l, l2)
	if ipv6 == nil {
		t.Fatal("input: l1+l3+l2, output shoud be: ipv6")
	}
	if ipv6.Payload[0] != 0x01 || ipv6.Payload[15] != 0x18 || ipv6.Payload[16] != 0x21 {
		t.Fatal("return invalid payload")
	}
}

// testIPv6 is the header every fragment built by mkFrag6 arrives in.
var testIPv6 = &layers.IPv6{
	Version:    6,
	NextHeader: layers.IPProtocolIPv6Fragment,
	HopLimit:   64,
	SrcIP:      net.ParseIP("2001:db8::1"),
	DstIP:      net.ParseIP("2001:db8::2"),
}

// mkFrag6 builds one IPv6 fragment of packet id covering payload bytes
// [offset, offset+len(payload)).
func mkFrag6(id uint32, offset int, more bool, payload []byte) *layers.IPv6Fragment {
	fg := &layers.IPv6Fragment{
		NextHeader:     layers.IPProtocolUDP,
		FragmentOffset: uint16(offset / 8),
		MoreFragments:  more,
		Identification: id,
	}
	fg.Payload = payload
	return fg
}

// feedFrags passes fragments in and expects none of them to complete
// a packet.
func feedFrags(t *testing.T, d *IPv6Defragmenter, frags ...*layers.IPv6Fragment) {
	t.Helper()
	for i, fg := range frags {
		if out := d.DefragIPv6(testIPv6, fg); out != nil {
			t.Fatalf("defrag: fragment %d completed a packet of %d bytes", i, len(out.Payload))
		}
	}
}

// lastFrag passes the fragment that should complete the packet and
// checks the payload that comes back.
func lastFrag(t *testing.T, d *IPv6Defragmenter, fg *layers.IPv6Fragment, want []byte) *layers.IPv6 {
	t.Helper()
	out := d.DefragIPv6(testIPv6, fg)
	if out == nil {
		t.Fatal("defrag: got nil, want the packet")
	}
	if !bytes.Equal(out.Payload, want) {
		t.Fatalf("defrag: got payload %q, want %q", out.Payload, want)
	}
	return out
}

func cat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

func TestFragOverlap(t *testing.T) {
	decoy := bytes.Repeat([]byte("d"), 32)
	real := bytes.Repeat([]byte("r"), 32)
	tail := bytes.Repeat([]byte("t"), 8)

	// RFC 8200 section 4.5: an overlapping fragment ends reassembly
	// of the whole packet. The decoy must go with it, or it shadows
	// the real first fragment.
	d := NewIPv6Defragmenter()
	feedFrags(t, d, mkFrag6(1, 0, true, decoy), mkFrag6(1, 0, true, cat(decoy, tail)),
		mkFrag6(1, 0, true, real))
	lastFrag(t, d, mkFrag6(1, 32, false, tail), cat(real, tail))

	// A last fragment ending inside data already held, and a fragment
	// reaching past the last one, make no packet either.
	x := make([]byte, 8)
	for i, seq := range [][]*layers.IPv6Fragment{
		{mkFrag6(2, 0, true, cat(x, x)), mkFrag6(2, 24, true, x), mkFrag6(2, 16, false, cat(x, x, x))},
		{mkFrag6(3, 0, true, cat(x, x)), mkFrag6(3, 24, false, x), mkFrag6(3, 16, false, x)},
	} {
		for _, fg := range seq {
			if out := d.DefragIPv6(testIPv6, fg); out != nil {
				t.Fatalf("defrag: sequence %d returned a packet of %d bytes", i, len(out.Payload))
			}
		}
	}

	// A repeated fragment is ignored.
	feedFrags(t, d, mkFrag6(4, 0, true, real[:8]), mkFrag6(4, 0, true, real[:8]))
	lastFrag(t, d, mkFrag6(4, 8, false, tail), cat(real[:8], tail))
}

func TestFragInvalidLength(t *testing.T) {
	head := bytes.Repeat([]byte("h"), 16)
	mid := bytes.Repeat([]byte("m"), 16)
	tail := bytes.Repeat([]byte("t"), 6)
	want := cat(head, mid, tail)

	// A receiver discards a fragment with no data, a non-final one
	// that is not a multiple of 8 bytes, and one reaching past 65535
	// bytes. Stored, each took the place of the real fragment.
	d := NewIPv6Defragmenter()
	feedFrags(t, d, mkFrag6(1, 16, true, nil), mkFrag6(1, 0, true, head), mkFrag6(1, 16, true, mid))
	lastFrag(t, d, mkFrag6(1, 32, false, tail), want)

	d = NewIPv6Defragmenter()
	feedFrags(t, d, mkFrag6(2, 16, true, make([]byte, 20)), mkFrag6(2, 0, true, head), mkFrag6(2, 16, true, mid))
	lastFrag(t, d, mkFrag6(2, 32, false, tail), want)

	d = NewIPv6Defragmenter()
	piece := make([]byte, 1480)
	for i := 0; i < 44; i++ {
		feedFrags(t, d, mkFrag6(3, i*1480, true, piece))
	}
	feedFrags(t, d, mkFrag6(3, 44*1480, false, make([]byte, 1000)))
	lastFrag(t, d, mkFrag6(3, 44*1480, false, make([]byte, 200)), make([]byte, 44*1480+200))
}

func TestFragReuseIdentification(t *testing.T) {
	// A completed packet must leave the map, or the next packet with
	// the same Identification is taken for a repeat of it.
	d := NewIPv6Defragmenter()
	for _, c := range []byte("ab") {
		head := bytes.Repeat([]byte{c}, 24)
		tail := bytes.Repeat([]byte{c}, 16)
		feedFrags(t, d, mkFrag6(8, 0, true, head))
		lastFrag(t, d, mkFrag6(8, 24, false, tail), cat(head, tail))
	}
}

func TestFragDuplicateKeepsAge(t *testing.T) {
	// RFC 8200 section 4.5 ages a packet from its first fragment. A
	// repeated fragment used to make the list younger, so a sender
	// could keep it past DiscardOlderThan with one packet per period.
	d := NewIPv6Defragmenter()
	feedFrags(t, d, mkFrag6(1, 0, true, make([]byte, 16)))
	time.Sleep(time.Millisecond)
	cutoff := time.Now()

	feedFrags(t, d, mkFrag6(1, 0, true, make([]byte, 16)))
	if n := d.DiscardOlderThan(cutoff); n != 1 {
		t.Fatalf("defrag: discarded %d lists, want 1", n)
	}
}

func TestFragListWalk(t *testing.T) {
	// Placing a fragment used to walk the whole list twice. Filling a
	// list in order, then repeating its last fragment, made each
	// packet cost thousands of node visits. Compare with the same
	// number of fragments arriving as two-fragment packets.
	const fill, repeats = 8192, 10000
	eight := make([]byte, 8)

	attack := func() {
		d := NewIPv6Defragmenter()
		for off := 0; off < fill; off++ {
			d.DefragIPv6(testIPv6, mkFrag6(1, off*8, true, eight))
		}
		for i := 0; i < repeats; i++ {
			d.DefragIPv6(testIPv6, mkFrag6(1, (fill-1)*8, true, eight))
		}
	}
	pairs := func() {
		d := NewIPv6Defragmenter()
		for i := 0; i < (fill+repeats)/2; i++ {
			d.DefragIPv6(testIPv6, mkFrag6(1, 0, true, eight))
			d.DefragIPv6(testIPv6, mkFrag6(1, 8, false, eight))
		}
	}

	start := time.Now()
	pairs()
	base := time.Since(start)
	start = time.Now()
	attack()
	slow := time.Since(start)

	if slow > 5*base {
		t.Fatalf("defrag: a full list costs %v, two-fragment packets %v", slow, base)
	}
}

func TestAtomicFrag(t *testing.T) {
	// RFC 8200 section 4.5: a fragment with offset 0 and M = 0 is the
	// whole packet. It used to wait for fragments that never come.
	d := NewIPv6Defragmenter()
	payload := bytes.Repeat([]byte("a"), 24)
	out := lastFrag(t, d, mkFrag6(1, 0, false, payload), payload)
	if out.NextHeader != layers.IPProtocolUDP || !out.SrcIP.Equal(testIPv6.SrcIP) {
		t.Fatalf("defrag: got next header %v from %v", out.NextHeader, out.SrcIP)
	}
	if n := d.DiscardOlderThan(time.Now().Add(time.Hour)); n != 0 {
		t.Fatalf("defrag: %d lists left behind", n)
	}
}

func TestFragDifferentFlowsSameID(t *testing.T) {
	// RFC 8200 section 4.5: fragments belong to one packet only when
	// source, destination and Identification all match. A first
	// fragment between other addresses used to take the place of the
	// real one.
	d := NewIPv6Defragmenter()
	other := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Fragment,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::bad"),
		DstIP:      net.ParseIP("2001:db8::bae"),
	}
	head := bytes.Repeat([]byte("h"), 16)
	tail := bytes.Repeat([]byte("t"), 11)

	if out := d.DefragIPv6(other, mkFrag6(1, 0, true, bytes.Repeat([]byte("x"), 16))); out != nil {
		t.Fatal("defrag: a lone first fragment completed a packet")
	}
	feedFrags(t, d, mkFrag6(1, 0, true, head))
	out := lastFrag(t, d, mkFrag6(1, 16, false, tail), cat(head, tail))
	if !out.SrcIP.Equal(testIPv6.SrcIP) || !out.DstIP.Equal(testIPv6.DstIP) {
		t.Fatalf("defrag: packet carries %v -> %v", out.SrcIP, out.DstIP)
	}
}
