// SPDX-FileCopyrightText: 2013 Google, Inc
// SPDX-FileCopyrightText: 2022 Cloud <cloud@txthinking.com>
// SPDX-License-Identifier: BSD-3-Clause
//
// The `ip6defrag` package was created by txthinking to provide IPv6 fragment reassembly (defragmentation) support.
// This feature was originally submitted as PR #943 to the google/gopacket repository: https://github.com/google/gopacket/pull/943
// Since google/gopacket has infrequent maintenance, I've ported the implementation to the active community fork: gopacket/gopacket.

// Package ip6defrag implements a IPv6 defragmenter
package ip6defrag

import (
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// maxPayload is the largest payload a fragmented packet can
// reassemble to, see RFC 8200 section 4.5.
const maxPayload = 65535

// fragmentUnit is the granularity of the fragment offset field.
const fragmentUnit = 8

// IPv6Defragmenter is a struct which embedded a map of all fragment/packet.
type IPv6Defragmenter struct {
	container map[ipv6Key]*fragmentList
	lock      *sync.Mutex
}

// ipv6Key identifies a packet under reassembly. RFC 8200 section 4.5:
// fragments belong to one packet only when source, destination and
// Identification all match.
type ipv6Key struct {
	ip6 gopacket.Flow
	id  uint32
}

// fragment is one stored IPv6 fragment and the payload byte range
// [start, end) it covers in the packet.
type fragment struct {
	ipv6       *layers.IPv6
	start      int
	end        int
	payload    []byte
	more       bool
	nextheader layers.IPProtocol
}

// fragmentList holds the fragments of one packet, sorted by offset
// and never overlapping. end is the highest byte seen, and the end
// of the packet once the last fragment is in.
type fragmentList struct {
	frags    []fragment
	end      int
	current  int
	lastSeen bool
	time     time.Time
}

// insertResult says what insert did with a fragment.
type insertResult int

const (
	stored insertResult = iota
	// a repeat of bytes already held
	ignored
	// the fragment contradicts the packet, drop it all
	dropPacket
)

// NewIPv6Defragmenter returns a new IPv6Defragmenter with an initialized map.
func NewIPv6Defragmenter() *IPv6Defragmenter {
	return &IPv6Defragmenter{
		container: make(map[ipv6Key]*fragmentList),
		lock:      &sync.Mutex{},
	}
}

// DefragIPv6 takes in an IPv6 packet with a fragment payload.
//
// It do not modify the IPv6 layer fragment in place,
// It returns a ready-to be used IPv6 layer.
//
// If and we don't have all fragments,
// it will return nil and store whatever internal
// information it needs to eventually defrag the packet.
//
// If the IPv6 fragment is the last fragment needed to reconstruct
// the packet, a new IPv6 layer will be returned, and will be set to
// the entire defragmented packet,
//
// # It use a map of all the running flows
//
// Usage example:
//
// var d = NewIPv6Defragmenter()
//
//	func HandlePacket(p gopacket.Packet) {
//		ipv6, ok := p.NetworkLayer().(*layers.IPv6)
//		if !ok {
//			// ignore: not ipv6
//			return
//		}
//		if fg, ok := p.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment); ok {
//			if fg.NextHeader != layers.IPProtocolUDP && fg.NextHeader != layers.IPProtocolTCP {
//				// ignore: !TCP and !UDP fragment
//				return
//			}
//			ipv6 = d.DefragIPv6(ipv6, fg)
//			if ipv6 == nil {
//				// ignore: do nothing, wait next fragment
//				return
//			}
//		}
//		// You got the ipv6 layer
//	}
func (d *IPv6Defragmenter) DefragIPv6(ipv6 *layers.IPv6, fg *layers.IPv6Fragment) *layers.IPv6 {
	in := fragment{
		start:      int(fg.FragmentOffset) * fragmentUnit,
		payload:    fg.LayerPayload(),
		more:       fg.MoreFragments,
		nextheader: fg.NextHeader,
	}
	in.end = in.start + len(in.payload)
	// first
	if in.start == 0 {
		in.ipv6 = ipv6
	}

	// a receiver discards a fragment that would make the packet
	// exceed 65535 bytes, and a non-final one that is not a whole
	// number of 8 byte units (RFC 8200 section 4.5). Stored, it would
	// take the place of the real fragment at that offset
	if in.end > maxPayload || (in.more && len(in.payload)%fragmentUnit != 0) {
		return nil
	}

	d.lock.Lock()
	defer d.lock.Unlock()

	key := ipv6Key{ip6: ipv6.NetworkFlow(), id: fg.Identification}
	f, ok := d.container[key]
	if !ok {
		// remember the first coming. The packet is as old as it
		// (RFC 8200 section 4.5), later fragments do not make it younger
		f = &fragmentList{time: time.Now()}
	}

	switch f.insert(in) {
	case ignored:
		return nil
	case dropPacket:
		delete(d.container, key)
		return nil
	}
	if !f.complete() {
		d.container[key] = f
		return nil
	}

	// the packet is complete, forget its fragments: the next one with
	// this Identification is a new packet
	delete(d.container, key)
	return f.build()
}

// insert files in into the list. It applies the rules of RFC 8200
// section 4.5 as Linux does: the last fragment fixes the end of the
// packet and nothing may reach beyond it, an empty fragment or an
// overlap ends reassembly of the whole packet, and a repeat of bytes
// already held is ignored.
//
//	held:   [0,16)      [24,32) last
//	[8,16)  repeat, ignored
//	[8,24)  overlap, packet dropped
//	[32,40) beyond the last fragment, packet dropped
//	[16,24) stored, packet complete
func (f *fragmentList) insert(in fragment) insertResult {
	switch {
	case !in.more:
		if in.end < f.end || (f.lastSeen && in.end != f.end) {
			return dropPacket
		}
		f.lastSeen = true
		f.end = in.end
	case in.end > f.end:
		if f.lastSeen {
			return dropPacket
		}
		f.end = in.end
	}
	if in.start == in.end {
		return dropPacket
	}

	// the stored fragments [i, j) share bytes with the new one
	i := sort.Search(len(f.frags), func(k int) bool { return f.frags[k].end > in.start })
	j := i
	for j < len(f.frags) && f.frags[j].start < in.end {
		j++
	}
	if i < j {
		if f.covered(i, j, in.start, in.end) {
			return ignored
		}
		return dropPacket
	}

	f.frags = slices.Insert(f.frags, i, in)
	f.current += in.end - in.start
	return stored
}

// covered tells whether the stored fragments [i, j), which all touch
// [start, end), hold every byte of it without a gap.
func (f *fragmentList) covered(i, j, start, end int) bool {
	if f.frags[i].start > start || f.frags[j-1].end < end {
		return false
	}
	for k := i; k < j-1; k++ {
		if f.frags[k].end != f.frags[k+1].start {
			return false
		}
	}
	return true
}

// complete tells whether the fragments held tile the whole packet.
func (f *fragmentList) complete() bool {
	return f.lastSeen && f.current == f.end
}

// build makes the packet out of the fragments, which tile [0, end).
func (f *fragmentList) build() *layers.IPv6 {
	b := make([]byte, 0, f.end)
	for _, frag := range f.frags {
		b = append(b, frag.payload...)
	}

	first := f.frags[0]
	last := f.frags[len(f.frags)-1]
	l := &layers.IPv6{
		Version:      6,
		TrafficClass: first.ipv6.TrafficClass,
		FlowLabel:    first.ipv6.FlowLabel,
		NextHeader:   last.nextheader,
		HopLimit:     first.ipv6.HopLimit,
		SrcIP:        first.ipv6.SrcIP,
		DstIP:        first.ipv6.DstIP,
	}
	l.Payload = b
	return l
}

// DiscardOlderThan forgets all packets whose first fragment arrived
// before time t. It returns the number of FragmentList aka number of
// fragment packets it has discarded.
func (d *IPv6Defragmenter) DiscardOlderThan(t time.Time) int {
	var n int
	d.lock.Lock()
	defer d.lock.Unlock()
	for k, v := range d.container {
		if v.time.Before(t) {
			n = n + 1
			delete(d.container, k)
		}
	}
	return n
}
