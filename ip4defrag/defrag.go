// Copyright 2013 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package ip4defrag implements a IPv4 defragmenter
package ip4defrag

import (
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Quick and Easy to use debug code to trace
// how defrag works.
var debug debugging = false // or flip to true
type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	if d {
		log.Printf(format, args...)
	}
}

// Constants determining how to handle fragments.
// Reference RFC 791, page 25
const (
	IPv4MinimumFragmentSize    = 8     // Minimum size of a single fragment
	IPv4MaximumSize            = 65535 // Maximum size of a fragment (2^16)
	IPv4MaximumFragmentOffset  = 8189  // Maximum offset of a fragment, (65535 - 20) / 8
	IPv4MaximumFragmentListLen = 8192  // Back out if we get more than this many fragments
)

// fragmentUnit is the granularity of the fragment offset field.
const fragmentUnit = 8

// DefragIPv4 takes in an IPv4 packet with a fragment payload.
//
// It do not modify the IPv4 layer in place, 'in' remains untouched
// It returns a ready-to be used IPv4 layer.
//
// If the passed-in IPv4 layer is NOT fragmented, it will
// immediately return it without modifying the layer.
//
// If the IPv4 layer is a fragment and we don't have all
// fragments, it will return nil and store whatever internal
// information it needs to eventually defrag the packet.
//
// If the IPv4 layer is the last fragment needed to reconstruct
// the packet, a new IPv4 layer will be returned, and will be set to
// the entire defragmented packet,
//
// # It use a map of all the running flows
//
// Usage example:
//
//	func HandlePacket(in *layers.IPv4) err {
//	    defragger := ip4defrag.NewIPv4Defragmenter()
//	    in, err := defragger.DefragIPv4(in)
//	    if err != nil {
//	        return err
//	    } else if in == nil {
//	        return nil  // packet fragment, we don't have whole packet yet.
//	    }
//	    // At this point, we know that 'in' is defragmented.
//	    //It may be the same 'in' passed to
//		   // HandlePacket, or it may not, but we don't really care :)
//		   ... do stuff to 'in' ...
//	}
func (d *IPv4Defragmenter) DefragIPv4(in *layers.IPv4) (*layers.IPv4, error) {
	return d.DefragIPv4WithTimestamp(in, time.Now())
}

// DefragIPv4WithTimestamp provides functionality of DefragIPv4 with
// an additional timestamp parameter which is used for discarding
// old fragments instead of time.Now()
//
// This is useful when operating on pcap files instead of live captured data
func (d *IPv4Defragmenter) DefragIPv4WithTimestamp(in *layers.IPv4, t time.Time) (*layers.IPv4, error) {
	// check if we need to defrag
	if st := d.dontDefrag(in); st == true {
		debug.Printf("defrag: do nothing, do not need anything")
		return in, nil
	}
	// perfom security checks
	if err := d.securityChecks(in); err != nil {
		debug.Printf("defrag: alert security check")
		// a receiver (Linux at least) drops the fragments it held
		// before such a fragment. Drop them too, or they take the
		// place of the ones sent again with the same Id
		d.flush(newIPv4(in))
		return nil, err
	}

	// ok, got a fragment
	debug.Printf("defrag: got a new fragment in.Id=%d in.FragOffset=%d in.Flags=%d\n",
		in.Id, in.FragOffset*8, in.Flags)

	// have we already seen a flow between src/dst with that Id?
	ipf := newIPv4(in)
	var fl *fragmentList
	var exist bool
	d.Lock()
	fl, exist = d.ipFlows[ipf]
	if !exist {
		debug.Printf("defrag: unknown flow, creating a new one\n")
		fl = new(fragmentList)
		d.ipFlows[ipf] = fl
	}
	d.Unlock()
	// insert, and if final build it
	out, err2 := fl.insert(in, t)

	// the fragments contradict each other and will never make a
	// datagram: drop them all, as receivers do, so that they can't
	// get in the way of the next datagram using that Id
	if err2 != nil {
		d.flush(ipf)
		return nil, err2
	}

	// at last, if we hit the maximum frag list len
	// without any defrag success, we just drop everything and
	// raise an error
	if out == nil && len(fl.frags)+1 > IPv4MaximumFragmentListLen {
		d.flush(ipf)
		return nil, fmt.Errorf("defrag: Fragment List hits its maximum"+
			"size(%d), without success. Flushing the list",
			IPv4MaximumFragmentListLen)
	}

	// if we got a packet, it's a new one, and he is defragmented
	if out != nil {
		// when defrag is done for a flow between two ip
		// clean the list
		d.flush(ipf)
		return out, nil
	}
	return nil, err2
}

// DiscardOlderThan forgets all packets without any activity since
// time t. It returns the number of FragmentList aka number of
// fragment packets it has discarded.
func (d *IPv4Defragmenter) DiscardOlderThan(t time.Time) int {
	var nb int
	d.Lock()
	for k, v := range d.ipFlows {
		if v.LastSeen.Before(t) {
			nb = nb + 1
			delete(d.ipFlows, k)
		}
	}
	d.Unlock()
	return nb
}

// flush the fragment list for a particular flow
func (d *IPv4Defragmenter) flush(ipf ipv4) {
	d.Lock()
	delete(d.ipFlows, ipf)
	d.Unlock()
}

// dontDefrag returns true if the IPv4 packet do not need
// any defragmentation
func (d *IPv4Defragmenter) dontDefrag(ip *layers.IPv4) bool {
	// don't defrag not fragmented ones. The DF flag is not looked
	// at: it only forbids further fragmentation on the path, and
	// receivers reassemble fragments that carry it
	if ip.Flags&layers.IPv4MoreFragments == 0 && ip.FragOffset == 0 {
		return true
	}
	return false
}

// securityChecks performs the needed security checks
func (d *IPv4Defragmenter) securityChecks(ip *layers.IPv4) error {
	fragSize := ip.Length - uint16(ip.IHL)*4

	// don't allow small fragments outside of specification
	if ip.Flags&layers.IPv4MoreFragments != 0 && fragSize < IPv4MinimumFragmentSize {
		return fmt.Errorf("defrag: fragment too small "+
			"(handcrafted? %d < %d)", fragSize, IPv4MinimumFragmentSize)
	}

	// don't allow too big fragment offset
	if ip.FragOffset > IPv4MaximumFragmentOffset {
		return fmt.Errorf("defrag: fragment offset too big "+
			"(handcrafted? %d > %d)", ip.FragOffset, IPv4MaximumFragmentOffset)
	}

	// don't allow fragment that would oversize an IP packet
	// (summed in int: the uint16 sum wrapped and never fired)
	fragEnd := int(ip.FragOffset)*8 + int(ip.Length)
	if fragEnd > IPv4MaximumSize {
		return fmt.Errorf("defrag: fragment will overrun "+
			"(handcrafted? %d > %d)", fragEnd, IPv4MaximumSize)
	}

	return nil
}

// fragment is one stored IPv4 fragment and the payload byte range
// [start, end) it covers in the datagram.
type fragment struct {
	ip    *layers.IPv4
	start int
	end   int
}

// fragmentList holds the fragments of one datagram, sorted by offset
// and never overlapping. It stores internal counters to track the
// maximum total of byte, and the current length it has received.
// It also stores a flag to know if he has seen the last packet.
type fragmentList struct {
	frags         []fragment
	Highest       int
	Current       int
	FinalReceived bool
	LastSeen      time.Time
}

// insert insert an IPv4 fragment/packet into the Fragment List.
// It applies the rules a receiver (Linux) uses: only whole 8 byte
// units of a non-final fragment count, the final fragment fixes the
// end of the datagram, a repeat of bytes already held is ignored and
// any other overlap or contradiction is an error, after which the
// caller drops the whole list.
//
//	held:   [0,16)      [24,32) final
//	[8,16)  repeat, ignored
//	[8,24)  overlaps, error
//	[32,40) beyond the final fragment, error
//	[16,24) stored, datagram complete
func (f *fragmentList) insert(in *layers.IPv4, t time.Time) (*layers.IPv4, error) {
	// TODO: should keep a copy of *in in the list
	// or not (ie the packet source is reliable) ? -> depends on Lazy / last packet
	start := int(in.FragOffset) * 8
	length := int(in.Length) - int(in.IHL)*4
	more := in.Flags&layers.IPv4MoreFragments != 0

	// a receiver only uses whole 8 byte units of a non-final
	// fragment, the rest is dropped (RFC 791: all fragments but the
	// last hold a multiple of 8 bytes)
	if more {
		length &^= fragmentUnit - 1
	}
	end := start + length
	if length <= 0 {
		return nil, errors.New("defrag: empty fragment")
	}

	// the stored fragments [i, j) share bytes with the new one; a
	// repeat is decided before the list state changes, so it leaves
	// no trace
	i := sort.Search(len(f.frags), func(k int) bool { return f.frags[k].end > start })
	j := i
	for j < len(f.frags) && f.frags[j].start < end {
		j++
	}
	if i < j {
		if f.covered(i, j, start, end) {
			debug.Printf("defrag: ignoring frag %d as we already have it (duplicate?)\n", start)
			return nil, nil
		}
		return nil, errors.New("defrag: fragment overlaps another one")
	}

	// the final fragment tells where the datagram ends: it can't end
	// before data already held, two final fragments have to agree,
	// and nothing may reach beyond it
	switch {
	case !more:
		if end < f.Highest || (f.FinalReceived && end != f.Highest) {
			return nil, errors.New("defrag: final fragment does not end the datagram")
		}
		f.FinalReceived = true
		f.Highest = end
	case end > f.Highest:
		if f.FinalReceived {
			return nil, errors.New("defrag: fragment beyond the final fragment")
		}
		f.Highest = end
	}

	f.frags = slices.Insert(f.frags, i, fragment{ip: in, start: start, end: end})
	f.LastSeen = t
	f.Current += length

	debug.Printf("defrag: insert ListLen: %d Highest:%d Current:%d\n",
		len(f.frags), f.Highest, f.Current)

	// Ready to try defrag ?
	if f.FinalReceived && f.Highest == f.Current {
		return f.build(in)
	}
	return nil, nil
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

// Build builds the final datagram, modifying ip in place.
func (f *fragmentList) build(in *layers.IPv4) (*layers.IPv4, error) {
	final := make([]byte, 0, f.Highest)
	currentOffset := 0

	debug.Printf("defrag: building the datagram \n")
	for _, frag := range f.frags {
		if frag.start != currentOffset {
			// Houston - we have an hole !
			debug.Printf("defrag: hole found while building, " +
				"stopping the defrag process\n")
			return nil, errors.New("defrag: building - hole found")
		}
		debug.Printf("defrag: building - adding %d\n", frag.start)
		// the payload may hold fewer bytes than the header announces
		// (truncated capture) and more when a non-final fragment was
		// cut to whole 8 byte units
		final = append(final, frag.ip.Payload[:min(frag.end-frag.start, len(frag.ip.Payload))]...)
		currentOffset = frag.end
	}

	// TODO recompute IP Checksum
	out := &layers.IPv4{
		Version:    in.Version,
		IHL:        in.IHL,
		TOS:        in.TOS,
		Length:     uint16(int(in.IHL)*4 + len(final)),
		Id:         in.Id,
		Flags:      0,
		FragOffset: 0,
		TTL:        in.TTL,
		Protocol:   in.Protocol,
		Checksum:   0,
		SrcIP:      in.SrcIP,
		DstIP:      in.DstIP,
		Options:    in.Options,
		Padding:    in.Padding,
	}
	out.Payload = final

	return out, nil
}

// ipv4 is a struct to be used as a key.
// RFC 791 section 2.3: fragments belong to one datagram only when
// source, destination, protocol and Id all match.
type ipv4 struct {
	ip4      gopacket.Flow
	id       uint16
	protocol layers.IPProtocol
}

// newIPv4 returns a new initialized IPv4 Flow
func newIPv4(ip *layers.IPv4) ipv4 {
	return ipv4{
		ip4:      ip.NetworkFlow(),
		id:       ip.Id,
		protocol: ip.Protocol,
	}
}

// IPv4Defragmenter is a struct which embedded a map of
// all fragment/packet.
type IPv4Defragmenter struct {
	sync.RWMutex
	ipFlows map[ipv4]*fragmentList
}

// NewIPv4Defragmenter returns a new IPv4Defragmenter
// with an initialized map.
func NewIPv4Defragmenter() *IPv4Defragmenter {
	return &IPv4Defragmenter{
		ipFlows: make(map[ipv4]*fragmentList),
	}
}
