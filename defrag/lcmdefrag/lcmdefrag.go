// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package lcmdefrag contains a defragmenter for LCM messages.
package lcmdefrag

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const (
	// Packages are cleaned up/removed after no input was received for this
	// amount of seconds.
	timeout time.Duration = 3 * time.Second

	// Limits on the fragments held for incomplete packages, the same as
	// MAX_FRAG_BUF_TOTAL_SIZE and MAX_NUM_FRAG_BUFS of the LCM reference
	// implementation. The timeout alone bounds nothing, as every further
	// fragment of a package renews it.
	maxFragBufTotalSize = 1 << 24
	maxNumFragBufs      = 1000

	// What a held fragment roughly costs on top of its bytes (the
	// layers.LCM and the map entry), so tiny fragments are not held for free.
	fragOverhead = 128
)

// timeNow is time.Now, replaced by tests that move the clock.
var timeNow = time.Now

type lcmPacket struct {
	lastPacket time.Time
	done       bool
	recFrags   uint16
	totalFrags uint16
	size       int
	frags      map[uint16]*layers.LCM
}

// LCMDefragmenter supports defragmentation of LCM messages.
//
// The fragments of at most 1000 incomplete messages and 16 MB in total are
// held at a time. Beyond that the least recently updated messages are
// dropped.
//
// References
//
//	https://lcm-proj.github.io/
//	https://github.com/lcm-proj/lcm
type LCMDefragmenter struct {
	packets     map[uint32]*lcmPacket
	lastCleanUp time.Time
	held        int // bytes of fragments in packets, as fragSize counts them
}

func newLCMPacket(totalFrags uint16) *lcmPacket {
	return &lcmPacket{
		done:       false,
		recFrags:   0,
		totalFrags: totalFrags,
		frags:      make(map[uint16]*layers.LCM),
	}
}

// NewLCMDefragmenter returns a new LCMDefragmenter.
func NewLCMDefragmenter() *LCMDefragmenter {
	return &LCMDefragmenter{
		packets: make(map[uint32]*lcmPacket),
	}
}

func fragSize(frag *layers.LCM) int {
	return fragOverhead + len(frag.LayerContents()) + len(frag.Payload())
}

// append stores a fragment and returns by how many bytes the held fragments
// grew.
func (lp *lcmPacket) append(in *layers.LCM, now time.Time) int {
	grown := fragSize(in)

	// A retransmitted fragment replaces the one it repeats and must not
	// count towards completion twice.
	if old, ok := lp.frags[in.FragmentNumber]; ok {
		grown -= fragSize(old)
	} else {
		lp.recFrags++
	}
	lp.frags[in.FragmentNumber] = in
	lp.size += grown
	lp.lastPacket = now
	return grown
}

func (lp *lcmPacket) assemble() (out *layers.LCM, err error) {
	var blob []byte

	//Extract packets
	for i := uint16(0); i < lp.totalFrags; i++ {
		fragment, ok := lp.frags[i]
		if !ok {
			err = fmt.Errorf("Tried to defragment incomplete packet. Waiting "+
				"for more potential (unordered) packets... %d", i)
			return
		}

		// For the very first packet, we also want the header.
		if i == 0 {
			blob = append(blob, fragment.LayerContents()...)
		}

		// Append the data for each packet.
		blob = append(blob, fragment.Payload()...)
	}

	packet := gopacket.NewPacket(blob, layers.LayerTypeLCM, gopacket.NoCopy)
	lcmHdrLayer := packet.Layer(layers.LayerTypeLCM)
	out, ok := lcmHdrLayer.(*layers.LCM)
	if !ok {
		err = fmt.Errorf("Error while decoding the defragmented packet. " +
			"Erasing/dropping packet.")
	}

	lp.done = true

	return
}

func (ld *LCMDefragmenter) cleanUp() {
	now := timeNow()
	ld.lastCleanUp = now
	for key, packet := range ld.packets {
		if packet.done || now.Sub(packet.lastPacket) > timeout {
			ld.drop(key)
		}
	}
}

// drop forgets a pending package and the bytes it held.
func (ld *LCMDefragmenter) drop(key uint32) {
	ld.held -= ld.packets[key].size
	delete(ld.packets, key)
}

// enforceLimits drops the least recently updated packages until the held
// fragments are within maxFragBufTotalSize and maxNumFragBufs. The package
// current, which just received a fragment, is only dropped if it exceeds
// the size limit on its own.
func (ld *LCMDefragmenter) enforceLimits(current uint32) {
	for ld.held > maxFragBufTotalSize || len(ld.packets) > maxNumFragBufs {
		var oldestKey uint32
		var oldest *lcmPacket
		for key, packet := range ld.packets {
			if key == current {
				continue
			}
			if oldest == nil || packet.lastPacket.Before(oldest.lastPacket) {
				oldestKey, oldest = key, packet
			}
		}

		// Nothing else left to drop: the current package is too big.
		if oldest == nil {
			ld.drop(current)
			return
		}
		ld.drop(oldestKey)
	}
}

// Defrag takes a reference to an LCM packet and processes it.
// In case the packet does not need to be defragmented, it immediately returns
// the as in passed reference. In case in was the last missing fragment, out
// will be the defragmented packet. If in was a fragment, but we are awaiting
// more, out will be set to nil.
// In the case that in was nil, we will just run the internal cleanup of the
// defragmenter that times out packages.
// If an error was encountered during defragmentation, out will also be nil,
// while err will contain further information on the failure.
func (ld *LCMDefragmenter) Defrag(in *layers.LCM) (out *layers.LCM, err error) {
	// For running cleanup only
	if in == nil {
		ld.cleanUp()
		return
	}

	// Timeout old packages and erase error prone ones. The sweep visits
	// every pending package, so run it once per timeout instead of on every
	// fragment: a sender that keeps starting new sequences would otherwise
	// make each call cost as much as all of its unfinished messages.
	now := timeNow()
	if now.Sub(ld.lastCleanUp) > timeout {
		ld.cleanUp()
	}

	// Quick check if this is acutally a single packet. In that case, just
	// return it quickly.
	if !in.Fragmented {
		out = in
		return
	}

	// A fragment outside of the range it announces can never be assembled.
	if in.FragmentNumber >= in.TotalFragments {
		err = fmt.Errorf("Fragment number %d is out of range for a message "+
			"of %d fragments. Dropping fragment.", in.FragmentNumber,
			in.TotalFragments)
		return
	}

	// Do we need to start a new fragments obj? A package that timed out but
	// was not swept yet belongs to an earlier message with this number.
	packet, ok := ld.packets[in.SequenceNumber]
	if ok && now.Sub(packet.lastPacket) > timeout {
		ld.drop(in.SequenceNumber)
		ok = false
	}
	if !ok {
		packet = newLCMPacket(in.TotalFragments)
		ld.packets[in.SequenceNumber] = packet
	}

	// All fragments of a message have to agree on the number of fragments,
	// otherwise a sender could make us run assemble() on every fragment.
	if in.TotalFragments != packet.totalFrags {
		err = fmt.Errorf("Fragment announces %d total fragments, but the "+
			"message was started with %d. Dropping fragment.",
			in.TotalFragments, packet.totalFrags)
		return
	}

	// Append the packet
	ld.held += packet.append(in, now)

	// Make room for it, which is not possible if the package itself is too
	// big.
	ld.enforceLimits(in.SequenceNumber)
	if _, ok := ld.packets[in.SequenceNumber]; !ok {
		err = fmt.Errorf("Fragments of packet %d exceed the limit of %d bytes. "+
			"Erasing/dropping packet.", in.SequenceNumber, maxFragBufTotalSize)
		return
	}

	// Check if this is the last package of that series
	if packet.recFrags != packet.totalFrags {
		return
	}
	out, err = packet.assemble()
	ld.drop(in.SequenceNumber)

	return
}
