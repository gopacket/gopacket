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
)

// timeNow is time.Now, replaced by tests that move the clock.
var timeNow = time.Now

type lcmPacket struct {
	lastPacket time.Time
	done       bool
	recFrags   uint16
	totalFrags uint16
	frags      map[uint16]*layers.LCM
}

// LCMDefragmenter supports defragmentation of LCM messages.
//
// References
//
//	https://lcm-proj.github.io/
//	https://github.com/lcm-proj/lcm
type LCMDefragmenter struct {
	packets     map[uint32]*lcmPacket
	lastCleanUp time.Time
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

func (lp *lcmPacket) append(in *layers.LCM, now time.Time) {
	// A retransmitted fragment must not count towards completion twice.
	if _, ok := lp.frags[in.FragmentNumber]; !ok {
		lp.recFrags++
	}
	lp.frags[in.FragmentNumber] = in
	lp.lastPacket = now
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
			delete(ld.packets, key)
		}
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
		delete(ld.packets, in.SequenceNumber)
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
	packet.append(in, now)

	// Check if this is the last package of that series
	if packet.recFrags != packet.totalFrags {
		return
	}
	out, err = packet.assemble()
	delete(ld.packets, in.SequenceNumber)

	return
}
