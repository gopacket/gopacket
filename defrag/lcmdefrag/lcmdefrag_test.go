// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package lcmdefrag

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	fragmentOne = []byte{
		0x4c, 0x43, 0x30, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0d,
		0x00, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x02, 0x4c, 0x43, 0x4d, 0x5f,
		0x53, 0x45, 0x4c, 0x46, 0x5f, 0x54, 0x45, 0x53, 0x54, 0x00, 0x6c, 0x63,
		0x6d, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x20, 0x74, 0x65, 0x73, 0x74,
	}

	fragmentTwo = []byte{
		0x4c, 0x43, 0x30, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0d,
		0x00, 0x00, 0x00, 0x2d, 0x00, 0x01, 0x00, 0x02, 0x6c, 0x63, 0x6d, 0x20,
		0x73, 0x65, 0x6c, 0x66, 0x20, 0x74, 0x65, 0x73, 0x74,
	}

	completePacket = []byte{
		0x4c, 0x43, 0x30, 0x32, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x43, 0x4d, 0x5f,
		0x53, 0x45, 0x4c, 0x46, 0x5f, 0x54, 0x45, 0x53, 0x54, 0x00, 0x6c, 0x63,
		0x6d, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x20, 0x74, 0x65, 0x73, 0x74,
	}
)

func TestOrderedLCMDefrag(t *testing.T) {
	defragmenter := NewLCMDefragmenter()
	var err error

	packet := gopacket.NewPacket(fragmentOne, layers.LayerTypeLCM, gopacket.NoCopy)
	lcm := packet.Layer(layers.LayerTypeLCM).(*layers.LCM)

	lcm, err = defragmenter.Defrag(lcm)
	if lcm != nil {
		t.Fatal("Returned incomplete LCM message.")
	}
	if err != nil {
		t.Fatal(err)
	}

	packet = gopacket.NewPacket(fragmentTwo, layers.LayerTypeLCM, gopacket.NoCopy)
	lcm = packet.Layer(layers.LayerTypeLCM).(*layers.LCM)

	lcm, err = defragmenter.Defrag(lcm)
	if lcm == nil {
		t.Fatal("Did not receive defragmented LCM message.")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnorderedLCMDefrag(t *testing.T) {
	defragmenter := NewLCMDefragmenter()
	var err error

	packet := gopacket.NewPacket(fragmentTwo, layers.LayerTypeLCM, gopacket.NoCopy)
	lcm := packet.Layer(layers.LayerTypeLCM).(*layers.LCM)

	lcm, err = defragmenter.Defrag(lcm)
	if lcm != nil {
		t.Fatal("Returned incomplete LCM message.")
	}
	if err != nil {
		t.Fatal(err)
	}

	packet = gopacket.NewPacket(fragmentOne, layers.LayerTypeLCM, gopacket.NoCopy)
	lcm = packet.Layer(layers.LayerTypeLCM).(*layers.LCM)

	lcm, err = defragmenter.Defrag(lcm)
	if lcm == nil {
		t.Fatal("Did not receive defragmented LCM message.")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestNonLCMDefrag(t *testing.T) {
	defragmenter := NewLCMDefragmenter()
	var err error

	packet := gopacket.NewPacket(completePacket, layers.LayerTypeLCM, gopacket.NoCopy)
	lcm := packet.Layer(layers.LayerTypeLCM).(*layers.LCM)

	lcm, err = defragmenter.Defrag(lcm)
	if lcm == nil {
		t.Fatal("Did not receive complete LCM message.")
	}
	if err != nil {
		t.Fatal(err)
	}
}

// decodeFragment decodes raw LCM bytes into a layer for Defrag.
func decodeFragment(t *testing.T, data []byte) *layers.LCM {
	t.Helper()
	packet := gopacket.NewPacket(data, layers.LayerTypeLCM, gopacket.NoCopy)
	lcm, ok := packet.Layer(layers.LayerTypeLCM).(*layers.LCM)
	if !ok {
		t.Fatal("Could not decode LCM fragment.")
	}
	return lcm
}

// newFragment builds fragment number of total for message sequence, with
// size bytes of payload. Fragment 0 carries an empty channel name.
func newFragment(t *testing.T, sequence uint32, number, total uint16, size int) *layers.LCM {
	t.Helper()
	data := make([]byte, 20, 21+size)
	binary.BigEndian.PutUint32(data[0:4], layers.LCMFragmentedHeaderMagic)
	binary.BigEndian.PutUint32(data[4:8], sequence)
	binary.BigEndian.PutUint32(data[8:12], uint32(total)*uint32(size))
	binary.BigEndian.PutUint32(data[12:16], uint32(number)*uint32(size))
	binary.BigEndian.PutUint16(data[16:18], number)
	binary.BigEndian.PutUint16(data[18:20], total)
	if number == 0 {
		data = append(data, 0)
	}
	data = append(data, make([]byte, size)...)
	return decodeFragment(t, data)
}

// fakeClock replaces the defragmenter's clock for the test and returns a
// function that moves it forward.
func fakeClock(t *testing.T) func(time.Duration) {
	t.Helper()
	now := time.Unix(1000, 0)
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = time.Now })
	return func(d time.Duration) { now = now.Add(d) }
}

// A retransmitted fragment must neither complete the message early nor keep
// it from completing once the missing fragment arrives.
func TestDuplicateFragmentLCMDefrag(t *testing.T) {
	defragmenter := NewLCMDefragmenter()

	for i := 0; i < 2; i++ {
		lcm, err := defragmenter.Defrag(decodeFragment(t, fragmentOne))
		if lcm != nil {
			t.Fatal("Returned incomplete LCM message.")
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	lcm, err := defragmenter.Defrag(decodeFragment(t, fragmentTwo))
	if lcm == nil {
		t.Fatal("Did not receive defragmented LCM message.")
	}
	if err != nil {
		t.Fatal(err)
	}
}

// Fragments that disagree with their message about its number of fragments,
// or that lie outside of it, are dropped with an error and do not trigger an
// assembly attempt. {FragmentNumber, TotalFragments}
func TestInconsistentFragmentLCMDefrag(t *testing.T) {
	defragmenter := NewLCMDefragmenter()

	lcm, err := defragmenter.Defrag(decodeFragment(t, fragmentOne))
	if lcm != nil {
		t.Fatal("Returned incomplete LCM message.")
	}
	if err != nil {
		t.Fatal(err)
	}

	for _, header := range [][2]uint16{{1, 3}, {2, 2}, {1, 1}, {0, 0}} {
		lcm = decodeFragment(t, fragmentTwo)
		lcm.FragmentNumber, lcm.TotalFragments = header[0], header[1]

		lcm, err = defragmenter.Defrag(lcm)
		if lcm != nil {
			t.Fatal("Returned incomplete LCM message.")
		}
		if err == nil {
			t.Fatalf("Accepted fragment %d of %d for a message of 2 fragments.",
				header[0], header[1])
		}
	}

	// The genuine second fragment still completes the message.
	lcm, err = defragmenter.Defrag(decodeFragment(t, fragmentTwo))
	if lcm == nil {
		t.Fatal("Did not receive defragmented LCM message.")
	}
	if err != nil {
		t.Fatal(err)
	}
}

// The sweep over pending messages costs as much as there are of them, so it
// runs once per timeout, not on every fragment: a message may then outlive
// its timeout until the next sweep, and Defrag(nil) always sweeps.
func TestSweepOncePerTimeoutLCMDefrag(t *testing.T) {
	advance := fakeClock(t)
	defragmenter := NewLCMDefragmenter()

	pending := func(want int) {
		t.Helper()
		if got := len(defragmenter.packets); got != want {
			t.Fatalf("%d pending messages, want %d", got, want)
		}
	}
	first := func(sequence uint32) {
		t.Helper()
		if _, err := defragmenter.Defrag(newFragment(t, sequence, 0, 2, 4)); err != nil {
			t.Fatal(err)
		}
	}

	first(1)
	advance(time.Second)
	first(2)
	advance(timeout - time.Second + time.Millisecond)
	first(3) // sweeps: 1 has timed out, 2 has not
	pending(2)

	advance(time.Second)
	first(4) // 2 has timed out, but it is too early for another sweep
	pending(3)

	if _, err := defragmenter.Defrag(nil); err != nil {
		t.Fatal(err)
	}
	pending(2)

	// A completed message leaves the table at once.
	if lcm, err := defragmenter.Defrag(newFragment(t, 4, 1, 2, 4)); lcm == nil || err != nil {
		t.Fatalf("Did not receive defragmented LCM message: %v", err)
	}
	pending(1)
}

// A message that timed out but was not swept yet must not be completed by a
// later message reusing its sequence number.
func TestTimedOutMessageIsNotCompletedLCMDefrag(t *testing.T) {
	advance := fakeClock(t)
	defragmenter := NewLCMDefragmenter()

	if _, err := defragmenter.Defrag(newFragment(t, 1, 0, 2, 4)); err != nil {
		t.Fatal(err)
	}
	advance(timeout + time.Millisecond)
	lcm, err := defragmenter.Defrag(newFragment(t, 1, 1, 2, 4))
	if lcm != nil || err != nil {
		t.Fatalf("got %v, %v for the fragment of a timed out message, want nothing", lcm, err)
	}
}

// The fragments held for incomplete messages are capped in bytes: the least
// recently updated messages go first, and a message that alone exceeds the
// cap is dropped with an error.
func TestHeldBytesCappedLCMDefrag(t *testing.T) {
	advance := fakeClock(t)
	defragmenter := NewLCMDefragmenter()

	// A small message, waiting for its second fragment.
	if _, err := defragmenter.Defrag(newFragment(t, 1, 0, 2, 4)); err != nil {
		t.Fatal(err)
	}
	advance(time.Millisecond)

	// A message that never completes, growing past the cap.
	const fragSize = 1 << 16
	var dropped error
	for i := uint16(0); i <= maxFragBufTotalSize/fragSize && dropped == nil; i++ {
		_, dropped = defragmenter.Defrag(newFragment(t, 2, i, 65535, fragSize))
	}
	if dropped == nil {
		t.Fatal("A message larger than the cap was kept.")
	}
	if got := len(defragmenter.packets); got != 0 {
		t.Fatalf("%d messages still held, want none", got)
	}

	// The small message was evicted to make room, so it cannot complete.
	lcm, err := defragmenter.Defrag(newFragment(t, 1, 1, 2, 4))
	if lcm != nil || err != nil {
		t.Fatalf("got %v, %v for the evicted message, want nothing", lcm, err)
	}
}

// Tiny fragments are not held for free: each costs an overhead, so a flood
// of header-only fragments on fresh sequence numbers also hits the cap.
func TestHeldFragmentOverheadLCMDefrag(t *testing.T) {
	defragmenter := NewLCMDefragmenter()
	for i := uint32(0); i < 2*maxNumFragBufs; i++ {
		if _, err := defragmenter.Defrag(newFragment(t, i, 0, 2, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(defragmenter.packets); got > maxNumFragBufs {
		t.Fatalf("%d messages held, want at most %d", got, maxNumFragBufs)
	}
	if defragmenter.held > maxFragBufTotalSize || defragmenter.held < maxNumFragBufs*fragOverhead {
		t.Fatalf("%d bytes accounted for %d header-only fragments", defragmenter.held, len(defragmenter.packets))
	}
}
