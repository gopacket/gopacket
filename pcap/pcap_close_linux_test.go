// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

import (
	"io"
	"testing"
	"time"
)

// closeDeadline bounds how long Close may wait for a blocked reader.
const closeDeadline = 3 * time.Second

// TestCloseWhileReadBlocked checks that Close returns while ReadPacketData is
// blocked on an interface with no matching traffic (#27). With BlockForever
// the reader holds the handle lock inside pcap_next_ex, so Close used to wait
// for a packet that never came.
func TestCloseWhileReadBlocked(t *testing.T) {
	t.Run("OpenLive", func(t *testing.T) { testCloseWhileReadBlocked(t, false) })
	t.Run("Activate", func(t *testing.T) { testCloseWhileReadBlocked(t, true) })
}

func testCloseWhileReadBlocked(t *testing.T, activate bool) {
	if activate {
		inactive, err := NewInactiveHandle("lo")
		if err != nil {
			t.Fatal(err)
		}
		defer inactive.CleanUp()
		if err := inactive.SetTimeout(BlockForever); err != nil {
			t.Fatal(err)
		}
		handle, err := inactive.Activate()
		if err != nil {
			t.Skipf("cannot activate live capture: %v", err)
		}
		checkBlockedClose(t, handle)
		return
	}
	handle, err := OpenLive("lo", 65535, false, BlockForever)
	if err != nil {
		t.Skipf("cannot open live capture on lo (needs CAP_NET_RAW): %v", err)
	}
	checkBlockedClose(t, handle)
}

func checkBlockedClose(t *testing.T, handle *Handle) {
	if !handle.live {
		t.Fatal("live handle was not marked live")
	}

	// Match nothing, so the reader stays blocked.
	if err := handle.SetBPFFilter("ip proto 253"); err != nil {
		handle.Close()
		t.Fatal(err)
	}

	readDone := make(chan error, 1)
	go func() {
		_, _, err := handle.ReadPacketData()
		readDone <- err
	}()

	// Give the reader time to block in pcap_next_ex.
	time.Sleep(200 * time.Millisecond)

	closeDone := make(chan struct{})
	go func() {
		closeConcurrently(handle)
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(closeDeadline):
		t.Fatal("Close did not return while ReadPacketData was blocked")
	}

	select {
	case err := <-readDone:
		if err != io.EOF {
			t.Errorf("ReadPacketData error = %v, want io.EOF after Close", err)
		}
	case <-time.After(closeDeadline):
		t.Fatal("ReadPacketData did not return after Close")
	}
}
