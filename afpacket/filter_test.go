// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build linux
// +build linux

package afpacket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// udpDstPortFilter accepts IPv4 UDP packets (without IP options) sent to port on an Ethernet link.
func udpDstPortFilter(t *testing.T, port uint16) []bpf.RawInstruction {
	t.Helper()

	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.ETH_P_IP, SkipTrue: 5},
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: unix.IPPROTO_UDP, SkipTrue: 3},
		bpf.LoadAbsolute{Off: 14 + 20 + 2, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(port), SkipTrue: 1},
		bpf.RetConstant{Val: 0x40000},
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		t.Fatal(err)
	}

	return filter
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { conn.Close() })

	return conn
}

// TestBPFFilterAttachedBeforeBind checks that with OptBPFFilter the ring never
// contains packets which don't match the filter, even while the interface is busy
// with non-matching traffic when the TPacket is created.
//
// It needs CAP_NET_RAW and a loopback interface which is up, e.g.:
//
//	unshare -rn sh -c 'ip link set lo up && go test -run TestBPFFilterAttachedBeforeBind ./afpacket'
func TestBPFFilterAttachedBeforeBind(t *testing.T) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Skipf("can't open AF_PACKET socket (needs CAP_NET_RAW): %v", err)
	}

	unix.Close(fd)

	lo, err := net.InterfaceByName("lo")
	if err != nil || lo.Flags&net.FlagUp == 0 {
		t.Skip("loopback interface is not up")
	}

	match, noise := listenUDP(t), listenUDP(t)
	matchPort := uint16(match.LocalAddr().(*net.UDPAddr).Port)

	sender := listenUDP(t)

	stop := make(chan struct{})

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()

		payload := []byte("gopacket")

		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}

			to := noise.LocalAddr()
			if i%100 == 0 {
				to = match.LocalAddr()
			}

			sender.WriteTo(payload, to) //nolint:errcheck
		}
	}()

	t.Cleanup(func() {
		close(stop)
		wg.Wait()
	})

	filter := udpDstPortFilter(t, matchPort)

	var matched int

	for range 20 {
		h, err := NewTPacket(
			OptInterface("lo"),
			OptPollTimeout(10*time.Millisecond),
			OptBPFFilter(filter),
		)
		if err != nil {
			t.Fatal(err)
		}

		deadline := time.Now().Add(50 * time.Millisecond)

		for time.Now().Before(deadline) {
			data, _, err := h.ZeroCopyReadPacketData()
			if errors.Is(err, ErrTimeout) {
				continue
			}

			if err != nil {
				h.Close()
				t.Fatal(err)
			}

			if len(data) < 14+20+4 || binary.BigEndian.Uint16(data[14+20+2:]) != matchPort {
				// data points into the ring, so format it before Close unmaps the ring
				msg := fmt.Sprintf("captured a packet which doesn't match the filter: % x", data)
				h.Close()
				t.Fatal(msg)
			}

			matched++
		}

		h.Close()
	}

	if matched == 0 {
		t.Fatal("no packets matching the filter were captured")
	}
}
