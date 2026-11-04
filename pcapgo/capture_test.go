// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//go:build linux

package pcapgo_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const (
	timeout = 100 * time.Millisecond
)

func Example_captureEthernet() {
	f, err := os.Create("/tmp/lo.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	}

	handle, err := pcapgo.NewEthernetHandle("lo")
	if err != nil {
		log.Fatalf("OpenEthernet: %v", err)
	}

	pkgsrc := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for packet := range pkgsrc.PacketsCtx(ctx) {
		if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			log.Fatalf("pcap.WritePacket(): %v", err)
		}
	}
}

func TestEthernetHandle_Close_WithTimeout(t *testing.T) {
	var (
		handle *pcapgo.EthernetHandle
		err    error
		done   = make(chan struct{})
	)

	handle, err = pcapgo.NewEthernetHandle(setupDummyInterface(t))
	if err != nil {
		t.Fatalf("OpenEthernet: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	pkgsrc := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)

	go consumePacketSource(ctx, t, pkgsrc, done)

	select {
	case _, more := <-done:
		if more {
			t.Fatalf("done channel is polluted?!")
		} else {
			t.Log("PacketSource got closed")
		}
	case <-time.After(2 * timeout):
	}
}

func TestEthernetHandle_Close_WithCancel(t *testing.T) {
	var (
		handle *pcapgo.EthernetHandle
		err    error
		done   = make(chan struct{})
	)

	handle, err = pcapgo.NewEthernetHandle(setupDummyInterface(t))
	if err != nil {
		t.Fatalf("OpenEthernet: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	pkgsrc := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	go consumePacketSource(ctx, t, pkgsrc, done)

	go func() {
		<-time.After(timeout)
		cancel()
	}()

	select {
	case _, more := <-done:
		if more {
			t.Fatalf("done channel is polluted?!")
		} else {
			t.Log("PacketSource got closed")
		}
	case <-time.After(2 * timeout):
	}
}

func consumePacketSource(ctx context.Context, tb testing.TB, pkgsrc *gopacket.PacketSource, done chan<- struct{}) {
	tb.Helper()
	var writer = pcapgo.NewWriter(new(bytes.Buffer))
	defer close(done)
	for packet := range pkgsrc.PacketsCtx(ctx) {
		if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			tb.Errorf("pcap.WritePacket(): %v", err)
		}
	}
}

var (
	dummyInterfaceIdx int32 = -1
)

// setupDummyInterface configures a dummy interface and returns the generated interface name.
// It assigns an address from the 127.10.0.0/24 network.
// It does not check if there are already more than 254 interfaces.
// If there are the call to netlink.ParseAddr will fail because 127.10.0.256/24 isn't a valid IP address,
// but it should be fine for testing purposes.
func setupDummyInterface(tb testing.TB) (ifName string) {
	tb.Helper()
	la := netlink.NewLinkAttrs()
	idx := atomic.AddInt32(&dummyInterfaceIdx, 1)
	la.Name = fmt.Sprintf("dummy%02d", idx)
	dummyInterface := &netlink.Dummy{LinkAttrs: la}
	if err := netlink.LinkAdd(dummyInterface); err != nil {
		tb.Fatalf("netlink.LinkAdd() error = %v", err)
	}

	var (
		link netlink.Link
		addr *netlink.Addr
		err  error
	)

	link, err = netlink.LinkByName(la.Name)
	if err != nil {
		tb.Fatalf("netlink.LinkByName() error = %v", err)
	}

	tb.Cleanup(func() {
		if err := netlink.LinkDel(link); err != nil {
			tb.Fatalf("netlink.LinkDel() error = %v", err)
		}
	})

	addr, err = netlink.ParseAddr(fmt.Sprintf("127.10.0.%d/24", idx+1))
	if err != nil {
		tb.Fatalf("netlink.ParseAddr() = %v", err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		tb.Fatalf("netlink.AddrAdd() error = %v", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		tb.Fatalf("netlink.LinkSetUp() error = %v", err)
	}

	return la.Name
}

// setupVethPair configures a veth pair and returns both names. A frame sent
// on the first arrives on the second through the receive path, as it would
// from the wire.
func setupVethPair(tb testing.TB) (send, recv string) {
	tb.Helper()
	idx := atomic.AddInt32(&dummyInterfaceIdx, 1)
	la := netlink.NewLinkAttrs()
	la.Name = fmt.Sprintf("vethsend%02d", idx)
	veth := &netlink.Veth{LinkAttrs: la, PeerName: fmt.Sprintf("vethrecv%02d", idx)}
	if err := netlink.LinkAdd(veth); err != nil {
		tb.Fatalf("netlink.LinkAdd() error = %v", err)
	}
	tb.Cleanup(func() {
		if err := netlink.LinkDel(veth); err != nil {
			tb.Fatalf("netlink.LinkDel() error = %v", err)
		}
	})

	for _, name := range []string{la.Name, veth.PeerName} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			tb.Fatalf("netlink.LinkByName() error = %v", err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			tb.Fatalf("netlink.LinkSetUp() error = %v", err)
		}
	}

	return la.Name, veth.PeerName
}

// sendFrame puts one frame on the wire of the named interface.
func sendFrame(tb testing.TB, ifname string, frame []byte) {
	tb.Helper()
	intf, err := net.InterfaceByName(ifname)
	if err != nil {
		tb.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		tb.Fatalf("socket: %v", err)
	}
	defer unix.Close(fd)
	if err := unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{Ifindex: intf.Index}); err != nil {
		tb.Fatalf("sendto: %v", err)
	}
}

// readFrame returns the next frame from the handle, or fails when none
// arrives within the test timeout.
func readFrame(tb testing.TB, handle *pcapgo.EthernetHandle) ([]byte, gopacket.CaptureInfo) {
	tb.Helper()
	type result struct {
		data []byte
		ci   gopacket.CaptureInfo
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data, ci, err := handle.ReadPacketData()
		done <- result{data, ci, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			tb.Fatal(r.err)
		}
		return r.data, r.ci
	case <-time.After(timeout):
		tb.Fatal("no frame within the timeout")
	}
	return nil, gopacket.CaptureInfo{}
}

// A frame that fills the MTU is 14 bytes longer than the MTU, so a handle
// sized by the MTU cut the tail off every full-size frame.
func TestEthernetHandleCapturesFullFrame(t *testing.T) {
	send, recv := setupVethPair(t)
	handle, err := pcapgo.NewEthernetHandle(recv)
	if err != nil {
		t.Fatalf("OpenEthernet: %v", err)
	}
	defer handle.Close()

	intf, err := net.InterfaceByName(recv)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, intf.MTU+14)
	frame[12] = 0x08 // ethertype IPv4
	for i := range frame[14:] {
		frame[14+i] = byte(i)
	}
	sendFrame(t, send, frame)

	data, ci := readFrame(t, handle)
	if ci.CaptureLength != len(frame) || ci.Length != len(frame) {
		t.Errorf("got CaptureLength %d, Length %d, want %d", ci.CaptureLength, ci.Length, len(frame))
	}
	if !bytes.Equal(data, frame) {
		t.Errorf("frame differs from the one sent (%d bytes read)", len(data))
	}
}
