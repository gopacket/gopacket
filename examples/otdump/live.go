// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build cgo

package main

import "github.com/gopacket/gopacket/pcap"

// openLive captures from iface with libpcap.
func openLive(iface string, snaplen int) (captureSource, func(), error) {
	h, err := pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever)
	if err != nil {
		return nil, nil, err
	}
	return h, h.Close, nil
}
