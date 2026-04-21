// Copyright 2024 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build darwin
// +build darwin

package pcap

/*
#cgo darwin LDFLAGS: -lpcap

#include <pcap.h>

extern int pcap_set_want_pktap(pcap_t *, int);
*/
import "C"

const (
	DLT_PKTAP = C.DLT_PKTAP
)

// SetWantPktap calls pcap_set_want_pktap on the pcap handle.
// This is a Darwin-specific function that tells the kernel to wrap packets
// with pktap metadata when capturing. This must be called before Activate.
// see: https://github.com/apple-oss-distributions/tcpdump/blob/tcpdump-156/tcpdump/tcpdump.c#L1541
// see: https://github.com/apple-oss-distributions/libpcap/blob/libpcap-144/libpcap/pcap/pcap.h#L1240-L1244
func (p *InactiveHandle) SetWantPktap(wantPktap bool) error {
	var v C.int
	if wantPktap {
		v = 1
	}

	if status := C.pcap_set_want_pktap(p.cptr, v); status < 0 {
		return statusError(status)
	}
	return nil
}
