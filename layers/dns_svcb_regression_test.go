// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"

	"github.com/gopacket/gopacket"
)

// TestDNSDecodeSVCBTruncatedParamsNoPanic is a regression test for a
// pre-existing out-of-bounds panic in decodeSVCB. The SvcParams loop bounded
// its reads against the fixed RDATA start (offset) rather than the advancing
// cursor (ofs), so a record whose SvcParams field was truncated to fewer than
// four bytes made binary.BigEndian.Uint16 read past the end of the buffer. A
// malformed SVCB/HTTPS record must decode to an error, never panic.
func TestDNSDecodeSVCBTruncatedParamsNoPanic(t *testing.T) {
	for _, rtype := range []DNSType{DNSTypeSVCB, DNSTypeHTTPS} {
		// RDATA: Priority (0x0000) + root Target (0x00) + a single stray byte.
		// After the target is consumed, the cursor sits one byte short of a
		// SvcParam key/length pair at the very end of the packet, which is what
		// tripped the original bounds bug.
		rdata := []byte{0x00, 0x00, 0x00, 0xff}
		pkt := dottestAnswer(dottestWireName("x"), rtype, rdata)

		var dns DNS
		err := dns.DecodeFromBytes(pkt, gopacket.NilDecodeFeedback)
		if err == nil {
			t.Errorf("%v: expected an error decoding a truncated SvcParams record, got nil", rtype)
		}
	}
}
