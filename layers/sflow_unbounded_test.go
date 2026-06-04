// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket"
)

// putU32 appends a big-endian uint32 to b.
func putU32(b *[]byte, v uint32) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, v)
	*b = append(*b, tmp...)
}

// buildExtendedGatewayDatagram builds a minimal, otherwise well-formed sFlow v5
// datagram carrying a single FlowSample with a single ExtendedGatewayFlow
// (1003) record whose communities count is commLen. The packet is intentionally
// short (no community bytes follow), so a faithful decoder must reject an
// oversized count rather than pre-allocating make([]uint32, commLen).
func buildExtendedGatewayDatagram(commLen uint32) []byte {
	var d []byte
	putU32(&d, 5)          // DatagramVersion
	putU32(&d, 1)          // agentAddressType = SFlowIPv4
	putU32(&d, 0x7f000001) // AgentAddress
	putU32(&d, 0)          // SubAgentID
	putU32(&d, 0)          // SequenceNumber
	putU32(&d, 0)          // AgentUptime
	putU32(&d, 1)          // SampleCount = 1
	putU32(&d, 1)          // sample data format -> FlowSample
	putU32(&d, 0)          // SampleLength
	putU32(&d, 0)          // SequenceNumber
	putU32(&d, 0)          // SourceID
	putU32(&d, 0)          // SamplingRate
	putU32(&d, 0)          // SamplePool
	putU32(&d, 0)          // Dropped
	putU32(&d, 0)          // InputInterface
	putU32(&d, 0)          // OutputInterface
	putU32(&d, 1)          // RecordCount = 1
	putU32(&d, 1003)       // record format -> ExtendedGatewayFlow
	putU32(&d, 0)          // FlowDataLength
	putU32(&d, 1)          // extendedGatewayAddressType = IPv4
	putU32(&d, 0x08080808) // NextHop
	putU32(&d, 0)          // AS
	putU32(&d, 0)          // SourceAS
	putU32(&d, 0)          // PeerAS
	putU32(&d, 0)          // ASPathCount = 0
	putU32(&d, commLen)    // communitiesLength
	return d
}

// TestSFlowExtendedGatewayUnboundedCommunities verifies that an attacker
// controlled, oversized communities count is rejected with a decode error
// instead of triggering an unbounded make([]uint32, commLen) allocation
// (CWE-770). Without the bound check this datagram would request up to 16 GiB.
func TestSFlowExtendedGatewayUnboundedCommunities(t *testing.T) {
	data := buildExtendedGatewayDatagram(0xFFFFFFFF)
	var dg SFlowDatagram
	if err := dg.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
		t.Fatalf("expected decode error for oversized communities count, got nil")
	}
}

// TestSFlowExtendedGatewayValidCommunities is the negative control: a count
// that the remaining buffer can actually back must still decode successfully.
func TestSFlowExtendedGatewayValidCommunities(t *testing.T) {
	const n = 2
	data := buildExtendedGatewayDatagram(n)
	for i := 0; i < n; i++ {
		putU32(&data, 0) // community values
	}
	putU32(&data, 0) // LocalPref
	var dg SFlowDatagram
	if err := dg.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("expected valid extended-gateway record to decode, got error: %v", err)
	}
}
