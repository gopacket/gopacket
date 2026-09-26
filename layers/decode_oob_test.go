// Copyright 2026 The GoPacket Authors. All rights reserved.
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

// TestDecodeOOBRegression verifies that crafted, truncated packets which
// previously triggered out-of-bounds panics (GHSA-8mcr-459q-5mx2) are now
// rejected with an error instead of crashing. Each decoder is driven through
// the direct DecodeFromBytes path, which does not recover panics (unlike
// gopacket.NewPacket with default options), mirroring how DecodingLayerParser
// invokes decoders.
func TestDecodeOOBRegression(t *testing.T) {
	dhcp := make([]byte, 240)
	dhcp[2] = 0xFF // HardwareLen: 28+0xFF wraps in uint8
	dhcp[236], dhcp[237], dhcp[238], dhcp[239] = 0x63, 0x82, 0x53, 0x63

	cases := []struct {
		name  string
		layer func() gopacket.DecodingLayer
		data  []byte
	}{
		{"TLS/empty-handshake", func() gopacket.DecodingLayer { return &TLS{} }, []byte{0x16, 0x03, 0x01, 0x00, 0x00}},
		{"TLS/short-clienthello", func() gopacket.DecodingLayer { return &TLS{} }, []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}},
		{"DHCPv4/hwlen-overflow", func() gopacket.DecodingLayer { return &DHCPv4{} }, dhcp},
		{"SFlow/short-header", func() gopacket.DecodingLayer { return &SFlowDatagram{} }, []byte{0x00, 0x00, 0x00}},
		{"IPSecAH/short-actuallen", func() gopacket.DecodingLayer { return &IPSecAH{} }, make([]byte, 12)},
		{"VRRPv2/count-overrun", func() gopacket.DecodingLayer { return &VRRPv2{} }, []byte{0x21, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00}},
		{"Diameter/short-msglen", func() gopacket.DecodingLayer { return &Diameter{} }, func() []byte { b := make([]byte, 20); b[0] = 0x01; return b }()},
		{"GTPv1U/ext-header-overrun", func() gopacket.DecodingLayer { return &GTPv1U{} }, []byte{0x04, 0xFF, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0x01}},
		{"ERSPANII/short", func() gopacket.DecodingLayer { return &ERSPANII{} }, make([]byte, 6)},
		{"LCM/short-fragmented", func() gopacket.DecodingLayer { return &LCM{} }, []byte{0x4c, 0x43, 0x30, 0x33, 0x00, 0x00, 0x00, 0x00}},
		{"RadioTap/present-ext-overrun", func() gopacket.DecodingLayer { return &RadioTap{} }, []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x80}},
		{"Dot11IE/ext-id-overrun", func() gopacket.DecodingLayer { return &Dot11InformationElement{} }, []byte{0xFF, 0x00}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decoder panicked on crafted input: %v", r)
				}
			}()
			// A returned error is expected and fine; the point is that it must
			// not panic.
			_ = c.layer().DecodeFromBytes(c.data, gopacket.NilDecodeFeedback)
		})
	}
}

// mptcpSegment builds a minimal TCP segment whose options region is exactly
// optBytes long and carries a single kind-30 (MPTCP) option declaring
// optLength with the given subtype. A declared length larger than the option
// bytes actually present is what previously ran the fixed-offset slices in the
// MPTCP branch past the end of the buffer.
func mptcpSegment(subtype, optLength byte, optBytes int) []byte {
	words := (20 + optBytes + 3) / 4
	seg := make([]byte, words*4)
	seg[12] = byte(words) << 4
	seg[20] = 30 // TCPOptionKindMultipathTCP
	if optBytes > 1 {
		seg[21] = optLength
	}
	if optBytes > 2 {
		seg[22] = subtype << 4
	}
	return seg
}

// TestDecodeMPTCPOptionRegression covers GHSA-6h9g-cjv3-pg2c: the MPTCP option
// branch validated OptionLength only by value-equality against the expected
// constant for each subtype, never against the number of option bytes actually
// present, so a segment declaring a long option while supplying few bytes
// panicked.
func TestDecodeMPTCPOptionRegression(t *testing.T) {
	cases := []struct {
		name            string
		subtype, optLen byte
		optBytes        int
	}{
		{"MP_CAPABLE/synack", 0x0, 12, 4},
		{"MP_CAPABLE/ack", 0x0, 20, 4},
		{"MP_CAPABLE/ackdata", 0x0, 22, 4},
		{"MP_CAPABLE/ackdatacsum", 0x0, 24, 4},
		{"MP_JOIN/syn", 0x1, 12, 4},
		{"MP_JOIN/synack", 0x1, 16, 4},
		{"MP_JOIN/ack", 0x1, 24, 4},
		{"DSS/short", 0x2, 4, 4},
		{"DSS/underflow", 0x2, 3, 3},
		{"ADD_ADDR/v6", 0x3, 20, 4},
		{"REMOVE_ADDR/overrun", 0x4, 8, 4},
		{"MP_PRIO/addr", 0x5, 4, 3},
		{"MP_FAIL", 0x6, 12, 4},
		{"MP_FASTCLOSE", 0x7, 12, 4},
		{"MP_TCPRST", 0x8, 4, 4},
		{"subtype-byte-missing", 0x0, 2, 2},
		{"length-byte-missing", 0x0, 0, 1},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("TCP decoder panicked on crafted MPTCP option: %v", r)
				}
			}()
			_ = (&TCP{}).DecodeFromBytes(mptcpSegment(c.subtype, c.optLen, c.optBytes), gopacket.NilDecodeFeedback)
		})
	}
}

// TestDecodeSIPFoldingRegression covers GHSA-25xj-ggj7-jqgf: a header
// continuation line (RFC 3261 7.3.1 folding) appearing before any header had
// been parsed indexed a nil slice at [-1]. Unlike the other cases here this is
// a missing parser-state precondition, not a missing length check — the input
// is well-formed and fully present.
func TestDecodeSIPFoldingRegression(t *testing.T) {
	for _, msg := range []string{
		"SIP/2.0 200 OK\r\n\tfoo\r\n\r\n",
		"SIP/2.0 200 OK\r\n foo\r\n\r\n",
		"INVITE sip:b@example.com SIP/2.0\r\n\tfoo\r\n\r\n",
	} {
		t.Run(msg, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("SIP decoder panicked on leading continuation line: %v", r)
				}
			}()
			_ = (&SIP{}).DecodeFromBytes([]byte(msg), gopacket.NilDecodeFeedback)
		})
	}
}

// TestDecodeOOBRegressionLinkLayers covers GHSA-cxrr-2gv2-m94w: twelve further
// decoders that read or sliced using an attacker- or capture-stack-controlled
// length, count or offset before validating it against the buffer size.
func TestDecodeOOBRegressionLinkLayers(t *testing.T) {
	pflog := make([]byte, 60) // exactly 60 passed the old guard, then read data[60]
	pflog[0] = 60

	sll := make([]byte, 16)
	sll[4], sll[5] = 0xFF, 0xFF // AddrLen 0xFFFF wrapped the uint16 addition

	sll2 := make([]byte, 20)
	sll2[11] = 0xFF // AddrLength 0xFF resliced past the fixed 8-byte window

	pktap := make([]byte, 156)
	pktap[0] = 200 // HeaderLength above len(data), only lower-bounded before
	pktap[4] = byte(PKTRecPacket)

	direct := []struct {
		name  string
		layer func() gopacket.DecodingLayer
		data  []byte
	}{
		{"EtherIP/short", func() gopacket.DecodingLayer { return &EtherIP{} }, []byte{0x30}},
		{"AGUEVar0/short", func() gopacket.DecodingLayer { return &AGUEVar0{} }, []byte{0x00}},
		{"AGUEVar0/hlen-overrun", func() gopacket.DecodingLayer { return &AGUEVar0{} }, []byte{0x05, 0x00, 0x00, 0x00}},
		{"PFLog/direction-offbyone", func() gopacket.DecodingLayer { return &PFLog{} }, pflog},
		{"LinuxSLL/addrlen-wrap", func() gopacket.DecodingLayer { return &LinuxSLL{} }, sll},
		{"LinuxSLL2/addrlen-overrun", func() gopacket.DecodingLayer { return &LinuxSLL2{} }, sll2},
		{"PktapV1/headerlen-overrun", func() gopacket.DecodingLayer { return &PktapV1{} }, pktap},
		{"Prism/length-underflow", func() gopacket.DecodingLayer { return &PrismHeader{} }, make([]byte, 12)},
	}

	for _, c := range direct {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decoder panicked on crafted input: %v", r)
				}
			}()
			_ = c.layer().DecodeFromBytes(c.data, gopacket.NilDecodeFeedback)
		})
	}

	// These decoders have no exported DecodeFromBytes, so they are only
	// reachable through gopacket.NewPacket. Recovery is disabled here so a
	// regression surfaces as a panic rather than a decode error.
	viaPacket := []struct {
		name string
		typ  gopacket.LayerType
		data []byte
	}{
		{"UDPLite/short", LayerTypeUDPLite, []byte{0, 0, 0, 0}},
		{"MPLS/short", LayerTypeMPLS, []byte{0, 0, 0}},
		{"MPLS/empty-payload-guess", LayerTypeMPLS, []byte{0, 0, 0x01, 0}},
		{"EthernetCTP/short", LayerTypeEthernetCTP, []byte{0}},
		{"EthernetCTP/reply-short", LayerTypeEthernetCTP, []byte{0, 0, 1, 0}},
		{"EthernetCTP/forward-short", LayerTypeEthernetCTP, []byte{0, 0, 2, 0}},
		{"PPP/short", LayerTypePPP, []byte{0xFF}},
		{"PPP/type-truncated", LayerTypePPP, []byte{0xFF, 0x03, 0x00}},
		{"FDDI/short", LayerTypeFDDI, []byte{0, 0, 0, 0, 0}},
	}

	for _, c := range viaPacket {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decoder panicked on crafted input: %v", r)
				}
			}()
			gopacket.NewPacket(c.data, c.typ, gopacket.DecodeOptions{SkipDecodeRecovery: true})
		})
	}
}

// TestDecodeSCTPChunkRegression covers GHSA-358w-w75h-x6rx: SCTP chunk
// sub-decoders read their fixed fields and parameter TLVs using declared
// lengths and counts that were never checked against the chunk size.
func TestDecodeSCTPChunkRegression(t *testing.T) {
	cases := []struct {
		name  string
		chunk []byte
	}{
		{"Init/short", []byte{1, 0, 0, 8, 0, 0, 0, 0}},
		{"InitAck/short", []byte{2, 0, 0, 8, 0, 0, 0, 0}},
		{"Init/len15", []byte{1, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"Sack/count-overrun", []byte{3, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}},
		{"Shutdown/short", []byte{7, 0, 0, 4}},
		{"Error/param-len-zero", []byte{9, 0, 0, 8, 0, 1, 0, 0}},
		{"Error/param-len-overrun", []byte{9, 0, 0, 8, 0, 1, 0, 0x40}},
		{"Heartbeat/param-len-zero", []byte{4, 0, 0, 8, 0, 1, 0, 0}},
		{"Error/param-header-short", []byte{9, 0, 0, 6, 0, 1, 0, 0}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("SCTP decoder panicked on crafted chunk: %v", r)
				}
			}()
			data := append(make([]byte, 12), c.chunk...)
			gopacket.NewPacket(data, LayerTypeSCTP, gopacket.DecodeOptions{SkipDecodeRecovery: true})
		})
	}
}

// TestDecodeSCTPParameterPadding checks that a final parameter whose padding
// is excluded from the chunk length (RFC 9260 3.2) still decodes.
func TestDecodeSCTPParameterPadding(t *testing.T) {
	// Heartbeat chunk, length 9: one 5-byte parameter, then 3 padding bytes.
	data := append(make([]byte, 12), 4, 0, 0, 9, 0, 1, 0, 5, 0xAA, 0, 0, 0)

	p := gopacket.NewPacket(data, LayerTypeSCTP, gopacket.DecodeOptions{SkipDecodeRecovery: true})
	if p.ErrorLayer() != nil {
		t.Fatalf("unexpected decode error: %v", p.ErrorLayer().Error())
	}

	hb, ok := p.Layer(LayerTypeSCTPHeartbeat).(*SCTPHeartbeat)
	if !ok || len(hb.Parameters) != 1 || len(hb.Parameters[0].Value) != 1 {
		t.Fatalf("heartbeat parameter not decoded: %+v", hb)
	}
}

// TestDecodeOOBRegressionBatch3 covers the 2026-09 batch of decoder panics
// (sFlow sample loop, OSPFv2/v3 LSA headers, MDP TLVs, GTPv2 IE header,
// Geneve header and option, CDP header). Each input declares more structure
// than the buffer holds.
func TestDecodeOOBRegressionBatch3(t *testing.T) {
	sflow := make([]byte, 28)
	binary.BigEndian.PutUint32(sflow[0:4], 5)
	binary.BigEndian.PutUint32(sflow[4:8], 1)
	binary.BigEndian.PutUint32(sflow[24:28], 1) // SampleCount=1, no sample

	ospf3 := make([]byte, 20)
	ospf3[0], ospf3[1] = 3, 4 // v3, Link State Update
	binary.BigEndian.PutUint16(ospf3[2:4], 20)
	binary.BigEndian.PutUint32(ospf3[16:20], 1) // one LSA, no body

	ospf2 := make([]byte, 28)
	ospf2[0], ospf2[1] = 2, 4
	binary.BigEndian.PutUint16(ospf2[2:4], 28)
	binary.BigEndian.PutUint32(ospf2[24:28], 1)

	mdp := make([]byte, 30)
	mdp[28], mdp[29] = MdpTlvDeviceInfo, 0xFF

	gtp2 := make([]byte, 9) // 8-byte header + 1 byte of IE header
	gtp2[0], gtp2[1] = 0x20, 0x01
	binary.BigEndian.PutUint16(gtp2[2:4], 4)

	geneveOpt := make([]byte, 11) // 8-byte header, OptLen=4, only 3 option bytes
	geneveOpt[0] = 1

	cases := []struct {
		name  string
		layer func() gopacket.DecodingLayer
		data  []byte
	}{
		{"SFlow/sample-count-no-body", func() gopacket.DecodingLayer { return &SFlowDatagram{} }, sflow},
		{"OSPFv3/lsu-no-lsa", func() gopacket.DecodingLayer { return &OSPFv3{} }, ospf3},
		{"OSPFv2/lsu-no-lsa", func() gopacket.DecodingLayer { return &OSPFv2{} }, ospf2},
		{"MDP/tlv-length-overrun", func() gopacket.DecodingLayer { return &MDP{} }, mdp},
		{"GTPv2/ie-header-truncated", func() gopacket.DecodingLayer { return &GTPv2{} }, gtp2},
		{"Geneve/7-byte-header", func() gopacket.DecodingLayer { return &Geneve{} }, make([]byte, 7)},
		{"Geneve/3-byte-option", func() gopacket.DecodingLayer { return &Geneve{} }, geneveOpt},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decoder panicked on crafted input: %v", r)
				}
			}()
			_ = c.layer().DecodeFromBytes(c.data, gopacket.NilDecodeFeedback)
		})
	}

	// CDP has no DecodingLayer; drive it through the non-recovering packet path.
	t.Run("CDP/2-byte-header", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("decoder panicked on crafted input: %v", r)
			}
		}()
		gopacket.NewPacket([]byte{0x00, 0x01}, LayerTypeCiscoDiscovery, gopacket.DecodeOptions{SkipDecodeRecovery: true})
	})
}
