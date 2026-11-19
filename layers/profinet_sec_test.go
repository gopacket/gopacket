// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// Values of the TSN, CIM, security and reporting system frames (85 to
// 103) of profinet-blocks.pcap that the golden strings do not reach: the
// sub-fields, and every block behind the first of its type in a frame.

// pnFrameBlocks returns every block of one frame of the block capture,
// nested ones included, without the header of a read response.
func pnFrameBlocks(t *testing.T, frame int) []*ProfinetBlock {
	frames := readPNECATPcap(t, pnBlocksPcap)
	p := gopacket.NewPacket(frames[frame-1], LinkTypeEthernet, gopacket.Default)

	var out []*ProfinetBlock
	pnWalkBlocks(pnTopBlocks(p), func(b *ProfinetBlock) {
		if b.Type == ProfinetBlockIODReadRes {
			return
		}

		out = append(out, b)
	})
	return out
}

func TestProfinetTSNAccessors(t *testing.T) {
	withProfinet(t)

	// Frame 86: queue 7, PCP 6, shaper 2, preemption 1, offsets 250000
	// and 125000; port with preemption and boundary status 2; limiters.
	for _, b := range pnFrameBlocks(t, 86) {
		switch v := b.Value.(type) {
		case *ProfinetCIMQueueConfig:
			q := v.Queues[0]
			if q.QueueID() != 7 || q.TciPcp() != 6 || q.Shaper() != 2 || q.PreemptionMode() != 1 ||
				q.UnmaskTimeOffset() != 250000 || q.MaskTimeOffset() != 125000 {
				t.Errorf("queue config 0x%016x", uint64(q))
			}
		case *ProfinetCIMPortConfig:
			if !v.Status.Preemption() || v.Status.BoundaryPort() != 2 || len(b.Blocks) != 2 {
				t.Errorf("port status 0x%02x, %d blocks", uint8(v.Status), len(b.Blocks))
			}
		case *ProfinetCIMIngressLimiter:
			l := v.Limiters[0]
			if l.CIR() != 100 || l.CBS() != 1522 || l.Envelope() != 2 || l.Rank() != 1 {
				t.Errorf("ingress limiter 0x%016x", uint64(l))
			}
		case *ProfinetCIMEgressLimiter:
			l := v.Limiters[0]
			if l.CIR() != 100 || l.CBS() != 1522 || l.Envelope() != 2 || l.Rank() != 1 || l.QueueID() != 7 {
				t.Errorf("egress limiter 0x%016x", uint64(l))
			}
		case *ProfinetCIMForwardingDelay:
			d := v.Entries[1].ForwardingDelay
			if d.Independent() != 12000 || d.Dependent() != 1 {
				t.Errorf("forwarding delay 0x%08x", uint32(d))
			}
		case *ProfinetCIMPortCapabilities:
			a, c := v.Ports[0].Capabilities, v.Ports[1].Capabilities
			if !a.TimeAware() || !a.Preemption() || !a.QueueMasking() || c.TimeAware() || !c.Preemption() || c.QueueMasking() {
				t.Errorf("port capabilities 0x%02x 0x%02x", uint8(a), uint8(c))
			}
		default:
			t.Errorf("frame 86: block 0x%04x not typed", uint16(b.Type))
		}
	}

	// Frame 89: the upload attributes hold their two blocks.
	upload := pnFrameBlocks(t, 89)[0]
	if _, ok := upload.Value.(*ProfinetCIMUploadAttributes); !ok || len(upload.Blocks) != 2 ||
		upload.Blocks[0].Type != ProfinetBlockCIMPortCapabilities || upload.Blocks[1].Type != ProfinetBlockCIMForwardingDelay {
		t.Errorf("upload attributes: %T with %d blocks", upload.Value, len(upload.Blocks))
	}

	// Frame 90: calling home flags and the record access policy ranges.
	blocks := pnFrameBlocks(t, 90)
	adjust, real := blocks[0].Value.(*ProfinetCIMCallingHome), blocks[1].Value.(*ProfinetCIMCallingHome)
	if !adjust.UseLayer3() || !adjust.UseLayer2() || !real.UseLayer3() || real.UseLayer2() {
		t.Errorf("calling home flags 0x%04x 0x%04x", adjust.Flags, real.Flags)
	}

	policy := blocks[3].Value.(*ProfinetRecordAccessPolicy).Entries
	if policy[0].ARType() != 1 || policy[1].AccessType() != 1 || policy[0].Slot.Start() != 1 || policy[0].Slot.End() != 2 ||
		policy[1].Index.Start() != 0xB000 || policy[1].Index.End() != 0xB02E {
		t.Errorf("record policy %+v", policy)
	}

	// The sub-fields of the CIM control words.
	ctl := ProfinetCIMControl{Control: 0x0906}
	if ctl.CLRPC() || !ctl.IODInterface() || !ctl.IOCInterface() || ctl.ProtectableProtocols() != 2 ||
		ctl.NonProtectableProtocols() != 1 || ctl.PlainTCPServerPort() != 2 || ctl.PlainTCPCallingHomePort() != 1 ||
		ctl.PlainRTAv3ServerSAP() != 1 || ctl.PlainRTAv3CallingHomeSAP() != 2 {
		t.Errorf("CIM control 0x%04x", ctl.Control)
	}

	dcp := ProfinetCIMDCP{SetControl: 0x0005, GetControl: 0x0001, MulticastControl: 0x0100}
	if !dcp.Set() || !dcp.SetNameOfStation() || !dcp.Get() || dcp.Identify() || !dcp.Hello() {
		t.Errorf("CIM DCP %+v", dcp)
	}
}

// pnSecurityWant is what one security, SCM or SAM block of the capture
// holds: its operation and the sizes of its lists.
type pnSecurityWant struct {
	op           ProfinetSecurityOperation
	certs        int
	csr          int
	capabilities int
}

func TestProfinetSecurityBlocks(t *testing.T) {
	withProfinet(t)

	// Sizes of the test certificate, its request and the request info;
	// the info has no length field and takes two bytes of padding along.
	const certLen, csrLen, csrInfoLen = 347, 208, 118 + 2
	want := map[int][]pnSecurityWant{
		93: {{op: 2}, {op: 4}, {op: 6, csr: csrInfoLen}, {op: 8, certs: 2}, {op: 10, certs: 1}, {op: 12}},
		94: {{op: 1, capabilities: 3}, {op: 2}, {op: 3}, {op: 4, certs: 2}, {op: 5, certs: 1}, {op: 6, csr: csrLen}, {op: 8}},
		95: {{op: 1}, {op: 4}, {op: 6, csr: csrInfoLen}, {op: 8, certs: 1}, {op: 10, certs: 1}, {op: 12}, {op: 13}},
		96: {{op: 1, capabilities: 2}, {op: 3}, {op: 4, certs: 1}, {op: 5, certs: 1}, {op: 6, csr: csrLen}, {op: 9}},
		97: {{op: ProfinetSecOpEAP}, {op: 4}},
		98: {{op: ProfinetSecOpEAP}, {op: 1, capabilities: 1}},
	}

	for frame, rows := range want {
		blocks := pnFrameBlocks(t, frame)
		if len(blocks) != len(rows) {
			t.Fatalf("frame %d: %d blocks, want %d", frame, len(blocks), len(rows))
		}

		for i, row := range rows {
			var op ProfinetSecurityOperation
			var params ProfinetSecurityParams
			switch v := blocks[i].Value.(type) {
			case *ProfinetSecurityService:
				op, params = v.Operation, v.ProfinetSecurityParams
			case *ProfinetSCMService:
				op, params = v.Operation, v.ProfinetSecurityParams
			default:
				t.Fatalf("frame %d block %d: %T", frame, i, blocks[i].Value)
			}

			if op != row.op || len(params.Certificates) != row.certs || len(params.CSR) != row.csr ||
				len(params.Data) != 0 || len(params.Capabilities) != row.capabilities {
				t.Errorf("frame %d block %d: op %d, %d certificates, CSR %d, data %d, %d capabilities", frame, i,
					uint16(op), len(params.Certificates), len(params.CSR), len(params.Data), len(params.Capabilities))
			}
			for _, c := range params.Certificates {
				if len(c) != certLen {
					t.Errorf("frame %d block %d: certificate of %d bytes", frame, i, len(c))
				}
			}
		}
	}

	// Mode 1, validity check 1, SACK threshold 0x20; SCM: check 1, factor 5.
	sec := pnFrameBlocks(t, 93)[5].Value.(*ProfinetSecurityService)
	if sec.Config.SecurityMode() != 1 || sec.Config.ValidityPeriodCheck() != 1 || sec.Config.SACKDegradationThreshold() != 0x20 {
		t.Errorf("security config 0x%x", uint64(sec.Config))
	}

	scm := pnFrameBlocks(t, 95)[5].Value.(*ProfinetSCMService)
	if scm.Config.ValidityPeriodCheck() != 1 || scm.Config.SACKDegradationFactor() != 5 {
		t.Errorf("SCM config 0x%x", uint64(scm.Config))
	}

	list := pnFrameBlocks(t, 94)[1].Value.(*ProfinetSecurityService)
	if len(list.Credentials) != 2 || list.Credentials[0] != 0x0101 || list.Credentials[1].Type() != 2 {
		t.Errorf("credential IDs %v", list.Credentials)
	}

	algo := pnFrameBlocks(t, 91)[1].Value.(*ProfinetARAlgorithmInfo)
	if algo.KeyAgreement.Usage() != 4 || algo.KeyAgreement.Algorithm() != 1 {
		t.Errorf("key agreement 0x%04x", uint16(algo.KeyAgreement))
	}
	if ProfinetSecOpEAP.String() != "Process EAP Message" {
		t.Errorf("operation name %q", ProfinetSecOpEAP.String())
	}
}

func TestProfinetRSExtValues(t *testing.T) {
	withProfinet(t)

	ext := func(frame int) interface{} {
		info := pnFrameBlocks(t, frame)[0].Value.(*ProfinetRSEventInfo)
		if len(info.Events) != 1 || len(info.Events[0].Extensions) != 1 {
			t.Fatalf("frame %d: %+v", frame, info)
		}
		return info.Events[0].Extensions[0].Value
	}

	stop, ok := ext(101).(*ProfinetRSStop)
	if !ok || stop.Observer != ProfinetRSDigitalInputObserver || stop.Reason != 1 || stop.Detail != 2 ||
		!bytes.Equal(stop.Data, []byte{0, 1}) {
		t.Errorf("stop observer: %+v", stop)
	}

	status, ok := ext(102).(*ProfinetRSTimeStatus)
	if !ok || len(status.DomainIdentification) != 16 || status.DomainIdentification[0] != 0x70 ||
		!bytes.Equal(status.MasterIdentification, []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}) ||
		status.TimeStamp.Seconds != 0x65000001 || status.TimeStamp.Nanoseconds != 123456790 {
		t.Errorf("time status observer: %+v", status)
	}

	source, ok := ext(103).(*ProfinetRSSourceIdent)
	if !ok || source.VendorID != 0x2A || source.DeviceID != 0x0101 || source.DeviceSubID != 2 ||
		strings.TrimRight(source.TagFunction, " ") != "function" || strings.TrimRight(source.TagLocation, " ") != "location" {
		t.Errorf("source identification observer: %+v", source)
	}

	// The digital input observer carries the current value.
	in, ok := decodeProfinetRSExt(ProfinetRSDigitalInputObserver, []byte{0xAA, 0xBB}).(*ProfinetRSDigitalInput)
	if !ok || in.CurrentValue != 0xAABB || !in.One() {
		t.Errorf("digital input observer: %+v", in)
	}
	if decodeProfinetRSExt(ProfinetRSStopObserver, []byte{0x40}) != nil {
		t.Error("short stop extension decoded")
	}
}
