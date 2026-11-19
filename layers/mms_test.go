// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// MMS test captures, all public:
//
//	iec61850_mms.pcap              Wireshark SampleCaptures mms.pcap (ICCP over MMS)
//	iec61850_mms_reports_goose.pcap IEC 61850 reports and GOOSE, association not captured (goosestalker)
//	iec61850_mms_siemens.pcap      Siemens IED, first 160 frames of Substation/simens.pcap (EmreEkin/ICS-Pcaps);
//	                               COTP segmented TSDUs
//	iec61850_mms_libiec61850.pcap  iec61850.pcap (EmreEkin/ICS-Pcaps): an AC SPDU whose length overruns the TSDU
//	                               and a confirmed response without service
//
// Expected values come from tshark 4.7. Session layer tests start at
// LayerTypeISOSession with the COTP DT user data, stripped by hand.

const (
	iecTPKTVersion  = 3
	iecTPKTLen      = 4
	iecCOTPTypeMask = 0xf0
	iecCOTPTypeDT   = 0xf0
	iecCOTPEOT      = 0x80
	iecISOTSAPPort  = 102
)

// iecTSDU is one session TSDU (reassembled COTP DT user data) and the
// 1-based frame number in which its last byte arrived, as tshark reports.
type iecTSDU struct {
	frame int
	data  []byte
}

// iecFlow is the reassembly state of one TCP direction.
type iecFlow struct {
	next   uint32
	synced bool
	buf    []byte
	cotp   []byte
}

// iecExtractTSDUs strips Ethernet (optionally 802.1Q), IPv4, TCP, TPKT and
// COTP DT by hand and returns the session TSDUs carried on port 102. It
// reassembles in-order TCP segments, TPKTs split over segments and COTP DT
// units without EOT. Out of order data resets the flow.
func iecExtractTSDUs(frames [][]byte) []iecTSDU {
	flows := map[string]*iecFlow{}
	var out []iecTSDU
	for i, f := range frames {
		key, seq, payload, ok := iecTCPPayload(f)
		if !ok || len(payload) == 0 {
			continue
		}

		fl := flows[key]
		if fl == nil {
			fl = &iecFlow{}
			flows[key] = fl
		}

		// Drop retransmitted bytes; a gap loses the stream position.
		if fl.synced && seq != fl.next {
			seen := int32(fl.next - seq)
			switch {
			case seen < 0:
				fl.buf, fl.cotp = nil, nil
			case int(seen) >= len(payload):
				continue
			default:
				payload = payload[seen:]
				seq = fl.next
			}
		}
		fl.synced = true
		fl.next = seq + uint32(len(payload))
		fl.buf = append(fl.buf, payload...)

		for _, t := range fl.drain() {
			out = append(out, iecTSDU{frame: i + 1, data: t})
		}
	}
	return out
}

// drain consumes every complete TPKT of the flow buffer and returns the
// TSDUs whose last COTP DT unit had EOT set.
func (fl *iecFlow) drain() [][]byte {
	var out [][]byte
	for len(fl.buf) >= iecTPKTLen {
		if fl.buf[0] != iecTPKTVersion {
			fl.buf, fl.cotp = nil, nil
			break
		}
		n := int(binary.BigEndian.Uint16(fl.buf[2:]))
		if n < iecTPKTLen+2 || len(fl.buf) < n {
			break
		}
		tpdu := fl.buf[iecTPKTLen:n]
		fl.buf = fl.buf[n:]

		// COTP: LI, type; a DT carries one more octet with EOT.
		li := int(tpdu[0])
		if tpdu[1]&iecCOTPTypeMask != iecCOTPTypeDT || li < 2 || li+1 > len(tpdu) {
			continue
		}
		fl.cotp = append(fl.cotp, tpdu[1+li:]...)
		if tpdu[2]&iecCOTPEOT == 0 {
			continue
		}
		out = append(out, fl.cotp)
		fl.cotp = nil
	}
	return out
}

// iecTCPPayload returns the flow key, sequence number and payload of a TCP
// segment to or from port 102.
func iecTCPPayload(f []byte) (string, uint32, []byte, bool) {
	const ethLen, vlanLen, ipMinLen, tcpMinLen = 14, 4, 20, 20
	if len(f) < ethLen {
		return "", 0, nil, false
	}

	off := ethLen
	etype := EthernetType(binary.BigEndian.Uint16(f[12:]))
	if etype == EthernetTypeDot1Q {
		if len(f) < ethLen+vlanLen {
			return "", 0, nil, false
		}
		etype = EthernetType(binary.BigEndian.Uint16(f[16:]))
		off += vlanLen
	}
	if etype != EthernetTypeIPv4 || len(f) < off+ipMinLen {
		return "", 0, nil, false
	}

	ip := f[off:]
	ihl := int(ip[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(ip[2:]))
	if total == 0 {
		// Captured with TCP segmentation offload: the NIC fills it in.
		total = len(ip)
	}
	if IPProtocol(ip[9]) != IPProtocolTCP || total > len(ip) || ihl+tcpMinLen > total {
		return "", 0, nil, false
	}

	tcp := ip[ihl:total]
	sport := binary.BigEndian.Uint16(tcp[0:])
	dport := binary.BigEndian.Uint16(tcp[2:])
	doff := int(tcp[12]>>4) * 4
	if (sport != iecISOTSAPPort && dport != iecISOTSAPPort) || doff < tcpMinLen || doff > len(tcp) {
		return "", 0, nil, false
	}

	key := fmt.Sprintf("%x:%d>%x:%d", ip[12:16], sport, ip[16:20], dport)
	return key, binary.BigEndian.Uint32(tcp[4:]), tcp[doff:], true
}

// iecTSDUsByFrame indexes the TSDUs of a capture by frame number.
func iecTSDUsByFrame(t *testing.T, name string) map[int][][]byte {
	out := map[int][][]byte{}
	for _, ts := range iecExtractTSDUs(iecReadPcap(t, "testdata/"+name)) {
		out[ts.frame] = append(out[ts.frame], ts.data)
	}
	return out
}

func iecSession(data []byte) gopacket.Packet {
	return gopacket.NewPacket(data, LayerTypeISOSession, gopacket.Default)
}

// iecMMSOf decodes the only TSDU of a frame down to MMS.
func iecMMSOf(t *testing.T, tsdus map[int][][]byte, frame int) (gopacket.Packet, *MMS) {
	t.Helper()
	if len(tsdus[frame]) != 1 {
		t.Fatalf("frame %d: %d TSDUs", frame, len(tsdus[frame]))
	}
	p := iecSession(tsdus[frame][0])
	m, ok := p.Layer(LayerTypeMMS).(*MMS)
	if !ok {
		t.Fatalf("frame %d: no MMS layer: %v", frame, p.ErrorLayer())
	}
	return p, m
}

func TestMMSPcaps(t *testing.T) {
	tests := []struct {
		name   string
		frames int
		errors []int
	}{
		{"iec61850_mms.pcap", 163, nil},
		{"iec61850_mms_reports_goose.pcap", 31, nil},
		{"iec61850_mms_siemens.pcap", 129, nil},
		{"iec61850_mms_libiec61850.pcap", 6, []int{10, 18}},
	}

	for _, tc := range tests {
		tsdus := iecTSDUsByFrame(t, tc.name)
		if len(tsdus) != tc.frames {
			t.Errorf("%s: %d frames with TSDUs, want %d", tc.name, len(tsdus), tc.frames)
		}

		var failed []int
		for frame, list := range tsdus {
			for _, data := range list {
				p := iecSession(data)
				if p.ErrorLayer() != nil {
					failed = append(failed, frame)
					continue
				}

				// Every TSDU here carries MMS or ACSE.
				if p.Layer(LayerTypeISOPresentation) == nil || (p.Layer(LayerTypeMMS) == nil && p.Layer(LayerTypeACSE) == nil) {
					t.Errorf("%s frame %d: layers %v", tc.name, frame, p.Layers())
				}
			}
		}
		if !iecSameInts(failed, tc.errors) {
			t.Errorf("%s: failed frames %v, want %v", tc.name, failed, tc.errors)
		}
	}
}

func iecSameInts(a, b []int) bool {
	seen := map[int]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestMMSConnect(t *testing.T) {
	tsdus := iecTSDUsByFrame(t, "iec61850_mms.pcap")

	// Frame 11: CN / CP / AARQ / initiate-Request.
	p, m := iecMMSOf(t, tsdus, 11)
	checkLayers(p, []gopacket.LayerType{LayerTypeISOSession, LayerTypeISOPresentation, LayerTypeACSE, LayerTypeMMS}, t)

	s := p.Layer(LayerTypeISOSession).(*ISOSession)
	cn := s.SPDUs[0]
	if len(s.SPDUs) != 1 || cn.Type != ISOSessionConnect || cn.Length != 188 ||
		!bytes.Equal(cn.Param(ISOSessionParamCallingSelector).Value, []byte{0, 1}) ||
		!bytes.Equal(cn.Param(ISOSessionParamCalledSelector).Value, []byte{0, 2}) ||
		!bytes.Equal(cn.Param(ISOSessionParamVersion).Value, []byte{2}) ||
		len(s.Payload) != 166 {
		t.Errorf("unexpected CN %+v", s)
	}

	pr := p.Layer(LayerTypeISOPresentation).(*ISOPresentation)
	wantCtx := []ISOPresentationContext{{1, osiOIDACSE, []string{"2.1.1"}}, {3, osiOIDMMS, []string{"2.1.1"}}}
	if pr.Type != ISOPresentationCP || pr.Mode != 1 || !bytes.Equal(pr.CallingSelector, []byte{0, 0, 0, 1}) ||
		!bytes.Equal(pr.CalledSelector, []byte{0, 0, 0, 2}) || !reflect.DeepEqual(pr.Contexts, wantCtx) ||
		len(pr.PDVs) != 1 || pr.PDVs[0].ContextID != 1 || pr.PDVs[0].Encoding != ISOPresentationSingleASN1 {
		t.Errorf("unexpected CP %+v", pr)
	}

	a := p.Layer(LayerTypeACSE).(*ACSE)
	if a.Type != ACSEAARQ || a.ApplicationContext != "1.0.9506.1.1" ||
		!reflect.DeepEqual(a.Called, ACSEAETitle{"1.1.2", []byte{0x29, 0x02}, 2, true}) ||
		a.Calling.APTitle != "1.1.1" || a.Calling.AEQualifier != 1 ||
		len(a.UserInformation) != 1 || a.UserInformation[0].TransferSyntax != "2.1.1" || a.UserInformation[0].ContextID != 3 {
		t.Errorf("unexpected AARQ %+v", a)
	}

	services := []byte{0x6e, 0x1d, 0, 0, 0, 0, 0, 0x64, 0, 0x01, 0x98}
	want := &MMSInitiate{LocalDetail: 32000, HasLocalDetail: true, MaxServOutstandingCalling: 20,
		MaxServOutstandingCalled: 20, NestingLevel: 4, HasNestingLevel: true, Version: 1,
		ParameterCBB: []byte{0xfb, 0x00}, ServicesSupported: services, servicesUnused: 3}
	if m.Type != MMSInitiateRequest || !reflect.DeepEqual(m.Initiate, want) {
		t.Errorf("initiate-Request %+v", m.Initiate)
	}
	if !m.Initiate.SupportsService(MMSRead) || m.Initiate.SupportsService(MMSStatus) || m.Initiate.SupportsService(200) {
		t.Error("SupportsService")
	}

	// Frame 14: AC / CPA / AARE / initiate-Response.
	p, m = iecMMSOf(t, tsdus, 14)
	if s := p.Layer(LayerTypeISOSession).(*ISOSession); s.Type() != ISOSessionAccept {
		t.Errorf("SPDU %v", s.Type())
	}
	pr = p.Layer(LayerTypeISOPresentation).(*ISOPresentation)
	if pr.Type != ISOPresentationCPA || !bytes.Equal(pr.RespondingSelector, []byte{0, 0, 0, 2}) ||
		!reflect.DeepEqual(pr.Results, []ISOPresentationResult{{0, "2.1.1", 0}, {0, "2.1.1", 0}}) {
		t.Errorf("unexpected CPA %+v", pr)
	}
	a = p.Layer(LayerTypeACSE).(*ACSE)
	if a.Type != ACSEAARE || a.Result != ACSEAccepted || a.DiagnosticSource != ACSEDiagnosticServiceUser || a.Diagnostic != 0 ||
		a.Responding.APTitle != "1.1.2" || a.Responding.AEQualifier != 2 ||
		a.UserInformation[0].TransferSyntax != "" || a.UserInformation[0].ContextID != 3 {
		t.Errorf("unexpected AARE %+v", a)
	}
	if m.Type != MMSInitiateResponse || m.Initiate.LocalDetail != 32000 || !bytes.Equal(m.Initiate.ServicesSupported, services) {
		t.Errorf("initiate-Response %+v", m.Initiate)
	}
}

func TestMMSServices(t *testing.T) {
	tsdus := iecTSDUsByFrame(t, "iec61850_mms.pcap")
	kirkland := func(item string) MMSObjectName { return MMSObjectName{MMSScopeDomain, "KIRKLAND", item} }

	// Frame 20: read request; GT + DT session.
	p, m := iecMMSOf(t, tsdus, 20)
	s := p.Layer(LayerTypeISOSession).(*ISOSession)
	if len(s.SPDUs) != 2 || s.SPDUs[0].Type != ISOSessionGiveTokens || s.Type() != ISOSessionDataTransfer {
		t.Errorf("session %+v", s.SPDUs)
	}
	if m.Type != MMSConfirmedRequest || m.InvokeID != 4432 || m.Service != MMSRead ||
		m.ReadReq.Access.Kind != MMSAccessListOfVariable || m.ReadReq.Access.Variables[0].Name != kirkland("Bilateral_Table_ID") {
		t.Errorf("read request %+v %+v", m, m.ReadReq)
	}

	// Frame 26: identify response.
	_, m = iecMMSOf(t, tsdus, 26)
	if m.Type != MMSConfirmedResponse || m.Service != MMSIdentify ||
		!reflect.DeepEqual(*m.IdentifyResp, MMSIdentifyResponse{Vendor: "AREVA T&D Corporation", Model: "e-terracomm", Revision: "2.3.1"}) {
		t.Errorf("identify response %+v", m.IdentifyResp)
	}

	// Frame 32: read response: "1.0", {1996, 8}, bit-string fb00/4.
	_, m = iecMMSOf(t, tsdus, 32)
	r := m.ReadResp.Results
	if m.InvokeID != 4432 || len(r) != 3 || r[0].Data.String != "1.0" || r[1].Data.Items[0].Int != 1996 ||
		r[1].Data.Items[1].Int != 8 || !bytes.Equal(r[2].Data.Bits, []byte{0xfb, 0}) || r[2].Data.UnusedBits != 4 {
		t.Errorf("read response %+v", r)
	}

	// Frame 44: getNamedVariableListAttributes response.
	_, m = iecMMSOf(t, tsdus, 44)
	l := m.NamedVariableList
	if m.Service != MMSGetNamedVariableListAttributes || !l.Deletable || len(l.Variables) != 19 ||
		l.Variables[0].Name != kirkland("Transfer_Set_Name") || l.Variables[2].Name != (MMSObjectName{MMSScopeVMD, "", "TP34"}) {
		t.Errorf("getNamedVariableListAttributes %+v", l)
	}

	// Frame 59: write request of a 12 member structure.
	_, m = iecMMSOf(t, tsdus, 59)
	w := m.WriteReq
	if m.Service != MMSWrite || w.Access.Variables[0].Name != kirkland("CITEC_TS0") || len(w.Data) != 1 ||
		len(w.Data[0].Items) != 12 || w.Data[0].Items[0].Items[2].String != "EMS_ANALOG_ICCP_IN" || !w.Data[0].Items[10].Bool {
		t.Errorf("write request %+v", w)
	}

	// Frame 65: write response.
	_, m = iecMMSOf(t, tsdus, 65)
	if m.InvokeID != 4436 || !reflect.DeepEqual(m.WriteResp, []MMSWriteResult{{}}) {
		t.Errorf("write response %+v", m.WriteResp)
	}

	// Frame 68: information report on a named variable list.
	_, m = iecMMSOf(t, tsdus, 68)
	ir := m.InformationReport
	if m.Type != MMSUnconfirmed || m.Unconfirmed != MMSUnconfirmedInfoReport ||
		ir.Access.Kind != MMSAccessVariableListName || ir.Access.ListName != kirkland("EMS_ANALOG_ICCP_IN") ||
		len(ir.Results) != 19 || ir.Results[0].Data.Items[2].String != "CITEC_TS0" {
		t.Errorf("information report %+v", ir)
	}
}

// TestMMSReports decodes IEC 61850 reports of an association whose
// connect was not captured: presentation routes them by tag.
func TestMMSReports(t *testing.T) {
	tsdus := iecTSDUsByFrame(t, "iec61850_mms_reports_goose.pcap")
	p, m := iecMMSOf(t, tsdus, 3)
	if pr := p.Layer(LayerTypeISOPresentation).(*ISOPresentation); pr.Contexts != nil || pr.PDVs[0].ContextID != 3 {
		t.Errorf("presentation %+v", pr)
	}

	ir := m.InformationReport
	r := ir.Results
	if ir.Access.ListName != (MMSObjectName{MMSScopeVMD, "", "RPT"}) || len(r) != 6 ||
		r[0].Data.String != "AA1C1Q01A1LD0/LLN0$rcb_I02" || r[1].Data.UnusedBits != 6 || !r[1].Data.Bit(1) ||
		r[2].Data.Uint != 57 || len(r[4].Data.Items) != 3 {
		t.Fatalf("report %+v", r)
	}

	// FN + RLRQ and DN + RLRE close the association.
	for frame, want := range map[int]ACSEAPDUType{139: ACSERLRQ, 140: ACSERLRE} {
		p := iecSession(tsdus[frame][0])
		a, ok := p.Layer(LayerTypeACSE).(*ACSE)
		if !ok || a.Type != want || !a.HasReason || a.Reason != 1 || p.Layer(LayerTypeMMS) != nil {
			t.Errorf("frame %d: %v", frame, p.Layers())
		}
	}

	// mag.f, then q and t of the first data set member.
	member := r[4].Data.Items[0].Items
	f := member[0].Items[0].Items[0]
	if f.Type != MMSDataFloatingPoint || f.Float != float64(math.Float32frombits(0x3e5a95fc)) {
		t.Errorf("float %+v", f)
	}
	if got := member[3].UTC.Time().Format(iecTimeLayout); got != "Jul 18, 2008 12:34:17.541000008" || member[3].UTC.Quality != 0x0a {
		t.Errorf("utc-time %s", got)
	}
}

func TestMMSSiemens(t *testing.T) {
	tsdus := iecTSDUsByFrame(t, "iec61850_mms_siemens.pcap")

	_, m := iecMMSOf(t, tsdus, 3)
	if g := m.GetNameListReq; g == nil || g.ObjectClass != MMSClassDomain || g.Scope != MMSScopeVMD {
		t.Errorf("getNameList request %+v", g)
	}

	_, m = iecMMSOf(t, tsdus, 4)
	if g := m.GetNameListResp; len(g.Identifiers) != 5 || g.MoreFollows {
		t.Errorf("getNameList response %+v", g)
	}

	// Four requests in one frame.
	if len(tsdus[7]) != 4 {
		t.Errorf("frame 7: %d TSDUs, want 4", len(tsdus[7]))
	}

	// Reassembled from three COTP DT units.
	_, m = iecMMSOf(t, tsdus, 11)
	if g := m.GetNameListResp; len(g.Identifiers) != 100 || !g.MoreFollows || g.Identifiers[0] != "LLN0" {
		t.Errorf("getNameList response %d ids, more %v", len(g.Identifiers), g.MoreFollows)
	}

	_, m = iecMMSOf(t, tsdus, 16)
	if m.Service != MMSGetVariableAccessAttributes || m.ObjectName == nil || m.ObjectName.Scope != MMSScopeDomain {
		t.Errorf("getVariableAccessAttributes %+v", m.ObjectName)
	}
}

func TestMMSLibIEC61850(t *testing.T) {
	tsdus := iecTSDUsByFrame(t, "iec61850_mms_libiec61850.pcap")
	p, m := iecMMSOf(t, tsdus, 8)
	a := p.Layer(LayerTypeACSE).(*ACSE)
	if a.ApplicationContext != "1.0.9506.2.3" || a.Called.APTitle != "1.3.9999.2" || a.Called.AEQualifier != 23 ||
		m.Initiate.LocalDetail != 30000 || m.Initiate.MaxServOutstandingCalling != 1000 || m.Initiate.NestingLevel != 5 {
		t.Errorf("AARQ %+v initiate %+v", a, m.Initiate)
	}

	// The AC SPDU length overruns the TSDU by one octet.
	if err := (&ISOSession{}).DecodeFromBytes(tsdus[10][0], gopacket.NilDecodeFeedback); err != errISOSessionTruncated {
		t.Errorf("AC: %v", err)
	}

	// A confirmed-ResponsePDU with an invokeID and no service.
	p = iecSession(tsdus[18][0])
	if p.Layer(LayerTypeISOPresentation) == nil || p.ErrorLayer() == nil || p.ErrorLayer().Error() != errMMSNoService {
		t.Errorf("response without service: %v", p.ErrorLayer())
	}
}

// Hand built PPDUs and SPDUs, from ISO 8327-1, ISO 8823-1 and ISO 8650-1:
// no capture holds a refuse, an abort or a release carrying MMS conclude.

// iecSPDU encodes an SPDU or parameter: identifier, LI, value.
func iecSPDU(id byte, parts ...[]byte) []byte {
	v := bytes.Join(parts, nil)
	if len(v) < isoSessionLongLI {
		return append([]byte{id, byte(len(v))}, v...)
	}
	return append([]byte{id, isoSessionLongLI, byte(len(v) >> 8), byte(len(v))}, v...)
}

// iecUserData wraps an APDU in fully-encoded presentation user data.
func iecUserData(ctx byte, apdu []byte) []byte {
	return iecTLV(0x61, iecTLV(0x30, iecTLV(0x02, []byte{ctx}), iecTLV(0xa0, apdu)))
}

// iecDT builds the usual GT + DT TSDU around an MMS PDU.
func iecDT(mms []byte) []byte {
	return append([]byte{0x01, 0x00, 0x01, 0x00}, iecUserData(3, mms)...)
}

func TestISOSessionRelease(t *testing.T) {
	rlrq := iecTLV(0x62, iecTLV(0x80, []byte{0}), iecTLV(0xbe, iecTLV(0x28, iecTLV(0x02, []byte{3}), iecTLV(0xa0, []byte{0x8b, 0x00}))))
	fn := iecSPDU(byte(ISOSessionFinish), iecSPDU(17, []byte{3}), iecSPDU(193, iecUserData(1, rlrq)))

	p := iecSession(fn)
	checkLayers(p, []gopacket.LayerType{LayerTypeISOSession, LayerTypeISOPresentation, LayerTypeACSE, LayerTypeMMS}, t)
	a := p.Layer(LayerTypeACSE).(*ACSE)
	m := p.Layer(LayerTypeMMS).(*MMS)
	if a.Type != ACSERLRQ || !a.HasReason || a.Reason != 0 || m.Type != MMSConcludeRequest {
		t.Errorf("RLRQ %+v, MMS %v", a, m.Type)
	}

	rlre := iecTLV(0x63, iecTLV(0x80, []byte{0}), iecTLV(0xbe, iecTLV(0x28, iecTLV(0x02, []byte{3}), iecTLV(0xa0, []byte{0x8c, 0x00}))))
	p = iecSession(iecSPDU(byte(ISOSessionDisconnect), iecSPDU(193, iecUserData(1, rlre))))
	if a, ok := p.Layer(LayerTypeACSE).(*ACSE); !ok || a.Type != ACSERLRE || p.Layer(LayerTypeMMS).(*MMS).Type != MMSConcludeResponse {
		t.Errorf("RLRE: %v", p.Layers())
	}
}

func TestISOSessionRefuse(t *testing.T) {
	// RF with reason 2 followed by a CPR rejecting the default context.
	cpr := iecTLV(0x30, iecTLV(0x80, []byte{0x07, 0x80}), iecTLV(0x83, []byte{0, 0, 0, 1}),
		iecTLV(0xa5, iecTLV(0x30, iecTLV(0x80, []byte{2}), iecTLV(0x82, []byte{1}))), iecTLV(0x8a, []byte{1}))
	p := iecSession(iecSPDU(byte(ISOSessionRefuse), iecSPDU(50, []byte{2}, cpr)))

	pr, ok := p.Layer(LayerTypeISOPresentation).(*ISOPresentation)
	if !ok || pr.Type != ISOPresentationCPR || !pr.HasProviderReason || pr.ProviderReason != 1 ||
		!reflect.DeepEqual(pr.Results, []ISOPresentationResult{{Result: 2, ProviderReason: 1}}) {
		t.Errorf("CPR %+v: %v", pr, p.ErrorLayer())
	}

	// Without the session hint, the same SEQUENCE is still a CPR.
	var alone ISOPresentation
	if err := alone.DecodeFromBytes(cpr, gopacket.NilDecodeFeedback); err != nil || alone.Type != ISOPresentationCPR {
		t.Errorf("CPR alone: %v %v", alone.Type, err)
	}
}

func TestISOSessionAbort(t *testing.T) {
	// AB carrying an ARU with an ACSE ABRT.
	abrt := iecTLV(0x64, iecTLV(0x80, []byte{1}))
	aru := iecTLV(0xa0, iecTLV(0xa0, iecTLV(0x30, iecTLV(0x02, []byte{1}), iecTLV(0x06, []byte{0x52, 0x01, 0x00, 0x01}))), iecUserData(1, abrt))
	p := iecSession(iecSPDU(byte(ISOSessionAbort), iecSPDU(17, []byte{0x0b}), iecSPDU(193, aru)))
	pr, ok := p.Layer(LayerTypeISOPresentation).(*ISOPresentation)
	if !ok || pr.Type != ISOPresentationARU || !reflect.DeepEqual(pr.ContextIDs, []int64{1}) {
		t.Fatalf("ARU %+v: %v", pr, p.ErrorLayer())
	}
	if a := p.Layer(LayerTypeACSE).(*ACSE); a.Type != ACSEABRT || a.AbortSource != 1 || a.NextLayerType() != gopacket.LayerTypeZero {
		t.Errorf("ABRT %+v", a)
	}

	// AB carrying an ARP.
	p = iecSession(iecSPDU(byte(ISOSessionAbort), iecSPDU(193, iecTLV(0x30, iecTLV(0x80, []byte{5}), iecTLV(0x81, []byte{7})))))
	pr, ok = p.Layer(LayerTypeISOPresentation).(*ISOPresentation)
	if !ok || pr.Type != ISOPresentationARP || pr.ProviderReason != 5 || pr.EventID != 7 {
		t.Errorf("ARP %+v: %v", pr, p.ErrorLayer())
	}
}

func TestISOSessionForms(t *testing.T) {
	read := []byte{0xa0, 0x05, 0x02, 0x01, 0x07, 0x82, 0x00}
	tests := map[string]struct {
		tsdu  []byte
		types []ISOSessionSPDUType
		mms   bool
	}{
		"GT alone":    {[]byte{0x01, 0x00}, []ISOSessionSPDUType{ISOSessionGiveTokens}, false},
		"PT + DT":     {append([]byte{0x02, 0x00, 0x01, 0x00}, iecUserData(3, read)...), []ISOSessionSPDUType{ISOSessionPleaseTokens, ISOSessionDataTransfer}, true},
		"lone DT":     {append([]byte{0x01, 0x00}, iecUserData(3, read)...), []ISOSessionSPDUType{ISOSessionDataTransfer}, true},
		"PGI + PI":    {iecSPDU(byte(ISOSessionConnect), iecSPDU(5, iecSPDU(19, []byte{0}))), []ISOSessionSPDUType{ISOSessionConnect}, false},
		"long LI 300": {iecSPDU(byte(ISOSessionAccept), iecSPDU(60, make([]byte, 300))), []ISOSessionSPDUType{ISOSessionAccept}, false},
	}
	for name, tc := range tests {
		p := iecSession(tc.tsdu)
		s, ok := p.Layer(LayerTypeISOSession).(*ISOSession)
		if !ok {
			t.Errorf("%s: %v", name, p.ErrorLayer())
			continue
		}
		var got []ISOSessionSPDUType
		for _, sp := range s.SPDUs {
			got = append(got, sp.Type)
		}
		if !reflect.DeepEqual(got, tc.types) || (p.Layer(LayerTypeMMS) != nil) != tc.mms {
			t.Errorf("%s: SPDUs %v, layers %v", name, got, p.Layers())
		}
	}

	bad := map[string][]byte{
		"empty":         {},
		"short":         {0x0d},
		"LI overrun":    {0x0d, 0x05, 0x01},
		"long LI short": {0x0d, 0xff, 0x00},
		"param overrun": {0x0d, 0x03, 0x14, 0x05, 0x00},
		"PGI in PGI":    iecSPDU(byte(ISOSessionConnect), iecSPDU(5, iecSPDU(1, iecSPDU(9, []byte{0})))),
		"DT truncated":  {0x01, 0x00, 0x01, 0x05, 0x00},
	}
	for name, tsdu := range bad {
		if err := (&ISOSession{}).DecodeFromBytes(tsdu, gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

func TestMMSHandBuilt(t *testing.T) {
	name := iecTLV(0xa1, iecTLV(0x1a, []byte("LD0")), iecTLV(0x1a, []byte("LLN0$ST")))
	tests := map[string]struct {
		pdu   []byte
		check func(m *MMS) bool
	}{
		"conclude-Request":  {[]byte{0x8b, 0x00}, func(m *MMS) bool { return m.Type == MMSConcludeRequest }},
		"conclude-Response": {[]byte{0x8c, 0x00}, func(m *MMS) bool { return m.Type == MMSConcludeResponse }},
		"conclude-Error": {iecTLV(0xad, iecTLV(0xa0, iecTLV(0x89, []byte{0}))), func(m *MMS) bool {
			return m.Error.Class == MMSErrorConclude && m.Error.Code == 0
		}},
		"cancel-Request":  {[]byte{0x85, 0x01, 0x05}, func(m *MMS) bool { return m.Type == MMSCancelRequest && m.InvokeID == 5 }},
		"cancel-Response": {[]byte{0x86, 0x01, 0x05}, func(m *MMS) bool { return m.Type == MMSCancelResponse && m.InvokeID == 5 }},
		"cancel-Error": {iecTLV(0xa7, iecTLV(0x80, []byte{5}), iecTLV(0xa1, iecTLV(0xa0, iecTLV(0x8a, []byte{1})))), func(m *MMS) bool {
			return m.InvokeID == 5 && m.Error.Class == MMSErrorCancel && m.Error.Code == 1
		}},
		"reject": {iecTLV(0xa4, iecTLV(0x80, []byte{7}), iecTLV(0x81, []byte{2})), func(m *MMS) bool {
			return *m.Reject == MMSRejectInfo{HasInvokeID: true, InvokeID: 7, Type: MMSRejectConfirmedRequest, Reason: 2}
		}},
		"confirmed-Error": {iecTLV(0xa2, iecTLV(0x80, []byte{9}), iecTLV(0xa2, iecTLV(0xa0, iecTLV(0x87, []byte{3})), iecTLV(0x81, []byte{4}), iecTLV(0x82, []byte("no")))), func(m *MMS) bool {
			return m.InvokeID == 9 && *m.Error == MMSServiceError{MMSErrorAccess, 3, 4, "no"}
		}},
		"initiate-Error": {iecTLV(0xaa, iecTLV(0xa0, iecTLV(0x88, []byte{1}))), func(m *MMS) bool { return m.Error.Class == MMSErrorInitiate }},
		"status": {iecTLV(0xa0, iecTLV(0x02, []byte{3}), iecTLV(0x80, []byte{0})), func(m *MMS) bool {
			return m.Service == MMSStatus && bytes.Equal(m.ServiceData, []byte{0})
		}},
		"modifier + fileOpen": {iecTLV(0xa0, iecTLV(0x02, []byte{1}), iecTLV(0x30), []byte{0xbf, 0x48, 0x01, 0xaa}), func(m *MMS) bool {
			return m.Service == MMSFileOpen && bytes.Equal(m.ServiceData, []byte{0xaa})
		}},
		"getNameList domain": {iecTLV(0xa0, iecTLV(0x02, []byte{1}), iecTLV(0xa1, iecTLV(0xa0, iecTLV(0x80, []byte{0})), iecTLV(0xa1, iecTLV(0x81, []byte("LD0"))), iecTLV(0x82, []byte("x")))), func(m *MMS) bool {
			return *m.GetNameListReq == MMSGetNameListRequest{MMSClassNamedVariable, MMSScopeDomain, "LD0", "x"}
		}},
		"getVariableAccessAttributes": {iecTLV(0xa0, iecTLV(0x02, []byte{2}), iecTLV(0xa6, iecTLV(0xa0, name))), func(m *MMS) bool {
			return *m.ObjectName == MMSObjectName{MMSScopeDomain, "LD0", "LLN0$ST"}
		}},
		"read failure": {iecTLV(0xa1, iecTLV(0x02, []byte{4}), iecTLV(0xa4, iecTLV(0xa1, iecTLV(0x80, []byte{10}), iecTLV(0x83, []byte{1})))), func(m *MMS) bool {
			r := m.ReadResp.Results
			return r[0].Failed && r[0].Error == MMSObjectNonExistent && r[1].Data.Bool
		}},
		"read aa-specific list": {iecTLV(0xa0, iecTLV(0x02, []byte{4}), iecTLV(0xa4, iecTLV(0x80, []byte{1}), iecTLV(0xa1, iecTLV(0xa1, iecTLV(0x82, []byte("L")))))), func(m *MMS) bool {
			return m.ReadReq.SpecificationWithResult && m.ReadReq.Access.ListName == MMSObjectName{MMSScopeAA, "", "L"}
		}},
		"write failure": {iecTLV(0xa1, iecTLV(0x02, []byte{4}), iecTLV(0xa5, iecTLV(0x80, []byte{3}), iecTLV(0x81))), func(m *MMS) bool {
			return reflect.DeepEqual(m.WriteResp, []MMSWriteResult{{true, MMSObjectAccessDenied}, {}})
		}},
		"defineNamedVariableList": {iecTLV(0xa0, iecTLV(0x02, []byte{4}), iecTLV(0xab, name, iecTLV(0xa0, iecTLV(0x30, iecTLV(0xa0, name), iecTLV(0xa5, []byte{0x80, 0x00}))))), func(m *MMS) bool {
			l := m.NamedVariableList
			return l.Name.ItemID == "LLN0$ST" && l.Variables[0].Name.DomainID == "LD0" && len(l.Variables[0].AlternateAccess) == 2
		}},
	}
	for n, tc := range tests {
		p := iecSession(iecDT(tc.pdu))
		m, ok := p.Layer(LayerTypeMMS).(*MMS)
		if !ok {
			t.Errorf("%s: %v", n, p.ErrorLayer())
			continue
		}
		if !tc.check(m) {
			t.Errorf("%s: %+v", n, m)
		}
	}

	bad := map[string][]byte{
		"unknown PDU":        {0xae, 0x00},
		"application class":  {0x61, 0x00},
		"primitive request":  {0x80, 0x00},
		"conclude with data": {0x8b, 0x01, 0x00},
		"no invokeID":        iecTLV(0xa0, iecTLV(0x80, []byte{0})),
		"bad read response":  iecTLV(0xa1, iecTLV(0x02, []byte{4}), iecTLV(0xa4, iecTLV(0xa0))),
		"bad access error":   iecTLV(0xa1, iecTLV(0x02, []byte{4}), iecTLV(0xa4, iecTLV(0xa1, iecTLV(0x80, []byte{99})))),
		"bad object name":    iecTLV(0xa0, iecTLV(0x02, []byte{2}), iecTLV(0xa6, iecTLV(0xa0, iecTLV(0x83, nil)))),
		"bad reject":         iecTLV(0xa4, iecTLV(0x8c, []byte{0})),
		"service-ext only":   iecTLV(0xa0, iecTLV(0x02, []byte{1}), []byte{0xbf, 0x4f, 0x00}),
		"primitive read":     iecTLV(0xa0, iecTLV(0x02, []byte{1}), iecTLV(0x84)),
		"service tag > 16b":  iecTLV(0xa0, iecTLV(0x02, []byte{1}), []byte{0xbf, 0x84, 0x80, 0x80, 0x04, 0x00}),
		"data tag 259":       iecTLV(0xa1, iecTLV(0x02, []byte{4}), iecTLV(0xa4, iecTLV(0xa1, []byte{0x9f, 0x82, 0x03, 0x01, 0x00}))),
	}
	for n, pdu := range bad {
		if err := (&MMS{}).DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("%s: decoded", n)
		}
	}
}

// TestISOPresentationOpaque checks octet-aligned PDV data is not routed.
func TestISOPresentationOpaque(t *testing.T) {
	ud := iecTLV(0x61, iecTLV(0x30, iecTLV(0x02, []byte{3}), iecTLV(0x81, []byte{0x8b, 0x00})))
	p := iecSession(append([]byte{0x01, 0x00, 0x01, 0x00}, ud...))
	pr, ok := p.Layer(LayerTypeISOPresentation).(*ISOPresentation)
	if !ok || pr.PDVs[0].Encoding != ISOPresentationOctetAligned || p.Layer(LayerTypeMMS) != nil || p.Layer(gopacket.LayerTypePayload) == nil {
		t.Errorf("layers %v", p.Layers())
	}
}

// TestISODecodingLayerParser runs the stack through a DecodingLayerParser,
// which only sees NextLayerType.
func TestISODecodingLayerParser(t *testing.T) {
	var s ISOSession
	var pr ISOPresentation
	var a ACSE
	var m MMS
	parser := gopacket.NewDecodingLayerParser(LayerTypeISOSession, &s, &pr, &a, &m)

	tsdus := iecTSDUsByFrame(t, "iec61850_mms.pcap")
	for _, frame := range []int{11, 14, 20} {
		var decoded []gopacket.LayerType
		if err := parser.DecodeLayers(tsdus[frame][0], &decoded); err != nil {
			t.Fatalf("frame %d: %v", frame, err)
		}
		if decoded[len(decoded)-1] != LayerTypeMMS {
			t.Errorf("frame %d: decoded %v", frame, decoded)
		}
	}
	if m.Service != MMSRead || m.InvokeID != 4432 {
		t.Errorf("last MMS %+v", m)
	}
}

// TestISOStackTruncation cuts every TSDU of two captures at every offset.
func TestISOStackTruncation(t *testing.T) {
	for _, name := range []string{"iec61850_mms.pcap", "iec61850_mms_reports_goose.pcap"} {
		for _, ts := range iecExtractTSDUs(iecReadPcap(t, "testdata/"+name)) {
			for i := range ts.data {
				iecSession(ts.data[:i])
			}
		}
	}
}

// TestMMSStackDeepNesting sends 10k nested structures in a read response.
func TestMMSStackDeepNesting(t *testing.T) {
	pdu := iecTLV(0xa1, iecTLV(0x02, []byte{1}), iecTLV(0xa4, iecTLV(0xa1, iecNested(10000))))

	p := iecSession(iecDT(pdu))
	if p.Layer(LayerTypeMMS) != nil || p.ErrorLayer() == nil || p.ErrorLayer().Error() != errOSIBERDepth {
		t.Errorf("deep nesting: %v", p.ErrorLayer())
	}
}

func FuzzISOSession(f *testing.F) {
	const maxSeeds = 400
	n := 0
	for _, name := range []string{"iec61850_mms.pcap", "iec61850_mms_libiec61850.pcap", "iec61850_mms_reports_goose.pcap", "iec61850_mms_siemens.pcap"} {
		for _, ts := range iecExtractTSDUs(iecReadPcap(f, "testdata/"+name)) {
			if n < maxSeeds {
				f.Add(ts.data)
			}
			n++
		}
	}
	f.Add(iecDT([]byte{0x8b, 0x00}))

	f.Fuzz(func(t *testing.T, data []byte) {
		p := iecSession(data)
		for _, l := range p.Layers() {
			if len(l.LayerContents()) > len(data) {
				t.Fatalf("%v contents longer than input", l.LayerType())
			}
		}
	})
}

// Bits past the end of a BIT STRING are padding: a set padding bit does
// not announce a service.
func TestMMSSupportsServicePadding(t *testing.T) {
	// One octet, seven unused bits: only bit 0 (status) is real.
	in := &MMSInitiate{ServicesSupported: []byte{0xC0}, servicesUnused: 7}
	if !in.SupportsService(MMSConfirmedService(0)) {
		t.Fatal("bit 0 not reported")
	}
	if in.SupportsService(MMSConfirmedService(1)) {
		t.Fatal("padding bit 1 reported as a supported service")
	}
}
