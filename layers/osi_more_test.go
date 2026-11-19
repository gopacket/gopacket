// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// TestISOSessionExtended decodes extended concatenation: more than one
// category 2 SPDU after the token SPDU. Hand built; tshark 4.7 lists the
// same SPDUs.
func TestISOSessionExtended(t *testing.T) {
	gt := iecSPDU(byte(ISOSessionGiveTokens))
	mip := iecSPDU(byte(ISOSessionMinorSync), iecSPDU(byte(ISOSessionParamSerialNumber), []byte("42")))
	dt := iecSPDU(byte(ISOSessionDataTransfer))
	user := iecUserData(3, mreq(mp(0, []byte{0})))

	p := iecSession(bytes.Join([][]byte{gt, mip, dt, user}, nil))
	s, ok := p.Layer(LayerTypeISOSession).(*ISOSession)
	if !ok || p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer())
	}
	if len(s.SPDUs) != 3 || s.SPDUs[1].Type != ISOSessionMinorSync || s.SPDUs[1].SerialNumber() != "42" ||
		s.Type() != ISOSessionDataTransfer || !bytes.Equal(s.Payload, user) || p.Layer(LayerTypeMMS) == nil {
		t.Errorf("%+v, layers %v", s, p.Layers())
	}

	// What follows the second SPDU and is no SPDU is left alone.
	cut := bytes.Join([][]byte{gt, mip, {byte(ISOSessionMinorSync), 9, 1}}, nil)
	s = &ISOSession{}
	if err := s.DecodeFromBytes(cut, gopacket.NilDecodeFeedback); err != nil || len(s.SPDUs) != 2 || len(s.Contents) != len(gt)+len(mip) {
		t.Errorf("trailing garbage: %v, %+v", err, s)
	}

	// A DT ends the TSDU: its user data is not searched for SPDUs.
	s = &ISOSession{}
	data := bytes.Join([][]byte{gt, dt, mip, mip}, nil)
	if err := s.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil || len(s.SPDUs) != 2 || len(s.Payload) != 2*len(mip) {
		t.Errorf("SPDUs after DT: %v, %+v", err, s)
	}

	// The number of SPDUs is capped.
	s = &ISOSession{}
	data = append(gt, bytes.Repeat(mip, 1000)...)
	if err := s.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil || len(s.SPDUs) != isoSessionMaxSPDUs {
		t.Errorf("many SPDUs: %v, %d", err, len(s.SPDUs))
	}
}

// TestISOSessionParams reads the typed parameters of the CN and AC SPDUs
// of iec61850_mms.pcap (frames 11 and 14), values from tshark 4.7, and of
// hand built SPDUs.
func TestISOSessionParams(t *testing.T) {
	tsdus := iecTSDUsByFrame(t, "iec61850_mms.pcap")
	for _, frame := range []int{11, 14} {
		s := &ISOSession{}
		if err := s.DecodeFromBytes(tsdus[frame][0], gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}

		sp := &s.SPDUs[0]
		opts, okOpts := sp.ProtocolOptions()
		vers, okVers := sp.Versions()
		reqs, okReqs := sp.Requirements()
		if !okOpts || opts&ISOSessionExtendedConcat != 0 || !okVers || vers != ISOSessionVersion2 || !okReqs || reqs != ISOSessionFUDuplex {
			t.Errorf("frame %d: options %v %v, versions %v %v, requirements %v %v", frame, opts, okOpts, vers, okVers, reqs, okReqs)
		}
		if _, ok := sp.Enclosure(); ok {
			t.Errorf("frame %d: enclosure item", frame)
		}
	}

	cn := &ISOSession{}
	if err := cn.DecodeFromBytes(tsdus[11][0], gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if sp := &cn.SPDUs[0]; !bytes.Equal(sp.CallingSelector(), []byte{0, 1}) || !bytes.Equal(sp.CalledSelector(), []byte{0, 2}) {
		t.Errorf("selectors %x %x", sp.CallingSelector(), sp.CalledSelector())
	}

	param := func(id ISOSessionParamID, v ...byte) []byte { return iecSPDU(byte(id), v) }
	s := &ISOSession{}
	data := iecSPDU(byte(ISOSessionConnect),
		iecSPDU(byte(ISOSessionParamConnectAccept), param(ISOSessionParamProtocolOptions, 1), param(ISOSessionParamTSDUMaxSize, 0x04, 0, 0x02, 0),
			param(ISOSessionParamVersion, 3), param(ISOSessionParamTokenSetting, 0x55)),
		param(ISOSessionParamSessionUserReq, 0x03, 0x49), param(ISOSessionParamEnclosure, 3), param(ISOSessionParamTokenItem, 0x40))
	if err := s.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	sp := &s.SPDUs[0]
	opts, _ := sp.ProtocolOptions()
	vers, _ := sp.Versions()
	reqs, _ := sp.Requirements()
	enc, _ := sp.Enclosure()
	tok, _ := sp.TokenItem()
	set, _ := sp.TokenSetting()
	to, from, okSize := sp.MaxTSDUSize()
	wantReqs := ISOSessionFUHalfDuplex | ISOSessionFUMinorSync | ISOSessionFUActivity | ISOSessionFUCapabilityData | ISOSessionFUExceptions
	if opts != ISOSessionExtendedConcat || vers != ISOSessionVersion1|ISOSessionVersion2 || reqs != wantReqs ||
		enc != ISOSessionEnclosureBegin|ISOSessionEnclosureEnd || tok != 0x40 || set != 0x55 || !okSize || to != 0x400 || from != 0x200 {
		t.Errorf("options %v versions %v requirements %#x enclosure %v tokens %#x %#x size %d %d", opts, vers, reqs, enc, tok, set, to, from)
	}

	// Refuse and abort.
	s = &ISOSession{}
	data = iecSPDU(byte(ISOSessionRefuse), param(ISOSessionParamTransportDisc, 1), param(ISOSessionParamReasonCode, 2, 0xaa))
	if err := s.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	code, okCode := s.SPDUs[0].ReasonCode()
	disc, okDisc := s.SPDUs[0].TransportDisconnect()
	if !okCode || code != 2 || !okDisc || disc != ISOSessionTransportReleased || !bytes.Equal(s.Payload, []byte{0xaa}) {
		t.Errorf("refuse: reason %d %v, disconnect %v %v, payload %x", code, okCode, disc, okDisc, s.Payload)
	}

	// Malformed lengths give ok = false.
	s = &ISOSession{}
	data = iecSPDU(byte(ISOSessionConnect), param(ISOSessionParamSessionUserReq, 1), param(ISOSessionParamVersion), param(ISOSessionParamTSDUMaxSize, 1, 2, 3))
	if err := s.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	_, okReqs := s.SPDUs[0].Requirements()
	_, okVers := s.SPDUs[0].Versions()
	_, _, okSize = s.SPDUs[0].MaxTSDUSize()
	if okReqs || okVers || okSize {
		t.Errorf("malformed parameters accepted: %v %v %v", okReqs, okVers, okSize)
	}
}

// x410Open builds the x410-mode CP or CPA SET around the reliable
// transfer fields.
func x410Open(fields ...[]byte) []byte {
	return iecTLV(0x31, mc(0, mp(0, []byte{0})), mc(1, fields...))
}

// TestISOPresentationX410 decodes the x410-1984 mode PPDUs. Hand built
// from ISO 8823-1 clause 8 and X.410; tshark 4.7 shows the same values
// for the CP, CPA, CPR and ARU. It does not dissect RTTP and RTTR
// without their association.
func TestISOPresentationX410(t *testing.T) {
	open := []byte{0x04, 0x01, 0xaa}
	rtorq := x410Open(mp(0, []byte{1}), mp(1, []byte{5}), mp(2, []byte{1}), mc(3, mc(0, open)), mp(4, []byte{12}))
	rtoac := x410Open(mp(0, []byte{2}), mc(2, mc(1, []byte{0x30, 0x00})))
	wantRQ := ISOPresentationX410{CheckpointSize: 1, WindowSize: 5, DialogueMode: 1, ApplicationProtocol: 12, HasApplicationProtocol: true, ConnectionData: open}
	wantAC := ISOPresentationX410{CheckpointSize: 2, WindowSize: isoPresDefaultWindow, ConnectionData: []byte{0x30, 0x00}, Recover: true}

	tests := []struct {
		name string
		data []byte
		hint ISOPresentationType
		typ  ISOPresentationType
		want ISOPresentationX410
	}{
		{"CP", rtorq, ISOPresentationCP, ISOPresentationCP, wantRQ},
		{"CP no hint", rtorq, 0, ISOPresentationCP, wantRQ},
		{"CPA", rtoac, ISOPresentationCPA, ISOPresentationCPA, wantAC},
		{"CPA no hint", rtoac, 0, ISOPresentationCPA, wantAC},
		{"CPR", iecTLV(0x31, mp(0, []byte{2}), mc(1, open)), ISOPresentationCPR, ISOPresentationCPR,
			ISOPresentationX410{Reason: 2, HasReason: true, UserData: open}},
		{"ARU", iecTLV(0x31, mp(0, []byte{4}), mp(1, []byte{0, 0x80}), mc(2, open)), ISOPresentationARP, ISOPresentationARU,
			ISOPresentationX410{Reason: 4, HasReason: true, Reflected: []byte{0, 0x80}, UserData: open}},
		{"RTTP", iecTLV(0x02, []byte{7}), 0, ISOPresentationRTTP, ISOPresentationX410{Priority: 7}},
		{"RTTR", iecTLV(0x04, []byte{0xa0, 0x00}), 0, ISOPresentationRTTR, ISOPresentationX410{}},
	}
	for _, tc := range tests {
		p := &ISOPresentation{}
		if err := p.decode(tc.data, tc.hint); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if p.Type != tc.typ || p.X410 == nil || !reflect.DeepEqual(*p.X410, tc.want) {
			t.Errorf("%s: type %v, x410 %+v", tc.name, p.Type, p.X410)
		}
	}

	// The data of an RTTR is opaque, even when it looks like MMS.
	p := &ISOPresentation{}
	if err := p.decode(iecTLV(0x04, []byte{0xa0, 0x00}), 0); err != nil || p.NextLayerType() != gopacket.LayerTypePayload || !bytes.Equal(p.Payload, []byte{0xa0, 0x00}) {
		t.Errorf("RTTR payload: %v, %v, %x", err, p.NextLayerType(), p.Payload)
	}

	// Through the stack: AB SPDU with an RTAB.
	ab := iecSPDU(byte(ISOSessionAbort), iecSPDU(byte(ISOSessionParamTransportDisc), []byte{3}), iecSPDU(byte(ISOSessionParamUserData), iecTLV(0x31, mp(0, []byte{1}))))
	pkt := iecSession(ab)
	pr, ok := pkt.Layer(LayerTypeISOPresentation).(*ISOPresentation)
	if !ok || pr.Type != ISOPresentationARU || !pr.X410.HasReason || pr.X410.Reason != 1 {
		t.Errorf("abort: %v, %+v", pkt.ErrorLayer(), pr)
	}

	// Malformed and truncated parameters never panic.
	for _, tc := range tests {
		for i := range tc.data {
			_ = (&ISOPresentation{}).decode(tc.data[:i], tc.hint)
		}
	}
	bad := [][]byte{
		x410Open(mc(3, mc(2))),
		x410Open(mc(3, mp(0))),
		x410Open(mp(0, nil)),
		iecTLV(0x02, nil),
	}
	for i, data := range bad {
		if err := (&ISOPresentation{}).decode(data, ISOPresentationCP); err == nil {
			t.Errorf("bad %d: decoded", i)
		}
	}
}

// TestACSEOptions decodes the ACSE fields past the titles: protocol
// version, requirements, authentication value and context name list.
// Hand built from X.227; tshark was not run on these.
func TestACSEOptions(t *testing.T) {
	ctx := mc(1, iecTLV(0x06, []byte{0x28, 0xca, 0x22, 0x02, 0x03}))
	names := iecTLV(0x06, []byte{0x28, 0xca, 0x22, 0x02, 0x03})
	tests := []struct {
		name  string
		apdu  []byte
		kind  ACSEAuthenticationKind
		value []byte
	}{
		{"AARQ charstring", iecTLV(0x60, mp(0, []byte{7, 0x80}), ctx, mp(10, []byte{6, 0xc0}), mp(11, []byte{0x52, 0x03, 0x01}), mc(12, mp(0, []byte("secret"))), mc(13, names)),
			ACSEAuthCharString, []byte("secret")},
		{"AARE bitstring", iecTLV(0x61, mp(0, []byte{7, 0x80}), ctx, mc(2, iecTLV(0x02, []byte{0})), mp(8, []byte{6, 0xc0}), mc(10, mp(1, []byte{0, 0xff})), mc(11, names)),
			ACSEAuthBitString, []byte{0, 0xff}},
		{"AARQ external", iecTLV(0x60, mp(0, []byte{7, 0x80}), ctx, mp(10, []byte{6, 0xc0}), mc(12, mc(2, iecTLV(0x02, []byte{1}), mc(0, []byte{5, 0}))), mc(13, names)),
			ACSEAuthExternal, bytes.Join([][]byte{iecTLV(0x02, []byte{1}), mc(0, []byte{5, 0})}, nil)},
		{"AARQ other", iecTLV(0x60, mp(0, []byte{7, 0x80}), ctx, mp(10, []byte{6, 0xc0}), mc(12, mc(3, names, []byte{5, 0})), mc(13, names)),
			ACSEAuthOther, append(append([]byte{}, names...), 5, 0)},
	}
	for _, tc := range tests {
		a := &ACSE{}
		if err := a.DecodeFromBytes(tc.apdu, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !a.HasProtocolVersion || a.ProtocolVersion != 0x80 || !a.HasRequirements ||
			a.Requirements != ACSERequireAuthentication|ACSERequireContextNegotiation ||
			a.AuthenticationKind != tc.kind || !bytes.Equal(a.AuthenticationValue, tc.value) ||
			!reflect.DeepEqual(a.ContextNames, []string{"1.0.9506.2.3"}) || a.ApplicationContext != "1.0.9506.2.3" {
			t.Errorf("%s: %+v", tc.name, a)
		}

		for i := range tc.apdu {
			_ = (&ACSE{}).DecodeFromBytes(tc.apdu[:i], gopacket.NilDecodeFeedback)
		}
	}

	// Malformed optional fields leave the APDU decoded and the fields unset.
	a := &ACSE{}
	apdu := iecTLV(0x60, mp(0, nil), ctx, mp(10, []byte{9}), mc(12, mp(7)), mc(13, []byte{0x04, 0x00}))
	if err := a.DecodeFromBytes(apdu, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if a.HasProtocolVersion || a.HasRequirements || a.AuthenticationKind != ACSEAuthNone || a.AuthenticationValue != nil ||
		a.ContextNames != nil || len(a.Authentication) != 2 {
		t.Errorf("malformed options: %+v", a)
	}
}

// osiMoreSeeds returns fuzz seeds for extended concatenation, the typed
// session parameters, x410 mode and the ACSE options.
func osiMoreSeeds() [][]byte {
	user := func(spdu ISOSessionSPDUType, ppdu []byte) []byte {
		return iecSPDU(byte(spdu), iecSPDU(byte(ISOSessionParamSessionUserReq), []byte{0x03, 0x49}),
			iecSPDU(byte(ISOSessionParamReasonCode), []byte{2}), iecSPDU(byte(ISOSessionParamUserData), ppdu))
	}
	gt := iecSPDU(byte(ISOSessionGiveTokens))
	mip := iecSPDU(byte(ISOSessionMinorSync), iecSPDU(byte(ISOSessionParamSerialNumber), []byte("42")))
	open := mc(3, mc(0, []byte{0x04, 0x01, 0xaa}))
	aarq := iecTLV(0x60, mp(0, []byte{7, 0x80}), mp(10, []byte{6, 0xc0}), mc(12, mp(0, []byte("secret"))),
		mc(13, iecTLV(0x06, []byte{0x28, 0xca, 0x22, 0x02, 0x03})))

	return [][]byte{
		bytes.Join([][]byte{gt, mip, iecSPDU(byte(ISOSessionDataTransfer)), iecUserData(3, mreq(mp(0, []byte{0})))}, nil),
		bytes.Join([][]byte{gt, mip, mip, mip}, nil),
		user(ISOSessionConnect, x410Open(mp(0, []byte{1}), mp(1, []byte{5}), mp(2, []byte{1}), open, mp(4, []byte{12}))),
		user(ISOSessionAccept, x410Open(mp(0, []byte{2}), mc(2, mc(1, []byte{0x30, 0x00})))),
		user(ISOSessionRefuse, iecTLV(0x31, mp(0, []byte{2}), mc(1, []byte{0x04, 0x00}))),
		user(ISOSessionAbort, iecTLV(0x31, mp(0, []byte{4}), mp(1, []byte{0, 0x80}), mc(2, []byte{0x04, 0x00}))),
		append(append(gt, iecSPDU(byte(ISOSessionDataTransfer))...), iecTLV(0x02, []byte{7})...),
		append(append(gt, iecSPDU(byte(ISOSessionDataTransfer))...), iecTLV(0x04, []byte{0xa0, 0x00})...),
		append(append(gt, iecSPDU(byte(ISOSessionDataTransfer))...), iecUserData(1, aarq)...),
	}
}

// osiReadParams calls every typed parameter accessor of the SPDUs.
func osiReadParams(s *ISOSession) {
	for i := range s.SPDUs {
		sp := &s.SPDUs[i]
		_, _ = sp.ProtocolOptions()
		_, _ = sp.Versions()
		_, _ = sp.Requirements()
		_, _ = sp.Enclosure()
		_, _ = sp.TransportDisconnect()
		_, _ = sp.TokenItem()
		_, _ = sp.TokenSetting()
		_, _ = sp.ReasonCode()
		_, _, _ = sp.MaxTSDUSize()
		_ = sp.CallingSelector()
		_ = sp.CalledSelector()
		_ = sp.SerialNumber()
	}
}

// TestOSIMoreTruncation cuts every seed at every offset: no panic, and
// no layer claims more than the input.
func TestOSIMoreTruncation(t *testing.T) {
	for i, seed := range osiMoreSeeds() {
		for cut := 0; cut <= len(seed); cut++ {
			p := iecSession(seed[:cut])
			for _, l := range p.Layers() {
				if len(l.LayerContents()) > cut {
					t.Fatalf("seed %d cut %d: %v contents longer than input", i, cut, l.LayerType())
				}
			}
			if s, ok := p.Layer(LayerTypeISOSession).(*ISOSession); ok {
				osiReadParams(s)
			}
		}
	}
}
