// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
)

// isoTruncFeedback records SetTruncated.
type isoTruncFeedback struct{ truncated bool }

func (f *isoTruncFeedback) SetTruncated() { f.truncated = true }

// isoSessionOf decodes a TSDU that must decode.
func isoSessionOf(t *testing.T, name string, tsdu []byte) (*ISOSession, bool) {
	t.Helper()
	s := &ISOSession{}
	df := &isoTruncFeedback{}
	if err := s.DecodeFromBytes(tsdu, df); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return s, df.truncated
}

// Frame 10 of iec61850_mms_libiec61850.pcap: an AC SPDU with LI 137 in a
// TSDU that has 136 octets left. ISO 8327-1 8.2 makes that invalid;
// tshark 4.7 dissects the parameters present and so do we, flagged.
//
//	0e 89             AC, LI 137
//	05 06 13 01 00    Connect/Accept Item: Protocol Options 0,
//	      06 01 02      PI 6 (undefined; a Version Number is 0x16)
//	14 02 00 02       Session User Requirements: duplex
//	c1 00             User Data, LI 0
//	31 78 ...         120 octets, read as a Reflect Parameter (PI 49);
//	                  they are the CPA PPDU the User Data should hold
func TestISOSessionLongAC(t *testing.T) {
	tsdus := iecTSDUsByFrame(t, "iec61850_mms_libiec61850.pcap")
	tsdu := tsdus[10][0]
	if len(tsdu) != 138 || tsdu[1] != 137 {
		t.Fatalf("frame 10: %d octets, LI %d", len(tsdu), tsdu[1])
	}

	s, truncated := isoSessionOf(t, "frame 10", tsdu)
	if s.Flaws != ISOSessionLengthOverrun || !truncated || s.Flaws.String() != "length-overrun" {
		t.Errorf("flaws %v, truncated %v", s.Flaws, truncated)
	}

	// tshark: Protocol Options 0x00, Session Requirement 0x0002, Session
	// user data of length 0.
	ac := s.SPDUs[0]
	opts, hasOpts := ac.ProtocolOptions()
	req, hasReq := ac.Requirements()
	user := ac.Param(ISOSessionParamUserData)
	switch {
	case len(s.SPDUs) != 1 || ac.Type != ISOSessionAccept || ac.Length != 137:
		t.Errorf("SPDU %v length %d", ac.Type, ac.Length)
	case !hasOpts || opts != 0 || !hasReq || req != ISOSessionFUDuplex:
		t.Errorf("options %v %v, requirements %v %v", opts, hasOpts, req, hasReq)
	case user == nil || len(user.Value) != 0 || len(s.Payload) != 0:
		t.Errorf("user data %+v, payload % x", user, s.Payload)
	case len(ac.Params) != 4 || ac.Params[3].ID != ISOSessionParamReflect || len(ac.Params[3].Value) != 120:
		t.Errorf("parameters %+v", ac.Params)
	case len(s.Contents) != len(tsdu):
		t.Errorf("contents %d octets", len(s.Contents))
	}

	// With the right LI nothing is flagged.
	fixed := append([]byte{tsdu[0], 136}, tsdu[2:]...)
	if s, truncated := isoSessionOf(t, "fixed", fixed); s.Flaws != 0 || truncated {
		t.Errorf("fixed LI: flaws %v, truncated %v", s.Flaws, truncated)
	}

	// The three wrong octets put right (LI, the Version Number PI and the
	// User Data LI), the TSDU is the association response tshark then
	// shows too.
	fixed[7], fixed[15] = byte(ISOSessionParamVersion), 122
	p := iecSession(fixed)
	if m, ok := p.Layer(LayerTypeMMS).(*MMS); !ok || m.Type != MMSInitiateResponse || p.Layer(LayerTypeACSE) == nil {
		t.Errorf("repaired AC: layers %v, error %v", p.Layers(), p.ErrorLayer())
	}

	// No presentation layer: the User Data is empty.
	if p := iecSession(tsdu); p.ErrorLayer() != nil || len(p.Layers()) != 1 {
		t.Errorf("packet layers %v, error %v", p.Layers(), p.ErrorLayer())
	}
}

func TestISOSessionOverrun(t *testing.T) {
	req := iecSPDU(byte(ISOSessionParamSessionUserReq), []byte{0, 2})
	ud := iecSPDU(byte(ISOSessionParamUserData), iecUserData(3, mreq(mp(0, []byte{0}))))

	ok := map[string][]byte{
		"one octet over":  append([]byte{byte(ISOSessionAccept), byte(len(req) + 1)}, req...),
		"far over":        append([]byte{byte(ISOSessionAccept), 0xfe}, req...),
		"long LI over":    append([]byte{byte(ISOSessionAccept), 0xff, 0xff, 0xff}, req...),
		"with user data":  append([]byte{byte(ISOSessionAccept), byte(len(req) + len(ud) + 9)}, append(req, ud...)...),
		"second SPDU":     append([]byte{1, 0, byte(ISOSessionAbort), 9}, iecSPDU(byte(ISOSessionParamTransportDisc), []byte{1})...),
		"PGI whole":       append([]byte{byte(ISOSessionConnect), 50}, iecSPDU(5, iecSPDU(19, []byte{0}))...),
		"lone DT overrun": append([]byte{1, 7}, req...),
	}
	for name, tsdu := range ok {
		s, truncated := isoSessionOf(t, name, tsdu)
		if s.Flaws != ISOSessionLengthOverrun || !truncated || len(s.Contents) != len(tsdu) {
			t.Errorf("%s: flaws %v, truncated %v, %d octets of contents", name, s.Flaws, truncated, len(s.Contents))
		}
	}

	// The user data of an overrun SPDU still goes up the stack.
	if p := iecSession(ok["with user data"]); p.Layer(LayerTypeMMS) == nil {
		t.Errorf("user data: layers %v, %v", p.Layers(), p.ErrorLayer())
	}

	// Cut inside a parameter, or without any, the TSDU is truncated.
	bad := map[string][]byte{
		"no parameter":      {byte(ISOSessionAccept), 5},
		"long LI, no param": {byte(ISOSessionAccept), 0xff, 0x01, 0x00},
		"half a PI header":  {byte(ISOSessionAccept), 5, 0x14},
		"PI value cut":      {byte(ISOSessionAccept), 5, 0x14, 0x02, 0x00},
		"PGI content cut":   {byte(ISOSessionConnect), 9, 0x05, 0x03, 0x13, 0x01},
		"PI in PGI cut":     {byte(ISOSessionConnect), 9, 0x05, 0x02, 0x13, 0x01},
	}
	for name, tsdu := range bad {
		s := &ISOSession{}
		df := &isoTruncFeedback{}
		if err := s.DecodeFromBytes(tsdu, df); err != errISOSessionTruncated || !df.truncated {
			t.Errorf("%s: %v, truncated %v", name, err, df.truncated)
		}
	}
}

// isoConcat builds GT, n minor sync points and what follows them.
func isoConcat(n int, tail ...[]byte) []byte {
	mip := iecSPDU(byte(ISOSessionMinorSync), iecSPDU(byte(ISOSessionParamSerialNumber), []byte("42")))
	out := iecSPDU(byte(ISOSessionGiveTokens))
	out = append(out, bytes.Repeat(mip, n)...)
	return append(out, bytes.Join(tail, nil)...)
}

func TestISOSessionConcatFlaws(t *testing.T) {
	dt := append(iecSPDU(byte(ISOSessionDataTransfer)), iecUserData(3, mreq(mp(0, []byte{0})))...)
	cutMIP := []byte{byte(ISOSessionMinorSync), 4, byte(ISOSessionParamSerialNumber), 9, '4'}

	tests := map[string]struct {
		tsdu  []byte
		spdus int
		flaws ISOSessionFlaws
		rest  int
	}{
		"8 SPDUs":            {isoConcat(7), 8, 0, 0},
		"7 and DT":           {isoConcat(6, dt), 8, 0, len(dt) - 2},
		"9 SPDUs":            {isoConcat(8), 8, ISOSessionTooManySPDUs, 6},
		"8 and DT":           {isoConcat(7, dt), 8, ISOSessionTooManySPDUs, len(dt)},
		"1000 SPDUs":         {isoConcat(999), 8, ISOSessionTooManySPDUs, 992 * 6},
		"malformed third":    {isoConcat(1, cutMIP), 2, ISOSessionBadConcat, len(cutMIP)},
		"malformed after DT": {isoConcat(1, dt, cutMIP), 3, 0, len(dt) - 2 + len(cutMIP)},
		"not an SPDU":        {isoConcat(1, []byte{0xee, 0x00}), 2, 0, 2},
		"overrun third":      {isoConcat(1, []byte{byte(ISOSessionMinorSync), 9, byte(ISOSessionParamSerialNumber), 1, '4'}), 3, ISOSessionLengthOverrun, 0},
	}
	for name, tc := range tests {
		s, _ := isoSessionOf(t, name, tc.tsdu)
		if len(s.SPDUs) != tc.spdus || s.Flaws != tc.flaws || len(tc.tsdu)-len(s.Contents) != tc.rest {
			t.Errorf("%s: %d SPDUs, flaws %v, %d octets left, want %d, %v, %d",
				name, len(s.SPDUs), s.Flaws, len(tc.tsdu)-len(s.Contents), tc.spdus, tc.flaws, tc.rest)
		}
	}

	// A malformed SPDU in second place stays an error.
	if err := (&ISOSession{}).DecodeFromBytes(append(iecSPDU(1), cutMIP...), gopacket.NilDecodeFeedback); err == nil {
		t.Error("malformed second SPDU decoded")
	}
}

func TestISOSessionFlawNames(t *testing.T) {
	tests := map[ISOSessionFlaws]string{
		0:                       "none",
		ISOSessionLengthOverrun: "length-overrun",
		ISOSessionBadConcat | ISOSessionTooManySPDUs: "bad-concatenation|too-many-spdus",
		ISOSessionLengthOverrun | 0x80:               "length-overrun|Unknown(0x80)",
		0x40:                                         "Unknown(0x40)",
	}
	for f, want := range tests {
		if got := f.String(); got != want {
			t.Errorf("%#x: %q, want %q", uint8(f), got, want)
		}
	}
}

// Every cut of the flawed TSDUs decodes or fails, and a TSDU of many
// SPDUs costs a bounded amount of memory.
func TestISOSessionFlawBounds(t *testing.T) {
	tsdus := iecTSDUsByFrame(t, "iec61850_mms_libiec61850.pcap")
	for _, tsdu := range [][]byte{tsdus[10][0], isoConcat(12), isoConcat(3, []byte{byte(ISOSessionMinorSync), 4, 42, 9})} {
		for i := range tsdu {
			iecSession(tsdu[:i])
		}
	}

	const maxPerByte = 2
	tsdu := isoConcat(100000)
	s := &ISOSession{}
	got := allocPerByte(len(tsdu), func() {
		_ = s.DecodeFromBytes(tsdu, gopacket.NilDecodeFeedback)
	})
	if got > maxPerByte || s.Flaws != ISOSessionTooManySPDUs {
		t.Errorf("%.2f bytes per input byte, flaws %v", got, s.Flaws)
	}
}
