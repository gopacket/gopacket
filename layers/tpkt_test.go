// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// TCP payloads from the S7 captures of github.com/automayt/ICS-pcap
// (S7/1-S7comm-VarService-Read-DB1DBD0).
var (
	s7TestCR       = s7Hex("0300001611e00000000100c1020100c2020302c00109")
	s7TestCC       = s7Hex("0300001611d00001143000c00109c1020100c2020302")
	s7TestSetupJob = s7Hex("0300001902f08032010000ffff00080000f0000004000403c0")
	s7TestSetupAck = s7Hex("0300001b02f08032030000ffff000800000000f0000004000401e0")
	s7TestEmptyDT  = s7Hex("0300000702f000")
	s7TestReadJob  = s7Hex("0300001f02f080320100000000000e00000401120a10020004000184000000")
	s7TestReadAck  = s7Hex("0300001d02f0803203000000000002000800000401ff04002000010002")
)

// s7NoRecover makes decode panics fail the test instead of turning into
// a DecodeFailure layer.
var s7NoRecover = gopacket.DecodeOptions{SkipDecodeRecovery: true}

// s7Feedback records SetTruncated calls.
type s7Feedback struct{ truncated bool }

func (f *s7Feedback) SetTruncated() { f.truncated = true }

// s7Hex decodes hex, ignoring spaces.
func s7Hex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func s7LayerTypes(p gopacket.Packet) []gopacket.LayerType {
	var types []gopacket.LayerType
	for _, l := range p.Layers() {
		types = append(types, l.LayerType())
	}
	return types
}

func TestTPKTCOTPConnect(t *testing.T) {
	p := gopacket.NewPacket(s7TestCR, LayerTypeTPKT, s7NoRecover)
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer().Error())
	}

	tpkt := p.Layer(LayerTypeTPKT).(*TPKT)
	if tpkt.Version != TPKTVersion || tpkt.Length != 22 {
		t.Errorf("TPKT = %+v", tpkt)
	}

	cr := p.Layer(LayerTypeCOTP).(*COTP)
	want := []COTPParameter{
		{COTPParamCallingTSAP, []byte{0x01, 0x00}},
		{COTPParamCalledTSAP, []byte{0x03, 0x02}},
		{COTPParamTPDUSize, []byte{0x09}},
	}
	if cr.Length != 17 || cr.Type != COTPTypeCR || cr.DstRef != 0 || cr.SrcRef != 1 || cr.Class != 0 {
		t.Errorf("CR fixed part = %+v", cr)
	}
	if !reflect.DeepEqual(cr.Parameters, want) {
		t.Errorf("CR parameters = %v, want %v", cr.Parameters, want)
	}
	if cr.TPDUSize() != 512 {
		t.Errorf("TPDU size = %d, want 512", cr.TPDUSize())
	}
	if cr.NextLayerType() != gopacket.LayerTypeZero {
		t.Errorf("CR next layer = %v", cr.NextLayerType())
	}

	cc := gopacket.NewPacket(s7TestCC, LayerTypeTPKT, s7NoRecover).Layer(LayerTypeCOTP).(*COTP)
	if cc.Type != COTPTypeCC || cc.DstRef != 1 || cc.SrcRef != 0x1430 {
		t.Errorf("CC = %+v", cc)
	}
	if tsap, ok := cc.Parameter(COTPParamCalledTSAP); !ok || !bytes.Equal(tsap, []byte{0x03, 0x02}) {
		t.Errorf("CC called TSAP = %x %v", tsap, ok)
	}
}

func TestCOTPTypes(t *testing.T) {
	cases := []struct {
		name string
		tpdu string
		want COTP
	}{
		{"DT class 0", "02f080", COTP{Length: 2, Type: COTPTypeDT, EOT: true}},
		{"DT class 0 segment", "02f005", COTP{Length: 2, Type: COTPTypeDT, TPDUNumber: 5}},
		{"DT normal", "04f0123481", COTP{Length: 4, Type: COTPTypeDT, DstRef: 0x1234, EOT: true, TPDUNumber: 1}},
		{"DR", "0680000100028a", COTP{Length: 6, Type: COTPTypeDR, DstRef: 1, SrcRef: 2, Reason: 0x8a}},
		{"DC", "05c000010002", COTP{Length: 5, Type: COTPTypeDC, DstRef: 1, SrcRef: 2}},
		{"AK", "0461000105", COTP{Length: 4, Type: COTPTypeAK, Credit: 1, DstRef: 1, TPDUNumber: 5}},
		{"ED", "0410000182", COTP{Length: 4, Type: COTPTypeED, DstRef: 1, EOT: true, TPDUNumber: 2}},
		{"ER", "0670000102c100", COTP{Length: 6, Type: COTPTypeER, DstRef: 1, Reason: 2,
			Parameters: []COTPParameter{{COTPParamCallingTSAP, []byte{}}}}},
		{"CR class 2", "06e2000000012a", COTP{Length: 6, Type: COTPTypeCR, Credit: 2, SrcRef: 1, Class: 2, Options: 0xa}},
	}

	for _, c := range cases {
		data := s7Hex(c.tpdu)
		var got COTP
		if err := got.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}

		got.BaseLayer = BaseLayer{}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

func TestCOTPErrors(t *testing.T) {
	cases := []struct {
		name string
		tpdu string
		want error
	}{
		{"empty", "", ErrCOTPTooShort},
		{"LI only", "02", ErrCOTPTooShort},
		{"LI past data", "06e00000", ErrCOTPTooShort},
		{"reserved LI", "ff" + strings.Repeat("00", 255), ErrCOTPBadLength},
		{"unknown type", "023080", ErrCOTPUnknownType},
		{"CR too short", "05e000000001", ErrCOTPBadLength},
		{"DT LI 3", "03f00080", ErrCOTPBadLength},
		{"param header cut", "07e000000001 00c1", ErrCOTPBadParameter},
		{"param overruns", "09e000000001 00c105ab", ErrCOTPBadParameter},
	}

	for _, c := range cases {
		data := s7Hex(c.tpdu)
		var got COTP
		err := got.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

// TestCOTPNextLayer checks how DT user data is routed: S7 PDUs by their
// first octets, everything else to the ISO session layer, segments to
// LayerTypeFragment.
func TestCOTPNextLayer(t *testing.T) {
	cases := []struct {
		name string
		tpdu string
		want gopacket.LayerType
	}{
		{"S7comm", "02f080" + "320100000000000000000000", LayerTypeS7Comm},
		{"S7comm-plus", "02f080" + "720100000000", LayerTypeS7CommPlus},
		{"0x32 with bad ROSCTR", "02f080" + "320900000000000000000000", LayerTypeISOSession},
		{"0x72 with bad version", "02f080" + "720900000000", LayerTypeISOSession},
		{"ISO session CONNECT", "02f080" + "0d1205060000", LayerTypeISOSession},
		{"DT segment", "02f000" + "3201000000", gopacket.LayerTypeFragment},
		{"empty DT", "02f080", gopacket.LayerTypeZero},
		{"ED data", "0410000180" + "aa", gopacket.LayerTypePayload},
	}

	for _, c := range cases {
		var cotp COTP
		if err := cotp.DecodeFromBytes(s7Hex(c.tpdu), gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := cotp.NextLayerType(); got != c.want {
			t.Errorf("%s: next layer = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTPKTErrors(t *testing.T) {
	cases := []struct {
		name      string
		data      string
		want      error
		truncated bool
	}{
		{"short header", "030000", ErrTPKTTooShort, true},
		{"bad version", "0400000702f080", ErrTPKTBadVersion, false},
		{"length below 7", "0300000602f0", ErrTPKTBadLength, false},
		{"length past data", "0300001002f080", ErrTPKTTooShort, true},
	}

	for _, c := range cases {
		var df s7Feedback
		var tpkt TPKT
		err := tpkt.DecodeFromBytes(s7Hex(c.data), &df)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if df.truncated != c.truncated {
			t.Errorf("%s: truncated = %v, want %v", c.name, df.truncated, c.truncated)
		}

		p := gopacket.NewPacket(s7Hex(c.data), LayerTypeTPKT, s7NoRecover)
		if p.ErrorLayer() == nil {
			t.Errorf("%s: packet has no error layer", c.name)
		}
	}
}

// TestTPKTSegment checks that every TPKT of a segment gets its stack,
// in eager and lazy packets alike, and that a trailing partial TPKT is
// an error after the complete ones.
func TestTPKTSegment(t *testing.T) {
	seg := bytes.Join([][]byte{s7TestSetupJob, s7TestEmptyDT, s7TestReadJob}, nil)
	want := []gopacket.LayerType{
		LayerTypeTPKT, LayerTypeCOTP, LayerTypeS7Comm,
		LayerTypeTPKT, LayerTypeCOTP,
		LayerTypeTPKT, LayerTypeCOTP, LayerTypeS7Comm,
	}

	for _, opt := range []gopacket.DecodeOptions{s7NoRecover, {Lazy: true, SkipDecodeRecovery: true}} {
		p := gopacket.NewPacket(seg, LayerTypeTPKT, opt)
		if got := s7LayerTypes(p); !reflect.DeepEqual(got, want) {
			t.Errorf("lazy=%v: layers = %v, want %v", opt.Lazy, got, want)
		}
		if p.ErrorLayer() != nil {
			t.Errorf("lazy=%v: %v", opt.Lazy, p.ErrorLayer().Error())
		}

		var fns []S7CommFunction
		for _, l := range p.Layers() {
			if s, ok := l.(*S7Comm); ok {
				fns = append(fns, s.Function)
			}
		}
		if !reflect.DeepEqual(fns, []S7CommFunction{S7CommFuncSetupComm, S7CommFuncReadVar}) {
			t.Errorf("lazy=%v: functions = %v", opt.Lazy, fns)
		}
	}

	partial := append(append([]byte{}, s7TestSetupJob...), s7TestReadJob[:10]...)
	p := gopacket.NewPacket(partial, LayerTypeTPKT, s7NoRecover)
	if p.ErrorLayer() == nil || !p.Metadata().Truncated {
		t.Errorf("partial trailing TPKT: error %v, truncated %v", p.ErrorLayer(), p.Metadata().Truncated)
	}
	if p.Layer(LayerTypeS7Comm) == nil {
		t.Error("partial trailing TPKT: first PDU not decoded")
	}
}

// TestTPKTDecodingLayerParser checks the DecodingLayer path, which
// decodes the first TPKT of a segment.
func TestTPKTDecodingLayerParser(t *testing.T) {
	var (
		tpkt TPKT
		cotp COTP
		s7   S7Comm
	)
	parser := gopacket.NewDecodingLayerParser(LayerTypeTPKT, &tpkt, &cotp, &s7)
	var decoded []gopacket.LayerType

	if err := parser.DecodeLayers(s7TestReadAck, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, []gopacket.LayerType{LayerTypeTPKT, LayerTypeCOTP, LayerTypeS7Comm}) {
		t.Errorf("decoded = %v", decoded)
	}
	if s7.ROSCTR != S7CommROSCTRAckData || len(s7.DataItems) != 1 {
		t.Errorf("S7comm = %+v", s7)
	}
}

func TestRegisterS7Decoders(t *testing.T) {
	registerS7Decoders()
	registerS7Decoders()
	if got := TCPPort(TCPPortTPKT).LayerType(); got != LayerTypeTPKT {
		t.Errorf("port 102 layer type = %v, want TPKT", got)
	}
}
