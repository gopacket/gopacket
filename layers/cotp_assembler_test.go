// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// cotpDTForm is a DT header layout of ISO 8073 13.7.
type cotpDTForm int

const (
	cotpDTClass0      cotpDTForm = iota // LI 2: EOT+NR
	cotpDTNormal                        // LI 4: DST-REF, EOT+NR
	cotpDTNormalCksum                   // LI 8: normal and checksum
	cotpDTExtended                      // LI 7: DST-REF, 4-octet EOT+NR
	cotpDTExtCksum                      // LI 11: extended and checksum
)

var cotpDTForms = []cotpDTForm{cotpDTClass0, cotpDTNormal, cotpDTNormalCksum, cotpDTExtended, cotpDTExtCksum}

// cotpEOTMode says whether a test DT ends its TSDU.
type cotpEOTMode int

const (
	cotpMore cotpEOTMode = iota
	cotpLast
)

// cotpTestDT builds a DT TPDU of the given form around user data.
func cotpTestDT(form cotpDTForm, nr uint32, eot cotpEOTMode, user []byte) []byte {
	const dstRef = 0x1234
	checksum := []byte{byte(COTPParamChecksum), 2, 0xAB, 0xCD}

	short := byte(nr & cotpNRMask)
	var long [4]byte
	binary.BigEndian.PutUint32(long[:], nr&cotpExtNRMask)
	if eot == cotpLast {
		short |= cotpEOTMask
		long[0] |= cotpEOTMask
	}

	h := []byte{0, byte(COTPTypeDT)}
	if form != cotpDTClass0 {
		h = binary.BigEndian.AppendUint16(h, dstRef)
	}
	switch form {
	case cotpDTClass0, cotpDTNormal:
		h = append(h, short)
	case cotpDTNormalCksum:
		h = append(append(h, short), checksum...)
	case cotpDTExtended:
		h = append(h, long[:]...)
	case cotpDTExtCksum:
		h = append(append(h, long[:]...), checksum...)
	}
	h[0] = byte(len(h) - 1)
	return append(h, user...)
}

// cotpDecode decodes a TPDU or fails the test.
func cotpDecode(t *testing.T, tpdu []byte) *COTP {
	t.Helper()
	c := &COTP{}
	if err := c.DecodeFromBytes(tpdu, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("COTP % x: %v", tpdu, err)
	}
	return c
}

// TestCOTPDTForms decodes every DT header layout, extended format
// included, to the same EOT, number and user data.
func TestCOTPDTForms(t *testing.T) {
	user := []byte{0x32, 0x01, 0x02}
	for _, form := range cotpDTForms {
		for _, eot := range []cotpEOTMode{cotpMore, cotpLast} {
			c := cotpDecode(t, cotpTestDT(form, 0x12345, eot, user))
			ext := form == cotpDTExtended || form == cotpDTExtCksum
			if c.Type != COTPTypeDT || c.EOT != (eot == cotpLast) || !bytes.Equal(c.Payload, user) || c.Extended != ext {
				t.Errorf("form %d eot %d: %+v", form, eot, c)
			}

			wantRef := uint16(0x1234)
			if form == cotpDTClass0 {
				wantRef = 0
			}
			if c.DstRef != wantRef || c.TPDUNumber != 0x45 {
				t.Errorf("form %d: DstRef %#x NR %#x", form, c.DstRef, c.TPDUNumber)
			}
			if ext && c.ExtTPDUNumber != 0x12345 {
				t.Errorf("form %d: extended NR %#x", form, c.ExtTPDUNumber)
			}

			_, hasSum := c.Parameter(COTPParamChecksum)
			if hasSum != (form == cotpDTNormalCksum || form == cotpDTExtCksum) {
				t.Errorf("form %d: checksum parameter %v, params %v", form, hasSum, c.Parameters)
			}
		}
	}
}

// cotpSegments cuts a TSDU at the given offsets into DT TPDUs.
func cotpSegments(form cotpDTForm, tsdu []byte, cuts ...int) [][]byte {
	var out [][]byte
	start := 0
	for i, end := range append(cuts, len(tsdu)) {
		eot := cotpMore
		if i == len(cuts) {
			eot = cotpLast
		}
		out = append(out, cotpTestDT(form, uint32(i), eot, tsdu[start:end]))
		start = end
	}
	return out
}

// cotpFeedAll feeds TPDUs and returns the one TSDU they must complete,
// on the last TPDU only.
func cotpFeedAll(t *testing.T, a *COTPAssembler, tpdus [][]byte) ([]byte, gopacket.LayerType) {
	t.Helper()
	for i, tpdu := range tpdus {
		tsdu, next, err := a.Feed(cotpDecode(t, tpdu))
		if err != nil {
			t.Fatalf("TPDU %d: %v", i, err)
		}
		if i == len(tpdus)-1 {
			return tsdu, next
		}
		if tsdu != nil || next != gopacket.LayerTypeZero {
			t.Fatalf("TPDU %d completed a TSDU early", i)
		}
	}
	return nil, gopacket.LayerTypeZero
}

func TestCOTPAssemblerEveryOffset(t *testing.T) {
	// User data of the three upper layers COTP routes to.
	s7 := s7TestReadJob[7:]
	plus := s7Hex("7201000831000004ca0000000272010000")
	session := s7Hex("0100010061093007020103a0020500")
	tsdus := []struct {
		data []byte
		next gopacket.LayerType
	}{
		{s7, LayerTypeS7Comm},
		{plus, LayerTypeS7CommPlus},
		{session, LayerTypeISOSession},
	}

	for _, form := range cotpDTForms {
		for _, tc := range tsdus {
			for cut := 0; cut <= len(tc.data); cut++ {
				var a COTPAssembler
				got, next := cotpFeedAll(t, &a, cotpSegments(form, tc.data, cut))
				if !bytes.Equal(got, tc.data) || next != tc.next {
					t.Fatalf("form %d cut %d: next %v, TSDU % x", form, cut, next, got)
				}
				if a.Pending() != 0 {
					t.Fatalf("form %d cut %d: %d octets pending after EOT", form, cut, a.Pending())
				}
			}
		}
	}

	// One octet per TPDU.
	var cuts []int
	for i := 1; i < len(s7); i++ {
		cuts = append(cuts, i)
	}
	var a COTPAssembler
	got, next := cotpFeedAll(t, &a, cotpSegments(cotpDTClass0, s7, cuts...))
	if !bytes.Equal(got, s7) || next != LayerTypeS7Comm {
		t.Errorf("octet-wise: next %v, TSDU % x", next, got)
	}
}

// TestCOTPAssemblerSingle checks a TSDU in one DT is returned without
// a copy, routed as COTP routes it.
func TestCOTPAssemblerSingle(t *testing.T) {
	var a COTPAssembler
	for _, v := range [][]byte{s7TestSetupJob, s7TestReadAck, s7TestEmptyDT} {
		c := cotpDecode(t, v[tpktHeaderLen:])
		tsdu, next, err := a.Feed(c)
		if err != nil || next != c.NextLayerType() || !bytes.Equal(tsdu, c.Payload) {
			t.Errorf("% x: next %v (COTP %v), err %v", v, next, c.NextLayerType(), err)
		}
		if len(tsdu) > 0 && &tsdu[0] != &c.Payload[0] {
			t.Errorf("% x: single DT was copied", v)
		}
	}

	if tsdu, next, err := a.Feed(nil); tsdu != nil || next != gopacket.LayerTypeZero || err != nil {
		t.Errorf("nil TPDU: %v %v %v", tsdu, next, err)
	}
}

func TestCOTPAssemblerCap(t *testing.T) {
	a := COTPAssembler{MaxSize: 8}
	feed := func(eot cotpEOTMode, user string) ([]byte, error) {
		tsdu, _, err := a.Feed(cotpDecode(t, cotpTestDT(cotpDTClass0, 0, eot, []byte(user))))
		return tsdu, err
	}

	// 5 + 4 octets pass the cap: reported once, the rest of the TSDU is
	// skipped up to its EOT.
	if _, err := feed(cotpMore, "abcde"); err != nil {
		t.Fatal(err)
	}
	if _, err := feed(cotpMore, "fghi"); !errors.Is(err, ErrCOTPTSDUTooLong) {
		t.Fatalf("over cap: %v", err)
	}
	if a.Pending() != 0 {
		t.Errorf("%d octets held after overflow", a.Pending())
	}
	for _, eot := range []cotpEOTMode{cotpMore, cotpLast} {
		if tsdu, err := feed(eot, "jk"); tsdu != nil || err != nil {
			t.Errorf("skipped segment: % x, %v", tsdu, err)
		}
	}

	// The next TSDU is whole again, at exactly the cap.
	if _, err := feed(cotpMore, "1234"); err != nil {
		t.Fatal(err)
	}
	if tsdu, err := feed(cotpLast, "5678"); string(tsdu) != "12345678" || err != nil {
		t.Errorf("TSDU after overflow: %q, %v", tsdu, err)
	}

	// A single DT above the cap, and an overflow on the EOT segment,
	// leave nothing to skip.
	if _, err := feed(cotpLast, "123456789"); !errors.Is(err, ErrCOTPTSDUTooLong) {
		t.Errorf("single DT over cap: %v", err)
	}
	if tsdu, err := feed(cotpLast, "ok"); string(tsdu) != "ok" || err != nil {
		t.Errorf("after single overflow: %q, %v", tsdu, err)
	}
}

func TestCOTPAssemblerDefaultCap(t *testing.T) {
	var a COTPAssembler
	seg := make([]byte, 1<<16)
	var err error
	fed := 0
	for err == nil && fed <= 2*COTPDefaultMaxTSDU {
		_, _, err = a.Feed(&COTP{Type: COTPTypeDT, BaseLayer: BaseLayer{Payload: seg}})
		fed += len(seg)

		if a.Pending() > COTPDefaultMaxTSDU {
			t.Fatalf("%d octets held, above the default cap", a.Pending())
		}
	}
	if !errors.Is(err, ErrCOTPTSDUTooLong) || fed != COTPDefaultMaxTSDU+len(seg) {
		t.Errorf("default cap: err %v after %d octets", err, fed)
	}
}

func TestCOTPAssemblerInterleaved(t *testing.T) {
	tsdu := s7TestReadJob[7:]
	segs := cotpSegments(cotpDTNormal, tsdu, 5, 11)
	others := [][]byte{
		s7Hex("0461123405"),     // AK
		s7Hex("041012348299"),   // ED with user data
		s7Hex("0420123405"),     // EA
		s7Hex("0450123405"),     // RJ
		s7Hex("0670123402c100"), // ER
	}

	// Non-DT TPDUs between segments leave the TSDU alone.
	var a COTPAssembler
	var tpdus [][]byte
	for _, seg := range segs {
		tpdus = append(tpdus, others...)
		tpdus = append(tpdus, seg)
	}
	if got, next := cotpFeedAll(t, &a, tpdus); !bytes.Equal(got, tsdu) || next != LayerTypeS7Comm {
		t.Errorf("interleaved: next %v, TSDU % x", next, got)
	}

	// Connection set-up and release drop a half-joined TSDU.
	for _, reset := range [][]byte{
		s7TestCR[tpktHeaderLen:], s7TestCC[tpktHeaderLen:],
		s7Hex("0680000100028a"), s7Hex("05c000010002"),
	} {
		var a COTPAssembler
		got, _ := cotpFeedAll(t, &a, [][]byte{segs[0], reset, cotpTestDT(cotpDTNormal, 0, cotpLast, tsdu)})
		if !bytes.Equal(got, tsdu) {
			t.Errorf("after % x: TSDU % x", reset, got)
		}
	}

	// So does Reset.
	a = COTPAssembler{}
	cotpFeedAll(t, &a, [][]byte{segs[0], segs[1]})
	if a.Pending() == 0 {
		t.Fatal("nothing pending")
	}
	a.Reset()
	if got, _ := cotpFeedAll(t, &a, [][]byte{segs[2]}); a.Pending() != 0 || !bytes.Equal(got, tsdu[11:]) {
		t.Errorf("after Reset: % x", got)
	}
}

// TestCOTPAssemblerOwnership checks a joined TSDU is not overwritten
// by the TSDUs joined after it.
func TestCOTPAssemblerOwnership(t *testing.T) {
	var a COTPAssembler
	first, _ := cotpFeedAll(t, &a, cotpSegments(cotpDTClass0, []byte("first TSDU"), 3))
	second, _ := cotpFeedAll(t, &a, cotpSegments(cotpDTClass0, []byte("other data"), 6))
	if string(first) != "first TSDU" || string(second) != "other data" {
		t.Errorf("TSDUs %q, %q", first, second)
	}
}

// cotpStreams returns the TCP payload of each direction of a capture
// holding one in-order connection, keyed by source port.
func cotpStreams(t *testing.T, name string) map[TCPPort][]byte {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	r, err := newSimplePcapReader(f)
	if err != nil {
		t.Fatal(err)
	}

	streams := map[TCPPort][]byte{}
	next := map[TCPPort]uint32{}
	for {
		data, err := r.readPacketData()
		if err == io.EOF {
			return streams
		}
		if err != nil {
			t.Fatal(err)
		}

		tcp, _ := gopacket.NewPacket(data, r.linkType, gopacket.Default).Layer(LayerTypeTCP).(*TCP)
		if tcp == nil || len(tcp.Payload) == 0 {
			continue
		}
		if want, ok := next[tcp.SrcPort]; ok && want != tcp.Seq {
			t.Fatalf("%s: port %d sequence %d, want %d", name, tcp.SrcPort, tcp.Seq, want)
		}
		next[tcp.SrcPort] = tcp.Seq + uint32(len(tcp.Payload))
		streams[tcp.SrcPort] = append(streams[tcp.SrcPort], tcp.Payload...)
	}
}

// cotpCountLayers splits a stream into TPKTs, joins their DT segments
// and counts the layers of every TSDU.
func cotpCountLayers(t *testing.T, stream []byte, counts map[gopacket.LayerType]int) {
	t.Helper()
	var a COTPAssembler
	sc := bufio.NewScanner(bytes.NewReader(stream))
	sc.Split(ScanTPKT)
	for sc.Scan() {
		var tpkt TPKT
		var c COTP
		if err := tpkt.DecodeFromBytes(sc.Bytes(), gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		if err := c.DecodeFromBytes(tpkt.Payload, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		counts[LayerTypeTPKT]++
		counts[LayerTypeCOTP]++

		tsdu, next, err := a.Feed(&c)
		if err != nil {
			t.Fatal(err)
		}
		if next == gopacket.LayerTypeZero {
			continue
		}

		p := gopacket.NewPacket(tsdu, next, s7NoRecover)
		if e := p.ErrorLayer(); e != nil {
			t.Errorf("TSDU of %d octets: %v", len(tsdu), e.Error())
		}
		for _, l := range p.Layers() {
			counts[l.LayerType()]++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if a.Pending() != 0 {
		t.Errorf("%d octets of an unfinished TSDU", a.Pending())
	}
}

// TestCOTPAssemblerPcap joins the segmented MMS responses of a Siemens
// relay. tshark 4.7 decodes 134 MMS PDUs in 174 TPKTs
// (-T pdml, <proto name="mms"> and "tpkt").
func TestCOTPAssemblerPcap(t *testing.T) {
	counts := map[gopacket.LayerType]int{}
	for _, stream := range cotpStreams(t, "iec61850_mms_siemens.pcap") {
		cotpCountLayers(t, stream, counts)
	}

	want := map[gopacket.LayerType]int{LayerTypeTPKT: 174, LayerTypeCOTP: 174, LayerTypeMMS: 134}
	for lt, n := range want {
		if counts[lt] != n {
			t.Errorf("%v: %d, want %d (all: %v)", lt, counts[lt], n, counts)
		}
	}
}

// FuzzCOTPAssembler feeds length-prefixed TPDUs cut from the input to
// an assembler with a small cap.
func FuzzCOTPAssembler(f *testing.F) {
	join := func(tpdus ...[]byte) []byte {
		var b []byte
		for _, tpdu := range tpdus {
			b = append(append(b, byte(len(tpdu))), tpdu...)
		}
		return b
	}
	f.Add(join(cotpSegments(cotpDTClass0, s7TestReadJob[7:], 4, 9)...))
	f.Add(join(cotpSegments(cotpDTExtCksum, s7TestReadJob[7:], 1)...))
	f.Add(join(s7TestCR[4:], cotpTestDT(cotpDTNormal, 1, cotpMore, []byte("abc")), s7Hex("0461123405")))
	f.Add(join(cotpTestDT(cotpDTClass0, 0, cotpMore, bytes.Repeat([]byte{1}, 200)), cotpTestDT(cotpDTClass0, 0, cotpLast, nil)))

	f.Fuzz(func(t *testing.T, data []byte) {
		const maxSize = 64
		a := COTPAssembler{MaxSize: maxSize}
		var joined [][]byte
		var copies [][]byte
		for len(data) > 0 {
			n := int(data[0])
			data = data[1:]
			if n > len(data) {
				n = len(data)
			}
			tpdu := data[:n]
			data = data[n:]

			var c COTP
			if c.DecodeFromBytes(tpdu, gopacket.NilDecodeFeedback) != nil {
				continue
			}
			tsdu, next, err := a.Feed(&c)
			if len(tsdu) > maxSize || a.Pending() > maxSize {
				t.Fatalf("TSDU %d, pending %d above cap %d", len(tsdu), a.Pending(), maxSize)
			}
			if err != nil && (tsdu != nil || next != gopacket.LayerTypeZero) {
				t.Fatalf("error %v with a TSDU", err)
			}
			if (next == gopacket.LayerTypeZero) != (len(tsdu) == 0) {
				t.Fatalf("next %v for %d octets", next, len(tsdu))
			}
			joined = append(joined, tsdu)
			copies = append(copies, bytes.Clone(tsdu))
		}

		// Earlier TSDUs must survive later feeds.
		if !reflect.DeepEqual(joined, copies) {
			t.Fatal("a returned TSDU was overwritten")
		}
	})
}
