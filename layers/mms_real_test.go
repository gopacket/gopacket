// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"math"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// MMS Data real [8] is the ASN.1 REAL of ISO 9506-2:1990. No capture
// holds one, so the vectors are hand built from X.690 8.5 and checked
// against tshark 4.7 (mms.real) in read responses sent on an association.
// It shows the same value for all but two kinds:
//
//	"-1,5"      tshark stops at the comma ISO 6093 allows and shows -1
//	overflow    tshark adds a "REAL overflow" expert note to the same
//	            infinity or zero

// mmsRealVector is a REAL contents encoding and its value.
type mmsRealVector struct {
	name string
	raw  []byte
	want float64
}

func mmsRealVectors() []mmsRealVector {
	return []mmsRealVector{
		{"zero", nil, 0},
		{"binary 5 * 2^-5", []byte{0x80, 0xfb, 0x05}, 0.15625},
		{"binary negative", []byte{0xc0, 0x00, 0x03}, -3},
		{"binary 1 * 2^10", []byte{0x80, 0x0a, 0x01}, 1024},
		{"two exponent octets", []byte{0x81, 0x01, 0x00, 0x01}, math.Ldexp(1, 256)},
		{"three exponent octets", []byte{0x82, 0xff, 0xff, 0xff, 0x04}, 2},
		{"exponent length octet", []byte{0x83, 0x02, 0x00, 0x03, 0x01}, 8},
		{"base 8", []byte{0x90, 0x02, 0x01}, 64},
		{"base 16", []byte{0xa0, 0x02, 0x01}, 256},
		{"scale factor 3", []byte{0x8c, 0x00, 0x01}, 8},
		{"float64 pi", []byte{0x80, 0xcd, 0x19, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18}, math.Pi},
		{"exponent past float64", []byte{0x81, 0x7f, 0xff, 0x01}, math.Inf(1)},
		{"exponent below float64", []byte{0x81, 0x80, 0x00, 0x01}, 0},
		{"decimal NR1", []byte("\x01 42"), 42},
		{"decimal NR2", []byte("\x021.5"), 1.5},
		{"decimal NR2 comma", []byte("\x02-1,5"), -1.5},
		{"decimal NR3", []byte("\x0315.E-1"), 1.5},
		{"decimal out of range", []byte("\x031E999"), math.Inf(1)},
		{"plus infinity", []byte{0x40}, math.Inf(1)},
		{"minus infinity", []byte{0x41}, math.Inf(-1)},
	}
}

func TestOSIBERReal(t *testing.T) {
	for _, tc := range mmsRealVectors() {
		got, err := osiBERReal(tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v, want %v", tc.name, got, err, tc.want)
		}
	}

	if got, err := osiBERReal([]byte{0x42}); err != nil || !math.IsNaN(got) {
		t.Errorf("NaN: %v, %v", got, err)
	}
	if got, err := osiBERReal([]byte{0x43}); err != nil || got != 0 || !math.Signbit(got) {
		t.Errorf("minus zero: %v, %v", got, err)
	}

	bad := map[string][]byte{
		"binary without exponent":  {0x80},
		"binary without mantissa":  {0x80, 0x01},
		"reserved base":            {0xb0, 0x00, 0x01},
		"exponent count missing":   {0x83},
		"exponent count zero":      {0x83, 0x00, 0x01},
		"exponent count too long":  {0x83, 0x05, 0, 0, 0, 0, 1, 1},
		"exponent count overrun":   {0x83, 0x04, 0x00, 0x01},
		"special with content":     {0x40, 0x00},
		"reserved special":         {0x44},
		"decimal form 0":           []byte("\x001"),
		"decimal form 4":           []byte("\x041"),
		"decimal empty":            {0x01},
		"decimal letters":          []byte("\x02abc"),
		"decimal hex float":        []byte("\x030x1p4"),
		"decimal infinity keyword": []byte("\x03inf"),
		"decimal underscore":       []byte("\x011_0"),
	}
	for name, raw := range bad {
		if got, err := osiBERReal(raw); err != errOSIBERReal {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
}

// A real decodes in GOOSE allData and in an MMS read response alike.
func TestMMSDataReal(t *testing.T) {
	for _, tc := range mmsRealVectors() {
		d, err := decodeMMSData(osiBERTLV{Class: osiBERContext, Form: osiBERPrimitive, Tag: 8, Value: tc.raw}, 0)
		if err != nil || d.Type != MMSDataReal || d.Float != tc.want || !bytes.Equal(d.Raw, tc.raw) {
			t.Errorf("%s: %+v, %v", tc.name, d, err)
		}
	}
	if got := MMSDataReal.String(); got != "real" {
		t.Errorf("name %q", got)
	}

	real := mp(8, []byte{0x80, 0xfb, 0x05})
	m := &MMS{}
	if err := m.DecodeFromBytes(mresp(mc(4, mc(1, real))), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if r := m.ReadResp.Results; len(r) != 1 || r[0].Data.Type != MMSDataReal || r[0].Data.Float != 0.15625 {
		t.Errorf("read response %+v", r)
	}

	// Nested in a structure of a GOOSE message.
	g := mmsGOOSEWith(t, iecTLV(0xa2, real, iecTLV(0x87, []byte{0x08, 0x3f, 0xc0, 0, 0})))
	if s := g.AllData[0]; len(s.Items) != 2 || s.Items[0].Float != 0.15625 || s.Items[1].Float != 1.5 {
		t.Errorf("GOOSE structure %+v", s)
	}

	// A constructed real and a malformed one fail as other Data does.
	for name, data := range map[string][]byte{"constructed": mc(8), "malformed": mp(8, []byte{0x80})} {
		if err := m.DecodeFromBytes(mresp(mc(4, mc(1, data))), gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// mmsGOOSEWith decodes a goosePdu whose allData is data.
func mmsGOOSEWith(t *testing.T, data []byte) *GOOSE {
	t.Helper()
	pdu := iecTLV(0x61,
		iecTLV(0x80, []byte("gcb")), iecTLV(0x81, []byte{1}), iecTLV(0x82, []byte("ds")),
		iecTLV(0x84, make([]byte, 8)), iecTLV(0x85, []byte{1}), iecTLV(0x86, []byte{1}),
		iecTLV(0x88, []byte{1}), iecTLV(0x8a, []byte{1}), iecTLV(0xab, data))

	p := iecDecode(iecFrame(EthernetTypeGOOSE, 1, pdu))
	g, ok := p.Layer(LayerTypeGOOSE).(*GOOSE)
	if !ok {
		t.Fatal("no GOOSE layer:", p.ErrorLayer())
	}
	return g
}

func TestMMSGeneralizedTime(t *testing.T) {
	plus1 := time.FixedZone("", 3600)
	tests := map[string]time.Time{
		"20260102030405Z":       time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		"20260102030405.5Z":     time.Date(2026, 1, 2, 3, 4, 5, 5e8, time.UTC),
		"20260102030405,25Z":    time.Date(2026, 1, 2, 3, 4, 5, 25e7, time.UTC),
		"20260102030405+0100":   time.Date(2026, 1, 2, 3, 4, 5, 0, plus1),
		"20260102030405":        time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		"20260102030405.125":    time.Date(2026, 1, 2, 3, 4, 5, 125e6, time.UTC),
		"202601020304Z":         time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC),
		"202601020304+0100":     time.Date(2026, 1, 2, 3, 4, 0, 0, plus1),
		"2026010203Z":           time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC),
		"2026010203":            time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC),
		"19991231235959.999Z":   time.Date(1999, 12, 31, 23, 59, 59, 999e6, time.UTC),
		"20260102030405-0530":   time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("", -19800)),
		"20260102030405.5-0530": time.Date(2026, 1, 2, 3, 4, 5, 5e8, time.FixedZone("", -19800)),
	}
	for text, want := range tests {
		d := mmsGOOSEWith(t, iecTLV(0x8b, []byte(text))).AllData[0]
		got, ok := d.GeneralizedTime()
		if !ok || !got.Equal(want) || d.String != text {
			t.Errorf("%q: %v, %v, want %v", text, got, ok, want)
		}
	}

	for _, text := range []string{"", "2026", "20261302030405Z", "20260102030405Q", "2026-01-02T03:04:05Z", "20260102250000Z"} {
		d := MMSData{Type: MMSDataGeneralizedTime, String: text}
		if got, ok := d.GeneralizedTime(); ok {
			t.Errorf("%q: parsed as %v", text, got)
		}
	}

	// Only a generalized-time has one.
	other := MMSData{Type: MMSDataVisibleString, String: "20260102030405Z"}
	if _, ok := other.GeneralizedTime(); ok {
		t.Error("visible-string parsed as a time")
	}
}

func TestMMSDataAccessors(t *testing.T) {
	g := mmsGOOSEWith(t, bytes.Join([][]byte{
		iecTLV(0x89, []byte{0xde, 0xad}),
		iecTLV(0x8d, []byte{0x12}),
		iecTLV(0x8d, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}),
		iecTLV(0x85, []byte{0x12}),
	}, nil))
	d := g.AllData

	if !bytes.Equal(d[0].Octets(), []byte{0xde, 0xad}) || d[1].Octets() != nil {
		t.Errorf("octets %x %x", d[0].Octets(), d[1].Octets())
	}
	if n, ok := d[1].BCD(); !ok || n != 18 {
		t.Errorf("bcd %d %v", n, ok)
	}
	if _, ok := d[2].BCD(); ok {
		t.Error("9 octet bcd fits an int64")
	}
	if _, ok := d[3].BCD(); ok {
		t.Error("integer read as bcd")
	}
}

// Every Data alternative of ISO 9506-2 has a name and decodes.
func TestMMSDataEveryType(t *testing.T) {
	values := map[MMSDataType][]byte{
		MMSDataArray: mc(1, mp(3, []byte{1})), MMSDataStructure: mc(2, mp(3, []byte{1})),
		MMSDataBoolean: mp(3, []byte{1}), MMSDataBitString: mp(4, []byte{0, 0x80}),
		MMSDataInteger: mp(5, []byte{1}), MMSDataUnsigned: mp(6, []byte{1}),
		MMSDataFloatingPoint: mp(7, []byte{8, 0, 0, 0, 0}), MMSDataReal: mp(8, []byte{0x80, 0, 1}),
		MMSDataOctetString: mp(9, []byte{1}), MMSDataVisibleString: mp(10, []byte("a")),
		MMSDataGeneralizedTime: mp(11, []byte("2026010203Z")), MMSDataBinaryTime: mp(12, []byte{0, 0, 0, 1}),
		MMSDataBCD: mp(13, []byte{1}), MMSDataBooleanArray: mp(14, []byte{0, 0x80}),
		MMSDataObjID: mp(15, []byte{0x28}), MMSDataMMSString: mp(16, []byte("a")),
		MMSDataUTCTime: mp(17, make([]byte, 8)),
	}

	for tag := MMSDataArray; tag <= MMSDataUTCTime; tag++ {
		raw, ok := values[tag]
		if !ok {
			t.Errorf("tag %d: no vector", tag)
			continue
		}

		g := mmsGOOSEWith(t, raw)
		if d := g.AllData[0]; d.Type != tag || bytes.HasPrefix([]byte(tag.String()), []byte("Unknown")) {
			t.Errorf("tag %d: decoded as %v", tag, d.Type)
		}
	}

	// Tags around the CHOICE stay errors.
	for _, raw := range [][]byte{mp(0, []byte{1}), mp(18, []byte{1}), iecTLV(0x05)} {
		p := iecDecode(iecFrame(EthernetTypeGOOSE, 1, iecTLV(0x61,
			iecTLV(0x80, []byte("g")), iecTLV(0x81, []byte{1}), iecTLV(0x82, []byte("d")),
			iecTLV(0x84, make([]byte, 8)), iecTLV(0x85, []byte{1}), iecTLV(0x86, []byte{1}),
			iecTLV(0x88, []byte{1}), iecTLV(0x8a, []byte{1}), iecTLV(0xab, raw))))
		if p.ErrorLayer() == nil {
			t.Errorf("data % x decoded", raw)
		}
	}
}

// mmsNullServices are the confirmed services whose response is NULL.
var mmsNullServices = []MMSConfirmedService{
	MMSRename, MMSDefineNamedVariable, MMSDefineScatteredAccess, MMSDefineNamedVariableList, MMSDefineNamedType,
	MMSOutput, MMSRelinquishControl, MMSDefineSemaphore, MMSDeleteSemaphore,
	MMSInitiateDownloadSequence, MMSTerminateDownloadSequence, MMSTerminateUploadSequence,
	MMSRequestDomainDownload, MMSRequestDomainUpload, MMSLoadDomainContent, MMSStoreDomainContent, MMSDeleteDomain,
	MMSCreateProgramInvocation, MMSDeleteProgramInvocation, MMSStart, MMSStop, MMSResume, MMSReset, MMSKill,
	MMSObtainFile, MMSFileClose, MMSFileRename, MMSFileDelete,
	MMSDefineEventCondition, MMSAlterEventConditionMonitoring, MMSTriggerEvent, MMSDefineEventAction,
	MMSDefineEventEnrollment, MMSAcknowledgeEventNotification,
	MMSWriteJournal, MMSCreateJournal, MMSDeleteJournal,
	MMSDefineAccessControlList, MMSDeleteAccessControlList,
}

// A NULL response with content, or constructed, still decodes: only
// ServiceDecodeErr tells.
func TestMMSNullResponses(t *testing.T) {
	for _, s := range mmsNullServices {
		m := &MMS{}
		if err := m.DecodeFromBytes(mresp(mp(int(s))), gopacket.NilDecodeFeedback); err != nil || m.ServiceDecodeErr != nil || m.Service != s {
			t.Errorf("%v: %v, soft %v", s, err, m.ServiceDecodeErr)
		}

		if err := m.DecodeFromBytes(mresp(mp(int(s), []byte{0})), gopacket.NilDecodeFeedback); err != nil || m.ServiceDecodeErr == nil || m.Service != s {
			t.Errorf("%v with content: %v, soft %v", s, err, m.ServiceDecodeErr)
		}
		if !bytes.Equal(m.ServiceData, []byte{0}) {
			t.Errorf("%v with content: service data % x", s, m.ServiceData)
		}
	}

	for _, s := range mmsNullServices {
		m := &MMS{}
		if err := m.DecodeFromBytes(mresp(mc(int(s))), gopacket.NilDecodeFeedback); err != nil || m.ServiceDecodeErr == nil {
			t.Errorf("%v constructed: %v, soft %v", s, err, m.ServiceDecodeErr)
		}
	}
}

func TestMMSRealTruncation(t *testing.T) {
	pdu := mresp(mc(4, mc(1, mp(8, []byte{0x83, 0x02, 0x00, 0x03, 0x01}), mp(11, []byte("20260102030405Z")))))
	for i := range pdu {
		m := &MMS{}
		if err := m.DecodeFromBytes(pdu[:i], gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("cut at %d: decoded", i)
		}
	}

	// Every cut of a REAL value is an error or a number, never a panic.
	for _, tc := range mmsRealVectors() {
		for i := range tc.raw {
			_, _ = osiBERReal(tc.raw[:i])
		}
	}
}

// A long mantissa or decimal string costs no memory beyond its length.
func TestMMSRealAllocBound(t *testing.T) {
	const size = 60000
	const maxPerByte = 4

	tests := map[string][]byte{
		"mantissa": append([]byte{0x80, 0x00}, bytes.Repeat([]byte{0xff}, size)...),
		"decimal":  append([]byte{0x01}, bytes.Repeat([]byte{'9'}, size)...),
		"spaces":   append([]byte{0x01}, bytes.Repeat([]byte{' '}, size)...),
	}
	for name, raw := range tests {
		pdu := mresp(mc(4, mc(1, mp(8, raw))))
		m := &MMS{}
		got := allocPerByte(len(pdu), func() {
			_ = m.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback)
		})
		t.Logf("%s: %.1f bytes per input byte", name, got)
		if got > maxPerByte {
			t.Errorf("%s: %.1f bytes per input byte, want <= %d", name, got, maxPerByte)
		}
	}

	// Both overflow to an infinity instead of failing.
	if f, err := osiBERReal(tests["mantissa"]); err != nil || !math.IsInf(f, 1) {
		t.Errorf("mantissa: %v, %v", f, err)
	}
	if f, err := osiBERReal(tests["decimal"]); err != nil || !math.IsInf(f, 1) {
		t.Errorf("decimal: %v, %v", f, err)
	}
}

// mmsDataWalk calls every accessor of a Data value and its members.
func mmsDataWalk(t *testing.T, d *MMSData) {
	_, _ = d.GeneralizedTime()
	_, _ = d.BCD()
	_ = d.Octets()
	_ = d.BigInt()
	_ = d.Bit(d.BitLen() - 1)

	if d.Type != MMSDataArray && d.Type != MMSDataStructure && len(d.Items) != 0 {
		t.Fatalf("%v with %d members", d.Type, len(d.Items))
	}
	for i := range d.Items {
		mmsDataWalk(t, &d.Items[i])
	}
}

// FuzzMMSData decodes a SEQUENCE OF Data body, as GOOSE allData and the
// MMS variable services hold.
func FuzzMMSData(f *testing.F) {
	for _, v := range mmsRealVectors() {
		f.Add(mp(8, v.raw))
	}
	f.Add(bytes.Join([][]byte{
		mp(3, []byte{1}), mp(4, []byte{6, 0x40}), mp(5, []byte{0xfe, 0x0c}), mp(6, []byte{1}),
		mp(7, []byte{8, 0x3f, 0xc0, 0, 0}), mp(9, []byte{0xde}), mp(10, []byte("abc")),
		mp(12, []byte{0, 0, 3, 0xe8, 0, 1}), mp(14, []byte{5, 0xa0}), mp(15, []byte{0x28, 0xca, 0x22}),
		mp(16, []byte("é")), mp(17, make([]byte, 8)),
	}, nil))
	f.Add(mc(2, mc(1, mp(11, []byte("20260102030405+0100")), mp(13, []byte{0x12}))))

	f.Fuzz(func(t *testing.T, data []byte) {
		list, err := decodeMMSDataList(data, 0)
		if err != nil {
			return
		}
		if len(list) > len(data) {
			t.Fatalf("%d values from %d octets", len(list), len(data))
		}
		for i := range list {
			mmsDataWalk(t, &list[i])
		}
	})
}
