// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/gopacket/gopacket"
)

// iec104ResyncRow is one TCP payload and what tshark 4.7 shows for it
// with TCP reassembly off, in the form of iec104Dump.
type iec104ResyncRow struct {
	frame   int
	payload string
	want    string
	// skipped is the garbage before each APDU.
	skipped []int
}

// iec104ResyncCapture holds the frames of Wireshark's sample capture
// TestDissectIec104.pcap that carry garbage before an APDU, each a
// different damage: lengths 0 to 3, a format the length does not fit, an
// ASDU cut in its data unit identifier and APDUs cut by the segment.
var iec104ResyncCapture = []iec104ResyncRow{
	{11, "020268001212", "", nil},
	{16, "0303036801131313", "apdulen=1", []int{3}},
	{18, "040404046802141414", "apdulen=2", []int{4}},
	{23, "0505050505680315151515", "apdulen=3", []int{5}},
	{25, "0606060606066804161616161616", "apdulen=4 type=0x00000000 tx=2827 rx=2827", []int{6}},
	{36, "07070707070707680517171717171717", "apdulen=5 type=0x00000003 utype=0x00000005", []int{7}},
	{41, "080808080808080868061818181818181818",
		"apdulen=6 type=0x00000000 tx=3084 rx=3084 typeid=24 sq=False numix=24", []int{8}},
	{56, "08080808080808086806181818", "apdulen=6", []int{8}},
	{71, "0909090909090909096806191919191919191919", "apdulen=6 type=0x00000001 rx=3212", []int{9}},
	{73, "0909090909090909096806191919", "apdulen=6", []int{9}},
	{83, "0a0a0a0a0a0a0a0a0a0a68081a1a1a1a1a1a1a1a1a1a",
		"apdulen=8 type=0x00000000 tx=3341 rx=3341 typeid=26 sq=False numix=26 causetx=26 nega=False test=False oa=26",
		[]int{10}},
	{94, "0a0a0a0a0a0a0a0a0a0a68081a1a1a1a1a", "apdulen=8 type=0x00000000 tx=3341 rx=3341 typeid=26", []int{10}},
}

// iec104ResyncHandmade holds hand-built payloads tshark 4.7 and this
// decoder agree on.
var iec104ResyncHandmade = []iec104ResyncRow{
	// Garbage, S, U.
	{2, "03680401000200680443000000", "apdulen=4,4 type=0x00000001,0x00000003 utype=0x00000010 rx=1", []int{1, 0}},
	// U, garbage, U.
	{3, "680443000000aabb680483000000",
		"apdulen=4,4 type=0x00000003,0x00000003 utype=0x00000010,0x00000020", []int{0, 2}},
	// U, then garbage to the end.
	{4, "680443000000aabb", "apdulen=4 type=0x00000003 utype=0x00000010", []int{0}},
	// An I frame without ASDU does not hide the U frame after it.
	{11, "680402000000680483000000",
		"apdulen=4,4 type=0x00000000,0x00000003 utype=0x00000020 tx=1 rx=0", []int{0, 0}},
	// U, then a start octet alone.
	{13, "68044300000068", "apdulen=4 type=0x00000003 utype=0x00000010", []int{0}},
	// U, then an APDU cut inside its control field.
	{14, "680443000000680443", "apdulen=4,4 type=0x00000003 utype=0x00000010", []int{0, 0}},
}

// iec104ResyncOurs holds hand-built payloads where this decoder parts
// from tshark 4.7 on purpose: it prefers a whole, sound APDU further on
// to a start octet that cannot be one. tshark's view is in the comment.
var iec104ResyncOurs = []iec104ResyncRow{
	// tshark: malformed, no fields.
	{1, "03680113680443000000", "apdulen=4 type=0x00000003 utype=0x00000010", []int{4}},
	// tshark: apdulen=5,4, both U frames.
	{5, "aa68054300000000680483000000", "apdulen=4 type=0x00000003 utype=0x00000020", []int{8}},
	// tshark: apdulen=254, an I frame with type 104 read from the U frame.
	{6, "aa68fe00000000680483000000", "apdulen=4 type=0x00000003 utype=0x00000020", []int{7}},
	// tshark: malformed, no fields.
	{8, "aa6800680483000000", "apdulen=4 type=0x00000003 utype=0x00000020", []int{3}},
	// tshark: apdulen=3,4 and the U frame.
	{9, "aa6803010203680483000000", "apdulen=4 type=0x00000003 utype=0x00000020", []int{6}},
	// tshark: apdulen=32, a cut I frame with type 104 read from the U frame.
	{10, "aa682000000000680483000000", "apdulen=4 type=0x00000003 utype=0x00000020", []int{7}},
	// tshark: the first U frame, then malformed.
	{15, "6804430000006803430000680483000000",
		"apdulen=4,4 type=0x00000003,0x00000003 utype=0x00000010,0x00000020", []int{0, 5}},
}

func iec104ResyncCheck(t *testing.T, name string, rows []iec104ResyncRow) {
	t.Helper()

	for _, row := range rows {
		data, err := hex.DecodeString(row.payload)
		if err != nil {
			t.Fatal(err)
		}

		p := gopacket.NewPacket(data, LayerTypeIEC104, gopacket.Default)
		x := &iec104Dump{}
		x.apdus(p)
		if got := x.String(); got != row.want {
			t.Errorf("%s %d:\n got %s\nwant %s", name, row.frame, got, row.want)
		}

		var skipped []int
		for _, l := range p.Layers() {
			apdu, ok := l.(*IEC104)
			if !ok {
				continue
			}
			skipped = append(skipped, apdu.Skipped)

			if (apdu.Skipped > 0) != apdu.Faults.Has(IEC104FaultGarbage) {
				t.Errorf("%s %d: skipped %d with faults %v", name, row.frame, apdu.Skipped, apdu.Faults)
			}
		}
		if len(skipped) != len(row.skipped) {
			t.Errorf("%s %d: skipped %v, want %v", name, row.frame, skipped, row.skipped)
			continue
		}
		for k := range skipped {
			if skipped[k] != row.skipped[k] {
				t.Errorf("%s %d: skipped %v, want %v", name, row.frame, skipped, row.skipped)
				break
			}
		}
	}
}

// Garbage before and between APDUs is skipped and counted, as tshark
// skips it.
func TestIEC104Resync(t *testing.T) {
	iec104ResyncCheck(t, "capture", iec104ResyncCapture)
	iec104ResyncCheck(t, "handmade", iec104ResyncHandmade)
	iec104ResyncCheck(t, "ours", iec104ResyncOurs)
}

func TestIEC104ResyncFaults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		faults  IEC104Fault
		err     error
	}{
		{"clean", "680443000000", 0, nil},
		{"garbage", "aa680443000000", IEC104FaultGarbage, nil},
		{"short length", "aa680113", IEC104FaultGarbage | IEC104FaultLength, ErrIEC104BadLength},
		{"short and cut", "6803aa", IEC104FaultLength | IEC104FaultTruncated, ErrIEC104BadLength},
		{"U with ASDU", "68054300000000", IEC104FaultLength, ErrIEC104BadLength},
		{"cut", "68064300", IEC104FaultTruncated, ErrIEC104TooShort},
		{"bad ASDU", "6806000000000101", IEC104FaultASDU, ErrIEC104ASDUTooShort},
	} {
		data, _ := hex.DecodeString(tc.payload)

		var apdu IEC104
		err := apdu.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
		if !errors.Is(err, tc.err) || apdu.Faults != tc.faults {
			t.Errorf("%s: faults %v err %v, want %v %v", tc.name, apdu.Faults, err, tc.faults, tc.err)
		}

		p := gopacket.NewPacket(data, LayerTypeIEC104, gopacket.Default)
		l, _ := p.Layer(LayerTypeIEC104).(*IEC104)
		if l == nil || l.Faults != tc.faults {
			t.Errorf("%s: packet layer %+v", tc.name, l)
		}
		if (p.ErrorLayer() != nil) != (tc.err != nil) {
			t.Errorf("%s: error layer %v", tc.name, p.ErrorLayer())
		}
	}

	// No start octet at all is still an error, without a layer.
	p := gopacket.NewPacket([]byte{0xaa, 0xbb, 0xcc}, LayerTypeIEC104, gopacket.Default)
	if e := p.ErrorLayer(); e == nil || !errors.Is(e.Error(), ErrIEC104BadStart) || len(p.Layers()) != 1 {
		t.Errorf("no start: %v", p.Layers())
	}

	if got := (IEC104FaultGarbage | IEC104FaultTruncated).String(); got != "Garbage|Truncated" {
		t.Errorf("String() = %q", got)
	}
	if got := IEC104Fault(0).String(); got != "None" {
		t.Errorf("String() = %q", got)
	}
}

// A start octet that only looks like an APDU is passed over when a sound
// APDU follows: each rule of iec104Sound rejects one.
func TestIEC104ResyncSound(t *testing.T) {
	good := "680483000000"
	for _, tc := range []struct{ name, bad string }{
		{"I without ASDU", "680400000000"},
		{"I with odd N(R)", "680e0000010064010600010000000014"},
		{"S with ASDU", "68050100020000"},
		{"S with N(S) bits", "680401020200"},
		{"U with two functions", "68040f000000"},
		{"U without function", "680403000000"},
		{"U with sequence octets", "680443000100"},
		{"length above 253", "68fe00000000"},
		{"cut", "680e0000000064"},
	} {
		data, _ := hex.DecodeString("aa" + tc.bad + good)
		p := gopacket.NewPacket(data, LayerTypeIEC104, gopacket.Default)

		apdus := p.Layers()
		if len(apdus) != 1 || p.ErrorLayer() != nil {
			t.Errorf("%s: layers %v", tc.name, apdus)
			continue
		}
		if apdu := apdus[0].(*IEC104); apdu.UFunction != IEC104TestFRCon || apdu.Skipped != len(data)-iec104APCILen {
			t.Errorf("%s: got %+v", tc.name, apdu)
		}
	}
}

// Garbage costs time linear in its length: a search that finds no sound
// APDU is not repeated for each start octet.
func TestIEC104ResyncLinear(t *testing.T) {
	const apdus = 1 << 14

	// Each start octet opens a damaged APDU after one octet of garbage.
	data := bytes.Repeat([]byte{0xaa, 0x68, 0x04, 0x00, 0x00, 0x00, 0x00}, apdus)

	var mode iec104Resync
	var apdu IEC104
	steps := 0
	for len(data) > 0 {
		before := len(data)
		_ = apdu.decodeAPCI(data, gopacket.NilDecodeFeedback, &mode)
		data = apdu.Payload
		if len(data) >= before {
			t.Fatal("no progress")
		}
		steps++
	}
	if steps != apdus || mode != iec104ResyncFirst {
		t.Errorf("%d steps, mode %d", steps, mode)
	}
}

func TestIEC104ResyncAllocs(t *testing.T) {
	// Garbage alone allocates nothing per octet: the packet and its
	// error layer only.
	garbage := bytes.Repeat([]byte{0x68, 0x01, 0xaa}, 1<<12)
	small := testing.AllocsPerRun(20, func() {
		gopacket.NewPacket(garbage[:30], LayerTypeIEC104, gopacket.NoCopy)
	})
	large := testing.AllocsPerRun(20, func() {
		gopacket.NewPacket(garbage, LayerTypeIEC104, gopacket.NoCopy)
	})

	// Each damaged APDU becomes a layer: bound the cost per input octet.
	const perOctet = 1
	if large > small+perOctet*float64(len(garbage)) {
		t.Errorf("%v allocations for %d octets (%v for 30)", large, len(garbage), small)
	}
}

func iec104ScanAll(t *testing.T, stream []byte, chunk int) [][]byte {
	t.Helper()

	s := bufio.NewScanner(&otChunkReader{data: stream, chunk: chunk})
	s.Split(ScanIEC104Resync)

	var tokens [][]byte
	for s.Scan() {
		tokens = append(tokens, bytes.Clone(s.Bytes()))
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	return tokens
}

// otChunkReader hands out data chunk octets at a time.
type otChunkReader struct {
	data  []byte
	chunk int
}

func (r *otChunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}

	n := r.chunk
	if n > len(r.data) {
		n = len(r.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

// ScanIEC104Resync loses no octet: garbage rides in front of the APDU
// that follows it, and the decoder counts it as skipped.
func TestIEC104ScanResync(t *testing.T) {
	garbage := []byte{0x00, 0x11, 0x68, 0x04, 0x00}
	stream := bytes.Join([][]byte{garbage, testIEC104U, testIEC104I, garbage, garbage, testIEC104U, {0x68, 0x04}}, nil)
	want := [][]byte{
		append(bytes.Clone(garbage), testIEC104U...),
		testIEC104I,
		bytes.Join([][]byte{garbage, garbage, testIEC104U}, nil),
		{0x68, 0x04},
	}

	for _, chunk := range []int{1, 3, len(stream)} {
		tokens := iec104ScanAll(t, stream, chunk)
		if len(tokens) != len(want) {
			t.Fatalf("chunk %d: %d tokens %x, want %d", chunk, len(tokens), tokens, len(want))
		}
		for k := range want {
			if !bytes.Equal(tokens[k], want[k]) {
				t.Errorf("chunk %d token %d: %x, want %x", chunk, k, tokens[k], want[k])
			}
		}
		if got := bytes.Join(tokens, nil); !bytes.Equal(got, stream) {
			t.Errorf("chunk %d: tokens do not add up to the stream", chunk)
		}

		// Each token with an APDU decodes to that APDU alone.
		for k, tok := range tokens[:3] {
			p := gopacket.NewPacket(tok, LayerTypeIEC104, gopacket.Default)
			apdu, _ := p.Layer(LayerTypeIEC104).(*IEC104)
			if p.ErrorLayer() != nil || len(p.Layers()) != 1 || apdu.Skipped+len(apdu.Contents) != len(tok) {
				t.Errorf("chunk %d token %d: layers %v", chunk, k, p.Layers())
			}
		}
	}
}

// Garbage without end comes out in bounded tokens.
func TestIEC104ScanResyncCap(t *testing.T) {
	// Every start octet claims an APDU the stream never completes.
	stream := bytes.Repeat([]byte{0xaa, 0xbb, 0xcc, 0x68, 0x00}, 1<<10)
	stream = append(stream, testIEC104U...)

	tokens := iec104ScanAll(t, stream, 7)
	for k, tok := range tokens {
		if len(tok) > iec104GarbageMax+iec104HeaderLen+iec104MaxLength {
			t.Fatalf("token %d is %d octets", k, len(tok))
		}
	}
	if got := bytes.Join(tokens, nil); !bytes.Equal(got, stream) {
		t.Error("tokens do not add up to the stream")
	}
	if last := tokens[len(tokens)-1]; !bytes.HasSuffix(last, testIEC104U) {
		t.Errorf("last token %x", last)
	}
}

func FuzzIEC104Resync(f *testing.F) {
	for _, rows := range [][]iec104ResyncRow{iec104ResyncCapture, iec104ResyncHandmade, iec104ResyncOurs} {
		for _, row := range rows {
			data, _ := hex.DecodeString(row.payload)
			f.Add(data)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// The packet decoder accounts for every octet up to the last
		// APDU: skipped garbage and contents add up.
		p := gopacket.NewPacket(data, LayerTypeIEC104, gopacket.Default)
		used := 0
		for _, l := range p.Layers() {
			apdu, ok := l.(*IEC104)
			if !ok {
				continue
			}
			if apdu.Skipped < 0 || len(apdu.Contents) < iec104HeaderLen {
				t.Fatalf("skipped %d, contents %d", apdu.Skipped, len(apdu.Contents))
			}
			used += apdu.Skipped + len(apdu.Contents)
		}
		if used > len(data) {
			t.Fatalf("layers cover %d of %d octets", used, len(data))
		}

		// The splitter returns the stream whole, in bounded tokens, the
		// same however the stream arrives.
		whole, errWhole := otScan(ScanIEC104Resync, data, otReadWhole)
		byByte, errByte := otScan(ScanIEC104Resync, data, otReadByByte)
		if errWhole != nil || errByte != nil {
			t.Fatalf("errors %v, %v", errWhole, errByte)
		}
		otWantTokens(t, byByte, whole)

		for _, tok := range whole {
			if len(tok) == 0 || len(tok) > iec104GarbageMax+iec104HeaderLen+iec104MaxLength {
				t.Fatalf("token of %d octets", len(tok))
			}
		}
		if got := bytes.Join(whole, nil); !bytes.Equal(got, data) {
			t.Fatalf("tokens hold %d of %d octets", len(got), len(data))
		}
	})
}

func TestIEC104TimeFaults(t *testing.T) {
	cp56 := func(ms uint16, min, hour, day, month, year uint8) IEC104Time {
		return iec104DecodeTime([]byte{uint8(ms), uint8(ms >> 8), min, hour, day, month, year})
	}

	for _, tc := range []struct {
		name string
		tag  IEC104Time
		want IEC104TimeFault
	}{
		{"valid", cp56(59999, 59, 23, 31, 12, 99), 0},
		{"leap day", cp56(0, 0, 0, 29, 2, 24), 0},
		{"no leap day", cp56(0, 0, 0, 29, 2, 23), IEC104TimeBadDay},
		{"30 February", cp56(0, 0, 0, 30, 2, 24), IEC104TimeBadDay},
		{"31 April", cp56(0, 0, 0, 31, 4, 26), IEC104TimeBadDay},
		{"day 0", cp56(0, 0, 0, 0, 1, 26), IEC104TimeBadDay},
		{"milliseconds", cp56(60000, 0, 0, 1, 1, 26), IEC104TimeBadMilliseconds},
		{"minute", cp56(0, 60, 0, 1, 1, 26), IEC104TimeBadMinute},
		{"hour", cp56(0, 0, 24, 1, 1, 26), IEC104TimeBadHour},
		{"month 0", cp56(0, 0, 0, 31, 0, 26), IEC104TimeBadMonth},
		{"month 13", cp56(0, 0, 0, 31, 13, 26), IEC104TimeBadMonth},
		{"year", cp56(0, 0, 0, 1, 1, 100), IEC104TimeBadYear},
		{"all", cp56(0xffff, 0x3f, 0x1f, 0, 0x0f, 0x7f), IEC104TimeBadMilliseconds | IEC104TimeBadMinute |
			IEC104TimeBadHour | IEC104TimeBadDay | IEC104TimeBadMonth | IEC104TimeBadYear},
		{"CP24 valid", iec104DecodeTime([]byte{0x5f, 0xea, 59}), 0},
		{"CP24", iec104DecodeTime([]byte{0x60, 0xea, 60}), IEC104TimeBadMilliseconds | IEC104TimeBadMinute},
		{"none", IEC104Time{Minute: 99}, 0},
	} {
		if got := tc.tag.RangeFaults(); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}

	if got := (IEC104TimeBadHour | IEC104TimeBadDay).String(); got != "Hour|Day" {
		t.Errorf("String() = %q", got)
	}
	if got := IEC104TimeFault(0xc1).String(); got != "Milliseconds|Unknown(0xC0)" {
		t.Errorf("String() = %q", got)
	}

	// An out of range tag is no decode error: the object keeps it.
	apdu := []byte{0x68, 0x15, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01,
		0xff, 0xff, 0x3f, 0x1f, 0x00, 0x0f, 0x7f}
	var l IEC104
	if err := l.DecodeFromBytes(apdu, gopacket.NilDecodeFeedback); err != nil || len(l.ASDU.Objects) != 1 {
		t.Fatalf("decode: %v %+v", err, l.ASDU)
	}
	if got := l.ASDU.Objects[0].Time.RangeFaults(); got.String() != "Milliseconds|Minute|Hour|Day|Month|Year" {
		t.Errorf("object tag faults %v", got)
	}
}

func TestIEC104ValueNames(t *testing.T) {
	for _, tc := range []struct {
		got  fmt.Stringer
		want string
	}{
		{IEC104NOF(0), "Default"},
		{IEC104NOFTransparent, "Transparent file"},
		{IEC104NOFDisturbance, "Disturbance data of protection equipment"},
		{IEC104NOFEvents, "Sequences of events"},
		{IEC104NOFAnalogue, "Sequences of recorded analogue values"},
		{IEC104NOF(5), "Reserved, standard(5)"},
		{IEC104NOF(127), "Reserved, standard(127)"},
		{IEC104NOF(128), "Reserved, private(128)"},
		{IEC104NOF(255), "Reserved, private(255)"},
		{IEC104NOF(256), "File(256)"},
		{IEC104NOS(0), "Default"},
		{IEC104NOS(3), "Section(3)"},
		{IEC104FRQ(0x00), "Positive, Default"},
		{IEC104FRQ(0x81), "Negative, Reserved, standard(1)"},
		{IEC104FRQ(0x40), "Positive, Reserved, private(64)"},
		{IEC104SRQ(0x00), "Ready, Default"},
		{IEC104SRQ(0xff), "Not ready, Reserved, private(127)"},
		{IEC104SOF(0x00), "Default, Additional file follows, File, Waits for transfer"},
		{IEC104SOF(0xef), "Reserved, standard(15), Last file, Subdirectory, Transfer active"},
		{IEC104SOF(0x10), "Reserved, private(16), Additional file follows, File, Waits for transfer"},
		{IEC104UserUnknown, "(Unknown)"},
		{IEC104UserDefault, "Default"},
		{IEC104User(2), "Chosen by the controlling station(2)"},
		{IEC104ChallengeReason(0), "(not used)"},
		{IEC104ReasonCritical, "CRITICAL"},
		{IEC104ChallengeReason(2), "Unknown(2)"},
		{IEC104MACSHA1x8, "HMAC SHA-1 truncated to 8 octets (serial)"},
		{IEC104MACAlgorithm(7), "Unknown(7)"},
	} {
		if got := tc.got.String(); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}

	// Every algorithm IEC 62351-5 names has its MAC length.
	sizes := map[IEC104MACAlgorithm]int{
		IEC104MACNone: 0, IEC104MACSHA1x4: 4, IEC104MACSHA1x10: 10, IEC104MACSHA256x8: 8,
		IEC104MACSHA256x16: 16, IEC104MACSHA1x8: 8, IEC104MACAESGMAC: 12, 7: 0, 128: 0,
	}
	for alg, want := range sizes {
		if got := alg.Size(); got != want {
			t.Errorf("%v: size %d, want %d", alg, got, want)
		}
	}

	// The accessors name the fields of decoded objects.
	f := IEC104File{Name: 3, Section: 2}
	s := IEC104Security{User: 1, Reason: 1}
	if f.NOF() != IEC104NOFEvents || f.NOS().String() != "Section(2)" ||
		s.USR() != IEC104UserDefault || s.RSC() != IEC104ReasonCritical {
		t.Errorf("accessors: %v %v %v %v", f.NOF(), f.NOS(), s.USR(), s.RSC())
	}
}

// Every prefix of every resync payload decodes without panic, its layers
// stay inside the prefix, and a cut never adds a sound APDU.
func TestIEC104ResyncTruncated(t *testing.T) {
	for _, rows := range [][]iec104ResyncRow{iec104ResyncCapture, iec104ResyncHandmade, iec104ResyncOurs} {
		for _, row := range rows {
			data, _ := hex.DecodeString(row.payload)
			whole := len(gopacket.NewPacket(data, LayerTypeIEC104, gopacket.Default).Layers())

			for n := 0; n < len(data); n++ {
				p := gopacket.NewPacket(data[:n], LayerTypeIEC104, gopacket.Default)
				used := 0
				for _, l := range p.Layers() {
					if apdu, ok := l.(*IEC104); ok {
						used += apdu.Skipped + len(apdu.Contents)
					}
				}
				if used > n {
					t.Errorf("%s cut to %d: layers cover %d octets", row.payload, n, used)
				}

				// A cut payload is damaged: it has an error, or APDUs
				// that say what is wrong with them.
				sound := p.ErrorLayer() == nil
				for _, l := range p.Layers() {
					if apdu, ok := l.(*IEC104); ok && apdu.Faults&^IEC104FaultGarbage != 0 {
						sound = false
					}
				}
				if sound && len(p.Layers()) > whole {
					t.Errorf("%s cut to %d: %d sound layers, %d whole", row.payload, n, len(p.Layers()), whole)
				}
			}
		}
	}
}
