// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// iec104Golden is tshark 4.7 ground truth for testdata/iec104.pcap, one
// line per frame: "type;tx;rx;utype;typeid;cause;numix;ioa", each a comma
// separated list over the APDUs of the frame. utype is coded as Wireshark
// codes it, without the two format bits.
var iec104Golden = []string{
	";;;;;;;",
	";;;;;;;",
	";;;;;;;",
	"3;;;16;;;;",
	"3;;;32;;;;",
	";;;;;;;",
	"3;;;1;;;;",
	"3;;;2;;;;",
	"0;0;0;;100;6;1;0",
	"0;0;0;;70;4;1;0",
	"0;1;1;;100;6;1;0",
	"0,0,0;1,2,3;1,1,1;;100,1,3;7,20,20;1,4,4;0,1,2,3,4,1,2,3,4",
	";;;;;;;",
	"0,0,0,0,0,0,0,0,0;4,5,6,7,8,9,10,11,12;2,2,2,2,2,2,2,2,2;;5,7,9,11,13,30,31,32,33;20,20,20,20,20,20,20,20,20;4,4,4,4,4,4,4,4,4;1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4,11,12,13,14,11,12,13,14,11,12,13,14,11,12,13,14",
	"1;;13;;;;;",
	"0,0,0,0,0,0,0,0,0,0,0,0;13,14,15,16,17,18,19,20,21,22,23,24;2,2,2,2,2,2,2,2,2,2,2,2;;34,35,36,100,100,1,3,5,7,9,11,13;20,20,20,10,7,20,20,20,20,20,20,20;4,4,4,1,1,4,4,4,4,4,4,4;11,12,13,14,11,12,13,14,11,12,13,14,0,0,1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4,1,2,3,4",
	"1;;25;;;;;",
	"0,0,0,0,0,0,0,0;25,26,27,28,29,30,31,32;2,2,2,2,2,2,2,2;;30,31,32,33,34,35,36,100;20,20,20,20,20,20,20,10;4,4,4,4,4,4,4,1;11,12,13,14,11,12,13,14,11,12,13,14,11,12,13,14,11,12,13,14,11,12,13,14,11,12,13,14,0",
	";;;;;;;",
	"0;2;33;;45;6;1;2",
	"0,0,0;33,34,35;3,3,3;;45,45,1;7,10,3;1,1,1;2,2,2",
	"1;;36;;;;;",
	";;;;;;;",
	"0;3;36;;45;6;1;13",
	"0,0,0;36,37,38;4,4,4;;45,45,30;7,10,3;1,1,1;13,13,13",
	";;;;;;;",
	"1;;4;;;;;",
	";;;;;;;",
	"0;4;39;;46;6;1;1",
	"0;39;5;;46;7;1;1",
	";;;;;;;",
	"0,0;40,41;5,5;;46,3;10,3;1,1;1,1",
	";;;;;;;",
	"0;5;42;;46;6;1;14",
	"0,0,0;42,43,44;6,6,6;;46,46,31;7,10,3;1,1,1;14,14,14",
	";;;;;;;",
	"1;;45;;;;;",
	";;;;;;;",
	"0;6;45;;47;6;1;1",
	"0,0,0;45,46,47;7,7,7;;47,47,5;7,10,3;1,1,1;1,1,1",
	";;;;;;;",
	"0;7;48;;47;6;1;12",
	"0,0,0;48,49,50;8,8,8;;47,47,32;7,10,3;1,1,1;12,12,12",
	";;;;;;;",
	"1;;8;;;;;",
	";;;;;;;",
	"1;;51;;;;;",
	";;;;;;;",
	"0;8;51;;51;6;1;3",
	"0;51;9;;51;7;1;3",
	";;;;;;;",
	"0,0;52,53;9,9;;51,7;10,3;1,1;3,3",
	";;;;;;;",
	"0;9;54;;51;6;1;14",
	"0,0,0;54,55,56;10,10,10;;51,51,33;7,10,3;1,1,1;14,14,14",
	";;;;;;;",
	"0;10;57;;48;6;1;1",
	"0;57;11;;48;7;1;1",
	";;;;;;;",
	"0,0;58,59;11,11;;48,9;10,3;1,1;1,1",
	";;;;;;;",
	"0;11;60;;48;6;1;12",
	"0,0,0;60,61,62;12,12,12;;48,48,34;7,10,3;1,1,1;12,12,12",
	"1;;60;;;;;",
	";;;;;;;",
	"1;;12;;;;;",
	";;;;;;;",
	"1;;63;;;;;",
	";;;;;;;",
	"0;12;63;;49;6;1;3",
	"0;63;13;;49;7;1;3",
	";;;;;;;",
	"0,0;64,65;13,13;;49,11;10,3;1,1;3,3",
	";;;;;;;",
	"0;13;66;;49;6;1;14",
	"0,0,0;66,67,68;14,14,14;;49,49,35;7,10,3;1,1,1;14,14,14",
	";;;;;;;",
	"0;14;69;;50;6;1;1",
	"0,0,0;69,70,71;15,15,15;;50,50,13;7,10,3;1,1,1;1,1,1",
	";;;;;;;",
	"1;;72;;;;;",
	";;;;;;;",
	"1;;15;;;;;",
	";;;;;;;",
	"0;15;72;;50;6;1;12",
	"0;72;16;;50;7;1;12",
	";;;;;;;",
	"0,0;73,74;16,16;;50,36;10,3;1,1;12,12",
	";;;;;;;",
	"1;;75;;;;;",
	";;;;;;;",
	"1;;16;;;;;",
	";;;;;;;",
	"3;;;16;;;;",
	"3;;;32;;;;",
	";;;;;;;",
	"3;;;16;;;;",
	"3;;;32;;;;",
	";;;;;;;",
	"3;;;16;;;;",
	"3;;;32;;;;",
	";;;;;;;",
	";;;;;;;",
	";;;;;;;",
	";;;;;;;",
}

// iec104SQGolden is the same for testdata/iec104_sq.pcap.
var iec104SQGolden = []string{
	"0,0,0,0;1,2,3,4;1,1,1,1;;1,1,1,1;20,20,20,20;16,16,16,16;0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63",
}

// iec104Vectors are hand-built APDUs, one per entry, checked against
// tshark 4.7. Each I-format APDU has N(R)=1 and N(S) its index plus one.
var iec104Vectors = [][]byte{
	// M_ME_TF_1 Spont CA=10 IOA=4660: 23.5, QDS 0, 2026-11-19 15:34:12.345.
	{0x68, 0x19, 0x02, 0x00, 0x02, 0x00, 0x24, 0x01, 0x03, 0x00, 0x0a, 0x00, 0x34, 0x12, 0x00,
		0x00, 0x00, 0xbc, 0x41, 0x00, 0x39, 0x30, 0x22, 0x0f, 0x93, 0x0b, 0x1a},
	// M_IT_NA_1 SQ=1 Reqcogen CA=1 IOA=100,101: BCR -5 (SQ 3, CY, IV), 1000 (SQ 4).
	{0x68, 0x17, 0x04, 0x00, 0x02, 0x00, 0x0f, 0x82, 0x25, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00,
		0xfb, 0xff, 0xff, 0xff, 0xa3, 0xe8, 0x03, 0x00, 0x00, 0x04},
	// C_SE_NC_1 Act+Test OA=3 IOA=66051: -1.25, QOS select.
	{0x68, 0x12, 0x06, 0x00, 0x02, 0x00, 0x32, 0x01, 0x86, 0x03, 0x0a, 0x00, 0x03, 0x02, 0x01,
		0x00, 0x00, 0xa0, 0xbf, 0x80},
	// C_DC_NA_1 ActCon+Negative IOA=5: DCO on, QU short pulse, execute.
	{0x68, 0x0e, 0x08, 0x00, 0x02, 0x00, 0x2e, 0x01, 0x47, 0x00, 0x0a, 0x00, 0x05, 0x00, 0x00, 0x06},
	// M_EP_TE_1 IOA=7: SPE GS|SL1|SIE, QDP EI, 250 ms, CP56.
	{0x68, 0x18, 0x0a, 0x00, 0x02, 0x00, 0x27, 0x01, 0x03, 0x00, 0x0a, 0x00, 0x07, 0x00, 0x00,
		0x13, 0x08, 0xfa, 0x00, 0x39, 0x30, 0x22, 0x0f, 0x93, 0x0b, 0x1a},
	// F_SG_NA_1 File IOA=768: NOF 2, NOS 1, LOS 4, deadbeef.
	{0x68, 0x15, 0x0c, 0x00, 0x02, 0x00, 0x7d, 0x01, 0x0d, 0x00, 0x0a, 0x00, 0x00, 0x03, 0x00,
		0x02, 0x00, 0x01, 0x04, 0xde, 0xad, 0xbe, 0xef},
	// M_DP_TA_1 IOA=9: DIQ on + BL, CP24 59:59.999 invalid.
	{0x68, 0x11, 0x0e, 0x00, 0x02, 0x00, 0x04, 0x01, 0x03, 0x00, 0x0a, 0x00, 0x09, 0x00, 0x00,
		0x12, 0x5f, 0xea, 0xbb},
	// M_ST_NA_1 IOA=11: VTI -3 transient, QDS OV|NT.
	{0x68, 0x0f, 0x10, 0x00, 0x02, 0x00, 0x05, 0x01, 0x03, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x00, 0xfd, 0x41},
	// F_SC_NB_1 Req IOA=0: NOF 1, 2026-11-19 15:34:12.345 to 16:00:00.000.
	{0x68, 0x1d, 0x12, 0x00, 0x02, 0x00, 0x7f, 0x01, 0x05, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x39, 0x30, 0x22, 0x0f, 0x93, 0x0b, 0x1a, 0x00, 0x00, 0x00, 0x10, 0x93, 0x0b, 0x1a},
	// M_PS_NA_1 Inrogen IOA=2: ST 0x00f0, CD 0x0101.
	{0x68, 0x12, 0x14, 0x00, 0x02, 0x00, 0x14, 0x01, 0x14, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x00,
		0xf0, 0x00, 0x01, 0x01, 0x00},
	// M_ME_NA_1 IOA=3: NVA 0x4000 (0.5).
	{0x68, 0x10, 0x16, 0x00, 0x02, 0x00, 0x09, 0x01, 0x03, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x00, 0x00, 0x40, 0x00},
	// Type 200, private range, not decoded: kept raw.
	{0x68, 0x0e, 0x18, 0x00, 0x02, 0x00, 0xc8, 0x01, 0x06, 0x00, 0x0a, 0x00, 0xaa, 0xbb, 0xcc, 0xdd},
	// S-format, N(R)=5.
	{0x68, 0x04, 0x01, 0x00, 0x0a, 0x00},
	// U-format TESTFR act.
	{0x68, 0x04, 0x43, 0x00, 0x00, 0x00},
}

// iec104T is the CP56Time2a of the vectors.
var iec104T = IEC104Time{Format: IEC104TimeCP56, Milliseconds: 12345, Minute: 34, Hour: 15,
	Day: 19, Weekday: 4, Month: 11, Year: 26}

// iec104Want is the decoded form of iec104Vectors, with object Raw left out.
var iec104Want = []IEC104{
	{Length: 25, SendSeq: 1, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypeFloatTime56, NumObjects: 1,
		Cause: IEC104CauseSpontaneous, CommonAddr: 10,
		Objects: []IEC104Object{{IOA: 4660, Float: 23.5, Time: iec104T}}}},
	{Length: 23, SendSeq: 2, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypeTotals, Sequence: true,
		NumObjects: 2, Cause: IEC104CauseCounterRequest, CommonAddr: 1,
		Objects: []IEC104Object{
			{IOA: 100, Counter: IEC104Counter{Value: -5, Sequence: 3, Carry: true, Invalid: true}},
			{IOA: 101, Counter: IEC104Counter{Value: 1000, Sequence: 4}},
		}}},
	{Length: 18, SendSeq: 3, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypeSetpointFloat, NumObjects: 1,
		Cause: IEC104CauseActivation, Test: true, Originator: 3, CommonAddr: 10,
		Objects: []IEC104Object{{IOA: 66051, Float: -1.25, Command: IEC104Command{Select: true}}}}},
	{Length: 14, SendSeq: 4, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypeDoubleCommand, NumObjects: 1,
		Cause: IEC104CauseActivationCon, Negative: true, CommonAddr: 10,
		Objects: []IEC104Object{{IOA: 5, Command: IEC104Command{State: 2, Qualifier: 1}}}}},
	{Length: 24, SendSeq: 5, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypeProtStartTime56, NumObjects: 1,
		Cause: IEC104CauseSpontaneous, CommonAddr: 10,
		Objects: []IEC104Object{{IOA: 7, Event: IEC104EventGeneral | IEC104EventPhaseL1 | IEC104EventEarth,
			Quality: IEC104QualityElapsedInvalid, Elapsed: 250, Time: iec104T}}}},
	{Length: 21, SendSeq: 6, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypeSegment, NumObjects: 1,
		Cause: IEC104CauseFileTransfer, CommonAddr: 10,
		Objects: []IEC104Object{{IOA: 768, File: IEC104File{Name: 2, Section: 1, Length: 4,
			Segment: []byte{0xde, 0xad, 0xbe, 0xef}}}}}},
	{Length: 17, SendSeq: 7, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypeDoublePointTime24, NumObjects: 1,
		Cause: IEC104CauseSpontaneous, CommonAddr: 10,
		Objects: []IEC104Object{{IOA: 9, DoublePoint: IEC104DoublePointOn, Quality: IEC104QualityBlocked,
			Time: IEC104Time{Format: IEC104TimeCP24, Milliseconds: 59999, Minute: 59, Invalid: true}}}}},
	{Length: 15, SendSeq: 8, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypeStepPosition, NumObjects: 1,
		Cause: IEC104CauseSpontaneous, CommonAddr: 10,
		Objects: []IEC104Object{{IOA: 11, Step: -3, Transient: true,
			Quality: IEC104QualityOverflow | IEC104QualityNotTopical}}}},
	{Length: 29, SendSeq: 9, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypeQueryLog, NumObjects: 1,
		Cause: IEC104CauseRequest, CommonAddr: 10,
		Objects: []IEC104Object{{IOA: 0, Time: iec104T, File: IEC104File{Name: 1,
			Stop: IEC104Time{Format: IEC104TimeCP56, Hour: 16, Day: 19, Weekday: 4, Month: 11, Year: 26}}}}}},
	{Length: 18, SendSeq: 10, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypePackedSinglePoint, NumObjects: 1,
		Cause: IEC104CauseInterrogated, CommonAddr: 10,
		Objects: []IEC104Object{{IOA: 2, Status: 0x00f0, Changed: 0x0101}}}},
	{Length: 16, SendSeq: 11, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: IEC104TypeNormalized, NumObjects: 1,
		Cause: IEC104CauseSpontaneous, CommonAddr: 10,
		Objects: []IEC104Object{{IOA: 3, Normalized: 0x4000}}}},
	{Length: 14, SendSeq: 12, RecvSeq: 1, ASDU: IEC104ASDU{TypeID: 200, NumObjects: 1,
		Cause: IEC104CauseActivation, CommonAddr: 10, Raw: []byte{0xaa, 0xbb, 0xcc, 0xdd}}},
	{Length: 4, Format: IEC104FormatS, RecvSeq: 5},
	{Length: 4, Format: IEC104FormatU, UFunction: IEC104TestFRAct},
}

// iec104Check compares a decoded APDU with its wanted form, ignoring the
// layer octets and the Raw of each object, which it checks against the
// element sizes instead.
func iec104Check(t *testing.T, name string, got *IEC104, want IEC104) {
	t.Helper()

	g := *got
	g.BaseLayer = BaseLayer{}
	g.ASDU.Objects = nil
	for _, o := range got.ASDU.Objects {
		size := 0
		for _, part := range iec104Types[got.ASDU.TypeID].parts {
			size += iec104PartSize[part]
		}
		if part := iec104Types[got.ASDU.TypeID].parts; len(part) > 0 && part[len(part)-1] == partSegment {
			size += len(o.File.Segment)
		}
		if len(o.Raw) != size {
			t.Errorf("%s: IOA %d Raw is %d octets, want %d", name, o.IOA, len(o.Raw), size)
		}
		o.Raw = nil
		g.ASDU.Objects = append(g.ASDU.Objects, o)
	}
	if len(g.ASDU.Raw) == 0 {
		g.ASDU.Raw = nil
	}

	if !reflect.DeepEqual(g, want) {
		t.Errorf("%s:\n got %+v\nwant %+v", name, g, want)
	}
}

func TestIEC104Vectors(t *testing.T) {
	for i, v := range iec104Vectors {
		var got IEC104
		if err := got.DecodeFromBytes(v, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("vector %d: %v", i, err)
			continue
		}
		if !bytes.Equal(got.Contents, v) || len(got.Payload) != 0 {
			t.Errorf("vector %d: contents %x payload %x", i, got.Contents, got.Payload)
		}
		iec104Check(t, fmt.Sprintf("vector %d", i), &got, iec104Want[i])
	}
}

// All vectors sent in one segment decode as one layer each.
func TestIEC104Segment(t *testing.T) {
	segment := bytes.Join(iec104Vectors, nil)
	p := gopacket.NewPacket(segment, LayerTypeIEC104, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer().Error())
	}

	apdus := p.Layers()
	if len(apdus) != len(iec104Want) {
		t.Fatalf("got %d layers, want %d", len(apdus), len(iec104Want))
	}
	for i, l := range apdus {
		iec104Check(t, fmt.Sprintf("layer %d", i), l.(*IEC104), iec104Want[i])
	}

	// A DecodingLayerParser keeps the first APDU, the rest as payload.
	var apdu IEC104
	parser := gopacket.NewDecodingLayerParser(LayerTypeIEC104, &apdu)
	var decoded []gopacket.LayerType
	if err := parser.DecodeLayers(segment, &decoded); err != nil {
		t.Fatal(err)
	}
	if apdu.SendSeq != 1 || !bytes.Equal(apdu.Payload, segment[len(iec104Vectors[0]):]) {
		t.Errorf("parser got N(S) %d, payload %d octets", apdu.SendSeq, len(apdu.Payload))
	}
}

func TestIEC104Strings(t *testing.T) {
	tests := []struct {
		got  fmt.Stringer
		want string
	}{
		{IEC104TypeFloatTime56, "M_ME_TF_1"},
		{IEC104TypeQueryLog, "F_SC_NB_1"},
		{IEC104TypeID(81), "S_CH_NA_1"},
		{IEC104TypeSecurityStatistics, "S_IT_TC_1"},
		{IEC104TypeID(200), "Unknown(200)"},
		{IEC104CauseInterrogated, "Inrogen"},
		{IEC104Cause(23), "Inro3"},
		{IEC104Cause(40), "Reqco3"},
		{IEC104Cause(60), "Unknown(60)"},
		{IEC104QualityBlocked | IEC104QualityInvalid, "BL|IV"},
		{IEC104Quality(0), "OK"},
		{IEC104StartDTCon, "STARTDT con"},
		{IEC104FormatS, "S"},
		{IEC104DoublePointOff, "Off"},
	}
	for _, tt := range tests {
		if s := tt.got.String(); s != tt.want {
			t.Errorf("got %q, want %q", s, tt.want)
		}
	}
}

func TestIEC104Time(t *testing.T) {
	want := time.Date(2026, time.November, 19, 15, 34, 12, 345000000, time.UTC)
	if got := iec104T.Time(nil); !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}

	loc := time.FixedZone("NZDT", 13*3600)
	if got := iec104T.Time(loc); !got.Equal(want.Add(-13 * time.Hour)) {
		t.Errorf("in %v got %v", loc, got)
	}

	cp24 := IEC104Time{Format: IEC104TimeCP24, Milliseconds: 1, Minute: 2}
	if !cp24.Time(nil).IsZero() {
		t.Error("CP24Time2a gave a date")
	}

	nva := IEC104Object{Normalized: -32768}
	if nva.NormalizedValue() != -1 {
		t.Errorf("NVA -32768 is %v", nva.NormalizedValue())
	}
}

// iec104Summary renders the APDUs of a packet like a golden line.
func iec104Summary(p gopacket.Packet) string {
	var cols [8][]string
	add := func(i int, v interface{}) {
		cols[i] = append(cols[i], fmt.Sprint(v))
	}

	for _, l := range p.Layers() {
		a, ok := l.(*IEC104)
		if !ok {
			continue
		}
		add(0, uint8(a.Format))
		switch a.Format {
		case IEC104FormatU:
			add(3, uint8(a.UFunction)>>2)
			continue
		case IEC104FormatS:
			add(2, a.RecvSeq)
			continue
		}

		add(1, a.SendSeq)
		add(2, a.RecvSeq)
		add(4, uint8(a.ASDU.TypeID))
		add(5, uint8(a.ASDU.Cause))
		add(6, a.ASDU.NumObjects)
		for _, o := range a.ASDU.Objects {
			add(7, o.IOA)
		}
	}

	var out []string
	for _, c := range cols {
		out = append(out, strings.Join(c, ","))
	}
	return strings.Join(out, ";")
}

// iec104ReadPcap reads the frames of a test capture.
func iec104ReadPcap(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r, err := newSimplePcapReader(f)
	if err != nil {
		return nil, err
	}

	var packets [][]byte
	for {
		data, err := r.readPacketData()
		if err == io.EOF {
			return packets, nil
		}
		if err != nil {
			return nil, err
		}
		packets = append(packets, data)
	}
}

// iec104Packets reads a test capture or fails the test.
func iec104Packets(t *testing.T, path string) [][]byte {
	t.Helper()

	packets, err := iec104ReadPcap(path)
	if err != nil {
		t.Fatal(err)
	}
	return packets
}

// Every frame of the captures decodes as tshark decodes it.
func TestIEC104Pcap(t *testing.T) {
	registerIEC104Decoders()

	for _, tc := range []struct {
		path   string
		golden []string
	}{
		{"testdata/iec104.pcap", iec104Golden},
		{"testdata/iec104_sq.pcap", iec104SQGolden},
	} {
		packets := iec104Packets(t, tc.path)
		if len(packets) != len(tc.golden) {
			t.Fatalf("%s: %d packets, want %d", tc.path, len(packets), len(tc.golden))
		}

		for i, data := range packets {
			p := gopacket.NewPacket(data, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
			if p.ErrorLayer() != nil {
				t.Errorf("%s frame %d: %v", tc.path, i+1, p.ErrorLayer().Error())
			}
			if got := iec104Summary(p); got != tc.golden[i] {
				t.Errorf("%s frame %d:\n got %s\nwant %s", tc.path, i+1, got, tc.golden[i])
			}
		}
	}
}

// Spot checks of values in testdata/iec104.pcap, as tshark shows them.
func TestIEC104PcapValues(t *testing.T) {
	registerIEC104Decoders()
	packets := iec104Packets(t, "testdata/iec104.pcap")

	// iec104At returns APDU n of frame f, both counted from 1.
	iec104At := func(f, n int) *IEC104 {
		p := gopacket.NewPacket(packets[f-1], LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
		var apdus []*IEC104
		for _, l := range p.Layers() {
			if a, ok := l.(*IEC104); ok {
				apdus = append(apdus, a)
			}
		}
		if n > len(apdus) {
			t.Fatalf("frame %d has %d APDUs", f, len(apdus))
		}
		return apdus[n-1]
	}

	// Frame 9: C_IC_NA_1 Act, QOI 20 (station interrogation).
	if a := iec104At(9, 1); a.ASDU.TypeID != IEC104TypeInterrogation || a.ASDU.Objects[0].Qualifier != 20 {
		t.Errorf("frame 9: %+v", a.ASDU)
	}

	// Frame 25, third APDU: M_SP_TB_1 Spont IOA 13, on, 2013-07-04 08:23:24.007.
	a := iec104At(25, 3)
	o := a.ASDU.Objects[0]
	want := time.Date(2013, time.July, 4, 8, 23, 24, 7000000, time.UTC)
	if a.ASDU.TypeID != IEC104TypeSinglePointTime56 || o.IOA != 13 || !o.SinglePoint || !o.Time.Time(nil).Equal(want) {
		t.Errorf("frame 25: %+v, time %v", o, o.Time.Time(nil))
	}

	// Frame 10: M_EI_NA_1 Init, COI 0.
	if a := iec104At(10, 1); a.ASDU.TypeID != IEC104TypeEndOfInit || a.ASDU.Cause != IEC104CauseInitialized {
		t.Errorf("frame 10: %+v", a.ASDU)
	}
}

// Every prefix of every vector and capture payload decodes without panic,
// and a prefix cut inside an APDU never decodes as complete.
func TestIEC104Truncated(t *testing.T) {
	inputs := append([][]byte{bytes.Join(iec104Vectors, nil)}, iec104Vectors...)
	for _, v := range inputs {
		for n := 0; n < len(v); n++ {
			var apdu IEC104
			df := &iec104Feedback{}
			err := apdu.DecodeFromBytes(v[:n], df)
			if n < 2+int(v[1]) && err == nil {
				t.Errorf("%x cut to %d decoded", v[:6], n)
			}
			if errors.Is(err, ErrIEC104TooShort) && !df.truncated {
				t.Errorf("%x cut to %d: truncation not flagged", v[:6], n)
			}
			gopacket.NewPacket(v[:n], LayerTypeIEC104, gopacket.Default)
		}
	}
}

type iec104Feedback struct {
	truncated bool
}

func (f *iec104Feedback) SetTruncated() {
	f.truncated = true
}

func TestIEC104Malformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"no start octet", []byte{0x69, 0x04, 0x01, 0x00, 0x00, 0x00}, ErrIEC104BadStart},
		{"length under control field", []byte{0x68, 0x03, 0x01, 0x00, 0x00, 0x00}, ErrIEC104BadLength},
		{"length past data", []byte{0x68, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x01}, ErrIEC104TooShort},
		{"S-format with ASDU", []byte{0x68, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00}, ErrIEC104BadLength},
		{"I-format without DUI", []byte{0x68, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01}, ErrIEC104ASDUTooShort},
		// 127 single points claimed, one present.
		{"object count past data", []byte{0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7f, 0x03, 0x00,
			0x01, 0x00, 0x01, 0x00, 0x00, 0x01}, ErrIEC104ObjectsTooLong},
		// 127 SQ single points claimed, three present.
		{"SQ count past data", []byte{0x68, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x03, 0x00,
			0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01}, ErrIEC104ObjectsTooLong},
		// 127 C_RD_NA_1 objects from one address: no octets behind them.
		{"SQ without elements", []byte{0x68, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x66, 0xff, 0x05, 0x00,
			0x01, 0x00, 0x01, 0x00, 0x00}, ErrIEC104BadSequence},
		// A segment of 0xff octets claimed, two present.
		{"segment length past data", []byte{0x68, 0x13, 0x00, 0x00, 0x00, 0x00, 0x7d, 0x01, 0x0d, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xff, 0xaa, 0xbb}, ErrIEC104ObjectsTooLong},
	}
	for _, tt := range tests {
		var apdu IEC104
		if err := apdu.DecodeFromBytes(tt.data, gopacket.NilDecodeFeedback); !errors.Is(err, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, err, tt.want)
		}
		p := gopacket.NewPacket(tt.data, LayerTypeIEC104, gopacket.Default)
		if p.ErrorLayer() == nil {
			t.Errorf("%s: packet decoded without error", tt.name)
		}
	}

	// A bad first ASDU keeps its valid APCI as a layer, then the error.
	for _, tt := range tests[4:] {
		p := gopacket.NewPacket(tt.data, LayerTypeIEC104, gopacket.Default)
		apdu, _ := p.Layer(LayerTypeIEC104).(*IEC104)
		if apdu == nil || apdu.Format != IEC104FormatI || len(apdu.Contents) != len(tt.data) {
			t.Errorf("%s: APCI layer not kept: %v", tt.name, p.Layers())
		}
		if e := p.ErrorLayer(); e == nil || !errors.Is(e.Error(), tt.want) {
			t.Errorf("%s: error layer %v, want %v", tt.name, e, tt.want)
		}
	}

	// An APDU cut short after a good one is a layer flagged truncated,
	// then the error, and the packet is flagged truncated.
	good := iec104Vectors[len(iec104Vectors)-1]
	cut := []byte{0x68, 0x04, 0x01}
	p := gopacket.NewPacket(append(append([]byte{}, good...), cut...), LayerTypeIEC104, gopacket.Default)
	e := p.ErrorLayer()
	if e == nil || !errors.Is(e.Error(), ErrIEC104TooShort) || len(p.Layers()) != 3 || !p.Metadata().Truncated {
		t.Fatalf("trailing fragment: %v", p.Layers())
	}
	if l := p.Layers()[1].(*IEC104); l.Faults != IEC104FaultTruncated || !bytes.Equal(l.Contents, cut) {
		t.Errorf("trailing fragment: %+v", l)
	}

	// A start octet with a length that cannot be between good APDUs is
	// garbage: the APDU after it counts it as skipped.
	broken := []byte{0x68, 0x02, 0x00, 0x00, 0x00, 0x00}
	p = gopacket.NewPacket(bytes.Join([][]byte{good, broken, good}, nil), LayerTypeIEC104, gopacket.Default)
	if p.ErrorLayer() != nil || len(p.Layers()) != 2 {
		t.Fatalf("broken middle APDU: %v", p.Layers())
	}
	if l := p.Layers()[1].(*IEC104); l.Skipped != len(broken) || !bytes.Equal(l.Contents, good) {
		t.Errorf("broken middle APDU: %+v", l)
	}

	// A middle APDU with a valid APCI and a bad ASDU keeps its layer, and
	// the APDU after it is decoded too.
	bad := tests[5].data
	p = gopacket.NewPacket(bytes.Join([][]byte{good, bad, good}, nil), LayerTypeIEC104, gopacket.Default)
	e = p.ErrorLayer()
	if e == nil || !errors.Is(e.Error(), tests[5].want) || len(p.Layers()) != 4 ||
		!bytes.Equal(p.Layers()[1].LayerContents(), bad) || !bytes.Equal(p.Layers()[2].LayerContents(), good) {
		t.Fatalf("bad middle ASDU: %v", p.Layers())
	}
	if l := p.Layers()[1].(*IEC104); l.Faults != IEC104FaultASDU {
		t.Errorf("bad middle ASDU: %+v", l)
	}
}

// Decoding into a reused layer clears what the previous APDU set.
func TestIEC104Reuse(t *testing.T) {
	var apdu IEC104
	if err := apdu.DecodeFromBytes(iec104Vectors[1], gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}

	// An S-format frame leaves no ASDU or N(S) behind.
	if err := apdu.DecodeFromBytes(iec104Vectors[len(iec104Vectors)-2], gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	iec104Check(t, "S after I", &apdu, iec104Want[len(iec104Want)-2])

	// Objects reuse their slice and are replaced, not appended to.
	if err := apdu.DecodeFromBytes(iec104Vectors[0], gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	iec104Check(t, "I after S", &apdu, iec104Want[0])
}

func FuzzIEC104(f *testing.F) {
	for _, v := range iec104Vectors {
		f.Add(v)
	}
	f.Add(bytes.Join(iec104Vectors, nil))
	for _, tc := range []string{"testdata/iec104.pcap", "testdata/iec104_sq.pcap"} {
		packets, err := iec104ReadPcap(tc)
		if err != nil {
			f.Fatal(err)
		}
		for _, data := range packets {
			const tcpPayload = 54 // Ethernet, IPv4 and TCP headers without options
			if len(data) > tcpPayload {
				f.Add(data[tcpPayload:])
			}
		}
	}

	for _, data := range iec104Handmade(f) {
		f.Add(data)
		f.Add(data[iec104APCILen:])
	}

	sizes := []IEC104ASDUOptions{{}, {COTSize: 1, CommonAddrSize: 1, IOASize: 2}, {COTSize: 1, CommonAddrSize: 2, IOASize: 1}}
	assembler := IEC104SecurityAssembler{MaxSize: 1 << 10}

	f.Fuzz(func(t *testing.T, data []byte) {
		// The ASDU alone, under each set of field sizes: what it holds
		// fits the input, and the accessors take any value.
		for _, opts := range sizes {
			var a IEC104ASDU
			if err := a.DecodeWithOptions(data, opts); err != nil {
				continue
			}
			iec104Bounded(t, &a, data)

			x := iec104Dump{}
			x.asdu(&a)
			_ = x.String()

			if body, err := assembler.Add(&a.Security); err == nil && body != nil {
				var s IEC104Security
				_, _ = s.DecodeBody(a.TypeID, body, opts)
			}
			if len(assembler.body) > assembler.MaxSize {
				t.Fatalf("assembler holds %d octets", len(assembler.body))
			}
		}

		var apdu IEC104
		if err := apdu.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
			if len(apdu.Contents) != 2+int(apdu.Length) {
				t.Fatalf("contents %d octets for length %d", len(apdu.Contents), apdu.Length)
			}
			if _, known := iec104Types[apdu.ASDU.TypeID]; known && apdu.Format == IEC104FormatI &&
				len(apdu.ASDU.Objects) != int(apdu.ASDU.NumObjects) {
				t.Fatalf("%d objects for count %d", len(apdu.ASDU.Objects), apdu.ASDU.NumObjects)
			}
		}
		gopacket.NewPacket(data, LayerTypeIEC104, gopacket.Default)
	})
}
