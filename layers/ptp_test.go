// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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

// The ptpGolden* tables are tshark 4.7 ground truth for the PTP test
// captures, one line per frame:
// "type;seq;domain;flags;correction_ns;clock;port;length;seconds;ns;tlvtypes".

// ptpGoldenWireshark is for ptpv2.pcap, from the Wireshark wiki.
var ptpGoldenWireshark = []string{
	"2;1118;0;0;0;008063ffff0009ba;2;54;1169232201;474052852;",
	"0;1085;0;0;0;008063ffff0009ba;2;44;1169232201;775045731;",
	"11;542;0;12;0;008063ffff0009ba;2;64;1169232201;775959131;",
	"2;1119;0;0;0;008063ffff0009ba;2;54;1169232202;173773091;",
	"2;1120;0;0;0;008063ffff0009ba;2;54;1169232202;674007861;",
	"0;1086;0;0;0;008063ffff0009ba;2;44;1169232202;774748600;",
	"0;1087;0;0;0;008063ffff0009ba;2;44;1169232203;774735169;",
	"11;543;0;12;0;008063ffff0009ba;2;64;1169232203;775642089;",
	"2;1121;0;0;0;008063ffff0009ba;2;54;1169232204;73724469;",
	"0;1088;0;0;0;008063ffff0009ba;2;44;1169232204;774943959;",
	"2;1122;0;0;0;008063ffff0009ba;2;54;1169232204;874765628;",
	"0;1089;0;0;0;008063ffff0009ba;2;44;1169232205;774697008;",
	"11;544;0;12;0;008063ffff0009ba;2;64;1169232205;775609868;",
	"2;1123;0;0;0;008063ffff0009ba;2;54;1169232205;873666148;",
	"2;40520;0;0;0;008063ffff0009ba;1;54;1169232209;74643905;",
	"2;40521;0;0;0;008063ffff0009ba;1;54;1169232209;673581884;",
	"2;40522;0;0;0;008063ffff0009ba;1;54;1169232210;173828684;",
	"2;40523;0;0;0;008063ffff0009ba;1;54;1169232210;673567483;",
	"2;40524;0;0;0;008063ffff0009ba;1;54;1169232212;73497880;",
	"2;40525;0;0;0;008063ffff0009ba;1;54;1169232213;73500431;",
	"2;40526;0;0;0;008063ffff0009ba;1;54;1169232213;773744420;",
	"2;40527;0;0;0;008063ffff0009ba;1;54;1169232214;273457600;",
	"2;40528;0;0;0;008063ffff0009ba;1;54;1169232215;73421199;",
	"2;40529;0;0;0;008063ffff0009ba;1;54;1169232216;373402228;",
	"0;115;0;0;0;008063ffff0009ba;1;44;1169232217;174421797;",
	"2;40530;0;0;0;008063ffff0009ba;1;54;1169232217;573396197;",
	"0;116;0;0;0;008063ffff0009ba;1;44;1169232218;174389936;",
	"11;58;0;12;0;008063ffff0009ba;1;64;1169232218;175326816;",
	"2;40531;0;0;0;008063ffff0009ba;1;54;1169232218;973336521;",
	"0;117;0;0;0;008063ffff0009ba;1;44;1169232219;174623365;",
	"2;40532;0;0;0;008063ffff0009ba;1;54;1169232219;573331005;",
	"0;118;0;0;0;008063ffff0009ba;1;44;1169232220;174377504;",
	"11;59;0;12;0;008063ffff0009ba;1;64;1169232220;175300904;",
	"2;40533;0;0;0;008063ffff0009ba;1;54;1169232220;773282804;",
	"0;119;0;0;0;008063ffff0009ba;1;44;1169232221;174308853;",
	"2;40534;0;0;0;008063ffff0009ba;1;54;1169232221;373258293;",
	"2;40535;0;0;0;008063ffff0009ba;1;54;1169232222;73257582;",
	"0;120;0;0;0;008063ffff0009ba;1;44;1169232222;174537162;",
	"11;60;0;12;0;008063ffff0009ba;1;64;1169232222;175459752;",
}

// ptpGoldenTcpdump is for ptp_tcpdump.pcap, from the tcpdump tests.
var ptpGoldenTcpdump = []string{
	"1;132;0;0;0;7cfe90fffef950b4;1;44;0;0;",
	"9;132;0;0;0;000200fffe000001;1;54;1516736649;248292005;",
	"11;534;0;0;0;000200fffe000001;1;64;0;0;",
	"0;1067;0;512;0;000200fffe000001;1;44;0;0;",
	"8;1067;0;0;0;000200fffe000001;1;44;1516736650;34751783;",
}

// ptpGoldenManagement is for ptp_tcpdump_management.pcap.
var ptpGoldenManagement = []string{
	"13;0;0;0;0;000000fffe000011;1;72;;;1",
	"13;0;0;0;0;000000fffe000012;1;72;;;1",
	"13;0;0;0;0;000000fffe000011;1;80;;;1",
	"13;0;0;0;0;000000fffe000012;1;80;;;1",
	"13;0;0;0;0;000000fffe000011;1;74;;;1",
	"13;0;0;0;0;000000fffe000012;1;74;;;1",
	"13;0;0;0;0;000000fffe000011;1;86;;;1",
	"13;0;0;0;0;000000fffe000012;1;86;;;1",
	"13;0;0;0;0;000000fffe000011;1;76;;;1",
	"13;0;0;0;0;000000fffe000012;1;102;;;1",
}

// ptpGoldenV21 is for ptp_tcpdump_v2_1.pcap, PTP version 2.1.
var ptpGoldenV21 = []string{
	"0;690;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;690;0;0;0;38f3abfffe96ec12;1;44;1689274220;141087131;",
	"2;697;0;0;0;38f3abfffe96ec12;1;54;0;0;",
	"11;346;0;8;0;38f3abfffe96ec12;1;64;0;0;",
	"0;691;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;691;0;0;0;38f3abfffe96ec12;1;44;1689274221;139650073;",
	"2;698;0;0;0;38f3abfffe96ec12;1;54;0;0;",
	"0;692;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;692;0;0;0;38f3abfffe96ec12;1;44;1689274222;138235505;",
	"2;699;0;0;0;38f3abfffe96ec12;1;54;0;0;",
	"11;347;0;8;0;38f3abfffe96ec12;1;64;0;0;",
	"0;693;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;693;0;0;0;38f3abfffe96ec12;1;44;1689274223;136790595;",
	"2;700;0;0;0;38f3abfffe96ec12;1;54;0;0;",
	"0;694;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;694;0;0;0;38f3abfffe96ec12;1;44;1689274224;135367681;",
	"2;701;0;0;0;38f3abfffe96ec12;1;54;0;0;",
	"11;348;0;8;0;38f3abfffe96ec12;1;64;0;0;",
	"0;695;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;695;0;0;0;38f3abfffe96ec12;1;44;1689274225;133933535;",
	"2;702;0;0;0;38f3abfffe96ec12;1;54;0;0;",
	"0;696;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;696;0;0;0;38f3abfffe96ec12;1;44;1689274226;132490523;",
	"2;703;0;0;0;38f3abfffe96ec12;1;54;0;0;",
	"11;349;0;8;0;38f3abfffe96ec12;1;64;0;0;",
	"0;697;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;697;0;0;0;38f3abfffe96ec12;1;44;1689274227;131069455;",
	"2;704;0;0;0;38f3abfffe96ec12;1;54;0;0;",
	"0;698;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;698;0;0;0;38f3abfffe96ec12;1;44;1689274228;129632683;",
	"2;705;0;0;0;38f3abfffe96ec12;1;54;0;0;",
	"11;350;0;8;0;38f3abfffe96ec12;1;64;0;0;",
	"0;699;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;699;0;0;0;38f3abfffe96ec12;1;44;1689274229;128232389;",
	"2;706;0;0;0;38f3abfffe96ec12;1;54;0;0;",
	"0;700;0;512;0;38f3abfffe96ec12;1;44;0;0;",
	"8;700;0;0;0;38f3abfffe96ec12;1;44;1689274230;126823307;",
	"2;707;0;0;0;38f3abfffe96ec12;1;54;0;0;",
}

// ptpGoldenCorrections is for ptp_tcpdump_corrections.pcap.
var ptpGoldenCorrections = []string{
	"1;1203;44;1024;0;a0369ffffe856e8a;1;44;0;0;",
	"9;1203;44;1024;36035;e8c57affff01313f;3;54;1665510783;679015501;",
	"0;1213;44;1024;105045;e8c57affff01313f;3;44;1665510783;681548698;",
}

// ptpVectorHex are hand-built PTPv2 messages, checked against tshark 4.7
// over UDP. They cover the message types the captures lack.
var ptpVectorHex = []string{
	// Pdelay_Resp, IEEE 802.1AS, twoStep|ptpTimescale.
	"1302003600000208000000000000000000000000001b19fffe0009ba00011234057f" +
		"0000691de374075bcd15008063fffe1234560002",
	// Pdelay_Resp_Follow_Up.
	"1a02003600000008000000000000000000000000001b19fffe0009ba00011234057f" +
		"0000691de374076416ff008063fffe1234560002",
	// Signaling: REQUEST_UNICAST_TRANSMISSION of Announce for 300 s, then
	// CANCEL_UNICAST_TRANSMISSION.
	"0c02003c00000400000000000000000000000000001b19fffe0009ba00010007057f" +
		"ffffffffffffffffffff" + "00040006b0010000012c" + "00060002b000",
	// Management RESPONSE, MANAGEMENT_ERROR_STATUS NO_SUCH_ID for
	// CURRENT_DATA_SET.
	"0d02003e00000000000000000000000000000000001b19fffe0009ba00010009047f" +
		"ffffffffffffffffffff01010200" + "0002000a00022001000000000000",
	// Announce with a PATH_TRACE TLV.
	"0b02004c0000000c000000000000000000000000001b19fffe0009ba0001002a0501" +
		"000000000000000000000025008006214e5d80001b19fffe0009ba000120" +
		"00080008001b19fffe0009ba",
	// Follow_Up, IEEE 802.1AS, correction -10 ns, Follow_Up information TLV.
	"1802004c00000008fffffffffff6000000000000001b19fffe0009ba0001002b02fd" +
		"0000691de37400000005" +
		"0003001c0080c200000100000000000000000000000000000000000000000000",
}

var (
	ptpClock = PTPClockIdentity{0x00, 0x1b, 0x19, 0xff, 0xfe, 0x00, 0x09, 0xba}
	ptpPeer  = PTPPortIdentity{ClockIdentity: PTPClockIdentity{0x00, 0x80, 0x63, 0xff, 0xfe, 0x12, 0x34, 0x56}, PortNumber: 2}
	ptpAll   = PTPPortIdentity{ClockIdentity: PTPClockIdentity{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, PortNumber: 0xffff}
	ptpSrc   = PTPPortIdentity{ClockIdentity: ptpClock, PortNumber: 1}
)

// ptpWant is the decoded form of ptpVectorHex, BaseLayer left out.
var ptpWant = []PTP{
	{MajorSdoID: 1, MessageType: PTPMessagePdelayResp, Version: 2, MessageLength: 54,
		Flags: PTPFlagTwoStep | PTPFlagPTPTimescale, SourcePort: ptpSrc, SequenceID: 0x1234,
		Control: PTPControlOther, LogMessageInterval: 0x7f,
		Timestamp: PTPTimestamp{Seconds: 1763566452, Nanoseconds: 123456789}, RequestingPort: ptpPeer},
	{MajorSdoID: 1, MessageType: PTPMessagePdelayRespFollowUp, Version: 2, MessageLength: 54,
		Flags: PTPFlagPTPTimescale, SourcePort: ptpSrc, SequenceID: 0x1234,
		Control: PTPControlOther, LogMessageInterval: 0x7f,
		Timestamp: PTPTimestamp{Seconds: 1763566452, Nanoseconds: 123999999}, RequestingPort: ptpPeer},
	{MessageType: PTPMessageSignaling, Version: 2, MessageLength: 60, Flags: PTPFlagUnicast,
		SourcePort: ptpSrc, SequenceID: 7, Control: PTPControlOther, LogMessageInterval: 0x7f,
		TargetPort: ptpAll, TLVs: []PTPTLV{
			{Type: PTPTLVRequestUnicast, Length: 6, Value: []byte{0xb0, 0x01, 0x00, 0x00, 0x01, 0x2c}},
			{Type: PTPTLVCancelUnicast, Length: 2, Value: []byte{0xb0, 0x00}},
		}},
	{MessageType: PTPMessageManagement, Version: 2, MessageLength: 62, SourcePort: ptpSrc,
		SequenceID: 9, Control: PTPControlManagement, LogMessageInterval: 0x7f, TargetPort: ptpAll,
		Management: PTPManagement{StartingBoundaryHops: 1, BoundaryHops: 1, Action: PTPActionResponse,
			ID: PTPMgmtCurrentDataSet, Error: PTPMgmtErrNoSuchID},
		TLVs: []PTPTLV{{Type: PTPTLVManagementErrorStatus, Length: 10,
			Value: []byte{0x00, 0x02, 0x20, 0x01, 0, 0, 0, 0, 0, 0}}}},
	{MessageType: PTPMessageAnnounce, Version: 2, MessageLength: 76,
		Flags: PTPFlagPTPTimescale | PTPFlagUTCOffsetValid, SourcePort: ptpSrc, SequenceID: 42,
		Control: PTPControlOther, LogMessageInterval: 1,
		Announce: PTPAnnounce{CurrentUTCOffset: 37, GrandmasterPriority1: 128,
			GrandmasterClockQuality: PTPClockQuality{Class: 6, Accuracy: PTPAccuracy100ns, OffsetScaledLogVariance: 0x4e5d},
			GrandmasterPriority2:    128, GrandmasterIdentity: ptpClock, StepsRemoved: 1, TimeSource: PTPTimeSourceGNSS},
		TLVs: []PTPTLV{{Type: PTPTLVPathTrace, Length: 8, Value: ptpClock[:]}}},
	{MajorSdoID: 1, MessageType: PTPMessageFollowUp, Version: 2, MessageLength: 76,
		Flags: PTPFlagPTPTimescale, Correction: -10 << 16, SourcePort: ptpSrc, SequenceID: 43,
		Control: PTPControlFollowUp, LogMessageInterval: -3,
		Timestamp: PTPTimestamp{Seconds: 1763566452, Nanoseconds: 5},
		TLVs: []PTPTLV{{Type: PTPTLVOrganizationExtension, Length: 28,
			Value: append([]byte{0x00, 0x80, 0xc2, 0x00, 0x00, 0x01}, make([]byte, 22)...)}}},
}

// ptpVectors decodes ptpVectorHex.
func ptpVectors(tb testing.TB) [][]byte {
	tb.Helper()

	var out [][]byte
	for _, h := range ptpVectorHex {
		b, err := hex.DecodeString(h)
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func TestPTPVectors(t *testing.T) {
	for i, v := range ptpVectors(t) {
		var got PTP
		if err := got.DecodeFromBytes(v, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("vector %d: %v", i, err)
			continue
		}
		if !bytes.Equal(got.Contents, v) || len(got.Payload) != 0 {
			t.Errorf("vector %d: contents %x payload %x", i, got.Contents, got.Payload)
		}

		got.BaseLayer = BaseLayer{}
		if len(got.TLVs) == 0 {
			got.TLVs = nil
		}
		if !reflect.DeepEqual(got, ptpWant[i]) {
			t.Errorf("vector %d:\n got %+v\nwant %+v", i, got, ptpWant[i])
		}
	}
}

func TestPTPHelpers(t *testing.T) {
	ts := PTPTimestamp{Seconds: 1763566452, Nanoseconds: 123456789}
	if want := time.Unix(1763566452, 123456789).UTC(); !ts.Time().Equal(want) {
		t.Errorf("time %v, want %v", ts.Time(), want)
	}

	p := PTP{Correction: -10<<16 - 1<<15}
	if p.CorrectionNs() != -10.5 {
		t.Errorf("correction %v ns", p.CorrectionNs())
	}

	tests := []struct {
		got  fmt.Stringer
		want string
	}{
		{PTPMessagePdelayRespFollowUp, "Pdelay_Resp_Follow_Up"},
		{PTPMessageType(5), "Unknown(5)"},
		{PTPFlagTwoStep | PTPFlagPTPTimescale, "twoStep|ptpTimescale"},
		{PTPFlags(0), "none"},
		{ptpClock, "00:1b:19:ff:fe:00:09:ba"},
		{PTPAccuracy100ns, "100ns"},
		{PTPTimeSourceGNSS, "GNSS"},
		{PTPTLVPathTrace, "PATH_TRACE"},
		{PTPMgmtCurrentDataSet, "CURRENT_DATA_SET"},
		{PTPMgmtErrNoSuchID, "NO_SUCH_ID"},
		{PTPActionResponse, "RESPONSE"},
		{PTPControlFollowUp, "Follow_Up"},
	}
	for _, tt := range tests {
		if s := tt.got.String(); s != tt.want {
			t.Errorf("got %q, want %q", s, tt.want)
		}
	}
}

// ptpSummary renders the PTP layer of a packet like a golden line.
func ptpSummary(p gopacket.Packet) string {
	m, ok := p.Layer(LayerTypePTP).(*PTP)
	if !ok {
		return ""
	}

	var sec, ns, tlvs []string
	if _, timed := ptpBodyLen[m.MessageType]; timed &&
		m.MessageType != PTPMessageSignaling && m.MessageType != PTPMessageManagement {
		sec = append(sec, fmt.Sprint(m.Timestamp.Seconds))
		ns = append(ns, fmt.Sprint(m.Timestamp.Nanoseconds))
	}
	for _, tlv := range m.TLVs {
		tlvs = append(tlvs, fmt.Sprint(uint16(tlv.Type)))
	}

	return strings.Join([]string{
		fmt.Sprint(uint8(m.MessageType)), fmt.Sprint(m.SequenceID), fmt.Sprint(m.Domain),
		fmt.Sprint(uint16(m.Flags)), fmt.Sprint(m.Correction >> 16),
		hex.EncodeToString(m.SourcePort.ClockIdentity[:]), fmt.Sprint(m.SourcePort.PortNumber),
		fmt.Sprint(m.MessageLength), strings.Join(sec, ""), strings.Join(ns, ""), strings.Join(tlvs, ","),
	}, ";")
}

// ptpReadPcap reads the frames of a test capture.
func ptpReadPcap(path string) ([][]byte, error) {
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

// ptpCaptures are the test captures with their tshark ground truth.
var ptpCaptures = []struct {
	path   string
	golden []string
}{
	{"testdata/ptpv2.pcap", ptpGoldenWireshark},
	{"testdata/ptp_tcpdump.pcap", ptpGoldenTcpdump},
	{"testdata/ptp_tcpdump_management.pcap", ptpGoldenManagement},
	{"testdata/ptp_tcpdump_v2_1.pcap", ptpGoldenV21},
	{"testdata/ptp_tcpdump_corrections.pcap", ptpGoldenCorrections},
}

// Every frame of the captures, over UDP and over Ethernet, decodes as
// tshark decodes it.
func TestPTPPcap(t *testing.T) {
	registerPTPDecoders()

	for _, tc := range ptpCaptures {
		packets, err := ptpReadPcap(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if len(packets) != len(tc.golden) {
			t.Fatalf("%s: %d packets, want %d", tc.path, len(packets), len(tc.golden))
		}

		for i, data := range packets {
			p := gopacket.NewPacket(data, LinkTypeEthernet, gopacket.Default)
			if p.ErrorLayer() != nil {
				t.Errorf("%s frame %d: %v", tc.path, i+1, p.ErrorLayer().Error())
			}
			if got := ptpSummary(p); got != tc.golden[i] {
				t.Errorf("%s frame %d:\n got %s\nwant %s", tc.path, i+1, got, tc.golden[i])
			}
		}
	}
}

// Spot checks of the Announce and Management fields in the captures.
func TestPTPPcapValues(t *testing.T) {
	registerPTPDecoders()

	packets, err := ptpReadPcap("testdata/ptpv2.pcap")
	if err != nil {
		t.Fatal(err)
	}

	// Frame 3: Announce over Ethernet.
	p := gopacket.NewPacket(packets[2], LinkTypeEthernet, gopacket.Default)
	m := p.Layer(LayerTypePTP).(*PTP)
	a := m.Announce
	if a.GrandmasterPriority1 != 96 || a.GrandmasterClockQuality.Class != 0 ||
		a.GrandmasterClockQuality.Accuracy != 0 || a.TimeSource != 0x80 {
		t.Errorf("frame 3 announce: %+v", a)
	}

	packets, err = ptpReadPcap("testdata/ptp_tcpdump_management.pcap")
	if err != nil {
		t.Fatal(err)
	}

	// Frame 2: RESPONSE to a CURRENT_DATA_SET GET.
	p = gopacket.NewPacket(packets[1], LinkTypeEthernet, gopacket.Default)
	m = p.Layer(LayerTypePTP).(*PTP)
	if m.Management.Action != PTPActionResponse || m.Management.ID != PTPMgmtCurrentDataSet {
		t.Errorf("frame 2 management: %+v", m.Management)
	}
}

// Every prefix of every vector and capture message decodes without
// panic, and a prefix cut inside a message never decodes as complete.
func TestPTPTruncated(t *testing.T) {
	inputs := ptpVectors(t)
	for _, tc := range ptpCaptures {
		packets, err := ptpReadPcap(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, packets...)
	}

	for _, v := range inputs {
		for n := 0; n < len(v); n++ {
			gopacket.NewPacket(v[:n], LinkTypeEthernet, gopacket.Default)
			gopacket.NewPacket(v[:n], LayerTypePTP, gopacket.Default)
		}
	}

	for i, v := range ptpVectors(t) {
		for n := 0; n < len(v); n++ {
			var m PTP
			df := &ptpFeedback{}
			err := m.DecodeFromBytes(v[:n], df)
			if err == nil {
				t.Errorf("vector %d cut to %d decoded", i, n)
			}
			if errors.Is(err, ErrPTPTooShort) != df.truncated {
				t.Errorf("vector %d cut to %d: %v, truncated %v", i, n, err, df.truncated)
			}
		}
	}
}

type ptpFeedback struct {
	truncated bool
}

func (f *ptpFeedback) SetTruncated() {
	f.truncated = true
}

// ptpWithLength returns vector i with messageLength set to n.
func ptpWithLength(t *testing.T, i int, n uint16) []byte {
	v := ptpVectors(t)[i]
	binary.BigEndian.PutUint16(v[2:4], n)
	return v
}

func TestPTPMalformed(t *testing.T) {
	v1 := ptpVectors(t)[0]
	v1[1] = 0x01

	// The Signaling vector with its first TLV length raised past the message.
	tlv := ptpVectors(t)[2]
	binary.BigEndian.PutUint16(tlv[46:48], 100)

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"version 1", v1, ErrPTPVersion},
		{"length under header", ptpWithLength(t, 0, 33), ErrPTPBadLength},
		{"length under body", ptpWithLength(t, 0, 44), ErrPTPBadLength},
		{"length past data", ptpWithLength(t, 0, 0xffff), ErrPTPTooShort},
		{"TLV past message", tlv, ErrPTPBadTLV},
	}
	for _, tt := range tests {
		var m PTP
		if err := m.DecodeFromBytes(tt.data, gopacket.NilDecodeFeedback); !errors.Is(err, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, err, tt.want)
		}
	}

	// Octets past messageLength are payload, not TLVs.
	padded := append(ptpVectors(t)[0], 0, 0, 0, 0, 0, 0)
	var m PTP
	if err := m.DecodeFromBytes(padded, gopacket.NilDecodeFeedback); err != nil || len(m.Payload) != 6 || len(m.TLVs) != 0 {
		t.Errorf("padded: %v, payload %d, TLVs %d", err, len(m.Payload), len(m.TLVs))
	}

	// A reserved message type keeps its header and skips its body.
	reserved := ptpVectors(t)[0]
	reserved[0] = 0x05
	if err := m.DecodeFromBytes(reserved, gopacket.NilDecodeFeedback); err != nil || m.MessageType != 5 || m.Timestamp.Seconds != 0 {
		t.Errorf("reserved type: %v, %+v", err, m)
	}
}

func FuzzPTP(f *testing.F) {
	for _, v := range ptpVectors(f) {
		f.Add(v)
	}
	for _, tc := range ptpCaptures {
		packets, err := ptpReadPcap(tc.path)
		if err != nil {
			f.Fatal(err)
		}
		for _, data := range packets {
			const ethHeader = 14
			const udpOffset = ethHeader + 20 + 8 // IPv4 without options, UDP
			if binary.BigEndian.Uint16(data[12:14]) == uint16(EthernetTypePTP) {
				f.Add(data[ethHeader:])
				continue
			}
			f.Add(data[udpOffset:])
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var m PTP
		if err := m.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
			if len(m.Contents) != int(m.MessageLength) {
				t.Fatalf("contents %d octets for messageLength %d", len(m.Contents), m.MessageLength)
			}
			size := 0
			for _, tlv := range m.TLVs {
				size += ptpTLVHeaderLen + len(tlv.Value)
			}
			if size > len(m.Contents) {
				t.Fatalf("TLVs take %d octets of %d", size, len(m.Contents))
			}
		}
		gopacket.NewPacket(data, LayerTypePTP, gopacket.Default)
	})
}
