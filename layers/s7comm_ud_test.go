// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// Userdata, Read Var and PI service PDUs for the views of
// s7comm_ud_*.go. The "real" ones are frames of the ICS-pcap captures
// s7comm_reading_setting_plc_time (plctime), s7comm_reading_plc_status
// (plcstatus), 3-S7comm-VAT_MB100_MW200_MD300_M400-0 (vat) and
// 2-S7comm-VarService-CyclicData-1s (cyclic), by frame number. The
// others are hand-built. All were checked against Wireshark 4.7.
var (
	s7TestClockRead  = s7Hex("320700000700000c000e000112081287010100000000ff09000a00191408201159439124") // plctime 26
	s7TestClockSetPC = s7Hex("320700000c000008000e0001120411470200ff09000a00191408201159330400")         // plctime 43
	s7TestVarStatReq = s7Hex("320700000700000c0036000112081241020000000000ff0900320014001a000000000001001c0001000100010001" +
		"0001000000040101000000640201000000c803010000012c010100000190") // vat 35
	s7TestVarStatInd = s7Hex("320700000000000c0028000112081201021200000000ff0900240004001c010000010004ff09000100" +
		"00ff0900020000ff09000400000000ff0900010000") // vat 41
	s7TestCyclicSub = s7Hex("3207000000010008008c0001120411420100ff090088000b0101" +
		"120a10040001012c84000020120a1004000100c884000000120a10040001012c84000000120a10040001012c84000010" +
		"120a1004000100c884000038120a10040001012c84000030120a1004000100c884000018120a1004000100c884000010" +
		"120a1004000100c884000050120a10040001012c84000040120a1004000100c884000028") // cyclic 17
	s7TestCyclicPush = s7Hex("320700000001000c0048000112081282010200000000ff090044000b" +
		"ff0400103000ff0400100060ff0400103000ff0400103000ff0400100007ff0400100000" +
		"ff040010e000ff04001000e0ff040010e000ff0400100000ff040010004b") // cyclic 25
	s7TestSZL0011 = s7Hex("320700000b00000c0028000112081284010100000000ff09002401110001001c0001" +
		"000136455337203135312d38414230312d304142302000c000030001") // plcstatus 39
	s7TestMsgSubReq = s7Hex("320700000f000008000e0001120411440200ff09000a030061736d6573730000") // plcstatus 52
	s7TestMsgSubRes = s7Hex("320700000f00000c0006000112081284020100000000ff0900020200")         // plcstatus 53

	s7TestAlarmSQInd = s7Hex("320700000100000c0020000112081204110000000000ff09001c1408201159337464" +
		"0001121016010000510101010000ff0900021234")
	s7TestNotifyInd = s7Hex("320700000100000c002b000112081204060000000000ff0900271408201159337464" +
		"0001121b1c02000051020302010001020300ff0400080a00ff090003aabbcc")
	s7TestAlarmAckReq   = s7Hex("3207000001000008001a0001120411440b00ff09001609021208190000005101010112081900000051020001")
	s7TestAlarmAckRes   = s7Hex("320700000100000c00080001120812840b0000000000ff0900040902ff0a")
	s7TestAlarmQueryReq = s7Hex("320700000100000800100001120411441300ff09000c000112081a00013400000004")
	s7TestAlarmQueryRes = s7Hex("320700000100000c0033000112081284130000000000ff09002f0001ff09ffff" +
		"2800000400005101000100011408201159337464ff09000212349912312359599997ff090002567800")
	s7TestAlarmQueryRes8 = s7Hex("320700000100000c0016000112081284130000000000ff0900120001ff09000c0c0000020000510300010001")
	s7TestScanInd        = s7Hex("320700000100000c001a000112081204090000000000ff0900160001140820115933746400000001" +
		"1206150000005104")
	s7TestDiagMsg      = s7Hex("320700000100000c0018000112081204030000000000ff0900144301016400000002000000039912312359599997")
	s7TestClockSet     = s7Hex("3207000001000008000e0001120411470200ff09000a00191408201159337464")
	s7TestTISModVar    = s7Hex("320700000100000800220001120411410800ff09001e0000001a000201010000006470030005000aff0400082a00ff0300010100")
	s7TestTISModVarInd = s7Hex("320700000100000c000e000112081201080000000000ff09000a000000060003ffff0a00")
	s7TestTISForce     = s7Hex("320700000100000800160001120411410900ff0900120000000e0001720100070010ff040010beef")
	s7TestReadVarExt   = s7Hex("320100000200002600000403120cb0020400010000020002001012088241000100021a01120aa2010002000303e80005")
	s7TestCyclicNCK    = s7Hex("320700000100000c0012000112081202010000000000ff09000e0001ff1112088241000100021a01")
	s7TestCyclicReq    = s7Hex("3207000001000008001e0001120411420100ff09001a000201051207b001040001000000120a10020001000083000000")
	s7TestPINCDelete   = s7Hex("3201000002000030000028000000000000fd001c03503031162f5f4e5f4d50465f4449522f5f4e5f5453545f4d5046" +
		"00095f4e5f465f44454c45")
	s7TestSZL00A0 = s7Hex("320700000100000c0020000112081284010000000000ff09001c00a00000001400014301016400000002000000039912312359599997")
	s7TestSZL001C = s7Hex("320700000100000c0072000112081284010000000000ff09006e001c000000220003" +
		"0001504c432d310000000000000000000000000000000000000000000000000000000009002af600000100000000000000" +
		"00000000000000000000000000000000000000000a4f454d00000000000000000000000000000000000000000000000007" +
		"00000009")
)

// s7UDVectors are the PDUs above, for the truncation test and fuzzing.
var s7UDVectors = [][]byte{
	s7TestClockRead, s7TestClockSetPC, s7TestVarStatReq, s7TestVarStatInd, s7TestCyclicSub, s7TestCyclicPush,
	s7TestSZL0011, s7TestMsgSubReq, s7TestMsgSubRes, s7TestAlarmSQInd, s7TestNotifyInd, s7TestAlarmAckReq,
	s7TestAlarmAckRes, s7TestAlarmQueryReq, s7TestAlarmQueryRes, s7TestAlarmQueryRes8, s7TestScanInd,
	s7TestDiagMsg, s7TestClockSet, s7TestTISModVar, s7TestTISModVarInd, s7TestTISForce, s7TestReadVarExt,
	s7TestCyclicNCK, s7TestCyclicReq, s7TestPINCDelete, s7TestSZL00A0, s7TestSZL001C,
}

// s7Decode decodes an S7comm PDU that must not fail.
func s7Decode(t *testing.T, pdu []byte) *S7Comm {
	t.Helper()
	s := &S7Comm{}
	if err := s.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	return s
}

// s7UTC builds a UTC time with milliseconds.
func s7UTC(y int, mo time.Month, d, h, mi, s, ms int) time.Time {
	return time.Date(y, mo, d, h, mi, s, ms*int(time.Millisecond), time.UTC)
}

var (
	s7TestTime  = s7UTC(2014, time.August, 20, 11, 59, 33, 746)
	s7TestTimeB = s7UTC(1999, time.December, 31, 23, 59, 59, 999)
)

func TestS7CommUDClock(t *testing.T) {
	for _, c := range []struct {
		name string
		pdu  []byte
		want time.Time
	}{
		{"read response", s7TestClockRead, s7UTC(2014, time.August, 20, 11, 59, 43, 912)},
		{"set request", s7TestClockSetPC, s7UTC(2014, time.August, 20, 11, 59, 33, 40)},
		{"set request 2", s7TestClockSet, s7TestTime},
	} {
		u := s7Decode(t, c.pdu).Userdata
		if u.Clock == nil || !u.Clock.Equal(c.want) || u.DecodeErr != nil {
			t.Errorf("%s: clock %v, err %v, want %v", c.name, u.Clock, u.DecodeErr, c.want)
		}
	}
}

func TestS7CommBCDTime(t *testing.T) {
	for _, c := range []struct {
		in   string
		form s7commBCDForm
		want time.Time
		ok   bool
	}{
		{"14082011593374 64", s7commBCDShort, s7TestTime, true},
		{"9912312359599997", s7commBCDShort, s7TestTimeB, true},
		// Years below 89 are 20xx whatever the century octet says.
		{"00191408201159337464", s7commBCDLong, s7TestTime, true},
		{"00209912312359599997", s7commBCDLong, s7UTC(2099, time.December, 31, 23, 59, 59, 999), true},
		{"14132011593374 64", s7commBCDShort, time.Time{}, false}, // month 13
		{"14082024593374 64", s7commBCDShort, time.Time{}, false}, // hour 24
		{"140820115933", s7commBCDShort, time.Time{}, false},
	} {
		got, err := s7commBCDTime(s7Hex(c.in), c.form)
		if (err == nil) != c.ok || !got.Equal(c.want) {
			t.Errorf("%s: %v, %v; want %v", c.in, got, err, c.want)
		}
	}
}

func TestS7CommUDBlockInfo(t *testing.T) {
	pkts := s7Packets(t, "s7comm-blocklist.pcap")
	u := s7Layer(t, pkts, 134).Userdata
	want := &S7CommBlockInfo{
		Head: 0x0100, InfoLength: 74, Unknown2: 0x4230, Const3: "pp", Unknown: 1, Flags: 0x09,
		Language: S7CommLangAWL, SubblockType: S7CommSubblockSFC, Number: 0, LoadMemLength: 90,
		Security:  S7CommSecurityNone,
		CodeTime:  s7UTC(1994, time.November, 2, 12, 50, 46, 600),
		SSBLength: 12, AddLength: 4, LocalDataLength: 0, MC7Length: 2,
		Author: "SIMATIC", Family: "CLK_FUNC", Name: "SET_CLK", Version: 0x10, Checksum: 0xc5a0,
	}
	want.InterfaceTime = want.CodeTime
	if !reflect.DeepEqual(u.BlockInfo, want) || u.BlockInfo.VersionString() != "1.0" {
		t.Errorf("block info =\n%+v\nwant\n%+v", u.BlockInfo, want)
	}

	// An error response (frame 44) and a request (43) have no info.
	for _, f := range []int{43, 44} {
		if u := s7Layer(t, pkts, f).Userdata; u.BlockInfo != nil || u.DecodeErr != nil {
			t.Errorf("frame %d: block info %+v, err %v", f, u.BlockInfo, u.DecodeErr)
		}
	}
}

func TestS7CommUDSZLRecords(t *testing.T) {
	pkts := s7Packets(t, "s7comm-blocklist.pcap")

	prot := []S7CommSZLProtection{{4, 1, 0, 1, 2, 0, 0, 22102, 1212, 54691, 388, 45782}}
	if got := s7Layer(t, pkts, 11).Userdata.SZL.Protection; !reflect.DeepEqual(got, prot) {
		t.Errorf("SZL 0132/4 = %+v", got)
	}

	leds := s7Layer(t, pkts, 29).Userdata.SZL.LEDs
	if len(leds) != 7 || leds[0] != (S7CommSZLLED{1, 1, 0}) || leds[4] != (S7CommSZLLED{11, 1, 1}) {
		t.Errorf("SZL 0074 = %+v", leds)
	}

	ev := s7Layer(t, pkts, 23).Userdata.SZL.ModeEvents
	if len(ev) == 0 || ev[0].Event != 20802 || ev[0].AE != 0xff || ev[0].BZUID != 8 ||
		!ev[0].Time.Equal(s7UTC(2014, time.August, 20, 12, 0, 49, 548)) {
		t.Errorf("SZL 0424 = %+v", ev)
	}

	// Header-only and unknown layouts keep no view.
	if z := s7Layer(t, pkts, 26).Userdata.SZL; z.LEDs != nil {
		t.Errorf("SZL 0F74 LEDs = %+v", z.LEDs)
	}

	mod := s7Decode(t, s7TestSZL0011).Userdata.SZL.ModuleIDs
	wantMod := []S7CommSZLModuleID{{1, "6ES7 151-8AB01-0AB0 ", 0xc0, 3, 1}}
	if !reflect.DeepEqual(mod, wantMod) {
		t.Errorf("SZL 0111 = %+v", mod)
	}

	diag := s7Decode(t, s7TestSZL00A0).Userdata.SZL.DiagEvents
	wantDiag := []S7CommDiagMessage{{0x4301, 1, 100, 0, 2, 3, s7TestTimeB}}
	if !reflect.DeepEqual(diag, wantDiag) {
		t.Errorf("SZL 00A0 = %+v", diag)
	}

	comp := s7Decode(t, s7TestSZL001C).Userdata.SZL.Components
	wantComp := []S7CommSZLComponent{
		{Index: 1, Text: "PLC-1"},
		{Index: 9, ManufacturerID: 42, ProfileID: 0xf600, ProfileSpecType: 1},
		{Index: 0xa, Text: "OEM", OEMID: 7, OEMAddID: 9},
	}
	if !reflect.DeepEqual(comp, wantComp) {
		t.Errorf("SZL 001C = %+v", comp)
	}
}

func TestS7CommUDTIS(t *testing.T) {
	req := s7Decode(t, s7TestVarStatReq).Userdata.TIS
	addrs := []S7CommTISAddress{
		{Area: S7CommTISAreaMB, Repetition: 1, Start: 100},
		{Area: S7CommTISAreaMW, Repetition: 1, Start: 200},
		{Area: S7CommTISAreaMD, Repetition: 1, Start: 300},
		{Area: S7CommTISAreaMB, Repetition: 1, Start: 400},
	}
	if req == nil || req.ParamSize != 20 || req.DataSize != 26 || len(req.Param) != 20 || !reflect.DeepEqual(req.Addresses, addrs) {
		t.Errorf("variable status request = %+v", req)
	}

	ind := s7Decode(t, s7TestVarStatInd).Userdata.TIS
	if ind == nil || len(ind.Values) != 4 || !bytes.Equal(ind.Values[2].Data, s7Hex("00000000")) || len(ind.Values[3].Data) != 1 {
		t.Errorf("variable status indication = %+v", ind)
	}

	mod := s7Decode(t, s7TestTISModVar).Userdata.TIS
	if mod == nil || len(mod.Addresses) != 2 || mod.Addresses[1] != (S7CommTISAddress{Area: S7CommTISAreaDBX, BitPos: 3, DBNumber: 5, Start: 10}) ||
		len(mod.Values) != 2 || !bytes.Equal(mod.Values[0].Data, []byte{0x2a}) || !bytes.Equal(mod.Values[1].Data, []byte{0x01}) {
		t.Errorf("modify request = %+v", mod)
	}

	res := s7Decode(t, s7TestTISModVarInd).Userdata.TIS
	if res == nil || !reflect.DeepEqual(res.Results, []S7CommReturnCode{S7CommRetSuccess, S7CommRetSuccess, S7CommRetObjectMissing}) {
		t.Errorf("modify indication = %+v", res)
	}

	force := s7Decode(t, s7TestTISForce).Userdata.TIS
	if force == nil || len(force.Values) != 1 || !bytes.Equal(force.Values[0].Data, s7Hex("beef")) || force.Addresses[0].Area != S7CommTISAreaDBW {
		t.Errorf("force request = %+v", force)
	}
}

func TestS7CommUDCyclic(t *testing.T) {
	sub := s7Decode(t, s7TestCyclicSub).Userdata.Cyclic
	if sub == nil || sub.ItemCount != 11 || len(sub.Items) != 11 || sub.Interval() != time.Second ||
		sub.Items[0].DBNumber != 300 || sub.Items[0].ByteOffset() != 4 {
		t.Errorf("subscribe = %+v", sub)
	}

	push := s7Decode(t, s7TestCyclicPush).Userdata.Cyclic
	if push == nil || len(push.Values) != 11 || !bytes.Equal(push.Values[10].Data, s7Hex("004b")) {
		t.Errorf("push = %+v", push)
	}

	req := s7Decode(t, s7TestCyclicReq).Userdata.Cyclic
	areas := []S7CommDBReadArea{{4, 1, 0}}
	if req == nil || len(req.Items) != 2 || !reflect.DeepEqual(req.Items[0].DBRead, areas) ||
		req.Items[1].Area != S7CommAreaFlags || req.Interval() != 5*time.Second {
		t.Errorf("request with fill octet = %+v", req)
	}

	nck := s7Decode(t, s7TestCyclicNCK).Userdata.Cyclic
	if nck == nil || len(nck.Items) != 1 || nck.Items[0].NCK == nil || nck.Values != nil {
		t.Errorf("NCK address push = %+v", nck)
	}
}

func TestS7CommUDAddress(t *testing.T) {
	s := s7Decode(t, s7TestReadVarExt)
	if len(s.VarItems) != 3 {
		t.Fatalf("items = %+v", s.VarItems)
	}

	areas := []S7CommDBReadArea{{4, 1, 0}, {2, 2, 16}}
	if !reflect.DeepEqual(s.VarItems[0].DBRead, areas) {
		t.Errorf("DBREAD = %+v", s.VarItems[0].DBRead)
	}
	if n := s.VarItems[1].NCK; n == nil || *n != (S7CommNCKAddress{2, 1, 1, 2, 0x1a, 1}) {
		t.Errorf("NCK = %+v", n)
	}
	if d := s.VarItems[2].DriveES; d == nil || *d != (S7CommDriveESAddress{1, 2, 3, 1000, 5}) {
		t.Errorf("Drive ES = %+v", d)
	}

	// An area count overrunning the address sets no view.
	lie := s7Hex("32010000020000100000" + "0401" + "120cb00304000100000200020010")
	if s := s7Decode(t, lie); s.VarItems[0].DBRead != nil {
		t.Errorf("DBREAD count lie = %+v", s.VarItems[0].DBRead)
	}
}

func TestS7CommUDAlarm(t *testing.T) {
	sq := s7Decode(t, s7TestAlarmSQInd).Userdata.Alarm
	if sq == nil || !sq.Time.Equal(s7TestTime) || len(sq.Objects) != 1 {
		t.Fatalf("ALARM_SQ = %+v", sq)
	}
	o := sq.Objects[0]
	if o.SyntaxID != S7CommSyntaxAlarmInd || o.EventID != 0x5101 || o.EventState != 1 || o.State != 1 ||
		len(o.Values) != 1 || !bytes.Equal(o.Values[0].Data, s7Hex("1234")) {
		t.Errorf("ALARM_SQ object = %+v", o)
	}

	n := s7Decode(t, s7TestNotifyInd).Userdata.Alarm.Objects[0]
	if n.EventGoing != 1 || n.EventComing != 2 || n.EventLastChanged != 3 || len(n.Values) != 2 ||
		!bytes.Equal(n.Values[0].Data, []byte{0x0a}) || !bytes.Equal(n.Values[1].Data, s7Hex("aabbcc")) {
		t.Errorf("NOTIFY object = %+v", n)
	}

	ack := s7Decode(t, s7TestAlarmAckReq).Userdata.Alarm
	if ack == nil || !ack.Time.IsZero() || len(ack.Objects) != 2 || ack.Objects[1].EventID != 0x5102 || ack.Objects[1].AckComing != 1 {
		t.Errorf("ack request = %+v", ack)
	}
	res := s7Decode(t, s7TestAlarmAckRes).Userdata.Alarm
	if res == nil || len(res.Objects) != 2 || res.Objects[1].ReturnCode != S7CommRetObjectMissing {
		t.Errorf("ack response = %+v", res)
	}

	scan := s7Decode(t, s7TestScanInd).Userdata.Alarm
	if scan == nil || !scan.Time.Equal(s7TestTime) || scan.Objects[0].EventID != 0x5104 {
		t.Errorf("scan = %+v", scan)
	}

	qr := s7Decode(t, s7TestAlarmQueryReq).Userdata.Alarm
	if qr == nil || qr.Objects[0].QueryType != S7CommQueryByAlarmType || qr.Objects[0].AlarmType != S7CommAlarmTypeAlarmS {
		t.Errorf("query request = %+v", qr)
	}

	q := s7Decode(t, s7TestAlarmQueryRes).Userdata.AlarmQuery
	if q == nil || len(q.Alarms) != 1 {
		t.Fatalf("query response = %+v", q)
	}
	e := q.Alarms[0]
	if e.AlarmType != S7CommAlarmTypeAlarmS || e.EventID != 0x5101 || !e.Coming.Equal(s7TestTime) || !e.Going.Equal(s7TestTimeB) ||
		!bytes.Equal(e.GoingValue.Data, s7Hex("5678")) {
		t.Errorf("query alarm = %+v", e)
	}
	q8 := s7Decode(t, s7TestAlarmQueryRes8).Userdata.AlarmQuery
	if q8 == nil || len(q8.Alarms) != 1 || q8.Alarms[0].AlarmType != S7CommAlarmTypeAlarm8 || q8.Alarms[0].ComingValue != nil {
		t.Errorf("ALARM_8 query response = %+v", q8)
	}

	diag := s7Decode(t, s7TestDiagMsg).Userdata.Diag
	if diag == nil || *diag != (S7CommDiagMessage{0x4301, 1, 100, 0, 2, 3, s7TestTimeB}) {
		t.Errorf("diagnostic message = %+v", diag)
	}
}

func TestS7CommUDMsgService(t *testing.T) {
	req := s7Decode(t, s7TestMsgSubReq).Userdata.MsgService
	if req == nil || req.Events != 3 || req.Username != "asmess" {
		t.Errorf("subscribe request = %+v", req)
	}
	res := s7Decode(t, s7TestMsgSubRes).Userdata.MsgService
	if res == nil || res.Result != 2 {
		t.Errorf("subscribe response = %+v", res)
	}
}

func TestS7CommUDPIService(t *testing.T) {
	pi := s7Layer(t, s7Packets(t, "s7comm-download-db1.pcap"), 75).PIService
	blocks := []S7CommPIBlock{{S7CommBlockDB, "00001", 'P'}}
	if !reflect.DeepEqual(pi.Blocks, blocks) || pi.DecodeErr != nil {
		t.Errorf("_INSE blocks = %+v, err %v", pi.Blocks, pi.DecodeErr)
	}

	nc := s7Decode(t, s7TestPINCDelete).PIService
	if nc == nil || !reflect.DeepEqual(nc.Args, []string{"P01", "/_N_MPF_DIR/_N_TST_MPF"}) {
		t.Errorf("_N_F_DELE args = %+v", nc)
	}

	// Lies in the parameter block leave the views nil, not the PDU.
	for _, lie := range []string{
		"320100000200001a0000" + "28000000000000fd000a" + "09000000000000000000" + "05" + "5f494e5345", // 9 blocks
		"32010000020000140000" + "28000000000000fd0004" + "09503031" + "05" + "5f4e5f5858",             // arg length
	} {
		s := s7Decode(t, s7Hex(lie))
		if pi := s.PIService; pi == nil || pi.DecodeErr == nil || pi.Blocks != nil || pi.Args != nil {
			t.Errorf("%s: PI = %+v", lie, pi)
		}
	}
}

// s7UDPDU builds a Userdata PDU with the long parameter.
func s7UDPDU(typeGroup, sub byte, value []byte) []byte {
	data := append([]byte{byte(S7CommRetSuccess), byte(S7CommDataTSOctetStr), 0, 0}, value...)
	binary.BigEndian.PutUint16(data[2:4], uint16(len(value)))
	pdu := append(s7Hex("32070000000100000000"), s7Hex("000112081200000000000000")...)
	pdu[15], pdu[16] = typeGroup, sub
	binary.BigEndian.PutUint16(pdu[6:8], s7commUDExtLen)
	binary.BigEndian.PutUint16(pdu[8:10], uint16(len(data)))
	return append(pdu, data...)
}

// TestS7CommUDLies checks that counts and lengths overrunning the value
// leave the view nil and set DecodeErr, while the PDU still decodes.
func TestS7CommUDLies(t *testing.T) {
	const (
		cpuPush  = 0x04
		cpuReq   = 0x44
		cpuRes   = 0x84
		tisReq   = 0x41
		tisPush  = 0x01
		cycReq   = 0x42
		cycPush  = 0x02
		blockRes = 0x83
		timeReq  = 0x47
	)
	ts := "1408201159337464"

	cases := []struct {
		name    string
		tg, sub byte
		value   string
		viewNil func(u *S7CommUserdata) bool
	}{
		{"alarm object count", cpuPush, 0x11, ts + "00ff" + "121016010000510101010000",
			func(u *S7CommUserdata) bool { return u.Alarm == nil }},
		{"alarm value count", cpuPush, 0x11, ts + "0001" + "121016090000510101010000ff0900021234",
			func(u *S7CommUserdata) bool { return u.Alarm == nil }},
		{"alarm value length", cpuPush, 0x11, ts + "0001" + "121016010000510101010000ff09ffff1234",
			func(u *S7CommUserdata) bool { return u.Alarm == nil }},
		{"alarm unknown syntax length", cpuReq, 0x0b, "0001" + "12ff99",
			func(u *S7CommUserdata) bool { return u.Alarm == nil }},
		{"alarm result count", cpuRes, 0x0b, "0905ff",
			func(u *S7CommUserdata) bool { return u.Alarm == nil }},
		{"alarm indication short", cpuPush, 0x11, "1408",
			func(u *S7CommUserdata) bool { return u.Alarm == nil }},
		{"query dataset cut", cpuRes, 0x13, "0001ff09ffff" + "2800000400005101000100011408",
			func(u *S7CommUserdata) bool { return u.AlarmQuery == nil }},
		{"diagnostic message short", cpuPush, 0x03, "430101",
			func(u *S7CommUserdata) bool { return u.Diag == nil }},
		{"message service short", cpuReq, 0x02, "0300",
			func(u *S7CommUserdata) bool { return u.MsgService == nil }},
		{"TIS sizes", tisReq, 0x02, "ffff0000",
			func(u *S7CommUserdata) bool { return u.TIS == nil }},
		{"TIS address count", tisReq, 0x02, "00000008" + "ffff010100000064",
			func(u *S7CommUserdata) bool { return u.TIS == nil }},
		{"TIS value count", tisPush, 0x02, "00000006" + "0009ff090001",
			func(u *S7CommUserdata) bool { return u.TIS == nil }},
		{"TIS value length", tisPush, 0x02, "00000008" + "0001ff0900ff0000",
			func(u *S7CommUserdata) bool { return u.TIS == nil }},
		{"TIS result count", tisPush, 0x08, "00000004" + "0009ff00",
			func(u *S7CommUserdata) bool { return u.TIS == nil }},
		{"cyclic item count", cycReq, 0x01, "00ff0105" + "120a10020001000083000000",
			func(u *S7CommUserdata) bool { return u.Cyclic == nil }},
		{"cyclic item length", cycReq, 0x01, "00010105" + "12ff10",
			func(u *S7CommUserdata) bool { return u.Cyclic == nil }},
		{"cyclic S7ANY length", cycReq, 0x01, "00010105" + "120310020001",
			func(u *S7CommUserdata) bool { return u.Cyclic == nil }},
		{"cyclic value count", cycPush, 0x01, "00ff" + "ff0400103000",
			func(u *S7CommUserdata) bool { return u.Cyclic == nil }},
		{"cyclic NCK count", cycPush, 0x01, "0005" + "ff1112088241000100021a01",
			func(u *S7CommUserdata) bool { return u.Cyclic == nil }},
		{"block info short", blockRes, 0x03, "0100004a",
			func(u *S7CommUserdata) bool { return u.BlockInfo == nil }},
		{"clock month 13", timeReq, 0x02, "0019141320115933 7464",
			func(u *S7CommUserdata) bool { return u.Clock == nil }},
		{"clock short", timeReq, 0x02, "00191408",
			func(u *S7CommUserdata) bool { return u.Clock == nil }},
		{"SZL record too short", cpuRes, 0x01, "00110000" + "00040001" + "00010203",
			func(u *S7CommUserdata) bool { return u.SZL != nil && u.SZL.ModuleIDs == nil }},
	}

	for _, c := range cases {
		s := &S7Comm{}
		if err := s.DecodeFromBytes(s7UDPDU(c.tg, c.sub, s7Hex(c.value)), gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: DecodeFromBytes = %v", c.name, err)
			continue
		}
		u := s.Userdata
		if !c.viewNil(u) || !errors.Is(u.DecodeErr, ErrS7CommMalformed) {
			t.Errorf("%s: view set or DecodeErr %v; userdata %+v", c.name, u.DecodeErr, u)
		}
	}
}
