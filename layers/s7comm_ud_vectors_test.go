// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// Hand-built Userdata values for the services no capture in testdata
// holds. Each was written to a capture file and its decoding compared
// field by field with tshark 4.7; the two marked "differs" are where
// this package departs from Wireshark on purpose.

// Type and group octets of the Userdata parameter.
const (
	s7TGCPUPush = 0x04
	s7TGTISReq  = 0x41
	s7TGTISRes  = 0x81
	s7TGTISPush = 0x01
	s7TGCycReq  = 0x42
	s7TGCycRes  = 0x82
	s7TGPBCRes  = 0x86
	s7TGNCReq   = 0x7f
	s7TGNCRes   = 0xbf
)

// s7UDVec is one test value. units holds the size of every data unit
// but the last when the value spans PDUs; head is the unit header each
// unit starts with. ret 0 means return code 0xFF.
type s7UDVec struct {
	name      string
	typeGroup byte
	sub       S7CommSubfunction
	ret       S7CommReturnCode
	head      string
	value     []byte
	units     []int
	want      string
}

// s7Seq returns n octets counting up from first.
func s7Seq(n int, first byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = first + byte(i)
	}
	return b
}

// s7Cat joins hex strings and octet slices.
func s7Cat(parts ...interface{}) []byte {
	var b []byte
	for _, p := range parts {
		switch v := p.(type) {
		case string:
			b = append(b, s7Hex(v)...)
		case []byte:
			b = append(b, v...)
		}
	}
	return b
}

// s7TISValue builds a programmer command value from its two parts.
func s7TISValue(param, data []byte) []byte {
	return s7Cat([]byte{byte(len(param) >> 8), byte(len(param)), byte(len(data) >> 8), byte(len(data))}, param, data)
}

// s7IStack builds an ISTACK reply for an OB number.
func s7IStack(ob byte) []byte {
	info := s7Seq(s7commTISOBInfoLen, 0xa0)
	info[s7commTISOBNumAt] = ob
	return s7TISValue(s7Hex("00000000"), s7Cat(s7Seq(56, 1), info, s7TestStamp))
}

const (
	s7TestStamp  = "1408201159337464" // 2014-08-20 11:59:33.746
	s7TestStamp2 = "1512312359599991" // 2015-12-31 23:59:59.999
	// Alarm objects: lock/free, indication, ack, NOTIFY, query.
	s7AlarmLockObj  = "120615" + "01" + "60000001"
	s7AlarmIndObj   = "120a16" + "01" + "60000002" + "0180" + "0302"
	s7AlarmAckObj   = "120819" + "01" + "60000003" + "0102"
	s7AlarmNotifObj = "120e1c" + "02" + "60000004" + "0180" + "0302" + "04050600"
	s7TISParam20    = "0001000200030014000500060007000800090000"
	s7TISParam28    = s7TISParam20 + "000c0005002a" + "0001"
	s7NCFileHead    = "2020202020313233" + "3134303832303131353933333734363 4"
	s7PBCHead       = "12061300" + "00000123"
)

// s7UDLeftovers returns the hand-built values.
func s7UDLeftovers() []s7UDVec {
	path := []byte("/_N_MPF_DIR/_N_TEST_MPF\n")
	file := s7Cat(s7NCFileHead, path, s7Seq(40, 0x30))

	return []s7UDVec{
		// Alarm services of the CPU group.
		{name: "alarm8 lock request", typeGroup: s7TGCPUReq, sub: S7CommCPUAlarm8Lock,
			value: s7Cat("0001", s7AlarmLockObj)},
		{name: "alarm8 lock response", typeGroup: s7TGCPURes, sub: S7CommCPUAlarm8Lock,
			value: s7Cat("0001ff")},
		{name: "alarm8 unlock request", typeGroup: s7TGCPUReq, sub: S7CommCPUAlarm8Unlock,
			value: s7Cat("0002", s7AlarmLockObj, s7AlarmLockObj)},
		{name: "alarm8 unlock response", typeGroup: s7TGCPURes, sub: S7CommCPUAlarm8Unlock,
			value: s7Cat("0002ff0a")},
		{name: "alarm8 lock indication", typeGroup: s7TGCPUPush, sub: S7CommCPUAlarm8LockInd,
			value: s7Cat("0001", s7AlarmLockObj)},
		{name: "alarm8 unlock indication", typeGroup: s7TGCPUPush, sub: S7CommCPUAlarm8UnlockInd,
			value: s7Cat("0001", s7AlarmLockObj)},
		{name: "alarm ack request", typeGroup: s7TGCPUReq, sub: S7CommCPUAlarmAck,
			value: s7Cat("0001", s7AlarmAckObj)},
		{name: "alarm ack indication", typeGroup: s7TGCPUPush, sub: S7CommCPUAlarmAckInd,
			value: s7Cat(s7TestStamp, "0001", s7AlarmAckObj)},
		{name: "alarm8 indication", typeGroup: s7TGCPUPush, sub: S7CommCPUAlarm8Ind,
			value: s7Cat(s7TestStamp, "0001", s7AlarmIndObj, "ff090002abcd")},
		{name: "notify indication", typeGroup: s7TGCPUPush, sub: S7CommCPUNotifyInd,
			value: s7Cat(s7TestStamp, "0001", s7AlarmNotifObj, "ff0400100102", "ff09000101")},
		{name: "scan indication", typeGroup: s7TGCPUPush, sub: S7CommCPUScanInd,
			value: s7Cat("0102", s7TestStamp, "0304", "0001", "120499aabbcc")},
		{name: "alarm query by type", typeGroup: s7TGCPUReq, sub: S7CommCPUAlarmQuery,
			value: s7Cat("0001", "12081a", "00", "01", "00", "00000004")},
		{name: "alarm query by event", typeGroup: s7TGCPUReq, sub: S7CommCPUAlarmQuery,
			value: s7Cat("0001", "12081a", "00", "03", "00", "60000005")},
		{name: "alarm query response", typeGroup: s7TGCPURes, sub: S7CommCPUAlarmQuery,
			value: s7Cat("0001", "ff09", "002e",
				"0c000002", "60000006", "00010203",
				"22000004", "60000007", "00010203", s7TestStamp, "ff090002abcd", s7TestStamp2, "ff0900021234")},
		{name: "ar_send indication", typeGroup: s7TGCPUPush, sub: S7CommCPUARSendInd,
			head: s7PBCHead, value: s7Cat("0400", "deadbeef")},

		// Programmer commands.
		{name: "block status request", typeGroup: s7TGTISReq, sub: S7CommTISBlockStat,
			value: s7TISValue(s7Hex(s7TISParam20+"000c0005002a"), s7Hex("003f"+"0001"+"0003"))},
		{name: "block status 2 request", typeGroup: s7TGTISReq, sub: S7CommTISBlockStat2,
			value: s7TISValue(s7Hex(s7TISParam28), s7Hex("0102003f"+"00100001"+"00140003"))},
		{name: "block status call condition", typeGroup: s7TGTISReq, sub: S7CommTISBlockStat2,
			value: s7TISValue(s7Hex(s7TISParam28+"00010002"+"000c0007"+"0010"), s7Hex("0100003f"))},
		{name: "block status call without address", typeGroup: s7TGTISReq, sub: S7CommTISBlockStat2,
			value: s7TISValue(s7Hex(s7TISParam28+"00010002"+"000c0007"), s7Hex("0100003f"))},
		{name: "block status DB condition", typeGroup: s7TGTISReq, sub: S7CommTISBlockStat2,
			value: s7TISValue(s7Hex(s7TISParam28+"00020002"+"00050006"), s7Hex("0100003f"))},
		{name: "block status indication", typeGroup: s7TGTISPush, sub: S7CommTISBlockStat,
			value: s7TISValue(s7Hex("01000001"), s7Cat("002a", s7Seq(10, 1)))},
		{name: "block status response", typeGroup: s7TGTISRes, sub: S7CommTISBlockStat,
			value: s7TISValue(s7Hex("01000001"), s7Hex("0000"))},
		{name: "istack request", typeGroup: s7TGTISReq, sub: S7CommTISIStack,
			value: s7TISValue(s7Hex("00000000"), s7Hex("0000"))},
		{name: "istack OB 1", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(1)},
		{name: "istack OB 10", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(10)},
		{name: "istack OB 20 (differs)", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(20)},
		{name: "istack OB 35", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(35)},
		{name: "istack OB 40", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(40)},
		{name: "istack OB 55", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(55)},
		{name: "istack OB 80", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(80)},
		{name: "istack OB 81", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(81)},
		{name: "istack OB 82", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(82)},
		{name: "istack OB 83", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(83)},
		{name: "istack OB 84", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(84)},
		{name: "istack OB 85", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(85)},
		{name: "istack OB 86", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(86)},
		{name: "istack OB 90", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(90)},
		{name: "istack OB 100", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(100)},
		{name: "istack OB 121", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(121)},
		{name: "istack OB 122", typeGroup: s7TGTISPush, sub: S7CommTISIStack, value: s7IStack(122)},
		{name: "istack OB 200", typeGroup: s7TGTISRes, sub: S7CommTISIStack, value: s7IStack(200)},
		{name: "bstack request", typeGroup: s7TGTISReq, sub: S7CommTISBStack,
			value: s7TISValue(s7Hex("00000000"), s7Hex("0000"))},
		{name: "bstack response", typeGroup: s7TGTISRes, sub: S7CommTISBStack,
			value: s7TISValue(s7Hex("00000000"), s7Cat("000c", s7Seq(14, 1), "0008", s7Seq(14, 0x21), "01000000", s7TestStamp))},
		{name: "bstack last entry (differs)", typeGroup: s7TGTISRes, sub: S7CommTISBStack,
			value: s7TISValue(s7Hex("00000000"), s7Cat("000c", s7Seq(14, 1), "000e", s7Seq(14, 0x21)))},
		{name: "lstack request", typeGroup: s7TGTISReq, sub: S7CommTISLStack,
			value: s7TISValue(s7Hex("00000000"), s7Hex("0102"))},
		{name: "lstack response", typeGroup: s7TGTISRes, sub: S7CommTISLStack,
			value: s7TISValue(s7Hex("00000000"), s7Cat("000c0005002a", "0004", "a1a2a3a4", "01000000", s7TestStamp))},
		{name: "breakpoint request", typeGroup: s7TGTISReq, sub: S7CommTISBreakpoint,
			value: s7TISValue(s7Hex("00000000"), s7Hex("0000"))},
		{name: "breakpoint response", typeGroup: s7TGTISRes, sub: S7CommTISBreakpoint,
			value: s7TISValue(s7Hex("00000000"), s7Seq(38, 1))},
		{name: "exit hold request", typeGroup: s7TGTISReq, sub: S7CommTISExitHold,
			value: s7TISValue(s7Hex("00000000"), s7Hex("0100"))},
		{name: "delete job request", typeGroup: s7TGTISReq, sub: S7CommTISDeleteJob,
			value: s7TISValue(s7Hex("00000000"), s7Hex("0000"))},
		{name: "enable job request", typeGroup: s7TGTISReq, sub: S7CommTISEnableJob,
			value: s7TISValue(s7Hex("00000000"), s7Hex("0207"))},
		{name: "disable job request", typeGroup: s7TGTISReq, sub: S7CommTISDisableJob,
			value: s7TISValue(s7Hex("00000000"), s7Hex("0207"))},
		{name: "read job request", typeGroup: s7TGTISReq, sub: S7CommTISReadJob,
			value: s7TISValue(s7Hex("00000000"), s7Hex("0207"))},
		{name: "read job response", typeGroup: s7TGTISRes, sub: S7CommTISReadJob,
			value: s7TISValue(s7Hex("00000000"), s7Cat("00040003", "00010002", "aabbcc"))},
		{name: "read job list request", typeGroup: s7TGTISReq, sub: S7CommTISReadJobList,
			value: s7TISValue(s7Hex("00000000"), s7Hex("00000000"))},
		{name: "read job list response", typeGroup: s7TGTISRes, sub: S7CommTISReadJobList,
			value: s7TISValue(s7Hex("00000000"), s7Hex("02070000"+"01080000"))},
		{name: "replace job request", typeGroup: s7TGTISReq, sub: S7CommTISReplaceJob,
			value: s7TISValue(s7Hex("00000000"), s7Cat("0000", "0107", "00040006", "00010002", "003f"+"0001"+"0003"))},
		{name: "replace job nested", typeGroup: s7TGTISReq, sub: S7CommTISReplaceJob,
			value: s7TISValue(s7Hex("00000000"), s7Cat("0000", "1207", "0004000a", "00010002",
				"0000", "0b08", "00000002", "0100"))},

		// Cyclic data: read record.
		{name: "read record request", typeGroup: s7TGCycReq, sub: S7CommCyclicReadRecord,
			value: s7Cat("0001", "120a10020004000184000000")},
		{name: "read record response", typeGroup: s7TGCycRes, sub: S7CommCyclicReadRecord,
			value: s7Cat("0001", "ff09", "04", "00010203", "0003", "aabbcc")},
		{name: "read record no status", typeGroup: s7TGCycRes, sub: S7CommCyclicReadRecord,
			value: s7Cat("0001", "ff09", "00", "00", "0002", "aabb")},
		{name: "read record error", typeGroup: s7TGCycRes, sub: S7CommCyclicReadRecord,
			value: s7Cat("0001", "0a", "04", "c0800a00")},
		{name: "read record empty", typeGroup: s7TGCycRes, sub: S7CommCyclicReadRecord,
			value: s7Cat("0000")},

		// PBC BSEND.
		{name: "bsend request", typeGroup: s7TGPBCReq, sub: 0x01, head: s7PBCHead,
			value: s7Cat("0006", "010203040506")},
		{name: "bsend request in two units", typeGroup: s7TGPBCReq, sub: 0x01, head: s7PBCHead,
			value: s7Cat("0010", s7Seq(16, 0x40)), units: []int{10}},
		{name: "bsend response", typeGroup: s7TGPBCRes, sub: 0x01, head: s7PBCHead,
			value: s7Cat("0002", "0000")},

		// NC programming.
		{name: "nc request download", typeGroup: s7TGNCReq, sub: S7CommNCRequestDownload,
			value: []byte("_N_TEST_MPF")},
		{name: "nc request download response", typeGroup: s7TGNCRes, sub: S7CommNCRequestDownload,
			value: s7Hex("0500")},
		{name: "nc download block", typeGroup: s7TGNCPush, sub: S7CommNCDownloadBlock, head: "0001",
			value: file, units: []int{30, 50}},
		{name: "nc continue download", typeGroup: s7TGNCPush, sub: S7CommNCContDownload,
			value: s7Hex("0300")},
		{name: "nc download ended", typeGroup: s7TGNCReq, sub: S7CommNCDownloadEnded,
			value: s7Hex("0000" + "01020304")},
		{name: "nc start upload", typeGroup: s7TGNCReq, sub: S7CommNCStartUpload,
			value: s7Cat("0500", []byte("_N_TEST_MPF"))},
		{name: "nc start upload response", typeGroup: s7TGNCRes, sub: S7CommNCStartUpload, head: "0001",
			value: s7Hex(s7NCFileHead)},
		{name: "nc upload", typeGroup: s7TGNCRes, sub: S7CommNCUpload, head: "0001",
			value: file},
		{name: "nc continue upload", typeGroup: s7TGNCPush, sub: S7CommNCContUpload,
			value: s7Hex("0300")},

		// Values sent with a return code other than 0xFF still decode,
		// except where Wireshark asks for 0xFF.
		{name: "alarm with error return", typeGroup: s7TGCPUReq, sub: S7CommCPUAlarm8Lock,
			ret: S7CommRetObjectMissing, value: s7Cat("0001", s7AlarmLockObj)},
		{name: "szl response with error return", typeGroup: s7TGCPURes, sub: S7CommCPUReadSZL,
			ret: S7CommRetObjectMissing, value: s7TestSZLValue},
		{name: "clock with error return", typeGroup: s7TGTimeRes, sub: S7CommTimeReadClock,
			ret: S7CommRetObjectMissing, value: s7Hex("0019" + s7TestStamp)},
	}
}

// s7TGTimeRes is the response type of the time function group.
const s7TGTimeRes = 0x87

// pdus returns the Userdata PDUs carrying the value. seq is the
// sequence number, also the data unit reference of a split value.
func (v s7UDVec) pdus(seq byte) [][]byte {
	var out [][]byte
	start := 0
	for i, end := range append(append([]int{}, v.units...), len(v.value)) {
		unit := s7UDUnit{typeGroup: v.typeGroup, sub: byte(v.sub), seq: seq, value: s7Cat(v.head, v.value[start:end])}
		if len(v.units) > 0 {
			unit.ref = seq
		}
		if i < len(v.units) {
			unit.last = 1
		}

		pdu := unit.pdu()
		if v.ret != 0 {
			pdu[s7commHeaderLen+s7commUDExtLen] = byte(v.ret)
		}
		out = append(out, pdu)
		start = end
	}
	return out
}

// s7ViewString renders the value views of a Userdata, one per line.
func s7ViewString(u *S7CommUserdata) string {
	var b strings.Builder
	line := func(format string, args ...interface{}) {
		fmt.Fprintf(&b, format+"\n", args...)
	}

	if len(u.UnitHeader) > 0 {
		line("head %x", u.UnitHeader)
	}
	if u.Alarm != nil {
		line("alarm %+v", *u.Alarm)
	}
	if q := u.AlarmQuery; q != nil {
		line("query %d %d %v %v %d", q.Function, q.ObjectCount, q.ReturnCode, q.TransportSize, q.CompleteLength)
		for _, a := range q.Alarms {
			line(" %d %v %#x %d %d %d", a.Length, a.AlarmType, a.EventID, a.EventState, a.AckGoing, a.AckComing)
			if a.ComingValue != nil && a.GoingValue != nil {
				line(" coming %v %x going %v %x", a.Coming, a.ComingValue.Data, a.Going, a.GoingValue.Data)
			}
		}
	}
	if u.SZL != nil {
		line("szl %04x %04x %d records", u.SZL.ID, u.SZL.Index, len(u.SZL.Records))
	}
	if u.Clock != nil {
		line("clock %v", *u.Clock)
	}
	if t := u.TIS; t != nil {
		line("param %v", t.ParamFields())
		line("data %v", t.DataFields())
	}
	if c := u.Cyclic; c != nil {
		line("cyclic %d %d", c.Reserved, c.ItemCount)
		if r := c.Record; r != nil && r.Item != nil {
			line(" item %v %v %d %d %d", r.Item.SyntaxID, r.Item.Area, r.Item.DBNumber, r.Item.Count, r.Item.BitAddress)
		} else if r != nil {
			line(" record %v %v %x %d %x", r.ReturnCode, r.TransportSize, r.Status, r.Length, r.Data)
		}
	}
	if s := u.Send; s != nil {
		line("send %#x %d %x", s.ID, s.Length, s.Data)
	}
	if n := u.NC; n != nil {
		line("nc %d %d %q %q %q %q %x %x", n.UnackCount, n.Unknown, n.Filename, n.FileLength, n.FileTime,
			n.FilePath, n.FileData, n.Rest)
	}
	if u.DecodeErr != nil {
		line("error %v", u.DecodeErr)
	}
	return b.String()
}

// s7FeedVec decodes the PDUs of a vector and returns the joined view.
func s7FeedVec(t *testing.T, v s7UDVec) *S7CommUserdata {
	t.Helper()
	var a S7CommUDAssembler
	var u *S7CommUserdata
	for i, pdu := range v.pdus(1) {
		var err error
		if u, err = a.Feed(s7Decode(t, pdu)); err != nil {
			t.Fatalf("%s: unit %d: %v", v.name, i, err)
		}
	}
	if u == nil {
		t.Fatalf("%s: no view", v.name)
	}
	return u
}

func TestS7CommUDLeftovers(t *testing.T) {
	for _, v := range s7UDLeftovers() {
		got := s7ViewString(s7FeedVec(t, v))
		want, ok := s7UDLeftoverWant[v.name]
		if !ok || got != want {
			t.Errorf("%q: `%s`,\nwant `%s`", v.name, got, want)
		}
	}
}

// TestS7CommUDLeftoversCut decodes every vector cut at every offset
// and with every octet of its value changed: a view may be missing,
// nothing may panic, and the field views must stay inside the value.
func TestS7CommUDLeftoversCut(t *testing.T) {
	check := func(name string, pdu []byte) {
		s := &S7Comm{}
		if err := s.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil || s.Userdata == nil {
			return
		}

		var a S7CommUDAssembler
		u, _ := a.Feed(s)
		if u == nil {
			u = s.Userdata
		}
		if u.TIS != nil {
			for _, fields := range [][]S7CommField{u.TIS.ParamFields(), u.TIS.DataFields()} {
				n := 0
				for _, f := range fields {
					n += len(f.Raw)
				}
				if n > len(u.Data) {
					t.Fatalf("%s: fields cover %d of %d octets", name, n, len(u.Data))
				}
			}
		}
		_ = s7ViewString(u)
	}

	for _, v := range s7UDLeftovers() {
		v.units = nil
		whole := v.value
		for n := 0; n <= len(whole); n++ {
			v.value = whole[:n]
			check(v.name, v.pdus(1)[0])
		}

		v.value = whole
		pdu := v.pdus(1)[0]
		for i := s7commHeaderLen + s7commUDExtLen + s7commDataItemHead; i < len(pdu); i++ {
			for _, x := range []byte{0x01, 0x80, 0xff} {
				mod := append([]byte{}, pdu...)
				mod[i] ^= x
				check(v.name, mod)
			}
		}
	}
}
