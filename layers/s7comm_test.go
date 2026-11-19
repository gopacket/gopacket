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
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// The s7comm-*.pcap and s7commplus-*.pcap files are captures from
// github.com/automayt/ICS-pcap (directory S7), renamed:
//
//	s7comm-read-var.pcap        1-S7comm-VarService-Read-DB1DBD0
//	s7comm-download-db1.pcap    4-S7comm-Download-DB1-with-password-request
//	s7comm-blocklist.pcap       s7comm_program_blocklist_onlineview
//	s7commplus-1511-opc.pcap    S7-1511-opc-request-all-types
//	s7commplus-1200-upload.pcap S7-1200-Uploading-OB1-TIAV12

// s7Expect is Wireshark 4.7's view of one frame: COTP type, and for
// S7comm frames the header, function and Userdata group/subfunction.
// The tables below were extracted with tshark -T fields; frames tshark
// does not dissect (TCP retransmissions) are absent.
type s7Expect struct {
	frame    int
	cotpType COTPType
	rosctr   S7CommROSCTR
	function S7CommFunction
	pduRef   uint16
	paramLen uint16
	dataLen  uint16
	group    S7CommFuncGroup
	subfunc  S7CommSubfunction
}

// s7Packets decodes every packet of a testdata capture with port 102
// mapped to TPKT. Panics are not recovered.
func s7Packets(t *testing.T, name string) []gopacket.Packet {
	t.Helper()
	registerS7Decoders()

	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	r, err := newSimplePcapReader(f)
	if err != nil {
		t.Fatal(err)
	}

	opts := gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true, SkipDecodeRecovery: true}
	var pkts []gopacket.Packet
	for {
		data, err := r.readPacketData()
		if err == io.EOF {
			return pkts
		}
		if err != nil {
			t.Fatal(err)
		}
		pkts = append(pkts, gopacket.NewPacket(data, r.linkType, opts))
	}
}

// s7CheckCapture asserts that every packet decodes without error (one
// octet TCP keep-alives aside) and matches the tshark table where it
// has a row.
func s7CheckCapture(t *testing.T, name string, want []s7Expect) []gopacket.Packet {
	t.Helper()
	pkts := s7Packets(t, name)
	rows := map[int]s7Expect{}
	for _, w := range want {
		rows[w.frame] = w
	}

	seen := 0
	for i, p := range pkts {
		frame := i + 1
		if el := p.ErrorLayer(); el != nil && !s7KeepAlive(p) {
			t.Errorf("%s frame %d: %v", name, frame, el.Error())
		}

		w, ok := rows[frame]
		if !ok {
			continue
		}
		seen++

		cotp, _ := p.Layer(LayerTypeCOTP).(*COTP)
		if cotp == nil || cotp.Type != w.cotpType {
			t.Errorf("%s frame %d: COTP %v, want type %v", name, frame, cotp, w.cotpType)
			continue
		}

		s, _ := p.Layer(LayerTypeS7Comm).(*S7Comm)
		if w.rosctr == 0 {
			if s != nil {
				t.Errorf("%s frame %d: unexpected S7comm layer", name, frame)
			}
			continue
		}
		if s == nil {
			t.Errorf("%s frame %d: no S7comm layer", name, frame)
			continue
		}

		got := s7Expect{frame, cotp.Type, s.ROSCTR, s.Function, s.PDURef, s.ParamLength, s.DataLength, 0, 0}
		if u := s.Userdata; u != nil {
			got.group, got.subfunc = u.FunctionGroup, u.Subfunction
		}
		if got != w {
			t.Errorf("%s frame %d:\n got %+v\nwant %+v", name, frame, got, w)
		}
	}

	if seen != len(want) {
		t.Errorf("%s: matched %d of %d tshark rows", name, seen, len(want))
	}
	return pkts
}

// s7KeepAlive reports whether p is a TCP keep-alive carrying one octet,
// which is not a TPKT.
func s7KeepAlive(p gopacket.Packet) bool {
	tcp, ok := p.Layer(LayerTypeTCP).(*TCP)
	return ok && len(tcp.Payload) == 1
}

// s7Layer returns the S7comm layer of frame (1-based) or fails.
func s7Layer(t *testing.T, pkts []gopacket.Packet, frame int) *S7Comm {
	t.Helper()
	s, ok := pkts[frame-1].Layer(LayerTypeS7Comm).(*S7Comm)
	if !ok {
		t.Fatalf("frame %d: no S7comm layer", frame)
	}
	return s
}

func TestS7CommReadVarPcap(t *testing.T) {
	pkts := s7CheckCapture(t, "s7comm-read-var.pcap", s7ExpectReadVar)

	setup := s7Layer(t, pkts, 7).SetupComm
	if setup == nil || *setup != (S7CommSetupComm{MaxAmQCalling: 4, MaxAmQCalled: 4, PDULength: 480}) {
		t.Errorf("setup communication = %+v", setup)
	}

	job := s7Layer(t, pkts, 10)
	wantItem := S7CommVarItem{
		VarSpec: 0x12, Length: 10, SyntaxID: S7CommSyntaxS7Any,
		TransportSize: S7CommTSByte, Count: 4, DBNumber: 1, Area: S7CommAreaDataBlocks,
		Address: s7Hex("020004000184000000"),
	}
	if job.ItemCount != 1 || len(job.VarItems) != 1 || !reflect.DeepEqual(job.VarItems[0], wantItem) {
		t.Errorf("read var items = %+v", job.VarItems)
	}

	ack := s7Layer(t, pkts, 11)
	wantData := []S7CommDataItem{{S7CommRetSuccess, S7CommDataTSByte, 32, s7Hex("00010002")}}
	if !reflect.DeepEqual(ack.DataItems, wantData) {
		t.Errorf("read var data = %+v", ack.DataItems)
	}
}

func TestS7CommDownloadPcap(t *testing.T) {
	pkts := s7CheckCapture(t, "s7comm-download-db1.pcap", s7ExpectDownload)

	req := s7Layer(t, pkts, 62).BlockControl
	if req == nil || req.Filename != "_0A00001P" || req.LoadMemLength != "000086" || req.MC7Length != "000002" {
		t.Errorf("request download = %+v", req)
	}

	blk := s7Layer(t, pkts, 69).BlockControl
	if blk == nil || blk.DataLength != 86 || blk.DataUnknown != 0x00fb || len(blk.BlockData) != 86 {
		t.Errorf("download block ack = %+v", blk)
	}

	ended := s7Layer(t, pkts, 72)
	if ended.Function != S7CommFuncDownloadEnded || ended.BlockControl.Filename != "_0A00001P" {
		t.Errorf("download ended = %+v", ended.BlockControl)
	}

	pi := s7Layer(t, pkts, 75).PIService
	if pi == nil || pi.ServiceName != "_INSE" || !bytes.Equal(pi.ParamBlock, []byte("\x01\x000A00001P")) {
		t.Errorf("PI service = %+v", pi)
	}

	pw := s7Layer(t, pkts, 57).Userdata
	if pw == nil || pw.FunctionGroup != S7CommGroupSecurity || pw.Type != S7CommUDTypeRequest || pw.Length != 8 {
		t.Errorf("password userdata = %+v", pw)
	}
}

func TestS7CommBlocklistPcap(t *testing.T) {
	pkts := s7CheckCapture(t, "s7comm-blocklist.pcap", s7ExpectBlocklist)

	szl := s7Layer(t, pkts, 11).Userdata.SZL
	if szl == nil || szl.ID != 0x0132 || szl.Index != 0x0004 || szl.RecordLength != 40 || len(szl.Records) != 1 || len(szl.Records[0]) != 40 {
		t.Errorf("SZL 0x0132 = %+v", szl)
	}

	hdr := s7Layer(t, pkts, 26).Userdata.SZL
	if hdr == nil || !hdr.HeaderOnly() || hdr.RecordCount != 7 || hdr.Records != nil {
		t.Errorf("SZL 0x0F74 = %+v", hdr)
	}

	part := s7Layer(t, pkts, 29).Userdata.SZL
	if part == nil || part.ID != 0x0074 || len(part.Records) != 7 || len(part.Records[6]) != 4 {
		t.Errorf("SZL 0x0074 = %+v", part)
	}

	info := s7Layer(t, pkts, 43).Userdata
	if info.BlockType != S7CommBlockSDB || info.BlockNumber != "32768" || info.Filesystem != 'B' {
		t.Errorf("get block info request = %+v", info)
	}
	if e := s7Layer(t, pkts, 44).Userdata; e.ErrorCode != 0xd209 || e.ReturnCode != S7CommRetObjectMissing {
		t.Errorf("get block info response = %+v", e)
	}

	counts := []S7CommBlockCount{
		{S7CommBlockOB, 1}, {S7CommBlockFB, 0}, {S7CommBlockFC, 0}, {S7CommBlockDB, 1},
		{S7CommBlockSDB, 12}, {S7CommBlockSFC, 71}, {S7CommBlockSFB, 14},
	}
	if got := s7Layer(t, pkts, 59).Userdata.BlockCounts; !reflect.DeepEqual(got, counts) {
		t.Errorf("list blocks = %v", got)
	}

	if bt := s7Layer(t, pkts, 61).Userdata.BlockType; bt != S7CommBlockDB {
		t.Errorf("list blocks of type request = %v", bt)
	}
	entries := []S7CommBlockEntry{{1, 0x22, S7CommLangDB}}
	if got := s7Layer(t, pkts, 62).Userdata.BlockEntries; !reflect.DeepEqual(got, entries) {
		t.Errorf("list blocks of type = %v", got)
	}

	// A response split over PDUs stays raw: only the whole has structure.
	frag := s7Layer(t, pkts, 17).Userdata
	if !frag.Fragmented() || frag.SZL != nil || len(frag.Data) == 0 {
		t.Errorf("fragmented SZL = %+v", frag)
	}
}

// s7PDU wraps an S7comm PDU in TPKT and a class 0 DT.
func s7PDU(pdu []byte) []byte {
	b := []byte{TPKTVersion, 0, 0, 0, 0x02, 0xf0, 0x80}
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)+len(pdu)))
	return append(b, pdu...)
}

// Hand-built PDUs for functions the captures do not cover.
var (
	// Write Var job: DB1.DBB0 (BYTE, fill octet follows) and M2.3 (BIT).
	s7TestWriteJob = s7Hex("3201000000010" + "01a000b" +
		"0502" + "120a10020001000184000000" + "120a10010001000083000013" +
		"00040008ab00" + "0003000101")
	s7TestWriteAck   = s7Hex("320300000001000200020000" + "0502" + "ff0a")
	s7TestStartUpJob = s7Hex("320100000002001200 00" + "1d000000000000000" + "9" + "5f3038303030303141")
	s7TestStartUpAck = s7Hex("3203000000020010000000 00" + "1d00010000000007" + "07" + "30303030313834")
	s7TestUploadJob  = s7Hex("320100000003000800 00" + "1e00000000000007")
	s7TestUploadAck  = s7Hex("320300000003000200070000" + "1e00" + "000300fb707001")
	s7TestEndUpJob   = s7Hex("320100000004000800 00" + "1f00000000000007")
	s7TestPLCStop    = s7Hex("320100000005001000 00" + "290000000000" + "09" + "505f50524f4752414d")
)

func TestS7CommWriteVar(t *testing.T) {
	var s S7Comm
	if err := s.DecodeFromBytes(s7TestWriteJob, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}

	if len(s.VarItems) != 2 || s.VarItems[1].Area != S7CommAreaFlags || s.VarItems[1].ByteOffset() != 2 || s.VarItems[1].BitOffset() != 3 {
		t.Errorf("items = %+v", s.VarItems)
	}
	want := []S7CommDataItem{
		{S7CommRetReserved, S7CommDataTSByte, 8, []byte{0xab}},
		{S7CommRetReserved, S7CommDataTSBit, 1, []byte{0x01}},
	}
	if !reflect.DeepEqual(s.DataItems, want) {
		t.Errorf("data items = %+v", s.DataItems)
	}

	if err := s.DecodeFromBytes(s7TestWriteAck, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.WriteResults, []S7CommReturnCode{S7CommRetSuccess, S7CommRetObjectMissing}) {
		t.Errorf("write results = %v", s.WriteResults)
	}
}

func TestS7CommUpload(t *testing.T) {
	cases := []struct {
		name string
		pdu  []byte
		want S7CommBlockControl
	}{
		{"start upload job", s7TestStartUpJob, S7CommBlockControl{Filename: "_0800001A"}},
		{"start upload ack", s7TestStartUpAck, S7CommBlockControl{ErrorCode: 0x0100, UploadID: 7, BlockLength: "0000184"}},
		{"upload job", s7TestUploadJob, S7CommBlockControl{UploadID: 7}},
		{"upload ack", s7TestUploadAck, S7CommBlockControl{DataLength: 3, DataUnknown: 0xfb, BlockData: s7Hex("707001")}},
		{"end upload job", s7TestEndUpJob, S7CommBlockControl{UploadID: 7}},
	}

	for _, c := range cases {
		var s S7Comm
		if err := s.DecodeFromBytes(c.pdu, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if s.BlockControl == nil || !reflect.DeepEqual(*s.BlockControl, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, s.BlockControl, c.want)
		}
	}

	var stop S7Comm
	if err := stop.DecodeFromBytes(s7TestPLCStop, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if stop.PIService == nil || stop.PIService.ServiceName != "P_PROGRAM" || stop.PIService.ParamBlock != nil {
		t.Errorf("PLC stop = %+v", stop.PIService)
	}
}

// TestS7CommMalformed feeds length lies and counts larger than the data.
func TestS7CommMalformed(t *testing.T) {
	cases := []struct {
		name string
		pdu  string
		want error
	}{
		{"short header", "320100000000", ErrS7CommTooShort},
		{"bad protocol", "33010000000000000000", ErrS7CommBadProtocol},
		{"bad ROSCTR", "32050000000000000000", ErrS7CommUnknownROSCTR},
		{"ack header cut", "32030000000000000000", ErrS7CommTooShort},
		{"param length lie", "3201000000000010000004", ErrS7CommTooShort},
		{"data length lie", "320100000000000000ff", ErrS7CommTooShort},
		{"item count lie", "32010000000000080000" + "04ff120a1002000400", ErrS7CommMalformed},
		{"item address lie", "32010000000000080000" + "040112ff10020004", ErrS7CommMalformed},
		{"S7ANY too short", "32010000000000070000" + "04011203100200", ErrS7CommMalformed},
		{"data item count lie", "320300000000000200040000" + "04ffff040008", ErrS7CommMalformed},
		{"data item length lie", "320300000000000200050000" + "0401ff0400ffaa", ErrS7CommMalformed},
		{"write result lie", "320300000000000200010000" + "0503ff", ErrS7CommMalformed},
		{"setup too short", "32010000000000020000" + "f000", ErrS7CommMalformed},
		{"filename lie", "32010000000000090000" + "1b000000000000000f", ErrS7CommMalformed},
		{"PI block lie", "320100000000000c0000" + "28000000000000fd0fff" + "0000", ErrS7CommMalformed},
		{"userdata param lie", "32070000000000080000" + "000112ff11440100", ErrS7CommMalformed},
		{"userdata data lie", "32070000000000080005" + "0001120411440100" + "ff09ffff00", ErrS7CommMalformed},
		{"SZL count lie", "320700000000000c000c" + "000112081284010000000000" + "ff090008" + "0011000000140005", ErrS7CommMalformed},
	}

	for _, c := range cases {
		var s S7Comm
		err := s.DecodeFromBytes(s7Hex(c.pdu), gopacket.NilDecodeFeedback)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

// TestS7CommSZLZeroLength checks that a huge record count of zero-length
// records allocates nothing: the claim is not backed by data.
func TestS7CommSZLZeroLength(t *testing.T) {
	pdu := s7Hex("320700000000000c000c" + "000112081284010000000000" + "ff090008" + "00110000" + "0000ffff")
	var s S7Comm
	if err := s.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}

	szl := s.Userdata.SZL
	if szl == nil || szl.RecordCount != 0xffff || szl.Records != nil {
		t.Errorf("SZL = %+v", szl)
	}
}

// s7Squeeze truncates an S7comm PDU to n octets and shrinks the header
// lengths to fit, so inner parsers see consistent but cut content.
func s7Squeeze(pdu []byte, n int) []byte {
	b := append([]byte{}, pdu[:n]...)
	hdr := s7commHeaderLen
	if len(b) > 1 && S7CommROSCTR(b[1]).hasError() {
		hdr = s7commAckHeaderLen
	}
	if n < hdr {
		return b
	}

	param := int(binary.BigEndian.Uint16(b[6:8]))
	if param > n-hdr {
		param = n - hdr
	}
	binary.BigEndian.PutUint16(b[6:8], uint16(param))
	binary.BigEndian.PutUint16(b[8:10], uint16(n-hdr-param))
	return b
}

// s7Vectors returns every TPKT frame of the S7comm captures plus the
// hand-built PDUs, as TPKT frames.
func s7Vectors(t *testing.T) [][]byte {
	t.Helper()
	var out [][]byte
	for _, name := range []string{"s7comm-read-var.pcap", "s7comm-download-db1.pcap", "s7comm-blocklist.pcap"} {
		for _, p := range s7Packets(t, name) {
			if tp, ok := p.Layer(LayerTypeTPKT).(*TPKT); ok {
				out = append(out, append(tp.Contents, tp.Payload...))
			}
		}
	}

	for _, pdu := range [][]byte{s7TestWriteJob, s7TestWriteAck, s7TestStartUpJob, s7TestStartUpAck,
		s7TestUploadJob, s7TestUploadAck, s7TestEndUpJob, s7TestPLCStop} {
		out = append(out, s7PDU(pdu))
	}
	return out
}

// TestS7CommTruncation cuts every vector at every offset, both as a
// whole TPKT frame and as an S7comm PDU with consistent header lengths.
// Nothing may panic; cut TPKT frames must report an error.
func TestS7CommTruncation(t *testing.T) {
	for _, v := range s7Vectors(t) {
		for n := 0; n < len(v); n++ {
			p := gopacket.NewPacket(v[:n], LayerTypeTPKT, s7NoRecover)
			if p.ErrorLayer() == nil {
				t.Fatalf("frame %x cut at %d: no error", v, n)
			}
		}

		var s S7Comm
		pdu := v[tpktHeaderLen+3:]
		if !isS7Comm(pdu) {
			continue
		}
		for n := 0; n <= len(pdu); n++ {
			_ = s.DecodeFromBytes(s7Squeeze(pdu, n), gopacket.NilDecodeFeedback)
		}
	}
}

// FuzzTPKT decodes arbitrary segments from TPKT down through COTP and
// S7comm, eagerly, lazily and with DecodeFromBytes.
func FuzzTPKT(f *testing.F) {
	for _, v := range [][]byte{s7TestCR, s7TestCC, s7TestSetupJob, s7TestSetupAck, s7TestEmptyDT, s7TestReadJob, s7TestReadAck} {
		f.Add(v)
	}
	for _, pdu := range [][]byte{s7TestWriteJob, s7TestWriteAck, s7TestStartUpAck, s7TestUploadAck, s7TestPLCStop} {
		f.Add(s7PDU(pdu))
	}
	f.Add(bytes.Join([][]byte{s7TestSetupJob, s7TestEmptyDT, s7TestReadAck}, nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, opt := range []gopacket.DecodeOptions{s7NoRecover, {Lazy: true, SkipDecodeRecovery: true}} {
			p := gopacket.NewPacket(data, LayerTypeTPKT, opt)
			for _, l := range p.Layers() {
				_ = gopacket.LayerString(l)
			}
		}

		var s S7Comm
		if s.DecodeFromBytes(data, gopacket.NilDecodeFeedback) == nil {
			if len(s.Contents)+len(s.Payload) != len(data) || len(s.DataItems) > int(s.ItemCount) {
				t.Fatalf("inconsistent S7comm: %+v", s)
			}
		}
		var c COTP
		_ = c.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	})
}

var s7ExpectReadVar = []s7Expect{
	{4, 0xE0, 0, 0, 0, 0, 0, 0, 0},
	{5, 0xD0, 0, 0, 0, 0, 0, 0, 0},
	{6, 0xF0, 1, 0xF0, 65535, 8, 0, 0, 0},
	{7, 0xF0, 3, 0xF0, 65535, 8, 0, 0, 0},
	{8, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{10, 0xF0, 1, 0x04, 0, 14, 0, 0, 0},
	{11, 0xF0, 3, 0x04, 0, 2, 8, 0, 0},
	{12, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{14, 0xF0, 1, 0x04, 0, 14, 0, 0, 0},
	{15, 0xF0, 3, 0x04, 0, 2, 8, 0, 0},
	{16, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{18, 0xF0, 1, 0x04, 0, 14, 0, 0, 0},
	{19, 0xF0, 3, 0x04, 0, 2, 8, 0, 0},
	{20, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{22, 0xF0, 1, 0x04, 0, 14, 0, 0, 0},
	{23, 0xF0, 3, 0x04, 0, 2, 8, 0, 0},
	{24, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{26, 0xF0, 1, 0x04, 0, 14, 0, 0, 0},
	{27, 0xF0, 3, 0x04, 0, 2, 8, 0, 0},
	{28, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{30, 0xF0, 1, 0x04, 0, 14, 0, 0, 0},
	{31, 0xF0, 3, 0x04, 0, 2, 8, 0, 0},
	{32, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{34, 0xF0, 1, 0x04, 0, 14, 0, 0, 0},
	{35, 0xF0, 3, 0x04, 0, 2, 8, 0, 0},
	{36, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{38, 0xF0, 1, 0x04, 0, 14, 0, 0, 0},
}

var s7ExpectDownload = []s7Expect{
	{4, 0xE0, 0, 0, 0, 0, 0, 0, 0},
	{6, 0xD0, 0, 0, 0, 0, 0, 0, 0},
	{7, 0xF0, 1, 0xF0, 512, 8, 0, 0, 0},
	{9, 0xF0, 3, 0xF0, 512, 8, 0, 0, 0},
	{10, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{11, 0xF0, 7, 0x00, 768, 8, 8, 4, 1},
	{14, 0xF0, 7, 0x00, 768, 12, 52, 4, 1},
	{15, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{17, 0xF0, 7, 0x00, 1024, 8, 8, 4, 1},
	{19, 0xF0, 7, 0x00, 1024, 12, 52, 4, 1},
	{20, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{21, 0xF0, 7, 0x00, 1280, 8, 8, 4, 1},
	{24, 0xF0, 7, 0x00, 1280, 12, 192, 4, 1},
	{25, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{26, 0xF0, 7, 0x00, 1536, 8, 8, 4, 1},
	{29, 0xF0, 7, 0x00, 1536, 12, 52, 4, 1},
	{30, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{31, 0xF0, 7, 0x00, 1792, 8, 4, 3, 1},
	{34, 0xF0, 7, 0x00, 1792, 12, 32, 3, 1},
	{35, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{36, 0xF0, 7, 0x00, 2048, 8, 4, 3, 1},
	{39, 0xF0, 7, 0x00, 2048, 12, 32, 3, 1},
	{40, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{41, 0xF0, 7, 0x00, 2304, 8, 6, 3, 2},
	{44, 0xF0, 7, 0x00, 2304, 12, 8, 3, 2},
	{45, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{46, 0xF0, 7, 0x00, 2560, 8, 12, 3, 3},
	{49, 0xF0, 7, 0x00, 2560, 12, 4, 3, 3},
	{50, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{51, 0xF0, 7, 0x00, 2816, 8, 8, 4, 1},
	{54, 0xF0, 7, 0x00, 2816, 12, 52, 4, 1},
	{55, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{57, 0xF0, 7, 0x00, 3072, 8, 12, 5, 1},
	{59, 0xF0, 7, 0x00, 3072, 12, 4, 5, 1},
	{60, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{62, 0xF0, 1, 0x1A, 3328, 32, 0, 0, 0},
	{64, 0xF0, 3, 0x1A, 3328, 1, 0, 0, 0},
	{65, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{67, 0xF0, 1, 0x1B, 208, 18, 0, 0, 0},
	{68, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{69, 0xF0, 3, 0x1B, 208, 2, 90, 0, 0},
	{72, 0xF0, 1, 0x1C, 208, 18, 0, 0, 0},
	{73, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{74, 0xF0, 3, 0x1C, 208, 1, 0, 0, 0},
	{75, 0xF0, 1, 0x28, 3584, 26, 0, 0, 0},
	{79, 0xF0, 3, 0x28, 3584, 1, 0, 0, 0},
	{80, 0xF0, 0, 0, 0, 0, 0, 0, 0},
}

var s7ExpectBlocklist = []s7Expect{
	{5, 0xE0, 0, 0, 0, 0, 0, 0, 0},
	{6, 0xD0, 0, 0, 0, 0, 0, 0, 0},
	{7, 0xF0, 1, 0xF0, 512, 8, 0, 0, 0},
	{8, 0xF0, 3, 0xF0, 512, 8, 0, 0, 0},
	{9, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{10, 0xF0, 7, 0x00, 768, 8, 8, 4, 1},
	{11, 0xF0, 7, 0x00, 768, 12, 52, 4, 1},
	{12, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{13, 0xF0, 7, 0x00, 1024, 8, 8, 4, 1},
	{14, 0xF0, 7, 0x00, 1024, 12, 218, 4, 1},
	{15, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{16, 0xF0, 7, 0x00, 1280, 12, 4, 4, 1},
	{17, 0xF0, 7, 0x00, 1280, 12, 22, 4, 1},
	{18, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{19, 0xF0, 7, 0x00, 1536, 8, 8, 4, 1},
	{20, 0xF0, 7, 0x00, 1536, 12, 40, 4, 1},
	{21, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{22, 0xF0, 7, 0x00, 1792, 8, 8, 4, 1},
	{23, 0xF0, 7, 0x00, 1792, 12, 32, 4, 1},
	{24, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{25, 0xF0, 7, 0x00, 2048, 8, 8, 4, 1},
	{26, 0xF0, 7, 0x00, 2048, 12, 12, 4, 1},
	{27, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{28, 0xF0, 7, 0x00, 2304, 8, 8, 4, 1},
	{29, 0xF0, 7, 0x00, 2304, 12, 40, 4, 1},
	{30, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{35, 0xE0, 0, 0, 0, 0, 0, 0, 0},
	{36, 0xD0, 0, 0, 0, 0, 0, 0, 0},
	{37, 0xF0, 1, 0xF0, 512, 8, 0, 0, 0},
	{38, 0xF0, 3, 0xF0, 512, 8, 0, 0, 0},
	{39, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{40, 0xF0, 7, 0x00, 768, 8, 8, 4, 1},
	{41, 0xF0, 7, 0x00, 768, 12, 52, 4, 1},
	{42, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{43, 0xF0, 7, 0x00, 1024, 8, 12, 3, 3},
	{44, 0xF0, 7, 0x00, 1024, 12, 4, 3, 3},
	{45, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{50, 0xE0, 0, 0, 0, 0, 0, 0, 0},
	{51, 0xD0, 0, 0, 0, 0, 0, 0, 0},
	{52, 0xF0, 1, 0xF0, 512, 8, 0, 0, 0},
	{53, 0xF0, 3, 0xF0, 512, 8, 0, 0, 0},
	{54, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{55, 0xF0, 7, 0x00, 768, 8, 8, 4, 1},
	{56, 0xF0, 7, 0x00, 768, 12, 52, 4, 1},
	{57, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{58, 0xF0, 7, 0x00, 1024, 8, 4, 3, 1},
	{59, 0xF0, 7, 0x00, 1024, 12, 32, 3, 1},
	{60, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{61, 0xF0, 7, 0x00, 1280, 8, 6, 3, 2},
	{62, 0xF0, 7, 0x00, 1280, 12, 8, 3, 2},
	{63, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{68, 0xE0, 0, 0, 0, 0, 0, 0, 0},
	{69, 0xD0, 0, 0, 0, 0, 0, 0, 0},
	{70, 0xF0, 1, 0xF0, 512, 8, 0, 0, 0},
	{71, 0xF0, 3, 0xF0, 512, 8, 0, 0, 0},
	{72, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{73, 0xF0, 7, 0x00, 768, 8, 8, 4, 1},
	{74, 0xF0, 7, 0x00, 768, 12, 52, 4, 1},
	{75, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{76, 0xF0, 7, 0x00, 1024, 8, 12, 3, 3},
	{78, 0xF0, 7, 0x00, 1024, 12, 4, 3, 3},
	{79, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{84, 0xE0, 0, 0, 0, 0, 0, 0, 0},
	{85, 0xD0, 0, 0, 0, 0, 0, 0, 0},
	{86, 0xF0, 1, 0xF0, 512, 8, 0, 0, 0},
	{87, 0xF0, 3, 0xF0, 512, 8, 0, 0, 0},
	{88, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{89, 0xF0, 7, 0x00, 768, 8, 8, 4, 1},
	{90, 0xF0, 7, 0x00, 768, 12, 52, 4, 1},
	{91, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{92, 0xF0, 7, 0x00, 1024, 8, 4, 3, 1},
	{93, 0xF0, 7, 0x00, 1024, 12, 32, 3, 1},
	{94, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{95, 0xF0, 7, 0x00, 1280, 8, 6, 3, 2},
	{96, 0xF0, 7, 0x00, 1280, 12, 212, 3, 2},
	{97, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{98, 0xF0, 7, 0x00, 1536, 12, 4, 3, 2},
	{99, 0xF0, 7, 0x00, 1536, 12, 80, 3, 2},
	{100, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{101, 0xF0, 7, 0x00, 1792, 8, 4, 3, 1},
	{102, 0xF0, 7, 0x00, 1792, 12, 32, 3, 1},
	{103, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{104, 0xF0, 7, 0x00, 2048, 8, 6, 3, 2},
	{105, 0xF0, 7, 0x00, 2048, 12, 60, 3, 2},
	{106, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{107, 0xF0, 7, 0x00, 2304, 8, 4, 3, 1},
	{109, 0xF0, 7, 0x00, 2304, 12, 32, 3, 1},
	{110, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{111, 0xF0, 7, 0x00, 2560, 8, 4, 3, 1},
	{112, 0xF0, 7, 0x00, 2560, 12, 32, 3, 1},
	{113, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{114, 0xF0, 7, 0x00, 2816, 8, 4, 3, 1},
	{115, 0xF0, 7, 0x00, 2816, 12, 32, 3, 1},
	{116, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{117, 0xF0, 7, 0x00, 3072, 8, 6, 3, 2},
	{118, 0xF0, 7, 0x00, 3072, 12, 8, 3, 2},
	{119, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{120, 0xF0, 7, 0x00, 3328, 8, 4, 3, 1},
	{121, 0xF0, 7, 0x00, 3328, 12, 32, 3, 1},
	{122, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{123, 0xF0, 7, 0x00, 3584, 8, 6, 3, 2},
	{124, 0xF0, 7, 0x00, 3584, 12, 8, 3, 2},
	{125, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{126, 0xF0, 7, 0x00, 3840, 8, 4, 3, 1},
	{127, 0xF0, 7, 0x00, 3840, 12, 32, 3, 1},
	{128, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{129, 0xF0, 7, 0x00, 4096, 8, 6, 3, 2},
	{130, 0xF0, 7, 0x00, 4096, 12, 52, 3, 2},
	{131, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{133, 0xF0, 7, 0x00, 4352, 8, 12, 3, 3},
	{134, 0xF0, 7, 0x00, 4352, 12, 82, 3, 3},
	{135, 0xF0, 0, 0, 0, 0, 0, 0, 0},
	{136, 0xF0, 7, 0x00, 4608, 8, 12, 3, 3},
	{137, 0xF0, 7, 0x00, 4608, 12, 82, 3, 3},
	{138, 0xF0, 0, 0, 0, 0, 0, 0, 0},
}

// RecordLength 0xFFFF times RecordCount 0x8001 overflows a 32-bit int to
// a negative size, which used to pass the size check and panic.
func TestS7CommSZLSizeOverflow(t *testing.T) {
	pdu := []byte{
		0x32, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x0c,
		0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x09, 0x00, 0x08, 0x00, 0x11, 0x00, 0x00, 0xff, 0xff, 0x80, 0x01,
	}

	s := &S7Comm{}
	if err := s.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err == nil {
		t.Fatal("SZL with an overflowing size decoded without error")
	}
}
