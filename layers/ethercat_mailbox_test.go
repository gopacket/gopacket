// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// ethercat-handmade.pcap holds 75 hand-built frames (text2pcap) for what
// the public captures lack: every mailbox protocol and CoE service, all
// ADS commands, frame types 2 to 5 and the common ESC registers. tshark
// 4.7 dissects every frame without a malformed or expert note except
// frame 34, a packed EoE set IP request it calls too short. Expected
// values were checked against tshark field by field.
const ecatHandPcap = "testdata/ethercat-handmade.pcap"

// Frame numbers in ethercat-handmade.pcap, 1-based.
const (
	ecatHandSDOInfoListReq = 1 + iota
	ecatHandSDOInfoListRes
	ecatHandSDOInfoObjReq
	ecatHandSDOInfoObjRes
	ecatHandSDOInfoEntryReq
	ecatHandSDOInfoEntryRes
	ecatHandSDOInfoEntryLimits
	ecatHandSDOInfoError
	ecatHandEmergency
	ecatHandTxPDO
	ecatHandRxPDO
	ecatHandTxPDORTR
	ecatHandRxPDORTR
	ecatHandSDODownloadNormal
	ecatHandSDODownloadRes
	ecatHandSDODownloadSeg
	ecatHandSDODownloadSegRes
	ecatHandSDOUploadComplete
	ecatHandSDOUploadNormal
	ecatHandSDOUploadSeg
	ecatHandSDOUploadSegRes
	ecatHandSDOUpload2
	ecatHandSDOUpload1
	ecatHandSDOUpload3
	ecatHandSDODownload4
	ecatHandSDOAbort
	ecatHandEoEFragment0
	ecatHandEoEFragment1
	ecatHandEoETimestamp
	ecatHandEoESetIP
	ecatHandEoESetIPRes
	ecatHandEoEMACFilter
	ecatHandEoEMACFilterRes
	ecatHandEoESetIPPacked
	ecatHandFoEWRQ
	ecatHandFoERRQ
	ecatHandFoEData
	ecatHandFoEDataLong
	ecatHandFoEAck
	ecatHandFoEErr
	ecatHandFoEBusy
	ecatHandSoEReadReq
	ecatHandSoEReadRes
	ecatHandSoEWriteReq
	ecatHandSoEWriteRes
	ecatHandSoENotification
	ecatHandSoEFragment
	ecatHandSoEError
	ecatHandVoE
	ecatHandADSReadReq
	ecatHandADSReadRes
	ecatHandADSWriteReq
	ecatHandADSWriteRes
	ecatHandADSReadWriteReq
	ecatHandADSReadWriteRes
	ecatHandADSReadStateReq
	ecatHandADSReadStateRes
	ecatHandADSWriteCtrlReq
	ecatHandADSWriteCtrlRes
	ecatHandADSDevInfoReq
	ecatHandADSDevInfoRes
	ecatHandADSAddNoteReq
	ecatHandADSAddNoteRes
	ecatHandADSDelNoteReq
	ecatHandADSDelNoteRes
	ecatHandADSNotification
	ecatHandAMSSystem
	ecatHandFrameADS
	ecatHandFrameRawIO
	ecatHandFrameNV
	ecatHandFrameMailbox
	ecatHandRegistersAL
	ecatHandRegistersFMMU
	ecatHandRegistersDC
	ecatHandRegistersInfo
	ecatHandFrames = iota
)

// ecatHand decodes the hand-made capture; index 0 is frame 1.
func ecatHand(t *testing.T) []*EtherCAT {
	t.Helper()
	withEtherCAT(t)

	var out []*EtherCAT
	for i, data := range readPNECATPcap(t, ecatHandPcap) {
		p := gopacket.NewPacket(data, LinkTypeEthernet, gopacket.Default)
		if el := p.ErrorLayer(); el != nil {
			t.Fatalf("frame %d: %v", i+1, el.Error())
		}
		e, ok := p.Layer(LayerTypeEtherCAT).(*EtherCAT)
		if !ok {
			t.Fatalf("frame %d: no EtherCAT layer", i+1)
		}
		out = append(out, e)
	}
	if len(out) != ecatHandFrames {
		t.Fatalf("%d frames, want %d", len(out), ecatHandFrames)
	}
	return out
}

// ecatSame compares two values by their %+v form, which treats nil and
// empty slices alike. Pointers must be compared one level down.
func ecatSame(t *testing.T, name string, got, want interface{}) {
	t.Helper()
	g, w := fmt.Sprintf("%+v", got), fmt.Sprintf("%+v", want)
	if g != w {
		t.Errorf("%s:\n got %s\nwant %s", name, g, w)
	}
}

// ecatMbx returns the mailbox of the only datagram of a hand-made frame.
func ecatMbx(t *testing.T, frames []*EtherCAT, n int) *EtherCATMailbox {
	t.Helper()
	e := frames[n-1]
	if len(e.Datagrams) != 1 || e.Datagrams[0].Mailbox == nil {
		t.Fatalf("frame %d: no mailbox: %+v", n, e)
	}
	return e.Datagrams[0].Mailbox
}

func TestEtherCATSDOInfo(t *testing.T) {
	frames := ecatHand(t)
	info := func(n int) EtherCATSDOInfo {
		m := ecatMbx(t, frames, n)
		if m.CoE == nil || m.CoE.Service != EtherCATCoESDOInfo || m.CoE.SDOInfo == nil {
			t.Fatalf("frame %d: no SDO info: %+v", n, m.CoE)
		}
		i := *m.CoE.SDOInfo
		i.Data = nil
		return i
	}

	ecatSame(t, "list req", info(ecatHandSDOInfoListReq),
		EtherCATSDOInfo{OpCode: EtherCATSDOInfoListRequest, ListType: EtherCATSDOInfoListAll})
	ecatSame(t, "list res", info(ecatHandSDOInfoListRes), EtherCATSDOInfo{
		OpCode: EtherCATSDOInfoListResponse, Incomplete: true, FragmentsLeft: 2,
		ListType: EtherCATSDOInfoListAll, Indexes: []uint16{0x1000, 0x1018, 0x1c00},
	})
	ecatSame(t, "obj req", info(ecatHandSDOInfoObjReq),
		EtherCATSDOInfo{OpCode: EtherCATSDOInfoObjectRequest, Index: 0x1018})
	ecatSame(t, "obj res", info(ecatHandSDOInfoObjRes), EtherCATSDOInfo{
		OpCode: EtherCATSDOInfoObjectResponse, Index: 0x1018, DataType: 0x23,
		MaxSubIndex: 4, ObjectCode: 9, Name: []byte("Identity"),
	})
	ecatSame(t, "entry req", info(ecatHandSDOInfoEntryReq),
		EtherCATSDOInfo{OpCode: EtherCATSDOInfoEntryRequest, Index: 0x1018, SubIndex: 1})
	ecatSame(t, "entry res", info(ecatHandSDOInfoEntryRes), EtherCATSDOInfo{
		OpCode: EtherCATSDOInfoEntryResponse, Index: 0x1018, SubIndex: 1,
		DataType: 7, BitLength: 32, Access: 7, Name: []byte("Vendor ID"),
	})

	// Unit, default, min and max: decoded per ETG.1000.6, not by tshark.
	ecatSame(t, "entry limits", info(ecatHandSDOInfoEntryLimits), EtherCATSDOInfo{
		OpCode: EtherCATSDOInfoEntryResponse, Index: 0x6040, SubIndex: 2, ValueInfo: 0x78,
		DataType: 6, BitLength: 16, Access: 0x3f, UnitType: 0x1234,
		Default: []byte{100, 0}, Min: []byte{0, 0}, Max: []byte{0x88, 0x13}, Name: []byte("Speed"),
	})
	ecatSame(t, "error", info(ecatHandSDOInfoError),
		EtherCATSDOInfo{OpCode: EtherCATSDOInfoError, AbortCode: EtherCATSDOAbortNoObject})

	if got := EtherCATSDOAbortNoObject.String(); got != "Object does not exist in the object dictionary" {
		t.Errorf("abort string %q", got)
	}
	if got := EtherCATSDOAbortCode(1).String(); got != "Unknown(0x00000001)" {
		t.Errorf("abort string %q", got)
	}
	if got := EtherCATSDOInfoEntryResponse.String(); got != "Entry Res" {
		t.Errorf("opcode string %q", got)
	}
}

func TestEtherCATCoEServices(t *testing.T) {
	frames := ecatHand(t)
	coe := func(n int, service EtherCATCoEService) *EtherCATCoE {
		m := ecatMbx(t, frames, n)
		if m.CoE == nil || m.CoE.Service != service {
			t.Fatalf("frame %d: CoE %+v, want service %v", n, m.CoE, service)
		}
		return m.CoE
	}

	c := coe(ecatHandEmergency, EtherCATCoEEmergency)
	if c.Emergency == nil {
		t.Fatal("no emergency")
	}
	ecatSame(t, "emergency", *c.Emergency,
		EtherCATEmergency{ErrorCode: 0x8130, ErrorRegister: 0x10, Data: []byte{1, 2, 3, 4, 5}})

	// PDO services: the number is the PDO number, Data the PDO.
	c = coe(ecatHandTxPDO, EtherCATCoETxPDO)
	ecatSame(t, "txpdo", []interface{}{c.Number, c.Data}, []interface{}{uint16(0x1a0), []byte{0, 1, 2, 3, 4, 5, 6, 7}})
	c = coe(ecatHandRxPDO, EtherCATCoERxPDO)
	ecatSame(t, "rxpdo", []interface{}{c.Number, c.Data}, []interface{}{uint16(0x1a1), []byte{8, 9, 10, 11}})
	c = coe(ecatHandTxPDORTR, EtherCATCoETxPDORemote)
	ecatSame(t, "txpdo rtr", []interface{}{c.Number, len(c.Data)}, []interface{}{uint16(0x1a0), 0})
	c = coe(ecatHandRxPDORTR, EtherCATCoERxPDORemote)
	ecatSame(t, "rxpdo rtr", []interface{}{c.Number, len(c.Data)}, []interface{}{uint16(0x1a1), 0})

	sdo := func(n int, service EtherCATCoEService) EtherCATSDO {
		c := coe(n, service)
		if c.SDO == nil {
			t.Fatalf("frame %d: no SDO", n)
		}
		return *c.SDO
	}
	req, res := EtherCATCoESDORequest, EtherCATCoESDOResponse

	ecatSame(t, "download normal", sdo(ecatHandSDODownloadNormal, req), EtherCATSDO{
		Command: 0x31, Specifier: EtherCATSDOCCSInitiateDownload, Index: 0x1c12, Value: 6,
		Data: []byte{2, 0, 0, 0x16, 1, 0x16}, SizeIndicated: true, CompleteAccess: true,
	})
	ecatSame(t, "download res", sdo(ecatHandSDODownloadRes, res),
		EtherCATSDO{Command: 0x60, Specifier: EtherCATSDOSCSInitiateDownload, Index: 0x1c12})
	ecatSame(t, "download segment", sdo(ecatHandSDODownloadSeg, req), EtherCATSDO{
		Command: 0x17, Specifier: EtherCATSDOCCSDownloadSegment, Segment: true,
		Data: []byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0}, LastSegment: true, Toggle: true, UnusedBytes: 3,
	})
	ecatSame(t, "download segment res", sdo(ecatHandSDODownloadSegRes, res),
		EtherCATSDO{Command: 0x30, Specifier: EtherCATSDOSCSDownloadSegment, Toggle: true})
	ecatSame(t, "upload complete", sdo(ecatHandSDOUploadComplete, req),
		EtherCATSDO{Command: 0x50, Specifier: EtherCATSDOCCSInitiateUpload, Index: 0x1c13, CompleteAccess: true})
	ecatSame(t, "upload normal", sdo(ecatHandSDOUploadNormal, res), EtherCATSDO{
		Command: 0x41, Specifier: EtherCATSDOSCSInitiateUpload, Index: 0x1c13, Value: 20,
		Data: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, SizeIndicated: true,
	})
	ecatSame(t, "upload segment", sdo(ecatHandSDOUploadSeg, req),
		EtherCATSDO{Command: 0x70, Specifier: EtherCATSDOCCSUploadSegment, Toggle: true})
	ecatSame(t, "upload segment res", sdo(ecatHandSDOUploadSegRes, res), EtherCATSDO{
		Command: 0x15, Specifier: EtherCATSDOSCSUploadSegment, Segment: true,
		Data: []byte{10, 11, 12, 13, 14, 0, 0}, LastSegment: true, Toggle: true, UnusedBytes: 2,
	})

	// Expedited transfers of 2, 1, 3 and 4 bytes.
	expedited := []struct {
		frame   int
		service EtherCATCoEService
		want    EtherCATSDO
	}{
		{ecatHandSDOUpload2, res, EtherCATSDO{Command: 0x4b, Index: 0x6041, Value: 0x1234, UnusedBytes: 2, ExpeditedData: []byte{0x34, 0x12}}},
		{ecatHandSDOUpload1, res, EtherCATSDO{Command: 0x4f, Index: 0x6060, Value: 8, UnusedBytes: 3, ExpeditedData: []byte{8}}},
		{ecatHandSDOUpload3, res, EtherCATSDO{Command: 0x47, Index: 0x6061, SubIndex: 3, Value: 0x030201, UnusedBytes: 1, ExpeditedData: []byte{1, 2, 3}}},
		{ecatHandSDODownload4, req, EtherCATSDO{Command: 0x23, Index: 0x607a, Value: 0xcafebabe, ExpeditedData: []byte{0xbe, 0xba, 0xfe, 0xca}}},
	}
	for _, c := range expedited {
		c.want.Specifier = EtherCATSDOSpecifier(c.want.Command >> ethercatSDOSpecShift)
		c.want.SizeIndicated, c.want.Expedited = true, true
		ecatSame(t, fmt.Sprintf("expedited frame %d", c.frame), sdo(c.frame, c.service), c.want)
	}

	abort := sdo(ecatHandSDOAbort, req)
	if abort.Specifier != EtherCATSDOCCSAbort || abort.Index != 0x6040 || abort.SubIndex != 9 ||
		abort.AbortCode() != EtherCATSDOAbortNoSubIndex {
		t.Errorf("abort: %+v", abort)
	}
}

func TestEtherCATEoE(t *testing.T) {
	frames := ecatHand(t)
	eoe := func(n int) *EtherCATEoE {
		m := ecatMbx(t, frames, n)
		if m.Type != EtherCATMailboxEoE || m.EoE == nil {
			t.Fatalf("frame %d: no EoE: %+v", n, m)
		}
		return m.EoE
	}

	// Fragment 0 carries a whole 60-byte ARP frame and a timestamp.
	e := eoe(ecatHandEoEFragment0)
	if e.Type != EtherCATEoEFragment || e.Port != 1 || !e.LastFragment || !e.TimeAppended || e.TimeRequested ||
		e.FragmentNo != 0 || e.Offset != 64 || e.FrameNo != 5 || !e.HasTimestamp || e.Timestamp != 0x01020304 {
		t.Errorf("fragment 0: %+v", e)
	}
	inner := gopacket.NewPacket(e.Data, LinkTypeEthernet, gopacket.Default)
	if arp, ok := inner.Layer(LayerTypeARP).(*ARP); !ok || len(e.Data) != 60 || !net.IP(arp.DstProtAddress).Equal(net.IPv4(10, 0, 0, 2)) {
		t.Errorf("fragment 0 data: %d bytes, %v", len(e.Data), inner)
	}

	e = eoe(ecatHandEoEFragment1)
	if e.LastFragment || e.TimeAppended || !e.TimeRequested || e.FragmentNo != 1 || e.Offset != 32 ||
		e.FrameNo != 6 || e.HasTimestamp || len(e.Data) != 28 {
		t.Errorf("fragment 1: %+v", e)
	}

	e = eoe(ecatHandEoETimestamp)
	if e.Type != EtherCATEoETimestamp || !e.HasTimestamp || e.Timestamp != 0xa1b2c3d4 || e.FrameNo != 5 {
		t.Errorf("timestamp: %+v", e)
	}

	e = eoe(ecatHandEoESetIP)
	if e.Type != EtherCATEoESetIPRequest || e.SetIP == nil {
		t.Fatalf("set ip: %+v", e)
	}
	ecatSame(t, "set ip", *e.SetIP, EtherCATEoESetIP{
		Flags: 0x0001003f,
		MAC:   net.HardwareAddr{2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		IP:    net.IPv4(192, 168, 1, 10).To4(), SubnetMask: net.IPv4(255, 255, 255, 0).To4(),
		Gateway: net.IPv4(192, 168, 1, 1).To4(), DNSServer: net.IPv4(8, 8, 8, 8).To4(),
		DNSName: []byte("slave-1"),
	})
	if !e.SetIP.Has(EtherCATEoEHasDNSName) || !e.SetIP.Has(EtherCATEoEAppendTimestamp) {
		t.Errorf("set ip flags: %#x", e.SetIP.Flags)
	}

	// The packed form sends the flagged fields only.
	e = eoe(ecatHandEoESetIPPacked)
	if e.SetIP == nil {
		t.Fatalf("packed set ip: %+v", e)
	}
	ecatSame(t, "packed set ip", *e.SetIP, EtherCATEoESetIP{
		Flags: EtherCATEoEHasIP | EtherCATEoEHasSubnetMask, Packed: true,
		IP: net.IPv4(192, 168, 1, 10).To4(), SubnetMask: net.IPv4(255, 255, 255, 0).To4(),
	})

	if e = eoe(ecatHandEoESetIPRes); e.Type != EtherCATEoESetIPResponse || e.Result != 0x0201 {
		t.Errorf("set ip response: %+v", e)
	}
	if e = eoe(ecatHandEoEMACFilterRes); e.Type != EtherCATEoEMACFilterReply || e.Result != 0x0401 {
		t.Errorf("mac filter response: %+v", e)
	}

	e = eoe(ecatHandEoEMACFilter)
	if e.MACFilter == nil {
		t.Fatalf("mac filter: %+v", e)
	}
	ecatSame(t, "mac filter", *e.MACFilter, EtherCATEoEMACFilter{
		NoBroadcasts: true,
		Filters:      []net.HardwareAddr{{2, 0, 0, 0, 0, 1}, {2, 0, 0, 0, 0, 2}},
		Masks:        []net.HardwareAddr{{0xff, 0xff, 0xff, 0xff, 0xff, 0}},
	})
}

func TestEtherCATFoE(t *testing.T) {
	frames := ecatHand(t)
	foe := func(n int) *EtherCATFoE {
		m := ecatMbx(t, frames, n)
		if m.Type != EtherCATMailboxFoE || m.FoE == nil {
			t.Fatalf("frame %d: no FoE: %+v", n, m)
		}
		return m.FoE
	}

	f := foe(ecatHandFoEWRQ)
	if f.OpCode != EtherCATFoEWRQ || f.Password != 0x12345678 || f.FileName() != "firmware.efw" || f.Text() != "" {
		t.Errorf("wrq: %+v", f)
	}
	if f = foe(ecatHandFoERRQ); f.OpCode != EtherCATFoERRQ || f.Password != 0 || f.FileName() != "config.bin" {
		t.Errorf("rrq: %+v", f)
	}
	if f = foe(ecatHandFoEData); f.OpCode != EtherCATFoEDATA || f.PacketNo != 1 || len(f.Data) != 6 || f.FileName() != "" {
		t.Errorf("data: %+v", f)
	}

	// The packet number is 32 bits wide; tshark shows the low 16.
	if f = foe(ecatHandFoEDataLong); f.PacketNo != 0x00010002 || len(f.Data) != 16 {
		t.Errorf("long data: %+v", f)
	}
	if f = foe(ecatHandFoEAck); f.OpCode != EtherCATFoEACK || f.PacketNo != 1 || len(f.Data) != 0 {
		t.Errorf("ack: %+v", f)
	}
	if f = foe(ecatHandFoEErr); f.OpCode != EtherCATFoEERR || f.ErrorCode != EtherCATFoEErrNotFound || f.Text() != "not found" {
		t.Errorf("err: %+v", f)
	}
	if f = foe(ecatHandFoEBusy); f.OpCode != EtherCATFoEBUSY || f.Done != 10 || f.Entire != 100 || f.Text() != "wait" {
		t.Errorf("busy: %+v", f)
	}

	// Error codes with and without the 0x8000 base share a name.
	if a, b := EtherCATFoEErrDiskFull.String(), EtherCATFoEError(3).String(); a != "Disk full" || a != b {
		t.Errorf("error strings %q %q", a, b)
	}
}

func TestEtherCATSoEVoE(t *testing.T) {
	frames := ecatHand(t)
	soe := func(n int) EtherCATSoE {
		m := ecatMbx(t, frames, n)
		if m.Type != EtherCATMailboxSoE || m.SoE == nil {
			t.Fatalf("frame %d: no SoE: %+v", n, m)
		}
		return *m.SoE
	}

	ecatSame(t, "read req", soe(ecatHandSoEReadReq),
		EtherCATSoE{OpCode: EtherCATSoEReadRequest, DriveNo: 1, Elements: EtherCATSoEValue, IDN: 100})
	ecatSame(t, "read res", soe(ecatHandSoEReadRes), EtherCATSoE{
		OpCode: EtherCATSoEReadResponse, DriveNo: 1, Elements: EtherCATSoEValue, IDN: 100, Data: []byte{0xdc, 5, 0, 0},
	})
	ecatSame(t, "write req", soe(ecatHandSoEWriteReq), EtherCATSoE{
		OpCode: EtherCATSoEWriteRequest, DriveNo: 2, Elements: EtherCATSoEValue, IDN: 0x9012, Data: []byte{7, 0},
	})
	ecatSame(t, "write res", soe(ecatHandSoEWriteRes),
		EtherCATSoE{OpCode: EtherCATSoEWriteResponse, DriveNo: 2, Elements: EtherCATSoEValue, IDN: 0x9012})
	ecatSame(t, "notification", soe(ecatHandSoENotification), EtherCATSoE{
		OpCode: EtherCATSoENotification, Elements: EtherCATSoEDataState, IDN: 99, Data: []byte{3, 0},
	})
	ecatSame(t, "fragment", soe(ecatHandSoEFragment), EtherCATSoE{
		OpCode: EtherCATSoEReadResponse, Incomplete: true, DriveNo: 1, Elements: EtherCATSoEName,
		FragmentsLeft: 3, Data: []byte("Drive name par"),
	})
	ecatSame(t, "error", soe(ecatHandSoEError), EtherCATSoE{
		OpCode: EtherCATSoEReadResponse, Error: true, DriveNo: 1, Elements: EtherCATSoEValue,
		IDN: 100, ErrorCode: 0x1001, Data: []byte{1, 0x10},
	})

	// IDN strings as tshark prints them.
	for idn, want := range map[EtherCATSoEIDN]string{100: "S-0-0100", 0x9012: "P-1-0018", 0x7fff: "S-7-4095"} {
		if got := idn.String(); got != want {
			t.Errorf("IDN %#x: %q, want %q", uint16(idn), got, want)
		}
	}
	if e := EtherCATSoEValue | EtherCATSoEName; !e.Has(EtherCATSoEName) || e.Has(EtherCATSoEUnit) {
		t.Error("element flags")
	}

	m := ecatMbx(t, frames, ecatHandVoE)
	if m.Type != EtherCATMailboxVoE || m.VoE == nil {
		t.Fatalf("no VoE: %+v", m)
	}
	ecatSame(t, "voe", *m.VoE, EtherCATVoE{VendorID: 2, VendorType: 1, Data: []byte{9, 8, 7}})
}

func TestEtherCATAoE(t *testing.T) {
	frames := ecatHand(t)
	ads := func(n int, cmd EtherCATADSCommand, response bool) EtherCATADS {
		m := ecatMbx(t, frames, n)
		a := m.AoE
		if m.Type != EtherCATMailboxAoE || a == nil {
			t.Fatalf("frame %d: no AoE: %+v", n, m)
		}
		if a.Command != cmd || a.IsResponse() != response || a.TargetNetID.String() != "192.168.1.10.1.1" ||
			a.SourceNetID.String() != "192.168.1.20.1.1" || a.TargetPort != 851 || a.SourcePort != 32905 ||
			a.InvokeID != 0x11223344 || int(a.Length) != len(a.Data) || !a.Flags.Has(EtherCATAMSADSCommand) {
			t.Fatalf("frame %d: AMS header %+v", n, a)
		}
		if a.ADS == nil {
			return EtherCATADS{}
		}
		return *a.ADS
	}

	ecatSame(t, "read req", ads(ecatHandADSReadReq, EtherCATADSRead, false),
		EtherCATADS{IndexGroup: 0x4020, IndexOffset: 0x10, Length: 4})
	ecatSame(t, "read res", ads(ecatHandADSReadRes, EtherCATADSRead, true),
		EtherCATADS{Length: 4, Data: []byte{1, 2, 3, 4}})
	ecatSame(t, "write req", ads(ecatHandADSWriteReq, EtherCATADSWrite, false),
		EtherCATADS{IndexGroup: 0x4020, IndexOffset: 0x10, Length: 2, Data: []byte{0xaa, 0xbb}})
	ecatSame(t, "write res", ads(ecatHandADSWriteRes, EtherCATADSWrite, true), EtherCATADS{Result: 0x705})
	ecatSame(t, "readwrite req", ads(ecatHandADSReadWriteReq, EtherCATADSReadWrite, false),
		EtherCATADS{IndexGroup: 0xf003, Length: 4, WriteLength: 9, Data: []byte("MAIN.var\x00")})
	ecatSame(t, "readwrite res", ads(ecatHandADSReadWriteRes, EtherCATADSReadWrite, true),
		EtherCATADS{Length: 4, Data: []byte{1, 0, 0, 0x1f}})
	ecatSame(t, "readstate req", ads(ecatHandADSReadStateReq, EtherCATADSReadState, false), EtherCATADS{})
	ecatSame(t, "readstate res", ads(ecatHandADSReadStateRes, EtherCATADSReadState, true), EtherCATADS{ADSState: 5})
	ecatSame(t, "writectrl req", ads(ecatHandADSWriteCtrlReq, EtherCATADSWriteControl, false),
		EtherCATADS{ADSState: 6, Length: 2, Data: []byte{1, 0}})
	ecatSame(t, "writectrl res", ads(ecatHandADSWriteCtrlRes, EtherCATADSWriteControl, true), EtherCATADS{})
	ecatSame(t, "devinfo req", ads(ecatHandADSDevInfoReq, EtherCATADSReadDeviceInfo, false), EtherCATADS{})
	ecatSame(t, "devinfo res", ads(ecatHandADSDevInfoRes, EtherCATADSReadDeviceInfo, true),
		EtherCATADS{MajorVersion: 3, MinorVersion: 1, Build: 4024, DeviceName: []byte("Plc30 App")})
	ecatSame(t, "add note req", ads(ecatHandADSAddNoteReq, EtherCATADSAddNotification, false), EtherCATADS{
		IndexGroup: 0x4020, IndexOffset: 0x10, Length: 4, TransmissionMode: 4, CycleTime: 100000,
	})
	ecatSame(t, "add note res", ads(ecatHandADSAddNoteRes, EtherCATADSAddNotification, true), EtherCATADS{Handle: 0x21})
	ecatSame(t, "del note req", ads(ecatHandADSDelNoteReq, EtherCATADSDeleteNotification, false), EtherCATADS{Handle: 0x21})
	ecatSame(t, "del note res", ads(ecatHandADSDelNoteRes, EtherCATADSDeleteNotification, true), EtherCATADS{})

	// Notification: two stamps with two and one samples.
	ecatSame(t, "notification", ads(ecatHandADSNotification, EtherCATADSNotification, false), EtherCATADS{
		Length: 59, StampCount: 2,
		Stamps: []EtherCATADSStamp{
			{Timestamp: 0x01d9f0a0b0c0d0e0, Samples: []EtherCATADSSample{{0x21, []byte{1, 0, 0, 0}}, {0x22, []byte{7, 0}}}},
			{Timestamp: 0x01d9f0a0b0c0d0e1, Samples: []EtherCATADSSample{{0x23, []byte{9}}}},
		},
	})

	// A system command keeps its body raw.
	a := ecatMbx(t, frames, ecatHandAMSSystem).AoE
	if a == nil || a.ADS != nil || !a.Flags.Has(EtherCATAMSSystemCommand) || len(a.Data) != 3 {
		t.Errorf("system command: %+v", a)
	}
	if got := EtherCATADSReadWrite.String(); got != "ADS Read Write" {
		t.Errorf("command string %q", got)
	}
}

func TestEtherCATFrameTypes(t *testing.T) {
	frames := ecatHand(t)

	// Decoded frame types have no payload and cover the whole frame.
	for _, n := range []int{ecatHandFrameADS, ecatHandFrameRawIO, ecatHandFrameNV, ecatHandFrameMailbox} {
		e := frames[n-1]
		if len(e.LayerPayload()) != 0 || len(e.LayerContents()) != ethercatFrameHeaderLen+int(e.Length) || len(e.Datagrams) != 0 {
			t.Errorf("frame %d: contents %d, payload %d", n, len(e.LayerContents()), len(e.LayerPayload()))
		}
	}

	e := frames[ecatHandFrameADS-1]
	if e.Type != EtherCATFrameADS || e.ADS == nil || e.ADS.Command != EtherCATADSReadState || e.ADS.ADS == nil || e.ADS.ADS.ADSState != 5 {
		t.Errorf("ADS frame: %+v", e.ADS)
	}

	e = frames[ecatHandFrameRawIO-1]
	if e.Type != EtherCATFrameRawIO || e.RawIO == nil || e.RawIO.Header != 1 || len(e.RawIO.Data) != 12 {
		t.Errorf("raw IO frame: %+v", e.RawIO)
	}

	e = frames[ecatHandFrameNV-1]
	if e.Type != EtherCATFrameNV || e.NV == nil {
		t.Fatalf("NV frame: %+v", e)
	}
	ecatSame(t, "nv", *e.NV, EtherCATNV{
		Publisher: EtherCATAMSNetID{10, 0, 0, 1, 1, 1}, Count: 2, Cycle: 77,
		Variables: []EtherCATNVVariable{
			{ID: 1, Hash: 0xbeef, Length: 4, Data: []byte{1, 2, 3, 4}},
			{ID: 2, Hash: 0xf00d, Length: 2, Quality: 100, Data: []byte{5, 6}},
		},
	})

	e = frames[ecatHandFrameMailbox-1]
	m := e.Mailbox
	if e.Type != EtherCATFrameMailbox || m == nil || m.CoE == nil || m.CoE.SDO == nil ||
		m.CoE.SDO.Specifier != EtherCATSDOCCSInitiateUpload || m.CoE.SDO.Index != 0x1018 || m.CoE.SDO.SubIndex != 1 {
		t.Errorf("mailbox gateway frame: %+v", m)
	}
}

func TestEtherCATRegisters(t *testing.T) {
	frames := ecatHand(t)
	names := func(d *EtherCATDatagram) string {
		s := ""
		for _, v := range d.Registers() {
			s += fmt.Sprintf("%v=%#x;", v.Register, v.Uint())
		}
		return s
	}

	// AL status and code read by broadcast, AL control written, DL status.
	d := frames[ecatHandRegistersAL-1].Datagrams
	if got, want := names(&d[0]), "AL Status=0x12;AL Status Code=0x1e;"; got != want {
		t.Errorf("AL read: %s, want %s", got, want)
	}
	if s, ok := d[0].ALStatus(); !ok || s.State() != ESCALStatePreOp || !s.Error() || s.IDLoaded() {
		t.Errorf("AL status %#x %v", uint16(s), ok)
	}
	if c, ok := d[1].ALControl(); !ok || c.State() != ESCALStateSafeOp || !c.ErrorAck() || c.IDRequest() ||
		d[1].Register() != ESCRegisterALControl {
		t.Errorf("AL control %#x %v", uint16(c), ok)
	}
	s, ok := d[2].DLStatus()
	if !ok || !s.PDIOperational() || s.PDIWatchdog() || !s.EnhancedLinkDetection() ||
		!s.PhysicalLink(0) || !s.PhysicalLink(1) || s.PhysicalLink(2) || s.PhysicalLink(3) ||
		s.LoopClosed(0) || !s.Communication(0) || s.LoopClosed(1) || !s.Communication(1) ||
		!s.LoopClosed(2) || s.Communication(2) || !s.LoopClosed(3) || s.Communication(3) ||
		s.PhysicalLink(4) || s.LoopClosed(-1) {
		t.Errorf("DL status %#x %v", uint16(s), ok)
	}
	if got, want := names(&d[2]), "DL Status 0=0x35;DL Status 1=0x5a;"; got != want {
		t.Errorf("DL read: %s, want %s", got, want)
	}

	// A read that no slave answered holds no register values.
	if _, ok := d[3].ALStatus(); ok || d[3].Registers() != nil || d[3].RegisterBytes(ESCRegisterALStatus, 2) != nil {
		t.Error("read with working counter 0 decoded as register values")
	}

	// Two FMMUs and two sync managers written in one datagram each.
	d = frames[ecatHandRegistersFMMU-1].Datagrams
	if got := names(&d[0]); got != "FMMU 0=0x0;FMMU 1=0x0;" {
		t.Errorf("FMMU registers: %s", got)
	}
	f, ok := d[0].FMMU(1)
	ecatSame(t, "fmmu 1", f, ESCFMMU{
		LogicalStart: 0x00010800, Length: 6, LogicalEndBit: 7, PhysicalStart: 0x1180, Type: 1, Activate: 1,
	})
	if !ok || !f.Read() || f.Write() || !f.Enabled() {
		t.Errorf("fmmu 1 flags: %+v %v", f, ok)
	}
	if f0, _ := d[0].FMMU(0); f0.Read() || !f0.Write() || f0.PhysicalStart != 0x1100 {
		t.Errorf("fmmu 0: %+v", f0)
	}
	if _, ok := d[0].FMMU(2); ok {
		t.Error("FMMU 2 found in a 32-byte write")
	}
	if _, ok := d[0].FMMU(-1); ok {
		t.Error("FMMU -1 found")
	}

	sm, ok := d[1].SyncManager(0)
	ecatSame(t, "sm 0", sm, ESCSyncManager{Start: 0x1000, Length: 128, Control: 0x26, Activate: 1})
	if !ok || sm.Mode() != ESCSMModeMailbox || !sm.MasterWrites() || !sm.Enabled() {
		t.Errorf("sm 0 flags: %+v %v", sm, ok)
	}
	if sm, ok = d[1].SyncManager(1); !ok || sm.MasterWrites() || sm.Start != 0x1080 || sm.Status != 8 {
		t.Errorf("sm 1: %+v %v", sm, ok)
	}
	if _, ok = d[1].SyncManager(8); ok {
		t.Error("sync manager 8 found")
	}
	if got := names(&d[2]); got != "Station Address=0x1001;" {
		t.Errorf("station address: %s", got)
	}

	// DC system time: full, low half only, and written by ARMW.
	d = frames[ecatHandRegistersDC-1].Datagrams
	ns, ok := d[0].DCSystemTime()
	if want := time.Date(2026, time.September, 19, 0, 0, 0, 0, time.UTC); !ok || !ESCDCTime(ns).Equal(want) {
		t.Errorf("DC system time %d (%v) %v, want %v", ns, ESCDCTime(ns), ok, want)
	}
	if got := names(&d[0]); got != fmt.Sprintf("DC System Time=%#x;", ns) {
		t.Errorf("DC time registers: %s", got)
	}
	if _, ok = d[1].DCSystemTime(); ok || names(&d[1]) != "DC System Time=0x12345678;" {
		t.Errorf("DC low half: %s", names(&d[1]))
	}
	if got := names(&d[2]); got != "DC System Time=0x12345679;" {
		t.Errorf("ARMW: %s", got)
	}
	if got, want := names(&d[3]), "DC Receive Time 0=0x3e8;DC Receive Time 1=0x578;DC Receive Time 2=0x0;DC Receive Time 3=0x0;"; got != want {
		t.Errorf("DC receive times: %s", got)
	}
	if got, want := names(&d[4]), "DC System Time Offset=0x1122334455667788;DC System Time Delay=0xfa;"; got != want {
		t.Errorf("DC offset: %s", got)
	}

	// ESC information block, EEPROM registers, and a logical command.
	d = frames[ecatHandRegistersInfo-1].Datagrams
	want := "ESC Type=0x11;ESC Revision=0x2;ESC Build=0x300;ESC FMMU Count=0x8;ESC SM Count=0x8;" +
		"ESC DPRAM Size=0x8;ESC Ports=0xf;ESC Features=0x1fc;"
	if got := names(&d[0]); got != want {
		t.Errorf("ESC info: %s", got)
	}
	want = "EEPROM Control/Status=0x8;EEPROM Address Lo=0x8;EEPROM Address Hi=0x0;" +
		"EEPROM Data 0=0x7788;EEPROM Data 1=0x5566;EEPROM Data 2=0x3344;EEPROM Data 3=0x1122;"
	if got := names(&d[1]); got != want {
		t.Errorf("EEPROM: %s", got)
	}
	if d[2].Registers() != nil || d[2].Command.IsPhysical() {
		t.Error("logical command decoded as registers")
	}
}

func TestESCRegisterNames(t *testing.T) {
	cases := map[ESCRegister]string{
		ESCRegisterType:           "ESC Type",
		ESCRegisterALStatus:       "AL Status",
		ESCRegisterDCSystemTime:   "DC System Time",
		ESCRegisterDCSystemTimeHi: "DC System Time H",
		ESCRegisterDCActivation:   "DC Activation",
		ESCRegisterFMMU:           "FMMU 0",
		0x06f0:                    "FMMU 15",
		0x0601:                    "0x0601",
		0x0700:                    "0x0700",
		0x0838:                    "SyncManager 7",
		0x0840:                    "0x0840",
		0x0131:                    "0x0131",
		0x1000:                    "0x1000",
		0xffff:                    "0xffff",
	}
	for reg, want := range cases {
		if got := reg.String(); got != want {
			t.Errorf("%#04x: %q, want %q", uint16(reg), got, want)
		}
	}

	if ESCRegisterDCPDISMChange.IsMemory() || !ESCRegister(0x1000).IsMemory() {
		t.Error("IsMemory")
	}

	// The table must stay sorted: String and Registers stop early on it.
	for i := 1; i < len(escRegisters); i++ {
		if escRegisters[i].reg < escRegisters[i-1].reg {
			t.Errorf("register table not sorted at %#x", uint16(escRegisters[i].reg))
		}
	}
}

// TestEtherCATBodyTruncation decodes every prefix of every hand-made
// frame, through the packet decoder and through the mailbox decoder.
func TestEtherCATBodyTruncation(t *testing.T) {
	withEtherCAT(t)

	for _, frame := range readPNECATPcap(t, ecatHandPcap) {
		for n := 0; n <= len(frame); n++ {
			data := append([]byte(nil), frame[:n]...)
			p := gopacket.NewPacket(data, LinkTypeEthernet, gopacket.Default)
			if e, ok := p.Layer(LayerTypeEtherCAT).(*EtherCAT); ok {
				ecatTouch(e)
			}
		}

		// The mailbox sits after the Ethernet, frame and datagram headers.
		const mbxStart = 14 + ethercatFrameHeaderLen + ethercatDatagramHeaderLen
		if len(frame) < mbxStart {
			continue
		}
		for n := mbxStart; n <= len(frame); n++ {
			m, err := DecodeEtherCATMailbox(append([]byte(nil), frame[mbxStart:n]...))
			if err == nil {
				ecatTouchMailbox(m)
			}
		}
	}
}

// ecatTouch calls every accessor of a decoded frame, to shake out panics
// on odd input.
func ecatTouch(e *EtherCAT) {
	for i := range e.Datagrams {
		d := &e.Datagrams[i]
		for _, v := range d.Registers() {
			_ = v.Register.String()
			_ = v.Uint()
		}
		d.ALControl()
		d.ALStatus()
		d.DLStatus()
		d.DCSystemTime()
		for n := -1; n <= escFMMUCount; n++ {
			d.FMMU(n)
			d.SyncManager(n)
		}
		ecatTouchRegs(d)
		ecatTouchMailbox(d.Mailbox)
	}
	ecatTouchMailbox(e.Mailbox)
	ecatTouchAMS(e.ADS)
}

// ecatTouchRegs calls the typed register accessors of a datagram.
func ecatTouchRegs(d *EtherCATDatagram) {
	_ = d.Register().Area().String()
	if code, ok := d.ALStatusCode(); ok {
		_ = code.String()
	}
	if div, ok := d.WatchdogDivider(); ok {
		_ = div.Period()
	}
	d.WatchdogTimePDI()
	d.WatchdogTimeSM()
	d.WatchdogStatus()
	if c, ok := d.EEPROMControl(); ok {
		_ = c.Command().String()
		_ = c.ReadSize()
	}
	d.EEPROMAddress()
	d.EEPROMData()
	d.MIIControl()
	if m, ok := d.MII(); ok {
		_ = m.Control.Command().String()
	}
	d.DCActivation()
	d.DCStartTime()
	for n := -1; n <= escDCUnitCount; n++ {
		d.DCCycleTime(n)
		d.DCLatchControl(n)
		d.DCLatchStatus(n)
		d.DCLatchTime(n, ESCDCEdgePositive)
		d.DCLatchTime(n, ESCDCEdgeNegative)
	}
}

// ecatTouchAMS calls the accessors of an AMS packet.
func ecatTouchAMS(a *EtherCATAMS) {
	if a == nil {
		return
	}
	_ = a.TargetNetID.String()
	_ = a.TargetPort.String()
	_ = a.SourcePort.String()
	_ = a.Command.String()
	_ = a.ErrorCode.String()
	if a.ADS == nil {
		return
	}

	_ = a.ADS.Result.String()
	_ = a.ADS.IndexGroup.String()
	_ = a.ADS.ADSState.String()
	_ = a.ADS.TransmissionMode.String()
	_ = a.ADS.MaxDelayTime()
	_ = a.ADS.CycleDuration()
	for _, r := range a.ADS.SumUpResults(a.ADS) {
		_ = r.Result.String()
	}
}

// ecatTouchAMSTCP calls the accessors of every AMS/TCP packet.
func ecatTouchAMSTCP(a *EtherCATAMSTCP) {
	for i := range a.PDUs {
		_ = a.PDUs[i].Command.String()
		ecatTouchAMS(a.PDUs[i].AMS)
	}
}

// ecatTouchMailbox calls the accessors of a mailbox body.
func ecatTouchMailbox(m *EtherCATMailbox) {
	if m == nil {
		return
	}
	if m.FoE != nil {
		_ = m.FoE.FileName()
		_ = m.FoE.Text()
		_ = m.FoE.ErrorCode.String()
	}
	if m.SoE != nil {
		_ = m.SoE.IDN.String()
	}
	if m.CoE != nil && m.CoE.SDO != nil {
		_ = m.CoE.SDO.AbortCode().String()
	}
	if m.EoE != nil {
		_ = m.EoE.Type.String()
		_ = m.EoE.Result.String()
	}
	if m.Error != nil {
		_ = m.Error.Detail.String()
	}
	ecatTouchAMS(m.AoE)
}

// ecatMailboxBytes wraps a body in a mailbox header of the given type.
func ecatMailboxBytes(typ EtherCATMailboxType, body []byte) []byte {
	out := make([]byte, ethercatMailboxHeaderLen, ethercatMailboxHeaderLen+len(body))
	binary.LittleEndian.PutUint16(out, uint16(len(body)))
	out[5] = byte(typ)
	return append(out, body...)
}

// ecatAMSBytes builds an AMS packet with the ADS flag set.
func ecatAMSBytes(cmd EtherCATADSCommand, flags EtherCATAMSFlags, body []byte) []byte {
	out := make([]byte, ethercatAMSHeaderLen, ethercatAMSHeaderLen+len(body))
	binary.LittleEndian.PutUint16(out[16:], uint16(cmd))
	binary.LittleEndian.PutUint16(out[18:], uint16(flags|EtherCATAMSADSCommand))
	binary.LittleEndian.PutUint32(out[20:], uint32(len(body)))
	return append(out, body...)
}

// TestEtherCATLengthLies feeds counts and sizes that claim more than the
// data holds.
func TestEtherCATLengthLies(t *testing.T) {
	// NV: 65535 variables announced, one present, one cut short.
	nv := []byte{1, 2, 3, 4, 5, 6, 0xff, 0xff, 9, 0, 0, 0,
		1, 0, 0, 0, 2, 0, 0, 0, 0xaa, 0xbb, // variable 1, 2 bytes
		2, 0, 0, 0, 0xff, 0xff, 0, 0, 0xcc} // variable 2 claims 65535 bytes
	got := decodeEtherCATNV(nv)
	if got == nil || got.Count != 0xffff || len(got.Variables) != 1 || got.Variables[0].ID != 1 {
		t.Errorf("NV count lie: %+v", got)
	}
	if got = decodeEtherCATNV(nv[:ethercatNVHeaderLen]); got == nil || got.Variables != nil {
		t.Errorf("NV without variables: %+v", got)
	}
	if decodeEtherCATNV(nv[:ethercatNVHeaderLen-1]) != nil {
		t.Error("NV with a cut header decoded")
	}

	// ADS notification: 2^32-1 stamps and samples announced.
	note := make([]byte, 0, 64)
	note = append(note, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff) // length, stamps
	note = append(note, 1, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff) // stamp: time, samples
	note = append(note, 7, 0, 0, 0, 1, 0, 0, 0, 0x55)                   // sample: handle, size 1
	note = append(note, 8, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x66)       // sample: size 2^32-1
	a := decodeEtherCATAMS(ecatAMSBytes(EtherCATADSNotification, 0, note))
	if a == nil || a.ADS == nil || a.ADS.StampCount != 0xffffffff || len(a.ADS.Stamps) != 1 ||
		len(a.ADS.Stamps[0].Samples) != 1 || a.ADS.Stamps[0].Samples[0].Handle != 7 {
		t.Errorf("notification count lie: %+v", a)
	}

	// Stamps announced but none present.
	a = decodeEtherCATAMS(ecatAMSBytes(EtherCATADSNotification, 0, note[:8]))
	if a == nil || a.ADS == nil || a.ADS.Stamps != nil {
		t.Errorf("notification without stamps: %+v", a)
	}

	// Bodies too short for their command stay raw.
	for cmd := EtherCATADSInvalid; cmd <= EtherCATADSReadWrite+1; cmd++ {
		for _, flags := range []EtherCATAMSFlags{0, EtherCATAMSResponse} {
			a = decodeEtherCATAMS(ecatAMSBytes(cmd, flags, []byte{1, 2, 3}))
			if a == nil || a.ADS != nil || len(a.Data) != 3 {
				t.Errorf("command %v flags %#x: short body decoded: %+v", cmd, flags, a)
			}
		}
	}

	// SDO information: an odd list tail drops the half index.
	list := []byte{0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x10, 0x99}
	m, err := DecodeEtherCATMailbox(ecatMailboxBytes(EtherCATMailboxCoE, list))
	if err != nil || m.CoE == nil || m.CoE.SDOInfo == nil || len(m.CoE.SDOInfo.Indexes) != 1 || m.CoE.SDOInfo.Indexes[0] != 0x1018 {
		t.Errorf("odd list: %+v %v", m, err)
	}

	// Entry description whose limits do not fit: 65535 bits each.
	entry := []byte{0x00, 0x80, 0x06, 0, 0, 0, 0x18, 0x10, 1, 0x70, 7, 0, 0xff, 0xff, 7, 0, 'a', 'b'}
	m, err = DecodeEtherCATMailbox(ecatMailboxBytes(EtherCATMailboxCoE, entry))
	if err != nil || m.CoE.SDOInfo == nil {
		t.Fatalf("entry: %+v %v", m, err)
	}
	if i := m.CoE.SDOInfo; i.Default != nil || i.Min != nil || i.Max != nil || string(i.Name) != "ab" || i.BitLength != 0xffff {
		t.Errorf("entry with oversized limits: %+v", i)
	}

	// EoE: bodies shorter than the fixed layouts leave the detail nil.
	short := []struct {
		name string
		body []byte
	}{
		{"set ip", append([]byte{2, 0, 0, 0}, make([]byte, ethercatEoEInitLen-1)...)},
		{"mac filter", append([]byte{4, 0, 0, 0}, make([]byte, ethercatEoEFilterLen-1)...)},
		{"timestamp", []byte{1, 0, 0, 0, 1, 2, 3}},
		{"fragment with a cut timestamp", []byte{0, 2, 0, 0, 1, 2, 3}},
	}
	for _, c := range short {
		m, err = DecodeEtherCATMailbox(ecatMailboxBytes(EtherCATMailboxEoE, c.body))
		if err != nil || m.EoE == nil || m.EoE.SetIP != nil || m.EoE.MACFilter != nil || m.EoE.HasTimestamp {
			t.Errorf("%s: %+v %v", c.name, m.EoE, err)
		}
	}

	// A mailbox gateway frame whose mailbox length lies stays raw.
	withEtherCAT(t)
	frame := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 0x88, 0xa4, 8, 0x50,
		0xff, 0x00, 0, 0, 0, 3, 0, 0x20}
	p := gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)
	e, ok := p.Layer(LayerTypeEtherCAT).(*EtherCAT)
	if !ok || e.Mailbox != nil || len(e.LayerPayload()) != 8 || p.ErrorLayer() != nil {
		t.Errorf("mailbox gateway length lie: %+v", e)
	}

	// Frame types 2 to 4 with a body shorter than their header: raw too.
	for typ := EtherCATFrameADS; typ <= EtherCATFrameNV; typ++ {
		frame[15] = byte(typ) << 4
		frame[14] = 3
		p = gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)
		e, ok = p.Layer(LayerTypeEtherCAT).(*EtherCAT)
		if !ok || e.ADS != nil || e.RawIO != nil || e.NV != nil || len(e.LayerPayload()) != 3 {
			t.Errorf("%v with a 3-byte body: %+v", typ, e)
		}
	}
}

// TestEtherCATAllocBound checks that attacker-chosen counts do not size
// allocations.
func TestEtherCATAllocBound(t *testing.T) {
	// 65535 variables announced in a 1500-byte frame of empty variables.
	nv := make([]byte, 1500)
	nv[6], nv[7] = 0xff, 0xff
	maxVars := (len(nv) - ethercatNVHeaderLen) / ethercatNVVarHeaderLen
	var got *EtherCATNV
	allocs := testing.AllocsPerRun(20, func() { got = decodeEtherCATNV(nv) })
	if len(got.Variables) != maxVars || cap(got.Variables) != maxVars || allocs > 2 {
		t.Errorf("NV: %d variables (cap %d), %v allocs", len(got.Variables), cap(got.Variables), allocs)
	}

	// 2^32-1 stamps announced in 1500 bytes of empty stamps.
	note := make([]byte, 1500)
	for i := range note[:8] {
		note[i] = 0xff
	}
	pkt := ecatAMSBytes(EtherCATADSNotification, 0, note)
	maxStamps := (len(note) - ethercatADSNoteLen) / ethercatADSStampLen
	var a *EtherCATAMS
	allocs = testing.AllocsPerRun(20, func() { a = decodeEtherCATAMS(pkt) })
	if len(a.ADS.Stamps) != maxStamps || cap(a.ADS.Stamps) != maxStamps || allocs > 4 {
		t.Errorf("stamps: %d (cap %d), %v allocs", len(a.ADS.Stamps), cap(a.ADS.Stamps), allocs)
	}

	// One stamp announcing 2^32-1 empty samples.
	for i := range note {
		note[i] = 0
	}
	note[4] = 1
	for i := 16; i < 20; i++ {
		note[i] = 0xff
	}
	pkt = ecatAMSBytes(EtherCATADSNotification, 0, note)
	maxSamples := (len(note) - ethercatADSNoteLen - ethercatADSStampLen) / ethercatADSSampleLen
	a = decodeEtherCATAMS(pkt)
	if len(a.ADS.Stamps) != 1 || len(a.ADS.Stamps[0].Samples) != maxSamples {
		t.Errorf("samples: %+v stamps, %d samples, want %d", len(a.ADS.Stamps), len(a.ADS.Stamps[0].Samples), maxSamples)
	}

	// SDO information list: bounded by the body.
	list := make([]byte, 1400)
	list[0] = byte(EtherCATSDOInfoListResponse)
	if i := decodeEtherCATSDOInfo(list); len(i.Indexes) != (len(list)-ethercatSDOInfoHeaderLen-ethercatIndexLen)/ethercatIndexLen {
		t.Errorf("list: %d indexes", len(i.Indexes))
	}

	// Registers: one allocation, bounded by the table whatever the data.
	d := EtherCATDatagram{Command: EtherCATCommandBWR, Data: make([]byte, ethercatLengthMask)}
	var regs []ESCRegisterValue
	allocs = testing.AllocsPerRun(20, func() { regs = d.Registers() })
	if len(regs) == 0 || len(regs) > escRegisterMax || cap(regs) != escRegisterMax || allocs > 1 {
		t.Errorf("registers: %d (cap %d, max %d), %v allocs", len(regs), cap(regs), escRegisterMax, allocs)
	}

	// The same datagram at the top of the address space must not wrap.
	d.Address = 0xffff << ethercatAddressHalfShift
	if regs = d.Registers(); regs != nil {
		t.Errorf("registers at ADO 0xffff: %d", len(regs))
	}
}
