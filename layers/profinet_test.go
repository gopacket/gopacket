// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"

	"github.com/gopacket/gopacket"
)

// Test captures. Expected values below were checked against tshark 4.7.
//
//	profinet-dcp.pcap       DCP from the Wireshark wiki (ChangeIPUsingDCP.pcap),
//	                        ITI ICS-Security-Tools (CC BY 4.0: PROFINET-RT.pcap,
//	                        profinet-wireshark-bug.pcap) and the pnio-rs DCP
//	                        golden frames (MIT; S7-1500 / PLCSIM bench).
//	profinet-rt-alarm.pcap  pnio-rs testdata (MIT): RT_CLASS_1 cyclic and alarm
//	                        frames between an S7-1500 and a p-net device.
//	profinet-handmade.pcap  frames built by hand from IEC 61158-6-10 and
//	                        Wireshark's dissectors for kinds no public capture
//	                        has: DCP hello/get/set, PTCP, RT_CLASS_3, fragments.
const (
	pnDCPPcap      = "testdata/profinet-dcp.pcap"
	pnRTAlarmPcap  = "testdata/profinet-rt-alarm.pcap"
	pnHandmadePcap = "testdata/profinet-handmade.pcap"
)

// withProfinet registers the PROFINET EtherType for one test and restores
// the previous table entry afterwards, so other tests see the defaults.
func withProfinet(t testing.TB) {
	old := EthernetTypeMetadata[EthernetTypeProfinet]
	port := uint16(UDPPortProfinetIO)
	oldWord := udpPortLayerTypeOverride[port>>6]
	oldType, hadType := udpPortLayerType[UDPPortProfinetIO]

	t.Cleanup(func() {
		EthernetTypeMetadata[EthernetTypeProfinet] = old
		udpPortLayerTypeOverride[port>>6] = oldWord
		if hadType {
			udpPortLayerType[UDPPortProfinetIO] = oldType
			return
		}
		delete(udpPortLayerType, UDPPortProfinetIO)
	})
	registerProfinetDecoders()
}

// readPNECATPcap returns every frame of a classic pcap file.
func readPNECATPcap(t testing.TB, path string) [][]byte {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	r, err := newSimplePcapReader(f)
	if err != nil {
		t.Fatal(err)
	}

	var frames [][]byte
	for {
		data, err := r.readPacketData()
		if err == io.EOF {
			return frames
		}
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, data)
	}
}

// decodePN decodes every frame of a capture and fails on any error layer.
func decodePN(t *testing.T, path string) []gopacket.Packet {
	var pkts []gopacket.Packet
	for i, data := range readPNECATPcap(t, path) {
		p := gopacket.NewPacket(data, LinkTypeEthernet, gopacket.Default)
		if el := p.ErrorLayer(); el != nil {
			t.Fatalf("%s frame %d: %v", path, i+1, el.Error())
		}
		if p.Layer(LayerTypeProfinet) == nil {
			t.Fatalf("%s frame %d: no PROFINET layer", path, i+1)
		}
		pkts = append(pkts, p)
	}
	return pkts
}

func pnDCP(t *testing.T, p gopacket.Packet) *ProfinetDCP {
	l, ok := p.Layer(LayerTypeProfinetDCP).(*ProfinetDCP)
	if !ok {
		t.Fatalf("no DCP layer in %v", p)
	}
	return l
}

func TestProfinetNotRegisteredByDefault(t *testing.T) {
	if EthernetTypeMetadata[EthernetTypeProfinet].DecodeWith != nil {
		t.Fatal("PROFINET EtherType registered without opt-in")
	}

	frame := readPNECATPcap(t, pnDCPPcap)[0]
	p := gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)
	if p.Layer(LayerTypeProfinet) != nil {
		t.Fatal("PROFINET decoded without opt-in")
	}
}

func TestProfinetFrameClass(t *testing.T) {
	cases := []struct {
		id    ProfinetFrameID
		class ProfinetFrameClass
	}{
		{0x0000, ProfinetFrameClassReserved},
		{0x0020, ProfinetFrameClassPTCPSync},
		{0x0081, ProfinetFrameClassPTCPSync},
		{0x0082, ProfinetFrameClassReserved},
		{0x0100, ProfinetFrameClassRTClass3},
		{0x0FFF, ProfinetFrameClassRTClass3},
		{0x1000, ProfinetFrameClassReserved},
		{0x8000, ProfinetFrameClassRTClass1},
		{0xBFFF, ProfinetFrameClassRTClass1},
		{0xC000, ProfinetFrameClassRTClass1Legacy},
		{0xFBFF, ProfinetFrameClassRTClass1Legacy},
		{0xFC00, ProfinetFrameClassAcyclic},
		{0xFC01, ProfinetFrameClassAlarmHigh},
		{0xFE01, ProfinetFrameClassAlarmLow},
		{0xFE02, ProfinetFrameClassAcyclic},
		{0xFEFC, ProfinetFrameClassDCP},
		{0xFEFF, ProfinetFrameClassDCP},
		{0xFF00, ProfinetFrameClassPTCPAnnounce},
		{0xFF02, ProfinetFrameClassReserved},
		{0xFF21, ProfinetFrameClassPTCPFollowUp},
		{0xFF43, ProfinetFrameClassPTCPDelay},
		{0xFF44, ProfinetFrameClassReserved},
		{0xFF8F, ProfinetFrameClassFragment},
		{0xFFFF, ProfinetFrameClassReserved},
	}
	for _, c := range cases {
		if got := c.id.Class(); got != c.class {
			t.Errorf("%#04x: class %v, want %v", uint16(c.id), got, c.class)
		}
	}
}

func TestProfinetDCPPcap(t *testing.T) {
	withProfinet(t)
	pkts := decodePN(t, pnDCPPcap)
	if len(pkts) != 24 {
		t.Fatalf("%d frames, want 24", len(pkts))
	}

	// Every frame is DCP; the profinet-wireshark-bug.pcap ones are 802.1Q tagged.
	for i, p := range pkts {
		d := pnDCP(t, p)
		pn := p.Layer(LayerTypeProfinet).(*Profinet)
		if pn.FrameID.Class() != ProfinetFrameClassDCP {
			t.Errorf("frame %d: class %v", i+1, pn.FrameID.Class())
		}
		if len(d.Blocks) == 0 {
			t.Errorf("frame %d: no blocks", i+1)
		}
		tagged := p.Layer(LayerTypeDot1Q) != nil
		if want := i >= 4 && i < 8; tagged != want {
			t.Errorf("frame %d: tagged %v, want %v", i+1, tagged, want)
		}
	}

	// Frame 1: Identify request for all stations.
	d := pnDCP(t, pkts[0])
	if d.ServiceID != ProfinetDCPServiceIdentify || d.ServiceType != ProfinetDCPRequest ||
		d.Xid != 0x01000001 || d.ResponseDelay != 1 || d.DataLength != 4 {
		t.Errorf("frame 1 header: %+v", d)
	}
	if len(d.Blocks) != 1 || d.Blocks[0].Type() != ProfinetDCPBlockAllSelector {
		t.Errorf("frame 1 blocks: %+v", d.Blocks)
	}

	// Frame 2: Identify response from a Siemens SCALANCE X208.
	d = pnDCP(t, pkts[1])
	want := map[ProfinetDCPBlockType]bool{}
	for _, b := range d.Blocks {
		want[b.Type()] = true
		if b.Prefix != ProfinetDCPPrefixBlockInfo {
			t.Errorf("frame 2 block %v: prefix %v", b.Type(), b.Prefix)
		}
		switch b.Type() {
		case ProfinetDCPBlockNameOfStation:
			if b.Name != "X208-BORD" {
				t.Errorf("name %q", b.Name)
			}
		case ProfinetDCPBlockDeviceID:
			if b.VendorID != 0x002a || b.DeviceID != 0x0a01 {
				t.Errorf("device id %#x/%#x", b.VendorID, b.DeviceID)
			}
		case ProfinetDCPBlockIPParameter:
			if !b.IP.Equal(net.IPv4(192, 168, 0, 6)) || !b.Subnet.Equal(net.IPv4(255, 255, 255, 0)) ||
				!b.Gateway.Equal(net.IPv4(192, 168, 0, 1)) || b.BlockInfo != 1 {
				t.Errorf("ip %v/%v/%v info %d", b.IP, b.Subnet, b.Gateway, b.BlockInfo)
			}
		case ProfinetDCPBlockDeviceOptions:
			if len(b.Options) != 13 {
				t.Errorf("%d device options, want 13", len(b.Options))
			}
		case ProfinetDCPBlockDeviceRole:
			if b.Role != ProfinetDCPRoleIODevice {
				t.Errorf("role %#x", b.Role)
			}
		}
	}
	for _, bt := range []ProfinetDCPBlockType{ProfinetDCPBlockNameOfStation, ProfinetDCPBlockDeviceID,
		ProfinetDCPBlockIPParameter, ProfinetDCPBlockDeviceOptions, ProfinetDCPBlockTypeOfStation} {
		if !want[bt] {
			t.Errorf("frame 2: missing %v", bt)
		}
	}

	// Frame 3: Set request for a new IP, with BlockQualifier.
	b := pnDCP(t, pkts[2]).Blocks[0]
	if b.Type() != ProfinetDCPBlockIPParameter || b.Prefix != ProfinetDCPPrefixBlockQualifier ||
		!b.IP.Equal(net.IPv4(192, 168, 0, 10)) {
		t.Errorf("frame 3 block: %+v", b)
	}

	// Frame 4: Set response, Control/Response OK for IP parameter.
	b = pnDCP(t, pkts[3]).Blocks[0]
	if b.Type() != ProfinetDCPBlockResponse || b.Response.Type() != ProfinetDCPBlockIPParameter ||
		b.BlockError != ProfinetDCPErrorOK || b.Prefix != ProfinetDCPPrefixNone {
		t.Errorf("frame 4 block: %+v", b)
	}

	// Frame 9: Identify request filtered by name of station.
	d = pnDCP(t, pkts[8])
	if d.Xid != 0x0300bf9a || d.Blocks[0].Name != "switch3" || d.Blocks[0].Prefix != ProfinetDCPPrefixNone {
		t.Errorf("frame 9: %+v", d)
	}

	// Frame 24: S7-1500 (PLCSIM) identify response, pnio-rs golden frame.
	d = pnDCP(t, pkts[23])
	if d.Xid != 0x03000152 || d.DataLength != 88 || len(d.Blocks) != 7 {
		t.Fatalf("frame 24: %+v", d)
	}
	if b := d.Blocks[2]; b.Type() != ProfinetDCPBlockTypeOfStation || b.Name != "S7-1500 (PLCSIM)" {
		t.Errorf("frame 24 type of station: %+v", b)
	}
	if b := d.Blocks[3]; b.VendorID != 0x002a || b.DeviceID != 0x010e {
		t.Errorf("frame 24 device id: %+v", b)
	}
	if b := d.Blocks[5]; b.Type() != ProfinetDCPBlockDeviceInstance || b.Instance != 0x1064 {
		t.Errorf("frame 24 instance: %+v", b)
	}
	if b := d.Blocks[6]; !b.IP.Equal(net.IPv4(192, 168, 1, 61)) || b.BlockInfo != 1 {
		t.Errorf("frame 24 ip: %+v", b)
	}
}

func TestProfinetRTAlarmPcap(t *testing.T) {
	withProfinet(t)
	pkts := decodePN(t, pnRTAlarmPcap)
	if len(pkts) != 20 {
		t.Fatalf("%d frames, want 20", len(pkts))
	}

	// Frames 1-4: RT_CLASS_1 cyclic, 40 bytes of IO data in a tagged 64-byte frame.
	cyclic := []struct {
		id     ProfinetFrameID
		cycle  uint16
		status ProfinetDataStatus
	}{
		{0x8001, 58368, 0x35},
		{0x8000, 60416, 0x36},
		{0x8001, 47104, 0x35},
		{0x8000, 7168, 0x35},
	}
	for i, c := range cyclic {
		p := pkts[i]
		pn := p.Layer(LayerTypeProfinet).(*Profinet)
		if pn.FrameID != c.id || pn.CycleCounter != c.cycle || pn.DataStatus != c.status || pn.TransferStatus != 0 {
			t.Errorf("frame %d: %+v", i+1, pn)
		}
		if len(pn.IOData) != 40 || pn.NextLayerType() != gopacket.LayerTypeZero {
			t.Errorf("frame %d: %d IO bytes", i+1, len(pn.IOData))
		}
		if p.Layer(LayerTypeDot1Q) == nil {
			t.Errorf("frame %d: not tagged", i+1)
		}
	}

	ds := pkts[0].Layer(LayerTypeProfinet).(*Profinet).DataStatus
	if !ds.DataValid() || !ds.Primary() || !ds.Run() || ds.StationProblem() || ds.Ignore() {
		t.Errorf("data status %v", ds)
	}
	if ds := ProfinetDataStatus(0x36); ds.Primary() || !ds.Redundancy() {
		t.Errorf("data status %v: want backup with redundancy", ds)
	}

	// Frames 5-20: alarms.
	alarms := []struct {
		pdu      ProfinetAlarmPDUType
		send     uint16
		ack      uint16
		varPart  int
		priority ProfinetFrameID
	}{
		{ProfinetAlarmData, 0xffff, 0xffff, 0x16, ProfinetFrameIDAlarmHigh},
		{ProfinetAlarmACK, 0xfffe, 0xffff, 0, ProfinetFrameIDAlarmHigh},
		{ProfinetAlarmACK, 0xffff, 0xffff, 0, ProfinetFrameIDAlarmHigh},
		{ProfinetAlarmACK, 0xfffe, 0xffff, 0, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmACK, 0xffff, 0xffff, 0, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmData, 0xffff, 0xffff, 0x16, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmData, 0xffff, 0xfffe, 0x28, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmData, 0x0005, 0x0004, 0x28, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmData, 0x0000, 0xffff, 0x28, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmData, 0x0001, 0x0000, 0x28, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmData, 0x0004, 0x0003, 0x1c, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmERR, 0x0005, 0x0005, 4, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmERR, 0xfffe, 0xfffe, 4, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmERR, 0x0006, 0x0005, 4, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmERR, 0xffff, 0xfffe, 4, ProfinetFrameIDAlarmLow},
		{ProfinetAlarmData, 0xffff, 0xfffe, 0x1d, ProfinetFrameIDAlarmHigh},
	}
	for i, w := range alarms {
		p := pkts[4+i]
		a, ok := p.Layer(LayerTypeProfinetAlarm).(*ProfinetAlarm)
		if !ok {
			t.Fatalf("frame %d: no alarm layer", 5+i)
		}
		pn := p.Layer(LayerTypeProfinet).(*Profinet)
		if pn.FrameID != w.priority || a.PDUType != w.pdu || a.SendSeqNum != w.send || a.AckSeqNum != w.ack ||
			int(a.VarPartLength) != w.varPart || len(a.LayerPayload()) != w.varPart || a.Version != 1 || a.WindowSize != 1 {
			t.Errorf("frame %d: %+v", 5+i, a)
		}
	}

	// Frame 16: ERR-RTA, RTA protocol error, AR alarm.ind(err).
	a := pkts[15].Layer(LayerTypeProfinetAlarm).(*ProfinetAlarm)
	if a.ErrorCode != 0xcf || a.ErrorDecode != 0x81 || a.ErrorCode1 != 0xfd || a.ErrorCode2 != 0x0b {
		t.Errorf("frame 16 status %#x %#x %#x %#x", a.ErrorCode, a.ErrorDecode, a.ErrorCode1, a.ErrorCode2)
	}
}

func TestProfinetHandmadePcap(t *testing.T) {
	withProfinet(t)
	pkts := decodePN(t, pnHandmadePcap)
	if len(pkts) != 16 {
		t.Fatalf("%d frames, want 16", len(pkts))
	}

	// 1: Hello request, BlockInfo on every block, odd name padded.
	d := pnDCP(t, pkts[0])
	if d.ServiceID != ProfinetDCPServiceHello || len(d.Blocks) != 6 {
		t.Fatalf("hello: %+v", d)
	}
	if b := d.Blocks[0]; b.Name != "plc-1" || b.Length != 7 || b.Prefix != ProfinetDCPPrefixBlockInfo {
		t.Errorf("hello name: %+v", b)
	}
	if b := d.Blocks[1]; !b.Gateway.Equal(net.IPv4(192, 168, 0, 254)) {
		t.Errorf("hello ip: %+v", b)
	}
	if b := d.Blocks[5]; b.Type() != ProfinetDCPBlockDeviceInitiative || b.DeviceInitiative != 1 {
		t.Errorf("hello initiative: %+v", b)
	}

	// 2: Get request lists bare selectors.
	d = pnDCP(t, pkts[1])
	if len(d.Blocks) != 2 || d.Blocks[0].Type() != ProfinetDCPBlockNameOfStation ||
		d.Blocks[1].Type() != ProfinetDCPBlockIPParameter || d.Blocks[1].IP != nil {
		t.Errorf("get request: %+v", d.Blocks)
	}

	// 3: Get response carries BlockInfo.
	if b := pnDCP(t, pkts[2]).Blocks[1]; b.Prefix != ProfinetDCPPrefixBlockInfo || !b.IP.Equal(net.IPv4(10, 0, 0, 5)) {
		t.Errorf("get response: %+v", b)
	}

	// 4: Set request, VLAN tagged: transaction, full IP suite, flash once.
	d = pnDCP(t, pkts[3])
	if len(d.Blocks) != 4 {
		t.Fatalf("set request: %+v", d.Blocks)
	}
	suite := d.Blocks[1]
	if suite.Type() != ProfinetDCPBlockIPSuite || suite.Prefix != ProfinetDCPPrefixBlockQualifier || suite.BlockInfo != 1 ||
		len(suite.DNS) != 4 || !suite.DNS[0].Equal(net.IPv4(8, 8, 8, 8)) || !suite.DNS[3].Equal(net.IPv4(9, 9, 9, 9)) {
		t.Errorf("ip suite: %+v", suite)
	}
	if b := d.Blocks[2]; b.Type() != ProfinetDCPBlockSignal || b.Signal != 0x0100 {
		t.Errorf("signal: %+v", b)
	}

	// 5: Set response, two control responses.
	d = pnDCP(t, pkts[4])
	if len(d.Blocks) != 2 || d.Blocks[1].Response.Type() != ProfinetDCPBlockSignal ||
		d.Blocks[1].BlockError != ProfinetDCPErrorInOperation {
		t.Errorf("set response: %+v", d.Blocks)
	}

	// 6: Reset to factory, mode in qualifier bits 1-15.
	if b := pnDCP(t, pkts[5]).Blocks[0]; b.Type() != ProfinetDCPBlockResetToFactory || b.BlockInfo>>1 != 2 {
		t.Errorf("reset to factory: %+v", b)
	}

	// 7: Identify, service unsupported, no blocks.
	if d := pnDCP(t, pkts[6]); d.ServiceType != ProfinetDCPResponseUnsupported || len(d.Blocks) != 0 {
		t.Errorf("unsupported: %+v", d)
	}

	// 8: Identify request with response delay.
	if d := pnDCP(t, pkts[7]); d.ResponseDelay != 0x80 || d.Blocks[0].Type() != ProfinetDCPBlockAllSelector {
		t.Errorf("identify: %+v", d)
	}

	// 9: PTCP RTSync, delay 10*10 + 3 + 5 ns.
	ptcp := pkts[8].Layer(LayerTypeProfinetPTCP).(*ProfinetPTCP)
	if ptcp.SequenceID != 1 || ptcp.DelayNs() != 108 || len(ptcp.TLVs) != 3 ||
		ptcp.MasterSourceAddress.String() != "00:1b:1b:00:00:02" || ptcp.Seconds != 100 || ptcp.NanoSeconds != 1000 ||
		ptcp.EpochNumber != 1 || !bytes.Equal(ptcp.SubdomainUUID, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}) {
		t.Errorf("rtsync: %+v", ptcp)
	}

	// 10-12: follow up, announce, delay request.
	if p := pkts[9].Layer(LayerTypeProfinetPTCP).(*ProfinetPTCP); p.SequenceID != 2 || p.Delay1ns != 100 {
		t.Errorf("follow up: %+v", p)
	}
	if p := pkts[10].Layer(LayerTypeProfinetPTCP).(*ProfinetPTCP); p.SequenceID != 3 || p.TLVs[1].Type != ProfinetPTCPTLVMaster {
		t.Errorf("announce: %+v", p)
	}
	if p := pkts[11].Layer(LayerTypeProfinetPTCP).(*ProfinetPTCP); p.SequenceID != 5 || p.TLVs[0].Type != ProfinetPTCPTLVDelayParameter {
		t.Errorf("delay request: %+v", p)
	}

	// 13: RT_CLASS_3.
	pn := pkts[12].Layer(LayerTypeProfinet).(*Profinet)
	if pn.FrameID.Class() != ProfinetFrameClassRTClass3 || pn.CycleCounter != 0x1234 || len(pn.IOData) != 40 || pn.IOData[39] != 39 {
		t.Errorf("rtc3: %+v", pn)
	}

	// 14: RT_CLASS_1 legacy: valid, backup, ok, stop, ignore, transfer status set.
	pn = pkts[13].Layer(LayerTypeProfinet).(*Profinet)
	if ds := pn.DataStatus; !ds.DataValid() || ds.Primary() || ds.Run() || ds.StationProblem() || !ds.Ignore() || pn.TransferStatus != 1 {
		t.Errorf("rtc1 legacy: %+v", pn)
	}

	// 15: fragment: the 2-byte fragment header, then the fragment as payload.
	pn = pkts[14].Layer(LayerTypeProfinet).(*Profinet)
	if pn.FrameID.Class() != ProfinetFrameClassFragment || len(pn.LayerPayload()) != 42 || pkts[14].ApplicationLayer() == nil {
		t.Errorf("fragment: %+v", pn)
	}
	if pn.FragDataLength != 0x2a || !pn.FragStatus.MoreFollows() || pn.FragStatus.Number() != 0 {
		t.Errorf("fragment header: %d %v", pn.FragDataLength, pn.FragStatus)
	}

	// 16: NACK-RTA.
	a := pkts[15].Layer(LayerTypeProfinetAlarm).(*ProfinetAlarm)
	if a.PDUType != ProfinetAlarmNACK || a.DstEndpoint != 1 || a.SrcEndpoint != 0x8001 || a.Version != 1 || a.TACK != 1 {
		t.Errorf("nack: %+v", a)
	}
}

// TestProfinetDecodingLayerParser runs a tagged cyclic frame and a DCP frame
// through DecodingLayerParser, which relies on EthernetType.LayerType.
func TestProfinetDecodingLayerParser(t *testing.T) {
	withProfinet(t)

	var (
		eth   Ethernet
		dot1q Dot1Q
		pn    Profinet
		dcp   ProfinetDCP
		alarm ProfinetAlarm
		ptcp  ProfinetPTCP
	)
	parser := gopacket.NewDecodingLayerParser(LayerTypeEthernet, &eth, &dot1q, &pn, &dcp, &alarm, &ptcp)
	parser.IgnoreUnsupported = true

	cases := []struct {
		frame []byte
		want  []gopacket.LayerType
	}{
		{readPNECATPcap(t, pnRTAlarmPcap)[0], []gopacket.LayerType{LayerTypeEthernet, LayerTypeDot1Q, LayerTypeProfinet}},
		{readPNECATPcap(t, pnDCPPcap)[1], []gopacket.LayerType{LayerTypeEthernet, LayerTypeProfinet, LayerTypeProfinetDCP}},
		{readPNECATPcap(t, pnHandmadePcap)[8], []gopacket.LayerType{LayerTypeEthernet, LayerTypeDot1Q, LayerTypeProfinet, LayerTypeProfinetPTCP}},
	}
	for i, c := range cases {
		var got []gopacket.LayerType
		if err := parser.DecodeLayers(c.frame, &got); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("case %d: layers %v, want %v", i, got, c.want)
		}
		for j := range got {
			if got[j] != c.want[j] {
				t.Errorf("case %d: layers %v, want %v", i, got, c.want)
			}
		}
	}
	if len(dcp.Blocks) == 0 {
		t.Errorf("DCP blocks not decoded: %+v", dcp.Blocks)
	}
}

// TestProfinetTruncation decodes every prefix of every test frame. It must
// never panic, and must report errors rather than read past the data.
func TestProfinetTruncation(t *testing.T) {
	withProfinet(t)

	for _, path := range []string{pnDCPPcap, pnRTAlarmPcap, pnHandmadePcap, pnExtraPcap} {
		for _, frame := range readPNECATPcap(t, path) {
			for n := 0; n <= len(frame); n++ {
				data := append([]byte(nil), frame[:n]...)
				gopacket.NewPacket(data, LinkTypeEthernet, gopacket.Default)
			}
		}
	}
}

// pnFrame wraps a PROFINET PDU in an untagged Ethernet header.
func pnFrame(pdu ...byte) []byte {
	hdr := []byte{0x01, 0x0e, 0xcf, 0, 0, 0, 0, 0x1b, 0x1b, 0, 0, 1, 0x88, 0x92}
	return append(hdr, pdu...)
}

func TestProfinetMalformed(t *testing.T) {
	withProfinet(t)

	cases := []struct {
		name      string
		frame     []byte
		err       error // expected from the failing layer, nil if none
		truncated bool
	}{
		{"frame id only half", pnFrame(0xfe), ErrProfinetTooShort, true},
		{"cyclic without trailer", pnFrame(0x80, 0x00, 1, 2, 3), ErrProfinetTooShort, true},
		{"dcp header short", pnFrame(0xfe, 0xfe, 5, 0, 0, 0, 0, 1), ErrProfinetDCPTooShort, true},
		// DataLength says 0x100 but only one 4-byte block follows: the capture
		// was cut, so this is truncation, not an error.
		{"dcp data length lies", pnFrame(0xfe, 0xfe, 5, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0xff, 0xff, 0, 0), nil, true},
		// A block length past DataLength is malformed.
		{"dcp block length lies", pnFrame(0xfe, 0xfe, 5, 0, 0, 0, 0, 1, 0, 0, 0, 6, 2, 2, 0xff, 0xff, 'a', 'b'), ErrProfinetDCPBlock, false},
		{"dcp block header cut", pnFrame(0xfe, 0xfe, 5, 0, 0, 0, 0, 1, 0, 0, 0, 3, 2, 2, 0), ErrProfinetDCPBlock, false},
		{"alarm header short", pnFrame(0xfe, 0x01, 0, 1, 0, 2, 0x11), ErrProfinetAlarmTooShort, true},
		{"alarm var part lies", pnFrame(0xfe, 0x01, 0, 1, 0, 2, 0x11, 0x11, 0, 1, 0, 1, 0xff, 0xff, 9), nil, true},
		{"ptcp header short", pnFrame(0xff, 0x40, 0, 0, 0), ErrProfinetPTCPTooShort, true},
		{"ptcp tlv lies", pnFrame(append(make([]byte, 22), 0x0d, 0xff, 0)...), ErrProfinetPTCPTLV, true},
	}
	// Put the PTCP frame ID in front of the zero header.
	cases[len(cases)-1].frame[14], cases[len(cases)-1].frame[15] = 0xff, 0x40

	for _, c := range cases {
		p := gopacket.NewPacket(c.frame, LinkTypeEthernet, gopacket.Default)
		if got := p.Metadata().Truncated; got != c.truncated {
			t.Errorf("%s: truncated %v, want %v", c.name, got, c.truncated)
		}

		el := p.ErrorLayer()
		if c.err == nil {
			if el != nil {
				t.Errorf("%s: unexpected error %v", c.name, el.Error())
			}
			continue
		}
		if el == nil || el.Error() != c.err {
			t.Errorf("%s: error %v, want %v", c.name, el, c.err)
		}
	}
}

// TestProfinetDCPBlockLoop checks that a block area of zero-length blocks
// decodes in bounded time and memory (each block still takes 4 bytes).
func TestProfinetDCPBlockLoop(t *testing.T) {
	const blocks = 1000
	area := make([]byte, 4*blocks)
	for i := 0; i < blocks; i++ {
		area[4*i] = byte(ProfinetDCPOptionAll)
		area[4*i+1] = 0xff
	}

	pdu := make([]byte, profinetDCPHeaderLen, profinetDCPHeaderLen+len(area))
	pdu[0] = byte(ProfinetDCPServiceIdentify)
	binary.BigEndian.PutUint16(pdu[8:], uint16(len(area)))
	pdu = append(pdu, area...)

	var d ProfinetDCP
	if err := d.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if len(d.Blocks) != blocks {
		t.Fatalf("%d blocks, want %d", len(d.Blocks), blocks)
	}
}

func FuzzProfinet(f *testing.F) {
	withProfinet(f)
	for _, path := range []string{pnDCPPcap, pnRTAlarmPcap, pnHandmadePcap, pnExtraPcap} {
		for _, frame := range readPNECATPcap(f, path) {
			f.Add(frame)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		p := gopacket.NewPacket(data, LinkTypeEthernet, gopacket.Default)

		// Each sub-layer must stay within its input.
		for _, l := range p.Layers() {
			if len(l.LayerContents())+len(l.LayerPayload()) > len(data) {
				t.Fatalf("%v covers more than the frame", l.LayerType())
			}
		}

		// Decode the PDU types directly too, skipping the frame ID dispatch.
		for _, dl := range []gopacket.DecodingLayer{&Profinet{}, &ProfinetDCP{}, &ProfinetAlarm{}, &ProfinetPTCP{}, &ProfinetIORPC{}} {
			_ = dl.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
		}

		// The block list, and the count that sizes it.
		blocks, err := ProfinetDecodeBlocks(data)
		if err == nil && len(blocks) != countProfinetBlocks(data) {
			t.Fatalf("counted %d blocks, decoded %d", countProfinetBlocks(data), len(blocks))
		}

		// DFP with the addresses of the frame, and reassembly.
		if len(data) > 14 {
			pn := &Profinet{}
			if pn.DecodeFromBytes(data[14:], gopacket.NilDecodeFeedback) != nil {
				return
			}
			pn.DecodeSubframes(data[0:6], data[6:12])

			asm := NewProfinetFragAssembler(64)
			for i := 0; i < 3; i++ {
				if out, _ := asm.Add(data[6:12], data[0:6], pn); len(out) > asm.MaxSize {
					t.Fatalf("reassembled %d bytes past the cap", len(out))
				}
			}
		}
	})
}

// Delay1ns_FUP is an Integer32: 0xFFFFFFFF in a follow up is -1 ns, not
// 4294967295.
func TestProfinetPTCPNegativeDelay(t *testing.T) {
	pdu := make([]byte, 22)
	binary.BigEndian.PutUint32(pdu[16:20], 0xFFFFFFFF)

	p := &ProfinetPTCP{}
	if err := p.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if got := p.DelayNs(); got != -1 {
		t.Fatalf("DelayNs() = %d, want -1", got)
	}
}
