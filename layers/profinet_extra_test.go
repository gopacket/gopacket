// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
)

// profinet-extra.pcap holds 64 frames built by hand from IEC 61158-6-10
// and Wireshark's dissectors (text2pcap), for the kinds no public capture
// has. Every value below was compared with tshark 4.7.4.
//
//	1-3    DCP: DHCP, NME/CIM, RSI and protocol properties, reset modes
//	4-10   PTCP: every TLV, a misaligned one, an unknown OUI
//	11-23  alarms: every user structure, acks, ERR-RTA, a version 2.1 block
//	24-26  one DCP frame in three fragments
//	27-29  DFP with and without CRCs, a plain RT_CLASS_3 frame
//	30-33  secured cyclic frames and a secured alarm
//	34-45  one frame per Frame ID range
//	46-64  PNIO-CM over DCE/RPC: connect, read, write, control, release,
//	       an unknown block, a fault and a ping
const pnExtraPcap = "testdata/profinet-extra.pcap"

// pnExtra decodes the hand-made capture; frame n is at index n-1.
func pnExtra(t *testing.T) []gopacket.Packet {
	withProfinet(t)

	var pkts []gopacket.Packet
	for i, data := range readPNECATPcap(t, pnExtraPcap) {
		p := gopacket.NewPacket(data, LinkTypeEthernet, gopacket.Default)
		if el := p.ErrorLayer(); el != nil {
			t.Fatalf("frame %d: %v", i+1, el.Error())
		}
		pkts = append(pkts, p)
	}

	if len(pkts) != 64 {
		t.Fatalf("got %d frames, want 64", len(pkts))
	}
	return pkts
}

func pnAlarmBlock(t *testing.T, p gopacket.Packet) *ProfinetBlock {
	a, ok := p.Layer(LayerTypeProfinetAlarm).(*ProfinetAlarm)
	if !ok || a.Block == nil {
		t.Fatalf("no alarm block in %v", p)
	}
	return a.Block
}

func pnRPC(t *testing.T, p gopacket.Packet) *ProfinetIORPC {
	r, ok := p.Layer(LayerTypeProfinetIORPC).(*ProfinetIORPC)
	if !ok {
		t.Fatalf("no RPC layer in %v", p)
	}
	return r
}

func TestProfinetRPCNotRegistered(t *testing.T) {
	if _, ok := udpPortLayerType[UDPPortProfinetIO]; ok {
		t.Fatal("PROFINET IO UDP port registered without opt-in")
	}

	frame := readPNECATPcap(t, pnExtraPcap)[45]
	p := gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)
	if p.Layer(LayerTypeProfinetIORPC) != nil {
		t.Fatal("PROFINET IO RPC decoded without opt-in")
	}
}

func TestProfinetExtraDCP(t *testing.T) {
	pkts := pnExtra(t)

	seen := map[ProfinetDCPBlockType]*ProfinetDCPBlock{}
	d := pnDCP(t, pkts[0])
	for i := range d.Blocks {
		seen[d.Blocks[i].Type()] = &d.Blocks[i]
	}

	if b := seen[ProfinetDCPBlockNameOfStation]; b == nil || b.Name != "dev-1" {
		t.Errorf("name of station: %+v", b)
	}
	if b := seen[ProfinetDCPBlockDHCPClientID]; b == nil || b.DHCPOptionCode != DHCPOptClientID || b.Name != "cli1" || !bytes.Equal(b.DHCPParameter(), []byte("\x00cli1")) {
		t.Errorf("DHCP client ID: %+v", b)
	}
	if b := seen[ProfinetDCPBlockDHCPControl]; b == nil || !bytes.Equal(b.DHCPParameter(), []byte{2}) {
		t.Errorf("DHCP control: %+v", b)
	}

	b := seen[ProfinetDCPBlockNMEDomain]
	if b == nil || b.Name != "nme.domain" {
		t.Fatalf("NME domain: %+v", b)
	}
	if _, ok := b.UUID(); !ok {
		t.Error("NME domain has no UUID")
	}
}

func TestProfinetExtraPTCP(t *testing.T) {
	pkts := pnExtra(t)

	// 4: announce with a Master TLV.
	p := pkts[3].Layer(LayerTypeProfinetPTCP).(*ProfinetPTCP)
	if p.MasterPriority1.Priority() != 1 || p.MasterPriority1.Level() != 1 || !p.MasterPriority1.Active() {
		t.Errorf("priority1: %v", p.MasterPriority1)
	}
	if p.MasterPriority2 != 2 || p.ClockClass != 255 || p.ClockAccuracy != 0x21 || p.ClockVariance != -300 {
		t.Errorf("master: %+v", p)
	}

	// 5: sync with time extension and the IRData option.
	p = pkts[4].Layer(LayerTypeProfinetPTCP).(*ProfinetPTCP)
	if p.Flags != 3 || p.CurrentUTCOffset != 37 || p.OUI != 0x000ECF || p.OptionSubType != 1 {
		t.Errorf("sync: %+v", p)
	}
	if got := p.IRDataUUID.String(); got != "a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf" {
		t.Errorf("IRDataUUID = %s", got)
	}

	// 7, 8: delay responses with PortParameter and PortTime.
	p = pkts[6].Layer(LayerTypeProfinetPTCP).(*ProfinetPTCP)
	if p.T2PortRxDelay != 111 || p.T3PortTxDelay != 222 || p.PortMACAddress.String() != "00:1b:1b:00:00:02" {
		t.Errorf("port parameter: %+v", p)
	}
	p = pkts[7].Layer(LayerTypeProfinetPTCP).(*ProfinetPTCP)
	if p.T2TimeStamp != 987654321 {
		t.Errorf("T2TimeStamp = %d", p.T2TimeStamp)
	}

	// 9: a TLV of odd length; the next one starts on a 4-byte boundary.
	p = pkts[8].Layer(LayerTypeProfinetPTCP).(*ProfinetPTCP)
	if len(p.TLVs) != 3 || p.TLVs[0].Length != 8 || p.T2PortRxDelay != 333 || p.T3PortTxDelay != 444 {
		t.Errorf("misaligned TLV: %+v", p)
	}

	// 10: an option of another organisation stays raw.
	p = pkts[9].Layer(LayerTypeProfinetPTCP).(*ProfinetPTCP)
	if p.OUI != 0x008041 || p.OptionSubType != 1 || !bytes.Equal(p.OptionData, []byte{1, 2, 3, 4}) || !p.IRDataUUID.IsZero() {
		t.Errorf("foreign option: %+v", p)
	}
}

func TestProfinetExtraAlarms(t *testing.T) {
	pkts := pnExtra(t)

	// 11: channel, extended and qualified diagnosis in one notification.
	b := pnAlarmBlock(t, pkts[10])
	a := b.Alarm
	if b.Type != ProfinetBlockAlarmLow || b.Length != 62 || a == nil {
		t.Fatalf("block: %+v", b)
	}
	if a.AlarmType != ProfinetAlarmTypeDiagnosis || a.API != 0 || a.Slot != 1 || a.Subslot != 1 || a.ModuleIdentNumber != 0x100 || a.SubmoduleIdentNumber != 0x101 {
		t.Errorf("notification: %+v", a)
	}
	if s := a.Specifier; s.SequenceNumber() != 5 || !s.ChannelDiagnosis() || s.ManufacturerDiagnosis() || !s.SubmoduleDiagnosis() || !s.ARDiagnosis() {
		t.Errorf("specifier: %#x", uint16(s))
	}
	if len(a.Items) != 3 {
		t.Fatalf("items: %+v", a.Items)
	}

	it := a.Items[0]
	if it.USI != ProfinetUSIChannelDiagnosis || it.ChannelNumber != 5 || it.ChannelProperties != 0x2804 || it.ChannelErrorType != 6 {
		t.Errorf("channel diagnosis: %+v", it)
	}
	if cp := it.ChannelProperties; cp.Type() != 4 || cp.Accumulative() || cp.Maintenance() != 0 || cp.Specifier() != 1 || cp.Direction() != 1 {
		t.Errorf("channel properties: %#x", uint16(cp))
	}

	it = a.Items[1]
	if it.USI != ProfinetUSIExtChannelDiagnosis || it.ChannelNumber != 0x8000 || it.ChannelErrorType != 0x8000 || it.ExtChannelErrorType != 0x8001 || it.ExtChannelAddValue != 0xCAFEBABE {
		t.Errorf("ext channel diagnosis: %+v", it)
	}

	it = a.Items[2]
	if it.USI != ProfinetUSIQualifiedDiagnosis || it.ChannelErrorType != 0x10 || it.ExtChannelErrorType != 2 || it.ExtChannelAddValue != 77 || it.QualifiedChannelQualifier != 0x08000000 {
		t.Errorf("qualified diagnosis: %+v", it)
	}

	// 12: a maintenance item block, then a qualified diagnosis.
	a = pnAlarmBlock(t, pkts[11]).Alarm
	if len(a.Items) != 2 || a.Items[0].USI != ProfinetUSIMaintenance || a.Items[0].Block == nil {
		t.Fatalf("maintenance: %+v", a.Items)
	}
	mb := a.Items[0].Block
	if mb.Type != ProfinetBlockMaintenanceItem || mb.Item == nil || mb.Item.MaintenanceStatus != 3 || !mb.Item.MaintenanceStatus.Required() || !mb.Item.MaintenanceStatus.Demanded() {
		t.Errorf("maintenance block: %+v", mb)
	}
	if a.Items[1].USI != ProfinetUSIQualifiedDiagnosis {
		t.Errorf("item after maintenance: %+v", a.Items[1])
	}

	// 13, 14: upload and retrieval, iParameter.
	a = pnAlarmBlock(t, pkts[12]).Alarm
	if a.AlarmType != ProfinetAlarmTypeUploadRetrieval || len(a.Items) != 1 || a.Items[0].USI != ProfinetUSIUploadRetrieval || a.Items[0].Block == nil || a.Items[0].Block.Item == nil {
		t.Errorf("upload and retrieval: %+v", a)
	}
	a = pnAlarmBlock(t, pkts[13]).Alarm
	if len(a.Items) != 1 || a.Items[0].USI != ProfinetUSIIParameter || a.Items[0].Block == nil || a.Items[0].Block.Item == nil {
		t.Errorf("iParameter: %+v", a)
	}

	// 15: PE energy saving status.
	a = pnAlarmBlock(t, pkts[14]).Alarm
	if a.AlarmType != ProfinetAlarmTypeStatus || len(a.Items) != 1 || a.Items[0].Block == nil || a.Items[0].Block.Item == nil || a.Items[0].Block.Item.PEOperationalMode != 0xF0 {
		t.Errorf("PE alarm: %+v", a)
	}

	// 16: process alarm with a PRAL item.
	b = pnAlarmBlock(t, pkts[15])
	it = b.Alarm.Items[0]
	if b.Type != ProfinetBlockAlarmHigh || it.USI != ProfinetUSIPRAL || it.ChannelNumber != 3 || it.PRALReason != 2 || it.PRALExtReason != 1 || !bytes.Equal(it.PRALReasonAddValue, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}) {
		t.Errorf("PRAL: %+v", it)
	}

	// 17: a manufacturer structure stays raw.
	it = pnAlarmBlock(t, pkts[16]).Alarm.Items[0]
	if it.USI != 0x42 || !it.USI.IsManufacturer() || len(it.Data) == 0 {
		t.Errorf("manufacturer item: %+v", it)
	}

	// 19: pull alarm without user structures.
	a = pnAlarmBlock(t, pkts[18]).Alarm
	if a.AlarmType != ProfinetAlarmTypePull || len(a.Items) != 0 {
		t.Errorf("pull: %+v", a)
	}

	// 20, 21: acks, one with an error status.
	ack := pnAlarmBlock(t, pkts[19]).AlarmAck
	if ack == nil || ack.AlarmType != ProfinetAlarmTypeDiagnosis || ack.Specifier.SequenceNumber() != 5 || ack.Status.ErrorCode != ProfinetErrorCodeAlarmAck || ack.Status.ErrorDecode != ProfinetErrorDecodePNIO || ack.Status.OK() {
		t.Errorf("ack: %+v", ack)
	}
	ack = pnAlarmBlock(t, pkts[20]).AlarmAck
	if ack == nil || ack.AlarmType != ProfinetAlarmTypeProcess || !ack.Status.OK() {
		t.Errorf("ack ok: %+v", ack)
	}

	// 22: ERR-RTA carries a PNIO status.
	e := pkts[21].Layer(LayerTypeProfinetAlarm).(*ProfinetAlarm)
	if st := e.Status(); e.PDUType != ProfinetAlarmERR || st.ErrorCode != ProfinetErrorCodeRTA || st.ErrorDecode != ProfinetErrorDecodePNIO {
		t.Errorf("ERR-RTA: %+v %v", e, st)
	}

	// 23: a version this decoder does not know keeps the header only.
	b = pnAlarmBlock(t, pkts[22])
	if b.VersionHigh != 2 || b.VersionLow != 1 || b.Alarm != nil || len(b.Body) != 24 {
		t.Errorf("version 2.1: %+v", b)
	}
}

func TestProfinetExtraFragments(t *testing.T) {
	pkts := pnExtra(t)
	asm := NewProfinetFragAssembler(0)

	var whole []byte
	for i := 23; i <= 25; i++ {
		pn := pkts[i].Layer(LayerTypeProfinet).(*Profinet)
		eth := pkts[i].Layer(LayerTypeEthernet).(*Ethernet)
		if pn.FragDataLength != 2 || int(pn.FragStatus.Number()) != i-23 || pn.FragStatus.MoreFollows() != (i < 25) {
			t.Errorf("frame %d: %d %v", i+1, pn.FragDataLength, pn.FragStatus)
		}

		out, err := asm.Add(eth.SrcMAC, eth.DstMAC, pn)
		if err != nil {
			t.Fatalf("frame %d: %v", i+1, err)
		}
		if (out != nil) != (i == 25) {
			t.Fatalf("frame %d: reassembled = %v", i+1, out != nil)
		}
		whole = out
	}

	if asm.Pending() != 0 {
		t.Errorf("pending = %d", asm.Pending())
	}
	if et := EthernetType(binary.BigEndian.Uint16(whole)); et != EthernetTypeProfinet {
		t.Fatalf("EtherType = %v", et)
	}

	p := gopacket.NewPacket(whole[2:], LayerTypeProfinet, gopacket.Default)
	d := pnDCP(t, p)
	if d.ServiceID != ProfinetDCPServiceIdentify || d.Xid != 0x1234 || len(d.Blocks) != 1 || d.Blocks[0].Option != ProfinetDCPOptionAll {
		t.Errorf("reassembled DCP: %+v", d)
	}
}

func TestProfinetExtraDFP(t *testing.T) {
	pkts := pnExtra(t)

	// 27: header CRC and a checked subframe CRC.
	pn := pkts[26].Layer(LayerTypeProfinet).(*Profinet)
	if pn.SubframeHeaderCRC != 0xC849 || len(pn.Subframes) != 2 || pn.CycleCounter != 4660 {
		t.Fatalf("DFP: %+v", pn)
	}
	if sf := pn.Subframes[0]; sf.Position != 1 || !sf.CRCFlag || sf.DataLength != 4 || len(sf.Data) != 4 || sf.CycleCounter != 9 || sf.DataStatus != 0x35 || sf.CRC != 0xFEA1 {
		t.Errorf("subframe 1: %+v", sf)
	}
	if sf := pn.Subframes[1]; sf.Position != 2 || sf.CRCFlag || sf.DataLength != 2 || sf.CycleCounter != 10 || sf.DataStatus != 0x15 || sf.CRC != 0 {
		t.Errorf("subframe 2: %+v", sf)
	}

	eth := pkts[26].Layer(LayerTypeEthernet).(*Ethernet)
	if got := ProfinetDFPHeaderCRC(eth.DstMAC, eth.SrcMAC, pn.FrameID); got != 0xC849 {
		t.Errorf("header CRC = %#x", got)
	}

	// Without the addresses the header CRC cannot be checked.
	alone := &Profinet{}
	if err := alone.DecodeFromBytes(eth.LayerPayload(), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if alone.Subframes != nil {
		t.Error("subframes decoded without addresses")
	}
	if !alone.DecodeSubframes(eth.DstMAC, eth.SrcMAC) || len(alone.Subframes) != 2 {
		t.Error("DecodeSubframes with addresses failed")
	}
	if alone.DecodeSubframes(eth.SrcMAC, eth.DstMAC) || alone.Subframes != nil {
		t.Error("DecodeSubframes accepted a wrong header CRC")
	}

	// 28: no header CRC, redundant range.
	pn = pkts[27].Layer(LayerTypeProfinet).(*Profinet)
	if pn.SubframeHeaderCRC != 0 || len(pn.Subframes) != 1 || pn.Subframes[0].Position != 3 || pn.Subframes[0].DataLength != 20 || pn.Subframes[0].CycleCounter != 200 || pn.Subframes[0].CRC != 0xC6F3 {
		t.Errorf("DFP without header CRC: %+v", pn)
	}

	// 29: plain IO data.
	pn = pkts[28].Layer(LayerTypeProfinet).(*Profinet)
	if pn.Subframes != nil || len(pn.IOData) != 40 {
		t.Errorf("plain RT_CLASS_3: %+v", pn)
	}
}

func TestProfinetExtraSecurity(t *testing.T) {
	pkts := pnExtra(t)

	// 30: authentication only: data, APDU status, checksum.
	pn := pkts[29].Layer(LayerTypeProfinet).(*Profinet)
	sec := pn.Security
	if sec == nil || sec.Encrypted() || sec.GenerationNumber() != 3 || sec.SequenceCounter != 0x01020304 || sec.Length != 0x2C {
		t.Fatalf("RTC1 auth only: %+v", sec)
	}
	if len(pn.IOData) != 40 || pn.CycleCounter != 17185 || pn.DataStatus != 0x35 || len(sec.Checksum) != 16 || sec.Checksum[0] != 0xE0 {
		t.Errorf("RTC1 auth only: %+v", pn)
	}

	// 31: authenticated encryption: no trailer to read.
	pn = pkts[30].Layer(LayerTypeProfinet).(*Profinet)
	sec = pn.Security
	if sec == nil || !sec.Encrypted() || sec.GenerationNumber() != 4 || sec.SequenceCounter != 7 || sec.Length != 0x28 {
		t.Fatalf("RTC1 encrypted: %+v", sec)
	}
	if len(pn.IOData) != 40 || pn.CycleCounter != 0 || pn.DataStatus != 0 || sec.Checksum[0] != 0xC0 {
		t.Errorf("RTC1 encrypted: %+v", pn)
	}

	// 32: secured alarm; the alarm PDU is decoded as usual.
	pn = pkts[31].Layer(LayerTypeProfinet).(*Profinet)
	sec = pn.Security
	if pn.FrameID != ProfinetFrameIDAlarmLowSec || sec == nil || sec.Encrypted() || sec.GenerationNumber() != 1 || sec.SequenceCounter != 0x63 || sec.Length != 0x2E || len(sec.Checksum) != 16 || sec.Checksum[0] != 0x50 {
		t.Fatalf("secured alarm: %+v %+v", pn, sec)
	}
	a := pnAlarmBlock(t, pkts[31]).Alarm
	if a == nil || a.AlarmType != ProfinetAlarmTypeDiagnosis || len(a.Items) != 1 || a.Items[0].ChannelErrorType != 6 {
		t.Errorf("secured alarm body: %+v", a)
	}

	// 33: secured RT_CLASS_3: no subframe search.
	pn = pkts[32].Layer(LayerTypeProfinet).(*Profinet)
	if pn.Security == nil || pn.Security.GenerationNumber() != 2 || pn.Security.SequenceCounter != 5 || pn.Subframes != nil || pn.CycleCounter != 257 {
		t.Errorf("RTC3 secured: %+v", pn)
	}
}

func TestProfinetFrameNames(t *testing.T) {
	for _, tc := range []struct {
		id     ProfinetFrameID
		name   string
		stream string
	}{
		{0x0010, "0x0000-0x001F: Reserved ID", ""},
		{0x0080, "0x0080-0x0081: Real-Time: Sync (without follow up)", ""},
		{0x0102, "0x0100-0x06FF: RED: Real-Time(class=3): non redundant, normal or DFP", "0x0100-0x0FFF: Reserved ID"},
		{0x0700, "0x0700-0x0FFF: RED: Real-Time(class=3): redundant, normal or DFP", "0x0100-0x0FFF: Reserved ID"},
		{0x1000, "0x1000-0x7FFF: Reserved ID", "0x1000-0x2FFF: RT_CLASS_STREAM"},
		{0x2ABC, "0x1000-0x7FFF: Reserved ID", "0x1000-0x2FFF: RT_CLASS_STREAM"},
		{0x3000, "0x1000-0x7FFF: Reserved ID", "0x3000-0x37FF: Reserved ID"},
		{0x3900, "0x1000-0x7FFF: Reserved ID", "0x3800-0x3FFF: RT_CLASS_STREAM with security"},
		{0x4000, "0x1000-0x7FFF: Reserved ID", ""},
		{0x7FFF, "0x1000-0x7FFF: Reserved ID", ""},
		{0x8010, "0x8000-0xBBFF: Real-Time(class=1 unicast): non redundant, normal", ""},
		{0xFC00, "0xFC00-0xFDFF: Reserved", ""},
		{0xFC01, "Real-Time: Acyclic PN-IO Alarm high priority", ""},
		{0xFE41, "Real-Time: Acyclic PN-IO Alarm low priority with security", ""},
		{0xFEFD, "Real-Time: DCP (Discovery and basic Configuration Protocol) get/set", ""},
		{0xFF00, "0xFF00-0xFF01: PTCP Announce", ""},
		{0xFF10, "0xFF02-0xFF1F: Reserved", ""},
		{0xFF42, "0xFF40-0xFF43: Acyclic Real-Time: Delay", ""},
		{0xFF50, "0xFF44-0xFF7F: reserved ID", ""},
		{0xFF85, "0xFF80-0xFF8F: Fragmentation", ""},
		{0xFF90, "0xFF90-0xFFFF: reserved ID", ""},
	} {
		if got := tc.id.Name(); got != tc.name {
			t.Errorf("%#04x Name() = %q, want %q", uint16(tc.id), got, tc.name)
		}

		want := tc.stream
		if want == "" {
			want = tc.name
		}
		if got := tc.id.StreamName(); got != want {
			t.Errorf("%#04x StreamName() = %q, want %q", uint16(tc.id), got, want)
		}
	}

	// The stream ranges exist on time-aware networks only.
	if c := ProfinetFrameID(0x1000).Class(); c != ProfinetFrameClassReserved {
		t.Errorf("0x1000 class = %v", c)
	}
	if c := ProfinetFrameID(0x1000).StreamClass(); c != ProfinetFrameClassRTStream {
		t.Errorf("0x1000 stream class = %v", c)
	}
	if c := ProfinetFrameID(0x0102).StreamClass(); c != ProfinetFrameClassReserved {
		t.Errorf("0x0102 stream class = %v", c)
	}
	if c := ProfinetFrameID(0x8010).StreamClass(); c != ProfinetFrameClassRTClass1 {
		t.Errorf("0x8010 stream class = %v", c)
	}
}

func TestProfinetExtraRPC(t *testing.T) {
	pkts := pnExtra(t)
	const arUUID = "60616263-6465-6667-6869-6a6b6c6d6e6f"

	// 46: connect request, little-endian.
	r := pnRPC(t, pkts[45])
	if r.PacketType != ProfinetRPCRequest || r.Opnum != ProfinetRPCConnect || r.Interface() != ProfinetRPCInterfaceDevice || !r.LittleEndian() || r.Fragmented() {
		t.Fatalf("connect request header: %+v", r)
	}
	if got := r.InterfaceUUID.String(); got != "dea00001-6c97-11d1-8271-00a02442df7d" {
		t.Errorf("interface UUID = %s", got)
	}
	if !r.HasNDR || r.ArgsMaximum != 4096 || r.ArgsLength != 322 || r.MaximumCount != 4096 || r.Offset != 0 || r.ActualCount != 322 || r.FragmentLength != 342 {
		t.Errorf("connect request NDR: %+v", r)
	}
	if len(r.Blocks) != 5 || len(r.LayerPayload()) != 0 || pkts[45].ApplicationLayer() != gopacket.ApplicationLayer(r) {
		t.Fatalf("connect request blocks: %d", len(r.Blocks))
	}

	ar := r.Blocks[0].AR
	if r.Blocks[0].Type != ProfinetBlockARReq || ar == nil || ar.ARUUID.String() != arUUID || ar.StationName != "controller" || ar.MAC.String() != "00:1b:1b:00:00:01" || ar.ActivityTimeoutFactor != 600 {
		t.Errorf("ARBlockReq: %+v", ar)
	}
	if ap := ar.Properties; ap != 0x40000111 || ap.State() != 1 || !ap.DeviceAccess() || !ap.AdvancedStartup() || ap.PullModuleAlarm() {
		t.Errorf("AR properties: %#x", uint32(ap))
	}

	cr := r.Blocks[1].IOCR
	if r.Blocks[1].Type != ProfinetBlockIOCRReq || cr == nil || cr.FrameID != 0x8001 || cr.LT != EthernetTypeProfinet || len(cr.APIs) != 1 {
		t.Fatalf("IOCRBlockReq: %+v", cr)
	}
	if r.Blocks[2].IOCR == nil || r.Blocks[2].IOCR.FrameID != 0xFFFF {
		t.Errorf("second IOCRBlockReq: %+v", r.Blocks[2].IOCR)
	}
	if ex := r.Blocks[3].Expected; r.Blocks[3].Type != ProfinetBlockExpectedSubmodule || ex == nil || len(ex.APIs) == 0 || len(ex.APIs[0].Submodules) == 0 {
		t.Errorf("ExpectedSubmoduleBlockReq: %+v", ex)
	}
	if acr := r.Blocks[4].AlarmCR; r.Blocks[4].Type != ProfinetBlockAlarmCRReq || acr == nil || acr.AlarmCRType != 1 || acr.LocalAlarmRef != 1 || acr.TagHeaderHigh != 0xC000 || acr.TagHeaderLow != 0xA000 {
		t.Errorf("AlarmCRBlockReq: %+v", acr)
	}

	// 47: connect response, big-endian: same UUIDs, same values.
	r = pnRPC(t, pkts[46])
	if r.PacketType != ProfinetRPCResponse || r.LittleEndian() || r.Interface() != ProfinetRPCInterfaceDevice || !r.Status.OK() || r.ArgsLength != 130 || len(r.Blocks) != 6 {
		t.Fatalf("connect response: %+v", r)
	}
	if ar := r.Blocks[0].AR; ar == nil || ar.ARType != 1 || ar.ARUUID.String() != arUUID || ar.SessionKey != 0x1122 || ar.MAC.String() != "00:1b:1b:00:00:02" || ar.UDPRTPort != 0x8892 {
		t.Errorf("ARBlockRes: %+v", ar)
	}
	if a, b := r.Blocks[1].IOCR, r.Blocks[2].IOCR; a == nil || b == nil || a.FrameID != 0x8001 || b.FrameID != 0x8000 || a.IOCRReference != 1 || b.IOCRType != 2 {
		t.Errorf("IOCRBlockRes: %+v %+v", a, b)
	}
	if acr := r.Blocks[3].AlarmCR; acr == nil || acr.LocalAlarmRef != 2 || acr.MaxAlarmDataLength != 200 {
		t.Errorf("AlarmCRBlockRes: %+v", acr)
	}
	md := r.Blocks[4].ModuleDiff
	if md == nil || len(md.APIs) != 1 || len(md.APIs[0].Modules) != 2 || md.APIs[0].Modules[0].State != 1 || len(md.APIs[0].Modules[0].Submodules) != 1 || len(md.APIs[0].Modules[1].Submodules) != 0 {
		t.Errorf("ModuleDiffBlock: %+v", md)
	}
	if as := r.Blocks[5].ARServer; as == nil || as.StationName != "device-1" {
		t.Errorf("ARServerBlockRes: %+v", as)
	}

	// 48, 49: write request with its record data, and the response.
	r = pnRPC(t, pkts[47])
	rec := r.Blocks[0].Record
	if r.Opnum != ProfinetRPCWrite || len(r.Blocks) != 1 || rec == nil || rec.SeqNumber != 5 || rec.Slot != 1 || rec.Subslot != 1 || rec.Index != 0x0100 || rec.RecordDataLength != 6 || !bytes.Equal(rec.Data, []byte{1, 2, 3, 4, 5, 6}) {
		t.Errorf("write request: %+v", rec)
	}
	rec = pnRPC(t, pkts[48]).Blocks[0].Record
	if rec == nil || rec.AddVal1 != 7 || rec.AddVal2 != 8 || !rec.Status.OK() || rec.Data != nil {
		t.Errorf("write response: %+v", rec)
	}

	// 50: multiple write: the outer header wraps two padded writes.
	r = pnRPC(t, pkts[49])
	if len(r.Blocks) != 3 || r.Blocks[0].Record.Index != 0xE040 || r.Blocks[0].Record.Data != nil {
		t.Fatalf("multiple write: %+v", r.Blocks)
	}
	if a, b := r.Blocks[1].Record, r.Blocks[2].Record; a.Index != 0x0101 || !bytes.Equal(a.Data, []byte{0xAA, 0xBB, 0xCC}) || b.Index != 0x0102 || !bytes.Equal(b.Data, []byte{1, 2, 3, 4, 5}) {
		t.Errorf("multiple write records: %+v %+v", a, b)
	}

	// 51, 52: read request; the response's record data is an I&M0 block.
	rec = pnRPC(t, pkts[50]).Blocks[0].Record
	if rec == nil || rec.Index != 0xAFF0 || rec.RecordDataLength != 4096 || rec.ARUUID.String() != arUUID {
		t.Errorf("read request: %+v", rec)
	}
	rec = pnRPC(t, pkts[51]).Blocks[0].Record
	if rec == nil || rec.RecordDataLength != 60 || len(rec.Data) != 60 {
		t.Fatalf("read response: %+v", rec)
	}
	inner, err := ProfinetDecodeBlocks(rec.Data)
	if err != nil || len(inner) != 1 || inner[0].Type != 0x0020 || inner[0].Length != 56 || inner[0].Type.String() != "I&M0" {
		t.Errorf("I&M0 block: %v %+v", err, inner)
	}

	// 53: failed read: status only, in the sender's byte order.
	r = pnRPC(t, pkts[52])
	if st := r.Status; st.ErrorCode != ProfinetErrorCodeRead || st.ErrorDecode != ProfinetErrorDecodePNIORW || st.ErrorCode1 != 0xB0 || st.ErrorCode2 != 0 || len(r.Blocks) != 0 {
		t.Errorf("failed read: %v %+v", st, r.Blocks)
	}

	// 54-60: control and release.
	for _, tc := range []struct {
		frame int
		typ   ProfinetBlockType
		cmd   ProfinetControlCommand
	}{
		{54, ProfinetBlockPrmEndReq, ProfinetControlPrmEnd},
		{55, ProfinetBlockPrmEndRes, ProfinetControlDone},
		{56, ProfinetBlockAppReadyReq, ProfinetControlApplicationReady},
		{57, ProfinetBlockPlugPrmEndReq, ProfinetControlPrmEnd},
		{58, ProfinetBlockReleaseReq, ProfinetControlRelease},
		{59, ProfinetBlockReleaseRes, ProfinetControlDone},
	} {
		r := pnRPC(t, pkts[tc.frame-1])
		if len(r.Blocks) != 1 || r.Blocks[0].Type != tc.typ || r.Blocks[0].Control == nil || r.Blocks[0].Control.Command != tc.cmd || r.Blocks[0].Control.ARUUID.String() != arUUID {
			t.Errorf("frame %d: %+v", tc.frame, r.Blocks)
		}
	}
	if r := pnRPC(t, pkts[55]); r.Interface() != ProfinetRPCInterfaceController {
		t.Errorf("application ready interface = %v", r.Interface())
	}

	// 61: implicit read names the AR in TargetARUUID.
	r = pnRPC(t, pkts[60])
	rec = r.Blocks[0].Record
	if r.Opnum != ProfinetRPCReadImplicit || rec == nil || !rec.ARUUID.IsZero() || rec.TargetARUUID.IsZero() || rec.Index != 0xF840 {
		t.Errorf("implicit read: %+v", rec)
	}

	// 62: an unknown block and a version 1.1 block keep header and body.
	r = pnRPC(t, pkts[61])
	if len(r.Blocks) != 2 || r.Blocks[0].Type != 0x7F00 || len(r.Blocks[0].Body) != 4 || r.Blocks[1].Type != ProfinetBlockAlarmCRReq || r.Blocks[1].VersionLow != 1 || r.Blocks[1].AlarmCR != nil || len(r.Blocks[1].Body) != 20 {
		t.Errorf("unknown blocks: %+v", r.Blocks)
	}

	// 63: fault; 64: ping without a body.
	r = pnRPC(t, pkts[62])
	if r.PacketType != ProfinetRPCFault || r.FaultStatus != 0x1C010003 || r.HasNDR || len(r.LayerPayload()) != 4 {
		t.Errorf("fault: %+v", r)
	}
	r = pnRPC(t, pkts[63])
	if r.PacketType != ProfinetRPCPing || r.HasNDR || len(r.LayerPayload()) != 0 || r.FragmentLength != 0 {
		t.Errorf("ping: %+v", r)
	}
}

// pnRPCHeader builds a little-endian DCE/RPC header for the PNIO device
// interface with the given packet type and body length.
func pnRPCHeader(ptype ProfinetRPCPacketType, bodyLen int) []byte {
	h := make([]byte, profinetRPCHeaderLen)
	h[0] = profinetRPCVersion
	h[1] = byte(ptype)
	h[4] = profinetRPCLittleEndian
	copy(h[profinetRPCIfaceOff:], []byte{0x01, 0x00, 0xA0, 0xDE, 0x97, 0x6C, 0xD1, 0x11, 0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D})
	binary.LittleEndian.PutUint16(h[profinetRPCFragLenOff:], uint16(bodyLen))
	return h
}

// pnBlock builds a version 1.0 block.
func pnBlock(typ ProfinetBlockType, body ...byte) []byte {
	b := make([]byte, profinetBlockHeaderLen, profinetBlockHeaderLen+len(body))
	binary.BigEndian.PutUint16(b, uint16(typ))
	binary.BigEndian.PutUint16(b[2:], uint16(len(body)+profinetBlockVersionLen))
	b[4] = 1
	return append(b, body...)
}

func TestProfinetRPCMalformed(t *testing.T) {
	rpc := &ProfinetIORPC{}

	// Not DCE/RPC version 4.
	bad := pnRPCHeader(ProfinetRPCRequest, 0)
	bad[0] = 5
	if err := rpc.DecodeFromBytes(bad, gopacket.NilDecodeFeedback); err != ErrProfinetRPCVersion {
		t.Errorf("version 5: %v", err)
	}
	if err := rpc.DecodeFromBytes(bad[:79], gopacket.NilDecodeFeedback); err != ErrProfinetRPCTooShort {
		t.Errorf("short header: %v", err)
	}

	// FragmentLength beyond the data: the body is what was captured.
	data := append(pnRPCHeader(ProfinetRPCRequest, 5000), make([]byte, profinetNDRHeaderLen)...)
	data = append(data, pnBlock(ProfinetBlockPrmEndReq, make([]byte, profinetControlLen)...)...)
	if err := rpc.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil || !rpc.HasNDR || len(rpc.Blocks) != 1 || rpc.Blocks[0].Control == nil {
		t.Errorf("fragment length lie: %v %+v", err, rpc)
	}

	// FragmentLength short of the data: the rest is not PNIO.
	binary.LittleEndian.PutUint16(data[profinetRPCFragLenOff:], profinetNDRHeaderLen)
	if err := rpc.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil || !rpc.HasNDR || len(rpc.Blocks) != 0 {
		t.Errorf("short fragment length: %v %+v", err, rpc)
	}

	// ArgsLength and the array counts are not trusted for anything.
	data = append(pnRPCHeader(ProfinetRPCRequest, profinetNDRHeaderLen), bytes.Repeat([]byte{0xFF}, profinetNDRHeaderLen)...)
	if err := rpc.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil || rpc.ArgsLength != 0xFFFFFFFF || rpc.ActualCount != 0xFFFFFFFF || len(rpc.Blocks) != 0 {
		t.Errorf("NDR length lies: %v %+v", err, rpc)
	}

	// A body too short for the NDR header stays payload.
	data = append(pnRPCHeader(ProfinetRPCRequest, 19), make([]byte, 19)...)
	if err := rpc.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil || rpc.HasNDR || len(rpc.LayerPayload()) != 19 {
		t.Errorf("short NDR: %v %+v", err, rpc)
	}

	// Fragments and foreign interfaces are left alone.
	data = append(pnRPCHeader(ProfinetRPCRequest, 40), make([]byte, 40)...)
	data[2] = ProfinetRPCFlagFragment
	if err := rpc.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil || rpc.HasNDR || !rpc.Fragmented() || len(rpc.LayerPayload()) != 40 {
		t.Errorf("fragment: %v %+v", err, rpc)
	}
	data[2] = 0
	data[profinetRPCIfaceOff] = 9
	if err := rpc.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil || rpc.HasNDR || rpc.Interface() != ProfinetRPCInterfaceOther {
		t.Errorf("foreign interface: %v %+v", err, rpc)
	}

	// A block length below the version bytes is an error, after the layer.
	withProfinet(t)
	body := append(make([]byte, profinetNDRHeaderLen), 0x01, 0x01, 0x00, 0x01, 0x01, 0x00)
	data = append(pnRPCHeader(ProfinetRPCRequest, len(body)), body...)
	p := gopacket.NewPacket(data, LayerTypeProfinetIORPC, gopacket.Default)
	if p.Layer(LayerTypeProfinetIORPC) == nil || p.ErrorLayer() == nil || p.ErrorLayer().Error() != ErrProfinetBlockLength {
		t.Errorf("bad block length: %v", p)
	}
}

func TestProfinetBlockMalformed(t *testing.T) {
	// A block cut by the capture is clipped, not refused.
	full := pnBlock(ProfinetBlockPrmEndReq, make([]byte, profinetControlLen)...)
	blocks, err := ProfinetDecodeBlocks(full[:20])
	if err != nil || len(blocks) != 1 || !blocks[0].Clipped() || blocks[0].Control != nil || len(blocks[0].Body) != 14 {
		t.Errorf("clipped: %v %+v", err, blocks)
	}

	// A header cut short is an error; the blocks before it are kept.
	blocks, err = ProfinetDecodeBlocks(append(full, 0x01, 0x10, 0x00))
	if err != ErrProfinetBlockTooShort || len(blocks) != 1 {
		t.Errorf("short header: %v %d", err, len(blocks))
	}

	// A zero block type ends the list.
	blocks, err = ProfinetDecodeBlocks(append(full, make([]byte, 12)...))
	if err != nil || len(blocks) != 1 {
		t.Errorf("zero type: %v %d", err, len(blocks))
	}

	// Counts that promise more elements than the body holds.
	iocr := make([]byte, profinetIOCRReqFixedLen)
	binary.BigEndian.PutUint16(iocr[38:], 0xFFFF)
	blocks, err = ProfinetDecodeBlocks(pnBlock(ProfinetBlockIOCRReq, iocr...))
	if err != nil || len(blocks) != 1 || blocks[0].IOCR == nil || len(blocks[0].IOCR.APIs) != 0 {
		t.Errorf("IOCR count lie: %v %+v", err, blocks)
	}

	exp := []byte{0xFF, 0xFF, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0xFF, 0xFF}
	blocks, err = ProfinetDecodeBlocks(pnBlock(ProfinetBlockExpectedSubmodule, exp...))
	if err != nil || len(blocks) != 1 || blocks[0].Expected == nil || len(blocks[0].Expected.APIs) > 1 {
		t.Errorf("expected submodule count lie: %v %+v", err, blocks)
	}

	diff := []byte{0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF}
	blocks, err = ProfinetDecodeBlocks(pnBlock(ProfinetBlockModuleDiff, diff...))
	if err != nil || len(blocks) != 1 || blocks[0].ModuleDiff == nil || len(blocks[0].ModuleDiff.APIs) > 1 {
		t.Errorf("module diff count lie: %v %+v", err, blocks)
	}

	// A station name length beyond the body.
	ar := make([]byte, profinetARReqFixedLen)
	binary.BigEndian.PutUint16(ar[50:], 0xFFFF)
	blocks, err = ProfinetDecodeBlocks(pnBlock(ProfinetBlockARReq, append(ar, "plc"...)...))
	if err != nil || len(blocks) != 1 || blocks[0].AR == nil || len(blocks[0].AR.StationName) > 3 {
		t.Errorf("station name lie: %v %+v", err, blocks)
	}

	// A record data length beyond the data takes what is there.
	rec := make([]byte, 60)
	binary.BigEndian.PutUint32(rec[profinetRecordLengthOff:], 0xFFFFFFFF)
	blocks, err = ProfinetDecodeBlocks(append(pnBlock(ProfinetBlockIODWriteReq, rec...), 1, 2, 3))
	if err != nil || len(blocks) != 1 || !bytes.Equal(blocks[0].Record.Data, []byte{1, 2, 3}) {
		t.Errorf("record length lie: %v %+v", err, blocks)
	}

	// An alarm block inside an alarm item is not followed.
	item := pnBlock(ProfinetBlockAlarmLow, make([]byte, profinetAlarmHeadLen)...)
	head := make([]byte, profinetAlarmHeadLen)
	body := append(head, 0x81, 0x00)
	body = append(body, item...)
	blocks, err = ProfinetDecodeBlocks(pnBlock(ProfinetBlockAlarmLow, body...))
	if err != nil || len(blocks) != 1 || blocks[0].Alarm == nil || len(blocks[0].Alarm.Items) != 1 {
		t.Fatalf("nested alarm: %v %+v", err, blocks)
	}
	if nb := blocks[0].Alarm.Items[0].Block; nb != nil && nb.Alarm != nil {
		t.Error("alarm block decoded inside an alarm item")
	}
}

func TestProfinetCyclicMalformed(t *testing.T) {
	trailer := []byte{0x12, 0x34, 0x35, 0x00}

	// decode returns the layer for an RT_CLASS_3 frame with the given IO
	// data, sent between two fixed stations.
	dst := net.HardwareAddr{0x01, 0x0e, 0xcf, 0, 0, 0}
	src := net.HardwareAddr{0, 0x1b, 0x1b, 0, 0, 1}
	decode := func(io []byte) *Profinet {
		pdu := append([]byte{0x01, 0x02}, io...)
		pn := &Profinet{}
		if err := pn.decode(append(pdu, trailer...), gopacket.NilDecodeFeedback, dst, src); err != nil {
			t.Fatal(err)
		}
		return pn
	}

	// One subframe, no CRCs, terminator.
	good := []byte{0, 0, 1, 2, 9, 0x35, 0xAA, 0xBB, 0, 0, 0, 0}
	if pn := decode(good); len(pn.Subframes) != 1 || !bytes.Equal(pn.Subframes[0].Data, []byte{0xAA, 0xBB}) {
		t.Fatalf("good DFP: %+v", pn)
	}

	for name, io := range map[string][]byte{
		"length beyond the data":   {0, 0, 1, 200, 9, 0x35, 0xAA, 0xBB, 0, 0, 0, 0},
		"no terminator":            {0, 0, 1, 2, 9, 0x35, 0xAA, 0xBB, 0, 0},
		"wrong header CRC":         {1, 0, 1, 2, 9, 0x35, 0xAA, 0xBB, 0, 0, 0, 0},
		"wrong subframe CRC":       {0, 0, 0x81, 2, 9, 0x35, 0xAA, 0xBB, 1, 0, 0, 0},
		"terminator comes first":   {0, 0, 0, 0, 9, 0x35, 0xAA, 0xBB, 0, 0, 0, 0},
		"too short for a subframe": {0, 0, 1, 2, 9},
	} {
		if pn := decode(io); pn.Subframes != nil || len(pn.IOData) != len(io) {
			t.Errorf("%s: %+v", name, pn)
		}
	}

	// A subframe CRC that is not checked (bit 7 clear) may be anything.
	if pn := decode([]byte{0, 0, 1, 2, 9, 0x35, 0xAA, 0xBB, 1, 0, 0, 0}); len(pn.Subframes) != 1 || pn.Subframes[0].CRC != 1 {
		t.Errorf("unchecked CRC: %+v", pn)
	}

	// SecurityMetaData is accepted only when SecurityLength fits the
	// frame exactly.
	secured := func(length uint16, counter uint32, info byte) *Profinet {
		pdu := []byte{0x80, 0x10, info, 0x03}
		pdu = binary.BigEndian.AppendUint32(pdu, counter)
		pdu = binary.BigEndian.AppendUint16(pdu, length)
		pdu = append(pdu, make([]byte, 8)...)
		pdu = append(pdu, trailer...)
		pdu = append(pdu, make([]byte, profinetSecurityChecksumLen)...)

		pn := &Profinet{}
		if err := pn.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		return pn
	}

	if pn := secured(12, 1, 0); pn.Security == nil || len(pn.IOData) != 8 || pn.CycleCounter != 0x1234 {
		t.Errorf("secured: %+v", pn)
	}
	if pn := secured(11, 1, 0); pn.Security != nil || len(pn.IOData) != 32 {
		t.Errorf("length too small: %+v", pn)
	}
	if pn := secured(13, 1, 0); pn.Security != nil {
		t.Errorf("length too large: %+v", pn)
	}
	if pn := secured(12, 0, 0); pn.Security != nil {
		t.Errorf("zero sequence counter: %+v", pn)
	}
	if pn := secured(12, 1, 2); pn.Security != nil {
		t.Errorf("reserved information bits: %+v", pn)
	}
	if pn := secured(12|0x0800, 1, 0); pn.Security != nil {
		t.Errorf("reserved length bits: %+v", pn)
	}
}

func TestProfinetSecAlarmBad(t *testing.T) {
	withProfinet(t)

	// alarm builds a secured low-priority alarm frame around an ACK-RTA.
	alarm := func(info byte, length uint16, tail int) gopacket.Packet {
		pdu := []byte{0xFE, 0x41, info, 0x01, 0, 0, 0, 9}
		pdu = binary.BigEndian.AppendUint16(pdu, length)
		pdu = append(pdu, 0, 1, 0, 2, 0x13, 0x11, 0, 1, 0, 2, 0, 0)
		pdu = append(pdu, make([]byte, tail)...)
		return gopacket.NewPacket(pnFrame(pdu...), LinkTypeEthernet, gopacket.Default)
	}

	// Authentication only: the alarm is in clear, the checksum follows.
	p := alarm(0, 12, 16)
	pn := p.Layer(LayerTypeProfinet).(*Profinet)
	a, ok := p.Layer(LayerTypeProfinetAlarm).(*ProfinetAlarm)
	if !ok || a.PDUType != ProfinetAlarmACK || pn.Security == nil || len(pn.Security.Checksum) != 16 || p.ErrorLayer() != nil {
		t.Errorf("auth only: %v", p)
	}

	// Encrypted: the alarm cannot be read and stays payload.
	p = alarm(1, 12, 16)
	pn = p.Layer(LayerTypeProfinet).(*Profinet)
	if p.Layer(LayerTypeProfinetAlarm) != nil || !pn.Security.Encrypted() || len(pn.LayerPayload()) != 12 || p.ErrorLayer() != nil {
		t.Errorf("encrypted: %v", p)
	}

	// SecurityLength beyond the frame: truncated, no checksum.
	p = alarm(0, 2000, 0)
	pn = p.Layer(LayerTypeProfinet).(*Profinet)
	if !p.Metadata().Truncated || pn.Security.Checksum != nil || len(pn.LayerPayload()) != 12 {
		t.Errorf("length lie: %v", p)
	}

	// The checksum cut short is not reported as one.
	p = alarm(0, 12, 5)
	pn = p.Layer(LayerTypeProfinet).(*Profinet)
	if pn.Security.Checksum != nil || !p.Metadata().Truncated {
		t.Errorf("short checksum: %v", p)
	}
}

func TestProfinetFragAssembler(t *testing.T) {
	src := net.HardwareAddr{0, 0x1b, 0x1b, 0, 0, 1}
	dst := net.HardwareAddr{0, 0x1b, 0x1b, 0, 0, 2}

	// frag builds fragment number n of fragment ID id with size bytes.
	frag := func(id, n uint8, more ProfinetFragStatus, size int) *Profinet {
		pdu := append([]byte{0xFF, 0x80 | id, uint8(size / profinetFragUnit), uint8(more) | n}, bytes.Repeat([]byte{n + 1}, size)...)
		pn := &Profinet{}
		if err := pn.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		return pn
	}

	asm := NewProfinetFragAssembler(32)
	if asm.MaxSize != 32 || NewProfinetFragAssembler(0).MaxSize != profinetFragDefaultMax {
		t.Fatal("wrong size cap")
	}

	// Two streams interleaved; each completes on its own.
	if out, err := asm.Add(src, dst, frag(1, 0, ProfinetFragMoreFollows, 8)); out != nil || err != nil {
		t.Fatalf("first: %v %v", out, err)
	}
	if out, err := asm.Add(src, dst, frag(2, 0, ProfinetFragMoreFollows, 8)); out != nil || err != nil {
		t.Fatalf("other stream: %v %v", out, err)
	}
	out, err := asm.Add(src, dst, frag(1, 1, 0, 8))
	if err != nil || !bytes.Equal(out, append(bytes.Repeat([]byte{1}, 8), bytes.Repeat([]byte{2}, 8)...)) {
		t.Fatalf("reassembled: %v %v", out, err)
	}
	if asm.Pending() != 1 {
		t.Errorf("pending = %d, want 1", asm.Pending())
	}

	// The same fragment ID in the other direction is another stream.
	if _, err := asm.Add(dst, src, frag(2, 1, 0, 8)); err != ErrProfinetFragOrder {
		t.Errorf("other direction: %v", err)
	}

	// A gap drops the reassembly.
	if _, err := asm.Add(src, dst, frag(2, 2, 0, 8)); err != ErrProfinetFragOrder || asm.Pending() != 0 {
		t.Errorf("gap: %v, pending %d", err, asm.Pending())
	}

	// A continuation with nothing started.
	if _, err := asm.Add(src, dst, frag(3, 1, 0, 8)); err != ErrProfinetFragOrder {
		t.Errorf("no start: %v", err)
	}

	// The size cap: 32 bytes fit, the 33rd does not.
	for n := uint8(0); n < 4; n++ {
		if _, err := asm.Add(src, dst, frag(4, n, ProfinetFragMoreFollows, 8)); err != nil {
			t.Fatalf("fragment %d: %v", n, err)
		}
	}
	if _, err := asm.Add(src, dst, frag(4, 4, 0, 8)); err != ErrProfinetFragTooBig || asm.Pending() != 0 {
		t.Errorf("size cap: %v, pending %d", err, asm.Pending())
	}

	// FragDataLength beyond the fragment.
	short := frag(5, 0, 0, 8)
	short.FragDataLength = 2
	if _, err := asm.Add(src, dst, short); err != ErrProfinetFragShort {
		t.Errorf("short: %v", err)
	}

	// A single-fragment frame.
	if out, err := asm.Add(src, dst, frag(6, 0, 0, 8)); err != nil || len(out) != 8 {
		t.Errorf("single: %v %v", out, err)
	}

	// Anything else is refused.
	if _, err := asm.Add(src, dst, &Profinet{FrameID: ProfinetFrameIDAlarmLow}); err != ErrProfinetNotFragment {
		t.Errorf("not a fragment: %v", err)
	}

	// The zero value works too.
	var zero ProfinetFragAssembler
	if out, err := zero.Add(src, dst, frag(1, 0, 0, 8)); err != nil || len(out) != 8 || zero.MaxSize != profinetFragDefaultMax {
		t.Errorf("zero value: %v %v", out, err)
	}
}

// Reassemblies that never complete must not pile up: memory stays within
// 64 reassemblies of MaxSize bytes, whatever arrives.
func TestProfinetFragAsmBound(t *testing.T) {
	const maxSize = 256

	asm := NewProfinetFragAssembler(maxSize)
	dst := net.HardwareAddr{0, 0x1b, 0x1b, 0, 0, 2}
	pdu := append([]byte{0xFF, 0x80, 8, 0x80}, make([]byte, 64)...)

	for i := 0; i < 5000; i++ {
		src := net.HardwareAddr{2, 0, 0, 0, byte(i >> 8), byte(i)}
		pdu[1] = 0x80 | byte(i%16)

		pn := &Profinet{}
		if err := pn.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		if _, err := asm.Add(src, dst, pn); err != nil {
			t.Fatal(err)
		}
		if asm.Pending() > profinetFragMaxReassembly {
			t.Fatalf("%d reassemblies pending after %d fragments", asm.Pending(), i+1)
		}
	}

	// The newest stream survived eviction; the oldest did not.
	held := 0
	for _, st := range asm.states {
		held += len(st.data)
	}
	if asm.Pending() != profinetFragMaxReassembly || held > profinetFragMaxReassembly*maxSize {
		t.Errorf("pending %d, %d bytes held", asm.Pending(), held)
	}
	if _, ok := asm.states[profinetFragKey{src: [6]byte{2, 0, 0, 0, 0, 0}, dst: [6]byte{0, 0x1b, 0x1b, 0, 0, 2}}]; ok {
		t.Error("oldest reassembly not evicted")
	}
}

// Lists sized by the packet are counted before they are allocated: a
// packet of minimal elements costs about the element structs, not twice
// that from append growing the list.
func TestProfinetAllocBounds(t *testing.T) {
	const maxPerByte = 64

	// 10000 empty blocks of an unknown type, 6 bytes each.
	blocks := bytes.Repeat([]byte{0x7F, 0x00, 0x00, 0x02, 0x01, 0x00}, 10000)

	// Empty blocks of every typed kind: the typed structs must not be
	// allocated for bodies too short to hold them.
	var typed []byte
	for i := 0; i < 2000; i++ {
		for _, typ := range []ProfinetBlockType{ProfinetBlockAlarmLow, ProfinetBlockARReq, ProfinetBlockIOCRReq, ProfinetBlockExpectedSubmodule, ProfinetBlockModuleDiff, ProfinetBlockIODWriteReq} {
			typed = append(typed, pnBlock(typ)...)
		}
	}

	// One alarm notification full of 2-byte manufacturer structures is one
	// item; full of channel diagnoses it is one item per 8 bytes.
	alarm := make([]byte, profinetAlarmHeadLen, 60000)
	for len(alarm) < 59990 {
		alarm = append(alarm, 0x80, 0x00, 0, 1, 0x28, 0x04, 0, 6)
	}
	alarm = pnBlock(ProfinetBlockAlarmLow, alarm...)

	// An IOCR whose single API claims 65535 objects of 6 bytes each.
	iocr := make([]byte, profinetIOCRReqFixedLen, 60000)
	binary.BigEndian.PutUint16(iocr[38:], 1)
	iocr = append(iocr, 0, 0, 0, 0, 0xFF, 0xFF)
	iocr = append(iocr, make([]byte, 59000)...)
	iocr = pnBlock(ProfinetBlockIOCRReq, iocr...)

	// Expected submodules: one API per 14 bytes.
	exp := append([]byte{0xFF, 0xFF}, make([]byte, 59000)...)
	exp = pnBlock(ProfinetBlockExpectedSubmodule, exp...)

	// Module diff: 0xFFFF APIs, each claiming 0xFFFF modules.
	diff := append([]byte{0xFF, 0xFF}, bytes.Repeat([]byte{0, 0, 0, 0, 0xFF, 0xFF}, 9000)...)
	diff = pnBlock(ProfinetBlockModuleDiff, diff...)

	for name, data := range map[string][]byte{
		"empty blocks": blocks, "empty typed blocks": typed, "alarm items": alarm,
		"IO objects": iocr, "expected submodules": exp, "module diff": diff,
	} {
		got := allocPerByte(len(data), func() {
			_, _ = ProfinetDecodeBlocks(data)
		})
		t.Logf("PROFINET %s: %.0f bytes per input byte", name, got)
		if got > maxPerByte {
			t.Errorf("%s: %.0f bytes per input byte, want <= %d", name, got, maxPerByte)
		}
	}

	// DFP: one 40-byte subframe struct per 6 input bytes at most.
	dfp := []byte{0x01, 0x02, 0, 0}
	for i := 0; i < 5000; i++ {
		dfp = append(dfp, 1, 1, 0, 0, 0xAA, 0, 0)
	}
	dfp = append(dfp, 0, 0, 0, 0, 0, 0)
	got := allocPerByte(len(dfp), func() {
		pn := &Profinet{}
		_ = pn.DecodeFromBytes(dfp, gopacket.NilDecodeFeedback)
	})
	t.Logf("PROFINET DFP: %.0f bytes per input byte", got)
	if got > maxPerByte {
		t.Errorf("DFP: %.0f bytes per input byte, want <= %d", got, maxPerByte)
	}
}

// TestProfinetExtraTruncation decodes every prefix of the RPC bodies and
// of the alarm blocks directly; the frame-level sweep is in
// TestProfinetTruncation.
func TestProfinetExtraTruncation(t *testing.T) {
	withProfinet(t)

	for _, frame := range readPNECATPcap(t, pnExtraPcap) {
		p := gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)

		var body []byte
		if r, ok := p.Layer(LayerTypeProfinetIORPC).(*ProfinetIORPC); ok {
			body = r.LayerContents()
		}
		if a, ok := p.Layer(LayerTypeProfinetAlarm).(*ProfinetAlarm); ok {
			body = a.LayerPayload()
		}

		for n := 0; n <= len(body); n++ {
			data := append([]byte(nil), body[:n]...)
			_ = (&ProfinetIORPC{}).DecodeFromBytes(data, gopacket.NilDecodeFeedback)

			blocks, err := ProfinetDecodeBlocks(data)
			if err == nil && len(blocks) != countProfinetBlocks(data) {
				t.Fatalf("counted %d blocks, decoded %d", countProfinetBlocks(data), len(blocks))
			}
		}
	}
}
