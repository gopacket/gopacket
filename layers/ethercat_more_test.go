// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// ecatRead and ecatWrite build a register access of the test slave: a
// read answered by it, and a write on its way out.
func ecatRead(reg ESCRegister, data ...byte) []byte {
	return ecatDgramFrame(EtherCATCommandFPRD, ecatAsmStation, uint16(reg), 1, data)
}

func ecatWrite(reg ESCRegister, data ...byte) []byte {
	return ecatDgramFrame(EtherCATCommandFPWR, ecatAsmStation, uint16(reg), 0, data)
}

// Frame numbers of ecatRegFrames, 0-based.
const (
	ecatRegALCode = iota
	ecatRegWDDivider
	ecatRegWDTimes
	ecatRegWDStatus
	ecatRegEEWrite
	ecatRegEEBusy
	ecatRegEEData8
	ecatRegEEData4
	ecatRegMII
	ecatRegDCActivation
	ecatRegDCStart
	ecatRegDCCycle
	ecatRegDCLatchCtrl
	ecatRegDCLatchStatus
	ecatRegDCLatchTimes
	ecatRegSpecific
	ecatRegGPIO
)

// ecatRegFrames holds one hand-built access per typed register. tshark
// 4.7 decodes all of them but the last two; the values were compared
// with its ecat.reg.* fields.
func ecatRegFrames() [][]byte {
	latch := make([]byte, 32)
	for i := range latch {
		latch[i] = byte(i + 1)
	}

	return [][]byte{
		ecatRead(ESCRegisterALStatus, 0x14, 0, 0, 0, 0x1b, 0),
		ecatRead(ESCRegisterWDDivider, 0xc2, 0x09),
		ecatWrite(ESCRegisterWDTimePDI, 0xe8, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0),
		ecatRead(ESCRegisterWDStatus, 0x01, 0),
		// Read command for word address 8, 8-byte reads, write enabled.
		ecatWrite(ESCRegisterEEPROMControl, 0x41, 0x01, 0x08, 0, 0, 0),
		// Busy with a checksum and an acknowledge error; low word only.
		ecatRead(ESCRegisterEEPROMControl, 0xa0, 0xa8, 0x08, 0),
		ecatRead(ESCRegisterEEPROMData0, 0x02, 0x00, 0x00, 0x00, 0x52, 0x2c, 0x04, 0x04),
		ecatRead(ESCRegisterEEPROMData0, 0x11, 0x22, 0x33, 0x44),
		// Write of 0x1200 to register 4 of PHY 3; PHY offset 2.
		ecatWrite(ESCRegisterMIIControl, 0x15, 0x02, 0x03, 0x04, 0x00, 0x12),
		ecatWrite(ESCRegisterDCCyclicControl, 0x00, 0x07),
		ecatWrite(ESCRegisterDCStartTime0, 0x00, 0xe4, 0x0b, 0x54, 0x02, 0, 0, 0),
		ecatWrite(ESCRegisterDCCycleTime0, 0x40, 0x42, 0x0f, 0x00, 0x20, 0xa1, 0x07, 0x00),
		ecatRead(ESCRegisterDCLatch0Control, 0x01, 0x02),
		ecatRead(ESCRegisterDCLatch0Status, 0x05, 0x02),
		ecatRead(ESCRegisterDCLatch0Pos, latch...),
		ecatRead(ESCRegisterProductID, 0x00, 0x11, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0),
		ecatRead(ESCRegisterGPOutput, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0),
	}
}

// ecatRegDatagrams decodes ecatRegFrames to their datagram.
func ecatRegDatagrams(t *testing.T) []*EtherCATDatagram {
	t.Helper()
	withEtherCAT(t)

	var out []*EtherCATDatagram
	for i, frame := range ecatRegFrames() {
		p := gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)
		e, ok := p.Layer(LayerTypeEtherCAT).(*EtherCAT)
		if !ok || len(e.Datagrams) != 1 || p.ErrorLayer() != nil {
			t.Fatalf("frame %d: %v", i+1, p)
		}
		out = append(out, &e.Datagrams[0])
	}
	return out
}

func TestESCALStatusCode(t *testing.T) {
	d := ecatRegDatagrams(t)

	code, ok := d[ecatRegALCode].ALStatusCode()
	if !ok || code != ESCALSyncManagerWatchdog || code.String() != "Sync manager watchdog" {
		t.Errorf("AL status code: %v %v", code, ok)
	}
	if _, ok = d[ecatRegWDDivider].ALStatusCode(); ok {
		t.Error("AL status code from a watchdog access")
	}

	names := map[ESCALStatusCode]string{
		ESCALNoError:            "No error",
		ESCALInvalidStateChange: "Invalid requested state change",
		ESCALMailboxConfigPreOp: "Invalid mailbox configuration (pre-operational)",
		ESCALDCSync1CycleTime:   "DC Sync1 cycle time",
		ESCALMailboxVoE:         "Mailbox VoE",
		ESCALAppControllerReady: "Application controller available",
		0x0005:                  "Unknown(0x0005)",
		0x8001:                  "Vendor specific(0x8001)",
	}
	for code, want := range names {
		if got := code.String(); got != want {
			t.Errorf("code %#x: %q, want %q", uint16(code), got, want)
		}
	}

	for i := 1; i < len(escALStatusNames); i++ {
		if escALStatusNames[i].code <= escALStatusNames[i-1].code {
			t.Errorf("AL status table not sorted at %#x", uint16(escALStatusNames[i].code))
		}
	}
}

func TestESCWatchdog(t *testing.T) {
	d := ecatRegDatagrams(t)

	div, ok := d[ecatRegWDDivider].WatchdogDivider()
	if !ok || div != 2498 || div.Period() != 100*time.Microsecond {
		t.Errorf("divider: %d %v %v", div, div.Period(), ok)
	}

	// One write covers both watchdog times.
	pdi, okPDI := d[ecatRegWDTimes].WatchdogTimePDI()
	sm, okSM := d[ecatRegWDTimes].WatchdogTimeSM()
	if !okPDI || !okSM || pdi != 1000 || sm != 100 {
		t.Errorf("times: PDI %d %v, SM %d %v", pdi, okPDI, sm, okSM)
	}

	st, ok := d[ecatRegWDStatus].WatchdogStatus()
	if !ok || !st.Running() || ESCWatchdogStatus(0).Running() {
		t.Errorf("status: %v %v", st, ok)
	}
}

func TestESCEEPROM(t *testing.T) {
	d := ecatRegDatagrams(t)

	c, ok := d[ecatRegEEWrite].EEPROMControl()
	if !ok || !c.WriteEnable() || c.Emulated() || c.ReadSize() != 8 || c.TwoAddressBytes() ||
		c.Command() != ESCEEPROMRead || c.Busy() || c.ChecksumError() || c.Command().String() != "Read" {
		t.Errorf("control write: %#x %v", uint16(c), ok)
	}
	if addr, ok := d[ecatRegEEWrite].EEPROMAddress(); !ok || addr != 8 {
		t.Errorf("address: %d %v", addr, ok)
	}

	c, ok = d[ecatRegEEBusy].EEPROMControl()
	if !ok || c.WriteEnable() || !c.Emulated() || c.ReadSize() != 4 || !c.TwoAddressBytes() ||
		c.Command() != ESCEEPROMNop || !c.Busy() || !c.ChecksumError() || c.LoadError() || !c.AckError() || c.WriteError() {
		t.Errorf("control read: %#x %v", uint16(c), ok)
	}
	if addr, ok := d[ecatRegEEBusy].EEPROMAddress(); !ok || addr != 8 {
		t.Errorf("low address word: %d %v", addr, ok)
	}

	if b := d[ecatRegEEData8].EEPROMData(); !bytes.Equal(b, []byte{2, 0, 0, 0, 0x52, 0x2c, 4, 4}) {
		t.Errorf("8 data bytes: %x", b)
	}
	if b := d[ecatRegEEData4].EEPROMData(); !bytes.Equal(b, []byte{0x11, 0x22, 0x33, 0x44}) {
		t.Errorf("4 data bytes: %x", b)
	}
	if b := d[ecatRegEEBusy].EEPROMData(); b != nil {
		t.Errorf("data from a control read: %x", b)
	}

	for cmd, want := range map[ESCEEPROMCommand]string{
		ESCEEPROMNop: "No command", ESCEEPROMWrite: "Write", ESCEEPROMReload: "Reload", 3: "Unknown(3)",
	} {
		if cmd.String() != want {
			t.Errorf("command %d: %q", cmd, cmd.String())
		}
	}
}

func TestESCMII(t *testing.T) {
	d := ecatRegDatagrams(t)

	m, ok := d[ecatRegMII].MII()
	c := m.Control
	if !ok || m.PHYAddress != 3 || m.PHYRegister != 4 || m.Data != 0x1200 || !c.WriteEnable() || c.PDIControl() ||
		!c.LinkDetection() || c.PHYOffset() != 2 || c.Command() != ESCMIIWrite || c.Busy() || c.ReadError() || c.CommandError() {
		t.Errorf("MII: %+v %v", m, ok)
	}
	if only, ok := d[ecatRegMII].MIIControl(); !ok || only != c {
		t.Errorf("MII control: %#x %v", uint16(only), ok)
	}
	if _, ok = d[ecatRegEEBusy].MII(); ok {
		t.Error("MII from an EEPROM access")
	}

	for cmd, want := range map[ESCMIICommand]string{
		ESCMIINop: "No command", ESCMIIRead: "Read", ESCMIIWrite: "Write", 3: "Unknown(3)",
	} {
		if cmd.String() != want {
			t.Errorf("command %d: %q", cmd, cmd.String())
		}
	}
}

func TestESCDCSyncLatch(t *testing.T) {
	d := ecatRegDatagrams(t)

	act, ok := d[ecatRegDCActivation].DCActivation()
	if !ok || !act.CyclicOperation() || !act.Sync0() || !act.Sync1() || ESCDCActivation(1).Sync0() {
		t.Errorf("activation: %#x %v", uint8(act), ok)
	}

	start, ok := d[ecatRegDCStart].DCStartTime()
	if !ok || start != 10000000000 || !ESCDCTime(start).Equal(time.Date(2000, 1, 1, 0, 0, 10, 0, time.UTC)) {
		t.Errorf("start time: %d %v", start, ok)
	}

	c0, ok0 := d[ecatRegDCCycle].DCCycleTime(0)
	c1, ok1 := d[ecatRegDCCycle].DCCycleTime(1)
	if !ok0 || !ok1 || c0 != time.Millisecond || c1 != 500*time.Microsecond {
		t.Errorf("cycle times: %v %v, %v %v", c0, ok0, c1, ok1)
	}

	l0, ok0 := d[ecatRegDCLatchCtrl].DCLatchControl(0)
	l1, ok1 := d[ecatRegDCLatchCtrl].DCLatchControl(1)
	if !ok0 || !ok1 || !l0.PositiveSingle() || l0.NegativeSingle() || l1.PositiveSingle() || !l1.NegativeSingle() {
		t.Errorf("latch control: %#x %v, %#x %v", uint8(l0), ok0, uint8(l1), ok1)
	}

	s0, ok0 := d[ecatRegDCLatchStatus].DCLatchStatus(0)
	s1, ok1 := d[ecatRegDCLatchStatus].DCLatchStatus(1)
	if !ok0 || !ok1 || !s0.PositiveEvent() || s0.NegativeEvent() || !s0.PinState() ||
		s1.PositiveEvent() || !s1.NegativeEvent() || s1.PinState() {
		t.Errorf("latch status: %#x %v, %#x %v", uint8(s0), ok0, uint8(s1), ok1)
	}

	// Four 64-bit times: latch 0 and 1, positive then negative edge.
	want := uint64(0x0807060504030201)
	for n := 0; n < escDCUnitCount; n++ {
		for _, edge := range []ESCDCEdge{ESCDCEdgePositive, ESCDCEdgeNegative} {
			got, ok := d[ecatRegDCLatchTimes].DCLatchTime(n, edge)
			if !ok || got != want {
				t.Errorf("latch %d edge %d: %#x %v, want %#x", n, edge, got, ok, want)
			}
			want += 0x0808080808080808
		}
	}

	// Units and edges that do not exist.
	dg := d[ecatRegDCLatchTimes]
	for _, n := range []int{-1, escDCUnitCount} {
		_, okC := dg.DCCycleTime(n)
		_, okL := dg.DCLatchControl(n)
		_, okS := dg.DCLatchStatus(n)
		_, okT := dg.DCLatchTime(n, ESCDCEdgePositive)
		if okC || okL || okS || okT {
			t.Errorf("unit %d exists", n)
		}
	}
	if _, ok := dg.DCLatchTime(0, ESCDCEdgeNegative+1); ok {
		t.Error("third edge exists")
	}
}

func TestESCHighRegisters(t *testing.T) {
	d := ecatRegDatagrams(t)

	regs := d[ecatRegSpecific].Registers()
	if len(regs) != 2 || regs[0].Register != ESCRegisterProductID || regs[0].Uint() != 0x1100 ||
		regs[1].Register != ESCRegisterVendorID || regs[1].Uint() != 2 {
		t.Errorf("ESC specific: %+v", regs)
	}

	regs = d[ecatRegGPIO].Registers()
	if len(regs) != 2 || regs[0].Register.String() != "General Purpose Outputs" || regs[1].Register.String() != "General Purpose Inputs" ||
		regs[1].Uint() != 2 {
		t.Errorf("general purpose I/O: %+v", regs)
	}

	// User RAM is one 128-byte block.
	ram := EtherCATDatagram{Command: EtherCATCommandFPWR, Address: uint32(ESCRegisterUserRAM) << ethercatAddressHalfShift, Data: make([]byte, escUserRAMLen)}
	regs = ram.Registers()
	if len(regs) != 1 || regs[0].Register.String() != "User RAM" || len(regs[0].Data) != escUserRAMLen || regs[0].Uint() != 0 {
		t.Errorf("user RAM: %+v", regs)
	}

	areas := map[ESCRegister]ESCArea{
		0x0000: ESCAreaInformation, 0x0012: ESCAreaStation, 0x0040: ESCAreaProtection, 0x0060: ESCAreaReserved,
		0x0110: ESCAreaDataLink, 0x0134: ESCAreaApplication, 0x0220: ESCAreaInterrupt, 0x0300: ESCAreaErrorCounter,
		0x0440: ESCAreaWatchdog, 0x0502: ESCAreaEEPROM, 0x0514: ESCAreaMII, 0x06f0: ESCAreaFMMU,
		0x0838: ESCAreaSyncManager, 0x09a0: ESCAreaDC, 0x0a00: ESCAreaReserved, 0x0e10: ESCAreaSpecific,
		0x0f18: ESCAreaDigitalIO, 0x0fa4: ESCAreaUserRAM, 0x0fff: ESCAreaUserRAM, 0x1000: ESCAreaMemory, 0xffff: ESCAreaMemory,
	}
	for reg, want := range areas {
		if got := reg.Area(); got != want {
			t.Errorf("area of %#x: %v, want %v", uint16(reg), got, want)
		}
	}
	if ESCAreaSpecific.String() != "ESC specific" || ESCAreaUserRAM.String() != "User RAM" || ESCArea(200).String() != "Unknown(200)" {
		t.Errorf("area names: %v, %v, %v", ESCAreaSpecific, ESCAreaUserRAM, ESCArea(200))
	}

	for i := 1; i < len(escAreas); i++ {
		if escAreas[i].start <= escAreas[i-1].start {
			t.Errorf("area table not sorted at %#x", uint16(escAreas[i].start))
		}
	}
}

// TestESCRegsTruncation shortens every register access byte by byte: an
// accessor answers only while its whole register is there.
func TestESCRegsTruncation(t *testing.T) {
	for i, d := range ecatRegDatagrams(t) {
		full := len(d.Registers())
		for n := len(d.Data); n >= 0; n-- {
			short := *d
			short.Data = d.Data[:n]
			ecatTouch(&EtherCAT{Datagrams: []EtherCATDatagram{short}})

			if got := len(short.Registers()); got > full {
				t.Errorf("frame %d cut to %d bytes: %d registers, %d in full", i+1, n, got, full)
			}
		}

		// A read nobody answered holds no register values.
		unanswered := *d
		unanswered.Command, unanswered.WorkingCounter = EtherCATCommandFPRD, 0
		if _, ok := unanswered.ALStatusCode(); ok {
			t.Errorf("frame %d: AL status code from an unanswered read", i+1)
		}
		if unanswered.EEPROMData() != nil || unanswered.Registers() != nil {
			t.Errorf("frame %d: registers from an unanswered read", i+1)
		}
	}
}

// Frame numbers of ecatMbxFrames, 0-based.
const (
	ecatMbxError = iota
	ecatMbxGetIPReq
	ecatMbxGetIPRes
	ecatMbxGetIPFail
	ecatMbxGetFilterReq
	ecatMbxGetFilterRes
)

// ecatMbxFrames holds an error reply and the EoE get services. The
// error reply has the bytes of the replies in the public capture
// ethercat_example.pcap of github.com/cisagov/icsnpp-ethercat (frame
// 13801). tshark 4.7 decodes none of these bodies.
func ecatMbxFrames() [][]byte {
	ip := []byte{
		0x3f, 0, 0, 0, // MAC, IP, subnet mask, gateway, DNS server, DNS name
		0x00, 0x01, 0x05, 0x4c, 0xb8, 0xaf,
		10, 1, 168, 192, 0, 255, 255, 255, 1, 1, 168, 192, 8, 8, 8, 8,
	}
	ip = append(ip, append([]byte("ek1100"), make([]byte, ethercatEoEDNSNameLen-6)...)...)

	filter := make([]byte, ethercatEoEFilterLen)
	filter[0] = 0x92 // 2 filters, 1 mask, no broadcasts
	copy(filter[2:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	copy(filter[2+ethercatEoEMaxFilters*ethercatMACLen:], []byte{0xff, 0xff, 0xff, 0, 0, 0})

	return [][]byte{
		ecatFromSlave(EtherCATMailboxERR, 0x01, 0x00, 0x02, 0x00),
		ecatToSlave(EtherCATMailboxEoE, byte(EtherCATEoEGetIPRequest), 0, 0, 0),
		ecatFromSlave(EtherCATMailboxEoE, append([]byte{byte(EtherCATEoEGetIPResponse), 0, 0, 0}, ip...)...),
		ecatFromSlave(EtherCATMailboxEoE, byte(EtherCATEoEGetIPResponse), 0, 0x01, 0x02),
		ecatToSlave(EtherCATMailboxEoE, byte(EtherCATEoEGetFilterRequest), 0, 0, 0),
		ecatFromSlave(EtherCATMailboxEoE, append([]byte{byte(EtherCATEoEGetFilterReply), 0, 0, 0}, filter...)...),
	}
}

// ecatMbxOf decodes hand-built frames to the mailbox of their datagram.
func ecatMbxOf(t *testing.T, frames [][]byte) []*EtherCATMailbox {
	t.Helper()
	withEtherCAT(t)

	var out []*EtherCATMailbox
	for i, frame := range frames {
		p := gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)
		e, ok := p.Layer(LayerTypeEtherCAT).(*EtherCAT)
		if !ok || len(e.Datagrams) != 1 || e.Datagrams[0].Mailbox == nil {
			t.Fatalf("frame %d: no mailbox", i+1)
		}
		out = append(out, e.Datagrams[0].Mailbox)
	}
	return out
}

func TestEtherCATMailboxError(t *testing.T) {
	m := ecatMbxOf(t, ecatMbxFrames())[ecatMbxError]
	if m.Type != EtherCATMailboxERR || m.Error == nil || m.Error.Type != EtherCATMailboxErrCommand ||
		m.Error.Detail != EtherCATMailboxErrProtocol || m.Error.Detail.String() != "Unsupported protocol" {
		t.Errorf("error reply: %+v", m.Error)
	}

	names := []string{"Unknown(0x0000)", "Syntax error in mailbox header", "Unsupported protocol", "Invalid channel",
		"Service not supported", "Invalid protocol header", "Mailbox too short", "No more memory", "Invalid size",
		"Service in work", "Unknown(0x000a)"}
	for detail, want := range names {
		if got := EtherCATMailboxErrDetail(detail).String(); got != want {
			t.Errorf("detail %d: %q, want %q", detail, got, want)
		}
	}

	// Memory that only looks a little like an error reply is left alone:
	// zeros, a wrong length, another reply type, an undefined detail and
	// a reply cut short.
	not := [][]byte{
		make([]byte, 16),
		{5, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0},
		{4, 0, 0, 0, 0, 0, 2, 0, 2, 0},
		{4, 0, 0, 0, 0, 0, 1, 0, 10, 0},
		{4, 0, 0, 0, 0, 0, 1, 0, 0, 0},
		{4, 0, 0, 0, 0, 0, 1, 0, 2},
	}
	for i, data := range not {
		d := EtherCATDatagram{Command: EtherCATCommandFPRD, Address: ecatAsmInADO << ethercatAddressHalfShift, WorkingCounter: 1, Data: data}
		if got := findMailbox(&d); got != nil {
			t.Errorf("case %d taken for a mailbox: %+v", i, got)
		}
	}

	// The direct decoder takes any type 0 mailbox; a short body stays raw.
	got, err := DecodeEtherCATMailbox([]byte{3, 0, 0, 0, 0, 0, 1, 0, 2})
	if err != nil || got.Error != nil || len(got.Data) != 3 {
		t.Errorf("short error body: %+v %v", got, err)
	}
}

func TestEtherCATEoEGet(t *testing.T) {
	m := ecatMbxOf(t, ecatMbxFrames())

	req := m[ecatMbxGetIPReq].EoE
	if req.Type != EtherCATEoEGetIPRequest || req.SetIP != nil || req.Type.String() != "Get IP Req" {
		t.Errorf("get IP request: %+v", req)
	}

	res := m[ecatMbxGetIPRes].EoE
	if res.Type != EtherCATEoEGetIPResponse || res.Result != EtherCATEoESuccess || res.SetIP == nil {
		t.Fatalf("get IP response: %+v", res)
	}
	ip := res.SetIP
	if ip.MAC.String() != "00:01:05:4c:b8:af" || !ip.IP.Equal(net.IPv4(192, 168, 1, 10)) || !ip.SubnetMask.Equal(net.IPv4(255, 255, 255, 0)) ||
		!ip.Gateway.Equal(net.IPv4(192, 168, 1, 1)) || !ip.DNSServer.Equal(net.IPv4(8, 8, 8, 8)) || string(ip.DNSName) != "ek1100" || ip.Packed {
		t.Errorf("get IP parameters: %+v", ip)
	}

	fail := m[ecatMbxGetIPFail].EoE
	if fail.Result != EtherCATEoENoIPSupport || fail.SetIP != nil || fail.Result.String() != "No IP support" {
		t.Errorf("failed get IP response: %+v", fail)
	}

	if f := m[ecatMbxGetFilterReq].EoE; f.Type != EtherCATEoEGetFilterRequest || f.MACFilter != nil {
		t.Errorf("get filter request: %+v", f)
	}
	f := m[ecatMbxGetFilterRes].EoE
	if f.Type != EtherCATEoEGetFilterReply || f.MACFilter == nil || !f.MACFilter.NoBroadcasts || len(f.MACFilter.Filters) != 2 ||
		len(f.MACFilter.Masks) != 1 || f.MACFilter.Filters[1].String() != "07:08:09:0a:0b:0c" || f.MACFilter.Masks[0].String() != "ff:ff:ff:00:00:00" {
		t.Errorf("get filter response: %+v", f.MACFilter)
	}

	results := map[EtherCATEoEResult]string{
		EtherCATEoESuccess: "Success", EtherCATEoEUnspecifiedError: "Unspecified error",
		EtherCATEoEUnsupportedType: "Unsupported frame type", EtherCATEoENoDHCPSupport: "DHCP not supported",
		EtherCATEoENoFilterSupport: "No filter support", 0x0300: "Unknown(0x0300)",
	}
	for r, want := range results {
		if r.String() != want {
			t.Errorf("result %#x: %q", uint16(r), r.String())
		}
	}
	for typ, want := range map[EtherCATEoEType]string{
		EtherCATEoEGetIPResponse: "Get IP Res", EtherCATEoEGetFilterRequest: "Get MAC Req", EtherCATEoEGetFilterReply: "Get MAC Res",
	} {
		if typ.String() != want {
			t.Errorf("type %d: %q", typ, typ.String())
		}
	}
}

func TestEtherCATADSNames(t *testing.T) {
	errs := map[EtherCATADSError]string{
		0x000: "No error", 0x006: "Target port not found", 0x007: "Target machine not found", 0x01e: "Access denied",
		0x01f: "Unknown(0x1f)", 0x500: "Locked memory cannot be allocated", 0x50d: "Port removed", 0x50e: "Unknown(0x50e)",
		0x700: "General device error", 0x703: "Invalid index offset", 0x710: "Symbol not found", 0x723: "Access denied",
		0x739: "Context: forward to real time", 0x73a: "Unknown(0x73a)", 0x740: "Client error", 0x745: "Timeout",
		0x749: "No AMS address", 0x74a: "Unknown(0x74a)", 0x750: "Internal error in ADS sync", 0x755: "Sync port is locked",
		0x756: "Unknown(0x756)", 0x274c: "Unknown(0x274c)", 0xffffffff: "Unknown(0xffffffff)",
	}
	for code, want := range errs {
		if got := code.String(); got != want {
			t.Errorf("error %#x: %q, want %q", uint32(code), got, want)
		}
	}

	ports := map[EtherCATAMSPort]string{
		1: "1(Router)", 300: "300(I/O)", 801: "801(PLC runtime 1)", 851: "851(TwinCAT 3 PLC 1)",
		10000: "10000(System service)", 32768: "32768",
	}
	for port, want := range ports {
		if got := port.String(); got != want {
			t.Errorf("port %d: %q, want %q", uint16(port), got, want)
		}
	}

	if EtherCATADSStateRun.String() != "Run" || EtherCATADSStateReconfig.String() != "Reconfig" || EtherCATADSState(17).String() != "Unknown(17)" {
		t.Error("ADS state names")
	}
	if EtherCATADSTransServerOnChange.String() != "Server on change" || EtherCATADSTransMode(7).String() != "Unknown(7)" {
		t.Error("transmission mode names")
	}
	if EtherCATADSGroupSumUpRW.String() != "Sum-up read write" || EtherCATADSGroupHandleByName.String() != "Handle by name" ||
		EtherCATADSGroup(0x1234).String() != "0x1234" || EtherCATADSGroupSumUpAddNote.IsSumUp() || !EtherCATADSGroupSumUpReadEx2.IsSumUp() {
		t.Error("index group names")
	}
}

// AMS addresses of the hand-built ADS packets.
var (
	ecatADSTarget = EtherCATAMSNetID{5, 1, 2, 3, 1, 1}
	ecatADSSource = EtherCATAMSNetID{192, 168, 0, 10, 1, 1}
)

// ecatADSPacket builds an AMS packet between the test addresses.
func ecatADSPacket(cmd EtherCATADSCommand, flags EtherCATAMSFlags, invoke uint32, body []byte) []byte {
	out := ecatAMSBytes(cmd, flags, body)
	copy(out[0:], ecatADSTarget[:])
	binary.LittleEndian.PutUint16(out[6:], uint16(EtherCATAMSPortTC3PLC1))
	copy(out[8:], ecatADSSource[:])
	binary.LittleEndian.PutUint16(out[14:], 32768)
	binary.LittleEndian.PutUint32(out[28:], invoke)
	return out
}

// ecatLE packs 32-bit words little endian.
func ecatLE(words ...uint32) []byte {
	var out []byte
	for _, w := range words {
		out = binary.LittleEndian.AppendUint32(out, w)
	}
	return out
}

// ecatSumUp is one hand-built sum-up exchange: the bodies of the read
// write request and of its response.
type ecatSumUp struct {
	name     string
	req, res []byte
	items    []EtherCATADSSumItem
	results  []EtherCATADSSumResult
}

// ecatSumUps covers the five sum-up kinds, two accesses each.
func ecatSumUps() []ecatSumUp {
	const mem = uint32(EtherCATADSGroupPLCMemory)
	byName := uint32(EtherCATADSGroupHandleByName)
	list := ecatLE(mem, 0, 4, mem, 8, 2)
	rw := func(group EtherCATADSGroup, readLen uint32, data []byte) []byte {
		return append(ecatLE(uint32(group), 2, readLen, uint32(len(data))), data...)
	}
	res := func(data []byte) []byte { return append(ecatLE(0, uint32(len(data))), data...) }
	readItems := []EtherCATADSSumItem{
		{IndexGroup: EtherCATADSGroupPLCMemory, Length: 4},
		{IndexGroup: EtherCATADSGroupPLCMemory, IndexOffset: 8, Length: 2},
	}

	return []ecatSumUp{{
		name:  "read",
		req:   rw(EtherCATADSGroupSumUpRead, 14, list),
		res:   res(append(ecatLE(0, 0x703), 1, 2, 3, 4, 5, 6)),
		items: readItems,
		results: []EtherCATADSSumResult{
			{Data: []byte{1, 2, 3, 4}},
			{Result: 0x703, Data: []byte{5, 6}},
		},
	}, {
		name: "write",
		req:  rw(EtherCATADSGroupSumUpWrite, 8, append(ecatLE(mem, 0, 2, mem, 2, 1), 0x11, 0x22, 0x33)),
		res:  res(ecatLE(0, 0x704)),
		items: []EtherCATADSSumItem{
			{IndexGroup: EtherCATADSGroupPLCMemory, WriteLength: 2, Data: []byte{0x11, 0x22}},
			{IndexGroup: EtherCATADSGroupPLCMemory, IndexOffset: 2, WriteLength: 1, Data: []byte{0x33}},
		},
		results: []EtherCATADSSumResult{{}, {Result: 0x704}},
	}, {
		name: "read write",
		req:  rw(EtherCATADSGroupSumUpRW, 24, append(ecatLE(byName, 0, 4, 5, byName, 0, 4, 3), []byte("MAIN.abc")...)),
		res:  res(append(ecatLE(0, 4, 0x710, 0), 0x0c, 0, 0, 0x55)),
		items: []EtherCATADSSumItem{
			{IndexGroup: EtherCATADSGroupHandleByName, Length: 4, WriteLength: 5, Data: []byte("MAIN.")},
			{IndexGroup: EtherCATADSGroupHandleByName, Length: 4, WriteLength: 3, Data: []byte("abc")},
		},
		results: []EtherCATADSSumResult{
			{Length: 4, Data: []byte{0x0c, 0, 0, 0x55}},
			{Result: 0x710, Data: []byte{}},
		},
	}, {
		// Data sits at the requested lengths: 4 and 2.
		name:  "read ex",
		req:   rw(EtherCATADSGroupSumUpReadEx, 22, list),
		res:   res(append(ecatLE(0, 4, 0, 1), 1, 2, 3, 4, 5, 0)),
		items: readItems,
		results: []EtherCATADSSumResult{
			{Length: 4, Data: []byte{1, 2, 3, 4}},
			{Length: 1, Data: []byte{5, 0}},
		},
	}, {
		// Data sits at the returned lengths: 4 and 1.
		name:  "read ex 2",
		req:   rw(EtherCATADSGroupSumUpReadEx2, 22, list),
		res:   res(append(ecatLE(0, 4, 0, 1), 1, 2, 3, 4, 5)),
		items: readItems,
		results: []EtherCATADSSumResult{
			{Length: 4, Data: []byte{1, 2, 3, 4}},
			{Length: 1, Data: []byte{5}},
		},
	}}
}

func TestEtherCATADSSumUp(t *testing.T) {
	for i, c := range ecatSumUps() {
		req := decodeEtherCATAMS(ecatADSPacket(EtherCATADSReadWrite, 0, uint32(i), c.req))
		res := decodeEtherCATAMS(ecatADSPacket(EtherCATADSReadWrite, EtherCATAMSResponse, uint32(i), c.res))
		if req == nil || req.ADS == nil || res == nil || res.ADS == nil {
			t.Fatalf("%s: not decoded", c.name)
		}

		ecatSame(t, c.name+" items", req.ADS.SumUp, c.items)
		ecatSame(t, c.name+" results", res.ADS.SumUpResults(req.ADS), c.results)
		if req.ADS.IndexOffset != 2 || !req.ADS.IndexGroup.IsSumUp() || res.ADS.SumUp != nil {
			t.Errorf("%s: request %+v", c.name, req.ADS)
		}
	}

	// A plain read write is no sum-up, and answers none.
	plain := decodeEtherCATAMS(ecatADSPacket(EtherCATADSReadWrite, 0, 1, ecatLE(uint32(EtherCATADSGroupHandleByName), 0, 4, 0)))
	if plain.ADS.SumUp != nil || plain.ADS.SumUpResults(plain.ADS) != nil {
		t.Errorf("plain read write: %+v", plain.ADS)
	}
	var none *EtherCATADS
	if none.SumUpResults(plain.ADS) != nil || plain.ADS.SumUpResults(nil) != nil {
		t.Error("results from nil")
	}
}

// TestEtherCATADSSumUpLies feeds sum-up counts and lengths that claim
// more than the packets hold.
func TestEtherCATADSSumUpLies(t *testing.T) {
	const mem = uint32(EtherCATADSGroupPLCMemory)
	decode := func(group EtherCATADSGroup, count uint32, data []byte) *EtherCATADS {
		body := append(ecatLE(uint32(group), count, 0, uint32(len(data))), data...)
		return decodeEtherCATAMS(ecatADSPacket(EtherCATADSReadWrite, 0, 0, body)).ADS
	}

	// 2^32-1 accesses announced, one and a half present.
	a := decode(EtherCATADSGroupSumUpRead, 0xffffffff, append(ecatLE(mem, 0, 4), 1, 2, 3, 4, 5, 6))
	if len(a.SumUp) != 1 || a.SumUp[0].Length != 4 {
		t.Errorf("count above the data: %+v", a.SumUp)
	}

	// Fewer announced than present: the rest is not an access.
	a = decode(EtherCATADSGroupSumUpRead, 1, ecatLE(mem, 0, 4, mem, 4, 4))
	if len(a.SumUp) != 1 {
		t.Errorf("count below the data: %+v", a.SumUp)
	}
	if a = decode(EtherCATADSGroupSumUpRead, 0, ecatLE(mem, 0, 4)); a.SumUp != nil {
		t.Errorf("no accesses announced: %+v", a.SumUp)
	}

	// Write data shorter than its length: that access and the ones
	// after it have none.
	a = decode(EtherCATADSGroupSumUpWrite, 3, append(ecatLE(mem, 0, 2, mem, 2, 0xffffffff, mem, 6, 1), 0x11, 0x22, 0x33))
	if len(a.SumUp) != 3 || !bytes.Equal(a.SumUp[0].Data, []byte{0x11, 0x22}) || a.SumUp[1].Data != nil || a.SumUp[2].Data != nil ||
		a.SumUp[1].WriteLength != 0xffffffff {
		t.Errorf("write length above the data: %+v", a.SumUp)
	}

	// A response without a result for every access is no answer; one
	// whose data is cut keeps the results.
	req := decode(EtherCATADSGroupSumUpReadEx2, 2, ecatLE(mem, 0, 4, mem, 4, 4))
	res := &EtherCATADS{Data: ecatLE(0, 4, 0)}
	if got := res.SumUpResults(req); got != nil {
		t.Errorf("response short of results: %+v", got)
	}
	res.Data = append(ecatLE(0, 4, 0, 0xffffffff), 1, 2, 3, 4, 5)
	got := res.SumUpResults(req)
	if len(got) != 2 || !bytes.Equal(got[0].Data, []byte{1, 2, 3, 4}) || got[1].Data != nil || got[1].Length != 0xffffffff {
		t.Errorf("returned length above the data: %+v", got)
	}

	// One allocation each, sized by the data: 100 accesses in a request
	// that announces 2^32-1.
	list := make([]byte, 100*ethercatADSSumReadLen)
	body := append(ecatLE(uint32(EtherCATADSGroupSumUpRead), 0xffffffff, 0, uint32(len(list))), list...)
	pkt := ecatADSPacket(EtherCATADSReadWrite, 0, 0, body)
	var ams *EtherCATAMS
	allocs := testing.AllocsPerRun(20, func() { ams = decodeEtherCATAMS(pkt) })
	if len(ams.ADS.SumUp) != 100 || cap(ams.ADS.SumUp) != 100 || allocs > 3 {
		t.Errorf("request: %d accesses (cap %d), %v allocs", len(ams.ADS.SumUp), cap(ams.ADS.SumUp), allocs)
	}

	res.Data = make([]byte, 100*ethercatADSSumResLen)
	allocs = testing.AllocsPerRun(20, func() { got = res.SumUpResults(ams.ADS) })
	if len(got) != 100 || cap(got) != 100 || allocs > 1 {
		t.Errorf("response: %d results (cap %d), %v allocs", len(got), cap(got), allocs)
	}
}

func TestEtherCATADSNotifyAttrs(t *testing.T) {
	// Group, offset, length, mode, max delay, cycle time, 16 reserved.
	body := append(ecatLE(uint32(EtherCATADSGroupValueByHandle), 0x0c, 4, 4, 1000000, 50000), make([]byte, 16)...)
	a := decodeEtherCATAMS(ecatADSPacket(EtherCATADSAddNotification, 0, 9, body))
	if a.ADS == nil || a.ADS.IndexGroup != EtherCATADSGroupValueByHandle || a.ADS.TransmissionMode != EtherCATADSTransServerOnChange ||
		a.ADS.MaxDelayTime() != 100*time.Millisecond || a.ADS.CycleDuration() != 5*time.Millisecond || a.ADS.Length != 4 {
		t.Errorf("add notification: %+v", a.ADS)
	}
	if a.TargetPort != EtherCATAMSPortTC3PLC1 || a.SourcePort != 32768 || a.TargetNetID != ecatADSTarget || a.InvokeID != 9 {
		t.Errorf("AMS header: %+v", a)
	}

	// The largest counts stay in range of a Duration.
	a.ADS.MaxDelay, a.ADS.CycleTime = 0xffffffff, 0xffffffff
	if a.ADS.MaxDelayTime() != 429496729500*time.Nanosecond || a.ADS.CycleDuration() <= 0 {
		t.Errorf("largest delay: %v", a.ADS.MaxDelayTime())
	}

	state := decodeEtherCATAMS(ecatADSPacket(EtherCATADSReadState, EtherCATAMSResponse, 9, []byte{0, 0, 0, 0, 5, 0, 1, 0}))
	if state.ADS.ADSState != EtherCATADSStateRun || state.ADS.Result != EtherCATADSNoError || state.ErrorCode.String() != "No error" {
		t.Errorf("read state: %+v", state.ADS)
	}
}

// ecatAMSTCPBytes wraps a payload in an AMS/TCP header.
func ecatAMSTCPBytes(cmd EtherCATAMSTCPCommand, payload []byte) []byte {
	out := binary.LittleEndian.AppendUint16(nil, uint16(cmd))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(payload)))
	return append(out, payload...)
}

// Segment numbers of ecatAMSTCPSegments, 0-based.
const (
	ecatTCPSumUp = iota
	ecatTCPSumUpRes
	ecatTCPNotify
	ecatTCPTwo
	ecatTCPConnect
	ecatTCPCut
)

// ecatAMSTCPSegments holds the TCP payloads of the hand-built AMS/TCP
// vectors. tshark 4.7 decodes their AMS headers and ADS request fields;
// it knows neither sum-up commands nor the router commands, and shows a
// segment with a cut packet as a TCP segment to reassemble.
func ecatAMSTCPSegments() [][]byte {
	sum := ecatSumUps()[0]
	notify := append(ecatLE(uint32(EtherCATADSGroupValueByHandle), 0x0c, 4, 4, 1000000, 50000), make([]byte, 16)...)
	stateReq := ecatAMSTCPBytes(EtherCATAMSTCPPacket, ecatADSPacket(EtherCATADSReadState, 0, 3, nil))
	stateRes := ecatAMSTCPBytes(EtherCATAMSTCPPacket, ecatADSPacket(EtherCATADSReadState, EtherCATAMSResponse, 3, []byte{0, 0, 0, 0, 5, 0, 1, 0}))
	cut := ecatAMSTCPBytes(EtherCATAMSTCPPacket, ecatADSPacket(EtherCATADSRead, EtherCATAMSResponse, 4, append(ecatLE(0, 100), make([]byte, 100)...)))

	return [][]byte{
		ecatAMSTCPBytes(EtherCATAMSTCPPacket, ecatADSPacket(EtherCATADSReadWrite, 0, 1, sum.req)),
		ecatAMSTCPBytes(EtherCATAMSTCPPacket, ecatADSPacket(EtherCATADSReadWrite, EtherCATAMSResponse, 1, sum.res)),
		ecatAMSTCPBytes(EtherCATAMSTCPPacket, ecatADSPacket(EtherCATADSAddNotification, 0, 2, notify)),
		append(stateReq, stateRes...),
		ecatAMSTCPBytes(EtherCATAMSTCPPortConnect, []byte{0x00, 0x80}),
		append(append([]byte(nil), stateReq...), cut[:len(cut)-60]...),
	}
}

// ecatTCPOpts decodes TCP payloads per packet, which the port mapping
// of AMS/TCP needs.
var ecatTCPOpts = gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true}

// ecatTCPFrame puts an AMS/TCP payload in an Ethernet, IPv4 and TCP
// frame to port 48898, at sequence number seq.
func ecatTCPFrame(t testing.TB, seq uint32, payload []byte) []byte {
	t.Helper()
	eth := &Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 5, 0x4c, 0xb8, 0xaf}, EthernetType: EthernetTypeIPv4}
	ip := &IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: IPProtocolTCP, SrcIP: net.IPv4(192, 168, 0, 10), DstIP: net.IPv4(192, 168, 0, 20)}
	tcp := &TCP{SrcPort: 49152, DstPort: TCPPortEtherCATAMS, Seq: seq, Ack: 1, ACK: true, PSH: true, Window: 8192}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestEtherCATAMSTCP(t *testing.T) {
	withEtherCAT(t)
	segs := ecatAMSTCPSegments()

	decode := func(n int) *EtherCATAMSTCP {
		p := gopacket.NewPacket(ecatTCPFrame(t, 1, segs[n]), LinkTypeEthernet, ecatTCPOpts)
		a, ok := p.Layer(LayerTypeEtherCATAMSTCP).(*EtherCATAMSTCP)
		if !ok || p.ErrorLayer() != nil {
			t.Fatalf("segment %d: %v", n, p)
		}
		if len(a.LayerContents()) != len(segs[n]) || len(a.LayerPayload()) != 0 || a.NextLayerType() != gopacket.LayerTypeZero {
			t.Errorf("segment %d: %d content bytes of %d", n, len(a.LayerContents()), len(segs[n]))
		}
		return a
	}

	// A sum-up request and its response, paired by invoke ID.
	req, res := decode(ecatTCPSumUp), decode(ecatTCPSumUpRes)
	if len(req.PDUs) != 1 || len(res.PDUs) != 1 {
		t.Fatalf("%d and %d packets", len(req.PDUs), len(res.PDUs))
	}
	q, r := req.PDUs[0], res.PDUs[0]
	if q.Command != EtherCATAMSTCPPacket || q.Truncated || int(q.Length) != len(q.Data) || q.AMS == nil || r.AMS == nil ||
		q.AMS.InvokeID != r.AMS.InvokeID || q.AMS.TargetNetID != ecatADSTarget || q.AMS.SourceNetID.String() != "192.168.0.10.1.1" {
		t.Fatalf("sum-up packets: %+v %+v", q, r)
	}
	ecatSame(t, "sum-up results", r.AMS.ADS.SumUpResults(q.AMS.ADS), ecatSumUps()[0].results)

	if n := decode(ecatTCPNotify).PDUs[0].AMS; n.ADS == nil || n.ADS.TransmissionMode != EtherCATADSTransServerOnChange {
		t.Errorf("add notification: %+v", n.ADS)
	}

	// Two packets in one segment.
	two := decode(ecatTCPTwo)
	if len(two.PDUs) != 2 || two.PDUs[0].AMS.IsResponse() || !two.PDUs[1].AMS.IsResponse() || two.PDUs[1].AMS.ADS.ADSState != EtherCATADSStateRun {
		t.Errorf("two packets: %+v", two.PDUs)
	}

	// A router command has no AMS packet.
	c := decode(ecatTCPConnect).PDUs[0]
	if c.Command != EtherCATAMSTCPPortConnect || c.AMS != nil || !bytes.Equal(c.Data, []byte{0, 0x80}) || c.Command.String() != "Port connect" {
		t.Errorf("port connect: %+v", c)
	}

	// The second packet ends 60 bytes early: its header and the start
	// of its data are there.
	cut := decode(ecatTCPCut)
	if len(cut.PDUs) != 2 || cut.PDUs[0].Truncated || !cut.PDUs[1].Truncated {
		t.Fatalf("cut segment: %+v", cut.PDUs)
	}
	last := cut.PDUs[1]
	if last.Length != 140 || len(last.Data) != 80 || last.AMS == nil || last.AMS.ADS == nil || last.AMS.ADS.Length != 100 || len(last.AMS.ADS.Data) != 40 {
		t.Errorf("cut packet: %+v", last)
	}

	for cmd, want := range map[EtherCATAMSTCPCommand]string{
		EtherCATAMSTCPPacket: "AMS command", EtherCATAMSTCPPortClose: "Port close", EtherCATAMSTCPRouterNote: "Router notification",
		EtherCATAMSTCPGetLocalAddr: "Get local net ID", 0x2000: "Unknown(0x2000)",
	} {
		if cmd.String() != want {
			t.Errorf("command %#x: %q", uint16(cmd), cmd.String())
		}
	}
}

// TestEtherCATAMSTCPOptIn checks that port 48898 only decodes after the
// opt-in registration.
func TestEtherCATAMSTCPOptIn(t *testing.T) {
	frame := ecatTCPFrame(t, 1, ecatAMSTCPSegments()[ecatTCPSumUp])

	p := gopacket.NewPacket(frame, LinkTypeEthernet, ecatTCPOpts)
	if p.Layer(LayerTypeEtherCATAMSTCP) != nil {
		t.Fatal("AMS/TCP decoded without registration")
	}

	withEtherCAT(t)
	p = gopacket.NewPacket(frame, LinkTypeEthernet, ecatTCPOpts)
	if p.Layer(LayerTypeEtherCATAMSTCP) == nil {
		t.Fatal("AMS/TCP not decoded after registration")
	}

	// Without per-packet stream decoding the payload stays raw.
	p = gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)
	if p.Layer(LayerTypeEtherCATAMSTCP) != nil {
		t.Fatal("AMS/TCP decoded as a datagram by default")
	}
}

// TestEtherCATAMSTCPBounds covers short segments, every truncation and
// the cost of a segment full of empty packets.
func TestEtherCATAMSTCPBounds(t *testing.T) {
	var a EtherCATAMSTCP

	for n := 0; n < ethercatAMSTCPHeaderLen; n++ {
		if err := a.DecodeFromBytes(make([]byte, n), gopacket.NilDecodeFeedback); !errors.Is(err, ErrEtherCATAMSTCP) {
			t.Errorf("%d bytes: %v", n, err)
		}
	}

	for i, seg := range ecatAMSTCPSegments() {
		for n := ethercatAMSTCPHeaderLen; n <= len(seg); n++ {
			if err := a.DecodeFromBytes(seg[:n:n], gopacket.NilDecodeFeedback); err != nil {
				t.Fatalf("segment %d cut to %d: %v", i, n, err)
			}

			// Packets and trailing bytes account for the input.
			used := 0
			for _, pdu := range a.PDUs {
				used += ethercatAMSTCPHeaderLen + len(pdu.Data)
				if pdu.AMS != nil && pdu.AMS.ADS != nil {
					pdu.AMS.ADS.SumUpResults(pdu.AMS.ADS)
				}
			}
			if used != len(a.LayerContents()) || n-used >= ethercatAMSTCPHeaderLen {
				t.Fatalf("segment %d cut to %d: %d bytes in packets, %d in layer", i, n, used, len(a.LayerContents()))
			}
		}
	}

	// A length of 2^32-1 claims the rest of the segment, no more.
	lie := []byte{0, 0, 0xff, 0xff, 0xff, 0xff, 1, 2, 3}
	if err := a.DecodeFromBytes(lie, gopacket.NilDecodeFeedback); err != nil || len(a.PDUs) != 1 || !a.PDUs[0].Truncated || len(a.PDUs[0].Data) != 3 {
		t.Errorf("length lie: %+v %v", a.PDUs, err)
	}

	// 1000 empty packets: one list, sized by a first pass.
	seg := make([]byte, 1000*ethercatAMSTCPHeaderLen+5)
	var fresh *EtherCATAMSTCP
	allocs := testing.AllocsPerRun(20, func() {
		fresh = &EtherCATAMSTCP{}
		if err := fresh.DecodeFromBytes(seg, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
	})
	if len(fresh.PDUs) != 1000 || cap(fresh.PDUs) != 1000 || allocs > 2 {
		t.Errorf("%d packets (cap %d), %v allocs", len(fresh.PDUs), cap(fresh.PDUs), allocs)
	}
	if len(fresh.LayerContents()) != 1000*ethercatAMSTCPHeaderLen {
		t.Errorf("%d content bytes", len(fresh.LayerContents()))
	}
}

func TestScanEtherCATAMSTCP(t *testing.T) {
	segs := ecatAMSTCPSegments()
	stream := bytes.Join(segs[:ecatTCPCut], nil)

	// The stream holds 6 packets; segment 4 of the list carries two.
	sc := bufio.NewScanner(bytes.NewReader(stream))
	sc.Split(ScanEtherCATAMSTCP)
	count := 0
	for sc.Scan() {
		var a EtherCATAMSTCP
		if err := a.DecodeFromBytes(sc.Bytes(), gopacket.NilDecodeFeedback); err != nil || len(a.PDUs) != 1 || a.PDUs[0].Truncated {
			t.Fatalf("token %d: %+v %v", count, a.PDUs, err)
		}
		count++
	}
	if sc.Err() != nil || count != 6 {
		t.Errorf("%d tokens, %v", count, sc.Err())
	}

	// Every split point: more data is asked for without a token.
	first := len(segs[0])
	for n := 0; n < first; n++ {
		adv, tok, err := ScanEtherCATAMSTCP(stream[:n], false)
		if adv != 0 || tok != nil || err != nil {
			t.Fatalf("%d bytes: %d %v %v", n, adv, tok, err)
		}
	}
	adv, tok, err := ScanEtherCATAMSTCP(stream, false)
	if adv != first || len(tok) != first || cap(tok) != first || err != nil {
		t.Errorf("first token: %d %d %v", adv, len(tok), err)
	}

	// A stream that ends inside a packet, and a forged length.
	if _, _, err = ScanEtherCATAMSTCP(stream[:first-1], true); !errors.Is(err, ErrOTStreamTruncated) {
		t.Errorf("cut stream: %v", err)
	}
	if _, _, err = ScanEtherCATAMSTCP(nil, true); err != nil {
		t.Errorf("empty stream: %v", err)
	}
	if _, _, err = ScanEtherCATAMSTCP([]byte{0, 0, 1, 0, 0, 1}, false); !errors.Is(err, ErrOTStreamTooLong) {
		t.Errorf("forged length: %v", err)
	}
	if _, _, err = ScanEtherCATAMSTCP([]byte{0, 0, 0xff, 0xff, 0xff, 0xff}, false); !errors.Is(err, ErrOTStreamTooLong) {
		t.Errorf("largest length: %v", err)
	}
}

// ecatMoreFrames returns the hand-built Ethernet frames of this file.
func ecatMoreFrames(t testing.TB) [][]byte {
	out := append(ecatRegFrames(), ecatMbxFrames()...)
	seq := uint32(1)
	for _, seg := range ecatAMSTCPSegments() {
		out = append(out, ecatTCPFrame(t, seq, seg))
		seq += uint32(len(seg))
	}

	// The sum-up exchanges as AoE mailboxes too.
	for i, c := range ecatSumUps() {
		out = append(out,
			ecatToSlave(EtherCATMailboxAoE, ecatADSPacket(EtherCATADSReadWrite, 0, uint32(i), c.req)...),
			ecatFromSlave(EtherCATMailboxAoE, ecatADSPacket(EtherCATADSReadWrite, EtherCATAMSResponse, uint32(i), c.res)...))
	}
	return out
}

// TestEtherCATMoreTruncation decodes every prefix of every hand-built
// frame of this file and of the transfer frames, and runs the cut
// mailboxes through an assembler.
func TestEtherCATMoreTruncation(t *testing.T) {
	withEtherCAT(t)
	var a EtherCATMailboxAssembler

	for _, frame := range append(ecatMoreFrames(t), ecatAsmFrames()...) {
		for n := 0; n <= len(frame); n++ {
			data := append([]byte(nil), frame[:n]...)
			p := gopacket.NewPacket(data, LinkTypeEthernet, ecatTCPOpts)

			if e, ok := p.Layer(LayerTypeEtherCAT).(*EtherCAT); ok {
				ecatTouch(e)
				for i := range e.Datagrams {
					a.Feed(&e.Datagrams[i])
				}
			}
			if tcp, ok := p.Layer(LayerTypeEtherCATAMSTCP).(*EtherCATAMSTCP); ok {
				ecatTouchAMSTCP(tcp)
			}
		}

		// Mailboxes cut inside their body, without the datagram.
		const mbxStart = 14 + ethercatFrameHeaderLen + ethercatDatagramHeaderLen
		for n := mbxStart; n <= len(frame); n++ {
			m, err := DecodeEtherCATMailbox(append([]byte(nil), frame[mbxStart:n]...))
			if err != nil {
				continue
			}
			ecatTouchMailbox(m)
			a.FeedMailbox(1, EtherCATFromSlave, m)
		}
	}
	if a.Open() > EtherCATAssemblerMaxOpen {
		t.Errorf("%d transfers open", a.Open())
	}
}
