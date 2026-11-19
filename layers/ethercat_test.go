// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
)

// ethercat.pcap holds frames 1-150 and 700-986 of ETHERCAT/ethercat.pcap
// from github.com/automayt/ICS-pcap: the boot of a Beckhoff network,
// including CoE SDO mailbox traffic. Expected values were checked against
// tshark 4.7.
const ecatPcap = "testdata/ethercat.pcap"

// withEtherCAT registers the EtherCAT EtherType and UDP port for one test
// and restores the previous state afterwards.
func withEtherCAT(t testing.TB) {
	oldEth := EthernetTypeMetadata[EthernetTypeEtherCAT]
	port := uint16(UDPPortEtherCAT)
	oldWord := udpPortLayerTypeOverride[port>>6]
	oldType, hadType := udpPortLayerType[UDPPortEtherCAT]

	t.Cleanup(func() {
		EthernetTypeMetadata[EthernetTypeEtherCAT] = oldEth
		udpPortLayerTypeOverride[port>>6] = oldWord
		if hadType {
			udpPortLayerType[UDPPortEtherCAT] = oldType
			return
		}
		delete(udpPortLayerType, UDPPortEtherCAT)
	})
	registerEtherCATDecoders()
}

func decodeECAT(t *testing.T) []*EtherCAT {
	var out []*EtherCAT
	for i, data := range readPNECATPcap(t, ecatPcap) {
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
	return out
}

func TestEtherCATNotRegisteredByDefault(t *testing.T) {
	if EthernetTypeMetadata[EthernetTypeEtherCAT].DecodeWith != nil {
		t.Fatal("EtherCAT EtherType registered without opt-in")
	}
	if UDPPortEtherCAT.LayerType() == LayerTypeEtherCAT {
		t.Fatal("EtherCAT UDP port registered without opt-in")
	}
}

func TestEtherCATPcap(t *testing.T) {
	withEtherCAT(t)
	frames := decodeECAT(t)
	if len(frames) != 437 {
		t.Fatalf("%d frames, want 437", len(frames))
	}

	// Every frame is a command frame; the chain ends exactly at the header length.
	cmds := map[EtherCATCommand]int{}
	mailboxes := 0
	for i, e := range frames {
		if e.Type != EtherCATFrameCommands || len(e.Datagrams) == 0 {
			t.Fatalf("frame %d: %+v", i+1, e)
		}
		if int(e.Length)+ethercatFrameHeaderLen != len(e.LayerContents()) {
			t.Errorf("frame %d: contents %d, header length %d", i+1, len(e.LayerContents()), e.Length)
		}
		last := e.Datagrams[len(e.Datagrams)-1]
		if last.More {
			t.Errorf("frame %d: last datagram has more-follows set", i+1)
		}
		for _, d := range e.Datagrams {
			cmds[d.Command]++
			if d.Mailbox != nil {
				mailboxes++
			}
		}
	}

	// Totals per command, from tshark -e ecat.cmd.
	want := map[EtherCATCommand]int{
		EtherCATCommandAPRD: 2175, EtherCATCommandAPWR: 10, EtherCATCommandFPRD: 336,
		EtherCATCommandFPWR: 291, EtherCATCommandBRD: 439, EtherCATCommandBWR: 18,
		EtherCATCommandLRD: 62, EtherCATCommandLWR: 62,
	}
	for c, n := range want {
		if cmds[c] != n {
			t.Errorf("%v: %d datagrams, want %d", c, cmds[c], n)
		}
	}
	if mailboxes != 30 {
		t.Errorf("%d mailboxes, want 30", mailboxes)
	}

	// Frame 1: one BRD of the AL status register.
	d := frames[0].Datagrams[0]
	if len(frames[0].Datagrams) != 1 || d.Command != EtherCATCommandBRD || d.Index != 2 || d.ADP() != 0 ||
		d.ADO() != 0x0130 || d.Length != 2 || d.WorkingCounter != 0 || d.Circulating {
		t.Errorf("frame 1: %+v", d)
	}

	// Frame 216: nine datagrams; the second writes a CoE SDO initiate
	// download of 0x1C12:00 into slave 0x1004's mailbox.
	e := frames[215]
	if len(e.Datagrams) != 9 {
		t.Fatalf("frame 216: %d datagrams", len(e.Datagrams))
	}
	d = e.Datagrams[1]
	if d.Command != EtherCATCommandFPWR || d.Index != 0xc2 || d.ADP() != 0x1004 || d.ADO() != 0x1800 || d.Length != 16 {
		t.Errorf("frame 216 datagram 2: %+v", d)
	}
	m := d.Mailbox
	if m == nil || m.Length != 10 || m.Address != 0x1004 || m.Type != EtherCATMailboxCoE || m.CoE == nil {
		t.Fatalf("frame 216 mailbox: %+v", m)
	}
	sdo := m.CoE.SDO
	if m.CoE.Service != EtherCATCoESDORequest || sdo == nil || sdo.Command != 0x2f ||
		sdo.Specifier != EtherCATSDOCCSInitiateDownload || sdo.Index != 0x1c12 || sdo.SubIndex != 0 || sdo.Value != 0 {
		t.Errorf("frame 216 SDO: %+v %+v", m.CoE, sdo)
	}
	if e.Datagrams[0].Mailbox != nil {
		t.Error("frame 216: sync manager write taken as a mailbox")
	}

	// Frame 223: the slave's SDO response, read back with FPRD (WKC 1). Its
	// CoE body is too short for an SDO header, as Wireshark also reports.
	var read *EtherCATDatagram
	for i := range frames[222].Datagrams {
		if frames[222].Datagrams[i].Mailbox != nil {
			read = &frames[222].Datagrams[i]
			break
		}
	}
	if read == nil || read.Command != EtherCATCommandFPRD || read.WorkingCounter != 1 {
		t.Fatalf("frame 223: no mailbox read: %+v", frames[222].Datagrams)
	}
	m = read.Mailbox
	if m.CoE == nil || m.CoE.Service != EtherCATCoESDOResponse || m.CoE.SDO != nil || m.Length != 6 {
		t.Errorf("frame 223 mailbox: %+v", m)
	}

	// Frame 308: LRD with a 32-bit logical address.
	d = frames[307].Datagrams[0]
	if d.Command != EtherCATCommandLRD || !d.Command.IsLogical() || d.Address != 0x00011000 {
		t.Errorf("frame 308: %+v", d)
	}
}

func TestEtherCATOverUDP(t *testing.T) {
	withEtherCAT(t)

	// A one-datagram NOP frame inside UDP to port 0x88A4.
	ecat := []byte{0x0e, 0x10, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 0xaa, 0xbb, 3, 0}
	buf := gopacket.NewSerializeBuffer()
	ip := &IPv4{Version: 4, TTL: 64, Protocol: IPProtocolUDP, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2)}
	udp := &UDP{SrcPort: 40000, DstPort: UDPPortEtherCAT}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(ecat)); err != nil {
		t.Fatal(err)
	}

	p := gopacket.NewPacket(buf.Bytes(), LayerTypeIPv4, gopacket.Default)
	e, ok := p.Layer(LayerTypeEtherCAT).(*EtherCAT)
	if !ok {
		t.Fatalf("no EtherCAT layer: %v", p)
	}
	d := e.Datagrams[0]
	if len(e.Datagrams) != 1 || d.Index != 1 || !bytes.Equal(d.Data, []byte{0xaa, 0xbb}) || d.WorkingCounter != 3 {
		t.Errorf("datagram: %+v", d)
	}
}

func TestEtherCATDecodingLayerParser(t *testing.T) {
	withEtherCAT(t)

	var (
		eth  Ethernet
		ecat EtherCAT
	)
	parser := gopacket.NewDecodingLayerParser(LayerTypeEthernet, &eth, &ecat)
	var got []gopacket.LayerType
	frames := readPNECATPcap(t, ecatPcap)
	if err := parser.DecodeLayers(frames[215], &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1] != LayerTypeEtherCAT || len(ecat.Datagrams) != 9 || ecat.Datagrams[1].Mailbox == nil {
		t.Errorf("layers %v, %d datagrams", got, len(ecat.Datagrams))
	}

	// Reuse must not leak datagrams from the previous frame.
	if err := parser.DecodeLayers(frames[0], &got); err != nil {
		t.Fatal(err)
	}
	if len(ecat.Datagrams) != 1 {
		t.Errorf("%d datagrams after reuse, want 1", len(ecat.Datagrams))
	}
}

func TestEtherCATMailbox(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		err  error
		typ  EtherCATMailboxType
		sdo  *EtherCATSDO
	}{
		{
			name: "upload segment response",
			// len 10, addr 0x1001, prio 3, CoE counter 2; CoE SDO response,
			// SCS 0 (upload segment), then 7 segment bytes.
			data: []byte{10, 0, 0x01, 0x10, 0xc0, 0x23, 0x00, 0x30, 0x00, 1, 2, 3, 4, 5, 6, 7},
			typ:  EtherCATMailboxCoE,
			sdo:  &EtherCATSDO{Command: 0, Specifier: EtherCATSDOSCSUploadSegment, Segment: true, Data: []byte{1, 2, 3, 4, 5, 6, 7}},
		},
		{
			name: "abort",
			// CoE SDO request, CCS 4, 0x6040:00, abort code 0x06020000.
			data: []byte{10, 0, 0, 0, 0, 0x03, 0x00, 0x20, 0x80, 0x40, 0x60, 0x00, 0x00, 0x00, 0x02, 0x06},
			typ:  EtherCATMailboxCoE,
			sdo:  &EtherCATSDO{Command: 0x80, Specifier: EtherCATSDOCCSAbort, Index: 0x6040, Value: 0x06020000, Data: []byte{}},
		},
		{
			name: "eoe header only",
			data: []byte{4, 0, 0, 0, 0, 0x02, 1, 2, 3, 4, 0xff},
			typ:  EtherCATMailboxEoE,
		},
		{
			name: "header cut",
			data: []byte{4, 0, 0, 0, 0},
			err:  ErrEtherCATMailbox,
		},
		{
			name: "length lies",
			data: []byte{0xff, 0x05, 0, 0, 0, 0x03, 0, 0},
			err:  ErrEtherCATMailbox,
		},
	}
	for _, c := range cases {
		m, err := DecodeEtherCATMailbox(c.data)
		if err != c.err {
			t.Errorf("%s: error %v, want %v", c.name, err, c.err)
			continue
		}
		if err != nil {
			continue
		}
		if m.Type != c.typ || int(m.Length) != len(m.Data) {
			t.Errorf("%s: %+v", c.name, m)
		}
		if c.sdo == nil {
			if m.CoE != nil {
				t.Errorf("%s: unexpected CoE %+v", c.name, m.CoE)
			}
			continue
		}
		got := m.CoE.SDO
		if got == nil || got.Command != c.sdo.Command || got.Specifier != c.sdo.Specifier || got.Segment != c.sdo.Segment ||
			got.Index != c.sdo.Index || got.SubIndex != c.sdo.SubIndex || got.Value != c.sdo.Value || !bytes.Equal(got.Data, c.sdo.Data) {
			t.Errorf("%s: SDO %+v, want %+v", c.name, got, c.sdo)
		}
	}

	// The first upload segment case also checks the header bit fields.
	m, _ := DecodeEtherCATMailbox(cases[0].data)
	if m.Address != 0x1001 || m.Priority != 3 || m.Channel != 0 || m.Counter != 2 {
		t.Errorf("header fields: %+v", m)
	}
}

// ecatFrame wraps an EtherCAT body in an Ethernet header and frame header.
func ecatFrame(length uint16, body ...byte) []byte {
	hdr := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 0x88, 0xa4,
		byte(length), byte(EtherCATFrameCommands)<<4 | byte(length>>8)}
	return append(hdr, body...)
}

func TestEtherCATMalformed(t *testing.T) {
	withEtherCAT(t)

	nop := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // NOP, length 0, last
	more := []byte{0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0}
	long := []byte{1, 0, 0, 0, 0, 0, 0xff, 0x07, 0, 0, 1, 2} // claims 2047 data bytes

	cases := []struct {
		name      string
		frame     []byte
		err       error
		truncated bool
		datagrams int
	}{
		{"frame header cut", ecatFrame(0)[:15], ErrEtherCATTooShort, true, 0},
		{"length past data", ecatFrame(100, nop...), nil, true, 1},
		{"datagram past header length", ecatFrame(6, nop...), ErrEtherCATDatagram, false, 0},
		{"datagram length lies", ecatFrame(uint16(len(long)), long...), ErrEtherCATDatagram, false, 0},
		{"more follows into nothing", ecatFrame(12, more...), nil, false, 1},
		{"chain past data", ecatFrame(24, append(append([]byte{}, more...), more[:6]...)...), ErrEtherCATDatagram, true, 1},
	}
	for _, c := range cases {
		p := gopacket.NewPacket(c.frame, LinkTypeEthernet, gopacket.Default)
		if got := p.Metadata().Truncated; got != c.truncated {
			t.Errorf("%s: truncated %v, want %v", c.name, got, c.truncated)
		}

		el := p.ErrorLayer()
		if c.err != nil {
			if el == nil || el.Error() != c.err {
				t.Errorf("%s: error %v, want %v", c.name, el, c.err)
			}
			continue
		}
		if el != nil {
			t.Errorf("%s: unexpected error %v", c.name, el.Error())
			continue
		}
		if e := p.Layer(LayerTypeEtherCAT).(*EtherCAT); len(e.Datagrams) != c.datagrams {
			t.Errorf("%s: %d datagrams, want %d", c.name, len(e.Datagrams), c.datagrams)
		}
	}
}

// TestEtherCATTruncation decodes every prefix of every test frame.
func TestEtherCATTruncation(t *testing.T) {
	withEtherCAT(t)

	for _, frame := range readPNECATPcap(t, ecatPcap) {
		for n := 0; n <= len(frame); n++ {
			data := append([]byte(nil), frame[:n]...)
			gopacket.NewPacket(data, LinkTypeEthernet, gopacket.Default)
		}
	}
}

func FuzzEtherCAT(f *testing.F) {
	withEtherCAT(f)
	for _, path := range []string{ecatPcap, ecatHandPcap} {
		for _, frame := range readPNECATPcap(f, path) {
			f.Add(frame)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		p := gopacket.NewPacket(data, LinkTypeEthernet, gopacket.Default)
		if e, ok := p.Layer(LayerTypeEtherCAT).(*EtherCAT); ok {
			// Every datagram costs at least 12 bytes of input.
			if len(e.Datagrams)*(ethercatDatagramHeaderLen+ethercatWKCLen) > len(data) {
				t.Fatalf("%d datagrams from %d bytes", len(e.Datagrams), len(data))
			}
			ecatFuzzBounds(t, e, len(data))
			ecatTouch(e)
		}

		// Decode the frame and the mailbox directly too.
		var e EtherCAT
		if err := e.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
			ecatFuzzBounds(t, &e, len(data))
			ecatTouch(&e)
		}
		if m, err := DecodeEtherCATMailbox(data); err == nil {
			ecatFuzzMailbox(t, m, len(data))
			ecatTouchMailbox(m)
		}
	})
}

// ecatFuzzBounds fails when a decoded list is larger than its input
// could pay for.
func ecatFuzzBounds(t *testing.T, e *EtherCAT, size int) {
	if e.NV != nil && len(e.NV.Variables)*ethercatNVVarHeaderLen > size {
		t.Fatalf("%d NV variables from %d bytes", len(e.NV.Variables), size)
	}
	if e.ADS != nil {
		ecatFuzzADS(t, e.ADS, size)
	}
	ecatFuzzMailbox(t, e.Mailbox, size)

	for i := range e.Datagrams {
		d := &e.Datagrams[i]
		ecatFuzzMailbox(t, d.Mailbox, size)
		if n := len(d.Registers()); n > escRegisterMax {
			t.Fatalf("%d registers, table allows %d", n, escRegisterMax)
		}
	}
}

// ecatFuzzMailbox checks the lists of a mailbox body against the input.
func ecatFuzzMailbox(t *testing.T, m *EtherCATMailbox, size int) {
	if m == nil {
		return
	}
	if m.AoE != nil {
		ecatFuzzADS(t, m.AoE, size)
	}
	if m.CoE != nil && m.CoE.SDOInfo != nil && len(m.CoE.SDOInfo.Indexes)*ethercatIndexLen > size {
		t.Fatalf("%d indexes from %d bytes", len(m.CoE.SDOInfo.Indexes), size)
	}
	if m.EoE != nil && m.EoE.MACFilter != nil {
		if f := m.EoE.MACFilter; len(f.Filters) >= ethercatEoEMaxFilters || len(f.Masks) >= ethercatEoEMaxMasks {
			t.Fatalf("%d filters, %d masks", len(f.Filters), len(f.Masks))
		}
	}
}

// ecatFuzzADS checks the notification stamps against the input.
func ecatFuzzADS(t *testing.T, a *EtherCATAMS, size int) {
	if a.ADS == nil {
		return
	}

	cost := 0
	for _, s := range a.ADS.Stamps {
		cost += ethercatADSStampLen + len(s.Samples)*ethercatADSSampleLen
	}
	if cost > size {
		t.Fatalf("stamps worth %d bytes from %d", cost, size)
	}
}
