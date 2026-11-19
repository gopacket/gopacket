// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gopacket/gopacket"
)

// The hand-built transfers below talk to one slave: writes go to its
// receive mailbox, reads with a working counter of one come from its
// send mailbox. tshark 4.7 shows every fragment of them (it reassembles
// none); the fragment fields were compared with it.
const (
	ecatAsmStation = 0x1001
	ecatAsmOutADO  = 0x1000
	ecatAsmInADO   = 0x1080
)

// ecatDgramFrame wraps data in the only datagram of an EtherCAT frame
// on Ethernet.
func ecatDgramFrame(cmd EtherCATCommand, adp, ado, wkc uint16, data []byte) []byte {
	out := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 0x88, 0xa4}
	size := ethercatDatagramHeaderLen + len(data) + ethercatWKCLen
	out = binary.LittleEndian.AppendUint16(out, uint16(size)|uint16(EtherCATFrameCommands)<<ethercatTypeShift)

	out = append(out, byte(cmd), 0)
	out = binary.LittleEndian.AppendUint16(out, adp)
	out = binary.LittleEndian.AppendUint16(out, ado)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(data)))
	out = append(out, 0, 0)
	out = append(out, data...)
	return binary.LittleEndian.AppendUint16(out, wkc)
}

// ecatToSlave and ecatFromSlave carry a mailbox to and from the slave.
func ecatToSlave(typ EtherCATMailboxType, body ...byte) []byte {
	return ecatDgramFrame(EtherCATCommandFPWR, ecatAsmStation, ecatAsmOutADO, 0, ecatMailboxBytes(typ, body))
}

func ecatFromSlave(typ EtherCATMailboxType, body ...byte) []byte {
	return ecatDgramFrame(EtherCATCommandFPRD, ecatAsmStation, ecatAsmInADO, 1, ecatMailboxBytes(typ, body))
}

// ecatCoE prefixes an SDO body with the CoE header of a request or
// response.
func ecatCoE(service EtherCATCoEService, body ...byte) []byte {
	return append([]byte{0, byte(service) << 4}, body...)
}

// ecatSDODownFrames is a normal download of 17 bytes to 0x1C12 with
// complete access: 4 bytes in the initiate request, 7 and 6 in two
// segments, the first of which is sent twice.
func ecatSDODownFrames() [][]byte {
	req, res := EtherCATCoESDORequest, EtherCATCoESDOResponse
	seg := ecatToSlave(EtherCATMailboxCoE, ecatCoE(req, 0x00, 5, 6, 7, 8, 9, 10, 11)...)

	return [][]byte{
		ecatToSlave(EtherCATMailboxCoE, ecatCoE(req, 0x31, 0x12, 0x1c, 0, 17, 0, 0, 0, 1, 2, 3, 4)...),
		ecatFromSlave(EtherCATMailboxCoE, ecatCoE(res, 0x60, 0x12, 0x1c, 0, 0, 0, 0, 0)...),
		seg,
		ecatFromSlave(EtherCATMailboxCoE, ecatCoE(res, 0x20, 0, 0, 0, 0, 0, 0, 0)...),
		seg,
		// Toggle set, last, one of the 7 bytes unused.
		ecatToSlave(EtherCATMailboxCoE, ecatCoE(req, 0x13, 12, 13, 14, 15, 16, 17, 0xee)...),
	}
}

// ecatSDOUpFrames is a normal upload of the 12-byte name at 0x1008: 4
// bytes in the initiate response, 8 in one segment larger than the
// minimum.
func ecatSDOUpFrames() [][]byte {
	req, res := EtherCATCoESDORequest, EtherCATCoESDOResponse

	return [][]byte{
		ecatToSlave(EtherCATMailboxCoE, ecatCoE(req, 0x40, 0x08, 0x10, 0, 0, 0, 0, 0)...),
		ecatFromSlave(EtherCATMailboxCoE, ecatCoE(res, 0x41, 0x08, 0x10, 0, 12, 0, 0, 0, 'E', 'K', '1', '1')...),
		ecatToSlave(EtherCATMailboxCoE, ecatCoE(req, 0x60, 0, 0, 0, 0, 0, 0, 0)...),
		ecatFromSlave(EtherCATMailboxCoE, ecatCoE(res, 0x01, '0', '0', '-', '0', '0', '1', '0', ' ')...),
	}
}

// ecatSDOMiscFrames is an expedited download of 2 bytes, then an upload
// the slave aborts.
func ecatSDOMiscFrames() [][]byte {
	req := EtherCATCoESDORequest

	return [][]byte{
		ecatToSlave(EtherCATMailboxCoE, ecatCoE(req, 0x2b, 0x12, 0x1c, 1, 0x00, 0x16, 0xaa, 0xbb)...),
		ecatToSlave(EtherCATMailboxCoE, ecatCoE(req, 0x40, 0x99, 0x20, 0, 0, 0, 0, 0)...),
		ecatFromSlave(EtherCATMailboxCoE, ecatCoE(req, 0x80, 0x99, 0x20, 0, 0, 0, 0x02, 0x06)...),
	}
}

// ecatEoEFrame is the 80-byte Ethernet frame the EoE fragments carry: an
// ARP request with padding.
func ecatEoEFrame() []byte {
	frame := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x05, 0x4c, 0xb8, 0xaf, 0x08, 0x06,
		0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
		0x00, 0x01, 0x05, 0x4c, 0xb8, 0xaf, 169, 254, 93, 65,
		0, 0, 0, 0, 0, 0, 169, 254, 93, 66,
	}
	return append(frame, make([]byte, 80-len(frame))...)
}

// ecatEoEHeader builds the 4-byte header of an EoE fragment on port 1.
func ecatEoEHeader(frag, blocks, frameNo uint16, flags uint16) []byte {
	out := binary.LittleEndian.AppendUint16(nil, 1<<ethercatEoEPortShift|flags)
	return binary.LittleEndian.AppendUint16(out, frag|blocks<<ethercatEoEOffsetShift|frameNo<<ethercatEoEFrameNoShift)
}

// ecatEoEFrames sends ecatEoEFrame from the slave in fragments of 32, 32
// and 16 bytes, the last with a timestamp, then a fragment of a frame
// whose start is missing.
func ecatEoEFrames() [][]byte {
	frame := ecatEoEFrame()
	last := append(ecatEoEHeader(2, 2, 5, ethercatEoELastBit|ethercatEoETimeAppBit), frame[64:]...)
	last = append(last, 0x78, 0x56, 0x34, 0x12)

	return [][]byte{
		ecatFromSlave(EtherCATMailboxEoE, append(ecatEoEHeader(0, 3, 5, 0), frame[:32]...)...),
		ecatFromSlave(EtherCATMailboxEoE, append(ecatEoEHeader(1, 1, 5, 0), frame[32:64]...)...),
		ecatFromSlave(EtherCATMailboxEoE, last...),
		ecatFromSlave(EtherCATMailboxEoE, append(ecatEoEHeader(3, 3, 9, 0), frame[:32]...)...),
	}
}

// ecatFoEFile is the 37-byte file of ecatFoEFrames.
func ecatFoEFile() []byte {
	file := make([]byte, 37)
	for i := range file {
		file[i] = byte(0xa0 + i)
	}
	return file
}

// ecatFoEFrames writes ecatFoEFile as "fw.bin" in packets of 16, 16 and
// 5 bytes; packet 2 is sent twice.
func ecatFoEFrames() [][]byte {
	file := ecatFoEFile()
	data := func(no byte, part []byte) []byte {
		return ecatToSlave(EtherCATMailboxFoE, append([]byte{byte(EtherCATFoEDATA), 0, no, 0, 0, 0}, part...)...)
	}
	ack := func(no byte) []byte {
		return ecatFromSlave(EtherCATMailboxFoE, byte(EtherCATFoEACK), 0, no, 0, 0, 0)
	}

	return [][]byte{
		ecatToSlave(EtherCATMailboxFoE, byte(EtherCATFoEWRQ), 0, 0x78, 0x56, 0x34, 0x12, 'f', 'w', '.', 'b', 'i', 'n'),
		ack(0),
		data(1, file[:16]),
		ack(1),
		data(2, file[16:32]),
		data(2, file[16:32]),
		ack(2),
		data(3, file[32:]),
	}
}

// ecatSoEFrames is a read response of drive 2 for S-0-0030 in three
// fragments.
func ecatSoEFrames() [][]byte {
	const head = byte(EtherCATSoEReadResponse) | 2<<ethercatSoEDriveShift
	value := byte(EtherCATSoEValue)

	return [][]byte{
		ecatFromSlave(EtherCATMailboxSoE, head|ethercatSoEIncomplete, value, 2, 0, 'f', 'i', 'r', 'm', 'w', 'a'),
		ecatFromSlave(EtherCATMailboxSoE, head|ethercatSoEIncomplete, value, 1, 0, 'r', 'e', ' ', 'v', '1', '.'),
		ecatFromSlave(EtherCATMailboxSoE, head, value, 30, 0, '2', '.', '3'),
	}
}

// ecatAsmFrames returns every hand-built transfer frame.
func ecatAsmFrames() [][]byte {
	var out [][]byte
	for _, group := range [][][]byte{
		ecatSDODownFrames(), ecatSDOUpFrames(), ecatSDOMiscFrames(),
		ecatEoEFrames(), ecatFoEFrames(), ecatSoEFrames(),
	} {
		out = append(out, group...)
	}
	return out
}

// ecatAsmRun decodes frames and feeds their datagram to the assembler.
// It returns the status of every frame and the transfers that finished.
func ecatAsmRun(t *testing.T, a *EtherCATMailboxAssembler, frames [][]byte) ([]EtherCATAssemblyStatus, []*EtherCATTransfer) {
	t.Helper()
	withEtherCAT(t)

	var states []EtherCATAssemblyStatus
	var done []*EtherCATTransfer
	for i, frame := range frames {
		p := gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)
		e, ok := p.Layer(LayerTypeEtherCAT).(*EtherCAT)
		if !ok || len(e.Datagrams) != 1 || e.Datagrams[0].Mailbox == nil {
			t.Fatalf("frame %d: no mailbox", i+1)
		}

		x, st := a.Feed(&e.Datagrams[0])
		if (x != nil) != (st == EtherCATAssemblyComplete) {
			t.Fatalf("frame %d: transfer %v with status %v", i+1, x != nil, st)
		}
		states = append(states, st)
		if x != nil {
			done = append(done, x)
		}
	}
	return states, done
}

// ecatAsmOne runs frames and expects the statuses given and exactly one
// transfer, which it returns.
func ecatAsmOne(t *testing.T, frames [][]byte, want ...EtherCATAssemblyStatus) *EtherCATTransfer {
	t.Helper()
	var a EtherCATMailboxAssembler

	states, done := ecatAsmRun(t, &a, frames)
	ecatSame(t, "statuses", states, want)
	if len(done) != 1 || a.Open() != 0 {
		t.Fatalf("%d transfers, %d open", len(done), a.Open())
	}
	return done[0]
}

func TestECATAsmSDO(t *testing.T) {
	const (
		pending = EtherCATAssemblyPending
		done    = EtherCATAssemblyComplete
	)

	x := ecatAsmOne(t, ecatSDODownFrames(), pending, pending, pending, pending, EtherCATAssemblyToggle, done)
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}
	if x.Kind != EtherCATTransferSDODownload || x.Station != ecatAsmStation || x.Index != 0x1c12 || x.SubIndex != 0 ||
		!x.CompleteAccess || x.Announced != 17 || !bytes.Equal(x.Data, want) || x.Dir != EtherCATToSlave {
		t.Errorf("download: %+v", x)
	}
	if x.NextLayerType() != gopacket.LayerTypePayload || x.Kind.String() != "SDO download" {
		t.Errorf("download: next %v, kind %v", x.NextLayerType(), x.Kind)
	}

	x = ecatAsmOne(t, ecatSDOUpFrames(), EtherCATAssemblyNone, pending, pending, done)
	if x.Kind != EtherCATTransferSDOUpload || x.Index != 0x1008 || x.Announced != 12 || string(x.Data) != "EK1100-0010 " ||
		x.Dir != EtherCATFromSlave {
		t.Errorf("upload: %+v", x)
	}

	// Expedited: the size bits leave 2 of the 4 bytes. The aborted
	// upload had nothing open, as an upload request carries no data.
	x = ecatAsmOne(t, ecatSDOMiscFrames(), done, EtherCATAssemblyNone, EtherCATAssemblyNone)
	if x.Kind != EtherCATTransferSDODownload || x.Index != 0x1c12 || x.SubIndex != 1 || x.Announced != 0 ||
		!bytes.Equal(x.Data, []byte{0x00, 0x16}) {
		t.Errorf("expedited: %+v", x)
	}
}

// TestECATAsmSDOAbort drops an open transfer on an abort and treats a
// segment after it as an orphan.
func TestECATAsmSDOAbort(t *testing.T) {
	var a EtherCATMailboxAssembler
	down := ecatSDODownFrames()
	abort := ecatFromSlave(EtherCATMailboxCoE, ecatCoE(EtherCATCoESDORequest, 0x80, 0x12, 0x1c, 0, 0, 0, 0x02, 0x06)...)

	states, done := ecatAsmRun(t, &a, [][]byte{down[0], down[2], abort, down[5]})
	ecatSame(t, "statuses", states, []EtherCATAssemblyStatus{
		EtherCATAssemblyPending, EtherCATAssemblyPending, EtherCATAssemblyAborted, EtherCATAssemblyOrphan,
	})
	if len(done) != 0 || a.Open() != 0 {
		t.Errorf("%d transfers, %d open", len(done), a.Open())
	}

	// An upload segment does not continue a download.
	up := ecatSDOUpFrames()
	states, _ = ecatAsmRun(t, &a, [][]byte{down[0], up[3]})
	if states[1] != EtherCATAssemblyOrphan {
		t.Errorf("upload segment into a download: %v", states[1])
	}
}

func TestECATAsmEoE(t *testing.T) {
	const pending = EtherCATAssemblyPending
	frames := ecatEoEFrames()

	x := ecatAsmOne(t, frames, pending, pending, EtherCATAssemblyComplete, EtherCATAssemblyOrphan)
	if x.Kind != EtherCATTransferEoE || x.Port != 1 || x.FrameNo != 5 || !x.HasTimestamp || x.Timestamp != 0x12345678 ||
		x.Dir != EtherCATFromSlave || !bytes.Equal(x.Data, ecatEoEFrame()) {
		t.Fatalf("frame: %+v", x)
	}

	// The frame comes back as Ethernet.
	if x.NextLayerType() != LayerTypeEthernet {
		t.Fatalf("next layer %v", x.NextLayerType())
	}
	p := gopacket.NewPacket(x.Data, x.NextLayerType(), gopacket.Default)
	arp, ok := p.Layer(LayerTypeARP).(*ARP)
	if !ok || p.ErrorLayer() != nil || !bytes.Equal(arp.DstProtAddress, []byte{169, 254, 93, 66}) {
		t.Errorf("inner frame: %v", p)
	}

	// Out of order: fragment 2 after 0 drops the frame, so 1 is an
	// orphan. A repeated fragment is ignored.
	var a EtherCATMailboxAssembler
	states, done := ecatAsmRun(t, &a, [][]byte{frames[0], frames[2], frames[1], frames[0], frames[1], frames[1], frames[2]})
	ecatSame(t, "statuses", states, []EtherCATAssemblyStatus{
		pending, EtherCATAssemblySequence, EtherCATAssemblyOrphan,
		pending, pending, EtherCATAssemblyDuplicate, EtherCATAssemblyComplete,
	})
	if len(done) != 1 || !bytes.Equal(done[0].Data, ecatEoEFrame()) {
		t.Errorf("after a resend: %+v", done)
	}
}

// TestECATAsmEoEChecks covers the fragment checks that need odd headers.
func TestECATAsmEoEChecks(t *testing.T) {
	var a EtherCATMailboxAssembler
	feed := func(e EtherCATEoE) EtherCATAssemblyStatus {
		_, st := a.FeedMailbox(1, EtherCATFromSlave, &EtherCATMailbox{EoE: &e})
		return st
	}
	block := make([]byte, 32)

	// Fragment 1 must sit at the offset the bytes so far give.
	feed(EtherCATEoE{Data: block})
	if st := feed(EtherCATEoE{FragmentNo: 1, Offset: 64, Data: block}); st != EtherCATAssemblySequence || a.Open() != 0 {
		t.Errorf("wrong offset: %v, %d open", st, a.Open())
	}

	// A fragment of another frame number does not continue this one.
	feed(EtherCATEoE{Data: block})
	if st := feed(EtherCATEoE{FragmentNo: 1, Offset: 32, FrameNo: 1, Data: block}); st != EtherCATAssemblySequence {
		t.Errorf("wrong frame number: %v", st)
	}

	// The other direction has a frame of its own.
	feed(EtherCATEoE{Data: block})
	if _, st := a.FeedMailbox(1, EtherCATToSlave, &EtherCATMailbox{EoE: &EtherCATEoE{FragmentNo: 1, Offset: 32}}); st != EtherCATAssemblyOrphan {
		t.Errorf("other direction: %v", st)
	}

	// No frame grows past the EoE cap, whatever the fragments claim.
	big := make([]byte, ethercatEoEMaxFrame)
	feed(EtherCATEoE{Data: block})
	if st := feed(EtherCATEoE{FragmentNo: 1, Offset: 32, Data: big}); st != EtherCATAssemblyTooLarge || a.Open() != 0 {
		t.Errorf("oversized frame: %v, %d open", st, a.Open())
	}

	// Frames other than fragments are not the assembler's business.
	if st := feed(EtherCATEoE{Type: EtherCATEoESetIPRequest}); st != EtherCATAssemblyNone {
		t.Errorf("set IP request: %v", st)
	}
}

func TestECATAsmFoE(t *testing.T) {
	const pending = EtherCATAssemblyPending
	frames := ecatFoEFrames()

	x := ecatAsmOne(t, frames, pending, pending, pending, pending, pending,
		EtherCATAssemblyDuplicate, pending, EtherCATAssemblyComplete)
	if x.Kind != EtherCATTransferFoE || x.FoEOp != EtherCATFoEWRQ || string(x.FileName) != "fw.bin" ||
		x.Password != 0x12345678 || x.Unfinished || !bytes.Equal(x.Data, ecatFoEFile()) {
		t.Errorf("file: %+v", x)
	}

	// Packet 3 right after packet 1 drops the file.
	var a EtherCATMailboxAssembler
	states, _ := ecatAsmRun(t, &a, [][]byte{frames[0], frames[2], frames[7], frames[4]})
	ecatSame(t, "statuses", states, []EtherCATAssemblyStatus{
		pending, pending, EtherCATAssemblySequence, EtherCATAssemblyOrphan,
	})

	// An error reply ends the transfer; one without a transfer is none
	// of the assembler's business.
	errFrame := ecatFromSlave(EtherCATMailboxFoE, byte(EtherCATFoEERR), 0, 0x03, 0x80, 0, 0)
	states, _ = ecatAsmRun(t, &a, [][]byte{frames[0], frames[2], errFrame, errFrame, frames[1]})
	ecatSame(t, "statuses", states, []EtherCATAssemblyStatus{
		pending, pending, EtherCATAssemblyAborted, EtherCATAssemblyNone, EtherCATAssemblyNone,
	})
}

// TestECATAsmFoEEnd covers the ways a file ends when no short packet
// says so.
func TestECATAsmFoEEnd(t *testing.T) {
	frames := ecatFoEFrames()

	// One full packet: only a flush tells.
	var a EtherCATMailboxAssembler
	ecatAsmRun(t, &a, [][]byte{frames[0], frames[2]})
	if a.FlushFoE(ecatAsmStation+1) != nil {
		t.Error("flush of another station returned a file")
	}
	x := a.FlushFoE(ecatAsmStation)
	if x == nil || !x.Unfinished || len(x.Data) != 16 || string(x.FileName) != "fw.bin" || a.Open() != 0 {
		t.Errorf("flush: %+v", x)
	}
	if a.FlushFoE(ecatAsmStation) != nil {
		t.Error("second flush returned a file")
	}

	// The next request hands back what the previous file left.
	states, done := ecatAsmRun(t, &a, [][]byte{frames[0], frames[2], frames[0]})
	if states[2] != EtherCATAssemblyComplete || len(done) != 1 || !done[0].Unfinished || len(done[0].Data) != 16 || a.Open() != 1 {
		t.Errorf("request after an open file: %v %+v", states, done)
	}

	// With the packet size known a short first packet ends the file,
	// and data without a request still makes one.
	b := EtherCATMailboxAssembler{FoEPacketSize: 16}
	states, done = ecatAsmRun(t, &b, [][]byte{frames[7], frames[2], frames[4], frames[7]})
	ecatSame(t, "statuses", states, []EtherCATAssemblyStatus{
		EtherCATAssemblyOrphan, EtherCATAssemblyPending, EtherCATAssemblyPending, EtherCATAssemblyComplete,
	})
	if len(done) != 1 || done[0].FoEOp != 0 || done[0].FileName != nil || !bytes.Equal(done[0].Data, ecatFoEFile()) {
		t.Errorf("file without request: %+v", done)
	}

	// An empty packet ends a file whose size is a multiple of a packet.
	empty := &EtherCATMailbox{FoE: &EtherCATFoE{OpCode: EtherCATFoEDATA, PacketNo: 1}}
	if x, st := b.FeedMailbox(7, EtherCATToSlave, empty); st != EtherCATAssemblyComplete || len(x.Data) != 0 {
		t.Errorf("empty packet: %v %+v", st, x)
	}
}

func TestECATAsmSoE(t *testing.T) {
	const pending = EtherCATAssemblyPending
	frames := ecatSoEFrames()

	x := ecatAsmOne(t, frames, pending, pending, EtherCATAssemblyComplete)
	if x.Kind != EtherCATTransferSoE || x.SoEOp != EtherCATSoEReadResponse || x.DriveNo != 2 ||
		x.IDN.String() != "S-0-0030" || x.Elements != EtherCATSoEValue || string(x.Data) != "firmware v1.2.3" {
		t.Errorf("element data: %+v", x)
	}

	// A fragment sent twice is ignored.
	var a EtherCATMailboxAssembler
	states, done := ecatAsmRun(t, &a, [][]byte{frames[0], frames[0], frames[1], frames[1], frames[2]})
	ecatSame(t, "statuses", states, []EtherCATAssemblyStatus{
		pending, EtherCATAssemblyDuplicate, pending, EtherCATAssemblyDuplicate, EtherCATAssemblyComplete,
	})
	if len(done) != 1 || string(done[0].Data) != "firmware v1.2.3" {
		t.Errorf("after resends: %+v", done)
	}

	// A skipped fragment drops the transfer.
	states, _ = ecatAsmRun(t, &a, [][]byte{frames[0]})
	skip := &EtherCATMailbox{SoE: &EtherCATSoE{OpCode: EtherCATSoEReadResponse, DriveNo: 2, Incomplete: true}}
	if _, st := a.FeedMailbox(ecatAsmStation, EtherCATFromSlave, skip); st != EtherCATAssemblySequence || a.Open() != 0 || states[0] != pending {
		t.Errorf("fragment count skipping one: %v, %d open", st, a.Open())
	}

	// An error response ends it; requests without data are not followed.
	soe := func(s EtherCATSoE) EtherCATAssemblyStatus {
		_, st := a.FeedMailbox(1, EtherCATFromSlave, &EtherCATMailbox{SoE: &s})
		return st
	}
	soe(EtherCATSoE{OpCode: EtherCATSoEReadResponse, Incomplete: true, FragmentsLeft: 1})
	if st := soe(EtherCATSoE{OpCode: EtherCATSoEReadResponse, Error: true}); st != EtherCATAssemblyAborted {
		t.Errorf("error response: %v", st)
	}
	if st := soe(EtherCATSoE{OpCode: EtherCATSoEReadRequest}); st != EtherCATAssemblyNone {
		t.Errorf("read request: %v", st)
	}

	// Drives are kept apart; another opcode does not continue a transfer.
	soe(EtherCATSoE{OpCode: EtherCATSoEReadResponse, Incomplete: true, FragmentsLeft: 1, DriveNo: 1})
	soe(EtherCATSoE{OpCode: EtherCATSoEReadResponse, Incomplete: true, FragmentsLeft: 1, DriveNo: 2})
	if a.Open() != 2 {
		t.Errorf("%d open, want one per drive", a.Open())
	}
	if st := soe(EtherCATSoE{OpCode: EtherCATSoENotification, DriveNo: 1}); st != EtherCATAssemblySequence {
		t.Errorf("other opcode: %v", st)
	}
}

// ecatSDOInit is a normal initiate download announcing size bytes.
func ecatSDOInit(size uint32, first ...byte) *EtherCATMailbox {
	return &EtherCATMailbox{CoE: &EtherCATCoE{Service: EtherCATCoESDORequest, SDO: &EtherCATSDO{
		Specifier: EtherCATSDOCCSInitiateDownload, SizeIndicated: true, Value: size, Data: first,
	}}}
}

// ecatSegKind says where a download segment stands in its transfer.
type ecatSegKind uint8

const (
	ecatSegEven ecatSegKind = iota // toggle bit clear
	ecatSegOdd                     // toggle bit set
	ecatSegLast                    // toggle bit clear, last segment
)

// ecatSDOSeg is a download segment.
func ecatSDOSeg(kind ecatSegKind, data []byte) *EtherCATMailbox {
	return &EtherCATMailbox{CoE: &EtherCATCoE{Service: EtherCATCoESDORequest, SDO: &EtherCATSDO{
		Segment: true, Toggle: kind == ecatSegOdd, LastSegment: kind == ecatSegLast, Data: data,
	}}}
}

// TestECATAsmLies feeds sizes that claim more or less than is sent.
func TestECATAsmLies(t *testing.T) {
	var a EtherCATMailboxAssembler
	seg := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// 4 GiB announced, 12 bytes sent: the transfer is what arrived.
	a.FeedMailbox(1, EtherCATToSlave, ecatSDOInit(0xffffffff, 9, 9, 9, 9))
	x, st := a.FeedMailbox(1, EtherCATToSlave, ecatSDOSeg(ecatSegLast, seg))
	if st != EtherCATAssemblyComplete || len(x.Data) != 12 || cap(x.Data) > 64 || x.Announced != 0xffffffff {
		t.Errorf("size above the data: %v %+v", st, x)
	}

	// 2 bytes announced, 4 in the mailbox: the mailbox is cut.
	x, st = a.FeedMailbox(1, EtherCATToSlave, ecatSDOInit(2, 9, 8, 7, 6))
	if st != EtherCATAssemblyComplete || !bytes.Equal(x.Data, []byte{9, 8}) {
		t.Errorf("size below the data: %v %+v", st, x)
	}

	// Unused-byte bits above the 7 bytes of a minimum segment cannot
	// reach the decoder (3 bits), and mean nothing in a larger one.
	a.FeedMailbox(1, EtherCATToSlave, ecatSDOInit(100))
	m := ecatSDOSeg(ecatSegLast, seg)
	m.CoE.SDO.UnusedBytes = 7
	if x, _ = a.FeedMailbox(1, EtherCATToSlave, m); x == nil || len(x.Data) != len(seg) {
		t.Errorf("unused bytes in a large segment: %+v", x)
	}

	a.FeedMailbox(1, EtherCATToSlave, ecatSDOInit(100))
	m = ecatSDOSeg(ecatSegLast, seg[:ethercatSDOMinSegment])
	m.CoE.SDO.UnusedBytes = 7
	if x, _ = a.FeedMailbox(1, EtherCATToSlave, m); x == nil || len(x.Data) != 0 {
		t.Errorf("minimum segment without used bytes: %+v", x)
	}

	// Nil input.
	if x, st = a.FeedMailbox(1, EtherCATToSlave, nil); x != nil || st != EtherCATAssemblyNone {
		t.Errorf("nil mailbox: %v", st)
	}
	if x, st = a.Feed(nil); x != nil || st != EtherCATAssemblyNone {
		t.Errorf("nil datagram: %v", st)
	}
	if x, st = a.Feed(&EtherCATDatagram{}); x != nil || st != EtherCATAssemblyNone {
		t.Errorf("datagram without mailbox: %v", st)
	}
}

// TestECATAsmCaps checks the size cap of a transfer and the cap on open
// transfers.
func TestECATAsmCaps(t *testing.T) {
	a := EtherCATMailboxAssembler{MaxBytes: 16, MaxOpen: 4}
	seg := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// 10 + 8 bytes pass the 16-byte cap.
	a.FeedMailbox(1, EtherCATToSlave, ecatSDOInit(100, make([]byte, 10)...))
	if _, st := a.FeedMailbox(1, EtherCATToSlave, ecatSDOSeg(ecatSegEven, seg)); st != EtherCATAssemblyTooLarge || a.Open() != 0 {
		t.Errorf("past the cap: %v, %d open", st, a.Open())
	}
	if _, st := a.FeedMailbox(1, EtherCATToSlave, ecatSDOInit(100, make([]byte, 17)...)); st != EtherCATAssemblyTooLarge || a.Open() != 0 {
		t.Errorf("first bytes past the cap: %v, %d open", st, a.Open())
	}

	// The cap holds for the other protocols too.
	big := make([]byte, 17)
	if _, st := a.FeedMailbox(1, EtherCATToSlave, &EtherCATMailbox{EoE: &EtherCATEoE{Data: big}}); st != EtherCATAssemblyTooLarge {
		t.Errorf("EoE past the cap: %v", st)
	}
	if _, st := a.FeedMailbox(1, EtherCATToSlave, &EtherCATMailbox{FoE: &EtherCATFoE{OpCode: EtherCATFoEDATA, PacketNo: 1, Data: big}}); st != EtherCATAssemblyTooLarge {
		t.Errorf("FoE past the cap: %v", st)
	}
	if _, st := a.FeedMailbox(1, EtherCATToSlave, &EtherCATMailbox{SoE: &EtherCATSoE{OpCode: EtherCATSoEWriteRequest, Data: big}}); st != EtherCATAssemblyTooLarge {
		t.Errorf("SoE past the cap: %v", st)
	}
	name := &EtherCATMailbox{FoE: &EtherCATFoE{OpCode: EtherCATFoERRQ, Data: make([]byte, 100)}}
	a.FeedMailbox(9, EtherCATToSlave, name)
	if x := a.FlushFoE(9); x == nil || len(x.FileName) != 16 {
		t.Errorf("file name past the cap: %+v", x)
	}
	if a.Open() != 0 {
		t.Fatalf("%d open", a.Open())
	}

	// A fifth station evicts the oldest transfer.
	for station := uint16(1); station <= 5; station++ {
		a.FeedMailbox(station, EtherCATToSlave, ecatSDOInit(100, 1))
	}
	if a.Open() != 4 {
		t.Errorf("%d open, cap is 4", a.Open())
	}
	if _, st := a.FeedMailbox(1, EtherCATToSlave, ecatSDOSeg(ecatSegEven, seg)); st != EtherCATAssemblyOrphan {
		t.Errorf("evicted transfer: %v", st)
	}
	if _, st := a.FeedMailbox(2, EtherCATToSlave, ecatSDOSeg(ecatSegEven, seg)); st != EtherCATAssemblyPending {
		t.Errorf("kept transfer: %v", st)
	}

	// Restarting an open transfer evicts nothing.
	a.FeedMailbox(5, EtherCATToSlave, ecatSDOInit(100, 1))
	if _, st := a.FeedMailbox(3, EtherCATToSlave, ecatSDOSeg(ecatSegEven, seg)); st != EtherCATAssemblyPending || a.Open() != 4 {
		t.Errorf("after a restart: %v, %d open", st, a.Open())
	}
}

// TestECATAsmAllocBound checks that a long transfer costs far less than
// one allocation per mailbox and no more memory than twice its bytes.
func TestECATAsmAllocBound(t *testing.T) {
	const segments = 1000
	seg := make([]byte, 100)
	first := ecatSDOInit(0xffffffff, 1)
	even, odd, last := ecatSDOSeg(ecatSegEven, seg), ecatSDOSeg(ecatSegOdd, seg), ecatSDOSeg(ecatSegLast, seg)

	var a EtherCATMailboxAssembler
	var x *EtherCATTransfer
	allocs := testing.AllocsPerRun(10, func() {
		a.FeedMailbox(1, EtherCATToSlave, first)
		for i := 0; i < segments; i += 2 {
			a.FeedMailbox(1, EtherCATToSlave, even)
			a.FeedMailbox(1, EtherCATToSlave, odd)
		}
		x, _ = a.FeedMailbox(1, EtherCATToSlave, last)
	})

	size := 1 + (segments+1)*len(seg)
	if x == nil || len(x.Data) != size || cap(x.Data) > 2*size {
		t.Fatalf("transfer: %d bytes, cap %d, want %d", len(x.Data), cap(x.Data), size)
	}
	if allocs > segments/10 {
		t.Errorf("%v allocations for %d mailboxes", allocs, segments+2)
	}
}

// TestECATAsmCapture runs the assembler over the Beckhoff boot capture.
// tshark shows 20 expedited SDO transfers in these frames (10 downloads
// with ecat_mailbox.coe.sdoccsid.expedited, each captured on its way out
// and back); none is segmented.
func TestECATAsmCapture(t *testing.T) {
	withEtherCAT(t)
	var a EtherCATMailboxAssembler
	done := 0

	for _, e := range decodeECAT(t) {
		for i := range e.Datagrams {
			x, st := a.Feed(&e.Datagrams[i])
			if st == EtherCATAssemblyNone || st == EtherCATAssemblyPending {
				continue
			}
			if st != EtherCATAssemblyComplete || x.Kind != EtherCATTransferSDODownload || x.Announced != 0 || len(x.Data) == 0 {
				t.Fatalf("status %v: %+v", st, x)
			}
			done++
		}
	}
	if done != 20 || a.Open() != 0 {
		t.Errorf("%d transfers, %d open", done, a.Open())
	}
}

// ecatAsmRecords packs the mailboxes of frames for the assembler fuzz
// target: a byte of station and direction, a 2-byte length, the mailbox.
func ecatAsmRecords(frames [][]byte) []byte {
	const mbxStart = 14 + ethercatFrameHeaderLen + ethercatDatagramHeaderLen

	var out []byte
	for _, frame := range frames {
		mbx := frame[mbxStart : len(frame)-ethercatWKCLen]
		dir := byte(0)
		if EtherCATCommand(frame[16]) == EtherCATCommandFPRD {
			dir = 0x80
		}
		out = append(out, dir|1)
		out = binary.LittleEndian.AppendUint16(out, uint16(len(mbx)))
		out = append(out, mbx...)
	}
	return out
}

// FuzzEtherCATAssembler feeds a chain of mailboxes to a small assembler
// and checks its bounds: open transfers, transfer size and no more
// output than input.
func FuzzEtherCATAssembler(f *testing.F) {
	for _, group := range [][][]byte{
		ecatSDODownFrames(), ecatSDOUpFrames(), ecatSDOMiscFrames(),
		ecatEoEFrames(), ecatFoEFrames(), ecatSoEFrames(), ecatAsmFrames(),
	} {
		f.Add(ecatAsmRecords(group))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		const (
			maxBytes = 64
			maxOpen  = 3
			recHead  = 3
		)
		a := EtherCATMailboxAssembler{MaxBytes: maxBytes, MaxOpen: maxOpen}
		if len(data) > 0 {
			a.FoEPacketSize = int(data[0] & 0x1f)
		}
		in, out := len(data), 0

		for len(data) >= recHead {
			station := uint16(data[0] & 0x03)
			dir := EtherCATMailboxDir(data[0] >> 7)
			size := int(binary.LittleEndian.Uint16(data[1:]))
			data = data[recHead:]
			if size > len(data) {
				size = len(data)
			}

			m, err := DecodeEtherCATMailbox(data[:size])
			data = data[size:]
			if err != nil {
				continue
			}

			x, st := a.FeedMailbox(station, dir, m)
			if (x != nil) != (st == EtherCATAssemblyComplete) {
				t.Fatalf("transfer %v with status %v", x != nil, st)
			}
			_ = st.String()
			if a.Open() > maxOpen {
				t.Fatalf("%d transfers open", a.Open())
			}
			if x == nil {
				continue
			}

			if len(x.Data) > maxBytes || len(x.FileName) > maxBytes {
				t.Fatalf("transfer of %d bytes, name of %d", len(x.Data), len(x.FileName))
			}
			out += len(x.Data)
			_ = x.Kind.String()
			_ = x.NextLayerType()
		}

		for station := uint16(0); station <= 3; station++ {
			if x := a.FlushFoE(station); x != nil {
				out += len(x.Data)
			}
		}
		if out > in {
			t.Fatalf("%d bytes out of %d in", out, in)
		}
	})
}
