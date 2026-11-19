// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Reassembly of EtherCAT mailbox transfers that span several mailboxes
// (ETG.1000.6):
//
//	CoE  segmented SDO download and upload
//	        initiate (size, first bytes) -> segment, segment, ... last
//	        the toggle bit flips with every segment, starting at 0
//	EoE  Ethernet frame fragments
//	        fragment 0 (frame size) -> fragment 1 (offset) -> ... last
//	FoE  file data
//	        RRQ/WRQ (name) -> DATA 1 -> DATA 2 -> ... short DATA
//	SoE  IDN element data
//	        incomplete (fragments left) -> ... -> last (IDN)
//
//	datagram --> EtherCATMailbox --> EtherCATMailboxAssembler.Feed
//	                                        |
//	                 one state per station and protocol, bounded
//	                                        |
//	                                 EtherCATTransfer
//
// The assembler sees one side of the wire: it trusts nothing a mailbox
// announces, grows a transfer only by the bytes it receives and caps
// both the size of a transfer and the number of open ones.

package layers

import (
	"fmt"

	"github.com/gopacket/gopacket"
)

// Assembler limits.
const (
	// EtherCATAssemblerMaxBytes is the default cap of one transfer.
	EtherCATAssemblerMaxBytes = 1 << 20

	// EtherCATAssemblerMaxOpen is the default cap of open transfers.
	EtherCATAssemblerMaxOpen = 16

	// ethercatEoEMaxFrame caps a reassembled EoE frame. The 6-bit
	// offset field addresses 63 blocks of 32 bytes; a last fragment of
	// the largest mailbox may follow.
	ethercatEoEMaxFrame = 4096

	// ethercatSDOMinSegment is the segment data size of the smallest
	// mailbox; only then do the size bits count unused bytes.
	ethercatSDOMinSegment = 7
)

// EtherCATMailboxDir is the direction a mailbox travels.
type EtherCATMailboxDir uint8

// Mailbox directions.
const (
	EtherCATToSlave EtherCATMailboxDir = iota
	EtherCATFromSlave
)

// EtherCATTransferKind is the kind of a reassembled transfer.
type EtherCATTransferKind uint8

// Transfer kinds.
const (
	EtherCATTransferSDODownload EtherCATTransferKind = iota + 1
	EtherCATTransferSDOUpload
	EtherCATTransferEoE
	EtherCATTransferFoE
	EtherCATTransferSoE
)

// String returns the kind name.
func (k EtherCATTransferKind) String() string {
	switch k {
	case EtherCATTransferSDODownload:
		return "SDO download"
	case EtherCATTransferSDOUpload:
		return "SDO upload"
	case EtherCATTransferEoE:
		return "EoE frame"
	case EtherCATTransferFoE:
		return "FoE file"
	case EtherCATTransferSoE:
		return "SoE element data"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(k))
}

// EtherCATAssemblyStatus says what the assembler did with a mailbox.
type EtherCATAssemblyStatus uint8

// Assembly results. Only EtherCATAssemblyComplete comes with a transfer.
const (
	// EtherCATAssemblyNone: the mailbox is not part of a transfer.
	EtherCATAssemblyNone EtherCATAssemblyStatus = iota
	// EtherCATAssemblyPending: taken, the transfer goes on.
	EtherCATAssemblyPending
	// EtherCATAssemblyComplete: the transfer is returned.
	EtherCATAssemblyComplete
	// EtherCATAssemblyDuplicate: a repeat of the last fragment or
	// packet, ignored.
	EtherCATAssemblyDuplicate
	// EtherCATAssemblyToggle: an SDO segment with the toggle bit of the
	// previous one, ignored. The transfer stays open.
	EtherCATAssemblyToggle
	// EtherCATAssemblySequence: a fragment or packet out of order. The
	// transfer is dropped.
	EtherCATAssemblySequence
	// EtherCATAssemblyOrphan: a continuation without its start.
	EtherCATAssemblyOrphan
	// EtherCATAssemblyTooLarge: the transfer passed the size cap and is
	// dropped.
	EtherCATAssemblyTooLarge
	// EtherCATAssemblyAborted: an abort or error ended the transfer.
	EtherCATAssemblyAborted
)

// String returns the status name.
func (s EtherCATAssemblyStatus) String() string {
	switch s {
	case EtherCATAssemblyNone:
		return "None"
	case EtherCATAssemblyPending:
		return "Pending"
	case EtherCATAssemblyComplete:
		return "Complete"
	case EtherCATAssemblyDuplicate:
		return "Duplicate"
	case EtherCATAssemblyToggle:
		return "Toggle error"
	case EtherCATAssemblySequence:
		return "Sequence error"
	case EtherCATAssemblyOrphan:
		return "Orphan"
	case EtherCATAssemblyTooLarge:
		return "Too large"
	case EtherCATAssemblyAborted:
		return "Aborted"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(s))
}

// EtherCATTransfer is one finished mailbox transfer. Data is owned by
// the caller. The other fields set depend on Kind:
//
//	SDO download, upload  Index, SubIndex, CompleteAccess, Announced
//	EoE                   Port, FrameNo, Timestamp, HasTimestamp
//	FoE                   FoEOp, FileName, Password, Unfinished
//	SoE                   SoEOp, DriveNo, Elements, IDN
//
// Transfers that fit one mailbox (expedited SDO, single EoE fragment,
// unfragmented SoE) are returned too, so a caller sees every transfer.
type EtherCATTransfer struct {
	Kind    EtherCATTransferKind
	Station uint16
	Dir     EtherCATMailboxDir
	Data    []byte

	// SDO. Announced is the complete size of the initiate service, 0
	// for an expedited transfer; it may differ from len(Data).
	Index          uint16
	SubIndex       uint8
	CompleteAccess bool
	Announced      uint32

	// EoE. The timestamp is the one appended to the last fragment.
	Port         uint8
	FrameNo      uint8
	Timestamp    uint32
	HasTimestamp bool

	// FoE. FoEOp is RRQ or WRQ, or 0 when the request was not seen.
	// Unfinished marks a file whose end was not seen: it was flushed,
	// or cut off by the next request.
	FoEOp      EtherCATFoEOpCode
	FileName   []byte
	Password   uint32
	Unfinished bool

	// SoE.
	SoEOp    EtherCATSoEOpCode
	DriveNo  uint8
	Elements EtherCATSoEElements
	IDN      EtherCATSoEIDN
}

// NextLayerType returns the layer type Data decodes as: LayerTypeEthernet
// for an EoE frame, LayerTypePayload for everything else.
func (t *EtherCATTransfer) NextLayerType() gopacket.LayerType {
	if t.Kind == EtherCATTransferEoE {
		return LayerTypeEthernet
	}
	return gopacket.LayerTypePayload
}

// ethercatSlot separates the transfers one station can have open at the
// same time.
type ethercatSlot uint8

const (
	ethercatSlotSDO ethercatSlot = iota
	ethercatSlotEoE
	ethercatSlotFoE
	ethercatSlotSoE
)

// ethercatXferKey names one open transfer. SDO and FoE dialogues use
// both directions, so their key leaves dir at zero.
type ethercatXferKey struct {
	station uint16
	slot    ethercatSlot
	dir     EtherCATMailboxDir
	drive   uint8
}

// ethercatXfer is the state of one open transfer.
type ethercatXfer struct {
	t      EtherCATTransfer
	toggle bool   // SDO: toggle bit of the next segment
	next   uint32 // EoE: next fragment; FoE: next packet; SoE: fragments left
	full   int    // FoE: size of a full data packet
	age    uint64
}

// EtherCATMailboxAssembler reassembles segmented SDO transfers, EoE
// frames, FoE files and fragmented SoE element data.
//
// The zero value is ready to use. It holds at most MaxOpen transfers of
// at most MaxBytes each; opening one more drops the oldest. It is not
// safe for concurrent use.
type EtherCATMailboxAssembler struct {
	// MaxBytes caps one transfer; 0 means EtherCATAssemblerMaxBytes.
	MaxBytes int
	// MaxOpen caps the open transfers; 0 means EtherCATAssemblerMaxOpen.
	MaxOpen int
	// FoEPacketSize is the data size of a full FoE packet (mailbox size
	// less 12), when known. A shorter packet ends the file. When 0 the
	// first data packet of a file sets it, and a file of one packet
	// only ends by FlushFoE or the next request.
	FoEPacketSize int

	open  map[ethercatXferKey]*ethercatXfer
	clock uint64
}

// Open returns the number of transfers in progress.
func (a *EtherCATMailboxAssembler) Open() int { return len(a.open) }

// Feed hands the mailbox of a datagram to the assembler. The station is
// the datagram's ADP; a write travels to the slave, a read from it. A
// datagram without a mailbox returns EtherCATAssemblyNone.
//
// A capture taken at the master holds every frame twice, on its way out
// and back. The second copy of a fragment reports Duplicate, Toggle or
// Orphan and adds nothing; the second copy of a transfer that fits one
// mailbox, or of the last SoE fragment, cannot be told from a new one
// and is returned again.
func (a *EtherCATMailboxAssembler) Feed(d *EtherCATDatagram) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	if d == nil || d.Mailbox == nil {
		return nil, EtherCATAssemblyNone
	}

	dir := EtherCATToSlave
	switch d.Command {
	case EtherCATCommandAPRD, EtherCATCommandFPRD, EtherCATCommandBRD:
		dir = EtherCATFromSlave
	}
	return a.FeedMailbox(d.ADP(), dir, d.Mailbox)
}

// FeedMailbox hands one mailbox of a station to the assembler. Mailboxes
// must come in capture order. The mailbox data is copied; nothing of it
// is kept.
func (a *EtherCATMailboxAssembler) FeedMailbox(station uint16, dir EtherCATMailboxDir, m *EtherCATMailbox) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	if m == nil {
		return nil, EtherCATAssemblyNone
	}

	switch {
	case m.CoE != nil && m.CoE.SDO != nil:
		return a.feedSDO(station, dir, m.CoE)
	case m.EoE != nil && m.EoE.Type == EtherCATEoEFragment:
		return a.feedEoE(station, dir, m.EoE)
	case m.FoE != nil:
		return a.feedFoE(station, dir, m.FoE)
	case m.SoE != nil:
		return a.feedSoE(station, dir, m.SoE)
	}
	return nil, EtherCATAssemblyNone
}

// FlushFoE ends the open FoE transfer of a station and returns what it
// holds, marked Unfinished. It returns nil when there is none.
func (a *EtherCATMailboxAssembler) FlushFoE(station uint16) *EtherCATTransfer {
	key := ethercatXferKey{station: station, slot: ethercatSlotFoE}
	x := a.open[key]
	if x == nil {
		return nil
	}

	delete(a.open, key)
	x.t.Unfinished = true
	return &x.t
}

// maxBytes returns the size cap of one transfer.
func (a *EtherCATMailboxAssembler) maxBytes() int {
	if a.MaxBytes > 0 {
		return a.MaxBytes
	}
	return EtherCATAssemblerMaxBytes
}

// start opens a transfer under key, replacing the one that was there.
// At the cap it first drops the oldest transfer.
func (a *EtherCATMailboxAssembler) start(key ethercatXferKey, t EtherCATTransfer) *ethercatXfer {
	if a.open == nil {
		a.open = make(map[ethercatXferKey]*ethercatXfer)
	}

	limit := a.MaxOpen
	if limit <= 0 {
		limit = EtherCATAssemblerMaxOpen
	}

	if _, replaces := a.open[key]; !replaces && len(a.open) >= limit {
		a.evict()
	}

	a.clock++
	t.Station = key.station
	x := &ethercatXfer{t: t, age: a.clock}
	a.open[key] = x
	return x
}

// evict drops the transfer opened longest ago. The scan is bounded by
// MaxOpen.
func (a *EtherCATMailboxAssembler) evict() {
	var oldest ethercatXferKey
	var age uint64
	found := false

	for key, x := range a.open {
		if !found || x.age < age {
			oldest, age, found = key, x.age, true
		}
	}
	delete(a.open, oldest)
}

// grow appends data to a transfer. Past the cap it drops the transfer
// and reports false.
func (a *EtherCATMailboxAssembler) grow(key ethercatXferKey, x *ethercatXfer, data []byte) bool {
	if len(x.t.Data)+len(data) > a.maxBytes() {
		delete(a.open, key)
		return false
	}

	x.t.Data = append(x.t.Data, data...)
	return true
}

// finish closes a transfer and returns it.
func (a *EtherCATMailboxAssembler) finish(key ethercatXferKey, x *ethercatXfer) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	delete(a.open, key)
	return &x.t, EtherCATAssemblyComplete
}

// feedSDO follows an SDO dialogue. Download data travels in requests,
// upload data in responses; the other side only acknowledges.
func (a *EtherCATMailboxAssembler) feedSDO(station uint16, dir EtherCATMailboxDir, c *EtherCATCoE) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	s := c.SDO
	key := ethercatXferKey{station: station, slot: ethercatSlotSDO}
	request := c.Service == EtherCATCoESDORequest

	if s.Segment {
		kind := EtherCATTransferSDOUpload
		if request {
			kind = EtherCATTransferSDODownload
		}
		return a.feedSegment(key, kind, s)
	}

	switch {
	case s.Specifier == EtherCATSDOCCSAbort:
		if a.open[key] == nil {
			return nil, EtherCATAssemblyNone
		}
		delete(a.open, key)
		return nil, EtherCATAssemblyAborted
	case request && s.Specifier == EtherCATSDOCCSInitiateDownload:
		return a.initiateSDO(key, dir, EtherCATTransferSDODownload, s)
	case !request && s.Specifier == EtherCATSDOSCSInitiateUpload:
		return a.initiateSDO(key, dir, EtherCATTransferSDOUpload, s)
	}

	// Acknowledgements and upload requests carry no data.
	if a.open[key] == nil {
		return nil, EtherCATAssemblyNone
	}
	return nil, EtherCATAssemblyPending
}

// initiateSDO starts a transfer from the initiate service that carries
// data: expedited data ends it at once, a normal transfer when the
// announced size is there.
func (a *EtherCATMailboxAssembler) initiateSDO(key ethercatXferKey, dir EtherCATMailboxDir, kind EtherCATTransferKind, s *EtherCATSDO) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	x := a.start(key, EtherCATTransfer{
		Kind:           kind,
		Dir:            dir,
		Index:          s.Index,
		SubIndex:       s.SubIndex,
		CompleteAccess: s.CompleteAccess,
	})

	if s.Expedited {
		if !a.grow(key, x, s.ExpeditedData) {
			return nil, EtherCATAssemblyTooLarge
		}
		return a.finish(key, x)
	}

	// A normal transfer: the complete size, then the first bytes.
	x.t.Announced = s.Value
	first := s.Data
	if uint64(len(first)) > uint64(s.Value) {
		first = first[:s.Value]
	}
	if !a.grow(key, x, first) {
		return nil, EtherCATAssemblyTooLarge
	}

	if uint64(len(x.t.Data)) >= uint64(s.Value) {
		return a.finish(key, x)
	}
	return nil, EtherCATAssemblyPending
}

// feedSegment adds a download segment request or upload segment
// response. A segment that repeats the previous toggle bit is a resend
// and is ignored.
func (a *EtherCATMailboxAssembler) feedSegment(key ethercatXferKey, kind EtherCATTransferKind, s *EtherCATSDO) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	x := a.open[key]
	if x == nil || x.t.Kind != kind {
		return nil, EtherCATAssemblyOrphan
	}
	if s.Toggle != x.toggle {
		return nil, EtherCATAssemblyToggle
	}
	x.toggle = !x.toggle

	// The smallest mailbox pads its 7 data bytes; larger ones are full.
	data := s.Data
	if len(data) == ethercatSDOMinSegment {
		data = data[:ethercatSDOMinSegment-int(s.UnusedBytes)]
	}
	if !a.grow(key, x, data) {
		return nil, EtherCATAssemblyTooLarge
	}

	if s.LastSegment {
		return a.finish(key, x)
	}
	return nil, EtherCATAssemblyPending
}

// feedEoE adds an EoE fragment. Fragments of a frame must follow each
// other, each at the byte offset its header names.
func (a *EtherCATMailboxAssembler) feedEoE(station uint16, dir EtherCATMailboxDir, e *EtherCATEoE) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	key := ethercatXferKey{station: station, slot: ethercatSlotEoE, dir: dir}
	x := a.open[key]

	switch {
	case e.FragmentNo == 0:
		// Fragment 0 opens a frame; its offset field is the frame size.
		x = a.start(key, EtherCATTransfer{Kind: EtherCATTransferEoE, Dir: dir, Port: e.Port, FrameNo: e.FrameNo})
	case x == nil:
		return nil, EtherCATAssemblyOrphan
	case e.FrameNo == x.t.FrameNo && uint32(e.FragmentNo)+1 == x.next:
		return nil, EtherCATAssemblyDuplicate
	case e.FrameNo != x.t.FrameNo || uint32(e.FragmentNo) != x.next || int(e.Offset) != len(x.t.Data):
		delete(a.open, key)
		return nil, EtherCATAssemblySequence
	}
	x.next = uint32(e.FragmentNo) + 1

	if len(x.t.Data)+len(e.Data) > ethercatEoEMaxFrame {
		delete(a.open, key)
		return nil, EtherCATAssemblyTooLarge
	}
	if !a.grow(key, x, e.Data) {
		return nil, EtherCATAssemblyTooLarge
	}

	if !e.LastFragment {
		return nil, EtherCATAssemblyPending
	}
	x.t.Timestamp, x.t.HasTimestamp = e.Timestamp, e.HasTimestamp
	return a.finish(key, x)
}

// feedFoE follows an FoE dialogue: a request names the file, numbered
// data packets carry it and a packet shorter than a full one ends it.
func (a *EtherCATMailboxAssembler) feedFoE(station uint16, dir EtherCATMailboxDir, f *EtherCATFoE) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	key := ethercatXferKey{station: station, slot: ethercatSlotFoE}
	x := a.open[key]

	switch f.OpCode {
	case EtherCATFoERRQ, EtherCATFoEWRQ:
		return a.requestFoE(key, dir, f)
	case EtherCATFoEDATA:
		return a.dataFoE(key, dir, f)
	case EtherCATFoEERR:
		if x == nil {
			return nil, EtherCATAssemblyNone
		}
		delete(a.open, key)
		return nil, EtherCATAssemblyAborted
	}

	// ACK and BUSY carry no file data.
	if x == nil {
		return nil, EtherCATAssemblyNone
	}
	return nil, EtherCATAssemblyPending
}

// requestFoE opens a file transfer. Data left from the previous file,
// whose end was not seen, is returned as an unfinished transfer.
func (a *EtherCATMailboxAssembler) requestFoE(key ethercatXferKey, dir EtherCATMailboxDir, f *EtherCATFoE) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	old := a.open[key]

	name := f.Data
	if len(name) > a.maxBytes() {
		name = name[:a.maxBytes()]
	}

	x := a.start(key, EtherCATTransfer{
		Kind:     EtherCATTransferFoE,
		Dir:      dir,
		FoEOp:    f.OpCode,
		FileName: append([]byte(nil), name...),
		Password: f.Password,
	})
	x.next = 1

	if old == nil || len(old.t.Data) == 0 {
		return nil, EtherCATAssemblyPending
	}
	old.t.Unfinished = true
	return &old.t, EtherCATAssemblyComplete
}

// dataFoE adds a data packet. Packet 1 may open a transfer whose
// request was not captured.
func (a *EtherCATMailboxAssembler) dataFoE(key ethercatXferKey, dir EtherCATMailboxDir, f *EtherCATFoE) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	x := a.open[key]
	if x == nil {
		if f.PacketNo != 1 {
			return nil, EtherCATAssemblyOrphan
		}
		x = a.start(key, EtherCATTransfer{Kind: EtherCATTransferFoE, Dir: dir})
		x.next = 1
	}

	switch {
	case f.PacketNo+1 == x.next && x.next > 1:
		return nil, EtherCATAssemblyDuplicate
	case f.PacketNo != x.next:
		delete(a.open, key)
		return nil, EtherCATAssemblySequence
	}
	x.next++

	if !a.grow(key, x, f.Data) {
		return nil, EtherCATAssemblyTooLarge
	}

	// The first packet of a file is a full one unless the caller knows
	// better.
	if x.full == 0 {
		x.full = a.FoEPacketSize
	}
	if x.full == 0 {
		x.full = len(f.Data)
		if x.full > 0 {
			return nil, EtherCATAssemblyPending
		}
	}

	if len(f.Data) < x.full || len(f.Data) == 0 {
		return a.finish(key, x)
	}
	return nil, EtherCATAssemblyPending
}

// feedSoE adds SoE element data. Only the services that carry data are
// followed: read responses, write requests and notifications. While the
// incomplete bit is set the header counts the fragments left; the last
// fragment names the IDN.
func (a *EtherCATMailboxAssembler) feedSoE(station uint16, dir EtherCATMailboxDir, s *EtherCATSoE) (*EtherCATTransfer, EtherCATAssemblyStatus) {
	switch s.OpCode {
	case EtherCATSoEReadResponse, EtherCATSoEWriteRequest, EtherCATSoENotification:
	default:
		return nil, EtherCATAssemblyNone
	}

	key := ethercatXferKey{station: station, slot: ethercatSlotSoE, dir: dir, drive: s.DriveNo}
	x := a.open[key]

	if s.Error {
		if x == nil {
			return nil, EtherCATAssemblyNone
		}
		delete(a.open, key)
		return nil, EtherCATAssemblyAborted
	}

	switch {
	case x == nil:
		x = a.start(key, EtherCATTransfer{Kind: EtherCATTransferSoE, Dir: dir, SoEOp: s.OpCode, DriveNo: s.DriveNo})
	case x.t.SoEOp == s.OpCode && s.Incomplete && uint32(s.FragmentsLeft) == x.next:
		// The count has to fall, so the same count is a resend.
		return nil, EtherCATAssemblyDuplicate
	case x.t.SoEOp != s.OpCode, s.Incomplete && uint32(s.FragmentsLeft)+1 != x.next:
		delete(a.open, key)
		return nil, EtherCATAssemblySequence
	}

	if !a.grow(key, x, s.Data) {
		return nil, EtherCATAssemblyTooLarge
	}

	if s.Incomplete {
		x.next = uint32(s.FragmentsLeft)
		return nil, EtherCATAssemblyPending
	}
	x.t.IDN, x.t.Elements = s.IDN, s.Elements
	return a.finish(key, x)
}
