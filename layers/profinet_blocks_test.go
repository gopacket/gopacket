// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"sort"
	"testing"

	"github.com/gopacket/gopacket"
)

// profinet-blocks.pcap holds 84 hand-built frames, one or more blocks
// each: records in read responses and write requests, the optional blocks
// of connect, and alarms. Their values were compared with tshark 4.7.
//
//	 1-16  I&M0-5, I&M0FilterData, identification, diagnosis, assets
//	17-35  PDev: port, interface, IRT, fiber optic, fast start up
//	36-47  MRP, versions 1.0 and 1.1
//	48-50  MultipleBlockHeader, CombinedObjectContainer, PDevData
//	51-64  ARData, log book, IO data records, PROFIenergy
//	65-70  optional connect blocks, SubmoduleListBlock, ARUUIDBlock
//	71-79  reporting system records and alarms, a multiple alarm item
//	80-84  NME and CIM records
const pnBlocksPcap = "testdata/profinet-blocks.pcap"

const pnBlocksFrames = 84

// pnGoldenMax bounds a golden string; longer values compare by prefix.
const pnGoldenMax = 300

// pnGolden formats a block value for the golden table.
func pnGolden(v interface{}) string {
	s := fmt.Sprintf("%+v", v)
	if len(s) > pnGoldenMax {
		return s[:pnGoldenMax]
	}
	return s
}

// pnTopBlocks returns the blocks of the RPC body or of the alarm of a
// packet.
func pnTopBlocks(p gopacket.Packet) []ProfinetBlock {
	if r, ok := p.Layer(LayerTypeProfinetIORPC).(*ProfinetIORPC); ok {
		return r.Blocks
	}
	if a, ok := p.Layer(LayerTypeProfinetAlarm).(*ProfinetAlarm); ok && a.Block != nil {
		return []ProfinetBlock{*a.Block}
	}
	return nil
}

// pnWalkBlocks visits every block: nested ones, record data and the
// blocks of alarm items.
func pnWalkBlocks(blocks []ProfinetBlock, visit func(*ProfinetBlock)) {
	for i := range blocks {
		b := &blocks[i]
		visit(b)
		pnWalkBlocks(b.Blocks, visit)

		if b.Record != nil {
			pnWalkBlocks(b.Record.Blocks, visit)
		}
		if b.Alarm == nil {
			continue
		}
		for j := range b.Alarm.Items {
			pnWalkBlocks(b.Alarm.Items[j].Blocks, visit)
		}
	}
}

// pnBlockDepth returns the deepest nesting below blocks.
func pnBlockDepth(blocks []ProfinetBlock) int {
	depth := 0
	for i := range blocks {
		if d := 1 + pnBlockDepth(blocks[i].Blocks); d > depth {
			depth = d
		}
	}
	return depth
}

// pnBlockVer builds a block of version 1.low.
func pnBlockVer(typ ProfinetBlockType, low uint8, body ...byte) []byte {
	b := pnBlock(typ, body...)
	b[5] = low
	return b
}

func TestProfinetBlocksPcap(t *testing.T) {
	withProfinet(t)

	frames := readPNECATPcap(t, pnBlocksPcap)
	if len(frames) != pnBlocksFrames {
		t.Fatalf("got %d frames, want %d", len(frames), pnBlocksFrames)
	}

	typed := map[ProfinetBlockType]bool{}
	for i, data := range frames {
		p := gopacket.NewPacket(data, LinkTypeEthernet, gopacket.Default)
		if el := p.ErrorLayer(); el != nil {
			t.Fatalf("frame %d: %v", i+1, el.Error())
		}

		blocks := pnTopBlocks(p)
		if len(blocks) == 0 {
			t.Fatalf("frame %d: no blocks", i+1)
		}

		// Nothing in the capture is header-only or clipped.
		pnWalkBlocks(blocks, func(b *ProfinetBlock) {
			typed[b.Type] = true
			if !b.Decoded() || b.Clipped() {
				t.Errorf("frame %d: %v version 1.%d not decoded", i+1, b.Type, b.VersionLow)
			}
		})
	}

	if len(typed) < 120 {
		t.Errorf("%d block types in the capture, want at least 120", len(typed))
	}
}

func TestProfinetBlockValues(t *testing.T) {
	withProfinet(t)
	frames := readPNECATPcap(t, pnBlocksPcap)

	for _, test := range pnBlockGolden {
		p := gopacket.NewPacket(frames[test.frame-1], LinkTypeEthernet, gopacket.Default)

		var got string
		pnWalkBlocks(pnTopBlocks(p), func(b *ProfinetBlock) {
			if got == "" && b.Type == test.typ && b.VersionLow == test.low && b.Value != nil {
				got = pnGolden(b.Value)
			}
		})
		if got != test.want {
			t.Errorf("frame %d %v 1.%d:\n got %s\nwant %s", test.frame, test.typ, test.low, got, test.want)
		}
	}
}

// TestProfinetBlockAccessors checks the bit fields the golden strings do
// not show.
func TestProfinetBlockAccessors(t *testing.T) {
	props := ProfinetARProperties(0x38000A19)
	if !props.SupervisorTakeoverAllowed() || !props.ParameterizationServer() || props.CompanionAR() != 1 ||
		!props.AcknowledgeCompanionAR() || !props.RejectDCPSetRequests() || !props.TimeAwareSystem() ||
		!props.CombinedObjectContainer() {
		t.Errorf("AR properties 0x%08x", uint32(props))
	}

	sub := ProfinetSubmoduleProperties(0x003E)
	if sub.Type() != 2 || !sub.SharedInput() || !sub.ReduceInputLength() || !sub.ReduceOutputLength() || !sub.DiscardIOXS() {
		t.Errorf("submodule properties 0x%04x", uint16(sub))
	}

	// Format 1, IdentInfo wrong (2), ARInfo locked by controller (3), fault.
	state := ProfinetSubmoduleState(0x9000 | 3<<7 | 0x40 | 0x1)
	if !state.FormatIndicator() || state.IdentInfo() != 2 || state.ARInfo() != 3 || !state.Fault() ||
		state.Advice() || state.MaintenanceRequired() || state.MaintenanceDemanded() || state.AddInfo() != 1 {
		t.Errorf("submodule state 0x%04x", uint16(state))
	}
	if ProfinetModuleWrong.String() != "Wrong module" || ProfinetModuleState(9).String() != "Reserved(0x0009)" {
		t.Error("module state names")
	}

	tag := ProfinetTagHeader(0xC123)
	if tag.VLANID() != 0x123 || tag.UserPriority() != 6 {
		t.Errorf("tag header: VLAN 0x%x priority %d", tag.VLANID(), tag.UserPriority())
	}

	iops := ProfinetIOxS(0x41)
	if iops.Good() || iops.Instance() != 2 || !iops.Extension() {
		t.Errorf("IOxS 0x%02x", uint8(iops))
	}

	// ARUUID of a system redundancy AR: AR number 2, resource 2.
	uuid := ProfinetUUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0x00, 0x12}
	if !bytes.Equal(uuid.Discriminator(), []byte{1, 2, 3, 4, 5, 6}) || len(uuid.ConfigID()) != 8 ||
		uuid.Selector().ARNumber() != 2 || uuid.Selector().ARResource() != 2 {
		t.Errorf("ARUUID split: selector 0x%04x", uint16(uuid.Selector()))
	}

	spec := ProfinetRSSpecifier(0x8123)
	if spec.SequenceNumber() != 0x123 || spec.Specifier() != 2 {
		t.Errorf("RS specifier 0x%04x", uint16(spec))
	}
	if ProfinetRSDigitalInputObserver.String() != "Digital input observer" || ProfinetRSBlockType(0x10).String() != "Manufacturer specific(0x0010)" {
		t.Error("RS block type names")
	}

	// Level tree: levels 0x005, 0x302, 0x300, the rest unused.
	tree := ProfinetAMLocation{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF0, 0x0C, 0x08, 0x05, 0x01}
	if l := tree.Levels(); tree.Structure() != 1 || l[0] != 0x005 || l[1] != 0x302 || l[2] != 0x300 || l[11] != 0x3FF {
		t.Errorf("AM location levels %v", l)
	}

	slots := ProfinetAMLocation{0, 0, 0, 0, 0, 0, 0x80, 0x02, 0, 3, 0x80, 0x01, 0, 2, 0, 2}
	if slots.BeginSlot() != 2 || slots.BeginSubslot() != 0x8001 || slots.EndSlot() != 3 || slots.EndSubslot() != 0x8002 {
		t.Errorf("AM location slots %v", slots)
	}

	sf := ProfinetSubframeData(0x0000050C)
	if sf.Position() != 12 || sf.DataLength() != 5 {
		t.Errorf("subframe data 0x%08x", uint32(sf))
	}
}

func TestProfinetStatusNames(t *testing.T) {
	for _, test := range []struct {
		status       ProfinetPNIOStatus
		code1, code2 string
	}{
		{ProfinetPNIOStatus{}, "", ""},
		{ProfinetPNIOStatus{ProfinetErrorCodeRead, ProfinetErrorDecodePNIORW, 0xB0, 0}, "Access: invalid index", ""},
		{ProfinetPNIOStatus{ProfinetErrorCodeWrite, ProfinetErrorDecodePNIORW, 0xAC, 0}, "Application: user specific", ""},
		{ProfinetPNIOStatus{ProfinetErrorCodeWrite, ProfinetErrorDecodePNIORW, 0x10, 0}, "", ""},
		{ProfinetPNIOStatus{ProfinetErrorCodeConnect, ProfinetErrorDecodePNIO, 1, 1}, "Connect: faulty ARBlockReq", "BlockLength"},
		{ProfinetPNIOStatus{ProfinetErrorCodeConnect, ProfinetErrorDecodePNIO, 2, 6}, "Connect: faulty IOCRBlockReq", "Field 3 of the block"},
		{ProfinetPNIOStatus{ProfinetErrorCodeConnect, ProfinetErrorDecodePNIO, 30, 1}, "", ""},
		{ProfinetPNIOStatus{ProfinetErrorCodeConnect, ProfinetErrorDecodePNIO, 64, 5}, "CMRPC", "Out of AR resources"},
		{ProfinetPNIOStatus{ProfinetErrorCodeConnect, ProfinetErrorDecodePNIO, 64, 200}, "CMRPC", ""},
		{ProfinetPNIOStatus{ProfinetErrorCodeRTA, ProfinetErrorDecodePNIO, 253, 5}, "RTA protocol error", "AR consumer DHT or WDT expired"},
		{ProfinetPNIOStatus{ProfinetErrorCodeRTA, ProfinetErrorDecodePNIO, 253, 0}, "RTA protocol error", ""},
		{ProfinetPNIOStatus{ProfinetErrorCodeRTA, ProfinetErrorDecodeManufacturer, 1, 1}, "", ""},
	} {
		if got := test.status.Code1Name(); got != test.code1 {
			t.Errorf("%v: ErrorCode1 %q, want %q", test.status, got, test.code1)
		}
		if got := test.status.Code2Name(); got != test.code2 {
			t.Errorf("%v: ErrorCode2 %q, want %q", test.status, got, test.code2)
		}
	}
}

// TestProfinetBlockVersions: a version the standard does not define
// leaves the block header-only, never half decoded.
func TestProfinetBlockVersions(t *testing.T) {
	body := make([]byte, 400)

	for _, test := range []struct {
		typ  ProfinetBlockType
		low  uint8
		want bool
	}{
		{ProfinetBlockDiagnosisData, 0, true},
		{ProfinetBlockDiagnosisData, 1, true},
		{ProfinetBlockDiagnosisData, 2, false},
		{ProfinetBlockRealIdent, 1, true},
		{ProfinetBlockRealIdent, 2, false},
		{ProfinetBlockIM0, 1, false},
		{ProfinetBlockARData, 1, true},
		{ProfinetBlockARData, 2, false},
		{ProfinetBlockPDSyncData, 2, true},
		{ProfinetBlockPDSyncData, 0, false},
		{ProfinetBlockPDIRGlobalData, 2, true},
		{ProfinetBlockPDIRGlobalData, 3, false},
		{ProfinetBlockPDIRFrameData, 1, true},
		{ProfinetBlockPDPortStatistic, 1, true},
		{ProfinetBlockPDPortStatistic, 2, false},
		{ProfinetBlockAdjDomainBoundary, 1, true},
		{ProfinetBlockAdjDomainBoundary, 2, false},
		{ProfinetBlockPDIfMrpReal, 1, true},
		{ProfinetBlockPDIfMrpReal, 2, false},
		{ProfinetBlockLogBookData, 1, false},
		{ProfinetBlockRSGetEvent, 1, false},
		{ProfinetBlockCIMDCPReal, 1, false},
	} {
		blocks, err := ProfinetDecodeBlocks(pnBlockVer(test.typ, test.low, body...))
		if err != nil || len(blocks) != 1 {
			t.Fatalf("%v 1.%d: %v", test.typ, test.low, err)
		}
		if got := blocks[0].Decoded(); got != test.want {
			t.Errorf("%v 1.%d: decoded %v, want %v", test.typ, test.low, got, test.want)
		}
	}

	// VersionHigh other than 1 is never decoded.
	b := pnBlock(ProfinetBlockIM0, body...)
	b[4] = 2
	if blocks, _ := ProfinetDecodeBlocks(b); len(blocks) != 1 || blocks[0].Decoded() {
		t.Error("version 2.0 decoded")
	}
}

// TestProfinetRecordDispatch: record data is decoded as blocks for the
// indexes that hold blocks and stays raw for user records.
func TestProfinetRecordDispatch(t *testing.T) {
	im1 := pnBlock(ProfinetBlockIM1, bytes.Repeat([]byte{'x'}, profinetIM1Len)...)

	for _, test := range []struct {
		index  ProfinetRecordIndex
		blocks int
	}{
		{ProfinetIndexIM1, 1},
		{ProfinetRecordIndex(0x0001), 0}, // user specific
		{ProfinetRecordIndex(0xB000), 0}, // profile specific
	} {
		head := make([]byte, profinetRecordHeadLen+24)
		binary.BigEndian.PutUint16(head[profinetRecordIndexOff:], uint16(test.index))
		binary.BigEndian.PutUint32(head[profinetRecordLengthOff:], uint32(len(im1)))

		data := append(pnBlock(ProfinetBlockIODWriteReq, head...), im1...)
		blocks, err := ProfinetDecodeBlocks(data)
		if err != nil || len(blocks) != 1 || blocks[0].Record == nil {
			t.Fatalf("index %v: %v, %d blocks", test.index, err, len(blocks))
		}

		rec := blocks[0].Record
		if rec.Index != test.index || len(rec.Blocks) != test.blocks || !bytes.Equal(rec.Data, im1) {
			t.Errorf("index %v: %d blocks, want %d", test.index, len(rec.Blocks), test.blocks)
		}
		if test.index.HoldsBlocks() != (test.blocks > 0) {
			t.Errorf("index %v: HoldsBlocks %v", test.index, test.index.HoldsBlocks())
		}
	}

	if !ProfinetRecordIndex(0x0001).IsUser() || !ProfinetRecordIndex(0xB000).IsProfile() || ProfinetIndexIM1.String() == "" {
		t.Error("record index classes")
	}
}

// TestProfinetBlockNesting: containers nest no deeper than the cap, and a
// chain of 200 containers costs no recursion beyond it.
func TestProfinetBlockNesting(t *testing.T) {
	for _, typ := range []ProfinetBlockType{ProfinetBlockPDevData, ProfinetBlockARFSU, ProfinetBlockIM5, ProfinetBlockRecordOutput} {
		// Each container holds the previous one behind two bytes of head;
		// RecordOutputDataObjectElement needs eight.
		head := 2
		if typ == ProfinetBlockRecordOutput {
			head = profinetRecordOutputMin
		}

		data := pnBlock(ProfinetBlockIM1, make([]byte, profinetIM1Len)...)
		for i := 0; i < 200; i++ {
			data = pnBlock(typ, append(make([]byte, head), data...)...)
		}

		blocks, err := ProfinetDecodeBlocks(data)
		if err != nil || len(blocks) != 1 {
			t.Fatalf("%v: %v", typ, err)
		}
		if depth := pnBlockDepth(blocks); depth > int(profinetMaxDepth)+1 {
			t.Errorf("%v: nested %d deep, cap %d", typ, depth, profinetMaxDepth+1)
		}
	}

	// A multiple alarm item inside a record inside a container stays
	// within the cap too.
	item := append([]byte{0x80, 0x01}, pnBlockVer(ProfinetBlockDiagnosisData, 1, make([]byte, 12)...)...)
	alarm := pnBlock(ProfinetBlockAlarmLow, append(make([]byte, profinetAlarmHeadLen), item...)...)
	for i := 0; i < 20; i++ {
		alarm = pnBlock(ProfinetBlockPDevData, append([]byte{0, 0}, alarm...)...)
	}
	if blocks, err := ProfinetDecodeBlocks(alarm); err != nil || pnBlockDepth(blocks) > int(profinetMaxDepth)+1 {
		t.Errorf("alarm in containers: %v", err)
	}
}

// TestProfinetBlocksTruncation decodes every prefix of every body of the
// capture, and every body with one byte at a time set to 0x00 and 0xFF,
// which makes each length and count lie in turn.
func TestProfinetBlocksTruncation(t *testing.T) {
	withProfinet(t)

	for _, frame := range readPNECATPcap(t, pnBlocksPcap) {
		p := gopacket.NewPacket(frame, LinkTypeEthernet, gopacket.Default)

		var body []byte
		if r, ok := p.Layer(LayerTypeProfinetIORPC).(*ProfinetIORPC); ok {
			body = r.LayerContents()[profinetRPCHeaderLen:]
		}
		if a, ok := p.Layer(LayerTypeProfinetAlarm).(*ProfinetAlarm); ok {
			body = a.LayerPayload()
		}

		for n := 0; n <= len(body); n++ {
			data := append([]byte(nil), body[:n]...)
			_ = (&ProfinetIORPC{}).DecodeFromBytes(data, gopacket.NilDecodeFeedback)
			pnDecodeAnywhere(t, data)
		}

		for i := range body {
			for _, v := range []byte{0x00, 0xFF} {
				data := append([]byte(nil), body...)
				data[i] = v
				pnDecodeAnywhere(t, data)
			}
		}
	}
}

// pnDecodeAnywhere decodes data as a block list from every offset that
// could start a block of the RPC body: the NDR header shifts the blocks
// by 20 bytes in requests and responses.
func pnDecodeAnywhere(t *testing.T, data []byte) {
	for _, off := range []int{0, profinetNDRHeaderLen} {
		if off > len(data) {
			continue
		}

		blocks, err := ProfinetDecodeBlocks(data[off:])
		if err == nil && len(blocks) != countProfinetBlocks(data[off:]) {
			t.Fatalf("counted %d blocks, decoded %d", countProfinetBlocks(data[off:]), len(blocks))
		}
	}
}

// pnAllocPerByte is allocPerByte for one block list, without the
// collection that makes it slow over thousands of inputs: TotalAlloc
// only grows.
func pnAllocPerByte(data []byte) float64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _ = ProfinetDecodeBlocks(data)
	runtime.ReadMemStats(&after)
	return float64(after.TotalAlloc-before.TotalAlloc) / float64(len(data))
}

// TestProfinetBlockAllocs: no block type allocates more than a bounded
// number of bytes per input byte, whatever its counts and lengths claim.
func TestProfinetBlockAllocs(t *testing.T) {
	const maxPerByte = 64
	const bodyLen = 60000

	// Bodies of all ones (every count at its maximum), of zeroes (every
	// string and list empty, so elements are as short as they get) and of
	// small counts.
	fills := map[string][]byte{
		"ones":   bytes.Repeat([]byte{0xFF}, bodyLen),
		"zeroes": make([]byte, bodyLen),
		"small":  bytes.Repeat([]byte{0x00, 0x01}, bodyLen/2),
		"mixed":  bytes.Repeat([]byte{0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x08}, bodyLen/8),
	}

	var types []int
	for typ := range profinetBlockNames {
		types = append(types, int(typ))
	}
	sort.Ints(types)

	for _, typ := range types {
		for low := uint8(0); low <= 2; low++ {
			for name, fill := range fills {
				data := pnBlockVer(ProfinetBlockType(typ), low, fill...)
				got := pnAllocPerByte(data)
				if got > maxPerByte {
					t.Errorf("%v 1.%d %s: %.0f bytes per input byte, want <= %d", ProfinetBlockType(typ), low, name, got, maxPerByte)
				}
			}
		}
	}

	// Containers full of the smallest blocks, nested to the cap.
	inner := bytes.Repeat(pnBlock(ProfinetBlockType(0x7F00)), 9000)
	for i := 0; i < 8; i++ {
		inner = pnBlock(ProfinetBlockPDevData, append([]byte{0, 0}, inner...)...)
	}

	// Reporting system: events whose extensions are all empty.
	event := append(make([]byte, profinetRSEventFixedLen), bytes.Repeat([]byte{0x80, 0x00}, 100)...)
	event = pnBlock(ProfinetBlockType(ProfinetRSDigitalInputObserver), event...)
	events := pnBlock(ProfinetBlockRSGetEvent, append([]byte{0xFF, 0xFF}, bytes.Repeat(event, 200)...)...)

	// A multiple alarm item full of empty diagnosis blocks.
	item := append([]byte{0x80, 0x01}, bytes.Repeat(pnBlockVer(ProfinetBlockDiagnosisData, 1), 9000)...)
	alarm := pnBlock(ProfinetBlockAlarmLow, append(make([]byte, profinetAlarmHeadLen), item...)...)

	for name, data := range map[string][]byte{"nested containers": inner, "RS events": events, "multiple alarm item": alarm} {
		got := allocPerByte(len(data), func() {
			_, _ = ProfinetDecodeBlocks(data)
		})
		t.Logf("PROFINET %s: %.0f bytes per input byte", name, got)
		if got > maxPerByte {
			t.Errorf("%s: %.0f bytes per input byte, want <= %d", name, got, maxPerByte)
		}
	}
}

// pnBlockGolden holds the decoded value of the first block of each type
// and version in the capture, as %+v prints it.
var pnBlockGolden = []struct {
	frame int
	typ   ProfinetBlockType
	low   uint8
	want  string
}{
	{1, 0x0020, 0, "&{VendorID:298 OrderID:6ES7 123-4AB56-7CD0  SerialNumber:SN-0123456789    HardwareRevision:773 SoftwareRevision:{Prefix:86 FunctionalEnhancement:4 BugFix:5 InternalChange:6} RevisionCounter:258 ProfileID:62976 ProfileSpecificType:3 VersionMajor:1 VersionMinor:1 Supported:30}"},
	{2, 0x0021, 0, "&{TagFunction:function tag                     TagLocation:location tag          }"},
	{3, 0x0022, 0, "&{Date:2026-11-20 10:30}"},
	{4, 0x0023, 0, "&{Descriptor:descriptor text                                       }"},
	{5, 0x0024, 0, "&{Signature:[1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54]}"},
	{6, 0x0025, 0, "&{NumberOfEntries:2}"},
	{6, 0x0034, 0, "&{Annotation:annotation                                                       OrderID:order-id                                                         VendorID:298 SerialNumber:SER-777          HardwareRevision:9 SoftwareRevision:{Prefix:86 FunctionalEnhancement:7 BugFix:8 InternalChange:9}}"},
	{7, 0x0030, 0, "&{APIs:[{API:4660 Modules:[{Slot:0 ModuleIdentNumber:257 Submodules:[{Subslot:1 SubmoduleIdentNumber:513} {Subslot:32768 SubmoduleIdentNumber:514}]} {Slot:3 ModuleIdentNumber:259 Submodules:[{Subslot:1 SubmoduleIdentNumber:769}]}]}]}"},
	{7, 0x0031, 0, "&{APIs:[{API:4660 Modules:[{Slot:0 ModuleIdentNumber:257 Submodules:[{Subslot:1 SubmoduleIdentNumber:513} {Subslot:32768 SubmoduleIdentNumber:514}]} {Slot:3 ModuleIdentNumber:259 Submodules:[{Subslot:1 SubmoduleIdentNumber:769}]}]}]}"},
	{7, 0x0032, 0, "&{APIs:[{API:4660 Modules:[{Slot:0 ModuleIdentNumber:257 Submodules:[{Subslot:1 SubmoduleIdentNumber:513} {Subslot:32768 SubmoduleIdentNumber:514}]} {Slot:3 ModuleIdentNumber:259 Submodules:[{Subslot:1 SubmoduleIdentNumber:769}]}]}]}"},
	{8, 0x0013, 0, "&{APIs:[{API:0 Modules:[{Slot:0 ModuleIdentNumber:257 Submodules:[{Subslot:1 SubmoduleIdentNumber:513} {Subslot:32768 SubmoduleIdentNumber:514}]} {Slot:3 ModuleIdentNumber:259 Submodules:[{Subslot:1 SubmoduleIdentNumber:769}]}]}]}"},
	{9, 0x0013, 1, "&{APIs:[{API:4660 Modules:[{Slot:0 ModuleIdentNumber:257 Submodules:[{Subslot:1 SubmoduleIdentNumber:513} {Subslot:32768 SubmoduleIdentNumber:514}]} {Slot:3 ModuleIdentNumber:259 Submodules:[{Subslot:1 SubmoduleIdentNumber:769}]}]}]}"},
	{10, 0x0012, 0, "&{APIs:[{API:0 Modules:[{Slot:0 ModuleIdentNumber:257 Submodules:[{Subslot:1 SubmoduleIdentNumber:513} {Subslot:32768 SubmoduleIdentNumber:514}]} {Slot:3 ModuleIdentNumber:259 Submodules:[{Subslot:1 SubmoduleIdentNumber:769}]}]}]}"},
	{11, 0x0012, 1, "&{APIs:[{API:4660 Modules:[{Slot:0 ModuleIdentNumber:257 Submodules:[{Subslot:1 SubmoduleIdentNumber:513} {Subslot:32768 SubmoduleIdentNumber:514}]} {Slot:3 ModuleIdentNumber:259 Submodules:[{Subslot:1 SubmoduleIdentNumber:769}]}]}]}"},
	{12, 0x0010, 0, "&{API:0 Slot:1 Subslot:2 ChannelNumber:32768 ChannelProperties:2048 USI:ChannelDiagnosis Channels:[{ChannelNumber:4 ChannelProperties:10759 ChannelErrorType:Line break ExtChannelErrorType:0 ExtChannelAddValue:0 QualifiedChannelQualifier:0x00000000} {ChannelNumber:4 ChannelProperties:10759 ChannelErr"},
	{13, 0x0010, 1, "&{API:119 Slot:1 Subslot:2 ChannelNumber:32768 ChannelProperties:2048 USI:ExtChannelDiagnosis Channels:[{ChannelNumber:5 ChannelProperties:19457 ChannelErrorType:Remote mismatch ExtChannelErrorType:32772 ExtChannelAddValue:3735928559 QualifiedChannelQualifier:0x00000000} {ChannelNumber:5 ChannelProp"},
	{16, 0x0035, 0, "&{NumberOfEntries:3}"},
	{16, 0x0036, 0, "&{UniqueIdentifier:50515253-5455-5657-5859-5a5b5c5d5e5f Location:[255 255 255 255 255 255 255 255 255 255 255 240 12 8 5 1] Annotation:asset annotation                                                 OrderID:asset order                                                      SoftwareRevision:sw rev 1.2"},
	{16, 0x0037, 0, "&{UniqueIdentifier:60616263-6465-6667-6869-6a6b6c6d6e6f Location:[0 0 0 0 0 0 128 2 0 3 128 1 0 2 0 2] Annotation:hw annotation                                                    OrderID:hw order                                                         SoftwareRevision: HardwareRevision:hw rev D     "},
	{16, 0x0038, 0, "&{UniqueIdentifier:50515253-5455-5657-5859-5a5b5c5d5e5f Location:[255 255 255 255 255 255 255 255 255 255 255 240 12 8 5 1] Annotation:asset annotation                                                 OrderID:asset order                                                      SoftwareRevision:fw rev 9  "},
	{17, 0x0200, 0, "&{Slot:0 Subslot:32769}"},
	{17, 0x020A, 0, "&{Peers:[{PortID:port-002 ChassisID:switch0} {PortID:port-003 ChassisID:switch1}]}"},
	{17, 0x020B, 0, "&{LineDelay:2147486396}"},
	{17, 0x020C, 0, "&{Value:16}"},
	{17, 0x021C, 0, "&{Value:1}"},
	{17, 0x021E, 0, "&{Value:3}"},
	{17, 0x021F, 0, "&{Value:1}"},
	{17, 0x0227, 0, "&{Value:256}"},
	{18, 0x0202, 0, "&{Slot:0 Subslot:32769}"},
	{18, 0x0209, 0, "&{Boundary:3 Egress:0 AdjustProperties:1}"},
	{18, 0x0209, 1, "&{Boundary:5 Egress:6 AdjustProperties:1}"},
	{18, 0x0210, 0, "&{Boundary:61455 Egress:0 AdjustProperties:1}"},
	{18, 0x020E, 0, "&{Value:16 AdjustProperties:1}"},
	{18, 0x021B, 0, "&{Value:2 AdjustProperties:1}"},
	{18, 0x0224, 0, "&{Boundary:7 Egress:0 AdjustProperties:1}"},
	{18, 0x0225, 0, "&{Boundary:3 Egress:0 AdjustProperties:1}"},
	{18, 0x0226, 0, "&{Value:1 AdjustProperties:1}"},
	{18, 0x0229, 0, "&{Value:256 AdjustProperties:1}"},
	{19, 0x020F, 0, "&{Slot:0 Subslot:32769 OwnPortID:port-001 Peers:[{PortID:port-002 ChassisID:switch0 LineDelay:2147483939 MACAddress:00:0e:8c:40:41:42 MAUType:Unknown MAUTypeExtension:0} {PortID:port-003 ChassisID:switch1 LineDelay:2147483940 MACAddress:00:0e:8c:41:42:43 MAUType:Unknown MAUTypeExtension:0}] MAUType:"},
	{20, 0x022C, 0, "&{Slot:0 Subslot:32769}"},
	{20, 0x0260, 0, "&{OwnPortID:port-001 LineDelay:1110 MediaType:1 MulticastBoundary:51 MAUType:100BASE-TX full duplex MAUTypeExtension:256 LinkState:1281 RTClass3Status:4610}"},
	{20, 0x0261, 0, "&{Peers:[{PortID:port-005 ChassisID:dev0 LineDelay:2147484160 MACAddress:00:0e:8c:50:51:52 MAUType:100BASE-TX full duplex MAUTypeExtension:256} {PortID:port-006 ChassisID:dev1 LineDelay:2147484161 MACAddress:00:0e:8c:51:52:53 MAUType:100BASE-TX full duplex MAUTypeExtension:256}]}"},
	{21, 0x0240, 0, "&{OwnChassisID:device1 MACAddress:00:0e:8c:10:11:12 IPAddress:192.168.0.50 Subnetmask:255.255.255.0 StandardGateway:192.168.0.1}"},
	{22, 0x0250, 0, "&{MultipleInterfaceMode:1}"},
	{23, 0x0251, 0, "&{CounterStatus:0 InOctets:4097 OutOctets:4098 InDiscards:4099 OutDiscards:4100 InErrors:4101 OutErrors:4102}"},
	{24, 0x0251, 1, "&{CounterStatus:36 InOctets:4097 OutOctets:4098 InDiscards:4099 OutDiscards:4100 InErrors:4101 OutErrors:4102}"},
	{25, 0x0203, 2, "&{PTCPSubdomainUUID:80818283-8485-8687-8889-8a8b8c8d8e8f ReservedIntervalBegin:1000 ReservedIntervalEnd:2000 PLLWindow:3000 SyncSendFactor:4000 SendClockFactor:32 PTCPTimeoutFactor:6 PTCPTakeoverFactor:3 PTCPMasterStartupTime:60 SyncProperties:258 MasterPriority1:17 MasterPriority2:34 PTCPSubdomainN"},
	{26, 0x0205, 0, "&{Slot:0 Subslot:32768}"},
	{26, 0x0206, 1, "&{IRDataUUID:90919293-9495-9697-9899-9a9b9c9d9e9f MaxBridgeDelay:2900 Ports:[{MaxPortTxDelay:101 MaxPortRxDelay:102 MaxLineRxDelay:0 YellowTime:0} {MaxPortTxDelay:201 MaxPortRxDelay:202 MaxLineRxDelay:0 YellowTime:0}]}"},
	{26, 0x0207, 0, "&{FrameDataProperties:0 Frames:[{FrameSendOffset:125000 DataLength:40 ReductionRatio:4 Phase:1 FrameID:0x0105(RT_CLASS_3) EtherType:Profinet RxPort:1 FrameDetails:4 TxPortGroups:[3]} {FrameSendOffset:250000 DataLength:40 ReductionRatio:4 Phase:1 FrameID:0x0106(RT_CLASS_3) EtherType:Profinet RxPort:1"},
	{27, 0x0205, 1, "&{Slot:0 Subslot:32768}"},
	{27, 0x0206, 2, "&{IRDataUUID:90919293-9495-9697-9899-9a9b9c9d9e9f MaxBridgeDelay:2900 Ports:[{MaxPortTxDelay:101 MaxPortRxDelay:102 MaxLineRxDelay:103 YellowTime:104} {MaxPortTxDelay:201 MaxPortRxDelay:202 MaxLineRxDelay:203 YellowTime:204}]}"},
	{27, 0x0207, 1, "&{FrameDataProperties:1 Frames:[{FrameSendOffset:125000 DataLength:40 ReductionRatio:4 Phase:1 FrameID:0x0105(RT_CLASS_3) EtherType:Profinet RxPort:1 FrameDetails:4 TxPortGroups:[3]} {FrameSendOffset:250000 DataLength:40 ReductionRatio:4 Phase:1 FrameID:0x0106(RT_CLASS_3) EtherType:Profinet RxPort:1"},
	{27, 0x0208, 0, "&{StartOfRedFrameID:0x0100(RT_CLASS_3) EndOfRedFrameID:0x06ff(RT_CLASS_3) Ports:[{Assignments:[{TxRedOrangePeriodBegin:11 TxOrangePeriodBegin:12 TxGreenPeriodBegin:13 RxRedOrangePeriodBegin:21 RxOrangePeriodBegin:22 RxGreenPeriodBegin:23}] Phases:[{TxPhaseAssignment:256 RxPhaseAssignment:512} {TxPha"},
	{28, 0x022A, 0, "&{NumberOfEntries:2}"},
	{28, 0x022B, 0, "&{FrameID:0x0700(RT_CLASS_3) SFIOCRProperties:258 SubframeData:[1032 1292]}"},
	{29, 0x0204, 0, "&{Slot:1 Subslot:1 ControllerApplicationCycleFactor:4 TimeDataCycle:2 TimeIOInput:100000 TimeIOOutput:200000 TimeIOInputValid:50000 TimeIOOutputValid:60000}"},
	{30, 0x0220, 0, "&{FiberOpticType:3 FiberOpticCableType:1}"},
	{30, 0x0221, 0, "&{VendorID:298 VendorBlockType:5 Data:[1 2 3 4]}"},
	{30, 0x0228, 0, "&{FiberOpticPowerBudgetReal:2147483673}"},
	{31, 0x0223, 0, "&{MaintenanceRequired:2147483668 MaintenanceDemanded:2147483658 Error:2147483653}"},
	{32, 0x0222, 0, "&{FiberOpticType:3 FiberOpticCableType:1}"},
	{33, 0x0230, 0, "&{MaintenanceRequired:2147483748 MaintenanceDemanded:2147483848 Error:2147483948}"},
	{34, 0x0600, 0, "&{Mode:1 Interval:30 Retry:3 Delay:50}"},
	{34, 0x0601, 0, "&{Mode:1 UUID:a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf}"},
	{36, 0x0211, 0, "&{NumberOfEntries:0 Instance:0 DomainUUID:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf Role:Manager Version:0 DomainName:mrpdomain-1 Check:0}"},
	{36, 0x0216, 0, "&{Prio:32768 TOPchgT:10 TOPNRmax:3 TSTshortT:11 TSTdefaultT:20 TSTNRmax:4}"},
	{37, 0x0212, 0, "&{NumberOfEntries:0 Instance:0 DomainUUID:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf Role:Client Version:1 DomainName:mrpdomain-1 Check:0}"},
	{37, 0x0217, 0, "&{LNKdownT:20 LNKupT:21 LNKNRmax:5}"},
	{37, 0x0219, 0, "&{Value:1}"},
	{38, 0x0211, 1, "&{NumberOfEntries:2 Instance:0 DomainUUID:00000000-0000-0000-0000-000000000000 Role:Off Version:0 DomainName: Check:0}"},
	{38, 0x0231, 0, "&{NumberOfEntries:0 Instance:1 DomainUUID:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf Role:Manager Version:0 DomainName:mrpdomain-2 Check:0}"},
	{39, 0x0212, 1, "&{NumberOfEntries:1 Instance:0 DomainUUID:00000000-0000-0000-0000-000000000000 Role:Off Version:0 DomainName: Check:0}"},
	{39, 0x0232, 0, "&{NumberOfEntries:0 Instance:1 DomainUUID:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf Role:Manager Version:1 DomainName:mrpdomain-2 Check:0}"},
	{41, 0x0213, 0, "&{NumberOfEntries:0 Instance:0 DomainUUID:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf Role:Off Version:0 DomainName: Check:3}"},
	{42, 0x0213, 1, "&{NumberOfEntries:1 Instance:0 DomainUUID:00000000-0000-0000-0000-000000000000 Role:Off Version:0 DomainName: Check:0}"},
	{42, 0x0233, 0, "&{NumberOfEntries:0 Instance:1 DomainUUID:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf Role:Off Version:0 DomainName: Check:1}"},
	{43, 0x0214, 0, "&{Instance:0 DomainUUID:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf}"},
	{44, 0x0214, 1, "&{Instance:1 DomainUUID:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf}"},
	{45, 0x0215, 0, "&{Instance:0 DomainUUID:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf}"},
	{46, 0x0215, 1, "&{Instance:1 DomainUUID:b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf}"},
	{47, 0x0218, 0, "&{TSTNRmax:4 TSTdefaultT:20 RTMode:3}"},
	{47, 0x021D, 0, "&{TSTNRmax:0 TSTdefaultT:0 RTMode:1}"},
	{47, 0x021A, 0, "&{Value:1}"},
	{48, 0x0400, 0, "&{API:0 Slot:0 Subslot:32769}"},
	{49, 0x0401, 0, "&{API:0 Slot:0 Subslot:32769 Index:PDPortDataAdjust}"},
	{51, 0x0018, 0, "&{ARs:[{ARUUID:40414243-4445-4647-4849-4a4b4c4d4e4f ARType:IO Controller AR Properties:1073742097 InitiatorObjectUUID:50515253-5455-5657-5859-5a5b5c5d5e5f InitiatorStationName:ctrl IOCRs:[{IOCRType:Input CR Properties:2 FrameID:0x8001(RT_CLASS_1) CycleCounter:4660 DataStatus:0x35(Valid,Primary,Ok,Ru"},
	{52, 0x0018, 1, "&{ARs:[{ARUUID:40414243-4445-4647-4849-4a4b4c4d4e4f ARType:IO Controller AR Properties:1073742097 InitiatorObjectUUID:50515253-5455-5657-5859-5a5b5c5d5e5f InitiatorStationName:ctrl IOCRs:[{IOCRType:Output CR Properties:2 FrameID:0x8002(RT_CLASS_1) CycleCounter:17185 DataStatus:0x35(Valid,Primary,Ok,"},
	{53, 0x001A, 0, "&{APIs:[0 14848]}"},
	{54, 0x0019, 0, "&{ActualLocalTimeStamp:1234605616436508552 Entries:[{LocalTimeStamp:72623859790382856 ARUUID:70717273-7475-7677-7879-7a7b7c7d7e7f Status:IODConnectRsp, PNIO, ErrorCode1 0x01, ErrorCode2 0x05 EntryDetail:2575857510} {LocalTimeStamp:72623859790382856 ARUUID:70717273-7475-7677-7879-7a7b7c7d7e7f Status:"},
	{55, 0x001B, 0, "&{RedundancyInfo:2}"},
	{56, 0x0014, 0, "&{Mode:2 IOCS:128 Data:[17 18 19 20 128]}"},
	{57, 0x0015, 0, "&{SubstituteActiveFlag:0 LengthIOCS:1 LengthIOPS:1 IOCS:128 IOPS:96 Data:[25 24 23 22]}"},
	{58, 0x0016, 0, "&{SubstituteActiveFlag:1 LengthIOCS:1 LengthIOPS:1 IOCS:128 IOPS:160 Data:[25 24 23 22]}"},
	{61, 0x0810, 0, "&{APIs:[{API:14848 Modules:[{Slot:3 ModuleIdentNumber:48 Submodules:[{Subslot:1 SubmoduleIdentNumber:49} {Subslot:2 SubmoduleIdentNumber:50}]}]}]}"},
	{62, 0x0811, 0, "&{APIs:[{API:14848 Modules:[{Slot:3 Submodules:[{Subslot:1 OperationalMode:240} {Subslot:2 OperationalMode:31}]}]}]}"},
	{63, 0x0800, 0, "&{ServiceID:1 RequestRef:66 Modifier:0 Status:0 StructID:1 Data:[0 0 234 96]}"},
	{64, 0x0801, 0, "&{ServiceID:1 RequestRef:66 Modifier:0 Status:1 StructID:1 Data:[31 0 0 0 5 220]}"},
	{65, 0x0105, 0, "&{ObjectUUID:60616263-6465-6667-6869-6a6b6c6d6e6f Properties:0 ActivityTimeoutFactor:100 StationName:prm}"},
	{65, 0x0106, 0, "&{IOCRReference:3 AddressResolutionProperties:327681 MCITimeoutFactor:100 ProviderStationName:provider}"},
	{65, 0x0108, 0, "&{APStructureIdentifier:32768 API:14848 Data:[193 194 195 196]}"},
	{65, 0x0109, 0, "&{IRDataUUID:70717273-7475-7677-7879-7a7b7c7d7e7f IOCRs:[{IOCRReference:1 SubframeOffset:16 SubframeData:1032} {IOCRReference:2 SubframeOffset:32 SubframeData:1290}]}"},
	{65, 0x010A, 0, "&{RedundancyDataHoldFactor:200 SRProperties:5}"},
	{65, 0x010C, 0, "&{RSProperties:1}"},
	{66, 0x8108, 0, "&{APStructureIdentifier:32768 API:14848 Data:[209 210]}"},
	{66, 0x8105, 0, "&{ObjectUUID:00000000-0000-0000-0000-000000000000 Properties:0 ActivityTimeoutFactor:0 StationName:prm}"},
	{67, 0x0107, 0, "&{RPCServerPort:49153}"},
	{68, 0x8107, 0, "&{RPCServerPort:49154}"},
	{69, 0x0119, 0, "&{Entries:[{API:0 Slot:1 Subslot:1} {API:14848 Slot:2 Subslot:3}]}"},
	{70, 0x06E1, 0, "&{ARUUID:c0c1c2c3-c4c5-c6c7-c8c9-cacbcccdcecf}"},
	{71, 0x0901, 0, "&{NumberOfEntries:1 Events:[{ProfinetRSBlockHead:{BlockType:Digital input observer Length:52 VersionHigh:1 VersionLow:0} ARUUID:d0d1d2d3-d4d5-d6d7-d8d9-dadbdcdddedf API:14848 Slot:1 Subslot:2 ChannelNumber:3 Specifier:16675 TimeStamp:{Status:2 SecondsHigh:0 Seconds:1694498816 Nanoseconds:123456789} "},
	{73, 0x0902, 0, "&{Specifier:291}"},
	{74, 0x0900, 0, "&{NumberOfEntries:1 Blocks:[{ProfinetRSBlockHead:{BlockType:Digital input observer Length:16 VersionHigh:1 VersionLow:0} Data:[48 49 50 51 52 53 54 55 56 57 58 59]}]}"},
	{80, 0x0274, 0, "&{TimeDomainNumber:0 TimePLLWindow:1000 MessageIntervalFactor:4000 MessageTimeoutFactor:3 TimeSyncProperties:2 TimeDomainUUID:30313233-3435-3637-3839-3a3b3c3d3e3f TimeDomainName:timedomai}"},
	{80, 0x027F, 0, "&{StreamCollectionUUID:40414243-4445-4647-4849-4a4b4c4d4e4f SyncTreeDataUUID:50515253-5455-5657-5859-5a5b5c5d5e5f ExpectedNetworkAttributesUUID:60616263-6465-6667-6869-6a6b6c6d6e6f}"},
	{81, 0x0300, 0, "&{SNMPControl:2 ReadCommunity:public ReadWriteCommunity:private}"},
	{81, 0x0302, 0, "&{SNMPControl:1 ReadCommunity: ReadWriteCommunity:}"},
	{82, 0x0303, 0, "&{Control:7}"},
	{82, 0x0304, 0, "&{Control:3}"},
	{82, 0x0307, 0, "&{Control:1}"},
	{82, 0x0308, 0, "&{Control:3}"},
	{82, 0x0309, 0, "&{Control:17}"},
	{82, 0x030A, 0, "&{Control:34}"},
	{83, 0x0305, 0, "&{SetControl:17 GetControl:1 MulticastControl:257}"},
	{83, 0x0306, 0, "&{SetControl:1 GetControl:0 MulticastControl:256}"},
	{84, 0x011B, 0, "&{ARUUID:c0c1c2c3-c4c5-c6c7-c8c9-cacbcccdcecf}"},
}
