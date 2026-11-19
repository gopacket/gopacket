// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO blocks.
//
// Alarm PDUs, the RPC services on UDP 34964 and record data all carry the
// same block structure (IEC 61158-6-10, Wireshark packet-dcerpc-pn-io.c
// dissect_block). Blocks are always big-endian, whatever the RPC data
// representation says:
//
//	+-----------+-------------+-------------+------------+------+
//	| BlockType | BlockLength | VersionHigh | VersionLow | Body |
//	| 2         | 2           | 1           | 1          | n    |
//	+-----------+-------------+-------------+------------+------+
//
// BlockLength counts the two version bytes and the body, so a block takes
// BlockLength+4 bytes.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	profinetBlockHeaderLen = 6

	// profinetBlockVersionLen is the part of the header BlockLength covers.
	profinetBlockVersionLen = 2

	profinetUUIDLen    = 16
	profinetMACLen     = 6
	profinetBlockAlign = 4

	// Fixed body sizes, version bytes excluded.
	profinetAlarmHeadLen    = 20 // AlarmType .. AlarmSpecifier
	profinetAlarmAckLen     = 16
	profinetARReqFixedLen   = 52 // ARType .. StationNameLength
	profinetARResLen        = 28
	profinetIOCRReqFixedLen = 40 // IOCRType .. NumberOfAPIs
	profinetIOCRResLen      = 6
	profinetAlarmCRReqLen   = 20
	profinetAlarmCRResLen   = 6
	profinetControlLen      = 26
	profinetRecordHeadLen   = 34 // SeqNumber .. RecordDataLength
	profinetRecordIndexOff  = 28 // Index within the record header
	profinetRecordLengthOff = 30 // RecordDataLength within the record header

	// Smallest list elements; they bound how many a body can hold.
	profinetIOObjectLen       = 6  // slot, subslot, frame offset
	profinetIOCRAPIMinLen     = 8  // API, two counts
	profinetExpAPIMinLen      = 14 // API, slot, ident, properties, count
	profinetExpSubmoduleMin   = 12 // subslot, ident, properties, one description
	profinetDataDescLen       = 4
	profinetDiffAPIMinLen     = 6
	profinetDiffModuleMinLen  = 10
	profinetDiffSubmoduleLen  = 8
	profinetChannelDiagLen    = 6
	profinetExtChannelDiagLen = 12
	profinetQualChannelLen    = 16
	profinetPRALMinLen        = 12 // Wireshark leaves shorter items raw
	profinetPRALFixedLen      = 8
	profinetAlarmItemMinLen   = 8 // USI plus the smallest typed item
)

var (
	// ErrProfinetBlockTooShort is returned when a block header is truncated.
	ErrProfinetBlockTooShort = errors.New("PROFINET block header too short")
	// ErrProfinetBlockLength is returned when BlockLength does not cover
	// the version bytes.
	ErrProfinetBlockLength = errors.New("PROFINET block length below 2")
)

// ProfinetUUID is a UUID in its canonical (big-endian) byte order.
type ProfinetUUID [profinetUUIDLen]byte

// String formats the UUID as 8-4-4-4-12 hex digits, as Wireshark does.
func (u ProfinetUUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// IsZero reports whether the UUID is the nil UUID.
func (u ProfinetUUID) IsZero() bool { return u == ProfinetUUID{} }

// profinetReader walks big-endian fields. A read past the end sets short
// and yields zero, so decoders check once after reading a group of fields.
type profinetReader struct {
	data  []byte
	off   int
	short bool
}

// left returns the number of unread bytes.
func (r *profinetReader) left() int { return len(r.data) - r.off }

// bytes returns the next n bytes, or nil when fewer are left.
func (r *profinetReader) bytes(n int) []byte {
	if n < 0 || n > r.left() {
		r.short = true
		r.off = len(r.data)
		return nil
	}

	b := r.data[r.off : r.off+n]
	r.off += n
	return b
}

func (r *profinetReader) u8() uint8 {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *profinetReader) u16() uint16 {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *profinetReader) u32() uint32 {
	b := r.bytes(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *profinetReader) uuid() (u ProfinetUUID) {
	copy(u[:], r.bytes(profinetUUIDLen))
	return u
}

func (r *profinetReader) mac() net.HardwareAddr {
	return net.HardwareAddr(r.bytes(profinetMACLen))
}

// rest returns every unread byte.
func (r *profinetReader) rest() []byte { return r.bytes(r.left()) }

// count reads a 16-bit element count and clips it to what the unread bytes
// can hold, so a lying count never sizes an allocation.
func (r *profinetReader) count(elemLen int) int {
	n := int(r.u16())
	if max := r.left() / elemLen; n > max {
		r.short = true
		return max
	}
	return n
}

// ProfinetBlockType is the BlockType of a PROFINET IO block.
type ProfinetBlockType uint16

// Block types with a typed decode. ProfinetBlockType.String names every
// type Wireshark knows.
const (
	ProfinetBlockAlarmHigh         ProfinetBlockType = 0x0001
	ProfinetBlockAlarmLow          ProfinetBlockType = 0x0002
	ProfinetBlockIODWriteReq       ProfinetBlockType = 0x0008
	ProfinetBlockIODReadReq        ProfinetBlockType = 0x0009
	ProfinetBlockARReq             ProfinetBlockType = 0x0101
	ProfinetBlockIOCRReq           ProfinetBlockType = 0x0102
	ProfinetBlockAlarmCRReq        ProfinetBlockType = 0x0103
	ProfinetBlockExpectedSubmodule ProfinetBlockType = 0x0104
	ProfinetBlockPrmEndReq         ProfinetBlockType = 0x0110
	ProfinetBlockPlugPrmEndReq     ProfinetBlockType = 0x0111
	ProfinetBlockAppReadyReq       ProfinetBlockType = 0x0112
	ProfinetBlockPlugAppReadyReq   ProfinetBlockType = 0x0113
	ProfinetBlockReleaseReq        ProfinetBlockType = 0x0114
	ProfinetBlockReadyCompanionReq ProfinetBlockType = 0x0116
	ProfinetBlockReadyRTC3Req      ProfinetBlockType = 0x0117
	ProfinetBlockPrmBeginReq       ProfinetBlockType = 0x0118
	ProfinetBlockMaintenanceItem   ProfinetBlockType = 0x0F00
	ProfinetBlockUploadRecords     ProfinetBlockType = 0x0F01
	ProfinetBlockIParameterItem    ProfinetBlockType = 0x0F02
	ProfinetBlockRetrieveRecords   ProfinetBlockType = 0x0F03
	ProfinetBlockRetrieveAll       ProfinetBlockType = 0x0F04
	ProfinetBlockPEAlarm           ProfinetBlockType = 0x0F05
	ProfinetBlockAlarmAckHigh      ProfinetBlockType = 0x8001
	ProfinetBlockAlarmAckLow       ProfinetBlockType = 0x8002
	ProfinetBlockIODWriteRes       ProfinetBlockType = 0x8008
	ProfinetBlockIODReadRes        ProfinetBlockType = 0x8009
	ProfinetBlockARRes             ProfinetBlockType = 0x8101
	ProfinetBlockIOCRRes           ProfinetBlockType = 0x8102
	ProfinetBlockAlarmCRRes        ProfinetBlockType = 0x8103
	ProfinetBlockModuleDiff        ProfinetBlockType = 0x8104
	ProfinetBlockARServer          ProfinetBlockType = 0x8106
	ProfinetBlockPrmEndRes         ProfinetBlockType = 0x8110
	ProfinetBlockPlugPrmEndRes     ProfinetBlockType = 0x8111
	ProfinetBlockAppReadyRes       ProfinetBlockType = 0x8112
	ProfinetBlockPlugAppReadyRes   ProfinetBlockType = 0x8113
	ProfinetBlockReleaseRes        ProfinetBlockType = 0x8114
	ProfinetBlockReadyCompanionRes ProfinetBlockType = 0x8116
	ProfinetBlockReadyRTC3Res      ProfinetBlockType = 0x8117
	ProfinetBlockPrmBeginRes       ProfinetBlockType = 0x8118
)

// profinetBlockResponse is the BlockType bit that marks a response.
const profinetBlockResponse ProfinetBlockType = 0x8000

// String returns the block type name used by Wireshark.
func (t ProfinetBlockType) String() string {
	if name, ok := profinetBlockNames[t]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04x)", uint16(t))
}

// ProfinetPNIOStatus is the 4-byte PNIO status of responses, alarm
// acknowledges and ERR-RTA PDUs.
type ProfinetPNIOStatus struct {
	ErrorCode   ProfinetErrorCode
	ErrorDecode ProfinetErrorDecode
	ErrorCode1  uint8
	ErrorCode2  uint8
}

// OK reports whether the status signals success (all four bytes zero).
func (s ProfinetPNIOStatus) OK() bool { return s == ProfinetPNIOStatus{} }

// String formats the status as Wireshark's summary does.
func (s ProfinetPNIOStatus) String() string {
	if s.OK() {
		return "OK"
	}
	return fmt.Sprintf("%v, %v, ErrorCode1 0x%02x, ErrorCode2 0x%02x",
		s.ErrorCode, s.ErrorDecode, s.ErrorCode1, s.ErrorCode2)
}

// ProfinetErrorCode is the ErrorCode byte of a PNIO status: the service
// that failed.
type ProfinetErrorCode uint8

// PNIO status error codes.
const (
	ProfinetErrorCodeOK         ProfinetErrorCode = 0x00
	ProfinetErrorCodePNIO       ProfinetErrorCode = 0x81
	ProfinetErrorCodeRTA        ProfinetErrorCode = 0xCF
	ProfinetErrorCodeAlarmAck   ProfinetErrorCode = 0xDA
	ProfinetErrorCodeConnect    ProfinetErrorCode = 0xDB
	ProfinetErrorCodeRelease    ProfinetErrorCode = 0xDC
	ProfinetErrorCodeControl    ProfinetErrorCode = 0xDD
	ProfinetErrorCodeRead       ProfinetErrorCode = 0xDE
	ProfinetErrorCodeWrite      ProfinetErrorCode = 0xDF
	ProfinetErrorCodeSXPConnect ProfinetErrorCode = 0xE0
	ProfinetErrorCodeSCMService ProfinetErrorCode = 0xE1
	ProfinetErrorCodeSXP        ProfinetErrorCode = 0xE2
)

// String returns the error code name.
func (c ProfinetErrorCode) String() string {
	switch c {
	case ProfinetErrorCodeOK:
		return "OK"
	case ProfinetErrorCodePNIO:
		return "PNIO"
	case ProfinetErrorCodeRTA:
		return "RTA error"
	case ProfinetErrorCodeAlarmAck:
		return "AlarmAck"
	case ProfinetErrorCodeConnect:
		return "IODConnectRsp"
	case ProfinetErrorCodeRelease:
		return "IODReleaseRsp"
	case ProfinetErrorCodeControl:
		return "IODControlRsp, IOXControlRsp"
	case ProfinetErrorCodeRead:
		return "IODReadRsp"
	case ProfinetErrorCodeWrite:
		return "IODWriteRsp"
	case ProfinetErrorCodeSXPConnect:
		return "SXP-SAMConnect-RSP, SXP-SAMService-RSP"
	case ProfinetErrorCodeSCMService:
		return "SCMServiceReq response"
	case ProfinetErrorCodeSXP:
		return "SXP error"
	}
	return fmt.Sprintf("Unknown(0x%02x)", uint8(c))
}

// ProfinetErrorDecode is the ErrorDecode byte of a PNIO status: how to
// read ErrorCode1 and ErrorCode2.
type ProfinetErrorDecode uint8

// PNIO status error decodes.
const (
	ProfinetErrorDecodeOK           ProfinetErrorDecode = 0x00
	ProfinetErrorDecodePNIORW       ProfinetErrorDecode = 0x80
	ProfinetErrorDecodePNIO         ProfinetErrorDecode = 0x81
	ProfinetErrorDecodeManufacturer ProfinetErrorDecode = 0x82
	ProfinetErrorDecodePNIOSEC      ProfinetErrorDecode = 0x83
)

// String returns the error decode name.
func (d ProfinetErrorDecode) String() string {
	switch d {
	case ProfinetErrorDecodeOK:
		return "OK"
	case ProfinetErrorDecodePNIORW:
		return "PNIORW"
	case ProfinetErrorDecodePNIO:
		return "PNIO"
	case ProfinetErrorDecodeManufacturer:
		return "Manufacturer specific"
	case ProfinetErrorDecodePNIOSEC:
		return "PNIOSEC"
	}
	return fmt.Sprintf("Unknown(0x%02x)", uint8(d))
}

// status reads a PNIO status in block (big-endian) byte order.
func (r *profinetReader) status() ProfinetPNIOStatus {
	b := r.bytes(profinetPNIOStatusLen)
	if b == nil {
		return ProfinetPNIOStatus{}
	}
	return ProfinetPNIOStatus{ProfinetErrorCode(b[0]), ProfinetErrorDecode(b[1]), b[2], b[3]}
}

// ProfinetBlock is one PROFINET IO block.
//
// Body holds the bytes after the version, clipped to the captured data.
// At most one of the typed pointers is set, for the block types listed
// with them; every other type stays raw in Body. Wireshark decodes a typed
// body only for block version 1.0 and so does this decoder.
type ProfinetBlock struct {
	Type        ProfinetBlockType
	Length      uint16 // BlockLength as sent
	VersionHigh uint8
	VersionLow  uint8
	Body        []byte

	Alarm      *ProfinetAlarmNotification // Alarm Notification High/Low
	AlarmAck   *ProfinetAlarmAck          // Alarm Ack High/Low
	AR         *ProfinetARBlock           // ARBlockReq, ARBlockRes
	IOCR       *ProfinetIOCRBlock         // IOCRBlockReq, IOCRBlockRes
	AlarmCR    *ProfinetAlarmCRBlock      // AlarmCRBlockReq, AlarmCRBlockRes
	Expected   *ProfinetExpectedBlock     // ExpectedSubmoduleBlockReq
	ModuleDiff *ProfinetModuleDiffBlock   // ModuleDiffBlock
	ARServer   *ProfinetARServerBlock     // ARServerBlockRes
	Control    *ProfinetControlBlock      // IODControl, IOXControl, IODRelease, PrmBegin
	Record     *ProfinetRecordBlock       // IODWrite/IODRead request and response headers
	Item       *ProfinetAlarmItemBlock    // MaintenanceItem, Upload&Retrieval, iParameter, PE alarm
}

// Clipped reports whether BlockLength promised more body than was captured.
func (b *ProfinetBlock) Clipped() bool {
	return int(b.Length)-profinetBlockVersionLen > len(b.Body)
}

// profinetBlockNesting says where a block sits. Blocks inside an alarm
// item are leaves: they never hold alarm blocks, which bounds recursion.
type profinetBlockNesting uint8

const (
	profinetBlockTop profinetBlockNesting = iota
	profinetBlockNested
)

// ProfinetDecodeBlocks decodes a run of blocks, such as the record data of
// a read response whose index is known to hold blocks. It stops at the end
// of the data or at a zero block type, like Wireshark. Blocks decoded
// before an error are returned with it.
func ProfinetDecodeBlocks(data []byte) ([]ProfinetBlock, error) {
	return appendProfinetBlocks(nil, data)
}

// appendProfinetBlocks decodes the blocks in data onto dst.
//
// Record data follows its IODWriteReqHeader or IODReadResHeader block
// outside any block; it is attached to that header. A write request with
// several records pads each one to a multiple of four bytes.
func appendProfinetBlocks(dst []ProfinetBlock, data []byte) ([]ProfinetBlock, error) {
	// Size the list before decoding: append must not grow it block by
	// block on a packet of minimal blocks.
	if n := countProfinetBlocks(data); cap(dst)-len(dst) < n {
		grown := make([]ProfinetBlock, len(dst), len(dst)+n)
		copy(grown, dst)
		dst = grown
	}

	off := 0
	for off+profinetBlockVersionLen <= len(data) {
		// A zero block type ends the list: padding, not a block.
		if binary.BigEndian.Uint16(data[off:]) == 0 {
			break
		}

		b, n, err := decodeProfinetBlock(data[off:], profinetBlockTop)
		if err != nil {
			return dst, err
		}
		off += n

		if rec := b.Record; rec != nil && rec.carriesData(b.Type) {
			n = int(rec.RecordDataLength)
			if rec.RecordDataLength > uint32(len(data)-off) {
				n = len(data) - off
			}
			rec.Data = data[off : off+n]
			off += n

			// Wireshark aligns to the start of the RPC body, which the
			// block list shares modulo four (the NDR header is 20 bytes).
			if pad := (profinetBlockAlign - off%profinetBlockAlign) % profinetBlockAlign; off+pad <= len(data) {
				off += pad
			}
		}
		dst = append(dst, b)
	}
	return dst, nil
}

// countProfinetBlocks walks the block headers the way appendProfinetBlocks
// does and returns how many blocks it will decode. Each block takes at
// least 6 bytes, so the walk is bounded by len(data).
func countProfinetBlocks(data []byte) int {
	n, off := 0, 0
	for off+profinetBlockHeaderLen <= len(data) {
		length := int(binary.BigEndian.Uint16(data[off+2:]))
		if binary.BigEndian.Uint16(data[off:]) == 0 || length < profinetBlockVersionLen {
			break
		}

		end := off + profinetBlockHeaderLen + length - profinetBlockVersionLen
		if end > len(data) {
			end = len(data)
		}
		off = profinetRecordEnd(data, off, end)
		n++
	}
	return n
}

// profinetRecordEnd returns the offset behind the record data and padding
// that follow the block at data[off:end], or end when the block carries
// none. It reads the record header fields in place, without decoding.
func profinetRecordEnd(data []byte, off, end int) int {
	block := data[off:end]
	body := block[profinetBlockHeaderLen:]
	if block[4] != 1 || block[5] != 0 || len(body) < profinetRecordHeadLen {
		return end
	}

	rec := ProfinetRecordBlock{Index: binary.BigEndian.Uint16(body[profinetRecordIndexOff:])}
	if !rec.carriesData(ProfinetBlockType(binary.BigEndian.Uint16(block))) {
		return end
	}

	next := len(data)
	if dataLen := binary.BigEndian.Uint32(body[profinetRecordLengthOff:]); dataLen < uint32(len(data)-end) {
		next = end + int(dataLen)
	}
	if pad := (profinetBlockAlign - next%profinetBlockAlign) % profinetBlockAlign; next+pad <= len(data) {
		next += pad
	}
	return next
}

// decodeProfinetBlock decodes the block at the start of data and returns
// the number of bytes it takes. A body cut short by the capture is clipped
// (see ProfinetBlock.Clipped), as Wireshark does.
func decodeProfinetBlock(data []byte, nesting profinetBlockNesting) (ProfinetBlock, int, error) {
	if len(data) < profinetBlockHeaderLen {
		return ProfinetBlock{}, 0, ErrProfinetBlockTooShort
	}

	b := ProfinetBlock{
		Type:        ProfinetBlockType(binary.BigEndian.Uint16(data)),
		Length:      binary.BigEndian.Uint16(data[2:]),
		VersionHigh: data[4],
		VersionLow:  data[5],
	}
	if b.Length < profinetBlockVersionLen {
		return b, 0, ErrProfinetBlockLength
	}

	end := profinetBlockHeaderLen + int(b.Length) - profinetBlockVersionLen
	if end > len(data) {
		end = len(data)
	}
	b.Body = data[profinetBlockHeaderLen:end]

	if b.VersionHigh == 1 && b.VersionLow == 0 {
		b.decodeBody(nesting)
	}
	return b, end, nil
}

// decodeBody fills the typed pointer for the block types we know.
func (b *ProfinetBlock) decodeBody(nesting profinetBlockNesting) {
	r := &profinetReader{data: b.Body}

	switch b.Type {
	case ProfinetBlockAlarmHigh, ProfinetBlockAlarmLow:
		if nesting == profinetBlockTop {
			b.Alarm = decodeProfinetAlarmNotif(r)
		}
	case ProfinetBlockAlarmAckHigh, ProfinetBlockAlarmAckLow:
		b.AlarmAck = decodeProfinetAlarmAck(r)
	case ProfinetBlockIODWriteReq, ProfinetBlockIODReadReq, ProfinetBlockIODWriteRes, ProfinetBlockIODReadRes:
		b.Record = decodeProfinetRecord(r, b.Type)
	case ProfinetBlockARReq:
		b.AR = decodeProfinetARReq(r)
	case ProfinetBlockARRes:
		b.AR = decodeProfinetARRes(r)
	case ProfinetBlockIOCRReq:
		b.IOCR = decodeProfinetIOCRReq(r)
	case ProfinetBlockIOCRRes:
		b.IOCR = decodeProfinetIOCRRes(r)
	case ProfinetBlockAlarmCRReq:
		b.AlarmCR = decodeProfinetAlarmCRReq(r)
	case ProfinetBlockAlarmCRRes:
		b.AlarmCR = decodeProfinetAlarmCRRes(r)
	case ProfinetBlockExpectedSubmodule:
		b.Expected = decodeProfinetExpected(r)
	case ProfinetBlockModuleDiff:
		b.ModuleDiff = decodeProfinetModuleDiff(r)
	case ProfinetBlockARServer:
		b.ARServer = decodeProfinetARServer(r)
	case ProfinetBlockMaintenanceItem, ProfinetBlockUploadRecords, ProfinetBlockIParameterItem,
		ProfinetBlockRetrieveRecords, ProfinetBlockRetrieveAll, ProfinetBlockPEAlarm:
		b.Item = decodeProfinetItemBlock(r, b.Type)
	}

	switch b.Type &^ profinetBlockResponse {
	case ProfinetBlockPrmEndReq, ProfinetBlockPlugPrmEndReq, ProfinetBlockAppReadyReq,
		ProfinetBlockPlugAppReadyReq, ProfinetBlockReleaseReq, ProfinetBlockReadyCompanionReq,
		ProfinetBlockReadyRTC3Req, ProfinetBlockPrmBeginReq:
		b.Control = decodeProfinetControl(r)
	}
}

// ProfinetAlarmType is the AlarmType of an alarm notification.
type ProfinetAlarmType uint16

// Common alarm types; String names all of them.
const (
	ProfinetAlarmTypeDiagnosis         ProfinetAlarmType = 0x0001
	ProfinetAlarmTypeProcess           ProfinetAlarmType = 0x0002
	ProfinetAlarmTypePull              ProfinetAlarmType = 0x0003
	ProfinetAlarmTypePlug              ProfinetAlarmType = 0x0004
	ProfinetAlarmTypeStatus            ProfinetAlarmType = 0x0005
	ProfinetAlarmTypeUpdate            ProfinetAlarmType = 0x0006
	ProfinetAlarmTypeRedundancy        ProfinetAlarmType = 0x0007
	ProfinetAlarmTypeSupervisor        ProfinetAlarmType = 0x0008
	ProfinetAlarmTypeReleased          ProfinetAlarmType = 0x0009
	ProfinetAlarmTypePlugWrong         ProfinetAlarmType = 0x000A
	ProfinetAlarmTypeReturnOfSubmodule ProfinetAlarmType = 0x000B
	ProfinetAlarmTypeDiagDisappears    ProfinetAlarmType = 0x000C
	ProfinetAlarmTypeUploadRetrieval   ProfinetAlarmType = 0x001E
	ProfinetAlarmTypePullModule        ProfinetAlarmType = 0x001F
)

// String returns the alarm type name used by Wireshark.
func (t ProfinetAlarmType) String() string {
	if name, ok := profinetAlarmTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("(0x%x)", uint16(t))
}

// ProfinetAlarmSpecifier is the AlarmSpecifier bit field.
type ProfinetAlarmSpecifier uint16

// AlarmSpecifier bits.
const (
	ProfinetAlarmSpecChannel      ProfinetAlarmSpecifier = 0x0800
	ProfinetAlarmSpecManufacturer ProfinetAlarmSpecifier = 0x1000
	ProfinetAlarmSpecSubmodule    ProfinetAlarmSpecifier = 0x2000
	ProfinetAlarmSpecARDiagnosis  ProfinetAlarmSpecifier = 0x8000

	profinetAlarmSpecSeqMask = 0x07FF
)

// ChannelProperties layout: type (bits 0-7), accumulative (8),
// maintenance (9-10), specifier (11-12), direction (13-15).
const (
	profinetChannelPropTypeMask   = 0x00FF
	profinetChannelPropAccumBit   = 0x0100
	profinetChannelPropMaintShift = 9
	profinetChannelPropSpecShift  = 11
	profinetChannelPropDirShift   = 13
	profinetTwoBitMask            = 0x3
	profinetThreeBitMask          = 0x7
)

// Bits of the other block bit fields.
const (
	profinetMaintRequiredBit       uint32 = 0x1
	profinetMaintDemandedBit       uint32 = 0x2
	profinetSubmodulePropTypeMask         = 0x3
	profinetSubmoduleTypeInOut            = 0x3
	profinetARPropStateMask        uint32 = 0x7
	profinetARPropDeviceAccess     uint32 = 0x100
	profinetARPropAdvancedStartup  uint32 = 0x40000000
	profinetARPropPullModuleAlarm  uint32 = 0x80000000
	profinetIOCRPropRTClassMask    uint32 = 0xF
	profinetAlarmCRPropPriorityBit uint32 = 0x1
	profinetAlarmCRPropTransport   uint32 = 0x2
)

// SequenceNumber returns the alarm sequence number (11 bits).
func (s ProfinetAlarmSpecifier) SequenceNumber() uint16 { return uint16(s) & profinetAlarmSpecSeqMask }

// ChannelDiagnosis reports whether a channel diagnosis is pending.
func (s ProfinetAlarmSpecifier) ChannelDiagnosis() bool { return s&ProfinetAlarmSpecChannel != 0 }

// ManufacturerDiagnosis reports whether a manufacturer specific diagnosis
// is pending.
func (s ProfinetAlarmSpecifier) ManufacturerDiagnosis() bool {
	return s&ProfinetAlarmSpecManufacturer != 0
}

// SubmoduleDiagnosis reports whether the submodule has a diagnosis pending.
func (s ProfinetAlarmSpecifier) SubmoduleDiagnosis() bool { return s&ProfinetAlarmSpecSubmodule != 0 }

// ARDiagnosis reports whether the AR has a diagnosis pending.
func (s ProfinetAlarmSpecifier) ARDiagnosis() bool { return s&ProfinetAlarmSpecARDiagnosis != 0 }

// ProfinetUSI is the UserStructureIdentifier that opens each alarm item.
type ProfinetUSI uint16

// User structure identifiers. Values below 0x8000 are manufacturer
// specific.
const (
	ProfinetUSIChannelDiagnosis    ProfinetUSI = 0x8000
	ProfinetUSIMultiple            ProfinetUSI = 0x8001
	ProfinetUSIExtChannelDiagnosis ProfinetUSI = 0x8002
	ProfinetUSIQualifiedDiagnosis  ProfinetUSI = 0x8003
	ProfinetUSIMaintenance         ProfinetUSI = 0x8100
	ProfinetUSIUploadRetrieval     ProfinetUSI = 0x8200
	ProfinetUSIIParameter          ProfinetUSI = 0x8201
	ProfinetUSIRSLowWatermark      ProfinetUSI = 0x8300
	ProfinetUSIRSTimeout           ProfinetUSI = 0x8301
	ProfinetUSIRSOverflow          ProfinetUSI = 0x8302
	ProfinetUSIRSEvent             ProfinetUSI = 0x8303
	ProfinetUSIPEEnergySaving      ProfinetUSI = 0x8310
	ProfinetUSIPRAL                ProfinetUSI = 0x8320

	profinetUSIStandardFirst ProfinetUSI = 0x8000
)

// IsManufacturer reports whether the item is manufacturer specific data.
func (u ProfinetUSI) IsManufacturer() bool { return u < profinetUSIStandardFirst }

// String returns the identifier name used by Wireshark.
func (u ProfinetUSI) String() string {
	switch u {
	case ProfinetUSIChannelDiagnosis:
		return "ChannelDiagnosis"
	case ProfinetUSIMultiple:
		return "Multiple"
	case ProfinetUSIExtChannelDiagnosis:
		return "ExtChannelDiagnosis"
	case ProfinetUSIQualifiedDiagnosis:
		return "QualifiedChannelDiagnosis"
	case ProfinetUSIMaintenance:
		return "Maintenance"
	case ProfinetUSIUploadRetrieval:
		return "Upload&Retrieval"
	case ProfinetUSIIParameter:
		return "iParameter"
	case ProfinetUSIRSLowWatermark:
		return "Reporting system RS_LowWatermark"
	case ProfinetUSIRSTimeout:
		return "Reporting system RS_Timeout"
	case ProfinetUSIRSOverflow:
		return "Reporting system RS_Overflow"
	case ProfinetUSIRSEvent:
		return "Reporting system RS_Event"
	case ProfinetUSIPEEnergySaving:
		return "PE_EnergySavingStatus"
	case ProfinetUSIPRAL:
		return "Channel related Process Alarm reasons"
	}
	if u.IsManufacturer() {
		return fmt.Sprintf("Manufacturer specific(0x%04x)", uint16(u))
	}
	return fmt.Sprintf("Reserved(0x%04x)", uint16(u))
}

// ProfinetChannelProperties is the ChannelProperties field of a channel
// diagnosis.
type ProfinetChannelProperties uint16

// Type returns the channel data type (bits 0-7).
func (p ProfinetChannelProperties) Type() uint8 { return uint8(p & profinetChannelPropTypeMask) }

// Accumulative reports whether the diagnosis sums up several channels.
func (p ProfinetChannelProperties) Accumulative() bool { return p&profinetChannelPropAccumBit != 0 }

// Maintenance returns the severity (bits 9-10): 0 fault, 1 maintenance
// required, 2 maintenance demanded, 3 see the qualified qualifier.
func (p ProfinetChannelProperties) Maintenance() uint8 {
	return uint8(p>>profinetChannelPropMaintShift) & profinetTwoBitMask
}

// Specifier returns bits 11-12: 0 all disappear, 1 appears, 2 disappears,
// 3 disappears but others remain.
func (p ProfinetChannelProperties) Specifier() uint8 {
	return uint8(p>>profinetChannelPropSpecShift) & profinetTwoBitMask
}

// Direction returns bits 13-15: 0 manufacturer specific, 1 input,
// 2 output, 3 input/output.
func (p ProfinetChannelProperties) Direction() uint8 {
	return uint8(p>>profinetChannelPropDirShift) & profinetThreeBitMask
}

// ProfinetAlarmItem is one user structure of an alarm notification.
//
// Data holds the item's bytes after the identifier. The typed fields are
// set for the identifiers they belong to.
type ProfinetAlarmItem struct {
	USI  ProfinetUSI
	Data []byte

	// ChannelDiagnosis, ExtChannelDiagnosis, QualifiedChannelDiagnosis
	// and, for the first two fields, PRAL items.
	ChannelNumber     uint16
	ChannelProperties ProfinetChannelProperties
	ChannelErrorType  uint16

	// ExtChannelDiagnosis and QualifiedChannelDiagnosis.
	ExtChannelErrorType uint16
	ExtChannelAddValue  uint32

	// QualifiedChannelDiagnosis.
	QualifiedChannelQualifier uint32

	// PRAL (channel related process alarm reason).
	PRALReason         uint16
	PRALExtReason      uint16
	PRALReasonAddValue []byte

	// Maintenance, Upload&Retrieval, iParameter and PE_EnergySavingStatus
	// items wrap a block.
	Block *ProfinetBlock
}

// ProfinetAlarmNotification is the body of an alarm notification block.
type ProfinetAlarmNotification struct {
	AlarmType            ProfinetAlarmType
	API                  uint32
	Slot                 uint16
	Subslot              uint16
	ModuleIdentNumber    uint32
	SubmoduleIdentNumber uint32
	Specifier            ProfinetAlarmSpecifier
	Items                []ProfinetAlarmItem
}

// ProfinetAlarmAck is the body of an alarm acknowledge block.
type ProfinetAlarmAck struct {
	AlarmType ProfinetAlarmType
	API       uint32
	Slot      uint16
	Subslot   uint16
	Specifier ProfinetAlarmSpecifier
	Status    ProfinetPNIOStatus
}

func decodeProfinetAlarmNotif(r *profinetReader) *ProfinetAlarmNotification {
	if r.left() < profinetAlarmHeadLen {
		return nil
	}

	a := &ProfinetAlarmNotification{
		AlarmType:            ProfinetAlarmType(r.u16()),
		API:                  r.u32(),
		Slot:                 r.u16(),
		Subslot:              r.u16(),
		ModuleIdentNumber:    r.u32(),
		SubmoduleIdentNumber: r.u32(),
		Specifier:            ProfinetAlarmSpecifier(r.u16()),
	}

	// Items until the body ends. Each takes at least its 2-byte USI, and
	// typed ones at least 8 bytes, which sizes the list.
	if n := r.left() / profinetAlarmItemMinLen; n > 0 {
		a.Items = make([]ProfinetAlarmItem, 0, n)
	}
	for r.left() >= 2 {
		a.Items = append(a.Items, decodeProfinetAlarmItem(r))
	}
	return a
}

// decodeProfinetAlarmItem reads one user structure. Identifiers with no
// fixed size take the rest of the body, as in Wireshark.
func decodeProfinetAlarmItem(r *profinetReader) ProfinetAlarmItem {
	it := ProfinetAlarmItem{USI: ProfinetUSI(r.u16())}
	start := r.off

	switch it.USI {
	case ProfinetUSIChannelDiagnosis:
		it.decodeDiagnosis(r, profinetChannelDiagLen)
	case ProfinetUSIExtChannelDiagnosis:
		it.decodeDiagnosis(r, profinetExtChannelDiagLen)
	case ProfinetUSIQualifiedDiagnosis:
		it.decodeDiagnosis(r, profinetQualChannelLen)
	case ProfinetUSIMaintenance:
		it.decodeItemBlock(r)
	case ProfinetUSIUploadRetrieval, ProfinetUSIIParameter, ProfinetUSIPEEnergySaving:
		it.decodeItemBlock(r)
		r.rest()
	case ProfinetUSIPRAL:
		it.decodePRAL(r)
	default:
		r.rest()
	}

	it.Data = r.data[start:r.off]
	return it
}

// decodeDiagnosis reads a channel diagnosis of the given size: 6 bytes
// plain, 12 extended, 16 qualified. A cut item stays raw.
func (it *ProfinetAlarmItem) decodeDiagnosis(r *profinetReader, size int) {
	if r.left() < size {
		r.rest()
		return
	}

	it.ChannelNumber = r.u16()
	it.ChannelProperties = ProfinetChannelProperties(r.u16())
	it.ChannelErrorType = r.u16()
	if size == profinetChannelDiagLen {
		return
	}

	it.ExtChannelErrorType = r.u16()
	it.ExtChannelAddValue = r.u32()
	if size == profinetExtChannelDiagLen {
		return
	}

	it.QualifiedChannelQualifier = r.u32()
}

// decodeItemBlock reads the block an item wraps. Without a whole block
// header the item stays raw.
func (it *ProfinetAlarmItem) decodeItemBlock(r *profinetReader) {
	b, n, err := decodeProfinetBlock(r.data[r.off:], profinetBlockNested)
	if err != nil {
		r.rest()
		return
	}

	it.Block = &b
	r.bytes(n)
}

// decodePRAL reads a process alarm reason; everything after the fixed
// fields is the reason add value.
func (it *ProfinetAlarmItem) decodePRAL(r *profinetReader) {
	if r.left() < profinetPRALMinLen {
		r.rest()
		return
	}

	it.ChannelNumber = r.u16()
	it.ChannelProperties = ProfinetChannelProperties(r.u16())
	it.PRALReason = r.u16()
	it.PRALExtReason = r.u16()
	it.PRALReasonAddValue = r.rest()
}

func decodeProfinetAlarmAck(r *profinetReader) *ProfinetAlarmAck {
	if r.left() < profinetAlarmAckLen {
		return nil
	}

	return &ProfinetAlarmAck{
		AlarmType: ProfinetAlarmType(r.u16()),
		API:       r.u32(),
		Slot:      r.u16(),
		Subslot:   r.u16(),
		Specifier: ProfinetAlarmSpecifier(r.u16()),
		Status:    r.status(),
	}
}

// ProfinetMaintenanceStatus is the MaintenanceStatus of a MaintenanceItem.
type ProfinetMaintenanceStatus uint32

// Required reports whether maintenance is required.
func (s ProfinetMaintenanceStatus) Required() bool { return uint32(s)&profinetMaintRequiredBit != 0 }

// Demanded reports whether maintenance is demanded.
func (s ProfinetMaintenanceStatus) Demanded() bool { return uint32(s)&profinetMaintDemandedBit != 0 }

// ProfinetAlarmItemBlock is the body of the blocks alarm items wrap.
type ProfinetAlarmItemBlock struct {
	// MaintenanceItem.
	MaintenanceStatus ProfinetMaintenanceStatus

	// Upload&Retrieval items (IEC 61158-6-10; Wireshark leaves them raw).
	URRecordIndex  uint32
	URRecordLength uint32

	// iParameterItem (IEC 61158-6-10; Wireshark leaves it raw).
	IParReqHeader uint32
	MaxSegmSize   uint32
	TransferIndex uint32
	TotalIParSize uint32

	// PE alarm: PE_OperationalMode.
	PEOperationalMode uint8
}

// decodeProfinetItemBlock reads an alarm item block. All but the PE alarm
// open with two padding bytes.
func decodeProfinetItemBlock(r *profinetReader, t ProfinetBlockType) *ProfinetAlarmItemBlock {
	it := &ProfinetAlarmItemBlock{}
	if t == ProfinetBlockPEAlarm {
		it.PEOperationalMode = r.u8()
		return it.orNil(r)
	}

	r.bytes(2)
	switch t {
	case ProfinetBlockMaintenanceItem:
		it.MaintenanceStatus = ProfinetMaintenanceStatus(r.u32())
	case ProfinetBlockIParameterItem:
		it.IParReqHeader = r.u32()
		it.MaxSegmSize = r.u32()
		it.TransferIndex = r.u32()
		it.TotalIParSize = r.u32()
	default:
		it.URRecordIndex = r.u32()
		it.URRecordLength = r.u32()
	}
	return it.orNil(r)
}

// orNil drops a body that ended before its fields.
func (it *ProfinetAlarmItemBlock) orNil(r *profinetReader) *ProfinetAlarmItemBlock {
	if r.short {
		return nil
	}
	return it
}

// ProfinetARType is the ARType of an AR block.
type ProfinetARType uint16

// AR types.
const (
	ProfinetARTypeIOController ProfinetARType = 0x0001
	ProfinetARTypeIOCARCIR     ProfinetARType = 0x0003
	ProfinetARTypeSupervisor   ProfinetARType = 0x0006
	ProfinetARTypeRTClass3     ProfinetARType = 0x0010
	ProfinetARTypeSysRed       ProfinetARType = 0x0020
)

// String returns the AR type name used by Wireshark.
func (t ProfinetARType) String() string {
	switch t {
	case ProfinetARTypeIOController:
		return "IO Controller AR"
	case ProfinetARTypeIOCARCIR:
		return "IOCARCIR"
	case ProfinetARTypeSupervisor:
		return "IO Supervisor AR / DeviceAccess AR"
	case ProfinetARTypeRTClass3:
		return "IO Controller AR (RT_CLASS_3)"
	case ProfinetARTypeSysRed:
		return "IO Controller AR (sysred/CiR)"
	}
	return fmt.Sprintf("reserved(0x%04x)", uint16(t))
}

// ProfinetARProperties is the ARProperties bit field of an ARBlockReq.
type ProfinetARProperties uint32

// State returns the AR state (bits 0-2): 1 active.
func (p ProfinetARProperties) State() uint8 { return uint8(uint32(p) & profinetARPropStateMask) }

// DeviceAccess reports whether the AR is a device access AR.
func (p ProfinetARProperties) DeviceAccess() bool { return uint32(p)&profinetARPropDeviceAccess != 0 }

// AdvancedStartup reports whether the advanced startup mode is used.
func (p ProfinetARProperties) AdvancedStartup() bool {
	return uint32(p)&profinetARPropAdvancedStartup != 0
}

// PullModuleAlarm reports whether pull module alarms are allowed.
func (p ProfinetARProperties) PullModuleAlarm() bool {
	return uint32(p)&profinetARPropPullModuleAlarm != 0
}

// ProfinetARBlock is an ARBlockReq or ARBlockRes.
//
// The request names the CM initiator, the response the CM responder; the
// fields after UDPRTPort exist only in requests.
type ProfinetARBlock struct {
	ARType     ProfinetARType
	ARUUID     ProfinetUUID
	SessionKey uint16
	MAC        net.HardwareAddr // CMInitiatorMacAdd or CMResponderMacAdd
	UDPRTPort  uint16           // InitiatorUDPRTPort or ResponderUDPRTPort

	ObjectUUID            ProfinetUUID // CMInitiatorObjectUUID
	Properties            ProfinetARProperties
	ActivityTimeoutFactor uint16
	StationName           string // CMInitiatorStationName
}

func decodeProfinetARReq(r *profinetReader) *ProfinetARBlock {
	if r.left() < profinetARReqFixedLen {
		return nil
	}

	a := &ProfinetARBlock{
		ARType:                ProfinetARType(r.u16()),
		ARUUID:                r.uuid(),
		SessionKey:            r.u16(),
		MAC:                   r.mac(),
		ObjectUUID:            r.uuid(),
		Properties:            ProfinetARProperties(r.u32()),
		ActivityTimeoutFactor: r.u16(),
		UDPRTPort:             r.u16(),
	}

	// The name is clipped to the body when its length lies.
	n := int(r.u16())
	if n > r.left() {
		n = r.left()
	}
	a.StationName = string(r.bytes(n))
	return a
}

func decodeProfinetARRes(r *profinetReader) *ProfinetARBlock {
	if r.left() < profinetARResLen {
		return nil
	}

	return &ProfinetARBlock{
		ARType:     ProfinetARType(r.u16()),
		ARUUID:     r.uuid(),
		SessionKey: r.u16(),
		MAC:        r.mac(),
		UDPRTPort:  r.u16(),
	}
}

// ProfinetIOCRType is the IOCRType of an IOCR block.
type ProfinetIOCRType uint16

// IOCR types.
const (
	ProfinetIOCRInput             ProfinetIOCRType = 0x0001
	ProfinetIOCROutput            ProfinetIOCRType = 0x0002
	ProfinetIOCRMulticastProvider ProfinetIOCRType = 0x0003
	ProfinetIOCRMulticastConsumer ProfinetIOCRType = 0x0004
)

// String returns the IOCR type name used by Wireshark.
func (t ProfinetIOCRType) String() string {
	switch t {
	case ProfinetIOCRInput:
		return "Input CR"
	case ProfinetIOCROutput:
		return "Output CR"
	case ProfinetIOCRMulticastProvider:
		return "Multicast Provider CR"
	case ProfinetIOCRMulticastConsumer:
		return "Multicast Consumer CR"
	}
	return fmt.Sprintf("reserved(0x%04x)", uint16(t))
}

// ProfinetIOCRProperties is the IOCRProperties bit field.
type ProfinetIOCRProperties uint32

// RTClass returns the RT class (bits 0-3): 1 and 2 RT_CLASS_1, 3
// RT_CLASS_3, 4 RT_CLASS_UDP, 5 RT_CLASS_STREAM.
func (p ProfinetIOCRProperties) RTClass() uint8 {
	return uint8(uint32(p) & profinetIOCRPropRTClassMask)
}

// ProfinetIOObject locates an IO data object or an IOCS in the cyclic frame.
type ProfinetIOObject struct {
	Slot        uint16
	Subslot     uint16
	FrameOffset uint16
}

// ProfinetIOCRAPI lists the IO data of one API in an IOCRBlockReq.
type ProfinetIOCRAPI struct {
	API           uint32
	IODataObjects []ProfinetIOObject
	IOCS          []ProfinetIOObject
}

// ProfinetIOCRBlock is an IOCRBlockReq or IOCRBlockRes. The response
// carries only the type, the reference and the frame ID.
type ProfinetIOCRBlock struct {
	IOCRType      ProfinetIOCRType
	IOCRReference uint16
	FrameID       ProfinetFrameID

	LT              EthernetType
	Properties      ProfinetIOCRProperties
	DataLength      uint16
	SendClockFactor uint16
	ReductionRatio  uint16
	Phase           uint16
	Sequence        uint16
	FrameSendOffset uint32
	WatchdogFactor  uint16
	DataHoldFactor  uint16
	TagHeader       uint16
	MulticastMAC    net.HardwareAddr
	APIs            []ProfinetIOCRAPI
}

func decodeProfinetIOCRReq(r *profinetReader) *ProfinetIOCRBlock {
	if r.left() < profinetIOCRReqFixedLen {
		return nil
	}

	c := &ProfinetIOCRBlock{
		IOCRType:        ProfinetIOCRType(r.u16()),
		IOCRReference:   r.u16(),
		LT:              EthernetType(r.u16()),
		Properties:      ProfinetIOCRProperties(r.u32()),
		DataLength:      r.u16(),
		FrameID:         ProfinetFrameID(r.u16()),
		SendClockFactor: r.u16(),
		ReductionRatio:  r.u16(),
		Phase:           r.u16(),
		Sequence:        r.u16(),
		FrameSendOffset: r.u32(),
		WatchdogFactor:  r.u16(),
		DataHoldFactor:  r.u16(),
		TagHeader:       r.u16(),
		MulticastMAC:    r.mac(),
	}

	c.APIs = make([]ProfinetIOCRAPI, r.count(profinetIOCRAPIMinLen))
	for i := range c.APIs {
		api := &c.APIs[i]
		api.API = r.u32()
		api.IODataObjects = r.ioObjects()
		api.IOCS = r.ioObjects()
	}
	return c
}

// ioObjects reads a counted list of slot, subslot and frame offset.
func (r *profinetReader) ioObjects() []ProfinetIOObject {
	objs := make([]ProfinetIOObject, r.count(profinetIOObjectLen))
	for i := range objs {
		objs[i] = ProfinetIOObject{Slot: r.u16(), Subslot: r.u16(), FrameOffset: r.u16()}
	}
	return objs
}

func decodeProfinetIOCRRes(r *profinetReader) *ProfinetIOCRBlock {
	if r.left() < profinetIOCRResLen {
		return nil
	}

	return &ProfinetIOCRBlock{
		IOCRType:      ProfinetIOCRType(r.u16()),
		IOCRReference: r.u16(),
		FrameID:       ProfinetFrameID(r.u16()),
	}
}

// ProfinetAlarmCRProperties is the AlarmCRProperties bit field.
type ProfinetAlarmCRProperties uint32

// LowPriorityOnly reports whether the user priority is ignored and every
// alarm travels with low priority (bit 0).
func (p ProfinetAlarmCRProperties) LowPriorityOnly() bool {
	return uint32(p)&profinetAlarmCRPropPriorityBit != 0
}

// UDPTransport reports whether alarms use RTA_CLASS_UDP rather than
// RTA_CLASS_1 (bit 1).
func (p ProfinetAlarmCRProperties) UDPTransport() bool {
	return uint32(p)&profinetAlarmCRPropTransport != 0
}

// ProfinetAlarmCRBlock is an AlarmCRBlockReq or AlarmCRBlockRes. The
// response carries only the type, the reference and the data length.
type ProfinetAlarmCRBlock struct {
	AlarmCRType        uint16
	LocalAlarmRef      uint16
	MaxAlarmDataLength uint16

	LT               EthernetType
	Properties       ProfinetAlarmCRProperties
	RTATimeoutFactor uint16
	RTARetries       uint16
	TagHeaderHigh    uint16
	TagHeaderLow     uint16
}

func decodeProfinetAlarmCRReq(r *profinetReader) *ProfinetAlarmCRBlock {
	if r.left() < profinetAlarmCRReqLen {
		return nil
	}

	return &ProfinetAlarmCRBlock{
		AlarmCRType:        r.u16(),
		LT:                 EthernetType(r.u16()),
		Properties:         ProfinetAlarmCRProperties(r.u32()),
		RTATimeoutFactor:   r.u16(),
		RTARetries:         r.u16(),
		LocalAlarmRef:      r.u16(),
		MaxAlarmDataLength: r.u16(),
		TagHeaderHigh:      r.u16(),
		TagHeaderLow:       r.u16(),
	}
}

func decodeProfinetAlarmCRRes(r *profinetReader) *ProfinetAlarmCRBlock {
	if r.left() < profinetAlarmCRResLen {
		return nil
	}

	return &ProfinetAlarmCRBlock{
		AlarmCRType:        r.u16(),
		LocalAlarmRef:      r.u16(),
		MaxAlarmDataLength: r.u16(),
	}
}

// ProfinetDataDescription sizes the input or output data of a submodule.
type ProfinetDataDescription struct {
	Type       uint16 // 1 input, 2 output
	DataLength uint16
	LengthIOCS uint8
	LengthIOPS uint8
}

// ProfinetExpectedSubmodule is one submodule of an expected module.
type ProfinetExpectedSubmodule struct {
	Subslot      uint16
	IdentNumber  uint32
	Properties   uint16
	Descriptions []ProfinetDataDescription // two for input and output submodules
}

// ProfinetExpectedAPI is one API entry of an ExpectedSubmoduleBlockReq:
// the module expected in a slot and its submodules.
type ProfinetExpectedAPI struct {
	API               uint32
	Slot              uint16
	ModuleIdentNumber uint32
	ModuleProperties  uint16
	Submodules        []ProfinetExpectedSubmodule
}

// ProfinetExpectedBlock is an ExpectedSubmoduleBlockReq.
type ProfinetExpectedBlock struct {
	APIs []ProfinetExpectedAPI
}

func decodeProfinetExpected(r *profinetReader) *ProfinetExpectedBlock {
	if r.left() < 2 {
		return nil
	}

	e := &ProfinetExpectedBlock{APIs: make([]ProfinetExpectedAPI, r.count(profinetExpAPIMinLen))}
	for i := range e.APIs {
		api := &e.APIs[i]
		api.API = r.u32()
		api.Slot = r.u16()
		api.ModuleIdentNumber = r.u32()
		api.ModuleProperties = r.u16()

		api.Submodules = make([]ProfinetExpectedSubmodule, r.count(profinetExpSubmoduleMin))
		for j := range api.Submodules {
			r.expectedSubmodule(&api.Submodules[j])
		}
	}
	return e
}

// expectedSubmodule reads one submodule. Input and output submodules
// (properties type 3) carry two data descriptions, all others one.
func (r *profinetReader) expectedSubmodule(s *ProfinetExpectedSubmodule) {
	s.Subslot = r.u16()
	s.IdentNumber = r.u32()
	s.Properties = r.u16()

	n := 1
	if s.Properties&profinetSubmodulePropTypeMask == profinetSubmoduleTypeInOut {
		n = 2
	}
	if max := r.left() / profinetDataDescLen; n > max {
		r.short = true
		n = max
	}

	s.Descriptions = make([]ProfinetDataDescription, n)
	for i := range s.Descriptions {
		s.Descriptions[i] = ProfinetDataDescription{Type: r.u16(), DataLength: r.u16(), LengthIOCS: r.u8(), LengthIOPS: r.u8()}
	}
}

// ProfinetDiffSubmodule is one submodule of a ModuleDiffBlock.
type ProfinetDiffSubmodule struct {
	Subslot     uint16
	IdentNumber uint32
	State       uint16
}

// ProfinetDiffModule is one module of a ModuleDiffBlock. State is 0 no
// module, 1 wrong module, 2 proper module, 3 substitute.
type ProfinetDiffModule struct {
	Slot        uint16
	IdentNumber uint32
	State       uint16
	Submodules  []ProfinetDiffSubmodule
}

// ProfinetDiffAPI is one API entry of a ModuleDiffBlock.
type ProfinetDiffAPI struct {
	API     uint32
	Modules []ProfinetDiffModule
}

// ProfinetModuleDiffBlock is a ModuleDiffBlock: how the real configuration
// differs from the expected one.
type ProfinetModuleDiffBlock struct {
	APIs []ProfinetDiffAPI
}

func decodeProfinetModuleDiff(r *profinetReader) *ProfinetModuleDiffBlock {
	if r.left() < 2 {
		return nil
	}

	d := &ProfinetModuleDiffBlock{APIs: make([]ProfinetDiffAPI, r.count(profinetDiffAPIMinLen))}
	for i := range d.APIs {
		api := &d.APIs[i]
		api.API = r.u32()

		api.Modules = make([]ProfinetDiffModule, r.count(profinetDiffModuleMinLen))
		for j := range api.Modules {
			m := &api.Modules[j]
			m.Slot = r.u16()
			m.IdentNumber = r.u32()
			m.State = r.u16()

			m.Submodules = make([]ProfinetDiffSubmodule, r.count(profinetDiffSubmoduleLen))
			for k := range m.Submodules {
				m.Submodules[k] = ProfinetDiffSubmodule{Subslot: r.u16(), IdentNumber: r.u32(), State: r.u16()}
			}
		}
	}
	return d
}

// ProfinetARServerBlock is an ARServerBlockRes.
type ProfinetARServerBlock struct {
	StationName string // CMResponderStationName
}

func decodeProfinetARServer(r *profinetReader) *ProfinetARServerBlock {
	if r.left() < 2 {
		return nil
	}

	n := int(r.u16())
	if n > r.left() {
		n = r.left()
	}
	return &ProfinetARServerBlock{StationName: string(r.bytes(n))}
}

// ProfinetControlCommand is the ControlCommand bit field.
type ProfinetControlCommand uint16

// Control commands.
const (
	ProfinetControlPrmEnd            ProfinetControlCommand = 0x0001
	ProfinetControlApplicationReady  ProfinetControlCommand = 0x0002
	ProfinetControlRelease           ProfinetControlCommand = 0x0004
	ProfinetControlDone              ProfinetControlCommand = 0x0008
	ProfinetControlReadyForCompanion ProfinetControlCommand = 0x0010
	ProfinetControlReadyForRTClass3  ProfinetControlCommand = 0x0020
	ProfinetControlPrmBegin          ProfinetControlCommand = 0x0040
)

// String names the command bits that are set.
func (c ProfinetControlCommand) String() string {
	names := []struct {
		bit  ProfinetControlCommand
		name string
	}{
		{ProfinetControlPrmEnd, "PrmEnd"},
		{ProfinetControlApplicationReady, "ApplicationReady"},
		{ProfinetControlRelease, "Release"},
		{ProfinetControlDone, "Done"},
		{ProfinetControlReadyForCompanion, "ReadyForCompanion"},
		{ProfinetControlReadyForRTClass3, "ReadyForRT_CLASS_3"},
		{ProfinetControlPrmBegin, "PrmBegin"},
	}

	s := ""
	for _, n := range names {
		if c&n.bit == 0 {
			continue
		}
		if s != "" {
			s += "|"
		}
		s += n.name
	}
	if s == "" {
		return fmt.Sprintf("0x%04x", uint16(c))
	}
	return s
}

// ProfinetControlBlock is the body shared by the IODControl, IOXControl,
// IODRelease and PrmBegin request and response blocks.
type ProfinetControlBlock struct {
	ARUUID     ProfinetUUID
	SessionKey uint16

	// AlarmSequenceNumber is meaningful in the plug variants (Plug Prm End,
	// Plug Application Ready); it is reserved in the others.
	AlarmSequenceNumber uint16
	Command             ProfinetControlCommand
	Properties          uint16
}

func decodeProfinetControl(r *profinetReader) *ProfinetControlBlock {
	if r.left() < profinetControlLen {
		return nil
	}

	r.bytes(2) // reserved
	return &ProfinetControlBlock{
		ARUUID:              r.uuid(),
		SessionKey:          r.u16(),
		AlarmSequenceNumber: r.u16(),
		Command:             ProfinetControlCommand(r.u16()),
		Properties:          r.u16(),
	}
}

// ProfinetRecordBlock is an IODWriteReqHeader, IODReadReqHeader,
// IODWriteResHeader or IODReadResHeader block.
//
// Data is the record data that follows a write request or a read response
// header, clipped to the captured bytes. Its layout depends on Index; for
// the indices that hold blocks, ProfinetDecodeBlocks parses it.
type ProfinetRecordBlock struct {
	SeqNumber        uint16
	ARUUID           ProfinetUUID
	API              uint32
	Slot             uint16
	Subslot          uint16
	Index            uint16
	RecordDataLength uint32

	TargetARUUID ProfinetUUID       // read request with a nil ARUUID (implicit read)
	AddVal1      uint16             // responses
	AddVal2      uint16             // responses
	Status       ProfinetPNIOStatus // write response

	Data []byte
}

// profinetIndexMultiWrite is the record index of a write request that
// wraps several write requests instead of record data.
const profinetIndexMultiWrite = 0xE040

// carriesData reports whether record data follows a header of block
// type t.
func (rec *ProfinetRecordBlock) carriesData(t ProfinetBlockType) bool {
	switch t {
	case ProfinetBlockIODWriteReq:
		return rec.Index != profinetIndexMultiWrite
	case ProfinetBlockIODReadRes:
		return true
	}
	return false
}

func decodeProfinetRecord(r *profinetReader, t ProfinetBlockType) *ProfinetRecordBlock {
	if r.left() < profinetRecordHeadLen {
		return nil
	}

	rec := &ProfinetRecordBlock{
		SeqNumber: r.u16(),
		ARUUID:    r.uuid(),
		API:       r.u32(),
		Slot:      r.u16(),
		Subslot:   r.u16(),
	}
	r.bytes(2) // padding
	rec.Index = r.u16()
	rec.RecordDataLength = r.u32()

	// The tail differs per block; the rest of each body is padding.
	switch t {
	case ProfinetBlockIODReadReq:
		if rec.ARUUID.IsZero() && r.left() >= profinetUUIDLen {
			rec.TargetARUUID = r.uuid()
		}
	case ProfinetBlockIODWriteRes:
		if r.left() >= 2*2+profinetPNIOStatusLen {
			rec.AddVal1 = r.u16()
			rec.AddVal2 = r.u16()
			rec.Status = r.status()
		}
	case ProfinetBlockIODReadRes:
		if r.left() >= 2*2 {
			rec.AddVal1 = r.u16()
			rec.AddVal2 = r.u16()
		}
	}
	return rec
}
