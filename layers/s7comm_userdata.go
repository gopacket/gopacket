// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"time"
)

// S7comm Userdata (ROSCTR 7) carries the programming and diagnostic
// services. Its parameter is
//
//	0x00 | count | 0x12 | len | syntax | type+group | subfunction | seq
//	[ data unit ref | last data unit | error code(2) ]   (len 8 only)
//
// and its data a single item: return code, transport size, length,
// value. Decoded values: SZL read and its records, alarms, diagnostic
// and message service, AR_SEND (CPU functions); block lists and info
// (block functions); clock read and set; cyclic data and read record;
// programmer commands; PBC BSEND; NC programming. The security and
// data record routing groups and other subfunctions stay raw in
// S7CommUserdata.Data. Responses
// split over several PDUs (data unit reference set, or more data units
// following) are left raw: only the reassembled whole has the
// structure, and gopacket decodes one packet at a time. Feed the
// layers to an S7CommUDAssembler to get the joined, decoded value.

const (
	// Head octets before the userdata address length: function, count,
	// variable specification.
	s7commUDHeadLen = 3
	// Head, length and the four octets every userdata parameter has.
	s7commUDShortLen = s7commUDHeadLen + 1 + 4
	// Short parameter plus data unit reference, last unit, error code.
	s7commUDExtLen = s7commUDShortLen + 4

	s7commUDTypeShift = 6
	s7commUDGroupMask = 0x3F

	// Shortest data that counts as a data unit, as in Wireshark.
	s7commUDMinUnit = 2
	// Octets before each data unit: NC programming; PBC BSEND, AR_SEND.
	s7commNCUnitHead  = 2
	s7commPBCUnitHead = 8

	// SZL request: ID, index. Response adds record length and count.
	s7commSZLReqLen  = 4
	s7commSZLRespLen = 8

	// Bits 8-11 of an SZL ID select the partial list extract; extract
	// 0xF asks for the list header (record length and count) alone.
	s7commSZLExtractShift = 8
	s7commSZLExtractMask  = 0x0F
	s7commSZLHeaderOnly   = 0x0F

	// Block functions: 2-octet ASCII block type; 4-octet list entries;
	// get block info request: type, 5-digit number, filesystem.
	s7commBlockTypeLen    = 2
	s7commBlockEntryLen   = 4
	s7commBlockNumDigits  = 5
	s7commBlockInfoReqLen = s7commBlockTypeLen + s7commBlockNumDigits + 1
)

// S7CommUserdataType is the direction of a Userdata PDU, the top two
// bits of the type/group octet.
type S7CommUserdataType uint8

// S7comm Userdata types.
const (
	S7CommUDTypePush     S7CommUserdataType = 0
	S7CommUDTypeRequest  S7CommUserdataType = 1
	S7CommUDTypeResponse S7CommUserdataType = 2
)

// String returns a human-readable name of the type.
func (t S7CommUserdataType) String() string {
	switch t {
	case S7CommUDTypePush:
		return "Push"
	case S7CommUDTypeRequest:
		return "Request"
	case S7CommUDTypeResponse:
		return "Response"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(t))
	}
}

// S7CommFuncGroup is the Userdata function group.
type S7CommFuncGroup uint8

// S7comm Userdata function groups.
const (
	S7CommGroupModeTransition S7CommFuncGroup = 0x0
	S7CommGroupProgrammer     S7CommFuncGroup = 0x1
	S7CommGroupCyclicData     S7CommFuncGroup = 0x2
	S7CommGroupBlock          S7CommFuncGroup = 0x3
	S7CommGroupCPU            S7CommFuncGroup = 0x4
	S7CommGroupSecurity       S7CommFuncGroup = 0x5
	S7CommGroupPBC            S7CommFuncGroup = 0x6
	S7CommGroupTime           S7CommFuncGroup = 0x7
	S7CommGroupDRR            S7CommFuncGroup = 0x20
	S7CommGroupNCProgramming  S7CommFuncGroup = 0x3F
)

// String returns the Wireshark name of the function group.
func (g S7CommFuncGroup) String() string {
	switch g {
	case S7CommGroupModeTransition:
		return "Mode-transition"
	case S7CommGroupProgrammer:
		return "Programmer commands"
	case S7CommGroupCyclicData:
		return "Cyclic data"
	case S7CommGroupBlock:
		return "Block functions"
	case S7CommGroupCPU:
		return "CPU functions"
	case S7CommGroupSecurity:
		return "Security"
	case S7CommGroupPBC:
		return "PBC BSEND/BRECV"
	case S7CommGroupTime:
		return "Time functions"
	case S7CommGroupDRR:
		return "Data record routing"
	case S7CommGroupNCProgramming:
		return "NC programming"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(g))
	}
}

// S7CommSubfunction is a Userdata subfunction; its meaning depends on
// the function group, so the constants carry the group in their name.
type S7CommSubfunction uint8

// Subfunctions of the CPU, block and time function groups.
const (
	S7CommCPUReadSZL        S7CommSubfunction = 0x01
	S7CommCPUMessageService S7CommSubfunction = 0x02
	S7CommCPUDiagMessage    S7CommSubfunction = 0x03
	S7CommCPUAlarm8Ind      S7CommSubfunction = 0x05
	S7CommCPUNotifyInd      S7CommSubfunction = 0x06
	S7CommCPUAlarm8Lock     S7CommSubfunction = 0x07
	S7CommCPUAlarm8Unlock   S7CommSubfunction = 0x08
	S7CommCPUAlarmAck       S7CommSubfunction = 0x0B
	S7CommCPUAlarmAckInd    S7CommSubfunction = 0x0C
	S7CommCPUAlarmSInd      S7CommSubfunction = 0x11
	S7CommCPUAlarmQuery     S7CommSubfunction = 0x13

	S7CommBlockList       S7CommSubfunction = 0x01
	S7CommBlockListOfType S7CommSubfunction = 0x02
	S7CommBlockGetInfo    S7CommSubfunction = 0x03

	S7CommTimeReadClock    S7CommSubfunction = 0x01
	S7CommTimeSetClock     S7CommSubfunction = 0x02
	S7CommTimeReadClockFol S7CommSubfunction = 0x03
	S7CommTimeSetClock2    S7CommSubfunction = 0x04
)

// Subfunctions of the NC programming group (Sinumerik file transfer).
const (
	S7CommNCRequestDownload S7CommSubfunction = 0x01
	S7CommNCDownloadBlock   S7CommSubfunction = 0x02
	S7CommNCContDownload    S7CommSubfunction = 0x03
	S7CommNCDownloadEnded   S7CommSubfunction = 0x04
	S7CommNCStartUpload     S7CommSubfunction = 0x06
	S7CommNCUpload          S7CommSubfunction = 0x07
	S7CommNCContUpload      S7CommSubfunction = 0x08
)

// ncHasUnitHeader reports whether the NC subfunction sends two unknown
// octets before each data unit of a response or push.
func (s S7CommSubfunction) ncHasUnitHeader() bool {
	switch s {
	case S7CommNCDownloadBlock, S7CommNCUpload, S7CommNCStartUpload:
		return true
	}
	return false
}

// S7CommBlockType is a block type as its two ASCII octets ("08" is OB).
type S7CommBlockType uint16

// S7 block types.
const (
	S7CommBlockOB  S7CommBlockType = 0x3038
	S7CommBlockDB  S7CommBlockType = 0x3041
	S7CommBlockSDB S7CommBlockType = 0x3042
	S7CommBlockFC  S7CommBlockType = 0x3043
	S7CommBlockSFC S7CommBlockType = 0x3044
	S7CommBlockFB  S7CommBlockType = 0x3045
	S7CommBlockSFB S7CommBlockType = 0x3046
)

// String returns the block type name.
func (b S7CommBlockType) String() string {
	switch b {
	case S7CommBlockOB:
		return "OB"
	case S7CommBlockDB:
		return "DB"
	case S7CommBlockSDB:
		return "SDB"
	case S7CommBlockFC:
		return "FC"
	case S7CommBlockSFC:
		return "SFC"
	case S7CommBlockFB:
		return "FB"
	case S7CommBlockSFB:
		return "SFB"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", uint16(b))
	}
}

// S7CommBlockLang is the programming language of a block.
type S7CommBlockLang uint8

// S7 block languages.
const (
	S7CommLangUndefined S7CommBlockLang = 0x00
	S7CommLangAWL       S7CommBlockLang = 0x01
	S7CommLangKOP       S7CommBlockLang = 0x02
	S7CommLangFUP       S7CommBlockLang = 0x03
	S7CommLangSCL       S7CommBlockLang = 0x04
	S7CommLangDB        S7CommBlockLang = 0x05
	S7CommLangGRAPH     S7CommBlockLang = 0x06
	S7CommLangSDB       S7CommBlockLang = 0x07
	S7CommLangCPUDB     S7CommBlockLang = 0x08
	S7CommLangSDBReset  S7CommBlockLang = 0x11
	S7CommLangSDBRoute  S7CommBlockLang = 0x12
	S7CommLangEncrypted S7CommBlockLang = 0x29
)

// String returns the Wireshark name of the block language.
func (l S7CommBlockLang) String() string {
	switch l {
	case S7CommLangUndefined:
		return "Not defined"
	case S7CommLangAWL:
		return "AWL"
	case S7CommLangKOP:
		return "KOP"
	case S7CommLangFUP:
		return "FUP"
	case S7CommLangSCL:
		return "SCL"
	case S7CommLangDB:
		return "DB"
	case S7CommLangGRAPH:
		return "GRAPH"
	case S7CommLangSDB:
		return "SDB"
	case S7CommLangCPUDB:
		return "CPU-DB"
	case S7CommLangSDBReset:
		return "SDB (after overall reset)"
	case S7CommLangSDBRoute:
		return "SDB (Routing)"
	case S7CommLangEncrypted:
		return "ENCRYPT"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(l))
	}
}

// S7CommSZL is a system status list (SZL) read. A request sets ID and
// Index only. Records alias the packet data, RecordLength octets each.
//
// The record views below Records are set for the IDs and indexes in
// s7comm_szl.go, one entry per record; others stay nil.
type S7CommSZL struct {
	ID           uint16
	Index        uint16
	RecordLength uint16
	RecordCount  uint16
	Records      [][]byte

	ModuleIDs       []S7CommSZLModuleID   // xy11
	Characteristics []uint16              // xy12
	Components      []S7CommSZLComponent  // xy1C
	CommCaps        []S7CommSZLCommCaps   // 0131 index 1
	CommStatus      []S7CommSZLCommStatus // 0132 index 1
	Protection      []S7CommSZLProtection // 0132 index 4
	TimeSystem      []S7CommSZLTimeSystem // 0132 index 8
	LEDs            []S7CommSZLLED        // xy74, xy19
	ModeEvents      []S7CommSZLModeEvent  // 0124, 0424
	DiagEvents      []S7CommDiagMessage   // xyA0
}

// HeaderOnly reports whether the SZL ID asks for the list header alone
// (partial list extract 0xF), so a response carries no records.
func (z *S7CommSZL) HeaderOnly() bool {
	return (z.ID>>s7commSZLExtractShift)&s7commSZLExtractMask == s7commSZLHeaderOnly
}

// S7CommBlockCount is one entry of a list blocks response.
type S7CommBlockCount struct {
	Type  S7CommBlockType
	Count uint16
}

// S7CommBlockEntry is one entry of a list blocks of type response.
type S7CommBlockEntry struct {
	Number   uint16
	Flags    uint8
	Language S7CommBlockLang
}

// S7CommUserdata is the decoded parameter and data of a Userdata PDU.
// DataUnitRef, LastDataUnit and ErrorCode are set only with the long
// (response) parameter. The value views below Data are set for an
// unfragmented value with data, whatever its return code, as Wireshark
// does; only an SZL response, a block info response and the clock
// need return code 0xFF, and block queries a transport size. A view is
// nil when its service does not apply. Data always keeps the raw
// value.
//
// DecodeErr records why the view matching the group and subfunction
// was not set, e.g. a count overrunning the data. DecodeFromBytes does
// not return it: the PDU itself is well formed. It does return a
// malformed SZL or block function value sent with return code 0xFF.
type S7CommUserdata struct {
	VarSpec       uint8
	ParamLength   uint8 // octets after this one
	SyntaxID      S7CommSyntaxID
	Type          S7CommUserdataType
	FunctionGroup S7CommFuncGroup
	Subfunction   S7CommSubfunction
	Sequence      uint8
	DataUnitRef   uint8
	LastDataUnit  uint8 // 0x00: last; otherwise more follow
	ErrorCode     uint16
	ReturnCode    S7CommReturnCode
	TransportSize S7CommDataTransportSize
	Length        uint16
	Data          []byte

	// UnitHeader holds the octets NC programming, PBC BSEND and AR_SEND
	// put before each data unit; Data starts after them.
	UnitHeader []byte

	// Fragments is the number of data units an S7CommUDAssembler joined
	// into Data; 0 for a view decoded from a single PDU.
	Fragments int

	SZL          *S7CommSZL
	BlockCounts  []S7CommBlockCount // list blocks response
	BlockEntries []S7CommBlockEntry // list blocks of type response
	BlockType    S7CommBlockType    // list of type and get info requests
	BlockNumber  string             // get block info request, ASCII digits
	Filesystem   uint8              // get block info request

	BlockInfo  *S7CommBlockInfo  // get block info response
	Clock      *time.Time        // clock read response, set request; UTC
	Cyclic     *S7CommCyclic     // cyclic data
	TIS        *S7CommTIS        // programmer commands
	Alarm      *S7CommAlarm      // alarm indications, ack, lock, query request
	AlarmQuery *S7CommAlarmQuery // alarm query response
	Diag       *S7CommDiagMessage
	MsgService *S7CommMsgService
	NC         *S7CommNCFile   // NC programming, joined value only
	Send       *S7CommSendData // PBC BSEND, AR_SEND
	DecodeErr  error
}

// Fragmented reports whether the PDU is one part of a multi-PDU
// value, which S7CommUDAssembler joins. It is false for the view the
// assembler returns.
func (u *S7CommUserdata) Fragmented() bool {
	if u.Fragments > 0 {
		return false
	}
	return u.DataUnitRef != 0 || u.LastDataUnit != 0
}

// SubfunctionName returns the subfunction name within its group.
func (u *S7CommUserdata) SubfunctionName() string {
	switch u.FunctionGroup {
	case S7CommGroupCPU:
		return s7commCPUSubfuncName(u.Subfunction)
	case S7CommGroupBlock:
		return s7commBlockSubfuncName(u.Subfunction)
	case S7CommGroupTime:
		return s7commTimeSubfuncName(u.Subfunction)
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(u.Subfunction))
}

func s7commCPUSubfuncName(s S7CommSubfunction) string {
	switch s {
	case S7CommCPUReadSZL:
		return "Read SZL"
	case S7CommCPUMessageService:
		return "Message service"
	case S7CommCPUDiagMessage:
		return "Diagnostic message"
	case S7CommCPUAlarm8Ind:
		return "ALARM_8 indication"
	case S7CommCPUNotifyInd:
		return "NOTIFY indication"
	case S7CommCPUAlarm8Lock:
		return "ALARM_8 lock"
	case S7CommCPUAlarm8Unlock:
		return "ALARM_8 unlock"
	case S7CommCPUAlarmAck:
		return "ALARM ack"
	case S7CommCPUAlarmAckInd:
		return "ALARM ack indication"
	case S7CommCPUAlarmSInd:
		return "ALARM_S indication"
	case S7CommCPUAlarmQuery:
		return "ALARM query"
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(s))
}

func s7commBlockSubfuncName(s S7CommSubfunction) string {
	switch s {
	case S7CommBlockList:
		return "List blocks"
	case S7CommBlockListOfType:
		return "List blocks of type"
	case S7CommBlockGetInfo:
		return "Get block info"
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(s))
}

func s7commTimeSubfuncName(s S7CommSubfunction) string {
	switch s {
	case S7CommTimeReadClock:
		return "Read clock"
	case S7CommTimeSetClock:
		return "Set clock"
	case S7CommTimeReadClockFol:
		return "Read clock (following)"
	case S7CommTimeSetClock2:
		return "Set clock"
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(s))
}

// decodeUserdata decodes the Userdata parameter and its data item.
func (s *S7Comm) decodeUserdata() error {
	p := s.Params
	if len(p) < s7commUDShortLen {
		return fmt.Errorf("%w: userdata parameter %d octets", ErrS7CommMalformed, len(p))
	}

	u := &S7CommUserdata{VarSpec: p[2], ParamLength: p[3]}
	s.ItemCount = p[1]
	s.Userdata = u
	if s7commUDHeadLen+1+int(u.ParamLength) > len(p) {
		return fmt.Errorf("%w: userdata parameter length %d", ErrS7CommMalformed, u.ParamLength)
	}

	u.SyntaxID = S7CommSyntaxID(p[4])
	u.Type = S7CommUserdataType(p[5] >> s7commUDTypeShift)
	u.FunctionGroup = S7CommFuncGroup(p[5] & s7commUDGroupMask)
	u.Subfunction = S7CommSubfunction(p[6])
	u.Sequence = p[7]
	if s7commUDHeadLen+1+int(u.ParamLength) >= s7commUDExtLen {
		u.DataUnitRef = p[8]
		u.LastDataUnit = p[9]
		u.ErrorCode = binary.BigEndian.Uint16(p[10:12])
	}

	d := s.Data
	if len(d) == 0 {
		return nil
	}
	if len(d) < s7commDataItemHead {
		return fmt.Errorf("%w: userdata data %d octets", ErrS7CommMalformed, len(d))
	}
	u.ReturnCode = S7CommReturnCode(d[0])
	u.TransportSize = S7CommDataTransportSize(d[1])
	u.Length = binary.BigEndian.Uint16(d[2:4])
	end := s7commDataItemHead + int(u.Length)
	if end > len(d) {
		return fmt.Errorf("%w: userdata data length %d", ErrS7CommMalformed, u.Length)
	}
	u.Data = d[s7commDataItemHead:end]
	u.splitUnitHeader()

	if u.Fragmented() {
		return nil
	}
	return u.decodeView()
}

// decodeView decodes the value if there is one. A value that does not
// parse fails the PDU only when it came with return code 0xFF; with
// any other the station vouches for nothing and the reason goes to
// DecodeErr.
func (u *S7CommUserdata) decodeView() error {
	if len(u.Data) == 0 {
		return nil
	}

	err := u.decodeValue()
	if err != nil && u.ReturnCode != S7CommRetSuccess {
		u.DecodeErr = err
		return nil
	}
	return err
}

// splitUnitHeader moves the octets some services send before every
// data unit from Data to UnitHeader, so that joined units form the
// value:
//
//	NC programming download block, upload and start upload,
//	response or push:                         unknown(2)
//	PBC BSEND request or response, AR_SEND:   varspec, length,
//	                                          syntax ID, unknown,
//	                                          R_ID or AR_ID(4)
func (u *S7CommUserdata) splitUnitHeader() {
	n := 0
	switch {
	case len(u.Data) < s7commUDMinUnit:
	case u.FunctionGroup == S7CommGroupNCProgramming:
		if u.Type != S7CommUDTypeRequest && u.Subfunction.ncHasUnitHeader() {
			n = s7commNCUnitHead
		}
	case u.FunctionGroup == S7CommGroupPBC:
		if u.Type != S7CommUDTypePush {
			n = s7commPBCUnitHead
		}
	case u.FunctionGroup == S7CommGroupCPU && u.Subfunction == S7CommCPUARSendInd:
		n = s7commPBCUnitHead
	}
	if n == 0 || len(u.Data) < n {
		return
	}

	u.UnitHeader = u.Data[:n]
	u.Data = u.Data[n:]
}

// decodeValue decodes the data value of the services this package
// understands; others stay raw. Only the SZL and block function
// checks that predate the other views return errors; the rest record
// theirs in DecodeErr.
func (u *S7CommUserdata) decodeValue() error {
	switch u.FunctionGroup {
	case S7CommGroupCPU:
		if u.Subfunction != S7CommCPUReadSZL {
			u.DecodeErr = u.decodeCPU()
			return nil
		}
		if u.Type == S7CommUDTypeResponse && u.ReturnCode != S7CommRetSuccess {
			return nil
		}
		if err := u.decodeSZL(); err != nil {
			return err
		}
		u.DecodeErr = u.SZL.decodeRecords()
	case S7CommGroupBlock:
		if err := u.decodeBlockFunc(); err != nil {
			return err
		}
		if u.Subfunction == S7CommBlockGetInfo && u.Type == S7CommUDTypeResponse && u.ReturnCode == S7CommRetSuccess {
			u.DecodeErr = u.decodeBlockInfo()
		}
	case S7CommGroupProgrammer:
		u.DecodeErr = u.decodeTIS()
	case S7CommGroupCyclicData:
		u.DecodeErr = u.decodeCyclic()
	case S7CommGroupTime:
		if u.ReturnCode == S7CommRetSuccess {
			u.DecodeErr = u.decodeClock()
		}
	case S7CommGroupPBC:
		u.DecodeErr = u.decodeSend(binary.BigEndian)
	case S7CommGroupNCProgramming:
		u.DecodeErr = u.decodeNC()
	}
	return nil
}

// decodeSZL reads an SZL request (ID, index) or response (ID, index,
// record length, record count, records).
func (u *S7CommUserdata) decodeSZL() error {
	d := u.Data
	if len(d) < s7commSZLReqLen {
		return fmt.Errorf("%w: SZL data %d octets", ErrS7CommMalformed, len(d))
	}

	szl := &S7CommSZL{
		ID:    binary.BigEndian.Uint16(d[0:2]),
		Index: binary.BigEndian.Uint16(d[2:4]),
	}
	u.SZL = szl
	if u.Type != S7CommUDTypeResponse {
		return nil
	}
	if len(d) < s7commSZLRespLen {
		return fmt.Errorf("%w: SZL response %d octets", ErrS7CommMalformed, len(d))
	}

	szl.RecordLength = binary.BigEndian.Uint16(d[4:6])
	szl.RecordCount = binary.BigEndian.Uint16(d[6:8])
	recs := d[s7commSZLRespLen:]
	if szl.HeaderOnly() {
		return nil
	}

	// Check the claimed size against the data before allocating; a zero
	// record length would otherwise let a count of 65535 allocate for
	// nothing.
	// uint64: 0xFFFF * 0x8001 overflows a 32-bit int.
	size := uint64(szl.RecordLength) * uint64(szl.RecordCount)
	count := int(szl.RecordCount)
	if size > uint64(len(recs)) {
		// Some CPUs send a count of 0xFFFF in lists spanning PDUs; like
		// Wireshark, take the records a joined value holds.
		if u.Fragments == 0 || szl.RecordLength == 0 {
			return fmt.Errorf("%w: SZL %d records of %d octets in %d", ErrS7CommMalformed, szl.RecordCount, szl.RecordLength, len(recs))
		}
		count = len(recs) / int(szl.RecordLength)
	}
	if szl.RecordLength == 0 {
		return nil
	}

	szl.Records = make([][]byte, count)
	for i := range szl.Records {
		off := i * int(szl.RecordLength)
		szl.Records[i] = recs[off : off+int(szl.RecordLength)]
	}
	return nil
}

// decodeBlockFunc reads the block function values:
//
//	List blocks response:         {type(2), count(2)}...
//	List blocks of type request:  type(2)
//	List blocks of type response: {number(2), flags, language}...
//	Get block info request:       type(2), number(5 ASCII), filesystem
func (u *S7CommUserdata) decodeBlockFunc() error {
	d := u.Data
	req := u.Type == S7CommUDTypeRequest

	// Like Wireshark, take the queries only with a transport size.
	if u.Subfunction != S7CommBlockList && u.TransportSize == S7CommDataTSNull {
		return nil
	}

	switch {
	case u.Subfunction == S7CommBlockList && !req:
		for ; len(d) >= s7commBlockEntryLen; d = d[s7commBlockEntryLen:] {
			u.BlockCounts = append(u.BlockCounts, S7CommBlockCount{
				Type:  S7CommBlockType(binary.BigEndian.Uint16(d[0:2])),
				Count: binary.BigEndian.Uint16(d[2:4]),
			})
		}
	case u.Subfunction == S7CommBlockListOfType && req:
		if len(d) < s7commBlockTypeLen {
			return fmt.Errorf("%w: list blocks of type %d octets", ErrS7CommMalformed, len(d))
		}
		u.BlockType = S7CommBlockType(binary.BigEndian.Uint16(d[0:2]))
	case u.Subfunction == S7CommBlockListOfType:
		for ; len(d) >= s7commBlockEntryLen; d = d[s7commBlockEntryLen:] {
			u.BlockEntries = append(u.BlockEntries, S7CommBlockEntry{
				Number:   binary.BigEndian.Uint16(d[0:2]),
				Flags:    d[2],
				Language: S7CommBlockLang(d[3]),
			})
		}
	case u.Subfunction == S7CommBlockGetInfo && req:
		if len(d) < s7commBlockInfoReqLen {
			return fmt.Errorf("%w: get block info %d octets", ErrS7CommMalformed, len(d))
		}
		u.BlockType = S7CommBlockType(binary.BigEndian.Uint16(d[0:2]))
		u.BlockNumber = string(d[s7commBlockTypeLen : s7commBlockTypeLen+s7commBlockNumDigits])
		u.Filesystem = d[s7commBlockInfoReqLen-1]
	}
	return nil
}
