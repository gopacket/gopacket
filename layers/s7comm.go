// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// S7comm is the Siemens S7 protocol of S7-300/400 (and S7-1200/1500 in
// PUT/GET mode), carried in COTP DT TPDUs:
//
//	+--------------------+------------------+-----------------+
//	| header (10 or 12)  | parameter        | data            |
//	| 0x32, ROSCTR, ...  | ParamLength      | DataLength      |
//	+--------------------+------------------+-----------------+
//
// Ack and Ack_Data headers carry two more octets: error class and code.
// Decoded: header; Setup Communication; Read/Write Var items (S7ANY
// addresses, other syntax IDs raw) and data items; block download and
// upload control; PI service and PLC stop; Userdata (see
// S7CommUserdata). Anything else stays in Params and Data.

// LayerTypeS7Comm is the layer type of a Siemens S7comm PDU.
var LayerTypeS7Comm = gopacket.RegisterLayerType(162, gopacket.LayerTypeMetadata{Name: "S7comm", Decoder: gopacket.DecodeFunc(decodeS7Comm)})

const (
	// S7CommProtocolID is the first octet of every S7comm PDU.
	S7CommProtocolID uint8 = 0x32

	s7commHeaderLen    = 10
	s7commAckHeaderLen = 12

	// Var service: function, item count.
	s7commVarParamHead = 2
	// Item: variable specification, address length.
	s7commItemHead = 2
	// S7ANY address: syntax ID, transport size, count, DB, area, address.
	s7commS7AnyLen = 10
	// Data item: return code, transport size, length.
	s7commDataItemHead = 4
	s7commBitsPerByte  = 8
	s7commAddrMask     = 0x00FFFFFF
	s7commBitAddrMask  = 0x07
	s7commBitAddrShift = 3

	// Setup Communication parameter: function, reserved, 3 x uint16.
	s7commSetupCommLen = 8

	// Block control parameter: function, status, error code, upload ID.
	s7commBlockHeadLen = 8
	// Block control data: length, unknown.
	s7commBlockDataHead = 4
	// Request download part 2: length, unknown, load memory, MC7 sizes.
	s7commLenFieldDigits = 6
	s7commDownloadPart2  = 2 + 2*s7commLenFieldDigits

	// PI service: function, 7 unknown, block length.
	s7commPIHeadLen = 10
	// PLC stop: function, 5 unknown.
	s7commStopHeadLen = 6
)

var (
	// ErrS7CommTooShort is returned when data is shorter than the S7comm
	// header or than the parameter and data lengths it announces.
	ErrS7CommTooShort = errors.New("S7comm PDU truncated")
	// ErrS7CommBadProtocol is returned when the first octet is not 0x32.
	ErrS7CommBadProtocol = errors.New("S7comm protocol ID is not 0x32")
	// ErrS7CommUnknownROSCTR is returned for a message type S7comm does
	// not define.
	ErrS7CommUnknownROSCTR = errors.New("S7comm unknown ROSCTR")
	// ErrS7CommMalformed is returned when parameter or data content
	// overruns its part or disagrees with its own counts.
	ErrS7CommMalformed = errors.New("S7comm malformed PDU")
)

// S7CommROSCTR is the S7comm message type (remote operating service
// control).
type S7CommROSCTR uint8

// S7comm message types.
const (
	S7CommROSCTRJob      S7CommROSCTR = 0x01
	S7CommROSCTRAck      S7CommROSCTR = 0x02
	S7CommROSCTRAckData  S7CommROSCTR = 0x03
	S7CommROSCTRUserdata S7CommROSCTR = 0x07
)

// String returns the Wireshark name of the message type.
func (r S7CommROSCTR) String() string {
	switch r {
	case S7CommROSCTRJob:
		return "Job"
	case S7CommROSCTRAck:
		return "Ack"
	case S7CommROSCTRAckData:
		return "Ack_Data"
	case S7CommROSCTRUserdata:
		return "Userdata"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(r))
	}
}

// valid reports whether r is a message type S7comm defines.
func (r S7CommROSCTR) valid() bool {
	switch r {
	case S7CommROSCTRJob, S7CommROSCTRAck, S7CommROSCTRAckData, S7CommROSCTRUserdata:
		return true
	}
	return false
}

// hasError reports whether the header carries error class and code.
func (r S7CommROSCTR) hasError() bool {
	return r == S7CommROSCTRAck || r == S7CommROSCTRAckData
}

// S7CommFunction is the function code, the first parameter octet.
type S7CommFunction uint8

// S7comm function codes.
const (
	S7CommFuncCPUServices     S7CommFunction = 0x00
	S7CommFuncReadVar         S7CommFunction = 0x04
	S7CommFuncWriteVar        S7CommFunction = 0x05
	S7CommFuncRequestDownload S7CommFunction = 0x1A
	S7CommFuncDownloadBlock   S7CommFunction = 0x1B
	S7CommFuncDownloadEnded   S7CommFunction = 0x1C
	S7CommFuncStartUpload     S7CommFunction = 0x1D
	S7CommFuncUpload          S7CommFunction = 0x1E
	S7CommFuncEndUpload       S7CommFunction = 0x1F
	S7CommFuncPLCControl      S7CommFunction = 0x28 // PI service
	S7CommFuncPLCStop         S7CommFunction = 0x29
	S7CommFuncSetupComm       S7CommFunction = 0xF0
)

// String returns a human-readable name of the function.
func (f S7CommFunction) String() string {
	switch f {
	case S7CommFuncCPUServices:
		return "CPU services"
	case S7CommFuncReadVar:
		return "Read Var"
	case S7CommFuncWriteVar:
		return "Write Var"
	case S7CommFuncRequestDownload:
		return "Request download"
	case S7CommFuncDownloadBlock:
		return "Download block"
	case S7CommFuncDownloadEnded:
		return "Download ended"
	case S7CommFuncStartUpload:
		return "Start upload"
	case S7CommFuncUpload:
		return "Upload"
	case S7CommFuncEndUpload:
		return "End upload"
	case S7CommFuncPLCControl:
		return "PLC Control"
	case S7CommFuncPLCStop:
		return "PLC Stop"
	case S7CommFuncSetupComm:
		return "Setup communication"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(f))
	}
}

// isBlockControl reports whether f is a download or upload function.
func (f S7CommFunction) isBlockControl() bool {
	return f >= S7CommFuncRequestDownload && f <= S7CommFuncEndUpload
}

// S7CommErrorClass is the error class of an Ack or Ack_Data header.
type S7CommErrorClass uint8

// S7comm header error classes.
const (
	S7CommErrClassNone        S7CommErrorClass = 0x00
	S7CommErrClassAppRelation S7CommErrorClass = 0x81
	S7CommErrClassObjectDef   S7CommErrorClass = 0x82
	S7CommErrClassNoResources S7CommErrorClass = 0x83
	S7CommErrClassService     S7CommErrorClass = 0x84
	S7CommErrClassSupplies    S7CommErrorClass = 0x85
	S7CommErrClassAccess      S7CommErrorClass = 0x87
)

// String returns a human-readable name of the error class.
func (e S7CommErrorClass) String() string {
	switch e {
	case S7CommErrClassNone:
		return "No error"
	case S7CommErrClassAppRelation:
		return "Application relationship"
	case S7CommErrClassObjectDef:
		return "Object definition"
	case S7CommErrClassNoResources:
		return "No resources available"
	case S7CommErrClassService:
		return "Error on service processing"
	case S7CommErrClassSupplies:
		return "Error on supplies"
	case S7CommErrClassAccess:
		return "Access error"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(e))
	}
}

// S7CommReturnCode is the per-item return code of a data item.
type S7CommReturnCode uint8

// S7comm item return codes.
const (
	S7CommRetReserved         S7CommReturnCode = 0x00
	S7CommRetHardwareFault    S7CommReturnCode = 0x01
	S7CommRetAccessDenied     S7CommReturnCode = 0x03
	S7CommRetInvalidAddress   S7CommReturnCode = 0x05
	S7CommRetTypeUnsupported  S7CommReturnCode = 0x06
	S7CommRetTypeInconsistent S7CommReturnCode = 0x07
	S7CommRetObjectMissing    S7CommReturnCode = 0x0A
	S7CommRetSuccess          S7CommReturnCode = 0xFF
)

// String returns a human-readable name of the return code.
func (r S7CommReturnCode) String() string {
	switch r {
	case S7CommRetReserved:
		return "Reserved"
	case S7CommRetHardwareFault:
		return "Hardware fault"
	case S7CommRetAccessDenied:
		return "Accessing the object not allowed"
	case S7CommRetInvalidAddress:
		return "Invalid address"
	case S7CommRetTypeUnsupported:
		return "Data type not supported"
	case S7CommRetTypeInconsistent:
		return "Data type inconsistent"
	case S7CommRetObjectMissing:
		return "Object does not exist"
	case S7CommRetSuccess:
		return "Success"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(r))
	}
}

// hasData reports whether an item with this code carries data. Error
// items are a bare 4-octet header, as Wireshark reads them.
func (r S7CommReturnCode) hasData() bool {
	return r == S7CommRetSuccess || r == S7CommRetReserved
}

// S7CommDataTransportSize is the transport size of a data item, which
// also says whether its length counts bits or octets.
type S7CommDataTransportSize uint8

// S7comm data item transport sizes.
const (
	S7CommDataTSNull     S7CommDataTransportSize = 0x00
	S7CommDataTSBit      S7CommDataTransportSize = 0x03
	S7CommDataTSByte     S7CommDataTransportSize = 0x04 // BYTE/WORD/DWORD
	S7CommDataTSInt      S7CommDataTransportSize = 0x05
	S7CommDataTSDInt     S7CommDataTransportSize = 0x06
	S7CommDataTSReal     S7CommDataTransportSize = 0x07
	S7CommDataTSOctetStr S7CommDataTransportSize = 0x09
)

// String returns a human-readable name of the transport size.
func (t S7CommDataTransportSize) String() string {
	switch t {
	case S7CommDataTSNull:
		return "NULL"
	case S7CommDataTSBit:
		return "BIT"
	case S7CommDataTSByte:
		return "BYTE/WORD/DWORD"
	case S7CommDataTSInt:
		return "INTEGER"
	case S7CommDataTSDInt:
		return "DINTEGER"
	case S7CommDataTSReal:
		return "REAL"
	case S7CommDataTSOctetStr:
		return "OCTET STRING"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(t))
	}
}

// ByteLength converts a data item length field to octets: BIT, BYTE
// and INTEGER count bits, rounded up to whole octets; others count
// octets.
func (t S7CommDataTransportSize) ByteLength(length uint16) int {
	switch t {
	case S7CommDataTSBit, S7CommDataTSByte, S7CommDataTSInt:
		return (int(length) + s7commBitsPerByte - 1) / s7commBitsPerByte
	default:
		return int(length)
	}
}

// S7CommTransportSize is the element type of an S7ANY address.
type S7CommTransportSize uint8

// S7ANY transport sizes.
const (
	S7CommTSBit       S7CommTransportSize = 0x01
	S7CommTSByte      S7CommTransportSize = 0x02
	S7CommTSChar      S7CommTransportSize = 0x03
	S7CommTSWord      S7CommTransportSize = 0x04
	S7CommTSInt       S7CommTransportSize = 0x05
	S7CommTSDWord     S7CommTransportSize = 0x06
	S7CommTSDInt      S7CommTransportSize = 0x07
	S7CommTSReal      S7CommTransportSize = 0x08
	S7CommTSDate      S7CommTransportSize = 0x09
	S7CommTSTOD       S7CommTransportSize = 0x0A
	S7CommTSTime      S7CommTransportSize = 0x0B
	S7CommTSS5Time    S7CommTransportSize = 0x0C
	S7CommTSDateTime  S7CommTransportSize = 0x0F
	S7CommTSCounter   S7CommTransportSize = 0x1C
	S7CommTSTimer     S7CommTransportSize = 0x1D
	S7CommTSIECTimer  S7CommTransportSize = 0x1E
	S7CommTSIECCount  S7CommTransportSize = 0x1F
	S7CommTSHSCounter S7CommTransportSize = 0x20
)

// String returns the S7 type name of the transport size.
func (t S7CommTransportSize) String() string {
	switch t {
	case S7CommTSBit:
		return "BIT"
	case S7CommTSByte:
		return "BYTE"
	case S7CommTSChar:
		return "CHAR"
	case S7CommTSWord:
		return "WORD"
	case S7CommTSInt:
		return "INT"
	case S7CommTSDWord:
		return "DWORD"
	case S7CommTSDInt:
		return "DINT"
	case S7CommTSReal:
		return "REAL"
	case S7CommTSDate:
		return "DATE"
	case S7CommTSTOD:
		return "TOD"
	case S7CommTSTime:
		return "TIME"
	case S7CommTSS5Time:
		return "S5TIME"
	case S7CommTSDateTime:
		return "DATE_AND_TIME"
	case S7CommTSCounter:
		return "COUNTER"
	case S7CommTSTimer:
		return "TIMER"
	case S7CommTSIECTimer:
		return "IEC TIMER"
	case S7CommTSIECCount:
		return "IEC COUNTER"
	case S7CommTSHSCounter:
		return "HS COUNTER"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(t))
	}
}

// S7CommArea is the memory area of an S7ANY address.
type S7CommArea uint8

// S7ANY memory areas.
const (
	S7CommAreaSysInfo200   S7CommArea = 0x03
	S7CommAreaSysFlags200  S7CommArea = 0x05
	S7CommAreaAnaIn200     S7CommArea = 0x06
	S7CommAreaAnaOut200    S7CommArea = 0x07
	S7CommAreaCounter      S7CommArea = 0x1C
	S7CommAreaTimer        S7CommArea = 0x1D
	S7CommAreaIECCounter   S7CommArea = 0x1E
	S7CommAreaIECTimer     S7CommArea = 0x1F
	S7CommAreaPeripheral   S7CommArea = 0x80
	S7CommAreaInputs       S7CommArea = 0x81
	S7CommAreaOutputs      S7CommArea = 0x82
	S7CommAreaFlags        S7CommArea = 0x83
	S7CommAreaDataBlocks   S7CommArea = 0x84
	S7CommAreaInstanceDB   S7CommArea = 0x85
	S7CommAreaLocal        S7CommArea = 0x86
	S7CommAreaPreviousLocl S7CommArea = 0x87
)

// String returns a human-readable name of the area.
func (a S7CommArea) String() string {
	switch a {
	case S7CommAreaSysInfo200:
		return "System info (S7-200)"
	case S7CommAreaSysFlags200:
		return "System flags (S7-200)"
	case S7CommAreaAnaIn200:
		return "Analog inputs (S7-200)"
	case S7CommAreaAnaOut200:
		return "Analog outputs (S7-200)"
	case S7CommAreaCounter:
		return "Counter (C)"
	case S7CommAreaTimer:
		return "Timer (T)"
	case S7CommAreaIECCounter:
		return "IEC counter (S7-200)"
	case S7CommAreaIECTimer:
		return "IEC timer (S7-200)"
	case S7CommAreaPeripheral:
		return "Direct peripheral access (P)"
	case S7CommAreaInputs:
		return "Inputs (I)"
	case S7CommAreaOutputs:
		return "Outputs (Q)"
	case S7CommAreaFlags:
		return "Flags (M)"
	case S7CommAreaDataBlocks:
		return "Data blocks (DB)"
	case S7CommAreaInstanceDB:
		return "Instance data blocks (DI)"
	case S7CommAreaLocal:
		return "Local data (L)"
	case S7CommAreaPreviousLocl:
		return "Previous local data (V)"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(a))
	}
}

// S7CommSyntaxID is the address syntax of a variable item, or the
// parameter format of a Userdata PDU.
type S7CommSyntaxID uint8

// S7comm syntax IDs.
const (
	S7CommSyntaxS7Any       S7CommSyntaxID = 0x10
	S7CommSyntaxParamShort  S7CommSyntaxID = 0x11 // Userdata request
	S7CommSyntaxParamExt    S7CommSyntaxID = 0x12 // Userdata response
	S7CommSyntaxPBCID       S7CommSyntaxID = 0x13
	S7CommSyntaxAlarmLock   S7CommSyntaxID = 0x15
	S7CommSyntaxAlarmInd    S7CommSyntaxID = 0x16
	S7CommSyntaxAlarmAck    S7CommSyntaxID = 0x19
	S7CommSyntaxAlarmQuery  S7CommSyntaxID = 0x1A
	S7CommSyntaxNotifyInd   S7CommSyntaxID = 0x1C
	S7CommSyntaxNCK         S7CommSyntaxID = 0x82
	S7CommSyntaxNCKMetric   S7CommSyntaxID = 0x83
	S7CommSyntaxNCKInch     S7CommSyntaxID = 0x84
	S7CommSyntaxDriveESAny  S7CommSyntaxID = 0xA2
	S7CommSyntaxDBRead      S7CommSyntaxID = 0xB0
	S7CommSyntax1200Symbol  S7CommSyntaxID = 0xB2
	s7commVarSpecIdentifier                = 0x12
)

// String returns the Wireshark name of the syntax ID.
func (s S7CommSyntaxID) String() string {
	switch s {
	case S7CommSyntaxS7Any:
		return "S7ANY"
	case S7CommSyntaxParamShort:
		return "ParameterShort"
	case S7CommSyntaxParamExt:
		return "ParameterExtended"
	case S7CommSyntaxPBCID:
		return "PBC-R_ID"
	case S7CommSyntaxAlarmLock:
		return "ALARM_LOCKFREE"
	case S7CommSyntaxAlarmInd:
		return "ALARM_IND"
	case S7CommSyntaxAlarmAck:
		return "ALARM_ACK"
	case S7CommSyntaxAlarmQuery:
		return "ALARM_QUERYREQ"
	case S7CommSyntaxNotifyInd:
		return "NOTIFY_IND"
	case S7CommSyntaxNCK:
		return "NCK"
	case S7CommSyntaxNCKMetric:
		return "NCK_METRIC"
	case S7CommSyntaxNCKInch:
		return "NCK_INCH"
	case S7CommSyntaxDriveESAny:
		return "DRIVEESANY"
	case S7CommSyntaxDBRead:
		return "DBREAD"
	case S7CommSyntax1200Symbol:
		return "1200SYM"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(s))
	}
}

// S7CommVarItem is one Read Var or Write Var request item. The S7ANY
// fields are set only when SyntaxID is S7CommSyntaxS7Any; Address holds
// every syntax's address octets after the syntax ID.
type S7CommVarItem struct {
	VarSpec       uint8 // 0x12
	Length        uint8 // octets after this one
	SyntaxID      S7CommSyntaxID
	TransportSize S7CommTransportSize
	Count         uint16 // elements of TransportSize
	DBNumber      uint16
	Area          S7CommArea
	BitAddress    uint32 // 24-bit address in bits: byte*8 + bit
	Address       []byte

	// Set for their syntax IDs only (see s7comm_address.go).
	DBRead  []S7CommDBReadArea
	NCK     *S7CommNCKAddress
	DriveES *S7CommDriveESAddress
}

// ByteOffset returns the byte part of an S7ANY address.
func (i *S7CommVarItem) ByteOffset() uint32 { return i.BitAddress >> s7commBitAddrShift }

// BitOffset returns the bit part (0-7) of an S7ANY address.
func (i *S7CommVarItem) BitOffset() uint8 { return uint8(i.BitAddress & s7commBitAddrMask) }

// S7CommDataItem is one data item of a Read Var response or a Write
// Var request. Length is the wire value, in bits or octets per
// TransportSize; Data excludes the fill octet after odd-sized items.
type S7CommDataItem struct {
	ReturnCode    S7CommReturnCode
	TransportSize S7CommDataTransportSize
	Length        uint16
	Data          []byte
}

// S7CommSetupComm is the Setup Communication parameter.
type S7CommSetupComm struct {
	Reserved      uint8
	MaxAmQCalling uint16
	MaxAmQCalled  uint16
	PDULength     uint16
}

// S7CommBlockControl holds the parameter (and data, where present) of
// the download and upload functions. Which fields are set depends on
// the function and direction:
//
//	Job: FunctionStatus, ErrorCode, UploadID, Filename (not Upload,
//	     End upload); LoadMemLength, MC7Length (Request download)
//	Ack_Data: FunctionStatus; UploadID, BlockLength (Start upload);
//	     DataLength, DataUnknown, BlockData (Download block, Upload)
type S7CommBlockControl struct {
	FunctionStatus uint8
	ErrorCode      uint16 // Download ended and End upload; reserved otherwise
	UploadID       uint32
	Filename       string // e.g. "_0A00001P": file ID, block type, number, filesystem
	LoadMemLength  string // ASCII digits
	MC7Length      string // ASCII digits
	BlockLength    string // ASCII digits
	DataLength     uint16
	DataUnknown    uint16
	BlockData      []byte
}

// S7CommPIService is the parameter of a PLC Control (PI service) or PLC
// Stop job. PLC Stop has no ParamBlock. ParamBlock is kept raw; Blocks
// and Args are its views for the services in s7comm_pi.go. DecodeErr
// records why they were not set; DecodeFromBytes does not return it.
type S7CommPIService struct {
	Unknown     []byte
	ParamBlock  []byte
	ServiceName string // e.g. "_INSE", "P_PROGRAM"

	Blocks    []S7CommPIBlock // _INSE, _INS2, _DELE
	Args      []string        // P_PROGRAM, _MODU, _GARB, _N_* (file names...)
	DecodeErr error
}

// S7Comm is a Siemens S7comm PDU. Params and Data always hold the raw
// parameter and data parts; the decoded views below are set only for
// the message types and functions they belong to.
type S7Comm struct {
	BaseLayer
	ProtocolID   uint8
	ROSCTR       S7CommROSCTR
	RedundancyID uint16
	PDURef       uint16
	ParamLength  uint16
	DataLength   uint16
	ErrorClass   S7CommErrorClass // Ack, Ack_Data
	ErrorCode    uint8            // Ack, Ack_Data
	Function     S7CommFunction   // first parameter octet, if any
	ItemCount    uint8            // Read/Write Var, Userdata
	Params       []byte
	Data         []byte

	SetupComm    *S7CommSetupComm
	VarItems     []S7CommVarItem    // Read/Write Var job
	DataItems    []S7CommDataItem   // Read Var Ack_Data, Write Var job
	WriteResults []S7CommReturnCode // Write Var Ack_Data
	BlockControl *S7CommBlockControl
	PIService    *S7CommPIService
	Userdata     *S7CommUserdata
}

// LayerType returns LayerTypeS7Comm.
func (s *S7Comm) LayerType() gopacket.LayerType { return LayerTypeS7Comm }

// CanDecode returns LayerTypeS7Comm.
func (s *S7Comm) CanDecode() gopacket.LayerClass { return LayerTypeS7Comm }

// NextLayerType returns LayerTypePayload for octets after the PDU, else
// LayerTypeZero.
func (s *S7Comm) NextLayerType() gopacket.LayerType {
	if len(s.Payload) > 0 {
		return gopacket.LayerTypePayload
	}
	return gopacket.LayerTypeZero
}

// isS7Comm reports whether b starts like an S7comm PDU: protocol ID
// 0x32 and a defined ROSCTR. COTP uses it to tell S7comm from the ISO
// session layer, whose SPDU codes can also be 0x32.
func isS7Comm(b []byte) bool {
	if len(b) < s7commHeaderLen || b[0] != S7CommProtocolID {
		return false
	}
	return S7CommROSCTR(b[1]).valid()
}

// DecodeFromBytes decodes an S7comm PDU from data.
func (s *S7Comm) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*s = S7Comm{}
	if len(data) < s7commHeaderLen {
		df.SetTruncated()
		return ErrS7CommTooShort
	}

	s.ProtocolID = data[0]
	s.ROSCTR = S7CommROSCTR(data[1])
	s.RedundancyID = binary.BigEndian.Uint16(data[2:4])
	s.PDURef = binary.BigEndian.Uint16(data[4:6])
	s.ParamLength = binary.BigEndian.Uint16(data[6:8])
	s.DataLength = binary.BigEndian.Uint16(data[8:10])
	if s.ProtocolID != S7CommProtocolID {
		return ErrS7CommBadProtocol
	}
	if !s.ROSCTR.valid() {
		return ErrS7CommUnknownROSCTR
	}

	hdrLen := s7commHeaderLen
	if s.ROSCTR.hasError() {
		hdrLen = s7commAckHeaderLen
	}
	paramEnd := hdrLen + int(s.ParamLength)
	dataEnd := paramEnd + int(s.DataLength)
	if dataEnd > len(data) {
		df.SetTruncated()
		return ErrS7CommTooShort
	}
	if s.ROSCTR.hasError() {
		s.ErrorClass = S7CommErrorClass(data[10])
		s.ErrorCode = data[11]
	}

	s.Params = data[hdrLen:paramEnd]
	s.Data = data[paramEnd:dataEnd]
	s.Contents = data[:dataEnd]
	s.Payload = data[dataEnd:]
	if len(s.Params) > 0 {
		s.Function = S7CommFunction(s.Params[0])
	}
	return s.decodeBody()
}

// decodeBody dispatches the parameter and data parts by message type
// and function.
func (s *S7Comm) decodeBody() error {
	switch s.ROSCTR {
	case S7CommROSCTRUserdata:
		return s.decodeUserdata()
	case S7CommROSCTRAck:
		return nil
	}
	if len(s.Params) == 0 {
		return nil
	}

	switch {
	case s.Function == S7CommFuncSetupComm:
		return s.decodeSetupComm()
	case s.Function == S7CommFuncReadVar, s.Function == S7CommFuncWriteVar:
		return s.decodeVar()
	case s.Function.isBlockControl():
		return s.decodeBlockControl()
	case s.Function == S7CommFuncPLCControl, s.Function == S7CommFuncPLCStop:
		return s.decodePIService()
	}
	return nil
}

func (s *S7Comm) decodeSetupComm() error {
	p := s.Params
	if len(p) < s7commSetupCommLen {
		return fmt.Errorf("%w: setup communication parameter %d octets", ErrS7CommMalformed, len(p))
	}

	s.SetupComm = &S7CommSetupComm{
		Reserved:      p[1],
		MaxAmQCalling: binary.BigEndian.Uint16(p[2:4]),
		MaxAmQCalled:  binary.BigEndian.Uint16(p[4:6]),
		PDULength:     binary.BigEndian.Uint16(p[6:8]),
	}
	return nil
}

// decodeVar decodes Read Var and Write Var in both directions:
//
//	Job      Read:  param items
//	Job      Write: param items, data items
//	Ack_Data Read:  data items
//	Ack_Data Write: data return codes
func (s *S7Comm) decodeVar() error {
	if len(s.Params) < s7commVarParamHead {
		return fmt.Errorf("%w: var parameter %d octets", ErrS7CommMalformed, len(s.Params))
	}
	s.ItemCount = s.Params[1]

	if s.ROSCTR == S7CommROSCTRJob {
		if err := s.decodeVarItems(s.Params[s7commVarParamHead:]); err != nil {
			return err
		}
		if s.Function == S7CommFuncReadVar {
			return nil
		}
		return s.decodeDataItems()
	}

	if s.Function == S7CommFuncReadVar {
		return s.decodeDataItems()
	}
	return s.decodeWriteResults()
}

// decodeVarItems reads ItemCount request items from p. Items are
// appended as they are read, so memory follows real data, not the count.
func (s *S7Comm) decodeVarItems(p []byte) error {
	for i := 0; i < int(s.ItemCount); i++ {
		if len(p) < s7commItemHead+1 {
			return fmt.Errorf("%w: item %d of %d truncated", ErrS7CommMalformed, i, s.ItemCount)
		}

		item := S7CommVarItem{VarSpec: p[0], Length: p[1]}
		end := s7commItemHead + int(item.Length)
		if item.Length == 0 || end > len(p) {
			return fmt.Errorf("%w: item %d address length %d", ErrS7CommMalformed, i, item.Length)
		}
		item.SyntaxID = S7CommSyntaxID(p[2])
		item.Address = p[s7commItemHead+1 : end]

		if item.SyntaxID == S7CommSyntaxS7Any {
			if err := item.decodeS7Any(); err != nil {
				return err
			}
		} else {
			item.decodeAddress()
		}
		s.VarItems = append(s.VarItems, item)
		p = p[end:]
	}
	return nil
}

// decodeS7Any splits a 10-octet S7ANY address:
//
//	syntax | tsize | count(2) | DB(2) | area | address(3, in bits)
func (i *S7CommVarItem) decodeS7Any() error {
	a := i.Address
	if int(i.Length) != s7commS7AnyLen {
		return fmt.Errorf("%w: S7ANY address length %d", ErrS7CommMalformed, i.Length)
	}

	i.TransportSize = S7CommTransportSize(a[0])
	i.Count = binary.BigEndian.Uint16(a[1:3])
	i.DBNumber = binary.BigEndian.Uint16(a[3:5])
	i.Area = S7CommArea(a[5])
	i.BitAddress = binary.BigEndian.Uint32(a[5:9]) & s7commAddrMask
	return nil
}

// decodeDataItems reads ItemCount data items from s.Data. Every item but
// the last is padded to an even length.
func (s *S7Comm) decodeDataItems() error {
	d := s.Data
	for i := 0; i < int(s.ItemCount); i++ {
		if len(d) < s7commDataItemHead {
			return fmt.Errorf("%w: data item %d of %d truncated", ErrS7CommMalformed, i, s.ItemCount)
		}

		item := S7CommDataItem{
			ReturnCode:    S7CommReturnCode(d[0]),
			TransportSize: S7CommDataTransportSize(d[1]),
			Length:        binary.BigEndian.Uint16(d[2:4]),
		}
		n := 0
		if item.ReturnCode.hasData() {
			n = item.TransportSize.ByteLength(item.Length)
		}
		end := s7commDataItemHead + n
		if end > len(d) {
			return fmt.Errorf("%w: data item %d length %d", ErrS7CommMalformed, i, n)
		}
		item.Data = d[s7commDataItemHead:end]
		s.DataItems = append(s.DataItems, item)

		// Fill octet after an odd item, except the last.
		if n%2 == 1 && i < int(s.ItemCount)-1 {
			end++
		}
		if end > len(d) {
			end = len(d)
		}
		d = d[end:]
	}
	return nil
}

// decodeWriteResults reads one return code per item from s.Data.
func (s *S7Comm) decodeWriteResults() error {
	if int(s.ItemCount) > len(s.Data) {
		return fmt.Errorf("%w: %d write results in %d octets", ErrS7CommMalformed, s.ItemCount, len(s.Data))
	}

	s.WriteResults = make([]S7CommReturnCode, s.ItemCount)
	for i := range s.WriteResults {
		s.WriteResults[i] = S7CommReturnCode(s.Data[i])
	}
	return nil
}

// decodeBlockControl decodes download and upload parameters:
//
//	func | status | error(2) | upload ID(4) | len | filename | part 2
//
// An Ack_Data parameter stops after status, except for Start upload,
// which carries the block length string where a job has the filename.
func (s *S7Comm) decodeBlockControl() error {
	p := s.Params
	if len(p) < 2 {
		return nil
	}

	bc := &S7CommBlockControl{FunctionStatus: p[1]}
	s.BlockControl = bc
	if s.ROSCTR == S7CommROSCTRAckData {
		if err := bc.decodeAckData(s.Data); err != nil {
			return err
		}
	}
	if len(p) < s7commBlockHeadLen {
		return nil
	}

	bc.ErrorCode = binary.BigEndian.Uint16(p[2:4])
	bc.UploadID = binary.BigEndian.Uint32(p[4:8])
	if len(p) == s7commBlockHeadLen {
		return nil
	}

	str, rest, err := s7commString(p[s7commBlockHeadLen:])
	if err != nil {
		return err
	}
	if s.ROSCTR == S7CommROSCTRAckData {
		bc.BlockLength = str
		return nil
	}
	bc.Filename = str

	if s.Function != S7CommFuncRequestDownload || len(rest) == 0 {
		return nil
	}
	if len(rest) < s7commDownloadPart2 {
		return fmt.Errorf("%w: download part 2 %d octets", ErrS7CommMalformed, len(rest))
	}
	bc.LoadMemLength = string(rest[2 : 2+s7commLenFieldDigits])
	bc.MC7Length = string(rest[2+s7commLenFieldDigits : s7commDownloadPart2])
	return nil
}

// decodeAckData reads the block data of a Download block or Upload
// response: length(2), unknown(2), data.
func (bc *S7CommBlockControl) decodeAckData(d []byte) error {
	if len(d) == 0 {
		return nil
	}
	if len(d) < s7commBlockDataHead {
		return fmt.Errorf("%w: block data %d octets", ErrS7CommMalformed, len(d))
	}

	bc.DataLength = binary.BigEndian.Uint16(d[0:2])
	bc.DataUnknown = binary.BigEndian.Uint16(d[2:4])
	end := s7commBlockDataHead + int(bc.DataLength)
	if end > len(d) {
		return fmt.Errorf("%w: block data length %d", ErrS7CommMalformed, bc.DataLength)
	}
	bc.BlockData = d[s7commBlockDataHead:end]
	return nil
}

// decodePIService decodes the PLC Control and PLC Stop job parameters:
//
//	PLC Control: func | unknown(7) | len(2) | param block | len | name
//	PLC Stop:    func | unknown(5) | len | name
//
// An Ack_Data parameter is the function alone.
func (s *S7Comm) decodePIService() error {
	p := s.Params
	if s.ROSCTR != S7CommROSCTRJob {
		return nil
	}

	pi := &S7CommPIService{}
	if s.Function == S7CommFuncPLCStop {
		if len(p) < s7commStopHeadLen {
			return fmt.Errorf("%w: PLC stop parameter %d octets", ErrS7CommMalformed, len(p))
		}
		pi.Unknown = p[1:s7commStopHeadLen]
		p = p[s7commStopHeadLen:]
	} else {
		if len(p) < s7commPIHeadLen {
			return fmt.Errorf("%w: PI service parameter %d octets", ErrS7CommMalformed, len(p))
		}
		pi.Unknown = p[1 : s7commPIHeadLen-2]
		n := int(binary.BigEndian.Uint16(p[s7commPIHeadLen-2 : s7commPIHeadLen]))
		if s7commPIHeadLen+n > len(p) {
			return fmt.Errorf("%w: PI parameter block length %d", ErrS7CommMalformed, n)
		}
		pi.ParamBlock = p[s7commPIHeadLen : s7commPIHeadLen+n]
		p = p[s7commPIHeadLen+n:]
	}

	name, _, err := s7commString(p)
	if err != nil {
		return err
	}
	pi.ServiceName = name
	pi.DecodeErr = pi.decodeParams()
	s.PIService = pi
	return nil
}

// s7commString reads a string prefixed by a one-octet length and
// returns it with the octets after it.
func s7commString(b []byte) (string, []byte, error) {
	if len(b) == 0 {
		return "", nil, fmt.Errorf("%w: missing string length", ErrS7CommMalformed)
	}

	n := int(b[0])
	if 1+n > len(b) {
		return "", nil, fmt.Errorf("%w: string length %d", ErrS7CommMalformed, n)
	}
	return string(b[1 : 1+n]), b[1+n:], nil
}

func decodeS7Comm(data []byte, p gopacket.PacketBuilder) error {
	s := &S7Comm{}
	if err := s.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(s)

	if len(s.Payload) == 0 {
		return nil
	}
	return p.NextDecoder(gopacket.LayerTypePayload)
}
