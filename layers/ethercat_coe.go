// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// CoE services besides plain SDO transfers (ETG.1000.6, Wireshark
// packet-ecatmb.c): SDO information, emergency and the abort codes.
//
//	SDO information (after the CoE header):
//	    OpCode (7 bits), Incomplete (1) | reserved (1) | FragmentsLeft (2)
//	    then by opcode:
//	    list request      ListType (2)
//	    list response     ListType (2) | Index (2) ...
//	    object request    Index (2)
//	    object response   Index (2) | DataType (2) | MaxSubIndex (1) |
//	                      ObjectCode (1) | Name ...
//	    entry request     Index (2) | SubIndex (1) | ValueInfo (1)
//	    entry response    Index (2) | SubIndex (1) | ValueInfo (1) |
//	                      DataType (2) | BitLength (2) | Access (2) |
//	                      [UnitType (2)] [Default] [Min] [Max] | Name ...
//	    error             AbortCode (4)
//
//	Emergency: ErrorCode (2) | ErrorRegister (1) | Data (5)

package layers

import (
	"encoding/binary"
	"fmt"
)

const (
	// ethercatSDOInfoMinLen is the shortest body Wireshark accepts: the
	// 4-byte header and a 2-byte list type or index.
	ethercatSDOInfoMinLen     = 6
	ethercatSDOInfoHeaderLen  = 4
	ethercatSDOInfoOpCodeMask = 0x7F
	ethercatSDOInfoIncomplete = 0x80
	ethercatSDOInfoObjLen     = 6 // index, data type, max subindex, object code
	ethercatSDOInfoEntryQLen  = 4 // index, subindex, value info
	ethercatSDOInfoEntryLen   = 10
	ethercatSDOInfoErrorLen   = 4
	ethercatSDOInfoUnitLen    = 2
	ethercatIndexLen          = 2
	ethercatEmergencyMinLen   = 3
	ethercatBitsPerByte       = 8
)

// ValueInfo bits that announce optional entry description fields.
const (
	ethercatSDOInfoValueUnit    = 0x08
	ethercatSDOInfoValueDefault = 0x10
	ethercatSDOInfoValueMin     = 0x20
	ethercatSDOInfoValueMax     = 0x40
)

// EtherCATSDOInfoOpCode is the SDO information service opcode.
type EtherCATSDOInfoOpCode uint8

// SDO information opcodes.
const (
	EtherCATSDOInfoListRequest    EtherCATSDOInfoOpCode = 1
	EtherCATSDOInfoListResponse   EtherCATSDOInfoOpCode = 2
	EtherCATSDOInfoObjectRequest  EtherCATSDOInfoOpCode = 3
	EtherCATSDOInfoObjectResponse EtherCATSDOInfoOpCode = 4
	EtherCATSDOInfoEntryRequest   EtherCATSDOInfoOpCode = 5
	EtherCATSDOInfoEntryResponse  EtherCATSDOInfoOpCode = 6
	EtherCATSDOInfoError          EtherCATSDOInfoOpCode = 7
)

// String returns the opcode name.
func (o EtherCATSDOInfoOpCode) String() string {
	switch o {
	case EtherCATSDOInfoListRequest:
		return "List Req"
	case EtherCATSDOInfoListResponse:
		return "List Res"
	case EtherCATSDOInfoObjectRequest:
		return "Obj Req"
	case EtherCATSDOInfoObjectResponse:
		return "Obj Res"
	case EtherCATSDOInfoEntryRequest:
		return "Entry Req"
	case EtherCATSDOInfoEntryResponse:
		return "Entry Res"
	case EtherCATSDOInfoError:
		return "Error Res"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(o))
}

// EtherCATSDOInfoListType selects the objects an OD list names.
type EtherCATSDOInfoListType uint16

// OD list types.
const (
	EtherCATSDOInfoListLengths  EtherCATSDOInfoListType = 0 // the lengths of the five lists
	EtherCATSDOInfoListAll      EtherCATSDOInfoListType = 1
	EtherCATSDOInfoListRxPDOMap EtherCATSDOInfoListType = 2
	EtherCATSDOInfoListTxPDOMap EtherCATSDOInfoListType = 3
	EtherCATSDOInfoListBackup   EtherCATSDOInfoListType = 4
	EtherCATSDOInfoListSettings EtherCATSDOInfoListType = 5
)

// EtherCATSDOInfo is a CoE SDO information message. The fields set depend
// on OpCode, as drawn in the file comment; Data keeps the bytes after the
// 4-byte header.
//
// Only the first fragment of a fragmented response starts with the opcode
// fields; later fragments (those after a message with Incomplete set)
// continue the list or name where the previous one stopped. Without the
// previous fragments that cannot be told apart, so every message is read
// as a first fragment, as Wireshark does.
//
// Wireshark never shows UnitType, Default, Min and Max: it tests a copy
// of ValueInfo that it does not fill. They are decoded here as ETG.1000.6
// lays them out.
type EtherCATSDOInfo struct {
	OpCode        EtherCATSDOInfoOpCode
	Incomplete    bool
	FragmentsLeft uint16
	Data          []byte

	// List request and response.
	ListType EtherCATSDOInfoListType
	Indexes  []uint16

	// Object and entry description.
	Index       uint16
	SubIndex    uint8
	ValueInfo   uint8
	DataType    uint16
	MaxSubIndex uint8
	ObjectCode  uint8
	BitLength   uint16
	Access      uint16
	UnitType    uint16
	Default     []byte
	Min         []byte
	Max         []byte
	Name        []byte

	// Error response.
	AbortCode EtherCATSDOAbortCode
}

// decodeEtherCATSDOInfo decodes an SDO information body. It returns nil
// when the body is shorter than Wireshark's minimum.
func decodeEtherCATSDOInfo(data []byte) *EtherCATSDOInfo {
	if len(data) < ethercatSDOInfoMinLen {
		return nil
	}

	i := &EtherCATSDOInfo{
		OpCode:        EtherCATSDOInfoOpCode(data[0] & ethercatSDOInfoOpCodeMask),
		Incomplete:    data[0]&ethercatSDOInfoIncomplete != 0,
		FragmentsLeft: binary.LittleEndian.Uint16(data[2:4]),
		Data:          data[ethercatSDOInfoHeaderLen:],
	}
	body := i.Data

	switch i.OpCode {
	case EtherCATSDOInfoListRequest:
		i.ListType = EtherCATSDOInfoListType(binary.LittleEndian.Uint16(body))
	case EtherCATSDOInfoListResponse:
		i.ListType = EtherCATSDOInfoListType(binary.LittleEndian.Uint16(body))
		i.Indexes = decodeEtherCATIndexes(body[ethercatIndexLen:])
	case EtherCATSDOInfoObjectRequest:
		i.Index = binary.LittleEndian.Uint16(body)
	case EtherCATSDOInfoObjectResponse:
		i.decodeObject(body)
	case EtherCATSDOInfoEntryRequest:
		i.decodeEntryRequest(body)
	case EtherCATSDOInfoEntryResponse:
		i.decodeEntry(body)
	case EtherCATSDOInfoError:
		if len(body) >= ethercatSDOInfoErrorLen {
			i.AbortCode = EtherCATSDOAbortCode(binary.LittleEndian.Uint32(body))
		}
	}
	return i
}

// decodeEtherCATIndexes reads a list of 16-bit object indexes. The list
// is sized from the data, so it cannot outgrow the mailbox.
func decodeEtherCATIndexes(data []byte) []uint16 {
	n := len(data) / ethercatIndexLen
	if n == 0 {
		return nil
	}

	out := make([]uint16, n)
	for k := range out {
		out[k] = binary.LittleEndian.Uint16(data[k*ethercatIndexLen:])
	}
	return out
}

// decodeObject reads an object description response.
func (i *EtherCATSDOInfo) decodeObject(body []byte) {
	i.Index = binary.LittleEndian.Uint16(body)
	if len(body) < ethercatSDOInfoObjLen {
		return
	}

	i.DataType = binary.LittleEndian.Uint16(body[2:4])
	i.MaxSubIndex = body[4]
	i.ObjectCode = body[5]
	i.Name = body[ethercatSDOInfoObjLen:]
}

// decodeEntryRequest reads an entry description request.
func (i *EtherCATSDOInfo) decodeEntryRequest(body []byte) {
	i.Index = binary.LittleEndian.Uint16(body)
	if len(body) < ethercatSDOInfoEntryQLen {
		return
	}

	i.SubIndex = body[2]
	i.ValueInfo = body[3]
}

// decodeEntry reads an entry description response. The optional unit
// type, default, minimum and maximum follow the fixed part when their
// ValueInfo bit is set; the three values are BitLength bits wide. A value
// that does not fit is left in Name with the other tail bytes.
func (i *EtherCATSDOInfo) decodeEntry(body []byte) {
	i.decodeEntryRequest(body)
	if len(body) < ethercatSDOInfoEntryLen {
		return
	}

	i.DataType = binary.LittleEndian.Uint16(body[4:6])
	i.BitLength = binary.LittleEndian.Uint16(body[6:8])
	i.Access = binary.LittleEndian.Uint16(body[8:10])
	rest := body[ethercatSDOInfoEntryLen:]

	if i.ValueInfo&ethercatSDOInfoValueUnit != 0 && len(rest) >= ethercatSDOInfoUnitLen {
		i.UnitType = binary.LittleEndian.Uint16(rest)
		rest = rest[ethercatSDOInfoUnitLen:]
	}

	// Default, min and max share one size, rounded up to whole bytes.
	size := (int(i.BitLength) + ethercatBitsPerByte - 1) / ethercatBitsPerByte
	limits := [...]struct {
		bit uint8
		dst *[]byte
	}{
		{ethercatSDOInfoValueDefault, &i.Default},
		{ethercatSDOInfoValueMin, &i.Min},
		{ethercatSDOInfoValueMax, &i.Max},
	}
	for _, l := range limits {
		if i.ValueInfo&l.bit == 0 || size == 0 {
			continue
		}
		if len(rest) < size {
			break
		}

		*l.dst = rest[:size]
		rest = rest[size:]
	}
	i.Name = rest
}

// EtherCATEmergency is a CoE emergency message (CiA 301 EMCY).
type EtherCATEmergency struct {
	ErrorCode     uint16
	ErrorRegister uint8
	Data          []byte // manufacturer specific, 5 bytes when complete
}

// decodeEtherCATEmergency decodes an emergency body, nil when too short.
func decodeEtherCATEmergency(data []byte) *EtherCATEmergency {
	if len(data) < ethercatEmergencyMinLen {
		return nil
	}

	return &EtherCATEmergency{
		ErrorCode:     binary.LittleEndian.Uint16(data),
		ErrorRegister: data[2],
		Data:          data[ethercatEmergencyMinLen:],
	}
}

// EtherCATSDOAbortCode is an SDO abort code (ETG.1000.6 table 41).
type EtherCATSDOAbortCode uint32

// SDO abort codes.
const (
	EtherCATSDOAbortToggle          EtherCATSDOAbortCode = 0x05030000
	EtherCATSDOAbortTimeout         EtherCATSDOAbortCode = 0x05040000
	EtherCATSDOAbortSpecifier       EtherCATSDOAbortCode = 0x05040001
	EtherCATSDOAbortOutOfMemory     EtherCATSDOAbortCode = 0x05040005
	EtherCATSDOAbortAccess          EtherCATSDOAbortCode = 0x06010000
	EtherCATSDOAbortWriteOnly       EtherCATSDOAbortCode = 0x06010001
	EtherCATSDOAbortReadOnly        EtherCATSDOAbortCode = 0x06010002
	EtherCATSDOAbortSubIndexWrite   EtherCATSDOAbortCode = 0x06010003
	EtherCATSDOAbortNoCompleteAcc   EtherCATSDOAbortCode = 0x06010004
	EtherCATSDOAbortObjectTooLong   EtherCATSDOAbortCode = 0x06010005
	EtherCATSDOAbortMappedToRxPDO   EtherCATSDOAbortCode = 0x06010006
	EtherCATSDOAbortNoObject        EtherCATSDOAbortCode = 0x06020000
	EtherCATSDOAbortNotMappable     EtherCATSDOAbortCode = 0x06040041
	EtherCATSDOAbortPDOLength       EtherCATSDOAbortCode = 0x06040042
	EtherCATSDOAbortParameter       EtherCATSDOAbortCode = 0x06040043
	EtherCATSDOAbortInternal        EtherCATSDOAbortCode = 0x06040047
	EtherCATSDOAbortHardware        EtherCATSDOAbortCode = 0x06060000
	EtherCATSDOAbortLength          EtherCATSDOAbortCode = 0x06070010
	EtherCATSDOAbortLengthHigh      EtherCATSDOAbortCode = 0x06070012
	EtherCATSDOAbortLengthLow       EtherCATSDOAbortCode = 0x06070013
	EtherCATSDOAbortNoSubIndex      EtherCATSDOAbortCode = 0x06090011
	EtherCATSDOAbortValueRange      EtherCATSDOAbortCode = 0x06090030
	EtherCATSDOAbortValueHigh       EtherCATSDOAbortCode = 0x06090031
	EtherCATSDOAbortValueLow        EtherCATSDOAbortCode = 0x06090032
	EtherCATSDOAbortMaxBelowMin     EtherCATSDOAbortCode = 0x06090036
	EtherCATSDOAbortGeneral         EtherCATSDOAbortCode = 0x08000000
	EtherCATSDOAbortTransfer        EtherCATSDOAbortCode = 0x08000020
	EtherCATSDOAbortLocalControl    EtherCATSDOAbortCode = 0x08000021
	EtherCATSDOAbortDeviceState     EtherCATSDOAbortCode = 0x08000022
	EtherCATSDOAbortNoObjDictionary EtherCATSDOAbortCode = 0x08000023
)

// String returns the abort reason.
func (c EtherCATSDOAbortCode) String() string {
	switch c {
	case EtherCATSDOAbortToggle:
		return "Toggle bit not changed"
	case EtherCATSDOAbortTimeout:
		return "SDO protocol timeout"
	case EtherCATSDOAbortSpecifier:
		return "Client/server command specifier not valid or unknown"
	case EtherCATSDOAbortOutOfMemory:
		return "Out of memory"
	case EtherCATSDOAbortAccess:
		return "Unsupported access to an object"
	case EtherCATSDOAbortWriteOnly:
		return "Attempt to read a write only object"
	case EtherCATSDOAbortReadOnly:
		return "Attempt to write a read only object"
	case EtherCATSDOAbortSubIndexWrite:
		return "Subindex cannot be written, SI0 must be 0 for write access"
	case EtherCATSDOAbortNoCompleteAcc:
		return "Complete access not supported for variable length objects"
	case EtherCATSDOAbortObjectTooLong:
		return "Object length exceeds mailbox size"
	case EtherCATSDOAbortMappedToRxPDO:
		return "Object mapped to RxPDO, SDO download blocked"
	case EtherCATSDOAbortNoObject:
		return "Object does not exist in the object dictionary"
	case EtherCATSDOAbortNotMappable:
		return "Object cannot be mapped into the PDO"
	case EtherCATSDOAbortPDOLength:
		return "Number and length of mapped objects exceed the PDO length"
	case EtherCATSDOAbortParameter:
		return "General parameter incompatibility"
	case EtherCATSDOAbortInternal:
		return "General internal incompatibility in the device"
	case EtherCATSDOAbortHardware:
		return "Access failed due to a hardware error"
	case EtherCATSDOAbortLength:
		return "Data type does not match, length of service parameter does not match"
	case EtherCATSDOAbortLengthHigh:
		return "Data type does not match, length of service parameter too high"
	case EtherCATSDOAbortLengthLow:
		return "Data type does not match, length of service parameter too low"
	case EtherCATSDOAbortNoSubIndex:
		return "Subindex does not exist"
	case EtherCATSDOAbortValueRange:
		return "Value range of parameter exceeded"
	case EtherCATSDOAbortValueHigh:
		return "Value of parameter written too high"
	case EtherCATSDOAbortValueLow:
		return "Value of parameter written too low"
	case EtherCATSDOAbortMaxBelowMin:
		return "Maximum value is less than minimum value"
	case EtherCATSDOAbortGeneral:
		return "General error"
	case EtherCATSDOAbortTransfer:
		return "Data cannot be transferred or stored to the application"
	case EtherCATSDOAbortLocalControl:
		return "Data cannot be transferred or stored because of local control"
	case EtherCATSDOAbortDeviceState:
		return "Data cannot be transferred or stored in the present device state"
	case EtherCATSDOAbortNoObjDictionary:
		return "Object dictionary dynamic generation failed or no object dictionary present"
	}
	return fmt.Sprintf("Unknown(0x%08x)", uint32(c))
}
