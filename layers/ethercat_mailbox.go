// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// EtherCAT mailbox support (ETG.1000.4/.6, Wireshark packet-ecatmb.c).
//
// A mailbox is carried in the data of a datagram that accesses a slave's
// mailbox sync manager. Fields are little endian.
//
//	Mailbox header (6):  Length (2) | Address (2) | Channel (6 bits),
//	                     Priority (2 bits) | Type (4 bits), Counter (3 bits)
//	CoE header (2):      Number (9 bits) | reserved (3) | Service (4 bits)
//	SDO header (8):      Command (1) | Index (2) | SubIndex (1) | Data (4)
//
// SDO segment services carry the command byte and then segment data, with
// no index. The other CoE services and the EoE, FoE, SoE, AoE and VoE
// bodies live in the ethercat_coe.go, ethercat_eoe.go, ethercat_foe.go,
// ethercat_soe.go and ethercat_ams.go files.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ethercatMailboxHeaderLen = 6
	ethercatCoEHeaderLen     = 2
	ethercatSDOHeaderLen     = 8
	ethercatSDOCommandLen    = 1
	ethercatMailboxMaxLen    = 1500 // Wireshark's heuristic upper bound
	ethercatMbxErrorLen      = 4    // type, detail
	ethercatMailboxMinADO    = 0x1000
	ethercatChannelMask      = 0x3F
	ethercatPriorityShift    = 6
	ethercatTypeMask         = 0x0F
	ethercatCounterShift     = 4
	ethercatCounterMask      = 0x07
	ethercatCoENumberMask    = 0x01FF
	ethercatCoEServiceShift  = 12
	ethercatSDOSpecShift     = 5

	// SDO command byte bits below the specifier. Initiate services use
	// the first set, segment services the second.
	ethercatSDOSizeIndBit    = 0x01
	ethercatSDOExpeditedBit  = 0x02
	ethercatSDOSizeShift     = 2
	ethercatSDOSizeMask      = 0x03
	ethercatSDOCompleteBit   = 0x10
	ethercatSDOLastSegBit    = 0x01
	ethercatSDOSegSizeShift  = 1
	ethercatSDOSegSizeMask   = 0x07
	ethercatSDOToggleBit     = 0x10
	ethercatSDOExpeditedSize = 4
	ethercatSDODataOffset    = 4 // of the 4 data bytes in the SDO header
)

// ErrEtherCATMailbox is returned when a mailbox header or its declared
// length does not fit the data.
var ErrEtherCATMailbox = errors.New("EtherCAT mailbox truncated")

// EtherCATMailboxType is the mailbox protocol.
type EtherCATMailboxType uint8

// Mailbox types.
const (
	EtherCATMailboxERR EtherCATMailboxType = 0
	EtherCATMailboxAoE EtherCATMailboxType = 1
	EtherCATMailboxEoE EtherCATMailboxType = 2
	EtherCATMailboxCoE EtherCATMailboxType = 3
	EtherCATMailboxFoE EtherCATMailboxType = 4
	EtherCATMailboxSoE EtherCATMailboxType = 5
	EtherCATMailboxVoE EtherCATMailboxType = 15
)

// String returns the mailbox type name.
func (t EtherCATMailboxType) String() string {
	switch t {
	case EtherCATMailboxERR:
		return "ERR"
	case EtherCATMailboxAoE:
		return "AoE"
	case EtherCATMailboxEoE:
		return "EoE"
	case EtherCATMailboxCoE:
		return "CoE"
	case EtherCATMailboxFoE:
		return "FoE"
	case EtherCATMailboxSoE:
		return "SoE"
	case EtherCATMailboxVoE:
		return "VoE"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(t))
}

// EtherCATCoEService is the CoE service.
type EtherCATCoEService uint8

// CoE services.
const (
	EtherCATCoEEmergency   EtherCATCoEService = 1
	EtherCATCoESDORequest  EtherCATCoEService = 2
	EtherCATCoESDOResponse EtherCATCoEService = 3
	EtherCATCoETxPDO       EtherCATCoEService = 4
	EtherCATCoERxPDO       EtherCATCoEService = 5
	EtherCATCoETxPDORemote EtherCATCoEService = 6
	EtherCATCoERxPDORemote EtherCATCoEService = 7
	EtherCATCoESDOInfo     EtherCATCoEService = 8
)

// String returns the CoE service name.
func (s EtherCATCoEService) String() string {
	switch s {
	case EtherCATCoEEmergency:
		return "Emergency"
	case EtherCATCoESDORequest:
		return "SDO Request"
	case EtherCATCoESDOResponse:
		return "SDO Response"
	case EtherCATCoETxPDO:
		return "TxPDO"
	case EtherCATCoERxPDO:
		return "RxPDO"
	case EtherCATCoETxPDORemote:
		return "TxPDO remote request"
	case EtherCATCoERxPDORemote:
		return "RxPDO remote request"
	case EtherCATCoESDOInfo:
		return "SDO Information"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(s))
}

// EtherCATSDOSpecifier is the 3-bit SDO command specifier: the client
// specifier (CCS) in requests, the server specifier (SCS) in responses.
type EtherCATSDOSpecifier uint8

// SDO command specifiers.
const (
	EtherCATSDOCCSDownloadSegment  EtherCATSDOSpecifier = 0
	EtherCATSDOCCSInitiateDownload EtherCATSDOSpecifier = 1
	EtherCATSDOCCSInitiateUpload   EtherCATSDOSpecifier = 2
	EtherCATSDOCCSUploadSegment    EtherCATSDOSpecifier = 3
	EtherCATSDOCCSAbort            EtherCATSDOSpecifier = 4
	EtherCATSDOSCSUploadSegment    EtherCATSDOSpecifier = 0
	EtherCATSDOSCSDownloadSegment  EtherCATSDOSpecifier = 1
	EtherCATSDOSCSInitiateUpload   EtherCATSDOSpecifier = 2
	EtherCATSDOSCSInitiateDownload EtherCATSDOSpecifier = 3
	EtherCATSDOSCSAbort            EtherCATSDOSpecifier = 4
)

// EtherCATSDO is a CoE SDO request or response.
//
// For initiate and abort services Index, SubIndex and Value are set; Value
// is the expedited data, the complete size or the abort code. For segment
// services Segment is true and Data holds the segment bytes after the
// command byte.
//
// The flags come from the command byte and only mean something for the
// services that define them:
//
//	initiate download request, initiate upload response:
//	    SizeIndicated, Expedited, UnusedBytes (of the 4 expedited bytes),
//	    CompleteAccess, ExpeditedData
//	initiate upload request:   CompleteAccess
//	download segment request, upload segment response:
//	    LastSegment, UnusedBytes (of the 7 byte minimum segment), Toggle
//	upload segment request, download segment response: Toggle
//
// A normal (not expedited) initiate transfer has its complete size in
// Value and the first data bytes in Data.
type EtherCATSDO struct {
	Command   uint8
	Specifier EtherCATSDOSpecifier
	Segment   bool
	Index     uint16
	SubIndex  uint8
	Value     uint32
	Data      []byte

	SizeIndicated  bool
	Expedited      bool
	CompleteAccess bool
	LastSegment    bool
	Toggle         bool
	UnusedBytes    uint8
	// ExpeditedData is the used part of the 4 data bytes of an expedited
	// transfer; it aliases the packet data.
	ExpeditedData []byte
}

// AbortCode returns Value as an SDO abort code.
func (s *EtherCATSDO) AbortCode() EtherCATSDOAbortCode { return EtherCATSDOAbortCode(s.Value) }

// EtherCATCoE is a CANopen over EtherCAT message.
//
// Number is the PDO number for the PDO services, whose PDO bytes are Data.
// The remote request services carry no data.
type EtherCATCoE struct {
	Number    uint16
	Service   EtherCATCoEService
	Data      []byte             // bytes after the CoE header
	SDO       *EtherCATSDO       // SDO request and response services
	SDOInfo   *EtherCATSDOInfo   // SDO information service
	Emergency *EtherCATEmergency // emergency service
}

// EtherCATMailbox is an EtherCAT mailbox. Data aliases the packet data.
type EtherCATMailbox struct {
	Length   uint16
	Address  uint16
	Channel  uint8
	Priority uint8
	Type     EtherCATMailboxType
	Counter  uint8
	Data     []byte       // Length bytes of service data
	CoE      *EtherCATCoE // Type CoE only
	EoE      *EtherCATEoE // Type EoE only
	FoE      *EtherCATFoE // Type FoE only
	SoE      *EtherCATSoE // Type SoE only
	VoE      *EtherCATVoE // Type VoE only
	AoE      *EtherCATAMS // Type AoE only

	// Error is the body of a Type ERR mailbox: the reply to a mailbox
	// the slave could not take.
	Error *EtherCATMailboxError
}

// DecodeEtherCATMailbox decodes a mailbox from the data of a datagram.
// Bytes after the declared length (unused mailbox space) are ignored.
func DecodeEtherCATMailbox(data []byte) (*EtherCATMailbox, error) {
	if len(data) < ethercatMailboxHeaderLen {
		return nil, ErrEtherCATMailbox
	}

	m := &EtherCATMailbox{
		Length:   binary.LittleEndian.Uint16(data[0:2]),
		Address:  binary.LittleEndian.Uint16(data[2:4]),
		Channel:  data[4] & ethercatChannelMask,
		Priority: data[4] >> ethercatPriorityShift,
		Type:     EtherCATMailboxType(data[5] & ethercatTypeMask),
		Counter:  (data[5] >> ethercatCounterShift) & ethercatCounterMask,
	}

	end := ethercatMailboxHeaderLen + int(m.Length)
	if end > len(data) {
		return nil, ErrEtherCATMailbox
	}
	m.Data = data[ethercatMailboxHeaderLen:end]

	// A body too short for its protocol header stays nil; Data keeps it.
	switch m.Type {
	case EtherCATMailboxCoE:
		m.CoE = decodeEtherCATCoE(m.Data)
	case EtherCATMailboxEoE:
		m.EoE = decodeEtherCATEoE(m.Data)
	case EtherCATMailboxFoE:
		m.FoE = decodeEtherCATFoE(m.Data)
	case EtherCATMailboxSoE:
		m.SoE = decodeEtherCATSoE(m.Data)
	case EtherCATMailboxVoE:
		m.VoE = decodeEtherCATVoE(m.Data)
	case EtherCATMailboxAoE:
		m.AoE = decodeEtherCATAMS(m.Data)
	case EtherCATMailboxERR:
		m.Error = decodeEtherCATMbxError(m.Data)
	}
	return m, nil
}

// EtherCATMailboxErrDetail says why a slave refused a mailbox.
type EtherCATMailboxErrDetail uint16

// Mailbox error details (ETG.1000.4 table 30).
const (
	EtherCATMailboxErrSyntax      EtherCATMailboxErrDetail = 1
	EtherCATMailboxErrProtocol    EtherCATMailboxErrDetail = 2
	EtherCATMailboxErrChannel     EtherCATMailboxErrDetail = 3
	EtherCATMailboxErrService     EtherCATMailboxErrDetail = 4
	EtherCATMailboxErrHeader      EtherCATMailboxErrDetail = 5
	EtherCATMailboxErrTooShort    EtherCATMailboxErrDetail = 6
	EtherCATMailboxErrNoMemory    EtherCATMailboxErrDetail = 7
	EtherCATMailboxErrSize        EtherCATMailboxErrDetail = 8
	EtherCATMailboxErrServiceBusy EtherCATMailboxErrDetail = 9
)

// String returns the error detail name.
func (d EtherCATMailboxErrDetail) String() string {
	switch d {
	case EtherCATMailboxErrSyntax:
		return "Syntax error in mailbox header"
	case EtherCATMailboxErrProtocol:
		return "Unsupported protocol"
	case EtherCATMailboxErrChannel:
		return "Invalid channel"
	case EtherCATMailboxErrService:
		return "Service not supported"
	case EtherCATMailboxErrHeader:
		return "Invalid protocol header"
	case EtherCATMailboxErrTooShort:
		return "Mailbox too short"
	case EtherCATMailboxErrNoMemory:
		return "No more memory"
	case EtherCATMailboxErrSize:
		return "Invalid size"
	case EtherCATMailboxErrServiceBusy:
		return "Service in work"
	}
	return fmt.Sprintf("Unknown(0x%04x)", uint16(d))
}

// EtherCATMailboxErrCommand is the only error reply type defined.
const EtherCATMailboxErrCommand uint16 = 0x0001

// EtherCATMailboxError is the body of an error reply (mailbox type 0):
//
//	Type (2) | Detail (2)
//
// Type is EtherCATMailboxErrCommand in every reply the standard defines.
type EtherCATMailboxError struct {
	Type   uint16
	Detail EtherCATMailboxErrDetail
}

// decodeEtherCATMbxError decodes an error reply, nil when it is cut.
func decodeEtherCATMbxError(data []byte) *EtherCATMailboxError {
	if len(data) < ethercatMbxErrorLen {
		return nil
	}

	return &EtherCATMailboxError{
		Type:   binary.LittleEndian.Uint16(data),
		Detail: EtherCATMailboxErrDetail(binary.LittleEndian.Uint16(data[2:])),
	}
}

// isEtherCATMbxError reports whether datagram data looks like an error
// reply. Type 0 is also what unused memory reads as, so the whole reply
// must fit: length 4, the command type and a defined detail.
func isEtherCATMbxError(data []byte) bool {
	if len(data) < ethercatMailboxHeaderLen+ethercatMbxErrorLen {
		return false
	}
	if binary.LittleEndian.Uint16(data) != ethercatMbxErrorLen {
		return false
	}

	body := data[ethercatMailboxHeaderLen:]
	detail := EtherCATMailboxErrDetail(binary.LittleEndian.Uint16(body[2:]))
	return binary.LittleEndian.Uint16(body) == EtherCATMailboxErrCommand &&
		detail >= EtherCATMailboxErrSyntax && detail <= EtherCATMailboxErrServiceBusy
}

// decodeEtherCATCoE decodes a CoE header and, for SDO services, the SDO
// header. It returns nil when the CoE header is missing.
func decodeEtherCATCoE(data []byte) *EtherCATCoE {
	if len(data) < ethercatCoEHeaderLen {
		return nil
	}

	hdr := binary.LittleEndian.Uint16(data)
	c := &EtherCATCoE{
		Number:  hdr & ethercatCoENumberMask,
		Service: EtherCATCoEService(hdr >> ethercatCoEServiceShift),
		Data:    data[ethercatCoEHeaderLen:],
	}

	switch c.Service {
	case EtherCATCoESDORequest, EtherCATCoESDOResponse:
		c.SDO = decodeEtherCATSDO(c.Data, c.Service)
	case EtherCATCoESDOInfo:
		c.SDOInfo = decodeEtherCATSDOInfo(c.Data)
	case EtherCATCoEEmergency:
		c.Emergency = decodeEtherCATEmergency(c.Data)
	}
	return c
}

// decodeEtherCATSDO decodes an SDO header. Like Wireshark it needs the
// full 8-byte header even for segment services, and returns nil otherwise.
func decodeEtherCATSDO(data []byte, service EtherCATCoEService) *EtherCATSDO {
	if len(data) < ethercatSDOHeaderLen {
		return nil
	}

	s := &EtherCATSDO{
		Command:   data[0],
		Specifier: EtherCATSDOSpecifier(data[0] >> ethercatSDOSpecShift),
	}

	// Download segment requests and upload segment responses carry segment
	// data right after the command byte.
	switch {
	case service == EtherCATCoESDORequest && s.Specifier == EtherCATSDOCCSDownloadSegment,
		service == EtherCATCoESDOResponse && s.Specifier == EtherCATSDOSCSUploadSegment:
		s.Segment = true
		s.LastSegment = s.Command&ethercatSDOLastSegBit != 0
		s.UnusedBytes = (s.Command >> ethercatSDOSegSizeShift) & ethercatSDOSegSizeMask
		s.Toggle = s.Command&ethercatSDOToggleBit != 0
		s.Data = data[ethercatSDOCommandLen:]
		return s
	}

	s.Index = binary.LittleEndian.Uint16(data[1:3])
	s.SubIndex = data[3]
	s.Value = binary.LittleEndian.Uint32(data[4:8])
	s.Data = data[ethercatSDOHeaderLen:]
	s.decodeFlags(data, service)
	return s
}

// decodeFlags splits the command byte of the services without segment
// data. data holds the full 8-byte SDO header.
func (s *EtherCATSDO) decodeFlags(data []byte, service EtherCATCoEService) {
	request := service == EtherCATCoESDORequest

	switch {
	case request && s.Specifier == EtherCATSDOCCSInitiateDownload,
		!request && s.Specifier == EtherCATSDOSCSInitiateUpload:
		s.SizeIndicated = s.Command&ethercatSDOSizeIndBit != 0
		s.Expedited = s.Command&ethercatSDOExpeditedBit != 0
		s.CompleteAccess = s.Command&ethercatSDOCompleteBit != 0
		if !s.Expedited {
			return
		}

		// Expedited: the size bits count the unused bytes of the 4.
		used := ethercatSDOExpeditedSize
		if s.SizeIndicated {
			s.UnusedBytes = (s.Command >> ethercatSDOSizeShift) & ethercatSDOSizeMask
			used -= int(s.UnusedBytes)
		}
		s.ExpeditedData = data[ethercatSDODataOffset : ethercatSDODataOffset+used]
	case request && s.Specifier == EtherCATSDOCCSInitiateUpload:
		s.CompleteAccess = s.Command&ethercatSDOCompleteBit != 0
	case request && s.Specifier == EtherCATSDOCCSUploadSegment,
		!request && s.Specifier == EtherCATSDOSCSDownloadSegment:
		s.Toggle = s.Command&ethercatSDOToggleBit != 0
	}
}

// findMailbox applies Wireshark's mailbox heuristic to a datagram: a
// write, or a read with a working counter of one, to ADO 0x1000 or above,
// whose header names a known mailbox type with a sane length. Error
// replies (type 0) are found too, by a stricter test.
func findMailbox(d *EtherCATDatagram) *EtherCATMailbox {
	if len(d.Data) < ethercatMailboxHeaderLen || d.ADO() < ethercatMailboxMinADO {
		return nil
	}

	switch d.Command {
	case EtherCATCommandFPWR, EtherCATCommandAPWR, EtherCATCommandAPRW, EtherCATCommandFPRW:
	case EtherCATCommandFPRD, EtherCATCommandAPRD:
		if d.WorkingCounter != 1 {
			return nil
		}
	default:
		return nil
	}

	switch EtherCATMailboxType(d.Data[5] & ethercatTypeMask) {
	case EtherCATMailboxAoE, EtherCATMailboxEoE, EtherCATMailboxCoE,
		EtherCATMailboxFoE, EtherCATMailboxSoE, EtherCATMailboxVoE:
	case EtherCATMailboxERR:
		// Wireshark leaves error replies out; they are taken here when
		// every field of the reply fits.
		if !isEtherCATMbxError(d.Data) {
			return nil
		}
	default:
		return nil
	}

	if binary.LittleEndian.Uint16(d.Data) > ethercatMailboxMaxLen {
		return nil
	}

	m, err := DecodeEtherCATMailbox(d.Data)
	if err != nil {
		return nil
	}
	return m
}
