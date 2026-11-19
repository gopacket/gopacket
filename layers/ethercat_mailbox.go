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
// no index.

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
	ethercatMailboxMinADO    = 0x1000
	ethercatChannelMask      = 0x3F
	ethercatPriorityShift    = 6
	ethercatTypeMask         = 0x0F
	ethercatCounterShift     = 4
	ethercatCounterMask      = 0x07
	ethercatCoENumberMask    = 0x01FF
	ethercatCoEServiceShift  = 12
	ethercatSDOSpecShift     = 5
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
type EtherCATSDO struct {
	Command   uint8
	Specifier EtherCATSDOSpecifier
	Segment   bool
	Index     uint16
	SubIndex  uint8
	Value     uint32
	Data      []byte
}

// EtherCATCoE is a CANopen over EtherCAT message.
type EtherCATCoE struct {
	Number  uint16
	Service EtherCATCoEService
	Data    []byte       // bytes after the CoE header
	SDO     *EtherCATSDO // SDO request and response services
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

	if m.Type == EtherCATMailboxCoE {
		m.CoE = decodeEtherCATCoE(m.Data)
	}
	return m, nil
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
	if c.Service == EtherCATCoESDORequest || c.Service == EtherCATCoESDOResponse {
		c.SDO = decodeEtherCATSDO(c.Data, c.Service)
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
		s.Data = data[ethercatSDOCommandLen:]
		return s
	}

	s.Index = binary.LittleEndian.Uint16(data[1:3])
	s.SubIndex = data[3]
	s.Value = binary.LittleEndian.Uint32(data[4:8])
	s.Data = data[ethercatSDOHeaderLen:]
	return s
}

// findMailbox applies Wireshark's mailbox heuristic to a datagram: a
// write, or a read with a working counter of one, to ADO 0x1000 or above,
// whose header names a known mailbox type with a sane length.
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
