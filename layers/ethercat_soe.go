// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Servo drive profile over EtherCAT (SoE) and vendor specific (VoE)
// mailbox bodies (ETG.1000.6, Wireshark packet-ecatmb.c). Fields are
// little endian.
//
//	SoE header (4 bytes):
//	    byte 0: OpCode (3 bits) | Incomplete (1) | Error (1) | DriveNo (3)
//	    byte 1: element flags
//	    word 1: IDN, or the fragments left when Incomplete is set
//	then the element data, or a 2-byte error code when Error is set.
//
//	VoE header (6 bytes): VendorID (4) | VendorType (2), then vendor data.

package layers

import (
	"encoding/binary"
	"fmt"
)

const (
	ethercatSoEHeaderLen    = 4
	ethercatSoEOpCodeMask   = 0x07
	ethercatSoEIncomplete   = 0x08
	ethercatSoEError        = 0x10
	ethercatSoEDriveShift   = 5
	ethercatSoEErrorCodeLen = 2
	ethercatVoEHeaderLen    = 6

	// IDN layout: S/P (1 bit) | parameter set (3) | number (12).
	ethercatIDNProductBit = 0x8000
	ethercatIDNSetShift   = 12
	ethercatIDNSetMask    = 0x07
	ethercatIDNNumberMask = 0x0FFF
)

// EtherCATSoEOpCode is the SoE service.
type EtherCATSoEOpCode uint8

// SoE opcodes.
const (
	EtherCATSoEReadRequest   EtherCATSoEOpCode = 1
	EtherCATSoEReadResponse  EtherCATSoEOpCode = 2
	EtherCATSoEWriteRequest  EtherCATSoEOpCode = 3
	EtherCATSoEWriteResponse EtherCATSoEOpCode = 4
	EtherCATSoENotification  EtherCATSoEOpCode = 5
	EtherCATSoEEmergency     EtherCATSoEOpCode = 6
)

// String returns the opcode name.
func (o EtherCATSoEOpCode) String() string {
	switch o {
	case EtherCATSoEReadRequest:
		return "readReq"
	case EtherCATSoEReadResponse:
		return "readRes"
	case EtherCATSoEWriteRequest:
		return "writeReq"
	case EtherCATSoEWriteResponse:
		return "writeRes"
	case EtherCATSoENotification:
		return "notification"
	case EtherCATSoEEmergency:
		return "emergency"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(o))
}

// EtherCATSoEElements is the element flag byte: the IDN elements a
// request asks for or a response carries.
type EtherCATSoEElements uint8

// SoE element flags.
const (
	EtherCATSoEDataState EtherCATSoEElements = 0x01
	EtherCATSoEName      EtherCATSoEElements = 0x02
	EtherCATSoEAttribute EtherCATSoEElements = 0x04
	EtherCATSoEUnit      EtherCATSoEElements = 0x08
	EtherCATSoEMin       EtherCATSoEElements = 0x10
	EtherCATSoEMax       EtherCATSoEElements = 0x20
	EtherCATSoEValue     EtherCATSoEElements = 0x40
	EtherCATSoEDefault   EtherCATSoEElements = 0x80
)

// Has reports whether the element flag is set.
func (e EtherCATSoEElements) Has(flag EtherCATSoEElements) bool { return e&flag != 0 }

// EtherCATSoEIDN is a SERCOS identification number.
type EtherCATSoEIDN uint16

// String formats the IDN the SERCOS way, e.g. "S-0-0100" or "P-1-0012".
func (i EtherCATSoEIDN) String() string {
	kind := 'S'
	if i&ethercatIDNProductBit != 0 {
		kind = 'P'
	}
	return fmt.Sprintf("%c-%d-%04d", kind, (i>>ethercatIDNSetShift)&ethercatIDNSetMask, i&ethercatIDNNumberMask)
}

// EtherCATSoE is a Servo drive profile over EtherCAT message.
//
// IDN is set unless Incomplete is, in which case FragmentsLeft is. With
// Error set, ErrorCode is read from the two bytes after the header.
// Data holds everything after the header.
//
// Wireshark differs on error messages: it shows the IDN word a second
// time as the error code.
type EtherCATSoE struct {
	OpCode        EtherCATSoEOpCode
	Incomplete    bool
	Error         bool
	DriveNo       uint8
	Elements      EtherCATSoEElements
	IDN           EtherCATSoEIDN
	FragmentsLeft uint16
	ErrorCode     uint16
	Data          []byte
}

// decodeEtherCATSoE decodes an SoE body, nil when the header is cut.
func decodeEtherCATSoE(data []byte) *EtherCATSoE {
	if len(data) < ethercatSoEHeaderLen {
		return nil
	}

	s := &EtherCATSoE{
		OpCode:     EtherCATSoEOpCode(data[0] & ethercatSoEOpCodeMask),
		Incomplete: data[0]&ethercatSoEIncomplete != 0,
		Error:      data[0]&ethercatSoEError != 0,
		DriveNo:    data[0] >> ethercatSoEDriveShift,
		Elements:   EtherCATSoEElements(data[1]),
		Data:       data[ethercatSoEHeaderLen:],
	}

	// The second word counts fragments while more of them follow.
	word := binary.LittleEndian.Uint16(data[2:4])
	if s.Incomplete && !s.Error {
		s.FragmentsLeft = word
	} else {
		s.IDN = EtherCATSoEIDN(word)
	}

	if s.Error && len(s.Data) >= ethercatSoEErrorCodeLen {
		s.ErrorCode = binary.LittleEndian.Uint16(s.Data)
	}
	return s
}

// EtherCATVoE is a vendor specific over EtherCAT message.
type EtherCATVoE struct {
	VendorID   uint32
	VendorType uint16
	Data       []byte
}

// decodeEtherCATVoE decodes a VoE body, nil when the header is cut.
func decodeEtherCATVoE(data []byte) *EtherCATVoE {
	if len(data) < ethercatVoEHeaderLen {
		return nil
	}

	return &EtherCATVoE{
		VendorID:   binary.LittleEndian.Uint32(data),
		VendorType: binary.LittleEndian.Uint16(data[4:6]),
		Data:       data[ethercatVoEHeaderLen:],
	}
}
