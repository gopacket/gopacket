// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// File access over EtherCAT (FoE) mailbox bodies (ETG.1000.6, Wireshark
// packet-ecatmb.c). Fields are little endian.
//
//	FoE header (6 bytes): OpCode (1) | reserved (1) | 4 bytes by opcode
//
//	RRQ, WRQ   Password (4)                     | file name ...
//	DATA       PacketNo (4)                     | data ...
//	ACK        PacketNo (4)
//	ERR        ErrorCode (4)                    | error text ...
//	BUSY       Done (2) | Entire (2)            | busy text ...
//
// Wireshark labels the password "file length" and reads only the low 16
// bits of the packet number.

package layers

import (
	"encoding/binary"
	"fmt"
)

const ethercatFoEHeaderLen = 6

// EtherCATFoEOpCode is the FoE operation.
type EtherCATFoEOpCode uint8

// FoE opcodes.
const (
	EtherCATFoERRQ  EtherCATFoEOpCode = 1
	EtherCATFoEWRQ  EtherCATFoEOpCode = 2
	EtherCATFoEDATA EtherCATFoEOpCode = 3
	EtherCATFoEACK  EtherCATFoEOpCode = 4
	EtherCATFoEERR  EtherCATFoEOpCode = 5
	EtherCATFoEBUSY EtherCATFoEOpCode = 6
)

// String returns the opcode mnemonic.
func (o EtherCATFoEOpCode) String() string {
	switch o {
	case EtherCATFoERRQ:
		return "RRQ"
	case EtherCATFoEWRQ:
		return "WRQ"
	case EtherCATFoEDATA:
		return "DATA"
	case EtherCATFoEACK:
		return "ACK"
	case EtherCATFoEERR:
		return "ERROR"
	case EtherCATFoEBUSY:
		return "BUSY"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(o))
}

// EtherCATFoEError is an FoE error code.
type EtherCATFoEError uint32

// FoE error codes (ETG.1000.6 table 92).
const (
	EtherCATFoEErrNotDefined    EtherCATFoEError = 0x8000
	EtherCATFoEErrNotFound      EtherCATFoEError = 0x8001
	EtherCATFoEErrAccessDenied  EtherCATFoEError = 0x8002
	EtherCATFoEErrDiskFull      EtherCATFoEError = 0x8003
	EtherCATFoEErrIllegal       EtherCATFoEError = 0x8004
	EtherCATFoEErrPacketNumber  EtherCATFoEError = 0x8005
	EtherCATFoEErrAlreadyExists EtherCATFoEError = 0x8006
	EtherCATFoEErrNoUser        EtherCATFoEError = 0x8007
	EtherCATFoEErrBootstrapOnly EtherCATFoEError = 0x8008
	EtherCATFoEErrNotBootstrap  EtherCATFoEError = 0x8009
	EtherCATFoEErrNoRights      EtherCATFoEError = 0x800A
	EtherCATFoEErrProgramError  EtherCATFoEError = 0x800B
)

// Old slaves send the error codes 0-11 without the 0x8000 base.
const (
	ethercatFoEErrBase      EtherCATFoEError = 0x8000
	ethercatFoEErrLegacyMax EtherCATFoEError = 0x000B
)

// String returns the error name. Old slaves send the codes without the
// 0x8000 base; both forms are named.
func (e EtherCATFoEError) String() string {
	code := e
	if code <= ethercatFoEErrLegacyMax {
		code += ethercatFoEErrBase
	}

	switch code {
	case EtherCATFoEErrNotDefined:
		return "Not defined"
	case EtherCATFoEErrNotFound:
		return "Not found"
	case EtherCATFoEErrAccessDenied:
		return "Access denied"
	case EtherCATFoEErrDiskFull:
		return "Disk full"
	case EtherCATFoEErrIllegal:
		return "Illegal"
	case EtherCATFoEErrPacketNumber:
		return "Packet number wrong"
	case EtherCATFoEErrAlreadyExists:
		return "Already exists"
	case EtherCATFoEErrNoUser:
		return "No user"
	case EtherCATFoEErrBootstrapOnly:
		return "Bootstrap only"
	case EtherCATFoEErrNotBootstrap:
		return "Not bootstrap"
	case EtherCATFoEErrNoRights:
		return "No rights"
	case EtherCATFoEErrProgramError:
		return "Program error"
	}
	return fmt.Sprintf("Unknown(0x%x)", uint32(e))
}

// EtherCATFoE is a File access over EtherCAT message.
//
// Data is what follows the 6-byte header: the file name of RRQ and WRQ,
// the file bytes of DATA, the text of ERR and BUSY. It aliases the
// packet data; names and texts carry no terminator.
type EtherCATFoE struct {
	OpCode    EtherCATFoEOpCode
	Password  uint32           // RRQ, WRQ
	PacketNo  uint32           // DATA, ACK
	ErrorCode EtherCATFoEError // ERR
	Done      uint16           // BUSY: progress, out of Entire
	Entire    uint16           // BUSY
	Data      []byte
}

// FileName returns the file name of a read or write request.
func (f *EtherCATFoE) FileName() string {
	if f.OpCode != EtherCATFoERRQ && f.OpCode != EtherCATFoEWRQ {
		return ""
	}
	return string(f.Data)
}

// Text returns the text of an error or busy message.
func (f *EtherCATFoE) Text() string {
	if f.OpCode != EtherCATFoEERR && f.OpCode != EtherCATFoEBUSY {
		return ""
	}
	return string(trimEtherCATNUL(f.Data))
}

// decodeEtherCATFoE decodes an FoE body, nil when the header is cut.
func decodeEtherCATFoE(data []byte) *EtherCATFoE {
	if len(data) < ethercatFoEHeaderLen {
		return nil
	}

	f := &EtherCATFoE{
		OpCode: EtherCATFoEOpCode(data[0]),
		Data:   data[ethercatFoEHeaderLen:],
	}
	word := binary.LittleEndian.Uint32(data[2:6])

	switch f.OpCode {
	case EtherCATFoERRQ, EtherCATFoEWRQ:
		f.Password = word
	case EtherCATFoEDATA, EtherCATFoEACK:
		f.PacketNo = word
	case EtherCATFoEERR:
		f.ErrorCode = EtherCATFoEError(word)
	case EtherCATFoEBUSY:
		f.Done = binary.LittleEndian.Uint16(data[2:4])
		f.Entire = binary.LittleEndian.Uint16(data[4:6])
	}
	return f
}
