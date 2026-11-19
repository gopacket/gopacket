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
	"time"
)

// Get block info response, 78 octets:
//
//	0  type(2) info length(2) unknown(2) const "pp"(2) unknown(1)
//	9  flags(1) language(1) subblock type(1) number(2)
//	14 load memory length(4) security(4)
//	22 code time(6) interface time(6)
//	34 SSB length(2) ADD length(2) local data length(2) MC7 length(2)
//	42 author(8) family(8) name(8)
//	66 version(1) unknown(1) checksum(2) reserved(4) reserved(4)
const (
	s7commBlockInfoLen  = 78
	s7commBlockNameLen  = 8
	s7commBlockConstLen = 2
	s7commVersionShift  = 4
	s7commVersionMask   = 0x0F
)

// S7CommSubblockType is the block type octet of block info, e.g. 0x0A
// for a DB. Unlike S7CommBlockType it is binary, not ASCII.
type S7CommSubblockType uint8

// Subblock types.
const (
	S7CommSubblockNone S7CommSubblockType = 0x00
	S7CommSubblockOB   S7CommSubblockType = 0x08
	S7CommSubblockDB   S7CommSubblockType = 0x0A
	S7CommSubblockSDB  S7CommSubblockType = 0x0B
	S7CommSubblockFC   S7CommSubblockType = 0x0C
	S7CommSubblockSFC  S7CommSubblockType = 0x0D
	S7CommSubblockFB   S7CommSubblockType = 0x0E
	S7CommSubblockSFB  S7CommSubblockType = 0x0F
)

func (t S7CommSubblockType) String() string {
	switch t {
	case S7CommSubblockNone:
		return "Not set"
	case S7CommSubblockOB:
		return "OB"
	case S7CommSubblockDB:
		return "DB"
	case S7CommSubblockSDB:
		return "SDB"
	case S7CommSubblockFC:
		return "FC"
	case S7CommSubblockSFC:
		return "SFC"
	case S7CommSubblockFB:
		return "FB"
	case S7CommSubblockSFB:
		return "SFB"
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(t))
}

// S7CommBlockSecurity is the block protection of block info.
type S7CommBlockSecurity uint32

// Block protection values.
const (
	S7CommSecurityNone    S7CommBlockSecurity = 0
	S7CommSecurityKnowHow S7CommBlockSecurity = 3
)

// S7CommBlockInfo is a get block info response. Times are UTC.
type S7CommBlockInfo struct {
	Head            uint16 // "block type" in Wireshark; 0x0100 seen
	InfoLength      uint16
	Unknown2        uint16
	Const3          string // "pp"
	Unknown         uint8
	Flags           uint8 // 0x01 linked, 0x02 standard block, 0x08 non-retain
	Language        S7CommBlockLang
	SubblockType    S7CommSubblockType
	Number          uint16
	LoadMemLength   uint32
	Security        S7CommBlockSecurity
	CodeTime        time.Time
	InterfaceTime   time.Time
	SSBLength       uint16
	AddLength       uint16
	LocalDataLength uint16
	MC7Length       uint16
	Author          string
	Family          string
	Name            string
	Version         uint8 // major << 4 | minor
	Unknown3        uint8
	Checksum        uint16
	Reserved1       uint32
	Reserved2       uint32
}

// VersionString returns the header version as "major.minor".
func (b *S7CommBlockInfo) VersionString() string {
	return fmt.Sprintf("%d.%d", b.Version>>s7commVersionShift, b.Version&s7commVersionMask)
}

// decodeBlockInfo reads a get block info response.
func (u *S7CommUserdata) decodeBlockInfo() error {
	d := u.Data
	if len(d) < s7commBlockInfoLen {
		return fmt.Errorf("%w: block info %d octets", ErrS7CommMalformed, len(d))
	}

	be := binary.BigEndian
	u.BlockInfo = &S7CommBlockInfo{
		Head:            be.Uint16(d[0:2]),
		InfoLength:      be.Uint16(d[2:4]),
		Unknown2:        be.Uint16(d[4:6]),
		Const3:          string(d[6 : 6+s7commBlockConstLen]),
		Unknown:         d[8],
		Flags:           d[9],
		Language:        S7CommBlockLang(d[10]),
		SubblockType:    S7CommSubblockType(d[11]),
		Number:          be.Uint16(d[12:14]),
		LoadMemLength:   be.Uint32(d[14:18]),
		Security:        S7CommBlockSecurity(be.Uint32(d[18:22])),
		CodeTime:        s7commS7Time(d[22 : 22+s7commS7TimeLen]),
		InterfaceTime:   s7commS7Time(d[28 : 28+s7commS7TimeLen]),
		SSBLength:       be.Uint16(d[34:36]),
		AddLength:       be.Uint16(d[36:38]),
		LocalDataLength: be.Uint16(d[38:40]),
		MC7Length:       be.Uint16(d[40:42]),
		Author:          s7commCString(d[42 : 42+s7commBlockNameLen]),
		Family:          s7commCString(d[50 : 50+s7commBlockNameLen]),
		Name:            s7commCString(d[58 : 58+s7commBlockNameLen]),
		Version:         d[66],
		Unknown3:        d[67],
		Checksum:        be.Uint16(d[68:70]),
		Reserved1:       be.Uint32(d[70:74]),
		Reserved2:       be.Uint32(d[74:78]),
	}
	return nil
}

// s7commCString returns a fixed-size ASCII field up to its first NUL.
func s7commCString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
