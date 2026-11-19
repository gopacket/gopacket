// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
)

// Programmer commands (function group 1, "TIS") carry the variable
// table service of STEP 7 among others. Their data value is
//
//	parameter size(2), data size(2), parameter, data
//
// and the data, for the variable status, modify and force services:
//
//	request:    count(2), addresses (6 octets each)[, values]
//	indication: count(2), values (variable status)
//	indication: count(2), return codes[, fill] (modify, force)
//
// A value is a return code, transport size, length and data padded to
// an even size.

// Subfunctions of the programmer commands group whose data is decoded.
const (
	S7CommTISVarStat S7CommSubfunction = 0x02
	S7CommTISModVar  S7CommSubfunction = 0x08
	S7CommTISForce   S7CommSubfunction = 0x09
)

const (
	s7commTISHead     = 4
	s7commTISCountLen = 2
	s7commTISAddrLen  = 6
	s7commTISRepMask  = 0x0F
	s7commRetDataErr  = S7CommRetObjectMissing // carries a header, no data
)

// S7CommTISArea is the memory area of a variable table address.
type S7CommTISArea uint8

// Variable table memory areas: bit (X), byte (B), word (W), double
// word (D) of flags (M), inputs (E), outputs (A), peripheral inputs
// (PE), data blocks, timers and counters.
const (
	S7CommTISAreaMX  S7CommTISArea = 0x00
	S7CommTISAreaMB  S7CommTISArea = 0x01
	S7CommTISAreaMW  S7CommTISArea = 0x02
	S7CommTISAreaMD  S7CommTISArea = 0x03
	S7CommTISAreaEX  S7CommTISArea = 0x10
	S7CommTISAreaEB  S7CommTISArea = 0x11
	S7CommTISAreaEW  S7CommTISArea = 0x12
	S7CommTISAreaED  S7CommTISArea = 0x13
	S7CommTISAreaAX  S7CommTISArea = 0x20
	S7CommTISAreaAB  S7CommTISArea = 0x21
	S7CommTISAreaAW  S7CommTISArea = 0x22
	S7CommTISAreaAD  S7CommTISArea = 0x23
	S7CommTISAreaPEB S7CommTISArea = 0x31
	S7CommTISAreaPEW S7CommTISArea = 0x32
	S7CommTISAreaPED S7CommTISArea = 0x33
	S7CommTISAreaDBX S7CommTISArea = 0x70
	S7CommTISAreaDBB S7CommTISArea = 0x71
	S7CommTISAreaDBW S7CommTISArea = 0x72
	S7CommTISAreaDBD S7CommTISArea = 0x73
	S7CommTISAreaT   S7CommTISArea = 0x54
	S7CommTISAreaC   S7CommTISArea = 0x64
)

var s7commTISAreaNames = map[S7CommTISArea]string{
	S7CommTISAreaMX: "MX", S7CommTISAreaMB: "MB", S7CommTISAreaMW: "MW", S7CommTISAreaMD: "MD",
	S7CommTISAreaEX: "EX", S7CommTISAreaEB: "EB", S7CommTISAreaEW: "EW", S7CommTISAreaED: "ED",
	S7CommTISAreaAX: "AX", S7CommTISAreaAB: "AB", S7CommTISAreaAW: "AW", S7CommTISAreaAD: "AD",
	S7CommTISAreaPEB: "PEB", S7CommTISAreaPEW: "PEW", S7CommTISAreaPED: "PED",
	S7CommTISAreaDBX: "DBX", S7CommTISAreaDBB: "DBB", S7CommTISAreaDBW: "DBW", S7CommTISAreaDBD: "DBD",
	S7CommTISAreaT: "T", S7CommTISAreaC: "C",
}

func (a S7CommTISArea) String() string {
	if n, ok := s7commTISAreaNames[a]; ok {
		return n
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(a))
}

// S7CommTISAddress is a variable table address. An area with a nonzero
// low nibble (byte, word, double word, timer, counter) carries a
// repetition factor; a bit area carries the bit position.
type S7CommTISAddress struct {
	Area       S7CommTISArea
	Repetition uint8
	BitPos     uint8
	DBNumber   uint16
	Start      uint16
}

// S7CommTIS is a programmer command. Param and Body are the raw
// parameter and data parts; the views below are set for variable
// status, modify and force. ParamFields and DataFields split the
// parameter and the data of the other services.
type S7CommTIS struct {
	ParamSize uint16
	DataSize  uint16
	Param     []byte
	Body      []byte
	ItemCount uint16
	Addresses []S7CommTISAddress
	Values    []S7CommDataItem
	Results   []S7CommReturnCode

	typ S7CommUserdataType
	sub S7CommSubfunction
}

// decodeTIS reads the programmer command sizes and, for the variable
// services, their items.
func (u *S7CommUserdata) decodeTIS() error {
	d := u.Data
	if len(d) < s7commTISHead {
		return fmt.Errorf("%w: TIS data %d octets", ErrS7CommMalformed, len(d))
	}

	t := &S7CommTIS{
		ParamSize: binary.BigEndian.Uint16(d[0:2]),
		DataSize:  binary.BigEndian.Uint16(d[2:4]),
		typ:       u.Type,
		sub:       u.Subfunction,
	}
	pEnd := s7commTISHead + int(t.ParamSize)
	dEnd := pEnd + int(t.DataSize)
	if dEnd > len(d) {
		return fmt.Errorf("%w: TIS sizes %d+%d in %d octets", ErrS7CommMalformed, t.ParamSize, t.DataSize, len(d))
	}
	t.Param = d[s7commTISHead:pEnd]
	t.Body = d[pEnd:dEnd]

	if err := t.decodeItems(u.Type, u.Subfunction); err != nil {
		return err
	}
	u.TIS = t
	return nil
}

// decodeItems reads the variable status, modify and force items.
func (t *S7CommTIS) decodeItems(typ S7CommUserdataType, sub S7CommSubfunction) error {
	switch sub {
	case S7CommTISVarStat, S7CommTISModVar, S7CommTISForce:
	default:
		return nil
	}
	if typ != S7CommUDTypeRequest && typ != S7CommUDTypePush {
		return nil
	}

	b := t.Body
	if len(b) < s7commTISCountLen {
		return fmt.Errorf("%w: TIS data %d octets", ErrS7CommMalformed, len(b))
	}
	t.ItemCount = binary.BigEndian.Uint16(b[0:2])
	b = b[s7commTISCountLen:]
	n := int(t.ItemCount)

	var err error
	switch {
	case typ == S7CommUDTypeRequest:
		if t.Addresses, b, err = s7commTISAddrs(b, n); err != nil {
			return err
		}
		if sub != S7CommTISVarStat {
			t.Values, err = s7commTISValues(b, n)
		}
	case sub == S7CommTISVarStat:
		t.Values, err = s7commTISValues(b, n)
	default:
		t.Results, err = s7commTISResults(b, n)
	}
	return err
}

// s7commTISAddrs reads n variable table addresses.
func s7commTISAddrs(b []byte, n int) ([]S7CommTISAddress, []byte, error) {
	if n*s7commTISAddrLen > len(b) {
		return nil, nil, fmt.Errorf("%w: %d TIS addresses in %d octets", ErrS7CommMalformed, n, len(b))
	}

	addrs := make([]S7CommTISAddress, n)
	for i := range addrs {
		a := b[i*s7commTISAddrLen:]
		addr := S7CommTISAddress{
			Area:     S7CommTISArea(a[0]),
			DBNumber: binary.BigEndian.Uint16(a[2:4]),
			Start:    binary.BigEndian.Uint16(a[4:6]),
		}
		if a[0]&s7commTISRepMask != 0 {
			addr.Repetition = a[1]
		} else {
			addr.BitPos = a[1]
		}
		addrs[i] = addr
	}
	return addrs, b[n*s7commTISAddrLen:], nil
}

// s7commTISValues reads n values. Unlike read data, the length is in
// bits only for BYTE and INT (truncated), and every odd value is padded.
// Return codes other than 0x00, 0x0A and 0xFF carry no transport size
// or length; Wireshark reports both as zero.
func s7commTISValues(b []byte, n int) ([]S7CommDataItem, error) {
	if n*s7commDataItemHead > len(b) {
		return nil, fmt.Errorf("%w: %d TIS values in %d octets", ErrS7CommMalformed, n, len(b))
	}

	vals := make([]S7CommDataItem, 0, n)
	for i := 0; i < n; i++ {
		if len(b) < s7commDataItemHead {
			return nil, fmt.Errorf("%w: TIS value %d of %d truncated", ErrS7CommMalformed, i, n)
		}

		v := S7CommDataItem{ReturnCode: S7CommReturnCode(b[0])}
		if v.ReturnCode.hasData() || v.ReturnCode == s7commRetDataErr {
			v.TransportSize = S7CommDataTransportSize(b[1])
			v.Length = binary.BigEndian.Uint16(b[2:4])
		}
		size := int(v.Length)
		if v.TransportSize == S7CommDataTSByte || v.TransportSize == S7CommDataTSInt {
			size /= s7commBitsPerByte
		}

		end := s7commDataItemHead
		if v.ReturnCode.hasData() {
			end += size
			if end > len(b) {
				return nil, fmt.Errorf("%w: TIS value %d length %d", ErrS7CommMalformed, i, size)
			}
			v.Data = b[s7commDataItemHead:end]
			if size%2 == 1 {
				end++
			}
		}
		vals = append(vals, v)

		if end > len(b) {
			end = len(b)
		}
		b = b[end:]
	}
	return vals, nil
}

// s7commTISResults reads n modify or force return codes.
func s7commTISResults(b []byte, n int) ([]S7CommReturnCode, error) {
	if n > len(b) {
		return nil, fmt.Errorf("%w: %d TIS results in %d octets", ErrS7CommMalformed, n, len(b))
	}

	res := make([]S7CommReturnCode, n)
	for i := range res {
		res[i] = S7CommReturnCode(b[i])
	}
	return res, nil
}
