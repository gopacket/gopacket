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

// A system event is the body of a frame with version 0xFE, the
// "extended keep-alive" PLCs and HMIs send since TIA Portal V14:
//
//	reserved(4) | confirmed bytes(4) | reserved(4) | reserved(4) | tail
//
// The tail is absent (16-octet event), a text such as "LOGOUT", or a
// STRUCT value with its members. That value is coded like any other,
// but without VLQ: IDs, array sizes, sparse keys and the UDInt, DInt,
// ULInt and LInt types take 4 or 8 octets, flags and datatype two
// octets each.
//
// The layout is the s7commwireshark plugin's. No public capture holds
// such a frame, so it is checked against vectors built from the plugin
// source only.

const (
	// s7plusEventHeadLen is the size of the four fixed words.
	s7plusEventHeadLen = 16

	// s7plusEventMarkLen is the size of the flags and datatype that
	// start a binary tail: 00 00 00 17, a plain STRUCT.
	s7plusEventMarkLen = 4
)

// S7CommPlusSysEvent is the body of a system event frame.
type S7CommPlusSysEvent struct {
	Reserved1 uint32

	// ConfirmedBytes counts the octets received since the last event.
	ConfirmedBytes uint32

	Reserved2 uint32
	Reserved3 uint32

	// Message is a text tail, Value a binary one. At most one is set.
	Message string
	Value   *S7CommPlusValue

	// Rest holds what follows Value.
	Rest []byte
}

// DecodeSysEvent decodes Data of a frame with version
// S7CommPlusKeepAlive. Other versions return ErrS7CommPlusUnsupported.
func (s *S7CommPlus) DecodeSysEvent() (*S7CommPlusSysEvent, error) {
	if s.Version != S7CommPlusKeepAlive {
		return nil, fmt.Errorf("%w: system event in a %v frame", ErrS7CommPlusUnsupported, s.Version)
	}
	return DecodeS7CommPlusSysEvent(s.Data)
}

// DecodeS7CommPlusSysEvent decodes the body of a system event. On
// error the returned event, when not nil, holds the fields decoded so
// far.
func DecodeS7CommPlusSysEvent(data []byte) (*S7CommPlusSysEvent, error) {
	if len(data) < s7plusEventHeadLen {
		return nil, fmt.Errorf("%w: system event of %d octets", ErrS7CommPlusMalformed, len(data))
	}

	e := &S7CommPlusSysEvent{
		Reserved1:      binary.BigEndian.Uint32(data[0:4]),
		ConfirmedBytes: binary.BigEndian.Uint32(data[4:8]),
		Reserved2:      binary.BigEndian.Uint32(data[8:12]),
		Reserved3:      binary.BigEndian.Uint32(data[12:16]),
	}
	tail := data[s7plusEventHeadLen:]
	if len(tail) == 0 {
		return e, nil
	}

	binaryTail := len(tail) >= s7plusEventMarkLen &&
		binary.BigEndian.Uint32(tail) == uint32(S7CommPlusTypeStruct)
	if !binaryTail {
		e.Message = string(tail)
		return e, nil
	}

	r := &s7plusReader{b: tail, wide: true}
	v, level := r.value()
	r.members(&v, level)
	e.Value = &v
	e.Rest = r.b
	return e, r.err
}
