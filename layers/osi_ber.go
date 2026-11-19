// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"strconv"
	"strings"
)

// A small, strict BER (X.690) TLV reader shared by the IEC 61850 GOOSE and
// SV decoders and the OSI presentation, ACSE and MMS decoders. It only
// accepts definite lengths of at most four length octets and tag numbers
// of at most four continuation octets. Values are subslices of the input:
// nothing is allocated from a claimed length.
//
//	identifier   length          value
//	+----------+ +-------------+ +-------------+
//	|cc f nnnnn| |0lllllll     | | len octets  |
//	+----------+ |1nnn + n octs| +-------------+
//	 class form  +-------------+
//	 number (31 = more octets follow)

// osiBERClass is the class of a BER tag.
type osiBERClass uint8

const (
	osiBERUniversal   osiBERClass = 0
	osiBERApplication osiBERClass = 1
	osiBERContext     osiBERClass = 2
	osiBERPrivate     osiBERClass = 3
)

// osiBERForm tells whether a BER value holds raw octets or nested TLVs.
type osiBERForm uint8

const (
	osiBERPrimitive   osiBERForm = 0
	osiBERConstructed osiBERForm = 1
)

// Universal tag numbers used by the OSI and IEC 61850 decoders.
const (
	osiBERTagBoolean  uint32 = 1
	osiBERTagInteger  uint32 = 2
	osiBERTagBitStr   uint32 = 3
	osiBERTagOctetStr uint32 = 4
	osiBERTagNull     uint32 = 5
	osiBERTagOID      uint32 = 6
	osiBERTagObjDesc  uint32 = 7
	osiBERTagExternal uint32 = 8
	osiBERTagSequence uint32 = 16
	osiBERTagSet      uint32 = 17
	osiBERTagVisible  uint32 = 26
)

const (
	// osiBERMaxDepth caps the nesting of recursive values (MMS Data) so
	// crafted input cannot exhaust the stack.
	osiBERMaxDepth = 32

	osiBERMaxTagOctets = 4
	osiBERMaxLenOctets = 4

	osiBERClassShift   = 6
	osiBERFormBit      = 0x20
	osiBERTagMask      = 0x1f
	osiBERHighTag      = 0x1f
	osiBERMoreBit      = 0x80
	osiBERLongLen      = 0x80
	osiBERIndefinite   = 0x80
	osiBERMaxUnusedBit = 7
	osiBERMaxIntOctets = 8
)

var (
	errOSIBERTruncated  = errors.New("BER: value truncated")
	errOSIBERIndefinite = errors.New("BER: indefinite length not supported")
	errOSIBERLength     = errors.New("BER: length too long")
	errOSIBERTag        = errors.New("BER: tag number too long")
	errOSIBERDepth      = errors.New("BER: nesting too deep")
	errOSIBERInteger    = errors.New("BER: invalid integer")
	errOSIBERBoolean    = errors.New("BER: invalid boolean")
	errOSIBERBitString  = errors.New("BER: invalid bit string")
	errOSIBEROID        = errors.New("BER: invalid object identifier")
	errOSIBERUnexpected = errors.New("BER: unexpected tag")
)

// osiBERTLV is one decoded BER element. Value aliases the input.
type osiBERTLV struct {
	Class osiBERClass
	Form  osiBERForm
	Tag   uint32
	Value []byte
}

// is reports whether t has the given class, form and tag number.
func (t osiBERTLV) is(c osiBERClass, f osiBERForm, n uint32) bool {
	return t.Class == c && t.Form == f && t.Tag == n
}

// osiBERNext reads the first TLV of data and returns it with the bytes
// that follow it.
func osiBERNext(data []byte) (osiBERTLV, []byte, error) {
	var t osiBERTLV
	if len(data) < 2 {
		return t, nil, errOSIBERTruncated
	}

	// Identifier octets.
	t.Class = osiBERClass(data[0] >> osiBERClassShift)
	if data[0]&osiBERFormBit != 0 {
		t.Form = osiBERConstructed
	}
	t.Tag = uint32(data[0] & osiBERTagMask)
	off := 1
	if t.Tag == osiBERHighTag {
		n, used, err := osiBERTagNum(data[1:])
		if err != nil {
			return t, nil, err
		}
		t.Tag = n
		off += used
	}

	// Length octets.
	length, used, err := osiBERLen(data[off:])
	if err != nil {
		return t, nil, err
	}
	off += used
	if length > len(data)-off {
		return t, nil, errOSIBERTruncated
	}

	t.Value = data[off : off+length]
	return t, data[off+length:], nil
}

// osiBERCount counts the TLVs of a SEQUENCE OF body so its list can be
// allocated once. Grown by append, a body of two-octet items costs about
// twice the final list in discarded arrays.
func osiBERCount(data []byte) (int, error) {
	count := 0
	for ; len(data) > 0; count++ {
		_, rest, err := osiBERNext(data)
		if err != nil {
			return 0, err
		}
		data = rest
	}
	return count, nil
}

// osiBERTagNum decodes a high tag number (base 128, high bit = more).
func osiBERTagNum(data []byte) (uint32, int, error) {
	var n uint32
	for i := 0; i < len(data); i++ {
		if i == osiBERMaxTagOctets {
			return 0, 0, errOSIBERTag
		}

		n = n<<7 | uint32(data[i]&^osiBERMoreBit)
		if data[i]&osiBERMoreBit == 0 {
			return n, i + 1, nil
		}
	}
	return 0, 0, errOSIBERTruncated
}

// osiBERLen decodes a definite length, e.g. 0x05 = 5, 0x82 0x01 0x00 = 256.
func osiBERLen(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, errOSIBERTruncated
	}

	first := data[0]
	if first < osiBERLongLen {
		return int(first), 1, nil
	}
	if first == osiBERIndefinite {
		return 0, 0, errOSIBERIndefinite
	}

	n := int(first &^ osiBERLongLen)
	if n > osiBERMaxLenOctets {
		return 0, 0, errOSIBERLength
	}
	if len(data) < 1+n {
		return 0, 0, errOSIBERTruncated
	}

	// Build in uint64: four octets overflow a 32-bit int into a negative
	// length that would pass the caller's bounds check.
	var length uint64
	for _, b := range data[1 : 1+n] {
		length = length<<8 | uint64(b)
	}
	if length > uint64(len(data)) {
		return 0, 0, errOSIBERTruncated
	}
	return int(length), 1 + n, nil
}

// osiBERExpect reads one TLV and fails unless it has the given identity.
func osiBERExpect(data []byte, c osiBERClass, f osiBERForm, n uint32) ([]byte, []byte, error) {
	t, rest, err := osiBERNext(data)
	if err != nil {
		return nil, nil, err
	}
	if !t.is(c, f, n) {
		return nil, nil, errOSIBERUnexpected
	}
	return t.Value, rest, nil
}

// osiBERSingle reads exactly one TLV filling all of data.
func osiBERSingle(data []byte) (osiBERTLV, error) {
	t, rest, err := osiBERNext(data)
	if err != nil {
		return t, err
	}
	if len(rest) != 0 {
		return t, errOSIBERUnexpected
	}
	return t, nil
}

// osiBERInt decodes a two's complement INTEGER of 1 to 8 octets.
func osiBERInt(v []byte) (int64, error) {
	if len(v) == 0 || len(v) > osiBERMaxIntOctets {
		return 0, errOSIBERInteger
	}

	// Sign extend from the first octet.
	n := int64(int8(v[0]))
	for _, b := range v[1:] {
		n = n<<8 | int64(b)
	}
	return n, nil
}

// osiBERUint decodes a non-negative INTEGER. A ninth octet is allowed
// only as the 0x00 sign octet in front of a value with the top bit set.
func osiBERUint(v []byte) (uint64, error) {
	if len(v) == 0 || v[0]&0x80 != 0 {
		return 0, errOSIBERInteger
	}
	if len(v) > osiBERMaxIntOctets+1 || (len(v) == osiBERMaxIntOctets+1 && v[0] != 0) {
		return 0, errOSIBERInteger
	}

	var n uint64
	for _, b := range v {
		n = n<<8 | uint64(b)
	}
	return n, nil
}

// osiBERUint32 decodes a non-negative INTEGER that must fit in 32 bits.
func osiBERUint32(v []byte) (uint32, error) {
	n, err := osiBERUint(v)
	if err != nil {
		return 0, err
	}
	if n > 0xffffffff {
		return 0, errOSIBERInteger
	}
	return uint32(n), nil
}

// osiBERBool decodes a one octet BOOLEAN.
func osiBERBool(v []byte) (bool, error) {
	if len(v) != 1 {
		return false, errOSIBERBoolean
	}
	return v[0] != 0, nil
}

// osiBERBits splits a BIT STRING into its octets and unused bit count.
func osiBERBits(v []byte) ([]byte, uint8, error) {
	if len(v) == 0 {
		return nil, 0, errOSIBERBitString
	}

	unused := v[0]
	if unused > osiBERMaxUnusedBit || (len(v) == 1 && unused != 0) {
		return nil, 0, errOSIBERBitString
	}
	return v[1:], unused, nil
}

// osiBEROID renders an OBJECT IDENTIFIER in dotted form, e.g.
// 28 ca 22 02 01 = "1.0.9506.2.1".
func osiBEROID(v []byte) (string, error) {
	if len(v) == 0 || v[len(v)-1]&osiBERMoreBit != 0 {
		return "", errOSIBEROID
	}

	var sb strings.Builder
	var arc uint64
	first := true
	for _, b := range v {
		// Reject arcs that would overflow 64 bits.
		if arc > (1<<57)-1 {
			return "", errOSIBEROID
		}

		arc = arc<<7 | uint64(b&^osiBERMoreBit)
		if b&osiBERMoreBit != 0 {
			continue
		}

		// The first subidentifier packs two arcs: 40*X + Y.
		if first {
			top := min(arc/40, 2)
			sb.WriteString(strconv.FormatUint(top, 10))
			sb.WriteByte('.')
			arc -= top * 40
			first = false
		} else {
			sb.WriteByte('.')
		}
		sb.WriteString(strconv.FormatUint(arc, 10))
		arc = 0
	}
	return sb.String(), nil
}
