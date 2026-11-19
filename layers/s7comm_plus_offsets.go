// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import "encoding/binary"

// The offset part of a type list entry is a run of little-endian
// sections. Which ones are present depends on the offset info type
// (the high nibble of the attribute flags):
//
//	section        octets  offset info types
//	legacy pair    4       all
//	addresses      8       all but standard (1, 8)
//	FB data        28      FB array (0), FB/SFB (15)
//	array          8       one- and multi-dimensional arrays and
//	                       struct arrays (3, 4, 6, 7, 10, 11, 13, 14)
//	FB array       16      FB array (0)
//	dimensions     48      multi-dimensional (4, 7, 11, 14), FB array
//	struct sizes   8       struct arrays (6, 7, 13, 14)
//	struct info    20      structs and struct arrays (5-7, 12-14)

const (
	// Soft datatypes whose legacy pair starts with a string length.
	s7plusSoftString  = 19
	s7plusSoftWString = 62

	// s7plusMaxDims is the number of dimensions a type list entry has
	// room for.
	s7plusMaxDims = 6

	// s7plusInfoWords is the number of unnamed words after a relation ID.
	s7plusInfoWords = 4
)

// S7CommPlusVarOffsets is the typed offset part of a type list entry.
// Sections the entry's offset info type does not have stay zero.
type S7CommPlusVarOffsets struct {
	// Addresses in the optimized and the non-optimized (classic)
	// layout: 16 bits wide for the standard types, else 32.
	OptimizedAddr    uint32
	NonOptimizedAddr uint32

	// The legacy pair of the other types. A STRING or WSTRING (also as
	// array element) has its maximum length in place of Unspecified1.
	StringLength uint16
	Unspecified1 uint16
	Unspecified2 uint16

	// FB and SFB instances.
	FBRelationID     uint32
	FBInfo           [s7plusInfoWords]uint32
	FBRetainOffset   uint32
	FBVolatileOffset uint32

	// Arrays. An FB array has an element count and three sizes.
	ArrayLowerBound   int32
	ArrayElementCount uint32
	FBClassicSize     uint32
	FBRetainSize      uint32
	FBVolatileSize    uint32

	// Multi-dimensional arrays; unused dimensions have count 0.
	DimLowerBounds   [s7plusMaxDims]int32
	DimElementCounts [s7plusMaxDims]uint32

	// Structs.
	NonOptimizedStructSize uint32
	OptimizedStructSize    uint32
	StructRelationID       uint32
	StructInfo             [s7plusInfoWords]uint32
}

// s7plusLE reads little-endian fields off a slice whose length the
// caller has checked.
type s7plusLE struct{ b []byte }

func (c *s7plusLE) u16() uint16 {
	v := binary.LittleEndian.Uint16(c.b)
	c.b = c.b[2:]
	return v
}

func (c *s7plusLE) u32() uint32 {
	v := binary.LittleEndian.Uint32(c.b)
	c.b = c.b[4:]
	return v
}

func (c *s7plusLE) words(out []uint32) {
	for i := range out {
		out[i] = c.u32()
	}
}

// Offsets splits OffsetInfo into its sections. It returns false when
// OffsetInfo does not have the size of the entry's offset info type,
// which a decoded entry always has.
func (v *S7CommPlusVarType) Offsets() (S7CommPlusVarOffsets, bool) {
	var o S7CommPlusVarOffsets
	t := v.OffsetInfoType()
	if len(v.OffsetInfo) != s7plusOffsetLen(t) {
		return o, false
	}

	c := &s7plusLE{b: v.OffsetInfo}
	v.legacyPair(c, &o)
	if t != s7plusOffElemStd && t != s7plusOffStd {
		o.OptimizedAddr = c.u32()
		o.NonOptimizedAddr = c.u32()
	}

	if t == s7plusOffFBArray || t == s7plusOffFBSFB {
		o.FBRelationID = c.u32()
		c.words(o.FBInfo[:])
		o.FBRetainOffset = c.u32()
		o.FBVolatileOffset = c.u32()
	}

	switch {
	case t == s7plusOffFBArray:
		o.ArrayElementCount = c.u32()
		o.FBClassicSize = c.u32()
		o.FBRetainSize = c.u32()
		o.FBVolatileSize = c.u32()
	case s7plusOffIsArray(t):
		o.ArrayLowerBound = int32(c.u32())
		o.ArrayElementCount = c.u32()
	}

	if s7plusOffIsMDim(t) {
		for i := range o.DimLowerBounds {
			o.DimLowerBounds[i] = int32(c.u32())
		}
		c.words(o.DimElementCounts[:])
	}

	switch t {
	case s7plusOffStruct1, s7plusOffElemStruct1, s7plusOffStructM, s7plusOffElemStructM:
		o.NonOptimizedStructSize = c.u32()
		o.OptimizedStructSize = c.u32()
		fallthrough
	case s7plusOffStruct, s7plusOffElemStruct:
		o.StructRelationID = c.u32()
		c.words(o.StructInfo[:])
	}
	return o, true
}

// legacyPair reads the two 16-bit words every entry starts with.
func (v *S7CommPlusVarType) legacyPair(c *s7plusLE, o *S7CommPlusVarOffsets) {
	t := v.OffsetInfoType()
	first, second := c.u16(), c.u16()

	switch t {
	case s7plusOffElemStd:
		o.NonOptimizedAddr, o.OptimizedAddr = uint32(first), uint32(second)
		return
	case s7plusOffStd:
		o.OptimizedAddr, o.NonOptimizedAddr = uint32(first), uint32(second)
		return
	}

	o.Unspecified2 = second
	isString := v.SoftDatatype == s7plusSoftString || v.SoftDatatype == s7plusSoftWString
	switch t {
	case s7plusOffString, s7plusOffElemString, s7plusOffArray1, s7plusOffElemArray1, s7plusOffArrayM, s7plusOffElemArrayM:
		if isString {
			o.StringLength = first
			return
		}
	}
	o.Unspecified1 = first
}

// s7plusOffIsArray reports whether offset info type t has the array
// section (lower bound, element count).
func s7plusOffIsArray(t uint8) bool {
	switch t {
	case s7plusOffArray1, s7plusOffElemArray1, s7plusOffStruct1, s7plusOffElemStruct1,
		s7plusOffArrayM, s7plusOffElemArrayM, s7plusOffStructM, s7plusOffElemStructM:
		return true
	}
	return false
}

// s7plusOffIsMDim reports whether offset info type t has the
// dimensions section.
func s7plusOffIsMDim(t uint8) bool {
	switch t {
	case s7plusOffArrayM, s7plusOffElemArrayM, s7plusOffStructM, s7plusOffElemStructM, s7plusOffFBArray:
		return true
	}
	return false
}
