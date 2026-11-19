// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// S7comm-plus values and objects, as the s7commwireshark plugin
// (packet-s7comm_plus.c) reads them:
//
//	value:  flags | datatype | [count] | element... | [struct tail]
//	ID/value list: {ID(VLQ) value [members]}... 0
//	object: 0xA1 relID(4) classID classFlags attrID [attrFlags]
//	        {attribute 0xA3 | relation 0xA4 | object 0xA1 |
//	         tag description 0xA7/0xA8 | type list 0xAB |
//	         name list 0xAC}... 0xA2
//
// Integers marked VLQ use the 7-bit encoding of S7CommPlusVarUint32 and
// friends. A STRUCT value is a 4-octet ID followed by an ID/value list
// of its members, except for packed structs (DTL and friends) and
// address arrays of structs, which carry their members differently.

const (
	// Nesting limit for struct members, blob value lists and objects.
	// Real PLC data nests a few levels; the limit only stops input that
	// would otherwise recurse once per octet.
	s7plusMaxDepth = 64

	s7plusMinCap = 4 // first capacity s7plusAppend allocates

	s7plusTermID = 0 // ends an ID/value or item number list

	// Packed struct: interface timestamp(8), flags, count[, count2],
	// data. Flag 0x400 says a second element count replaces the first.
	s7plusPackedTSLen    = 8
	s7plusPackedCount2   = 0x400
	s7plusPackedLowFrom  = 0x02000000
	s7plusPackedLowTo    = 0x02ffffff
	s7plusPackedHighFrom = 0x90000000
	s7plusPackedHighTo   = 0x9fffffff

	// Blob: root ID > 1 announces 8 unknown octets and a blob type.
	s7plusBlobExtRoot  = 1
	s7plusBlobUnknown  = 8
	s7plusBlobTypeList = 0x00
	s7plusBlobTypeRaw2 = 0x02
	s7plusBlobTypeRaw3 = 0x03

	// Variable type list entry: offset info type in bits 12-15 of the
	// attribute flags; offset words are little-endian.
	s7plusOffsetTypeShift = 12
	s7plusVarTypeHead     = 4 + 4 + 1 + 2 + 1
	s7plusLegacyOffLen    = 4
	s7plusNewOffLen       = 8
	s7plusFBInfoLen       = 7 * 4
	s7plusArrayDimLen     = 8
	s7plusFBArrayLen      = 4 * 4
	s7plusMDimLen         = 2 * 6 * 4
	s7plusStructSizeLen   = 8
	s7plusStructInfoLen   = 5 * 4
	s7plusVarTypeListHead = 4

	// Tag description offset info type bits.
	s7plusTagAccessBits = 0x0C
	s7plusTagKindMask   = 0x03
	s7plusTagSFBInst    = 0x08
)

// Offset info types of a variable type list entry.
const (
	s7plusOffFBArray = iota
	s7plusOffElemStd
	s7plusOffElemString
	s7plusOffElemArray1
	s7plusOffElemArrayM
	s7plusOffElemStruct
	s7plusOffElemStruct1
	s7plusOffElemStructM
	s7plusOffStd
	s7plusOffString
	s7plusOffArray1
	s7plusOffArrayM
	s7plusOffStruct
	s7plusOffStruct1
	s7plusOffStructM
	s7plusOffFBSFB
)

// Tag description offset info kinds (offset info type & 0x03).
const (
	s7plusTagPlain = iota
	s7plusTagBits
	s7plusTagArray1
	s7plusTagArrayM
)

var (
	// ErrS7CommPlusTooDeep is returned when structs, blobs or objects
	// nest deeper than the decoder follows.
	ErrS7CommPlusTooDeep = errors.New("S7comm-plus data nested too deep")
	// ErrS7CommPlusUnknownType is returned for a datatype, blob type or
	// notification item code whose layout is unknown: what follows it
	// cannot be located.
	ErrS7CommPlusUnknownType = errors.New("S7comm-plus unknown value type")
)

// S7CommPlusDatatype is the datatype of an S7comm-plus value.
type S7CommPlusDatatype uint8

// S7comm-plus datatypes.
const (
	S7CommPlusTypeNull      S7CommPlusDatatype = 0x00
	S7CommPlusTypeBool      S7CommPlusDatatype = 0x01
	S7CommPlusTypeUSInt     S7CommPlusDatatype = 0x02
	S7CommPlusTypeUInt      S7CommPlusDatatype = 0x03
	S7CommPlusTypeUDInt     S7CommPlusDatatype = 0x04 // VLQ
	S7CommPlusTypeULInt     S7CommPlusDatatype = 0x05 // VLQ
	S7CommPlusTypeSInt      S7CommPlusDatatype = 0x06
	S7CommPlusTypeInt       S7CommPlusDatatype = 0x07
	S7CommPlusTypeDInt      S7CommPlusDatatype = 0x08 // VLQ
	S7CommPlusTypeLInt      S7CommPlusDatatype = 0x09 // VLQ
	S7CommPlusTypeByte      S7CommPlusDatatype = 0x0A
	S7CommPlusTypeWord      S7CommPlusDatatype = 0x0B
	S7CommPlusTypeDWord     S7CommPlusDatatype = 0x0C
	S7CommPlusTypeLWord     S7CommPlusDatatype = 0x0D
	S7CommPlusTypeReal      S7CommPlusDatatype = 0x0E
	S7CommPlusTypeLReal     S7CommPlusDatatype = 0x0F
	S7CommPlusTypeTimestamp S7CommPlusDatatype = 0x10 // ns since 1970
	S7CommPlusTypeTimespan  S7CommPlusDatatype = 0x11 // ns, VLQ
	S7CommPlusTypeRID       S7CommPlusDatatype = 0x12
	S7CommPlusTypeAID       S7CommPlusDatatype = 0x13 // VLQ
	S7CommPlusTypeBlob      S7CommPlusDatatype = 0x14
	S7CommPlusTypeWString   S7CommPlusDatatype = 0x15 // UTF-8
	S7CommPlusTypeVariant   S7CommPlusDatatype = 0x16
	S7CommPlusTypeStruct    S7CommPlusDatatype = 0x17
	S7CommPlusTypeS7String  S7CommPlusDatatype = 0x19 // tag descriptions only
)

// String returns the plugin's name of the datatype.
func (d S7CommPlusDatatype) String() string {
	switch d {
	case S7CommPlusTypeNull:
		return "Null"
	case S7CommPlusTypeBool:
		return "Bool"
	case S7CommPlusTypeUSInt:
		return "USInt"
	case S7CommPlusTypeUInt:
		return "UInt"
	case S7CommPlusTypeUDInt:
		return "UDInt"
	case S7CommPlusTypeULInt:
		return "ULInt"
	case S7CommPlusTypeSInt:
		return "SInt"
	case S7CommPlusTypeInt:
		return "Int"
	case S7CommPlusTypeDInt:
		return "DInt"
	case S7CommPlusTypeLInt:
		return "LInt"
	case S7CommPlusTypeByte:
		return "Byte"
	case S7CommPlusTypeWord:
		return "Word"
	case S7CommPlusTypeDWord:
		return "DWord"
	case S7CommPlusTypeLWord:
		return "LWord"
	case S7CommPlusTypeReal:
		return "Real"
	case S7CommPlusTypeLReal:
		return "LReal"
	case S7CommPlusTypeTimestamp:
		return "Timestamp"
	case S7CommPlusTypeTimespan:
		return "Timespan"
	case S7CommPlusTypeRID:
		return "RID"
	case S7CommPlusTypeAID:
		return "AID"
	case S7CommPlusTypeBlob:
		return "Blob"
	case S7CommPlusTypeWString:
		return "WString"
	case S7CommPlusTypeVariant:
		return "Variant"
	case S7CommPlusTypeStruct:
		return "Struct"
	case S7CommPlusTypeS7String:
		return "S7String"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(d))
	}
}

// fixedLen returns the wire size of a fixed-size datatype, or 0.
func (d S7CommPlusDatatype) fixedLen() int {
	switch d {
	case S7CommPlusTypeBool, S7CommPlusTypeUSInt, S7CommPlusTypeSInt, S7CommPlusTypeByte:
		return 1
	case S7CommPlusTypeUInt, S7CommPlusTypeInt, S7CommPlusTypeWord:
		return 2
	case S7CommPlusTypeDWord, S7CommPlusTypeReal, S7CommPlusTypeRID, S7CommPlusTypeStruct:
		return 4
	case S7CommPlusTypeLWord, S7CommPlusTypeLReal, S7CommPlusTypeTimestamp:
		return 8
	}
	return 0
}

// S7CommPlusTypeFlags is the datatype flags octet before a datatype.
type S7CommPlusTypeFlags uint8

// S7comm-plus datatype flags.
const (
	S7CommPlusFlagArray        S7CommPlusTypeFlags = 0x10
	S7CommPlusFlagAddressArray S7CommPlusTypeFlags = 0x20
	S7CommPlusFlagSparseArray  S7CommPlusTypeFlags = 0x40
)

// S7CommPlusElement is one element of a value; a scalar has one.
//
// Bits holds every numeric type: unsigned integers and BYTE..LWORD as
// they are, signed integers and TIMESPAN sign-extended, REAL and LREAL
// as IEEE 754 bits, TIMESTAMP in ns since 1970, STRUCT and RID as their
// 32-bit ID. Bytes holds WSTRING text and BLOB content and aliases the
// frame.
type S7CommPlusElement struct {
	Type  S7CommPlusDatatype // the value's type; a VARIANT element's own
	Flags S7CommPlusTypeFlags
	Key   uint32 // sparse array key
	Bits  uint64
	Bytes []byte
	Blob  *S7CommPlusBlob // BLOB with root ID > 1
}

// Uint returns Bits, the unsigned view of the element.
func (e *S7CommPlusElement) Uint() uint64 { return e.Bits }

// Int returns the signed view of the element: Bits as two's complement
// for SINT, INT, DINT, LINT and TIMESPAN.
func (e *S7CommPlusElement) Int() int64 { return int64(e.Bits) }

// Float returns the value of a REAL or LREAL element.
func (e *S7CommPlusElement) Float() float64 {
	if e.Type == S7CommPlusTypeReal {
		return float64(math.Float32frombits(uint32(e.Bits)))
	}
	return math.Float64frombits(e.Bits)
}

// Time returns a TIMESTAMP element as a UTC time.
func (e *S7CommPlusElement) Time() time.Time {
	return time.Unix(0, int64(e.Bits)).UTC()
}

// Duration returns a TIMESPAN element.
func (e *S7CommPlusElement) Duration() time.Duration {
	return time.Duration(int64(e.Bits))
}

// S7CommPlusBlob is the extended BLOB form, announced by a root ID
// above 1: 8 unknown octets, a blob type, then raw octets (types 2 and
// 3, in the element's Bytes) or an ID/value list (type 0).
type S7CommPlusBlob struct {
	RootID  uint32
	Unknown []byte
	Type    uint8
	Values  []S7CommPlusIDValue
}

// S7CommPlusPacked is a packed STRUCT (struct IDs 0x02000001-0x02FFFFFE
// and 0x90000001-0x9FFFFFFE, DTL for example): its members are raw
// octets, not an ID/value list.
type S7CommPlusPacked struct {
	InterfaceTimestamp uint64 // ns since 1970
	TransportFlags     uint32
	ElementCount       uint32 // octets in Data
	Data               []byte
}

// S7CommPlusValue is a typed value. Members holds the ID/value list of
// a STRUCT where the enclosing list carries one; StructArray holds an
// address array of structs, one member list per element.
type S7CommPlusValue struct {
	Flags       S7CommPlusTypeFlags
	Type        S7CommPlusDatatype
	Elements    []S7CommPlusElement
	Members     []S7CommPlusIDValue
	StructArray [][]S7CommPlusIDValue
	Packed      *S7CommPlusPacked
}

// S7CommPlusIDValue is an ID (or item number) with its value.
type S7CommPlusIDValue struct {
	ID    uint32
	Value S7CommPlusValue
}

// S7CommPlusRelation is a relation element (0xA4).
type S7CommPlusRelation struct {
	RelationID uint32
	Unknown    uint32
}

// S7CommPlusTagDesc is a tag description (0xA7) of old S7-1200
// firmware. Which offset fields are set depends on OffsetInfoType:
// bit 0x04 or 0x08 adds Access and Section; kind 1 adds the bit
// offsets, kind 2 one array dimension, kind 3 padding and up to N
// dimensions; type 0x08 adds the SFB instance offsets.
type S7CommPlusTagDesc struct {
	OffsetInfoType uint8
	Name           string
	Unknown2       uint8
	Datatype       S7CommPlusDatatype
	SoftDatatype   uint32
	AttributeFlags uint32
	LID            uint32
	Length         uint32 // S7STRING length, struct relation ID or unknown
	Access         uint32
	Section        uint32
	OffsetType1    uint32
	OffsetType2    uint32
	BitOffset1     uint32
	BitOffset2     uint32
	Padding1       uint32
	Padding2       uint32
	LowerBounds    []int32
	ElementCounts  []uint32
	SFBInstOffset1 uint32
	SFBInstOffset2 uint32
}

// S7CommPlusVarType is one entry of a variable type list (0xAB).
// OffsetInfo is the rest of the entry, whose layout follows the offset
// info type; its 16 and 32-bit words are little-endian.
type S7CommPlusVarType struct {
	LID            uint32
	SymbolCRC      uint32
	SoftDatatype   uint8
	AttributeFlags uint16
	BitOffsetInfo  uint8
	OffsetInfo     []byte
}

// OffsetInfoType returns bits 12-15 of the attribute flags, which
// select the layout of OffsetInfo.
func (v *S7CommPlusVarType) OffsetInfoType() uint8 {
	return uint8(v.AttributeFlags >> s7plusOffsetTypeShift)
}

// S7CommPlusElements are the elements of an object, or of a top-level
// element list, grouped by kind in wire order within each kind.
type S7CommPlusElements struct {
	Objects    []S7CommPlusObject
	Attributes []S7CommPlusIDValue
	Relations  []S7CommPlusRelation
	TagDescs   []S7CommPlusTagDesc
	VarTypes   []S7CommPlusVarType
	VarNames   []string
}

// S7CommPlusObject is an object (0xA1 ... 0xA2). AttributeIDFlags is
// on the wire only when AttributeID is not 0.
type S7CommPlusObject struct {
	RelationID       uint32
	ClassID          uint32
	ClassFlags       uint32
	AttributeID      uint32
	AttributeIDFlags uint32
	S7CommPlusElements
}

// Object element IDs.
const (
	s7plusElemStartObject = 0xA1
	s7plusElemTermObject  = 0xA2
	s7plusElemAttribute   = 0xA3
	s7plusElemRelation    = 0xA4
	s7plusElemStartTag    = 0xA7
	s7plusElemTermTag     = 0xA8
	s7plusElemVarTypes    = 0xAB
	s7plusElemVarNames    = 0xAC
)

// s7plusReader reads body fields from b. The first error sticks:
// later reads return zero and consume nothing, so callers check err
// after loops rather than after every field.
//
// wide is set for the value of a system event, whose IDs, flags, types
// and integers take their full width instead of a VLQ. dry, hints and
// next belong to the dry runs of s7comm_plus_count.go.
type s7plusReader struct {
	b     []byte
	err   error
	depth int
	wide  bool

	dry     bool
	hints   []s7plusHint
	next    int
	dryRuns int
}

// fail records the first error.
func (r *s7plusReader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
	r.b = nil
}

// need fails unless n octets remain.
func (r *s7plusReader) need(n int, what string) bool {
	if r.err != nil {
		return false
	}
	if n > len(r.b) {
		r.fail(fmt.Errorf("%w: %s needs %d octets, %d left", ErrS7CommPlusMalformed, what, n, len(r.b)))
		return false
	}
	return true
}

// count fails unless n items of at least size octets each fit in what
// remains, so callers may allocate n items. uint64 keeps 32-bit int
// from overflowing.
func (r *s7plusReader) count(n uint32, size int, what string) bool {
	if r.err != nil {
		return false
	}
	if uint64(n)*uint64(size) > uint64(len(r.b)) {
		r.fail(fmt.Errorf("%w: %d %s in %d octets", ErrS7CommPlusMalformed, n, what, len(r.b)))
		return false
	}
	return true
}

func (r *s7plusReader) peek() byte {
	if !r.need(1, "element") {
		return 0
	}
	return r.b[0]
}

func (r *s7plusReader) bytes(n int, what string) []byte {
	if !r.need(n, what) {
		return nil
	}
	v := r.b[:n:n]
	r.b = r.b[n:]
	return v
}

func (r *s7plusReader) u8() uint8 {
	if !r.need(1, "octet") {
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *s7plusReader) u16() uint16 {
	if !r.need(2, "uint16") {
		return 0
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *s7plusReader) u32() uint32 {
	if !r.need(4, "uint32") {
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *s7plusReader) u64() uint64 {
	if !r.need(8, "uint64") {
		return 0
	}
	v := binary.BigEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

// vlq reads one VLQ with read (one of the S7CommPlusVar* readers).
func s7plusVLQ[T any](r *s7plusReader, read func([]byte) (T, int, error)) T {
	var zero T
	if r.err != nil {
		return zero
	}

	v, n, err := read(r.b)
	if err != nil {
		r.fail(fmt.Errorf("%w: %v", ErrS7CommPlusMalformed, err))
		return zero
	}
	r.b = r.b[n:]
	return v
}

func (r *s7plusReader) vu32() uint32 { return s7plusVLQ(r, S7CommPlusVarUint32) }
func (r *s7plusReader) vi32() int32  { return s7plusVLQ(r, S7CommPlusVarInt32) }
func (r *s7plusReader) vu64() uint64 { return s7plusVLQ(r, S7CommPlusVarUint64) }
func (r *s7plusReader) vi64() int64  { return s7plusVLQ(r, S7CommPlusVarInt64) }

// wu32 reads a VLQ, or 4 octets when wide; wi32, wu64 and wi64 do the
// same for the other integers the plugin reads "without VLQ".
func (r *s7plusReader) wu32() uint32 {
	if r.wide {
		return r.u32()
	}
	return r.vu32()
}

func (r *s7plusReader) wi32() int32 {
	if r.wide {
		return int32(r.u32())
	}
	return r.vi32()
}

func (r *s7plusReader) wu64() uint64 {
	if r.wide {
		return r.u64()
	}
	return r.vu64()
}

func (r *s7plusReader) wi64() int64 {
	if r.wide {
		return int64(r.u64())
	}
	return r.vi64()
}

// s7plusAppend appends v, doubling the capacity when full. The lists
// it grows end at a terminator, not a count. Most get their capacity
// from a dry run first; this covers the rest, where append would grow
// a large slice by a quarter at a time.
func s7plusAppend[T any](s []T, v T) []T {
	if len(s) < cap(s) {
		return append(s, v)
	}

	grown := make([]T, len(s), 2*len(s)+s7plusMinCap)
	copy(grown, s)
	return append(grown, v)
}

// enter steps one nesting level down; leave steps back.
func (r *s7plusReader) enter() bool {
	if r.err != nil {
		return false
	}
	if r.depth >= s7plusMaxDepth {
		r.fail(fmt.Errorf("%w: limit %d", ErrS7CommPlusTooDeep, s7plusMaxDepth))
		return false
	}
	r.depth++
	return true
}

func (r *s7plusReader) leave() { r.depth-- }

// structLevel is the struct nesting a value leaves its list in, as the
// plugin counts it: > 0 means an ID/value list of members follows; < 0
// (address array of structs) means the enclosing ID/value list ends
// here without a terminator.
type structLevel int

// s7plusStructID is the ID of the last STRUCT element read for a
// value: it decides whether a packed struct follows.
type s7plusStructID struct {
	id   uint64
	seen bool
}

// value reads one value: flags, datatype, then one element, a counted
// array or a sparse array ended by key 0.
func (r *s7plusReader) value() (S7CommPlusValue, structLevel) {
	v := r.valueHead()
	if r.err != nil {
		return v, 0
	}

	isStruct := v.Type == S7CommPlusTypeStruct
	sparse := v.Flags&S7CommPlusFlagSparseArray != 0
	counted := !isStruct && v.Flags&(S7CommPlusFlagArray|S7CommPlusFlagAddressArray) != 0

	var level structLevel
	var last s7plusStructID
	switch {
	case sparse:
		level, last = r.sparseElems(&v)
	case counted:
		level = r.arrayElems(&v)
	default:
		e, l := r.element(v.Type)
		level, last = l, s7plusStructID{id: e.Bits, seen: true}
		if !r.dry {
			v.Elements = []S7CommPlusElement{e}
		}
	}
	if r.err != nil {
		return v, 0
	}

	// An address array of structs: element count, then one member list
	// per element; the enclosing list ends after it.
	if isStruct && !sparse && v.Flags&S7CommPlusFlagAddressArray != 0 {
		level = r.structArray(&v)
	}

	if isStruct && last.seen && s7plusPacked(last.id) {
		v.Packed = r.packed()
		level--
	}
	return v, level
}

// valueHead reads the flags and datatype of a value: an octet each,
// or two octets each when wide, of which the low one counts.
func (r *s7plusReader) valueHead() S7CommPlusValue {
	if !r.wide {
		return S7CommPlusValue{Flags: S7CommPlusTypeFlags(r.u8()), Type: S7CommPlusDatatype(r.u8())}
	}
	return S7CommPlusValue{Flags: S7CommPlusTypeFlags(r.u16()), Type: S7CommPlusDatatype(r.u16())}
}

// arrayElems reads the element count and elements of an array.
func (r *s7plusReader) arrayElems(v *S7CommPlusValue) structLevel {
	n := r.wu32()
	if !r.count(n, 1, "array elements") {
		return 0
	}
	if !r.dry {
		v.Elements = make([]S7CommPlusElement, 0, n)
	}

	var level structLevel
	for i := uint32(0); i < n && r.err == nil; i++ {
		e, l := r.element(v.Type)
		level += l
		if !r.dry {
			v.Elements = append(v.Elements, e)
		}
	}
	return level
}

// s7plusPacked reports whether a struct ID marks a packed struct.
func s7plusPacked(id uint64) bool {
	return (id > s7plusPackedHighFrom && id < s7plusPackedHighTo) ||
		(id > s7plusPackedLowFrom && id < s7plusPackedLowTo)
}

// sparseElems reads key/element pairs until key 0. Every pair takes at
// least one octet, so the loop is bounded by the data. A dry run
// counts the pairs first.
func (r *s7plusReader) sparseElems(v *S7CommPlusValue) (structLevel, s7plusStructID) {
	if !r.dry {
		if h := r.ahead(func() { r.sparseElems(v) }); h.n > 0 {
			v.Elements = make([]S7CommPlusElement, 0, h.n)
		}
	}

	var level structLevel
	var last s7plusStructID
	left, slot := len(r.b), s7plusNoSlot
	for r.err == nil {
		key := r.wu32()
		if key == 0 || r.err != nil {
			break
		}

		// The slot is taken before the element, whose own lists follow it.
		if r.dry {
			slot = r.note(slot, left)
		}
		e, l := r.sparseElem(v.Type)
		e.Key = key
		level += l
		last = s7plusStructID{id: e.Bits, seen: true}

		if r.dry {
			r.hints[slot].n++
			continue
		}
		v.Elements = append(v.Elements, e)
	}
	return level, last
}

// sparseElem reads a sparse array element. A sparse VARIANT element has
// no flags and type of its own; the plugin then reads it as the
// VARIANT datatype itself (one VLQ).
func (r *s7plusReader) sparseElem(t S7CommPlusDatatype) (S7CommPlusElement, structLevel) {
	e := S7CommPlusElement{Type: t}
	l := r.scalar(&e)
	return e, l
}

// element reads one element of type t. VARIANT elements carry their
// own flags and type octets.
func (r *s7plusReader) element(t S7CommPlusDatatype) (S7CommPlusElement, structLevel) {
	e := S7CommPlusElement{Type: t}
	if t == S7CommPlusTypeVariant {
		e.Flags = S7CommPlusTypeFlags(r.u8())
		e.Type = S7CommPlusDatatype(r.u8())
	}
	l := r.scalar(&e)
	return e, l
}

// scalar reads the octets of one element of type e.Type and returns 1
// for a STRUCT (a struct level entered), else 0.
func (r *s7plusReader) scalar(e *S7CommPlusElement) structLevel {
	if r.err != nil {
		return 0
	}

	if n := e.Type.fixedLen(); n > 0 {
		b := r.bytes(n, e.Type.String())
		e.Bits = s7plusFixed(e.Type, b)
		if e.Type == S7CommPlusTypeStruct {
			return 1
		}
		return 0
	}

	switch e.Type {
	case S7CommPlusTypeNull:
	case S7CommPlusTypeUDInt:
		e.Bits = uint64(r.wu32())
	case S7CommPlusTypeAID, S7CommPlusTypeVariant:
		e.Bits = uint64(r.vu32())
	case S7CommPlusTypeULInt:
		e.Bits = r.wu64()
	case S7CommPlusTypeDInt:
		e.Bits = uint64(int64(r.wi32()))
	case S7CommPlusTypeLInt:
		e.Bits = uint64(r.wi64())
	case S7CommPlusTypeTimespan:
		e.Bits = uint64(r.vi64())
	case S7CommPlusTypeWString:
		n := r.vu32()
		if r.count(n, 1, "string octets") {
			e.Bytes = r.bytes(int(n), "WString")
		}
	case S7CommPlusTypeBlob:
		r.blob(e)
	default:
		r.fail(fmt.Errorf("%w: datatype 0x%02X", ErrS7CommPlusUnknownType, uint8(e.Type)))
	}
	return 0
}

// s7plusFixed converts the big-endian octets of a fixed-size type to
// Bits, sign-extending the signed ones.
func s7plusFixed(t S7CommPlusDatatype, b []byte) uint64 {
	var u uint64
	for _, c := range b {
		u = u<<8 | uint64(c)
	}

	switch t {
	case S7CommPlusTypeSInt:
		return uint64(int64(int8(u)))
	case S7CommPlusTypeInt:
		return uint64(int64(int16(u)))
	}
	return u
}

// blob reads a BLOB: root ID, then either size and octets, or (root ID
// above 1) 8 unknown octets, a blob type and raw octets or a value list.
func (r *s7plusReader) blob(e *S7CommPlusElement) {
	root := r.vu32()
	if root <= s7plusBlobExtRoot {
		e.Bytes = r.sized("blob octets")
		return
	}

	bl := S7CommPlusBlob{RootID: root, Unknown: r.bytes(s7plusBlobUnknown, "blob head"), Type: r.u8()}
	if r.err == nil {
		r.blobBody(e, &bl)
	}
	if r.dry {
		return
	}

	kept := bl
	e.Blob = &kept
}

// blobBody reads what follows the type of a BLOB with a root ID.
func (r *s7plusReader) blobBody(e *S7CommPlusElement, bl *S7CommPlusBlob) {
	switch bl.Type {
	case s7plusBlobTypeList:
		if r.enter() {
			bl.Values = r.idList()
			r.leave()
		}
	case s7plusBlobTypeRaw2, s7plusBlobTypeRaw3:
		e.Bytes = r.sized("blob octets")
	default:
		r.fail(fmt.Errorf("%w: blob type 0x%02X", ErrS7CommPlusUnknownType, bl.Type))
	}
}

// sized reads a VLQ length and that many octets.
func (r *s7plusReader) sized(what string) []byte {
	n := r.vu32()
	if !r.count(n, 1, what) {
		return nil
	}
	return r.bytes(int(n), what)
}

// structArray reads the element count and member lists of an address
// array of structs.
func (r *s7plusReader) structArray(v *S7CommPlusValue) structLevel {
	n := r.vu32()
	if !r.count(n, 1, "struct array elements") || !r.enter() {
		return 0
	}
	defer r.leave()

	if !r.dry {
		v.StructArray = make([][]S7CommPlusIDValue, 0, n)
	}
	for i := uint32(0); i < n && r.err == nil; i++ {
		members := r.idList()
		if !r.dry {
			v.StructArray = append(v.StructArray, members)
		}
	}
	return -1
}

// packed reads a packed struct after its struct ID.
func (r *s7plusReader) packed() *S7CommPlusPacked {
	p := S7CommPlusPacked{InterfaceTimestamp: r.u64(), TransportFlags: r.vu32(), ElementCount: r.vu32()}
	if p.TransportFlags&s7plusPackedCount2 != 0 {
		p.ElementCount = r.vu32()
	}
	if r.count(p.ElementCount, 1, "packed struct octets") {
		p.Data = r.bytes(int(p.ElementCount), "packed struct")
	}
	if r.dry {
		return nil
	}

	kept := p
	return &kept
}

// s7plusListKind tells how an ID/value list ends.
type s7plusListKind uint8

const (
	// s7plusIDList ends at ID 0 or after a value that ends the list (an
	// address array of structs).
	s7plusIDList s7plusListKind = iota
	// s7plusItemList ends at item number 0 only, as the plugin reads
	// multi-variable values.
	s7plusItemList
)

// idList reads ID/value pairs until ID 0, or until a value that ends
// the list (address array of structs). Struct members nest as their
// own ID/value lists.
func (r *s7plusReader) idList() []S7CommPlusIDValue { return r.list(s7plusIDList) }

// itemList reads item number/value pairs until item number 0, as the
// plugin does for multi-variable values: struct members use IDs, and
// an address array of structs does not end the list.
func (r *s7plusReader) itemList() []S7CommPlusIDValue { return r.list(s7plusItemList) }

// list reads an ID/value list. Its length comes from a dry run, so the
// list is allocated once.
func (r *s7plusReader) list(kind s7plusListKind) []S7CommPlusIDValue {
	var out []S7CommPlusIDValue
	if !r.dry {
		if h := r.ahead(func() { r.list(kind) }); h.n > 0 {
			out = make([]S7CommPlusIDValue, 0, h.n)
		}
	}

	left, slot := len(r.b), s7plusNoSlot
	for r.err == nil {
		id := r.wu32()
		if id == s7plusTermID || r.err != nil {
			break
		}

		// The slot is taken before the value, whose own lists follow it.
		if r.dry {
			slot = r.note(slot, left)
		}
		it := r.item(id)

		if r.dry {
			r.hints[slot].n++
		} else {
			out = s7plusAppend(out, it.S7CommPlusIDValue)
		}
		if kind == s7plusIDList && it.level < 0 {
			break
		}
	}
	return out
}

// s7plusItem is an ID/value pair with the struct level its value left.
type s7plusItem struct {
	S7CommPlusIDValue
	level structLevel
}

// item reads the value and struct members that follow an ID.
func (r *s7plusReader) item(id uint32) s7plusItem {
	it := s7plusItem{S7CommPlusIDValue: S7CommPlusIDValue{ID: id}}
	it.Value, it.level = r.value()
	r.members(&it.Value, it.level)
	return it
}

// members reads the member list of a struct value when level says one
// follows.
func (r *s7plusReader) members(v *S7CommPlusValue, level structLevel) {
	if level <= 0 || !r.enter() {
		return
	}
	v.Members = r.idList()
	r.leave()
}

// elements reads object elements until a terminating object (0xA2,
// consumed) or an octet that starts no element (left unread). A dry
// run counts the objects and attributes first.
func (r *s7plusReader) elements(es *S7CommPlusElements) {
	if !r.dry {
		h := r.ahead(func() { r.elements(es) })
		if h.n > 0 {
			es.Objects = make([]S7CommPlusObject, 0, h.n)
		}
		if h.m > 0 {
			es.Attributes = make([]S7CommPlusIDValue, 0, h.m)
		}
	}

	left, slot := len(r.b), s7plusNoSlot
	for r.err == nil {
		kind := r.peek()
		switch kind {
		case s7plusElemStartObject, s7plusElemAttribute:
			r.u8()
			if r.dry {
				slot = r.note(slot, left)
			}
			r.counted(es, kind, slot)
		case s7plusElemTermObject:
			r.u8()
			return
		case s7plusElemTermTag:
			r.u8()
		case s7plusElemRelation, s7plusElemStartTag, s7plusElemVarNames, s7plusElemVarTypes:
			r.u8()
			r.describe(es, kind)
		default:
			return
		}
	}
}

// counted reads an object or an attribute after its start octet. A
// dry run counts it in the hint at slot instead of keeping it.
func (r *s7plusReader) counted(es *S7CommPlusElements, kind byte, slot int) {
	if kind == s7plusElemStartObject {
		o := r.object()
		if r.dry {
			r.hints[slot].n++
			return
		}
		es.Objects = s7plusAppend(es.Objects, o)
		return
	}

	a := r.attribute()
	if r.dry {
		r.hints[slot].m++
		return
	}
	es.Attributes = s7plusAppend(es.Attributes, a)
}

// describe reads a relation, tag description or variable list after
// its start octet. A dry run reads it and keeps nothing.
func (r *s7plusReader) describe(es *S7CommPlusElements, kind byte) {
	if r.dry {
		es = &S7CommPlusElements{}
	}

	switch kind {
	case s7plusElemRelation:
		es.Relations = append(es.Relations, S7CommPlusRelation{RelationID: r.vu32(), Unknown: r.u32()})
	case s7plusElemStartTag:
		es.TagDescs = append(es.TagDescs, r.tagDesc())
	case s7plusElemVarNames:
		es.VarNames = append(es.VarNames, r.varNames()...)
	case s7plusElemVarTypes:
		es.VarTypes = append(es.VarTypes, r.varTypes()...)
	}
}

// object reads an object after its 0xA1, including its elements.
func (r *s7plusReader) object() S7CommPlusObject {
	o := S7CommPlusObject{RelationID: r.u32(), ClassID: r.vu32(), ClassFlags: r.vu32(), AttributeID: r.vu32()}
	if o.AttributeID != 0 {
		o.AttributeIDFlags = r.vu32()
	}
	if r.enter() {
		r.elements(&o.S7CommPlusElements)
		r.leave()
	}
	return o
}

// attribute reads one ID/value of an attribute element; ID 0 alone is
// an empty attribute.
func (r *s7plusReader) attribute() S7CommPlusIDValue {
	id := r.vu32()
	if id == s7plusTermID || r.err != nil {
		return S7CommPlusIDValue{}
	}
	return r.item(id).S7CommPlusIDValue
}

// tagDesc reads a tag description after its 0xA7.
func (r *s7plusReader) tagDesc() S7CommPlusTagDesc {
	t := S7CommPlusTagDesc{OffsetInfoType: r.u8()}
	t.Name = string(r.sized("tag name"))
	t.Unknown2 = r.u8()
	t.Datatype = S7CommPlusDatatype(r.u8())
	t.SoftDatatype = r.vu32()
	t.AttributeFlags = r.u32()
	t.LID = r.vu32()
	t.Length = r.vu32()

	if t.OffsetInfoType&s7plusTagAccessBits != 0 {
		t.Access = r.vu32()
		t.Section = r.vu32()
	}
	t.OffsetType1 = r.vu32()
	t.OffsetType2 = r.vu32()

	switch t.OffsetInfoType & s7plusTagKindMask {
	case s7plusTagBits:
		t.BitOffset1 = r.vu32()
		t.BitOffset2 = r.vu32()
	case s7plusTagArray1:
		t.LowerBounds = []int32{r.vi32()}
		t.ElementCounts = []uint32{r.vu32()}
		t.Padding1 = r.vu32()
		t.Padding2 = r.vu32()
	case s7plusTagArrayM:
		t.Padding1 = r.vu32()
		t.Padding2 = r.vu32()
		r.tagDims(&t)
	}

	if t.OffsetInfoType == s7plusTagSFBInst {
		t.SFBInstOffset1 = r.vu32()
		t.SFBInstOffset2 = r.vu32()
	}
	return t
}

// tagDims reads the dimension count and lower bound/count pairs of a
// multi-dimensional array tag.
func (r *s7plusReader) tagDims(t *S7CommPlusTagDesc) {
	const pairMin = 2
	n := r.vu32()
	if !r.count(n, pairMin, "array dimensions") {
		return
	}

	t.LowerBounds = make([]int32, 0, n)
	t.ElementCounts = make([]uint32, 0, n)
	for i := uint32(0); i < n && r.err == nil; i++ {
		t.LowerBounds = append(t.LowerBounds, r.vi32())
		t.ElementCounts = append(t.ElementCounts, r.vu32())
	}
}

// varNames reads a name list: blocks of {length, name, unknown octet}
// entries, each block prefixed by its length, until a block length 0.
// As in the plugin, a block runs until its length is used up, and has
// at least one entry.
func (r *s7plusReader) varNames() []string {
	var out []string
	blockLen := r.u16()
	for blockLen > 0 && r.err == nil {
		end := len(r.b) - int(blockLen)
		for r.err == nil {
			n := int(r.u8())
			out = append(out, string(r.bytes(n, "variable name")))
			r.u8()
			if len(r.b) <= end {
				break
			}
		}
		blockLen = r.u16()
	}
	return out
}

// varTypes reads a type list: blocks like varNames, the first with 4
// unknown octets counted in its length.
func (r *s7plusReader) varTypes() []S7CommPlusVarType {
	var out []S7CommPlusVarType
	blockLen := r.u16()
	end := len(r.b) - int(blockLen)
	r.bytes(s7plusVarTypeListHead, "type list head")

	for blockLen > 0 && r.err == nil {
		for r.err == nil {
			out = append(out, r.varType())
			if len(r.b) <= end {
				break
			}
		}
		blockLen = r.u16()
		end = len(r.b) - int(blockLen)
	}
	return out
}

// varType reads one type list entry.
func (r *s7plusReader) varType() S7CommPlusVarType {
	head := r.bytes(s7plusVarTypeHead, "type list entry")
	if r.err != nil {
		return S7CommPlusVarType{}
	}

	v := S7CommPlusVarType{
		LID:            binary.LittleEndian.Uint32(head[0:4]),
		SymbolCRC:      binary.LittleEndian.Uint32(head[4:8]),
		SoftDatatype:   head[8],
		AttributeFlags: binary.BigEndian.Uint16(head[9:11]),
		BitOffsetInfo:  head[11],
	}
	v.OffsetInfo = r.bytes(s7plusOffsetLen(v.OffsetInfoType()), "type list offsets")
	return v
}

// s7plusOffsetLen returns the size of the offset part of a type list
// entry, summing the sections the plugin reads for its offset info
// type: legacy offsets, new offsets, FB data, array dimensions,
// multi-dimensional bounds, struct sizes and struct info.
func s7plusOffsetLen(t uint8) int {
	n := s7plusLegacyOffLen
	if t != s7plusOffElemStd && t != s7plusOffStd {
		n += s7plusNewOffLen
	}

	switch t {
	case s7plusOffFBArray, s7plusOffFBSFB:
		n += s7plusFBInfoLen
	}

	switch t {
	case s7plusOffArray1, s7plusOffElemArray1, s7plusOffStruct1, s7plusOffElemStruct1,
		s7plusOffArrayM, s7plusOffElemArrayM, s7plusOffStructM, s7plusOffElemStructM:
		n += s7plusArrayDimLen
	case s7plusOffFBArray:
		n += s7plusFBArrayLen
	}

	switch t {
	case s7plusOffArrayM, s7plusOffElemArrayM, s7plusOffStructM, s7plusOffElemStructM, s7plusOffFBArray:
		n += s7plusMDimLen
	}

	switch t {
	case s7plusOffStruct1, s7plusOffElemStruct1, s7plusOffStructM, s7plusOffElemStructM:
		n += s7plusStructSizeLen + s7plusStructInfoLen
	case s7plusOffStruct, s7plusOffElemStruct:
		n += s7plusStructInfoLen
	}
	return n
}
