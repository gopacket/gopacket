// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// BACnet tagged encoding (ASHRAE 135 Clause 20.2): the generic tag decoder
// that service parameters are read with.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf16"
)

// Tag octet layout (Clause 20.2.1).
const (
	bacnetTagNumberShift     = 4
	bacnetTagClassBit        = 0x08
	bacnetTagLVTMask         = 0x07
	bacnetTagNumberExtended  = 0x0F // tag number in the next octet
	bacnetTagNumberReserved  = 0xFF
	bacnetLVTExtended        = 5 // length in the next octet(s)
	bacnetLVTOpening         = 6
	bacnetLVTClosing         = 7
	bacnetLength16           = 254 // length in the next 2 octets
	bacnetLength32           = 255 // length in the next 4 octets
	bacnetMaxTagDepth        = 32  // opening tags nested deeper are refused
	bacnetMaxUnsignedLen     = 8
	bacnetRealLen            = 4
	bacnetDoubleLen          = 8
	bacnetDateTimeLen        = 4
	bacnetObjectIDLen        = 4
	bacnetObjectTypeShift    = 22
	bacnetObjectInstanceMask = 1<<bacnetObjectTypeShift - 1
	bacnetDateYearBase       = 1900
	bacnetUCS2Len            = 2
	bacnetUCS4Len            = 4
	bacnetUint32Len          = 4
)

// BACnetUnspecified marks an unspecified ("any") Date or Time field.
const BACnetUnspecified uint8 = 0xFF

// ErrBACnetTag is returned for a tag stream that breaks Clause 20.2: a bad
// length, unbalanced opening and closing tags, or nesting past the limit.
var ErrBACnetTag = errors.New("BACnet tag encoding malformed")

// errBACnetTagType is returned by a tag accessor used on the wrong kind of tag.
var errBACnetTagType = errors.New("BACnet tag does not hold that type")

// BACnetTagClass tells application tags from context specific ones.
type BACnetTagClass uint8

// BACnetTagClass values.
const (
	BACnetTagClassApplication BACnetTagClass = 0
	BACnetTagClassContext     BACnetTagClass = 1
)

// String returns the class name.
func (c BACnetTagClass) String() string {
	if c == BACnetTagClassContext {
		return "Context"
	}
	return "Application"
}

// BACnetTagKind tells primitive tags from the opening and closing tags
// that bracket constructed data.
type BACnetTagKind uint8

// BACnetTagKind values.
const (
	BACnetTagPrimitive BACnetTagKind = 0
	BACnetTagOpening   BACnetTagKind = 1
	BACnetTagClosing   BACnetTagKind = 2
)

// String returns the kind name.
func (k BACnetTagKind) String() string {
	switch k {
	case BACnetTagOpening:
		return "Opening"
	case BACnetTagClosing:
		return "Closing"
	}
	return "Primitive"
}

// BACnetApplicationTag is the data type of an application tag (Clause 20.2.1.4).
type BACnetApplicationTag uint8

// BACnetApplicationTag values.
const (
	BACnetAppTagNull             BACnetApplicationTag = 0
	BACnetAppTagBoolean          BACnetApplicationTag = 1
	BACnetAppTagUnsigned         BACnetApplicationTag = 2
	BACnetAppTagSigned           BACnetApplicationTag = 3
	BACnetAppTagReal             BACnetApplicationTag = 4
	BACnetAppTagDouble           BACnetApplicationTag = 5
	BACnetAppTagOctetString      BACnetApplicationTag = 6
	BACnetAppTagCharacterString  BACnetApplicationTag = 7
	BACnetAppTagBitString        BACnetApplicationTag = 8
	BACnetAppTagEnumerated       BACnetApplicationTag = 9
	BACnetAppTagDate             BACnetApplicationTag = 10
	BACnetAppTagTime             BACnetApplicationTag = 11
	BACnetAppTagObjectIdentifier BACnetApplicationTag = 12
)

var bacnetAppTagNames = map[BACnetApplicationTag]string{
	BACnetAppTagNull:             "Null",
	BACnetAppTagBoolean:          "Boolean",
	BACnetAppTagUnsigned:         "Unsigned",
	BACnetAppTagSigned:           "Signed",
	BACnetAppTagReal:             "Real",
	BACnetAppTagDouble:           "Double",
	BACnetAppTagOctetString:      "OctetString",
	BACnetAppTagCharacterString:  "CharacterString",
	BACnetAppTagBitString:        "BitString",
	BACnetAppTagEnumerated:       "Enumerated",
	BACnetAppTagDate:             "Date",
	BACnetAppTagTime:             "Time",
	BACnetAppTagObjectIdentifier: "ObjectIdentifier",
}

// String returns the data type name.
func (t BACnetApplicationTag) String() string { return bacnetName(bacnetAppTagNames, t) }

// BACnetCharacterSet is the character set octet of a CharacterString
// (Clause 20.2.9).
type BACnetCharacterSet uint8

// BACnetCharacterSet values.
const (
	BACnetCharsetUTF8      BACnetCharacterSet = 0
	BACnetCharsetDBCS      BACnetCharacterSet = 1
	BACnetCharsetJISX0208  BACnetCharacterSet = 2
	BACnetCharsetUCS4      BACnetCharacterSet = 3
	BACnetCharsetUCS2      BACnetCharacterSet = 4
	BACnetCharsetISO8859_1 BACnetCharacterSet = 5
)

// BACnetTag is one tag of a service parameter stream. Tags come in a flat
// list in wire order; Depth counts the opening tags around a tag, so the
// opening and closing tags of a constructed value sit at the depth of its
// container and its contents one deeper.
type BACnetTag struct {
	Class BACnetTagClass
	Kind  BACnetTagKind
	// Number is the context tag number, or the BACnetApplicationTag of an
	// application tag.
	Number uint8
	Depth  uint8
	// Length is the content length, or for an application Boolean, which
	// has no content, the value itself.
	Length uint32
	Data   []byte
}

// IsContext reports whether t is a primitive context tag numbered n.
func (t *BACnetTag) IsContext(n uint8) bool {
	return t.Class == BACnetTagClassContext && t.Kind == BACnetTagPrimitive && t.Number == n
}

// IsApplication reports whether t is an application tag of type a.
func (t *BACnetTag) IsApplication(a BACnetApplicationTag) bool {
	return t.Class == BACnetTagClassApplication && t.Number == uint8(a)
}

// Boolean returns the value of an application or context Boolean.
func (t *BACnetTag) Boolean() (bool, error) {
	if t.Class == BACnetTagClassApplication {
		if t.Number != uint8(BACnetAppTagBoolean) {
			return false, errBACnetTagType
		}
		return t.Length != 0, nil
	}
	if len(t.Data) != 1 {
		return false, errBACnetTagType
	}
	return t.Data[0] != 0, nil
}

// Unsigned returns the value of an Unsigned or Enumerated, up to 64 bits.
func (t *BACnetTag) Unsigned() (uint64, error) {
	if !t.holds(BACnetAppTagUnsigned) && !t.holds(BACnetAppTagEnumerated) {
		return 0, errBACnetTagType
	}
	if len(t.Data) == 0 || len(t.Data) > bacnetMaxUnsignedLen {
		return 0, errBACnetTagType
	}
	var v uint64
	for _, b := range t.Data {
		v = v<<8 | uint64(b)
	}
	return v, nil
}

// Signed returns the value of a two's complement Signed, up to 64 bits.
func (t *BACnetTag) Signed() (int64, error) {
	if !t.holds(BACnetAppTagSigned) || len(t.Data) == 0 || len(t.Data) > bacnetMaxUnsignedLen {
		return 0, errBACnetTagType
	}

	// Sign-extend from the top bit of the first octet.
	v := int64(int8(t.Data[0]))
	for _, b := range t.Data[1:] {
		v = v<<8 | int64(b)
	}
	return v, nil
}

// Real returns the value of a single precision Real.
func (t *BACnetTag) Real() (float32, error) {
	if !t.holds(BACnetAppTagReal) || len(t.Data) != bacnetRealLen {
		return 0, errBACnetTagType
	}
	return math.Float32frombits(binary.BigEndian.Uint32(t.Data)), nil
}

// Double returns the value of a double precision Double.
func (t *BACnetTag) Double() (float64, error) {
	if !t.holds(BACnetAppTagDouble) || len(t.Data) != bacnetDoubleLen {
		return 0, errBACnetTagType
	}
	return math.Float64frombits(binary.BigEndian.Uint64(t.Data)), nil
}

// CharacterString returns the character set and text of a CharacterString.
// UTF-8, ISO 8859-1, UCS-2 and UCS-4 are converted to UTF-8; the double
// byte sets are returned as raw bytes.
//
// The text is every character after the character set octet (Clause
// 20.2.9), which knows no terminator: a NUL or a line feed that a device
// sends at the end of a name is part of the string and stays in it. The
// octets as sent are in Data.
func (t *BACnetTag) CharacterString() (BACnetCharacterSet, string, error) {
	if !t.holds(BACnetAppTagCharacterString) || len(t.Data) == 0 {
		return 0, "", errBACnetTagType
	}
	cs := BACnetCharacterSet(t.Data[0])
	s := t.Data[1:]

	switch cs {
	case BACnetCharsetISO8859_1:
		r := make([]rune, len(s))
		for i, b := range s {
			r[i] = rune(b)
		}
		return cs, string(r), nil

	case BACnetCharsetUCS2:
		if len(s)%bacnetUCS2Len != 0 {
			return cs, "", errBACnetTagType
		}
		u := make([]uint16, len(s)/bacnetUCS2Len)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(s[i*bacnetUCS2Len:])
		}
		return cs, string(utf16.Decode(u)), nil

	case BACnetCharsetUCS4:
		if len(s)%bacnetUCS4Len != 0 {
			return cs, "", errBACnetTagType
		}
		r := make([]rune, len(s)/bacnetUCS4Len)
		for i := range r {
			r[i] = rune(binary.BigEndian.Uint32(s[i*bacnetUCS4Len:]))
		}
		return cs, string(r), nil
	}
	return cs, string(s), nil
}

// BACnetBitString is a decoded BitString: the bits, most significant
// first, minus the unused bits of the last octet.
type BACnetBitString struct {
	Unused uint8
	Bytes  []byte
}

// Len returns the number of bits.
func (b BACnetBitString) Len() int {
	n := len(b.Bytes)*8 - int(b.Unused)
	if n < 0 {
		return 0
	}
	return n
}

// Bit returns bit i, counting from the first bit on the wire.
func (b BACnetBitString) Bit(i int) bool {
	if i < 0 || i >= b.Len() {
		return false
	}
	return b.Bytes[i/8]&(0x80>>uint(i%8)) != 0
}

// BitString returns the value of a BitString.
func (t *BACnetTag) BitString() (BACnetBitString, error) {
	const maxUnused = 7
	if !t.holds(BACnetAppTagBitString) || len(t.Data) == 0 || t.Data[0] > maxUnused {
		return BACnetBitString{}, errBACnetTagType
	}
	// An empty bit string cannot have unused bits.
	if len(t.Data) == 1 && t.Data[0] != 0 {
		return BACnetBitString{}, errBACnetTagType
	}
	return BACnetBitString{Unused: t.Data[0], Bytes: t.Data[1:]}, nil
}

// BACnetDate is a Date (Clause 20.2.12). Any field may be BACnetUnspecified;
// Year is then 0xFF too, else the full year.
type BACnetDate struct {
	Year    uint16
	Month   uint8
	Day     uint8
	Weekday uint8
}

// String returns the date as year-month-day, with * for unspecified fields.
func (d BACnetDate) String() string {
	y := "*"
	if d.Year != uint16(BACnetUnspecified) {
		y = fmt.Sprint(d.Year)
	}
	return fmt.Sprintf("%s-%s-%s", y, bacnetField(d.Month), bacnetField(d.Day))
}

// Date returns the value of a Date.
func (t *BACnetTag) Date() (BACnetDate, error) {
	if !t.holds(BACnetAppTagDate) || len(t.Data) != bacnetDateTimeLen {
		return BACnetDate{}, errBACnetTagType
	}
	d := BACnetDate{Year: uint16(t.Data[0]), Month: t.Data[1], Day: t.Data[2], Weekday: t.Data[3]}
	if t.Data[0] != BACnetUnspecified {
		d.Year += bacnetDateYearBase
	}
	return d, nil
}

// BACnetTime is a Time (Clause 20.2.13). Any field may be BACnetUnspecified.
type BACnetTime struct {
	Hour       uint8
	Minute     uint8
	Second     uint8
	Hundredths uint8
}

// String returns the time as hh:mm:ss.hh, with * for unspecified fields.
func (t BACnetTime) String() string {
	return fmt.Sprintf("%s:%s:%s.%s", bacnetField(t.Hour), bacnetField(t.Minute),
		bacnetField(t.Second), bacnetField(t.Hundredths))
}

// Time returns the value of a Time.
func (t *BACnetTag) Time() (BACnetTime, error) {
	if !t.holds(BACnetAppTagTime) || len(t.Data) != bacnetDateTimeLen {
		return BACnetTime{}, errBACnetTagType
	}
	return BACnetTime{Hour: t.Data[0], Minute: t.Data[1], Second: t.Data[2], Hundredths: t.Data[3]}, nil
}

// bacnetField formats a two-digit date or time field.
func bacnetField(v uint8) string {
	if v == BACnetUnspecified {
		return "*"
	}
	return fmt.Sprintf("%02d", v)
}

// BACnetObjectIdentifier names an object: a 10-bit type and a 22-bit
// instance number (Clause 20.2.14).
type BACnetObjectIdentifier struct {
	Type     BACnetObjectType
	Instance uint32
}

// String returns the identifier as type,instance.
func (o BACnetObjectIdentifier) String() string {
	return fmt.Sprintf("%v,%d", o.Type, o.Instance)
}

// ObjectIdentifier returns the value of an ObjectIdentifier.
func (t *BACnetTag) ObjectIdentifier() (BACnetObjectIdentifier, error) {
	if !t.holds(BACnetAppTagObjectIdentifier) || len(t.Data) != bacnetObjectIDLen {
		return BACnetObjectIdentifier{}, errBACnetTagType
	}
	v := binary.BigEndian.Uint32(t.Data)
	return BACnetObjectIdentifier{
		Type:     BACnetObjectType(v >> bacnetObjectTypeShift),
		Instance: v & bacnetObjectInstanceMask,
	}, nil
}

// Value returns the typed value of an application tag: nil for Null, bool,
// uint64 (Unsigned and Enumerated), int64, float32, float64, []byte
// (OctetString), string, BACnetBitString, BACnetDate, BACnetTime or
// BACnetObjectIdentifier. A context tag has no self-described type and
// returns its raw Data.
func (t *BACnetTag) Value() (interface{}, error) {
	if t.Class == BACnetTagClassContext {
		return t.Data, nil
	}

	switch BACnetApplicationTag(t.Number) {
	case BACnetAppTagNull:
		return nil, nil
	case BACnetAppTagBoolean:
		return t.Boolean()
	case BACnetAppTagUnsigned, BACnetAppTagEnumerated:
		return t.Unsigned()
	case BACnetAppTagSigned:
		return t.Signed()
	case BACnetAppTagReal:
		return t.Real()
	case BACnetAppTagDouble:
		return t.Double()
	case BACnetAppTagOctetString:
		return t.Data, nil
	case BACnetAppTagCharacterString:
		_, s, err := t.CharacterString()
		return s, err
	case BACnetAppTagBitString:
		return t.BitString()
	case BACnetAppTagDate:
		return t.Date()
	case BACnetAppTagTime:
		return t.Time()
	case BACnetAppTagObjectIdentifier:
		return t.ObjectIdentifier()
	}
	return t.Data, nil
}

// holds reports whether t may be read as type a: an application tag of
// that type, or any primitive context tag, whose type the service defines.
func (t *BACnetTag) holds(a BACnetApplicationTag) bool {
	if t.Kind != BACnetTagPrimitive {
		return false
	}
	if t.Class == BACnetTagClassContext {
		return true
	}
	return t.Number == uint8(a)
}

// decodeBACnetTags splits a parameter stream into its tags. Opening and
// closing tags must pair up, by number, and nest at most bacnetMaxTagDepth
// deep. Each tag takes at least one octet, so the list never outgrows the
// data it came from.
func decodeBACnetTags(data []byte) ([]BACnetTag, error) {
	count, err := countBACnetTags(data)
	if err != nil {
		return nil, err
	}

	var (
		tags  = make([]BACnetTag, 0, count)
		open  [bacnetMaxTagDepth]uint8
		depth int
	)
	for off := 0; off < len(data); {
		t, n, err := decodeBACnetTag(data[off:])
		if err != nil {
			return nil, err
		}
		off += n

		switch t.Kind {
		case BACnetTagOpening:
			if depth == bacnetMaxTagDepth {
				return nil, ErrBACnetTag
			}
			t.Depth = uint8(depth)
			open[depth] = t.Number
			depth++

		case BACnetTagClosing:
			if depth == 0 || open[depth-1] != t.Number {
				return nil, ErrBACnetTag
			}
			depth--
			t.Depth = uint8(depth)

		default:
			t.Depth = uint8(depth)
		}
		tags = append(tags, t)
	}

	if depth != 0 {
		return nil, ErrBACnetTag
	}
	return tags, nil
}

// countBACnetTags counts the tags of a parameter stream so the list is
// allocated once: grown by append, a stream of one-octet tags costs
// about twice its final size in discarded arrays.
func countBACnetTags(data []byte) (int, error) {
	count := 0
	for off := 0; off < len(data); count++ {
		_, n, err := decodeBACnetTag(data[off:])
		if err != nil {
			return 0, err
		}
		off += n
	}
	return count, nil
}

// decodeBACnetTag decodes the tag at the start of b and returns it with
// the number of octets it spans.
func decodeBACnetTag(b []byte) (BACnetTag, int, error) {
	if len(b) == 0 {
		return BACnetTag{}, 0, ErrBACnetTag
	}
	t := BACnetTag{Number: b[0] >> bacnetTagNumberShift}
	if b[0]&bacnetTagClassBit != 0 {
		t.Class = BACnetTagClassContext
	}
	lvt := uint32(b[0] & bacnetTagLVTMask)
	n := 1

	// Tag numbers past 14 take the next octet.
	if t.Number == bacnetTagNumberExtended {
		if len(b) < n+1 || b[n] == bacnetTagNumberReserved {
			return BACnetTag{}, 0, ErrBACnetTag
		}
		t.Number = b[n]
		n++
	}

	// Opening and closing tags only exist in the context class; an
	// application Boolean holds its value in the LVT field.
	if lvt == bacnetLVTOpening || lvt == bacnetLVTClosing {
		if t.Class != BACnetTagClassContext {
			return BACnetTag{}, 0, ErrBACnetTag
		}
		t.Kind = BACnetTagOpening
		if lvt == bacnetLVTClosing {
			t.Kind = BACnetTagClosing
		}
		return t, n, nil
	}
	if t.Class == BACnetTagClassApplication && t.Number == uint8(BACnetAppTagBoolean) {
		t.Length = lvt
		return t, n, nil
	}

	length, n, err := bacnetTagLength(b, n, lvt)
	if err != nil {
		return BACnetTag{}, 0, err
	}
	if uint64(length) > uint64(len(b)-n) {
		return BACnetTag{}, 0, ErrBACnetTag
	}
	t.Length = length
	t.Data = b[n : n+int(length)]
	return t, n + int(length), nil
}

// bacnetTagLength reads the content length announced by lvt, extended
// over one, three or five octets from n (Clause 20.2.1.3.1).
func bacnetTagLength(b []byte, n int, lvt uint32) (uint32, int, error) {
	if lvt < bacnetLVTExtended {
		return lvt, n, nil
	}
	if len(b) < n+1 {
		return 0, 0, ErrBACnetTag
	}
	ext := b[n]
	n++

	switch ext {
	case bacnetLength16:
		if len(b) < n+bacnetUint16Len {
			return 0, 0, ErrBACnetTag
		}
		return uint32(binary.BigEndian.Uint16(b[n:])), n + bacnetUint16Len, nil
	case bacnetLength32:
		if len(b) < n+bacnetUint32Len {
			return 0, 0, ErrBACnetTag
		}
		return binary.BigEndian.Uint32(b[n:]), n + bacnetUint32Len, nil
	}
	return uint32(ext), n, nil
}
