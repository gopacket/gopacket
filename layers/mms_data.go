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
	"math/big"
	"time"
)

// MMSDataType is the CHOICE tag of an MMS Data value (ISO 9506-2). GOOSE
// allData and MMS read, write and report values all use this type.
type MMSDataType uint8

// MMS Data CHOICE tags. MMSDataReal is the ASN.1 REAL of ISO 9506-2:1990,
// a tag the 2003 edition reserves.
const (
	MMSDataArray           MMSDataType = 1
	MMSDataStructure       MMSDataType = 2
	MMSDataBoolean         MMSDataType = 3
	MMSDataBitString       MMSDataType = 4
	MMSDataInteger         MMSDataType = 5
	MMSDataUnsigned        MMSDataType = 6
	MMSDataFloatingPoint   MMSDataType = 7
	MMSDataReal            MMSDataType = 8
	MMSDataOctetString     MMSDataType = 9
	MMSDataVisibleString   MMSDataType = 10
	MMSDataGeneralizedTime MMSDataType = 11
	MMSDataBinaryTime      MMSDataType = 12
	MMSDataBCD             MMSDataType = 13
	MMSDataBooleanArray    MMSDataType = 14
	MMSDataObjID           MMSDataType = 15
	MMSDataMMSString       MMSDataType = 16
	MMSDataUTCTime         MMSDataType = 17
)

// String returns the ASN.1 name of the Data alternative.
func (t MMSDataType) String() string {
	switch t {
	case MMSDataArray:
		return "array"
	case MMSDataStructure:
		return "structure"
	case MMSDataBoolean:
		return "boolean"
	case MMSDataBitString:
		return "bit-string"
	case MMSDataInteger:
		return "integer"
	case MMSDataUnsigned:
		return "unsigned"
	case MMSDataFloatingPoint:
		return "floating-point"
	case MMSDataReal:
		return "real"
	case MMSDataOctetString:
		return "octet-string"
	case MMSDataVisibleString:
		return "visible-string"
	case MMSDataGeneralizedTime:
		return "generalized-time"
	case MMSDataBinaryTime:
		return "binary-time"
	case MMSDataBCD:
		return "bcd"
	case MMSDataBooleanArray:
		return "booleanArray"
	case MMSDataObjID:
		return "objId"
	case MMSDataMMSString:
		return "mMSString"
	case MMSDataUTCTime:
		return "utc-time"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(t))
	}
}

const (
	// IEC 61850-8-1 floating point: exponent width octet + IEEE 754 value.
	mmsFloatSingleLen = 5
	mmsFloatDoubleLen = 9
	mmsFloatSingleExp = 8
	mmsFloatDoubleExp = 11

	// UtcTime: 4 octets seconds, 3 octets fraction, 1 octet quality.
	mmsUTCTimeLen      = 8
	mmsUTCFractionBits = 24

	// TimeOfDay: 4 octets milliseconds of day, optional 2 octets days.
	mmsTimeOfDayLen     = 4
	mmsTimeOfDayDaysLen = 6
)

// mmsTimeOfDayEpoch is day zero of the MMS TimeOfDay encoding.
var mmsTimeOfDayEpoch = time.Date(1984, time.January, 1, 0, 0, 0, 0, time.UTC)

var (
	errMMSDataType  = errors.New("MMS: unknown Data type")
	errMMSDataForm  = errors.New("MMS: Data has wrong primitive/constructed form")
	errMMSDataFloat = errors.New("MMS: invalid floating-point value")
	errMMSDataTime  = errors.New("MMS: invalid time value")
)

// MMSUTCTime is the IEC 61850 / MMS UtcTime: seconds since 1970, a 24 bit
// binary fraction of a second and a time quality octet. Quality bit 7 is
// leap second known, 6 clock failure, 5 clock not synchronized and bits
// 0-4 the number of accurate fraction bits.
type MMSUTCTime struct {
	Seconds  uint32
	Fraction uint32
	Quality  uint8
}

// Time converts the timestamp to a UTC time.Time, truncated to the
// nanosecond.
func (u MMSUTCTime) Time() time.Time {
	nsec := uint64(u.Fraction) * uint64(time.Second) >> mmsUTCFractionBits
	return time.Unix(int64(u.Seconds), int64(nsec)).UTC()
}

// decodeMMSUTCTime parses the 8 octet UtcTime encoding.
func decodeMMSUTCTime(v []byte) (MMSUTCTime, error) {
	if len(v) != mmsUTCTimeLen {
		return MMSUTCTime{}, errMMSDataTime
	}

	return MMSUTCTime{
		Seconds:  binary.BigEndian.Uint32(v),
		Fraction: uint32(v[4])<<16 | uint32(v[5])<<8 | uint32(v[6]),
		Quality:  v[7],
	}, nil
}

// MMSData is one decoded MMS Data value. Type selects which field holds
// the value; Raw always holds the encoded value octets.
type MMSData struct {
	Type MMSDataType
	Raw  []byte

	// Bool is set for boolean.
	Bool bool
	// IntOverflow is set for an integer, unsigned or bcd value too long
	// for Int or Uint, which then stay 0; BigInt returns its value.
	IntOverflow bool
	// Int is set for integer and bcd.
	Int int64
	// Uint is set for unsigned.
	Uint uint64
	// Float is set for floating-point and real.
	Float float64
	// Bits and UnusedBits are set for bit-string and booleanArray.
	Bits       []byte
	UnusedBits uint8
	// String is set for visible-string, mMSString, generalized-time and
	// objId (dotted form). GeneralizedTime parses a generalized-time.
	String string
	// Time is set for binary-time. A 4 octet TimeOfDay carries no date
	// and is reported on 1984-01-01.
	Time time.Time
	// UTC is set for utc-time.
	UTC MMSUTCTime
	// Items holds the members of an array or structure.
	Items []MMSData
}

// BitLen returns the number of bits of a bit-string or booleanArray.
func (d *MMSData) BitLen() int {
	return len(d.Bits)*8 - int(d.UnusedBits)
}

// Bit returns bit i (0 = most significant bit of the first octet) of a
// bit-string or booleanArray, or false when i is out of range.
func (d *MMSData) Bit(i int) bool {
	if i < 0 || i >= d.BitLen() {
		return false
	}
	return d.Bits[i/8]&(0x80>>uint(i%8)) != 0
}

// decodeMMSDataList decodes a SEQUENCE OF Data body.
func decodeMMSDataList(b []byte, depth int) ([]MMSData, error) {
	if depth > osiBERMaxDepth {
		return nil, errOSIBERDepth
	}

	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSData, 0, count)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		d, err := decodeMMSData(t, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// decodeMMSData decodes one Data CHOICE element.
func decodeMMSData(t osiBERTLV, depth int) (MMSData, error) {
	// Check the tag before narrowing it: tag 259 must not alias boolean.
	if t.Class != osiBERContext || t.Tag > uint32(MMSDataUTCTime) {
		return MMSData{}, errMMSDataType
	}
	d := MMSData{Type: MMSDataType(t.Tag), Raw: t.Value}

	// Only array and structure are constructed.
	wantForm := osiBERPrimitive
	if d.Type == MMSDataArray || d.Type == MMSDataStructure {
		wantForm = osiBERConstructed
	}
	if t.Form != wantForm {
		return d, errMMSDataForm
	}

	var err error
	v := t.Value
	switch d.Type {
	case MMSDataArray, MMSDataStructure:
		d.Items, err = decodeMMSDataList(v, depth+1)
	case MMSDataBoolean:
		d.Bool, err = osiBERBool(v)
	case MMSDataBitString, MMSDataBooleanArray:
		d.Bits, d.UnusedBits, err = osiBERBits(v)
	case MMSDataInteger, MMSDataBCD:
		d.Int, d.IntOverflow, err = mmsDataInt(v)
	case MMSDataUnsigned:
		d.Uint, d.IntOverflow, err = mmsDataUint(v)
	case MMSDataFloatingPoint:
		d.Float, err = decodeMMSFloat(v)
	case MMSDataReal:
		d.Float, err = osiBERReal(v)
	case MMSDataOctetString:
	case MMSDataVisibleString, MMSDataMMSString, MMSDataGeneralizedTime:
		d.String = string(v)
	case MMSDataBinaryTime:
		d.Time, err = decodeMMSTimeOfDay(v)
	case MMSDataObjID:
		d.String, err = osiBEROID(v)
	case MMSDataUTCTime:
		d.UTC, err = decodeMMSUTCTime(v)
	default:
		err = errMMSDataType
	}
	return d, err
}

// mmsDataInt decodes an integer value; one of more than 8 octets is
// flagged as overflow instead of rejected.
func mmsDataInt(v []byte) (int64, bool, error) {
	if len(v) > osiBERMaxIntOctets {
		return 0, true, nil
	}
	n, err := osiBERInt(v)
	return n, false, err
}

// mmsDataUint decodes an unsigned value; a non-negative one too long for
// 64 bits is flagged as overflow instead of rejected.
func mmsDataUint(v []byte) (uint64, bool, error) {
	if len(v) > osiBERMaxIntOctets && v[0]&0x80 == 0 && (len(v) > osiBERMaxIntOctets+1 || v[0] != 0) {
		return 0, true, nil
	}
	n, err := osiBERUint(v)
	return n, false, err
}

// BigInt returns the value of an integer, unsigned or bcd of any length,
// or nil for other types.
func (d *MMSData) BigInt() *big.Int {
	switch d.Type {
	case MMSDataInteger, MMSDataUnsigned, MMSDataBCD:
		return osiBERBig(d.Raw)
	}
	return nil
}

// decodeMMSFloat decodes the IEC 61850-8-1 FloatingPoint encoding:
// 08 + float32 or 0b + float64, e.g. 08 3f 80 00 00 = 1.0.
func decodeMMSFloat(v []byte) (float64, error) {
	switch {
	case len(v) == mmsFloatSingleLen && v[0] == mmsFloatSingleExp:
		return float64(math.Float32frombits(binary.BigEndian.Uint32(v[1:]))), nil
	case len(v) == mmsFloatDoubleLen && v[0] == mmsFloatDoubleExp:
		return math.Float64frombits(binary.BigEndian.Uint64(v[1:])), nil
	}
	return 0, errMMSDataFloat
}

// mmsGenTimeLayouts are the GeneralizedTime forms of X.680 with the hour
// alone, minutes and seconds, each with a UTC designator or offset or,
// last, as local time. time.Parse reads a fraction after the seconds.
var mmsGenTimeLayouts = [...]string{
	"20060102150405Z0700", "200601021504Z0700", "2006010215Z0700",
	"20060102150405", "200601021504", "2006010215",
}

// GeneralizedTime parses a generalized-time value, e.g.
// "20260102030405.5Z" or "202601020304+0100". A local time, one without
// "Z" or offset, is returned as UTC. ok is false for another Data type
// or a string that is no GeneralizedTime; a fraction of an hour or of a
// minute is not read.
func (d *MMSData) GeneralizedTime() (t time.Time, ok bool) {
	if d.Type != MMSDataGeneralizedTime {
		return time.Time{}, false
	}

	for _, layout := range mmsGenTimeLayouts {
		if t, err := time.Parse(layout, d.String); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Octets returns the value of an octet-string, nil for other types.
func (d *MMSData) Octets() []byte {
	if d.Type != MMSDataOctetString {
		return nil
	}
	return d.Raw
}

// BCD returns the value of a bcd, which is encoded as an INTEGER; ok is
// false for other types and for a value too long for an int64.
func (d *MMSData) BCD() (n int64, ok bool) {
	if d.Type != MMSDataBCD || d.IntOverflow {
		return 0, false
	}
	return d.Int, true
}

// decodeMMSTimeOfDay decodes TimeOfDay: milliseconds since midnight and,
// in the 6 octet form, days since 1984-01-01.
func decodeMMSTimeOfDay(v []byte) (time.Time, error) {
	if len(v) != mmsTimeOfDayLen && len(v) != mmsTimeOfDayDaysLen {
		return time.Time{}, errMMSDataTime
	}

	ms := binary.BigEndian.Uint32(v)
	days := 0
	if len(v) == mmsTimeOfDayDaysLen {
		days = int(binary.BigEndian.Uint16(v[4:]))
	}
	return mmsTimeOfDayEpoch.AddDate(0, 0, days).Add(time.Duration(ms) * time.Millisecond), nil
}
