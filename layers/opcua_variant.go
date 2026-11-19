// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA Binary built-in types that carry values (OPC 10000-6 §5.2.2):
// LocalizedText, DataValue and Variant, and the array readers the
// service bodies are built from.
//
//	DataValue ─ mask ─┬─ Variant ─ type ─┬─ scalar
//	                  │                  └─ array ─ elements ─ dimensions
//	                  ├─ StatusCode         (a Variant or DataValue element
//	                  └─ timestamps          nests, opcuaMaxValueDepth deep)

package layers

import (
	"math"
	"time"
)

// Value encoding limits and minimum sizes (OPC 10000-6 §5.2.2).
const (
	opcuaMaxValueDepth = 16 // Variant and DataValue nested deeper are refused
	opcuaUint8Len      = 1
	opcuaMinMaskedLen  = 1 // LocalizedText, DataValue, Variant, DiagnosticInfo: the mask
	opcuaMinExtObjLen  = opcuaMinNodeIDLen + opcuaUint8Len
	opcuaMinQNameLen   = opcuaUint16Len + opcuaUint32Len
)

// OPCUABuiltinType is a built-in type id (OPC 10000-6 §5.1.2), the type
// of a Variant.
type OPCUABuiltinType uint8

// OPCUABuiltinType values.
const (
	OPCUATypeNull            OPCUABuiltinType = 0
	OPCUATypeBoolean         OPCUABuiltinType = 1
	OPCUATypeSByte           OPCUABuiltinType = 2
	OPCUATypeByte            OPCUABuiltinType = 3
	OPCUATypeInt16           OPCUABuiltinType = 4
	OPCUATypeUInt16          OPCUABuiltinType = 5
	OPCUATypeInt32           OPCUABuiltinType = 6
	OPCUATypeUInt32          OPCUABuiltinType = 7
	OPCUATypeInt64           OPCUABuiltinType = 8
	OPCUATypeUInt64          OPCUABuiltinType = 9
	OPCUATypeFloat           OPCUABuiltinType = 10
	OPCUATypeDouble          OPCUABuiltinType = 11
	OPCUATypeString          OPCUABuiltinType = 12
	OPCUATypeDateTime        OPCUABuiltinType = 13
	OPCUATypeGUID            OPCUABuiltinType = 14
	OPCUATypeByteString      OPCUABuiltinType = 15
	OPCUATypeXMLElement      OPCUABuiltinType = 16
	OPCUATypeNodeID          OPCUABuiltinType = 17
	OPCUATypeExpandedNodeID  OPCUABuiltinType = 18
	OPCUATypeStatusCode      OPCUABuiltinType = 19
	OPCUATypeQualifiedName   OPCUABuiltinType = 20
	OPCUATypeLocalizedText   OPCUABuiltinType = 21
	OPCUATypeExtensionObject OPCUABuiltinType = 22
	OPCUATypeDataValue       OPCUABuiltinType = 23
	OPCUATypeVariant         OPCUABuiltinType = 24
	OPCUATypeDiagnosticInfo  OPCUABuiltinType = 25

	// opcuaMaxVariantType is the last of the type ids 26 to 31, which
	// OPC 10000-6 §5.2.2.16 reserves and tells decoders to read as a
	// ByteString. Wireshark 4.7 reads no value for them at all.
	opcuaMaxVariantType OPCUABuiltinType = 31
)

var opcuaBuiltinTypeNames = map[OPCUABuiltinType]string{
	OPCUATypeNull:            "Null",
	OPCUATypeBoolean:         "Boolean",
	OPCUATypeSByte:           "SByte",
	OPCUATypeByte:            "Byte",
	OPCUATypeInt16:           "Int16",
	OPCUATypeUInt16:          "UInt16",
	OPCUATypeInt32:           "Int32",
	OPCUATypeUInt32:          "UInt32",
	OPCUATypeInt64:           "Int64",
	OPCUATypeUInt64:          "UInt64",
	OPCUATypeFloat:           "Float",
	OPCUATypeDouble:          "Double",
	OPCUATypeString:          "String",
	OPCUATypeDateTime:        "DateTime",
	OPCUATypeGUID:            "Guid",
	OPCUATypeByteString:      "ByteString",
	OPCUATypeXMLElement:      "XmlElement",
	OPCUATypeNodeID:          "NodeId",
	OPCUATypeExpandedNodeID:  "ExpandedNodeId",
	OPCUATypeStatusCode:      "StatusCode",
	OPCUATypeQualifiedName:   "QualifiedName",
	OPCUATypeLocalizedText:   "LocalizedText",
	OPCUATypeExtensionObject: "ExtensionObject",
	OPCUATypeDataValue:       "DataValue",
	OPCUATypeVariant:         "Variant",
	OPCUATypeDiagnosticInfo:  "DiagnosticInfo",
}

// String returns the type name.
func (t OPCUABuiltinType) String() string { return opcuaName(opcuaBuiltinTypeNames, t) }

// opcuaBuiltinMinLen is the smallest encoding of each built-in type, used
// to bound array lengths.
var opcuaBuiltinMinLen = [...]int{
	OPCUATypeBoolean:         opcuaUint8Len,
	OPCUATypeSByte:           opcuaUint8Len,
	OPCUATypeByte:            opcuaUint8Len,
	OPCUATypeInt16:           opcuaUint16Len,
	OPCUATypeUInt16:          opcuaUint16Len,
	OPCUATypeInt32:           opcuaUint32Len,
	OPCUATypeUInt32:          opcuaUint32Len,
	OPCUATypeInt64:           opcuaUint64Len,
	OPCUATypeUInt64:          opcuaUint64Len,
	OPCUATypeFloat:           opcuaUint32Len,
	OPCUATypeDouble:          opcuaUint64Len,
	OPCUATypeString:          opcuaUint32Len,
	OPCUATypeDateTime:        opcuaUint64Len,
	OPCUATypeGUID:            opcuaGUIDLen,
	OPCUATypeByteString:      opcuaUint32Len,
	OPCUATypeXMLElement:      opcuaUint32Len,
	OPCUATypeNodeID:          opcuaMinNodeIDLen,
	OPCUATypeExpandedNodeID:  opcuaMinNodeIDLen,
	OPCUATypeStatusCode:      opcuaUint32Len,
	OPCUATypeQualifiedName:   opcuaMinQNameLen,
	OPCUATypeLocalizedText:   opcuaMinMaskedLen,
	OPCUATypeExtensionObject: opcuaMinExtObjLen,
	OPCUATypeDataValue:       opcuaMinMaskedLen,
	OPCUATypeVariant:         opcuaMinMaskedLen,
	OPCUATypeDiagnosticInfo:  opcuaMinMaskedLen,
}

// OPCUALocalizedText is a LocalizedText; Mask tells which fields were
// present.
type OPCUALocalizedText struct {
	Mask   uint8
	Locale string
	Text   string
}

// LocalizedText encoding mask bits.
const (
	opcuaTextLocale = 0x01
	opcuaTextText   = 0x02
)

// OPCUAVariant is a Variant (OPC 10000-6 §5.2.2.16). Value holds, by
// Type: bool, int8, uint8, int16, uint16, int32, uint32, int64, uint64,
// float32, float64, string (String and XmlElement), time.Time, OPCUAGUID,
// []byte, OPCUANodeID (NodeId and ExpandedNodeId), OPCUAStatusCode,
// OPCUAQualifiedName, OPCUALocalizedText, OPCUAExtensionObject,
// OPCUADataValue, OPCUAVariant or OPCUADiagnosticInfo. An array holds a
// slice of that type: a nil slice when null, an empty one when the
// array has length 0. Value is nil for
// Null. The reserved types 26 to 31 hold a []byte, as the specification
// asks: their value is read as a ByteString.
type OPCUAVariant struct {
	Type    OPCUABuiltinType
	IsArray bool
	// Dimensions are the ArrayDimensions of a multi-dimensional array,
	// whose elements Value lists in row-major order.
	Dimensions []int32
	Value      interface{}
}

// Variant encoding mask bits.
const (
	opcuaVariantTypeMask = 0x3F
	opcuaVariantDims     = 0x40
	opcuaVariantArray    = 0x80
)

// OPCUADataValue is a DataValue (OPC 10000-6 §5.2.2.17); Mask tells which
// fields were present. An absent Status is Good.
type OPCUADataValue struct {
	Mask              uint8
	Value             OPCUAVariant
	Status            OPCUAStatusCode
	SourceTimestamp   time.Time
	SourcePicoseconds uint16
	ServerTimestamp   time.Time
	ServerPicoseconds uint16
}

// DataValue encoding mask bits.
const (
	opcuaDataValueValue       = 0x01
	opcuaDataValueStatus      = 0x02
	opcuaDataValueSourceTime  = 0x04
	opcuaDataValueServerTime  = 0x08
	opcuaDataValueSourcePicos = 0x10
	opcuaDataValueServerPicos = 0x20
)

func (r *opcuaReader) boolean() bool { return r.u8() != 0 }

func (r *opcuaReader) i8() int8 { return int8(r.u8()) }

func (r *opcuaReader) i16() int16 { return int16(r.u16()) }

func (r *opcuaReader) i64() int64 { return int64(r.u64()) }

func (r *opcuaReader) f32() float32 { return math.Float32frombits(r.u32()) }

func (r *opcuaReader) statusCode() OPCUAStatusCode { return OPCUAStatusCode(r.u32()) }

func (r *opcuaReader) guid() OPCUAGUID {
	var g OPCUAGUID
	copy(g[:], r.take(opcuaGUIDLen))
	return g
}

// binaryTypeID returns the numeric namespace 0 type id of an
// ExtensionObject with a binary body, the form standard structures such
// as identity tokens and notifications take.
func (e OPCUAExtensionObject) binaryTypeID() (uint32, bool) {
	const binaryBody = 1
	n := e.TypeID
	if e.Encoding != binaryBody || n.Namespace != 0 {
		return 0, false
	}
	switch n.Encoding {
	case OPCUANodeIDTwoByte, OPCUANodeIDFourByte, OPCUANodeIDNumeric:
		return n.Numeric, true
	}
	return 0, false
}

// localizedText reads a LocalizedText.
func (r *opcuaReader) localizedText() OPCUALocalizedText {
	t := OPCUALocalizedText{Mask: r.u8()}
	if t.Mask&opcuaTextLocale != 0 {
		t.Locale = r.str()
	}
	if t.Mask&opcuaTextText != 0 {
		t.Text = r.str()
	}
	return t
}

// opcuaArray reads an array whose elements take at least minSize bytes,
// allocated once. While an element is read, the bytes the later ones
// need at least stay reserved, so an array nested in it cannot claim
// them too: the arrays open at once never claim more than the data.
//
//	[n=3 | elem0: [m=2 | a | b] | elem1 | elem2]
//	              m*size must fit in what is left minus 2*minSize
//
// A probing reader reads the elements and keeps none.
func opcuaArray[T any](r *opcuaReader, minSize int, read func() T) []T {
	n, kind := r.arrayLen(minSize)
	if r.err != nil || kind == opcuaArrayNull || r.mode == opcuaReadProbe && n == 0 {
		return nil
	}
	// An empty array is not null: it decodes to an empty slice, which
	// costs no allocation.
	if n == 0 {
		return []T{}
	}

	var out []T
	if r.mode == opcuaReadDecode {
		out = make([]T, n)
	}
	r.reserved += n * minSize
	for i := 0; i < n; i++ {
		r.reserved -= minSize
		v := read()
		if r.err != nil {
			return nil
		}
		if out != nil {
			out[i] = v
		}
	}
	return out
}

func (r *opcuaReader) u32s() []uint32 { return opcuaArray(r, opcuaUint32Len, r.u32) }

func (r *opcuaReader) statusCodes() []OPCUAStatusCode {
	return opcuaArray(r, opcuaUint32Len, r.statusCode)
}

func (r *opcuaReader) nodeIDs() []OPCUANodeID { return opcuaArray(r, opcuaMinNodeIDLen, r.nodeID) }

func (r *opcuaReader) byteStrings() [][]byte { return opcuaArray(r, opcuaUint32Len, r.byteString) }

// diagnosticInfos reads an array of DiagnosticInfo.
func (r *opcuaReader) diagnosticInfos() []OPCUADiagnosticInfo {
	return opcuaArray(r, opcuaMinMaskedLen, func() OPCUADiagnosticInfo { return r.diagnosticInfo(0) })
}

// variants reads an array of Variant at nesting depth.
func (r *opcuaReader) variants(depth int) []OPCUAVariant {
	return opcuaArray(r, opcuaMinMaskedLen, func() OPCUAVariant { return r.variant(depth) })
}

// dataValues reads an array of DataValue at nesting depth.
func (r *opcuaReader) dataValues(depth int) []OPCUADataValue {
	return opcuaArray(r, opcuaMinMaskedLen, func() OPCUADataValue { return r.dataValue(depth) })
}

// dataValue reads a DataValue; depth counts the Variants and DataValues
// it sits in.
func (r *opcuaReader) dataValue(depth int) OPCUADataValue {
	d := OPCUADataValue{Mask: r.u8()}
	if d.Mask&opcuaDataValueValue != 0 {
		d.Value = r.variant(depth + 1)
	}
	if d.Mask&opcuaDataValueStatus != 0 {
		d.Status = r.statusCode()
	}
	if d.Mask&opcuaDataValueSourceTime != 0 {
		d.SourceTimestamp = r.dateTime()
	}
	if d.Mask&opcuaDataValueSourcePicos != 0 {
		d.SourcePicoseconds = r.u16()
	}
	if d.Mask&opcuaDataValueServerTime != 0 {
		d.ServerTimestamp = r.dateTime()
	}
	if d.Mask&opcuaDataValueServerPicos != 0 {
		d.ServerPicoseconds = r.u16()
	}
	return d
}

// variant reads a Variant; depth counts the Variants and DataValues it
// sits in. Type ids past the reserved ones, and dimensions without an
// array, are malformed.
func (r *opcuaReader) variant(depth int) OPCUAVariant {
	mask := r.u8()
	v := OPCUAVariant{Type: OPCUABuiltinType(mask & opcuaVariantTypeMask), IsArray: mask&opcuaVariantArray != 0}
	if r.err != nil {
		return v
	}
	if depth >= opcuaMaxValueDepth || v.Type > opcuaMaxVariantType || (mask&opcuaVariantDims != 0 && !v.IsArray) {
		r.err = ErrOPCUAMalformed
		return v
	}

	// A probe skips the scalar: boxing it in Value would allocate.
	if !v.IsArray && r.mode == opcuaReadProbe {
		r.probeScalar(v.Type, depth)
		return v
	}
	if !v.IsArray {
		v.Value = r.scalar(v.Type, depth)
		return v
	}

	v.Value = r.valueArray(v.Type, depth)
	if mask&opcuaVariantDims != 0 {
		v.Dimensions = opcuaArray(r, opcuaUint32Len, r.i32)
	}
	return v
}

// probeScalar reads one value of built-in type t and drops it.
func (r *opcuaReader) probeScalar(t OPCUABuiltinType, depth int) {
	switch {
	case t > OPCUATypeDiagnosticInfo:
		r.byteString()
		return
	case t == OPCUATypeString, t == OPCUATypeXMLElement, t == OPCUATypeByteString:
		r.byteString()
		return
	}

	switch t {
	case OPCUATypeNodeID:
		r.nodeID()
	case OPCUATypeExpandedNodeID:
		r.expandedNodeID()
	case OPCUATypeQualifiedName:
		r.qualifiedName()
	case OPCUATypeLocalizedText:
		r.localizedText()
	case OPCUATypeExtensionObject:
		r.extensionObject()
	case OPCUATypeDataValue:
		r.dataValue(depth + 1)
	case OPCUATypeVariant:
		r.variant(depth + 1)
	case OPCUATypeDiagnosticInfo:
		r.diagnosticInfo(0)
	// The other types have a fixed size, which is their minimum.
	default:
		r.take(opcuaBuiltinMinLen[t])
	}
}

// scalar reads one value of built-in type t.
func (r *opcuaReader) scalar(t OPCUABuiltinType, depth int) interface{} {
	if t > OPCUATypeDiagnosticInfo {
		return r.byteString()
	}

	switch t {
	case OPCUATypeBoolean:
		return r.boolean()
	case OPCUATypeSByte:
		return r.i8()
	case OPCUATypeByte:
		return r.u8()
	case OPCUATypeInt16:
		return r.i16()
	case OPCUATypeUInt16:
		return r.u16()
	case OPCUATypeInt32:
		return r.i32()
	case OPCUATypeUInt32:
		return r.u32()
	case OPCUATypeInt64:
		return r.i64()
	case OPCUATypeUInt64:
		return r.u64()
	case OPCUATypeFloat:
		return r.f32()
	case OPCUATypeDouble:
		return r.f64()
	case OPCUATypeString, OPCUATypeXMLElement:
		return r.str()
	case OPCUATypeDateTime:
		return r.dateTime()
	case OPCUATypeGUID:
		return r.guid()
	case OPCUATypeByteString:
		return r.byteString()
	case OPCUATypeNodeID:
		return r.nodeID()
	case OPCUATypeExpandedNodeID:
		return r.expandedNodeID()
	case OPCUATypeStatusCode:
		return r.statusCode()
	case OPCUATypeQualifiedName:
		return r.qualifiedName()
	case OPCUATypeLocalizedText:
		return r.localizedText()
	case OPCUATypeExtensionObject:
		return r.extensionObject()
	case OPCUATypeDataValue:
		return r.dataValue(depth + 1)
	case OPCUATypeVariant:
		return r.variant(depth + 1)
	case OPCUATypeDiagnosticInfo:
		return r.diagnosticInfo(0)
	}
	return nil
}

// valueArray reads an array of built-in type t as a typed slice.
func (r *opcuaReader) valueArray(t OPCUABuiltinType, depth int) interface{} {
	if t > OPCUATypeDiagnosticInfo {
		return opcuaArray(r, opcuaUint32Len, r.byteString)
	}

	m := opcuaBuiltinMinLen[t]
	switch t {
	// A Null has no other field, array bit or not (OPC 10000-6
	// §5.2.2.16): no length is read, as in Wireshark 4.7.
	case OPCUATypeNull:
		return nil
	case OPCUATypeBoolean:
		return opcuaArray(r, m, r.boolean)
	case OPCUATypeSByte:
		return opcuaArray(r, m, r.i8)
	case OPCUATypeByte:
		return opcuaArray(r, m, r.u8)
	case OPCUATypeInt16:
		return opcuaArray(r, m, r.i16)
	case OPCUATypeUInt16:
		return opcuaArray(r, m, r.u16)
	case OPCUATypeInt32:
		return opcuaArray(r, m, r.i32)
	case OPCUATypeUInt32:
		return opcuaArray(r, m, r.u32)
	case OPCUATypeInt64:
		return opcuaArray(r, m, r.i64)
	case OPCUATypeUInt64:
		return opcuaArray(r, m, r.u64)
	case OPCUATypeFloat:
		return opcuaArray(r, m, r.f32)
	case OPCUATypeDouble:
		return opcuaArray(r, m, r.f64)
	case OPCUATypeString, OPCUATypeXMLElement:
		return opcuaArray(r, m, r.str)
	case OPCUATypeDateTime:
		return opcuaArray(r, m, r.dateTime)
	case OPCUATypeGUID:
		return opcuaArray(r, m, r.guid)
	case OPCUATypeByteString:
		return opcuaArray(r, m, r.byteString)
	case OPCUATypeNodeID:
		return opcuaArray(r, m, r.nodeID)
	case OPCUATypeExpandedNodeID:
		return opcuaArray(r, m, r.expandedNodeID)
	case OPCUATypeStatusCode:
		return opcuaArray(r, m, r.statusCode)
	case OPCUATypeQualifiedName:
		return opcuaArray(r, m, r.qualifiedName)
	case OPCUATypeLocalizedText:
		return opcuaArray(r, m, r.localizedText)
	case OPCUATypeExtensionObject:
		return opcuaArray(r, m, r.extensionObject)
	case OPCUATypeDataValue:
		return r.dataValues(depth + 1)
	case OPCUATypeVariant:
		return r.variants(depth + 1)
	case OPCUATypeDiagnosticInfo:
		return r.diagnosticInfos()
	}
	return nil
}
