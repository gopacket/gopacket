// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA Binary built-in types (OPC 10000-6 §5.2) and a bounds-checked
// reader for them.

package layers

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Built-in type sizes and markers (OPC 10000-6 §5.2.2).
const (
	opcuaUint16Len      = 2
	opcuaUint32Len      = 4
	opcuaUint64Len      = 8
	opcuaGUIDLen        = 16
	opcuaNullLength     = -1 // String, ByteString and array length of null
	opcuaMaxDiagDepth   = 16 // InnerDiagnosticInfo nested deeper is refused
	opcuaNodeIDTypeMask = 0x3F
	opcuaNodeIDURIFlag  = 0x80 // ExpandedNodeId: NamespaceUri follows
	opcuaNodeIDSrvFlag  = 0x40 // ExpandedNodeId: ServerIndex follows

	// DateTime counts 100 ns ticks since 1601-01-01 UTC.
	opcuaTicksPerSecond    = 10000000
	opcuaNanosPerTick      = 100
	opcuaEpochToUnixSecond = 11644473600
)

// OPCUANodeIDEncoding is the wire form of a NodeId (OPC 10000-6 §5.2.2.9).
type OPCUANodeIDEncoding uint8

// OPCUANodeIDEncoding values.
const (
	OPCUANodeIDTwoByte    OPCUANodeIDEncoding = 0
	OPCUANodeIDFourByte   OPCUANodeIDEncoding = 1
	OPCUANodeIDNumeric    OPCUANodeIDEncoding = 2
	OPCUANodeIDString     OPCUANodeIDEncoding = 3
	OPCUANodeIDGUID       OPCUANodeIDEncoding = 4
	OPCUANodeIDByteString OPCUANodeIDEncoding = 5
)

var opcuaNodeIDEncodingNames = map[OPCUANodeIDEncoding]string{
	OPCUANodeIDTwoByte:    "TwoByte",
	OPCUANodeIDFourByte:   "FourByte",
	OPCUANodeIDNumeric:    "Numeric",
	OPCUANodeIDString:     "String",
	OPCUANodeIDGUID:       "GUID",
	OPCUANodeIDByteString: "ByteString",
}

// String returns the encoding name.
func (e OPCUANodeIDEncoding) String() string { return opcuaName(opcuaNodeIDEncodingNames, e) }

// OPCUAGUID is a Guid as it appears on the wire: Data1 to Data3 little
// endian, Data4 as bytes.
type OPCUAGUID [opcuaGUIDLen]byte

// String returns the GUID in its canonical text form.
func (g OPCUAGUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(g[0:]),
		binary.LittleEndian.Uint16(g[4:]), binary.LittleEndian.Uint16(g[6:]), g[8:10], g[10:])
}

// OPCUANodeID is a NodeId or ExpandedNodeId. Which identifier field is set
// depends on Encoding: Numeric for the three numeric forms, StringID,
// GUID or Opaque for the others.
type OPCUANodeID struct {
	Encoding  OPCUANodeIDEncoding
	Namespace uint16
	Numeric   uint32
	StringID  string
	GUID      OPCUAGUID
	Opaque    []byte
	// NamespaceURI and ServerIndex are set by an ExpandedNodeId whose
	// flags announce them.
	NamespaceURI string
	ServerIndex  uint32
}

// String returns the NodeId in the OPC UA text form, such as "i=631" or
// "ns=2;s=Pump".
func (n OPCUANodeID) String() string {
	prefix := ""
	if n.NamespaceURI != "" {
		prefix = "nsu=" + n.NamespaceURI + ";"
	} else if n.Namespace != 0 {
		prefix = fmt.Sprintf("ns=%d;", n.Namespace)
	}
	if n.ServerIndex != 0 {
		prefix = fmt.Sprintf("svr=%d;", n.ServerIndex) + prefix
	}

	switch n.Encoding {
	case OPCUANodeIDString:
		return prefix + "s=" + n.StringID
	case OPCUANodeIDGUID:
		return prefix + "g=" + n.GUID.String()
	case OPCUANodeIDByteString:
		return prefix + "b=" + base64.StdEncoding.EncodeToString(n.Opaque)
	}
	return fmt.Sprintf("%si=%d", prefix, n.Numeric)
}

// OPCUAStatusCode is a StatusCode (OPC 10000-4 §7.39); the top two bits
// give the severity.
type OPCUAStatusCode uint32

// Status code severity bits.
const (
	opcuaSeverityMask      OPCUAStatusCode = 0xC0000000
	opcuaSeverityUncertain OPCUAStatusCode = 0x40000000
	opcuaSeverityBad       OPCUAStatusCode = 0x80000000
	opcuaCodeMask          OPCUAStatusCode = 0xFFFF0000 // drops the info bits
)

// IsGood reports whether the severity is Good.
func (s OPCUAStatusCode) IsGood() bool { return s&opcuaSeverityMask == 0 }

// IsBad reports whether the severity is Bad.
func (s OPCUAStatusCode) IsBad() bool { return s&opcuaSeverityBad != 0 }

// String returns the status code name, or its severity and value.
func (s OPCUAStatusCode) String() string {
	if n, ok := opcuaStatusNames[s&opcuaCodeMask]; ok {
		return n
	}
	sev := "Good"
	switch {
	case s.IsBad():
		sev = "Bad"
	case s&opcuaSeverityMask == opcuaSeverityUncertain:
		sev = "Uncertain"
	}
	return fmt.Sprintf("%s(0x%08X)", sev, uint32(s))
}

// OPCUAQualifiedName is a QualifiedName: a namespace index and a name.
type OPCUAQualifiedName struct {
	Namespace uint16
	Name      string
}

// OPCUAExtensionObject is an ExtensionObject (OPC 10000-6 §5.2.2.15). The
// body is left encoded.
type OPCUAExtensionObject struct {
	TypeID OPCUANodeID
	// Encoding is 0 for no body, 1 for a ByteString body, 2 for XML.
	Encoding uint8
	Body     []byte
}

// OPCUADiagnosticInfo is a DiagnosticInfo (OPC 10000-6 §5.2.2.12). The
// int32 fields index the response string table; -1 means absent.
type OPCUADiagnosticInfo struct {
	Mask            uint8
	SymbolicID      int32
	NamespaceURI    int32
	Locale          int32
	LocalizedText   int32
	AdditionalInfo  string
	InnerStatusCode OPCUAStatusCode
	Inner           *OPCUADiagnosticInfo
}

// DiagnosticInfo encoding mask bits, in wire order of their fields.
const (
	opcuaDiagSymbolicID     = 0x01
	opcuaDiagNamespaceURI   = 0x02
	opcuaDiagLocalizedText  = 0x04
	opcuaDiagLocale         = 0x08
	opcuaDiagAdditionalInfo = 0x10
	opcuaDiagInnerStatus    = 0x20
	opcuaDiagInnerDiag      = 0x40
)

// opcuaReader reads OPC UA Binary types from a buffer. The first error
// sticks: later reads return zero values, so a caller checks err once.
// Every length is checked against the bytes left before anything is
// sliced or allocated.
type opcuaReader struct {
	b   []byte
	off int
	err error
}

func (r *opcuaReader) remaining() int { return len(r.b) - r.off }

// take returns the next n bytes, a slice of the buffer.
func (r *opcuaReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > r.remaining() {
		r.err = ErrOPCUATruncated
		return nil
	}
	s := r.b[r.off : r.off+n : r.off+n]
	r.off += n
	return s
}

func (r *opcuaReader) u8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *opcuaReader) u16() uint16 {
	b := r.take(opcuaUint16Len)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint16(b)
}

func (r *opcuaReader) u32() uint32 {
	b := r.take(opcuaUint32Len)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func (r *opcuaReader) i32() int32 { return int32(r.u32()) }

func (r *opcuaReader) u64() uint64 {
	b := r.take(opcuaUint64Len)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

func (r *opcuaReader) f64() float64 { return math.Float64frombits(r.u64()) }

// byteString reads an int32 length then that many bytes; length -1 is
// null and returns nil, other negative lengths are malformed.
func (r *opcuaReader) byteString() []byte {
	n := r.i32()
	if r.err != nil || n == opcuaNullLength {
		return nil
	}
	if n < opcuaNullLength {
		r.err = ErrOPCUAMalformed
		return nil
	}
	return r.take(int(n))
}

// str reads a String; null and empty both return "".
func (r *opcuaReader) str() string { return string(r.byteString()) }

// arrayLen reads an array length and checks that count elements of at
// least minSize bytes each fit in what is left, so a claimed length never
// drives an allocation.
func (r *opcuaReader) arrayLen(minSize int) int {
	n := r.i32()
	if r.err != nil || n == opcuaNullLength {
		return 0
	}
	if n < opcuaNullLength || int64(n)*int64(minSize) > int64(r.remaining()) {
		r.err = ErrOPCUAMalformed
		return 0
	}
	return int(n)
}

// strings reads an array of String.
func (r *opcuaReader) strings() []string {
	n := r.arrayLen(opcuaUint32Len)
	var out []string
	for i := 0; i < n && r.err == nil; i++ {
		out = append(out, r.str())
	}
	return out
}

// dateTime reads a DateTime; 0 and negative ticks are the null time.
func (r *opcuaReader) dateTime() time.Time {
	ticks := int64(r.u64())
	if ticks <= 0 {
		return time.Time{}
	}
	sec := ticks/opcuaTicksPerSecond - opcuaEpochToUnixSecond
	nsec := ticks % opcuaTicksPerSecond * opcuaNanosPerTick
	return time.Unix(sec, nsec).UTC()
}

// nodeID reads a NodeId; ExpandedNodeId flags are malformed here.
func (r *opcuaReader) nodeID() OPCUANodeID {
	enc := r.u8()
	if enc&^opcuaNodeIDTypeMask != 0 {
		r.err = ErrOPCUAMalformed
		return OPCUANodeID{}
	}
	return r.nodeIDBody(enc)
}

// expandedNodeID reads an ExpandedNodeId: a NodeId whose encoding octet
// may announce a NamespaceUri and a ServerIndex after the identifier.
func (r *opcuaReader) expandedNodeID() OPCUANodeID {
	enc := r.u8()
	n := r.nodeIDBody(enc &^ (opcuaNodeIDURIFlag | opcuaNodeIDSrvFlag))
	if enc&opcuaNodeIDURIFlag != 0 {
		n.NamespaceURI = r.str()
	}
	if enc&opcuaNodeIDSrvFlag != 0 {
		n.ServerIndex = r.u32()
	}
	return n
}

// nodeIDBody reads the namespace and identifier of encoding enc.
func (r *opcuaReader) nodeIDBody(enc uint8) OPCUANodeID {
	n := OPCUANodeID{Encoding: OPCUANodeIDEncoding(enc)}

	switch n.Encoding {
	case OPCUANodeIDTwoByte:
		n.Numeric = uint32(r.u8())
	case OPCUANodeIDFourByte:
		n.Namespace = uint16(r.u8())
		n.Numeric = uint32(r.u16())
	case OPCUANodeIDNumeric:
		n.Namespace = r.u16()
		n.Numeric = r.u32()
	case OPCUANodeIDString:
		n.Namespace = r.u16()
		n.StringID = r.str()
	case OPCUANodeIDGUID:
		n.Namespace = r.u16()
		copy(n.GUID[:], r.take(opcuaGUIDLen))
	case OPCUANodeIDByteString:
		n.Namespace = r.u16()
		n.Opaque = r.byteString()
	default:
		r.err = ErrOPCUAMalformed
	}
	return n
}

// qualifiedName reads a QualifiedName.
func (r *opcuaReader) qualifiedName() OPCUAQualifiedName {
	return OPCUAQualifiedName{Namespace: r.u16(), Name: r.str()}
}

// extensionObject reads an ExtensionObject, keeping its body encoded.
func (r *opcuaReader) extensionObject() OPCUAExtensionObject {
	const noBody = 0
	e := OPCUAExtensionObject{TypeID: r.nodeID(), Encoding: r.u8()}
	if e.Encoding != noBody {
		e.Body = r.byteString()
	}
	return e
}

// diagnosticInfo reads a DiagnosticInfo, following InnerDiagnosticInfo at
// most opcuaMaxDiagDepth deep.
func (r *opcuaReader) diagnosticInfo(depth int) OPCUADiagnosticInfo {
	d := OPCUADiagnosticInfo{Mask: r.u8(), SymbolicID: -1, NamespaceURI: -1, Locale: -1, LocalizedText: -1}
	if d.Mask&opcuaDiagSymbolicID != 0 {
		d.SymbolicID = r.i32()
	}
	if d.Mask&opcuaDiagNamespaceURI != 0 {
		d.NamespaceURI = r.i32()
	}
	if d.Mask&opcuaDiagLocale != 0 {
		d.Locale = r.i32()
	}
	if d.Mask&opcuaDiagLocalizedText != 0 {
		d.LocalizedText = r.i32()
	}
	if d.Mask&opcuaDiagAdditionalInfo != 0 {
		d.AdditionalInfo = r.str()
	}
	if d.Mask&opcuaDiagInnerStatus != 0 {
		d.InnerStatusCode = OPCUAStatusCode(r.u32())
	}
	if d.Mask&opcuaDiagInnerDiag == 0 || r.err != nil {
		return d
	}

	if depth >= opcuaMaxDiagDepth {
		r.err = ErrOPCUAMalformed
		return d
	}
	inner := r.diagnosticInfo(depth + 1)
	d.Inner = &inner
	return d
}
