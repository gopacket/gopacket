// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"fmt"
	"time"
)

// The body of a request, response or notification is the data after
// the data header. The plugin reads it as
//
//	function fields | [object qualifier] | [extra] | [integrity] | rest
//
// The object qualifier (an ID and an ID/value list) follows the
// variable access requests; GetVarSubStreamed, SetVarSubStreamed and
// SetVariable requests add a few octets after it; V2 and V3 then put an
// integrity ID (VLQ), and V1/V2 PDUs of 32 octets or more left a
// 32-octet digest. What remains is usually four zero octets.

const (
	// Remaining octets above which an object qualifier is present.
	s7plusQualifierMin = 10
	// Remaining octets above which the integrity ID is present, and the
	// digest size of a V1/V2 integrity part.
	s7plusIntegrityMin = 4
	s7plusDigestLen    = 32

	// A notification's Unknown2 value that announces sequence numbers
	// and values; subscription IDs from 0x70000000 have a VLQ sequence.
	s7plusNotifyValues = 0x0400
	s7plusNotifyVLQSeq = 0x70000000

	// Notification item codes (the plugin's "return value").
	s7plusNotifyEnd       = 0x00
	s7plusNotifyAddrErr   = 0x03
	s7plusNotifyAddrErr2  = 0x13
	s7plusNotifyObject    = 0x81
	s7plusNotifyValueV1   = 0x83
	s7plusNotifyValue     = 0x92
	s7plusNotifyIDValue   = 0x9B
	s7plusNotifyVarTabRef = 0x9C

	// BeginSequence value type 1 announces an object.
	s7plusSeqObject = 1
	// Invoke responses: item numbers start at 1; anything else is a
	// fourth return value.
	s7plusInvokeFirstItem = 1

	// DB access areas: 0x8A0E0000 + DB number. I/Q/M/C/T are 80-84.
	s7plusAreaDBBase  = 0x8A0E0000
	s7plusAreaDBMask  = 0xFFFF0000
	s7plusAreaIQMCTLo = 80
	s7plusAreaIQMCTHi = 84
	// Classic blob access (LID 3): start offset, byte count and
	// optional bit offset follow.
	s7plusLIDClassicBlob = 3
	s7plusClassicLIDs    = 3
	// An address has CRC, area, LID count and sub-area at least.
	s7plusAddrMinLen = 4

	// Unknown octets the plugin skips, by request.
	s7plusCreateUnknown = 4
	s7plusGetLinkHead   = 4
	s7plusGetLinkTail   = 2
	s7plusEndSeqUnknown = 2
	s7plusInvokeHead    = 4
	s7plusSubStrTail    = 2
)

var (
	// ErrS7CommPlusFragment is returned by DecodeBody for a frame that is
	// not a whole PDU: a fragment, a frame cut before its trailer, or a
	// keep-alive.
	ErrS7CommPlusFragment = errors.New("S7comm-plus frame is not a whole PDU")
	// ErrS7CommPlusUnsupported is returned for opcodes and functions
	// whose body layout is unknown: AddLink, RemoveLink,
	// GetVariablesAddress and Abort. No public capture or dissector
	// describes them, so their octets stay raw in Rest.
	ErrS7CommPlusUnsupported = errors.New("S7comm-plus body layout unknown")
)

// Bit fields of a return value.
const (
	s7plusRetOMSShift     = 16
	s7plusRetSourceShift  = 32
	s7plusRetGenericShift = 40
	s7plusRetGenericMask  = 0x7F
	s7plusRetServerBit    = 1 << 47
	s7plusRetExtensionBit = 1 << 62
)

// S7CommPlusReturn is a 64-bit return value of a response.
type S7CommPlusReturn uint64

// ErrorCode returns the signed error code in bits 0-15; 0 is success.
func (r S7CommPlusReturn) ErrorCode() int16 { return int16(r) }

// OMSLine returns bits 16-31.
func (r S7CommPlusReturn) OMSLine() uint16 { return uint16(r >> s7plusRetOMSShift) }

// ErrorSource returns bits 32-39.
func (r S7CommPlusReturn) ErrorSource() uint8 { return uint8(r >> s7plusRetSourceShift) }

// GenericError returns the generic error code in bits 40-46.
func (r S7CommPlusReturn) GenericError() uint8 {
	return uint8(r>>s7plusRetGenericShift) & s7plusRetGenericMask
}

// ServerError reports bit 47.
func (r S7CommPlusReturn) ServerError() bool { return r&s7plusRetServerBit != 0 }

// Extension reports bit 62, the error extension: a DeleteObject
// response then carries an object.
func (r S7CommPlusReturn) Extension() bool { return r&s7plusRetExtensionBit != 0 }

// S7CommPlusAddress is a variable address of Get/SetMultiVariables:
//
//	symbol CRC | access area | LID count | sub-area | LID...
//
// LIDCount counts the sub-area and the LIDs. A DB area is 0x8A0E0000
// plus the DB number; I, Q, M, C and T are 80 to 84. With CRC 0 such an
// address can use classic blob access: LIDs 3, start offset, byte
// count[, bit offset].
type S7CommPlusAddress struct {
	SymbolCRC     uint32
	AccessArea    uint32
	LIDCount      uint32
	AccessSubArea uint32
	LIDs          []uint32
}

// DBNumber returns the DB number of a DB access area.
func (a *S7CommPlusAddress) DBNumber() (uint16, bool) {
	if a.AccessArea&s7plusAreaDBMask != s7plusAreaDBBase {
		return 0, false
	}
	return uint16(a.AccessArea), true
}

// S7CommPlusItemError is one entry of a response's error list.
type S7CommPlusItemError struct {
	Item   uint32
	Return S7CommPlusReturn
}

// S7CommPlusQualifier is the object qualifier after a variable access
// request.
type S7CommPlusQualifier struct {
	ID     uint32
	Values []S7CommPlusIDValue
}

// S7CommPlusExploreSet is one object/address set of an Explore request.
type S7CommPlusExploreSet struct {
	ObjectCount  uint8
	AddressCount uint8
	Datatype     S7CommPlusDatatype // set when ObjectCount > 0
	StructID     uint32             // Datatype STRUCT only
	Values       []S7CommPlusIDValue
	IDs          []uint32
}

// S7CommPlusExplore holds the Explore fields besides the area ID (the
// body's ObjectID): request filters, and the response's sequence
// integrity value (V3, and V2 from S7-1500s).
type S7CommPlusExplore struct {
	ExploreID         uint32
	ChildsRecursive   uint8
	Unknown3          uint8
	Parents           uint8
	Sets              []S7CommPlusExploreSet
	SequenceIntegrity uint32
	HasSeqIntegrity   bool
}

// S7CommPlusSequence holds the BeginSequence fields. V1 has only the
// transaction type, in the request.
type S7CommPlusSequence struct {
	TransactionType uint8
	ValueType       uint16
	RequestID       uint32
}

// S7CommPlusNotifyItem is one item of a notification value list. Code
// selects the rest: 0x92 reference and value, 0x9B ID and value, 0x83
// value, 0x81 objects, 0x9C reference, 0x13 and 0x03 the reference of
// an access error.
type S7CommPlusNotifyItem struct {
	Code     uint8
	ItemRef  uint32
	Value    *S7CommPlusValue
	Elements *S7CommPlusElements
}

// S7CommPlusNotification is the body of a notification. The sequence
// fields and value lists are present only when Unknown2 is 0x0400 (V2
// and V3) or V1Unknown3 is not 0 (V1). Subscriptions below 0x70000000
// count with a one-octet Sequence and no CreditTick; newer CPUs replace
// a zero change counter with a timestamp and a second counter.
type S7CommPlusNotification struct {
	SubscriptionID  uint32
	Unknown2        uint16
	Unknown3        uint16
	Unknown4        uint16
	CreditTick      uint8
	Sequence        uint32
	ChangeCounter   uint8
	Timestamp       uint64 // µs since 1970, when HasTimestamp
	HasTimestamp    bool
	Items           []S7CommPlusNotifyItem
	SubscriptionID2 uint32
	Unknown5        uint16
	Items2          []S7CommPlusNotifyItem
	V1Unknown2      uint32
	V1Unknown3      uint32
	V1Unknown4      uint16
}

// Time returns Timestamp as a UTC time.
func (n *S7CommPlusNotification) Time() time.Time {
	return time.UnixMicro(int64(n.Timestamp)).UTC()
}

// S7CommPlusBody is the decoded body of an S7comm-plus PDU. Which
// fields are set depends on opcode and function:
//
//	Request
//	  CreateObject       ObjectID (request ID), Value, InnerIntegrityID, Elements
//	  DeleteObject       ObjectID
//	  SetVariable        ObjectID, ItemCount, IDs (an ID 0 is followed by a raw length), Value
//	  GetVariable        ObjectID (relation ID), ItemCount, IDs
//	  SetMultiVariables  ObjectID (0: by address), ItemCount, FieldCount, Addresses or IDs, Values
//	  GetMultiVariables  ObjectID (0, or a link ID), ItemCount, FieldCount, Addresses or IDs
//	  Get/SetVarSubStreamed Values (4-octet IDs), Stream (Set)
//	  Explore            ObjectID (area), Explore
//	  GetLink            IDs
//	  BeginSequence      Sequence, Elements
//	  Invoke             ObjectID (sub-session), Values
//	Response
//	  all                Return
//	  CreateObject       ObjectIDs, Elements (V1)
//	  DeleteObject       ObjectID, Elements (error extension)
//	  GetVariable        Value
//	  GetMultiVariables  Values, Errors
//	  SetMultiVariables  Errors
//	  GetVarSubStreamed  Value
//	  Explore            ObjectID, Explore, Elements
//	  GetLink            ObjectIDs (link IDs)
//	  BeginSequence      Sequence
//	  Invoke             Returns, Values
//	Notification         Notification
//
// Unknown and fill octets the plugin does not name are skipped. Rest
// holds the octets after the integrity part, usually four zeros.
type S7CommPlusBody struct {
	Return           S7CommPlusReturn
	Returns          []S7CommPlusReturn
	ObjectID         uint32
	ObjectIDs        []uint32
	ItemCount        uint32
	FieldCount       uint32
	Addresses        []S7CommPlusAddress
	IDs              []uint32
	Value            *S7CommPlusValue
	Values           []S7CommPlusIDValue
	Errors           []S7CommPlusItemError
	Elements         *S7CommPlusElements
	Explore          *S7CommPlusExplore
	Sequence         *S7CommPlusSequence
	Notification     *S7CommPlusNotification
	Qualifier        *S7CommPlusQualifier
	Stream           *S7CommPlusValue
	InnerIntegrityID uint32
	HasInnerID       bool
	IntegrityID      uint32
	HasIntegrityID   bool
	Digest           []byte
	Rest             []byte
}

// s7plusQualified tells whether a request carries an object qualifier.
type s7plusQualified uint8

const (
	s7plusNoQualifier s7plusQualified = iota
	s7plusQualifier
)

// s7plusIntegrity tells whether the integrity part starts with an ID.
type s7plusIntegrity uint8

const (
	s7plusNoIntegrityID s7plusIntegrity = iota
	s7plusIntegrityID
)

// DecodeBody decodes Data of a frame that holds a whole PDU: one with
// a data header and a trailer. Fragments of larger PDUs return
// ErrS7CommPlusFragment; join them with an S7CommPlusAssembler and
// decode the PDU it returns. On error the returned body, when not
// nil, holds the fields decoded so far.
func (s *S7CommPlus) DecodeBody() (*S7CommPlusBody, error) {
	if !s.HasDataHeader || !s.HasTrailer {
		return nil, ErrS7CommPlusFragment
	}
	return DecodeS7CommPlusBody(s.Version, s.Opcode, s.Function, s.Data)
}

// DecodeS7CommPlusBody decodes the body that follows a data header with
// the given version, opcode and function (ignored for notifications).
func DecodeS7CommPlusBody(v S7CommPlusVersion, op S7CommPlusOpcode, fn S7CommPlusFunction, data []byte) (*S7CommPlusBody, error) {
	b := &S7CommPlusBody{}
	r := &s7plusReader{b: data}

	// V1 has no integrity ID; a DeleteObject response says itself.
	idf := s7plusIntegrityID
	if v == S7CommPlusV1 {
		idf = s7plusNoIntegrityID
	}

	qual := s7plusNoQualifier
	var err error
	switch op {
	case S7CommPlusOpNotification:
		b.Notification = r.notification(v)
	case S7CommPlusOpRequest:
		qual, err = b.request(r, v, fn)
	case S7CommPlusOpResponse, S7CommPlusOpResponse2:
		err = b.response(r, v, fn, &idf)
	default:
		err = fmt.Errorf("%w: opcode %v", ErrS7CommPlusUnsupported, op)
	}
	if err != nil {
		b.Rest = data
		return b, err
	}

	if qual == s7plusQualifier && len(r.b) > s7plusQualifierMin {
		b.Qualifier = &S7CommPlusQualifier{ID: r.u32()}
		b.Qualifier.Values = r.nested()
	}
	if op == S7CommPlusOpRequest {
		b.requestTail(r, fn)
	}
	b.integrity(r, v, idf)

	b.Rest = r.b
	return b, r.err
}

// request decodes the function fields of a request.
func (b *S7CommPlusBody) request(r *s7plusReader, v S7CommPlusVersion, fn S7CommPlusFunction) (s7plusQualified, error) {
	switch fn {
	case S7CommPlusFuncCreateObject:
		b.createObject(r, v)
	case S7CommPlusFuncDeleteObject:
		b.ObjectID = r.u32()
		r.u8()
		return s7plusQualifier, nil
	case S7CommPlusFuncSetVariable:
		b.setVariable(r)
		return s7plusQualifier, nil
	case S7CommPlusFuncGetVariable:
		b.ObjectID = r.u32()
		b.ItemCount = r.vu32()
		b.IDs = r.idArray(b.ItemCount)
		return s7plusQualifier, nil
	case S7CommPlusFuncSetMultiVariables:
		b.setMulti(r)
		return s7plusQualifier, nil
	case S7CommPlusFuncGetMultiVariables:
		b.getMulti(r)
		return s7plusQualifier, nil
	case S7CommPlusFuncGetVarSubStreamed, S7CommPlusFuncSetVarSubStreamed:
		b.Values = r.subItems()
		return s7plusQualifier, nil
	case S7CommPlusFuncExplore:
		b.exploreReq(r)
	case S7CommPlusFuncGetLink:
		r.bytes(s7plusGetLinkHead, "GetLink head")
		b.IDs = []uint32{r.vu32()}
		r.bytes(s7plusGetLinkTail, "GetLink tail")
	case S7CommPlusFuncBeginSequence:
		b.beginSeqReq(r, v)
	case S7CommPlusFuncEndSequence:
		r.bytes(s7plusEndSeqUnknown, "EndSequence")
	case S7CommPlusFuncInvoke:
		b.ObjectID = r.u32()
		r.bytes(s7plusInvokeHead, "Invoke head")
		b.Values = r.items()
		r.u8()
	case S7CommPlusFuncInitSSL:
	default:
		return s7plusNoQualifier, fmt.Errorf("%w: request %v", ErrS7CommPlusUnsupported, fn)
	}
	return s7plusNoQualifier, nil
}

// requestTail reads what follows the qualifier of some requests.
func (b *S7CommPlusBody) requestTail(r *s7plusReader, fn S7CommPlusFunction) {
	switch fn {
	case S7CommPlusFuncGetVarSubStreamed:
		r.bytes(s7plusSubStrTail, "GetVarSubStreamed tail")
	case S7CommPlusFuncSetVarSubStreamed:
		r.bytes(s7plusSubStrTail, "SetVarSubStreamed stream")
		v, _ := r.value()
		b.Stream = &v
	case S7CommPlusFuncSetVariable:
		r.u8()
	}
}

// response decodes the function fields of a response. idf is cleared
// when a DeleteObject response has no integrity ID.
func (b *S7CommPlusBody) response(r *s7plusReader, v S7CommPlusVersion, fn S7CommPlusFunction, idf *s7plusIntegrity) error {
	switch fn {
	case S7CommPlusFuncInvoke:
		b.invokeResp(r)
		return nil
	case S7CommPlusFuncError, S7CommPlusFuncError2, S7CommPlusFuncSetVariable,
		S7CommPlusFuncSetVarSubStreamed, S7CommPlusFuncEndSequence, S7CommPlusFuncInitSSL:
		b.Return = S7CommPlusReturn(r.vu64())
		return nil
	case S7CommPlusFuncGetMultiVariables, S7CommPlusFuncSetMultiVariables, S7CommPlusFuncGetVariable,
		S7CommPlusFuncCreateObject, S7CommPlusFuncDeleteObject, S7CommPlusFuncGetVarSubStreamed,
		S7CommPlusFuncExplore, S7CommPlusFuncGetLink, S7CommPlusFuncBeginSequence:
	default:
		return fmt.Errorf("%w: response %v", ErrS7CommPlusUnsupported, fn)
	}

	b.Return = S7CommPlusReturn(r.vu64())
	switch fn {
	case S7CommPlusFuncGetMultiVariables:
		b.Values = r.items()
		b.Errors = r.errorList()
	case S7CommPlusFuncSetMultiVariables:
		b.Errors = r.errorList()
	case S7CommPlusFuncGetVariable:
		val, _ := r.value()
		b.Value = &val
	case S7CommPlusFuncCreateObject:
		b.createResp(r, v)
	case S7CommPlusFuncDeleteObject:
		b.ObjectID = r.u32()
		if b.Return.Extension() {
			b.Elements = r.topElements()
		}

		// The integrity ID, when present, is not 0, and fill octets are.
		if r.peek() == 0 {
			*idf = s7plusNoIntegrityID
		}
	case S7CommPlusFuncGetVarSubStreamed:
		r.u8()
		val, level := r.value()
		r.members(&val, level)
		b.Value = &val
	case S7CommPlusFuncExplore:
		b.exploreResp(r, v)
	case S7CommPlusFuncGetLink:
		n := uint32(r.u8())
		if r.count(n, 4, "link IDs") {
			b.ObjectIDs = make([]uint32, n)
			for i := range b.ObjectIDs {
				b.ObjectIDs[i] = r.u32()
			}
		}
	case S7CommPlusFuncBeginSequence:
		if v != S7CommPlusV1 {
			b.Sequence = &S7CommPlusSequence{ValueType: r.u16(), RequestID: r.u32()}
		}
	}
	return nil
}

// integrity reads the integrity ID and, on V1/V2 PDUs with 32 octets
// or more left, the length-prefixed digest.
func (b *S7CommPlusBody) integrity(r *s7plusReader, v S7CommPlusVersion, idf s7plusIntegrity) {
	if r.err != nil {
		return
	}

	rem := len(r.b)
	withID := idf == s7plusIntegrityID && rem > s7plusIntegrityMin
	if v == S7CommPlusV3 || rem < s7plusDigestLen {
		if withID {
			b.IntegrityID, b.HasIntegrityID = r.vu32(), true
		}
		return
	}

	// The plugin guesses a DeleteObject response's integrity ID from a
	// non-zero next octet, which a bare digest length (32) also is: S7-1511
	// responses end in exactly length and digest, with no ID before them.
	bare := rem == 1+s7plusDigestLen && r.b[0] == s7plusDigestLen
	if idf == s7plusIntegrityID && !bare {
		b.IntegrityID, b.HasIntegrityID = r.vu32(), true
	}
	if n := r.u8(); n != s7plusDigestLen && r.err == nil {
		r.fail(fmt.Errorf("%w: integrity digest length %d", ErrS7CommPlusMalformed, n))
		return
	}
	b.Digest = r.bytes(s7plusDigestLen, "integrity digest")
}

// createObject reads a CreateObject request: request ID, value, 4
// unknown octets, an integrity ID on S7-1500s (V2/V3, recognised by
// not starting an object), then the objects to create.
func (b *S7CommPlusBody) createObject(r *s7plusReader, v S7CommPlusVersion) {
	b.ObjectID = r.u32()
	val, _ := r.value()
	b.Value = &val
	r.bytes(s7plusCreateUnknown, "CreateObject")

	if (v == S7CommPlusV2 || v == S7CommPlusV3) && r.peek() != s7plusElemStartObject {
		b.InnerIntegrityID, b.HasInnerID = r.vu32(), true
	}
	b.Elements = r.topElements()
}

// createResp reads the object IDs of a CreateObject response and, in
// V1 connection setup, the created object.
func (b *S7CommPlusBody) createResp(r *s7plusReader, v S7CommPlusVersion) {
	n := uint32(r.u8())
	b.ObjectIDs = r.idArray(n)
	if v == S7CommPlusV1 {
		b.Elements = r.topElements()
	}
}

// setVariable reads a SetVariable request: object ID, address count,
// IDs (an ID 0 is followed by a raw value length that counts as an
// address), then the value.
func (b *S7CommPlusBody) setVariable(r *s7plusReader) {
	b.ObjectID = r.u32()
	b.ItemCount = r.vu32()
	if !r.count(b.ItemCount, 1, "addresses") {
		return
	}

	b.IDs = make([]uint32, 0, b.ItemCount)
	for i := uint32(0); i < b.ItemCount && r.err == nil; i++ {
		id := r.vu32()
		b.IDs = append(b.IDs, id)
		if id == 0 {
			b.IDs = append(b.IDs, r.vu32())
			i++
		}
	}

	val, level := r.value()
	r.members(&val, level)
	b.Value = &val
}

// setMulti reads a SetMultiVariables request. A first word of 0 means
// addresses; otherwise it is an object ID and attribute IDs follow.
// Then one value per item and a fill octet.
func (b *S7CommPlusBody) setMulti(r *s7plusReader) {
	b.ObjectID = r.u32()
	b.ItemCount = r.vu32()
	b.FieldCount = r.vu32()
	if b.ObjectID == 0 {
		b.Addresses = r.addresses(b.ItemCount)
	} else {
		b.IDs = r.idArray(b.FieldCount)
	}

	if !r.count(b.ItemCount, 1, "values") {
		return
	}
	b.Values = make([]S7CommPlusIDValue, 0, b.ItemCount)
	for i := uint32(0); i < b.ItemCount && r.err == nil; i++ {
		if id := r.vu32(); id != s7plusTermID && r.err == nil {
			b.Values = append(b.Values, r.item(id).S7CommPlusIDValue)
		}
	}
	r.u8()
}

// getMulti reads a GetMultiVariables request: 0 and addresses, or a
// link ID and attribute IDs.
func (b *S7CommPlusBody) getMulti(r *s7plusReader) {
	b.ObjectID = r.u32()
	b.ItemCount = r.vu32()
	b.FieldCount = r.vu32()
	if b.ObjectID == 0 {
		b.Addresses = r.addresses(b.ItemCount)
		return
	}
	b.IDs = r.idArray(b.FieldCount)
}

// exploreReq reads an Explore request: area, explore ID, three flag
// octets, then object/address sets until one has no objects.
func (b *S7CommPlusBody) exploreReq(r *s7plusReader) {
	b.ObjectID = r.u32()
	e := &S7CommPlusExplore{ExploreID: r.vu32(), ChildsRecursive: r.u8(), Unknown3: r.u8(), Parents: r.u8()}
	b.Explore = e

	for r.err == nil {
		set := S7CommPlusExploreSet{ObjectCount: r.u8(), AddressCount: r.u8()}
		if set.ObjectCount > 0 {
			set.Datatype = S7CommPlusDatatype(r.u8())
			if set.Datatype == S7CommPlusTypeStruct {
				set.StructID = r.u32()
				set.Values = r.nested()
			}
		}
		set.IDs = r.idArray(uint32(set.AddressCount))

		e.Sets = append(e.Sets, set)
		if set.ObjectCount == 0 {
			break
		}
	}
}

// exploreResp reads an Explore response: area, the sequence integrity
// value where the plugin expects it, then the object tree.
func (b *S7CommPlusBody) exploreResp(r *s7plusReader, v S7CommPlusVersion) {
	b.ObjectID = r.u32()
	e := &S7CommPlusExplore{}
	b.Explore = e

	next := r.peek()
	if v == S7CommPlusV3 || (v == S7CommPlusV2 && next != s7plusElemStartObject && next != 0) {
		e.SequenceIntegrity, e.HasSeqIntegrity = r.vu32(), true
	}
	if r.peek() == s7plusElemStartObject {
		b.Elements = r.topElements()
	}
}

// beginSeqReq reads a BeginSequence request. A value type of 1 is
// followed by one or two unknown octets (S7-1200 firmware 2 drops one)
// and an object; any other by a request ID.
func (b *S7CommPlusBody) beginSeqReq(r *s7plusReader, v S7CommPlusVersion) {
	seq := &S7CommPlusSequence{TransactionType: r.u8()}
	b.Sequence = seq
	if v == S7CommPlusV1 {
		return
	}

	seq.ValueType = r.u16()
	if seq.ValueType != s7plusSeqObject {
		seq.RequestID = r.u32()
		return
	}

	skip := 2
	if r.need(2, "BeginSequence") && r.b[1] == s7plusElemStartObject {
		skip = 1
	}
	r.bytes(skip, "BeginSequence")
	b.Elements = r.topElements()
}

// invokeResp reads three return values, a fourth unless an item
// number 1 follows, the value list and an unknown octet.
func (b *S7CommPlusBody) invokeResp(r *s7plusReader) {
	const returns = 3
	for i := 0; i < returns; i++ {
		b.Returns = append(b.Returns, S7CommPlusReturn(r.vu64()))
	}
	if r.peek() != s7plusInvokeFirstItem {
		b.Returns = append(b.Returns, S7CommPlusReturn(r.vu64()))
	}

	b.Return = b.Returns[0]
	b.Values = r.items()
	r.u8()
}

// topElements reads a top-level element list (objects and friends).
func (r *s7plusReader) topElements() *S7CommPlusElements {
	es := &S7CommPlusElements{}
	if r.enter() {
		r.elements(es)
		r.leave()
	}
	return es
}

// nested reads an ID/value list one nesting level down.
func (r *s7plusReader) nested() []S7CommPlusIDValue {
	if !r.enter() {
		return nil
	}
	defer r.leave()
	return r.idList()
}

// items reads an item number/value list one nesting level down.
func (r *s7plusReader) items() []S7CommPlusIDValue {
	if !r.enter() {
		return nil
	}
	defer r.leave()
	return r.itemList()
}

// idArray reads n VLQ IDs.
func (r *s7plusReader) idArray(n uint32) []uint32 {
	if n == 0 || !r.count(n, 1, "IDs") {
		return nil
	}

	ids := make([]uint32, n)
	for i := range ids {
		ids[i] = r.vu32()
	}
	return ids
}

// addresses reads n variable addresses.
func (r *s7plusReader) addresses(n uint32) []S7CommPlusAddress {
	if !r.count(n, s7plusAddrMinLen, "addresses") {
		return nil
	}

	out := make([]S7CommPlusAddress, 0, n)
	for i := uint32(0); i < n && r.err == nil; i++ {
		out = append(out, r.address())
	}
	return out
}

// address reads one variable address. The plugin reads LIDCount-1
// LIDs, but at least three for classic blob access (CRC 0, DB or
// I/Q/M/C/T area, first LID 3).
func (r *s7plusReader) address() S7CommPlusAddress {
	a := S7CommPlusAddress{SymbolCRC: r.vu32(), AccessArea: r.vu32(), LIDCount: r.vu32(), AccessSubArea: r.vu32()}
	if r.err != nil || a.LIDCount <= 1 {
		return a
	}

	n := a.LIDCount - 1
	if a.classic() && n < s7plusClassicLIDs {
		if first, _, err := S7CommPlusVarUint32(r.b); err == nil && first == s7plusLIDClassicBlob {
			n = s7plusClassicLIDs
		}
	}
	a.LIDs = r.idArray(n)
	return a
}

// classic reports whether a may use classic blob access.
func (a *S7CommPlusAddress) classic() bool {
	if a.SymbolCRC != 0 {
		return false
	}
	_, db := a.DBNumber()
	return db || (a.AccessArea >= s7plusAreaIQMCTLo && a.AccessArea <= s7plusAreaIQMCTHi)
}

// errorList reads item number/return value pairs until item 0.
func (r *s7plusReader) errorList() []S7CommPlusItemError {
	var out []S7CommPlusItemError
	for r.err == nil {
		item := r.vu32()
		if item == 0 || r.err != nil {
			break
		}
		out = s7plusAppend(out, S7CommPlusItemError{Item: item, Return: S7CommPlusReturn(r.vu64())})
	}
	return out
}

// subItems reads the items of a Get/SetVarSubStreamed request, which
// use 4-octet IDs. As in the plugin, a struct level counter decides
// when the list ends: a STRUCT value opens a level (its members follow
// as items), a 4-octet 0 closes one, and the list ends at level 0.
// Members are attached to the struct they follow. A dry run counts
// the list and every member list first.
func (r *s7plusReader) subItems() []S7CommPlusIDValue {
	var out []S7CommPlusIDValue
	if h := r.ahead(r.subCount); h.n > 0 {
		out = make([]S7CommPlusIDValue, 0, h.n)
	}

	stack := []*[]S7CommPlusIDValue{&out}
	level := structLevel(0)
	for r.err == nil {
		id := r.u32()
		if r.err != nil {
			break
		}

		if id == s7plusTermID {
			level--
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		} else {
			level = r.subItem(&stack, id, level)
		}
		if level <= 0 {
			break
		}
	}
	return out
}

// subItem reads the value of one sub-streamed item, appends it to the
// list on top of stack, and opens its member list for a STRUCT. Only
// the top of stack is appended to, so the pointers below stay valid.
func (r *s7plusReader) subItem(stack *[]*[]S7CommPlusIDValue, id uint32, level structLevel) structLevel {
	v, l := r.value()
	cur := (*stack)[len(*stack)-1]
	*cur = s7plusAppend(*cur, S7CommPlusIDValue{ID: id, Value: v})
	if l < 0 {
		return -1
	}
	if l == 0 {
		return level
	}
	if len(*stack) > s7plusMaxDepth {
		r.fail(fmt.Errorf("%w: limit %d", ErrS7CommPlusTooDeep, s7plusMaxDepth))
		return 0
	}

	it := &(*cur)[len(*cur)-1]
	if h, ok := r.hint(); ok && h.n > 0 {
		it.Value.Members = make([]S7CommPlusIDValue, 0, h.n)
	}
	*stack = append(*stack, &it.Value.Members)
	return level + l
}

// subCount is the dry run of subItems: it notes the length of the
// list that starts here and of every member list, in stream order.
func (r *s7plusReader) subCount() {
	// One slot per open list: the top list and a member list per level.
	var slots [s7plusMaxDepth + 1]int
	top := 0
	slots[top] = r.note(s7plusNoSlot, len(r.b))

	level := structLevel(0)
	for r.err == nil {
		id := r.u32()
		if r.err != nil {
			break
		}

		if id == s7plusTermID {
			level--
			if top > 0 {
				top--
			}
		} else {
			_, l := r.value()
			r.hints[slots[top]].n++
			if l < 0 || (l > 0 && top == s7plusMaxDepth) {
				break
			}
			if l > 0 {
				top++
				slots[top] = r.note(s7plusNoSlot, len(r.b))
				level += l
			}
		}
		if level <= 0 {
			break
		}
	}
}

// notification reads a notification body.
func (r *s7plusReader) notification(v S7CommPlusVersion) *S7CommPlusNotification {
	n := &S7CommPlusNotification{SubscriptionID: r.u32()}
	if v == S7CommPlusV1 {
		r.notifyV1(n)
		return n
	}

	n.Unknown2 = r.u16()
	n.Unknown3 = r.u16()
	if n.Unknown2 != s7plusNotifyValues {
		return n
	}

	n.Unknown4 = r.u16()
	r.notifySeq(n)
	n.Items = r.notifyList()

	// A second part (ProgramAlarm events): subscription ID, unknown
	// word, value list.
	if r.peek() == 0 {
		return n
	}
	n.SubscriptionID2 = r.u32()
	n.Unknown5 = r.u16()
	n.Items2 = r.notifyList()
	return n
}

// notifySeq reads the credit tick, sequence number and change counter
// of a notification.
func (r *s7plusReader) notifySeq(n *S7CommPlusNotification) {
	if n.SubscriptionID < s7plusNotifyVLQSeq {
		n.Sequence = uint32(r.u8())
		n.ChangeCounter = r.u8()
		return
	}

	n.CreditTick = r.u8()
	n.Sequence = r.vu32()
	if r.peek() == 0 {
		n.Timestamp, n.HasTimestamp = r.u64(), true
	}
	n.ChangeCounter = r.u8()
}

// notifyV1 reads the rest of a V1 notification: values follow only
// when the third word is not 0.
func (r *s7plusReader) notifyV1(n *S7CommPlusNotification) {
	n.V1Unknown2 = r.u32()
	if !r.need(4, "notification") || r.b[0]|r.b[1]|r.b[2]|r.b[3] == 0 {
		return
	}

	n.V1Unknown3 = r.u32()
	n.V1Unknown4 = r.u16()
	n.Items = r.notifyList()
}

// notifyList reads notification items until code 0.
func (r *s7plusReader) notifyList() []S7CommPlusNotifyItem {
	var out []S7CommPlusNotifyItem
	if !r.enter() {
		return nil
	}
	defer r.leave()

	for r.err == nil {
		code := r.u8()
		if code == s7plusNotifyEnd || r.err != nil {
			break
		}
		out = s7plusAppend(out, r.notifyItem(code))
	}
	return out
}

// notifyItem reads the item after its code.
func (r *s7plusReader) notifyItem(code uint8) S7CommPlusNotifyItem {
	it := S7CommPlusNotifyItem{Code: code}
	withValue := false

	switch code {
	case s7plusNotifyValue:
		it.ItemRef = r.u32()
		withValue = true
	case s7plusNotifyIDValue:
		it.ItemRef = r.vu32()
		withValue = true
	case s7plusNotifyValueV1:
		withValue = true
	case s7plusNotifyVarTabRef, s7plusNotifyAddrErr, s7plusNotifyAddrErr2:
		it.ItemRef = r.u32()
	case s7plusNotifyObject:
		it.Elements = r.topElements()
	default:
		r.fail(fmt.Errorf("%w: notification item code 0x%02X", ErrS7CommPlusUnknownType, code))
	}

	if withValue {
		v, level := r.value()
		r.members(&v, level)
		it.Value = &v
	}
	return it
}
