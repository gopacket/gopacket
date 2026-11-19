// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// IEC 62351-5 secure authentication ASDUs of IEC 60870-5-7, as Wireshark's
// packet-iec104.c dissects them, and the IEC 60870-5-101 field sizes.
//
// The types S_CH_NA_1 (81) to S_ER_NA_1 (87) carry no information
// objects. Their body may be longer than one APDU, so it is cut into
// segments, each behind a segment sequence octet:
//
//	+-----+----+-----+-------------------+
//	| DUI | ASN | segment of the body ... |      ASN: FIN FIR number(6)
//	+-----+----+-----+-------------------+
//
//	S_CH_NA_1  CSQ(4) USR(2) MAL(1) RSC(1) CLN(2) challenge data(CLN)
//	S_RP_NA_1  CSQ(4) USR(2) HLN(2) MAC(HLN)
//	S_AR_NA_1  ASDU with one object, CSQ(4) USR(2) MAC(rest)
//	S_KS_NA_1  KSQ(4) USR(2) KWA(1) KST(1) HAL(1) CLN(2) challenge data(CLN) MAC
//	S_KC_NA_1  KSQ(4) USR(2) WKL(2) wrapped key data(WKL)
//	S_ER_NA_1  CSQ(4) USR(2) AID(2) ERR(1) ETM(7) ELN(2) error text(ELN)
//
// S_KR_NA_1 (84) is not segmented: its body is USR alone.
//
// A body that fits one segment (FIR and FIN both set) is decoded in place.
// Longer ones need IEC104SecurityAssembler.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Secure authentication type identifications. The comment of each names
// its mnemonic, which String returns.
const (
	IEC104TypeAuthChallenge    IEC104TypeID = 81 // S_CH_NA_1
	IEC104TypeAuthReply        IEC104TypeID = 82 // S_RP_NA_1
	IEC104TypeAuthAggressive   IEC104TypeID = 83 // S_AR_NA_1
	IEC104TypeKeyStatusRequest IEC104TypeID = 84 // S_KR_NA_1
	IEC104TypeKeyStatus        IEC104TypeID = 85 // S_KS_NA_1
	IEC104TypeKeyChange        IEC104TypeID = 86 // S_KC_NA_1
	IEC104TypeAuthError        IEC104TypeID = 87 // S_ER_NA_1
	IEC104TypeUserStatusChange IEC104TypeID = 90 // S_US_NA_1
	IEC104TypeUpdateKeyRequest IEC104TypeID = 91 // S_UQ_NA_1
	IEC104TypeUpdateKeyReply   IEC104TypeID = 92 // S_UR_NA_1
	IEC104TypeUpdateKeySym     IEC104TypeID = 93 // S_UK_NA_1
	IEC104TypeUpdateKeyAsym    IEC104TypeID = 94 // S_UA_NA_1
	IEC104TypeUpdateKeyConfirm IEC104TypeID = 95 // S_UC_NA_1
)

// Secure authentication body layout.
const (
	iec104SecurityBodyFirst = IEC104TypeAuthChallenge
	iec104SecurityBodyLast  = IEC104TypeAuthError

	iec104ASNMask     = 0x3F
	iec104ASNFirstBit = 0x40
	iec104ASNFinalBit = 0x80
	iec104ASNLen      = 1

	iec104USRLen = 2
	iec104SeqLen = 4 // CSQ, KSQ
	iec104LenLen = 2 // HLN, CLN, WKL, ELN
	iec104AIDLen = 2
	iec104ETMLen = 7

	// Codes from here up are a vendor's choice in MAL, HAL, KWA and ERR.
	iec104VendorFirst = 128

	iec104MaxIOALen          = 3
	iec104DefaultSecurityCap = 64 << 10
)

// iec104SecurityNames holds the mnemonics of the secure authentication
// types. S_US_NA_1 to S_UC_NA_1 are named only: like Wireshark, the
// decoder leaves their body in IEC104ASDU.Raw.
var iec104SecurityNames = map[IEC104TypeID]string{
	IEC104TypeAuthChallenge:    "S_CH_NA_1",
	IEC104TypeAuthReply:        "S_RP_NA_1",
	IEC104TypeAuthAggressive:   "S_AR_NA_1",
	IEC104TypeKeyStatusRequest: "S_KR_NA_1",
	IEC104TypeKeyStatus:        "S_KS_NA_1",
	IEC104TypeKeyChange:        "S_KC_NA_1",
	IEC104TypeAuthError:        "S_ER_NA_1",
	IEC104TypeUserStatusChange: "S_US_NA_1",
	IEC104TypeUpdateKeyRequest: "S_UQ_NA_1",
	IEC104TypeUpdateKeyReply:   "S_UR_NA_1",
	IEC104TypeUpdateKeySym:     "S_UK_NA_1",
	IEC104TypeUpdateKeyAsym:    "S_UA_NA_1",
	IEC104TypeUpdateKeyConfirm: "S_UC_NA_1",
}

var (
	// ErrIEC104SecurityTooShort is returned when a secure authentication
	// body ends before its fields do.
	ErrIEC104SecurityTooShort = errors.New("IEC 104 security ASDU truncated")
	// ErrIEC104BadOptions is returned for field sizes IEC 60870-5-101 does
	// not allow.
	ErrIEC104BadOptions = errors.New("IEC 104 ASDU field sizes invalid")
	// ErrIEC104SecurityTooLong is returned when the segments of a body
	// exceed the assembler's limit.
	ErrIEC104SecurityTooLong = errors.New("IEC 104 security ASDU exceeds limit")
	// ErrIEC104SecuritySequence is returned for a segment that does not
	// continue the body being assembled.
	ErrIEC104SecuritySequence = errors.New("IEC 104 security segment out of sequence")
)

// hasSecurityBody reports whether the type carries a secure authentication
// body rather than information objects.
func (t IEC104TypeID) hasSecurityBody() bool {
	return t >= iec104SecurityBodyFirst && t <= iec104SecurityBodyLast
}

// IEC104MACAlgorithm is MAL or HAL, the MAC algorithm.
type IEC104MACAlgorithm uint8

// MAC algorithms (IEC 62351-5, MAL). Wireshark names 1 to 4 and reads 6
// as AES-GMAC.
const (
	IEC104MACNone      IEC104MACAlgorithm = 0
	IEC104MACSHA1x4    IEC104MACAlgorithm = 1 // HMAC SHA-1 truncated to 4 octets
	IEC104MACSHA1x10   IEC104MACAlgorithm = 2
	IEC104MACSHA256x8  IEC104MACAlgorithm = 3
	IEC104MACSHA256x16 IEC104MACAlgorithm = 4
	IEC104MACSHA1x8    IEC104MACAlgorithm = 5 // HMAC SHA-1 truncated to 8 octets
	IEC104MACAESGMAC   IEC104MACAlgorithm = 6 // 12 octets
)

// MAC lengths in octets.
const (
	iec104MACLenSHA1x4    = 4
	iec104MACLenSHA1x10   = 10
	iec104MACLenSHA256x8  = 8
	iec104MACLenSHA256x16 = 16
	iec104MACLenSHA1x8    = 8
	iec104MACLenGMAC      = 12
)

// String returns the algorithm as Wireshark names it.
func (m IEC104MACAlgorithm) String() string {
	switch {
	case m == IEC104MACNone:
		return "(not used)"
	case m == IEC104MACSHA1x4:
		return "HMAC SHA-1 truncated to 4 octets (serial)"
	case m == IEC104MACSHA1x10:
		return "HMAC SHA-1 truncated to 10 octets (networked)"
	case m == IEC104MACSHA256x8:
		return "HMAC-SHA-256 truncated to 8 octets (serial)"
	case m == IEC104MACSHA256x16:
		return "HMAC-SHA-256 truncated to 16 octets (networked)"
	case m == IEC104MACSHA1x8:
		return "HMAC SHA-1 truncated to 8 octets (serial)"
	case m == IEC104MACAESGMAC:
		return "AES-GMAC"
	case m >= iec104VendorFirst:
		return "(vendor-specific choice)"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(m))
}

// Size returns the MAC length in octets, or 0 when the algorithm does not
// fix one.
func (m IEC104MACAlgorithm) Size() int {
	switch m {
	case IEC104MACSHA1x4:
		return iec104MACLenSHA1x4
	case IEC104MACSHA1x10:
		return iec104MACLenSHA1x10
	case IEC104MACSHA256x8:
		return iec104MACLenSHA256x8
	case IEC104MACSHA256x16:
		return iec104MACLenSHA256x16
	case IEC104MACSHA1x8:
		return iec104MACLenSHA1x8
	case IEC104MACAESGMAC:
		return iec104MACLenGMAC
	}
	return 0
}

// IEC104User is USR, the user number (IEC 62351-5).
type IEC104User uint16

// User numbers with a fixed meaning; the rest are handed out by the
// controlling station.
const (
	IEC104UserUnknown IEC104User = 0
	IEC104UserDefault IEC104User = 1
)

// String returns the user as Wireshark names it.
func (u IEC104User) String() string {
	switch u {
	case IEC104UserUnknown:
		return "(Unknown)"
	case IEC104UserDefault:
		return "Default"
	}
	return fmt.Sprintf("Chosen by the controlling station(%d)", uint16(u))
}

// IEC104ChallengeReason is RSC, the reason for a challenge.
type IEC104ChallengeReason uint8

// IEC104ReasonCritical is the one reason IEC 62351-5 defines: the
// challenged ASDU is a critical function.
const IEC104ReasonCritical IEC104ChallengeReason = 1

// String returns the reason as Wireshark names it.
func (r IEC104ChallengeReason) String() string {
	switch r {
	case 0:
		return "(not used)"
	case IEC104ReasonCritical:
		return "CRITICAL"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(r))
}

// USR returns the user number as a named value.
func (s *IEC104Security) USR() IEC104User { return IEC104User(s.User) }

// RSC returns the reason for challenge as a named value.
func (s *IEC104Security) RSC() IEC104ChallengeReason { return IEC104ChallengeReason(s.Reason) }

// IEC104KeyWrap is KWA, the key wrap algorithm.
type IEC104KeyWrap uint8

// Key wrap algorithms.
const (
	IEC104KeyWrapAES128 IEC104KeyWrap = 1
	IEC104KeyWrapAES256 IEC104KeyWrap = 2
)

// String returns the algorithm as Wireshark names it.
func (k IEC104KeyWrap) String() string {
	switch {
	case k == 0:
		return "(not used)"
	case k == IEC104KeyWrapAES128:
		return "AES-128 Key Wrap Algorithm"
	case k == IEC104KeyWrapAES256:
		return "AES-256 Key Wrap Algorithm"
	case k >= iec104VendorFirst:
		return "(vendor-specific choice)"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(k))
}

// IEC104KeyStatus is KST, the session key status.
type IEC104KeyStatus uint8

// Session key states.
const (
	IEC104KeyStatusOK       IEC104KeyStatus = 1
	IEC104KeyStatusNotInit  IEC104KeyStatus = 2
	IEC104KeyStatusCommFail IEC104KeyStatus = 3
	IEC104KeyStatusAuthFail IEC104KeyStatus = 4
)

// String returns the status as Wireshark names it.
func (k IEC104KeyStatus) String() string {
	switch k {
	case 0:
		return "(not used)"
	case IEC104KeyStatusOK:
		return "OK"
	case IEC104KeyStatusNotInit:
		return "NOT INIT"
	case IEC104KeyStatusCommFail:
		return "COMM FAIL"
	case IEC104KeyStatusAuthFail:
		return "AUTH FAIL"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(k))
}

// IEC104AuthErrorCode is ERR, the error code of S_ER_NA_1.
type IEC104AuthErrorCode uint8

// iec104AuthErrors names the error codes as Wireshark does; the index is
// the code.
var iec104AuthErrors = [...]string{
	"(not used)",
	"Authentication failed",
	"Unexpected reply",
	"No reply",
	"Aggressive Mode not permitted",
	"MAC algorithm not permitted",
	"Key Wrap algorithm not permitted",
	"Authorization failed",
	"Update Key Change Method not permitted",
	"Invalid Signature",
	"Invalid Certification Data",
	"Unknown User",
}

// String returns the error as Wireshark names it.
func (e IEC104AuthErrorCode) String() string {
	switch {
	case int(e) < len(iec104AuthErrors):
		return iec104AuthErrors[e]
	case e >= iec104VendorFirst:
		return "(vendor-specific choice)"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(e))
}

// IEC104Security is the body of a secure authentication ASDU. Which
// fields are set depends on the type identification; the others stay
// zero. Slices alias the packet data.
type IEC104Security struct {
	// SegmentNumber, First and Final are ASN, FIR and FIN of the segment
	// sequence octet. S_KR_NA_1 has none.
	SegmentNumber uint8
	First         bool
	Final         bool
	// Segment holds the octets after the segment sequence octet.
	Segment []byte
	// Decoded reports whether the fields below were read from the body.
	// It stays false for a segment that is not a whole body.
	Decoded bool

	// Sequence is CSQ, the challenge sequence number, or KSQ, the key
	// change sequence number.
	Sequence uint32
	// User is USR, the user number.
	User uint16
	// MACAlgorithm is MAL of a challenge or HAL of a key status.
	MACAlgorithm IEC104MACAlgorithm
	// Reason is RSC, the reason for challenge; 1 is CRITICAL.
	Reason uint8
	// Challenge is the pseudo-random challenge data.
	Challenge []byte
	// MAC is the MAC value.
	MAC       []byte
	KeyWrap   IEC104KeyWrap   // KWA
	KeyStatus IEC104KeyStatus // KST
	// WrappedKey is the wrapped key data of S_KC_NA_1.
	WrappedKey []byte
	// AssociationID, ErrorCode, ErrorTime and ErrorText are AID, ERR, ETM
	// and the text of S_ER_NA_1.
	AssociationID uint16
	ErrorCode     IEC104AuthErrorCode
	ErrorTime     IEC104Time
	ErrorText     []byte
	// EncapsulatedRaw is the ASDU an S_AR_NA_1 authenticates; Encapsulated
	// is that ASDU decoded, or nil when it is itself a secure
	// authentication type.
	EncapsulatedRaw []byte
	Encapsulated    *IEC104ASDU
}

// decode reads the body of an ASDU of type t and returns the octets it
// left over.
func (s *IEC104Security) decode(t IEC104TypeID, body []byte, f iec104Fields) ([]byte, error) {
	// A session key status request is the user number, unsegmented.
	if t == IEC104TypeKeyStatusRequest {
		if len(body) < iec104USRLen {
			return nil, ErrIEC104SecurityTooShort
		}
		s.User = binary.LittleEndian.Uint16(body)
		s.Decoded = true
		return body[iec104USRLen:], nil
	}

	if len(body) < iec104ASNLen {
		return nil, ErrIEC104SecurityTooShort
	}
	s.SegmentNumber = body[0] & iec104ASNMask
	s.First = body[0]&iec104ASNFirstBit != 0
	s.Final = body[0]&iec104ASNFinalBit != 0
	s.Segment = body[iec104ASNLen:]

	// Part of a longer body: the fields need the other segments.
	if !s.First || !s.Final {
		return nil, nil
	}
	return s.decodeBody(t, s.Segment, f)
}

// DecodeBody reads a whole secure authentication body of type t, such as
// IEC104SecurityAssembler returns, into the fields of s and returns the
// octets left over. The segment fields of s are kept.
func (s *IEC104Security) DecodeBody(t IEC104TypeID, body []byte, opts IEC104ASDUOptions) ([]byte, error) {
	f, err := opts.fields()
	if err != nil {
		return nil, err
	}

	*s = IEC104Security{SegmentNumber: s.SegmentNumber, First: s.First, Final: s.Final, Segment: s.Segment}
	return s.decodeBody(t, body, f)
}

// decodeBody reads the fields of a whole body.
func (s *IEC104Security) decodeBody(t IEC104TypeID, body []byte, f iec104Fields) ([]byte, error) {
	r := iec104Reader{data: body}

	switch t {
	case IEC104TypeAuthChallenge:
		s.Sequence = r.uint(iec104SeqLen)
		s.User = uint16(r.uint(iec104USRLen))
		s.MACAlgorithm = IEC104MACAlgorithm(r.uint(1))
		s.Reason = uint8(r.uint(1))
		s.Challenge = r.counted()
	case IEC104TypeAuthReply:
		s.Sequence = r.uint(iec104SeqLen)
		s.User = uint16(r.uint(iec104USRLen))
		s.MAC = r.counted()
	case IEC104TypeAuthAggressive:
		s.decodeAggressive(&r, f)
	case IEC104TypeKeyStatus:
		s.decodeKeyStatus(&r)
	case IEC104TypeKeyChange:
		s.Sequence = r.uint(iec104SeqLen)
		s.User = uint16(r.uint(iec104USRLen))
		s.WrappedKey = r.counted()
	case IEC104TypeAuthError:
		s.Sequence = r.uint(iec104SeqLen)
		s.User = uint16(r.uint(iec104USRLen))
		s.AssociationID = uint16(r.uint(iec104AIDLen))
		s.ErrorCode = IEC104AuthErrorCode(r.uint(1))
		if etm := r.take(iec104ETMLen); etm != nil {
			s.ErrorTime = iec104DecodeTime(etm)
		}
		s.ErrorText = r.counted()
	default:
		return body, nil
	}

	if r.err != nil {
		return nil, r.err
	}
	s.Decoded = true
	return r.data, nil
}

// decodeKeyStatus reads an S_KS_NA_1 body. HAL fixes the MAC length; a
// vendor's algorithm takes the rest. Wireshark reads a MAC for HAL 3, 4
// and 6 only; the SHA-1 lengths of HAL 1 and 2 come from their names.
func (s *IEC104Security) decodeKeyStatus(r *iec104Reader) {
	s.Sequence = r.uint(iec104SeqLen)
	s.User = uint16(r.uint(iec104USRLen))
	s.KeyWrap = IEC104KeyWrap(r.uint(1))
	s.KeyStatus = IEC104KeyStatus(r.uint(1))
	s.MACAlgorithm = IEC104MACAlgorithm(r.uint(1))
	s.Challenge = r.counted()

	switch size := s.MACAlgorithm.Size(); {
	case size != 0:
		s.MAC = r.take(size)
	case s.MACAlgorithm >= iec104VendorFirst:
		s.MAC = r.take(len(r.data))
	}
}

// decodeAggressive reads an S_AR_NA_1 body: an ASDU with one information
// object, then the sequence number, user and MAC that authenticate it.
func (s *IEC104Security) decodeAggressive(r *iec104Reader, f iec104Fields) {
	if len(r.data) == 0 {
		r.err = ErrIEC104SecurityTooShort
		return
	}

	// The ASDU has no length of its own: its type fixes it, as in
	// Wireshark. An unknown type counts as an address without elements.
	inner := IEC104TypeID(r.data[0])
	size := iec104TypeVSQLen + f.cot + f.ca + f.ioa
	for _, part := range iec104Types[inner].parts {
		size += iec104PartSize[part]
	}
	s.EncapsulatedRaw = r.take(size)

	// A nested secure authentication ASDU stays raw, so that a body
	// cannot nest decoders.
	if r.err == nil && !inner.hasSecurityBody() {
		s.Encapsulated = &IEC104ASDU{}
		r.err = s.Encapsulated.decode(s.EncapsulatedRaw, f)
	}

	s.Sequence = r.uint(iec104SeqLen)
	s.User = uint16(r.uint(iec104USRLen))
	s.MAC = r.take(len(r.data))
}

// iec104Reader takes little endian fields off the front of data. The
// first field that does not fit sets err, and later reads return zero.
type iec104Reader struct {
	data []byte
	err  error
}

// take returns the next n octets, or nil when they are not there.
func (r *iec104Reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if len(r.data) < n {
		r.err = ErrIEC104SecurityTooShort
		return nil
	}

	b := r.data[:n]
	r.data = r.data[n:]
	return b
}

// uint reads a little endian value of n octets, at most four.
func (r *iec104Reader) uint(n int) uint32 {
	return iec104UintLE(r.take(n))
}

// counted reads a 2-octet length and that many octets, e.g. CLN and the
// challenge data.
func (r *iec104Reader) counted() []byte {
	return r.take(int(r.uint(iec104LenLen)))
}

// IEC104ASDUOptions sets the sizes of the ASDU fields IEC 60870-5-101
// leaves to the system. A zero size selects the IEC 60870-5-104 value.
type IEC104ASDUOptions struct {
	// COTSize is the size of the cause of transmission: 1, or 2 with an
	// originator address.
	COTSize int
	// CommonAddrSize is the size of the common address: 1 or 2.
	CommonAddrSize int
	// IOASize is the size of the information object address: 1 to 3.
	IOASize int
}

// iec104Fields is IEC104ASDUOptions checked and with its defaults set.
type iec104Fields struct {
	cot, ca, ioa int
}

// iec104DefaultFields are the field sizes of IEC 60870-5-104.
var iec104DefaultFields = iec104Fields{cot: iec104COTLen, ca: iec104CALen, ioa: iec104IOALen}

// fields checks the options and fills in the defaults.
func (o IEC104ASDUOptions) fields() (iec104Fields, error) {
	f := iec104Fields{cot: o.COTSize, ca: o.CommonAddrSize, ioa: o.IOASize}
	if f.cot == 0 {
		f.cot = iec104COTLen
	}
	if f.ca == 0 {
		f.ca = iec104CALen
	}
	if f.ioa == 0 {
		f.ioa = iec104IOALen
	}

	if f.cot < 1 || f.cot > iec104COTLen || f.ca < 1 || f.ca > iec104CALen ||
		f.ioa < 1 || f.ioa > iec104MaxIOALen {
		return f, ErrIEC104BadOptions
	}
	return f, nil
}

// DecodeWithOptions decodes an ASDU, starting at its type identification,
// with the field sizes of opts. It serves IEC 60870-5-101 systems, which
// may use a 1-octet cause of transmission or common address and a 1- or
// 2-octet object address. The Objects slice of a is reused.
func (a *IEC104ASDU) DecodeWithOptions(data []byte, opts IEC104ASDUOptions) error {
	f, err := opts.fields()
	if err != nil {
		return err
	}

	*a = IEC104ASDU{Objects: a.Objects[:0]}
	return a.decode(data, f)
}

// DecodeIEC104ASDU decodes an ASDU with the field sizes of opts; see
// IEC104ASDU.DecodeWithOptions.
func DecodeIEC104ASDU(data []byte, opts IEC104ASDUOptions) (*IEC104ASDU, error) {
	a := &IEC104ASDU{}
	if err := a.DecodeWithOptions(data, opts); err != nil {
		return nil, err
	}
	return a, nil
}

// IEC104SecurityAssembler joins the segments of a secure authentication
// body that spans several ASDUs. It follows one direction of one
// connection; the zero value is ready to use.
type IEC104SecurityAssembler struct {
	// MaxSize caps the body in octets; 0 means 64 KiB.
	MaxSize int

	body   []byte
	next   uint8
	active bool
}

// Add takes the segment of a decoded ASDU. It returns the whole body once
// its final segment arrives, and nil before that. The body is a copy,
// valid until the next call; pass it to IEC104Security.DecodeBody.
//
// A first segment restarts the assembler. A segment that does not carry
// the next sequence number, or that would grow the body past MaxSize,
// drops the body and returns an error.
func (m *IEC104SecurityAssembler) Add(s *IEC104Security) ([]byte, error) {
	limit := m.MaxSize
	if limit <= 0 {
		limit = iec104DefaultSecurityCap
	}

	if s.First {
		m.body = m.body[:0]
		m.next = s.SegmentNumber
		m.active = true
	}

	if !m.active || s.SegmentNumber != m.next {
		m.active = false
		return nil, ErrIEC104SecuritySequence
	}
	if len(m.body)+len(s.Segment) > limit {
		m.active = false
		return nil, ErrIEC104SecurityTooLong
	}

	m.body = append(m.body, s.Segment...)
	m.next = (m.next + 1) & iec104ASNMask
	if !s.Final {
		return nil, nil
	}

	m.active = false
	return m.body, nil
}
