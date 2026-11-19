// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// BACnet network security (ASHRAE 135-2016 Clause 24, removed in
// 135-2020): the security wrapper of Clause 24.2, which follows the message
// type of the network security messages 0x0A to 0x11 and is the whole body
// of a Secure-BVLL, and the messages of Clause 24.3 it carries. Nothing is
// decrypted or verified: an encrypted wrapper keeps its service data as
// the octets on the wire.

package layers

import (
	"encoding/binary"

	"github.com/gopacket/gopacket"
)

// Security wrapper layout (Clause 24.2).
const (
	// control, key revision, key identifier, source device instance,
	// message ID, timestamp.
	bacnetSecurityFixedLen = 15

	// Offsets of the fixed fields after control and key revision.
	bacnetSecurityKeyAt     = 2
	bacnetSecuritySourceAt  = 4
	bacnetSecurityMessageAt = 7
	bacnetSecurityTimeAt    = 11

	bacnetSecuritySignatureLen = 16
	bacnetDeviceInstanceLen    = 3
	// authentication mechanism, user ID, user role.
	bacnetSecurityAuthLen = 4
	// user ID, user role and length: what the length of the
	// authentication data counts besides the data.
	bacnetSecurityAuthFixedLen = 5
	// bacnetSecurityVendorAuth is the first authentication mechanism that
	// belongs to a vendor, whose identifier then follows the length.
	bacnetSecurityVendorAuth uint8 = 200
)

// BACnetSecurityControl is the control octet of a security wrapper
// (Clause 24.2.2).
type BACnetSecurityControl uint8

// Security wrapper control bits.
const (
	bacnetSecurityNetworkMessage BACnetSecurityControl = 0x80
	bacnetSecurityEncrypted      BACnetSecurityControl = 0x40
	bacnetSecurityAuthPresent    BACnetSecurityControl = 0x10
	bacnetSecurityDoNotUnwrap    BACnetSecurityControl = 0x08
	bacnetSecurityDoNotDecrypt   BACnetSecurityControl = 0x04
	bacnetSecurityNonTrusted     BACnetSecurityControl = 0x02
	bacnetSecurityByRouter       BACnetSecurityControl = 0x01
)

// NetworkMessage reports whether the wrapped message is a network layer
// message rather than an APDU.
func (c BACnetSecurityControl) NetworkMessage() bool { return c&bacnetSecurityNetworkMessage != 0 }

// Encrypted reports whether the wrapper is encrypted from the destination
// device instance on.
func (c BACnetSecurityControl) Encrypted() bool { return c&bacnetSecurityEncrypted != 0 }

// AuthenticationPresent reports whether authentication data follows the
// addresses.
func (c BACnetSecurityControl) AuthenticationPresent() bool { return c&bacnetSecurityAuthPresent != 0 }

// DoNotUnwrap reports whether routers must pass the message on wrapped.
func (c BACnetSecurityControl) DoNotUnwrap() bool { return c&bacnetSecurityDoNotUnwrap != 0 }

// DoNotDecrypt reports whether routers must pass the message on encrypted.
func (c BACnetSecurityControl) DoNotDecrypt() bool { return c&bacnetSecurityDoNotDecrypt != 0 }

// NonTrustedSource reports whether the message came from a non-trusted
// source.
func (c BACnetSecurityControl) NonTrustedSource() bool { return c&bacnetSecurityNonTrusted != 0 }

// SecuredByRouter reports whether a router, not the source, secured the
// message.
func (c BACnetSecurityControl) SecuredByRouter() bool { return c&bacnetSecurityByRouter != 0 }

// BACnetSecurityWrapper is the header and trailer that secure a BACnet
// message (Clause 24.2). The fields from DestinationDevice to
// AuthenticationData, and Message, are readable only when the wrapper is
// not encrypted.
//
//	control | key rev | key id | source device | message id | timestamp
//	  | destination device | DNET DLEN DADR | SNET SLEN SADR
//	  | [mechanism | user id | user role | [length | [vendor id] | data]]
//	  | service data | [padding] | signature (16)
type BACnetSecurityWrapper struct {
	Control     BACnetSecurityControl
	KeyRevision uint8
	// KeyIdentifier is the key algorithm (high octet) and key number.
	KeyIdentifier uint16
	// SourceDevice is the device instance of the source.
	SourceDevice uint32
	MessageID    uint32
	// Timestamp is the time the message was secured, in seconds since
	// 1970-01-01 UTC.
	Timestamp uint32

	DestinationDevice uint32
	DNET              uint16
	DADR              []byte
	SNET              uint16
	SADR              []byte

	// AuthenticationMechanism, UserID and UserRole are set when the
	// control octet says authentication data is present.
	AuthenticationMechanism uint8
	UserID                  uint16
	UserRole                uint8
	// AuthenticationVendorID names the vendor of a mechanism from 200 on.
	AuthenticationVendorID uint16
	// AuthenticationData belongs to a mechanism other than 0.
	AuthenticationData []byte

	// ServiceData is what the wrapper secures, as octets: the message, or
	// for an encrypted wrapper (Control.Encrypted) every octet from the
	// destination device instance to the padding, still encrypted.
	ServiceData []byte
	// Message is ServiceData decoded as the network security message that
	// carries the wrapper. It is nil when the wrapper is encrypted, when
	// it is the body of a Secure-BVLL, and when ServiceData is too short
	// for the message.
	Message BACnetSecurityMessage
	// Signature is the HMAC that ends the wrapper.
	Signature []byte
}

// decodeBACnetSecurity decodes a security wrapper that takes all of data.
// The message it secures is not decoded: see decodeMessage.
func decodeBACnetSecurity(data []byte, df gopacket.DecodeFeedback) (*BACnetSecurityWrapper, error) {
	if len(data) < bacnetSecurityFixedLen+bacnetSecuritySignatureLen {
		return nil, bacnetTruncated(df)
	}
	w := &BACnetSecurityWrapper{
		Control:       BACnetSecurityControl(data[0]),
		KeyRevision:   data[1],
		KeyIdentifier: binary.BigEndian.Uint16(data[bacnetSecurityKeyAt:]),
		SourceDevice:  bacnetUint24(data[bacnetSecuritySourceAt:]),
		MessageID:     binary.BigEndian.Uint32(data[bacnetSecurityMessageAt:]),
		Timestamp:     binary.BigEndian.Uint32(data[bacnetSecurityTimeAt:]),
	}

	// The signature covers, and follows, everything else.
	end := len(data) - bacnetSecuritySignatureLen
	w.Signature = data[end:]
	body := data[bacnetSecurityFixedLen:end]

	if w.Control.Encrypted() {
		w.ServiceData = body
		return w, nil
	}

	off, err := w.decodeAddresses(body, df)
	if err != nil {
		return nil, err
	}
	if w.Control.AuthenticationPresent() {
		if off, err = w.decodeAuthentication(body, off, df); err != nil {
			return nil, err
		}
	}
	w.ServiceData = body[off:]
	return w, nil
}

// decodeAddresses reads the destination device instance and the two
// network addresses, and returns the offset after them.
func (w *BACnetSecurityWrapper) decodeAddresses(body []byte, df gopacket.DecodeFeedback) (int, error) {
	if len(body) < bacnetDeviceInstanceLen {
		return 0, bacnetTruncated(df)
	}
	w.DestinationDevice = bacnetUint24(body)
	off := bacnetDeviceInstanceLen

	var err error
	if w.DNET, w.DADR, off, err = bacnetNetAddr(body, off, df); err != nil {
		return 0, err
	}
	if w.SNET, w.SADR, off, err = bacnetNetAddr(body, off, df); err != nil {
		return 0, err
	}
	return off, nil
}

// decodeAuthentication reads the authentication data at off and returns
// the offset after it.
func (w *BACnetSecurityWrapper) decodeAuthentication(body []byte, off int, df gopacket.DecodeFeedback) (int, error) {
	if len(body)-off < bacnetSecurityAuthLen {
		return 0, bacnetTruncated(df)
	}
	w.AuthenticationMechanism = body[off]
	w.UserID = binary.BigEndian.Uint16(body[off+1:])
	w.UserRole = body[off+3]
	off += bacnetSecurityAuthLen

	// Mechanism 0 is the user ID and role alone.
	if w.AuthenticationMechanism == 0 {
		return off, nil
	}

	// The length counts the whole field: user ID, role and itself, the
	// vendor ID of a vendor's mechanism, and the data (Clause 24.2.11).
	if len(body)-off < bacnetUint16Len {
		return 0, bacnetTruncated(df)
	}
	size := int(binary.BigEndian.Uint16(body[off:])) - bacnetSecurityAuthFixedLen
	off += bacnetUint16Len

	if w.AuthenticationMechanism >= bacnetSecurityVendorAuth {
		if len(body)-off < bacnetUint16Len {
			return 0, bacnetTruncated(df)
		}
		w.AuthenticationVendorID = binary.BigEndian.Uint16(body[off:])
		off += bacnetUint16Len
		size -= bacnetUint16Len
	}
	if size < 0 {
		return 0, ErrBACnetMalformed
	}
	if len(body)-off < size {
		return 0, bacnetTruncated(df)
	}
	w.AuthenticationData = body[off : off+size]
	return off + size, nil
}

// bacnetUint24 reads a 3-octet big-endian number; the caller checked the
// length.
func bacnetUint24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

// bacnetSecurityOf returns the security wrapper in data, or nil when data
// does not hold a whole one. The layers that carry a wrapper kept it raw
// before it was decoded, so a broken one is not an error for them.
func bacnetSecurityOf(data []byte) *BACnetSecurityWrapper {
	w, err := decodeBACnetSecurity(data, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil
	}
	return w
}

// BACnetSecurityMessage is the decoded service data of a security wrapper:
// a *BACnetChallengeRequest, *BACnetSecurityPayload,
// *BACnetSecurityResponse, *BACnetRequestKeyUpdate, *BACnetUpdateKeySet,
// *BACnetUpdateDistributionKey, *BACnetRequestMasterKey or
// *BACnetSetMasterKey.
type BACnetSecurityMessage interface {
	bacnetSecurityMessage()
}

// BACnetSecurityResponseCode is the response code of a Security-Response
// (Clause 24.3.3).
type BACnetSecurityResponseCode uint8

// BACnetSecurityResponseCode values.
const (
	BACnetSecurityResponseSuccess                     BACnetSecurityResponseCode = 0x00
	BACnetSecurityResponseAccessDenied                BACnetSecurityResponseCode = 0x01
	BACnetSecurityResponseBadDestinationAddress       BACnetSecurityResponseCode = 0x02
	BACnetSecurityResponseBadDestinationDeviceID      BACnetSecurityResponseCode = 0x03
	BACnetSecurityResponseBadSignature                BACnetSecurityResponseCode = 0x04
	BACnetSecurityResponseBadSourceAddress            BACnetSecurityResponseCode = 0x05
	BACnetSecurityResponseBadTimestamp                BACnetSecurityResponseCode = 0x06
	BACnetSecurityResponseCannotUseKey                BACnetSecurityResponseCode = 0x07
	BACnetSecurityResponseCannotVerifyMessageID       BACnetSecurityResponseCode = 0x08
	BACnetSecurityResponseCorrectKeyRevision          BACnetSecurityResponseCode = 0x09
	BACnetSecurityResponseDestinationDeviceIDRequired BACnetSecurityResponseCode = 0x0A
	BACnetSecurityResponseDuplicateMessage            BACnetSecurityResponseCode = 0x0B
	BACnetSecurityResponseEncryptionNotConfigured     BACnetSecurityResponseCode = 0x0C
	BACnetSecurityResponseEncryptionRequired          BACnetSecurityResponseCode = 0x0D
	BACnetSecurityResponseIncorrectKey                BACnetSecurityResponseCode = 0x0E
	BACnetSecurityResponseInvalidKeyData              BACnetSecurityResponseCode = 0x0F
	BACnetSecurityResponseKeyUpdateInProgress         BACnetSecurityResponseCode = 0x10
	BACnetSecurityResponseMalformedMessage            BACnetSecurityResponseCode = 0x11
	BACnetSecurityResponseNotKeyServer                BACnetSecurityResponseCode = 0x12
	BACnetSecurityResponseSecurityNotConfigured       BACnetSecurityResponseCode = 0x13
	BACnetSecurityResponseSourceSecurityRequired      BACnetSecurityResponseCode = 0x14
	BACnetSecurityResponseTooManyKeys                 BACnetSecurityResponseCode = 0x15
	BACnetSecurityResponseUnknownAuthenticationType   BACnetSecurityResponseCode = 0x16
	BACnetSecurityResponseUnknownKey                  BACnetSecurityResponseCode = 0x17
	BACnetSecurityResponseUnknownKeyRevision          BACnetSecurityResponseCode = 0x18
	BACnetSecurityResponseUnknownSourceMessage        BACnetSecurityResponseCode = 0x19
)

var bacnetSecurityResponseNames = map[BACnetSecurityResponseCode]string{
	BACnetSecurityResponseSuccess:                     "success",
	BACnetSecurityResponseAccessDenied:                "accessDenied",
	BACnetSecurityResponseBadDestinationAddress:       "badDestinationAddress",
	BACnetSecurityResponseBadDestinationDeviceID:      "badDestinationDeviceId",
	BACnetSecurityResponseBadSignature:                "badSignature",
	BACnetSecurityResponseBadSourceAddress:            "badSourceAddress",
	BACnetSecurityResponseBadTimestamp:                "badTimestamp",
	BACnetSecurityResponseCannotUseKey:                "cannotUseKey",
	BACnetSecurityResponseCannotVerifyMessageID:       "cannotVerifyMessageId",
	BACnetSecurityResponseCorrectKeyRevision:          "correctKeyRevision",
	BACnetSecurityResponseDestinationDeviceIDRequired: "destinationDeviceIdRequired",
	BACnetSecurityResponseDuplicateMessage:            "duplicateMessage",
	BACnetSecurityResponseEncryptionNotConfigured:     "encryptionNotConfigured",
	BACnetSecurityResponseEncryptionRequired:          "encryptionRequired",
	BACnetSecurityResponseIncorrectKey:                "incorrectKey",
	BACnetSecurityResponseInvalidKeyData:              "invalidKeyData",
	BACnetSecurityResponseKeyUpdateInProgress:         "keyUpdateInProgress",
	BACnetSecurityResponseMalformedMessage:            "malformedMessage",
	BACnetSecurityResponseNotKeyServer:                "notKeyServer",
	BACnetSecurityResponseSecurityNotConfigured:       "securityNotConfigured",
	BACnetSecurityResponseSourceSecurityRequired:      "sourceSecurityRequired",
	BACnetSecurityResponseTooManyKeys:                 "tooManyKeys",
	BACnetSecurityResponseUnknownAuthenticationType:   "unknownAuthenticationType",
	BACnetSecurityResponseUnknownKey:                  "unknownKey",
	BACnetSecurityResponseUnknownKeyRevision:          "unknownKeyRevision",
	BACnetSecurityResponseUnknownSourceMessage:        "unknownSourceMessage",
}

// String returns the Clause 24.3.3 name of the response code.
func (c BACnetSecurityResponseCode) String() string {
	return bacnetName(bacnetSecurityResponseNames, c)
}

// BACnetChallengeRequest is a Challenge-Request (Clause 24.3.1): it asks
// the source of a message to prove that it sent it.
type BACnetChallengeRequest struct {
	// Challenge says why: 1 in response to a message, other values a
	// challenge of the sender's own making.
	Challenge uint8
	// OriginalMessageID and OriginalTimestamp name the challenged message.
	OriginalMessageID uint32
	OriginalTimestamp uint32
}

// BACnetSecurityPayload is a Security-Payload (Clause 24.3.2): the secured
// APDU or network layer message.
type BACnetSecurityPayload struct {
	// Payload is the secured message. When the wrapper control says it is
	// a network layer message it starts with the message type; else it is
	// an APDU, which BACnetNPDU hands to the APDU decoder.
	Payload []byte
	// NetworkMessage is Payload decoded when it is a network layer
	// message: only the message fields of the NPDU are set.
	NetworkMessage *BACnetNPDU
}

// BACnetSecurityResponse is a Security-Response (Clause 24.3.3): the
// answer to a Challenge-Request, or the report of a security error. The
// fields after Details are set according to Code.
type BACnetSecurityResponse struct {
	Code BACnetSecurityResponseCode
	// OriginalMessageID and OriginalTimestamp name the message answered.
	OriginalMessageID uint32
	OriginalTimestamp uint32
	// Details is the response specific parameters, as octets.
	Details []byte

	// ExpectedTimestamp is set by badTimestamp.
	ExpectedTimestamp uint32
	// Keys holds the key identifier of cannotUseKey, invalidKeyData and
	// unknownKey, and the identifiers the device knows of incorrectKey.
	Keys []uint16
	// MaxKeys is set by tooManyKeys.
	MaxKeys uint8
	// AuthenticationMechanism and VendorID are set by
	// unknownAuthenticationType.
	AuthenticationMechanism uint8
	VendorID                uint16
	// KeyRevision is set by unknownKeyRevision.
	KeyRevision uint8
}

// BACnetKeySetTiming is the revision and validity period of a key set;
// the times are in seconds since 1970-01-01 UTC.
type BACnetKeySetTiming struct {
	Revision       uint8
	ActivationTime uint32
	ExpirationTime uint32
}

// BACnetRequestKeyUpdate is a Request-Key-Update (Clause 24.3.4): the key
// sets a device holds, sent to the key server.
type BACnetRequestKeyUpdate struct {
	Set1                    BACnetKeySetTiming
	Set2                    BACnetKeySetTiming
	DistributionKeyRevision uint8
}

// BACnetSecurityKey is a key as distributed: its identifier (algorithm in
// the high octet, key number in the low one) and its octets.
type BACnetSecurityKey struct {
	Identifier uint16
	Value      []byte
}

// BACnetKeySetFlags is the control octet of an Update-Key-Set
// (Clause 24.3.5).
type BACnetKeySetFlags uint8

// Update-Key-Set control bits.
const (
	bacnetKeySet1Timing   BACnetKeySetFlags = 0x80
	bacnetKeySet1Keys     BACnetKeySetFlags = 0x40
	bacnetKeySet1Clear    BACnetKeySetFlags = 0x20
	bacnetKeySet2Timing   BACnetKeySetFlags = 0x10
	bacnetKeySet2Keys     BACnetKeySetFlags = 0x08
	bacnetKeySet2Clear    BACnetKeySetFlags = 0x04
	bacnetKeySetMore      BACnetKeySetFlags = 0x02
	bacnetKeySetRemoveAll BACnetKeySetFlags = 0x01
)

// ClearSet1 reports whether key set 1 is cleared before the update.
func (f BACnetKeySetFlags) ClearSet1() bool { return f&bacnetKeySet1Clear != 0 }

// ClearSet2 reports whether key set 2 is cleared before the update.
func (f BACnetKeySetFlags) ClearSet2() bool { return f&bacnetKeySet2Clear != 0 }

// MoreFollows reports whether further Update-Key-Set messages follow.
func (f BACnetKeySetFlags) MoreFollows() bool { return f&bacnetKeySetMore != 0 }

// RemoveAllKeys reports whether every key of both sets is removed.
func (f BACnetKeySetFlags) RemoveAllKeys() bool { return f&bacnetKeySetRemoveAll != 0 }

// BACnetKeySetUpdate is what an Update-Key-Set says of one key set.
type BACnetKeySetUpdate struct {
	// HasTiming is set when the message carries Timing, HasKeys when it
	// carries Keys, which may then be empty.
	HasTiming bool
	HasKeys   bool
	Timing    BACnetKeySetTiming
	Keys      []BACnetSecurityKey
}

// BACnetUpdateKeySet is an Update-Key-Set (Clause 24.3.5), by which the
// key server distributes keys. It is normally encrypted.
type BACnetUpdateKeySet struct {
	Flags BACnetKeySetFlags
	Set1  BACnetKeySetUpdate
	Set2  BACnetKeySetUpdate
}

// BACnetUpdateDistributionKey is an Update-Distribution-Key
// (Clause 24.3.6).
type BACnetUpdateDistributionKey struct {
	KeyRevision uint8
	Key         BACnetSecurityKey
}

// BACnetRequestMasterKey is a Request-Master-Key (Clause 24.3.7): the key
// algorithms (encryption and signature) the device supports.
type BACnetRequestMasterKey struct {
	Algorithms []uint8
}

// BACnetSetMasterKey is a Set-Master-Key (Clause 24.3.8).
type BACnetSetMasterKey struct {
	Key BACnetSecurityKey
}

func (*BACnetChallengeRequest) bacnetSecurityMessage()      {}
func (*BACnetSecurityPayload) bacnetSecurityMessage()       {}
func (*BACnetSecurityResponse) bacnetSecurityMessage()      {}
func (*BACnetRequestKeyUpdate) bacnetSecurityMessage()      {}
func (*BACnetUpdateKeySet) bacnetSecurityMessage()          {}
func (*BACnetUpdateDistributionKey) bacnetSecurityMessage() {}
func (*BACnetRequestMasterKey) bacnetSecurityMessage()      {}
func (*BACnetSetMasterKey) bacnetSecurityMessage()          {}

// bacnetOctets reads fixed fields off the front of a message body. A read
// past the end returns zero and sets short; the caller checks it once at
// the end.
type bacnetOctets struct {
	b     []byte
	short bool
}

// take returns the next n octets, or nil when fewer are left.
func (o *bacnetOctets) take(n int) []byte {
	if n < 0 || len(o.b) < n {
		o.short = true
		o.b = nil
		return nil
	}
	out := o.b[:n:n]
	o.b = o.b[n:]
	return out
}

func (o *bacnetOctets) u8() uint8 {
	b := o.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (o *bacnetOctets) u16() uint16 {
	b := o.take(bacnetUint16Len)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (o *bacnetOctets) u32() uint32 {
	b := o.take(bacnetUint32Len)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// key reads a key: identifier, size, octets.
func (o *bacnetOctets) key() BACnetSecurityKey {
	k := BACnetSecurityKey{Identifier: o.u16()}
	k.Value = o.take(int(o.u8()))
	return k
}

// timing reads the revision and validity period of a key set.
func (o *bacnetOctets) timing() BACnetKeySetTiming {
	return BACnetKeySetTiming{Revision: o.u8(), ActivationTime: o.u32(), ExpirationTime: o.u32()}
}

// decodeMessage decodes ServiceData as the body of network security
// message t into Message. Encrypted service data, and service data too
// short for the message, leave Message nil.
func (w *BACnetSecurityWrapper) decodeMessage(t BACnetNetworkMessageType) {
	if w.Control.Encrypted() {
		return
	}
	o := &bacnetOctets{b: w.ServiceData}

	var m BACnetSecurityMessage
	switch t {
	case BACnetNetworkMessageChallengeRequest:
		m = &BACnetChallengeRequest{Challenge: o.u8(), OriginalMessageID: o.u32(), OriginalTimestamp: o.u32()}

	case BACnetNetworkMessageSecurityPayload:
		m = w.securityPayload(o)

	case BACnetNetworkMessageSecurityResponse:
		m = bacnetSecurityResponse(o)

	case BACnetNetworkMessageRequestKeyUpdate:
		m = &BACnetRequestKeyUpdate{Set1: o.timing(), Set2: o.timing(), DistributionKeyRevision: o.u8()}

	case BACnetNetworkMessageUpdateKeySet:
		m = bacnetUpdateKeySet(o)

	case BACnetNetworkMessageUpdateDistributionKey:
		m = &BACnetUpdateDistributionKey{KeyRevision: o.u8(), Key: o.key()}

	case BACnetNetworkMessageRequestMasterKey:
		m = &BACnetRequestMasterKey{Algorithms: o.take(int(o.u8()))}

	case BACnetNetworkMessageSetMasterKey:
		m = &BACnetSetMasterKey{Key: o.key()}

	default:
		return
	}
	if o.short {
		return
	}
	w.Message = m
}

// securityPayload reads a Security-Payload: a 2-octet length, then the
// APDU or network layer message it counts.
func (w *BACnetSecurityWrapper) securityPayload(o *bacnetOctets) *BACnetSecurityPayload {
	p := &BACnetSecurityPayload{Payload: o.take(int(o.u16()))}
	if !w.Control.NetworkMessage() || len(p.Payload) == 0 {
		return p
	}

	// A network layer message: type, vendor ID when proprietary, body.
	n := &BACnetNPDU{Version: bacnetNPDUVersion, Control: bacnetControlNetworkMessage}
	msg := &bacnetOctets{b: p.Payload}
	n.MessageType = BACnetNetworkMessageType(msg.u8())
	if uint8(n.MessageType) >= bacnetProprietaryMsg {
		n.VendorID = msg.u16()
	}
	if msg.short {
		return p
	}
	n.Body = msg.b

	// A security message is not secured again; anything else that does
	// not decode is left as Payload.
	if n.MessageType.security() || n.decodeMessage(gopacket.NilDecodeFeedback) != nil {
		return p
	}
	p.NetworkMessage = n
	return p
}

// bacnetSecurityResponse reads a Security-Response: the code, the message
// answered, and what the code calls for.
func bacnetSecurityResponse(o *bacnetOctets) *BACnetSecurityResponse {
	r := &BACnetSecurityResponse{
		Code:              BACnetSecurityResponseCode(o.u8()),
		OriginalMessageID: o.u32(),
		OriginalTimestamp: o.u32(),
	}
	r.Details = o.b

	switch r.Code {
	case BACnetSecurityResponseBadTimestamp:
		r.ExpectedTimestamp = o.u32()

	case BACnetSecurityResponseCannotUseKey, BACnetSecurityResponseInvalidKeyData, BACnetSecurityResponseUnknownKey:
		r.Keys = []uint16{o.u16()}

	case BACnetSecurityResponseIncorrectKey:
		// A count, then that many key identifiers.
		list := o.take(int(o.u8()) * bacnetUint16Len)
		r.Keys = make([]uint16, len(list)/bacnetUint16Len)
		for i := range r.Keys {
			r.Keys[i] = binary.BigEndian.Uint16(list[i*bacnetUint16Len:])
		}

	case BACnetSecurityResponseTooManyKeys:
		r.MaxKeys = o.u8()

	case BACnetSecurityResponseUnknownAuthenticationType:
		r.AuthenticationMechanism = o.u8()
		r.VendorID = o.u16()

	case BACnetSecurityResponseUnknownKeyRevision:
		r.KeyRevision = o.u8()
	}
	return r
}

// bacnetUpdateKeySet reads an Update-Key-Set: the control flags, then for
// each key set the parts the flags announce.
//
//	flags | [revision | activation | expiration] | [count | keys] | (set 2)
func bacnetUpdateKeySet(o *bacnetOctets) *BACnetUpdateKeySet {
	u := &BACnetUpdateKeySet{Flags: BACnetKeySetFlags(o.u8())}
	u.Set1 = bacnetKeySetUpdate(o, u.Flags&bacnetKeySet1Timing, u.Flags&bacnetKeySet1Keys)
	u.Set2 = bacnetKeySetUpdate(o, u.Flags&bacnetKeySet2Timing, u.Flags&bacnetKeySet2Keys)
	return u
}

// bacnetKeySetUpdate reads the timing and the keys of one key set, each
// only when its flag is set.
func bacnetKeySetUpdate(o *bacnetOctets, timing, keys BACnetKeySetFlags) BACnetKeySetUpdate {
	// identifier and size: the least a key takes.
	const minKeyLen = bacnetUint16Len + 1

	s := BACnetKeySetUpdate{HasTiming: timing != 0, HasKeys: keys != 0}
	if s.HasTiming {
		s.Timing = o.timing()
	}
	if !s.HasKeys {
		return s
	}

	// The count is checked against what is left before the list is made.
	count := int(o.u8())
	if count*minKeyLen > len(o.b) {
		o.short = true
		return s
	}
	s.Keys = make([]BACnetSecurityKey, count)
	for i := range s.Keys {
		s.Keys[i] = o.key()
	}
	return s
}
