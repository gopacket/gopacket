// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// BACnet network security wrapper (ASHRAE 135-2016 Clause 24.2, removed in
// 135-2020). It follows the message type of the network security messages
// 0x0A to 0x11 and is the whole body of a Secure-BVLL.

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
// AuthenticationData are readable only when the wrapper is not encrypted.
//
//	control | key rev | key id | source device | message id | timestamp
//	  | destination device | DNET DLEN DADR | SNET SLEN SADR
//	  | [mechanism | user id | user role | [length | data]]
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
	// AuthenticationData belongs to a mechanism other than 0.
	AuthenticationData []byte

	// ServiceData is what the wrapper secures, undecoded: the message, or
	// for an encrypted wrapper every octet from the destination device
	// instance to the padding, still encrypted.
	ServiceData []byte
	// Signature is the HMAC that ends the wrapper.
	Signature []byte
}

// decodeBACnetSecurity decodes a security wrapper that takes all of data.
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
	if len(body)-off < bacnetUint16Len {
		return 0, bacnetTruncated(df)
	}
	size := int(binary.BigEndian.Uint16(body[off:]))
	off += bacnetUint16Len

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
