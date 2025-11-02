// Copyright 2024, The GoPacket Authors, All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//
//******************************************************************************

package layers

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"

	"github.com/gopacket/gopacket"
)

// This dissector works for BGP version number 4 as defined by
// A Border Gateway Protocol 4 (BGP-4) [RFC4271] and
// Route Refresh Capability for BGP-4 [RFC2918].
//
// [RFC4271]: https://datatracker.ietf.org/doc/html/rfc4271
// [RFC2918]: https://datatracker.ietf.org/doc/html/rfc2918

// The value of the Length field MUST always be at least
// and no greater than 4096
const (
	BGPv4MinimumSize int = 19   // [RFC4271]
	BGPv4MaximumSize int = 4096 // [RFC4271]
)

// BGPv4Marker is the expected marker for the BGP version number 4.
var BGPv4Marker = [16]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// BGPv4 implements the DecodingLayer interface. Each BGPv4 object represents
// in a structured form the BGP application version 4 as defined in [RFC4271].
type BGPv4 struct {
	BaseLayer
	// Marker is included for compatibility
	Marker [16]byte
	// Length indicates the total length of the
	// message, including the header in octets. Thus, it allows one
	// to locate the (Marker field of the) next message in the TCP
	// stream.
	Length uint16
	// Type indicates the type code of the message
	Type BGPv4Type
	// Data contains all information according to the type message
	Data interface{}
}

// BGPv4Type defines types for the BGP version number 4.
type BGPv4Type uint8

const (
	BGPv4TypeOpen           BGPv4Type = iota + 1 // Open 		[RFC4271]
	BGPv4TypeUpdate                              // Update 		[RFC4271]
	BGPv4TypeNotification                        // Notification 	[RFC4271]
	BGPv4TypeKeepAlive                           // Keep Alive 	[RFC4271]
	BGPv4TypeRouteRefreshed                      // Route Refreshed [RFC2918]
)

// String returns the associated string for a BGPv4Type
func (t BGPv4Type) String() string {
	switch t {
	case BGPv4TypeOpen:
		return "Open"
	case BGPv4TypeUpdate:
		return "Update"
	case BGPv4TypeNotification:
		return "Notification"
	case BGPv4TypeKeepAlive:
		return "Keep Alive"
	case BGPv4TypeRouteRefreshed:
		return "Route Refreshed"
	default:
		return fmt.Sprintf("Unknown_%d", uint8(t))
	}
}

// After a TCP connection is established, the first message sent by each
// side is an OPEN message.  If the OPEN message is acceptable, a
// KEEPALIVE message confirming the OPEN is sent back.
//
// The minimum length of the OPEN message is 29 octets (including the
// message header).
type BGPv4Open struct {
	// Version indicates the protocol version
	// number of the message. The current BGP version number is 4.
	Version uint8
	// MyAS indicates the Autonomous System number of the sender.
	MyAS uint16
	// HoldTime indicates the number of seconds the sender proposes for the
	// value of the Hold Timer.
	HoldTime uint16
	// BGPIdentifier indicates the BGP Identifier of
	// the sender. A given BGP speaker sets the value of its BGP
	// Identifier to an IP address that is assigned to that BGP
	// speaker. The value of the BGP Identifier is determined upon
	// startup and is the same for every local interface and BGP peer.
	BGPIdentifier net.IP
	// ParamLength indicates the total length of the
	// Optional Parameters field in octets. If the value of this
	// field is zero, no Optional Parameters are present.
	ParamLength uint8
	// Parameters contains a list of optional parameters, in which
	// each parameter is encoded as a <Parameter Type, Parameter
	// Length, Parameter Value> triplet.
	Parameters []BGPv4Parameter
}

// Parameter Type is a one octet field that unambiguously
// identifies individual parameters. Parameter Length is a one
// octet field that contains the length of the Parameter Value
// field in octets. Parameter Value is a variable length field
// that is interpreted according to the value of the Parameter
// Type field.
type BGPv4Parameter struct {
	// Type is a one octet field that unambiguously
	// identifies individual parameters
	Type uint8
	// Length is a one octet field that contains the length of the
	// Parameter Value field in octets
	Length uint8
	// Value is a variable length field that is interpreted according to
	// the value of the Parameter Type field
	Value []byte
}

// UPDATE messages are used to transfer routing information between BGP
// peers. The information in the UPDATE message can be used to
// construct a graph that describes the relationships of the various
// Autonomous Systems.
//
// An UPDATE message is used to advertise feasible routes that share
// common path attributes to a peer, or to withdraw multiple unfeasible
// routes from service
type BGPv4Update struct {
	// RoutesLength indicates the total length of
	// the Withdrawn Routes field in octets.
	RoutesLength uint16
	// Routes contains a list of IP
	// address prefixes for the routes that are being withdrawn from
	// service.
	Routes []BGPv4IPAddressPrefix
	// PathAttributeLength indicates the total length of the
	// Path Attributes field in octets.
	//
	// A value of 0 indicates that neither the Network Layer
	// Reachability Information field nor the Path Attribute field is
	// present in this UPDATE message.
	PathAttributeLength uint16
	// PathAttribute sequence of path attributes is present in
	// every UPDATE message, except for an UPDATE message that carries
	// only the withdrawn routes
	PathAttribute []BGPv4Attribute
	// Network Layer Reachability Information contains a list of IP address
	// prefixes. The length, in octets, of the Network Layer
	// Reachability Information is not encoded explicitly, but can be
	// calculated as:
	//
	//       UPDATE message Length - 23 - Total Path Attributes Length
	//       - Withdrawn Routes Length
	//
	// where UPDATE message Length is the value encoded in the fixed-
	// size BGP header, Total Path Attribute Length, and Withdrawn
	// Routes Length are the values encoded in the variable part of
	// the UPDATE message, and 23 is a combined length of the fixed-
	// size BGP header, the Total Path Attribute Length field, and the
	// Withdrawn Routes Length field.
	//
	// If PathAttribute length is 0, NLRI is not present in this message.
	NLRI []BGPv4IPAddressPrefix
}

// Each IP address prefix is encoded as a 2-tuple of the
// form <length, prefix>
type BGPv4IPAddressPrefix struct {
	// Length indicates the length in bits of the IP
	// address prefix. A length of zero indicates a prefix that
	// matches all IP addresses (with prefix, itself, of zero
	// octets).
	Length uint8
	// Prefix field contains an IP address prefix, followed by
	// the minimum number of trailing bits needed to make the end
	// of the field fall on an octet boundary. Note that the value
	// of trailing bits is irrelevant.
	Prefix []byte
}

// Each path attribute is a triple
// <attribute type, attribute length, attribute value> of variable
// length.
//
// Attribute Type is a two-octet field that consists of the
// Attribute Flags octet, followed by the Attribute Type Code
// octet.
type BGPv4Attribute struct {
	Flag   BGPv4AttributeFlags
	Code   BGPv4AttributeCode
	Length uint16
	Value  []byte
}

// BGPv4AttributeCode defines all code attribute for BGP version number 4.
type BGPv4AttributeCode uint8

const (
	BGPv4AttributeOriginCode          BGPv4AttributeCode = iota + 1 // ORIGIN 		[RFC4271]
	BGPv4AttributeAsPathCode                                        // AS_PATH 		[RFC4271]
	BGPv4AttributeNextHopCode                                       // NEXT_HOP 		[RFC4271]
	BGPv4AttributeMultiExitDiscCode                                 // MULTI_EXIT_DISC 	[RFC4271]
	BGPv4AttributeLocalPrefCode                                     // LOCAL_PREF 		[RFC4271]
	BGPv4AttributeAtomicAggregateCode                               // ATOMIC_AGGREGATE 	[RFC4271]
	BGPv4AttributeAggregatorCode                                    // AGGREGATOR 		[RFC4271]
)

// String returns the associated string for a code attribute
func (c BGPv4AttributeCode) String() string {
	switch c {
	case BGPv4AttributeOriginCode:
		return "ORIGIN"
	case BGPv4AttributeAsPathCode:
		return "AS_PATH"
	case BGPv4AttributeNextHopCode:
		return "NEXT_HOP"
	case BGPv4AttributeMultiExitDiscCode:
		return "MULTI_EXIT_DISC"
	case BGPv4AttributeLocalPrefCode:
		return "LOCAL_PREF"
	case BGPv4AttributeAtomicAggregateCode:
		return "ATOMIC_AGGREGATE"
	case BGPv4AttributeAggregatorCode:
		return "AGGREGATOR"
	default:
		return fmt.Sprintf("Unknown_%d", uint8(c))
	}
}

// BGPv4AttributeFlags defines all flags in an BGPv4Attribute.
type BGPv4AttributeFlags struct {
	// Optional is the high-order bit (bit 0) of the Attribute Flags octet is the
	// Optional bit. It defines whether the attribute is optional (if
	// set to 1) or well-known (if set to 0).
	Optional bool
	// Transitive is the second high-order bit (bit 1) of the Attribute Flags octet
	// is the Transitive bit. It defines whether an optional
	// attribute is transitive (if set to 1) or non-transitive (if set
	// to 0).
	//
	// For well-known attributes, the Transitive bit MUST be set to 1.
	Transitive bool
	// Partial is the third high-order bit (bit 2) of the Attribute Flags octet
	// is the Partial bit. It defines whether the information
	// contained in the optional transitive attribute is partial (if
	// set to 1) or complete (if set to 0). For well-known attributes
	// and for optional non-transitive attributes, the Partial bit
	// MUST be set to 0.
	Partial bool
	// ExtendedLength is the fourth high-order bit (bit 3) of the Attribute Flags octet
	// is the Extended Length bit. It defines whether the Attribute
	// Length is one octet (if set to 0) or two octets (if set to 1).
	ExtendedLength bool
	// Unused is the lower-order four bits of the Attribute Flags octet are
	// unused. They MUST be zero when sent and MUST be ignored when
	// received.
	Unused uint8
}

// A NOTIFICATION message is sent when an error condition is detected.
// The BGP connection is closed immediately after it is sent.
type BGPv4Notification struct {
	// ErrorCode indicates the type of NOTIFICATION
	ErrorCode BGPv4ErrorCode
	// ErrorSubCode provides more specific
	// information about the nature of the reported error.  Each Error
	// Code may have one or more Error Subcodes associated with it.
	// If no appropriate Error Subcode is defined, then a zero
	// (Unspecific) value is used for the Error Subcode field.
	ErrorSubCode BGPv4ErrorSubCode
	// Message is used to diagnose the reason for
	// the NOTIFICATION. The contents of the Data field depend upon
	// the Error Code and Error Subcode
	//
	// Note that the length of the Data field can be determined from
	// the message Length field by the formula:
	//
	// 	Message Length = 21 + Data Length
	Message []byte
}

// BGPv4ErrorCode defines code error for BGP version number 4.
type BGPv4ErrorCode uint8

const (
	BGPv4MessageHeaderError      BGPv4ErrorCode = iota + 1 // Message Header Error 		[RFC4271]
	BGPv4OpenMessageError                                  // Open Message Error 		[RFC4271]
	BGPv4UpdateMessageError                                // Update Message Error 		[RFC4271]
	BGPv4HoldTimerExpiredError                             // Hold Timer Expired 		[RFC4271]
	BGPv4FiniteStateMachineError                           // Finite State Machine Error 	[RFC4271]
	BGPv4CeaseError                                        // Cease Error 			[RFC4271]
)

// BGPv4ErrorSubCode defines sub-code error for BGP version number 4.
//
// BGPv4ErrorSubCode is defined as interface as code error may have one or more
// sub-code error associated with it. If no appropriate Error Subcode is defined,
// then a zero (Unspecific) value is used for the Error Subcode field.
type BGPv4ErrorSubCode interface {
	String() string
}

// BGPv4ErrorMessageHeaderSubCode defines sub-code error for a BGPv4MessageHeaderError.
type BGPv4ErrorMessageHeaderSubCode uint8

const (
	BGPv4ConnectionNotSynchronizedSubCode BGPv4ErrorMessageHeaderSubCode = iota + 1 // Connection Not Synchronized 	[RFC4271]
	BGPv4BadMessageLength                                                           // Bad Message Length 		[RFC4271]
	BGPv4BadMessageType                                                             // Bad Message Type 		[RFC4271]
)

// String returns the associated string for a BGPv4ErrorMessageHeaderSubCode
func (sb BGPv4ErrorMessageHeaderSubCode) String() string {
	switch sb {
	case BGPv4ConnectionNotSynchronizedSubCode:
		return "Connection Not Synchronized"
	case BGPv4BadMessageLength:
		return "Bad Message Length"
	case BGPv4BadMessageType:
		return "Bad Message Type"
	default:
		return fmt.Sprintf("Unknown_%d", uint8(sb))
	}
}

// BGPv4ErrorOpenMessageSubCode defines sub-code error for a BGPv4OpenMessageError.
type BGPv4ErrorOpenMessageSubCode uint8

const (
	BGPv4UnsupportedVersionNumber     BGPv4ErrorOpenMessageSubCode = iota + 1 // Unsupported Number Version 	[RFC4271]
	BGPv4BadPeerAS                                                            // Bad Peer AS 			[RFC4271]
	BGPv4BadBGPIdentifier                                                     // Bad BGP Identifier 		[RFC4271]
	BGPv4UnsupportedOptionalParameter                                         // Unsupported Optional Parameter 	[RFC4271]
	BGPv4AuthenticationFailure                                                // Authentication Failure 		[RFC4271] - Deprecated
	BGPv4UnacceptableHoldTime                                                 // Unacceptable Hold Time 		[RFC4271]
)

// Strings returns the associated string for a BGPv4ErrorOpenMessageSubCode.
func (sb BGPv4ErrorOpenMessageSubCode) String() string {
	switch sb {
	case BGPv4UnsupportedVersionNumber:
		return "Unsupported Version Number"
	case BGPv4BadPeerAS:
		return "Bad Peer AS"
	case BGPv4BadBGPIdentifier:
		return "Bad BGP Identifier"
	case BGPv4UnsupportedOptionalParameter:
		return "Unsupported Optional Parameter"
	case BGPv4AuthenticationFailure:
		return "Authentication Failure - Deprecated"
	case BGPv4UnacceptableHoldTime:
		return "Unacceptable Hold Time"
	default:
		return fmt.Sprintf("Unknown_%d", uint8(sb))
	}
}

// BGPv4ErrorUpdateMessageSubCode defines sub-code error for a BGPv4UpdateMessageError.
type BGPv4ErrorUpdateMessageSubCode uint8

const (
	BGPv4MalformedAttributeList         BGPv4ErrorUpdateMessageSubCode = iota + 1 // Malformed Attribute List 		[RFC4271]
	BGPv4UnrecognizedWellknownAttribute                                           // Unrecognized Well-known Attribute 	[RFC4271]
	BGPv4MissingWellknownAttribute                                                // Missing Well-known Attribute 		[RFC4271]
	BGPv4AttributeFlagsError                                                      // Attribute Flags Error 			[RFC4271]
	BGPv4AttributeLengthError                                                     // Attribute Length Error 		[RFC4271]
	BGPv4InvalidOriginAttribute                                                   // Invalid ORIGIN Attribute 		[RFC4271]
	BGPv4InvalidNextHopAttribute                                                  // Invalid NEXT_HOP Attribute 		[RFC4271] - Deprecated
	BGPv4OptionalAttributeError                                                   // Optional Attribute Error 		[RFC4271]
	BGPv4InvalidNetworkField                                                      // Invalid Network Field 			[RFC4271]
	BGPv4MalformedAsPath                                                          // Malformed AS_PATH 			[RFC4271]
)

// String returns the associated string for a BGPv4ErrorUpdateMessageSubCode.
func (sb BGPv4ErrorUpdateMessageSubCode) String() string {
	switch sb {
	case BGPv4MalformedAttributeList:
		return "Malformed Attribute List"
	case BGPv4UnrecognizedWellknownAttribute:
		return "Unrecognized Well-known Attribute"
	case BGPv4MissingWellknownAttribute:
		return "Missing Well-known attribute"
	case BGPv4AttributeFlagsError:
		return "Attribute Flags Error"
	case BGPv4AttributeLengthError:
		return "Attribute Length Error"
	case BGPv4InvalidOriginAttribute:
		return "Invalid ORIGIN Attribute"
	case BGPv4InvalidNextHopAttribute:
		return "Invalid NEXT_HOP Attribute - Deprecated"
	case BGPv4OptionalAttributeError:
		return "Optional Attribute Error"
	case BGPv4InvalidNetworkField:
		return "Invalid Network Field"
	case BGPv4MalformedAsPath:
		return "Malformed AS_PATH"
	default:
		return fmt.Sprintf("Unknown_%d", uint8(sb))
	}
}

// BGPv4ErrorDefaultSubCode defines sub-code error for all BGPv4ErrorCode
// without specific sub-code defined.
type BGPv4ErrorDefaultSubCode uint8

const (
	BGPv4UnspecificSubCode BGPv4ErrorDefaultSubCode = iota // Unspecific [RFC4271]
)

// String returns the associated string for a BGPv4ErrorDefaultSubCode.
func (sb BGPv4ErrorDefaultSubCode) String() string {
	switch sb {
	case BGPv4UnspecificSubCode:
		return "Unspecific"
	default:
		return fmt.Sprintf("Unknown_%d", uint8(sb))
	}
}

// BGPv4RouteRefreshed contains information form a Route Refreshed payload as
// defined in [RFC2918]
type BGPv4RouteRefreshed struct {
	// Address Family Identifier
	AFI uint16
	// Reserved field. Should be set to 0 by the sender and ignored by the receiver
	Res uint8
	// Subsequent Address Family Identifier
	SAFI uint8
}

//******************************************************************************

// LayerType returns the layer type of the BGPv4 object, which is LayerTypeBGPv4.
func (bgp *BGPv4) LayerType() gopacket.LayerType {
	return LayerTypeBGPv4
}

//******************************************************************************

// decodeBGPv4 analyses a byte slice and attempts to decode it as a BGPv4
// record of a TCP packet.
//
// If it succeeds, it loads p with information about the packet and returns nil.
// If it fails, it returns an error (non nil).
func decodeBGPv4(data []byte, p gopacket.PacketBuilder) error {
	bgp := &BGPv4{}
	err := bgp.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(bgp)
	p.SetApplicationLayer(bgp)

	return p.NextDecoder(bgp.NextLayerType())
}

//******************************************************************************

// DecodeFromBytes analyses a byte slice and attempts to decode it as an BGPv4
// record of a TCP packet.
//
// Upon succeeds, it loads the BGPv4 object with information about the packet
// and returns nil.
// Upon failure, it returns an error (non nil).
func (bgp *BGPv4) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < BGPv4MinimumSize {
		return fmt.Errorf("BGPv4 packet too short, %d", len(data))
	}

	if len(data) > BGPv4MaximumSize {
		return fmt.Errorf("BGPv4 packet too long, %d", len(data))
	}

	copy(bgp.Marker[:], data[0:16])
	bgp.Length = binary.BigEndian.Uint16(data[16:18])

	// no need to be equal as Payload could be another layer
	if len(data) < int(bgp.Length) {
		return fmt.Errorf("BGPv4 packet length field is %d, should be %d", bgp.Length, len(data))
	}
	bgp.Type = BGPv4Type(data[18])

	var err error

	switch bgp.Type {
	case BGPv4TypeOpen:
		err = bgp.decodeOpenType(data[19:int(bgp.Length)])
	case BGPv4TypeUpdate:
		err = bgp.decodeUpdateType(data[19:int(bgp.Length)])
	case BGPv4TypeNotification:
		err = bgp.decodeNotificationType(data[19:int(bgp.Length)])
	case BGPv4TypeKeepAlive:
		// Keep Alive packet has no data, only header
	case BGPv4TypeRouteRefreshed:
		err = bgp.decodeRouteRefreshed(data[19:int(bgp.Length)])
	}

	if err != nil {
		return err
	}

	bgp.BaseLayer = BaseLayer{Contents: data[:int(bgp.Length)], Payload: data[int(bgp.Length):]}

	return nil
}

// decodeOpenType takes a data slice of bytes and parses it as a
// BGPv4Open object. The object is the BGPv4.Data field.
// The function returns an error or nil.
func (bgp *BGPv4) decodeOpenType(data []byte) error {
	if len(data) < 10 {
		return fmt.Errorf("BGPv4 Open packet is too short, %d", len(data))
	}

	var open BGPv4Open
	open.Version = data[0]
	if open.Version != 4 {
		return fmt.Errorf("BGPv4 Open packet should have version number at 4, %d", open.Version)
	}

	open.MyAS = binary.BigEndian.Uint16(data[1:3])
	open.HoldTime = binary.BigEndian.Uint16(data[3:5])
	open.BGPIdentifier = net.IP(data[5:9])
	open.ParamLength = data[9]

	for i := 0; i < int(open.ParamLength) && 10+i < len(data); {
		parameter, err := bgp.decodeParameter(data[10+i:])
		if err != nil {
			return fmt.Errorf("BGPv4 Open parameter malformed, %s", err)
		}

		open.Parameters = append(open.Parameters, parameter)
		i += int(parameter.Length) + 2
	}

	bgp.Data = open

	return nil
}

// decodeUpdateType takes a data slice of bytes and parses it as a
// BGPv4Update object. The object is the BGPv4.Data field.
// The function returns an error or nil.
func (bgp *BGPv4) decodeUpdateType(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("BGPv4 Update packet too short, %d", len(data))
	}

	var update BGPv4Update
	var index int

	update.RoutesLength = binary.BigEndian.Uint16(data[index : index+2])
	index += 2
	for i := 0; i < int(update.RoutesLength) && index+i < len(data); {
		routeLength, route, err := bgp.decodeRouteIPAddress(data[2+i:])
		if err != nil {
			return fmt.Errorf("BGPv4 Update route malformed, %s", err)
		}

		update.Routes = append(update.Routes, route)
		i += routeLength
	}
	index += int(update.RoutesLength)

	if len(data[index:]) < 2 {
		return fmt.Errorf("BGPv4 Update malformed, path attribute length not found")
	}
	update.PathAttributeLength = binary.BigEndian.Uint16(data[index : index+2])
	index += 2

	for i := 0; i < int(update.PathAttributeLength) && index+i < len(data); {
		lengthAttribute, attribute, err := bgp.decodeAttribute(data[index+i:])
		if err != nil {
			return fmt.Errorf("BGPv4 Update malformed, %s", err)
		}

		update.PathAttribute = append(update.PathAttribute, attribute)
		i += int(lengthAttribute)
	}
	index += int(update.PathAttributeLength)

	//  UPDATE message Length - 23 - Total Path Attributes Length
	//  - Withdrawn Routes Length
	lengthNLRI := int(bgp.Length) - 23 - int(update.RoutesLength) - int(update.PathAttributeLength)

	if update.PathAttributeLength == 0 && lengthNLRI != 0 {
		return fmt.Errorf("BGPv4 Update malformed, NLRI should not be present without PathAttribute")
	}

	if len(data[index:]) < lengthNLRI {
		return fmt.Errorf("BGPv4 Update malformed, NLRI not found")
	}
	for i := 0; i < lengthNLRI && index+i < len(data); {
		routeLength, route, err := bgp.decodeRouteIPAddress(data[index+i:])
		if err != nil {
			return fmt.Errorf("BGPv4 Update route malformed, %s", err)
		}

		update.NLRI = append(update.NLRI, route)
		i += routeLength
	}
	index += lengthNLRI

	bgp.Data = update

	return nil
}

// decodeNotificationType takes a data slice of bytes and parses it as a
// BGPv4Notification object. The object is the BGPv4.Data field.
// The function returns an error or nil.
func (bgp *BGPv4) decodeNotificationType(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("BGPv4 Notification packet too short, %d", len(data))
	}

	var notification BGPv4Notification

	notification.ErrorCode = BGPv4ErrorCode(data[0])
	switch notification.ErrorCode {
	case BGPv4MessageHeaderError:
		notification.ErrorSubCode = BGPv4ErrorMessageHeaderSubCode(data[1])
	case BGPv4OpenMessageError:
		notification.ErrorSubCode = BGPv4ErrorOpenMessageSubCode(data[1])
	case BGPv4UpdateMessageError:
		notification.ErrorSubCode = BGPv4ErrorUpdateMessageSubCode(data[1])
	case BGPv4HoldTimerExpiredError, BGPv4FiniteStateMachineError, BGPv4CeaseError:
		notification.ErrorSubCode = BGPv4ErrorDefaultSubCode(data[1])
	default:
		return fmt.Errorf("BGPv4 Notification error code unknown, %d", uint8(notification.ErrorCode))
	}

	lengthMessage := int(bgp.Length) - 21
	if len(data[2:]) < lengthMessage {
		return fmt.Errorf("BGPv4 Notification malformed, message not found")
	}

	notification.Message = data[2 : 2+lengthMessage]

	bgp.Data = notification

	return nil
}

// decodeRouteRefreshed takes a data slice of bytes and parses it as a
// BGPv4RouteRefreshed object. The object is the BGPv4.Data field.
// The function returns an error or nil.
func (bgp *BGPv4) decodeRouteRefreshed(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("BGPv4 Route Refreshed packet too short, %d", len(data))
	}

	var routeRefreshed BGPv4RouteRefreshed

	routeRefreshed.AFI = binary.BigEndian.Uint16(data[0:2])
	routeRefreshed.Res = data[2]
	routeRefreshed.SAFI = data[3]

	bgp.Data = routeRefreshed

	return nil
}

// decodeRouteIPAddress takes a data slice of bytes and parses it as
// a BGPv4IPAddressPrefix object. The function returns the number of bytes used
// for the BGPv4IPAddressPrefix, the object and an error or nil.
func (bgp *BGPv4) decodeRouteIPAddress(data []byte) (int, BGPv4IPAddressPrefix, error) {
	var route BGPv4IPAddressPrefix

	if len(data) < 1 {
		return 0, route, fmt.Errorf("route is too short, %d", len(data))
	}

	route.Length = data[0]

	// convert route length in bits to bytes
	l := math.Ceil(float64(route.Length) / 8)

	if len(data[1:]) < int(l) {
		return 0, route, fmt.Errorf("route prefix not found")
	}

	route.Prefix = data[1 : 1+int(l)]

	return int(l) + 1, route, nil
}

// decodeAttribute takes a data slice of bytes and parses it as BGPv4Attribute
// object. The function returns the number of byte used for the BGPv4Attribute,
// the object and an error or nil.
func (bgp *BGPv4) decodeAttribute(data []byte) (int, BGPv4Attribute, error) {
	var attribute BGPv4Attribute
	var index int

	if len(data) < 3 {
		return index, attribute, fmt.Errorf("attribute too short, %d", len(data))
	}

	flags, err := bgp.decodeAttributeFlags(data[index])
	if err != nil {
		return index, attribute, fmt.Errorf("attribute malformed, %s", err)
	}
	attribute.Flag = flags
	index++

	attribute.Code = BGPv4AttributeCode(data[index])
	index++

	if attribute.Flag.ExtendedLength {
		if len(data[index:]) < 2 {
			return index, attribute, fmt.Errorf("attribute extended length not found")
		}
		attribute.Length = binary.BigEndian.Uint16(data[index : index+2])
		index += 2
	} else {
		attribute.Length = uint16(data[index])
		index++
	}

	if len(data[index:]) < int(attribute.Length) {
		return index, attribute, fmt.Errorf("attribute value not found")
	}
	attribute.Value = data[index : index+int(attribute.Length)]
	index += int(attribute.Length)

	return index, attribute, nil
}

// decodeAttributeFlags takes a flag uint8 value and parses it as a
// BGPv4AttributeFlags object. The function returns the object and an error
// or nil.
func (bgp *BGPv4) decodeAttributeFlags(f uint8) (BGPv4AttributeFlags, error) {
	var flags BGPv4AttributeFlags

	flags.Optional = (f>>7)&0b1 == 1
	flags.Transitive = (f>>6)&0b1 == 1
	flags.Partial = (f>>5)&0b1 == 1
	flags.ExtendedLength = (f>>4)&0b1 == 1
	flags.Unused = f & 0b00001111

	if flags.Unused != 0b0000 {
		return flags, fmt.Errorf("attribute flag unused should be at 0, %d", flags.Unused)
	}

	return flags, nil
}

// decodeParameter takes a data slice of bytes and parses it as a
// BGPv4Parameter object. The function returns the object and an error or nil.
func (bgp *BGPv4) decodeParameter(data []byte) (BGPv4Parameter, error) {
	var parameter BGPv4Parameter

	if len(data) < 2 {
		return parameter, fmt.Errorf("parameter too short")
	}

	parameter.Type = data[0]
	parameter.Length = data[1]

	if len(data[2:]) < int(parameter.Length) {
		return parameter, fmt.Errorf("parameter value not found")
	}

	parameter.Value = data[2 : 2+int(parameter.Length)]

	return parameter, nil
}

//******************************************************************************

// NextLayerType returns the layer type of the BGPv4 payload, which is LayerTypePayload.
func (bgp *BGPv4) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

//******************************************************************************

// Payload returns the remaining bytes unused after BGPv4.DecodeFromBytes.
func (bgp *BGPv4) Payload() []byte {
	return bgp.BaseLayer.Payload
}

// CanDecode returns the set of layer types that this DecodingLayer can decode
func (bgp *BGPv4) CanDecode() gopacket.LayerClass {
	return LayerTypeBGPv4
}
