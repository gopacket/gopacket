// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// BACnet network layer (ASHRAE 135 Clause 6).

package layers

import (
	"encoding/binary"

	"github.com/gopacket/gopacket"
)

// NPDU framing (Clause 6.2).
const (
	bacnetNPDUVersion      uint8 = 0x01
	bacnetNPDUMinLen             = 2 // version + control
	bacnetNetAddrHeaderLen       = 3 // network number + MAC length
	bacnetProprietaryMsg   uint8 = 0x80
	bacnetRouteEntryLen          = 4 // DNET + port ID + port info length
)

// BACnetNPDUControl is the NPCI control octet (Clause 6.2.2).
type BACnetNPDUControl uint8

// NPCI control bits.
const (
	bacnetControlNetworkMessage BACnetNPDUControl = 0x80
	bacnetControlDestination    BACnetNPDUControl = 0x20
	bacnetControlSource         BACnetNPDUControl = 0x08
	bacnetControlExpectingReply BACnetNPDUControl = 0x04
	bacnetControlPriorityMask   BACnetNPDUControl = 0x03
)

// NetworkMessage reports whether the NPDU carries a network layer message
// instead of an APDU.
func (c BACnetNPDUControl) NetworkMessage() bool { return c&bacnetControlNetworkMessage != 0 }

// HasDestination reports whether DNET, DLEN, DADR and the hop count are present.
func (c BACnetNPDUControl) HasDestination() bool { return c&bacnetControlDestination != 0 }

// HasSource reports whether SNET, SLEN and SADR are present.
func (c BACnetNPDUControl) HasSource() bool { return c&bacnetControlSource != 0 }

// ExpectingReply reports whether the sender expects a reply.
func (c BACnetNPDUControl) ExpectingReply() bool { return c&bacnetControlExpectingReply != 0 }

// Priority returns the network priority.
func (c BACnetNPDUControl) Priority() BACnetPriority {
	return BACnetPriority(c & bacnetControlPriorityMask)
}

// BACnetPriority is the network priority of an NPDU (Clause 6.2.2).
type BACnetPriority uint8

// BACnetPriority values.
const (
	BACnetPriorityNormal            BACnetPriority = 0
	BACnetPriorityUrgent            BACnetPriority = 1
	BACnetPriorityCriticalEquipment BACnetPriority = 2
	BACnetPriorityLifeSafety        BACnetPriority = 3
)

var bacnetPriorityNames = map[BACnetPriority]string{
	BACnetPriorityNormal:            "Normal",
	BACnetPriorityUrgent:            "Urgent",
	BACnetPriorityCriticalEquipment: "Critical Equipment",
	BACnetPriorityLifeSafety:        "Life Safety",
}

// String returns the name of the priority.
func (p BACnetPriority) String() string { return bacnetName(bacnetPriorityNames, p) }

// BACnetNetworkMessageType is a network layer message type (Clause 6.2.4).
type BACnetNetworkMessageType uint8

// BACnetNetworkMessageType values. Types from 0x80 are proprietary and
// carry a vendor ID.
const (
	BACnetNetworkMessageWhoIsRouterToNetwork          BACnetNetworkMessageType = 0x00
	BACnetNetworkMessageIAmRouterToNetwork            BACnetNetworkMessageType = 0x01
	BACnetNetworkMessageICouldBeRouterToNetwork       BACnetNetworkMessageType = 0x02
	BACnetNetworkMessageRejectMessageToNetwork        BACnetNetworkMessageType = 0x03
	BACnetNetworkMessageRouterBusyToNetwork           BACnetNetworkMessageType = 0x04
	BACnetNetworkMessageRouterAvailableToNetwork      BACnetNetworkMessageType = 0x05
	BACnetNetworkMessageInitializeRoutingTable        BACnetNetworkMessageType = 0x06
	BACnetNetworkMessageInitializeRoutingTableAck     BACnetNetworkMessageType = 0x07
	BACnetNetworkMessageEstablishConnectionToNetwork  BACnetNetworkMessageType = 0x08
	BACnetNetworkMessageDisconnectConnectionToNetwork BACnetNetworkMessageType = 0x09
	BACnetNetworkMessageChallengeRequest              BACnetNetworkMessageType = 0x0A
	BACnetNetworkMessageSecurityPayload               BACnetNetworkMessageType = 0x0B
	BACnetNetworkMessageSecurityResponse              BACnetNetworkMessageType = 0x0C
	BACnetNetworkMessageRequestKeyUpdate              BACnetNetworkMessageType = 0x0D
	BACnetNetworkMessageUpdateKeySet                  BACnetNetworkMessageType = 0x0E
	BACnetNetworkMessageUpdateDistributionKey         BACnetNetworkMessageType = 0x0F
	BACnetNetworkMessageRequestMasterKey              BACnetNetworkMessageType = 0x10
	BACnetNetworkMessageSetMasterKey                  BACnetNetworkMessageType = 0x11
	BACnetNetworkMessageWhatIsNetworkNumber           BACnetNetworkMessageType = 0x12
	BACnetNetworkMessageNetworkNumberIs               BACnetNetworkMessageType = 0x13
)

var bacnetNetworkMessageNames = map[BACnetNetworkMessageType]string{
	BACnetNetworkMessageWhoIsRouterToNetwork:          "Who-Is-Router-To-Network",
	BACnetNetworkMessageIAmRouterToNetwork:            "I-Am-Router-To-Network",
	BACnetNetworkMessageICouldBeRouterToNetwork:       "I-Could-Be-Router-To-Network",
	BACnetNetworkMessageRejectMessageToNetwork:        "Reject-Message-To-Network",
	BACnetNetworkMessageRouterBusyToNetwork:           "Router-Busy-To-Network",
	BACnetNetworkMessageRouterAvailableToNetwork:      "Router-Available-To-Network",
	BACnetNetworkMessageInitializeRoutingTable:        "Initialize-Routing-Table",
	BACnetNetworkMessageInitializeRoutingTableAck:     "Initialize-Routing-Table-Ack",
	BACnetNetworkMessageEstablishConnectionToNetwork:  "Establish-Connection-To-Network",
	BACnetNetworkMessageDisconnectConnectionToNetwork: "Disconnect-Connection-To-Network",
	BACnetNetworkMessageChallengeRequest:              "Challenge-Request",
	BACnetNetworkMessageSecurityPayload:               "Security-Payload",
	BACnetNetworkMessageSecurityResponse:              "Security-Response",
	BACnetNetworkMessageRequestKeyUpdate:              "Request-Key-Update",
	BACnetNetworkMessageUpdateKeySet:                  "Update-Key-Set",
	BACnetNetworkMessageUpdateDistributionKey:         "Update-Distribution-Key",
	BACnetNetworkMessageRequestMasterKey:              "Request-Master-Key",
	BACnetNetworkMessageSetMasterKey:                  "Set-Master-Key",
	BACnetNetworkMessageWhatIsNetworkNumber:           "What-Is-Network-Number",
	BACnetNetworkMessageNetworkNumberIs:               "Network-Number-Is",
}

// String returns the Clause 6 name of the message type.
func (t BACnetNetworkMessageType) String() string {
	if uint8(t) >= bacnetProprietaryMsg {
		return "Proprietary"
	}
	return bacnetName(bacnetNetworkMessageNames, t)
}

// BACnetNetworkRejectReason is the reason of a Reject-Message-To-Network
// (Clause 6.4.4).
type BACnetNetworkRejectReason uint8

// BACnetNetworkRejectReason values.
const (
	BACnetNetworkRejectOther           BACnetNetworkRejectReason = 0
	BACnetNetworkRejectUnknownNetwork  BACnetNetworkRejectReason = 1
	BACnetNetworkRejectRouterBusy      BACnetNetworkRejectReason = 2
	BACnetNetworkRejectUnknownMessage  BACnetNetworkRejectReason = 3
	BACnetNetworkRejectMessageTooLong  BACnetNetworkRejectReason = 4
	BACnetNetworkRejectSecurityError   BACnetNetworkRejectReason = 5
	BACnetNetworkRejectAddressingError BACnetNetworkRejectReason = 6
)

var bacnetNetworkRejectNames = map[BACnetNetworkRejectReason]string{
	BACnetNetworkRejectOther:           "Other",
	BACnetNetworkRejectUnknownNetwork:  "Not directly connected to DNET",
	BACnetNetworkRejectRouterBusy:      "Router busy",
	BACnetNetworkRejectUnknownMessage:  "Unknown network message type",
	BACnetNetworkRejectMessageTooLong:  "Message too long",
	BACnetNetworkRejectSecurityError:   "Security error",
	BACnetNetworkRejectAddressingError: "Addressing error",
}

// String returns the description of the reject reason.
func (r BACnetNetworkRejectReason) String() string {
	return bacnetName(bacnetNetworkRejectNames, r)
}

// BACnetNetworkNumberStatus tells how a router knows the number of the
// network in a Network-Number-Is (Clause 6.4.20).
type BACnetNetworkNumberStatus uint8

// BACnetNetworkNumberStatus values.
const (
	BACnetNetworkNumberLearned    BACnetNetworkNumberStatus = 0
	BACnetNetworkNumberConfigured BACnetNetworkNumberStatus = 1
)

// BACnetRoutingEntry is one entry of an Initialize-Routing-Table(-Ack)
// (Clause 6.4.7).
type BACnetRoutingEntry struct {
	DNET     uint16
	PortID   uint8
	PortInfo []byte
}

// BACnetNPDU is the BACnet network layer header (Clause 6.2). The
// destination, source and network message fields are set only when the
// control octet says they are present.
type BACnetNPDU struct {
	BaseLayer
	Version uint8
	Control BACnetNPDUControl

	// DNET and DADR name the destination network and MAC address; an empty
	// DADR is a broadcast on DNET, and DNET 0xFFFF a global broadcast.
	DNET     uint16
	DADR     []byte
	SNET     uint16
	SADR     []byte
	HopCount uint8

	MessageType BACnetNetworkMessageType
	// VendorID is set for proprietary message types.
	VendorID uint16
	// Body is the raw network layer message after its type (and vendor ID).
	Body []byte
	// Security is the security wrapper of the network security messages,
	// Challenge-Request to Set-Master-Key, or nil when Body is not a whole
	// wrapper. What the wrapper secures is its Message, unless encrypted.
	Security *BACnetSecurityWrapper

	// Networks is the DNET list of Who-Is-Router (at most one),
	// I-Am-Router, Router-Busy and Router-Available, and the single network
	// of I-Could-Be-Router, Reject-Message, Establish-Connection,
	// Disconnect-Connection and Network-Number-Is.
	Networks []uint16
	// PerformanceIndex is set by I-Could-Be-Router-To-Network.
	PerformanceIndex uint8
	// RejectReason is set by Reject-Message-To-Network.
	RejectReason BACnetNetworkRejectReason
	// TerminationTime is the Establish-Connection-To-Network time, in seconds.
	TerminationTime uint8
	// NetworkNumberStatus is set by Network-Number-Is.
	NetworkNumberStatus BACnetNetworkNumberStatus
	// RoutingTable holds the Initialize-Routing-Table(-Ack) entries.
	RoutingTable []BACnetRoutingEntry
}

// LayerType returns LayerTypeBACnetNPDU.
func (n *BACnetNPDU) LayerType() gopacket.LayerType { return LayerTypeBACnetNPDU }

// CanDecode returns LayerTypeBACnetNPDU.
func (n *BACnetNPDU) CanDecode() gopacket.LayerClass { return LayerTypeBACnetNPDU }

// NextLayerType returns LayerTypeBACnetAPDU when the NPDU carries an APDU:
// directly, or in a Security-Payload that is not encrypted. The other
// network layer messages end the packet.
func (n *BACnetNPDU) NextLayerType() gopacket.LayerType {
	if len(n.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	return LayerTypeBACnetAPDU
}

// DecodeFromBytes decodes an NPDU.
func (n *BACnetNPDU) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*n = BACnetNPDU{}
	if len(data) < bacnetNPDUMinLen {
		return bacnetTruncated(df)
	}
	n.Version = data[0]
	n.Control = BACnetNPDUControl(data[1])
	if n.Version != bacnetNPDUVersion {
		return ErrBACnetNPDUVersion
	}
	off := bacnetNPDUMinLen

	// The destination, source and hop count appear in that order, each
	// only when the control octet announces it (Clause 6.2.2).
	var err error
	if n.Control.HasDestination() {
		if n.DNET, n.DADR, off, err = bacnetNetAddr(data, off, df); err != nil {
			return err
		}
	}
	if n.Control.HasSource() {
		if n.SNET, n.SADR, off, err = bacnetNetAddr(data, off, df); err != nil {
			return err
		}
		// SLEN 0 is invalid: a source is never a broadcast.
		if len(n.SADR) == 0 {
			return ErrBACnetMalformed
		}
	}
	if n.Control.HasDestination() {
		if off >= len(data) {
			return bacnetTruncated(df)
		}
		n.HopCount = data[off]
		off++
	}

	if !n.Control.NetworkMessage() {
		n.Contents = data[:off]
		n.Payload = data[off:]
		return nil
	}

	// A network layer message: type, vendor ID when proprietary, body.
	if off >= len(data) {
		return bacnetTruncated(df)
	}
	n.MessageType = BACnetNetworkMessageType(data[off])
	off++
	if uint8(n.MessageType) >= bacnetProprietaryMsg {
		if len(data)-off < bacnetUint16Len {
			return bacnetTruncated(df)
		}
		n.VendorID = binary.BigEndian.Uint16(data[off:])
		off += bacnetUint16Len
	}
	n.Contents = data
	n.Body = data[off:]
	return n.decodeMessage(df)
}

// bacnetNetAddr reads a network number, MAC length and MAC address at off.
func bacnetNetAddr(data []byte, off int, df gopacket.DecodeFeedback) (uint16, []byte, int, error) {
	if len(data)-off < bacnetNetAddrHeaderLen {
		return 0, nil, off, bacnetTruncated(df)
	}
	num := binary.BigEndian.Uint16(data[off:])
	alen := int(data[off+bacnetUint16Len])
	off += bacnetNetAddrHeaderLen

	if len(data)-off < alen {
		return 0, nil, off, bacnetTruncated(df)
	}
	return num, data[off : off+alen], off + alen, nil
}

// decodeMessage decodes the body of the standard network layer messages
// that carry network numbers, and the wrapper of the security messages.
func (n *BACnetNPDU) decodeMessage(df gopacket.DecodeFeedback) error {
	body := n.Body

	switch n.MessageType {
	case BACnetNetworkMessageWhoIsRouterToNetwork:
		// The DNET is optional: absent, every reachable network is asked.
		if len(body) == 0 {
			return nil
		}
		return n.decodeNetworks(body, bacnetUint16Len, df)

	case BACnetNetworkMessageIAmRouterToNetwork, BACnetNetworkMessageRouterBusyToNetwork,
		BACnetNetworkMessageRouterAvailableToNetwork:
		if len(body)%bacnetUint16Len != 0 {
			return ErrBACnetMalformed
		}
		return n.decodeNetworks(body, len(body), df)

	case BACnetNetworkMessageICouldBeRouterToNetwork, BACnetNetworkMessageEstablishConnectionToNetwork,
		BACnetNetworkMessageNetworkNumberIs:
		// A DNET then one octet: performance index, seconds, or status.
		if len(body) < bacnetUint16Len+1 {
			return bacnetTruncated(df)
		}
		n.Networks = []uint16{binary.BigEndian.Uint16(body)}
		v := body[bacnetUint16Len]
		switch n.MessageType {
		case BACnetNetworkMessageICouldBeRouterToNetwork:
			n.PerformanceIndex = v
		case BACnetNetworkMessageEstablishConnectionToNetwork:
			n.TerminationTime = v
		default:
			n.NetworkNumberStatus = BACnetNetworkNumberStatus(v)
		}

	case BACnetNetworkMessageRejectMessageToNetwork:
		if len(body) < 1+bacnetUint16Len {
			return bacnetTruncated(df)
		}
		n.RejectReason = BACnetNetworkRejectReason(body[0])
		n.Networks = []uint16{binary.BigEndian.Uint16(body[1:])}

	case BACnetNetworkMessageDisconnectConnectionToNetwork:
		return n.decodeNetworks(body, bacnetUint16Len, df)

	case BACnetNetworkMessageInitializeRoutingTable, BACnetNetworkMessageInitializeRoutingTableAck:
		return n.decodeRoutingTable(body, df)

	default:
		if n.MessageType.security() {
			n.decodeSecurity()
		}
	}
	return nil
}

// decodeSecurity decodes the security wrapper that is the body of a
// network security message, and the message in it. An APDU secured in
// plain text becomes the payload of the NPDU:
//
//	01 80 | 0B | wrapper header | length | APDU | signature
//	NPDU    Security-Payload               Payload
func (n *BACnetNPDU) decodeSecurity() {
	w := bacnetSecurityOf(n.Body)
	if w == nil {
		return
	}
	w.decodeMessage(n.MessageType)
	n.Security = w

	p, ok := w.Message.(*BACnetSecurityPayload)
	if !ok || w.Control.NetworkMessage() || len(p.Payload) == 0 {
		return
	}
	n.Contents = n.Contents[:len(n.Contents)-len(w.Signature)-len(p.Payload)]
	n.Payload = p.Payload
}

// security reports whether t is one of the network security messages of
// Clause 24.3, whose body is a security wrapper.
func (t BACnetNetworkMessageType) security() bool {
	return t >= BACnetNetworkMessageChallengeRequest && t <= BACnetNetworkMessageSetMasterKey
}

// decodeNetworks reads size bytes of big-endian network numbers.
func (n *BACnetNPDU) decodeNetworks(body []byte, size int, df gopacket.DecodeFeedback) error {
	if len(body) < size {
		return bacnetTruncated(df)
	}
	for b := body[:size]; len(b) >= bacnetUint16Len; b = b[bacnetUint16Len:] {
		n.Networks = append(n.Networks, binary.BigEndian.Uint16(b))
	}
	return nil
}

// decodeRoutingTable reads a port count then that many routing entries.
// An empty Ack, sent in reply to a query, has no count at all.
func (n *BACnetNPDU) decodeRoutingTable(body []byte, df gopacket.DecodeFeedback) error {
	if len(body) == 0 {
		return nil
	}
	count := int(body[0])
	b := body[1:]

	for i := 0; i < count; i++ {
		if len(b) < bacnetRouteEntryLen {
			return bacnetTruncated(df)
		}
		infoLen := int(b[bacnetRouteEntryLen-1])
		if len(b)-bacnetRouteEntryLen < infoLen {
			return bacnetTruncated(df)
		}
		n.RoutingTable = append(n.RoutingTable, BACnetRoutingEntry{
			DNET:     binary.BigEndian.Uint16(b),
			PortID:   b[bacnetUint16Len],
			PortInfo: b[bacnetRouteEntryLen : bacnetRouteEntryLen+infoLen],
		})
		b = b[bacnetRouteEntryLen+infoLen:]
	}
	return nil
}

func decodeBACnetNPDU(data []byte, p gopacket.PacketBuilder) error {
	return decodingLayerDecoder(&BACnetNPDU{}, data, p)
}
