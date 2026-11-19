// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// BACnet Secure Connect Virtual Link Control (ASHRAE 135-2020 Annex AB.2).
// A BVLC message is one binary WebSocket message of a TLS connection, so
// no port maps to it: decode the unwrapped message with BACnetSC.
//
//	function | control | message id | [originating VMAC] | [destination VMAC]
//	  | [destination options] | [data options] | payload

package layers

import (
	"encoding/binary"
	"strings"

	"github.com/gopacket/gopacket"
)

// LayerTypeBACnetSC is the BACnet/SC Virtual Link Control layer.
var LayerTypeBACnetSC = gopacket.RegisterLayerType(180, gopacket.LayerTypeMetadata{Name: "BACnetSC", Decoder: gopacket.DecodeFunc(decodeBACnetSC)})

// BACnet/SC framing (Annex AB.2).
const (
	bacnetSCHeaderLen = 4 // function, control, message ID
	bacnetSCVMACLen   = 6
	bacnetSCUUIDLen   = 16

	// Header option marker (Annex AB.2.3).
	bacnetSCOptionMore           = 0x80
	bacnetSCOptionMustUnderstand = 0x40
	bacnetSCOptionData           = 0x20
	bacnetSCOptionTypeMask       = 0x1F

	// bacnetSCMaxOptions caps the options kept of one list; a message of
	// the largest size could otherwise name tens of thousands.
	bacnetSCMaxOptions = 64
)

// BACnetSCFunction is a BACnet/SC BVLC function (Annex AB.2.1).
type BACnetSCFunction uint8

// BACnetSCFunction values.
const (
	BACnetSCFunctionResult                    BACnetSCFunction = 0x00
	BACnetSCFunctionEncapsulatedNPDU          BACnetSCFunction = 0x01
	BACnetSCFunctionAddressResolution         BACnetSCFunction = 0x02
	BACnetSCFunctionAddressResolutionAck      BACnetSCFunction = 0x03
	BACnetSCFunctionAdvertisement             BACnetSCFunction = 0x04
	BACnetSCFunctionAdvertisementSolicitation BACnetSCFunction = 0x05
	BACnetSCFunctionConnectRequest            BACnetSCFunction = 0x06
	BACnetSCFunctionConnectAccept             BACnetSCFunction = 0x07
	BACnetSCFunctionDisconnectRequest         BACnetSCFunction = 0x08
	BACnetSCFunctionDisconnectAck             BACnetSCFunction = 0x09
	BACnetSCFunctionHeartbeatRequest          BACnetSCFunction = 0x0A
	BACnetSCFunctionHeartbeatAck              BACnetSCFunction = 0x0B
	BACnetSCFunctionProprietaryMessage        BACnetSCFunction = 0x0C
)

var bacnetSCFunctionNames = map[BACnetSCFunction]string{
	BACnetSCFunctionResult:                    "BVLC-Result",
	BACnetSCFunctionEncapsulatedNPDU:          "Encapsulated-NPDU",
	BACnetSCFunctionAddressResolution:         "Address-Resolution",
	BACnetSCFunctionAddressResolutionAck:      "Address-Resolution-ACK",
	BACnetSCFunctionAdvertisement:             "Advertisement",
	BACnetSCFunctionAdvertisementSolicitation: "Advertisement-Solicitation",
	BACnetSCFunctionConnectRequest:            "Connect-Request",
	BACnetSCFunctionConnectAccept:             "Connect-Accept",
	BACnetSCFunctionDisconnectRequest:         "Disconnect-Request",
	BACnetSCFunctionDisconnectAck:             "Disconnect-ACK",
	BACnetSCFunctionHeartbeatRequest:          "Heartbeat-Request",
	BACnetSCFunctionHeartbeatAck:              "Heartbeat-ACK",
	BACnetSCFunctionProprietaryMessage:        "Proprietary-Message",
}

// String returns the Annex AB name of the function.
func (f BACnetSCFunction) String() string { return bacnetName(bacnetSCFunctionNames, f) }

// BACnetSCControl is the control flags octet (Annex AB.2.2).
type BACnetSCControl uint8

// BACnet/SC control flags.
const (
	bacnetSCControlOrigin      BACnetSCControl = 0x08
	bacnetSCControlDestination BACnetSCControl = 0x04
	bacnetSCControlDestOptions BACnetSCControl = 0x02
	bacnetSCControlDataOptions BACnetSCControl = 0x01
)

// HasOrigin reports whether the originating virtual address is present.
func (c BACnetSCControl) HasOrigin() bool { return c&bacnetSCControlOrigin != 0 }

// HasDestination reports whether the destination virtual address is present.
func (c BACnetSCControl) HasDestination() bool { return c&bacnetSCControlDestination != 0 }

// HasDestinationOptions reports whether destination options are present.
func (c BACnetSCControl) HasDestinationOptions() bool { return c&bacnetSCControlDestOptions != 0 }

// HasDataOptions reports whether data options are present.
func (c BACnetSCControl) HasDataOptions() bool { return c&bacnetSCControlDataOptions != 0 }

// BACnetSCVMAC is the 6-octet virtual MAC address of a BACnet/SC node.
type BACnetSCVMAC [bacnetSCVMACLen]byte

// BACnetSCOptionType is the type of a header option (Annex AB.2.3).
type BACnetSCOptionType uint8

// BACnetSCOptionType values.
const (
	BACnetSCOptionSecurePath  BACnetSCOptionType = 1
	BACnetSCOptionProprietary BACnetSCOptionType = 31
)

var bacnetSCOptionNames = map[BACnetSCOptionType]string{
	BACnetSCOptionSecurePath:  "Secure Path",
	BACnetSCOptionProprietary: "Proprietary",
}

// String returns the Annex AB name of the option type.
func (t BACnetSCOptionType) String() string { return bacnetName(bacnetSCOptionNames, t) }

// BACnetSCOption is one header option (Annex AB.2.3). The standard
// defines two: Secure Path, a data option without data that marks a
// message which only ever travelled over secure links, and Proprietary.
type BACnetSCOption struct {
	Type BACnetSCOptionType
	// MustUnderstand tells a node that does not know the option to
	// reject the message.
	MustUnderstand bool
	// Data is the option data, nil when the marker says there is none.
	Data []byte

	// VendorID, ProprietaryType and ProprietaryData are Data decoded for
	// a Proprietary option: the vendor, the option type the vendor chose
	// and the data that goes with it.
	VendorID        uint16
	ProprietaryType uint8
	ProprietaryData []byte
}

// BACnetSCHubConnection is the hub connection status of an Advertisement
// (Annex AB.2.8).
type BACnetSCHubConnection uint8

// BACnetSCHubConnection values.
const (
	BACnetSCHubNone     BACnetSCHubConnection = 0
	BACnetSCHubPrimary  BACnetSCHubConnection = 1
	BACnetSCHubFailover BACnetSCHubConnection = 2
)

var bacnetSCHubNames = map[BACnetSCHubConnection]string{
	BACnetSCHubNone:     "No hub connection",
	BACnetSCHubPrimary:  "Connected to primary hub",
	BACnetSCHubFailover: "Connected to failover hub",
}

// String returns the Annex AB name of the hub connection status.
func (c BACnetSCHubConnection) String() string { return bacnetName(bacnetSCHubNames, c) }

// BACnetSCResultCode is the result code of a BVLC-Result (Annex AB.2.4).
type BACnetSCResultCode uint8

// BACnetSCResultCode values.
const (
	BACnetSCResultACK BACnetSCResultCode = 0
	BACnetSCResultNAK BACnetSCResultCode = 1
)

var bacnetSCResultNames = map[BACnetSCResultCode]string{
	BACnetSCResultACK: "ACK",
	BACnetSCResultNAK: "NAK",
}

// String returns the Annex AB name of the result code.
func (r BACnetSCResultCode) String() string { return bacnetName(bacnetSCResultNames, r) }

// BACnetSC is a BACnet/SC BVLC message (Annex AB.2). The header fields
// are set according to Control, the others only by the decoded function.
type BACnetSC struct {
	BaseLayer
	Function  BACnetSCFunction
	Control   BACnetSCControl
	MessageID uint16

	// OriginVMAC and DestinationVMAC are set when Control says so.
	OriginVMAC      BACnetSCVMAC
	DestinationVMAC BACnetSCVMAC
	// DestinationOptions and DataOptions hold at most 64 options each;
	// more are skipped.
	DestinationOptions []BACnetSCOption
	DataOptions        []BACnetSCOption

	// ResultFunction, ResultCode, Error and ErrorDetails belong to
	// BVLC-Result: the function answered, ACK or NAK, and for a NAK the
	// error and its UTF-8 details. ErrorMarker is the header marker of the
	// option that caused the NAK, 0 if none did.
	ResultFunction BACnetSCFunction
	ResultCode     BACnetSCResultCode
	ErrorMarker    uint8
	Error          BACnetError
	ErrorDetails   string

	// URIs is the space-separated WebSocket URI list of an
	// Address-Resolution-ACK.
	URIs string

	// HubConnection and AcceptsConnections (direct connections) belong to
	// Advertisement.
	HubConnection      BACnetSCHubConnection
	AcceptsConnections bool
	// MaxBVLCLength and MaxNPDULength are what the sender accepts, set by
	// Advertisement, Connect-Request and Connect-Accept.
	MaxBVLCLength uint16
	MaxNPDULength uint16
	// ConnectVMAC and DeviceUUID identify the sender of Connect-Request
	// and Connect-Accept.
	ConnectVMAC BACnetSCVMAC
	DeviceUUID  [bacnetSCUUIDLen]byte

	// VendorID, ProprietaryFunction and ProprietaryData belong to
	// Proprietary-Message.
	VendorID            uint16
	ProprietaryFunction uint8
	ProprietaryData     []byte
}

// LayerType returns LayerTypeBACnetSC.
func (b *BACnetSC) LayerType() gopacket.LayerType { return LayerTypeBACnetSC }

// CanDecode returns LayerTypeBACnetSC.
func (b *BACnetSC) CanDecode() gopacket.LayerClass { return LayerTypeBACnetSC }

// NextLayerType returns LayerTypeBACnetNPDU for an Encapsulated-NPDU.
func (b *BACnetSC) NextLayerType() gopacket.LayerType {
	if len(b.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	return LayerTypeBACnetNPDU
}

// DecodeFromBytes decodes a BACnet/SC BVLC message, which takes all of
// data: the WebSocket message gives its length.
func (b *BACnetSC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*b = BACnetSC{}
	if len(data) < bacnetSCHeaderLen {
		return bacnetTruncated(df)
	}
	b.Function = BACnetSCFunction(data[0])
	b.Control = BACnetSCControl(data[1])
	b.MessageID = binary.BigEndian.Uint16(data[2:])
	off := bacnetSCHeaderLen

	var err error
	if b.Control.HasOrigin() {
		if off, err = bacnetSCAddress(data, off, &b.OriginVMAC, df); err != nil {
			return err
		}
	}
	if b.Control.HasDestination() {
		if off, err = bacnetSCAddress(data, off, &b.DestinationVMAC, df); err != nil {
			return err
		}
	}
	if b.Control.HasDestinationOptions() {
		if b.DestinationOptions, off, err = bacnetSCOptions(data, off, df); err != nil {
			return err
		}
	}
	if b.Control.HasDataOptions() {
		if b.DataOptions, off, err = bacnetSCOptions(data, off, df); err != nil {
			return err
		}
	}

	b.Contents = data
	return b.decodePayload(data, off, df)
}

// bacnetSCAddress reads a VMAC at off and returns the offset after it.
func bacnetSCAddress(data []byte, off int, vmac *BACnetSCVMAC, df gopacket.DecodeFeedback) (int, error) {
	if len(data)-off < bacnetSCVMACLen {
		return off, bacnetTruncated(df)
	}
	copy(vmac[:], data[off:])
	return off + bacnetSCVMACLen, nil
}

// bacnetSCOptions reads a list of header options at off, each a marker
// octet and, when the marker says so, a 2-octet length and data. The
// list ends with the option whose marker has no "more" flag.
func bacnetSCOptions(data []byte, off int, df gopacket.DecodeFeedback) ([]BACnetSCOption, int, error) {
	var opts []BACnetSCOption

	for more := true; more; {
		if len(data)-off < 1 {
			return nil, off, bacnetTruncated(df)
		}
		marker := data[off]
		off++
		more = marker&bacnetSCOptionMore != 0

		opt := BACnetSCOption{
			Type:           BACnetSCOptionType(marker & bacnetSCOptionTypeMask),
			MustUnderstand: marker&bacnetSCOptionMustUnderstand != 0,
		}
		if marker&bacnetSCOptionData != 0 {
			if len(data)-off < bacnetUint16Len {
				return nil, off, bacnetTruncated(df)
			}
			size := int(binary.BigEndian.Uint16(data[off:]))
			off += bacnetUint16Len

			if len(data)-off < size {
				return nil, off, bacnetTruncated(df)
			}
			opt.Data = data[off : off+size : off+size]
			off += size
		}

		// vendor ID, proprietary option type, data
		const proprietaryHeaderLen = bacnetUint16Len + 1
		if opt.Type == BACnetSCOptionProprietary && len(opt.Data) >= proprietaryHeaderLen {
			opt.VendorID = binary.BigEndian.Uint16(opt.Data)
			opt.ProprietaryType = opt.Data[bacnetUint16Len]
			opt.ProprietaryData = opt.Data[proprietaryHeaderLen:]
		}

		if len(opts) < bacnetSCMaxOptions {
			opts = append(opts, opt)
		}
	}
	return opts, off, nil
}

// URIList returns the WebSocket URIs of an Address-Resolution-ACK, which
// a single space separates on the wire; nil when there are none.
func (b *BACnetSC) URIList() []string {
	if b.URIs == "" {
		return nil
	}
	return strings.Split(b.URIs, " ")
}

// SecurePath reports whether the message carries the Secure Path data
// option: it never left BACnet/SC on its way.
func (b *BACnetSC) SecurePath() bool {
	for i := range b.DataOptions {
		if b.DataOptions[i].Type == BACnetSCOptionSecurePath {
			return true
		}
	}
	return false
}

// decodePayload decodes what follows the header at off, by function.
// Address-Resolution, Advertisement-Solicitation, Disconnect-Request,
// Disconnect-ACK, Heartbeat-Request and Heartbeat-ACK have no payload;
// what follows them, and unknown functions, is left in Contents.
func (b *BACnetSC) decodePayload(data []byte, off int, df gopacket.DecodeFeedback) error {
	body := data[off:]

	switch b.Function {
	case BACnetSCFunctionEncapsulatedNPDU:
		b.Contents = data[:off]
		b.Payload = body

	case BACnetSCFunctionResult:
		return b.decodeResult(body, df)

	case BACnetSCFunctionAddressResolutionAck:
		b.URIs = string(body)

	case BACnetSCFunctionAdvertisement:
		// hub connection status, accept direct connections, two lengths
		const size = 2 + 2*bacnetUint16Len
		if len(body) < size {
			return bacnetTruncated(df)
		}
		b.HubConnection = BACnetSCHubConnection(body[0])
		b.AcceptsConnections = body[1] != 0
		b.decodeLengths(body[2:])

	case BACnetSCFunctionConnectRequest, BACnetSCFunctionConnectAccept:
		const size = bacnetSCVMACLen + bacnetSCUUIDLen + 2*bacnetUint16Len
		if len(body) < size {
			return bacnetTruncated(df)
		}
		copy(b.ConnectVMAC[:], body)
		copy(b.DeviceUUID[:], body[bacnetSCVMACLen:])
		b.decodeLengths(body[bacnetSCVMACLen+bacnetSCUUIDLen:])

	case BACnetSCFunctionProprietaryMessage:
		// vendor ID and proprietary function
		const size = bacnetUint16Len + 1
		if len(body) < size {
			return bacnetTruncated(df)
		}
		b.VendorID = binary.BigEndian.Uint16(body)
		b.ProprietaryFunction = body[bacnetUint16Len]
		b.ProprietaryData = body[size:]
	}
	return nil
}

// decodeLengths reads the maximum BVLC and NPDU lengths; the caller
// checked the length.
func (b *BACnetSC) decodeLengths(body []byte) {
	b.MaxBVLCLength = binary.BigEndian.Uint16(body)
	b.MaxNPDULength = binary.BigEndian.Uint16(body[bacnetUint16Len:])
}

// decodeResult decodes a BVLC-Result (Annex AB.2.4):
//
//	result for function | result code | [marker | class | code | details]
func (b *BACnetSC) decodeResult(body []byte, df gopacket.DecodeFeedback) error {
	const (
		ackLen = 2                     // function, result code
		nakLen = 1 + 2*bacnetUint16Len // marker, error class, error code
	)
	if len(body) < ackLen {
		return bacnetTruncated(df)
	}
	b.ResultFunction = BACnetSCFunction(body[0])
	b.ResultCode = BACnetSCResultCode(body[1])
	if b.ResultCode == BACnetSCResultACK {
		return nil
	}

	nak := body[ackLen:]
	if len(nak) < nakLen {
		return bacnetTruncated(df)
	}
	b.ErrorMarker = nak[0]
	b.Error = BACnetError{
		Class: BACnetErrorClass(binary.BigEndian.Uint16(nak[1:])),
		Code:  BACnetErrorCode(binary.BigEndian.Uint16(nak[1+bacnetUint16Len:])),
	}
	b.ErrorDetails = string(nak[nakLen:])
	return nil
}

func decodeBACnetSC(data []byte, p gopacket.PacketBuilder) error {
	return decodingLayerDecoder(&BACnetSC{}, data, p)
}
