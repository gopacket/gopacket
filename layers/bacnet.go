// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// BACnet/IP support for gopacket, after ASHRAE 135-2020: the BACnet Virtual
// Link Control of Annex J (IPv4) and Annex U (IPv6), the network layer of
// Clause 6 and the application layer of Clause 20.
//
//	UDP 47808
//	  └─ BVLC or BVLC6   link control: BBMD tables, foreign devices, forwarding
//	       └─ BACnetNPDU   network layer: routing, network layer messages
//	            └─ BACnetAPDU  application layer: services, tagged parameters
//
// BACnetSC is the link control of BACnet Secure Connect (Annex AB), which
// runs over WebSockets on TLS: it decodes a binary WebSocket message once
// the caller has unwrapped one. BACnetMSTP is the MS/TP data link of
// Clause 9, the link layer of captures of link type 165; it carries the
// NPDU directly. The other BACnet data links (ARCNET, LonTalk, PTP,
// ZigBee) are not decoded.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
)

// UDPPortBACnet is the default BACnet/IP UDP port (0xBAC0).
const UDPPortBACnet uint16 = 47808

// BACnet layer types, from the block reserved for BACnet and OPC UA.
var (
	// LayerTypeBVLC is the BACnet/IP (IPv4) Virtual Link Control layer. Its
	// decoder also hands a BACnet/IPv6 frame to BVLC6, so one port mapping
	// serves both.
	LayerTypeBVLC = gopacket.RegisterLayerType(175, gopacket.LayerTypeMetadata{Name: "BVLC", Decoder: gopacket.DecodeFunc(decodeBVLC)})
	// LayerTypeBVLC6 is the BACnet/IPv6 Virtual Link Control layer.
	LayerTypeBVLC6 = gopacket.RegisterLayerType(176, gopacket.LayerTypeMetadata{Name: "BVLC6", Decoder: gopacket.DecodeFunc(decodeBVLC6)})
	// LayerTypeBACnetNPDU is the BACnet network layer.
	LayerTypeBACnetNPDU = gopacket.RegisterLayerType(177, gopacket.LayerTypeMetadata{Name: "BACnetNPDU", Decoder: gopacket.DecodeFunc(decodeBACnetNPDU)})
	// LayerTypeBACnetAPDU is the BACnet application layer.
	LayerTypeBACnetAPDU = gopacket.RegisterLayerType(178, gopacket.LayerTypeMetadata{Name: "BACnetAPDU", Decoder: gopacket.DecodeFunc(decodeBACnetAPDU)})
)

// registerBACnetDecoders maps the BACnet/IP port to BVLC and the MS/TP
// link type to BACnetMSTP. It is opt-in so callers who never asked for
// BACnet keep seeing UDP 47808 as payload and link type 165 as unknown.
func registerBACnetDecoders() {
	RegisterUDPPortLayerType(UDPPort(UDPPortBACnet), LayerTypeBVLC)
	LinkTypeMetadata[LinkTypeBACnetMSTP] = EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeBACnetMSTP),
		Name:       "BACnetMSTP",
		LayerType:  LayerTypeBACnetMSTP,
	}
}

// BACnet decoding errors.
var (
	// ErrBACnetTruncated is returned when a BACnet PDU is shorter than its
	// header or than a length it declares.
	ErrBACnetTruncated = errors.New("BACnet PDU truncated")
	// ErrBVLCType is returned for a BVLC type octet that is not BACnet/IP.
	ErrBVLCType = errors.New("BVLC type is not BACnet/IP")
	// ErrBACnetNPDUVersion is returned for an NPDU version other than 1.
	ErrBACnetNPDUVersion = errors.New("BACnet NPDU version is not 1")
	// ErrBACnetMalformed is returned for a field that breaks the encoding rules.
	ErrBACnetMalformed = errors.New("BACnet PDU malformed")
)

// BVLC framing (Annex J.2, U.2).
const (
	bvlcTypeIPv4      uint8 = 0x81
	bvlcTypeIPv6      uint8 = 0x82
	bvlcHeaderLen           = 4
	bvlcAddrLen             = 6  // B/IP address: IPv4 address + UDP port
	bvlcBDTEntryLen         = 10 // B/IP address + broadcast distribution mask
	bvlcFDTEntryLen         = 10 // B/IP address + TTL + seconds remaining
	bvlc6VMACLen            = 3
	bvlc6AddrLen            = 18 // B/IPv6 address: IPv6 address + UDP port
	bacnetUint16Len         = 2
	bacnetIPv4AddrLen       = 4
	bacnetIPv6AddrLen       = 16
)

// BVLCFunction is a BACnet/IP BVLC function (Annex J.2).
type BVLCFunction uint8

// BVLCFunction values.
const (
	BVLCFunctionResult                       BVLCFunction = 0x00
	BVLCFunctionWriteBDT                     BVLCFunction = 0x01
	BVLCFunctionReadBDT                      BVLCFunction = 0x02
	BVLCFunctionReadBDTAck                   BVLCFunction = 0x03
	BVLCFunctionForwardedNPDU                BVLCFunction = 0x04
	BVLCFunctionRegisterForeignDevice        BVLCFunction = 0x05
	BVLCFunctionReadFDT                      BVLCFunction = 0x06
	BVLCFunctionReadFDTAck                   BVLCFunction = 0x07
	BVLCFunctionDeleteFDTEntry               BVLCFunction = 0x08
	BVLCFunctionDistributeBroadcastToNetwork BVLCFunction = 0x09
	BVLCFunctionOriginalUnicastNPDU          BVLCFunction = 0x0A
	BVLCFunctionOriginalBroadcastNPDU        BVLCFunction = 0x0B
	BVLCFunctionSecureBVLL                   BVLCFunction = 0x0C
)

var bvlcFunctionNames = map[BVLCFunction]string{
	BVLCFunctionResult:                       "BVLC-Result",
	BVLCFunctionWriteBDT:                     "Write-Broadcast-Distribution-Table",
	BVLCFunctionReadBDT:                      "Read-Broadcast-Distribution-Table",
	BVLCFunctionReadBDTAck:                   "Read-Broadcast-Distribution-Table-Ack",
	BVLCFunctionForwardedNPDU:                "Forwarded-NPDU",
	BVLCFunctionRegisterForeignDevice:        "Register-Foreign-Device",
	BVLCFunctionReadFDT:                      "Read-Foreign-Device-Table",
	BVLCFunctionReadFDTAck:                   "Read-Foreign-Device-Table-Ack",
	BVLCFunctionDeleteFDTEntry:               "Delete-Foreign-Device-Table-Entry",
	BVLCFunctionDistributeBroadcastToNetwork: "Distribute-Broadcast-To-Network",
	BVLCFunctionOriginalUnicastNPDU:          "Original-Unicast-NPDU",
	BVLCFunctionOriginalBroadcastNPDU:        "Original-Broadcast-NPDU",
	BVLCFunctionSecureBVLL:                   "Secure-BVLL",
}

// String returns the Annex J name of the function.
func (f BVLCFunction) String() string {
	return bacnetName(bvlcFunctionNames, f)
}

// BVLCResultCode is the result code of a BVLC-Result (Annex J.2.1).
type BVLCResultCode uint16

// BVLCResultCode values.
const (
	BVLCResultSuccess                     BVLCResultCode = 0x0000
	BVLCResultWriteBDTNAK                 BVLCResultCode = 0x0010
	BVLCResultReadBDTNAK                  BVLCResultCode = 0x0020
	BVLCResultRegisterForeignDeviceNAK    BVLCResultCode = 0x0030
	BVLCResultReadFDTNAK                  BVLCResultCode = 0x0040
	BVLCResultDeleteFDTEntryNAK           BVLCResultCode = 0x0050
	BVLCResultDistributeBroadcastToNetNAK BVLCResultCode = 0x0060
)

var bvlcResultNames = map[BVLCResultCode]string{
	BVLCResultSuccess:                     "Successful completion",
	BVLCResultWriteBDTNAK:                 "Write-Broadcast-Distribution-Table NAK",
	BVLCResultReadBDTNAK:                  "Read-Broadcast-Distribution-Table NAK",
	BVLCResultRegisterForeignDeviceNAK:    "Register-Foreign-Device NAK",
	BVLCResultReadFDTNAK:                  "Read-Foreign-Device-Table NAK",
	BVLCResultDeleteFDTEntryNAK:           "Delete-Foreign-Device-Table-Entry NAK",
	BVLCResultDistributeBroadcastToNetNAK: "Distribute-Broadcast-To-Network NAK",
}

// String returns the Annex J name of the result code.
func (r BVLCResultCode) String() string {
	return bacnetName(bvlcResultNames, r)
}

// BACnetIPAddress is a B/IP or B/IPv6 address: an IP address and UDP port.
type BACnetIPAddress struct {
	IP   net.IP
	Port uint16
}

// String returns the address as host:port.
func (a BACnetIPAddress) String() string {
	return net.JoinHostPort(a.IP.String(), fmt.Sprint(a.Port))
}

// BVLCBDTEntry is one Broadcast Distribution Table entry (Annex J.4.3.1).
type BVLCBDTEntry struct {
	Address BACnetIPAddress
	Mask    net.IPMask
}

// BVLCFDTEntry is one Foreign Device Table entry (Annex J.5.2.1).
type BVLCFDTEntry struct {
	Address BACnetIPAddress
	// TTL is the time-to-live the foreign device registered with, in seconds.
	TTL uint16
	// Remaining is the number of seconds before the entry is purged.
	Remaining uint16
}

// BVLC is the BACnet/IP Virtual Link Control header (Annex J). Only the
// fields of the decoded function are set.
type BVLC struct {
	BaseLayer
	Type     uint8
	Function BVLCFunction
	// Length is the BVLL length, header included.
	Length uint16

	// ResultCode is set by BVLC-Result.
	ResultCode BVLCResultCode
	// TTL is the time-to-live, in seconds, of Register-Foreign-Device.
	TTL uint16
	// Address is the original source of Forwarded-NPDU, or the entry that
	// Delete-Foreign-Device-Table-Entry removes.
	Address BACnetIPAddress
	// BDT holds the entries of Write-BDT and Read-BDT-Ack.
	BDT []BVLCBDTEntry
	// FDT holds the entries of Read-FDT-Ack.
	FDT []BVLCFDTEntry
	// Secured is the security wrapper of Secure-BVLL, raw.
	Secured []byte
	// Security is Secured decoded, or nil when it is not a whole wrapper.
	Security *BACnetSecurityWrapper
}

// LayerType returns LayerTypeBVLC.
func (b *BVLC) LayerType() gopacket.LayerType { return LayerTypeBVLC }

// CanDecode returns LayerTypeBVLC.
func (b *BVLC) CanDecode() gopacket.LayerClass { return LayerTypeBVLC }

// NextLayerType returns LayerTypeBACnetNPDU when the function carries an NPDU.
func (b *BVLC) NextLayerType() gopacket.LayerType {
	if len(b.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	return LayerTypeBACnetNPDU
}

// DecodeFromBytes decodes a BACnet/IP BVLL. A BACnet/IPv6 frame is
// rejected with ErrBVLCType; decode it with BVLC6. gopacket.NewPacket
// does that by itself; a DecodingLayerParser needs BVLCAny for it.
func (b *BVLC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*b = BVLC{}
	body, err := bvlcFrame(data, bvlcTypeIPv4, df)
	if err != nil {
		return err
	}

	b.Type = data[0]
	b.Function = BVLCFunction(data[1])
	b.Length = uint16(len(body) + bvlcHeaderLen)
	b.Contents = data[:b.Length]

	// Each function has a fixed layout (Annex J.2); the NPDU carriers end
	// their header where the NPDU starts.
	switch b.Function {
	case BVLCFunctionResult:
		if len(body) < bacnetUint16Len {
			return bacnetTruncated(df)
		}
		b.ResultCode = BVLCResultCode(binary.BigEndian.Uint16(body))

	case BVLCFunctionWriteBDT, BVLCFunctionReadBDTAck:
		if len(body)%bvlcBDTEntryLen != 0 {
			return ErrBACnetMalformed
		}
		for e := body; len(e) > 0; e = e[bvlcBDTEntryLen:] {
			b.BDT = append(b.BDT, BVLCBDTEntry{
				Address: bvlcAddress(e),
				Mask:    net.IPMask(e[bvlcAddrLen:bvlcBDTEntryLen]),
			})
		}

	case BVLCFunctionReadFDTAck:
		if len(body)%bvlcFDTEntryLen != 0 {
			return ErrBACnetMalformed
		}
		for e := body; len(e) > 0; e = e[bvlcFDTEntryLen:] {
			b.FDT = append(b.FDT, BVLCFDTEntry{
				Address:   bvlcAddress(e),
				TTL:       binary.BigEndian.Uint16(e[bvlcAddrLen:]),
				Remaining: binary.BigEndian.Uint16(e[bvlcAddrLen+bacnetUint16Len:]),
			})
		}

	case BVLCFunctionForwardedNPDU:
		if len(body) < bvlcAddrLen {
			return bacnetTruncated(df)
		}
		b.Address = bvlcAddress(body)
		b.Contents = data[:bvlcHeaderLen+bvlcAddrLen]
		b.Payload = body[bvlcAddrLen:]

	case BVLCFunctionRegisterForeignDevice:
		if len(body) < bacnetUint16Len {
			return bacnetTruncated(df)
		}
		b.TTL = binary.BigEndian.Uint16(body)

	case BVLCFunctionDeleteFDTEntry:
		if len(body) < bvlcAddrLen {
			return bacnetTruncated(df)
		}
		b.Address = bvlcAddress(body)

	case BVLCFunctionDistributeBroadcastToNetwork, BVLCFunctionOriginalUnicastNPDU, BVLCFunctionOriginalBroadcastNPDU:
		b.Contents = data[:bvlcHeaderLen]
		b.Payload = body

	case BVLCFunctionSecureBVLL:
		b.Secured = body
		b.Security = bacnetSecurityOf(body)
	}
	return nil
}

// bvlcFrame checks the BVLC type and length and returns the bytes after
// the 4-octet header, up to the declared length.
func bvlcFrame(data []byte, typ uint8, df gopacket.DecodeFeedback) ([]byte, error) {
	if len(data) < bvlcHeaderLen {
		return nil, bacnetTruncated(df)
	}
	if data[0] != typ {
		return nil, ErrBVLCType
	}

	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < bvlcHeaderLen {
		return nil, ErrBACnetMalformed
	}
	if length > len(data) {
		return nil, bacnetTruncated(df)
	}
	return data[bvlcHeaderLen:length], nil
}

// bvlcAddress reads a 6-octet B/IP address; the caller checked the length.
func bvlcAddress(b []byte) BACnetIPAddress {
	return BACnetIPAddress{
		IP:   net.IP(b[:bacnetIPv4AddrLen]),
		Port: binary.BigEndian.Uint16(b[bacnetIPv4AddrLen:]),
	}
}

// bacnetTruncated flags the packet truncated and returns ErrBACnetTruncated.
func bacnetTruncated(df gopacket.DecodeFeedback) error {
	df.SetTruncated()
	return ErrBACnetTruncated
}

// BVLCAny decodes either BVLL on the BACnet/IP port, so that a
// DecodingLayerParser reaches BACnet/IPv6 as well: it can decode
// LayerTypeBVLC, looks at the type octet and fills BVLC or BVLC6.
//
//	var any layers.BVLCAny
//	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip6, &udp, &any, &npdu, &apdu)
//
// The parser reports LayerTypeBVLC as decoded for both; IPv6 tells which
// of the two embedded layers the frame filled.
type BVLCAny struct {
	BVLC  BVLC
	BVLC6 BVLC6
	// IPv6 tells which of the two the last frame filled.
	IPv6 bool
}

// CanDecode returns LayerTypeBVLC, what the BACnet/IP port maps to.
func (b *BVLCAny) CanDecode() gopacket.LayerClass { return LayerTypeBVLC }

// NextLayerType returns LayerTypeBACnetNPDU when the function carries an NPDU.
func (b *BVLCAny) NextLayerType() gopacket.LayerType {
	if b.IPv6 {
		return b.BVLC6.NextLayerType()
	}
	return b.BVLC.NextLayerType()
}

// LayerPayload returns the NPDU, if the function carries one.
func (b *BVLCAny) LayerPayload() []byte {
	if b.IPv6 {
		return b.BVLC6.Payload
	}
	return b.BVLC.Payload
}

// DecodeFromBytes decodes a BACnet/IP or BACnet/IPv6 BVLL.
func (b *BVLCAny) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	b.IPv6 = len(data) > 0 && data[0] == bvlcTypeIPv6
	if b.IPv6 {
		return b.BVLC6.DecodeFromBytes(data, df)
	}
	return b.BVLC.DecodeFromBytes(data, df)
}

// decodeBVLC decodes BACnet/IP, handing a BACnet/IPv6 frame (type 0x82) to
// BVLC6 since both share the port.
func decodeBVLC(data []byte, p gopacket.PacketBuilder) error {
	if len(data) > 0 && data[0] == bvlcTypeIPv6 {
		return decodeBVLC6(data, p)
	}
	return decodingLayerDecoder(&BVLC{}, data, p)
}

// BVLC6Function is a BACnet/IPv6 BVLC function (Annex U.2).
type BVLC6Function uint8

// BVLC6Function values.
const (
	BVLC6FunctionResult                       BVLC6Function = 0x00
	BVLC6FunctionOriginalUnicastNPDU          BVLC6Function = 0x01
	BVLC6FunctionOriginalBroadcastNPDU        BVLC6Function = 0x02
	BVLC6FunctionAddressResolution            BVLC6Function = 0x03
	BVLC6FunctionForwardedAddressResolution   BVLC6Function = 0x04
	BVLC6FunctionAddressResolutionAck         BVLC6Function = 0x05
	BVLC6FunctionVirtualAddressResolution     BVLC6Function = 0x06
	BVLC6FunctionVirtualAddressResolutionAck  BVLC6Function = 0x07
	BVLC6FunctionForwardedNPDU                BVLC6Function = 0x08
	BVLC6FunctionRegisterForeignDevice        BVLC6Function = 0x09
	BVLC6FunctionDeleteFDTEntry               BVLC6Function = 0x0A
	BVLC6FunctionSecureBVLL                   BVLC6Function = 0x0B
	BVLC6FunctionDistributeBroadcastToNetwork BVLC6Function = 0x0C
)

var bvlc6FunctionNames = map[BVLC6Function]string{
	BVLC6FunctionResult:                       "BVLC-Result",
	BVLC6FunctionOriginalUnicastNPDU:          "Original-Unicast-NPDU",
	BVLC6FunctionOriginalBroadcastNPDU:        "Original-Broadcast-NPDU",
	BVLC6FunctionAddressResolution:            "Address-Resolution",
	BVLC6FunctionForwardedAddressResolution:   "Forwarded-Address-Resolution",
	BVLC6FunctionAddressResolutionAck:         "Address-Resolution-ACK",
	BVLC6FunctionVirtualAddressResolution:     "Virtual-Address-Resolution",
	BVLC6FunctionVirtualAddressResolutionAck:  "Virtual-Address-Resolution-ACK",
	BVLC6FunctionForwardedNPDU:                "Forwarded-NPDU",
	BVLC6FunctionRegisterForeignDevice:        "Register-Foreign-Device",
	BVLC6FunctionDeleteFDTEntry:               "Delete-Foreign-Device-Table-Entry",
	BVLC6FunctionSecureBVLL:                   "Secure-BVLL",
	BVLC6FunctionDistributeBroadcastToNetwork: "Distribute-Broadcast-To-Network",
}

// String returns the Annex U name of the function.
func (f BVLC6Function) String() string {
	return bacnetName(bvlc6FunctionNames, f)
}

// BVLC6ResultCode is the result code of a BACnet/IPv6 BVLC-Result (Annex U.2.1).
type BVLC6ResultCode uint16

// BVLC6ResultCode values.
const (
	BVLC6ResultSuccess                     BVLC6ResultCode = 0x0000
	BVLC6ResultAddressResolutionNAK        BVLC6ResultCode = 0x0030
	BVLC6ResultVirtualAddressResolutionNAK BVLC6ResultCode = 0x0060
	BVLC6ResultRegisterForeignDeviceNAK    BVLC6ResultCode = 0x0090
	BVLC6ResultDeleteFDTEntryNAK           BVLC6ResultCode = 0x00A0
	BVLC6ResultDistributeBroadcastNAK      BVLC6ResultCode = 0x00C0
)

var bvlc6ResultNames = map[BVLC6ResultCode]string{
	BVLC6ResultSuccess:                     "Successful completion",
	BVLC6ResultAddressResolutionNAK:        "Address-Resolution NAK",
	BVLC6ResultVirtualAddressResolutionNAK: "Virtual-Address-Resolution NAK",
	BVLC6ResultRegisterForeignDeviceNAK:    "Register-Foreign-Device NAK",
	BVLC6ResultDeleteFDTEntryNAK:           "Delete-Foreign-Device-Table-Entry NAK",
	BVLC6ResultDistributeBroadcastNAK:      "Distribute-Broadcast-To-Network NAK",
}

// String returns the Annex U name of the result code.
func (r BVLC6ResultCode) String() string {
	return bacnetName(bvlc6ResultNames, r)
}

// BACnetVMAC is the 3-octet virtual MAC address of a BACnet/IPv6 node.
type BACnetVMAC [bvlc6VMACLen]byte

// bvlc6Layout lists the fields that follow the source VMAC of a BACnet/IPv6
// function, in wire order (Annex U.2).
type bvlc6Layout uint8

const (
	bvlc6DestVMAC bvlc6Layout = 1 << iota
	bvlc6Address
	bvlc6Result
	bvlc6TTL
	bvlc6NPDU
)

var bvlc6Layouts = map[BVLC6Function]bvlc6Layout{
	BVLC6FunctionResult:                       bvlc6Result,
	BVLC6FunctionOriginalUnicastNPDU:          bvlc6DestVMAC | bvlc6NPDU,
	BVLC6FunctionOriginalBroadcastNPDU:        bvlc6NPDU,
	BVLC6FunctionAddressResolution:            bvlc6DestVMAC,
	BVLC6FunctionForwardedAddressResolution:   bvlc6DestVMAC | bvlc6Address,
	BVLC6FunctionAddressResolutionAck:         bvlc6DestVMAC,
	BVLC6FunctionVirtualAddressResolution:     0,
	BVLC6FunctionVirtualAddressResolutionAck:  bvlc6DestVMAC,
	BVLC6FunctionForwardedNPDU:                bvlc6Address | bvlc6NPDU,
	BVLC6FunctionRegisterForeignDevice:        bvlc6TTL,
	BVLC6FunctionDeleteFDTEntry:               bvlc6Address,
	BVLC6FunctionDistributeBroadcastToNetwork: bvlc6NPDU,
}

// BVLC6 is the BACnet/IPv6 Virtual Link Control header (Annex U). Only the
// fields of the decoded function are set.
type BVLC6 struct {
	BaseLayer
	Type     uint8
	Function BVLC6Function
	// Length is the BVLL length, header included.
	Length uint16

	SourceVMAC BACnetVMAC
	// DestinationVMAC is the destination, or the target of an address
	// resolution.
	DestinationVMAC BACnetVMAC
	// ResultCode is set by BVLC-Result.
	ResultCode BVLC6ResultCode
	// TTL is the time-to-live, in seconds, of Register-Foreign-Device.
	TTL uint16
	// Address is the original source of a forwarded message, or the entry
	// that Delete-Foreign-Device-Table-Entry removes.
	Address BACnetIPAddress
	// Secured is the security wrapper of Secure-BVLL, raw.
	Secured []byte
	// Security is Secured decoded, or nil when it is not a whole wrapper.
	Security *BACnetSecurityWrapper
}

// LayerType returns LayerTypeBVLC6.
func (b *BVLC6) LayerType() gopacket.LayerType { return LayerTypeBVLC6 }

// CanDecode returns LayerTypeBVLC6.
func (b *BVLC6) CanDecode() gopacket.LayerClass { return LayerTypeBVLC6 }

// NextLayerType returns LayerTypeBACnetNPDU when the function carries an NPDU.
func (b *BVLC6) NextLayerType() gopacket.LayerType {
	if len(b.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	return LayerTypeBACnetNPDU
}

// DecodeFromBytes decodes a BACnet/IPv6 BVLL.
func (b *BVLC6) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*b = BVLC6{}
	body, err := bvlcFrame(data, bvlcTypeIPv6, df)
	if err != nil {
		return err
	}

	b.Type = data[0]
	b.Function = BVLC6Function(data[1])
	b.Length = uint16(len(body) + bvlcHeaderLen)
	b.Contents = data[:b.Length]

	// Secure-BVLL carries no VMAC, only its wrapper; unknown functions
	// are left in Contents.
	if b.Function == BVLC6FunctionSecureBVLL {
		b.Secured = body
		b.Security = bacnetSecurityOf(body)
		return nil
	}
	layout, ok := bvlc6Layouts[b.Function]
	if !ok {
		return nil
	}

	// Walk the fields in wire order, each after a bounds check.
	if len(body) < bvlc6VMACLen {
		return bacnetTruncated(df)
	}
	copy(b.SourceVMAC[:], body)
	off := bvlc6VMACLen

	if layout&bvlc6DestVMAC != 0 {
		if len(body)-off < bvlc6VMACLen {
			return bacnetTruncated(df)
		}
		copy(b.DestinationVMAC[:], body[off:])
		off += bvlc6VMACLen
	}
	if layout&bvlc6Address != 0 {
		if len(body)-off < bvlc6AddrLen {
			return bacnetTruncated(df)
		}
		b.Address = BACnetIPAddress{
			IP:   net.IP(body[off : off+bacnetIPv6AddrLen]),
			Port: binary.BigEndian.Uint16(body[off+bacnetIPv6AddrLen:]),
		}
		off += bvlc6AddrLen
	}
	if layout&(bvlc6Result|bvlc6TTL) != 0 {
		if len(body)-off < bacnetUint16Len {
			return bacnetTruncated(df)
		}
		v := binary.BigEndian.Uint16(body[off:])
		off += bacnetUint16Len

		// Result and TTL never share a function.
		if layout&bvlc6Result != 0 {
			b.ResultCode = BVLC6ResultCode(v)
		} else {
			b.TTL = v
		}
	}
	if layout&bvlc6NPDU != 0 {
		b.Contents = data[:bvlcHeaderLen+off]
		b.Payload = body[off:]
	}
	return nil
}

func decodeBVLC6(data []byte, p gopacket.PacketBuilder) error {
	return decodingLayerDecoder(&BVLC6{}, data, p)
}

// bacnetName looks v up in a name table, falling back to its number.
func bacnetName[K ~uint8 | ~uint16 | ~uint32](names map[K]string, v K) string {
	if n, ok := names[v]; ok {
		return n
	}
	return fmt.Sprintf("Unknown(%d)", uint32(v))
}
