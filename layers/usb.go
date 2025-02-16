// Copyright 2014 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/gopacket/gopacket"
)

type USBEventType uint8

const (
	USBEventTypeSubmit   USBEventType = 'S'
	USBEventTypeComplete USBEventType = 'C'
	USBEventTypeError    USBEventType = 'E'
)

func (a USBEventType) String() string {
	switch a {
	case USBEventTypeSubmit:
		return "SUBMIT"
	case USBEventTypeComplete:
		return "COMPLETE"
	case USBEventTypeError:
		return "ERROR"
	default:
		return "Unknown event type"
	}
}

type USBRequestBlockSetupRequest uint8

const (
	USBRequestBlockSetupRequestGetStatus        USBRequestBlockSetupRequest = 0x00
	USBRequestBlockSetupRequestClearFeature     USBRequestBlockSetupRequest = 0x01
	USBRequestBlockSetupRequestSetFeature       USBRequestBlockSetupRequest = 0x03
	USBRequestBlockSetupRequestSetAddress       USBRequestBlockSetupRequest = 0x05
	USBRequestBlockSetupRequestGetDescriptor    USBRequestBlockSetupRequest = 0x06
	USBRequestBlockSetupRequestSetDescriptor    USBRequestBlockSetupRequest = 0x07
	USBRequestBlockSetupRequestGetConfiguration USBRequestBlockSetupRequest = 0x08
	USBRequestBlockSetupRequestSetConfiguration USBRequestBlockSetupRequest = 0x09
	USBRequestBlockSetupRequestSetIdle          USBRequestBlockSetupRequest = 0x0a
)

func (a USBRequestBlockSetupRequest) String() string {
	switch a {
	case USBRequestBlockSetupRequestGetStatus:
		return "GET_STATUS"
	case USBRequestBlockSetupRequestClearFeature:
		return "CLEAR_FEATURE"
	case USBRequestBlockSetupRequestSetFeature:
		return "SET_FEATURE"
	case USBRequestBlockSetupRequestSetAddress:
		return "SET_ADDRESS"
	case USBRequestBlockSetupRequestGetDescriptor:
		return "GET_DESCRIPTOR"
	case USBRequestBlockSetupRequestSetDescriptor:
		return "SET_DESCRIPTOR"
	case USBRequestBlockSetupRequestGetConfiguration:
		return "GET_CONFIGURATION"
	case USBRequestBlockSetupRequestSetConfiguration:
		return "SET_CONFIGURATION"
	case USBRequestBlockSetupRequestSetIdle:
		return "SET_IDLE"
	default:
		return "UNKNOWN"
	}
}

type USBTransportType uint8

const (
	USBTransportTypeTransferIn  USBTransportType = 0x80 // Indicates send or receive
	USBTransportTypeIsochronous USBTransportType = 0x00 // Isochronous transfers occur continuously and periodically. They typically contain time sensitive information, such as an audio or video stream.
	USBTransportTypeInterrupt   USBTransportType = 0x01 // Interrupt transfers are typically non-periodic, small device "initiated" communication requiring bounded latency, such as pointing devices or keyboards.
	USBTransportTypeControl     USBTransportType = 0x02 // Control transfers are typically used for command and status operations.
	USBTransportTypeBulk        USBTransportType = 0x03 // Bulk transfers can be used for large bursty data, using all remaining available bandwidth, no guarantees on bandwidth or latency, such as file transfers.
)

type USBDirectionType uint8

const (
	USBDirectionTypeUnknown USBDirectionType = iota
	USBDirectionTypeIn
	USBDirectionTypeOut
)

func (a USBDirectionType) String() string {
	switch a {
	case USBDirectionTypeIn:
		return "In"
	case USBDirectionTypeOut:
		return "Out"
	default:
		return "Unknown direction type"
	}
}

// The reference at http://www.beyondlogic.org/usbnutshell/usb1.shtml contains more information about the protocol.
type USB struct {
	BaseLayer
	ID             uint64
	EventType      USBEventType
	TransferType   USBTransportType
	Direction      USBDirectionType
	EndpointNumber uint8
	DeviceAddress  uint8
	BusID          uint16
	TimestampSec   int64
	TimestampUsec  int32
	Setup          bool
	Data           bool
	Status         int32
	UrbLength      uint32
	UrbDataLength  uint32

	UrbInterval            uint32
	UrbStartFrame          uint32
	UrbCopyOfTransferFlags uint32
	IsoNumDesc             uint32
}

func (u *USB) LayerType() gopacket.LayerType { return LayerTypeUSB }

func (u *USB) NextLayerType() gopacket.LayerType {
	if u.Setup {
		return LayerTypeUSBRequestBlockSetup
	} else if u.Data {
	}

	return u.TransferType.LayerType()
}

func decodeUSB(data []byte, p gopacket.PacketBuilder) error {
	d := &USB{}

	return decodingLayerDecoder(d, data, p)
}

func (u *USB) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 40 {
		df.SetTruncated()
		return errors.New("USB < 40 bytes")
	}
	u.ID = binary.LittleEndian.Uint64(data[0:8])
	u.EventType = USBEventType(data[8])
	u.TransferType = USBTransportType(data[9])

	u.EndpointNumber = data[10] & 0x7f
	if data[10]&uint8(USBTransportTypeTransferIn) > 0 {
		u.Direction = USBDirectionTypeIn
	} else {
		u.Direction = USBDirectionTypeOut
	}

	u.DeviceAddress = data[11]
	u.BusID = binary.LittleEndian.Uint16(data[12:14])

	if uint(data[14]) == 0 {
		u.Setup = true
	}

	if uint(data[15]) == 0 {
		u.Data = true
	}

	u.TimestampSec = int64(binary.LittleEndian.Uint64(data[16:24]))
	u.TimestampUsec = int32(binary.LittleEndian.Uint32(data[24:28]))
	u.Status = int32(binary.LittleEndian.Uint32(data[28:32]))
	u.UrbLength = binary.LittleEndian.Uint32(data[32:36])
	u.UrbDataLength = binary.LittleEndian.Uint32(data[36:40])

	u.Contents = data[:40]
	u.Payload = data[40:]

	if u.Setup {
		u.Payload = data[40:]
	} else if u.Data {
		u.Payload = data[uint32(len(data))-u.UrbDataLength:]
	}

	// if 64 bit, dissect_linux_usb_pseudo_header_ext
	if false {
		u.UrbInterval = binary.LittleEndian.Uint32(data[40:44])
		u.UrbStartFrame = binary.LittleEndian.Uint32(data[44:48])
		u.UrbDataLength = binary.LittleEndian.Uint32(data[48:52])
		u.IsoNumDesc = binary.LittleEndian.Uint32(data[52:56])
		u.Contents = data[:56]
		u.Payload = data[56:]
	}

	// crc5 or crc16
	// eop (end of packet)

	return nil
}

type USBRequestBlockSetup struct {
	BaseLayer
	RequestType uint8
	Request     USBRequestBlockSetupRequest
	Value       uint16
	Index       uint16
	Length      uint16
}

func (u *USBRequestBlockSetup) LayerType() gopacket.LayerType { return LayerTypeUSBRequestBlockSetup }

func (u *USBRequestBlockSetup) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (u *USBRequestBlockSetup) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	u.RequestType = data[0]
	u.Request = USBRequestBlockSetupRequest(data[1])
	u.Value = binary.LittleEndian.Uint16(data[2:4])
	u.Index = binary.LittleEndian.Uint16(data[4:6])
	u.Length = binary.LittleEndian.Uint16(data[6:8])
	u.Contents = data[:8]
	u.Payload = data[8:]
	return nil
}

func decodeUSBRequestBlockSetup(data []byte, p gopacket.PacketBuilder) error {
	d := &USBRequestBlockSetup{}
	return decodingLayerDecoder(d, data, p)
}

type USBControl struct {
	BaseLayer
}

func (u *USBControl) LayerType() gopacket.LayerType { return LayerTypeUSBControl }

func (u *USBControl) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (u *USBControl) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	u.Contents = data
	return nil
}

func decodeUSBControl(data []byte, p gopacket.PacketBuilder) error {
	d := &USBControl{}
	return decodingLayerDecoder(d, data, p)
}

type USBInterrupt struct {
	BaseLayer
}

func (u *USBInterrupt) LayerType() gopacket.LayerType { return LayerTypeUSBInterrupt }

func (u *USBInterrupt) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (u *USBInterrupt) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	u.Contents = data
	return nil
}

func decodeUSBInterrupt(data []byte, p gopacket.PacketBuilder) error {
	d := &USBInterrupt{}
	return decodingLayerDecoder(d, data, p)
}

type USBBulk struct {
	BaseLayer
}

func (u *USBBulk) LayerType() gopacket.LayerType { return LayerTypeUSBBulk }

func (u *USBBulk) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func (u *USBBulk) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	u.Contents = data
	return nil
}

func decodeUSBBulk(data []byte, p gopacket.PacketBuilder) error {
	d := &USBBulk{}
	return decodingLayerDecoder(d, data, p)
}
