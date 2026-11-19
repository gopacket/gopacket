// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// EtherCAT support for gopacket.
//
// EtherCAT frames ride on Ethernet (EtherType 0x88A4) or UDP (port 0x88A4).
// All fields are little endian (ETG.1000.4, Wireshark
// packet-ethercat-frame.c and packet-ethercat-datagram.c).
//
//	Frame header (2 bytes): Length (11 bits) | Reserved (1) | Type (4)
//
// A type 1 frame carries a chain of datagrams:
//
//	+-----+-------+-----------------+------------------+-----+------+-----+
//	| Cmd | Index | Address (ADP/   | Len (11) R (3)   | IRQ | Data | WKC |
//	| 1   | 1     | ADO, or logical)| C (1) M (1)      | 2   | Len  | 2   |
//	|     |       | 4               | 2                |     |      |     |
//	+-----+-------+-----------------+------------------+-----+------+-----+
//
// M (more follows) says another datagram comes next; C marks a frame that
// circulated the ring.
//
// The other frame types carry one PDU each, decoded into a field of the
// EtherCAT layer (see ethercat_nv.go):
//
//	type 2  ADS              -> EtherCAT.ADS
//	type 3  raw IO           -> EtherCAT.RawIO
//	type 4  network vars     -> EtherCAT.NV
//	type 5  mailbox gateway  -> EtherCAT.Mailbox

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// EthernetTypeEtherCAT is the EtherType of EtherCAT frames.
const EthernetTypeEtherCAT EthernetType = 0x88A4

// UDPPortEtherCAT is the UDP port of EtherCAT frames over UDP.
const UDPPortEtherCAT UDPPort = 0x88A4

// LayerTypeEtherCAT is the EtherCAT frame layer.
var LayerTypeEtherCAT = gopacket.RegisterLayerType(189, gopacket.LayerTypeMetadata{Name: "EtherCAT", Decoder: gopacket.DecodeFunc(decodeEtherCAT)})

const (
	ethercatFrameHeaderLen    = 2
	ethercatDatagramHeaderLen = 10
	ethercatWKCLen            = 2
	ethercatLengthMask        = 0x07FF
	ethercatReservedBit       = 0x0800
	ethercatTypeShift         = 12
	ethercatCirculatingBit    = 0x4000
	ethercatMoreBit           = 0x8000
	ethercatAddressHalfShift  = 16
)

var (
	// ErrEtherCATTooShort is returned when the frame header is truncated.
	ErrEtherCATTooShort = errors.New("EtherCAT frame too short")
	// ErrEtherCATDatagram is returned when a datagram runs past the frame.
	ErrEtherCATDatagram = errors.New("EtherCAT datagram exceeds frame")
)

// EtherCATFrameType is the protocol type in the frame header.
type EtherCATFrameType uint8

// EtherCAT frame types.
const (
	EtherCATFrameCommands EtherCATFrameType = 1
	EtherCATFrameADS      EtherCATFrameType = 2
	EtherCATFrameRawIO    EtherCATFrameType = 3
	EtherCATFrameNV       EtherCATFrameType = 4
	EtherCATFrameMailbox  EtherCATFrameType = 5
)

// String returns the frame type name.
func (t EtherCATFrameType) String() string {
	switch t {
	case EtherCATFrameCommands:
		return "EtherCAT command"
	case EtherCATFrameADS:
		return "ADS"
	case EtherCATFrameRawIO:
		return "RAW-IO"
	case EtherCATFrameNV:
		return "Network variables"
	case EtherCATFrameMailbox:
		return "Mailbox gateway"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(t))
}

// EtherCATCommand is the datagram command.
type EtherCATCommand uint8

// EtherCAT commands.
const (
	EtherCATCommandNOP  EtherCATCommand = 0
	EtherCATCommandAPRD EtherCATCommand = 1
	EtherCATCommandAPWR EtherCATCommand = 2
	EtherCATCommandAPRW EtherCATCommand = 3
	EtherCATCommandFPRD EtherCATCommand = 4
	EtherCATCommandFPWR EtherCATCommand = 5
	EtherCATCommandFPRW EtherCATCommand = 6
	EtherCATCommandBRD  EtherCATCommand = 7
	EtherCATCommandBWR  EtherCATCommand = 8
	EtherCATCommandBRW  EtherCATCommand = 9
	EtherCATCommandLRD  EtherCATCommand = 10
	EtherCATCommandLWR  EtherCATCommand = 11
	EtherCATCommandLRW  EtherCATCommand = 12
	EtherCATCommandARMW EtherCATCommand = 13
	EtherCATCommandFRMW EtherCATCommand = 14
)

// String returns the command mnemonic.
func (c EtherCATCommand) String() string {
	switch c {
	case EtherCATCommandNOP:
		return "NOP"
	case EtherCATCommandAPRD:
		return "APRD"
	case EtherCATCommandAPWR:
		return "APWR"
	case EtherCATCommandAPRW:
		return "APRW"
	case EtherCATCommandFPRD:
		return "FPRD"
	case EtherCATCommandFPWR:
		return "FPWR"
	case EtherCATCommandFPRW:
		return "FPRW"
	case EtherCATCommandBRD:
		return "BRD"
	case EtherCATCommandBWR:
		return "BWR"
	case EtherCATCommandBRW:
		return "BRW"
	case EtherCATCommandLRD:
		return "LRD"
	case EtherCATCommandLWR:
		return "LWR"
	case EtherCATCommandLRW:
		return "LRW"
	case EtherCATCommandARMW:
		return "ARMW"
	case EtherCATCommandFRMW:
		return "FRMW"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(c))
}

// IsLogical reports whether the command uses a 32-bit logical address
// instead of ADP/ADO.
func (c EtherCATCommand) IsLogical() bool {
	return c == EtherCATCommandLRD || c == EtherCATCommandLWR || c == EtherCATCommandLRW
}

// EtherCATDatagram is one datagram of an EtherCAT frame.
type EtherCATDatagram struct {
	Command EtherCATCommand
	Index   uint8
	// Address is the raw 32-bit address: a logical address for LRD, LWR
	// and LRW, otherwise ADP in the low and ADO in the high half.
	Address        uint32
	Length         uint16
	Circulating    bool
	More           bool
	IRQ            uint16
	Data           []byte
	WorkingCounter uint16

	// Mailbox is set when Data holds a mailbox, by Wireshark's heuristic:
	// a write (or a read answered by one slave) to ADO 0x1000 or above
	// whose header names a known mailbox type.
	Mailbox *EtherCATMailbox
}

// ADP returns the position or configured station address.
func (d *EtherCATDatagram) ADP() uint16 { return uint16(d.Address) }

// ADO returns the physical memory or register offset.
func (d *EtherCATDatagram) ADO() uint16 { return uint16(d.Address >> ethercatAddressHalfShift) }

// EtherCAT is an EtherCAT frame.
//
// For type 1 frames the datagrams are decoded and there is no payload;
// Ethernet padding after the last datagram is dropped.
//
// Types 2 to 5 set the one field that matches and have no payload
// either. A body too short for its header, or of an unknown type, stays
// raw in the payload.
type EtherCAT struct {
	BaseLayer

	Length    uint16
	Reserved  uint8
	Type      EtherCATFrameType
	Datagrams []EtherCATDatagram

	ADS     *EtherCATAMS     // type 2
	RawIO   *EtherCATRawIO   // type 3
	NV      *EtherCATNV      // type 4
	Mailbox *EtherCATMailbox // type 5
}

// LayerType returns LayerTypeEtherCAT.
func (e *EtherCAT) LayerType() gopacket.LayerType { return LayerTypeEtherCAT }

// CanDecode returns LayerTypeEtherCAT.
func (e *EtherCAT) CanDecode() gopacket.LayerClass { return LayerTypeEtherCAT }

// NextLayerType returns LayerTypePayload for frames left undecoded.
func (e *EtherCAT) NextLayerType() gopacket.LayerType {
	if len(e.BaseLayer.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes an EtherCAT frame, starting at the frame header.
func (e *EtherCAT) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < ethercatFrameHeaderLen {
		df.SetTruncated()
		return ErrEtherCATTooShort
	}

	hdr := binary.LittleEndian.Uint16(data)
	e.Length = hdr & ethercatLengthMask
	e.Reserved = 0
	if hdr&ethercatReservedBit != 0 {
		e.Reserved = 1
	}
	e.Type = EtherCATFrameType(hdr >> ethercatTypeShift)
	e.Datagrams = e.Datagrams[:0]
	e.ADS, e.RawIO, e.NV, e.Mailbox = nil, nil, nil, nil

	// The header length bounds the frame; past it is Ethernet padding.
	end := ethercatFrameHeaderLen + int(e.Length)
	if end > len(data) {
		df.SetTruncated()
		end = len(data)
	}
	body := data[ethercatFrameHeaderLen:end]

	if e.Type != EtherCATFrameCommands {
		if e.decodeOther(body) {
			e.BaseLayer = BaseLayer{Contents: data[:end]}
			return nil
		}

		e.BaseLayer = BaseLayer{Contents: data[:ethercatFrameHeaderLen], Payload: body}
		return nil
	}

	used, err := e.decodeDatagrams(body)
	if err != nil {
		return err
	}
	e.BaseLayer = BaseLayer{Contents: data[:ethercatFrameHeaderLen+used]}
	return nil
}

// decodeOther decodes the body of a type 2 to 5 frame into its field and
// reports whether it did.
func (e *EtherCAT) decodeOther(body []byte) bool {
	switch e.Type {
	case EtherCATFrameADS:
		e.ADS = decodeEtherCATAMS(body)
		return e.ADS != nil
	case EtherCATFrameRawIO:
		e.RawIO = decodeEtherCATRawIO(body)
		return e.RawIO != nil
	case EtherCATFrameNV:
		e.NV = decodeEtherCATNV(body)
		return e.NV != nil
	case EtherCATFrameMailbox:
		// A mailbox whose length field lies stays raw.
		e.Mailbox, _ = DecodeEtherCATMailbox(body)
		return e.Mailbox != nil
	}
	return false
}

// decodeDatagrams walks the datagram chain while the more-follows bit is
// set. Each datagram takes at least 12 bytes, so the loop is bounded by
// len(body). It returns the number of bytes used.
func (e *EtherCAT) decodeDatagrams(body []byte) (int, error) {
	off := 0
	for off < len(body) {
		if off+ethercatDatagramHeaderLen > len(body) {
			return off, ErrEtherCATDatagram
		}

		h := body[off:]
		lenField := binary.LittleEndian.Uint16(h[6:8])
		d := EtherCATDatagram{
			Command:     EtherCATCommand(h[0]),
			Index:       h[1],
			Address:     binary.LittleEndian.Uint32(h[2:6]),
			Length:      lenField & ethercatLengthMask,
			Circulating: lenField&ethercatCirculatingBit != 0,
			More:        lenField&ethercatMoreBit != 0,
			IRQ:         binary.LittleEndian.Uint16(h[8:10]),
		}

		dataStart := off + ethercatDatagramHeaderLen
		wkcStart := dataStart + int(d.Length)
		if wkcStart+ethercatWKCLen > len(body) {
			return off, ErrEtherCATDatagram
		}

		d.Data = body[dataStart:wkcStart]
		d.WorkingCounter = binary.LittleEndian.Uint16(body[wkcStart:])
		d.Mailbox = findMailbox(&d)
		e.Datagrams = append(e.Datagrams, d)
		off = wkcStart + ethercatWKCLen

		if !d.More {
			break
		}
	}
	return off, nil
}

func decodeEtherCAT(data []byte, p gopacket.PacketBuilder) error {
	e := &EtherCAT{}
	if err := e.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(e)
	next := e.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}

// registerEtherCATDecoders maps EtherType 0x88A4 and UDP port 0x88A4 to the
// EtherCAT decoder, and TCP port 48898 to the AMS over TCP decoder. It is
// opt-in because existing callers would otherwise start seeing new
// layers. Calling it more than once is harmless.
func registerEtherCATDecoders() {
	EthernetTypeMetadata[EthernetTypeEtherCAT] = EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeEtherCAT),
		Name:       "EtherCAT",
		LayerType:  LayerTypeEtherCAT,
	}
	RegisterUDPPortLayerType(UDPPortEtherCAT, LayerTypeEtherCAT)
	RegisterTCPPortLayerType(TCPPortEtherCATAMS, LayerTypeEtherCATAMSTCP)
}
