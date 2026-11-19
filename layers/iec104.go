// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// IEC 60870-5-104 support for gopacket: the APCI framing of IEC 104
// (telecontrol over TCP port 2404) and the ASDU it carries, as defined by
// IEC 60870-5-101 and IEC 60870-5-104.
//
//	APDU
//	+------+--------+-------------------+--------------------------+
//	| 0x68 | length | control field (4) | ASDU (I-format only)     |
//	+------+--------+-------------------+--------------------------+
//	                 \_______________ length octets ______________/

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// TCPPortIEC104 is the TCP port IEC 60870-5-104 runs on.
const TCPPortIEC104 uint16 = 2404

// APCI layout (IEC 60870-5-104, clause 5).
const (
	iec104StartByte  = 0x68
	iec104HeaderLen  = 2 // start and length octets
	iec104ControlLen = 4
	iec104APCILen    = iec104HeaderLen + iec104ControlLen

	// The low bits of the first control octet select the frame format.
	iec104FormatBitI = 0x01
	iec104FormatMask = 0x03
)

// LayerTypeIEC104 is one IEC 60870-5-104 APDU.
var LayerTypeIEC104 = gopacket.RegisterLayerType(170, gopacket.LayerTypeMetadata{Name: "IEC104", Decoder: gopacket.DecodeFunc(decodeIEC104)})

var (
	// ErrIEC104TooShort is returned when the data ends before the APDU does.
	ErrIEC104TooShort = errors.New("IEC 104 APDU truncated")
	// ErrIEC104BadStart is returned when an APDU does not open with 0x68.
	ErrIEC104BadStart = errors.New("IEC 104 APDU has no start octet")
	// ErrIEC104BadLength is returned when the APDU length does not fit its
	// frame format.
	ErrIEC104BadLength = errors.New("IEC 104 APDU length invalid")
)

// IEC104Format is the APCI frame format.
type IEC104Format uint8

// Frame formats, coded in the low bits of the first control octet.
const (
	// IEC104FormatI is a numbered information transfer carrying an ASDU.
	IEC104FormatI IEC104Format = 0x00
	// IEC104FormatS is a numbered supervisory acknowledgement.
	IEC104FormatS IEC104Format = 0x01
	// IEC104FormatU is an unnumbered control function.
	IEC104FormatU IEC104Format = 0x03
)

// String returns the format letter.
func (f IEC104Format) String() string {
	switch f {
	case IEC104FormatI:
		return "I"
	case IEC104FormatS:
		return "S"
	case IEC104FormatU:
		return "U"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(f))
}

// IEC104UFunction is the function bits of a U-format control field: the
// first control octet without its two format bits.
type IEC104UFunction uint8

// U-format functions.
const (
	IEC104StartDTAct IEC104UFunction = 0x04
	IEC104StartDTCon IEC104UFunction = 0x08
	IEC104StopDTAct  IEC104UFunction = 0x10
	IEC104StopDTCon  IEC104UFunction = 0x20
	IEC104TestFRAct  IEC104UFunction = 0x40
	IEC104TestFRCon  IEC104UFunction = 0x80
)

// String returns the function as Wireshark names it, e.g. "STARTDT act".
func (u IEC104UFunction) String() string {
	switch u {
	case IEC104StartDTAct:
		return "STARTDT act"
	case IEC104StartDTCon:
		return "STARTDT con"
	case IEC104StopDTAct:
		return "STOPDT act"
	case IEC104StopDTCon:
		return "STOPDT con"
	case IEC104TestFRAct:
		return "TESTFR act"
	case IEC104TestFRCon:
		return "TESTFR con"
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(u))
}

// IEC104 is one IEC 60870-5-104 APDU. Payload holds whatever follows it in
// the segment, normally further APDUs.
type IEC104 struct {
	BaseLayer

	// Length counts the octets after the length octet.
	Length uint8
	Format IEC104Format
	// SendSeq is N(S), set for I-format frames.
	SendSeq uint16
	// RecvSeq is N(R), set for I- and S-format frames.
	RecvSeq uint16
	// UFunction is set for U-format frames.
	UFunction IEC104UFunction
	// ASDU is set for I-format frames.
	ASDU IEC104ASDU
}

// LayerType returns LayerTypeIEC104.
func (i *IEC104) LayerType() gopacket.LayerType {
	return LayerTypeIEC104
}

// CanDecode returns LayerTypeIEC104.
func (i *IEC104) CanDecode() gopacket.LayerClass {
	return LayerTypeIEC104
}

// NextLayerType returns LayerTypeZero: following APDUs are decoded by
// decodeIEC104, not chained through the layer.
func (i *IEC104) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// DecodeFromBytes decodes the first APDU of data.
func (i *IEC104) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if err := i.decodeAPCI(data, df); err != nil {
		return err
	}
	return i.decodeASDU()
}

// decodeAPCI reads the framing of the first APDU of data: start, length
// and control field. It sets Contents and Payload and clears the ASDU.
func (i *IEC104) decodeAPCI(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < iec104APCILen {
		df.SetTruncated()
		return ErrIEC104TooShort
	}
	if data[0] != iec104StartByte {
		return ErrIEC104BadStart
	}

	// The length octet covers the control field and the ASDU.
	if data[1] < iec104ControlLen {
		return ErrIEC104BadLength
	}
	end := iec104HeaderLen + int(data[1])
	if len(data) < end {
		df.SetTruncated()
		return ErrIEC104TooShort
	}

	i.Length = data[1]
	i.decodeControl(data[iec104HeaderLen:iec104APCILen])
	i.ASDU = IEC104ASDU{Objects: i.ASDU.Objects[:0]}
	i.Contents = data[:end]
	i.Payload = data[end:]
	return nil
}

// decodeASDU reads the ASDU of an APDU whose APCI decodeAPCI accepted.
func (i *IEC104) decodeASDU() error {
	// Only I-format frames carry an ASDU.
	asdu := i.Contents[iec104APCILen:]
	if i.Format != IEC104FormatI {
		if len(asdu) != 0 {
			return ErrIEC104BadLength
		}
		return nil
	}
	return i.ASDU.decode(asdu, iec104DefaultFields)
}

// decodeControl reads the format and its numbers from the control field.
// Sequence numbers are 15 bits, stored little endian above a format bit.
func (i *IEC104) decodeControl(c []byte) {
	i.SendSeq, i.RecvSeq, i.UFunction = 0, 0, 0

	if c[0]&iec104FormatBitI == 0 {
		i.Format = IEC104FormatI
		i.SendSeq = binary.LittleEndian.Uint16(c[0:2]) >> 1
		i.RecvSeq = binary.LittleEndian.Uint16(c[2:4]) >> 1
		return
	}

	i.Format = IEC104Format(c[0] & iec104FormatMask)
	if i.Format == IEC104FormatS {
		i.RecvSeq = binary.LittleEndian.Uint16(c[2:4]) >> 1
		return
	}
	i.UFunction = IEC104UFunction(c[0] &^ iec104FormatMask)
}

func decodeIEC104(data []byte, p gopacket.PacketBuilder) error {
	// A segment may carry several APDUs back to back. Give each its own
	// layer, in a loop rather than through NextDecoder so a large buffer
	// does not cost a stack frame per APDU. Each pass consumes at least
	// iec104APCILen octets.
	//
	// An APDU that does not frame, such as one cut short by segmentation,
	// ends the loop with its error: gopacket turns that into an error
	// layer holding the octets from that APDU on. An APDU that frames but
	// carries a bad ASDU still becomes a layer, so its APCI is not lost,
	// and then ends the loop the same way.
	for {
		apdu := &IEC104{}
		if err := apdu.decodeAPCI(data, p); err != nil {
			return err
		}

		err := apdu.decodeASDU()
		p.AddLayer(apdu)
		if err != nil {
			return err
		}

		data = apdu.Payload
		if len(data) == 0 {
			return nil
		}
	}
}

// registerIEC104Decoders routes TCP port 2404 to the IEC 104 decoder.
func registerIEC104Decoders() {
	RegisterTCPPortLayerType(TCPPort(TCPPortIEC104), LayerTypeIEC104)
}
