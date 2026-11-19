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
	"bytes"
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

// IEC104Fault flags what is wrong with the framing of an APDU that still
// became a layer. A damaged APDU is decoded as far as its octets go, the
// way Wireshark shows it, and the flags tell how far to trust it.
type IEC104Fault uint8

// APDU faults.
const (
	// IEC104FaultGarbage: octets that start no APDU came before this
	// one. Skipped counts them.
	IEC104FaultGarbage IEC104Fault = 1 << iota
	// IEC104FaultLength: the length octet is below 4, or does not fit
	// the frame format: an S or U frame longer than its control field.
	IEC104FaultLength
	// IEC104FaultTruncated: the data ends inside the APDU. The control
	// field and the ASDU are set as far as the data reaches.
	IEC104FaultTruncated
	// IEC104FaultASDU: the ASDU of an I-format frame is malformed.
	IEC104FaultASDU
)

var iec104FaultNames = [...]string{"Garbage", "Length", "Truncated", "ASDU"}

// Has reports whether all of the faults in mask are set.
func (f IEC104Fault) Has(mask IEC104Fault) bool {
	return f&mask == mask
}

// String lists the faults, e.g. "Garbage|Truncated", or "None".
func (f IEC104Fault) String() string {
	if f == 0 {
		return "None"
	}

	var out []byte
	for k, name := range iec104FaultNames {
		if f&(1<<uint(k)) == 0 {
			continue
		}
		if len(out) > 0 {
			out = append(out, '|')
		}
		out = append(out, name...)
	}

	// Bits above the named ones.
	rest := f >> uint(len(iec104FaultNames)) << uint(len(iec104FaultNames))
	if rest == 0 {
		return string(out)
	}
	if len(out) > 0 {
		out = append(out, '|')
	}
	return fmt.Sprintf("%sUnknown(0x%02X)", out, uint8(rest))
}

// IEC104 is one IEC 60870-5-104 APDU. Payload holds whatever follows it in
// the segment, normally further APDUs.
//
// The decoder resynchronises instead of failing on octets that start no
// APDU, such as the tail of an APDU begun in an earlier segment:
//
//	| garbage ... | 0x68 | length | control | ASDU | next APDU ...
//	 \_ Skipped _/ \__________ Contents __________/ \_ Payload _
//
// It skips to the next whole APDU with a sound control field. When there
// is none it takes the first start octet and decodes what follows as far
// as it goes; Faults tells what was wrong.
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

	// Skipped counts the octets passed over before the start octet.
	// They belong to no layer.
	Skipped int
	// Faults is zero for a sound APDU.
	Faults IEC104Fault
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

// DecodeFromBytes decodes the first APDU of data, skipping garbage before
// it. A damaged APDU is filled in as far as it goes and returned with an
// error; Faults tells them apart.
func (i *IEC104) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var mode iec104Resync
	if err := i.decodeAPCI(data, df, &mode); err != nil {
		return err
	}
	return i.decodeASDU()
}

// iec104Resync is how the search for the next APDU goes on.
type iec104Resync uint8

const (
	// iec104ResyncSound looks for a whole APDU with a sound control field.
	iec104ResyncSound iec104Resync = iota
	// iec104ResyncFirst takes the first start octet: a search found no
	// sound APDU up to the end of the data, so none lies further on
	// either and searching again would cost the square of the length.
	iec104ResyncFirst
)

// iec104Sound reports whether data opens with a whole APDU whose length
// and control field fit its frame format (IEC 60870-5-104, 5.1):
//
//	I  | N(S) << 1         | N(R) << 1 |  with an ASDU
//	S  | 0x01 0x00         | N(R) << 1 |  control field only
//	U  | function | 0x03, 0x00 0x00 0x00  one function bit, control only
func iec104Sound(data []byte) bool {
	if len(data) < iec104APCILen || data[0] != iec104StartByte {
		return false
	}

	n := int(data[1])
	if n < iec104ControlLen || n > iec104MaxLength || len(data) < iec104HeaderLen+n {
		return false
	}

	c := data[iec104HeaderLen:iec104APCILen]
	if c[0]&iec104FormatBitI == 0 {
		return n > iec104ControlLen && c[2]&iec104FormatBitI == 0
	}
	if n != iec104ControlLen {
		return false
	}

	if IEC104Format(c[0]&iec104FormatMask) == IEC104FormatS {
		return c[0] == uint8(IEC104FormatS) && c[1] == 0 && c[2]&iec104FormatBitI == 0
	}

	// Exactly one of the six function bits.
	fn := c[0] &^ iec104FormatMask
	return fn != 0 && fn&(fn-1) == 0 && c[1] == 0 && c[2] == 0 && c[3] == 0
}

// iec104Locate returns the offset in data of the APDU to decode next, or
// false when data holds no start octet. An APDU that opens data is taken
// in place unless its length octet rules it out.
func iec104Locate(data []byte, mode *iec104Resync) (int, bool) {
	inPlace := len(data) > 0 && data[0] == iec104StartByte
	if inPlace && (len(data) < iec104HeaderLen || data[1] >= iec104ControlLen) {
		return 0, true
	}

	if *mode == iec104ResyncSound {
		for off := 0; off < len(data); off++ {
			if data[off] == iec104StartByte && iec104Sound(data[off:]) {
				return off, true
			}
		}
		*mode = iec104ResyncFirst
	}

	// A start octet with length 0 claims nothing, so it is garbage too.
	for off := 0; off < len(data); off++ {
		k := bytes.IndexByte(data[off:], iec104StartByte)
		if k < 0 {
			break
		}

		off += k
		if off+1 >= len(data) || data[off+1] != 0 {
			return off, true
		}
	}
	return 0, false
}

// decodeAPCI reads the framing of the next APDU of data: start, length
// and control field. It sets Contents and Payload and clears the ASDU.
// A damaged APDU still gets its Contents, and an error.
func (i *IEC104) decodeAPCI(data []byte, df gopacket.DecodeFeedback, mode *iec104Resync) error {
	i.Length, i.Format, i.Skipped, i.Faults = 0, 0, 0, 0
	i.SendSeq, i.RecvSeq, i.UFunction = 0, 0, 0
	i.ASDU = IEC104ASDU{Objects: i.ASDU.Objects[:0]}
	i.Contents, i.Payload = nil, nil

	if len(data) == 0 {
		df.SetTruncated()
		return ErrIEC104TooShort
	}

	off, found := iec104Locate(data, mode)
	if !found {
		return ErrIEC104BadStart
	}
	if off > 0 {
		i.Skipped = off
		i.Faults |= IEC104FaultGarbage
		data = data[off:]
	}

	// A start octet at the very end has no length to go by.
	if len(data) < iec104HeaderLen {
		i.Skipped, i.Faults = 0, 0
		df.SetTruncated()
		return ErrIEC104TooShort
	}

	i.Length = data[1]
	n := int(data[1])
	body := data[iec104HeaderLen:]
	if n < iec104ControlLen {
		return i.decodeShort(data, n)
	}
	if len(body) < n {
		df.SetTruncated()
		return i.decodeCut(data)
	}

	end := iec104HeaderLen + n
	i.decodeControl(data[iec104HeaderLen:iec104APCILen])
	i.Contents = data[:end]
	i.Payload = data[end:]
	return nil
}

// decodeShort keeps an APDU whose length n is below the control field as
// start, length and the n octets it claims, e.g. 68 02 aa bb.
func (i *IEC104) decodeShort(data []byte, n int) error {
	i.Faults |= IEC104FaultLength

	end := iec104HeaderLen + n
	if len(data) < end {
		i.Faults |= IEC104FaultTruncated
		end = len(data)
	}
	i.Contents = data[:end]
	i.Payload = data[end:]
	return ErrIEC104BadLength
}

// decodeCut keeps an APDU the data ends in: the control field when it is
// whole, and then the fields of the data unit identifier that are.
func (i *IEC104) decodeCut(data []byte) error {
	i.Faults |= IEC104FaultTruncated
	i.Contents = data
	i.Payload = data[len(data):]

	if len(data) < iec104APCILen {
		return ErrIEC104TooShort
	}

	i.decodeControl(data[iec104HeaderLen:iec104APCILen])
	if i.Format == IEC104FormatI {
		i.ASDU.decodeDUI(data[iec104APCILen:], iec104DefaultFields)
	}
	return ErrIEC104TooShort
}

// decodeASDU reads the ASDU of an APDU whose APCI decodeAPCI accepted.
func (i *IEC104) decodeASDU() error {
	// Only I-format frames carry an ASDU.
	asdu := i.Contents[iec104APCILen:]
	if i.Format != IEC104FormatI {
		if len(asdu) != 0 {
			i.Faults |= IEC104FaultLength
			return ErrIEC104BadLength
		}
		return nil
	}

	if err := i.ASDU.decode(asdu, iec104DefaultFields); err != nil {
		i.Faults |= IEC104FaultASDU
		return err
	}
	return nil
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
	// iec104HeaderLen octets.
	//
	// Garbage between APDUs is skipped and counted on the next layer. A
	// damaged APDU still becomes a layer, so what it holds is not lost,
	// and the APDUs after it are decoded too. The first error is
	// returned once the data is used up: gopacket turns it into an error
	// layer holding the octets no APDU took.
	var (
		mode  iec104Resync
		first error
	)
	for {
		apdu := &IEC104{}
		err := apdu.decodeAPCI(data, p, &mode)
		if err == nil {
			err = apdu.decodeASDU()
		}
		if first == nil {
			first = err
		}

		// Without contents no APDU was found: only garbage is left.
		if apdu.Contents == nil {
			break
		}
		p.AddLayer(apdu)

		data = apdu.Payload
		if len(data) == 0 {
			break
		}
	}
	return first
}

// registerIEC104Decoders routes TCP port 2404 to the IEC 104 decoder.
func registerIEC104Decoders() {
	RegisterTCPPortLayerType(TCPPort(TCPPortIEC104), LayerTypeIEC104)
}
