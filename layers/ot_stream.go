// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// Stream splitters cut one direction of a reassembled TCP connection
// into whole PDUs, so a PDU split over segments, or several PDUs in one
// segment, decode like a PDU that fills a segment alone:
//
//	segments  |TPKT hdr|TPKT body ...|... body|TPKT|TPKT|
//	              \_______ reassembly _______/
//	stream    |TPKT hdr TPKT body ....... body|TPKT|TPKT|
//	              \___ bufio.SplitFunc ____/
//	tokens    |    one PDU                    |PDU |PDU |
//	              -> gopacket.NewPacket(pdu, LayerTypeTPKT, ...)
//
// Each splitter reads only the PDU header to find its length, asks for
// more data (0, nil, nil) without allocating while a PDU is incomplete
// and bounds a PDU by its protocol maximum. Tokens alias the input.

// Stream splitter limits.
const (
	// iec104MaxLength is the largest APDU length octet: an APDU holds at
	// most 255 octets, start and length octets included.
	iec104MaxLength = 253

	// iec104GarbageMax is the most garbage ScanIEC104Resync puts in one
	// token.
	iec104GarbageMax = 1024

	// modbusLengthEnd is where the MBAP length field ends: the ADU is
	// modbusLengthEnd plus that many octets.
	modbusLengthEnd = 6
	modbusProtoOff  = 2

	// modbusMinLength covers unit identifier and function code.
	modbusMinLength = 2

	// modbusMaxLength is the largest MBAP length: an ADU holds at most
	// 260 octets (Modbus Messaging on TCP/IP, section 4.1).
	modbusMaxLength = 254

	// opcuaStreamMax caps an OPC UA message. The spec leaves the size to
	// Hello/Acknowledge negotiation; 16 MiB is far above common server
	// limits and keeps a forged size from holding memory unbounded.
	opcuaStreamMax = 16 << 20
)

var (
	dnp3Sync   = []byte{dnp3Start0, dnp3Start1}
	iec104Sync = []byte{iec104StartByte}
)

var (
	// ErrOTStreamBadHeader is returned by a stream splitter when the
	// next PDU header is invalid and the protocol has no start octets to
	// resynchronise on. The stream cannot be split any further.
	ErrOTStreamBadHeader = errors.New("OT stream: invalid PDU header")
	// ErrOTStreamTooLong is returned by a stream splitter when a PDU
	// claims a length above its protocol maximum.
	ErrOTStreamTooLong = errors.New("OT stream: PDU above protocol maximum")
	// ErrOTStreamTruncated is returned by a stream splitter at EOF when
	// the stream ends inside a PDU.
	ErrOTStreamTruncated = errors.New("OT stream: ends inside a PDU")
)

// ScanTPKT is a bufio.SplitFunc returning one RFC 1006 TPKT frame per
// token, decodable as LayerTypeTPKT. The 16 bit length field bounds a
// frame to 65535 octets. TPKT has no start marker to resynchronise on,
// so a version other than 3 or a length below 7 returns
// ErrOTStreamBadHeader.
func ScanTPKT(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < tpktHeaderLen {
		return otNeedMore(data, 0, atEOF)
	}

	if data[0] != TPKTVersion {
		return 0, nil, fmt.Errorf("%w: TPKT version %d", ErrOTStreamBadHeader, data[0])
	}

	n := int(binary.BigEndian.Uint16(data[2:4]))
	if n < tpktMinLen {
		return 0, nil, fmt.Errorf("%w: TPKT length %d", ErrOTStreamBadHeader, n)
	}
	return otCut(data, n, atEOF)
}

// ScanDNP3 is a bufio.SplitFunc returning one DNP3 link frame per token,
// block CRCs included, decodable as LayerTypeDNP3. The 8 bit length
// field bounds a frame to 292 octets.
//
// It resynchronises rather than fail: octets before the next 0x05 0x64
// are skipped, and so is a start whose length is below 5 or whose
// header CRC does not match, since its length cannot be trusted. Frames
// with a corrupt header are therefore dropped; user data CRCs are left
// for the decoder to check.
func ScanDNP3(data []byte, atEOF bool) (advance int, token []byte, err error) {
	return otScanSynced(data, atEOF, dnp3Sync, dnp3HeaderLen, dnp3PDULen)
}

// dnp3PDULen returns the wire length of the frame whose link header
// starts hdr, or false when its length or CRC is invalid.
func dnp3PDULen(hdr []byte) (int, bool) {
	if hdr[2] < dnp3MinLength {
		return 0, false
	}

	crc := binary.LittleEndian.Uint16(hdr[dnp3HeaderCRCOff:dnp3HeaderLen])
	if DNP3CRC(hdr[:dnp3HeaderCRCOff]) != crc {
		return 0, false
	}
	return dnp3FrameLen(int(hdr[2]) - dnp3MinLength), true
}

// ScanIEC104 is a bufio.SplitFunc returning one IEC 60870-5-104 APDU per
// token, decodable as LayerTypeIEC104. An APDU holds at most 255 octets.
//
// It resynchronises rather than fail: octets before the next 0x68 are
// skipped, and so is a 0x68 whose length does not fit the frame format
// (S and U frames are exactly 4 octets long, I frames longer, none above
// 253). 0x68 also occurs inside ASDUs, so after a gap the first APDUs
// found may be false.
func ScanIEC104(data []byte, atEOF bool) (advance int, token []byte, err error) {
	return otScanSynced(data, atEOF, iec104Sync, iec104APCILen, iec104PDULen)
}

// iec104PDULen returns the length of the APDU whose APCI starts hdr, or
// false when its length does not fit its frame format.
func iec104PDULen(hdr []byte) (int, bool) {
	n := hdr[1]
	if n > iec104MaxLength {
		return 0, false
	}

	// Only I frames carry an ASDU.
	isI := hdr[iec104HeaderLen]&iec104FormatBitI == 0
	if isI && n <= iec104ControlLen {
		return 0, false
	}
	if !isI && n != iec104ControlLen {
		return 0, false
	}
	return iec104HeaderLen + int(n), true
}

// ScanIEC104Resync is a bufio.SplitFunc like ScanIEC104 that drops no
// octet: garbage before an APDU comes in front of it in the same token,
//
//	stream  | garbage | APDU | APDU | garbage ... | APDU |
//	tokens  |<------ 1 ----->|<- 2 >|<-------- 3 ------->|
//
// and decoding the token as LayerTypeIEC104 gives the APDU with the
// garbage counted in IEC104.Skipped. It accepts a start octet only for
// an APDU whose control field is sound, which ScanIEC104 does not check:
// an I frame with an even N(R) octet, an S frame of 01 00 and N(R), a U
// frame with one function bit and three zero octets.
//
// Garbage is cut into tokens of 1024 octets when no APDU follows that
// soon, so a token holds 1279 octets at most. A token without APDU, and
// what is left at EOF, decodes to an error and whatever damaged APDUs
// the decoder makes out. It never returns an error itself.
func ScanIEC104Resync(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for off := 0; off < len(data) && off < iec104GarbageMax; off++ {
		if data[off] != iec104StartByte {
			continue
		}

		// A sound APDU ends the token.
		apdu := data[off:]
		if iec104Sound(apdu) {
			end := off + iec104HeaderLen + int(apdu[1])
			return end, data[:end:end], nil
		}

		// One that may become sound with more data is worth waiting
		// for. It is at most 255 octets long.
		if !atEOF && iec104MaySound(apdu) {
			return 0, nil, nil
		}
	}

	if len(data) >= iec104GarbageMax {
		return iec104GarbageMax, data[:iec104GarbageMax:iec104GarbageMax], nil
	}
	if !atEOF || len(data) == 0 {
		return 0, nil, nil
	}
	return len(data), data[:len(data):len(data)], nil
}

// iec104MaySound reports whether data, which opens with a start octet
// and is no sound APDU, may be the first octets of one.
func iec104MaySound(data []byte) bool {
	if len(data) < iec104APCILen {
		return len(data) < iec104HeaderLen || (data[1] >= iec104ControlLen && data[1] <= iec104MaxLength)
	}

	// The header is whole: it is sound if it is so without its ASDU.
	n := int(data[1])
	if n > iec104MaxLength || len(data) >= iec104HeaderLen+n {
		return false
	}

	var probe [iec104HeaderLen + iec104MaxLength]byte
	copy(probe[:], data[:iec104APCILen])
	return iec104Sound(probe[:])
}

// ScanOPCUA is a bufio.SplitFunc returning one OPC UA Binary transport
// message per token, decodable as LayerTypeOPCUA. A message must carry
// a known type (HEL, ACK, ERR, RHE, OPN, MSG, CLO), a chunk type of F, C
// or A and a size of at least 8, else ErrOTStreamBadHeader: OPC UA has
// no start marker to resynchronise on. A size above 16 MiB returns
// ErrOTStreamTooLong. A bufio.Scanner holds 64 KiB tokens by default;
// call its Buffer method to accept larger messages.
func ScanOPCUA(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < opcuaHeaderLen {
		return otNeedMore(data, 0, atEOF)
	}

	if !opcuaHeaderOK(data) {
		return 0, nil, fmt.Errorf("%w: OPC UA type %q", ErrOTStreamBadHeader, data[:opcuaMessageTypeLen+1])
	}

	// Compare as uint32 so a huge size cannot overflow int on 32 bit.
	size := binary.LittleEndian.Uint32(data[opcuaMessageTypeLen+1:])
	if size < opcuaHeaderLen {
		return 0, nil, fmt.Errorf("%w: OPC UA size %d", ErrOTStreamBadHeader, size)
	}
	if size > opcuaStreamMax {
		return 0, nil, fmt.Errorf("%w: OPC UA size %d", ErrOTStreamTooLong, size)
	}
	return otCut(data, int(size), atEOF)
}

// opcuaHeaderOK reports whether the message and chunk types at the start
// of data are known. The caller has checked data holds the header.
func opcuaHeaderOK(data []byte) bool {
	var t OPCUAMessageType
	for _, c := range data[:opcuaMessageTypeLen] {
		t = t<<opcuaMessageTypeBits | OPCUAMessageType(c)
	}

	switch t {
	case OPCUAMessageHello, OPCUAMessageAcknowledge, OPCUAMessageError,
		OPCUAMessageReverseHello, OPCUAMessageOpenSecureChannel,
		OPCUAMessageSecure, OPCUAMessageCloseSecureChannel:
	default:
		return false
	}

	switch OPCUAChunkType(data[opcuaMessageTypeLen]) {
	case OPCUAChunkFinal, OPCUAChunkIntermediate, OPCUAChunkAbort:
		return true
	}
	return false
}

// ScanModbusTCP is a bufio.SplitFunc returning one Modbus/TCP ADU per
// token, decodable as LayerTypeModbus. The MBAP protocol identifier
// must be 0 and the length at least 2, else ErrOTStreamBadHeader:
// Modbus has no start marker to resynchronise on. A length above 254
// (an ADU above 260 octets) returns ErrOTStreamTooLong.
func ScanModbusTCP(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < modbusLengthEnd {
		return otNeedMore(data, 0, atEOF)
	}

	if proto := binary.BigEndian.Uint16(data[modbusProtoOff:]); proto != 0 {
		return 0, nil, fmt.Errorf("%w: Modbus protocol %d", ErrOTStreamBadHeader, proto)
	}

	n := int(binary.BigEndian.Uint16(data[modbusProtoOff+2:]))
	if n < modbusMinLength {
		return 0, nil, fmt.Errorf("%w: Modbus length %d", ErrOTStreamBadHeader, n)
	}
	if n > modbusMaxLength {
		return 0, nil, fmt.Errorf("%w: Modbus length %d", ErrOTStreamTooLong, n)
	}
	return otCut(data, modbusLengthEnd+n, atEOF)
}

// OTStreamDecoder returns the splitter and the layer type to decode its
// tokens with for a TCP port of an OT protocol in this package: 102
// (TPKT), 502 (Modbus/TCP), 2404 (IEC 104), 4840 (OPC UA), 20000
// (DNP3) and 48898 (AMS/TCP). ok is false for any other port.
func OTStreamDecoder(port TCPPort) (split bufio.SplitFunc, layer gopacket.LayerType, ok bool) {
	switch uint16(port) {
	case TCPPortTPKT:
		return ScanTPKT, LayerTypeTPKT, true
	case ModbusPort:
		return ScanModbusTCP, LayerTypeModbus, true
	case TCPPortIEC104:
		return ScanIEC104, LayerTypeIEC104, true
	case TCPPortOPCUA:
		return ScanOPCUA, LayerTypeOPCUA, true
	case DNP3Port:
		return ScanDNP3, LayerTypeDNP3, true
	case uint16(TCPPortEtherCATAMS):
		return ScanEtherCATAMSTCP, LayerTypeEtherCATAMSTCP, true
	}
	return nil, gopacket.LayerTypeZero, false
}

// otCut returns the n octet PDU at the start of data, or asks for more
// data when data holds less.
func otCut(data []byte, n int, atEOF bool) (int, []byte, error) {
	if len(data) < n {
		return otNeedMore(data, 0, atEOF)
	}

	// Cap the token so appending to it cannot overwrite the next PDU.
	return n, data[:n:n], nil
}

// otNeedMore drops the skip garbage octets at the start of data and
// asks for more data, or reports a PDU cut by EOF.
func otNeedMore(data []byte, skip int, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) > skip {
		return 0, nil, fmt.Errorf("%w: %d octets left", ErrOTStreamTruncated, len(data)-skip)
	}
	return skip, nil, nil
}

// otScanSynced splits a stream whose PDUs open with sync octets. pduLen
// reads a header of hdrLen octets and returns its PDU length, or false
// for a false start. Garbage is skipped within the call, as
// bufio.Scanner stops at EOF on a nil token. Each pass skips at least
// one octet or returns, so the loop is bounded by data.
func otScanSynced(data []byte, atEOF bool, sync []byte, hdrLen int, pduLen func([]byte) (int, bool)) (int, []byte, error) {
	skip := 0
	for {
		skip += otResync(data[skip:], sync)
		pdu := data[skip:]
		if len(pdu) < hdrLen {
			return otNeedMore(data, skip, atEOF)
		}

		// A false start: skip its start octets and look for the next one.
		n, ok := pduLen(pdu)
		if !ok {
			skip += len(sync)
			continue
		}
		if len(pdu) < n {
			return otNeedMore(data, skip, atEOF)
		}
		return skip + n, pdu[:n:n], nil
	}
}

// otResync returns how many leading octets of data cannot start a PDU
// opening with sync. A tail that may be the first octets of sync is
// kept, e.g. a trailing 0x05 while looking for 0x05 0x64.
func otResync(data, sync []byte) int {
	if i := bytes.Index(data, sync); i >= 0 {
		return i
	}

	for k := len(sync) - 1; k > 0; k-- {
		if bytes.HasSuffix(data, sync[:k]) {
			return len(data) - k
		}
	}
	return len(data)
}
