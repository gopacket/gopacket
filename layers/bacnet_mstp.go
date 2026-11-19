// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// BACnet MS/TP, the master-slave/token-passing data link over EIA-485
// (ASHRAE 135-2020 Clause 9). A capture of link type 165 holds one frame
// per packet:
//
//	55 FF | type | destination | source | length (2) | header CRC
//	  | data (length) | data CRC (2)
//
// The frame types from 32 on are extended frames (Clause 9.10): their data
// and a CRC-32K are COBS encoded, so that no preamble shows up in them,
// and Length counts the encoded octets less two.

package layers

import (
	"encoding/binary"

	"github.com/gopacket/gopacket"
)

// LinkTypeBACnetMSTP is the pcap link type of BACnet MS/TP frames
// (LINKTYPE_BACNET_MS_TP).
const LinkTypeBACnetMSTP LinkType = 165

// LayerTypeBACnetMSTP is the BACnet MS/TP data link layer.
var LayerTypeBACnetMSTP = gopacket.RegisterLayerType(181, gopacket.LayerTypeMetadata{Name: "BACnetMSTP", Decoder: gopacket.DecodeFunc(decodeBACnetMSTP)})

// MS/TP framing (Clause 9.3, 9.10).
const (
	bacnetMSTPPreamble1 uint8 = 0x55
	bacnetMSTPPreamble2 uint8 = 0xFF
	// preamble, frame type, destination, source, length, header CRC
	bacnetMSTPHeaderLen = 8
	// Offsets of the header fields.
	bacnetMSTPTypeAt   = 2
	bacnetMSTPDestAt   = 3
	bacnetMSTPSourceAt = 4
	bacnetMSTPLengthAt = 5
	bacnetMSTPCRCAt    = 7

	bacnetMSTPDataCRCLen = 2
	// bacnetMSTPEncodedCRCLen is the size of a COBS encoded CRC-32K.
	bacnetMSTPEncodedCRCLen = 5
	bacnetMSTPCRC32Len      = 4
	// bacnetMSTPLengthBias is what the Length of an extended frame leaves
	// out, so that a node that does not know the frame skips it as data
	// followed by a CRC-16.
	bacnetMSTPLengthBias = 2

	// bacnetMSTPBroadcast is the broadcast MAC address.
	bacnetMSTPBroadcast uint8 = 0xFF

	// CRC parameters of Annex G.
	bacnetCRC8Init   uint8  = 0xFF
	bacnetCRC16Init  uint16 = 0xFFFF
	bacnetCRC32Init  uint32 = 0xFFFFFFFF
	bacnetCRC32KPoly uint32 = 0xEB31D82E // CRC-32K (Koopman), reflected

	// bacnetCOBSMask is XORed over every encoded octet so that the
	// encoding, which has no X'00', has no X'55' instead.
	bacnetCOBSMask uint8 = 0x55
	// bacnetCOBSMaxCode is the code of a block of 254 octets that no zero
	// follows.
	bacnetCOBSMaxCode uint8 = 0xFF
)

// BACnetMSTPFrameType is the type of an MS/TP frame (Clause 9.3).
type BACnetMSTPFrameType uint8

// BACnetMSTPFrameType values.
const (
	BACnetMSTPToken                      BACnetMSTPFrameType = 0
	BACnetMSTPPollForMaster              BACnetMSTPFrameType = 1
	BACnetMSTPReplyToPollForMaster       BACnetMSTPFrameType = 2
	BACnetMSTPTestRequest                BACnetMSTPFrameType = 3
	BACnetMSTPTestResponse               BACnetMSTPFrameType = 4
	BACnetMSTPDataExpectingReply         BACnetMSTPFrameType = 5
	BACnetMSTPDataNotExpectingReply      BACnetMSTPFrameType = 6
	BACnetMSTPReplyPostponed             BACnetMSTPFrameType = 7
	BACnetMSTPExtendedDataExpectingReply BACnetMSTPFrameType = 32
	BACnetMSTPExtendedDataNoReply        BACnetMSTPFrameType = 33
	BACnetMSTPIPv6Encapsulation          BACnetMSTPFrameType = 34

	// bacnetMSTPFirstExtended and bacnetMSTPFirstProprietary bound the
	// COBS encoded frame types.
	bacnetMSTPFirstExtended    BACnetMSTPFrameType = 32
	bacnetMSTPFirstProprietary BACnetMSTPFrameType = 128
)

var bacnetMSTPFrameTypeNames = map[BACnetMSTPFrameType]string{
	BACnetMSTPToken:                      "Token",
	BACnetMSTPPollForMaster:              "Poll For Master",
	BACnetMSTPReplyToPollForMaster:       "Reply To Poll For Master",
	BACnetMSTPTestRequest:                "Test_Request",
	BACnetMSTPTestResponse:               "Test_Response",
	BACnetMSTPDataExpectingReply:         "BACnet Data Expecting Reply",
	BACnetMSTPDataNotExpectingReply:      "BACnet Data Not Expecting Reply",
	BACnetMSTPReplyPostponed:             "Reply Postponed",
	BACnetMSTPExtendedDataExpectingReply: "BACnet Extended Data Expecting Reply",
	BACnetMSTPExtendedDataNoReply:        "BACnet Extended Data Not Expecting Reply",
	BACnetMSTPIPv6Encapsulation:          "IPv6 over MS/TP Encapsulation",
}

// String returns the Clause 9.3 name of the frame type.
func (t BACnetMSTPFrameType) String() string { return bacnetName(bacnetMSTPFrameTypeNames, t) }

// Extended reports whether frames of the type are COBS encoded and
// protected by a CRC-32K (Clause 9.10).
func (t BACnetMSTPFrameType) Extended() bool {
	return t >= bacnetMSTPFirstExtended && t < bacnetMSTPFirstProprietary
}

// Proprietary reports whether the type is a vendor's, in which case the
// data starts with the vendor identifier.
func (t BACnetMSTPFrameType) Proprietary() bool { return t >= bacnetMSTPFirstProprietary }

// BACnetMSTP is a BACnet MS/TP frame (Clause 9.3). A wrong CRC is flagged,
// not an error, since a capture is where one looks for them.
type BACnetMSTP struct {
	BaseLayer
	FrameType   BACnetMSTPFrameType
	Destination uint8
	Source      uint8
	// Length is the length field: the octets of data, or for an extended
	// frame the encoded octets less two.
	Length uint16

	HeaderCRC uint8
	// HeaderCRCValid is set when HeaderCRC is the CRC-8 of the header.
	HeaderCRCValid bool

	// Data is the data of the frame, COBS decoded for an extended frame
	// (in memory of its own then). It is nil when Length is 0.
	Data []byte
	// DataCRC is the CRC-16 after the data, or the CRC-32K of an extended
	// frame.
	DataCRC uint32
	// DataCRCValid is set when DataCRC is the CRC of the data as sent.
	DataCRCValid bool

	// VendorID starts the data of a proprietary frame.
	VendorID uint16
}

// LayerType returns LayerTypeBACnetMSTP.
func (m *BACnetMSTP) LayerType() gopacket.LayerType { return LayerTypeBACnetMSTP }

// CanDecode returns LayerTypeBACnetMSTP.
func (m *BACnetMSTP) CanDecode() gopacket.LayerClass { return LayerTypeBACnetMSTP }

// Broadcast reports whether the frame is sent to every node.
func (m *BACnetMSTP) Broadcast() bool { return m.Destination == bacnetMSTPBroadcast }

// NextLayerType returns LayerTypeBACnetNPDU for a BACnet data frame whose
// CRCs are right. Corrupt data is left in Data.
func (m *BACnetMSTP) NextLayerType() gopacket.LayerType {
	if len(m.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	return LayerTypeBACnetNPDU
}

// DecodeFromBytes decodes an MS/TP frame that starts at its preamble.
// Octets after the frame, such as the optional pad, are ignored.
func (m *BACnetMSTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*m = BACnetMSTP{}
	if len(data) < bacnetMSTPHeaderLen {
		return bacnetTruncated(df)
	}
	if data[0] != bacnetMSTPPreamble1 || data[1] != bacnetMSTPPreamble2 {
		return ErrBACnetMalformed
	}

	m.FrameType = BACnetMSTPFrameType(data[bacnetMSTPTypeAt])
	m.Destination = data[bacnetMSTPDestAt]
	m.Source = data[bacnetMSTPSourceAt]
	m.Length = binary.BigEndian.Uint16(data[bacnetMSTPLengthAt:])
	m.HeaderCRC = data[bacnetMSTPCRCAt]
	m.HeaderCRCValid = bacnetCRC8(data[bacnetMSTPTypeAt:bacnetMSTPCRCAt]) == m.HeaderCRC
	m.Contents = data[:bacnetMSTPHeaderLen]

	// A frame without data ends with its header.
	if m.Length == 0 {
		return nil
	}
	body := data[bacnetMSTPHeaderLen:]

	if m.FrameType.Extended() {
		if err := m.decodeExtended(body, df); err != nil {
			return err
		}
	} else {
		size := int(m.Length)
		if len(body) < size+bacnetMSTPDataCRCLen {
			return bacnetTruncated(df)
		}
		m.Data = body[:size:size]
		m.DataCRC = uint32(binary.LittleEndian.Uint16(body[size:]))
		m.DataCRCValid = uint32(bacnetCRC16(m.Data)) == m.DataCRC
		m.Contents = data[:bacnetMSTPHeaderLen+size+bacnetMSTPDataCRCLen]
	}

	switch {
	case m.FrameType.Proprietary():
		if len(m.Data) >= bacnetUint16Len {
			m.VendorID = binary.BigEndian.Uint16(m.Data)
		}

	case !m.HeaderCRCValid || !m.DataCRCValid:
		// Not handed on: the NPDU decoder would read noise.

	case m.FrameType == BACnetMSTPDataExpectingReply, m.FrameType == BACnetMSTPDataNotExpectingReply,
		m.FrameType == BACnetMSTPExtendedDataExpectingReply, m.FrameType == BACnetMSTPExtendedDataNoReply:
		m.Contents = data[:bacnetMSTPHeaderLen]
		m.Payload = m.Data
	}
	return nil
}

// decodeExtended reads the COBS encoded data and CRC-32K of an extended
// frame (Clause 9.10.3):
//
//	encoded data (Length + 2 - 5) | encoded CRC-32K (5)
//
// The CRC covers the data as encoded.
func (m *BACnetMSTP) decodeExtended(body []byte, df gopacket.DecodeFeedback) error {
	size := int(m.Length) + bacnetMSTPLengthBias
	if size < bacnetMSTPEncodedCRCLen {
		return ErrBACnetMalformed
	}
	if len(body) < size {
		return bacnetTruncated(df)
	}
	encoded := body[:size-bacnetMSTPEncodedCRCLen]
	m.Contents = m.Contents[:bacnetMSTPHeaderLen+size]

	var crc [bacnetMSTPCRC32Len]byte
	if n, ok := bacnetCOBSDecode(crc[:], body[size-bacnetMSTPEncodedCRCLen:size]); ok && n == len(crc) {
		m.DataCRC = binary.LittleEndian.Uint32(crc[:])
		m.DataCRCValid = bacnetCRC32K(encoded) == m.DataCRC
	}

	// Decoding never grows the data: every block loses its code octet.
	buf := make([]byte, len(encoded))
	n, ok := bacnetCOBSDecode(buf, encoded)
	if !ok {
		m.DataCRCValid = false
	}
	m.Data = buf[:n:n]
	return nil
}

// bacnetCOBSDecode undoes the masked COBS encoding of Clause 9.10.3 into
// dst, which must be as long as src, and returns the octets written. It
// reports false when a block runs past the data.
//
//	encoded   03 11 22 02 33   each block: its length + 1, then its octets
//	decoded      11 22 00 33   a zero stood between the blocks
func bacnetCOBSDecode(dst, src []byte) (int, bool) {
	n := 0
	for off := 0; off < len(src); {
		code := src[off] ^ bacnetCOBSMask
		off++
		if code == 0 {
			return n, false
		}

		block := int(code) - 1
		if block > len(src)-off {
			return n, false
		}
		for _, b := range src[off : off+block] {
			dst[n] = b ^ bacnetCOBSMask
			n++
		}
		off += block

		// The zero a block stands for; the last block and a full one
		// stand for none.
		if code != bacnetCOBSMaxCode && off < len(src) {
			dst[n] = 0
			n++
		}
	}
	return n, true
}

// bacnetCRC8 returns the header CRC of Annex G.1 as it is sent: the ones
// complement of the CRC-8 (x^8 + x^7 + 1) of data.
func bacnetCRC8(data []byte) uint8 {
	crc := bacnetCRC8Init
	for _, b := range data {
		// All eight shifts of the bit-serial register at once.
		v := uint16(crc ^ b)
		v = v ^ v<<1 ^ v<<2 ^ v<<3 ^ v<<4 ^ v<<5 ^ v<<6 ^ v<<7
		crc = uint8(v&0xFE) ^ uint8(v>>8&1)
	}
	return ^crc
}

// bacnetCRC16 returns the data CRC of Annex G.2 as it is sent: the ones
// complement of the CRC-16 (x^16 + x^12 + x^5 + 1) of data.
func bacnetCRC16(data []byte) uint16 {
	crc := bacnetCRC16Init
	for _, b := range data {
		low := crc&0xFF ^ uint16(b)
		crc = crc>>8 ^ low<<8 ^ low<<3 ^ low<<12 ^ low>>4 ^ low&0x0F ^ (low&0x0F)<<7
	}
	return ^crc
}

// bacnetCRC32K returns the CRC-32K of Annex G.3 as it is sent: the ones
// complement of the Koopman CRC of data. It works bit by bit: frames are
// short and a table would have to be built at start-up.
func bacnetCRC32K(data []byte) uint32 {
	const bitsPerOctet = 8

	crc := bacnetCRC32Init
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < bitsPerOctet; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ bacnetCRC32KPoly
				continue
			}
			crc >>= 1
		}
	}
	return ^crc
}

func decodeBACnetMSTP(data []byte, p gopacket.PacketBuilder) error {
	return decodingLayerDecoder(&BACnetMSTP{}, data, p)
}
