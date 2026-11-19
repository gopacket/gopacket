// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA PubSub, the UADP message mapping (OPC 10000-14 §7.2.4), sent
// over UDP 4840 or straight over Ethernet with EtherType 0xB62C.
//
//	NetworkMessage
//	  version/flags ─ ExtendedFlags1 ─ ExtendedFlags2 ─ PublisherId ─ DataSetClassId
//	  GroupHeader     flags, WriterGroupId, GroupVersion, NetworkMessageNumber, SequenceNumber
//	  PayloadHeader   count, DataSetWriterIds
//	  Timestamp ─ PicoSeconds ─ PromotedFields
//	  SecurityHeader  flags, token id, nonce, footer size
//	  Payload         sizes, then one DataSetMessage per writer:
//	                    flags1 ─ flags2 ─ sequence ─ timestamp ─ picoseconds
//	                    ─ status ─ configuration version ─ fields
//	  SecurityFooter ─ Signature
//
// Every part but the first octet is optional and announced by a flag.
// The header decodes in full or the message is an error. The payload is
// best effort: what does not decode is kept raw and PayloadError says
// why, as it does for the messages this layer does not decode (see
// ErrOPCUAPubSubUnsupported). Nothing is decrypted: the payload of an
// encrypted message stays in EncryptedPayload.

package layers

import (
	"errors"
	"time"

	"github.com/gopacket/gopacket"
)

// UDPPortOPCUAPubSub is the port of UADP over UDP (OPC 10000-14
// §7.3.4.2), the number of opc.tcp.
const UDPPortOPCUAPubSub uint16 = 4840

// EthernetTypeOPCUAPubSub is the EtherType of UADP over Ethernet
// (OPC 10000-14 §7.3.3).
const EthernetTypeOPCUAPubSub EthernetType = 0xB62C

// LayerTypeOPCUAPubSub is one UADP NetworkMessage.
var LayerTypeOPCUAPubSub = gopacket.RegisterLayerType(191, gopacket.LayerTypeMetadata{Name: "OPCUAPubSub", Decoder: gopacket.DecodeFunc(decodeOPCUAPubSub)})

// ErrOPCUAPubSubUnsupported is the PayloadError of a NetworkMessage
// whose payload this layer does not decode: one with an ActionHeader, a
// reserved NetworkMessage type, or an announcement of a type other than
// endpoints, DataSetMetaData and application information.
var ErrOPCUAPubSubUnsupported = errors.New("OPC UA PubSub payload not decoded")

// opcuaPubSubVersion is the only UADPVersion defined.
const opcuaPubSubVersion = 1

// First octet of a NetworkMessage.
const (
	opcuaPubSubVersionMask = 0x0F
	opcuaPubSubFlagsMask   = 0xF0
)

// OPCUAPubSubFlags are the UADPFlags, the high four bits of the first
// octet.
type OPCUAPubSubFlags uint8

// OPCUAPubSubFlags bits.
const (
	OPCUAPubSubFlagPublisherID   OPCUAPubSubFlags = 0x10
	OPCUAPubSubFlagGroupHeader   OPCUAPubSubFlags = 0x20
	OPCUAPubSubFlagPayloadHeader OPCUAPubSubFlags = 0x40
	OPCUAPubSubFlagExtFlags1     OPCUAPubSubFlags = 0x80
)

// OPCUAPubSubExtFlags1 is the ExtendedFlags1 octet.
type OPCUAPubSubExtFlags1 uint8

// OPCUAPubSubExtFlags1 bits; the low three give the PublisherId type.
const (
	OPCUAPubSubPublisherIDType OPCUAPubSubExtFlags1 = 0x07
	OPCUAPubSubDataSetClassID  OPCUAPubSubExtFlags1 = 0x08
	OPCUAPubSubSecurity        OPCUAPubSubExtFlags1 = 0x10
	OPCUAPubSubTimestamp       OPCUAPubSubExtFlags1 = 0x20
	OPCUAPubSubPicoSeconds     OPCUAPubSubExtFlags1 = 0x40
	OPCUAPubSubExtendedFlags2  OPCUAPubSubExtFlags1 = 0x80
)

// OPCUAPubSubExtFlags2 is the ExtendedFlags2 octet.
type OPCUAPubSubExtFlags2 uint8

// OPCUAPubSubExtFlags2 bits; bits 2 to 4 give the NetworkMessage type.
const (
	OPCUAPubSubChunk          OPCUAPubSubExtFlags2 = 0x01
	OPCUAPubSubPromotedFields OPCUAPubSubExtFlags2 = 0x02
	OPCUAPubSubTypeMask       OPCUAPubSubExtFlags2 = 0x1C
	OPCUAPubSubActionHeader   OPCUAPubSubExtFlags2 = 0x20
	opcuaPubSubMoreFlags      OPCUAPubSubExtFlags2 = 0x80
	opcuaPubSubTypeShift                           = 2
)

// OPCUAPubSubMessageType is the UADP NetworkMessage type.
type OPCUAPubSubMessageType uint8

// OPCUAPubSubMessageType values.
const (
	OPCUAPubSubDataSet      OPCUAPubSubMessageType = 0
	OPCUAPubSubProbe        OPCUAPubSubMessageType = 1
	OPCUAPubSubAnnouncement OPCUAPubSubMessageType = 2
)

var opcuaPubSubMessageTypeNames = map[OPCUAPubSubMessageType]string{
	OPCUAPubSubDataSet:      "DataSetMessage",
	OPCUAPubSubProbe:        "DiscoveryProbe",
	OPCUAPubSubAnnouncement: "DiscoveryAnnouncement",
}

// String returns the type name.
func (t OPCUAPubSubMessageType) String() string { return opcuaName(opcuaPubSubMessageTypeNames, t) }

// OPCUAPublisherIDType is the DataType of a PublisherId.
type OPCUAPublisherIDType uint8

// OPCUAPublisherIDType values.
const (
	OPCUAPublisherIDByte   OPCUAPublisherIDType = 0
	OPCUAPublisherIDUInt16 OPCUAPublisherIDType = 1
	OPCUAPublisherIDUInt32 OPCUAPublisherIDType = 2
	OPCUAPublisherIDUInt64 OPCUAPublisherIDType = 3
	OPCUAPublisherIDString OPCUAPublisherIDType = 4
)

var opcuaPublisherIDTypeNames = map[OPCUAPublisherIDType]string{
	OPCUAPublisherIDByte:   "Byte",
	OPCUAPublisherIDUInt16: "UInt16",
	OPCUAPublisherIDUInt32: "UInt32",
	OPCUAPublisherIDUInt64: "UInt64",
	OPCUAPublisherIDString: "String",
}

// String returns the type name.
func (t OPCUAPublisherIDType) String() string { return opcuaName(opcuaPublisherIDTypeNames, t) }

// OPCUAPublisherID is the id of the publisher of a NetworkMessage:
// Numeric for the integer types, Text for a String. Two ids are equal
// only when type and value are.
type OPCUAPublisherID struct {
	Type    OPCUAPublisherIDType
	Numeric uint64
	Text    string
}

// OPCUAPubSubGroupFlags is the GroupFlags octet.
type OPCUAPubSubGroupFlags uint8

// OPCUAPubSubGroupFlags bits.
const (
	OPCUAPubSubWriterGroupID    OPCUAPubSubGroupFlags = 0x01
	OPCUAPubSubGroupVersion     OPCUAPubSubGroupFlags = 0x02
	OPCUAPubSubNetworkMsgNumber OPCUAPubSubGroupFlags = 0x04
	OPCUAPubSubSequenceNumber   OPCUAPubSubGroupFlags = 0x08
	opcuaPubSubMoreGroupFlags   OPCUAPubSubGroupFlags = 0x80
)

// OPCUAPubSubGroupHeader is the GroupHeader; Flags tells which of its
// fields were sent.
type OPCUAPubSubGroupHeader struct {
	Flags         OPCUAPubSubGroupFlags
	WriterGroupID uint16
	// GroupVersion is a VersionTime: seconds since 2000-01-01 UTC.
	GroupVersion         uint32
	NetworkMessageNumber uint16
	SequenceNumber       uint16
}

// OPCUAPubSubSecurityFlags is the SecurityFlags octet.
type OPCUAPubSubSecurityFlags uint8

// OPCUAPubSubSecurityFlags bits.
const (
	OPCUAPubSubSigned         OPCUAPubSubSecurityFlags = 0x01
	OPCUAPubSubEncrypted      OPCUAPubSubSecurityFlags = 0x02
	OPCUAPubSubSecurityFooter OPCUAPubSubSecurityFlags = 0x04
	OPCUAPubSubForceKeyReset  OPCUAPubSubSecurityFlags = 0x08
)

// OPCUAPubSubSecurityHeader is the SecurityHeader. FooterSize is only
// sent with the SecurityFooter flag.
type OPCUAPubSubSecurityHeader struct {
	Flags      OPCUAPubSubSecurityFlags
	TokenID    uint32
	Nonce      []byte
	FooterSize uint16
}

// OPCUADataSetFlags1 is the DataSetFlags1 octet of a DataSetMessage.
type OPCUADataSetFlags1 uint8

// OPCUADataSetFlags1 bits; bits 1 and 2 give the field encoding.
const (
	OPCUADataSetValid        OPCUADataSetFlags1 = 0x01
	OPCUADataSetEncodingMask OPCUADataSetFlags1 = 0x06
	OPCUADataSetSequence     OPCUADataSetFlags1 = 0x08
	OPCUADataSetStatus       OPCUADataSetFlags1 = 0x10
	OPCUADataSetMajorVersion OPCUADataSetFlags1 = 0x20
	OPCUADataSetMinorVersion OPCUADataSetFlags1 = 0x40
	OPCUADataSetFlags2Follow OPCUADataSetFlags1 = 0x80
	opcuaDataSetEncShift                        = 1
)

// OPCUADataSetFlags2 is the DataSetFlags2 octet of a DataSetMessage.
type OPCUADataSetFlags2 uint8

// OPCUADataSetFlags2 bits; the low four give the DataSetMessage type.
const (
	OPCUADataSetTypeMask    OPCUADataSetFlags2 = 0x0F
	OPCUADataSetTimestamp   OPCUADataSetFlags2 = 0x10
	OPCUADataSetPicoSeconds OPCUADataSetFlags2 = 0x20
	opcuaDataSetMoreFlags   OPCUADataSetFlags2 = 0x80
)

// OPCUADataSetEncoding is the encoding of the fields of a
// DataSetMessage.
type OPCUADataSetEncoding uint8

// OPCUADataSetEncoding values.
const (
	OPCUADataSetVariant   OPCUADataSetEncoding = 0
	OPCUADataSetRawData   OPCUADataSetEncoding = 1
	OPCUADataSetDataValue OPCUADataSetEncoding = 2
)

var opcuaDataSetEncodingNames = map[OPCUADataSetEncoding]string{
	OPCUADataSetVariant:   "Variant",
	OPCUADataSetRawData:   "RawData",
	OPCUADataSetDataValue: "DataValue",
}

// String returns the encoding name.
func (e OPCUADataSetEncoding) String() string { return opcuaName(opcuaDataSetEncodingNames, e) }

// OPCUADataSetMessageType is the UADP DataSetMessage type.
type OPCUADataSetMessageType uint8

// OPCUADataSetMessageType values.
const (
	OPCUADataSetKeyFrame       OPCUADataSetMessageType = 0
	OPCUADataSetDeltaFrame     OPCUADataSetMessageType = 1
	OPCUADataSetEvent          OPCUADataSetMessageType = 2
	OPCUADataSetKeepAlive      OPCUADataSetMessageType = 3
	OPCUADataSetActionRequest  OPCUADataSetMessageType = 5
	OPCUADataSetActionResponse OPCUADataSetMessageType = 6
)

var opcuaDataSetMessageTypeNames = map[OPCUADataSetMessageType]string{
	OPCUADataSetKeyFrame:       "KeyFrame",
	OPCUADataSetDeltaFrame:     "DeltaFrame",
	OPCUADataSetEvent:          "Event",
	OPCUADataSetKeepAlive:      "KeepAlive",
	OPCUADataSetActionRequest:  "ActionRequest",
	OPCUADataSetActionResponse: "ActionResponse",
}

// String returns the type name.
func (t OPCUADataSetMessageType) String() string { return opcuaName(opcuaDataSetMessageTypeNames, t) }

// OPCUADataSetMessage is one DataSetMessage of a NetworkMessage
// (OPC 10000-14 §7.2.4.5.4). The header fields are set as Flags1 and
// Flags2 announce them.
//
// The fields decode by Encoding and Type:
//
//	Variant    key frame, event   Variants, in DataSet order
//	Variant    delta frame        Variants, with FieldIndexes beside
//	DataValue  key frame          DataValues, in DataSet order
//	DataValue  delta frame        DataValues, with FieldIndexes beside
//	RawData    key frame          RawData: the fields back to back, which
//	                              only the DataSetMetaData can split
//	RawData    delta frame        FieldCount, and RawData: index and
//	                              value of every field
//	any        keep alive         no fields
type OPCUADataSetMessage struct {
	// WriterID is the DataSetWriterId of the payload header, 0 without
	// one.
	WriterID uint16
	Flags1   OPCUADataSetFlags1
	Flags2   OPCUADataSetFlags2
	Encoding OPCUADataSetEncoding
	Type     OPCUADataSetMessageType

	SequenceNumber uint16
	Timestamp      time.Time
	// PicoSeconds counts 10 ps steps to add to Timestamp.
	PicoSeconds uint16
	// Status is the high 16 bits of a StatusCode.
	Status uint16
	// ConfigMajorVersion and ConfigMinorVersion are VersionTimes.
	ConfigMajorVersion uint32
	ConfigMinorVersion uint32

	// FieldCount is the count sent; a key frame of RawData sends none,
	// and a heartbeat, a key frame that ends with its header, neither.
	FieldCount   uint16
	FieldIndexes []uint16
	Variants     []OPCUAVariant
	DataValues   []OPCUADataValue
	RawData      []byte

	// Padding is what follows the fields up to the size the payload
	// gives the message. Without sizes it is part of the Trailer of the
	// NetworkMessage.
	Padding []byte
	// Undecoded is the message after its header when the fields were
	// not decoded: the valid bit is clear, the encoding or type is
	// reserved or an action, or a field does not parse. It is the whole
	// message when its header does not parse.
	Undecoded []byte
}

// Valid reports whether the valid bit is set; a subscriber skips the
// message otherwise, and the fields are not decoded.
func (m *OPCUADataSetMessage) Valid() bool { return m.Flags1&OPCUADataSetValid != 0 }

// OPCUAPubSubChunkData is the payload of a chunk NetworkMessage
// (OPC 10000-14 §7.2.4.4.4): a piece of one DataSetMessage or
// announcement too large for one NetworkMessage. Chunks are not joined.
type OPCUAPubSubChunkData struct {
	MessageSequenceNumber uint16
	ChunkOffset           uint32
	TotalSize             uint32
	Data                  []byte
}

// OPCUAPubSub is one UADP NetworkMessage.
type OPCUAPubSub struct {
	BaseLayer
	Version   uint8
	Flags     OPCUAPubSubFlags
	ExtFlags1 OPCUAPubSubExtFlags1
	ExtFlags2 OPCUAPubSubExtFlags2
	Type      OPCUAPubSubMessageType

	// PublisherID is set with the PublisherID flag, DataSetClassID with
	// its flag in ExtFlags1, Group with the GroupHeader flag.
	PublisherID    OPCUAPublisherID
	DataSetClassID OPCUAGUID
	Group          OPCUAPubSubGroupHeader
	// DataSetWriterIDs is the payload header: one id per DataSetMessage,
	// or the one id of a chunk.
	DataSetWriterIDs []uint16
	Timestamp        time.Time
	// PicoSeconds counts 10 ps steps to add to Timestamp.
	PicoSeconds uint16
	// PromotedFields are the promoted fields as sent; their layout is
	// that of the DataSetMetaData.
	PromotedFields []byte
	Security       OPCUAPubSubSecurityHeader

	// Messages are the DataSetMessages of a message of type DataSet.
	Messages []OPCUADataSetMessage
	// Chunk is set by a chunk NetworkMessage.
	Chunk *OPCUAPubSubChunkData
	// Probe and Announcement are the discovery messages.
	Probe        *OPCUAPubSubProbeData
	Announcement *OPCUAPubSubAnnounceData

	// EncryptedPayload is everything after the header of an encrypted
	// message: ciphertext, security footer and signature.
	EncryptedPayload []byte
	// Trailer is what follows the decoded payload: padding, the security
	// footer and the signature. Their sizes are not on the wire but for
	// Security.FooterSize; the standard PubSub policies sign with
	// HMAC-SHA256, 32 bytes.
	Trailer []byte
	// PayloadError is nil for a payload decoded in full. Otherwise it
	// is the reason the payload, or one of its Messages, was not:
	// ErrOPCUATruncated, ErrOPCUAMalformed or ErrOPCUAPubSubUnsupported.
	// Undecoded is the payload from where decoding stopped; it is nil
	// when only the fields of a message failed, which then holds its own
	// Undecoded.
	Undecoded    []byte
	PayloadError error
}

// LayerType returns LayerTypeOPCUAPubSub.
func (p *OPCUAPubSub) LayerType() gopacket.LayerType { return LayerTypeOPCUAPubSub }

// CanDecode returns LayerTypeOPCUAPubSub.
func (p *OPCUAPubSub) CanDecode() gopacket.LayerClass { return LayerTypeOPCUAPubSub }

// NextLayerType returns LayerTypePayload; a NetworkMessage carries no
// further layer and its Payload is empty.
func (p *OPCUAPubSub) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

// DecodeFromBytes decodes the NetworkMessage that fills data.
func (p *OPCUAPubSub) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*p = OPCUAPubSub{}
	r := &opcuaReader{b: data}

	if err := p.decodeHeader(r); err != nil {
		if err == ErrOPCUATruncated {
			df.SetTruncated()
		}
		return err
	}
	p.Contents = data

	p.decodePayload(r)
	return nil
}

func decodeOPCUAPubSub(data []byte, p gopacket.PacketBuilder) error {
	ps := &OPCUAPubSub{}
	if err := ps.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(ps)
	return nil
}

// decodeHeader reads everything up to the payload.
func (p *OPCUAPubSub) decodeHeader(r *opcuaReader) error {
	first := r.u8()
	p.Version = first & opcuaPubSubVersionMask
	p.Flags = OPCUAPubSubFlags(first & opcuaPubSubFlagsMask)
	if r.err != nil {
		return r.err
	}
	if p.Version != opcuaPubSubVersion {
		return ErrOPCUAMalformed
	}

	if p.Flags&OPCUAPubSubFlagExtFlags1 != 0 {
		p.ExtFlags1 = OPCUAPubSubExtFlags1(r.u8())
	}
	if p.ExtFlags1&OPCUAPubSubExtendedFlags2 != 0 {
		p.ExtFlags2 = OPCUAPubSubExtFlags2(r.u8())
	}
	p.Type = OPCUAPubSubMessageType(p.ExtFlags2 & OPCUAPubSubTypeMask >> opcuaPubSubTypeShift)

	// A further flags octet would move every field that follows.
	if p.ExtFlags2&opcuaPubSubMoreFlags != 0 {
		return ErrOPCUAMalformed
	}

	p.decodePublisher(r)
	p.decodeGroup(r)
	p.decodePayloadHeader(r)
	p.decodeExtended(r)
	return r.err
}

// decodePublisher reads the PublisherId and the DataSetClassId.
func (p *OPCUAPubSub) decodePublisher(r *opcuaReader) {
	if p.Flags&OPCUAPubSubFlagPublisherID != 0 {
		id := OPCUAPublisherID{Type: OPCUAPublisherIDType(p.ExtFlags1 & OPCUAPubSubPublisherIDType)}
		switch id.Type {
		case OPCUAPublisherIDByte:
			id.Numeric = uint64(r.u8())
		case OPCUAPublisherIDUInt16:
			id.Numeric = uint64(r.u16())
		case OPCUAPublisherIDUInt32:
			id.Numeric = uint64(r.u32())
		case OPCUAPublisherIDUInt64:
			id.Numeric = r.u64()
		case OPCUAPublisherIDString:
			id.Text = r.str()
		default:
			r.fail(ErrOPCUAMalformed)
		}
		p.PublisherID = id
	}

	if p.ExtFlags1&OPCUAPubSubDataSetClassID != 0 {
		p.DataSetClassID = r.guid()
	}
}

// fail sets the error of the reader unless it already has one.
func (r *opcuaReader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

// decodeGroup reads the GroupHeader.
func (p *OPCUAPubSub) decodeGroup(r *opcuaReader) {
	if p.Flags&OPCUAPubSubFlagGroupHeader == 0 {
		return
	}

	g := OPCUAPubSubGroupHeader{Flags: OPCUAPubSubGroupFlags(r.u8())}
	if g.Flags&opcuaPubSubMoreGroupFlags != 0 {
		r.fail(ErrOPCUAMalformed)
	}
	if g.Flags&OPCUAPubSubWriterGroupID != 0 {
		g.WriterGroupID = r.u16()
	}
	if g.Flags&OPCUAPubSubGroupVersion != 0 {
		g.GroupVersion = r.u32()
	}
	if g.Flags&OPCUAPubSubNetworkMsgNumber != 0 {
		g.NetworkMessageNumber = r.u16()
	}
	if g.Flags&OPCUAPubSubSequenceNumber != 0 {
		g.SequenceNumber = r.u16()
	}
	p.Group = g
}

// decodePayloadHeader reads the DataSetWriterIds: one for a chunk, a
// counted list for DataSetMessages. Discovery messages have none.
func (p *OPCUAPubSub) decodePayloadHeader(r *opcuaReader) {
	if p.Flags&OPCUAPubSubFlagPayloadHeader == 0 || r.err != nil {
		return
	}

	count := 1
	switch {
	case p.ExtFlags2&OPCUAPubSubChunk != 0:
	case p.Type == OPCUAPubSubDataSet:
		count = int(r.u8())
	default:
		r.fail(ErrOPCUAMalformed)
		return
	}

	// Counted before allocating: every id takes two bytes.
	if count*opcuaUint16Len > r.remaining() {
		r.fail(ErrOPCUATruncated)
		return
	}
	p.DataSetWriterIDs = make([]uint16, count)
	for i := range p.DataSetWriterIDs {
		p.DataSetWriterIDs[i] = r.u16()
	}
}

// decodeExtended reads the extended NetworkMessage header and the
// SecurityHeader.
func (p *OPCUAPubSub) decodeExtended(r *opcuaReader) {
	if p.ExtFlags1&OPCUAPubSubTimestamp != 0 {
		p.Timestamp = r.dateTime()
	}
	if p.ExtFlags1&OPCUAPubSubPicoSeconds != 0 {
		p.PicoSeconds = r.u16()
	}
	if p.ExtFlags2&OPCUAPubSubPromotedFields != 0 {
		p.PromotedFields = r.take(int(r.u16()))
	}
	if p.ExtFlags1&OPCUAPubSubSecurity == 0 {
		return
	}

	s := OPCUAPubSubSecurityHeader{Flags: OPCUAPubSubSecurityFlags(r.u8()), TokenID: r.u32()}
	s.Nonce = r.take(int(r.u8()))
	if s.Flags&OPCUAPubSubSecurityFooter != 0 {
		s.FooterSize = r.u16()
	}
	p.Security = s
}

// decodePayload decodes what follows the header, as far as it goes.
//
//	ActionHeader ──────────────► Undecoded, unsupported
//	encrypted ─────────────────► EncryptedPayload
//	chunk ─────────────────────► Chunk
//	DataSet ───────────────────► Messages
//	probe, announcement ───────► Probe, Announcement
//	reserved type ─────────────► Undecoded, unsupported
func (p *OPCUAPubSub) decodePayload(r *opcuaReader) {
	rest := r.b[r.off:]

	switch {
	case p.ExtFlags2&OPCUAPubSubActionHeader != 0:
		p.Undecoded, p.PayloadError = rest, ErrOPCUAPubSubUnsupported
		return
	case p.Security.Flags&OPCUAPubSubEncrypted != 0:
		p.EncryptedPayload = rest
		return
	case p.ExtFlags2&OPCUAPubSubChunk != 0:
		p.decodeChunk(r)
	case p.Type == OPCUAPubSubDataSet:
		p.decodeMessages(r)
	case p.Type == OPCUAPubSubProbe:
		p.decodeProbe(r)
	case p.Type == OPCUAPubSubAnnouncement:
		p.decodeAnnouncement(r)
	default:
		p.Undecoded, p.PayloadError = rest, ErrOPCUAPubSubUnsupported
		return
	}

	if r.err != nil {
		p.Undecoded, p.PayloadError = rest, r.err
		return
	}
	if p.Undecoded == nil {
		p.Trailer = r.b[r.off:]
	}
}

// decodeChunk reads the payload of a chunk NetworkMessage.
func (p *OPCUAPubSub) decodeChunk(r *opcuaReader) {
	c := OPCUAPubSubChunkData{
		MessageSequenceNumber: r.u16(),
		ChunkOffset:           r.u32(),
		TotalSize:             r.u32(),
		Data:                  r.byteString(),
	}
	if r.err != nil {
		return
	}
	p.Chunk = &c
}

// decodeMessages reads the DataSetMessages: one per id of the payload
// header, each as long as the Sizes say, or a single one that runs to
// the end of what decodes when there are no sizes.
func (p *OPCUAPubSub) decodeMessages(r *opcuaReader) {
	count := 1
	if p.Flags&OPCUAPubSubFlagPayloadHeader != 0 {
		count = len(p.DataSetWriterIDs)
	}
	if count == 0 || count == 1 && r.remaining() == 0 {
		return
	}

	// One message has no size and is read from the payload itself.
	if count == 1 {
		p.Messages = make([]OPCUADataSetMessage, 1)
		p.Messages[0].WriterID = p.writerID(0)
		p.PayloadError = p.Messages[0].decode(r, opcuaDataSetUnsized)
		return
	}

	// Sizes are counted before the messages are allocated.
	if count*opcuaUint16Len > r.remaining() {
		r.fail(ErrOPCUATruncated)
		return
	}
	sizes := &opcuaReader{b: r.take(count * opcuaUint16Len)}

	p.Messages = make([]OPCUADataSetMessage, 0, count)
	for i := 0; i < count; i++ {
		at := r.off
		body := r.take(int(sizes.u16()))

		// A size past the data ends the payload; the messages before it
		// stand.
		if r.err != nil {
			p.Undecoded, p.PayloadError = r.b[at:], r.err
			r.err = nil
			return
		}

		p.Messages = append(p.Messages, OPCUADataSetMessage{WriterID: p.writerID(i)})
		err := p.Messages[i].decode(&opcuaReader{b: body}, opcuaDataSetSized)
		if p.PayloadError == nil {
			p.PayloadError = err
		}
	}
}

// writerID returns the DataSetWriterId of message i, 0 without a
// payload header.
func (p *OPCUAPubSub) writerID(i int) uint16 {
	if i >= len(p.DataSetWriterIDs) {
		return 0
	}
	return p.DataSetWriterIDs[i]
}

// opcuaDataSetBounds tells a DataSetMessage that fills its reader from
// one that is followed by something else.
type opcuaDataSetBounds uint8

const (
	// opcuaDataSetSized: the reader holds the message and nothing else;
	// what follows the fields is padding.
	opcuaDataSetSized opcuaDataSetBounds = iota
	// opcuaDataSetUnsized: the reader runs on past the message.
	opcuaDataSetUnsized
)

// Minimum encoded sizes of the fields of a DataSetMessage.
const (
	opcuaMinVariantLen    = 1
	opcuaMinDeltaFieldLen = opcuaUint16Len + opcuaMinVariantLen
)

// decode reads the DataSetMessage at r. It never fails the reader: a
// message that does not parse keeps its bytes in Undecoded, and the
// reason is returned.
func (m *OPCUADataSetMessage) decode(r *opcuaReader, bounds opcuaDataSetBounds) error {
	start := r.off
	m.decodeHeader(r)
	if r.err != nil {
		return m.undecoded(r, start, r.err)
	}

	// A subscriber skips a message that is not valid.
	fieldsAt := r.off
	if !m.Valid() {
		return m.undecoded(r, fieldsAt, nil)
	}

	err := m.decodeFields(r)
	if r.err != nil {
		err = r.err
	}
	if err != nil {
		return m.undecoded(r, fieldsAt, err)
	}

	if bounds == opcuaDataSetSized {
		m.Padding = r.take(r.remaining())
	}
	return nil
}

// undecoded leaves the message raw from offset at and ends the reader,
// clean. It returns err.
func (m *OPCUADataSetMessage) undecoded(r *opcuaReader, at int, err error) error {
	m.FieldIndexes, m.Variants, m.DataValues, m.RawData = nil, nil, nil, nil
	m.Undecoded = r.b[at:]
	r.err, r.off = nil, len(r.b)
	return err
}

// decodeHeader reads the DataSetMessage header.
func (m *OPCUADataSetMessage) decodeHeader(r *opcuaReader) {
	m.Flags1 = OPCUADataSetFlags1(r.u8())
	if m.Flags1&OPCUADataSetFlags2Follow != 0 {
		m.Flags2 = OPCUADataSetFlags2(r.u8())
	}
	m.Encoding = OPCUADataSetEncoding(m.Flags1 & OPCUADataSetEncodingMask >> opcuaDataSetEncShift)
	m.Type = OPCUADataSetMessageType(m.Flags2 & OPCUADataSetTypeMask)

	// A further flags octet would move every field that follows.
	if m.Flags2&opcuaDataSetMoreFlags != 0 {
		r.fail(ErrOPCUAMalformed)
		return
	}

	if m.Flags1&OPCUADataSetSequence != 0 {
		m.SequenceNumber = r.u16()
	}
	if m.Flags2&OPCUADataSetTimestamp != 0 {
		m.Timestamp = r.dateTime()
	}
	if m.Flags2&OPCUADataSetPicoSeconds != 0 {
		m.PicoSeconds = r.u16()
	}
	if m.Flags1&OPCUADataSetStatus != 0 {
		m.Status = r.u16()
	}
	if m.Flags1&OPCUADataSetMajorVersion != 0 {
		m.ConfigMajorVersion = r.u32()
	}
	if m.Flags1&OPCUADataSetMinorVersion != 0 {
		m.ConfigMinorVersion = r.u32()
	}
}

// decodeFields reads the fields of a valid message by type and
// encoding. Actions and the reserved types and encoding are not
// decoded.
func (m *OPCUADataSetMessage) decodeFields(r *opcuaReader) error {
	switch m.Type {
	case OPCUADataSetKeepAlive:
		return nil
	case OPCUADataSetKeyFrame, OPCUADataSetDeltaFrame, OPCUADataSetEvent:
	default:
		return ErrOPCUAPubSubUnsupported
	}

	// A key frame that ends with its header is a heartbeat.
	if m.Type == OPCUADataSetKeyFrame && r.remaining() == 0 {
		return nil
	}

	switch m.Encoding {
	case OPCUADataSetVariant:
		m.decodeVariants(r)
	case OPCUADataSetDataValue:
		m.decodeDataValues(r)
	case OPCUADataSetRawData:
		m.decodeRaw(r)
	default:
		return ErrOPCUAMalformed
	}
	return nil
}

// fieldCount reads FieldCount and checks that so many fields of at
// least minSize bytes fit, before anything is allocated for them.
func (m *OPCUADataSetMessage) fieldCount(r *opcuaReader, minSize int) int {
	m.FieldCount = r.u16()
	n := int(m.FieldCount)
	if r.err == nil && n*minSize > r.remaining() {
		r.fail(ErrOPCUATruncated)
	}
	if r.err != nil {
		return 0
	}

	if m.Type == OPCUADataSetDeltaFrame {
		m.FieldIndexes = make([]uint16, n)
	}
	return n
}

// minFieldLen returns the least a field takes: a Variant or DataValue
// of one octet, behind its index in a delta frame.
func (m *OPCUADataSetMessage) minFieldLen() int {
	if m.Type == OPCUADataSetDeltaFrame {
		return opcuaMinDeltaFieldLen
	}
	return opcuaMinVariantLen
}

func (m *OPCUADataSetMessage) decodeVariants(r *opcuaReader) {
	n := m.fieldCount(r, m.minFieldLen())
	if r.err != nil {
		return
	}

	m.Variants = make([]OPCUAVariant, n)
	for i := 0; i < n && r.err == nil; i++ {
		if m.FieldIndexes != nil {
			m.FieldIndexes[i] = r.u16()
		}
		m.Variants[i] = r.variant(0)
	}
}

func (m *OPCUADataSetMessage) decodeDataValues(r *opcuaReader) {
	n := m.fieldCount(r, m.minFieldLen())
	if r.err != nil {
		return
	}

	m.DataValues = make([]OPCUADataValue, n)
	for i := 0; i < n && r.err == nil; i++ {
		if m.FieldIndexes != nil {
			m.FieldIndexes[i] = r.u16()
		}
		m.DataValues[i] = r.dataValue(0)
	}
}

// decodeRaw keeps the RawData fields as sent: their sizes are those of
// the DataSetMetaData, which the message does not carry. A key frame
// has no FieldCount; a delta frame has one, then index and value of
// each field. Without a size the fields run to the end of the data,
// trailer included.
func (m *OPCUADataSetMessage) decodeRaw(r *opcuaReader) {
	if m.Type != OPCUADataSetKeyFrame {
		m.FieldCount = r.u16()
	}
	m.RawData = r.take(r.remaining())
}
