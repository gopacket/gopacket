// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// No capture of UADP is committed. The vectors are built by hand after
// OPC 10000-14 §7.2.4; the NetworkMessage and DataSetMessage headers
// and the Variant and DataValue fields were checked against tshark 4.7,
// which dissects neither discovery messages nor delta frame indexes.

// psVector is a NetworkMessage and the layer it decodes to.
type psVector struct {
	name string
	data []byte
	want OPCUAPubSub
}

// psKeyFrame is a key frame of one Int32 Variant and what it decodes to.
func psKeyFrame(v uint32) ([]byte, OPCUADataSetMessage) {
	return uaBuilder{}.u8(0x01).u16(1).u8(uint8(OPCUATypeInt32)).u32(v), OPCUADataSetMessage{
		Flags1:     OPCUADataSetValid,
		FieldCount: 1,
		Variants:   []OPCUAVariant{{Type: OPCUATypeInt32, Value: int32(v)}},
	}
}

// psDataVectors are the DataSetMessage NetworkMessages.
func psDataVectors() []psVector {
	b := uaBuilder{}
	tm := uaTime()
	guid := OPCUAGUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	key, keyWant := psKeyFrame(1001)
	i32 := OPCUAVariant{Type: OPCUATypeInt32, Value: int32(1002)}
	dbl := OPCUAVariant{Type: OPCUATypeDouble, Value: 1003.5}

	// Every header field at once, and every DataSetMessage header field.
	fullMsg := b.u8(0xF9, 0x30).u16(1010).u64(uaTicks).u16(1011).u16(0x8001).u32(1012, 1013).
		u16(2).u8(uint8(OPCUATypeInt32)).u32(1002).u8(uint8(OPCUATypeDouble)).f64(1003.5)
	full := b.u8(0xF1, 0xE9, 0x02).u16(1020).u8(guid[:]...).u8(0x0F).u16(1021).u32(1022).u16(1023).u16(1024).
		u8(1).u16(1025).u64(uaTicks).u16(1026).u16(3).u8(0xAA, 0xBB, 0xCC).cat(fullMsg)

	// Four sized messages: delta frame of DataValues, keep alive, event
	// with padding, key frame of RawData.
	delta := b.u8(0x85, 0x01).u16(1).u16(1030).u8(opcuaDataValueValue|opcuaDataValueStatus, uint8(OPCUATypeInt32)).u32(1002).u32(1031)
	alive := b.u8(0x89, 0x03).u16(1032)
	event := b.u8(0x81, 0x02).u16(1).u8(uint8(OPCUATypeDouble)).f64(1003.5).u8(0, 0)
	raw := b.u8(0x03).u32(1033).u16(1034)
	sized := b.u8(0x51, 9, 4).u16(1040).u16(1041).u16(1042).u16(1043).
		u16(uint16(len(delta))).u16(uint16(len(alive))).u16(uint16(len(event))).u16(uint16(len(raw))).cat(delta, alive, event, raw)

	// Two sized messages, the second a heartbeat; then a delta of raw
	// data and an invalid message.
	beat := b.u8(0x09).u16(1050)
	rawDelta := b.u8(0x83, 0x01).u16(2).u16(0).u32(1051).u16(3).u32(1052)
	invalid := b.u8(0x00).u16(1).u8(uint8(OPCUATypeInt32)).u32(1002)
	more := b.u8(0x41, 4).u16(1, 2, 3, 4).u16(uint16(len(key))).u16(uint16(len(beat))).u16(uint16(len(rawDelta))).u16(uint16(len(invalid))).
		cat(key, beat, rawDelta, invalid)

	sig := bytes.Repeat([]byte{0xEE}, 32)
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	return []psVector{
		{"minimal", b.u8(0x01).cat(key), OPCUAPubSub{Version: 1, Messages: []OPCUADataSetMessage{keyWant}, Trailer: []byte{}}},
		{"all headers", full, OPCUAPubSub{
			Version: 1, Flags: 0xF0, ExtFlags1: 0xE9, ExtFlags2: 0x02,
			PublisherID:      OPCUAPublisherID{Type: OPCUAPublisherIDUInt16, Numeric: 1020},
			DataSetClassID:   guid,
			Group:            OPCUAPubSubGroupHeader{Flags: 0x0F, WriterGroupID: 1021, GroupVersion: 1022, NetworkMessageNumber: 1023, SequenceNumber: 1024},
			DataSetWriterIDs: []uint16{1025},
			Timestamp:        tm, PicoSeconds: 1026,
			PromotedFields: []byte{0xAA, 0xBB, 0xCC},
			Messages: []OPCUADataSetMessage{{
				WriterID: 1025, Flags1: 0xF9, Flags2: 0x30, SequenceNumber: 1010, Timestamp: tm, PicoSeconds: 1011,
				Status: 0x8001, ConfigMajorVersion: 1012, ConfigMinorVersion: 1013, FieldCount: 2,
				Variants: []OPCUAVariant{i32, dbl},
			}},
			Trailer: []byte{},
		}},
		{"sized messages", sized, OPCUAPubSub{
			Version: 1, Flags: 0x50,
			PublisherID:      OPCUAPublisherID{Type: OPCUAPublisherIDByte, Numeric: 9},
			DataSetWriterIDs: []uint16{1040, 1041, 1042, 1043},
			Messages: []OPCUADataSetMessage{
				{WriterID: 1040, Flags1: 0x85, Flags2: 0x01, Encoding: OPCUADataSetDataValue, Type: OPCUADataSetDeltaFrame,
					FieldCount: 1, FieldIndexes: []uint16{1030},
					DataValues: []OPCUADataValue{{Mask: opcuaDataValueValue | opcuaDataValueStatus, Value: i32, Status: 1031}},
					Padding:    []byte{}},
				{WriterID: 1041, Flags1: 0x89, Flags2: 0x03, Type: OPCUADataSetKeepAlive, SequenceNumber: 1032, Padding: []byte{}},
				{WriterID: 1042, Flags1: 0x81, Flags2: 0x02, Type: OPCUADataSetEvent, FieldCount: 1,
					Variants: []OPCUAVariant{dbl}, Padding: []byte{0, 0}},
				{WriterID: 1043, Flags1: 0x03, Encoding: OPCUADataSetRawData, RawData: b.u32(1033).u16(1034), Padding: []byte{}},
			},
			Trailer: []byte{},
		}},
		{"heartbeat, raw delta, invalid", more, OPCUAPubSub{
			Version: 1, Flags: 0x40,
			DataSetWriterIDs: []uint16{1, 2, 3, 4},
			Messages: []OPCUADataSetMessage{
				func() OPCUADataSetMessage { m := keyWant; m.WriterID, m.Padding = 1, []byte{}; return m }(),
				{WriterID: 2, Flags1: 0x09, SequenceNumber: 1050, Padding: []byte{}},
				{WriterID: 3, Flags1: 0x83, Flags2: 0x01, Encoding: OPCUADataSetRawData, Type: OPCUADataSetDeltaFrame,
					FieldCount: 2, RawData: b.u16(0).u32(1051).u16(3).u32(1052), Padding: []byte{}},
				{WriterID: 4, Flags1: 0x00, Undecoded: invalid[1:]},
			},
			Trailer: []byte{},
		}},
		{"signed", b.u8(0x91, 0x12).u32(1060).u8(0x05).u32(1061).u8(8).u8(nonce...).u16(2).cat(key, []byte{0xF0, 0xF1}, sig), OPCUAPubSub{
			Version: 1, Flags: 0x90, ExtFlags1: 0x12,
			PublisherID: OPCUAPublisherID{Type: OPCUAPublisherIDUInt32, Numeric: 1060},
			Security:    OPCUAPubSubSecurityHeader{Flags: OPCUAPubSubSigned | OPCUAPubSubSecurityFooter, TokenID: 1061, Nonce: nonce, FooterSize: 2},
			Messages:    []OPCUADataSetMessage{keyWant},
			Trailer:     append([]byte{0xF0, 0xF1}, sig...),
		}},
		{"encrypted", b.u8(0x91, 0x13).u64(1062).u8(0x03).u32(1061).u8(8).u8(nonce...).cat(sig), OPCUAPubSub{
			Version: 1, Flags: 0x90, ExtFlags1: 0x13,
			PublisherID:      OPCUAPublisherID{Type: OPCUAPublisherIDUInt64, Numeric: 1062},
			Security:         OPCUAPubSubSecurityHeader{Flags: OPCUAPubSubSigned | OPCUAPubSubEncrypted, TokenID: 1061, Nonce: nonce},
			EncryptedPayload: sig,
		}},
		{"chunk", b.u8(0xC1, 0x80, 0x01).u16(1070).u16(1071).u32(1072).u32(1073).str("\x01\x02\x03"), OPCUAPubSub{
			Version: 1, Flags: 0xC0, ExtFlags1: 0x80, ExtFlags2: 0x01,
			DataSetWriterIDs: []uint16{1070},
			Chunk:            &OPCUAPubSubChunkData{MessageSequenceNumber: 1071, ChunkOffset: 1072, TotalSize: 1073, Data: []byte{1, 2, 3}},
			Trailer:          []byte{},
		}},
		{"no payload", b.u8(0x11, 7), OPCUAPubSub{Version: 1, Flags: 0x10, PublisherID: OPCUAPublisherID{Numeric: 7}, Trailer: []byte{}}},
	}
}

// psDiscoveryHeader opens a discovery message of the given type: string
// PublisherId "tok60" and an empty SecurityHeader, as §7.2.4.6 asks.
func psDiscoveryHeader(typ OPCUAPubSubMessageType) (uaBuilder, OPCUAPubSub) {
	ext2 := uint8(typ) << opcuaPubSubTypeShift
	return uaBuilder{}.u8(0x91, 0x94, ext2).str("tok60").u8(0).u32(0).u8(0), OPCUAPubSub{
		Version: 1, Flags: 0x90, ExtFlags1: 0x94, ExtFlags2: OPCUAPubSubExtFlags2(ext2), Type: typ,
		PublisherID: OPCUAPublisherID{Type: OPCUAPublisherIDString, Text: "tok60"},
		Security:    OPCUAPubSubSecurityHeader{Nonce: []byte{}},
		Trailer:     []byte{},
	}
}

// psMetaData is a DataSetMetaDataType with one of everything, and what
// it decodes to.
func psMetaData() ([]byte, OPCUADataSetMetaData) {
	b := uaBuilder{}
	guid := OPCUAGUID{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	structField := b.str("tok70").text("tok71").node(0, 6).u32(0xFFFFFFFF).null().u32(1100).u8(1)
	structure := b.node(1, 1101).u16(1).str("tok72").node(1, 1102).node(0, 22).u32(1).u32(1).cat(structField)
	enumField := b.u64(1103).text("tok73").text("tok74").str("tok75")
	enum := b.node(1, 1104).u16(1).str("tok76").u32(1).cat(enumField).u8(uint8(OPCUATypeInt32))
	simple := b.node(1, 1105).u16(1).str("tok77").node(0, 11).u8(uint8(OPCUATypeDouble))
	field := b.str("tok78").text("tok79").u16(1).u8(uint8(OPCUATypeInt32)).node(0, 6).u32(0xFFFFFFFF).null().u32(1106).u8(guid[:]...).
		u32(1).u16(0).str("tok80").u8(uint8(OPCUATypeInt32)).u32(1107)

	body := b.u32(1).str("tok81").u32(1).cat(structure).u32(1).cat(enum).u32(1).cat(simple).
		str("tok82").text("tok83").u32(1).cat(field).u8(guid[:]...).u32(1108, 1109)

	return body, OPCUADataSetMetaData{
		OPCUADataTypeSchemaHeader: OPCUADataTypeSchemaHeader{
			Namespaces: []string{"tok81"},
			StructureDataTypes: []OPCUAStructureDescription{{
				DataTypeID: n4(1, 1101), Name: OPCUAQualifiedName{Namespace: 1, Name: "tok72"},
				Definition: OPCUAStructureDefinition{DefaultEncodingID: n4(1, 1102), BaseDataType: n4(0, 22), StructureType: 1,
					Fields: []OPCUAStructureField{{Name: "tok70", Description: uaText("tok71"), DataType: n4(0, 6), ValueRank: -1,
						MaxStringLength: 1100, IsOptional: true}}},
			}},
			EnumDataTypes: []OPCUAEnumDescription{{
				DataTypeID: n4(1, 1104), Name: OPCUAQualifiedName{Namespace: 1, Name: "tok76"},
				Definition: OPCUAEnumDefinition{Fields: []OPCUAEnumField{{
					OPCUAEnumValueType: OPCUAEnumValueType{Value: 1103, DisplayName: uaText("tok73"), Description: uaText("tok74")},
					Name:               "tok75"}}},
				BuiltInType: OPCUATypeInt32,
			}},
			SimpleDataTypes: []OPCUASimpleTypeDescription{{
				DataTypeID: n4(1, 1105), Name: OPCUAQualifiedName{Namespace: 1, Name: "tok77"}, BaseDataType: n4(0, 11), BuiltInType: OPCUATypeDouble,
			}},
		},
		Name:        "tok82",
		Description: uaText("tok83"),
		Fields: []OPCUAFieldMetaData{{
			Name: "tok78", Description: uaText("tok79"), FieldFlags: 1, BuiltInType: OPCUATypeInt32, DataType: n4(0, 6), ValueRank: -1,
			MaxStringLength: 1106, DataSetFieldID: guid,
			Properties: []OPCUAKeyValuePair{{Key: OPCUAQualifiedName{Name: "tok80"}, Value: OPCUAVariant{Type: OPCUATypeInt32, Value: int32(1107)}}},
		}},
		DataSetClassID:       guid,
		ConfigurationVersion: OPCUAConfigurationVersion{MajorVersion: 1108, MinorVersion: 1109},
	}
}

// uaMetaVectors is the metadata structures as ExtensionObject bodies.
func uaMetaVectors() []uaExtVector {
	b := uaBuilder{}
	meta, metaWant := psMetaData()
	structure := metaWant.StructureDataTypes[0]
	enum := metaWant.EnumDataTypes[0]
	field := metaWant.Fields[0]

	structField := b.str("tok70").text("tok71").node(0, 6).u32(0xFFFFFFFF).null().u32(1100).u8(1)
	structDef := b.node(1, 1102).node(0, 22).u32(1).u32(1).cat(structField)
	enumField := b.u64(1103).text("tok73").text("tok74").str("tok75")
	pair := b.u16(0).str("tok80").u8(uint8(OPCUATypeInt32)).u32(1107)
	header := meta[:bytes.Index(meta, b.str("tok82"))]

	return []uaExtVector{
		{opcuaDataSetMetaDataID, meta, &metaWant},
		{opcuaSchemaHeaderID, header, &metaWant.OPCUADataTypeSchemaHeader},
		{opcuaStructureDefinitionID, structDef, &structure.Definition},
		{opcuaStructureDescID, b.node(1, 1101).u16(1).str("tok72").cat(structDef), &structure},
		{opcuaStructureFieldID, structField, &structure.Definition.Fields[0]},
		{opcuaEnumDefinitionID, b.u32(1).cat(enumField), &enum.Definition},
		{opcuaEnumDescID, b.node(1, 1104).u16(1).str("tok76").u32(1).cat(enumField).u8(uint8(OPCUATypeInt32)), &enum},
		{opcuaEnumFieldID, enumField, &enum.Definition.Fields[0]},
		{opcuaSimpleTypeDescID, b.node(1, 1105).u16(1).str("tok77").node(0, 11).u8(uint8(OPCUATypeDouble)), &metaWant.SimpleDataTypes[0]},
		{opcuaFieldMetaDataID, meta[bytes.Index(meta, b.str("tok78")) : bytes.Index(meta, b.u32(1108, 1109))-opcuaGUIDLen], &field},
		{opcuaKeyValuePairID, pair, &field.Properties[0]},
		{opcuaConfigVersionID, b.u32(1108, 1109), &metaWant.ConfigurationVersion},
	}
}

// psDiscoveryVectors are the probes and announcements.
func psDiscoveryVectors() []psVector {
	b := uaBuilder{}
	tm := uaTime()
	meta, metaWant := psMetaData()

	app := b.str("tok20").str("tok21").text("tok22").u32(0).str("tok23").str("tok24").u32(1).str("tok25")
	appWant := OPCUAApplicationDescription{ApplicationURI: "tok20", ProductURI: "tok21", ApplicationName: uaText("tok22"),
		GatewayServerURI: "tok23", DiscoveryProfileURI: "tok24", DiscoveryURLs: []string{"tok25"}}
	endpoint := b.str("tok90").cat(app).str("\x30\x00").u32(1).str("tok91").u32(0).str("tok92").u8(5)
	endpointWant := OPCUAEndpointDescription{EndpointURL: "tok90", Server: appWant, ServerCertificate: []byte{0x30, 0},
		SecurityMode: OPCUASecurityModeNone, SecurityPolicyURI: "tok91", UserIdentityTokens: []OPCUAUserTokenPolicy{},
		TransportProfileURI: "tok92", SecurityLevel: 5}

	vec := func(name string, typ OPCUAPubSubMessageType, payload []byte, set func(*OPCUAPubSub)) psVector {
		head, want := psDiscoveryHeader(typ)
		set(&want)
		return psVector{name, head.cat(payload), want}
	}

	return []psVector{
		vec("probe metadata", OPCUAPubSubProbe, b.u8(1, 2).u32(2).u16(1200).u16(1201), func(p *OPCUAPubSub) {
			p.Probe = &OPCUAPubSubProbeData{ProbeType: OPCUAPubSubProbePublisherInfo, InformationType: OPCUAPubSubInfoMetaData,
				DataSetWriterIDs: []uint16{1200, 1201}}
		}),
		vec("probe endpoints", OPCUAPubSubProbe, b.u8(1, 1), func(p *OPCUAPubSub) {
			p.Probe = &OPCUAPubSubProbeData{ProbeType: OPCUAPubSubProbePublisherInfo, InformationType: OPCUAPubSubInfoEndpoints}
		}),
		vec("probe writer group", OPCUAPubSubProbe, b.u8(1, 4).u16(1202), func(p *OPCUAPubSub) {
			p.Probe = &OPCUAPubSubProbeData{ProbeType: OPCUAPubSubProbePublisherInfo, InformationType: OPCUAPubSubInfoWriterGroup,
				WriterGroupID: 1202}
		}),
		vec("probe connections", OPCUAPubSubProbe, b.u8(1, 5).u32(1).str("tok93").u8(1, 0), func(p *OPCUAPubSub) {
			p.Probe = &OPCUAPubSubProbeData{ProbeType: OPCUAPubSubProbePublisherInfo, InformationType: OPCUAPubSubInfoConnections,
				TransportProfileURIs: []string{"tok93"}, IncludeWriterGroups: true}
		}),
		vec("probe find applications", OPCUAPubSubProbe, b.u8(2), func(p *OPCUAPubSub) {
			p.Probe = &OPCUAPubSubProbeData{ProbeType: OPCUAPubSubProbeFindApplications}
		}),
		vec("announce endpoints", OPCUAPubSubAnnouncement, b.u8(1).u16(1210).u32(1).cat(endpoint).u32(1211), func(p *OPCUAPubSub) {
			p.Announcement = &OPCUAPubSubAnnounceData{AnnouncementType: OPCUAPubSubAnnounceEndpoints, SequenceNumber: 1210,
				Endpoints: []OPCUAEndpointDescription{endpointWant}, StatusCode: 1211}
		}),
		vec("announce metadata", OPCUAPubSubAnnouncement, b.u8(2).u16(1212).u16(1213).cat(meta).u32(1214), func(p *OPCUAPubSub) {
			p.Announcement = &OPCUAPubSubAnnounceData{AnnouncementType: OPCUAPubSubAnnounceMetaData, SequenceNumber: 1212,
				DataSetWriterID: 1213, MetaData: &metaWant, StatusCode: 1214}
		}),
		vec("announce application", OPCUAPubSubAnnouncement, b.u8(5).u16(1215).u16(1).cat(app).u32(1).str("tok94"), func(p *OPCUAPubSub) {
			p.Announcement = &OPCUAPubSubAnnounceData{AnnouncementType: OPCUAPubSubAnnounceApplication, SequenceNumber: 1215,
				ApplicationInformationType: 1, Application: &appWant, Capabilities: []string{"tok94"}}
		}),
		vec("announce status", OPCUAPubSubAnnouncement, b.u8(5).u16(1216).u16(2).u8(1).u32(2).u64(uaTicks).u64(uaTicks), func(p *OPCUAPubSub) {
			p.Announcement = &OPCUAPubSubAnnounceData{AnnouncementType: OPCUAPubSubAnnounceApplication, SequenceNumber: 1216,
				ApplicationInformationType: 2,
				Status:                     &OPCUAPubSubStatus{IsCyclic: true, Status: OPCUAPubSubStateOperational, NextReportTime: tm, Timestamp: tm}}
		}),
		vec("announce status once", OPCUAPubSubAnnouncement, b.u8(5).u16(1217).u16(2).u8(0).u32(3), func(p *OPCUAPubSub) {
			p.Announcement = &OPCUAPubSubAnnounceData{AnnouncementType: OPCUAPubSubAnnounceApplication, SequenceNumber: 1217,
				ApplicationInformationType: 2, Status: &OPCUAPubSubStatus{Status: OPCUAPubSubStateError}}
		}),
		vec("announce writer config", OPCUAPubSubAnnouncement, b.u8(3).u16(1218).u8(9, 9, 9), func(p *OPCUAPubSub) {
			p.Announcement = &OPCUAPubSubAnnounceData{AnnouncementType: OPCUAPubSubAnnounceWriterConfig, SequenceNumber: 1218,
				Body: []byte{9, 9, 9}}
			p.PayloadError = ErrOPCUAPubSubUnsupported
		}),
	}
}

func psVectors() []psVector { return append(psDataVectors(), psDiscoveryVectors()...) }

func decodePubSub(data []byte) (*OPCUAPubSub, error) {
	ps := &OPCUAPubSub{}
	err := ps.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	return ps, err
}

func TestOPCUAPubSubVectors(t *testing.T) {
	for _, v := range psVectors() {
		got, err := decodePubSub(v.data)
		if err != nil {
			t.Errorf("%s: %v", v.name, err)
			continue
		}
		if !bytes.Equal(got.Contents, v.data) || got.Payload != nil {
			t.Errorf("%s: contents %x payload %x", v.name, got.Contents, got.Payload)
		}
		got.BaseLayer = BaseLayer{}
		if !reflect.DeepEqual(*got, v.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", v.name, *got, v.want)
		}
		_ = fmt.Sprint(got.Type, got.PublisherID.Type)
		for i := range got.Messages {
			_ = fmt.Sprint(got.Messages[i].Type, got.Messages[i].Encoding, got.Messages[i].Valid())
		}
	}
}

// TestOPCUAPubSubNames spot-checks the enum names.
func TestOPCUAPubSubNames(t *testing.T) {
	for got, want := range map[string]string{
		OPCUAPubSubProbe.String():            "DiscoveryProbe",
		OPCUAPubSubMessageType(7).String():   "Unknown(7)",
		OPCUAPublisherIDString.String():      "String",
		OPCUADataSetDataValue.String():       "DataValue",
		OPCUADataSetKeepAlive.String():       "KeepAlive",
		OPCUAPubSubInfoMetaData.String():     "DataSetMetaData",
		OPCUAPubSubAnnounceMetaData.String(): "DataSetMetaData",
		OPCUAPubSubStatePaused.String():      "Paused",
		OPCUASortDescending.String():         "Descending",
		OPCUASortOrder(9).String():           "Unknown(9)",
		OPCUAComplianceCertified.String():    "Certified",
	} {
		if got != want {
			t.Errorf("name %q, want %q", got, want)
		}
	}
}

// TestOPCUAPubSubMalformed feeds headers that cannot be read and
// payloads that lie.
func TestOPCUAPubSubMalformed(t *testing.T) {
	b := uaBuilder{}
	key, _ := psKeyFrame(1)

	for name, tc := range map[string]struct {
		data []byte
		want error
	}{
		"empty":                {nil, ErrOPCUATruncated},
		"version 0":            {b.u8(0x00).cat(key), ErrOPCUAMalformed},
		"version 2":            {b.u8(0x02).cat(key), ErrOPCUAMalformed},
		"publisher id type 5":  {b.u8(0x91, 0x05).u32(1), ErrOPCUAMalformed},
		"third flags octet":    {b.u8(0x81, 0x80, 0x80), ErrOPCUAMalformed},
		"more group flags":     {b.u8(0x21, 0x80), ErrOPCUAMalformed},
		"probe payload header": {b.u8(0xC1, 0x80, 0x04, 1).u16(1), ErrOPCUAMalformed},
		"negative id length":   {b.u8(0x91, 0x04).u32(0xFFFFFFF0), ErrOPCUAMalformed},
		"writer ids missing":   {b.u8(0x41, 255), ErrOPCUATruncated},
		"cut class id":         {b.u8(0x81, 0x08, 1, 2, 3), ErrOPCUATruncated},
		"cut promoted fields":  {b.u8(0x81, 0x80, 0x02).u16(100).u8(1), ErrOPCUATruncated},
		"cut nonce":            {b.u8(0x81, 0x10, 0x01).u32(1).u8(8, 1, 2), ErrOPCUATruncated},
	} {
		if _, err := decodePubSub(tc.data); err != tc.want {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
		p := gopacket.NewPacket(tc.data, LayerTypeOPCUAPubSub, gopacket.Default)
		if p.ErrorLayer() == nil || p.Layer(LayerTypeOPCUAPubSub) != nil {
			t.Errorf("%s: packet decoded", name)
		}
	}

	// Payload lies are soft: the header stands, PayloadError tells.
	for name, tc := range map[string]struct {
		data []byte
		want error
		msgs int
	}{
		"field count lie":     {b.u8(0x01, 0x01).u16(0xFFFF).u8(1, 1), ErrOPCUATruncated, 1},
		"delta count lie":     {b.u8(0x01, 0x81, 0x01).u16(3).u16(0).u8(1, 1), ErrOPCUATruncated, 1},
		"bad variant":         {b.u8(0x01, 0x01).u16(1).u8(0x3F), ErrOPCUAMalformed, 1},
		"array count lie":     {b.u8(0x01, 0x01).u16(1).u8(0x86).u32(0x7FFFFFFF), ErrOPCUAMalformed, 1},
		"reserved encoding":   {b.u8(0x01, 0x07).u16(0), ErrOPCUAMalformed, 1},
		"action request":      {b.u8(0x01, 0x81, 0x05).u16(1), ErrOPCUAPubSubUnsupported, 1},
		"more message flags":  {b.u8(0x01, 0x81, 0x80), ErrOPCUAMalformed, 1},
		"cut message header":  {b.u8(0x01, 0x09, 0x01), ErrOPCUATruncated, 1},
		"sizes missing":       {b.u8(0x41, 2).u16(1, 2).u16(3), ErrOPCUATruncated, 0},
		"size past the data":  {b.u8(0x41, 2).u16(1, 2).u16(uint16(len(key)), 500).cat(key, key), ErrOPCUATruncated, 1},
		"action header":       {b.u8(0x81, 0x80, 0x20, 1, 2), ErrOPCUAPubSubUnsupported, 0},
		"reserved type":       {b.u8(0x81, 0x80, 0x0C, 1), ErrOPCUAPubSubUnsupported, 0},
		"cut chunk":           {b.u8(0x81, 0x80, 0x01).u16(1).u32(2), ErrOPCUATruncated, 0},
		"chunk length lie":    {b.u8(0x81, 0x80, 0x01).u16(1).u32(2, 3, 900), ErrOPCUATruncated, 0},
		"endpoint count lie":  {b.u8(0x81, 0x80, 0x08, 1).u16(1).u32(0x7FFFFFFF), ErrOPCUAMalformed, 0},
		"metadata count lie":  {b.u8(0x81, 0x80, 0x08, 2).u16(1).u16(1).u32(0x7FFFFFFF), ErrOPCUAMalformed, 0},
		"cut probe":           {b.u8(0x81, 0x80, 0x04, 1, 2).u32(5).u16(1), ErrOPCUAMalformed, 0},
		"empty probe":         {b.u8(0x81, 0x80, 0x04), ErrOPCUATruncated, 0},
		"cut application":     {b.u8(0x81, 0x80, 0x08, 5).u16(1).u16(1).u32(3), ErrOPCUATruncated, 0},
		"cut cyclic status":   {b.u8(0x81, 0x80, 0x08, 5).u16(1).u16(2).u8(1).u32(2).u32(1), ErrOPCUATruncated, 0},
		"cut announcement":    {b.u8(0x81, 0x80, 0x08, 1), ErrOPCUATruncated, 0},
		"unknown application": {b.u8(0x81, 0x80, 0x08, 5).u16(1).u16(9).u8(7), ErrOPCUAPubSubUnsupported, 0},
	} {
		ps, err := decodePubSub(tc.data)
		if err != nil || ps.PayloadError != tc.want || len(ps.Messages) != tc.msgs {
			t.Errorf("%s: %v, payload error %v with %d messages, want %v with %d", name, err, ps.PayloadError, len(ps.Messages), tc.want, tc.msgs)
			continue
		}

		// What failed is kept raw, in the layer or in its message.
		raw := ps.Undecoded != nil
		for i := range ps.Messages {
			raw = raw || ps.Messages[i].Undecoded != nil
		}
		if !raw && ps.Announcement == nil {
			t.Errorf("%s: nothing kept raw: %+v", name, ps)
		}
	}
}

// TestOPCUAPubSubTruncation cuts every vector at every offset: the
// header fails as a whole, the payload never does.
func TestOPCUAPubSubTruncation(t *testing.T) {
	for _, v := range psVectors() {
		header := -1
		for i := 0; i <= len(v.data); i++ {
			ps, err := decodePubSub(v.data[:i:i])
			if err == nil && header < 0 {
				header = i
			}
			if (err == nil) != (header >= 0) {
				t.Errorf("%s cut at %d: %v after the header decoded at %d", v.name, i, err, header)
			}
			_ = fmt.Sprintf("%+v", ps)
		}
		if header < 1 {
			t.Errorf("%s: header of %d bytes", v.name, header)
		}
	}
}

// TestOPCUAPubSubAllocBound checks that counts that lie cost nothing and
// that honest ones cost no more than the structs they fill.
func TestOPCUAPubSubAllocBound(t *testing.T) {
	const fields = 60000
	const maxPerByte = 160

	// One-octet Variants, as many as a field count can announce.
	data := uaBuilder{}.u8(0x01, 0x01).u16(fields).u8(make([]byte, fields)...)
	got := allocPerByte(len(data), func() { _, _ = decodePubSub(data) })
	t.Logf("UADP Variants: %.0f bytes per input byte", got)
	if got > maxPerByte {
		t.Errorf("Variants allocate %.0f bytes per input byte, want <= %d", got, maxPerByte)
	}

	// One-octet DataValues behind their index.
	delta := uaBuilder{}.u8(0x01, 0x85, 0x01).u16(fields / 3).u8(make([]byte, fields)...)
	got = allocPerByte(len(delta), func() { _, _ = decodePubSub(delta) })
	t.Logf("UADP delta DataValues: %.0f bytes per input byte", got)
	if got > maxPerByte {
		t.Errorf("delta DataValues allocate %.0f bytes per input byte, want <= %d", got, maxPerByte)
	}

	// 255 empty sized messages.
	many := uaBuilder{}.u8(0x41, 255).u8(make([]byte, 255*4)...)
	got = allocPerByte(len(many), func() { _, _ = decodePubSub(many) })
	t.Logf("UADP empty messages: %.0f bytes per input byte", got)
	if got > maxPerByte {
		t.Errorf("empty messages allocate %.0f bytes per input byte, want <= %d", got, maxPerByte)
	}

	// Counts that lie allocate nothing to speak of.
	const maxLie = 2048
	for name, lie := range map[string][]byte{
		"fields":    uaBuilder{}.u8(0x01, 0x01).u16(0xFFFF).u8(1),
		"writers":   uaBuilder{}.u8(0x41, 255).u8(1),
		"endpoints": uaBuilder{}.u8(0x81, 0x80, 0x08, 1).u16(1).u32(0x7FFFFFFF),
		"metadata":  uaBuilder{}.u8(0x81, 0x80, 0x08, 2).u16(1).u16(1).u32(1).u32(0x7FFFFFFF),
	} {
		if got := allocPerByte(1, func() { _, _ = decodePubSub(lie) }); got > maxLie {
			t.Errorf("%s count lie allocates %.0f bytes", name, got)
		}
	}
}

// TestOPCUAPubSubPackets decodes UADP below UDP and Ethernet once the
// decoders are registered.
func TestOPCUAPubSubPackets(t *testing.T) {
	udpTypes := copyUDPPortTypes()
	tcpTypes := copyTCPPortTypes()
	ether := EthernetTypeMetadata[EthernetTypeOPCUAPubSub]
	t.Cleanup(func() {
		udpPortLayerType, tcpPortLayerType = udpTypes, tcpTypes
		EthernetTypeMetadata[EthernetTypeOPCUAPubSub] = ether
	})
	registerOPCUADecoders()
	registerOPCUADecoders()

	key, _ := psKeyFrame(1001)
	msg := uaBuilder{}.u8(0x11, 7).cat(key)

	eth := &Ethernet{SrcMAC: []byte{2, 0, 0, 0, 0, 1}, DstMAC: []byte{1, 0, 0x5E, 0, 0, 1}, EthernetType: EthernetTypeOPCUAPubSub}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, gopacket.Payload(msg)); err != nil {
		t.Fatal(err)
	}
	p := gopacket.NewPacket(buf.Bytes(), LayerTypeEthernet, gopacket.Default)
	if ps, ok := p.Layer(LayerTypeOPCUAPubSub).(*OPCUAPubSub); !ok || p.ErrorLayer() != nil || ps.PublisherID.Numeric != 7 || len(ps.Messages) != 1 {
		t.Errorf("over Ethernet: %v", p)
	}

	eth.EthernetType = EthernetTypeIPv4
	ip := &IPv4{Version: 4, TTL: 1, Protocol: IPProtocolUDP, SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{224, 0, 2, 14}}
	udp := &UDP{SrcPort: 50000, DstPort: UDPPort(UDPPortOPCUAPubSub)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf = gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(msg)); err != nil {
		t.Fatal(err)
	}
	p = gopacket.NewPacket(buf.Bytes(), LayerTypeEthernet, gopacket.Default)
	if ps, ok := p.Layer(LayerTypeOPCUAPubSub).(*OPCUAPubSub); !ok || p.ErrorLayer() != nil || ps.Messages[0].Variants[0].Value != int32(1001) {
		t.Errorf("over UDP: %v", p)
	}

	// A DecodingLayerParser takes the layer too.
	var ps OPCUAPubSub
	var decoded []gopacket.LayerType
	if err := gopacket.NewDecodingLayerParser(LayerTypeOPCUAPubSub, &ps).DecodeLayers(msg, &decoded); err != nil ||
		len(decoded) != 1 || ps.Timestamp != (time.Time{}) || ps.PublisherID.Numeric != 7 {
		t.Errorf("DecodingLayerParser: %v %v", decoded, err)
	}
}

// psSeeds returns the hand-built NetworkMessages.
func psSeeds() [][]byte {
	var out [][]byte
	for _, v := range psVectors() {
		out = append(out, v.data)
	}
	return out
}

func FuzzOPCUAPubSub(f *testing.F) {
	for _, msg := range psSeeds() {
		f.Add(msg)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ps, err := decodePubSub(data)
		if err != nil {
			return
		}
		_ = fmt.Sprintf("%+v %v %v", ps, ps.Type, ps.PublisherID.Type)

		// The parts of a decoded message never hold more than it does.
		held := len(ps.Trailer) + len(ps.Undecoded) + len(ps.EncryptedPayload)
		if held > len(data) {
			t.Fatalf("%d bytes held of %d", held, len(data))
		}
		p := gopacket.NewPacket(data, LayerTypeOPCUAPubSub, gopacket.Default)
		if p.Layer(LayerTypeOPCUAPubSub) == nil {
			t.Fatalf("layer decodes, packet does not")
		}
	})
}
