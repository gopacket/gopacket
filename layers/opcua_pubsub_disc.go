// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// UADP discovery (OPC 10000-14 §7.2.4.6): the probe a subscriber sends
// and the announcements a publisher answers with, and the
// DataSetMetaData they carry (OPC 10000-14 §6.2.3.2.3).
//
//	probe         ProbeType ─ InformationType ─ what is asked for
//	announcement  AnnouncementType ─ SequenceNumber ─ body by type:
//	                1 endpoints        EndpointDescription[] ─ status
//	                2 DataSetMetaData  writer id ─ metadata ─ status
//	                5 application      description and capabilities,
//	                                   or publisher status
//	                3 4 6 7            kept raw in Body
//
// The type numbers are those of OPC UA 1.05.

package layers

import "time"

// Binary encoding ids of the metadata structures (NodeIds.csv).
const (
	opcuaStructureDefinitionID = 122
	opcuaEnumDefinitionID      = 123
	opcuaDataSetMetaDataID     = 124
	opcuaStructureDescID       = 126
	opcuaEnumDescID            = 127
	opcuaFieldMetaDataID       = 14839
	opcuaStructureFieldID      = 14844
	opcuaEnumFieldID           = 14845
	opcuaKeyValuePairID        = 14846
	opcuaConfigVersionID       = 14847
	opcuaSimpleTypeDescID      = 15421
	opcuaSchemaHeaderID        = 15676
)

// Minimum encoded sizes of the metadata structures.
const (
	opcuaMinStructFieldLen = opcuaUint32Len + opcuaMinMaskedLen + opcuaMinNodeIDLen + 3*opcuaUint32Len + opcuaUint8Len
	opcuaMinStructDefLen   = 2*opcuaMinNodeIDLen + 2*opcuaUint32Len
	opcuaMinStructDescLen  = opcuaMinNodeIDLen + opcuaMinQNameLen + opcuaMinStructDefLen
	opcuaMinEnumFieldLen   = opcuaUint64Len + 2*opcuaMinMaskedLen + opcuaUint32Len
	opcuaMinEnumDescLen    = opcuaMinNodeIDLen + opcuaMinQNameLen + opcuaUint32Len + opcuaUint8Len
	opcuaMinSimpleDescLen  = 2*opcuaMinNodeIDLen + opcuaMinQNameLen + opcuaUint8Len
	opcuaMinKeyValueLen    = opcuaMinQNameLen + opcuaMinVariantLen
	opcuaMinFieldMetaLen   = opcuaUint32Len + opcuaMinMaskedLen + opcuaUint16Len + opcuaUint8Len + opcuaMinNodeIDLen +
		3*opcuaUint32Len + opcuaGUIDLen + opcuaUint32Len
)

// OPCUAPubSubProbeType is the type of a discovery probe.
type OPCUAPubSubProbeType uint8

// OPCUAPubSubProbeType values.
const (
	OPCUAPubSubProbePublisherInfo    OPCUAPubSubProbeType = 1
	OPCUAPubSubProbeFindApplications OPCUAPubSubProbeType = 2
)

// OPCUAPubSubInformationType is what a publisher information probe
// asks for.
type OPCUAPubSubInformationType uint8

// OPCUAPubSubInformationType values.
const (
	OPCUAPubSubInfoEndpoints    OPCUAPubSubInformationType = 1
	OPCUAPubSubInfoMetaData     OPCUAPubSubInformationType = 2
	OPCUAPubSubInfoWriterConfig OPCUAPubSubInformationType = 3
	OPCUAPubSubInfoWriterGroup  OPCUAPubSubInformationType = 4
	OPCUAPubSubInfoConnections  OPCUAPubSubInformationType = 5
)

var opcuaPubSubInformationNames = map[OPCUAPubSubInformationType]string{
	OPCUAPubSubInfoEndpoints:    "PublisherEndpoints",
	OPCUAPubSubInfoMetaData:     "DataSetMetaData",
	OPCUAPubSubInfoWriterConfig: "DataSetWriterConfiguration",
	OPCUAPubSubInfoWriterGroup:  "WriterGroupConfiguration",
	OPCUAPubSubInfoConnections:  "PubSubConnections",
}

// String returns the information type name.
func (t OPCUAPubSubInformationType) String() string {
	return opcuaName(opcuaPubSubInformationNames, t)
}

// OPCUAPubSubProbeData is a discovery probe (OPC 10000-14 §7.2.4.6.12).
// The fields after InformationType are set by that type:
// DataSetWriterIDs for metadata and writer configuration, WriterGroupID
// for a writer group, the rest for connections.
type OPCUAPubSubProbeData struct {
	ProbeType             OPCUAPubSubProbeType
	InformationType       OPCUAPubSubInformationType
	DataSetWriterIDs      []uint16
	WriterGroupID         uint16
	TransportProfileURIs  []string
	IncludeWriterGroups   bool
	IncludeDataSetWriters bool
}

// OPCUAPubSubAnnouncementType is the type of a discovery announcement.
type OPCUAPubSubAnnouncementType uint8

// OPCUAPubSubAnnouncementType values.
const (
	OPCUAPubSubAnnounceEndpoints    OPCUAPubSubAnnouncementType = 1
	OPCUAPubSubAnnounceMetaData     OPCUAPubSubAnnouncementType = 2
	OPCUAPubSubAnnounceWriterConfig OPCUAPubSubAnnouncementType = 3
	OPCUAPubSubAnnounceConnections  OPCUAPubSubAnnouncementType = 4
	OPCUAPubSubAnnounceApplication  OPCUAPubSubAnnouncementType = 5
	OPCUAPubSubAnnounceResponders   OPCUAPubSubAnnouncementType = 6
	OPCUAPubSubAnnounceActionMeta   OPCUAPubSubAnnouncementType = 7
)

var opcuaPubSubAnnouncementNames = map[OPCUAPubSubAnnouncementType]string{
	OPCUAPubSubAnnounceEndpoints:    "PublisherEndpoints",
	OPCUAPubSubAnnounceMetaData:     "DataSetMetaData",
	OPCUAPubSubAnnounceWriterConfig: "DataSetWriterConfiguration",
	OPCUAPubSubAnnounceConnections:  "PubSubConnections",
	OPCUAPubSubAnnounceApplication:  "ApplicationInformation",
	OPCUAPubSubAnnounceResponders:   "ActionResponders",
	OPCUAPubSubAnnounceActionMeta:   "ActionMetaData",
}

// String returns the announcement type name.
func (t OPCUAPubSubAnnouncementType) String() string {
	return opcuaName(opcuaPubSubAnnouncementNames, t)
}

// Application information types of an announcement of type 5.
const (
	opcuaPubSubAppDescription = 1
	opcuaPubSubAppStatus      = 2
)

// OPCUAPubSubState is a PubSubState (OPC 10000-14 §6.2.1).
type OPCUAPubSubState uint32

// OPCUAPubSubState values.
const (
	OPCUAPubSubStateDisabled       OPCUAPubSubState = 0
	OPCUAPubSubStatePaused         OPCUAPubSubState = 1
	OPCUAPubSubStateOperational    OPCUAPubSubState = 2
	OPCUAPubSubStateError          OPCUAPubSubState = 3
	OPCUAPubSubStatePreOperational OPCUAPubSubState = 4
)

var opcuaPubSubStateNames = map[OPCUAPubSubState]string{
	OPCUAPubSubStateDisabled:       "Disabled",
	OPCUAPubSubStatePaused:         "Paused",
	OPCUAPubSubStateOperational:    "Operational",
	OPCUAPubSubStateError:          "Error",
	OPCUAPubSubStatePreOperational: "PreOperational",
}

// String returns the state name.
func (s OPCUAPubSubState) String() string { return opcuaName(opcuaPubSubStateNames, s) }

// OPCUAPubSubStatus is the status a publisher announces (OPC 10000-14
// §7.2.4.6.7). The times are only sent when IsCyclic.
type OPCUAPubSubStatus struct {
	IsCyclic       bool
	Status         OPCUAPubSubState
	NextReportTime time.Time
	Timestamp      time.Time
}

// OPCUAPubSubAnnounceData is a discovery announcement (OPC 10000-14
// §7.2.4.6.3). By AnnouncementType:
//
//   - endpoints: Endpoints and StatusCode.
//   - DataSetMetaData: DataSetWriterID, MetaData and StatusCode.
//   - application information: ApplicationInformationType, then
//     Application and Capabilities (1) or Status (2).
//   - any other type: Body, raw.
type OPCUAPubSubAnnounceData struct {
	AnnouncementType OPCUAPubSubAnnouncementType
	SequenceNumber   uint16

	Endpoints  []OPCUAEndpointDescription
	StatusCode OPCUAStatusCode

	DataSetWriterID uint16
	MetaData        *OPCUADataSetMetaData

	ApplicationInformationType uint16
	Application                *OPCUAApplicationDescription
	Capabilities               []string
	Status                     *OPCUAPubSubStatus

	Body []byte
}

// OPCUAStructureField is one field of a structure (OPC 10000-3 §8.51).
type OPCUAStructureField struct {
	Name            string
	Description     OPCUALocalizedText
	DataType        OPCUANodeID
	ValueRank       int32
	ArrayDimensions []uint32
	MaxStringLength uint32
	IsOptional      bool
}

// OPCUAStructureDefinition is the layout of a structure (OPC 10000-3
// §8.49). StructureType is 0 Structure, 1 with optional fields, 2 Union.
type OPCUAStructureDefinition struct {
	DefaultEncodingID OPCUANodeID
	BaseDataType      OPCUANodeID
	StructureType     uint32
	Fields            []OPCUAStructureField
}

// OPCUAStructureDescription names a structure and gives its layout.
type OPCUAStructureDescription struct {
	DataTypeID OPCUANodeID
	Name       OPCUAQualifiedName
	Definition OPCUAStructureDefinition
}

// OPCUAEnumField is one value of an enumeration (OPC 10000-3 §8.52).
type OPCUAEnumField struct {
	OPCUAEnumValueType
	Name string
}

// OPCUAEnumDefinition lists the values of an enumeration (OPC 10000-3
// §8.50).
type OPCUAEnumDefinition struct {
	Fields []OPCUAEnumField
}

// OPCUAEnumDescription names an enumeration and gives its values.
type OPCUAEnumDescription struct {
	DataTypeID  OPCUANodeID
	Name        OPCUAQualifiedName
	Definition  OPCUAEnumDefinition
	BuiltInType OPCUABuiltinType
}

// OPCUASimpleTypeDescription names a subtype of a built-in type.
type OPCUASimpleTypeDescription struct {
	DataTypeID   OPCUANodeID
	Name         OPCUAQualifiedName
	BaseDataType OPCUANodeID
	BuiltInType  OPCUABuiltinType
}

// OPCUAKeyValuePair is a KeyValuePair (OPC 10000-5 §12.21).
type OPCUAKeyValuePair struct {
	Key   OPCUAQualifiedName
	Value OPCUAVariant
}

// OPCUAFieldMetaData describes one field of a DataSet (OPC 10000-14
// §6.2.3.2.4). FieldFlags bit 0 marks a promoted field.
type OPCUAFieldMetaData struct {
	Name            string
	Description     OPCUALocalizedText
	FieldFlags      uint16
	BuiltInType     OPCUABuiltinType
	DataType        OPCUANodeID
	ValueRank       int32
	ArrayDimensions []uint32
	MaxStringLength uint32
	DataSetFieldID  OPCUAGUID
	Properties      []OPCUAKeyValuePair
}

// OPCUAConfigurationVersion is a ConfigurationVersionDataType
// (OPC 10000-14 §6.2.3.2.6): two VersionTimes.
type OPCUAConfigurationVersion struct {
	MajorVersion uint32
	MinorVersion uint32
}

// OPCUADataTypeSchemaHeader holds the types a DataSet uses beyond the
// standard ones (OPC 10000-5 §12.31).
type OPCUADataTypeSchemaHeader struct {
	Namespaces         []string
	StructureDataTypes []OPCUAStructureDescription
	EnumDataTypes      []OPCUAEnumDescription
	SimpleDataTypes    []OPCUASimpleTypeDescription
}

// OPCUADataSetMetaData is a DataSetMetaDataType (OPC 10000-14
// §6.2.3.2.3): the fields of a DataSet, which is what the RawData of a
// DataSetMessage is laid out by.
type OPCUADataSetMetaData struct {
	OPCUADataTypeSchemaHeader
	Name                 string
	Description          OPCUALocalizedText
	Fields               []OPCUAFieldMetaData
	DataSetClassID       OPCUAGUID
	ConfigurationVersion OPCUAConfigurationVersion
}

// opcuaPtr returns a pointer to v, or nil when r only probes or has
// failed, so that a probe allocates nothing.
func opcuaPtr[T any](r *opcuaReader, v T) *T {
	if r.err != nil || r.mode == opcuaReadProbe {
		return nil
	}
	p := new(T)
	*p = v
	return p
}

// decodeProbe reads a discovery probe.
func (p *OPCUAPubSub) decodeProbe(r *opcuaReader) {
	probe := opcuaReader{b: r.b, off: r.off, mode: opcuaReadProbe}
	probe.pubSubProbe()
	if probe.err != nil {
		r.fail(probe.err)
		return
	}
	p.Probe = opcuaPtr(r, r.pubSubProbe())
}

func (r *opcuaReader) pubSubProbe() OPCUAPubSubProbeData {
	d := OPCUAPubSubProbeData{ProbeType: OPCUAPubSubProbeType(r.u8())}
	if d.ProbeType != OPCUAPubSubProbePublisherInfo {
		return d
	}

	d.InformationType = OPCUAPubSubInformationType(r.u8())
	switch d.InformationType {
	case OPCUAPubSubInfoMetaData, OPCUAPubSubInfoWriterConfig:
		d.DataSetWriterIDs = opcuaArray(r, opcuaUint16Len, r.u16)
	case OPCUAPubSubInfoWriterGroup:
		d.WriterGroupID = r.u16()
	case OPCUAPubSubInfoConnections:
		d.TransportProfileURIs = r.strings()
		d.IncludeWriterGroups = r.boolean()
		d.IncludeDataSetWriters = r.boolean()
	}
	return d
}

// decodeAnnouncement reads a discovery announcement. It is probed
// first, so a count that lies costs no memory.
func (p *OPCUAPubSub) decodeAnnouncement(r *opcuaReader) {
	probe := opcuaReader{b: r.b, off: r.off, mode: opcuaReadProbe}
	probe.pubSubAnnouncement()
	if probe.err != nil {
		r.fail(probe.err)
		return
	}

	p.Announcement = opcuaPtr(r, r.pubSubAnnouncement())
	if p.Announcement != nil && p.Announcement.Body != nil {
		p.PayloadError = ErrOPCUAPubSubUnsupported
	}
}

func (r *opcuaReader) pubSubAnnouncement() OPCUAPubSubAnnounceData {
	a := OPCUAPubSubAnnounceData{AnnouncementType: OPCUAPubSubAnnouncementType(r.u8()), SequenceNumber: r.u16()}

	switch a.AnnouncementType {
	case OPCUAPubSubAnnounceEndpoints:
		a.Endpoints = r.endpoints()
		a.StatusCode = r.statusCode()
	case OPCUAPubSubAnnounceMetaData:
		a.DataSetWriterID = r.u16()
		a.MetaData = opcuaPtr(r, r.dataSetMetaData())
		a.StatusCode = r.statusCode()
	case OPCUAPubSubAnnounceApplication:
		r.applicationInfo(&a)
	default:
		a.Body = r.take(r.remaining())
	}
	return a
}

// applicationInfo reads the body of an application information
// announcement into a.
func (r *opcuaReader) applicationInfo(a *OPCUAPubSubAnnounceData) {
	a.ApplicationInformationType = r.u16()

	switch a.ApplicationInformationType {
	case opcuaPubSubAppDescription:
		a.Application = opcuaPtr(r, r.applicationDescription())
		a.Capabilities = r.strings()
	case opcuaPubSubAppStatus:
		s := OPCUAPubSubStatus{IsCyclic: r.boolean(), Status: OPCUAPubSubState(r.u32())}
		if s.IsCyclic {
			s.NextReportTime = r.dateTime()
			s.Timestamp = r.dateTime()
		}
		a.Status = opcuaPtr(r, s)
	default:
		a.Body = r.take(r.remaining())
	}
}

func (r *opcuaReader) structureField() OPCUAStructureField {
	return OPCUAStructureField{
		Name:            r.str(),
		Description:     r.localizedText(),
		DataType:        r.nodeID(),
		ValueRank:       r.i32(),
		ArrayDimensions: r.u32s(),
		MaxStringLength: r.u32(),
		IsOptional:      r.boolean(),
	}
}

func (r *opcuaReader) structureDefinition() OPCUAStructureDefinition {
	return OPCUAStructureDefinition{
		DefaultEncodingID: r.nodeID(),
		BaseDataType:      r.nodeID(),
		StructureType:     r.u32(),
		Fields:            opcuaArray(r, opcuaMinStructFieldLen, r.structureField),
	}
}

func (r *opcuaReader) structureDescription() OPCUAStructureDescription {
	return OPCUAStructureDescription{DataTypeID: r.nodeID(), Name: r.qualifiedName(), Definition: r.structureDefinition()}
}

func (r *opcuaReader) enumField() OPCUAEnumField {
	return OPCUAEnumField{
		OPCUAEnumValueType: OPCUAEnumValueType{Value: r.i64(), DisplayName: r.localizedText(), Description: r.localizedText()},
		Name:               r.str(),
	}
}

func (r *opcuaReader) enumDefinition() OPCUAEnumDefinition {
	return OPCUAEnumDefinition{Fields: opcuaArray(r, opcuaMinEnumFieldLen, r.enumField)}
}

func (r *opcuaReader) enumDescription() OPCUAEnumDescription {
	return OPCUAEnumDescription{
		DataTypeID:  r.nodeID(),
		Name:        r.qualifiedName(),
		Definition:  r.enumDefinition(),
		BuiltInType: OPCUABuiltinType(r.u8()),
	}
}

func (r *opcuaReader) simpleTypeDescription() OPCUASimpleTypeDescription {
	return OPCUASimpleTypeDescription{
		DataTypeID:   r.nodeID(),
		Name:         r.qualifiedName(),
		BaseDataType: r.nodeID(),
		BuiltInType:  OPCUABuiltinType(r.u8()),
	}
}

func (r *opcuaReader) keyValuePair() OPCUAKeyValuePair {
	return OPCUAKeyValuePair{Key: r.qualifiedName(), Value: r.variant(0)}
}

func (r *opcuaReader) fieldMetaData() OPCUAFieldMetaData {
	return OPCUAFieldMetaData{
		Name:            r.str(),
		Description:     r.localizedText(),
		FieldFlags:      r.u16(),
		BuiltInType:     OPCUABuiltinType(r.u8()),
		DataType:        r.nodeID(),
		ValueRank:       r.i32(),
		ArrayDimensions: r.u32s(),
		MaxStringLength: r.u32(),
		DataSetFieldID:  r.guid(),
		Properties:      opcuaArray(r, opcuaMinKeyValueLen, r.keyValuePair),
	}
}

func (r *opcuaReader) schemaHeader() OPCUADataTypeSchemaHeader {
	return OPCUADataTypeSchemaHeader{
		Namespaces:         r.strings(),
		StructureDataTypes: opcuaArray(r, opcuaMinStructDescLen, r.structureDescription),
		EnumDataTypes:      opcuaArray(r, opcuaMinEnumDescLen, r.enumDescription),
		SimpleDataTypes:    opcuaArray(r, opcuaMinSimpleDescLen, r.simpleTypeDescription),
	}
}

func (r *opcuaReader) dataSetMetaData() OPCUADataSetMetaData {
	return OPCUADataSetMetaData{
		OPCUADataTypeSchemaHeader: r.schemaHeader(),
		Name:                      r.str(),
		Description:               r.localizedText(),
		Fields:                    opcuaArray(r, opcuaMinFieldMetaLen, r.fieldMetaData),
		DataSetClassID:            r.guid(),
		ConfigurationVersion:      OPCUAConfigurationVersion{MajorVersion: r.u32(), MinorVersion: r.u32()},
	}
}

// extMetaData reads the metadata structures when they travel in an
// ExtensionObject, as the value of a DataTypeDefinition attribute or of
// the DataSetMetaData property of a published DataSet.
func (r *opcuaReader) extMetaData(id uint32) (interface{}, bool) {
	switch id {
	case opcuaStructureDefinitionID:
		return opcuaBoxed(r, r.structureDefinition()), true
	case opcuaEnumDefinitionID:
		return opcuaBoxed(r, r.enumDefinition()), true
	case opcuaDataSetMetaDataID:
		return opcuaBoxed(r, r.dataSetMetaData()), true
	case opcuaStructureDescID:
		return opcuaBoxed(r, r.structureDescription()), true
	case opcuaEnumDescID:
		return opcuaBoxed(r, r.enumDescription()), true
	case opcuaFieldMetaDataID:
		return opcuaBoxed(r, r.fieldMetaData()), true
	case opcuaStructureFieldID:
		return opcuaBoxed(r, r.structureField()), true
	case opcuaEnumFieldID:
		return opcuaBoxed(r, r.enumField()), true
	case opcuaKeyValuePairID:
		return opcuaBoxed(r, r.keyValuePair()), true
	case opcuaConfigVersionID:
		return opcuaBoxed(r, OPCUAConfigurationVersion{MajorVersion: r.u32(), MinorVersion: r.u32()}), true
	case opcuaSimpleTypeDescID:
		return opcuaBoxed(r, r.simpleTypeDescription()), true
	case opcuaSchemaHeaderID:
		return opcuaBoxed(r, r.schemaHeader()), true
	}
	return nil, false
}
