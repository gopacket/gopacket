// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// The captures hold no node management beyond AddNodes of Objects and
// Variables, no query, no history update, no filter results, no history
// data and no chunked message. Every vector here is built by hand after
// OPC 10000-4, -5, -8 and -11 and was checked field by field against
// tshark 4.7, GenericAttributes aside, which tshark does not know.

// uaTicks is 2019-04-19 00:00:00 UTC as a DateTime.
const uaTicks = 132000624000000000

func uaTime() time.Time {
	return time.Unix(uaTicks/opcuaTicksPerSecond-opcuaEpochToUnixSecond, 0).UTC()
}

func (b uaBuilder) u64(v uint64) uaBuilder { return binary.LittleEndian.AppendUint64(b, v) }

func (b uaBuilder) f32(v float32) uaBuilder {
	return binary.LittleEndian.AppendUint32(b, math.Float32bits(v))
}

// text appends a LocalizedText with only a text.
func (b uaBuilder) text(s string) uaBuilder { return b.u8(opcuaTextText).str(s) }

// cat appends parts into a fresh builder.
func (b uaBuilder) cat(parts ...[]byte) uaBuilder {
	out := append(uaBuilder{}, b...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func n4(ns uint16, id uint32) OPCUANodeID { return nsNumeric(OPCUANodeIDFourByte, ns, id) }

func uaText(s string) OPCUALocalizedText { return OPCUALocalizedText{Mask: opcuaTextText, Text: s} }

// uaExt is the ExtensionObject that uaBuilder.ext(id, body) decodes to.
func uaExt(id uint16, body []byte, v interface{}) OPCUAExtensionObject {
	return OPCUAExtensionObject{TypeID: n4(0, uint32(id)), Encoding: 1, Body: body, Value: v}
}

// uaExtVector is the body of a known structure and what it decodes to.
type uaExtVector struct {
	id   uint16
	body []byte
	want interface{}
}

// uaExtVectors lists one body per structure of the registry.
func uaExtVectors() []uaExtVector {
	b := uaBuilder{}
	tm := uaTime()
	n := n4(1, 5)
	noDiag := OPCUADiagnosticInfo{SymbolicID: -1, NamespaceURI: -1, Locale: -1, LocalizedText: -1}

	element := b.u32(1)
	literal := b.u8(uint8(OPCUATypeInt32)).u32(7)
	simple := b.node(0, 2041).u32(1).u16(0).str("Message").u32(13).null()
	simpleWant := OPCUASimpleAttributeOperand{
		TypeDefinitionID: n4(0, 2041),
		BrowsePath:       []OPCUAQualifiedName{{Name: "Message"}},
		AttributeID:      OPCUAAttributeValue,
	}
	filter := b.u32(1).cat(simple).u32(1, 0, 2).ext(opcuaElementOperandID, element).ext(opcuaLiteralOperandID, literal)
	filterWant := OPCUAEventFilter{
		SelectClauses: []OPCUASimpleAttributeOperand{simpleWant},
		WhereClause: OPCUAContentFilter{Elements: []OPCUAContentFilterElement{{
			FilterOperands: []OPCUAExtensionObject{
				uaExt(opcuaElementOperandID, element, &OPCUAElementOperand{Index: 1}),
				uaExt(opcuaLiteralOperandID, literal, &OPCUALiteralOperand{Value: OPCUAVariant{Type: OPCUATypeInt32, Value: int32(7)}}),
			},
		}}},
	}
	config := b.u8(1, 0, 100, 90, 0)
	configWant := OPCUAAggregateConfiguration{UseServerCapabilitiesDefaults: true, PercentDataBad: 100, PercentDataGood: 90}

	value := b.u8(opcuaDataValueValue, uint8(OPCUATypeInt32)).u32(1)
	valueWant := OPCUADataValue{Mask: opcuaDataValueValue, Value: OPCUAVariant{Type: OPCUATypeInt32, Value: int32(1)}}
	event := b.u32(1).u8(uint8(OPCUATypeString)).str("e")
	eventWant := OPCUAHistoryEventFieldList{EventFields: []OPCUAVariant{{Type: OPCUATypeString, Value: "e"}}}

	eu := b.str("urn:units").u32(4408652).text("°C").text("degree Celsius")
	euWant := OPCUAEUInformation{NamespaceURI: "urn:units", UnitID: 4408652, DisplayName: uaText("°C"), Description: uaText("degree Celsius")}
	build := b.str("urn:p").str("ACME").str("Server").str("1.2").str("77").u64(uaTicks)
	buildWant := OPCUABuildInfo{ProductURI: "urn:p", ManufacturerName: "ACME", ProductName: "Server", SoftwareVersion: "1.2", BuildNumber: "77", BuildDate: tm}
	app := b.str("urn:a").str("urn:p").text("App").u32(1).null().null().null()
	appWant := OPCUAApplicationDescription{ApplicationURI: "urn:a", ProductURI: "urn:p", ApplicationName: uaText("App"), ApplicationType: OPCUAApplicationClient}
	qname := b.u16(0).null()
	readID := b.u8(0, 0).u32(0).null().cat(qname)
	monParams := b.u32(0).f64(0).u8(0, 0, 0).u32(0).u8(0)

	return []uaExtVector{
		{opcuaDataChangeFilterID, b.u32(1, 1).f64(3), &OPCUADataChangeFilter{Trigger: 1, DeadbandType: 1, DeadbandValue: 3}},
		{opcuaEventFilterID, filter, &filterWant},
		{opcuaAggregateFilterID, b.u64(uaTicks).node(0, 2342).f64(1000).cat(config),
			&OPCUAAggregateFilter{StartTime: tm, AggregateType: n4(0, 2342), ProcessingInterval: 1000, AggregateConfiguration: configWant}},
		{opcuaEventFilterResultID, b.u32(1, 0).null().u32(1, 0x80C10000, 1, 0).null().null(),
			&OPCUAEventFilterResult{
				SelectClauseResults: []OPCUAStatusCode{0},
				WhereClauseResult: OPCUAContentFilterResult{ElementResults: []OPCUAContentFilterElementResult{
					{StatusCode: 0x80C10000, OperandStatusCodes: []OPCUAStatusCode{0}}}},
			}},
		{opcuaAggFilterResultID, b.u64(uaTicks).f64(500).cat(config),
			&OPCUAAggregateFilterResult{RevisedStartTime: tm, RevisedProcessingInterval: 500, RevisedAggregateConfiguration: configWant}},
		{opcuaAttributeOperandID, b.node(0, 85).str("a").u32(1).node(0, 46).u8(1, 1).u16(0).str("X").u32(13).str("1:2"),
			&OPCUAAttributeOperand{
				NodeID:      n4(0, 85),
				Alias:       "a",
				BrowsePath:  []OPCUARelativePathElement{{ReferenceTypeID: n4(0, 46), IsInverse: true, IncludeSubtypes: true, TargetName: OPCUAQualifiedName{Name: "X"}}},
				AttributeID: OPCUAAttributeValue,
				IndexRange:  "1:2",
			}},
		{opcuaSimpleAttrOperandID, simple, &simpleWant},

		{opcuaReadEventDetailsID, b.u32(10).u64(uaTicks).u64(uaTicks).cat(filter),
			&OPCUAReadEventDetails{NumValuesPerNode: 10, StartTime: tm, EndTime: tm, Filter: filterWant}},
		{opcuaReadRawDetailsID, b.u8(1).u64(uaTicks).u64(uaTicks).u32(100).u8(1),
			&OPCUAReadRawModifiedDetails{IsReadModified: true, StartTime: tm, EndTime: tm, NumValuesPerNode: 100, ReturnBounds: true}},
		{opcuaReadProcDetailsID, b.u64(uaTicks).u64(uaTicks).f64(60000).u32(1).node(0, 2342).cat(config),
			&OPCUAReadProcessedDetails{StartTime: tm, EndTime: tm, ProcessingInterval: 60000,
				AggregateType: []OPCUANodeID{n4(0, 2342)}, AggregateConfiguration: configWant}},
		{opcuaReadAtTimeDetailsID, b.u32(2).u64(uaTicks).u64(0).u8(1),
			&OPCUAReadAtTimeDetails{ReqTimes: []time.Time{tm, {}}, UseSimpleBounds: true}},
		{opcuaHistoryDataID, b.u32(2).cat(value).u8(opcuaDataValueValue|opcuaDataValueStatus, uint8(OPCUATypeDouble)).f64(2.5).u32(0x40000000),
			&OPCUAHistoryData{DataValues: []OPCUADataValue{valueWant,
				{Mask: 3, Value: OPCUAVariant{Type: OPCUATypeDouble, Value: 2.5}, Status: 0x40000000}}}},
		{opcuaHistoryModifiedID, b.u32(1).cat(value).u32(1).u64(uaTicks).u32(2).str("op"),
			&OPCUAHistoryModifiedData{DataValues: []OPCUADataValue{valueWant},
				ModificationInfos: []OPCUAModificationInfo{{ModificationTime: tm, UpdateType: 2, UserName: "op"}}}},
		{opcuaHistoryEventID, b.u32(1).cat(event), &OPCUAHistoryEvent{Events: []OPCUAHistoryEventFieldList{eventWant}}},

		{opcuaHistUpdDetailsID, b.node(1, 5), &OPCUAHistoryUpdateDetails{NodeID: n}},
		{opcuaUpdateDataID, b.node(1, 5).u32(1, 1).cat(value),
			&OPCUAUpdateDataDetails{NodeID: n, PerformInsertReplace: 1, UpdateValues: []OPCUADataValue{valueWant}}},
		{opcuaUpdateStructureID, b.node(1, 5).u32(2, 1).cat(value),
			&OPCUAUpdateDataDetails{NodeID: n, PerformInsertReplace: 2, UpdateValues: []OPCUADataValue{valueWant}}},
		{opcuaUpdateEventID, b.node(1, 5).u32(2).cat(filter).u32(1).cat(event),
			&OPCUAUpdateEventDetails{NodeID: n, PerformInsertReplace: 2, Filter: filterWant, EventData: []OPCUAHistoryEventFieldList{eventWant}}},
		{opcuaDeleteRawID, b.node(1, 5).u8(1).u64(uaTicks).u64(uaTicks),
			&OPCUADeleteRawModifiedDetails{NodeID: n, IsDeleteModified: true, StartTime: tm, EndTime: tm}},
		{opcuaDeleteAtTimeID, b.node(1, 5).u32(1).u64(uaTicks), &OPCUADeleteAtTimeDetails{NodeID: n, ReqTimes: []time.Time{tm}}},
		{opcuaDeleteEventID, b.node(1, 5).u32(1).str("id"), &OPCUADeleteEventDetails{NodeID: n, EventIDs: [][]byte{[]byte("id")}}},

		{opcuaAnonymousTokenID, b.str("anon"), &OPCUAUserIdentityToken{TokenType: OPCUAUserTokenAnonymous, PolicyID: "anon"}},
		{opcuaUserNameTokenID, b.str("user").str("joe").str("pw").str("alg"),
			&OPCUAUserIdentityToken{TokenType: OPCUAUserTokenUserName, PolicyID: "user", UserName: "joe", EncryptionAlgorithm: "alg"}},
		{opcuaStatusChangeNotifID, b.u32(0x80760000).u8(0),
			&OPCUAStatusChangeNotification{Status: 0x80760000, DiagnosticInfo: noDiag}},
		{opcuaMdnsConfigID, b.str("mdns").u32(1).str("LDS"),
			&OPCUAMdnsDiscoveryConfig{MdnsServerName: "mdns", ServerCapabilities: []string{"LDS"}}},

		{opcuaArgumentID, b.str("x").node(0, 6).u32(math.MaxUint32).null().text("the x"),
			&OPCUAArgument{Name: "x", DataType: n4(0, 6), ValueRank: -1, Description: uaText("the x")}},
		{opcuaRangeID, b.f64(-40).f64(125), &OPCUARange{Low: -40, High: 125}},
		{opcuaEUInformationID, eu, &euWant},
		{opcuaEnumValueTypeID, b.u64(math.MaxUint64 - 1).text("Low").u8(0), &OPCUAEnumValueType{Value: -2, DisplayName: uaText("Low")}},
		{opcuaTimeZoneID, b.u16(0xFFC4).u8(1), &OPCUATimeZone{Offset: -60, DaylightSavingInOffset: true}},
		{opcuaStatusResultID, b.u32(0x80340000).u8(opcuaDiagSymbolicID).u32(4),
			&OPCUAStatusResult{StatusCode: 0x80340000,
				DiagnosticInfo: OPCUADiagnosticInfo{Mask: 1, SymbolicID: 4, NamespaceURI: -1, Locale: -1, LocalizedText: -1}}},
		{opcuaBuildInfoID, build, &buildWant},
		{opcuaServerStatusID, b.u64(uaTicks).u64(uaTicks).u32(4).cat(build).u32(30).text("bye"),
			&OPCUAServerStatus{StartTime: tm, CurrentTime: tm, State: 4, BuildInfo: buildWant, SecondsTillShutdown: 30, ShutdownReason: uaText("bye")}},
		{opcuaAppDescriptionID, app, &appWant},
		{opcuaEndpointDescID, b.str("opc.tcp://a").cat(app).null().u32(1).str("none").null().null().u8(5),
			&OPCUAEndpointDescription{EndpointURL: "opc.tcp://a", Server: appWant, SecurityMode: OPCUASecurityModeNone,
				SecurityPolicyURI: "none", SecurityLevel: 5}},
		{opcuaUserTokenPolicyID, b.str("p").u32(1).null().null().null(), &OPCUAUserTokenPolicy{PolicyID: "p", TokenType: OPCUAUserTokenUserName}},
		{opcuaSoftwareCertID, b.str("c").str("s"), &OPCUASignedSoftwareCertificate{CertificateData: []byte("c"), Signature: []byte("s")}},
		{opcuaServiceCounterID, b.u32(10, 1), &OPCUAServiceCounter{TotalCount: 10, ErrorCount: 1}},
		{opcuaRedundantServerID, b.str("srv").u8(200).u32(3), &OPCUARedundantServer{ServerID: "srv", ServiceLevel: 200, ServerState: 3}},
		{opcuaModelChangeID, b.node(1, 5).node(0, 58).u8(1), &OPCUAModelChange{Affected: n, AffectedType: n4(0, 58), Verb: 1}},
		{opcuaSemanticChangeID, b.node(1, 5).node(0, 58), &OPCUASemanticChange{Affected: n, AffectedType: n4(0, 58)}},
		{opcuaAnnotationID, b.str("m").str("u").u64(uaTicks), &OPCUAAnnotation{Message: "m", UserName: "u", AnnotationTime: tm}},
		{opcuaAxisInformationID, b.cat(eu).f64(0).f64(10).text("t").u32(1, 2).f64(1).f64(2),
			&OPCUAAxisInformation{EngineeringUnits: euWant, EURange: OPCUARange{High: 10}, Title: uaText("t"), AxisScaleType: 1, AxisSteps: []float64{1, 2}}},
		{opcuaXVTypeID, b.f64(1.5).f32(2.5), &OPCUAXVType{X: 1.5, Value: 2.5}},
		{opcuaComplexNumberID, b.f32(1).f32(-1), &OPCUAComplexNumber{Real: 1, Imaginary: -1}},
		{opcuaDoubleComplexID, b.f64(1).f64(-1), &OPCUADoubleComplex{Real: 1, Imaginary: -1}},
		{opcuaSamplingDiagID, b.f64(100).u32(1, 2, 3),
			&OPCUASamplingDiagnostics{SamplingInterval: 100, MonitoredItemCount: 1, MaxMonitoredItemCount: 2, DisabledMonitoredItemCount: 3}},
		{opcuaServerDiagID, b.u32(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), &OPCUAServerDiagnostics{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}},
		{opcuaEndpointURLListID, b.u32(1).str("opc.tcp://a"), &OPCUAEndpointURLList{EndpointURLList: []string{"opc.tcp://a"}}},
		{opcuaOptionSetID, b.str("\x05").str("\x07"), &OPCUAOptionSet{Value: []byte{5}, ValidBits: []byte{7}}},
		{opcuaTrustListID, b.u32(15, 1).str("cert").null().null().null(),
			&OPCUATrustList{SpecifiedLists: 15, TrustedCertificates: [][]byte{[]byte("cert")}}},

		// The service parameter structures, each in its smallest form.
		{opcuaNodeAttrsID, b.u32(0).u8(0, 0).u32(0, 0), &OPCUANodeAttributes{}},
		{opcuaAddNodesItemID, b.u8(0, 0, 0, 0, 0, 0).cat(qname).u32(0).u8(0, 0, 0, 0, 0), &OPCUAAddNodesItem{}},
		{opcuaAddRefsItemID, b.u8(0, 0, 0, 0, 0).null().u8(0, 0).u32(0), &OPCUAAddReferencesItem{}},
		{opcuaDelRefsItemID, b.u8(0, 0, 0, 0, 0, 0, 0, 0), &OPCUADeleteReferencesItem{}},
		{opcuaRegisteredServerID, b.null().null().null().u32(0).null().null().null().u8(0), &OPCUARegisteredServer{}},
		{opcuaSignatureDataID, b.str("alg").str("sig"), &OPCUASignatureData{Algorithm: "alg", Signature: []byte("sig")}},
		{opcuaViewDescriptionID, b.u8(0, 0).u64(0).u32(0), &OPCUAViewDescription{}},
		{opcuaBrowseDescID, b.u8(0, 0).u32(0).u8(0, 0, 0).u32(0, 0), &OPCUABrowseDescription{}},
		{opcuaReferenceDescID, b.u8(0, 0, 0, 0, 0).cat(qname).u8(0).u32(0).u8(0, 0), &OPCUAReferenceDescription{}},
		{opcuaBrowseResultID, b.u32(0).null().null(), &OPCUABrowseResult{}},
		{opcuaPathElementID, b.u8(0, 0, 0, 0).cat(qname), &OPCUARelativePathElement{}},
		{opcuaPathResultID, b.u32(0).null(), &OPCUABrowsePathResult{}},
		{opcuaNodeTypeDescID, b.u8(0, 0, 0).null(), &OPCUANodeTypeDescription{}},
		{opcuaContentFilterID, b.null(), &OPCUAContentFilter{}},
		{opcuaFilterResultID, b.null().null(), &OPCUAContentFilterResult{}},
		{opcuaReadValueIDID, readID, &OPCUAReadValueID{}},
		{opcuaHistReadValueIDID, b.u8(0, 0).null().cat(qname).null(), &OPCUAHistoryReadValueID{}},
		{opcuaCallResultID, b.u32(0).null().null().null(), &OPCUACallMethodResult{}},
		{opcuaMonParamsID, monParams, &OPCUAMonitoringParameters{}},
		{opcuaItemCreateID, b.cat(readID).u32(0).cat(monParams), &OPCUAMonitoredItemCreate{}},
		{opcuaNotifMessageID, b.u32(0).u64(0).null(), &OPCUANotificationMessage{}},
		{opcuaAggregateConfigID, config, &configWant},
		{opcuaElementOperandID, element, &OPCUAElementOperand{Index: 1}},
		{opcuaLiteralOperandID, literal, &OPCUALiteralOperand{Value: OPCUAVariant{Type: OPCUATypeInt32, Value: int32(7)}}},
	}
}

// uaNodeClassVectors is one NodeAttributes body per node class.
func uaNodeClassVectors() []uaExtVector {
	b := uaBuilder{}
	base := b.u32(7).text("N").u8(0).u32(1, 2)
	baseWant := OPCUANodeAttributes{SpecifiedAttributes: 7, DisplayName: uaText("N"), WriteMask: 1, UserWriteMask: 2}
	str := OPCUAVariant{Type: OPCUATypeString, Value: "v"}

	return []uaExtVector{
		{opcuaObjectAttrsID, b.cat(base).u8(4), &OPCUAObjectAttributes{OPCUANodeAttributes: baseWant, EventNotifier: 4}},
		{opcuaVariableAttrsID, b.cat(base).u8(uint8(OPCUATypeInt32)).u32(5).node(0, 6).u32(math.MaxUint32).null().u8(1, 3).f64(100).u8(1),
			&OPCUAVariableAttributes{OPCUANodeAttributes: baseWant, Value: OPCUAVariant{Type: OPCUATypeInt32, Value: int32(5)},
				DataType: n4(0, 6), ValueRank: -1, AccessLevel: 1, UserAccessLevel: 3, MinimumSamplingInterval: 100, Historizing: true}},
		{opcuaMethodAttrsID, b.cat(base).u8(1, 0), &OPCUAMethodAttributes{OPCUANodeAttributes: baseWant, Executable: true}},
		{opcuaObjectTypeAttrsID, b.cat(base).u8(1), &OPCUAObjectTypeAttributes{OPCUANodeAttributes: baseWant, IsAbstract: true}},
		{opcuaVarTypeAttrsID, b.cat(base).u8(uint8(OPCUATypeString)).str("v").node(0, 12).u32(1, 1, 3).u8(1),
			&OPCUAVariableTypeAttributes{OPCUANodeAttributes: baseWant, Value: str, DataType: n4(0, 12), ValueRank: 1,
				ArrayDimensions: []uint32{3}, IsAbstract: true}},
		{opcuaRefTypeAttrsID, b.cat(base).u8(0, 1).text("inv"),
			&OPCUAReferenceTypeAttributes{OPCUANodeAttributes: baseWant, Symmetric: true, InverseName: uaText("inv")}},
		{opcuaDataTypeAttrsID, b.cat(base).u8(1), &OPCUADataTypeAttributes{OPCUANodeAttributes: baseWant, IsAbstract: true}},
		{opcuaViewAttrsID, b.cat(base).u8(1, 2), &OPCUAViewAttributes{OPCUANodeAttributes: baseWant, ContainsNoLoops: true, EventNotifier: 2}},
		{opcuaGenericAttrsID, b.cat(base).u32(1, 13).u8(uint8(OPCUATypeBoolean), 1),
			&OPCUAGenericAttributes{OPCUANodeAttributes: baseWant, AttributeValues: []OPCUAGenericAttributeValue{
				{AttributeID: OPCUAAttributeValue, Value: OPCUAVariant{Type: OPCUATypeBoolean, Value: true}}}}},
	}
}

// uaMgmtVectors are the services the captures lack.
func uaMgmtVectors() []uaVector {
	b := uaBuilder{}
	tm := uaTime()
	noDiag := OPCUADiagnosticInfo{SymbolicID: -1, NamespaceURI: -1, Locale: -1, LocalizedText: -1}

	// One AddNodesItem per node class.
	classes := uaNodeClassVectors()
	addNodes := b.u32(uint32(len(classes)))
	var addWant []OPCUAAddNodesItem
	for _, c := range classes {
		addNodes = addNodes.node(0, 85).node(0, 35).node(1, 1000).u16(1).str("Pump").u32(2).ext(c.id, c.body).node(0, 63)
		addWant = append(addWant, OPCUAAddNodesItem{
			ParentNodeID:       n4(0, 85),
			ReferenceTypeID:    n4(0, 35),
			RequestedNewNodeID: n4(1, 1000),
			BrowseName:         OPCUAQualifiedName{Namespace: 1, Name: "Pump"},
			NodeClass:          OPCUANodeClassVariable,
			NodeAttributes:     uaExt(c.id, c.body, c.want),
			TypeDefinition:     n4(0, 63),
		})
	}

	path := b.u32(1).node(0, 46).u8(0, 1).u16(0).str("Speed")
	pathWant := []OPCUARelativePathElement{{ReferenceTypeID: n4(0, 46), IncludeSubtypes: true, TargetName: OPCUAQualifiedName{Name: "Speed"}}}
	literal := b.u8(uint8(OPCUATypeDouble)).f64(1.5)
	dataSets := b.u32(1).node(1, 5).node(0, 58).u32(1).u8(uint8(OPCUATypeDouble)).f64(2)
	dataSetsWant := []OPCUAQueryDataSet{{NodeID: n4(1, 5), TypeDefinitionNode: n4(0, 58), Values: []OPCUAVariant{{Type: OPCUATypeDouble, Value: 2.0}}}}

	updates := uaExtVectors()[14:21]
	history := b.u32(uint32(len(updates)))
	var historyWant []OPCUAExtensionObject
	for _, u := range updates {
		history = history.ext(u.id, u.body)
		historyWant = append(historyWant, uaExt(u.id, u.body, u.want))
	}

	dataChange := b.u32(1, 1).f64(3)
	mdns := b.str("mdns").u32(1).str("LDS")
	server := b.str("urn:s").str("urn:p").u32(1).text("Srv").u32(0).null().u32(1).str("opc.tcp://s").str("/sem").u8(1)
	serverWant := OPCUARegisteredServer{ServerURI: "urn:s", ProductURI: "urn:p", ServerNames: []OPCUALocalizedText{uaText("Srv")},
		DiscoveryURLs: []string{"opc.tcp://s"}, SemaphoreFilePath: "/sem", IsOnline: true}
	raw := b.u8(1).u64(uaTicks).u64(uaTicks).u32(100).u8(0)
	histData := b.u32(1).u8(opcuaDataValueValue, uint8(OPCUATypeInt32)).u32(1)

	return []uaVector{
		{"AddNodes", OPCUAServiceAddNodesRequest, addNodes,
			func(s *OPCUAService) interface{} { return s.AddNodesRequest },
			&OPCUAAddNodesRequest{NodesToAdd: addWant}},
		{"AddNodes resp", OPCUAServiceAddNodesResponse, b.u32(2, 0).node(1, 1000).u32(0x805E0000).u8(0, 0).null(),
			func(s *OPCUAService) interface{} { return s.AddNodesResponse },
			&OPCUAAddNodesResponse{Results: []OPCUAAddNodesResult{{AddedNodeID: n4(1, 1000)}, {StatusCode: 0x805E0000}}}},
		{"AddReferences", OPCUAServiceAddReferencesRequest, b.u32(1).node(1, 5).node(0, 35).u8(1).str("urn:t").node(1, 6).u32(1),
			func(s *OPCUAService) interface{} { return s.AddReferencesRequest },
			&OPCUAAddReferencesRequest{ReferencesToAdd: []OPCUAAddReferencesItem{{SourceNodeID: n4(1, 5), ReferenceTypeID: n4(0, 35),
				IsForward: true, TargetServerURI: "urn:t", TargetNodeID: n4(1, 6), TargetNodeClass: OPCUANodeClassObject}}}},
		{"AddReferences resp", OPCUAServiceAddReferencesResponse, b.u32(1, 0).null(),
			func(s *OPCUAService) interface{} { return s.AddReferencesResponse },
			&OPCUAResults{Results: []OPCUAStatusCode{0}}},
		{"DeleteNodes", OPCUAServiceDeleteNodesRequest, b.u32(2).node(1, 5).u8(1).node(1, 6).u8(0),
			func(s *OPCUAService) interface{} { return s.DeleteNodesRequest },
			&OPCUADeleteNodesRequest{NodesToDelete: []OPCUADeleteNodesItem{{NodeID: n4(1, 5), DeleteTargetReferences: true}, {NodeID: n4(1, 6)}}}},
		{"DeleteNodes resp", OPCUAServiceDeleteNodesResponse, b.u32(1, 0x80340000).null(),
			func(s *OPCUAService) interface{} { return s.DeleteNodesResponse },
			&OPCUAResults{Results: []OPCUAStatusCode{0x80340000}}},
		{"DeleteReferences", OPCUAServiceDeleteReferencesRequest, b.u32(1).node(1, 5).node(0, 35).u8(1).node(1, 6).u8(1),
			func(s *OPCUAService) interface{} { return s.DeleteReferencesRequest },
			&OPCUADeleteReferencesRequest{ReferencesToDelete: []OPCUADeleteReferencesItem{{SourceNodeID: n4(1, 5),
				ReferenceTypeID: n4(0, 35), IsForward: true, TargetNodeID: n4(1, 6), DeleteBidirectional: true}}}},
		{"DeleteReferences resp", OPCUAServiceDeleteReferencesResponse, b.u32(1, 0).null(),
			func(s *OPCUAService) interface{} { return s.DeleteReferencesResponse },
			&OPCUAResults{Results: []OPCUAStatusCode{0}}},

		{"QueryFirst", OPCUAServiceQueryFirstRequest,
			b.u8(0, 0).u64(0).u32(0).u32(1).node(0, 58).u8(1).u32(1).cat(path).u32(13).null().
				u32(1, 4, 1).ext(opcuaLiteralOperandID, literal).u32(10, 0),
			func(s *OPCUAService) interface{} { return s.QueryFirstRequest },
			&OPCUAQueryFirstRequest{
				NodeTypes: []OPCUANodeTypeDescription{{TypeDefinitionNode: n4(0, 58), IncludeSubTypes: true,
					DataToReturn: []OPCUAQueryDataDescription{{RelativePath: pathWant, AttributeID: OPCUAAttributeValue}}}},
				Filter: OPCUAContentFilter{Elements: []OPCUAContentFilterElement{{FilterOperator: OPCUAFilterGreaterThanOrEqual,
					FilterOperands: []OPCUAExtensionObject{uaExt(opcuaLiteralOperandID, literal,
						&OPCUALiteralOperand{Value: OPCUAVariant{Type: OPCUATypeDouble, Value: 1.5}})}}}},
				MaxDataSetsToReturn: 10,
			}},
		{"QueryFirst resp", OPCUAServiceQueryFirstResponse,
			b.cat(dataSets).str("cp").u32(1, 0, 1, 0).null().null().u32(1, 0).null().null().null(),
			func(s *OPCUAService) interface{} { return s.QueryFirstResponse },
			&OPCUAQueryFirstResponse{
				QueryDataSets:     dataSetsWant,
				ContinuationPoint: []byte("cp"),
				ParsingResults:    []OPCUAParsingResult{{DataStatusCodes: []OPCUAStatusCode{0}}},
				FilterResult:      OPCUAContentFilterResult{ElementResults: []OPCUAContentFilterElementResult{{}}},
			}},
		{"QueryNext", OPCUAServiceQueryNextRequest, b.u8(1).str("cp"),
			func(s *OPCUAService) interface{} { return s.QueryNextRequest },
			&OPCUAQueryNextRequest{ReleaseContinuationPoint: true, ContinuationPoint: []byte("cp")}},
		{"QueryNext resp", OPCUAServiceQueryNextResponse, b.cat(dataSets).null(),
			func(s *OPCUAService) interface{} { return s.QueryNextResponse },
			&OPCUAQueryNextResponse{QueryDataSets: dataSetsWant}},

		{"HistoryUpdate", OPCUAServiceHistoryUpdateRequest, history,
			func(s *OPCUAService) interface{} { return s.HistoryUpdateRequest },
			&OPCUAHistoryUpdateRequest{HistoryUpdateDetails: historyWant}},
		{"HistoryUpdate resp", OPCUAServiceHistoryUpdateResponse, b.u32(1, 0, 2, 0, 0x80340000).null().null(),
			func(s *OPCUAService) interface{} { return s.HistoryUpdateResponse },
			&OPCUAHistoryUpdateResponse{Results: []OPCUAHistoryUpdateResult{{OperationResults: []OPCUAStatusCode{0, 0x80340000}}}}},
		{"HistoryRead raw", OPCUAServiceHistoryReadRequest, b.ext(opcuaReadRawDetailsID, raw).u32(2).u8(0).null(),
			func(s *OPCUAService) interface{} { return s.HistoryReadRequest.HistoryReadDetails.Value },
			&OPCUAReadRawModifiedDetails{IsReadModified: true, StartTime: tm, EndTime: tm, NumValuesPerNode: 100}},
		{"HistoryRead data", OPCUAServiceHistoryReadResponse, b.u32(1, 0).null().ext(opcuaHistoryDataID, histData).null(),
			func(s *OPCUAService) interface{} { return s.HistoryReadResponse.Results[0].HistoryData.Value },
			&OPCUAHistoryData{DataValues: []OPCUADataValue{{Mask: 1, Value: OPCUAVariant{Type: OPCUATypeInt32, Value: int32(1)}}}}},

		{"Cancel", OPCUAServiceCancelRequest, b.u32(42),
			func(s *OPCUAService) interface{} { return s.CancelRequest }, &OPCUACancelRequest{RequestHandle: 42}},
		{"Cancel resp", OPCUAServiceCancelResponse, b.u32(3),
			func(s *OPCUAService) interface{} { return s.CancelResponse }, &OPCUACancelResponse{CancelCount: 3}},
		{"SetTriggering", OPCUAServiceSetTriggeringRequest, b.u32(5, 1, 2, 7, 8).null(),
			func(s *OPCUAService) interface{} { return s.SetTriggeringRequest },
			&OPCUASetTriggeringRequest{SubscriptionID: 5, TriggeringItemID: 1, LinksToAdd: []uint32{7, 8}}},
		{"SetTriggering resp", OPCUAServiceSetTriggeringResponse, b.u32(2, 0, 0x80420000).null().u32(1, 0, 1).u8(0),
			func(s *OPCUAService) interface{} { return s.SetTriggeringResponse },
			&OPCUASetTriggeringResponse{AddResults: []OPCUAStatusCode{0, 0x80420000}, RemoveResults: []OPCUAStatusCode{0},
				RemoveDiagnosticInfos: []OPCUADiagnosticInfo{noDiag}}},
		{"TransferSubscriptions", OPCUAServiceTransferSubscriptionsRequest, b.u32(2, 5, 6).u8(1),
			func(s *OPCUAService) interface{} { return s.TransferSubscriptionsRequest },
			&OPCUATransferSubsRequest{SubscriptionIDs: []uint32{5, 6}, SendInitialValues: true}},
		{"TransferSubscriptions resp", OPCUAServiceTransferSubscriptionsResponse, b.u32(2, 0, 2, 11, 12, 0x80280000).null().null(),
			func(s *OPCUAService) interface{} { return s.TransferSubscriptionsResponse },
			&OPCUATransferSubsResponse{Results: []OPCUATransferResult{{AvailableSequenceNumbers: []uint32{11, 12}}, {StatusCode: 0x80280000}}}},

		{"FindServersOnNetwork", OPCUAServiceFindServersOnNetworkRequest, b.u32(0, 10, 1).str("LDS"),
			func(s *OPCUAService) interface{} { return s.FindServersOnNetworkRequest },
			&OPCUAFindOnNetworkRequest{MaxRecordsToReturn: 10, ServerCapabilityFilter: []string{"LDS"}}},
		{"FindServersOnNetwork resp", OPCUAServiceFindServersOnNetworkResponse,
			b.u64(uaTicks).u32(1, 4).str("pump").str("opc.tcp://pump:4840").u32(2).str("DA").str("HD"),
			func(s *OPCUAService) interface{} { return s.FindServersOnNetworkResponse },
			&OPCUAFindOnNetworkResponse{LastCounterResetTime: tm, Servers: []OPCUAServerOnNetwork{
				{RecordID: 4, ServerName: "pump", DiscoveryURL: "opc.tcp://pump:4840", ServerCapabilities: []string{"DA", "HD"}}}}},
		{"RegisterServer", OPCUAServiceRegisterServerRequest, server,
			func(s *OPCUAService) interface{} { return s.RegisterServerRequest },
			&OPCUARegisterServerRequest{Server: serverWant}},
		{"RegisterServer2", OPCUAServiceRegisterServer2Request, b.cat(server).u32(1).ext(opcuaMdnsConfigID, mdns),
			func(s *OPCUAService) interface{} { return s.RegisterServer2Request },
			&OPCUARegisterServer2Request{Server: serverWant, DiscoveryConfiguration: []OPCUAExtensionObject{
				uaExt(opcuaMdnsConfigID, mdns, &OPCUAMdnsDiscoveryConfig{MdnsServerName: "mdns", ServerCapabilities: []string{"LDS"}})}}},
		{"RegisterServer2 resp", OPCUAServiceRegisterServer2Response, b.u32(1, 0).null(),
			func(s *OPCUAService) interface{} { return s.RegisterServer2Response },
			&OPCUAResults{Results: []OPCUAStatusCode{0}}},

		{"monitoring filter", OPCUAServiceModifyMonitoredItemsRequest,
			b.u32(5, 2, 1, 7, 1).f64(100).ext(opcuaDataChangeFilterID, dataChange).u32(10).u8(1),
			func(s *OPCUAService) interface{} {
				return s.ModifyMonitoredItemsRequest.ItemsToModify[0].RequestedParameters.Filter.Value
			},
			&OPCUADataChangeFilter{Trigger: 1, DeadbandType: 1, DeadbandValue: 3}},
		{"reserved variant types", OPCUAServiceReadResponse,
			b.u32(2).u8(opcuaDataValueValue, 26).str("ab").u8(opcuaDataValueValue, opcuaVariantArray|31).u32(2).str("c").null().null(),
			func(s *OPCUAService) interface{} { return s.ReadResponse.Results },
			[]OPCUADataValue{
				{Mask: 1, Value: OPCUAVariant{Type: 26, Value: []byte("ab")}},
				{Mask: 1, Value: OPCUAVariant{Type: 31, IsArray: true, Value: [][]byte{[]byte("c"), nil}}},
			}},
	}
}

// TestOPCUANodeMgmtPcap checks the services and structures of
// opcua-nodemgmt.pcap against tshark.
func TestOPCUANodeMgmtPcap(t *testing.T) {
	const name = "opcua-nodemgmt.pcap"
	en := func(s string) OPCUALocalizedText { return OPCUALocalizedText{Mask: 3, Locale: "en-US", Text: s} }

	add := opcuaPcapService(t, name, 1).AddNodesRequest
	wantAttrs := &OPCUAReferenceTypeAttributes{
		OPCUANodeAttributes: OPCUANodeAttributes{
			DisplayName: en("NewReference"),
			Description: en("References something that might or might not exist"),
		},
		InverseName: en("IsNewlyReferencedBy"),
	}
	if add == nil || len(add.NodesToAdd) != 1 {
		t.Fatalf("AddNodes: %+v", add)
	}
	item := add.NodesToAdd[0]
	if item.ParentNodeID.String() != "i=35" ||
		item.ReferenceTypeID.String() != "i=45" || item.RequestedNewNodeID.String() != "ns=1;i=12133" ||
		item.BrowseName != (OPCUAQualifiedName{Namespace: 1, Name: "NewReference"}) ||
		item.NodeClass != OPCUANodeClassReferenceType || !reflect.DeepEqual(item.NodeAttributes.Value, wantAttrs) {
		t.Errorf("AddNodes item: %+v %+v", item, item.NodeAttributes.Value)
	}
	if res := opcuaPcapService(t, name, 2).AddNodesResponse; res == nil || len(res.Results) != 1 ||
		res.Results[0].StatusCode.String() != "BadNodeIdExists" || res.Results[0].AddedNodeID.String() != "i=0" {
		t.Errorf("AddNodes response: %+v", res)
	}
	objType, ok := opcuaPcapService(t, name, 3).AddNodesRequest.NodesToAdd[0].NodeAttributes.Value.(*OPCUAObjectTypeAttributes)
	if !ok || objType.DisplayName != en("TheNewObjectType") || objType.IsAbstract {
		t.Errorf("ObjectTypeAttributes: %+v", objType)
	}

	reg := opcuaPcapService(t, name, 5).RegisterServer2Request
	urls := []string{"opc.tcp://Maui-16714:51944/", "opc.tcp://Maui-16714:51944/"}
	if reg == nil || reg.Server.ServerURI != "urn:open62541.example.server_register" || reg.Server.ProductURI != "http://open62541.org" ||
		reg.Server.ServerNames[0].Text != "open62541-based OPC UA Application" || reg.Server.ServerType != OPCUAApplicationServer ||
		!reflect.DeepEqual(reg.Server.DiscoveryURLs, urls) || !reg.Server.IsOnline {
		t.Fatalf("RegisterServer2: %+v", reg)
	}
	if mdns, ok := reg.DiscoveryConfiguration[0].Value.(*OPCUAMdnsDiscoveryConfig); !ok || mdns.MdnsServerName != "Sample Server" ||
		mdns.ServerCapabilities != nil {
		t.Errorf("MdnsDiscoveryConfiguration: %+v", reg.DiscoveryConfiguration[0])
	}
	if res := opcuaPcapService(t, name, 6).RegisterServer2Response; res == nil || !reflect.DeepEqual(res.Results, []OPCUAStatusCode{0}) {
		t.Errorf("RegisterServer2 response: %+v", res)
	}

	if req := opcuaPcapService(t, name, 7).FindServersOnNetworkRequest; req == nil || !reflect.DeepEqual(req, &OPCUAFindOnNetworkRequest{}) {
		t.Errorf("FindServersOnNetwork: %+v", req)
	}
	wantNet := &OPCUAFindOnNetworkResponse{
		LastCounterResetTime: time.Date(2021, 9, 15, 14, 1, 44, 863903000, time.UTC),
		Servers: []OPCUAServerOnNetwork{
			{RecordID: 0, ServerName: "LDS-Maui-16714", DiscoveryURL: "opc.tcp://Maui-16714:4840", ServerCapabilities: []string{"LDS"}},
			{RecordID: 1, ServerName: "Sample Server-Maui-16714", DiscoveryURL: "opc.tcp://Maui-16714:51944", ServerCapabilities: []string{"NA"}},
		},
	}
	if res := opcuaPcapService(t, name, 8).FindServersOnNetworkResponse; !reflect.DeepEqual(res, wantNet) {
		t.Errorf("FindServersOnNetwork response: %+v", res)
	}

	// The three monitoring filters, in the order of the items.
	items := opcuaPcapService(t, name, 9).CreateMonitoredItemsRequest.ItemsToCreate
	if len(items) != 3 {
		t.Fatalf("%d monitored items", len(items))
	}
	if f, ok := items[0].RequestedParameters.Filter.Value.(*OPCUADataChangeFilter); !ok ||
		*f != (OPCUADataChangeFilter{Trigger: 1, DeadbandType: 1, DeadbandValue: 3}) {
		t.Errorf("DataChangeFilter: %+v", items[0].RequestedParameters.Filter)
	}
	ev, ok := items[1].RequestedParameters.Filter.Value.(*OPCUAEventFilter)
	wantSelect := []OPCUASimpleAttributeOperand{{
		TypeDefinitionID: n4(0, 2041),
		BrowsePath:       []OPCUAQualifiedName{{Name: "Message"}},
		AttributeID:      OPCUAAttributeEventNotifier,
	}}
	if !ok || !reflect.DeepEqual(ev.SelectClauses, wantSelect) || len(ev.WhereClause.Elements) != 1 {
		t.Fatalf("EventFilter: %+v", items[1].RequestedParameters.Filter)
	}
	where := ev.WhereClause.Elements[0]
	lit, _ := where.FilterOperands[0].Value.(*OPCUALiteralOperand)
	attr, _ := where.FilterOperands[1].Value.(*OPCUAAttributeOperand)
	wantAttr := &OPCUAAttributeOperand{
		Alias: "I hope this works",
		BrowsePath: []OPCUARelativePathElement{
			{IsInverse: true, IncludeSubtypes: true, TargetName: OPCUAQualifiedName{Name: "Message"}}},
		AttributeID: OPCUAAttributeValue,
		IndexRange:  "7-10",
	}
	if where.FilterOperator != OPCUAFilterEquals || lit == nil || lit.Value.Value != "What is happening?" || !reflect.DeepEqual(attr, wantAttr) {
		t.Errorf("where clause: %+v %+v %+v", where, lit, attr)
	}
	config := OPCUAAggregateConfiguration{UseServerCapabilitiesDefaults: true, TreatUncertainAsBad: true, PercentDataBad: 50, PercentDataGood: 50}
	wantAgg := &OPCUAAggregateFilter{
		StartTime:              time.Date(2023, 1, 11, 17, 15, 17, 585621000, time.UTC),
		AggregateType:          nsString(1, "IHopeIwork"),
		ProcessingInterval:     3.5,
		AggregateConfiguration: config,
	}
	if agg := items[2].RequestedParameters.Filter.Value; !reflect.DeepEqual(agg, wantAgg) {
		t.Errorf("AggregateFilter: %+v", agg)
	}

	results := opcuaPcapService(t, name, 10).CreateMonitoredItemsResponse.Results
	if len(results) != 3 || results[0].FilterResult.Value != nil {
		t.Fatalf("monitored item results: %+v", results)
	}
	evRes, ok := results[1].FilterResult.Value.(*OPCUAEventFilterResult)
	if !ok || !reflect.DeepEqual(evRes.SelectClauseResults, []OPCUAStatusCode{0x80630000}) ||
		evRes.SelectClauseDiagnosticInfos[0].AdditionalInfo != "INNER ADDITION INFO 1" ||
		evRes.SelectClauseDiagnosticInfos[0].Inner.Inner.InnerStatusCode.String() != "BadOutOfMemory" ||
		len(evRes.WhereClauseResult.ElementResults) != 1 ||
		!reflect.DeepEqual(evRes.WhereClauseResult.ElementResults[0].OperandStatusCodes, []OPCUAStatusCode{0, 0}) ||
		evRes.WhereClauseResult.ElementResults[0].OperandDiagnosticInfos[0].AdditionalInfo != "ADDITIONAL INFO" {
		t.Errorf("EventFilterResult: %+v", results[1].FilterResult)
	}
	wantAggRes := &OPCUAAggregateFilterResult{RevisedProcessingInterval: 3.5, RevisedAggregateConfiguration: config}
	if got := results[2].FilterResult.Value; !reflect.DeepEqual(got, wantAggRes) {
		t.Errorf("AggregateFilterResult: %+v", got)
	}

	// Structures as Variant values.
	token := opcuaPcapService(t, name, 11).ReadResponse.Results[0].Value.Value.(OPCUAExtensionObject)
	wantToken := &OPCUAUserIdentityToken{TokenType: OPCUAUserTokenUserName, PolicyID: "MyPolicyId", UserName: "MyUserName",
		EncryptionAlgorithm: "MyEncryptionAlgorithm"}
	if !reflect.DeepEqual(token.Value, wantToken) {
		t.Errorf("identity token value: %+v", token.Value)
	}
	details := opcuaPcapService(t, name, 12).ReadResponse.Results[0].Value.Value.(OPCUAExtensionObject)
	if !reflect.DeepEqual(details.Value, &OPCUAHistoryUpdateDetails{NodeID: nsString(1, "History Update Details String Node Id")}) {
		t.Errorf("HistoryUpdateDetails value: %+v", details.Value)
	}
}

// uaExtRead is a Read response whose one value is the ExtensionObject
// of v.
func uaExtRead(v uaExtVector) []byte {
	return uaBuilder{}.u32(1).u8(opcuaDataValueValue, uint8(OPCUATypeExtensionObject)).ext(v.id, v.body).null()
}

// uaVectors returns every hand-built service body: the base ones, the
// services added later and each known structure as a Variant value.
func uaVectors() []uaVector {
	out := append(uaBaseVectors(), uaMgmtVectors()...)
	for _, v := range append(uaExtVectors(), uaNodeClassVectors()...) {
		out = append(out, uaVector{"ExtensionObject " + n4(0, uint32(v.id)).String(), OPCUAServiceReadResponse, uaExtRead(v),
			func(s *OPCUAService) interface{} {
				return s.ReadResponse.Results[0].Value.Value.(OPCUAExtensionObject).Value
			}, v.want})
	}
	return out
}

// TestOPCUAExtBodyCut cuts the body of every known structure at every
// offset: a short body stays encoded and breaks nothing around it.
func TestOPCUAExtBodyCut(t *testing.T) {
	for _, v := range append(uaExtVectors(), uaNodeClassVectors()...) {
		for i := 0; i < len(v.body); i++ {
			cut := v
			cut.body = v.body[:i]
			s := decodeUAService(t, uaServiceMsg(OPCUAServiceReadResponse, uaExtRead(cut)))
			if s.ReadResponse == nil {
				t.Fatalf("i=%d cut at %d: Read not decoded", v.id, i)
			}
			e := s.ReadResponse.Results[0].Value.Value.(OPCUAExtensionObject)
			if e.Value != nil || !bytes.Equal(e.Body, cut.body) {
				t.Errorf("i=%d cut at %d: %+v", v.id, i, e)
			}
		}

		// A byte too many is not this structure either.
		long := v
		long.body = append(append([]byte{}, v.body...), 0)
		s := decodeUAService(t, uaServiceMsg(OPCUAServiceReadResponse, uaExtRead(long)))
		if e := s.ReadResponse.Results[0].Value.Value.(OPCUAExtensionObject); e.Value != nil {
			t.Errorf("i=%d with a trailing byte decoded: %+v", v.id, e.Value)
		}
	}
}

// uaNestedExt wraps levels LiteralOperands around an Int32: each is a
// Variant holding the next as an ExtensionObject.
func uaNestedExt(levels int) []byte {
	body := uaBuilder{}.u8(uint8(OPCUATypeInt32)).u32(42)
	for i := 0; i < levels; i++ {
		body = uaBuilder{}.u8(uint8(OPCUATypeExtensionObject)).ext(opcuaLiteralOperandID, body)
	}
	return body
}

func TestOPCUAExtObjects(t *testing.T) {
	// Unknown types, XML bodies and other namespaces stay encoded.
	b := uaBuilder{}
	for name, ext := range map[string][]byte{
		"unknown id":   b.ext(999, b.u32(1)),
		"xml body":     b.node(0, opcuaRangeID).u8(2).str("<Range/>"),
		"namespace 2":  b.node(2, opcuaRangeID).u8(1).str(string(b.f64(0).f64(1))),
		"no body":      b.node(0, opcuaRangeID).u8(0),
		"string id":    b.u8(0x03).u16(0).str("Range").u8(1).str(string(b.f64(0).f64(1))),
		"count lie":    b.ext(opcuaEventFilterID, b.u32(0x7FFFFFFF).null()),
		"negative len": b.ext(opcuaHistoryDataID, b.u32(0xFFFFFFFE)),
	} {
		params := b.u32(1).u8(opcuaDataValueValue, uint8(OPCUATypeExtensionObject)).cat(ext).null()
		s := decodeUAService(t, uaServiceMsg(OPCUAServiceReadResponse, params))
		if s.ReadResponse == nil {
			t.Errorf("%s: Read not decoded", name)
			continue
		}
		if e := s.ReadResponse.Results[0].Value.Value.(OPCUAExtensionObject); e.Value != nil {
			t.Errorf("%s: decoded to %+v", name, e.Value)
		}
	}

	// Bodies nest opcuaMaxExtDepth deep; the next one stays encoded.
	const levels = opcuaMaxExtDepth + 1
	params := b.u32(1).u8(opcuaDataValueValue).cat(uaNestedExt(levels)).null()
	s := decodeUAService(t, uaServiceMsg(OPCUAServiceReadResponse, params))
	v := s.ReadResponse.Results[0].Value
	for i := 0; i < opcuaMaxExtDepth; i++ {
		lit, ok := v.Value.(OPCUAExtensionObject).Value.(*OPCUALiteralOperand)
		if !ok {
			t.Fatalf("level %d not decoded: %+v", i, v)
		}
		v = lit.Value
	}
	if e := v.Value.(OPCUAExtensionObject); e.Value != nil || !bytes.Equal(e.Body, uaNestedExt(0)) {
		t.Errorf("level %d decoded: %+v", opcuaMaxExtDepth, e)
	}

	// A notification and an identity token are the Value of their object.
	for _, v := range uaBaseVectors() {
		s := decodeUAService(t, uaServiceMsg(v.id, v.params))
		switch v.name {
		case "Republish resp":
			n := s.RepublishResponse.NotificationMessage.NotificationData[0]
			if n.Raw.Value != n.StatusChange || n.StatusChange == nil {
				t.Errorf("notification value %+v", n)
			}
		case "X509 token":
			req := s.ActivateSessionRequest
			if req.UserIdentityToken.Value != req.IdentityToken || req.IdentityToken == nil {
				t.Errorf("token value %+v", req)
			}
		}
	}
}

// uaChunk frames body as one chunk of request id on channel 9.
func uaChunk(typ string, chunk OPCUAChunkType, id uint32, seq uint32, body []byte) *OPCUA {
	b := uaBuilder{}.u32(9)
	if typ == "OPN" {
		b = b.str(OPCUASecurityPolicyNone).null().null()
	} else {
		b = b.u32(14)
	}
	ua := &OPCUA{}
	if err := ua.DecodeFromBytes(uaMessage(typ, chunk, b.u32(seq, id).cat(body)), gopacket.NilDecodeFeedback); err != nil {
		panic(err)
	}
	return ua
}

// uaSplit cuts body into n nearly equal parts.
func uaSplit(body []byte, n int) [][]byte {
	var out [][]byte
	size := (len(body) + n - 1) / n
	for len(body) > size {
		out = append(out, body[:size])
		body = body[size:]
	}
	return append(out, body)
}

func TestOPCUAChunkAssembler(t *testing.T) {
	// Every vector, split in three, joins into the service it is whole.
	for _, v := range uaVectors() {
		body := uaServiceMsg(v.id, v.params)[opcuaHeaderLen+16:]
		parts := uaSplit(body, 3)
		var a OPCUAChunkAssembler
		var got *OPCUA
		for i, part := range parts {
			chunk := OPCUAChunkIntermediate
			if i == len(parts)-1 {
				chunk = OPCUAChunkFinal
			}
			msg, err := a.Add(uaChunk("MSG", chunk, 7, uint32(50+i), part))
			if err != nil || (msg != nil) != (chunk == OPCUAChunkFinal) {
				t.Fatalf("%s chunk %d: %v %v", v.name, i, msg, err)
			}
			got = msg
		}
		if got.Service == nil || !bytes.Equal(got.Body, body) || got.SequenceNumber != uint32(50+len(parts)-1) || a.Pending() != 0 {
			t.Errorf("%s: joined %+v", v.name, got)
			continue
		}
		if res := v.got(got.Service); !reflect.DeepEqual(res, v.want) {
			t.Errorf("%s: joined into %+v, want %+v", v.name, res, v.want)
		}
	}

	read := uaServiceMsg(OPCUAServiceReadResponse, uaBuilder{}.u32(1).u8(opcuaDataValueValue, uint8(OPCUATypeInt32)).u32(5).null())
	body := read[opcuaHeaderLen+16:]
	half := len(body) / 2

	// Two requests interleave; unchunked messages and HEL pass through.
	var a OPCUAChunkAssembler
	hello := &OPCUA{MessageType: OPCUAMessageHello, ChunkType: OPCUAChunkFinal}
	whole := uaChunk("MSG", OPCUAChunkFinal, 3, 1, body)
	steps := []struct {
		in   *OPCUA
		same bool
		join bool
	}{
		{uaChunk("MSG", OPCUAChunkIntermediate, 1, 2, body[:half]), false, false},
		{uaChunk("MSG", OPCUAChunkIntermediate, 2, 3, body[:half]), false, false},
		{hello, true, false},
		{whole, true, false},
		{uaChunk("MSG", OPCUAChunkFinal, 2, 4, body[half:]), false, true},
		{uaChunk("MSG", OPCUAChunkFinal, 1, 5, body[half:]), false, true},
	}
	for i, st := range steps {
		msg, err := a.Add(st.in)
		switch {
		case err != nil:
			t.Fatalf("step %d: %v", i, err)
		case st.same && msg != st.in:
			t.Errorf("step %d: not passed through", i)
		case st.join && (msg == nil || msg == st.in || msg.Service == nil || msg.Service.ReadResponse == nil || msg.RequestID != st.in.RequestID):
			t.Errorf("step %d: not joined: %+v", i, msg)
		case !st.same && !st.join && msg != nil:
			t.Errorf("step %d: early message", i)
		}
	}
	if a.Pending() != 0 {
		t.Errorf("%d pending", a.Pending())
	}
	if msg, err := a.Add(nil); msg != nil || err != nil {
		t.Errorf("nil layer: %v %v", msg, err)
	}

	// An abort drops the chunks; the final chunk after it stands alone.
	a.Add(uaChunk("MSG", OPCUAChunkIntermediate, 1, 2, body[:half]))
	abort := uaChunk("MSG", OPCUAChunkAbort, 1, 3, uaBuilder{}.u32(0x80B80000).str("too big"))
	if msg, err := a.Add(abort); msg != abort || err != nil || a.Pending() != 0 || msg.Error.Reason != "too big" {
		t.Errorf("abort: %+v %v", msg, err)
	}
	tail := uaChunk("MSG", OPCUAChunkFinal, 1, 4, body[half:])
	if msg, _ := a.Add(tail); msg != tail {
		t.Errorf("final after abort joined")
	}

	// An OPN joins by its own key and decodes under policy None.
	opn := uaBuilder{}.node(0, uint16(OPCUAServiceOpenSecureChannelRequest)).cat(uaRequestHeader()).u32(0, 0, 1).null().u32(3600000)
	a.Add(uaChunk("OPN", OPCUAChunkIntermediate, 1, 1, opn[:10]))
	a.Add(uaChunk("MSG", OPCUAChunkIntermediate, 1, 2, body[:half]))
	if msg, _ := a.Add(uaChunk("OPN", OPCUAChunkFinal, 1, 3, opn[10:])); msg == nil || msg.Service == nil ||
		msg.Service.OpenSecureChannelRequest == nil || msg.Service.OpenSecureChannelRequest.RequestedLifetime != 3600000 {
		t.Errorf("OPN: %+v", msg)
	}
	a.Add(abort)

	// An unknown chunk type is refused.
	bad := uaChunk("MSG", OPCUAChunkFinal, 1, 1, body)
	bad.ChunkType = 'X'
	if _, err := a.Add(bad); err != ErrOPCUAMalformed {
		t.Errorf("chunk type X: %v", err)
	}
}

func TestOPCUAChunkLimits(t *testing.T) {
	part := make([]byte, 100)

	// The chunk that passes the limit, and the rest of its message, fail.
	a := OPCUAChunkAssembler{MaxMessageSize: 250}
	for i, want := range []error{nil, nil, ErrOPCUAMessageTooLarge, ErrOPCUAMessageTooLarge} {
		if msg, err := a.Add(uaChunk("MSG", OPCUAChunkIntermediate, 1, uint32(i), part)); msg != nil || err != want {
			t.Errorf("chunk %d: %v %v", i, msg, err)
		}
	}
	if msg, err := a.Add(uaChunk("MSG", OPCUAChunkFinal, 1, 9, part)); msg != nil || err != ErrOPCUAMessageTooLarge || a.Pending() != 0 {
		t.Errorf("final of oversized message: %v %v", msg, err)
	}

	// A message of exactly the limit joins.
	a = OPCUAChunkAssembler{MaxMessageSize: 200}
	a.Add(uaChunk("MSG", OPCUAChunkIntermediate, 1, 1, part))
	if msg, err := a.Add(uaChunk("MSG", OPCUAChunkFinal, 1, 2, part)); msg == nil || err != nil || len(msg.Body) != 200 {
		t.Errorf("at the limit: %v %v", msg, err)
	}

	// The default limit holds without configuration.
	a = OPCUAChunkAssembler{}
	big := make([]byte, 1<<20)
	var err error
	for i := 0; i <= OPCUADefaultMaxMessageSize>>20 && err == nil; i++ {
		_, err = a.Add(uaChunk("MSG", OPCUAChunkIntermediate, 1, uint32(i), big))
	}
	if err != ErrOPCUAMessageTooLarge {
		t.Errorf("default limit: %v", err)
	}

	// One message more than MaxPending evicts the oldest.
	a = OPCUAChunkAssembler{MaxPending: 3}
	for id := uint32(1); id <= 4; id++ {
		a.Add(uaChunk("MSG", OPCUAChunkIntermediate, id, id, part))
	}
	if a.Pending() != 3 {
		t.Errorf("%d pending, want 3", a.Pending())
	}
	first := uaChunk("MSG", OPCUAChunkFinal, 1, 9, part)
	if msg, _ := a.Add(first); msg != first {
		t.Errorf("evicted message joined")
	}
	if msg, _ := a.Add(uaChunk("MSG", OPCUAChunkFinal, 2, 10, part)); msg == nil || len(msg.Body) != 200 {
		t.Errorf("kept message: %+v", msg)
	}

	// On a signing channel each chunk loses its signature.
	read := uaServiceMsg(OPCUAServiceReadResponse, uaBuilder{}.u32(1).u8(opcuaDataValueValue, uint8(OPCUATypeInt32)).u32(5).null())
	body := read[opcuaHeaderLen+16:]
	sig := bytes.Repeat([]byte{0xEE}, 32)
	a = OPCUAChunkAssembler{SignatureSize: len(sig)}
	a.Add(uaChunk("MSG", OPCUAChunkIntermediate, 1, 1, uaBuilder(body[:20]).cat(sig)))
	msg, err := a.Add(uaChunk("MSG", OPCUAChunkFinal, 1, 2, uaBuilder(body[20:]).cat(sig)))
	if err != nil || msg == nil || !bytes.Equal(msg.Body, body) || msg.Service.ReadResponse == nil {
		t.Errorf("signed chunks: %+v %v", msg, err)
	}
	a.Add(uaChunk("MSG", OPCUAChunkIntermediate, 1, 3, uaBuilder(body[:20]).cat(sig)))
	if _, err := a.Add(uaChunk("MSG", OPCUAChunkFinal, 1, 4, sig[:8])); err != ErrOPCUAMalformed {
		t.Errorf("chunk shorter than its signature: %v", err)
	}
}

// TestOPCUAProbeAlloc checks that a list whose count lies, or whose
// message fails later, is refused before anything is allocated for it,
// and that the lists of the newer services cost no more than a
// DataValue does.
func TestOPCUAProbeAlloc(t *testing.T) {
	const count = 60000
	const maxRefused = 1
	const maxPerByte = 160
	b := uaBuilder{}

	refused := map[string][]byte{
		// Every byte could be an empty DataValue, the first is not one.
		"first element bad": uaServiceMsg(OPCUAServiceReadResponse, b.u32(count).u8(bytes.Repeat([]byte{0xFF}, count)...)),
		// All the DataValues are there, the array after them is not.
		"fails after the list": uaServiceMsg(OPCUAServiceReadResponse, b.u32(count).u8(make([]byte, count)...)),
		"ExtensionObjects": uaServiceMsg(OPCUAServiceHistoryUpdateRequest,
			b.u32(count/3).u8(bytes.Repeat([]byte{0, 0, 0}, count/3-1)...)),
		"AddNodes": uaServiceMsg(OPCUAServiceAddNodesRequest, b.u32(count/opcuaMinAddNodesLen).u8(bytes.Repeat([]byte{0xFF}, count)...)),
		"strings":  uaServiceMsg(OPCUAServiceFindServersOnNetworkRequest, b.u32(0, 0, count/4).u8(make([]byte, count-4)...)),
	}
	for name, msg := range refused {
		body := msg[opcuaHeaderLen+16:]
		var s *OPCUAService
		got := allocPerByte(len(body), func() { s = decodeOPCUAService(body) })
		if s == nil || opcuaTyped(s) {
			t.Errorf("%s: decoded %+v", name, s)
		}
		if got > maxRefused {
			t.Errorf("%s: a refused body allocates %.2f bytes per input byte, want <= %d", name, got, maxRefused)
		}
	}

	// A known structure whose count lies is probed, not decoded.
	lie := b.ext(opcuaHistoryDataID, b.u32(count).u8(bytes.Repeat([]byte{0xFF}, count)...))
	got := allocPerByte(len(lie), func() {
		r := &opcuaReader{b: lie}
		_ = r.extensionObject()
	})
	if got > maxRefused {
		t.Errorf("refused ExtensionObject allocates %.2f bytes per input byte", got)
	}

	// Lists that are really there cost their structs, once.
	real := map[string][]byte{
		"HistoryUpdate details": uaServiceMsg(OPCUAServiceHistoryUpdateRequest, b.u32(count/3).u8(make([]byte, count)...)),
		"AddNodes results":      uaServiceMsg(OPCUAServiceAddNodesResponse, b.u32(count/6).u8(make([]byte, count)...).null()),
		"DeleteNodes":           uaServiceMsg(OPCUAServiceDeleteNodesRequest, b.u32(count/3).u8(make([]byte, count)...)),
		"HistoryData": uaServiceMsg(OPCUAServiceHistoryReadResponse,
			b.u32(1, 0).null().ext(opcuaHistoryDataID, b.u32(count).u8(make([]byte, count)...)).null()),
	}
	for name, msg := range real {
		body := msg[opcuaHeaderLen+16:]
		var s *OPCUAService
		got := allocPerByte(len(body), func() { s = decodeOPCUAService(body) })
		t.Logf("OPC UA %s: %.0f bytes per input byte", name, got)
		if s == nil || !opcuaTyped(s) {
			t.Errorf("%s: not decoded", name)
		}
		if got > maxPerByte {
			t.Errorf("%s allocates %.0f bytes per input byte, want <= %d", name, got, maxPerByte)
		}
	}
}
