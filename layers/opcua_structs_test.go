// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// No capture holds the structures of opcua_structs.go: every vector is
// built by hand after Opc.Ua.Types.bsd. Each scalar has a value of its
// own, numbers from 1100 up and strings "tokN", so that tshark 4.7 shows
// them in the order they are sent; the vectors were checked against it
// that way. tshark does not know SortRuleElement,
// ReadEventDetailsSorted, ReadAnnotationDataDetails,
// HistoryModifiedEvent and the 1.04 layout of the node classes.

// uaNone is the ExtensionObject without type or body.
func uaNone() []byte { return uaBuilder{}.node(0, 0).u8(0) }

// uaNodeBodies returns the common part of a node class in the 1.04 and
// the 1.03 layout, and what each decodes to.
func uaNodeBodies() (cur, old uaBuilder, curWant, oldWant OPCUANode) {
	b := uaBuilder{}
	ref := b.node(0, 1101).u8(1).node(0, 1102)
	head := b.node(0, 1103).u32(1).u16(0).str("tok1").text("tok2").text("tok3").u32(1104, 1105)

	oldWant = OPCUANode{
		NodeID:        n4(0, 1103),
		NodeClass:     OPCUANodeClassObject,
		BrowseName:    OPCUAQualifiedName{Name: "tok1"},
		DisplayName:   uaText("tok2"),
		Description:   uaText("tok3"),
		WriteMask:     1104,
		UserWriteMask: 1105,
		References:    []OPCUAReferenceNode{{ReferenceTypeID: n4(0, 1101), IsInverse: true, TargetID: n4(0, 1102)}},
		Legacy:        true,
	}
	curWant = oldWant
	curWant.Legacy = false
	curWant.RolePermissions = []OPCUARolePermission{{RoleID: n4(0, 1106), Permissions: 1107}}
	curWant.UserRolePermissions = []OPCUARolePermission{{RoleID: n4(0, 1108), Permissions: 1109}}
	curWant.AccessRestrictions = 1110

	cur = b.cat(head).u32(1).node(0, 1106).u32(1107).u32(1).node(0, 1108).u32(1109).u16(1110).u32(1).cat(ref)
	old = b.cat(head).u32(1).cat(ref)
	return cur, old, curWant, oldWant
}

// uaNodeVectors is one body per node class and layout.
func uaNodeVectors() []uaExtVector {
	b := uaBuilder{}
	cur, old, nw, ow := uaNodeBodies()
	i32 := OPCUAVariant{Type: OPCUATypeInt32, Value: int32(1111)}
	variable := b.u8(uint8(OPCUATypeInt32)).u32(1111).node(0, 6).u32(math.MaxUint32).null().u8(1, 3).f64(1112.5).u8(1)
	varType := b.u8(uint8(OPCUATypeString)).str("tok4").node(0, 12).u32(1, 1, 1114).u8(1)
	str := OPCUAVariant{Type: OPCUATypeString, Value: "tok4"}

	return []uaExtVector{
		{opcuaReferenceNodeID, b.node(0, 1101).u8(1).node(0, 1102),
			&OPCUAReferenceNode{ReferenceTypeID: n4(0, 1101), IsInverse: true, TargetID: n4(0, 1102)}},
		{opcuaNodeID, cur, &nw},
		{opcuaNodeID, old, &ow},
		{opcuaInstanceNodeID, cur, &nw},
		{opcuaTypeNodeID, old, &ow},
		{opcuaObjectNodeID, cur.cat().u8(4), &OPCUAObjectNode{OPCUANode: nw, EventNotifier: 4}},
		{opcuaObjectNodeID, old.cat().u8(4), &OPCUAObjectNode{OPCUANode: ow, EventNotifier: 4}},
		{opcuaObjectTypeNodeID, cur.cat().u8(1), &OPCUAObjectTypeNode{OPCUANode: nw, IsAbstract: true}},
		{opcuaObjectTypeNodeID, old.cat().u8(1), &OPCUAObjectTypeNode{OPCUANode: ow, IsAbstract: true}},
		{opcuaVariableNodeID, cur.cat(variable).u32(1113), &OPCUAVariableNode{OPCUANode: nw, Value: i32, DataType: n4(0, 6),
			ValueRank: -1, AccessLevel: 1, UserAccessLevel: 3, MinimumSamplingInterval: 1112.5, Historizing: true, AccessLevelEx: 1113}},
		{opcuaVariableNodeID, old.cat(variable), &OPCUAVariableNode{OPCUANode: ow, Value: i32, DataType: n4(0, 6),
			ValueRank: -1, AccessLevel: 1, UserAccessLevel: 3, MinimumSamplingInterval: 1112.5, Historizing: true}},
		{opcuaVariableTypeNodeID, cur.cat(varType), &OPCUAVariableTypeNode{OPCUANode: nw, Value: str, DataType: n4(0, 12),
			ValueRank: 1, ArrayDimensions: []uint32{1114}, IsAbstract: true}},
		{opcuaVariableTypeNodeID, old.cat(varType), &OPCUAVariableTypeNode{OPCUANode: ow, Value: str, DataType: n4(0, 12),
			ValueRank: 1, ArrayDimensions: []uint32{1114}, IsAbstract: true}},
		{opcuaReferenceTypeNodeID, cur.cat().u8(0, 1).text("tok5"),
			&OPCUAReferenceTypeNode{OPCUANode: nw, Symmetric: true, InverseName: uaText("tok5")}},
		{opcuaReferenceTypeNodeID, old.cat().u8(0, 1).text("tok5"),
			&OPCUAReferenceTypeNode{OPCUANode: ow, Symmetric: true, InverseName: uaText("tok5")}},
		{opcuaMethodNodeID, cur.cat().u8(1, 0), &OPCUAMethodNode{OPCUANode: nw, Executable: true}},
		{opcuaMethodNodeID, old.cat().u8(1, 0), &OPCUAMethodNode{OPCUANode: ow, Executable: true}},
		{opcuaViewNodeID, cur.cat().u8(1, 2), &OPCUAViewNode{OPCUANode: nw, ContainsNoLoops: true, EventNotifier: 2}},
		{opcuaViewNodeID, old.cat().u8(1, 2), &OPCUAViewNode{OPCUANode: ow, ContainsNoLoops: true, EventNotifier: 2}},
		{opcuaDataTypeNodeID, cur.cat().u8(1).cat(uaNone()),
			&OPCUADataTypeNode{OPCUANode: nw, IsAbstract: true, DataTypeDefinition: OPCUAExtensionObject{TypeID: n4(0, 0)}}},
		{opcuaDataTypeNodeID, old.cat().u8(1), &OPCUADataTypeNode{OPCUANode: ow, IsAbstract: true}},
	}
}

// uaDiagVectors is one body per diagnostics and profile structure.
func uaDiagVectors() []uaExtVector {
	b := uaBuilder{}
	tm := uaTime()
	noDiag := OPCUADiagnosticInfo{SymbolicID: -1, NamespaceURI: -1, Locale: -1, LocalizedText: -1}

	app := b.str("tok20").str("tok21").text("tok22").u32(1).str("tok23").str("tok24").u32(1).str("tok25")
	appWant := OPCUAApplicationDescription{ApplicationURI: "tok20", ProductURI: "tok21", ApplicationName: uaText("tok22"),
		ApplicationType: OPCUAApplicationClient, GatewayServerURI: "tok23", DiscoveryProfileURI: "tok24", DiscoveryURLs: []string{"tok25"}}

	session := b.node(0, 1200).str("tok26").cat(app).str("tok27").str("tok28").u32(1).str("tok29").
		f64(1201.5).u32(1202).u64(uaTicks).u64(uaTicks).u32(1203, 1204, 1205, 1206, 1207, 1208)
	sessionWant := OPCUASessionDiagnostics{
		SessionID: n4(0, 1200), SessionName: "tok26", ClientDescription: appWant, ServerURI: "tok27", EndpointURL: "tok28",
		LocaleIDs: []string{"tok29"}, ActualSessionTimeout: 1201.5, MaxResponseMessageSize: 1202,
		ClientConnectionTime: tm, ClientLastContactTime: tm, CurrentSubscriptionsCount: 1203,
		CurrentMonitoredItemsCount: 1204, CurrentPublishRequestsInQueue: 1205,
		TotalRequestCount: OPCUAServiceCounter{TotalCount: 1206, ErrorCount: 1207}, UnauthorizedRequestCount: 1208,
	}
	counters := reflect.ValueOf(&sessionWant).Elem()
	for i, next := counters.NumField()-28, uint32(1300); i < counters.NumField(); i, next = i+1, next+2 {
		session = session.u32(next, next+1)
		counters.Field(i).Set(reflect.ValueOf(OPCUAServiceCounter{TotalCount: next, ErrorCount: next + 1}))
	}

	sub := b.node(0, 1400).u32(1401).u8(7).f64(1402.5).u32(1403, 1404, 1405).u8(1)
	subWant := OPCUASubscriptionDiagnostics{SessionID: n4(0, 1400), SubscriptionID: 1401, Priority: 7, PublishingInterval: 1402.5,
		MaxKeepAliveCount: 1403, MaxLifetimeCount: 1404, MaxNotificationsPerPublish: 1405, PublishingEnabled: true}
	fields := reflect.ValueOf(&subWant).Elem()
	for i, next := fields.NumField()-23, uint32(1410); i < fields.NumField(); i, next = i+1, next+1 {
		sub = sub.u32(next)
		fields.Field(i).SetUint(uint64(next))
	}

	arg := b.str("tok30").node(0, 1500).u32(math.MaxUint32).null().text("tok31")
	argWant := OPCUAArgument{Name: "tok30", DataType: n4(0, 1500), ValueRank: -1, Description: uaText("tok31")}
	profile := b.str("tok7").str("tok8").str("tok9").u64(uaTicks).u32(3).u32(1).str("tok10")
	profileWant := OPCUASupportedProfile{OrganizationURI: "tok7", ProfileID: "tok8", ComplianceTool: "tok9",
		ComplianceDate: tm, ComplianceLevel: OPCUAComplianceCertified, UnsupportedUnitIDs: []string{"tok10"}}

	return []uaExtVector{
		{opcuaSessionDiagID, session, &sessionWant},
		{opcuaSessionSecurityDiagID, b.node(0, 1600).str("tok32").u32(1).str("tok33").str("tok34").str("tok35").str("tok36").u32(3).str("tok37").str("\x30\x00"),
			&OPCUASessionSecurityDiagnostics{SessionID: n4(0, 1600), ClientUserIDOfSession: "tok32", ClientUserIDHistory: []string{"tok33"},
				AuthenticationMechanism: "tok34", Encoding: "tok35", TransportProtocol: "tok36",
				SecurityMode: OPCUASecurityModeSignAndEncrypt, SecurityPolicyURI: "tok37", ClientCertificate: []byte{0x30, 0x00}}},
		{opcuaSubscriptionDiagID, sub, &subWant},
		{opcuaProgramDiagID, b.node(0, 1700).str("tok38").u64(uaTicks).u64(uaTicks).str("tok39").node(0, 1701).
			u32(1).cat(arg).u32(1).cat(arg).u64(uaTicks).u32(1702).u8(0),
			&OPCUAProgramDiagnostic{CreateSessionID: n4(0, 1700), CreateClientName: "tok38", InvocationCreationTime: tm,
				LastTransitionTime: tm, LastMethodCall: "tok39", LastMethodSessionID: n4(0, 1701),
				LastMethodInputArguments: []OPCUAArgument{argWant}, LastMethodOutputArguments: []OPCUAArgument{argWant},
				LastMethodCallTime: tm, LastMethodReturnStatus: OPCUAStatusResult{StatusCode: 1702, DiagnosticInfo: noDiag}}},
		{opcuaNetworkGroupID, b.str("tok40").u32(1).u32(1).str("tok41"),
			&OPCUANetworkGroup{ServerURI: "tok40", NetworkPaths: []OPCUAEndpointURLList{{EndpointURLList: []string{"tok41"}}}}},
		{opcuaEndpointConfigID, b.u32(1115).u8(1).u32(1116, 1117, 1118, 1119, 1120, 1121, 1122),
			&OPCUAEndpointConfiguration{OperationTimeout: 1115, UseBinaryEncoding: true, MaxStringLength: 1116,
				MaxByteStringLength: 1117, MaxArrayLength: 1118, MaxMessageSize: 1119, MaxBufferSize: 1120,
				ChannelLifetime: 1121, SecurityTokenLifetime: 1122}},
		{opcuaSupportedProfileID, profile, &profileWant},
		{opcuaSoftwareCertificateID, b.str("tok11").str("tok12").str("tok13").str("\x01\x02").str("tok14").str("tok15").
			u64(uaTicks).str("tok16").u64(uaTicks).u32(1).cat(profile),
			&OPCUASoftwareCertificate{ProductName: "tok11", ProductURI: "tok12", VendorName: "tok13",
				VendorProductCertificate: []byte{1, 2}, SoftwareVersion: "tok14", BuildNumber: "tok15", BuildDate: tm,
				IssuedBy: "tok16", IssueDate: tm, SupportedProfiles: []OPCUASupportedProfile{profileWant}}},
	}
}

// uaHeaderVectors is one body per header, token and history structure.
func uaHeaderVectors() []uaExtVector {
	b := uaBuilder{}
	tm := uaTime()
	noDiag := OPCUADiagnosticInfo{SymbolicID: -1, NamespaceURI: -1, Locale: -1, LocalizedText: -1}
	i32 := OPCUAVariant{Type: OPCUATypeInt32, Value: int32(1801)}
	variant := b.u8(uint8(OPCUATypeInt32)).u32(1801)

	simple := b.node(0, 2041).u32(1).u16(0).str("tok50").u32(13).null()
	simpleWant := OPCUASimpleAttributeOperand{TypeDefinitionID: n4(0, 2041), BrowsePath: []OPCUAQualifiedName{{Name: "tok50"}},
		AttributeID: OPCUAAttributeValue}
	sortRule := b.u32(1).cat(simple)
	sortWant := OPCUASortRuleElement{SortOrder: OPCUASortDescending, EventField: simpleWant}
	modInfo := b.u64(uaTicks).u32(2).str("tok51")
	modWant := OPCUAModificationInfo{ModificationTime: tm, UpdateType: 2, UserName: "tok51"}

	return []uaExtVector{
		{opcuaRequestHeaderID, b.node(0, 1124).u64(uaTicks).u32(1125, 1126).str("tok17").u32(1127).cat(uaNone()),
			&OPCUARequestHeader{AuthenticationToken: n4(0, 1124), Timestamp: tm, RequestHandle: 1125, ReturnDiagnostics: 1126,
				AuditEntryID: "tok17", TimeoutHint: 1127, AdditionalHeader: OPCUAExtensionObject{TypeID: n4(0, 0)}}},
		{opcuaResponseHeaderID, b.u64(uaTicks).u32(1128, 1129).u8(0).u32(1).str("tok18").cat(uaNone()),
			&OPCUAResponseHeader{Timestamp: tm, RequestHandle: 1128, ServiceResult: 1129, ServiceDiagnostics: noDiag,
				StringTable: []string{"tok18"}, AdditionalHeader: OPCUAExtensionObject{TypeID: n4(0, 0)}}},
		{opcuaChannelTokenID, b.u32(1130, 1131).u64(uaTicks).u32(1132),
			&OPCUAChannelSecurityToken{ChannelID: 1130, TokenID: 1131, CreatedAt: tm, RevisedLifetime: 1132}},
		{opcuaIdentityTokenID, b.str("tok6"), &OPCUAUserIdentityToken{TokenType: OPCUAUserTokenAnonymous, PolicyID: "tok6"}},
		{opcuaKerberosTokenID, b.str("tok52").str("\x01\x02\x03"), &OPCUAUserIdentityToken{TokenType: OPCUAUserTokenIssued, PolicyID: "tok52"}},
		{opcuaSortRuleElementID, sortRule, &sortWant},
		{opcuaReadEventsSortedID, b.u32(1802).u64(uaTicks).u64(uaTicks).u32(1).cat(simple).null().u32(1).cat(sortRule),
			&OPCUAReadEventDetailsSorted{
				OPCUAReadEventDetails: OPCUAReadEventDetails{NumValuesPerNode: 1802, StartTime: tm, EndTime: tm,
					Filter: OPCUAEventFilter{SelectClauses: []OPCUASimpleAttributeOperand{simpleWant}}},
				SortClause: []OPCUASortRuleElement{sortWant}}},
		{opcuaReadAnnotationDataID, b.u32(1).u64(uaTicks), &OPCUAReadAnnotationDataDetails{ReqTimes: []time.Time{tm}}},
		{opcuaHistoryModEventID, b.u32(1).u32(1).cat(variant).u32(1).cat(modInfo),
			&OPCUAHistoryModifiedEvent{Events: []OPCUAHistoryEventFieldList{{EventFields: []OPCUAVariant{i32}}},
				ModificationInfos: []OPCUAModificationInfo{modWant}}},
		{opcuaModificationInfoID, modInfo, &modWant},
		{opcuaHistEventFieldListID, b.u32(1).cat(variant), &OPCUAHistoryEventFieldList{EventFields: []OPCUAVariant{i32}}},
	}
}

// uaResultVectors is one body per result and item structure.
func uaResultVectors() []uaExtVector {
	b := uaBuilder{}
	i32 := OPCUAVariant{Type: OPCUATypeInt32, Value: int32(1801)}
	variant := b.u8(uint8(OPCUATypeInt32)).u32(1801)
	value := OPCUADataValue{Mask: opcuaDataValueValue, Value: i32}
	none := OPCUAExtensionObject{TypeID: n4(0, 0)}
	elem := b.node(0, 1135).u8(1, 0).u16(0).str("tok19")
	elemWant := OPCUARelativePathElement{ReferenceTypeID: n4(0, 1135), IsInverse: true, TargetName: OPCUAQualifiedName{Name: "tok19"}}
	revision := OPCUAMonitoredItemRevision{RevisedSamplingInterval: 1159.5, RevisedQueueSize: 1160, FilterResult: none}

	return []uaExtVector{
		{opcuaAddNodesResultID, b.u32(1133).node(0, 1134), &OPCUAAddNodesResult{StatusCode: 1133, AddedNodeID: n4(0, 1134)}},
		{opcuaBrowsePathTargetID, b.node(0, 1137).u32(1138), &OPCUABrowsePathTarget{TargetID: n4(0, 1137), RemainingPathIndex: 1138}},
		{opcuaFilterElemResultID, b.u32(1146).u32(1).u32(1147).null(),
			&OPCUAContentFilterElementResult{StatusCode: 1146, OperandStatusCodes: []OPCUAStatusCode{1147}}},
		{opcuaParsingResultID, b.u32(1148).u32(1).u32(1149).null(),
			&OPCUAParsingResult{StatusCode: 1148, DataStatusCodes: []OPCUAStatusCode{1149}}},
		{opcuaHistoryReadResultID, b.u32(1150).str("\x05\x06").cat(uaNone()),
			&OPCUAHistoryReadResult{StatusCode: 1150, ContinuationPoint: []byte{5, 6}, HistoryData: none}},
		{opcuaHistoryUpdResultID, b.u32(1153).u32(1).u32(1154).null(),
			&OPCUAHistoryUpdateResult{StatusCode: 1153, OperationResults: []OPCUAStatusCode{1154}}},
		{opcuaItemCreateResultID, b.u32(1157, 1158).f64(1159.5).u32(1160).cat(uaNone()),
			&OPCUAMonitoredItemCreateResult{StatusCode: 1157, MonitoredItemID: 1158, OPCUAMonitoredItemRevision: revision}},
		{opcuaItemModifyResultID, b.u32(1165).f64(1159.5).u32(1160).cat(uaNone()),
			&OPCUAMonitoredItemModifyResult{StatusCode: 1165, OPCUAMonitoredItemRevision: revision}},
		{opcuaTransferResultID, b.u32(1172).u32(1).u32(1173),
			&OPCUATransferResult{StatusCode: 1172, AvailableSequenceNumbers: []uint32{1173}}},

		{opcuaDeleteNodesItemID, b.node(0, 1123).u8(1), &OPCUADeleteNodesItem{NodeID: n4(0, 1123), DeleteTargetReferences: true}},
		{opcuaRelativePathID, b.u32(1).cat(elem), &OPCUARelativePath{Elements: []OPCUARelativePathElement{elemWant}}},
		{opcuaBrowsePathID, b.node(0, 1136).u32(1).cat(elem),
			&OPCUABrowsePath{StartingNode: n4(0, 1136), RelativePath: []OPCUARelativePathElement{elemWant}}},
		{opcuaQueryDataDescID, b.u32(1).cat(elem).u32(13).str("tok53"),
			&OPCUAQueryDataDescription{RelativePath: []OPCUARelativePathElement{elemWant}, AttributeID: OPCUAAttributeValue, IndexRange: "tok53"}},
		{opcuaQueryDataSetID, b.node(0, 1139).node(0, 1140).u32(1).cat(variant),
			&OPCUAQueryDataSet{NodeID: n4(0, 1139), TypeDefinitionNode: n4(0, 1140), Values: []OPCUAVariant{i32}}},
		{opcuaNodeReferenceID, b.node(0, 1142).node(0, 1143).u8(1).u32(1).node(0, 1144),
			&OPCUANodeReference{NodeID: n4(0, 1142), ReferenceTypeID: n4(0, 1143), IsForward: true, ReferencedNodeIDs: []OPCUANodeID{n4(0, 1144)}}},
		{opcuaFilterElementID, b.u32(1).u32(1).ext(opcuaElementOperandID, b.u32(1145)),
			&OPCUAContentFilterElement{FilterOperator: OPCUAFilterIsNull, FilterOperands: []OPCUAExtensionObject{
				uaExt(opcuaElementOperandID, b.u32(1145), &OPCUAElementOperand{Index: 1145})}}},
		{opcuaWriteValueID, b.node(0, 1151).u32(13).str("tok54").u8(opcuaDataValueValue).cat(variant),
			&OPCUAWriteValue{NodeID: n4(0, 1151), AttributeID: OPCUAAttributeValue, IndexRange: "tok54", Value: value}},
		{opcuaCallMethodRequestID, b.node(0, 1155).node(0, 1156).u32(1).cat(variant),
			&OPCUACallMethodRequest{ObjectID: n4(0, 1155), MethodID: n4(0, 1156), InputArguments: []OPCUAVariant{i32}}},
		{opcuaItemModifyID, b.u32(1161, 1162).f64(1163.5).cat(uaNone()).u32(1164).u8(1),
			&OPCUAMonitoredItemModify{MonitoredItemID: 1161, RequestedParameters: OPCUAMonitoringParameters{
				ClientHandle: 1162, SamplingInterval: 1163.5, Filter: none, QueueSize: 1164, DiscardOldest: true}}},
		{opcuaItemNotifID, b.u32(1168).u8(opcuaDataValueValue).cat(variant), &OPCUAMonitoredItemNotif{ClientHandle: 1168, Value: value}},
		{opcuaSubscriptionAckID, b.u32(1170, 1171), &OPCUASubscriptionAck{SubscriptionID: 1170, SequenceNumber: 1171}},
		{opcuaEventFieldListID, b.u32(1174).u32(1).cat(variant), &OPCUAEventFieldList{ClientHandle: 1174, EventFields: []OPCUAVariant{i32}}},
		{opcuaServerOnNetworkID, b.u32(1175).str("tok55").str("tok56").u32(1).str("tok57"),
			&OPCUAServerOnNetwork{RecordID: 1175, ServerName: "tok55", DiscoveryURL: "tok56", ServerCapabilities: []string{"tok57"}}},
	}
}

// uaStructVectors lists one body per structure of opcua_structs.go and
// of the metadata structures.
func uaStructVectors() []uaExtVector {
	out := append(uaNodeVectors(), uaDiagVectors()...)
	out = append(out, uaHeaderVectors()...)
	out = append(out, uaResultVectors()...)
	return append(out, uaMetaVectors()...)
}

// uaAllExtVectors lists every structure of the registry.
func uaAllExtVectors() []uaExtVector {
	out := append(uaExtVectors(), uaNodeClassVectors()...)
	return append(out, uaStructVectors()...)
}

// TestOPCUAStructIDs checks that every id the registry was missing now
// decodes, each to a value of its own type.
func TestOPCUAStructIDs(t *testing.T) {
	seen := map[uint32]bool{}
	for _, v := range uaStructVectors() {
		id := uint32(v.id)
		seen[id] = true

		r := opcuaReader{b: v.body}
		got := r.extBody(id)
		if r.err != nil || r.remaining() != 0 || !reflect.DeepEqual(got, v.want) {
			t.Errorf("i=%d: got %+v (%v, %d left), want %+v", id, got, r.err, r.remaining(), v.want)
		}
	}

	for _, id := range []uint32{260, 263, 266, 269, 272, 275, 278, 281, 284, 287, 318, 333, 337, 343, 384, 391, 394, 443,
		485, 542, 545, 548, 572, 579, 582, 585, 606, 612, 640, 670, 697, 706, 748, 757, 760, 808, 823, 838, 867, 870, 876,
		896, 919, 922, 11226, 11889, 11890, 11958, 12207, 12509, 23500, 18650, 18651, 32825} {
		if !seen[id] {
			t.Errorf("i=%d has no vector", id)
		}
		r := opcuaReader{b: nil, mode: opcuaReadProbe}
		r.extBody(id)
		if r.err != ErrOPCUATruncated {
			t.Errorf("i=%d: not in the registry: %v", id, r.err)
		}
	}
}

// uaLegacyNode reports whether v is a node class decoded in the 1.03
// layout. A 1.04 body cut short can be a whole 1.03 body: the role
// permissions then read as references.
func uaLegacyNode(v interface{}) bool {
	f := reflect.ValueOf(v).Elem().FieldByName("Legacy")
	return f.IsValid() && f.Bool()
}

// TestOPCUANodeLayouts checks that a node class body picks its layout
// by what parses, and that neither layout takes the other's bytes.
func TestOPCUANodeLayouts(t *testing.T) {
	cur, old, _, _ := uaNodeBodies()
	for name, tc := range map[string]struct {
		body   []byte
		legacy bool
	}{
		"1.04": {cur, false},
		"1.03": {old, true},
	} {
		r := opcuaReader{b: tc.body}
		n, ok := r.extBody(opcuaNodeID).(*OPCUANode)
		if !ok || r.err != nil || n.Legacy != tc.legacy || (n.RolePermissions == nil) != tc.legacy {
			t.Errorf("%s: %+v %v", name, n, r.err)
		}
	}

	// A body that is neither stays encoded.
	bad := append(append([]byte{}, old...), 0xFF)
	e := OPCUAExtensionObject{TypeID: n4(0, opcuaNodeID), Encoding: 1, Body: bad}
	if v := decodeOPCUAExtBody(e, 0); v != nil {
		t.Errorf("bad node decoded: %+v", v)
	}
}

// TestOPCUANullStrings checks that null Strings are told from empty
// ones, in the header, the service and a nested ExtensionObject.
func TestOPCUANullStrings(t *testing.T) {
	b := uaBuilder{}

	// ERR with a null reason; HEL with an empty URL.
	ua := &OPCUA{}
	if err := ua.DecodeFromBytes(uaMessage("ERR", OPCUAChunkFinal, b.u32(0x80010000).null()), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if h, body := ua.NullStrings(); !reflect.DeepEqual(h, []int{opcuaHeaderLen + 4}) || body != nil {
		t.Errorf("ERR: %v %v", h, body)
	}
	if err := ua.DecodeFromBytes(uaMessage("HEL", OPCUAChunkFinal, b.u32(0, 1, 2, 3, 4).str("")), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if h, body := ua.NullStrings(); h != nil || body != nil {
		t.Errorf("HEL: %v %v", h, body)
	}

	// A Read response holding an Argument: null Name, empty text. The
	// request header of uaServiceMsg has no String; the Argument body
	// starts 4+24+4+2+4+1+4 bytes into the service.
	arg := b.null().node(0, 12).u32(1).null().u8(opcuaTextText).str("")
	msg := uaServiceMsg(OPCUAServiceReadResponse, uaExtRead(uaExtVector{id: opcuaArgumentID, body: arg}))
	if err := ua.DecodeFromBytes(msg, gopacket.NilDecodeFeedback); err != nil || ua.Service == nil {
		t.Fatal(err)
	}
	argAt := bytes.Index(ua.Body, arg)
	if h, body := ua.NullStrings(); h != nil || argAt < 0 || !reflect.DeepEqual(body, []int{argAt}) {
		t.Errorf("Argument: %v %v, body at %d", h, body, argAt)
	}

	// The same String empty: nothing is null.
	arg = b.str("").node(0, 12).u32(1).null().u8(opcuaTextText).str("")
	msg = uaServiceMsg(OPCUAServiceReadResponse, uaExtRead(uaExtVector{id: opcuaArgumentID, body: arg}))
	if err := ua.DecodeFromBytes(msg, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if h, body := ua.NullStrings(); h != nil || len(body) != 0 {
		t.Errorf("empty Name: %v %v", h, body)
	}

	// The audit id of a request header is null in uaRequestHeader.
	msg = uaServiceMsg(OPCUAServiceCloseSessionRequest, b.u8(1))
	if err := ua.DecodeFromBytes(msg, gopacket.NilDecodeFeedback); err != nil || ua.Service == nil {
		t.Fatal(err)
	}
	if _, body := ua.NullStrings(); len(body) != 1 {
		t.Errorf("request header: %v", body)
	}

	// Null and empty arrays and ByteStrings differ in the decoded value.
	r := opcuaReader{b: b.null().u32(0).null().u32(0)}
	if a, e, bn, be := r.u32s(), r.u32s(), r.byteString(), r.byteString(); a != nil || e == nil || len(e) != 0 || bn != nil || be == nil || len(be) != 0 {
		t.Errorf("null and empty: %v %v %v %v", a, e, bn, be)
	}

	// An undecoded layer has nothing to walk.
	if h, body := (&OPCUA{}).NullStrings(); h != nil || body != nil {
		t.Errorf("zero layer: %v %v", h, body)
	}
}

// TestOPCUACertificates splits a certificate chain.
func TestOPCUACertificates(t *testing.T) {
	short := []byte{0x30, 0x02, 0xAA, 0xBB}
	long := append([]byte{0x30, 0x82, 0x01, 0x00}, make([]byte, 256)...)
	chain := append(append([]byte{}, long...), short...)

	h := OPCUAAsymmetricSecurityHeader{SenderCertificate: chain}
	if got := h.Certificates(); len(got) != 2 || !bytes.Equal(got[0], long) || !bytes.Equal(got[1], short) {
		t.Errorf("chain: %d certificates", len(got))
	}

	// Garbage, a length past the data and an indefinite length end it.
	for name, tc := range map[string]struct {
		in   []byte
		want int
	}{
		"nil":            {nil, 0},
		"not a sequence": {[]byte{0x31, 0x00}, 0},
		"overrun":        {[]byte{0x30, 0x05, 0x00}, 0},
		"indefinite":     {[]byte{0x30, 0x80, 0x00, 0x00}, 0},
		"long overrun":   {[]byte{0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF}, 0},
		"cut length":     {[]byte{0x30, 0x82, 0x01}, 0},
		"five octets":    {[]byte{0x30, 0x85, 0, 0, 0, 0, 0}, 0},
		"then garbage":   {append(append([]byte{}, short...), 0xFF), 1},
	} {
		h.SenderCertificate = tc.in
		if got := h.Certificates(); len(got) != tc.want {
			t.Errorf("%s: %d certificates, want %d", name, len(got), tc.want)
		}
	}

	// The count is capped whatever the input holds.
	h.SenderCertificate = bytes.Repeat([]byte{0x30, 0x00}, 1000)
	if got := h.Certificates(); len(got) != opcuaMaxCertChain {
		t.Errorf("cap: %d certificates", len(got))
	}

	// The certificate of the signed capture is one DER certificate.
	ua := opcuaPacketMsg(t, "opcua-signed.pcap", 5)
	if got := ua.SecurityHeader.Certificates(); len(got) != 1 || !bytes.Equal(got[0], ua.SecurityHeader.SenderCertificate) {
		t.Errorf("signed capture: %d certificates", len(got))
	}
}
