// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// The remaining OPC UA structures that may travel in an ExtensionObject:
// the node classes of an exported address space, the diagnostics of
// OPC 10000-5, and the service parameter structures that have a binary
// encoding id of their own. Ids are those of the OPC Foundation
// NodeIds.csv; layouts those of Opc.Ua.Types.bsd and OPC 10000-3, -4,
// -5 and -11.
//
// The node classes changed layout in OPC UA 1.04:
//
//	1.03  NodeId … UserWriteMask ─────────────────────────── References
//	1.04  NodeId … UserWriteMask ─ RolePermissions ─ UserRolePermissions
//	                               ─ AccessRestrictions ─── References
//
// The body does not say which it is, so the newer layout is tried first
// and the older one is taken when the newer does not parse to the last
// byte.

package layers

import "time"

// Binary encoding ids of the node classes (NodeIds.csv).
const (
	opcuaNodeID              = 260
	opcuaObjectNodeID        = 263
	opcuaObjectTypeNodeID    = 266
	opcuaVariableNodeID      = 269
	opcuaVariableTypeNodeID  = 272
	opcuaReferenceTypeNodeID = 275
	opcuaMethodNodeID        = 278
	opcuaViewNodeID          = 281
	opcuaDataTypeNodeID      = 284
	opcuaReferenceNodeID     = 287
	opcuaInstanceNodeID      = 11889
	opcuaTypeNodeID          = 11890
)

// Binary encoding ids of the other structures decoded here. The three
// that newer NodeIds.csv dropped are those of OPC UA 1.02 and 1.03.
const (
	opcuaIdentityTokenID       = 318
	opcuaEndpointConfigID      = 333
	opcuaSupportedProfileID    = 337 // OPC UA 1.02
	opcuaSoftwareCertificateID = 343 // OPC UA 1.02
	opcuaDeleteNodesItemID     = 384
	opcuaRequestHeaderID       = 391
	opcuaResponseHeaderID      = 394
	opcuaChannelTokenID        = 443
	opcuaAddNodesResultID      = 485
	opcuaRelativePathID        = 542
	opcuaBrowsePathID          = 545
	opcuaBrowsePathTargetID    = 548
	opcuaQueryDataDescID       = 572
	opcuaQueryDataSetID        = 579
	opcuaNodeReferenceID       = 582
	opcuaFilterElementID       = 585
	opcuaFilterElemResultID    = 606
	opcuaParsingResultID       = 612
	opcuaHistoryReadResultID   = 640
	opcuaWriteValueID          = 670
	opcuaHistoryUpdResultID    = 697
	opcuaCallMethodRequestID   = 706
	opcuaItemCreateResultID    = 748
	opcuaItemModifyID          = 757
	opcuaItemModifyResultID    = 760
	opcuaItemNotifID           = 808
	opcuaSubscriptionAckID     = 823
	opcuaTransferResultID      = 838
	opcuaSessionDiagID         = 867
	opcuaSessionSecurityDiagID = 870
	opcuaSubscriptionDiagID    = 876
	opcuaProgramDiagID         = 896
	opcuaEventFieldListID      = 919
	opcuaHistEventFieldListID  = 922
	opcuaModificationInfoID    = 11226
	opcuaNetworkGroupID        = 11958
	opcuaServerOnNetworkID     = 12207
	opcuaKerberosTokenID       = 12509 // OPC UA 1.03
	opcuaSortRuleElementID     = 18650
	opcuaReadEventsSortedID    = 18651
	opcuaReadAnnotationDataID  = 23500
	opcuaHistoryModEventID     = 32825
)

// Minimum encoded sizes of the structures that come in arrays here.
const (
	opcuaMinRefNodeLen  = 2*opcuaMinNodeIDLen + opcuaUint8Len
	opcuaMinRolePermLen = opcuaMinNodeIDLen + opcuaUint32Len
	opcuaMinArgumentLen = opcuaUint32Len + opcuaMinNodeIDLen + 2*opcuaUint32Len + opcuaMinMaskedLen
	opcuaMinProfileLen  = 3*opcuaUint32Len + opcuaUint64Len + 2*opcuaUint32Len
	opcuaMinSortRuleLen = opcuaUint32Len + opcuaMinSimpleAttrLen
	opcuaMinURLListLen  = opcuaUint32Len
)

// opcuaNodeLayout tells the two wire layouts of the node classes apart.
type opcuaNodeLayout uint8

const (
	// opcuaNodeLayout104 has the role permissions, AccessLevelEx and
	// DataTypeDefinition of OPC UA 1.04 and later.
	opcuaNodeLayout104 opcuaNodeLayout = iota
	// opcuaNodeLayout103 is the layout up to OPC UA 1.03.
	opcuaNodeLayout103
)

// OPCUARolePermission grants a role some permissions on a node
// (OPC 10000-3 §8.48). Permissions is a PermissionType bit mask.
type OPCUARolePermission struct {
	RoleID      OPCUANodeID
	Permissions uint32
}

// OPCUAReferenceNode is one reference of a node (OPC 10000-3 §5.3).
type OPCUAReferenceNode struct {
	ReferenceTypeID OPCUANodeID
	IsInverse       bool
	TargetID        OPCUANodeID
}

// OPCUANode holds the attributes every node class has, as a server
// exports them (OPC 10000-3 §5.2). It is the Value of a Node, an
// InstanceNode and a TypeNode, and the base of the other node classes.
type OPCUANode struct {
	NodeID        OPCUANodeID
	NodeClass     OPCUANodeClass
	BrowseName    OPCUAQualifiedName
	DisplayName   OPCUALocalizedText
	Description   OPCUALocalizedText
	WriteMask     uint32
	UserWriteMask uint32
	// RolePermissions, UserRolePermissions and AccessRestrictions are
	// not sent in the layout of OPC UA 1.03.
	RolePermissions     []OPCUARolePermission
	UserRolePermissions []OPCUARolePermission
	AccessRestrictions  uint16
	References          []OPCUAReferenceNode
	// Legacy is set when the body has the layout of OPC UA 1.03.
	Legacy bool
}

// OPCUAObjectNode is an ObjectNode (OPC 10000-3 §5.5.1).
type OPCUAObjectNode struct {
	OPCUANode
	EventNotifier uint8
}

// OPCUAObjectTypeNode is an ObjectTypeNode (OPC 10000-3 §5.5.2).
type OPCUAObjectTypeNode struct {
	OPCUANode
	IsAbstract bool
}

// OPCUAVariableNode is a VariableNode (OPC 10000-3 §5.6.2).
type OPCUAVariableNode struct {
	OPCUANode
	Value           OPCUAVariant
	DataType        OPCUANodeID
	ValueRank       int32
	ArrayDimensions []uint32
	AccessLevel     uint8
	UserAccessLevel uint8
	// MinimumSamplingInterval is in milliseconds.
	MinimumSamplingInterval float64
	Historizing             bool
	// AccessLevelEx is not sent in the layout of OPC UA 1.03.
	AccessLevelEx uint32
}

// OPCUAVariableTypeNode is a VariableTypeNode (OPC 10000-3 §5.6.5).
type OPCUAVariableTypeNode struct {
	OPCUANode
	Value           OPCUAVariant
	DataType        OPCUANodeID
	ValueRank       int32
	ArrayDimensions []uint32
	IsAbstract      bool
}

// OPCUAReferenceTypeNode is a ReferenceTypeNode (OPC 10000-3 §5.3.2).
type OPCUAReferenceTypeNode struct {
	OPCUANode
	IsAbstract  bool
	Symmetric   bool
	InverseName OPCUALocalizedText
}

// OPCUAMethodNode is a MethodNode (OPC 10000-3 §5.7).
type OPCUAMethodNode struct {
	OPCUANode
	Executable     bool
	UserExecutable bool
}

// OPCUAViewNode is a ViewNode (OPC 10000-3 §5.4).
type OPCUAViewNode struct {
	OPCUANode
	ContainsNoLoops bool
	EventNotifier   uint8
}

// OPCUADataTypeNode is a DataTypeNode (OPC 10000-3 §5.8.3).
type OPCUADataTypeNode struct {
	OPCUANode
	IsAbstract bool
	// DataTypeDefinition is not sent in the layout of OPC UA 1.03.
	DataTypeDefinition OPCUAExtensionObject
}

// OPCUAEndpointConfiguration is an EndpointConfiguration (OPC 10000-4
// §7.9 of OPC UA 1.03): the limits a client proposes to an endpoint.
// The times are in milliseconds.
type OPCUAEndpointConfiguration struct {
	OperationTimeout      int32
	UseBinaryEncoding     bool
	MaxStringLength       int32
	MaxByteStringLength   int32
	MaxArrayLength        int32
	MaxMessageSize        int32
	MaxBufferSize         int32
	ChannelLifetime       int32
	SecurityTokenLifetime int32
}

// OPCUAComplianceLevel tells how a profile was tested (OPC UA 1.02).
type OPCUAComplianceLevel uint32

// OPCUAComplianceLevel values.
const (
	OPCUAComplianceUntested   OPCUAComplianceLevel = 0
	OPCUACompliancePartial    OPCUAComplianceLevel = 1
	OPCUAComplianceSelfTested OPCUAComplianceLevel = 2
	OPCUAComplianceCertified  OPCUAComplianceLevel = 3
)

var opcuaComplianceLevelNames = map[OPCUAComplianceLevel]string{
	OPCUAComplianceUntested:   "Untested",
	OPCUACompliancePartial:    "Partial",
	OPCUAComplianceSelfTested: "SelfTested",
	OPCUAComplianceCertified:  "Certified",
}

// String returns the level name.
func (l OPCUAComplianceLevel) String() string { return opcuaName(opcuaComplianceLevelNames, l) }

// OPCUASupportedProfile is a profile a product claims (OPC UA 1.02
// Part 4 §7.31; later versions dropped it).
type OPCUASupportedProfile struct {
	OrganizationURI    string
	ProfileID          string
	ComplianceTool     string
	ComplianceDate     time.Time
	ComplianceLevel    OPCUAComplianceLevel
	UnsupportedUnitIDs []string
}

// OPCUASoftwareCertificate describes a certified product (OPC UA 1.02
// Part 4 §7.31; later versions dropped it).
type OPCUASoftwareCertificate struct {
	ProductName              string
	ProductURI               string
	VendorName               string
	VendorProductCertificate []byte
	SoftwareVersion          string
	BuildNumber              string
	BuildDate                time.Time
	IssuedBy                 string
	IssueDate                time.Time
	SupportedProfiles        []OPCUASupportedProfile
}

// OPCUARelativePath is a RelativePath (OPC 10000-4 §7.31).
type OPCUARelativePath struct {
	Elements []OPCUARelativePathElement
}

// OPCUANodeReference is a NodeReference of a query result (OPC 10000-4
// §7.28).
type OPCUANodeReference struct {
	NodeID            OPCUANodeID
	ReferenceTypeID   OPCUANodeID
	IsForward         bool
	ReferencedNodeIDs []OPCUANodeID
}

// OPCUASessionDiagnostics is a SessionDiagnosticsDataType (OPC 10000-5
// §12.11), the counters of one session.
type OPCUASessionDiagnostics struct {
	SessionID         OPCUANodeID
	SessionName       string
	ClientDescription OPCUAApplicationDescription
	ServerURI         string
	EndpointURL       string
	LocaleIDs         []string
	// ActualSessionTimeout is in milliseconds.
	ActualSessionTimeout          float64
	MaxResponseMessageSize        uint32
	ClientConnectionTime          time.Time
	ClientLastContactTime         time.Time
	CurrentSubscriptionsCount     uint32
	CurrentMonitoredItemsCount    uint32
	CurrentPublishRequestsInQueue uint32
	TotalRequestCount             OPCUAServiceCounter
	UnauthorizedRequestCount      uint32

	ReadCount                  OPCUAServiceCounter
	HistoryReadCount           OPCUAServiceCounter
	WriteCount                 OPCUAServiceCounter
	HistoryUpdateCount         OPCUAServiceCounter
	CallCount                  OPCUAServiceCounter
	CreateMonitoredItemsCount  OPCUAServiceCounter
	ModifyMonitoredItemsCount  OPCUAServiceCounter
	SetMonitoringModeCount     OPCUAServiceCounter
	SetTriggeringCount         OPCUAServiceCounter
	DeleteMonitoredItemsCount  OPCUAServiceCounter
	CreateSubscriptionCount    OPCUAServiceCounter
	ModifySubscriptionCount    OPCUAServiceCounter
	SetPublishingModeCount     OPCUAServiceCounter
	PublishCount               OPCUAServiceCounter
	RepublishCount             OPCUAServiceCounter
	TransferSubscriptionsCount OPCUAServiceCounter
	DeleteSubscriptionsCount   OPCUAServiceCounter
	AddNodesCount              OPCUAServiceCounter
	AddReferencesCount         OPCUAServiceCounter
	DeleteNodesCount           OPCUAServiceCounter
	DeleteReferencesCount      OPCUAServiceCounter
	BrowseCount                OPCUAServiceCounter
	BrowseNextCount            OPCUAServiceCounter
	TranslateBrowsePathsCount  OPCUAServiceCounter
	QueryFirstCount            OPCUAServiceCounter
	QueryNextCount             OPCUAServiceCounter
	RegisterNodesCount         OPCUAServiceCounter
	UnregisterNodesCount       OPCUAServiceCounter
}

// OPCUASessionSecurityDiagnostics is a
// SessionSecurityDiagnosticsDataType (OPC 10000-5 §12.12).
type OPCUASessionSecurityDiagnostics struct {
	SessionID               OPCUANodeID
	ClientUserIDOfSession   string
	ClientUserIDHistory     []string
	AuthenticationMechanism string
	Encoding                string
	TransportProtocol       string
	SecurityMode            OPCUAMessageSecurityMode
	SecurityPolicyURI       string
	ClientCertificate       []byte
}

// OPCUASubscriptionDiagnostics is a SubscriptionDiagnosticsDataType
// (OPC 10000-5 §12.15), the counters of one subscription.
type OPCUASubscriptionDiagnostics struct {
	SessionID      OPCUANodeID
	SubscriptionID uint32
	Priority       uint8
	// PublishingInterval is in milliseconds.
	PublishingInterval           float64
	MaxKeepAliveCount            uint32
	MaxLifetimeCount             uint32
	MaxNotificationsPerPublish   uint32
	PublishingEnabled            bool
	ModifyCount                  uint32
	EnableCount                  uint32
	DisableCount                 uint32
	RepublishRequestCount        uint32
	RepublishMessageRequestCount uint32
	RepublishMessageCount        uint32
	TransferRequestCount         uint32
	TransferredToAltClientCount  uint32
	TransferredToSameClientCount uint32
	PublishRequestCount          uint32
	DataChangeNotificationsCount uint32
	EventNotificationsCount      uint32
	NotificationsCount           uint32
	LatePublishRequestCount      uint32
	CurrentKeepAliveCount        uint32
	CurrentLifetimeCount         uint32
	UnacknowledgedMessageCount   uint32
	DiscardedMessageCount        uint32
	MonitoredItemCount           uint32
	DisabledMonitoredItemCount   uint32
	MonitoringQueueOverflowCount uint32
	NextSequenceNumber           uint32
	EventQueueOverflowCount      uint32
}

// OPCUAProgramDiagnostic is a ProgramDiagnosticDataType (OPC 10000-10
// §5.2.8), the last method call of a program.
type OPCUAProgramDiagnostic struct {
	CreateSessionID           OPCUANodeID
	CreateClientName          string
	InvocationCreationTime    time.Time
	LastTransitionTime        time.Time
	LastMethodCall            string
	LastMethodSessionID       OPCUANodeID
	LastMethodInputArguments  []OPCUAArgument
	LastMethodOutputArguments []OPCUAArgument
	LastMethodCallTime        time.Time
	LastMethodReturnStatus    OPCUAStatusResult
}

// OPCUANetworkGroup is a NetworkGroupDataType (OPC 10000-5 §12.20): the
// network paths to one server of a redundant set.
type OPCUANetworkGroup struct {
	ServerURI    string
	NetworkPaths []OPCUAEndpointURLList
}

// OPCUASortOrder is a SortOrderType (OPC 10000-11 §6.5).
type OPCUASortOrder uint32

// OPCUASortOrder values.
const (
	OPCUASortAscending  OPCUASortOrder = 0
	OPCUASortDescending OPCUASortOrder = 1
)

// String returns the sort order name.
func (o OPCUASortOrder) String() string {
	switch o {
	case OPCUASortAscending:
		return "Ascending"
	case OPCUASortDescending:
		return "Descending"
	}
	return opcuaName[OPCUASortOrder](nil, o)
}

// OPCUASortRuleElement sorts past events by one of their fields
// (OPC 10000-11 §6.5.2).
type OPCUASortRuleElement struct {
	SortOrder  OPCUASortOrder
	EventField OPCUASimpleAttributeOperand
}

// OPCUAReadEventDetailsSorted reads the history of events in a given
// order (OPC 10000-11 §6.5.2).
type OPCUAReadEventDetailsSorted struct {
	OPCUAReadEventDetails
	SortClause []OPCUASortRuleElement
}

// OPCUAReadAnnotationDataDetails reads the annotations at given times
// (OPC 10000-11 §6.5.6).
type OPCUAReadAnnotationDataDetails struct {
	ReqTimes []time.Time
}

// OPCUAHistoryModifiedEvent is the modified history of events
// (OPC 10000-11 §6.6.5).
type OPCUAHistoryModifiedEvent struct {
	Events            []OPCUAHistoryEventFieldList
	ModificationInfos []OPCUAModificationInfo
}

// extStructs reads the structures of this file.
func (r *opcuaReader) extStructs(id uint32) (interface{}, bool) {
	if v, ok := r.extNodeClass(id); ok {
		return v, true
	}
	if v, ok := r.extDiagnostics(id); ok {
		return v, true
	}
	if v, ok := r.extHeaders(id); ok {
		return v, true
	}
	if v, ok := r.extResults(id); ok {
		return v, true
	}
	if v, ok := r.extMetaData(id); ok {
		return v, true
	}
	return r.extItems(id)
}

// extNodeClass reads a node class in the layout its body parses in.
func (r *opcuaReader) extNodeClass(id uint32) (interface{}, bool) {
	switch id {
	case opcuaReferenceNodeID:
		return opcuaBoxed(r, r.referenceNode()), true
	case opcuaNodeID, opcuaInstanceNodeID, opcuaTypeNodeID, opcuaObjectNodeID, opcuaObjectTypeNodeID,
		opcuaVariableNodeID, opcuaVariableTypeNodeID, opcuaReferenceTypeNodeID, opcuaMethodNodeID,
		opcuaViewNodeID, opcuaDataTypeNodeID:
	default:
		return nil, false
	}

	// A probe of the newer layout picks the layout; reading the same
	// bytes again, the caller's probe and decode agree on it.
	layout := opcuaNodeLayout104
	probe := opcuaReader{b: r.b[r.off:], mode: opcuaReadProbe, extDepth: r.extDepth}
	probe.nodeClass(id, layout)
	if probe.err != nil || probe.remaining() != 0 {
		layout = opcuaNodeLayout103
	}
	return r.nodeClass(id, layout), true
}

// nodeClass reads the node class of encoding id in the given layout.
func (r *opcuaReader) nodeClass(id uint32, layout opcuaNodeLayout) interface{} {
	n := r.node(layout)

	switch id {
	case opcuaObjectNodeID:
		return opcuaBoxed(r, OPCUAObjectNode{OPCUANode: n, EventNotifier: r.u8()})
	case opcuaObjectTypeNodeID:
		return opcuaBoxed(r, OPCUAObjectTypeNode{OPCUANode: n, IsAbstract: r.boolean()})
	case opcuaVariableNodeID:
		return opcuaBoxed(r, r.variableNode(n, layout))
	case opcuaVariableTypeNodeID:
		return opcuaBoxed(r, OPCUAVariableTypeNode{
			OPCUANode:       n,
			Value:           r.variant(0),
			DataType:        r.nodeID(),
			ValueRank:       r.i32(),
			ArrayDimensions: r.u32s(),
			IsAbstract:      r.boolean(),
		})
	case opcuaReferenceTypeNodeID:
		return opcuaBoxed(r, OPCUAReferenceTypeNode{
			OPCUANode:   n,
			IsAbstract:  r.boolean(),
			Symmetric:   r.boolean(),
			InverseName: r.localizedText(),
		})
	case opcuaMethodNodeID:
		return opcuaBoxed(r, OPCUAMethodNode{OPCUANode: n, Executable: r.boolean(), UserExecutable: r.boolean()})
	case opcuaViewNodeID:
		return opcuaBoxed(r, OPCUAViewNode{OPCUANode: n, ContainsNoLoops: r.boolean(), EventNotifier: r.u8()})
	case opcuaDataTypeNodeID:
		d := OPCUADataTypeNode{OPCUANode: n, IsAbstract: r.boolean()}
		if layout == opcuaNodeLayout104 {
			d.DataTypeDefinition = r.extensionObject()
		}
		return opcuaBoxed(r, d)
	}
	return opcuaBoxed(r, n)
}

// node reads the attributes common to the node classes.
func (r *opcuaReader) node(layout opcuaNodeLayout) OPCUANode {
	n := OPCUANode{
		NodeID:        r.nodeID(),
		NodeClass:     OPCUANodeClass(r.u32()),
		BrowseName:    r.qualifiedName(),
		DisplayName:   r.localizedText(),
		Description:   r.localizedText(),
		WriteMask:     r.u32(),
		UserWriteMask: r.u32(),
		Legacy:        layout == opcuaNodeLayout103,
	}
	if layout == opcuaNodeLayout104 {
		n.RolePermissions = opcuaArray(r, opcuaMinRolePermLen, r.rolePermission)
		n.UserRolePermissions = opcuaArray(r, opcuaMinRolePermLen, r.rolePermission)
		n.AccessRestrictions = r.u16()
	}
	n.References = opcuaArray(r, opcuaMinRefNodeLen, r.referenceNode)
	return n
}

func (r *opcuaReader) rolePermission() OPCUARolePermission {
	return OPCUARolePermission{RoleID: r.nodeID(), Permissions: r.u32()}
}

func (r *opcuaReader) referenceNode() OPCUAReferenceNode {
	return OPCUAReferenceNode{ReferenceTypeID: r.nodeID(), IsInverse: r.boolean(), TargetID: r.expandedNodeID()}
}

func (r *opcuaReader) variableNode(n OPCUANode, layout opcuaNodeLayout) OPCUAVariableNode {
	v := OPCUAVariableNode{
		OPCUANode:               n,
		Value:                   r.variant(0),
		DataType:                r.nodeID(),
		ValueRank:               r.i32(),
		ArrayDimensions:         r.u32s(),
		AccessLevel:             r.u8(),
		UserAccessLevel:         r.u8(),
		MinimumSamplingInterval: r.f64(),
		Historizing:             r.boolean(),
	}
	if layout == opcuaNodeLayout104 {
		v.AccessLevelEx = r.u32()
	}
	return v
}

// extDiagnostics reads the diagnostics structures of OPC 10000-5 and
// the profile structures of OPC UA 1.02.
func (r *opcuaReader) extDiagnostics(id uint32) (interface{}, bool) {
	switch id {
	case opcuaSessionDiagID:
		return opcuaBoxed(r, r.sessionDiagnostics()), true
	case opcuaSessionSecurityDiagID:
		return opcuaBoxed(r, OPCUASessionSecurityDiagnostics{
			SessionID:               r.nodeID(),
			ClientUserIDOfSession:   r.str(),
			ClientUserIDHistory:     r.strings(),
			AuthenticationMechanism: r.str(),
			Encoding:                r.str(),
			TransportProtocol:       r.str(),
			SecurityMode:            OPCUAMessageSecurityMode(r.u32()),
			SecurityPolicyURI:       r.str(),
			ClientCertificate:       r.byteString(),
		}), true
	case opcuaSubscriptionDiagID:
		return opcuaBoxed(r, r.subscriptionDiagnostics()), true
	case opcuaProgramDiagID:
		return opcuaBoxed(r, OPCUAProgramDiagnostic{
			CreateSessionID:           r.nodeID(),
			CreateClientName:          r.str(),
			InvocationCreationTime:    r.dateTime(),
			LastTransitionTime:        r.dateTime(),
			LastMethodCall:            r.str(),
			LastMethodSessionID:       r.nodeID(),
			LastMethodInputArguments:  opcuaArray(r, opcuaMinArgumentLen, r.argument),
			LastMethodOutputArguments: opcuaArray(r, opcuaMinArgumentLen, r.argument),
			LastMethodCallTime:        r.dateTime(),
			LastMethodReturnStatus:    OPCUAStatusResult{StatusCode: r.statusCode(), DiagnosticInfo: r.diagnosticInfo(0)},
		}), true
	case opcuaNetworkGroupID:
		return opcuaBoxed(r, OPCUANetworkGroup{
			ServerURI: r.str(),
			NetworkPaths: opcuaArray(r, opcuaMinURLListLen, func() OPCUAEndpointURLList {
				return OPCUAEndpointURLList{EndpointURLList: r.strings()}
			}),
		}), true
	case opcuaEndpointConfigID:
		return opcuaBoxed(r, OPCUAEndpointConfiguration{
			OperationTimeout:      r.i32(),
			UseBinaryEncoding:     r.boolean(),
			MaxStringLength:       r.i32(),
			MaxByteStringLength:   r.i32(),
			MaxArrayLength:        r.i32(),
			MaxMessageSize:        r.i32(),
			MaxBufferSize:         r.i32(),
			ChannelLifetime:       r.i32(),
			SecurityTokenLifetime: r.i32(),
		}), true
	case opcuaSupportedProfileID:
		return opcuaBoxed(r, r.supportedProfile()), true
	case opcuaSoftwareCertificateID:
		return opcuaBoxed(r, OPCUASoftwareCertificate{
			ProductName:              r.str(),
			ProductURI:               r.str(),
			VendorName:               r.str(),
			VendorProductCertificate: r.byteString(),
			SoftwareVersion:          r.str(),
			BuildNumber:              r.str(),
			BuildDate:                r.dateTime(),
			IssuedBy:                 r.str(),
			IssueDate:                r.dateTime(),
			SupportedProfiles:        opcuaArray(r, opcuaMinProfileLen, r.supportedProfile),
		}), true
	}
	return nil, false
}

func (r *opcuaReader) argument() OPCUAArgument {
	return OPCUAArgument{
		Name:            r.str(),
		DataType:        r.nodeID(),
		ValueRank:       r.i32(),
		ArrayDimensions: r.u32s(),
		Description:     r.localizedText(),
	}
}

func (r *opcuaReader) supportedProfile() OPCUASupportedProfile {
	return OPCUASupportedProfile{
		OrganizationURI:    r.str(),
		ProfileID:          r.str(),
		ComplianceTool:     r.str(),
		ComplianceDate:     r.dateTime(),
		ComplianceLevel:    OPCUAComplianceLevel(r.u32()),
		UnsupportedUnitIDs: r.strings(),
	}
}

func (r *opcuaReader) serviceCounter() OPCUAServiceCounter {
	return OPCUAServiceCounter{TotalCount: r.u32(), ErrorCount: r.u32()}
}

func (r *opcuaReader) sessionDiagnostics() OPCUASessionDiagnostics {
	d := OPCUASessionDiagnostics{
		SessionID:                     r.nodeID(),
		SessionName:                   r.str(),
		ClientDescription:             r.applicationDescription(),
		ServerURI:                     r.str(),
		EndpointURL:                   r.str(),
		LocaleIDs:                     r.strings(),
		ActualSessionTimeout:          r.f64(),
		MaxResponseMessageSize:        r.u32(),
		ClientConnectionTime:          r.dateTime(),
		ClientLastContactTime:         r.dateTime(),
		CurrentSubscriptionsCount:     r.u32(),
		CurrentMonitoredItemsCount:    r.u32(),
		CurrentPublishRequestsInQueue: r.u32(),
		TotalRequestCount:             r.serviceCounter(),
		UnauthorizedRequestCount:      r.u32(),
	}

	// The per-service counters follow in the order of the fields.
	for _, c := range []*OPCUAServiceCounter{
		&d.ReadCount, &d.HistoryReadCount, &d.WriteCount, &d.HistoryUpdateCount, &d.CallCount,
		&d.CreateMonitoredItemsCount, &d.ModifyMonitoredItemsCount, &d.SetMonitoringModeCount,
		&d.SetTriggeringCount, &d.DeleteMonitoredItemsCount, &d.CreateSubscriptionCount,
		&d.ModifySubscriptionCount, &d.SetPublishingModeCount, &d.PublishCount, &d.RepublishCount,
		&d.TransferSubscriptionsCount, &d.DeleteSubscriptionsCount, &d.AddNodesCount,
		&d.AddReferencesCount, &d.DeleteNodesCount, &d.DeleteReferencesCount, &d.BrowseCount,
		&d.BrowseNextCount, &d.TranslateBrowsePathsCount, &d.QueryFirstCount, &d.QueryNextCount,
		&d.RegisterNodesCount, &d.UnregisterNodesCount,
	} {
		*c = r.serviceCounter()
	}
	return d
}

func (r *opcuaReader) subscriptionDiagnostics() OPCUASubscriptionDiagnostics {
	return OPCUASubscriptionDiagnostics{
		SessionID:                    r.nodeID(),
		SubscriptionID:               r.u32(),
		Priority:                     r.u8(),
		PublishingInterval:           r.f64(),
		MaxKeepAliveCount:            r.u32(),
		MaxLifetimeCount:             r.u32(),
		MaxNotificationsPerPublish:   r.u32(),
		PublishingEnabled:            r.boolean(),
		ModifyCount:                  r.u32(),
		EnableCount:                  r.u32(),
		DisableCount:                 r.u32(),
		RepublishRequestCount:        r.u32(),
		RepublishMessageRequestCount: r.u32(),
		RepublishMessageCount:        r.u32(),
		TransferRequestCount:         r.u32(),
		TransferredToAltClientCount:  r.u32(),
		TransferredToSameClientCount: r.u32(),
		PublishRequestCount:          r.u32(),
		DataChangeNotificationsCount: r.u32(),
		EventNotificationsCount:      r.u32(),
		NotificationsCount:           r.u32(),
		LatePublishRequestCount:      r.u32(),
		CurrentKeepAliveCount:        r.u32(),
		CurrentLifetimeCount:         r.u32(),
		UnacknowledgedMessageCount:   r.u32(),
		DiscardedMessageCount:        r.u32(),
		MonitoredItemCount:           r.u32(),
		DisabledMonitoredItemCount:   r.u32(),
		MonitoringQueueOverflowCount: r.u32(),
		NextSequenceNumber:           r.u32(),
		EventQueueOverflowCount:      r.u32(),
	}
}

// extHeaders reads the request and response headers, the tokens and
// the history structures that have an encoding id of their own.
func (r *opcuaReader) extHeaders(id uint32) (interface{}, bool) {
	switch id {
	case opcuaRequestHeaderID:
		return opcuaBoxed(r, r.requestHeader()), true
	case opcuaResponseHeaderID:
		return opcuaBoxed(r, r.responseHeader()), true
	case opcuaChannelTokenID:
		return opcuaBoxed(r, OPCUAChannelSecurityToken{
			ChannelID:       r.u32(),
			TokenID:         r.u32(),
			CreatedAt:       r.dateTime(),
			RevisedLifetime: r.u32(),
		}), true
	case opcuaIdentityTokenID:
		// The base type has the PolicyId alone, as an anonymous token.
		return opcuaBoxed(r, r.identityToken(OPCUAUserTokenAnonymous)), true
	case opcuaKerberosTokenID:
		// PolicyId and the ticket: an issued token without algorithm.
		t := OPCUAUserIdentityToken{TokenType: OPCUAUserTokenIssued, PolicyID: r.str()}
		r.byteString() // ticket data
		return opcuaBoxed(r, t), true
	case opcuaSortRuleElementID:
		return opcuaBoxed(r, r.sortRuleElement()), true
	case opcuaReadEventsSortedID:
		return opcuaBoxed(r, OPCUAReadEventDetailsSorted{
			OPCUAReadEventDetails: OPCUAReadEventDetails{
				NumValuesPerNode: r.u32(),
				StartTime:        r.dateTime(),
				EndTime:          r.dateTime(),
				Filter:           r.eventFilter(),
			},
			SortClause: opcuaArray(r, opcuaMinSortRuleLen, r.sortRuleElement),
		}), true
	case opcuaReadAnnotationDataID:
		return opcuaBoxed(r, OPCUAReadAnnotationDataDetails{ReqTimes: r.dateTimes()}), true
	case opcuaHistoryModEventID:
		return opcuaBoxed(r, OPCUAHistoryModifiedEvent{
			Events:            r.historyEvents(),
			ModificationInfos: opcuaArray(r, opcuaMinModInfoLen, r.modificationInfo),
		}), true
	case opcuaModificationInfoID:
		return opcuaBoxed(r, r.modificationInfo()), true
	case opcuaHistEventFieldListID:
		return opcuaBoxed(r, OPCUAHistoryEventFieldList{EventFields: r.variants(0)}), true
	}
	return nil, false
}

func (r *opcuaReader) sortRuleElement() OPCUASortRuleElement {
	return OPCUASortRuleElement{SortOrder: OPCUASortOrder(r.u32()), EventField: r.simpleAttrOperand()}
}

func (r *opcuaReader) modificationInfo() OPCUAModificationInfo {
	return OPCUAModificationInfo{ModificationTime: r.dateTime(), UpdateType: r.u32(), UserName: r.str()}
}

// extResults reads the per-operation results of the services.
func (r *opcuaReader) extResults(id uint32) (interface{}, bool) {
	switch id {
	case opcuaAddNodesResultID:
		return opcuaBoxed(r, OPCUAAddNodesResult{StatusCode: r.statusCode(), AddedNodeID: r.nodeID()}), true
	case opcuaBrowsePathTargetID:
		return opcuaBoxed(r, OPCUABrowsePathTarget{TargetID: r.expandedNodeID(), RemainingPathIndex: r.u32()}), true
	case opcuaFilterElemResultID:
		return opcuaBoxed(r, OPCUAContentFilterElementResult{
			StatusCode:             r.statusCode(),
			OperandStatusCodes:     r.statusCodes(),
			OperandDiagnosticInfos: r.diagnosticInfos(),
		}), true
	case opcuaParsingResultID:
		return opcuaBoxed(r, OPCUAParsingResult{
			StatusCode:          r.statusCode(),
			DataStatusCodes:     r.statusCodes(),
			DataDiagnosticInfos: r.diagnosticInfos(),
		}), true
	case opcuaHistoryReadResultID:
		return opcuaBoxed(r, OPCUAHistoryReadResult{
			StatusCode:        r.statusCode(),
			ContinuationPoint: r.byteString(),
			HistoryData:       r.extensionObject(),
		}), true
	case opcuaHistoryUpdResultID:
		return opcuaBoxed(r, OPCUAHistoryUpdateResult{
			StatusCode:       r.statusCode(),
			OperationResults: r.statusCodes(),
			DiagnosticInfos:  r.diagnosticInfos(),
		}), true
	case opcuaItemCreateResultID:
		return opcuaBoxed(r, OPCUAMonitoredItemCreateResult{
			StatusCode:                 r.statusCode(),
			MonitoredItemID:            r.u32(),
			OPCUAMonitoredItemRevision: r.itemRevision(),
		}), true
	case opcuaItemModifyResultID:
		return opcuaBoxed(r, OPCUAMonitoredItemModifyResult{
			StatusCode:                 r.statusCode(),
			OPCUAMonitoredItemRevision: r.itemRevision(),
		}), true
	case opcuaTransferResultID:
		return opcuaBoxed(r, OPCUATransferResult{StatusCode: r.statusCode(), AvailableSequenceNumbers: r.u32s()}), true
	}
	return nil, false
}

// extItems reads the per-operation items of the service requests and
// the notification elements.
func (r *opcuaReader) extItems(id uint32) (interface{}, bool) {
	switch id {
	case opcuaDeleteNodesItemID:
		return opcuaBoxed(r, OPCUADeleteNodesItem{NodeID: r.nodeID(), DeleteTargetReferences: r.boolean()}), true
	case opcuaRelativePathID:
		return opcuaBoxed(r, OPCUARelativePath{Elements: opcuaArray(r, opcuaMinPathElemLen, r.pathElement)}), true
	case opcuaBrowsePathID:
		return opcuaBoxed(r, OPCUABrowsePath{
			StartingNode: r.nodeID(),
			RelativePath: opcuaArray(r, opcuaMinPathElemLen, r.pathElement),
		}), true
	case opcuaQueryDataDescID:
		return opcuaBoxed(r, OPCUAQueryDataDescription{
			RelativePath: opcuaArray(r, opcuaMinPathElemLen, r.pathElement),
			AttributeID:  OPCUAAttributeID(r.u32()),
			IndexRange:   r.str(),
		}), true
	case opcuaQueryDataSetID:
		return opcuaBoxed(r, OPCUAQueryDataSet{
			NodeID:             r.expandedNodeID(),
			TypeDefinitionNode: r.expandedNodeID(),
			Values:             r.variants(0),
		}), true
	case opcuaNodeReferenceID:
		return opcuaBoxed(r, OPCUANodeReference{
			NodeID:            r.nodeID(),
			ReferenceTypeID:   r.nodeID(),
			IsForward:         r.boolean(),
			ReferencedNodeIDs: r.nodeIDs(),
		}), true
	case opcuaFilterElementID:
		return opcuaBoxed(r, OPCUAContentFilterElement{
			FilterOperator: OPCUAFilterOperator(r.u32()),
			FilterOperands: opcuaArray(r, opcuaMinExtObjLen, r.extensionObject),
		}), true
	case opcuaWriteValueID:
		return opcuaBoxed(r, OPCUAWriteValue{
			NodeID:      r.nodeID(),
			AttributeID: OPCUAAttributeID(r.u32()),
			IndexRange:  r.str(),
			Value:       r.dataValue(0),
		}), true
	case opcuaCallMethodRequestID:
		return opcuaBoxed(r, OPCUACallMethodRequest{
			ObjectID:       r.nodeID(),
			MethodID:       r.nodeID(),
			InputArguments: r.variants(0),
		}), true
	case opcuaItemModifyID:
		return opcuaBoxed(r, OPCUAMonitoredItemModify{MonitoredItemID: r.u32(), RequestedParameters: r.monitoringParams()}), true
	case opcuaItemNotifID:
		return opcuaBoxed(r, OPCUAMonitoredItemNotif{ClientHandle: r.u32(), Value: r.dataValue(0)}), true
	case opcuaSubscriptionAckID:
		return opcuaBoxed(r, OPCUASubscriptionAck{SubscriptionID: r.u32(), SequenceNumber: r.u32()}), true
	case opcuaEventFieldListID:
		return opcuaBoxed(r, OPCUAEventFieldList{ClientHandle: r.u32(), EventFields: r.variants(0)}), true
	case opcuaServerOnNetworkID:
		return opcuaBoxed(r, OPCUAServerOnNetwork{
			RecordID:           r.u32(),
			ServerName:         r.str(),
			DiscoveryURL:       r.str(),
			ServerCapabilities: r.strings(),
		}), true
	}
	return nil, false
}
