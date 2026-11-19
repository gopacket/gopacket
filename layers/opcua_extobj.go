// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA structures that travel in an ExtensionObject (OPC 10000-6
// §5.2.2.15), decoded by the binary encoding id that opens it.
//
//	ExtensionObject ─ TypeId ─ encoding ─ length ─ body
//	                    │                           │
//	                    └── i=724 ──────────────────┴─► *OPCUADataChangeFilter
//
// A body is probed first and decoded only when it parses to its last
// byte, so an unknown or damaged body stays in Body alone. A body may
// hold further ExtensionObjects, opcuaMaxExtDepth deep.

package layers

import "time"

// Binary encoding ids of the structures decoded here (NodeIds.csv).
const (
	opcuaArgumentID          = 298
	opcuaStatusResultID      = 301
	opcuaUserTokenPolicyID   = 306
	opcuaAppDescriptionID    = 310
	opcuaEndpointDescID      = 314
	opcuaBuildInfoID         = 340
	opcuaSoftwareCertID      = 346
	opcuaElementOperandID    = 594
	opcuaLiteralOperandID    = 597
	opcuaAttributeOperandID  = 600
	opcuaSimpleAttrOperandID = 603
	opcuaReadEventDetailsID  = 646
	opcuaReadRawDetailsID    = 649
	opcuaReadProcDetailsID   = 652
	opcuaReadAtTimeDetailsID = 655
	opcuaHistoryDataID       = 658
	opcuaHistoryEventID      = 661
	opcuaDataChangeFilterID  = 724
	opcuaEventFilterID       = 727
	opcuaAggregateFilterID   = 730
	opcuaEventFilterResultID = 736
	opcuaAggFilterResultID   = 739
	opcuaRedundantServerID   = 855
	opcuaServerStatusID      = 864
	opcuaServiceCounterID    = 873
	opcuaModelChangeID       = 879
	opcuaRangeID             = 886
	opcuaEUInformationID     = 889
	opcuaAnnotationID        = 893
	opcuaSemanticChangeID    = 899
	opcuaEnumValueTypeID     = 8251
	opcuaTimeZoneID          = 8917
	opcuaHistoryModifiedID   = 11227
	opcuaEndpointURLListID   = 11957
	opcuaAxisInformationID   = 12089
	opcuaXVTypeID            = 12090
	opcuaComplexNumberID     = 12181
	opcuaDoubleComplexID     = 12182
	opcuaTrustListID         = 12680
	opcuaOptionSetID         = 12765
)

// Binary encoding ids of structures that are parameters of the services
// and may also travel on their own.
const (
	opcuaRegisteredServerID = 434
	opcuaSignatureDataID    = 458
	opcuaViewDescriptionID  = 513
	opcuaBrowseDescID       = 516
	opcuaReferenceDescID    = 520
	opcuaBrowseResultID     = 524
	opcuaPathElementID      = 539
	opcuaPathResultID       = 551
	opcuaNodeTypeDescID     = 575
	opcuaContentFilterID    = 588
	opcuaFilterResultID     = 609
	opcuaReadValueIDID      = 628
	opcuaHistReadValueIDID  = 637
	opcuaCallResultID       = 709
	opcuaMonParamsID        = 742
	opcuaItemCreateID       = 745
	opcuaNotifMessageID     = 805
	opcuaAggregateConfigID  = 950
	opcuaSamplingDiagID     = 858
	opcuaServerDiagID       = 861
)

// Minimum encoded sizes of the structures that come in arrays.
const (
	opcuaMinSimpleAttrLen  = opcuaMinNodeIDLen + 3*opcuaUint32Len
	opcuaMinFilterElemLen  = 2 * opcuaUint32Len
	opcuaMinElemResultLen  = 3 * opcuaUint32Len
	opcuaMinModInfoLen     = opcuaUint64Len + 2*opcuaUint32Len
	opcuaMinEventFieldsLen = opcuaUint32Len
)

// OPCUAArgument describes a method argument (OPC 10000-3 §8.6), the value
// of the InputArguments and OutputArguments properties.
type OPCUAArgument struct {
	Name            string
	DataType        OPCUANodeID
	ValueRank       int32
	ArrayDimensions []uint32
	Description     OPCUALocalizedText
}

// OPCUARange is a Range (OPC 10000-8 §5.6.2), such as an EURange.
type OPCUARange struct {
	Low  float64
	High float64
}

// OPCUAEUInformation is an engineering unit (OPC 10000-8 §5.6.3).
type OPCUAEUInformation struct {
	NamespaceURI string
	UnitID       int32
	DisplayName  OPCUALocalizedText
	Description  OPCUALocalizedText
}

// OPCUAEnumValueType is one value of an enumeration (OPC 10000-3 §8.40).
type OPCUAEnumValueType struct {
	Value       int64
	DisplayName OPCUALocalizedText
	Description OPCUALocalizedText
}

// OPCUATimeZone is a TimeZoneDataType (OPC 10000-3 §8.31); Offset is in
// minutes from UTC.
type OPCUATimeZone struct {
	Offset                 int16
	DaylightSavingInOffset bool
}

// OPCUAStatusResult is a StatusCode and its diagnostics.
type OPCUAStatusResult struct {
	StatusCode     OPCUAStatusCode
	DiagnosticInfo OPCUADiagnosticInfo
}

// OPCUABuildInfo is a BuildInfo (OPC 10000-5 §12.4).
type OPCUABuildInfo struct {
	ProductURI       string
	ManufacturerName string
	ProductName      string
	SoftwareVersion  string
	BuildNumber      string
	BuildDate        time.Time
}

// OPCUAServerStatus is a ServerStatusDataType (OPC 10000-5 §12.10), the
// value of the ServerStatus variable.
type OPCUAServerStatus struct {
	StartTime           time.Time
	CurrentTime         time.Time
	State               uint32
	BuildInfo           OPCUABuildInfo
	SecondsTillShutdown uint32
	ShutdownReason      OPCUALocalizedText
}

// OPCUAServiceCounter is a ServiceCounterDataType (OPC 10000-5 §12.13).
type OPCUAServiceCounter struct {
	TotalCount uint32
	ErrorCount uint32
}

// OPCUARedundantServer is a RedundantServerDataType (OPC 10000-5 §12.5).
type OPCUARedundantServer struct {
	ServerID     string
	ServiceLevel uint8
	ServerState  uint32
}

// OPCUAModelChange is a ModelChangeStructureDataType (OPC 10000-5 §12.16).
type OPCUAModelChange struct {
	Affected     OPCUANodeID
	AffectedType OPCUANodeID
	Verb         uint8
}

// OPCUASemanticChange is a SemanticChangeStructureDataType (OPC 10000-5
// §12.17).
type OPCUASemanticChange struct {
	Affected     OPCUANodeID
	AffectedType OPCUANodeID
}

// OPCUAAnnotation is an Annotation of historical data (OPC 10000-11
// §6.6.6).
type OPCUAAnnotation struct {
	Message        string
	UserName       string
	AnnotationTime time.Time
}

// OPCUAAxisInformation is an AxisInformation (OPC 10000-8 §5.6.6).
type OPCUAAxisInformation struct {
	EngineeringUnits OPCUAEUInformation
	EURange          OPCUARange
	Title            OPCUALocalizedText
	AxisScaleType    uint32
	AxisSteps        []float64
}

// OPCUAXVType is a point of an XY array (OPC 10000-8 §5.6.8).
type OPCUAXVType struct {
	X     float64
	Value float32
}

// OPCUAComplexNumber is a ComplexNumberType (OPC 10000-8 §5.6.4).
type OPCUAComplexNumber struct {
	Real      float32
	Imaginary float32
}

// OPCUADoubleComplex is a DoubleComplexNumberType (OPC 10000-8 §5.6.5).
type OPCUADoubleComplex struct {
	Real      float64
	Imaginary float64
}

// OPCUASamplingDiagnostics is a SamplingIntervalDiagnosticsDataType
// (OPC 10000-5 §12.8).
type OPCUASamplingDiagnostics struct {
	// SamplingInterval is in milliseconds.
	SamplingInterval           float64
	MonitoredItemCount         uint32
	MaxMonitoredItemCount      uint32
	DisabledMonitoredItemCount uint32
}

// OPCUAServerDiagnostics is a ServerDiagnosticsSummaryDataType
// (OPC 10000-5 §12.9), the counters of a server.
type OPCUAServerDiagnostics struct {
	ServerViewCount               uint32
	CurrentSessionCount           uint32
	CumulatedSessionCount         uint32
	SecurityRejectedSessionCount  uint32
	RejectedSessionCount          uint32
	SessionTimeoutCount           uint32
	SessionAbortCount             uint32
	CurrentSubscriptionCount      uint32
	CumulatedSubscriptionCount    uint32
	PublishingIntervalCount       uint32
	SecurityRejectedRequestsCount uint32
	RejectedRequestsCount         uint32
}

// OPCUAEndpointURLList is an EndpointUrlListDataType (OPC 10000-5
// §12.19).
type OPCUAEndpointURLList struct {
	EndpointURLList []string
}

// OPCUAOptionSet is an OptionSet (OPC 10000-3 §8.39): a bit mask and
// the bits of it that are valid.
type OPCUAOptionSet struct {
	Value     []byte
	ValidBits []byte
}

// OPCUATrustList is a TrustListDataType (OPC 10000-12 §7.8.2.6): the
// DER certificates and CRLs a server trusts. SpecifiedLists is a bit
// mask of the lists present.
type OPCUATrustList struct {
	SpecifiedLists      uint32
	TrustedCertificates [][]byte
	TrustedCRLs         [][]byte
	IssuerCertificates  [][]byte
	IssuerCRLs          [][]byte
}

// OPCUADataChangeFilter is the filter of a monitored value (OPC 10000-4
// §7.22.2). Trigger is 0 Status, 1 StatusValue, 2 StatusValueTimestamp;
// DeadbandType is 0 None, 1 Absolute, 2 Percent.
type OPCUADataChangeFilter struct {
	Trigger       uint32
	DeadbandType  uint32
	DeadbandValue float64
}

// OPCUASimpleAttributeOperand names an attribute by a path of browse
// names from a type (OPC 10000-4 §7.7.4.5), as the select clauses of an
// EventFilter do.
type OPCUASimpleAttributeOperand struct {
	TypeDefinitionID OPCUANodeID
	BrowsePath       []OPCUAQualifiedName
	AttributeID      OPCUAAttributeID
	IndexRange       string
}

// OPCUAAttributeOperand names an attribute by a relative path from a
// node (OPC 10000-4 §7.7.4.4).
type OPCUAAttributeOperand struct {
	NodeID      OPCUANodeID
	Alias       string
	BrowsePath  []OPCUARelativePathElement
	AttributeID OPCUAAttributeID
	IndexRange  string
}

// OPCUAElementOperand refers to another element of the same
// ContentFilter (OPC 10000-4 §7.7.4.2).
type OPCUAElementOperand struct {
	Index uint32
}

// OPCUALiteralOperand is a literal value (OPC 10000-4 §7.7.4.3).
type OPCUALiteralOperand struct {
	Value OPCUAVariant
}

// OPCUAFilterOperator is a FilterOperator (OPC 10000-4 §7.7.3).
type OPCUAFilterOperator uint32

// OPCUAFilterOperator values.
const (
	OPCUAFilterEquals             OPCUAFilterOperator = 0
	OPCUAFilterIsNull             OPCUAFilterOperator = 1
	OPCUAFilterGreaterThan        OPCUAFilterOperator = 2
	OPCUAFilterLessThan           OPCUAFilterOperator = 3
	OPCUAFilterGreaterThanOrEqual OPCUAFilterOperator = 4
	OPCUAFilterLessThanOrEqual    OPCUAFilterOperator = 5
	OPCUAFilterLike               OPCUAFilterOperator = 6
	OPCUAFilterNot                OPCUAFilterOperator = 7
	OPCUAFilterBetween            OPCUAFilterOperator = 8
	OPCUAFilterInList             OPCUAFilterOperator = 9
	OPCUAFilterAnd                OPCUAFilterOperator = 10
	OPCUAFilterOr                 OPCUAFilterOperator = 11
	OPCUAFilterCast               OPCUAFilterOperator = 12
	OPCUAFilterInView             OPCUAFilterOperator = 13
	OPCUAFilterOfType             OPCUAFilterOperator = 14
	OPCUAFilterRelatedTo          OPCUAFilterOperator = 15
	OPCUAFilterBitwiseAnd         OPCUAFilterOperator = 16
	OPCUAFilterBitwiseOr          OPCUAFilterOperator = 17
)

var opcuaFilterOperatorNames = map[OPCUAFilterOperator]string{
	OPCUAFilterEquals:             "Equals",
	OPCUAFilterIsNull:             "IsNull",
	OPCUAFilterGreaterThan:        "GreaterThan",
	OPCUAFilterLessThan:           "LessThan",
	OPCUAFilterGreaterThanOrEqual: "GreaterThanOrEqual",
	OPCUAFilterLessThanOrEqual:    "LessThanOrEqual",
	OPCUAFilterLike:               "Like",
	OPCUAFilterNot:                "Not",
	OPCUAFilterBetween:            "Between",
	OPCUAFilterInList:             "InList",
	OPCUAFilterAnd:                "And",
	OPCUAFilterOr:                 "Or",
	OPCUAFilterCast:               "Cast",
	OPCUAFilterInView:             "InView",
	OPCUAFilterOfType:             "OfType",
	OPCUAFilterRelatedTo:          "RelatedTo",
	OPCUAFilterBitwiseAnd:         "BitwiseAnd",
	OPCUAFilterBitwiseOr:          "BitwiseOr",
}

// String returns the operator name.
func (o OPCUAFilterOperator) String() string { return opcuaName(opcuaFilterOperatorNames, o) }

// OPCUAContentFilterElement is one operator of a ContentFilter and its
// operands: each Value is an *OPCUAElementOperand, *OPCUALiteralOperand,
// *OPCUAAttributeOperand or *OPCUASimpleAttributeOperand.
type OPCUAContentFilterElement struct {
	FilterOperator OPCUAFilterOperator
	FilterOperands []OPCUAExtensionObject
}

// OPCUAContentFilter is a ContentFilter (OPC 10000-4 §7.7.1), the where
// clause of an EventFilter and the filter of a query.
type OPCUAContentFilter struct {
	Elements []OPCUAContentFilterElement
}

// OPCUAEventFilter selects the fields of the events to report and the
// events themselves (OPC 10000-4 §7.22.3).
type OPCUAEventFilter struct {
	SelectClauses []OPCUASimpleAttributeOperand
	WhereClause   OPCUAContentFilter
}

// OPCUAAggregateConfiguration tells how an aggregate is computed
// (OPC 10000-11 §6.4.4.2).
type OPCUAAggregateConfiguration struct {
	UseServerCapabilitiesDefaults bool
	TreatUncertainAsBad           bool
	PercentDataBad                uint8
	PercentDataGood               uint8
	UseSlopedExtrapolation        bool
}

// OPCUAAggregateFilter monitors an aggregate of a value (OPC 10000-4
// §7.22.4).
type OPCUAAggregateFilter struct {
	StartTime     time.Time
	AggregateType OPCUANodeID
	// ProcessingInterval is in milliseconds.
	ProcessingInterval     float64
	AggregateConfiguration OPCUAAggregateConfiguration
}

// OPCUAContentFilterElementResult is the status of one filter element.
type OPCUAContentFilterElementResult struct {
	StatusCode             OPCUAStatusCode
	OperandStatusCodes     []OPCUAStatusCode
	OperandDiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUAContentFilterResult is the status of a ContentFilter (OPC 10000-4
// §7.7.2).
type OPCUAContentFilterResult struct {
	ElementResults         []OPCUAContentFilterElementResult
	ElementDiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUAEventFilterResult is the status a server gives an EventFilter.
type OPCUAEventFilterResult struct {
	SelectClauseResults         []OPCUAStatusCode
	SelectClauseDiagnosticInfos []OPCUADiagnosticInfo
	WhereClauseResult           OPCUAContentFilterResult
}

// OPCUAAggregateFilterResult is what a server grants an AggregateFilter.
type OPCUAAggregateFilterResult struct {
	RevisedStartTime time.Time
	// RevisedProcessingInterval is in milliseconds.
	RevisedProcessingInterval     float64
	RevisedAggregateConfiguration OPCUAAggregateConfiguration
}

// OPCUAReadEventDetails reads the history of events (OPC 10000-11
// §6.4.2).
type OPCUAReadEventDetails struct {
	NumValuesPerNode uint32
	StartTime        time.Time
	EndTime          time.Time
	Filter           OPCUAEventFilter
}

// OPCUAReadRawModifiedDetails reads raw or modified values (OPC 10000-11
// §6.4.3).
type OPCUAReadRawModifiedDetails struct {
	IsReadModified   bool
	StartTime        time.Time
	EndTime          time.Time
	NumValuesPerNode uint32
	ReturnBounds     bool
}

// OPCUAReadProcessedDetails reads aggregates of the history
// (OPC 10000-11 §6.4.4).
type OPCUAReadProcessedDetails struct {
	StartTime time.Time
	EndTime   time.Time
	// ProcessingInterval is in milliseconds.
	ProcessingInterval     float64
	AggregateType          []OPCUANodeID
	AggregateConfiguration OPCUAAggregateConfiguration
}

// OPCUAReadAtTimeDetails reads the values at given times (OPC 10000-11
// §6.4.5).
type OPCUAReadAtTimeDetails struct {
	ReqTimes        []time.Time
	UseSimpleBounds bool
}

// OPCUAHistoryData is the history of a variable (OPC 10000-11 §6.5.2).
type OPCUAHistoryData struct {
	DataValues []OPCUADataValue
}

// OPCUAModificationInfo tells who changed a historical value and how.
// UpdateType is 1 Insert, 2 Replace, 3 Update, 4 Delete.
type OPCUAModificationInfo struct {
	ModificationTime time.Time
	UpdateType       uint32
	UserName         string
}

// OPCUAHistoryModifiedData is the modified history of a variable
// (OPC 10000-11 §6.5.3).
type OPCUAHistoryModifiedData struct {
	DataValues        []OPCUADataValue
	ModificationInfos []OPCUAModificationInfo
}

// OPCUAHistoryEventFieldList is the selected fields of one past event.
type OPCUAHistoryEventFieldList struct {
	EventFields []OPCUAVariant
}

// OPCUAHistoryEvent is the history of events (OPC 10000-11 §6.5.4).
type OPCUAHistoryEvent struct {
	Events []OPCUAHistoryEventFieldList
}

// decodeOPCUAExtBody decodes the body of a known structure that sits
// depth ExtensionObjects deep. The probe makes sure the body parses to
// its last byte before the decode allocates anything for it.
func decodeOPCUAExtBody(e OPCUAExtensionObject, depth int) interface{} {
	id, ok := e.binaryTypeID()
	if !ok || depth >= opcuaMaxExtDepth {
		return nil
	}

	probe := opcuaReader{b: e.Body, mode: opcuaReadProbe, extDepth: depth + 1}
	probe.extBody(id)
	if probe.err != nil || probe.remaining() != 0 {
		return nil
	}

	r := opcuaReader{b: e.Body, extDepth: depth + 1}
	return r.extBody(id)
}

// opcuaBoxed returns a pointer to v, or nil when r only probes or has
// failed. The copy is allocated here so that a probe allocates nothing.
func opcuaBoxed[T any](r *opcuaReader, v T) interface{} {
	if r.err != nil || r.mode == opcuaReadProbe {
		return nil
	}
	p := new(T)
	*p = v
	return p
}

// extBody reads the structure whose binary encoding id is id. An unknown
// id is an error, which leaves the body encoded.
func (r *opcuaReader) extBody(id uint32) interface{} {
	if v, ok := r.extFilter(id); ok {
		return v
	}
	if v, ok := r.extHistory(id); ok {
		return v
	}
	if v, ok := r.extNodeAttributes(id); ok {
		return v
	}
	if v, ok := r.extService(id); ok {
		return v
	}
	if v, ok := r.extCommon(id); ok {
		return v
	}
	if v, ok := r.extParameter(id); ok {
		return v
	}
	if v, ok := r.extStructs(id); ok {
		return v
	}
	r.err = ErrOPCUAMalformed
	return nil
}

// extFilter reads the monitoring filters, their results and the
// ContentFilter operands.
func (r *opcuaReader) extFilter(id uint32) (interface{}, bool) {
	switch id {
	case opcuaDataChangeFilterID:
		return opcuaBoxed(r, OPCUADataChangeFilter{Trigger: r.u32(), DeadbandType: r.u32(), DeadbandValue: r.f64()}), true
	case opcuaEventFilterID:
		return opcuaBoxed(r, r.eventFilter()), true
	case opcuaAggregateFilterID:
		return opcuaBoxed(r, OPCUAAggregateFilter{
			StartTime:              r.dateTime(),
			AggregateType:          r.nodeID(),
			ProcessingInterval:     r.f64(),
			AggregateConfiguration: r.aggregateConfig(),
		}), true
	case opcuaEventFilterResultID:
		return opcuaBoxed(r, OPCUAEventFilterResult{
			SelectClauseResults:         r.statusCodes(),
			SelectClauseDiagnosticInfos: r.diagnosticInfos(),
			WhereClauseResult:           r.contentFilterResult(),
		}), true
	case opcuaAggFilterResultID:
		return opcuaBoxed(r, OPCUAAggregateFilterResult{
			RevisedStartTime:              r.dateTime(),
			RevisedProcessingInterval:     r.f64(),
			RevisedAggregateConfiguration: r.aggregateConfig(),
		}), true
	case opcuaElementOperandID:
		return opcuaBoxed(r, OPCUAElementOperand{Index: r.u32()}), true
	case opcuaLiteralOperandID:
		return opcuaBoxed(r, OPCUALiteralOperand{Value: r.variant(0)}), true
	case opcuaAttributeOperandID:
		return opcuaBoxed(r, OPCUAAttributeOperand{
			NodeID:      r.nodeID(),
			Alias:       r.str(),
			BrowsePath:  opcuaArray(r, opcuaMinPathElemLen, r.pathElement),
			AttributeID: OPCUAAttributeID(r.u32()),
			IndexRange:  r.str(),
		}), true
	case opcuaSimpleAttrOperandID:
		return opcuaBoxed(r, r.simpleAttrOperand()), true
	}
	return nil, false
}

// extHistory reads the HistoryRead details and the history they return.
func (r *opcuaReader) extHistory(id uint32) (interface{}, bool) {
	switch id {
	case opcuaReadEventDetailsID:
		return opcuaBoxed(r, OPCUAReadEventDetails{
			NumValuesPerNode: r.u32(),
			StartTime:        r.dateTime(),
			EndTime:          r.dateTime(),
			Filter:           r.eventFilter(),
		}), true
	case opcuaReadRawDetailsID:
		return opcuaBoxed(r, OPCUAReadRawModifiedDetails{
			IsReadModified:   r.boolean(),
			StartTime:        r.dateTime(),
			EndTime:          r.dateTime(),
			NumValuesPerNode: r.u32(),
			ReturnBounds:     r.boolean(),
		}), true
	case opcuaReadProcDetailsID:
		return opcuaBoxed(r, OPCUAReadProcessedDetails{
			StartTime:              r.dateTime(),
			EndTime:                r.dateTime(),
			ProcessingInterval:     r.f64(),
			AggregateType:          r.nodeIDs(),
			AggregateConfiguration: r.aggregateConfig(),
		}), true
	case opcuaReadAtTimeDetailsID:
		return opcuaBoxed(r, OPCUAReadAtTimeDetails{ReqTimes: r.dateTimes(), UseSimpleBounds: r.boolean()}), true
	case opcuaHistoryDataID:
		return opcuaBoxed(r, OPCUAHistoryData{DataValues: r.dataValues(0)}), true
	case opcuaHistoryModifiedID:
		return opcuaBoxed(r, OPCUAHistoryModifiedData{
			DataValues: r.dataValues(0),
			ModificationInfos: opcuaArray(r, opcuaMinModInfoLen, func() OPCUAModificationInfo {
				return OPCUAModificationInfo{ModificationTime: r.dateTime(), UpdateType: r.u32(), UserName: r.str()}
			}),
		}), true
	case opcuaHistoryEventID:
		return opcuaBoxed(r, OPCUAHistoryEvent{Events: r.historyEvents()}), true
	}
	return r.extHistoryUpdate(id)
}

// extService reads the structures the session and subscription services
// carry: identity tokens, notifications and discovery configuration.
func (r *opcuaReader) extService(id uint32) (interface{}, bool) {
	if typ, ok := opcuaIdentityTokenTypes[id]; ok {
		return opcuaBoxed(r, r.identityToken(typ)), true
	}

	switch id {
	case opcuaDataChangeNotifID:
		return opcuaBoxed(r, OPCUADataChangeNotification{
			MonitoredItems: opcuaArray(r, opcuaMinItemNotifLen, func() OPCUAMonitoredItemNotif {
				return OPCUAMonitoredItemNotif{ClientHandle: r.u32(), Value: r.dataValue(0)}
			}),
			DiagnosticInfos: r.diagnosticInfos(),
		}), true
	case opcuaEventNotifListID:
		return opcuaBoxed(r, OPCUAEventNotificationList{
			Events: opcuaArray(r, opcuaMinEventListLen, func() OPCUAEventFieldList {
				return OPCUAEventFieldList{ClientHandle: r.u32(), EventFields: r.variants(0)}
			}),
		}), true
	case opcuaStatusChangeNotifID:
		return opcuaBoxed(r, OPCUAStatusChangeNotification{Status: r.statusCode(), DiagnosticInfo: r.diagnosticInfo(0)}), true
	case opcuaMdnsConfigID:
		return opcuaBoxed(r, OPCUAMdnsDiscoveryConfig{MdnsServerName: r.str(), ServerCapabilities: r.strings()}), true
	}
	return nil, false
}

// extCommon reads the structures that are values of well-known
// variables and properties.
func (r *opcuaReader) extCommon(id uint32) (interface{}, bool) {
	switch id {
	case opcuaArgumentID:
		return opcuaBoxed(r, r.argument()), true
	case opcuaRangeID:
		return opcuaBoxed(r, r.valueRange()), true
	case opcuaEUInformationID:
		return opcuaBoxed(r, r.euInformation()), true
	case opcuaEnumValueTypeID:
		return opcuaBoxed(r, OPCUAEnumValueType{Value: r.i64(), DisplayName: r.localizedText(), Description: r.localizedText()}), true
	case opcuaTimeZoneID:
		return opcuaBoxed(r, OPCUATimeZone{Offset: r.i16(), DaylightSavingInOffset: r.boolean()}), true
	case opcuaStatusResultID:
		return opcuaBoxed(r, OPCUAStatusResult{StatusCode: r.statusCode(), DiagnosticInfo: r.diagnosticInfo(0)}), true
	case opcuaBuildInfoID:
		return opcuaBoxed(r, r.buildInfo()), true
	case opcuaServerStatusID:
		return opcuaBoxed(r, OPCUAServerStatus{
			StartTime:           r.dateTime(),
			CurrentTime:         r.dateTime(),
			State:               r.u32(),
			BuildInfo:           r.buildInfo(),
			SecondsTillShutdown: r.u32(),
			ShutdownReason:      r.localizedText(),
		}), true
	case opcuaAppDescriptionID:
		return opcuaBoxed(r, r.applicationDescription()), true
	case opcuaEndpointDescID:
		return opcuaBoxed(r, r.endpointDescription()), true
	case opcuaUserTokenPolicyID:
		return opcuaBoxed(r, r.userTokenPolicy()), true
	case opcuaSoftwareCertID:
		return opcuaBoxed(r, OPCUASignedSoftwareCertificate{CertificateData: r.byteString(), Signature: r.byteString()}), true
	}
	return r.extData(id)
}

// extData reads the small data structures of OPC 10000-5 and 10000-8.
func (r *opcuaReader) extData(id uint32) (interface{}, bool) {
	switch id {
	case opcuaServiceCounterID:
		return opcuaBoxed(r, OPCUAServiceCounter{TotalCount: r.u32(), ErrorCount: r.u32()}), true
	case opcuaRedundantServerID:
		return opcuaBoxed(r, OPCUARedundantServer{ServerID: r.str(), ServiceLevel: r.u8(), ServerState: r.u32()}), true
	case opcuaModelChangeID:
		return opcuaBoxed(r, OPCUAModelChange{Affected: r.nodeID(), AffectedType: r.nodeID(), Verb: r.u8()}), true
	case opcuaSemanticChangeID:
		return opcuaBoxed(r, OPCUASemanticChange{Affected: r.nodeID(), AffectedType: r.nodeID()}), true
	case opcuaAnnotationID:
		return opcuaBoxed(r, OPCUAAnnotation{Message: r.str(), UserName: r.str(), AnnotationTime: r.dateTime()}), true
	case opcuaAxisInformationID:
		return opcuaBoxed(r, OPCUAAxisInformation{
			EngineeringUnits: r.euInformation(),
			EURange:          r.valueRange(),
			Title:            r.localizedText(),
			AxisScaleType:    r.u32(),
			AxisSteps:        opcuaArray(r, opcuaUint64Len, r.f64),
		}), true
	case opcuaXVTypeID:
		return opcuaBoxed(r, OPCUAXVType{X: r.f64(), Value: r.f32()}), true
	case opcuaComplexNumberID:
		return opcuaBoxed(r, OPCUAComplexNumber{Real: r.f32(), Imaginary: r.f32()}), true
	case opcuaDoubleComplexID:
		return opcuaBoxed(r, OPCUADoubleComplex{Real: r.f64(), Imaginary: r.f64()}), true
	case opcuaSamplingDiagID:
		return opcuaBoxed(r, OPCUASamplingDiagnostics{
			SamplingInterval:           r.f64(),
			MonitoredItemCount:         r.u32(),
			MaxMonitoredItemCount:      r.u32(),
			DisabledMonitoredItemCount: r.u32(),
		}), true
	case opcuaServerDiagID:
		return opcuaBoxed(r, r.serverDiagnostics()), true
	case opcuaEndpointURLListID:
		return opcuaBoxed(r, OPCUAEndpointURLList{EndpointURLList: r.strings()}), true
	case opcuaOptionSetID:
		return opcuaBoxed(r, OPCUAOptionSet{Value: r.byteString(), ValidBits: r.byteString()}), true
	case opcuaTrustListID:
		return opcuaBoxed(r, OPCUATrustList{
			SpecifiedLists:      r.u32(),
			TrustedCertificates: r.byteStrings(),
			TrustedCRLs:         r.byteStrings(),
			IssuerCertificates:  r.byteStrings(),
			IssuerCRLs:          r.byteStrings(),
		}), true
	}
	return nil, false
}

// extParameter reads the service parameter structures that have a
// binary encoding id of their own.
func (r *opcuaReader) extParameter(id uint32) (interface{}, bool) {
	switch id {
	case opcuaRegisteredServerID:
		return opcuaBoxed(r, r.registeredServer()), true
	case opcuaSignatureDataID:
		return opcuaBoxed(r, r.signatureData()), true
	case opcuaViewDescriptionID:
		return opcuaBoxed(r, r.viewDescription()), true
	case opcuaBrowseDescID:
		return opcuaBoxed(r, r.browseDescription()), true
	case opcuaReferenceDescID:
		return opcuaBoxed(r, r.referenceDescription()), true
	case opcuaBrowseResultID:
		return opcuaBoxed(r, r.browseResult()), true
	case opcuaPathElementID:
		return opcuaBoxed(r, r.pathElement()), true
	case opcuaPathResultID:
		return opcuaBoxed(r, r.pathResult()), true
	case opcuaNodeTypeDescID:
		return opcuaBoxed(r, r.nodeTypeDescription()), true
	case opcuaContentFilterID:
		return opcuaBoxed(r, r.contentFilter()), true
	case opcuaFilterResultID:
		return opcuaBoxed(r, r.contentFilterResult()), true
	case opcuaReadValueIDID:
		return opcuaBoxed(r, r.readValueID()), true
	case opcuaHistReadValueIDID:
		return opcuaBoxed(r, r.historyReadValueID()), true
	case opcuaCallResultID:
		return opcuaBoxed(r, r.callResult()), true
	case opcuaMonParamsID:
		return opcuaBoxed(r, r.monitoringParams()), true
	case opcuaItemCreateID:
		return opcuaBoxed(r, r.itemCreate()), true
	case opcuaNotifMessageID:
		return opcuaBoxed(r, r.notificationMessage()), true
	case opcuaAggregateConfigID:
		return opcuaBoxed(r, r.aggregateConfig()), true
	}
	return nil, false
}

func (r *opcuaReader) serverDiagnostics() OPCUAServerDiagnostics {
	return OPCUAServerDiagnostics{
		ServerViewCount:               r.u32(),
		CurrentSessionCount:           r.u32(),
		CumulatedSessionCount:         r.u32(),
		SecurityRejectedSessionCount:  r.u32(),
		RejectedSessionCount:          r.u32(),
		SessionTimeoutCount:           r.u32(),
		SessionAbortCount:             r.u32(),
		CurrentSubscriptionCount:      r.u32(),
		CumulatedSubscriptionCount:    r.u32(),
		PublishingIntervalCount:       r.u32(),
		SecurityRejectedRequestsCount: r.u32(),
		RejectedRequestsCount:         r.u32(),
	}
}

func (r *opcuaReader) dateTimes() []time.Time { return opcuaArray(r, opcuaUint64Len, r.dateTime) }

func (r *opcuaReader) valueRange() OPCUARange { return OPCUARange{Low: r.f64(), High: r.f64()} }

func (r *opcuaReader) euInformation() OPCUAEUInformation {
	return OPCUAEUInformation{
		NamespaceURI: r.str(),
		UnitID:       r.i32(),
		DisplayName:  r.localizedText(),
		Description:  r.localizedText(),
	}
}

func (r *opcuaReader) buildInfo() OPCUABuildInfo {
	return OPCUABuildInfo{
		ProductURI:       r.str(),
		ManufacturerName: r.str(),
		ProductName:      r.str(),
		SoftwareVersion:  r.str(),
		BuildNumber:      r.str(),
		BuildDate:        r.dateTime(),
	}
}

func (r *opcuaReader) aggregateConfig() OPCUAAggregateConfiguration {
	return OPCUAAggregateConfiguration{
		UseServerCapabilitiesDefaults: r.boolean(),
		TreatUncertainAsBad:           r.boolean(),
		PercentDataBad:                r.u8(),
		PercentDataGood:               r.u8(),
		UseSlopedExtrapolation:        r.boolean(),
	}
}

func (r *opcuaReader) simpleAttrOperand() OPCUASimpleAttributeOperand {
	return OPCUASimpleAttributeOperand{
		TypeDefinitionID: r.nodeID(),
		BrowsePath:       opcuaArray(r, opcuaMinQNameLen, r.qualifiedName),
		AttributeID:      OPCUAAttributeID(r.u32()),
		IndexRange:       r.str(),
	}
}

// contentFilter reads a ContentFilter; the operands are ExtensionObjects
// and decode into their Value.
func (r *opcuaReader) contentFilter() OPCUAContentFilter {
	return OPCUAContentFilter{Elements: opcuaArray(r, opcuaMinFilterElemLen, func() OPCUAContentFilterElement {
		return OPCUAContentFilterElement{
			FilterOperator: OPCUAFilterOperator(r.u32()),
			FilterOperands: opcuaArray(r, opcuaMinExtObjLen, r.extensionObject),
		}
	})}
}

func (r *opcuaReader) eventFilter() OPCUAEventFilter {
	return OPCUAEventFilter{
		SelectClauses: opcuaArray(r, opcuaMinSimpleAttrLen, r.simpleAttrOperand),
		WhereClause:   r.contentFilter(),
	}
}

func (r *opcuaReader) contentFilterResult() OPCUAContentFilterResult {
	return OPCUAContentFilterResult{
		ElementResults: opcuaArray(r, opcuaMinElemResultLen, func() OPCUAContentFilterElementResult {
			return OPCUAContentFilterElementResult{
				StatusCode:             r.statusCode(),
				OperandStatusCodes:     r.statusCodes(),
				OperandDiagnosticInfos: r.diagnosticInfos(),
			}
		}),
		ElementDiagnosticInfos: r.diagnosticInfos(),
	}
}

func (r *opcuaReader) historyEvents() []OPCUAHistoryEventFieldList {
	return opcuaArray(r, opcuaMinEventFieldsLen, func() OPCUAHistoryEventFieldList {
		return OPCUAHistoryEventFieldList{EventFields: r.variants(0)}
	})
}
