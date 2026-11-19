// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA node management, query and history update services
// (OPC 10000-4 §5.7, §5.9, §5.10.5).
//
//	AddNodes ─ AddNodesItem ─ NodeAttributes ─┬─ *OPCUAObjectAttributes
//	           (parent, name, class)          ├─ *OPCUAVariableAttributes
//	                                          └─ ... one type per node class
//	HistoryUpdate ─ details ─┬─ *OPCUAUpdateDataDetails
//	                         ├─ *OPCUAUpdateEventDetails
//	                         └─ *OPCUADelete...Details

package layers

import "time"

// Binary encoding ids of the node attributes and of the history update
// details (NodeIds.csv).
const (
	opcuaNodeAttrsID       = 351
	opcuaObjectAttrsID     = 354
	opcuaVariableAttrsID   = 357
	opcuaMethodAttrsID     = 360
	opcuaObjectTypeAttrsID = 363
	opcuaVarTypeAttrsID    = 366
	opcuaRefTypeAttrsID    = 369
	opcuaDataTypeAttrsID   = 372
	opcuaViewAttrsID       = 375
	opcuaAddNodesItemID    = 378
	opcuaAddRefsItemID     = 381
	opcuaDelRefsItemID     = 387
	opcuaGenericAttrsID    = 17611
	opcuaHistUpdDetailsID  = 679
	opcuaUpdateDataID      = 682
	opcuaUpdateEventID     = 685
	opcuaDeleteRawID       = 688
	opcuaDeleteAtTimeID    = 691
	opcuaDeleteEventID     = 694
	opcuaUpdateStructureID = 11300
)

// Minimum encoded sizes of the node management and query structures.
const (
	opcuaMinAddNodesLen    = 4*opcuaMinNodeIDLen + opcuaMinQNameLen + opcuaUint32Len + opcuaMinExtObjLen
	opcuaMinAddNodesResLen = opcuaUint32Len + opcuaMinNodeIDLen
	opcuaMinAddRefLen      = 3*opcuaMinNodeIDLen + opcuaUint8Len + 2*opcuaUint32Len
	opcuaMinDelNodeLen     = opcuaMinNodeIDLen + opcuaUint8Len
	opcuaMinDelRefLen      = 3*opcuaMinNodeIDLen + 2*opcuaUint8Len
	opcuaMinNodeTypeLen    = opcuaMinNodeIDLen + opcuaUint8Len + opcuaUint32Len
	opcuaMinQueryDataLen   = 3 * opcuaUint32Len
	opcuaMinDataSetLen     = 2*opcuaMinNodeIDLen + opcuaUint32Len
	opcuaMinParsingResLen  = 3 * opcuaUint32Len
	opcuaMinHistUpdResLen  = 3 * opcuaUint32Len
	opcuaMinGenericAttrLen = opcuaUint32Len + opcuaMinMaskedLen
)

// OPCUANodeAttributes are the attributes every node class has
// (OPC 10000-4 §7.24.1). SpecifiedAttributes is a bit mask of the
// attributes the sender set.
type OPCUANodeAttributes struct {
	SpecifiedAttributes uint32
	DisplayName         OPCUALocalizedText
	Description         OPCUALocalizedText
	WriteMask           uint32
	UserWriteMask       uint32
}

// OPCUAObjectAttributes are the attributes of an Object node.
type OPCUAObjectAttributes struct {
	OPCUANodeAttributes
	EventNotifier uint8
}

// OPCUAVariableAttributes are the attributes of a Variable node.
type OPCUAVariableAttributes struct {
	OPCUANodeAttributes
	Value           OPCUAVariant
	DataType        OPCUANodeID
	ValueRank       int32
	ArrayDimensions []uint32
	AccessLevel     uint8
	UserAccessLevel uint8
	// MinimumSamplingInterval is in milliseconds.
	MinimumSamplingInterval float64
	Historizing             bool
}

// OPCUAMethodAttributes are the attributes of a Method node.
type OPCUAMethodAttributes struct {
	OPCUANodeAttributes
	Executable     bool
	UserExecutable bool
}

// OPCUAObjectTypeAttributes are the attributes of an ObjectType node.
type OPCUAObjectTypeAttributes struct {
	OPCUANodeAttributes
	IsAbstract bool
}

// OPCUAVariableTypeAttributes are the attributes of a VariableType node.
type OPCUAVariableTypeAttributes struct {
	OPCUANodeAttributes
	Value           OPCUAVariant
	DataType        OPCUANodeID
	ValueRank       int32
	ArrayDimensions []uint32
	IsAbstract      bool
}

// OPCUAReferenceTypeAttributes are the attributes of a ReferenceType
// node.
type OPCUAReferenceTypeAttributes struct {
	OPCUANodeAttributes
	IsAbstract  bool
	Symmetric   bool
	InverseName OPCUALocalizedText
}

// OPCUADataTypeAttributes are the attributes of a DataType node.
type OPCUADataTypeAttributes struct {
	OPCUANodeAttributes
	IsAbstract bool
}

// OPCUAViewAttributes are the attributes of a View node.
type OPCUAViewAttributes struct {
	OPCUANodeAttributes
	ContainsNoLoops bool
	EventNotifier   uint8
}

// OPCUAGenericAttributeValue is one attribute of GenericAttributes.
type OPCUAGenericAttributeValue struct {
	AttributeID OPCUAAttributeID
	Value       OPCUAVariant
}

// OPCUAGenericAttributes lists attributes by id, for any node class.
type OPCUAGenericAttributes struct {
	OPCUANodeAttributes
	AttributeValues []OPCUAGenericAttributeValue
}

// OPCUAAddNodesItem is one node to add (OPC 10000-4 §5.7.2). The Value of
// NodeAttributes is a pointer to the attributes of its node class, such
// as *OPCUAVariableAttributes.
type OPCUAAddNodesItem struct {
	ParentNodeID       OPCUANodeID
	ReferenceTypeID    OPCUANodeID
	RequestedNewNodeID OPCUANodeID
	BrowseName         OPCUAQualifiedName
	NodeClass          OPCUANodeClass
	NodeAttributes     OPCUAExtensionObject
	TypeDefinition     OPCUANodeID
}

// OPCUAAddNodesRequest is the AddNodes request.
type OPCUAAddNodesRequest struct {
	NodesToAdd []OPCUAAddNodesItem
}

// OPCUAAddNodesResult is the result of adding one node.
type OPCUAAddNodesResult struct {
	StatusCode  OPCUAStatusCode
	AddedNodeID OPCUANodeID
}

// OPCUAAddNodesResponse is the AddNodes response.
type OPCUAAddNodesResponse struct {
	Results         []OPCUAAddNodesResult
	DiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUAAddReferencesItem is one reference to add (OPC 10000-4 §5.7.3).
type OPCUAAddReferencesItem struct {
	SourceNodeID    OPCUANodeID
	ReferenceTypeID OPCUANodeID
	IsForward       bool
	TargetServerURI string
	TargetNodeID    OPCUANodeID
	TargetNodeClass OPCUANodeClass
}

// OPCUAAddReferencesRequest is the AddReferences request.
type OPCUAAddReferencesRequest struct {
	ReferencesToAdd []OPCUAAddReferencesItem
}

// OPCUADeleteNodesItem is one node to delete (OPC 10000-4 §5.7.4).
type OPCUADeleteNodesItem struct {
	NodeID                 OPCUANodeID
	DeleteTargetReferences bool
}

// OPCUADeleteNodesRequest is the DeleteNodes request.
type OPCUADeleteNodesRequest struct {
	NodesToDelete []OPCUADeleteNodesItem
}

// OPCUADeleteReferencesItem is one reference to delete (OPC 10000-4
// §5.7.5).
type OPCUADeleteReferencesItem struct {
	SourceNodeID        OPCUANodeID
	ReferenceTypeID     OPCUANodeID
	IsForward           bool
	TargetNodeID        OPCUANodeID
	DeleteBidirectional bool
}

// OPCUADeleteReferencesRequest is the DeleteReferences request.
type OPCUADeleteReferencesRequest struct {
	ReferencesToDelete []OPCUADeleteReferencesItem
}

// OPCUAQueryDataDescription names an attribute a query returns, by a
// path from the node type.
type OPCUAQueryDataDescription struct {
	RelativePath []OPCUARelativePathElement
	AttributeID  OPCUAAttributeID
	IndexRange   string
}

// OPCUANodeTypeDescription is one type of node a query looks for.
type OPCUANodeTypeDescription struct {
	TypeDefinitionNode OPCUANodeID
	IncludeSubTypes    bool
	DataToReturn       []OPCUAQueryDataDescription
}

// OPCUAQueryFirstRequest is the QueryFirst request (OPC 10000-4 §5.9.3).
type OPCUAQueryFirstRequest struct {
	View                  OPCUAViewDescription
	NodeTypes             []OPCUANodeTypeDescription
	Filter                OPCUAContentFilter
	MaxDataSetsToReturn   uint32
	MaxReferencesToReturn uint32
}

// OPCUAQueryDataSet is the data of one node a query found.
type OPCUAQueryDataSet struct {
	NodeID             OPCUANodeID
	TypeDefinitionNode OPCUANodeID
	Values             []OPCUAVariant
}

// OPCUAParsingResult is the status of one node type of a query.
type OPCUAParsingResult struct {
	StatusCode          OPCUAStatusCode
	DataStatusCodes     []OPCUAStatusCode
	DataDiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUAQueryFirstResponse is the QueryFirst response.
type OPCUAQueryFirstResponse struct {
	QueryDataSets     []OPCUAQueryDataSet
	ContinuationPoint []byte
	ParsingResults    []OPCUAParsingResult
	DiagnosticInfos   []OPCUADiagnosticInfo
	FilterResult      OPCUAContentFilterResult
}

// OPCUAQueryNextRequest is the QueryNext request (OPC 10000-4 §5.9.4).
type OPCUAQueryNextRequest struct {
	ReleaseContinuationPoint bool
	ContinuationPoint        []byte
}

// OPCUAQueryNextResponse is the QueryNext response.
type OPCUAQueryNextResponse struct {
	QueryDataSets            []OPCUAQueryDataSet
	RevisedContinuationPoint []byte
}

// OPCUAHistoryUpdateDetails is the base of the history update details:
// the node alone.
type OPCUAHistoryUpdateDetails struct {
	NodeID OPCUANodeID
}

// OPCUAUpdateDataDetails inserts or replaces historical values
// (OPC 10000-11 §6.8.2); it is also the form of
// UpdateStructureDataDetails. PerformInsertReplace is 1 Insert,
// 2 Replace, 3 Update, 4 Remove.
type OPCUAUpdateDataDetails struct {
	NodeID               OPCUANodeID
	PerformInsertReplace uint32
	UpdateValues         []OPCUADataValue
}

// OPCUAUpdateEventDetails inserts or replaces historical events
// (OPC 10000-11 §6.8.4).
type OPCUAUpdateEventDetails struct {
	NodeID               OPCUANodeID
	PerformInsertReplace uint32
	Filter               OPCUAEventFilter
	EventData            []OPCUAHistoryEventFieldList
}

// OPCUADeleteRawModifiedDetails deletes the values of a time range
// (OPC 10000-11 §6.8.5).
type OPCUADeleteRawModifiedDetails struct {
	NodeID           OPCUANodeID
	IsDeleteModified bool
	StartTime        time.Time
	EndTime          time.Time
}

// OPCUADeleteAtTimeDetails deletes the values at given times
// (OPC 10000-11 §6.8.6).
type OPCUADeleteAtTimeDetails struct {
	NodeID   OPCUANodeID
	ReqTimes []time.Time
}

// OPCUADeleteEventDetails deletes events by id (OPC 10000-11 §6.8.7).
type OPCUADeleteEventDetails struct {
	NodeID   OPCUANodeID
	EventIDs [][]byte
}

// OPCUAHistoryUpdateRequest is the HistoryUpdate request (OPC 10000-4
// §5.10.5). The Value of each entry is a pointer to one of the update or
// delete details, such as *OPCUAUpdateDataDetails.
type OPCUAHistoryUpdateRequest struct {
	HistoryUpdateDetails []OPCUAExtensionObject
}

// OPCUAHistoryUpdateResult is the result of one history update.
type OPCUAHistoryUpdateResult struct {
	StatusCode       OPCUAStatusCode
	OperationResults []OPCUAStatusCode
	DiagnosticInfos  []OPCUADiagnosticInfo
}

// OPCUAHistoryUpdateResponse is the HistoryUpdate response.
type OPCUAHistoryUpdateResponse struct {
	Results         []OPCUAHistoryUpdateResult
	DiagnosticInfos []OPCUADiagnosticInfo
}

// decodeNodeMgmt reads the node management, query and history update
// parameters.
func (s *OPCUAService) decodeNodeMgmt(r *opcuaReader) {
	switch s.ID {
	case OPCUAServiceAddNodesRequest:
		s.AddNodesRequest = &OPCUAAddNodesRequest{NodesToAdd: opcuaArray(r, opcuaMinAddNodesLen, r.addNodesItem)}
	case OPCUAServiceAddNodesResponse:
		s.AddNodesResponse = r.addNodesResponse()
	case OPCUAServiceAddReferencesRequest:
		s.AddReferencesRequest = &OPCUAAddReferencesRequest{ReferencesToAdd: opcuaArray(r, opcuaMinAddRefLen, r.addReferencesItem)}
	case OPCUAServiceAddReferencesResponse:
		s.AddReferencesResponse = r.resultsPtr()
	case OPCUAServiceDeleteNodesRequest:
		s.DeleteNodesRequest = r.deleteNodesRequest()
	case OPCUAServiceDeleteNodesResponse:
		s.DeleteNodesResponse = r.resultsPtr()
	case OPCUAServiceDeleteReferencesRequest:
		s.DeleteReferencesRequest = r.deleteRefsRequest()
	case OPCUAServiceDeleteReferencesResponse:
		s.DeleteReferencesResponse = r.resultsPtr()
	case OPCUAServiceQueryFirstRequest:
		s.QueryFirstRequest = r.queryFirstRequest()
	case OPCUAServiceQueryFirstResponse:
		s.QueryFirstResponse = r.queryFirstResponse()
	case OPCUAServiceQueryNextRequest:
		s.QueryNextRequest = &OPCUAQueryNextRequest{ReleaseContinuationPoint: r.boolean(), ContinuationPoint: r.byteString()}
	case OPCUAServiceQueryNextResponse:
		s.QueryNextResponse = &OPCUAQueryNextResponse{QueryDataSets: r.queryDataSets(), RevisedContinuationPoint: r.byteString()}
	case OPCUAServiceHistoryUpdateRequest:
		s.HistoryUpdateRequest = &OPCUAHistoryUpdateRequest{
			HistoryUpdateDetails: opcuaArray(r, opcuaMinExtObjLen, r.extensionObject),
		}
	case OPCUAServiceHistoryUpdateResponse:
		s.HistoryUpdateResponse = r.historyUpdateResponse()
	}
}

func (r *opcuaReader) nodeAttributes() OPCUANodeAttributes {
	return OPCUANodeAttributes{
		SpecifiedAttributes: r.u32(),
		DisplayName:         r.localizedText(),
		Description:         r.localizedText(),
		WriteMask:           r.u32(),
		UserWriteMask:       r.u32(),
	}
}

// extNodeAttributes reads the attributes of one node class.
func (r *opcuaReader) extNodeAttributes(id uint32) (interface{}, bool) {
	switch id {
	case opcuaNodeAttrsID:
		return opcuaBoxed(r, r.nodeAttributes()), true
	case opcuaAddNodesItemID:
		return opcuaBoxed(r, r.addNodesItem()), true
	case opcuaAddRefsItemID:
		return opcuaBoxed(r, r.addReferencesItem()), true
	case opcuaDelRefsItemID:
		return opcuaBoxed(r, r.deleteRefsItem()), true
	case opcuaObjectAttrsID:
		return opcuaBoxed(r, OPCUAObjectAttributes{OPCUANodeAttributes: r.nodeAttributes(), EventNotifier: r.u8()}), true
	case opcuaVariableAttrsID:
		return opcuaBoxed(r, OPCUAVariableAttributes{
			OPCUANodeAttributes:     r.nodeAttributes(),
			Value:                   r.variant(0),
			DataType:                r.nodeID(),
			ValueRank:               r.i32(),
			ArrayDimensions:         r.u32s(),
			AccessLevel:             r.u8(),
			UserAccessLevel:         r.u8(),
			MinimumSamplingInterval: r.f64(),
			Historizing:             r.boolean(),
		}), true
	case opcuaMethodAttrsID:
		return opcuaBoxed(r, OPCUAMethodAttributes{
			OPCUANodeAttributes: r.nodeAttributes(),
			Executable:          r.boolean(),
			UserExecutable:      r.boolean(),
		}), true
	case opcuaObjectTypeAttrsID:
		return opcuaBoxed(r, OPCUAObjectTypeAttributes{OPCUANodeAttributes: r.nodeAttributes(), IsAbstract: r.boolean()}), true
	case opcuaVarTypeAttrsID:
		return opcuaBoxed(r, OPCUAVariableTypeAttributes{
			OPCUANodeAttributes: r.nodeAttributes(),
			Value:               r.variant(0),
			DataType:            r.nodeID(),
			ValueRank:           r.i32(),
			ArrayDimensions:     r.u32s(),
			IsAbstract:          r.boolean(),
		}), true
	case opcuaRefTypeAttrsID:
		return opcuaBoxed(r, OPCUAReferenceTypeAttributes{
			OPCUANodeAttributes: r.nodeAttributes(),
			IsAbstract:          r.boolean(),
			Symmetric:           r.boolean(),
			InverseName:         r.localizedText(),
		}), true
	case opcuaDataTypeAttrsID:
		return opcuaBoxed(r, OPCUADataTypeAttributes{OPCUANodeAttributes: r.nodeAttributes(), IsAbstract: r.boolean()}), true
	case opcuaViewAttrsID:
		return opcuaBoxed(r, OPCUAViewAttributes{
			OPCUANodeAttributes: r.nodeAttributes(),
			ContainsNoLoops:     r.boolean(),
			EventNotifier:       r.u8(),
		}), true
	case opcuaGenericAttrsID:
		return opcuaBoxed(r, OPCUAGenericAttributes{
			OPCUANodeAttributes: r.nodeAttributes(),
			AttributeValues: opcuaArray(r, opcuaMinGenericAttrLen, func() OPCUAGenericAttributeValue {
				return OPCUAGenericAttributeValue{AttributeID: OPCUAAttributeID(r.u32()), Value: r.variant(0)}
			}),
		}), true
	}
	return nil, false
}

// extHistoryUpdate reads the details of one HistoryUpdate operation.
func (r *opcuaReader) extHistoryUpdate(id uint32) (interface{}, bool) {
	switch id {
	case opcuaHistUpdDetailsID:
		return opcuaBoxed(r, OPCUAHistoryUpdateDetails{NodeID: r.nodeID()}), true
	case opcuaUpdateDataID, opcuaUpdateStructureID:
		return opcuaBoxed(r, OPCUAUpdateDataDetails{
			NodeID:               r.nodeID(),
			PerformInsertReplace: r.u32(),
			UpdateValues:         r.dataValues(0),
		}), true
	case opcuaUpdateEventID:
		return opcuaBoxed(r, OPCUAUpdateEventDetails{
			NodeID:               r.nodeID(),
			PerformInsertReplace: r.u32(),
			Filter:               r.eventFilter(),
			EventData:            r.historyEvents(),
		}), true
	case opcuaDeleteRawID:
		return opcuaBoxed(r, OPCUADeleteRawModifiedDetails{
			NodeID:           r.nodeID(),
			IsDeleteModified: r.boolean(),
			StartTime:        r.dateTime(),
			EndTime:          r.dateTime(),
		}), true
	case opcuaDeleteAtTimeID:
		return opcuaBoxed(r, OPCUADeleteAtTimeDetails{NodeID: r.nodeID(), ReqTimes: r.dateTimes()}), true
	case opcuaDeleteEventID:
		return opcuaBoxed(r, OPCUADeleteEventDetails{NodeID: r.nodeID(), EventIDs: r.byteStrings()}), true
	}
	return nil, false
}

func (r *opcuaReader) addNodesItem() OPCUAAddNodesItem {
	return OPCUAAddNodesItem{
		ParentNodeID:       r.expandedNodeID(),
		ReferenceTypeID:    r.nodeID(),
		RequestedNewNodeID: r.expandedNodeID(),
		BrowseName:         r.qualifiedName(),
		NodeClass:          OPCUANodeClass(r.u32()),
		NodeAttributes:     r.extensionObject(),
		TypeDefinition:     r.expandedNodeID(),
	}
}

func (r *opcuaReader) addNodesResponse() *OPCUAAddNodesResponse {
	return &OPCUAAddNodesResponse{
		Results: opcuaArray(r, opcuaMinAddNodesResLen, func() OPCUAAddNodesResult {
			return OPCUAAddNodesResult{StatusCode: r.statusCode(), AddedNodeID: r.nodeID()}
		}),
		DiagnosticInfos: r.diagnosticInfos(),
	}
}

func (r *opcuaReader) addReferencesItem() OPCUAAddReferencesItem {
	return OPCUAAddReferencesItem{
		SourceNodeID:    r.nodeID(),
		ReferenceTypeID: r.nodeID(),
		IsForward:       r.boolean(),
		TargetServerURI: r.str(),
		TargetNodeID:    r.expandedNodeID(),
		TargetNodeClass: OPCUANodeClass(r.u32()),
	}
}

func (r *opcuaReader) deleteNodesRequest() *OPCUADeleteNodesRequest {
	return &OPCUADeleteNodesRequest{NodesToDelete: opcuaArray(r, opcuaMinDelNodeLen, func() OPCUADeleteNodesItem {
		return OPCUADeleteNodesItem{NodeID: r.nodeID(), DeleteTargetReferences: r.boolean()}
	})}
}

func (r *opcuaReader) deleteRefsItem() OPCUADeleteReferencesItem {
	return OPCUADeleteReferencesItem{
		SourceNodeID:        r.nodeID(),
		ReferenceTypeID:     r.nodeID(),
		IsForward:           r.boolean(),
		TargetNodeID:        r.expandedNodeID(),
		DeleteBidirectional: r.boolean(),
	}
}

func (r *opcuaReader) deleteRefsRequest() *OPCUADeleteReferencesRequest {
	return &OPCUADeleteReferencesRequest{ReferencesToDelete: opcuaArray(r, opcuaMinDelRefLen, r.deleteRefsItem)}
}

func (r *opcuaReader) viewDescription() OPCUAViewDescription {
	return OPCUAViewDescription{ViewID: r.nodeID(), Timestamp: r.dateTime(), ViewVersion: r.u32()}
}

func (r *opcuaReader) nodeTypeDescription() OPCUANodeTypeDescription {
	return OPCUANodeTypeDescription{
		TypeDefinitionNode: r.expandedNodeID(),
		IncludeSubTypes:    r.boolean(),
		DataToReturn: opcuaArray(r, opcuaMinQueryDataLen, func() OPCUAQueryDataDescription {
			return OPCUAQueryDataDescription{
				RelativePath: opcuaArray(r, opcuaMinPathElemLen, r.pathElement),
				AttributeID:  OPCUAAttributeID(r.u32()),
				IndexRange:   r.str(),
			}
		}),
	}
}

func (r *opcuaReader) queryFirstRequest() *OPCUAQueryFirstRequest {
	return &OPCUAQueryFirstRequest{
		View:                  r.viewDescription(),
		NodeTypes:             opcuaArray(r, opcuaMinNodeTypeLen, r.nodeTypeDescription),
		Filter:                r.contentFilter(),
		MaxDataSetsToReturn:   r.u32(),
		MaxReferencesToReturn: r.u32(),
	}
}

func (r *opcuaReader) queryDataSets() []OPCUAQueryDataSet {
	return opcuaArray(r, opcuaMinDataSetLen, func() OPCUAQueryDataSet {
		return OPCUAQueryDataSet{NodeID: r.expandedNodeID(), TypeDefinitionNode: r.expandedNodeID(), Values: r.variants(0)}
	})
}

func (r *opcuaReader) queryFirstResponse() *OPCUAQueryFirstResponse {
	return &OPCUAQueryFirstResponse{
		QueryDataSets:     r.queryDataSets(),
		ContinuationPoint: r.byteString(),
		ParsingResults: opcuaArray(r, opcuaMinParsingResLen, func() OPCUAParsingResult {
			return OPCUAParsingResult{
				StatusCode:          r.statusCode(),
				DataStatusCodes:     r.statusCodes(),
				DataDiagnosticInfos: r.diagnosticInfos(),
			}
		}),
		DiagnosticInfos: r.diagnosticInfos(),
		FilterResult:    r.contentFilterResult(),
	}
}

func (r *opcuaReader) historyUpdateResponse() *OPCUAHistoryUpdateResponse {
	return &OPCUAHistoryUpdateResponse{
		Results: opcuaArray(r, opcuaMinHistUpdResLen, func() OPCUAHistoryUpdateResult {
			return OPCUAHistoryUpdateResult{
				StatusCode:       r.statusCode(),
				OperationResults: r.statusCodes(),
				DiagnosticInfos:  r.diagnosticInfos(),
			}
		}),
		DiagnosticInfos: r.diagnosticInfos(),
	}
}
