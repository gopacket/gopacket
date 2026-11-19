// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA services on nodes (OPC 10000-4 §5.8 to §5.11): Browse,
// BrowseNext, TranslateBrowsePathsToNodeIds, RegisterNodes,
// UnregisterNodes, Read, HistoryRead, Write and Call.

package layers

import "time"

// Minimum encoded sizes of the node service structures.
const (
	opcuaMinWriteValueLen = opcuaMinNodeIDLen + 2*opcuaUint32Len + opcuaMinMaskedLen
	opcuaMinBrowseDescLen = 2*opcuaMinNodeIDLen + opcuaUint32Len + opcuaUint8Len + 2*opcuaUint32Len
	opcuaMinBrowseResLen  = 3 * opcuaUint32Len
	opcuaMinRefDescLen    = 3*opcuaMinNodeIDLen + opcuaUint8Len + opcuaMinQNameLen + opcuaMinMaskedLen + opcuaUint32Len
	opcuaMinBrowsePathLen = opcuaMinNodeIDLen + opcuaUint32Len
	opcuaMinPathElemLen   = opcuaMinNodeIDLen + 2*opcuaUint8Len + opcuaMinQNameLen
	opcuaMinPathResultLen = 2 * opcuaUint32Len
	opcuaMinPathTargetLen = opcuaMinNodeIDLen + opcuaUint32Len
	opcuaMinCallMethodLen = 2*opcuaMinNodeIDLen + opcuaUint32Len
	opcuaMinCallResultLen = 4 * opcuaUint32Len
	opcuaMinHistReadIDLen = opcuaMinNodeIDLen + opcuaUint32Len + opcuaMinQNameLen + opcuaUint32Len
	opcuaMinHistResultLen = 2*opcuaUint32Len + opcuaMinExtObjLen
)

// OPCUABrowseDirection is a BrowseDirection (OPC 10000-4 §7.5).
type OPCUABrowseDirection uint32

// OPCUABrowseDirection values.
const (
	OPCUABrowseForward OPCUABrowseDirection = 0
	OPCUABrowseInverse OPCUABrowseDirection = 1
	OPCUABrowseBoth    OPCUABrowseDirection = 2
	OPCUABrowseInvalid OPCUABrowseDirection = 3
)

var opcuaBrowseDirectionNames = map[OPCUABrowseDirection]string{
	OPCUABrowseForward: "Forward",
	OPCUABrowseInverse: "Inverse",
	OPCUABrowseBoth:    "Both",
	OPCUABrowseInvalid: "Invalid",
}

// String returns the direction name.
func (d OPCUABrowseDirection) String() string { return opcuaName(opcuaBrowseDirectionNames, d) }

// OPCUANodeClass is a NodeClass (OPC 10000-3 §8.29), one bit per class.
type OPCUANodeClass uint32

// OPCUANodeClass values.
const (
	OPCUANodeClassUnspecified   OPCUANodeClass = 0
	OPCUANodeClassObject        OPCUANodeClass = 1
	OPCUANodeClassVariable      OPCUANodeClass = 2
	OPCUANodeClassMethod        OPCUANodeClass = 4
	OPCUANodeClassObjectType    OPCUANodeClass = 8
	OPCUANodeClassVariableType  OPCUANodeClass = 16
	OPCUANodeClassReferenceType OPCUANodeClass = 32
	OPCUANodeClassDataType      OPCUANodeClass = 64
	OPCUANodeClassView          OPCUANodeClass = 128
)

var opcuaNodeClassNames = map[OPCUANodeClass]string{
	OPCUANodeClassUnspecified:   "Unspecified",
	OPCUANodeClassObject:        "Object",
	OPCUANodeClassVariable:      "Variable",
	OPCUANodeClassMethod:        "Method",
	OPCUANodeClassObjectType:    "ObjectType",
	OPCUANodeClassVariableType:  "VariableType",
	OPCUANodeClassReferenceType: "ReferenceType",
	OPCUANodeClassDataType:      "DataType",
	OPCUANodeClassView:          "View",
}

// String returns the node class name.
func (c OPCUANodeClass) String() string { return opcuaName(opcuaNodeClassNames, c) }

// OPCUAReadResponse is the Read response (OPC 10000-4 §5.10.2).
type OPCUAReadResponse struct {
	Results         []OPCUADataValue
	DiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUAWriteValue is one attribute to write.
type OPCUAWriteValue struct {
	NodeID      OPCUANodeID
	AttributeID OPCUAAttributeID
	IndexRange  string
	Value       OPCUADataValue
}

// OPCUAWriteRequest is the Write request (OPC 10000-4 §5.10.4).
type OPCUAWriteRequest struct {
	NodesToWrite []OPCUAWriteValue
}

// OPCUAViewDescription names the view a Browse runs in (OPC 10000-4
// §7.45); a null ViewID is the whole address space.
type OPCUAViewDescription struct {
	ViewID      OPCUANodeID
	Timestamp   time.Time
	ViewVersion uint32
}

// OPCUABrowseDescription is one node to browse.
type OPCUABrowseDescription struct {
	NodeID          OPCUANodeID
	BrowseDirection OPCUABrowseDirection
	ReferenceTypeID OPCUANodeID
	IncludeSubtypes bool
	NodeClassMask   uint32
	ResultMask      uint32
}

// OPCUABrowseRequest is the Browse request (OPC 10000-4 §5.8.2).
type OPCUABrowseRequest struct {
	View                          OPCUAViewDescription
	RequestedMaxReferencesPerNode uint32
	NodesToBrowse                 []OPCUABrowseDescription
}

// OPCUAReferenceDescription is one reference a Browse found (OPC 10000-4
// §7.30).
type OPCUAReferenceDescription struct {
	ReferenceTypeID OPCUANodeID
	IsForward       bool
	NodeID          OPCUANodeID
	BrowseName      OPCUAQualifiedName
	DisplayName     OPCUALocalizedText
	NodeClass       OPCUANodeClass
	TypeDefinition  OPCUANodeID
}

// OPCUABrowseResult is the result of browsing one node (OPC 10000-4
// §7.6).
type OPCUABrowseResult struct {
	StatusCode        OPCUAStatusCode
	ContinuationPoint []byte
	References        []OPCUAReferenceDescription
}

// OPCUABrowseResponse is the Browse and BrowseNext response.
type OPCUABrowseResponse struct {
	Results         []OPCUABrowseResult
	DiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUABrowseNextRequest is the BrowseNext request (OPC 10000-4 §5.8.3).
type OPCUABrowseNextRequest struct {
	ReleaseContinuationPoints bool
	ContinuationPoints        [][]byte
}

// OPCUARelativePathElement is one hop of a browse path.
type OPCUARelativePathElement struct {
	ReferenceTypeID OPCUANodeID
	IsInverse       bool
	IncludeSubtypes bool
	TargetName      OPCUAQualifiedName
}

// OPCUABrowsePath is a start node and the hops from it.
type OPCUABrowsePath struct {
	StartingNode OPCUANodeID
	RelativePath []OPCUARelativePathElement
}

// OPCUATranslateRequest is the TranslateBrowsePathsToNodeIds request
// (OPC 10000-4 §5.8.4).
type OPCUATranslateRequest struct {
	BrowsePaths []OPCUABrowsePath
}

// OPCUABrowsePathTarget is a node a browse path reaches;
// RemainingPathIndex is 0xFFFFFFFF when the whole path was followed.
type OPCUABrowsePathTarget struct {
	TargetID           OPCUANodeID
	RemainingPathIndex uint32
}

// OPCUABrowsePathResult is the result of one browse path.
type OPCUABrowsePathResult struct {
	StatusCode OPCUAStatusCode
	Targets    []OPCUABrowsePathTarget
}

// OPCUATranslateResponse is the TranslateBrowsePathsToNodeIds response.
type OPCUATranslateResponse struct {
	Results         []OPCUABrowsePathResult
	DiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUANodeIDList is the parameter of RegisterNodes requests and
// responses and of UnregisterNodes requests (OPC 10000-4 §5.8.5, §5.8.6).
type OPCUANodeIDList struct {
	NodeIDs []OPCUANodeID
}

// OPCUACallMethodRequest is one method to call.
type OPCUACallMethodRequest struct {
	ObjectID       OPCUANodeID
	MethodID       OPCUANodeID
	InputArguments []OPCUAVariant
}

// OPCUACallRequest is the Call request (OPC 10000-4 §5.11.2).
type OPCUACallRequest struct {
	MethodsToCall []OPCUACallMethodRequest
}

// OPCUACallMethodResult is the result of one method call.
type OPCUACallMethodResult struct {
	StatusCode                   OPCUAStatusCode
	InputArgumentResults         []OPCUAStatusCode
	InputArgumentDiagnosticInfos []OPCUADiagnosticInfo
	OutputArguments              []OPCUAVariant
}

// OPCUACallResponse is the Call response.
type OPCUACallResponse struct {
	Results         []OPCUACallMethodResult
	DiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUAHistoryReadValueID is one node a HistoryRead reads.
type OPCUAHistoryReadValueID struct {
	NodeID            OPCUANodeID
	IndexRange        string
	DataEncoding      OPCUAQualifiedName
	ContinuationPoint []byte
}

// OPCUAHistoryReadRequest is the HistoryRead request (OPC 10000-4
// §5.10.3). The Value of HistoryReadDetails is an
// *OPCUAReadRawModifiedDetails, *OPCUAReadEventDetails,
// *OPCUAReadProcessedDetails or *OPCUAReadAtTimeDetails.
type OPCUAHistoryReadRequest struct {
	HistoryReadDetails        OPCUAExtensionObject
	TimestampsToReturn        OPCUATimestampsToReturn
	ReleaseContinuationPoints bool
	NodesToRead               []OPCUAHistoryReadValueID
}

// OPCUAHistoryReadResult is the history of one node. The Value of
// HistoryData is an *OPCUAHistoryData, *OPCUAHistoryModifiedData or
// *OPCUAHistoryEvent.
type OPCUAHistoryReadResult struct {
	StatusCode        OPCUAStatusCode
	ContinuationPoint []byte
	HistoryData       OPCUAExtensionObject
}

// OPCUAHistoryReadResponse is the HistoryRead response.
type OPCUAHistoryReadResponse struct {
	Results         []OPCUAHistoryReadResult
	DiagnosticInfos []OPCUADiagnosticInfo
}

func (r *opcuaReader) readResponse() *OPCUAReadResponse {
	return &OPCUAReadResponse{Results: r.dataValues(0), DiagnosticInfos: r.diagnosticInfos()}
}

func (r *opcuaReader) writeRequest() *OPCUAWriteRequest {
	return &OPCUAWriteRequest{NodesToWrite: opcuaArray(r, opcuaMinWriteValueLen, func() OPCUAWriteValue {
		return OPCUAWriteValue{
			NodeID:      r.nodeID(),
			AttributeID: OPCUAAttributeID(r.u32()),
			IndexRange:  r.str(),
			Value:       r.dataValue(0),
		}
	})}
}

func (r *opcuaReader) browseDescription() OPCUABrowseDescription {
	return OPCUABrowseDescription{
		NodeID:          r.nodeID(),
		BrowseDirection: OPCUABrowseDirection(r.u32()),
		ReferenceTypeID: r.nodeID(),
		IncludeSubtypes: r.boolean(),
		NodeClassMask:   r.u32(),
		ResultMask:      r.u32(),
	}
}

func (r *opcuaReader) browseRequest() *OPCUABrowseRequest {
	return &OPCUABrowseRequest{
		View:                          r.viewDescription(),
		RequestedMaxReferencesPerNode: r.u32(),
		NodesToBrowse:                 opcuaArray(r, opcuaMinBrowseDescLen, r.browseDescription),
	}
}

func (r *opcuaReader) referenceDescription() OPCUAReferenceDescription {
	return OPCUAReferenceDescription{
		ReferenceTypeID: r.nodeID(),
		IsForward:       r.boolean(),
		NodeID:          r.expandedNodeID(),
		BrowseName:      r.qualifiedName(),
		DisplayName:     r.localizedText(),
		NodeClass:       OPCUANodeClass(r.u32()),
		TypeDefinition:  r.expandedNodeID(),
	}
}

func (r *opcuaReader) browseResult() OPCUABrowseResult {
	return OPCUABrowseResult{
		StatusCode:        r.statusCode(),
		ContinuationPoint: r.byteString(),
		References:        opcuaArray(r, opcuaMinRefDescLen, r.referenceDescription),
	}
}

func (r *opcuaReader) browseResponse() *OPCUABrowseResponse {
	return &OPCUABrowseResponse{
		Results:         opcuaArray(r, opcuaMinBrowseResLen, r.browseResult),
		DiagnosticInfos: r.diagnosticInfos(),
	}
}

func (r *opcuaReader) browseNextRequest() *OPCUABrowseNextRequest {
	return &OPCUABrowseNextRequest{ReleaseContinuationPoints: r.boolean(), ContinuationPoints: r.byteStrings()}
}

func (r *opcuaReader) pathElement() OPCUARelativePathElement {
	return OPCUARelativePathElement{
		ReferenceTypeID: r.nodeID(),
		IsInverse:       r.boolean(),
		IncludeSubtypes: r.boolean(),
		TargetName:      r.qualifiedName(),
	}
}

func (r *opcuaReader) translateRequest() *OPCUATranslateRequest {
	return &OPCUATranslateRequest{BrowsePaths: opcuaArray(r, opcuaMinBrowsePathLen, func() OPCUABrowsePath {
		return OPCUABrowsePath{StartingNode: r.nodeID(), RelativePath: opcuaArray(r, opcuaMinPathElemLen, r.pathElement)}
	})}
}

func (r *opcuaReader) pathResult() OPCUABrowsePathResult {
	return OPCUABrowsePathResult{
		StatusCode: r.statusCode(),
		Targets: opcuaArray(r, opcuaMinPathTargetLen, func() OPCUABrowsePathTarget {
			return OPCUABrowsePathTarget{TargetID: r.expandedNodeID(), RemainingPathIndex: r.u32()}
		}),
	}
}

func (r *opcuaReader) translateResponse() *OPCUATranslateResponse {
	return &OPCUATranslateResponse{
		Results:         opcuaArray(r, opcuaMinPathResultLen, r.pathResult),
		DiagnosticInfos: r.diagnosticInfos(),
	}
}

func (r *opcuaReader) nodeIDList() *OPCUANodeIDList { return &OPCUANodeIDList{NodeIDs: r.nodeIDs()} }

func (r *opcuaReader) callRequest() *OPCUACallRequest {
	return &OPCUACallRequest{MethodsToCall: opcuaArray(r, opcuaMinCallMethodLen, func() OPCUACallMethodRequest {
		return OPCUACallMethodRequest{ObjectID: r.nodeID(), MethodID: r.nodeID(), InputArguments: r.variants(0)}
	})}
}

func (r *opcuaReader) callResult() OPCUACallMethodResult {
	return OPCUACallMethodResult{
		StatusCode:                   r.statusCode(),
		InputArgumentResults:         r.statusCodes(),
		InputArgumentDiagnosticInfos: r.diagnosticInfos(),
		OutputArguments:              r.variants(0),
	}
}

func (r *opcuaReader) callResponse() *OPCUACallResponse {
	return &OPCUACallResponse{
		Results:         opcuaArray(r, opcuaMinCallResultLen, r.callResult),
		DiagnosticInfos: r.diagnosticInfos(),
	}
}

func (r *opcuaReader) historyReadValueID() OPCUAHistoryReadValueID {
	return OPCUAHistoryReadValueID{
		NodeID:            r.nodeID(),
		IndexRange:        r.str(),
		DataEncoding:      r.qualifiedName(),
		ContinuationPoint: r.byteString(),
	}
}

func (r *opcuaReader) historyReadRequest() *OPCUAHistoryReadRequest {
	return &OPCUAHistoryReadRequest{
		HistoryReadDetails:        r.extensionObject(),
		TimestampsToReturn:        OPCUATimestampsToReturn(r.u32()),
		ReleaseContinuationPoints: r.boolean(),
		NodesToRead:               opcuaArray(r, opcuaMinHistReadIDLen, r.historyReadValueID),
	}
}

func (r *opcuaReader) historyReadResponse() *OPCUAHistoryReadResponse {
	return &OPCUAHistoryReadResponse{
		Results: opcuaArray(r, opcuaMinHistResultLen, func() OPCUAHistoryReadResult {
			return OPCUAHistoryReadResult{
				StatusCode:        r.statusCode(),
				ContinuationPoint: r.byteString(),
				HistoryData:       r.extensionObject(),
			}
		}),
		DiagnosticInfos: r.diagnosticInfos(),
	}
}
