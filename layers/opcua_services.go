// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA service bodies (OPC 10000-4 §5): the request and response
// headers and the parameters of every service.
//
// A body is read twice. The first pass probes: it checks every length
// and count against the data and allocates nothing. Only what the probe
// accepted is decoded, so each array is allocated for elements that are
// really there.

package layers

import "time"

// Minimum encoded sizes, used to bound array lengths before reading them.
const (
	opcuaMinNodeIDLen      = 2 // TwoByte: encoding + identifier
	opcuaMinReadValueIDLen = opcuaMinNodeIDLen + opcuaUint32Len + opcuaUint32Len + opcuaUint16Len + opcuaUint32Len
)

// OPCUAAttributeID names a node attribute (OPC 10000-6 §A.1).
type OPCUAAttributeID uint32

// OPCUAAttributeID values.
const (
	OPCUAAttributeNodeID                  OPCUAAttributeID = 1
	OPCUAAttributeNodeClass               OPCUAAttributeID = 2
	OPCUAAttributeBrowseName              OPCUAAttributeID = 3
	OPCUAAttributeDisplayName             OPCUAAttributeID = 4
	OPCUAAttributeDescription             OPCUAAttributeID = 5
	OPCUAAttributeWriteMask               OPCUAAttributeID = 6
	OPCUAAttributeUserWriteMask           OPCUAAttributeID = 7
	OPCUAAttributeIsAbstract              OPCUAAttributeID = 8
	OPCUAAttributeSymmetric               OPCUAAttributeID = 9
	OPCUAAttributeInverseName             OPCUAAttributeID = 10
	OPCUAAttributeContainsNoLoops         OPCUAAttributeID = 11
	OPCUAAttributeEventNotifier           OPCUAAttributeID = 12
	OPCUAAttributeValue                   OPCUAAttributeID = 13
	OPCUAAttributeDataType                OPCUAAttributeID = 14
	OPCUAAttributeValueRank               OPCUAAttributeID = 15
	OPCUAAttributeArrayDimensions         OPCUAAttributeID = 16
	OPCUAAttributeAccessLevel             OPCUAAttributeID = 17
	OPCUAAttributeUserAccessLevel         OPCUAAttributeID = 18
	OPCUAAttributeMinimumSamplingInterval OPCUAAttributeID = 19
	OPCUAAttributeHistorizing             OPCUAAttributeID = 20
	OPCUAAttributeExecutable              OPCUAAttributeID = 21
	OPCUAAttributeUserExecutable          OPCUAAttributeID = 22
	OPCUAAttributeDataTypeDefinition      OPCUAAttributeID = 23
	OPCUAAttributeRolePermissions         OPCUAAttributeID = 24
	OPCUAAttributeUserRolePermissions     OPCUAAttributeID = 25
	OPCUAAttributeAccessRestrictions      OPCUAAttributeID = 26
	OPCUAAttributeAccessLevelEx           OPCUAAttributeID = 27
)

var opcuaAttributeNames = map[OPCUAAttributeID]string{
	OPCUAAttributeNodeID:                  "NodeId",
	OPCUAAttributeNodeClass:               "NodeClass",
	OPCUAAttributeBrowseName:              "BrowseName",
	OPCUAAttributeDisplayName:             "DisplayName",
	OPCUAAttributeDescription:             "Description",
	OPCUAAttributeWriteMask:               "WriteMask",
	OPCUAAttributeUserWriteMask:           "UserWriteMask",
	OPCUAAttributeIsAbstract:              "IsAbstract",
	OPCUAAttributeSymmetric:               "Symmetric",
	OPCUAAttributeInverseName:             "InverseName",
	OPCUAAttributeContainsNoLoops:         "ContainsNoLoops",
	OPCUAAttributeEventNotifier:           "EventNotifier",
	OPCUAAttributeValue:                   "Value",
	OPCUAAttributeDataType:                "DataType",
	OPCUAAttributeValueRank:               "ValueRank",
	OPCUAAttributeArrayDimensions:         "ArrayDimensions",
	OPCUAAttributeAccessLevel:             "AccessLevel",
	OPCUAAttributeUserAccessLevel:         "UserAccessLevel",
	OPCUAAttributeMinimumSamplingInterval: "MinimumSamplingInterval",
	OPCUAAttributeHistorizing:             "Historizing",
	OPCUAAttributeExecutable:              "Executable",
	OPCUAAttributeUserExecutable:          "UserExecutable",
	OPCUAAttributeDataTypeDefinition:      "DataTypeDefinition",
	OPCUAAttributeRolePermissions:         "RolePermissions",
	OPCUAAttributeUserRolePermissions:     "UserRolePermissions",
	OPCUAAttributeAccessRestrictions:      "AccessRestrictions",
	OPCUAAttributeAccessLevelEx:           "AccessLevelEx",
}

// String returns the attribute name.
func (a OPCUAAttributeID) String() string { return opcuaName(opcuaAttributeNames, a) }

// OPCUATimestampsToReturn selects the timestamps a Read returns.
type OPCUATimestampsToReturn uint32

// OPCUATimestampsToReturn values.
const (
	OPCUATimestampsSource  OPCUATimestampsToReturn = 0
	OPCUATimestampsServer  OPCUATimestampsToReturn = 1
	OPCUATimestampsBoth    OPCUATimestampsToReturn = 2
	OPCUATimestampsNeither OPCUATimestampsToReturn = 3
	OPCUATimestampsInvalid OPCUATimestampsToReturn = 4
)

var opcuaTimestampsNames = map[OPCUATimestampsToReturn]string{
	OPCUATimestampsSource:  "Source",
	OPCUATimestampsServer:  "Server",
	OPCUATimestampsBoth:    "Both",
	OPCUATimestampsNeither: "Neither",
	OPCUATimestampsInvalid: "Invalid",
}

// String returns the selection name.
func (t OPCUATimestampsToReturn) String() string { return opcuaName(opcuaTimestampsNames, t) }

// OPCUAOpenSecureChannelRequest is the OpenSecureChannel request
// (OPC 10000-4 §5.5.2).
type OPCUAOpenSecureChannelRequest struct {
	ClientProtocolVersion uint32
	RequestType           OPCUASecurityTokenRequestType
	SecurityMode          OPCUAMessageSecurityMode
	ClientNonce           []byte
	// RequestedLifetime is in milliseconds.
	RequestedLifetime uint32
}

// OPCUAChannelSecurityToken identifies the keys of a secure channel.
type OPCUAChannelSecurityToken struct {
	ChannelID uint32
	TokenID   uint32
	CreatedAt time.Time
	// RevisedLifetime is in milliseconds.
	RevisedLifetime uint32
}

// OPCUAOpenSecureChannelResponse is the OpenSecureChannel response.
type OPCUAOpenSecureChannelResponse struct {
	ServerProtocolVersion uint32
	SecurityToken         OPCUAChannelSecurityToken
	ServerNonce           []byte
}

// OPCUAGetEndpointsRequest is the GetEndpoints request (OPC 10000-4 §5.4.4).
type OPCUAGetEndpointsRequest struct {
	EndpointURL string
	LocaleIDs   []string
	ProfileURIs []string
}

// OPCUAReadValueID names one attribute of one node to read.
type OPCUAReadValueID struct {
	NodeID       OPCUANodeID
	AttributeID  OPCUAAttributeID
	IndexRange   string
	DataEncoding OPCUAQualifiedName
}

// OPCUAReadRequest is the Read request (OPC 10000-4 §5.10.2).
type OPCUAReadRequest struct {
	// MaxAge is in milliseconds.
	MaxAge             float64
	TimestampsToReturn OPCUATimestampsToReturn
	NodesToRead        []OPCUAReadValueID
}

// OPCUAResults is the per-operation status of a response (OPC 10000-4
// §7.39, §7.12): Write, SetMonitoringMode, DeleteMonitoredItems,
// SetPublishingMode and DeleteSubscriptions return only this.
type OPCUAResults struct {
	Results         []OPCUAStatusCode
	DiagnosticInfos []OPCUADiagnosticInfo
}

func (r *opcuaReader) results() OPCUAResults {
	return OPCUAResults{Results: r.statusCodes(), DiagnosticInfos: r.diagnosticInfos()}
}

func (r *opcuaReader) resultsPtr() *OPCUAResults {
	res := r.results()
	return &res
}

// OPCUAService is a decoded service body. TypeID and ID name the service;
// one of the headers is always set; at most one of the typed parameter
// fields is. Params holds what follows the last decoded field: padding
// and signature.
//
// The parameters decode in full or not at all: when they do not parse,
// as in the first chunk of a long message, every typed field is nil and
// Params holds all of them. OPCUAChunkAssembler joins such a message.
// Services without parameters (CloseSecureChannel, the CloseSession,
// UnregisterNodes and RegisterServer responses, ServiceFault) have no
// typed field.
type OPCUAService struct {
	TypeID OPCUANodeID
	ID     OPCUAServiceID

	RequestHeader  *OPCUARequestHeader
	ResponseHeader *OPCUAResponseHeader

	OpenSecureChannelRequest  *OPCUAOpenSecureChannelRequest
	OpenSecureChannelResponse *OPCUAOpenSecureChannelResponse
	GetEndpointsRequest       *OPCUAGetEndpointsRequest
	ReadRequest               *OPCUAReadRequest

	FindServersRequest           *OPCUAFindServersRequest
	FindServersResponse          *OPCUAFindServersResponse
	FindServersOnNetworkRequest  *OPCUAFindOnNetworkRequest
	FindServersOnNetworkResponse *OPCUAFindOnNetworkResponse
	RegisterServerRequest        *OPCUARegisterServerRequest
	RegisterServer2Request       *OPCUARegisterServer2Request
	RegisterServer2Response      *OPCUAResults
	CancelRequest                *OPCUACancelRequest
	CancelResponse               *OPCUACancelResponse

	GetEndpointsResponse    *OPCUAGetEndpointsResponse
	CreateSessionRequest    *OPCUACreateSessionRequest
	CreateSessionResponse   *OPCUACreateSessionResponse
	ActivateSessionRequest  *OPCUAActivateSessionRequest
	ActivateSessionResponse *OPCUAActivateSessionResponse
	CloseSessionRequest     *OPCUACloseSessionRequest

	ReadResponse        *OPCUAReadResponse
	WriteRequest        *OPCUAWriteRequest
	WriteResponse       *OPCUAResults
	HistoryReadRequest  *OPCUAHistoryReadRequest
	HistoryReadResponse *OPCUAHistoryReadResponse
	CallRequest         *OPCUACallRequest
	CallResponse        *OPCUACallResponse

	AddNodesRequest          *OPCUAAddNodesRequest
	AddNodesResponse         *OPCUAAddNodesResponse
	AddReferencesRequest     *OPCUAAddReferencesRequest
	AddReferencesResponse    *OPCUAResults
	DeleteNodesRequest       *OPCUADeleteNodesRequest
	DeleteNodesResponse      *OPCUAResults
	DeleteReferencesRequest  *OPCUADeleteReferencesRequest
	DeleteReferencesResponse *OPCUAResults
	QueryFirstRequest        *OPCUAQueryFirstRequest
	QueryFirstResponse       *OPCUAQueryFirstResponse
	QueryNextRequest         *OPCUAQueryNextRequest
	QueryNextResponse        *OPCUAQueryNextResponse
	HistoryUpdateRequest     *OPCUAHistoryUpdateRequest
	HistoryUpdateResponse    *OPCUAHistoryUpdateResponse

	BrowseRequest                         *OPCUABrowseRequest
	BrowseResponse                        *OPCUABrowseResponse
	BrowseNextRequest                     *OPCUABrowseNextRequest
	BrowseNextResponse                    *OPCUABrowseResponse
	TranslateBrowsePathsToNodeIDsRequest  *OPCUATranslateRequest
	TranslateBrowsePathsToNodeIDsResponse *OPCUATranslateResponse
	RegisterNodesRequest                  *OPCUANodeIDList
	RegisterNodesResponse                 *OPCUANodeIDList
	UnregisterNodesRequest                *OPCUANodeIDList

	CreateMonitoredItemsRequest  *OPCUACreateItemsRequest
	CreateMonitoredItemsResponse *OPCUACreateItemsResponse
	ModifyMonitoredItemsRequest  *OPCUAModifyItemsRequest
	ModifyMonitoredItemsResponse *OPCUAModifyItemsResponse
	SetMonitoringModeRequest     *OPCUASetMonitoringRequest
	SetMonitoringModeResponse    *OPCUAResults
	DeleteMonitoredItemsRequest  *OPCUADeleteItemsRequest
	DeleteMonitoredItemsResponse *OPCUAResults
	CreateSubscriptionRequest    *OPCUACreateSubRequest
	CreateSubscriptionResponse   *OPCUACreateSubResponse
	ModifySubscriptionRequest    *OPCUAModifySubRequest
	ModifySubscriptionResponse   *OPCUASubscriptionRevision
	SetPublishingModeRequest     *OPCUASetPublishingRequest
	SetPublishingModeResponse    *OPCUAResults
	DeleteSubscriptionsRequest   *OPCUASubscriptionIDs
	DeleteSubscriptionsResponse  *OPCUAResults
	PublishRequest               *OPCUAPublishRequest
	PublishResponse              *OPCUAPublishResponse
	RepublishRequest             *OPCUARepublishRequest
	RepublishResponse            *OPCUARepublishResponse

	SetTriggeringRequest          *OPCUASetTriggeringRequest
	SetTriggeringResponse         *OPCUASetTriggeringResponse
	TransferSubscriptionsRequest  *OPCUATransferSubsRequest
	TransferSubscriptionsResponse *OPCUATransferSubsResponse

	Params []byte
}

// decodeOPCUAService decodes a body that opens with the binary encoding
// id of a known service and a header that parses; anything else, such as
// ciphertext or a later chunk of a long message, returns nil.
//
//	body ─ probe ─┬─ header fails ─► nil
//	              ├─ params fail ──► header decoded, Params raw
//	              └─ all parse ────► header and params decoded
func decodeOPCUAService(body []byte) *OPCUAService {
	probe := opcuaReader{b: body, mode: opcuaReadProbe}
	s := &OPCUAService{}
	if !s.decodeHeader(&probe) {
		return nil
	}
	paramsOff := probe.off
	s.decodeParams(&probe)

	// The header is known to parse; the decode cannot fail on it.
	*s = OPCUAService{}
	r := opcuaReader{b: body}
	s.decodeHeader(&r)
	s.Params = body[paramsOff:]

	// Typed parameters are best effort: a chunked message ends early, and
	// a failure leaves the parameters in Params.
	if probe.err != nil {
		return s
	}
	header := *s
	s.decodeParams(&r)

	// The probe read the same bytes, so the decode cannot fail; if it
	// ever did, the parameters would stay raw as for a failed probe.
	if r.err != nil {
		*s = header
		return s
	}
	s.Params = r.b[r.off:]
	return s
}

// decodeHeader reads the service id and its request or response header,
// and reports whether they parse. A probe keeps no header.
func (s *OPCUAService) decodeHeader(r *opcuaReader) bool {
	s.TypeID = r.expandedNodeID()
	if r.err != nil || !s.knownType() {
		return false
	}
	s.ID = OPCUAServiceID(s.TypeID.Numeric)

	if s.ID.IsRequest() {
		h := r.requestHeader()
		if r.mode == opcuaReadDecode {
			s.RequestHeader = new(OPCUARequestHeader)
			*s.RequestHeader = h
		}
		return r.err == nil
	}

	h := r.responseHeader()
	if r.mode == opcuaReadDecode {
		s.ResponseHeader = new(OPCUAResponseHeader)
		*s.ResponseHeader = h
	}
	return r.err == nil
}

// knownType reports whether TypeID is a namespace 0 numeric id of a
// service binary encoding.
func (s *OPCUAService) knownType() bool {
	n := s.TypeID
	if n.Namespace != 0 || n.NamespaceURI != "" || n.ServerIndex != 0 {
		return false
	}
	switch n.Encoding {
	case OPCUANodeIDTwoByte, OPCUANodeIDFourByte, OPCUANodeIDNumeric:
	default:
		return false
	}
	_, ok := opcuaServiceNames[OPCUAServiceID(n.Numeric)]
	return ok
}

// decodeParams reads the parameters of the services decoded in full.
func (s *OPCUAService) decodeParams(r *opcuaReader) {
	switch s.ID {
	case OPCUAServiceOpenSecureChannelRequest:
		s.OpenSecureChannelRequest = &OPCUAOpenSecureChannelRequest{
			ClientProtocolVersion: r.u32(),
			RequestType:           OPCUASecurityTokenRequestType(r.u32()),
			SecurityMode:          OPCUAMessageSecurityMode(r.u32()),
			ClientNonce:           r.byteString(),
			RequestedLifetime:     r.u32(),
		}

	case OPCUAServiceOpenSecureChannelResponse:
		s.OpenSecureChannelResponse = &OPCUAOpenSecureChannelResponse{
			ServerProtocolVersion: r.u32(),
			SecurityToken: OPCUAChannelSecurityToken{
				ChannelID:       r.u32(),
				TokenID:         r.u32(),
				CreatedAt:       r.dateTime(),
				RevisedLifetime: r.u32(),
			},
			ServerNonce: r.byteString(),
		}

	case OPCUAServiceGetEndpointsRequest:
		s.GetEndpointsRequest = &OPCUAGetEndpointsRequest{
			EndpointURL: r.str(),
			LocaleIDs:   r.strings(),
			ProfileURIs: r.strings(),
		}

	case OPCUAServiceReadRequest:
		s.ReadRequest = r.readRequest()

	// Each group switches on its own services and ignores the others.
	default:
		s.decodeSession(r)
		s.decodeNodes(r)
		s.decodeNodeMgmt(r)
		s.decodeSubscriptions(r)
	}
}

// decodeSession reads the discovery and session parameters.
func (s *OPCUAService) decodeSession(r *opcuaReader) {
	switch s.ID {
	case OPCUAServiceFindServersRequest:
		s.FindServersRequest = r.findServersRequest()
	case OPCUAServiceFindServersResponse:
		s.FindServersResponse = &OPCUAFindServersResponse{
			Servers: opcuaArray(r, opcuaMinAppDescLen, r.applicationDescription),
		}
	case OPCUAServiceGetEndpointsResponse:
		s.GetEndpointsResponse = &OPCUAGetEndpointsResponse{Endpoints: r.endpoints()}
	case OPCUAServiceCreateSessionRequest:
		s.CreateSessionRequest = r.createSessionRequest()
	case OPCUAServiceCreateSessionResponse:
		s.CreateSessionResponse = r.createSessionResponse()
	case OPCUAServiceActivateSessionRequest:
		s.ActivateSessionRequest = r.activateSessionRequest()
	case OPCUAServiceActivateSessionResponse:
		s.ActivateSessionResponse = r.activateSessionResponse()
	case OPCUAServiceCloseSessionRequest:
		s.CloseSessionRequest = &OPCUACloseSessionRequest{DeleteSubscriptions: r.boolean()}
	case OPCUAServiceCancelRequest:
		s.CancelRequest = &OPCUACancelRequest{RequestHandle: r.u32()}
	case OPCUAServiceCancelResponse:
		s.CancelResponse = &OPCUACancelResponse{CancelCount: r.u32()}
	case OPCUAServiceFindServersOnNetworkRequest:
		s.FindServersOnNetworkRequest = r.findOnNetworkRequest()
	case OPCUAServiceFindServersOnNetworkResponse:
		s.FindServersOnNetworkResponse = r.findOnNetworkResponse()
	case OPCUAServiceRegisterServerRequest:
		s.RegisterServerRequest = &OPCUARegisterServerRequest{Server: r.registeredServer()}
	case OPCUAServiceRegisterServer2Request:
		s.RegisterServer2Request = r.registerServer2Request()
	case OPCUAServiceRegisterServer2Response:
		s.RegisterServer2Response = r.resultsPtr()
	}
}

// decodeNodes reads the parameters of the node services.
func (s *OPCUAService) decodeNodes(r *opcuaReader) {
	switch s.ID {
	case OPCUAServiceReadResponse:
		s.ReadResponse = r.readResponse()
	case OPCUAServiceWriteRequest:
		s.WriteRequest = r.writeRequest()
	case OPCUAServiceWriteResponse:
		s.WriteResponse = r.resultsPtr()
	case OPCUAServiceHistoryReadRequest:
		s.HistoryReadRequest = r.historyReadRequest()
	case OPCUAServiceHistoryReadResponse:
		s.HistoryReadResponse = r.historyReadResponse()
	case OPCUAServiceCallRequest:
		s.CallRequest = r.callRequest()
	case OPCUAServiceCallResponse:
		s.CallResponse = r.callResponse()
	case OPCUAServiceBrowseRequest:
		s.BrowseRequest = r.browseRequest()
	case OPCUAServiceBrowseResponse:
		s.BrowseResponse = r.browseResponse()
	case OPCUAServiceBrowseNextRequest:
		s.BrowseNextRequest = r.browseNextRequest()
	case OPCUAServiceBrowseNextResponse:
		s.BrowseNextResponse = r.browseResponse()
	case OPCUAServiceTranslateBrowsePathsToNodeIdsRequest:
		s.TranslateBrowsePathsToNodeIDsRequest = r.translateRequest()
	case OPCUAServiceTranslateBrowsePathsToNodeIdsResponse:
		s.TranslateBrowsePathsToNodeIDsResponse = r.translateResponse()
	case OPCUAServiceRegisterNodesRequest:
		s.RegisterNodesRequest = r.nodeIDList()
	case OPCUAServiceRegisterNodesResponse:
		s.RegisterNodesResponse = r.nodeIDList()
	case OPCUAServiceUnregisterNodesRequest:
		s.UnregisterNodesRequest = r.nodeIDList()
	}
}

// decodeSubscriptions reads the monitored item and subscription
// parameters.
func (s *OPCUAService) decodeSubscriptions(r *opcuaReader) {
	switch s.ID {
	case OPCUAServiceCreateMonitoredItemsRequest:
		s.CreateMonitoredItemsRequest = r.createItemsRequest()
	case OPCUAServiceCreateMonitoredItemsResponse:
		s.CreateMonitoredItemsResponse = r.createItemsResponse()
	case OPCUAServiceModifyMonitoredItemsRequest:
		s.ModifyMonitoredItemsRequest = r.modifyItemsRequest()
	case OPCUAServiceModifyMonitoredItemsResponse:
		s.ModifyMonitoredItemsResponse = r.modifyItemsResponse()
	case OPCUAServiceSetMonitoringModeRequest:
		s.SetMonitoringModeRequest = r.setMonitoringRequest()
	case OPCUAServiceSetMonitoringModeResponse:
		s.SetMonitoringModeResponse = r.resultsPtr()
	case OPCUAServiceDeleteMonitoredItemsRequest:
		s.DeleteMonitoredItemsRequest = r.deleteItemsRequest()
	case OPCUAServiceDeleteMonitoredItemsResponse:
		s.DeleteMonitoredItemsResponse = r.resultsPtr()
	case OPCUAServiceCreateSubscriptionRequest:
		s.CreateSubscriptionRequest = r.createSubRequest()
	case OPCUAServiceCreateSubscriptionResponse:
		s.CreateSubscriptionResponse = r.createSubResponse()
	case OPCUAServiceModifySubscriptionRequest:
		s.ModifySubscriptionRequest = r.modifySubRequest()
	case OPCUAServiceModifySubscriptionResponse:
		s.ModifySubscriptionResponse = r.modifySubResponse()
	case OPCUAServiceSetPublishingModeRequest:
		s.SetPublishingModeRequest = r.setPublishingRequest()
	case OPCUAServiceSetPublishingModeResponse:
		s.SetPublishingModeResponse = r.resultsPtr()
	case OPCUAServiceDeleteSubscriptionsRequest:
		s.DeleteSubscriptionsRequest = &OPCUASubscriptionIDs{SubscriptionIDs: r.u32s()}
	case OPCUAServiceDeleteSubscriptionsResponse:
		s.DeleteSubscriptionsResponse = r.resultsPtr()
	case OPCUAServicePublishRequest:
		s.PublishRequest = r.publishRequest()
	case OPCUAServicePublishResponse:
		s.PublishResponse = r.publishResponse()
	case OPCUAServiceRepublishRequest:
		s.RepublishRequest = r.republishRequest()
	case OPCUAServiceRepublishResponse:
		s.RepublishResponse = r.republishResponse()
	case OPCUAServiceSetTriggeringRequest:
		s.SetTriggeringRequest = r.setTriggeringRequest()
	case OPCUAServiceSetTriggeringResponse:
		s.SetTriggeringResponse = r.setTriggeringResponse()
	case OPCUAServiceTransferSubscriptionsRequest:
		s.TransferSubscriptionsRequest = &OPCUATransferSubsRequest{SubscriptionIDs: r.u32s(), SendInitialValues: r.boolean()}
	case OPCUAServiceTransferSubscriptionsResponse:
		s.TransferSubscriptionsResponse = r.transferSubsResponse()
	}
}

// readRequest reads the Read parameters.
func (r *opcuaReader) readRequest() *OPCUAReadRequest {
	return &OPCUAReadRequest{
		MaxAge:             r.f64(),
		TimestampsToReturn: OPCUATimestampsToReturn(r.u32()),
		NodesToRead:        opcuaArray(r, opcuaMinReadValueIDLen, r.readValueID),
	}
}

// requestHeader reads a RequestHeader.
func (r *opcuaReader) requestHeader() OPCUARequestHeader {
	return OPCUARequestHeader{
		AuthenticationToken: r.nodeID(),
		Timestamp:           r.dateTime(),
		RequestHandle:       r.u32(),
		ReturnDiagnostics:   r.u32(),
		AuditEntryID:        r.str(),
		TimeoutHint:         r.u32(),
		AdditionalHeader:    r.extensionObject(),
	}
}

// responseHeader reads a ResponseHeader.
func (r *opcuaReader) responseHeader() OPCUAResponseHeader {
	return OPCUAResponseHeader{
		Timestamp:          r.dateTime(),
		RequestHandle:      r.u32(),
		ServiceResult:      OPCUAStatusCode(r.u32()),
		ServiceDiagnostics: r.diagnosticInfo(0),
		StringTable:        r.strings(),
		AdditionalHeader:   r.extensionObject(),
	}
}
