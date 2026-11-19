// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA service bodies (OPC 10000-4 §5): the request and response
// headers of every service, and the parameters of a few.

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

// OPCUAService is a decoded service body. TypeID and ID name the service;
// one of the headers is always set; at most one of the typed parameter
// fields is. Params holds what follows the last decoded field: the
// parameters of other services, then padding and signature.
type OPCUAService struct {
	TypeID OPCUANodeID
	ID     OPCUAServiceID

	RequestHeader  *OPCUARequestHeader
	ResponseHeader *OPCUAResponseHeader

	OpenSecureChannelRequest  *OPCUAOpenSecureChannelRequest
	OpenSecureChannelResponse *OPCUAOpenSecureChannelResponse
	GetEndpointsRequest       *OPCUAGetEndpointsRequest
	ReadRequest               *OPCUAReadRequest

	Params []byte
}

// decodeOPCUAService decodes a body that opens with the binary encoding
// id of a known service and a header that parses; anything else, such as
// ciphertext or a later chunk of a long message, returns nil.
func decodeOPCUAService(body []byte) *OPCUAService {
	r := &opcuaReader{b: body}
	s := &OPCUAService{TypeID: r.expandedNodeID()}
	if r.err != nil || !s.knownType() {
		return nil
	}
	s.ID = OPCUAServiceID(s.TypeID.Numeric)

	if s.ID.IsRequest() {
		h := r.requestHeader()
		s.RequestHeader = &h
	} else {
		h := r.responseHeader()
		s.ResponseHeader = &h
	}
	if r.err != nil {
		return nil
	}
	s.Params = r.b[r.off:]

	// Typed parameters are best effort: a chunked message ends early, and
	// a failure leaves the parameters in Params.
	pr := &opcuaReader{b: s.Params}
	s.decodeParams(pr)
	if pr.err != nil {
		s.OpenSecureChannelRequest, s.OpenSecureChannelResponse = nil, nil
		s.GetEndpointsRequest, s.ReadRequest = nil, nil
		return s
	}
	s.Params = pr.b[pr.off:]
	return s
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
	}
}

// readRequest reads the Read parameters.
func (r *opcuaReader) readRequest() *OPCUAReadRequest {
	req := &OPCUAReadRequest{MaxAge: r.f64(), TimestampsToReturn: OPCUATimestampsToReturn(r.u32())}

	n := r.arrayLen(opcuaMinReadValueIDLen)
	for i := 0; i < n && r.err == nil; i++ {
		req.NodesToRead = append(req.NodesToRead, OPCUAReadValueID{
			NodeID:       r.nodeID(),
			AttributeID:  OPCUAAttributeID(r.u32()),
			IndexRange:   r.str(),
			DataEncoding: r.qualifiedName(),
		})
	}
	return req
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
