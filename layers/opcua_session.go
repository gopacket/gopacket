// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA discovery and session services (OPC 10000-4 §5.4, §5.6):
// FindServers, GetEndpoints, CreateSession, ActivateSession and
// CloseSession.

package layers

// Minimum encoded sizes of the discovery structures.
const (
	opcuaMinAppDescLen  = 2*opcuaUint32Len + opcuaMinMaskedLen + 4*opcuaUint32Len
	opcuaMinTokenPolLen = 5 * opcuaUint32Len
	opcuaMinEndpointLen = opcuaUint32Len + opcuaMinAppDescLen + 2*opcuaUint32Len + opcuaUint32Len + 2*opcuaUint32Len + opcuaUint8Len
	opcuaMinSoftCertLen = 2 * opcuaUint32Len
)

// OPCUAApplicationType is an ApplicationType (OPC 10000-4 §7.2.2).
type OPCUAApplicationType uint32

// OPCUAApplicationType values.
const (
	OPCUAApplicationServer          OPCUAApplicationType = 0
	OPCUAApplicationClient          OPCUAApplicationType = 1
	OPCUAApplicationClientAndServer OPCUAApplicationType = 2
	OPCUAApplicationDiscoveryServer OPCUAApplicationType = 3
)

var opcuaApplicationTypeNames = map[OPCUAApplicationType]string{
	OPCUAApplicationServer:          "Server",
	OPCUAApplicationClient:          "Client",
	OPCUAApplicationClientAndServer: "ClientAndServer",
	OPCUAApplicationDiscoveryServer: "DiscoveryServer",
}

// String returns the application type name.
func (t OPCUAApplicationType) String() string { return opcuaName(opcuaApplicationTypeNames, t) }

// OPCUAUserTokenType is a UserTokenType (OPC 10000-4 §7.42).
type OPCUAUserTokenType uint32

// OPCUAUserTokenType values.
const (
	OPCUAUserTokenAnonymous   OPCUAUserTokenType = 0
	OPCUAUserTokenUserName    OPCUAUserTokenType = 1
	OPCUAUserTokenCertificate OPCUAUserTokenType = 2
	OPCUAUserTokenIssued      OPCUAUserTokenType = 3
)

var opcuaUserTokenTypeNames = map[OPCUAUserTokenType]string{
	OPCUAUserTokenAnonymous:   "Anonymous",
	OPCUAUserTokenUserName:    "UserName",
	OPCUAUserTokenCertificate: "Certificate",
	OPCUAUserTokenIssued:      "IssuedToken",
}

// String returns the token type name.
func (t OPCUAUserTokenType) String() string { return opcuaName(opcuaUserTokenTypeNames, t) }

// Binary encoding ids of the user identity tokens (NodeIds.csv).
const (
	opcuaAnonymousTokenID = 321
	opcuaUserNameTokenID  = 324
	opcuaX509TokenID      = 327
	opcuaIssuedTokenID    = 940
)

// opcuaIdentityTokenTypes maps an identity token encoding id to its type.
var opcuaIdentityTokenTypes = map[uint32]OPCUAUserTokenType{
	opcuaAnonymousTokenID: OPCUAUserTokenAnonymous,
	opcuaUserNameTokenID:  OPCUAUserTokenUserName,
	opcuaX509TokenID:      OPCUAUserTokenCertificate,
	opcuaIssuedTokenID:    OPCUAUserTokenIssued,
}

// OPCUAApplicationDescription describes a client or server application
// (OPC 10000-4 §7.2).
type OPCUAApplicationDescription struct {
	ApplicationURI      string
	ProductURI          string
	ApplicationName     OPCUALocalizedText
	ApplicationType     OPCUAApplicationType
	GatewayServerURI    string
	DiscoveryProfileURI string
	DiscoveryURLs       []string
}

// OPCUAUserTokenPolicy is a user identity token an endpoint accepts
// (OPC 10000-4 §7.43).
type OPCUAUserTokenPolicy struct {
	PolicyID          string
	TokenType         OPCUAUserTokenType
	IssuedTokenType   string
	IssuerEndpointURL string
	SecurityPolicyURI string
}

// OPCUAEndpointDescription describes a server endpoint (OPC 10000-4 §7.14).
type OPCUAEndpointDescription struct {
	EndpointURL         string
	Server              OPCUAApplicationDescription
	ServerCertificate   []byte
	SecurityMode        OPCUAMessageSecurityMode
	SecurityPolicyURI   string
	UserIdentityTokens  []OPCUAUserTokenPolicy
	TransportProfileURI string
	SecurityLevel       uint8
}

// OPCUASignatureData is a signature and its algorithm (OPC 10000-4 §7.37).
type OPCUASignatureData struct {
	Algorithm string
	Signature []byte
}

// OPCUASignedSoftwareCertificate is a SignedSoftwareCertificate
// (OPC 10000-4 §7.38).
type OPCUASignedSoftwareCertificate struct {
	CertificateData []byte
	Signature       []byte
}

// OPCUAUserIdentityToken is the decoded, non-secret part of a user
// identity token. The UserName password and the IssuedToken data stay
// only in the raw ExtensionObject body.
type OPCUAUserIdentityToken struct {
	TokenType OPCUAUserTokenType
	PolicyID  string
	// UserName is set by a UserName token.
	UserName string
	// EncryptionAlgorithm is set by UserName and IssuedToken tokens; empty
	// means the secret is in plaintext.
	EncryptionAlgorithm string
	// CertificateData is the DER certificate of an X509 token.
	CertificateData []byte
}

// OPCUAFindServersRequest is the FindServers request (OPC 10000-4 §5.4.2).
type OPCUAFindServersRequest struct {
	EndpointURL string
	LocaleIDs   []string
	ServerURIs  []string
}

// OPCUAFindServersResponse is the FindServers response.
type OPCUAFindServersResponse struct {
	Servers []OPCUAApplicationDescription
}

// OPCUAGetEndpointsResponse is the GetEndpoints response (OPC 10000-4
// §5.4.4).
type OPCUAGetEndpointsResponse struct {
	Endpoints []OPCUAEndpointDescription
}

// OPCUACreateSessionRequest is the CreateSession request (OPC 10000-4
// §5.6.2).
type OPCUACreateSessionRequest struct {
	ClientDescription OPCUAApplicationDescription
	ServerURI         string
	EndpointURL       string
	SessionName       string
	ClientNonce       []byte
	ClientCertificate []byte
	// RequestedSessionTimeout is in milliseconds.
	RequestedSessionTimeout float64
	MaxResponseMessageSize  uint32
}

// OPCUACreateSessionResponse is the CreateSession response.
type OPCUACreateSessionResponse struct {
	SessionID           OPCUANodeID
	AuthenticationToken OPCUANodeID
	// RevisedSessionTimeout is in milliseconds.
	RevisedSessionTimeout      float64
	ServerNonce                []byte
	ServerCertificate          []byte
	ServerEndpoints            []OPCUAEndpointDescription
	ServerSoftwareCertificates []OPCUASignedSoftwareCertificate
	ServerSignature            OPCUASignatureData
	MaxRequestMessageSize      uint32
}

// OPCUAActivateSessionRequest is the ActivateSession request (OPC 10000-4
// §5.6.3).
type OPCUAActivateSessionRequest struct {
	ClientSignature            OPCUASignatureData
	ClientSoftwareCertificates []OPCUASignedSoftwareCertificate
	LocaleIDs                  []string
	// UserIdentityToken is the token as sent; IdentityToken is its
	// decoded form, nil for an unknown or undecodable token.
	UserIdentityToken  OPCUAExtensionObject
	IdentityToken      *OPCUAUserIdentityToken
	UserTokenSignature OPCUASignatureData
}

// OPCUAActivateSessionResponse is the ActivateSession response.
type OPCUAActivateSessionResponse struct {
	ServerNonce []byte
	OPCUAResults
}

// OPCUACloseSessionRequest is the CloseSession request (OPC 10000-4
// §5.6.4).
type OPCUACloseSessionRequest struct {
	DeleteSubscriptions bool
}

// applicationDescription reads an ApplicationDescription.
func (r *opcuaReader) applicationDescription() OPCUAApplicationDescription {
	return OPCUAApplicationDescription{
		ApplicationURI:      r.str(),
		ProductURI:          r.str(),
		ApplicationName:     r.localizedText(),
		ApplicationType:     OPCUAApplicationType(r.u32()),
		GatewayServerURI:    r.str(),
		DiscoveryProfileURI: r.str(),
		DiscoveryURLs:       r.strings(),
	}
}

// userTokenPolicy reads a UserTokenPolicy.
func (r *opcuaReader) userTokenPolicy() OPCUAUserTokenPolicy {
	return OPCUAUserTokenPolicy{
		PolicyID:          r.str(),
		TokenType:         OPCUAUserTokenType(r.u32()),
		IssuedTokenType:   r.str(),
		IssuerEndpointURL: r.str(),
		SecurityPolicyURI: r.str(),
	}
}

// endpointDescription reads an EndpointDescription.
func (r *opcuaReader) endpointDescription() OPCUAEndpointDescription {
	return OPCUAEndpointDescription{
		EndpointURL:         r.str(),
		Server:              r.applicationDescription(),
		ServerCertificate:   r.byteString(),
		SecurityMode:        OPCUAMessageSecurityMode(r.u32()),
		SecurityPolicyURI:   r.str(),
		UserIdentityTokens:  opcuaArray(r, opcuaMinTokenPolLen, r.userTokenPolicy),
		TransportProfileURI: r.str(),
		SecurityLevel:       r.u8(),
	}
}

func (r *opcuaReader) endpoints() []OPCUAEndpointDescription {
	return opcuaArray(r, opcuaMinEndpointLen, r.endpointDescription)
}

func (r *opcuaReader) signatureData() OPCUASignatureData {
	return OPCUASignatureData{Algorithm: r.str(), Signature: r.byteString()}
}

func (r *opcuaReader) softwareCerts() []OPCUASignedSoftwareCertificate {
	return opcuaArray(r, opcuaMinSoftCertLen, func() OPCUASignedSoftwareCertificate {
		return OPCUASignedSoftwareCertificate{CertificateData: r.byteString(), Signature: r.byteString()}
	})
}

func (r *opcuaReader) findServersRequest() *OPCUAFindServersRequest {
	return &OPCUAFindServersRequest{EndpointURL: r.str(), LocaleIDs: r.strings(), ServerURIs: r.strings()}
}

func (r *opcuaReader) createSessionRequest() *OPCUACreateSessionRequest {
	return &OPCUACreateSessionRequest{
		ClientDescription:       r.applicationDescription(),
		ServerURI:               r.str(),
		EndpointURL:             r.str(),
		SessionName:             r.str(),
		ClientNonce:             r.byteString(),
		ClientCertificate:       r.byteString(),
		RequestedSessionTimeout: r.f64(),
		MaxResponseMessageSize:  r.u32(),
	}
}

func (r *opcuaReader) createSessionResponse() *OPCUACreateSessionResponse {
	return &OPCUACreateSessionResponse{
		SessionID:                  r.nodeID(),
		AuthenticationToken:        r.nodeID(),
		RevisedSessionTimeout:      r.f64(),
		ServerNonce:                r.byteString(),
		ServerCertificate:          r.byteString(),
		ServerEndpoints:            r.endpoints(),
		ServerSoftwareCertificates: r.softwareCerts(),
		ServerSignature:            r.signatureData(),
		MaxRequestMessageSize:      r.u32(),
	}
}

func (r *opcuaReader) activateSessionRequest() *OPCUAActivateSessionRequest {
	req := &OPCUAActivateSessionRequest{
		ClientSignature:            r.signatureData(),
		ClientSoftwareCertificates: r.softwareCerts(),
		LocaleIDs:                  r.strings(),
		UserIdentityToken:          r.extensionObject(),
		UserTokenSignature:         r.signatureData(),
	}
	req.IdentityToken = decodeIdentityToken(req.UserIdentityToken)
	return req
}

func (r *opcuaReader) activateSessionResponse() *OPCUAActivateSessionResponse {
	return &OPCUAActivateSessionResponse{ServerNonce: r.byteString(), OPCUAResults: r.results()}
}

// decodeIdentityToken decodes the non-secret fields of a binary user
// identity token; it returns nil for any other ExtensionObject.
func decodeIdentityToken(e OPCUAExtensionObject) *OPCUAUserIdentityToken {
	id, ok := e.binaryTypeID()
	if !ok {
		return nil
	}
	typ, ok := opcuaIdentityTokenTypes[id]
	if !ok {
		return nil
	}

	r := &opcuaReader{b: e.Body}
	t := &OPCUAUserIdentityToken{TokenType: typ, PolicyID: r.str()}
	switch typ {
	case OPCUAUserTokenUserName:
		t.UserName = r.str()
		r.byteString() // password
		t.EncryptionAlgorithm = r.str()
	case OPCUAUserTokenCertificate:
		t.CertificateData = r.byteString()
	case OPCUAUserTokenIssued:
		r.byteString() // token data
		t.EncryptionAlgorithm = r.str()
	}
	if r.err != nil {
		return nil
	}
	return t
}
