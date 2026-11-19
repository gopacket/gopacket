// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO security blocks: the AR block of a secured (SXP)
// connection and the services that manage credentials and security
// settings. The layouts are the ones Wireshark 4.7 dissects; the standard
// is not public.
//
// The service blocks open with an operation that selects what follows:
//
//	+-----------+----------------------------------------------+
//	| Operation | CredentialID or DevIDDomain, then parameters |
//	| 2         | n                                            |
//	+-----------+----------------------------------------------+
//
// Certificates, certification requests and EAP messages stay opaque
// bytes: only the framing around them is decoded.

package layers

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Security block types and the type of their ProfinetBlock.Value.
const (
	ProfinetBlockARSXPReq        ProfinetBlockType = 0x010D // *ProfinetARSXPBlock
	ProfinetBlockSecurityReq     ProfinetBlockType = 0x011A // *ProfinetSecurityService
	ProfinetBlockRecordQuery     ProfinetBlockType = 0x0500 // *ProfinetRecordQuery
	ProfinetBlockSAMReq          ProfinetBlockType = 0x06E0 // *ProfinetSCMService
	ProfinetBlockARAlgorithmInfo ProfinetBlockType = 0x06E2 // *ProfinetARAlgorithmInfo
	ProfinetBlockSCMReq          ProfinetBlockType = 0x06F0 // *ProfinetSCMService
	ProfinetBlockARSXPRes        ProfinetBlockType = 0x810D // *ProfinetARSXPBlock
	ProfinetBlockSecurityRes     ProfinetBlockType = 0x811A // *ProfinetSecurityService
	ProfinetBlockAuditableEvents ProfinetBlockType = 0x811C // *ProfinetAuditableEvents
	ProfinetBlockSAMRes          ProfinetBlockType = 0x86E0 // *ProfinetSCMService
	ProfinetBlockSCMRes          ProfinetBlockType = 0x86F0 // *ProfinetSCMService
)

const (
	profinetARSXPReqLen     = 42 // ARType .. StationNameLength
	profinetARSXPResLen     = 38
	profinetSXPEndpointLen  = 8
	profinetAlgorithmLen    = 14
	profinetLengthPrefixLen = 2 // a list element is at least its length
	profinetCredentialIDLen = 4
	profinetSecConfigLen    = 8
	profinetEAPHeaderLen    = 4
	profinetEAPLengthOff    = 2

	profinetCredentialTypeMask = 0x3
	profinetSecConfigModeMask  = 0x3
	profinetSecConfigChkShift  = 2
	profinetSecConfigSACKShift = 8
	profinetSCMConfigSACKShift = 16
)

// ProfinetSXPEndpoint is the SXP destination endpoint of an ARSXPBlock.
type ProfinetSXPEndpoint struct {
	ID         uint8 // SXP_EndPointID: 1 the CIM endpoint
	VendorID   uint16
	DeviceID   uint16
	InstanceID uint16
}

func (r *profinetReader) sxpEndpoint() ProfinetSXPEndpoint {
	e := ProfinetSXPEndpoint{ID: r.u8()}
	r.skip(1)
	e.VendorID = r.u16()
	e.DeviceID = r.u16()
	e.InstanceID = r.u16()
	return e
}

// ProfinetARSXPBlock is an ARSXPBlockReq or ARSXPBlockRsp: the AR block
// of a connection over the secure transport. The response has no timeout
// factor and no properties.
type ProfinetARSXPBlock struct {
	ARType                ProfinetARType
	ARUUID                ProfinetUUID
	SessionKey            uint16
	ActivityTimeoutFactor uint16
	Properties            ProfinetARProperties
	Endpoint              ProfinetSXPEndpoint
	MAC                   net.HardwareAddr // CMInitiatorMacAdd or CMResponderMacAdd
	StationName           string
}

func decodeProfinetARSXP(r *profinetReader, t ProfinetBlockType) interface{} {
	min := profinetARSXPReqLen
	if t == ProfinetBlockARSXPRes {
		min = profinetARSXPResLen
	}
	if r.left() < min {
		return nil
	}

	a := &ProfinetARSXPBlock{ARType: ProfinetARType(r.u16()), ARUUID: r.uuid(), SessionKey: r.u16()}
	if t == ProfinetBlockARSXPReq {
		a.ActivityTimeoutFactor = r.u16()
		a.Properties = ProfinetARProperties(r.u32())
	} else {
		r.skip(2)
	}

	a.Endpoint = r.sxpEndpoint()
	a.MAC = r.mac()
	a.StationName = r.str16()
	return a
}

// ProfinetSecurityCapability is a SecurityCapability: what an algorithm
// is used for and which one it is.
type ProfinetSecurityCapability uint16

// Usage returns the low byte: 2 symmetric authenticated encryption, 4
// key agreement.
func (c ProfinetSecurityCapability) Usage() uint8 { return uint8(c) }

// Algorithm returns the high byte, read in the number space of Usage.
func (c ProfinetSecurityCapability) Algorithm() uint8 { return uint8(c >> 8) }

// ProfinetARAlgorithmInfo is the body of ARAlgorithmInfoBlock: the
// algorithms that protect an AR.
type ProfinetARAlgorithmInfo struct {
	IOProtection    ProfinetSecurityCapability // InputOutputProtectionAlgorithm
	AlarmProtection ProfinetSecurityCapability // AlarmProtectionAlgorithm
	SXPProtection   ProfinetSecurityCapability // SXPProtectionAlgorithm
	KeyDerivation   ProfinetSecurityCapability // KeyDerivationAlgorithm
	KeyAgreement    ProfinetSecurityCapability // KeyAgreementAlgorithm
}

func decodeProfinetAlgorithms(r *profinetReader) interface{} {
	if r.left() < profinetAlgorithmLen {
		return nil
	}

	r.skip(2)
	return &ProfinetARAlgorithmInfo{
		IOProtection:    ProfinetSecurityCapability(r.u16()),
		AlarmProtection: ProfinetSecurityCapability(r.u16()),
		SXPProtection:   ProfinetSecurityCapability(r.u16()),
		KeyDerivation:   ProfinetSecurityCapability(r.u16()),
		KeyAgreement:    ProfinetSecurityCapability(r.u16()),
	}
}

// ProfinetSecurityOperation is the SecurityOperation, SCMOperation or
// SAMOperation that opens a security service block.
type ProfinetSecurityOperation uint16

// Security operations.
const (
	ProfinetSecOpGetCapabilities ProfinetSecurityOperation = 0x0001
	ProfinetSecOpGetCredentials  ProfinetSecurityOperation = 0x0002 // SecurityOperation only
	ProfinetSecOpGetConfig       ProfinetSecurityOperation = 0x0003
	ProfinetSecOpGetEEPath       ProfinetSecurityOperation = 0x0004
	ProfinetSecOpGetTrustedCA    ProfinetSecurityOperation = 0x0005
	ProfinetSecOpGenerateKeyCSR  ProfinetSecurityOperation = 0x0006
	ProfinetSecOpImprintEEPath   ProfinetSecurityOperation = 0x0008
	ProfinetSecOpRemoveEEPath    ProfinetSecurityOperation = 0x0009
	ProfinetSecOpImprintCA       ProfinetSecurityOperation = 0x000A
	ProfinetSecOpRemoveCA        ProfinetSecurityOperation = 0x000B
	ProfinetSecOpSetConfig       ProfinetSecurityOperation = 0x000C
	ProfinetSecOpReset           ProfinetSecurityOperation = 0x000D // SCMOperation only
	ProfinetSecOpEAP             ProfinetSecurityOperation = 0x0100 // SAMOperation only
)

// String returns the operation name used by Wireshark.
func (o ProfinetSecurityOperation) String() string {
	switch o {
	case ProfinetSecOpGetCapabilities:
		return "Get Security Capabilities"
	case ProfinetSecOpGetCredentials:
		return "Get Available CredentialIDs"
	case ProfinetSecOpGetConfig:
		return "Get Security Configuration Parameters"
	case ProfinetSecOpGetEEPath:
		return "Get EE Certification Path"
	case ProfinetSecOpGetTrustedCA:
		return "Get Trusted CA Certificate"
	case ProfinetSecOpGenerateKeyCSR:
		return "Generate Key Pair And CSR"
	case ProfinetSecOpImprintEEPath:
		return "Imprint EE Certification Path"
	case ProfinetSecOpRemoveEEPath:
		return "Remove EE Certification Path and Private Key"
	case ProfinetSecOpImprintCA:
		return "Imprint Trusted CA Certificate"
	case ProfinetSecOpRemoveCA:
		return "Remove Trusted CA Certificate"
	case ProfinetSecOpSetConfig:
		return "Set Security Configuration Parameters"
	case ProfinetSecOpReset:
		return "Reset Security Data"
	case ProfinetSecOpEAP:
		return "Process EAP Message"
	}
	return fmt.Sprintf("Reserved(0x%04x)", uint16(o))
}

// ProfinetCredentialID is a CredentialID; bits 0-1 are the credential
// type, zero when no credential exists.
type ProfinetCredentialID uint32

// Type returns the credential type (bits 0-1).
func (c ProfinetCredentialID) Type() uint8 { return uint8(c) & profinetCredentialTypeMask }

// ProfinetSecurityConfig is SecurityConfigurationParameters as a
// SecurityRequestBlock and a SecurityResponse carry it.
type ProfinetSecurityConfig uint64

// SecurityMode returns bits 0-1; zero preserves the stored value.
func (c ProfinetSecurityConfig) SecurityMode() uint8 { return uint8(c) & profinetSecConfigModeMask }

// ValidityPeriodCheck returns CertificateValidityPeriodCheck (bits 2-3).
func (c ProfinetSecurityConfig) ValidityPeriodCheck() uint8 {
	return uint8(c>>profinetSecConfigChkShift) & profinetTwoBitMask
}

// SACKDegradationThreshold returns bits 8-15.
func (c ProfinetSecurityConfig) SACKDegradationThreshold() uint8 {
	return uint8(c >> profinetSecConfigSACKShift)
}

// ProfinetSCMConfig is SecurityConfigurationParameters as the SCM and
// SAM blocks carry it.
type ProfinetSCMConfig uint64

// ValidityPeriodCheck returns CredentialValidityPeriodCheck (bits 2-3).
func (c ProfinetSCMConfig) ValidityPeriodCheck() uint8 {
	return uint8(c>>profinetSecConfigChkShift) & profinetTwoBitMask
}

// SACKDegradationFactor returns SACKDegradationThresholdFactor (bits
// 16-31).
func (c ProfinetSCMConfig) SACKDegradationFactor() uint16 {
	return uint16(c >> profinetSCMConfigSACKShift)
}

// ProfinetSecurityParams holds what both security services carry behind
// the operation and its identifier.
type ProfinetSecurityParams struct {
	// Get Security Capabilities response: bit 0 of Features is key pair
	// generation in a SecurityResponse and validity period checking in
	// an SCM response.
	Features     uint16
	Capabilities []ProfinetSecurityCapability

	// Certificates holds the DER certificates of a certification path or
	// the one trusted CA certificate, opaque.
	Certificates [][]byte

	// CSR is the certification request information of a Generate Key
	// Pair And CSR request, or the request its response returns, opaque.
	// The request carries no length: it runs to the end of the block,
	// padding included.
	CSR []byte

	// Data holds what follows an operation with no known parameters.
	Data []byte
}

// ProfinetSecurityService is the body of SecurityRequestBlock and
// SecurityResponse.
type ProfinetSecurityService struct {
	Operation    ProfinetSecurityOperation
	CredentialID ProfinetCredentialID   // requests of the operations 4 to 11
	Config       ProfinetSecurityConfig // Get and Set Security Configuration
	Credentials  []ProfinetCredentialID // Get Available CredentialIDs response
	ProfinetSecurityParams
}

// ProfinetSCMService is the body of SCMRequestBlock, SCMResponseBlock,
// SAMRequestBlock and SAMResponseBlock. Wireshark reads all four alike;
// only the SAM blocks carry EAP.
type ProfinetSCMService struct {
	Operation   ProfinetSecurityOperation
	DevIDDomain uint32            // requests that name a credential
	Config      ProfinetSCMConfig // Get and Set Security Configuration
	EAP         []byte            // Process EAP Message: one EAP packet
	ProfinetSecurityParams
}

// lenBytes reads a 16-bit length and that many bytes, clipped to the
// body.
func (r *profinetReader) lenBytes() []byte {
	return r.clipBytes(int(r.u16()))
}

// certificates reads a certification path: two padding bytes, a count
// and that many length-prefixed certificates, each padded to a multiple
// of four bytes from the block start.
func (r *profinetReader) certificates() [][]byte {
	r.skip(2)

	certs := make([][]byte, r.count(profinetLengthPrefixLen))
	for i := range certs {
		certs[i] = r.lenBytes()
		r.align()
	}
	return certs
}

// capabilities reads the SecurityFeatures word and the counted list of
// capabilities of a Get Security Capabilities response.
func (p *ProfinetSecurityParams) capabilities(r *profinetReader) {
	p.Features = r.u16()

	p.Capabilities = make([]ProfinetSecurityCapability, r.count(2))
	for i := range p.Capabilities {
		p.Capabilities[i] = ProfinetSecurityCapability(r.u16())
	}
}

// response reads the parameters the responses of both services share. It
// reports whether the operation has any.
func (p *ProfinetSecurityParams) response(r *profinetReader, op ProfinetSecurityOperation) bool {
	switch op {
	case ProfinetSecOpGetCapabilities:
		p.capabilities(r)
	case ProfinetSecOpGetEEPath:
		p.Certificates = r.certificates()
	case ProfinetSecOpGetTrustedCA:
		p.Certificates = [][]byte{r.lenBytes()}
	case ProfinetSecOpGenerateKeyCSR:
		p.CSR = r.lenBytes()
	case ProfinetSecOpImprintEEPath, ProfinetSecOpRemoveEEPath, ProfinetSecOpImprintCA,
		ProfinetSecOpRemoveCA, ProfinetSecOpSetConfig:
		// Acknowledged with the operation alone.
	default:
		return false
	}
	return true
}

// request reads the parameters that follow the credential of a request.
func (p *ProfinetSecurityParams) request(r *profinetReader, op ProfinetSecurityOperation) {
	switch op {
	case ProfinetSecOpGenerateKeyCSR:
		p.CSR = r.rest()
	case ProfinetSecOpImprintEEPath:
		p.Certificates = r.certificates()
	case ProfinetSecOpImprintCA:
		p.Certificates = [][]byte{r.lenBytes()}
	}
}

func decodeProfinetSecService(r *profinetReader, t ProfinetBlockType) interface{} {
	if r.left() < 2 {
		return nil
	}

	s := &ProfinetSecurityService{Operation: ProfinetSecurityOperation(r.u16())}
	op := s.Operation

	switch {
	case op == ProfinetSecOpGetConfig && t == ProfinetBlockSecurityRes,
		op == ProfinetSecOpSetConfig && t == ProfinetBlockSecurityReq:
		s.Config = ProfinetSecurityConfig(r.u64())
	case t == ProfinetBlockSecurityRes && op == ProfinetSecOpGetCredentials:
		r.skip(2)
		s.Credentials = make([]ProfinetCredentialID, r.count(profinetCredentialIDLen))
		for i := range s.Credentials {
			s.Credentials[i] = ProfinetCredentialID(r.u32())
		}
	case t == ProfinetBlockSecurityRes:
		if !s.response(r, op) {
			s.Data = r.rest()
		}
	case op >= ProfinetSecOpGetEEPath && op <= ProfinetSecOpRemoveCA:
		s.CredentialID = ProfinetCredentialID(r.u32())
		s.request(r, op)
	default:
		s.Data = r.rest()
	}
	return s
}

// scmNamesCredential reports whether an SCM request carries a
// DevIDDomain behind the operation.
func scmNamesCredential(op ProfinetSecurityOperation) bool {
	switch op {
	case ProfinetSecOpGetEEPath, ProfinetSecOpGetTrustedCA, ProfinetSecOpGenerateKeyCSR,
		ProfinetSecOpImprintEEPath, ProfinetSecOpRemoveEEPath, ProfinetSecOpImprintCA, ProfinetSecOpRemoveCA:
		return true
	}
	return false
}

// eap reads one EAP packet: code, identifier and a length that counts
// the whole packet.
func (r *profinetReader) eap() []byte {
	if r.left() < profinetEAPHeaderLen {
		return r.rest()
	}

	n := int(binary.BigEndian.Uint16(r.data[r.off+profinetEAPLengthOff:]))
	if n < profinetEAPHeaderLen {
		n = profinetEAPHeaderLen
	}
	return r.clipBytes(n)
}

func decodeProfinetSCMService(r *profinetReader, t ProfinetBlockType) interface{} {
	if r.left() < 2 {
		return nil
	}

	s := &ProfinetSCMService{Operation: ProfinetSecurityOperation(r.u16())}
	op := s.Operation
	isResponse := t&profinetBlockResponse != 0
	isSAM := t&^profinetBlockResponse == ProfinetBlockSAMReq

	switch {
	case op == ProfinetSecOpEAP && isSAM:
		s.EAP = r.eap()
	case op == ProfinetSecOpGetConfig && isResponse, op == ProfinetSecOpSetConfig && !isResponse:
		s.Config = ProfinetSCMConfig(r.u64())
	case isResponse:
		if !s.response(r, op) {
			s.Data = r.rest()
		}
	case scmNamesCredential(op):
		s.DevIDDomain = r.u32()
		s.request(r, op)
	default:
		s.Data = r.rest()
	}
	return s
}

// ProfinetAuditableEvents is the body of ReadAuditableEventsRsp: syslog
// messages (RFC 5424), each behind a 16-bit length and padded to a
// multiple of four bytes from the block start.
type ProfinetAuditableEvents struct {
	NumberOfEntries uint16
	Events          []string
}

func decodeProfinetAuditEvents(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	v := &ProfinetAuditableEvents{NumberOfEntries: binary.BigEndian.Uint16(r.data[r.off:])}
	v.Events = make([]string, r.count(profinetLengthPrefixLen))
	for i := range v.Events {
		v.Events[i] = r.str16()
		r.align()
	}
	return v
}

// ProfinetRecordQuery is the body of RecordDataReadQuery: the query a
// read request passes to the record, user specific.
type ProfinetRecordQuery struct {
	Data []byte
}

// decodeSecValue decodes the security blocks and RecordDataReadQuery,
// version 1.0.
func (b *ProfinetBlock) decodeSecValue(r *profinetReader, low uint8) interface{} {
	if low != 0 {
		return nil
	}

	switch b.Type {
	case ProfinetBlockARSXPReq, ProfinetBlockARSXPRes:
		return decodeProfinetARSXP(r, b.Type)
	case ProfinetBlockSecurityReq, ProfinetBlockSecurityRes:
		return decodeProfinetSecService(r, b.Type)
	case ProfinetBlockSAMReq, ProfinetBlockSAMRes, ProfinetBlockSCMReq, ProfinetBlockSCMRes:
		return decodeProfinetSCMService(r, b.Type)
	case ProfinetBlockARAlgorithmInfo:
		return decodeProfinetAlgorithms(r)
	case ProfinetBlockAuditableEvents:
		return decodeProfinetAuditEvents(r)
	case ProfinetBlockRecordQuery:
		return &ProfinetRecordQuery{Data: r.rest()}
	}
	return nil
}
