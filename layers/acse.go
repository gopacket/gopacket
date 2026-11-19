// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// LayerTypeACSE is the ISO 8650-1 Association Control Service Element.
var LayerTypeACSE = gopacket.RegisterLayerType(197, gopacket.LayerTypeMetadata{Name: "ACSE", Decoder: gopacket.DecodeFunc(decodeACSE)})

// ACSEAPDUType is the APPLICATION tag of an ACSE APDU.
type ACSEAPDUType uint8

// ACSE APDUs.
const (
	ACSEAARQ ACSEAPDUType = 0
	ACSEAARE ACSEAPDUType = 1
	ACSERLRQ ACSEAPDUType = 2
	ACSERLRE ACSEAPDUType = 3
	ACSEABRT ACSEAPDUType = 4
)

// String returns the APDU name.
func (t ACSEAPDUType) String() string {
	switch t {
	case ACSEAARQ:
		return "AARQ"
	case ACSEAARE:
		return "AARE"
	case ACSERLRQ:
		return "RLRQ"
	case ACSERLRE:
		return "RLRE"
	case ACSEABRT:
		return "ABRT"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(t))
	}
}

// ACSEResult is the AARE Associate-result.
type ACSEResult int64

// Associate-result values.
const (
	ACSEAccepted          ACSEResult = 0
	ACSERejectedPermanent ACSEResult = 1
	ACSERejectedTransient ACSEResult = 2
)

// String returns the result name.
func (r ACSEResult) String() string {
	switch r {
	case ACSEAccepted:
		return "accepted"
	case ACSERejectedPermanent:
		return "rejected-permanent"
	case ACSERejectedTransient:
		return "rejected-transient"
	default:
		return fmt.Sprintf("Unknown(%d)", int64(r))
	}
}

// ACSEDiagnosticSource tells who produced an AARE result-source-diagnostic.
type ACSEDiagnosticSource uint8

// Associate-source-diagnostic alternatives.
const (
	ACSEDiagnosticNone            ACSEDiagnosticSource = 0
	ACSEDiagnosticServiceUser     ACSEDiagnosticSource = 1
	ACSEDiagnosticServiceProvider ACSEDiagnosticSource = 2
)

// String returns the source name.
func (s ACSEDiagnosticSource) String() string {
	switch s {
	case ACSEDiagnosticNone:
		return "none"
	case ACSEDiagnosticServiceUser:
		return "acse-service-user"
	case ACSEDiagnosticServiceProvider:
		return "acse-service-provider"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// AARQ field tags; AARE fields share the protocol-version and
// application-context-name tags.
const (
	acseTagAppContext     uint32 = 1
	acseTagCalledAPTitle  uint32 = 2
	acseTagCalledAEQual   uint32 = 3
	acseTagCallingAPTitle uint32 = 6
	acseTagCallingAEQual  uint32 = 7
	acseTagMechanism      uint32 = 11
	acseTagCallingAuth    uint32 = 12
	acseTagImplInfo       uint32 = 29
	acseTagUserInfo       uint32 = 30
	acseTagVersion        uint32 = 0
	acseTagSenderReqs     uint32 = 10
	acseTagCallingNames   uint32 = 13
	acseTagRespReqs       uint32 = 8
	acseTagRespNames      uint32 = 11
	acseTagAuthOther      uint32 = 3

	acseTagResult       uint32 = 2
	acseTagResultDiag   uint32 = 3
	acseTagRespAPTitle  uint32 = 4
	acseTagRespAEQual   uint32 = 5
	acseTagRespMech     uint32 = 9
	acseTagRespAuth     uint32 = 10
	acseTagReason       uint32 = 0
	acseTagAbortSource  uint32 = 0
	acseTagAbortDiag    uint32 = 1
	acseTagAPTitleForm2 uint32 = osiBERTagOID
	acseTagAEQualForm2  uint32 = osiBERTagInteger

	acseTagCalledAPInv   uint32 = 4
	acseTagCalledAEInv   uint32 = 5
	acseTagCallingAPInv  uint32 = 8
	acseTagCallingAEInv  uint32 = 9
	acseTagRespAPInv     uint32 = 6
	acseTagRespAEInv     uint32 = 7
	acseTagAPTitleForm1  uint32 = osiBERTagSequence
	acseTagAEQualForm1   uint32 = osiBERTagSet
	acseTagAttributeType uint32 = osiBERTagOID
)

var (
	errACSEUnknown    = errors.New("ACSE: unknown APDU")
	errACSENoUserInfo = errors.New("ACSE: no such user-information")
)

// ACSEAETitle is an AP-title / AE-qualifier pair in their form 2 encoding
// (OBJECT IDENTIFIER and INTEGER). Form 1 (directory name) is kept raw.
type ACSEAETitle struct {
	APTitle        string
	APTitleRaw     []byte
	AEQualifier    int64
	HasAEQualifier bool
}

// ACSEAttribute is one AttributeTypeAndValue of a directory Name, e.g.
// type "2.5.4.3" (commonName) and value "IED1". RDN is the index of its
// RelativeDistinguishedName; Value holds the value octets of the
// attribute value element.
type ACSEAttribute struct {
	RDN   int
	Type  string
	Value []byte
}

// ACSEAEInfo holds the parts of an AE title that ACSEAETitle leaves out:
// the form 1 AP-title (a directory Name) and AE-qualifier (a
// RelativeDistinguishedName), and the AP and AE invocation identifiers.
type ACSEAEInfo struct {
	APTitleName       []ACSEAttribute
	AEQualifierName   []ACSEAttribute
	APInvocationID    int64
	HasAPInvocationID bool
	AEInvocationID    int64
	HasAEInvocationID bool
}

// ACSE is an ISO 8650-1 APDU. The layer payload is the single-ASN1-type
// of the first user-information EXTERNAL, normally an MMS initiate PDU;
// UserLayer decodes any of them.
//
// CalledInfo, CallingInfo and RespondingInfo are best effort: a
// malformed form 1 name or invocation identifier leaves them unset.
type ACSE struct {
	BaseLayer
	Type               ACSEAPDUType
	ApplicationContext string
	Called             ACSEAETitle
	Calling            ACSEAETitle
	Responding         ACSEAETitle
	Result             ACSEResult
	DiagnosticSource   ACSEDiagnosticSource
	Diagnostic         int64
	// Reason is the RLRQ/RLRE reason; HasReason tells it was present.
	Reason    int64
	HasReason bool
	// AbortSource is 0 for acse-service-user, 1 for acse-service-provider.
	AbortSource     int64
	AbortDiagnostic int64
	MechanismName   string
	// Authentication is the raw Authentication-value CHOICE element; for
	// the charstring alternative it holds a password in clear.
	Authentication  []byte
	Implementation  string
	UserInformation []ISOPresentationPDV

	CalledInfo     ACSEAEInfo
	CallingInfo    ACSEAEInfo
	RespondingInfo ACSEAEInfo

	// AuthenticationKind and AuthenticationValue are the alternative and
	// value of Authentication: the password of a charstring, the BIT
	// STRING value, or the body of the EXTERNAL or other SEQUENCE. They
	// are best effort, like the fields below: malformed ones stay unset.
	AuthenticationKind  ACSEAuthenticationKind
	AuthenticationValue []byte
	// Requirements is the sender- or responder-acse-requirements.
	Requirements    ACSERequirements
	HasRequirements bool
	// ProtocolVersion is the protocol-version BIT STRING: 0x80 version1.
	ProtocolVersion    uint8
	HasProtocolVersion bool
	// ContextNames is the application-context-name-list.
	ContextNames []string
}

// ACSEAuthenticationKind is the Authentication-value CHOICE tag.
type ACSEAuthenticationKind uint8

// Authentication-value alternatives. ACSEAuthNone means no value, or one
// that does not parse.
const (
	ACSEAuthNone ACSEAuthenticationKind = iota
	ACSEAuthCharString
	ACSEAuthBitString
	ACSEAuthExternal
	ACSEAuthOther
)

// String returns the ASN.1 name of the alternative.
func (k ACSEAuthenticationKind) String() string {
	switch k {
	case ACSEAuthNone:
		return "none"
	case ACSEAuthCharString:
		return "charstring"
	case ACSEAuthBitString:
		return "bitstring"
	case ACSEAuthExternal:
		return "external"
	case ACSEAuthOther:
		return "other"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(k))
	}
}

// ACSERequirements is the ACSE-requirements BIT STRING.
type ACSERequirements uint8

// ACSE functional units; bit 0 is the most significant.
const (
	ACSERequireAuthentication     ACSERequirements = 0x80
	ACSERequireContextNegotiation ACSERequirements = 0x40
)

// setAuth stores an EXPLICIT Authentication-value.
func (a *ACSE) setAuth(b []byte) {
	a.Authentication = b

	t, err := osiBERSingle(b)
	if err != nil || t.Class != osiBERContext || t.Tag > acseTagAuthOther {
		return
	}
	a.AuthenticationKind = ACSEAuthenticationKind(t.Tag) + ACSEAuthCharString
	a.AuthenticationValue = t.Value
}

// decodeOptional stores the best effort AARQ and AARE fields: reqs and
// names are the tags of the requirements and context name list.
func (a *ACSE) decodeOptional(f osiBERTLV, reqs, names uint32) {
	switch {
	case f.Tag == acseTagVersion && f.Form == osiBERPrimitive:
		a.ProtocolVersion, a.HasProtocolVersion = acseBits(f.Value)
	case f.Tag == reqs && f.Form == osiBERPrimitive:
		var v uint8
		v, a.HasRequirements = acseBits(f.Value)
		a.Requirements = ACSERequirements(v)
	case f.Tag == names && f.Form == osiBERConstructed:
		a.ContextNames, _ = decodeISOPresOIDs(f.Value)
	}
}

// acseBits returns the first octet of a BIT STRING value, 0 when it has
// no bits.
func acseBits(v []byte) (uint8, bool) {
	bits, _, err := osiBERBits(v)
	if err != nil {
		return 0, false
	}
	if len(bits) == 0 {
		return 0, true
	}
	return bits[0], true
}

// LayerType returns LayerTypeACSE.
func (a *ACSE) LayerType() gopacket.LayerType { return LayerTypeACSE }

// CanDecode returns LayerTypeACSE.
func (a *ACSE) CanDecode() gopacket.LayerClass { return LayerTypeACSE }

// NextLayerType returns LayerTypeMMS when user-information holds an MMS
// PDU, gopacket.LayerTypePayload for other data, else LayerTypeZero.
func (a *ACSE) NextLayerType() gopacket.LayerType {
	if len(a.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	if a.UserInformation[0].Encoding == ISOPresentationSingleASN1 && osiRouteByTag(a.Payload) == LayerTypeMMS {
		return LayerTypeMMS
	}
	return gopacket.LayerTypePayload
}

// DecodeFromBytes decodes one ACSE APDU.
func (a *ACSE) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*a = ACSE{}

	t, rest, err := osiBERNext(data)
	if err != nil {
		return err
	}
	if t.Class != osiBERApplication || t.Form != osiBERConstructed || t.Tag > uint32(ACSEABRT) {
		return errACSEUnknown
	}
	a.Type = ACSEAPDUType(t.Tag)
	a.Contents = data[:len(data)-len(rest)]

	for b := t.Value; len(b) > 0; {
		var f osiBERTLV
		if f, b, err = osiBERNext(b); err != nil {
			return err
		}
		if f.Class != osiBERContext {
			continue
		}
		if err := a.decodeField(f); err != nil {
			return err
		}
	}

	if len(a.UserInformation) > 0 {
		a.Payload = a.UserInformation[0].Data
	}
	return nil
}

// decodeField stores one field; tag meanings depend on the APDU type.
func (a *ACSE) decodeField(f osiBERTLV) error {
	if f.Tag == acseTagUserInfo {
		return a.decodeUserInfo(f.Value)
	}
	if f.Tag == acseTagImplInfo {
		a.Implementation = string(f.Value)
		return nil
	}

	switch a.Type {
	case ACSEAARQ:
		return a.decodeAARQField(f)
	case ACSEAARE:
		return a.decodeAAREField(f)
	case ACSERLRQ, ACSERLRE:
		if f.Tag != acseTagReason {
			return nil
		}
		var err error
		a.Reason, err = acseInt(f)
		a.HasReason = true
		return err
	}

	// ABRT.
	var err error
	switch f.Tag {
	case acseTagAbortSource:
		a.AbortSource, err = acseInt(f)
	case acseTagAbortDiag:
		a.AbortDiagnostic, err = acseInt(f)
	}
	return err
}

// decodeAARQField stores one AARQ field.
func (a *ACSE) decodeAARQField(f osiBERTLV) error {
	var err error
	switch f.Tag {
	case acseTagAppContext:
		a.ApplicationContext, err = acseExplicitOID(f.Value)
	case acseTagCalledAPTitle:
		err = a.Called.decodeAPTitle(f.Value)
		a.CalledInfo.decodeAPTitle(f.Value)
	case acseTagCalledAEQual:
		err = a.Called.decodeAEQualifier(f.Value)
		a.CalledInfo.decodeAEQualifier(f.Value)
	case acseTagCallingAPTitle:
		err = a.Calling.decodeAPTitle(f.Value)
		a.CallingInfo.decodeAPTitle(f.Value)
	case acseTagCallingAEQual:
		err = a.Calling.decodeAEQualifier(f.Value)
		a.CallingInfo.decodeAEQualifier(f.Value)
	case acseTagCalledAPInv:
		a.CalledInfo.APInvocationID, a.CalledInfo.HasAPInvocationID = acseInvocation(f)
	case acseTagCalledAEInv:
		a.CalledInfo.AEInvocationID, a.CalledInfo.HasAEInvocationID = acseInvocation(f)
	case acseTagCallingAPInv:
		a.CallingInfo.APInvocationID, a.CallingInfo.HasAPInvocationID = acseInvocation(f)
	case acseTagCallingAEInv:
		a.CallingInfo.AEInvocationID, a.CallingInfo.HasAEInvocationID = acseInvocation(f)
	case acseTagMechanism:
		a.MechanismName, err = osiBEROID(f.Value)
	case acseTagCallingAuth:
		a.setAuth(f.Value)
	default:
		a.decodeOptional(f, acseTagSenderReqs, acseTagCallingNames)
	}
	return err
}

// decodeAAREField stores one AARE field.
func (a *ACSE) decodeAAREField(f osiBERTLV) error {
	var err error
	switch f.Tag {
	case acseTagAppContext:
		a.ApplicationContext, err = acseExplicitOID(f.Value)
	case acseTagResult:
		var v []byte
		if v, _, err = osiBERExpect(f.Value, osiBERUniversal, osiBERPrimitive, osiBERTagInteger); err == nil {
			var r int64
			r, err = osiBERInt(v)
			a.Result = ACSEResult(r)
		}
	case acseTagResultDiag:
		err = a.decodeDiagnostic(f.Value)
	case acseTagRespAPTitle:
		err = a.Responding.decodeAPTitle(f.Value)
		a.RespondingInfo.decodeAPTitle(f.Value)
	case acseTagRespAEQual:
		err = a.Responding.decodeAEQualifier(f.Value)
		a.RespondingInfo.decodeAEQualifier(f.Value)
	case acseTagRespAPInv:
		a.RespondingInfo.APInvocationID, a.RespondingInfo.HasAPInvocationID = acseInvocation(f)
	case acseTagRespAEInv:
		a.RespondingInfo.AEInvocationID, a.RespondingInfo.HasAEInvocationID = acseInvocation(f)
	case acseTagRespMech:
		a.MechanismName, err = osiBEROID(f.Value)
	case acseTagRespAuth:
		a.setAuth(f.Value)
	default:
		a.decodeOptional(f, acseTagRespReqs, acseTagRespNames)
	}
	return err
}

// decodeDiagnostic reads result-source-diagnostic: CHOICE {
// acse-service-user [1] INTEGER, acse-service-provider [2] INTEGER }.
func (a *ACSE) decodeDiagnostic(b []byte) error {
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}
	if t.Class != osiBERContext || t.Form != osiBERConstructed {
		return errOSIBERUnexpected
	}
	switch t.Tag {
	case uint32(ACSEDiagnosticServiceUser), uint32(ACSEDiagnosticServiceProvider):
	default:
		return errOSIBERUnexpected
	}
	a.DiagnosticSource = ACSEDiagnosticSource(t.Tag)

	v, _, err := osiBERExpect(t.Value, osiBERUniversal, osiBERPrimitive, osiBERTagInteger)
	if err != nil {
		return err
	}
	a.Diagnostic, err = osiBERInt(v)
	return err
}

// decodeUserInfo reads Association-information: SEQUENCE OF EXTERNAL.
func (a *ACSE) decodeUserInfo(b []byte) error {
	for len(b) > 0 {
		v, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagExternal)
		if err != nil {
			return err
		}
		b = rest

		ext, err := decodeISOPresPDV(v)
		if err != nil {
			return err
		}
		a.UserInformation = append(a.UserInformation, ext)
	}
	return nil
}

// decodeAPTitle reads an EXPLICIT AP-title; form 2 is an OID.
func (t *ACSEAETitle) decodeAPTitle(b []byte) error {
	inner, err := osiBERSingle(b)
	if err != nil {
		return err
	}
	t.APTitleRaw = inner.Value
	if !inner.is(osiBERUniversal, osiBERPrimitive, acseTagAPTitleForm2) {
		return nil
	}
	t.APTitle, err = osiBEROID(inner.Value)
	return err
}

// decodeAEQualifier reads an EXPLICIT AE-qualifier; form 2 is an INTEGER.
func (t *ACSEAETitle) decodeAEQualifier(b []byte) error {
	inner, err := osiBERSingle(b)
	if err != nil {
		return err
	}
	if !inner.is(osiBERUniversal, osiBERPrimitive, acseTagAEQualForm2) {
		return nil
	}
	t.AEQualifier, err = osiBERInt(inner.Value)
	t.HasAEQualifier = true
	return err
}

// decodeAPTitle keeps a form 1 AP-title: a Name, which is an
// RDNSequence.
func (i *ACSEAEInfo) decodeAPTitle(b []byte) {
	inner, err := osiBERSingle(b)
	if err != nil || !inner.is(osiBERUniversal, osiBERConstructed, acseTagAPTitleForm1) {
		return
	}
	i.APTitleName, _ = decodeACSEName(inner.Value)
}

// decodeAEQualifier keeps a form 1 AE-qualifier: one
// RelativeDistinguishedName.
func (i *ACSEAEInfo) decodeAEQualifier(b []byte) {
	inner, err := osiBERSingle(b)
	if err != nil || !inner.is(osiBERUniversal, osiBERConstructed, acseTagAEQualForm1) {
		return
	}

	count, err := osiBERCount(inner.Value)
	if err != nil {
		return
	}
	i.AEQualifierName, _ = decodeACSERDN(inner.Value, 0, make([]ACSEAttribute, 0, count))
}

// decodeACSEName decodes an RDNSequence body: SEQUENCE OF SET OF
// SEQUENCE { type OID, value ANY }.
func decodeACSEName(b []byte) ([]ACSEAttribute, error) {
	// Count the attributes of all RDNs to allocate once.
	total := 0
	for rest := b; len(rest) > 0; {
		set, more, err := osiBERExpect(rest, osiBERUniversal, osiBERConstructed, osiBERTagSet)
		if err != nil {
			return nil, err
		}
		rest = more

		n, err := osiBERCount(set)
		if err != nil {
			return nil, err
		}
		total += n
	}

	out := make([]ACSEAttribute, 0, total)
	for rdn := 0; len(b) > 0; rdn++ {
		set, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSet)
		if err != nil {
			return nil, err
		}
		b = rest

		if out, err = decodeACSERDN(set, rdn, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// decodeACSERDN appends the AttributeTypeAndValues of one
// RelativeDistinguishedName body.
func decodeACSERDN(b []byte, rdn int, out []ACSEAttribute) ([]ACSEAttribute, error) {
	for len(b) > 0 {
		atv, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		v, rest, err := osiBERExpect(atv, osiBERUniversal, osiBERPrimitive, acseTagAttributeType)
		if err != nil {
			return nil, err
		}
		oid, err := osiBEROID(v)
		if err != nil {
			return nil, err
		}

		val, err := osiBERSingle(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, ACSEAttribute{RDN: rdn, Type: oid, Value: val.Value})
	}
	return out, nil
}

// acseInvocation reads an EXPLICIT INTEGER invocation identifier; ok is
// false when it is malformed.
func acseInvocation(f osiBERTLV) (int64, bool) {
	v, _, err := osiBERExpect(f.Value, osiBERUniversal, osiBERPrimitive, osiBERTagInteger)
	if err != nil || f.Form != osiBERConstructed {
		return 0, false
	}

	n, err := osiBERInt(v)
	return n, err == nil
}

// UserLayer decodes user-information EXTERNAL i as an MMS PDU, or as
// ACSE when it holds one. It returns nil, nil for other data.
func (a *ACSE) UserLayer(i int) (gopacket.Layer, error) {
	if i < 0 || i >= len(a.UserInformation) {
		return nil, errACSENoUserInfo
	}

	ext := a.UserInformation[i]
	if ext.Encoding != ISOPresentationSingleASN1 {
		return nil, nil
	}
	return osiDecodeLayer(osiRouteByTag(ext.Data), ext.Data)
}

// acseInt reads an IMPLICIT INTEGER field, which must be primitive.
func acseInt(f osiBERTLV) (int64, error) {
	if f.Form != osiBERPrimitive {
		return 0, errOSIBERUnexpected
	}
	return osiBERInt(f.Value)
}

// acseExplicitOID reads an EXPLICIT OBJECT IDENTIFIER.
func acseExplicitOID(b []byte) (string, error) {
	v, _, err := osiBERExpect(b, osiBERUniversal, osiBERPrimitive, osiBERTagOID)
	if err != nil {
		return "", err
	}
	return osiBEROID(v)
}

func decodeACSE(data []byte, p gopacket.PacketBuilder) error {
	a := &ACSE{}
	return decodingLayerDecoder(a, data, p)
}
