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
)

var errACSEUnknown = errors.New("ACSE: unknown APDU")

// ACSEAETitle is an AP-title / AE-qualifier pair in their form 2 encoding
// (OBJECT IDENTIFIER and INTEGER). Form 1 (directory name) is kept raw.
type ACSEAETitle struct {
	APTitle        string
	APTitleRaw     []byte
	AEQualifier    int64
	HasAEQualifier bool
}

// ACSE is an ISO 8650-1 APDU. The layer payload is the single-ASN1-type
// of the first user-information EXTERNAL, normally an MMS initiate PDU.
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
	case acseTagCalledAEQual:
		err = a.Called.decodeAEQualifier(f.Value)
	case acseTagCallingAPTitle:
		err = a.Calling.decodeAPTitle(f.Value)
	case acseTagCallingAEQual:
		err = a.Calling.decodeAEQualifier(f.Value)
	case acseTagMechanism:
		a.MechanismName, err = osiBEROID(f.Value)
	case acseTagCallingAuth:
		a.Authentication = f.Value
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
	case acseTagRespAEQual:
		err = a.Responding.decodeAEQualifier(f.Value)
	case acseTagRespMech:
		a.MechanismName, err = osiBEROID(f.Value)
	case acseTagRespAuth:
		a.Authentication = f.Value
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
