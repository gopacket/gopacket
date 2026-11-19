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

// LayerTypeISOPresentation is the ISO 8823 connection oriented
// presentation layer.
var LayerTypeISOPresentation = gopacket.RegisterLayerType(196, gopacket.LayerTypeMetadata{Name: "ISOPresentation", Decoder: gopacket.DecodeFunc(decodeISOPresentation)})

// ISOPresentationType is the kind of PPDU.
type ISOPresentationType uint8

// PPDU kinds. ISOPresentationUserData covers TD and the data of other
// session SPDUs: a bare fully- or simply-encoded User-data.
const (
	ISOPresentationCP ISOPresentationType = iota + 1
	ISOPresentationCPA
	ISOPresentationCPR
	ISOPresentationARU
	ISOPresentationARP
	ISOPresentationUserData
)

// String returns the PPDU abbreviation.
func (t ISOPresentationType) String() string {
	switch t {
	case ISOPresentationCP:
		return "CP"
	case ISOPresentationCPA:
		return "CPA"
	case ISOPresentationCPR:
		return "CPR"
	case ISOPresentationARU:
		return "ARU"
	case ISOPresentationARP:
		return "ARP"
	case ISOPresentationUserData:
		return "UserData"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(t))
	}
}

// ISOPresentationEncoding is the presentation-data-values (or EXTERNAL
// encoding) CHOICE of a PDV.
type ISOPresentationEncoding uint8

// PDV encodings.
const (
	ISOPresentationSingleASN1   ISOPresentationEncoding = 0
	ISOPresentationOctetAligned ISOPresentationEncoding = 1
	ISOPresentationArbitrary    ISOPresentationEncoding = 2
)

// String returns the ASN.1 name of the encoding.
func (e ISOPresentationEncoding) String() string {
	switch e {
	case ISOPresentationSingleASN1:
		return "single-ASN1-type"
	case ISOPresentationOctetAligned:
		return "octet-aligned"
	case ISOPresentationArbitrary:
		return "arbitrary"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(e))
	}
}

// Well known object identifiers of the MMS stack.
const (
	osiOIDACSE = "2.2.1.0.1"    // id-as-acse abstract syntax
	osiOIDMMS  = "1.0.9506.2.1" // mms-abstract-syntax-version1
)

// CP-type, CPA, CPR, ARU and ARP field tags (ISO 8823-1 clause 8).
const (
	isoPresTagModeSelector  uint32 = 0
	isoPresTagX410Mode      uint32 = 1
	isoPresTagNormalMode    uint32 = 2
	isoPresTagModeValue     uint32 = 0
	isoPresTagVersion       uint32 = 0
	isoPresTagCalling       uint32 = 1
	isoPresTagCalled        uint32 = 2
	isoPresTagResponding    uint32 = 3
	isoPresTagContextList   uint32 = 4
	isoPresTagResultList    uint32 = 5
	isoPresTagProvReason    uint32 = 10
	isoPresTagARUNormal     uint32 = 0
	isoPresTagARUContexts   uint32 = 0
	isoPresTagARPReason     uint32 = 0
	isoPresTagARPEvent      uint32 = 1
	isoPresTagResult        uint32 = 0
	isoPresTagResultSyntax  uint32 = 1
	isoPresTagResultReason  uint32 = 2
	isoPresTagSimplyEncoded uint32 = 0
	isoPresTagFullyEncoded  uint32 = 1
)

var (
	errISOPresUnknown = errors.New("ISO presentation: unknown PPDU")
	errISOPresPDV     = errors.New("ISO presentation: PDV without data")
)

// ISOPresentationContext is one presentation-context-definition-list
// item of a CP PPDU.
type ISOPresentationContext struct {
	ID               int64
	AbstractSyntax   string
	TransferSyntaxes []string
}

// ISOPresentationResult is one presentation-context-definition-result-list
// item of a CPA or CPR PPDU. Result 0 is acceptance, 1 user-rejection and
// 2 provider-rejection.
type ISOPresentationResult struct {
	Result         int64
	TransferSyntax string
	ProviderReason int64
}

// ISOPresentationPDV is one PDV-list of fully-encoded user data. ACSE
// reuses it for EXTERNAL, where TransferSyntax is the direct-reference and
// ContextID the indirect-reference.
type ISOPresentationPDV struct {
	TransferSyntax string
	ContextID      int64
	Encoding       ISOPresentationEncoding
	Data           []byte
}

// ISOPresentation is an ISO 8823 PPDU. The layer payload is the data of
// the first PDV.
//
// Presentation context identifiers are bound to abstract syntaxes by the
// CP/CPA exchange, which later packets do not repeat. When a CP in the
// same PPDU defines the context, the PDV is routed by its abstract syntax.
// Otherwise the decoder uses the tag of the PDV data, as Wireshark's
// conventional mapping does (context 1 = ACSE, 3 = MMS): ACSE APDUs are
// APPLICATION class, MMS PDUs context class, so the two never collide.
type ISOPresentation struct {
	BaseLayer
	Type ISOPresentationType
	// Mode is the mode-value: 0 x410-1984, 1 normal.
	Mode               int64
	CallingSelector    []byte
	CalledSelector     []byte
	RespondingSelector []byte
	Contexts           []ISOPresentationContext
	Results            []ISOPresentationResult
	// ContextIDs lists the presentation-context-identifier-list of an ARU.
	ContextIDs        []int64
	ProviderReason    int64
	HasProviderReason bool
	EventID           int64
	PDVs              []ISOPresentationPDV
	SimplyEncoded     []byte

	next gopacket.LayerType
}

// LayerType returns LayerTypeISOPresentation.
func (p *ISOPresentation) LayerType() gopacket.LayerType { return LayerTypeISOPresentation }

// CanDecode returns LayerTypeISOPresentation.
func (p *ISOPresentation) CanDecode() gopacket.LayerClass { return LayerTypeISOPresentation }

// NextLayerType returns LayerTypeACSE or LayerTypeMMS for the first PDV,
// gopacket.LayerTypePayload for other data, or LayerTypeZero.
func (p *ISOPresentation) NextLayerType() gopacket.LayerType { return p.next }

// DecodeFromBytes decodes a PPDU. Without the session SPDU type, CP vs CPA
// and CPR vs ARP are told apart by the fields present.
func (p *ISOPresentation) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	return p.decode(data, 0)
}

// decode decodes a PPDU; want is the PPDU kind implied by the session SPDU,
// or 0 when unknown.
func (p *ISOPresentation) decode(data []byte, want ISOPresentationType) error {
	*p = ISOPresentation{}

	t, rest, err := osiBERNext(data)
	if err != nil {
		return err
	}
	p.Contents = data[:len(data)-len(rest)]

	switch {
	case t.is(osiBERUniversal, osiBERConstructed, osiBERTagSet):
		err = p.decodeConnect(t.Value, want)
	case t.is(osiBERUniversal, osiBERConstructed, osiBERTagSequence):
		err = p.decodeCPRorARP(t.Value, want)
	case t.is(osiBERContext, osiBERConstructed, isoPresTagARUNormal):
		p.Type = ISOPresentationARU
		err = p.decodeNormal(t.Value)
	default:
		p.Type = ISOPresentationUserData
		var ok bool
		if ok, err = p.decodeUserData(t); err == nil && !ok {
			err = errISOPresUnknown
		}
	}
	if err != nil {
		return err
	}

	p.route()
	return nil
}

// decodeConnect decodes the CP-type or CPA-PPDU SET.
func (p *ISOPresentation) decodeConnect(b []byte, want ISOPresentationType) error {
	p.Type = want
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return err
		}
		b = rest

		if t.Class != osiBERContext {
			continue
		}
		switch t.Tag {
		case isoPresTagModeSelector:
			if err := p.decodeMode(t.Value); err != nil {
				return err
			}
		case isoPresTagNormalMode:
			if err := p.decodeNormal(t.Value); err != nil {
				return err
			}
		}
	}

	// Without a session hint, a responding selector or result list means
	// CPA; anything else is taken as CP.
	if p.Type != ISOPresentationCP && p.Type != ISOPresentationCPA {
		p.Type = ISOPresentationCP
		if p.RespondingSelector != nil || p.Results != nil {
			p.Type = ISOPresentationCPA
		}
	}
	return nil
}

// decodeMode reads mode-selector { mode-value [0] INTEGER }.
func (p *ISOPresentation) decodeMode(b []byte) error {
	v, _, err := osiBERExpect(b, osiBERContext, osiBERPrimitive, isoPresTagModeValue)
	if err != nil {
		return err
	}
	p.Mode, err = osiBERInt(v)
	return err
}

// decodeCPRorARP decodes a SEQUENCE PPDU: CPR normal-mode parameters or an
// ARP. An ARP only holds two primitive integers, [0] and [1].
func (p *ISOPresentation) decodeCPRorARP(b []byte, want ISOPresentationType) error {
	p.Type = want
	if want != ISOPresentationCPR && want != ISOPresentationARP {
		p.Type = ISOPresentationARP
		if !isoPresLooksARP(b) {
			p.Type = ISOPresentationCPR
		}
	}

	if p.Type == ISOPresentationCPR {
		return p.decodeNormal(b)
	}
	return p.decodeARP(b)
}

// isoPresLooksARP reports whether b only holds ARP fields.
func isoPresLooksARP(b []byte) bool {
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil || t.Class != osiBERContext || t.Form != osiBERPrimitive || t.Tag > isoPresTagARPEvent {
			return false
		}
		b = rest
	}
	return true
}

// decodeARP reads provider-reason [0] and event-identifier [1].
func (p *ISOPresentation) decodeARP(b []byte) error {
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERPrimitive, isoPresTagARPReason):
			p.ProviderReason, err = osiBERInt(t.Value)
			p.HasProviderReason = true
		case t.is(osiBERContext, osiBERPrimitive, isoPresTagARPEvent):
			p.EventID, err = osiBERInt(t.Value)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// decodeNormal walks the normal-mode parameters of CP, CPA, CPR or ARU.
// Their tags do not clash except [0], which is a primitive
// protocol-version everywhere but a constructed context list in ARU.
func (p *ISOPresentation) decodeNormal(b []byte) error {
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return err
		}
		b = rest

		// User data is the APPLICATION class element.
		ok, err := p.decodeUserData(t)
		if err != nil {
			return err
		}
		if ok || t.Class != osiBERContext {
			continue
		}

		if err := p.decodeNormalField(t); err != nil {
			return err
		}
	}
	return nil
}

// decodeNormalField stores one context class normal-mode parameter.
func (p *ISOPresentation) decodeNormalField(t osiBERTLV) error {
	var err error
	switch {
	case t.is(osiBERContext, osiBERConstructed, isoPresTagARUContexts):
		p.ContextIDs, err = decodeISOPresIDList(t.Value)
	case t.is(osiBERContext, osiBERPrimitive, isoPresTagCalling):
		p.CallingSelector = t.Value
	case t.is(osiBERContext, osiBERPrimitive, isoPresTagCalled):
		p.CalledSelector = t.Value
	case t.is(osiBERContext, osiBERPrimitive, isoPresTagResponding):
		p.RespondingSelector = t.Value
	case t.is(osiBERContext, osiBERConstructed, isoPresTagContextList):
		p.Contexts, err = decodeISOPresContexts(t.Value)
	case t.is(osiBERContext, osiBERConstructed, isoPresTagResultList):
		p.Results, err = decodeISOPresResults(t.Value)
	case t.is(osiBERContext, osiBERPrimitive, isoPresTagProvReason):
		p.ProviderReason, err = osiBERInt(t.Value)
		p.HasProviderReason = true
	}
	return err
}

// decodeUserData decodes User-data when t is one; ok tells whether it was.
func (p *ISOPresentation) decodeUserData(t osiBERTLV) (bool, error) {
	switch {
	case t.is(osiBERApplication, osiBERPrimitive, isoPresTagSimplyEncoded):
		p.SimplyEncoded = t.Value
		return true, nil
	case t.is(osiBERApplication, osiBERConstructed, isoPresTagFullyEncoded):
	default:
		return false, nil
	}

	// fully-encoded-data: SEQUENCE OF PDV-list.
	for b := t.Value; len(b) > 0; {
		v, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return true, err
		}
		b = rest

		pdv, err := decodeISOPresPDV(v)
		if err != nil {
			return true, err
		}
		p.PDVs = append(p.PDVs, pdv)
	}
	return true, nil
}

// decodeISOPresPDV decodes a PDV-list or EXTERNAL body:
// [OID] [INTEGER] [ObjectDescriptor] CHOICE { [0] ANY, [1] OCTETS, [2] BITS }.
func decodeISOPresPDV(b []byte) (ISOPresentationPDV, error) {
	var pdv ISOPresentationPDV
	found := false
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return pdv, err
		}
		b = rest

		switch {
		case t.is(osiBERUniversal, osiBERPrimitive, osiBERTagOID):
			pdv.TransferSyntax, err = osiBEROID(t.Value)
		case t.is(osiBERUniversal, osiBERPrimitive, osiBERTagInteger):
			pdv.ContextID, err = osiBERInt(t.Value)
		case t.Class == osiBERContext && t.Tag <= uint32(ISOPresentationArbitrary):
			pdv.Encoding = ISOPresentationEncoding(t.Tag)
			pdv.Data = t.Value
			found = true
		}
		if err != nil {
			return pdv, err
		}
	}

	if !found {
		return pdv, errISOPresPDV
	}
	return pdv, nil
}

// decodeISOPresContexts decodes the presentation-context-definition-list:
// SEQUENCE OF SEQUENCE { INTEGER, OID, SEQUENCE OF OID }.
func decodeISOPresContexts(b []byte) ([]ISOPresentationContext, error) {
	var out []ISOPresentationContext
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		var c ISOPresentationContext
		v, item, err := osiBERExpect(item, osiBERUniversal, osiBERPrimitive, osiBERTagInteger)
		if err != nil {
			return nil, err
		}
		if c.ID, err = osiBERInt(v); err != nil {
			return nil, err
		}

		v, item, err = osiBERExpect(item, osiBERUniversal, osiBERPrimitive, osiBERTagOID)
		if err != nil {
			return nil, err
		}
		if c.AbstractSyntax, err = osiBEROID(v); err != nil {
			return nil, err
		}

		list, _, err := osiBERExpect(item, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		if c.TransferSyntaxes, err = decodeISOPresOIDs(list); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// decodeISOPresOIDs decodes a SEQUENCE OF OBJECT IDENTIFIER body.
func decodeISOPresOIDs(b []byte) ([]string, error) {
	var out []string
	for len(b) > 0 {
		v, rest, err := osiBERExpect(b, osiBERUniversal, osiBERPrimitive, osiBERTagOID)
		if err != nil {
			return nil, err
		}
		b = rest

		oid, err := osiBEROID(v)
		if err != nil {
			return nil, err
		}
		out = append(out, oid)
	}
	return out, nil
}

// decodeISOPresResults decodes the presentation-context-definition-result-
// list: SEQUENCE OF SEQUENCE { [0] INTEGER, [1] OID OPTIONAL, [2] INTEGER
// OPTIONAL }.
func decodeISOPresResults(b []byte) ([]ISOPresentationResult, error) {
	out := []ISOPresentationResult{}
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		var r ISOPresentationResult
		for len(item) > 0 {
			var t osiBERTLV
			if t, item, err = osiBERNext(item); err != nil {
				return nil, err
			}

			switch {
			case t.is(osiBERContext, osiBERPrimitive, isoPresTagResult):
				r.Result, err = osiBERInt(t.Value)
			case t.is(osiBERContext, osiBERPrimitive, isoPresTagResultSyntax):
				r.TransferSyntax, err = osiBEROID(t.Value)
			case t.is(osiBERContext, osiBERPrimitive, isoPresTagResultReason):
				r.ProviderReason, err = osiBERInt(t.Value)
			}
			if err != nil {
				return nil, err
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// decodeISOPresIDList decodes an ARU presentation-context-identifier-list:
// SEQUENCE OF SEQUENCE { INTEGER, OID }; only the identifiers are kept.
func decodeISOPresIDList(b []byte) ([]int64, error) {
	var out []int64
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		v, _, err := osiBERExpect(item, osiBERUniversal, osiBERPrimitive, osiBERTagInteger)
		if err != nil {
			return nil, err
		}
		id, err := osiBERInt(v)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// route sets the payload to the first PDV and picks its decoder.
func (p *ISOPresentation) route() {
	p.next = gopacket.LayerTypeZero
	switch {
	case len(p.PDVs) > 0:
		p.Payload = p.PDVs[0].Data
	case p.SimplyEncoded != nil:
		p.Payload = p.SimplyEncoded
	}
	if len(p.Payload) == 0 {
		return
	}

	// octet-aligned and arbitrary data is opaque.
	if len(p.PDVs) > 0 && p.PDVs[0].Encoding != ISOPresentationSingleASN1 {
		p.next = gopacket.LayerTypePayload
		return
	}

	// A context defined in this very PPDU names its abstract syntax.
	if len(p.PDVs) > 0 {
		for _, c := range p.Contexts {
			if c.ID != p.PDVs[0].ContextID {
				continue
			}
			switch c.AbstractSyntax {
			case osiOIDACSE:
				p.next = LayerTypeACSE
				return
			case osiOIDMMS:
				p.next = LayerTypeMMS
				return
			}
		}
	}
	p.next = osiRouteByTag(p.Payload)
}

// osiRouteByTag picks ACSE for APPLICATION 0-4 APDUs and MMS for context
// class PDUs; anything else stays payload.
func osiRouteByTag(b []byte) gopacket.LayerType {
	if len(b) == 0 {
		return gopacket.LayerTypeZero
	}

	tag := b[0] & osiBERTagMask
	switch osiBERClass(b[0] >> osiBERClassShift) {
	case osiBERApplication:
		if b[0]&osiBERFormBit != 0 && tag <= uint8(ACSEABRT) {
			return LayerTypeACSE
		}
	case osiBERContext:
		if tag <= uint8(MMSConcludeError) {
			return LayerTypeMMS
		}
	}
	return gopacket.LayerTypePayload
}

// isoPresDecoder decodes a PPDU knowing the session SPDU that carried it.
type isoPresDecoder struct {
	spdu ISOSessionSPDUType
}

// Decode implements gopacket.Decoder.
func (d isoPresDecoder) Decode(data []byte, pb gopacket.PacketBuilder) error {
	var want ISOPresentationType
	switch d.spdu {
	case ISOSessionConnect:
		want = ISOPresentationCP
	case ISOSessionAccept:
		want = ISOPresentationCPA
	case ISOSessionRefuse:
		want = ISOPresentationCPR
	case ISOSessionAbort:
		// ARU is told by its own tag; a SEQUENCE here is an ARP.
		want = ISOPresentationARP
	}

	p := &ISOPresentation{}
	if err := p.decode(data, want); err != nil {
		return err
	}
	return isoPresNext(p, pb)
}

func decodeISOPresentation(data []byte, pb gopacket.PacketBuilder) error {
	p := &ISOPresentation{}
	if err := p.DecodeFromBytes(data, pb); err != nil {
		return err
	}
	return isoPresNext(p, pb)
}

// isoPresNext adds the layer and continues with the routed decoder.
func isoPresNext(p *ISOPresentation, pb gopacket.PacketBuilder) error {
	pb.AddLayer(p)
	if p.next == gopacket.LayerTypeZero {
		return nil
	}
	return pb.NextDecoder(p.next)
}
