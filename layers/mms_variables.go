// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

// MMS variable and type definition services: named variables, scattered
// access (ISO 9506-2 annex E), named types and data exchange. Best
// effort, like mms_services.go.

// MMSNamedVariable is a DefineNamedVariable-Request. Type is nil when the
// request leaves the type to the address.
type MMSNamedVariable struct {
	Name    MMSObjectName
	Address MMSAddress
	Type    *MMSTypeSpec
}

// Named variable tags.
const (
	mmsTagNVName    uint32 = 0
	mmsTagNVAddress uint32 = 1
	mmsTagNVType    uint32 = 2
)

// decodeMMSNamedVar reads DefineNamedVariable-Request: [0] variableName,
// [1] address, [2] typeSpecification OPTIONAL, all EXPLICIT.
func decodeMMSNamedVar(t osiBERTLV) (*MMSNamedVariable, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	v := &MMSNamedVariable{}
	found := false
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagNVName):
			v.Name, err = decodeMMSObjectNameIn(f.Value)
			found = true
		case f.is(osiBERContext, osiBERConstructed, mmsTagNVAddress):
			v.Address, err = decodeMMSAddressIn(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagNVType):
			var ts MMSTypeSpec
			if ts, err = decodeMMSTypeIn(f.Value, 0); err == nil {
				v.Type = &ts
			}
		}
		return err
	})
	if err == nil && !found {
		err = errMMSField
	}
	return mmsResult(v, err)
}

// MMSScatteredComponent is one component of a scattered access: a
// variable, optionally named and narrowed by an alternate access.
// AlternateAccess keeps the raw alternate access; Alternate is nil when
// it is absent or malformed.
type MMSScatteredComponent struct {
	Name            string
	Variable        MMSVariable
	AlternateAccess []byte
	Alternate       []MMSAlternateAccess
}

// MMSScatteredAccess is a DefineScatteredAccess-Request (Name) or a
// GetScatteredAccessAttributes-Response (Deletable, AccessControlList):
// one object made of pieces of other variables.
type MMSScatteredAccess struct {
	Name              MMSObjectName
	Deletable         bool
	Components        []MMSScatteredComponent
	AccessControlList string
}

// Scattered access tags.
const (
	mmsTagSAName      uint32 = 0
	mmsTagSADeletable uint32 = 0
	mmsTagSAList      uint32 = 1
	mmsTagSAACL       uint32 = 2
	mmsTagSCName      uint32 = 0
	mmsTagSCVariable  uint32 = 1
	mmsTagSCAlternate uint32 = 2
)

// decodeMMSScatteredAcc reads DefineScatteredAccess-Request or
// GetScatteredAccessAttributes-Response. They differ in [0]: the name or
// mmsDeletable.
func decodeMMSScatteredAcc(t osiBERTLV, enc mmsEventEncoding) (*MMSScatteredAccess, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	a := &MMSScatteredAccess{}
	found := false
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case enc == mmsEventDefine && f.is(osiBERContext, osiBERConstructed, mmsTagSAName):
			a.Name, err = decodeMMSObjectNameIn(f.Value)
		case enc == mmsEventAttributes && f.is(osiBERContext, osiBERPrimitive, mmsTagSADeletable):
			a.Deletable, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagSAList):
			a.Components, err = decodeMMSScattered(f.Value, 0)
			found = true
		case f.is(osiBERContext, osiBERPrimitive, mmsTagSAACL):
			a.AccessControlList = string(f.Value)
		}
		return err
	})
	if err == nil && !found {
		err = errMMSField
	}
	return mmsResult(a, err)
}

// decodeMMSScattered decodes a ScatteredAccessDescription body: SEQUENCE
// OF SEQUENCE { [0] componentName OPTIONAL, [1] EXPLICIT
// VariableSpecification, [2] alternateAccess OPTIONAL }. A component may
// itself be a scattered access; depth caps that nesting.
func decodeMMSScattered(b []byte, depth int) ([]MMSScatteredComponent, error) {
	if depth > osiBERMaxDepth {
		return nil, errOSIBERDepth
	}

	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSScatteredComponent, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		c, err := decodeMMSScatteredItem(item, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// decodeMMSScatteredItem decodes one scattered access component.
func decodeMMSScatteredItem(b []byte, depth int) (MMSScatteredComponent, error) {
	var c MMSScatteredComponent
	found := false
	err := mmsFields(b, func(f osiBERTLV) error {
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagSCName):
			c.Name = string(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagSCVariable):
			spec, err := osiBERSingle(f.Value)
			if err != nil {
				return err
			}
			found = true
			c.Variable, err = decodeMMSVarSpecAt(spec, depth+1)
			return err
		case f.is(osiBERContext, osiBERConstructed, mmsTagSCAlternate):
			c.AlternateAccess = f.Value
			c.Alternate, _ = decodeMMSAltAccess(f.Value, 0)
		}
		return nil
	})

	// The variable is mandatory.
	if err == nil && !found {
		err = errMMSField
	}
	return c, err
}

// MMSNamedType is a DefineNamedType-Request (Name and Type) or a
// GetNamedTypeAttributes-Response (Deletable, Type, AccessControlList
// and Meaning).
type MMSNamedType struct {
	Name              MMSObjectName
	Deletable         bool
	Type              MMSTypeSpec
	AccessControlList string
	Meaning           string
}

// Named type tags.
const (
	mmsTagNTDeletable uint32 = 0
	mmsTagNTACL       uint32 = 1
	mmsTagNTMeaning   uint32 = 4
)

// decodeMMSNamedTypeReq reads DefineNamedType-Request: an ObjectName and
// a TypeSpecification, both untagged CHOICEs.
func decodeMMSNamedTypeReq(t osiBERTLV) (*MMSNamedType, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	n := &MMSNamedType{}
	name, rest, err := osiBERNext(b)
	if err != nil {
		return nil, err
	}
	if n.Name, err = decodeMMSObjectName(name); err != nil {
		return nil, err
	}

	n.Type, err = decodeMMSTypeIn(rest, 0)
	return mmsResult(n, err)
}

// decodeMMSNamedTypeResp reads GetNamedTypeAttributes-Response: [0]
// mmsDeletable, TypeSpecification, [1] accessControlList OPTIONAL, [4]
// meaning OPTIONAL. The type is an untagged CHOICE whose tags overlap the
// others, so the fields are told apart by position.
func decodeMMSNamedTypeResp(t osiBERTLV) (*MMSNamedType, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	n := &MMSNamedType{}
	v, b, err := osiBERExpect(b, osiBERContext, osiBERPrimitive, mmsTagNTDeletable)
	if err != nil {
		return nil, err
	}
	if n.Deletable, err = osiBERBool(v); err != nil {
		return nil, err
	}

	ts, b, err := osiBERNext(b)
	if err != nil {
		return nil, err
	}
	if n.Type, err = decodeMMSType(ts, 0); err != nil {
		return nil, err
	}

	err = mmsFields(b, func(f osiBERTLV) error {
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagNTACL):
			n.AccessControlList = string(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagNTMeaning):
			n.Meaning = string(f.Value)
		}
		return nil
	})
	return mmsResult(n, err)
}

// MMSDataExchange holds the data exchange services of ISO 9506-2:2003:
//
//	Name, Data                         exchangeData request
//	Data                               exchangeData response
//	InUse .. AccessControlList         getDataExchangeAttributes response
type MMSDataExchange struct {
	Name              MMSObjectName
	Data              []MMSData
	InUse             bool
	RequestTypes      []MMSTypeSpec
	ResponseTypes     []MMSTypeSpec
	ProgramInvocation string
	AccessControlList string
}

// Data exchange tags.
const (
	mmsTagDXName      uint32 = 0
	mmsTagDXReqData   uint32 = 1
	mmsTagDXRespData  uint32 = 0
	mmsTagDXInUse     uint32 = 0
	mmsTagDXReqTypes  uint32 = 1
	mmsTagDXRespTypes uint32 = 2
	mmsTagDXProgram   uint32 = 3
	mmsTagDXACL       uint32 = 4
)

// decodeMMSExchange reads ExchangeData-Request ([0] dataExchangeName, [1]
// listOfRequestData) or ExchangeData-Response ([0] listOfResponseData).
func decodeMMSExchange(t osiBERTLV, pdu MMSPDUType) (*MMSDataExchange, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	x := &MMSDataExchange{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case pdu == MMSConfirmedRequest && f.is(osiBERContext, osiBERConstructed, mmsTagDXName):
			x.Name, err = decodeMMSObjectNameIn(f.Value)
		case pdu == MMSConfirmedRequest && f.is(osiBERContext, osiBERConstructed, mmsTagDXReqData),
			pdu == MMSConfirmedResponse && f.is(osiBERContext, osiBERConstructed, mmsTagDXRespData):
			x.Data, err = decodeMMSDataList(f.Value, 0)
		}
		return err
	})
	return mmsResult(x, err)
}

// decodeMMSExchangeAttrs reads GetDataExchangeAttributes-Response.
func decodeMMSExchangeAttrs(t osiBERTLV) (*MMSDataExchange, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	x := &MMSDataExchange{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDXInUse):
			x.InUse, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagDXReqTypes):
			x.RequestTypes, err = decodeMMSTypes(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagDXRespTypes):
			x.ResponseTypes, err = decodeMMSTypes(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDXProgram):
			x.ProgramInvocation = string(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDXACL):
			x.AccessControlList = string(f.Value)
		}
		return err
	})
	return mmsResult(x, err)
}

// decodeMMSTypes decodes a SEQUENCE OF TypeDescription body.
func decodeMMSTypes(b []byte) ([]MMSTypeSpec, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSTypeSpec, 0, count)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		ts, err := decodeMMSType(t, 0)
		if err != nil {
			return nil, err
		}
		out = append(out, ts)
	}
	return out, nil
}
