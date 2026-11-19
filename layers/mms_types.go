// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"math"
)

// MMS type descriptions: TypeSpecification, AlternateAccess and Address
// (ISO 9506-2 clause 14). TypeSpecification and AlternateAccess nest;
// both decoders stop at osiBERMaxDepth levels.

// MMSTypeKind is the TypeSpecification CHOICE tag. Except typeName, the
// tags match the MMSDataType of the values the type describes.
type MMSTypeKind uint8

// TypeSpecification alternatives.
const (
	MMSTypeName            MMSTypeKind = 0
	MMSTypeArray           MMSTypeKind = 1
	MMSTypeStructure       MMSTypeKind = 2
	MMSTypeBoolean         MMSTypeKind = 3
	MMSTypeBitString       MMSTypeKind = 4
	MMSTypeInteger         MMSTypeKind = 5
	MMSTypeUnsigned        MMSTypeKind = 6
	MMSTypeFloatingPoint   MMSTypeKind = 7
	MMSTypeOctetString     MMSTypeKind = 9
	MMSTypeVisibleString   MMSTypeKind = 10
	MMSTypeGeneralizedTime MMSTypeKind = 11
	MMSTypeBinaryTime      MMSTypeKind = 12
	MMSTypeBCD             MMSTypeKind = 13
	MMSTypeObjID           MMSTypeKind = 15
	MMSTypeMMSString       MMSTypeKind = 16
	MMSTypeUTCTime         MMSTypeKind = 17
)

// mmsTypeNames is indexed by MMSTypeKind; "" marks an unused tag.
var mmsTypeNames = [...]string{
	"typeName", "array", "structure", "boolean", "bit-string", "integer",
	"unsigned", "floating-point", "", "octet-string", "visible-string",
	"generalized-time", "binary-time", "bcd", "", "objId", "mMSString",
	"utc-time",
}

// String returns the ASN.1 name of the alternative.
func (k MMSTypeKind) String() string {
	if int(k) < len(mmsTypeNames) && mmsTypeNames[k] != "" {
		return mmsTypeNames[k]
	}
	return fmt.Sprintf("Unknown(%d)", uint8(k))
}

// MMSTypeSpec is a TypeSpecification. Kind selects the fields in use.
//
// IEC 61850 describes a data object as nested structures, e.g. Mod as
// structure {stVal integer(8), q bit-string(13), t utc-time}.
type MMSTypeSpec struct {
	Kind MMSTypeKind
	// Name is set for typeName.
	Name MMSObjectName
	// Packed is set for packed arrays and structures.
	Packed bool
	// Size is the Integer32 or Unsigned8 parameter: bits of a bit-string,
	// integer or unsigned, octets of an octet-string, characters of a
	// visible-string or mMSString and digits of a bcd. A negative string
	// size means variable length of at most -Size, e.g. -255.
	Size int64
	// Elements and Element describe an array.
	Elements uint32
	Element  *MMSTypeSpec
	// Components lists the members of a structure.
	Components []MMSTypeComponent
	// FormatWidth and ExponentWidth are set for floating-point, e.g. 32
	// and 8 for IEEE 754 single precision.
	FormatWidth   uint8
	ExponentWidth uint8
	// WithDate is set for a binary-time that includes the date.
	WithDate bool
}

// MMSTypeComponent is one structure member: an optional name and a type.
type MMSTypeComponent struct {
	Name string
	Type MMSTypeSpec
}

// TypeSpecification, AlternateAccess and Address tags.
const (
	mmsTagArrPacked   uint32 = 0
	mmsTagArrCount    uint32 = 1
	mmsTagArrElement  uint32 = 2
	mmsTagStrPacked   uint32 = 0
	mmsTagStrMembers  uint32 = 1
	mmsTagCompName    uint32 = 0
	mmsTagCompType    uint32 = 1
	mmsTagAltSelAlt   uint32 = 0
	mmsTagAltNamed    uint32 = 5
	mmsTagAltName     uint32 = 0
	mmsTagRangeLow    uint32 = 0
	mmsTagRangeCount  uint32 = 1
	mmsSelectAccessAt uint32 = 1
	mmsMaxUnsigned8   uint64 = math.MaxUint8
)

// decodeMMSTypeIn decodes the TypeSpecification that fills b, as found
// under an EXPLICIT tag.
func decodeMMSTypeIn(b []byte, depth int) (MMSTypeSpec, error) {
	t, err := osiBERSingle(b)
	if err != nil {
		return MMSTypeSpec{}, err
	}
	return decodeMMSType(t, depth)
}

// decodeMMSType decodes one TypeSpecification CHOICE element.
func decodeMMSType(t osiBERTLV, depth int) (MMSTypeSpec, error) {
	var s MMSTypeSpec
	if depth > osiBERMaxDepth {
		return s, errOSIBERDepth
	}
	if t.Class != osiBERContext || t.Tag > uint32(MMSTypeUTCTime) || mmsTypeNames[t.Tag] == "" {
		return s, errMMSField
	}
	s.Kind = MMSTypeKind(t.Tag)

	// typeName, array, structure and floating-point are constructed.
	wantForm := osiBERPrimitive
	switch s.Kind {
	case MMSTypeName, MMSTypeArray, MMSTypeStructure, MMSTypeFloatingPoint:
		wantForm = osiBERConstructed
	}
	if t.Form != wantForm {
		return s, errMMSField
	}

	var err error
	v := t.Value
	switch s.Kind {
	case MMSTypeName:
		s.Name, err = decodeMMSObjectNameIn(v)
	case MMSTypeArray:
		err = s.decodeArray(v, depth)
	case MMSTypeStructure:
		err = s.decodeStructure(v, depth)
	case MMSTypeBoolean, MMSTypeGeneralizedTime, MMSTypeObjID, MMSTypeUTCTime:
		err = mmsNull(v)
	case MMSTypeBitString, MMSTypeOctetString, MMSTypeVisibleString, MMSTypeMMSString:
		s.Size, err = mmsInt32(v)
	case MMSTypeInteger, MMSTypeUnsigned, MMSTypeBCD:
		var n uint8
		n, err = mmsUint8(v)
		s.Size = int64(n)
	case MMSTypeBinaryTime:
		s.WithDate, err = osiBERBool(v)
	case MMSTypeFloatingPoint:
		err = s.decodeFloat(v)
	}
	return s, err
}

// decodeArray reads array: [0] packed DEFAULT FALSE, [1] numberOfElements,
// [2] EXPLICIT elementType.
func (s *MMSTypeSpec) decodeArray(b []byte, depth int) error {
	found := false
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERPrimitive, mmsTagArrPacked):
			s.Packed, err = osiBERBool(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagArrCount):
			s.Elements, err = osiBERUint32(t.Value)
		case t.is(osiBERContext, osiBERConstructed, mmsTagArrElement):
			var e MMSTypeSpec
			if e, err = decodeMMSTypeIn(t.Value, depth+1); err == nil {
				s.Element = &e
				found = true
			}
		}
		if err != nil {
			return err
		}
	}

	if !found {
		return errMMSField
	}
	return nil
}

// decodeStructure reads structure: [0] packed DEFAULT FALSE, [1]
// components SEQUENCE OF SEQUENCE {[0] componentName OPTIONAL, [1]
// EXPLICIT componentType}.
func (s *MMSTypeSpec) decodeStructure(b []byte, depth int) error {
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERPrimitive, mmsTagStrPacked):
			s.Packed, err = osiBERBool(t.Value)
		case t.is(osiBERContext, osiBERConstructed, mmsTagStrMembers):
			s.Components, err = decodeMMSComponents(t.Value, depth)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// decodeMMSComponents decodes the components of a structure type.
func decodeMMSComponents(b []byte, depth int) ([]MMSTypeComponent, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSTypeComponent, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		var c MMSTypeComponent
		t, more, err := osiBERNext(item)
		if err != nil {
			return nil, err
		}
		if t.is(osiBERContext, osiBERPrimitive, mmsTagCompName) {
			c.Name = string(t.Value)
			if t, _, err = osiBERNext(more); err != nil {
				return nil, err
			}
		}
		if !t.is(osiBERContext, osiBERConstructed, mmsTagCompType) {
			return nil, errMMSField
		}

		if c.Type, err = decodeMMSTypeIn(t.Value, depth+1); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// decodeFloat reads floating-point: SEQUENCE { format-width Unsigned8,
// exponent-width Unsigned8 }, e.g. 02 01 20 02 01 08 = 32, 8.
func (s *MMSTypeSpec) decodeFloat(b []byte) error {
	v, b, err := osiBERExpect(b, osiBERUniversal, osiBERPrimitive, osiBERTagInteger)
	if err != nil {
		return err
	}
	if s.FormatWidth, err = mmsUint8(v); err != nil {
		return err
	}

	v, _, err = osiBERExpect(b, osiBERUniversal, osiBERPrimitive, osiBERTagInteger)
	if err != nil {
		return err
	}
	s.ExponentWidth, err = mmsUint8(v)
	return err
}

// MMSAltSelection is the accessSelection of an AlternateAccessSelection.
type MMSAltSelection uint8

// Access selections.
const (
	MMSAltComponent   MMSAltSelection = 0
	MMSAltIndex       MMSAltSelection = 1
	MMSAltIndexRange  MMSAltSelection = 2
	MMSAltAllElements MMSAltSelection = 3
)

// String returns the ASN.1 name of the selection.
func (s MMSAltSelection) String() string {
	switch s {
	case MMSAltComponent:
		return "component"
	case MMSAltIndex:
		return "index"
	case MMSAltIndexRange:
		return "indexRange"
	case MMSAltAllElements:
		return "allElements"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// MMSAlternateAccess is one AlternateAccess entry: it selects a part of a
// variable, e.g. component "q" of a structure or elements 2..5 of an
// array.
type MMSAlternateAccess struct {
	// Named is set for the named alternative, whose name is Name.
	Named bool
	Name  string
	// Selection picks Component, Index, or Index and Count.
	Selection MMSAltSelection
	Component string
	// Index is the index, or the low index of an indexRange.
	Index uint32
	// Count is the numberOfElements of an indexRange.
	Count uint32
	// SelectAlternate is set for selectAlternateAccess: Nested then
	// applies within the selected part.
	SelectAlternate bool
	Nested          []MMSAlternateAccess
}

// decodeMMSAltAccess decodes an AlternateAccess body: SEQUENCE OF CHOICE
// { unnamed AlternateAccessSelection, named [5] SEQUENCE }.
func decodeMMSAltAccess(b []byte, depth int) ([]MMSAlternateAccess, error) {
	if depth > osiBERMaxDepth {
		return nil, errOSIBERDepth
	}

	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSAlternateAccess, 0, count)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		var a MMSAlternateAccess
		if t.is(osiBERContext, osiBERConstructed, mmsTagAltNamed) {
			// named: [0] componentName, then the selection.
			v, sel, err := osiBERExpect(t.Value, osiBERContext, osiBERPrimitive, mmsTagAltName)
			if err != nil {
				return nil, err
			}
			a.Named = true
			a.Name = string(v)
			if t, err = osiBERSingle(sel); err != nil {
				return nil, err
			}
		}

		if err := a.decodeSelection(t, depth); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// decodeSelection reads an AlternateAccessSelection: selectAlternateAccess
// [0] SEQUENCE { accessSelection, AlternateAccess }, or a selectAccess
// whose tags [1]..[4] are those of accessSelection shifted by one.
func (a *MMSAlternateAccess) decodeSelection(t osiBERTLV, depth int) error {
	if !t.is(osiBERContext, osiBERConstructed, mmsTagAltSelAlt) {
		return a.decodeAccessSel(t, mmsSelectAccessAt)
	}

	a.SelectAlternate = true
	sel, rest, err := osiBERNext(t.Value)
	if err != nil {
		return err
	}
	if err := a.decodeAccessSel(sel, 0); err != nil {
		return err
	}

	v, _, err := osiBERExpect(rest, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
	if err != nil {
		return err
	}
	a.Nested, err = decodeMMSAltAccess(v, depth+1)
	return err
}

// decodeAccessSel reads component, index, indexRange or allElements, whose
// tags start at base.
func (a *MMSAlternateAccess) decodeAccessSel(t osiBERTLV, base uint32) error {
	if t.Class != osiBERContext || t.Tag < base || t.Tag > base+uint32(MMSAltAllElements) {
		return errMMSField
	}
	a.Selection = MMSAltSelection(t.Tag - base)

	// Only indexRange is constructed.
	wantForm := osiBERPrimitive
	if a.Selection == MMSAltIndexRange {
		wantForm = osiBERConstructed
	}
	if t.Form != wantForm {
		return errMMSField
	}

	var err error
	switch a.Selection {
	case MMSAltComponent:
		a.Component = string(t.Value)
	case MMSAltIndex:
		a.Index, err = osiBERUint32(t.Value)
	case MMSAltIndexRange:
		err = a.decodeRange(t.Value)
	case MMSAltAllElements:
		err = mmsNull(t.Value)
	}
	return err
}

// decodeRange reads indexRange: [0] lowIndex, [1] numberOfElements.
func (a *MMSAlternateAccess) decodeRange(b []byte) error {
	v, b, err := osiBERExpect(b, osiBERContext, osiBERPrimitive, mmsTagRangeLow)
	if err != nil {
		return err
	}
	if a.Index, err = osiBERUint32(v); err != nil {
		return err
	}

	v, _, err = osiBERExpect(b, osiBERContext, osiBERPrimitive, mmsTagRangeCount)
	if err != nil {
		return err
	}
	a.Count, err = osiBERUint32(v)
	return err
}

// MMSAddressKind is the Address CHOICE tag.
type MMSAddressKind uint8

// Address alternatives.
const (
	MMSAddressNumeric       MMSAddressKind = 0
	MMSAddressSymbolic      MMSAddressKind = 1
	MMSAddressUnconstrained MMSAddressKind = 2
)

// String returns the ASN.1 name of the alternative.
func (k MMSAddressKind) String() string {
	switch k {
	case MMSAddressNumeric:
		return "numericAddress"
	case MMSAddressSymbolic:
		return "symbolicAddress"
	case MMSAddressUnconstrained:
		return "unconstrainedAddress"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(k))
	}
}

// MMSAddress is a device specific variable Address.
type MMSAddress struct {
	Kind          MMSAddressKind
	Numeric       uint32
	Symbolic      string
	Unconstrained []byte
}

// decodeMMSAddress decodes one Address CHOICE element; all three
// alternatives are primitive.
func decodeMMSAddress(t osiBERTLV) (MMSAddress, error) {
	var a MMSAddress
	if t.Class != osiBERContext || t.Form != osiBERPrimitive || t.Tag > uint32(MMSAddressUnconstrained) {
		return a, errMMSField
	}
	a.Kind = MMSAddressKind(t.Tag)

	var err error
	switch a.Kind {
	case MMSAddressNumeric:
		a.Numeric, err = osiBERUint32(t.Value)
	case MMSAddressSymbolic:
		a.Symbolic = string(t.Value)
	case MMSAddressUnconstrained:
		a.Unconstrained = t.Value
	}
	return a, err
}

// decodeMMSAddressIn decodes the Address that fills b, as found under an
// EXPLICIT tag.
func decodeMMSAddressIn(b []byte) (MMSAddress, error) {
	t, err := osiBERSingle(b)
	if err != nil {
		return MMSAddress{}, err
	}
	return decodeMMSAddress(t)
}

// decodeSpec fills the address, variableDescription and
// scatteredAccessDescription alternatives of a VariableSpecification
// nested depth scattered accesses deep.
func (v *MMSVariable) decodeSpec(spec osiBERTLV, depth int) error {
	switch v.Kind {
	case MMSVariableScattered:
		if spec.Form != osiBERConstructed {
			return errMMSField
		}
		var err error
		v.Scattered, err = decodeMMSScattered(spec.Value, depth)
		return err
	case MMSVariableAddress:
		if spec.Form != osiBERConstructed {
			return errMMSField
		}
		var err error
		v.Address, err = decodeMMSAddressIn(spec.Value)
		return err
	case MMSVariableDescription:
		return v.decodeDescription(spec)
	case MMSVariableInvalidated:
		if spec.Form != osiBERPrimitive {
			return errMMSField
		}
		return mmsNull(spec.Value)
	}
	return nil
}

// decodeDescription reads variableDescription: SEQUENCE { Address,
// TypeSpecification }.
func (v *MMSVariable) decodeDescription(spec osiBERTLV) error {
	if spec.Form != osiBERConstructed {
		return errMMSField
	}

	t, rest, err := osiBERNext(spec.Value)
	if err != nil {
		return err
	}
	if v.Address, err = decodeMMSAddress(t); err != nil {
		return err
	}

	ts, err := decodeMMSTypeIn(rest, 0)
	if err != nil {
		return err
	}
	v.Type = &ts
	return nil
}

// mmsNull checks a NULL value.
func mmsNull(v []byte) error {
	if len(v) != 0 {
		return errMMSField
	}
	return nil
}

// mmsInt32 decodes an Integer32.
func mmsInt32(v []byte) (int64, error) {
	n, err := osiBERInt(v)
	if err != nil {
		return 0, err
	}
	if n < math.MinInt32 || n > math.MaxInt32 {
		return 0, errOSIBERInteger
	}
	return n, nil
}

// mmsUint8 decodes an Unsigned8.
func mmsUint8(v []byte) (uint8, error) {
	n, err := osiBERUint(v)
	if err != nil {
		return 0, err
	}
	if n > mmsMaxUnsigned8 {
		return 0, errOSIBERInteger
	}
	return uint8(n), nil
}
