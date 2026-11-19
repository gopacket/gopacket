// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// Typed BACnet values (ASHRAE 135 Clause 21): the tag list of a service is
// read against the ASN.1 production of that service, which gives every tag
// a name and a datatype.
//
//	tags      [0] 0c 02 00 00 01   [1] 19 55   [3]{ 44 42 c8 00 00 }
//	schema    object-identifier    property    property-value: ANY
//	                 │                 │              │ typed by the two
//	                 ▼                 ▼              ▼ fields before it
//	values    analog-value,1    present-value    Real 100
//
// A value whose type is not known (a proprietary property, a vendor
// deviation) is not an error: it keeps its tags, with the application
// tagged ones still typed.

package layers

import (
	"fmt"
	"strings"
)

// Limits of the value decoder.
const (
	// bacnetMaxValueDepth bounds the constructed values around a value. Tags
	// nest at most bacnetMaxTagDepth deep and a production adds a few
	// untagged levels of its own.
	bacnetMaxValueDepth = 2 * bacnetMaxTagDepth
	// bacnetMaxPropertyDepth bounds property values inside property values
	// (a Group present-value, a Command action): each level may be read
	// twice, typed then untyped, so the work doubles per level.
	bacnetMaxPropertyDepth = 3
	// bacnetNoTag marks a schema field that has no context tag: it is
	// application tagged, or its members follow inline.
	bacnetNoTag uint8 = 0xFF
)

// BACnetDataType names a datatype of Clause 21: a primitive type, an
// enumeration, a named bit string or a constructed production.
type BACnetDataType uint16

// BACnetEnumerated is the value of an Enumerated together with the
// enumeration it belongs to, which names it.
type BACnetEnumerated struct {
	Type  BACnetDataType
	Value uint32
}

// String returns the Clause 21 name of the value, or its number.
func (e BACnetEnumerated) String() string { return e.Type.EnumName(e.Value) }

// BACnetWeekNDay is a BACnetWeekNDay: a month (1-12, 13 odd, 14 even), a
// week of the month (1-5, 6 last 7 days, 7-9 the weeks before) and a day of
// the week (1 Monday to 7 Sunday). Any field may be BACnetUnspecified.
type BACnetWeekNDay struct {
	Month       uint8
	WeekOfMonth uint8
	DayOfWeek   uint8
}

// String returns the pattern as month/week/day, with * for any.
func (w BACnetWeekNDay) String() string {
	return fmt.Sprintf("%s/%s/%s", bacnetField(w.Month), bacnetField(w.WeekOfMonth), bacnetField(w.DayOfWeek))
}

// String returns the bits as a string of 0 and 1, first bit first.
func (b BACnetBitString) String() string {
	out := make([]byte, b.Len())
	for i := range out {
		out[i] = '0'
		if b.Bit(i) {
			out[i] = '1'
		}
	}
	return string(out)
}

// BACnetValue is one decoded value: a service parameter, a member of a
// constructed value or a property value.
//
// A primitive holds its Go value in Value: nil (Null), bool, uint64
// (Unsigned), int64, float32, float64, []byte (OctetString), string,
// BACnetBitString, BACnetEnumerated, BACnetDate, BACnetTime,
// BACnetObjectIdentifier or BACnetWeekNDay. A constructed value holds its
// parts in Fields: the members of a SEQUENCE, the one chosen alternative of
// a CHOICE, the elements when List is set, or the value or values of a
// property.
//
// Type BACnetDataTypeAny marks data of unknown type: a primitive context
// tag (its octets are Tags[0].Data) or, with Fields, a bracketed run. The
// vendor block of a private transfer that is not tag encoded is one too,
// with the block as a []byte Value and no Fields.
type BACnetValue struct {
	// Name is the Clause 21 name of the field, such as "object-identifier";
	// list elements and untyped data have none.
	Name string
	Type BACnetDataType
	// List is set when Fields holds the elements of a SEQUENCE OF Type.
	List   bool
	Value  interface{}
	Fields []BACnetValue
	// Tags are the tags the value was read from, brackets included.
	Tags []BACnetTag
}

// Field returns the first part of v named name, or nil.
func (v *BACnetValue) Field(name string) *BACnetValue {
	return bacnetFindField(v.Fields, name)
}

// bacnetFindField returns the first value named name, or nil.
func bacnetFindField(vals []BACnetValue, name string) *BACnetValue {
	for i := range vals {
		if vals[i].Name == name {
			return &vals[i]
		}
	}
	return nil
}

// String renders the value on one line: name=value for a primitive,
// name{...} for a constructed value and name[...] for a list, such as
//
//	timestamp{date-time{date=2024-01-31 time=10:00:00.00}}
func (v *BACnetValue) String() string {
	var b strings.Builder
	v.format(&b)
	return b.String()
}

// format appends the one-line rendering of v. The tree is as deep as the
// decoder allowed, so the recursion is bounded.
func (v *BACnetValue) format(b *strings.Builder) {
	b.WriteString(v.Name)

	if v.Fields != nil {
		open, closing := "{", "}"
		if v.List {
			open, closing = "[", "]"
		}
		b.WriteString(open)
		for i := range v.Fields {
			if i > 0 {
				b.WriteByte(' ')
			}
			v.Fields[i].format(b)
		}
		b.WriteString(closing)
		return
	}

	if v.Name != "" {
		b.WriteByte('=')
	}
	b.WriteString(v.text())
}

// text renders the value of a primitive.
func (v *BACnetValue) text() string {
	switch x := v.Value.(type) {
	case nil:
		if v.Type == BACnetDataTypeNull {
			return "null"
		}
		// Untyped: the context tag number and its octets.
		if len(v.Tags) == 1 {
			return fmt.Sprintf("[%d]%x", v.Tags[0].Number, v.Tags[0].Data)
		}
		return "?"

	case []byte:
		return fmt.Sprintf("%x", x)

	case string:
		return fmt.Sprintf("%q", x)

	case BACnetBitString:
		return v.Type.bitsText(x)
	}
	return fmt.Sprint(v.Value)
}

// bitsText renders a bit string by the names of its set bits when the type
// names them, else as binary digits.
func (t BACnetDataType) bitsText(b BACnetBitString) string {
	if bacnetTypeOf(t).bits == nil {
		return b.String()
	}

	var set []string
	for i := 0; i < b.Len(); i++ {
		if b.Bit(i) {
			set = append(set, t.BitName(i))
		}
	}
	return "(" + strings.Join(set, ",") + ")"
}

// String returns the Clause 21 name of the datatype.
func (t BACnetDataType) String() string {
	if n := bacnetTypeOf(t).name; n != "" {
		return n
	}
	return fmt.Sprintf("Unknown(%d)", uint16(t))
}

// EnumName returns the Clause 21 name of value v of enumeration t, or its
// number when t does not name it.
func (t BACnetDataType) EnumName(v uint32) string {
	const maxObjectType = 1<<10 - 1

	switch t {
	case BACnetDataTypePropertyIdentifier:
		return BACnetPropertyIdentifier(v).String()
	case BACnetDataTypeObjectType:
		if v <= maxObjectType {
			return BACnetObjectType(v).String()
		}
	case BACnetDataTypeErrorClass:
		return BACnetErrorClass(v).String()
	case BACnetDataTypeErrorCode:
		return BACnetErrorCode(v).String()
	}

	// A bare Enumerated has no names: the number says it all.
	names := bacnetTypeOf(t).names
	if names == nil {
		return fmt.Sprint(v)
	}
	return bacnetName(names, v)
}

// BitName returns the Clause 21 name of bit i of named bit string t, or
// its number.
func (t BACnetDataType) BitName(i int) string {
	bits := bacnetTypeOf(t).bits
	if i >= 0 && i < len(bits) && bits[i] != "" {
		return bits[i]
	}
	return fmt.Sprintf("bit%d", i)
}

// BACnetParameters is the ServiceData of the services that have no type of
// their own: the parameters as named, typed values, in the order and under
// the names of the service's Clause 21 production.
type BACnetParameters struct {
	Fields []BACnetValue
}

func (*BACnetParameters) bacnetServiceData() {}

// Field returns the first parameter named name, or nil.
func (p *BACnetParameters) Field(name string) *BACnetValue {
	return bacnetFindField(p.Fields, name)
}

// Values returns the service parameters as typed values, named after the
// Clause 21 production of the service. For the services whose ServiceData
// is a type of their own it decodes them on demand, with their property
// values typed; for the others it returns the Fields of ServiceData. It
// returns nil when the parameters do not match the service.
func (a *BACnetAPDU) Values() []BACnetValue {
	if p, ok := a.ServiceData.(*BACnetParameters); ok {
		return p.Fields
	}
	if a.Segmented {
		return nil
	}
	return a.decodeProduction()
}

// decodeProduction reads the tags against the production of the service.
func (a *BACnetAPDU) decodeProduction() []BACnetValue {
	fields, ok := a.production()
	if !ok {
		return nil
	}
	vals, err := bacnetDecodeFields(a.Tags, fields, bacnetScope{})
	if err != nil {
		return nil
	}

	// The brackets of a vendor block that is not tag encoded read as an
	// empty value; the block goes there.
	if a.vendorBlock != nil && len(vals) > 0 {
		last := &vals[len(vals)-1]
		if len(last.Tags) > 0 && last.Tags[0].Kind == BACnetTagOpening {
			last.Value, last.Fields = a.vendorBlock, nil
		}
	}
	return vals
}

// production returns the parameters of the service the APDU carries.
func (a *BACnetAPDU) production() ([]bacnetMember, bool) {
	var (
		fields []bacnetMember
		ok     bool
	)
	switch a.PDUType {
	case BACnetPDUConfirmedRequest:
		fields, ok = bacnetConfirmedRequests[a.ConfirmedService]
	case BACnetPDUUnconfirmedRequest:
		fields, ok = bacnetUnconfirmedRequests[a.UnconfirmedService]
	case BACnetPDUComplexACK:
		fields, ok = bacnetComplexACKs[a.ConfirmedService]
	case BACnetPDUError:
		// Most services return a bare Error.
		if fields, ok = bacnetServiceErrors[a.ConfirmedService]; !ok {
			return bacnetErrorFields, true
		}
	}
	return fields, ok
}

// DecodeBACnetProperty types the tags of a property value, such as the
// Value of a BACnetReadPropertyAck, by the datatype Clause 12 gives the
// property of that object type. It returns one value per element of an
// array or list. Pass BACnetNoArrayIndex when no element was named. A
// property that is unknown, or whose tags do not fit its datatype, is
// returned untyped.
func DecodeBACnetProperty(object BACnetObjectType, property BACnetPropertyIdentifier, arrayIndex uint32, tags []BACnetTag) []BACnetValue {
	d := bacnetDecoder{
		r:     bacnetTagReader{tags: tags},
		scope: bacnetScope{object: object, hasObject: true, property: property, hasProperty: true, index: arrayIndex},
	}
	var v BACnetValue
	if err := d.propertyValue(&v); err != nil {
		return nil
	}
	return v.Fields
}

// bacnetKind is the shape of a datatype on the wire.
type bacnetKind uint8

const (
	// bacnetKindAny is data of unknown type.
	bacnetKindAny bacnetKind = iota
	// bacnetKindPrimitive is one tag of application datatype app.
	bacnetKindPrimitive
	// bacnetKindEnumerated is an Enumerated with named values.
	bacnetKindEnumerated
	// bacnetKindBitString is a BitString with named bits.
	bacnetKindBitString
	// bacnetKindApplication is one application tag of any datatype.
	bacnetKindApplication
	bacnetKindSequence
	bacnetKindChoice
	// bacnetKindProperty is an ANY typed by the property it belongs to.
	bacnetKindProperty
)

// isTag reports whether a value of the kind is a single primitive tag.
func (k bacnetKind) isTag() bool {
	switch k {
	case bacnetKindPrimitive, bacnetKindEnumerated, bacnetKindBitString, bacnetKindApplication:
		return true
	}
	return false
}

// bacnetFieldFlags qualify a schema field.
type bacnetFieldFlags uint8

const (
	// bacnetOptional fields may be absent.
	bacnetOptional bacnetFieldFlags = 1 << iota
	// bacnetList fields are a SEQUENCE OF their type.
	bacnetList
	// bacnetObjectScope fields name the object whose properties follow.
	bacnetObjectScope
	// bacnetPropertyScope fields name the property whose value follows.
	bacnetPropertyScope
	// bacnetIndexScope fields name the array element whose value follows.
	bacnetIndexScope
	// bacnetFixedProperty fields hold the value of property prop of the
	// object in scope.
	bacnetFixedProperty
)

// bacnetMember is one member of a SEQUENCE or one alternative of a CHOICE.
type bacnetMember struct {
	name string
	// tag is the context tag number, or bacnetNoTag.
	tag   uint8
	typ   BACnetDataType
	flags bacnetFieldFlags
	// prop is the property of a bacnetFixedProperty member.
	prop BACnetPropertyIdentifier
	// sub holds the members of an anonymous SEQUENCE or CHOICE, typ saying
	// which.
	sub []bacnetMember
}

// bacnetType describes a datatype.
type bacnetType struct {
	name string
	kind bacnetKind
	// app is the application datatype of the tag kinds.
	app    BACnetApplicationTag
	names  map[uint32]string
	bits   []string
	fields []bacnetMember
}

// bacnetTypeOf returns the description of t; an unknown type is untyped.
func bacnetTypeOf(t BACnetDataType) *bacnetType {
	if t >= bacnetDataTypeNamedBase {
		if int(t-bacnetDataTypeNamedBase) < len(bacnetNamedTypes) {
			return &bacnetNamedTypes[t-bacnetDataTypeNamedBase]
		}
		return &bacnetTypes[BACnetDataTypeAny]
	}
	return &bacnetTypes[t]
}

// bacnetScope is the object and property the decoder last read, which
// type the ANY values that follow.
type bacnetScope struct {
	object      BACnetObjectType
	hasObject   bool
	property    BACnetPropertyIdentifier
	hasProperty bool
	index       uint32
}

// propertyType returns the datatype of the property in scope, or
// BACnetDataTypeAny. Element 0 of an array is its length, which is
// application tagged.
func (s *bacnetScope) propertyType() BACnetDataType {
	if !s.hasProperty || s.index == 0 {
		return BACnetDataTypeAny
	}
	if s.hasObject {
		if t, ok := bacnetObjectPropertyTypes[bacnetObjectProperty{s.object, s.property}]; ok {
			return t
		}
	}
	return bacnetPropertyTypes[s.property]
}

// bacnetSink receives the values of one constructed value. A counting
// pass leaves vals nil.
type bacnetSink struct {
	vals []BACnetValue
	n    int
}

func (s *bacnetSink) add(v BACnetValue) {
	s.n++
	if len(s.vals) < cap(s.vals) {
		s.vals = append(s.vals, v)
	}
}

// bacnetDecoder reads one level of a tag list against a schema.
//
// Every constructed value is walked twice: a dry pass counts its parts and
// checks them, then the list is allocated at its final size and filled.
// Nothing is allocated for data that does not fit, and a list never costs
// more than the tags it was read from.
type bacnetDecoder struct {
	r     bacnetTagReader
	scope bacnetScope
	// dry is set during a counting pass.
	dry   bool
	depth uint8
	// props counts the property values around the current one.
	props uint8
}

// bacnetDecodeFields reads tags as the members of a SEQUENCE; every tag
// must be consumed.
func bacnetDecodeFields(tags []BACnetTag, fields []bacnetMember, scope bacnetScope) ([]BACnetValue, error) {
	d := bacnetDecoder{r: bacnetTagReader{tags: tags}, scope: scope}
	top := bacnetMember{tag: bacnetNoTag, typ: BACnetDataTypeSequence, sub: fields}

	vals, err := d.collect(&top)
	if err != nil {
		return nil, err
	}
	if d.r.more() {
		return nil, errBACnetShape
	}
	return vals, nil
}

// nested returns a decoder for the tags inside a bracketed value. It
// inherits the scope; what it learns stays inside.
func (d *bacnetDecoder) nested(tags []BACnetTag) bacnetDecoder {
	sub := *d
	sub.r = bacnetTagReader{tags: tags}
	return sub
}

// collect returns the parts of the constructed value that f describes,
// read from the current position: counted first, then decoded.
func (d *bacnetDecoder) collect(f *bacnetMember) ([]BACnetValue, error) {
	if d.depth >= bacnetMaxValueDepth {
		return nil, errBACnetShape
	}
	d.depth++

	var sink bacnetSink
	if d.dry {
		err := d.walk(f, &sink)
		d.depth--
		return nil, err
	}

	// The dry pass moves the reader and the scope; both are put back.
	saved := *d
	d.dry = true
	err := d.walk(f, &sink)
	*d = saved
	if err != nil {
		d.depth--
		return nil, err
	}

	sink = bacnetSink{vals: make([]BACnetValue, 0, sink.n)}
	err = d.walk(f, &sink)
	d.depth--
	return sink.vals, err
}

// walk reads the content of the constructed value that f describes.
func (d *bacnetDecoder) walk(f *bacnetMember, sink *bacnetSink) error {
	if f.flags&bacnetList != 0 {
		return d.repeat(f, sink)
	}

	t := bacnetTypeOf(f.typ)
	members := t.fields
	if f.sub != nil {
		members = f.sub
	}

	switch t.kind {
	case bacnetKindSequence:
		for i := range members {
			if err := d.field(&members[i], sink); err != nil {
				return err
			}
		}
		return nil

	case bacnetKindChoice:
		for i := range members {
			if d.matches(&members[i]) {
				return d.field(&members[i], sink)
			}
		}
		return errBACnetShape
	}
	return d.any(sink)
}

// repeat reads the elements of a SEQUENCE OF up to the end of the level.
// An element that takes no tag would repeat forever, so it is refused.
func (d *bacnetDecoder) repeat(f *bacnetMember, sink *bacnetSink) error {
	elem := bacnetMember{tag: bacnetNoTag, typ: f.typ, sub: f.sub}

	for d.r.more() {
		before := d.r.pos
		if err := d.field(&elem, sink); err != nil {
			return err
		}
		if d.r.pos == before {
			return errBACnetShape
		}
	}
	return nil
}

// matches reports whether the next tag can start field f.
func (d *bacnetDecoder) matches(f *bacnetMember) bool {
	if !d.r.more() {
		return false
	}
	tag := &d.r.tags[d.r.pos]
	if f.tag != bacnetNoTag {
		return tag.Class == BACnetTagClassContext && tag.Number == f.tag
	}

	t := bacnetTypeOf(f.typ)
	isList := f.flags&bacnetList != 0
	switch {
	case isList && !t.kind.isTag():
		return true
	case t.kind == bacnetKindApplication:
		return tag.Class == BACnetTagClassApplication
	case t.kind.isTag():
		return tag.IsApplication(t.app)
	}

	members := t.fields
	if f.sub != nil {
		members = f.sub
	}
	switch t.kind {
	case bacnetKindSequence:
		// An inline SEQUENCE starts with its first member that is present.
		for i := range members {
			if d.matches(&members[i]) {
				return true
			}
			if members[i].flags&bacnetOptional == 0 {
				return false
			}
		}
		return false

	case bacnetKindChoice:
		for i := range members {
			if d.matches(&members[i]) {
				return true
			}
		}
		return false
	}
	return true
}

// field reads one member into sink. An absent optional member is skipped;
// an untagged list may be empty.
func (d *bacnetDecoder) field(f *bacnetMember, sink *bacnetSink) error {
	inlineList := f.flags&bacnetList != 0 && f.tag == bacnetNoTag
	if !inlineList && !d.matches(f) {
		if f.flags&bacnetOptional != 0 {
			return nil
		}
		return errBACnetShape
	}

	v := BACnetValue{Name: f.name, Type: f.typ, List: f.flags&bacnetList != 0}
	start := d.r.pos
	if err := d.value(f, &v); err != nil {
		return err
	}
	v.Tags = d.r.tags[start:d.r.pos]
	sink.add(v)
	return nil
}

// value reads the value of field f into v: a single tag, or a constructed
// value that a context tagged field brackets and an untagged one inlines.
func (d *bacnetDecoder) value(f *bacnetMember, v *BACnetValue) error {
	t := bacnetTypeOf(f.typ)
	if !v.List && t.kind.isTag() {
		return d.tagValue(f, t, v)
	}

	if f.tag == bacnetNoTag {
		return d.constructed(f, t, v)
	}
	inner, err := d.r.constructed(f.tag)
	if err != nil {
		return err
	}
	sub := d.nested(inner)
	if err := sub.constructed(f, t, v); err != nil {
		return err
	}
	if sub.r.more() {
		return errBACnetShape
	}

	// A bracketed object specifier still scopes the fields after it,
	// and so does a bracketed property reference.
	if f.flags&bacnetObjectScope != 0 {
		d.scope.object, d.scope.hasObject = sub.scope.object, sub.scope.hasObject
	}
	if f.flags&bacnetPropertyScope != 0 {
		d.scope.property, d.scope.hasProperty, d.scope.index = sub.scope.property, sub.scope.hasProperty, sub.scope.index
	}
	return nil
}

// constructed reads the content of a constructed value at this level.
func (d *bacnetDecoder) constructed(f *bacnetMember, t *bacnetType, v *BACnetValue) error {
	if t.kind == bacnetKindProperty && !v.List {
		if f.flags&bacnetFixedProperty != 0 {
			d.scope.property, d.scope.hasProperty, d.scope.index = f.prop, true, BACnetNoArrayIndex
		}
		return d.propertyValue(v)
	}
	var err error
	v.Fields, err = d.collect(f)
	return err
}

// tagValue reads the single primitive tag of field f.
func (d *bacnetDecoder) tagValue(f *bacnetMember, t *bacnetType, v *BACnetValue) error {
	tag := &d.r.tags[d.r.pos]
	if tag.Kind != BACnetTagPrimitive {
		return errBACnetShape
	}
	d.r.pos++

	// An application tag of any type says what it is.
	if t.kind == bacnetKindApplication {
		v.Type = bacnetApplicationType(tag)
	}
	val, err := d.leaf(tag, v.Type)
	if err != nil {
		return err
	}
	v.Value = val
	d.note(f, tag)
	return nil
}

// note records in the scope the object, property or array index that
// field f, just read from tag, names.
func (d *bacnetDecoder) note(f *bacnetMember, tag *BACnetTag) {
	const scoped = bacnetObjectScope | bacnetPropertyScope | bacnetIndexScope
	if f.flags&scoped == 0 {
		return
	}

	// An object is named by its identifier or by its type alone.
	if f.flags&bacnetObjectScope != 0 && f.typ == BACnetDataTypeObjectIdentifier {
		if o, err := tag.ObjectIdentifier(); err == nil {
			d.scope.object, d.scope.hasObject = o.Type, true
		}
		return
	}
	n, err := bacnetUint32(tag)
	if err != nil {
		return
	}

	switch {
	case f.flags&bacnetObjectScope != 0:
		d.scope.object, d.scope.hasObject = BACnetObjectType(n), true
	case f.flags&bacnetPropertyScope != 0:
		d.scope.property, d.scope.hasProperty = BACnetPropertyIdentifier(n), true
		d.scope.index = BACnetNoArrayIndex
	default:
		d.scope.index = n
	}
}

// bacnetApplicationType returns the datatype of an application tag; the
// tag numbers reserved by ASHRAE have none.
func bacnetApplicationType(tag *BACnetTag) BACnetDataType {
	if tag.Class != BACnetTagClassApplication || tag.Number > uint8(BACnetAppTagObjectIdentifier) {
		return BACnetDataTypeAny
	}
	return BACnetDataTypeNull + BACnetDataType(tag.Number)
}

// leaf returns the Go value of primitive tag read as datatype typ. A dry
// pass checks the encoding and returns nil.
func (d *bacnetDecoder) leaf(tag *BACnetTag, typ BACnetDataType) (interface{}, error) {
	t := bacnetTypeOf(typ)

	switch t.app {
	case BACnetAppTagNull:
		if t.kind == bacnetKindAny || len(tag.Data) != 0 {
			return nil, errBACnetShape
		}
		return nil, nil

	case BACnetAppTagBoolean:
		x, err := tag.Boolean()
		return bacnetBox(x, err, d.dry)

	case BACnetAppTagUnsigned:
		x, err := tag.Unsigned()
		return bacnetBox(x, err, d.dry)

	case BACnetAppTagSigned:
		x, err := tag.Signed()
		return bacnetBox(x, err, d.dry)

	case BACnetAppTagReal:
		x, err := tag.Real()
		return bacnetBox(x, err, d.dry)

	case BACnetAppTagDouble:
		x, err := tag.Double()
		return bacnetBox(x, err, d.dry)

	case BACnetAppTagOctetString:
		return d.octets(tag, typ)

	case BACnetAppTagCharacterString:
		return d.text(tag)

	case BACnetAppTagBitString:
		x, err := tag.BitString()
		return bacnetBox(x, err, d.dry)

	case BACnetAppTagEnumerated:
		n, err := bacnetUint32(tag)
		if err != nil || d.dry {
			return nil, err
		}
		return BACnetEnumerated{Type: typ, Value: n}, nil

	case BACnetAppTagDate:
		x, err := tag.Date()
		return bacnetBox(x, err, d.dry)

	case BACnetAppTagTime:
		x, err := tag.Time()
		return bacnetBox(x, err, d.dry)

	case BACnetAppTagObjectIdentifier:
		x, err := tag.ObjectIdentifier()
		return bacnetBox(x, err, d.dry)
	}
	return nil, errBACnetShape
}

// bacnetBox boxes the result of a tag accessor, except on a dry pass, which
// only wants the error.
func bacnetBox[T any](v T, err error, dry bool) (interface{}, error) {
	if err != nil || dry {
		return nil, err
	}
	return v, nil
}

// octets reads an OctetString, or the 3 octets of a BACnetWeekNDay.
func (d *bacnetDecoder) octets(tag *BACnetTag, typ BACnetDataType) (interface{}, error) {
	const weekNDayLen = 3

	if typ != BACnetDataTypeWeekNDay {
		if d.dry {
			return nil, nil
		}
		return tag.Data, nil
	}
	if len(tag.Data) != weekNDayLen {
		return nil, errBACnetShape
	}
	if d.dry {
		return nil, nil
	}
	return BACnetWeekNDay{Month: tag.Data[0], WeekOfMonth: tag.Data[1], DayOfWeek: tag.Data[2]}, nil
}

// text reads a CharacterString. A dry pass checks what the conversion
// would without building the string.
func (d *bacnetDecoder) text(tag *BACnetTag) (interface{}, error) {
	if !d.dry {
		_, s, err := tag.CharacterString()
		if err != nil {
			return nil, err
		}
		return s, nil
	}

	if len(tag.Data) == 0 {
		return nil, errBACnetShape
	}
	unit := 1
	switch BACnetCharacterSet(tag.Data[0]) {
	case BACnetCharsetUCS2:
		unit = bacnetUCS2Len
	case BACnetCharsetUCS4:
		unit = bacnetUCS4Len
	}
	if (len(tag.Data)-1)%unit != 0 {
		return nil, errBACnetShape
	}
	return nil, nil
}

// propertyValue reads the rest of the level as the value of the property
// in scope into v: one part per element. When the tags do not fit the
// datatype of the property they are read again untyped.
func (d *bacnetDecoder) propertyValue(v *BACnetValue) error {
	typ := d.scope.propertyType()
	if d.props >= bacnetMaxPropertyDepth {
		typ = BACnetDataTypeAny
	}

	if typ != BACnetDataTypeAny {
		saved := *d
		d.props++
		typed := bacnetMember{tag: bacnetNoTag, typ: typ, flags: bacnetList}

		fields, err := d.collect(&typed)
		d.props--
		if err == nil {
			v.Type, v.Fields = typ, fields
			return nil
		}
		*d = saved
	}

	untyped := bacnetMember{tag: bacnetNoTag, typ: BACnetDataTypeAny}
	fields, err := d.collect(&untyped)
	v.Type, v.Fields = BACnetDataTypeAny, fields
	return err
}

// any reads the rest of the level untyped: application tags by the type
// they announce, context tags raw, bracketed runs as nested untyped values.
func (d *bacnetDecoder) any(sink *bacnetSink) error {
	for d.r.more() {
		tag := &d.r.tags[d.r.pos]
		start := d.r.pos
		var v BACnetValue

		switch {
		case tag.Kind == BACnetTagOpening:
			inner, err := d.r.constructed(tag.Number)
			if err != nil {
				return err
			}
			// Untyped content always fits, so a counting pass does not
			// look inside: each level is walked twice, not once per
			// level around it.
			if d.dry {
				break
			}
			sub := d.nested(inner)
			untyped := bacnetMember{tag: bacnetNoTag, typ: BACnetDataTypeAny}
			if v.Fields, err = sub.collect(&untyped); err != nil {
				return err
			}

		case tag.Class == BACnetTagClassApplication && tag.Kind == BACnetTagPrimitive:
			d.r.pos++
			v.Type = bacnetApplicationType(tag)

			// A badly encoded primitive stays as its tag.
			val, err := d.leaf(tag, v.Type)
			if err != nil {
				v.Type = BACnetDataTypeAny
			}
			v.Value = val

		default:
			d.r.pos++
		}

		v.Tags = d.r.tags[start:d.r.pos]
		sink.add(v)
	}
	return nil
}
