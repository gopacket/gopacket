// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// Typed parameters of the common BACnet services (ASHRAE 135 Clauses 13,
// 15, 16), read from the generic tag list.

package layers

import (
	"errors"
	"math"
)

// BACnetNoArrayIndex is the ArrayIndex of a property reference that names
// the whole property rather than one array element.
const BACnetNoArrayIndex uint32 = math.MaxUint32

// errBACnetShape is returned when well-formed tags do not match the
// parameters of their service. It never reaches the caller: the APDU is
// kept with its tags and no ServiceData.
var errBACnetShape = errors.New("BACnet service parameters do not match the service")

// BACnetServiceData is the typed parameters of a decoded service, one of
// *BACnetWhoIs, *BACnetIAm, *BACnetWhoHas, *BACnetIHave,
// *BACnetReadProperty, *BACnetReadPropertyAck, *BACnetWriteProperty,
// *BACnetReadPropertyMultiple, *BACnetReadPropertyMultipleAck,
// *BACnetSubscribeCOV, *BACnetCOVNotification, *BACnetTimeSynchronization
// or, for every other service and for Error PDUs, *BACnetParameters.
type BACnetServiceData interface {
	bacnetServiceData()
}

// BACnetSegmentation is the segmentation a device supports (Clause 21).
type BACnetSegmentation uint8

// BACnetSegmentation values.
const (
	BACnetSegmentedBoth     BACnetSegmentation = 0
	BACnetSegmentedTransmit BACnetSegmentation = 1
	BACnetSegmentedReceive  BACnetSegmentation = 2
	BACnetNoSegmentation    BACnetSegmentation = 3
)

var bacnetSegmentationNames = map[BACnetSegmentation]string{
	BACnetSegmentedBoth:     "segmented-both",
	BACnetSegmentedTransmit: "segmented-transmit",
	BACnetSegmentedReceive:  "segmented-receive",
	BACnetNoSegmentation:    "no-segmentation",
}

// String returns the Clause 21 name of the segmentation.
func (s BACnetSegmentation) String() string { return bacnetName(bacnetSegmentationNames, s) }

// BACnetWhoIs is the Who-Is request (Clause 16.10). Without limits it asks
// every device.
type BACnetWhoIs struct {
	Limited   bool
	LowLimit  uint32
	HighLimit uint32
}

// BACnetIAm is the I-Am request (Clause 16.10).
type BACnetIAm struct {
	Device        BACnetObjectIdentifier
	MaxAPDULength uint32
	Segmentation  BACnetSegmentation
	VendorID      uint32
}

// BACnetWhoHas is the Who-Has request (Clause 16.9), for an object named
// by identifier or, when ByName is set, by ObjectName.
type BACnetWhoHas struct {
	Limited    bool
	LowLimit   uint32
	HighLimit  uint32
	ByName     bool
	Object     BACnetObjectIdentifier
	ObjectName string
}

// BACnetIHave is the I-Have request (Clause 16.9).
type BACnetIHave struct {
	Device     BACnetObjectIdentifier
	Object     BACnetObjectIdentifier
	ObjectName string
}

// BACnetReadProperty is the ReadProperty request (Clause 15.5).
type BACnetReadProperty struct {
	Object   BACnetObjectIdentifier
	Property BACnetPropertyIdentifier
	// ArrayIndex is BACnetNoArrayIndex when absent.
	ArrayIndex uint32
}

// BACnetReadPropertyAck is the ReadProperty ComplexACK (Clause 15.5).
type BACnetReadPropertyAck struct {
	Object     BACnetObjectIdentifier
	Property   BACnetPropertyIdentifier
	ArrayIndex uint32
	// Value holds the tags of the property value.
	Value []BACnetTag
}

// BACnetWriteProperty is the WriteProperty request (Clause 15.9).
type BACnetWriteProperty struct {
	Object     BACnetObjectIdentifier
	Property   BACnetPropertyIdentifier
	ArrayIndex uint32
	Value      []BACnetTag
	// Priority is the command priority, 1 to 16, or 0 when absent.
	Priority uint8
}

// BACnetPropertyReference names a property and, optionally, one element.
type BACnetPropertyReference struct {
	Property   BACnetPropertyIdentifier
	ArrayIndex uint32
}

// BACnetReadAccessSpec is one object of a ReadPropertyMultiple request.
type BACnetReadAccessSpec struct {
	Object     BACnetObjectIdentifier
	Properties []BACnetPropertyReference
}

// BACnetReadPropertyMultiple is the ReadPropertyMultiple request (Clause 15.7).
type BACnetReadPropertyMultiple struct {
	Specs []BACnetReadAccessSpec
}

// BACnetReadResult is one property of a ReadPropertyMultiple ACK: its
// value, or the error that reading it raised.
type BACnetReadResult struct {
	Property   BACnetPropertyIdentifier
	ArrayIndex uint32
	Value      []BACnetTag
	// Error is set, and Value empty, when the property could not be read.
	Error *BACnetError
}

// BACnetReadAccessResult is one object of a ReadPropertyMultiple ACK.
type BACnetReadAccessResult struct {
	Object  BACnetObjectIdentifier
	Results []BACnetReadResult
}

// BACnetReadPropertyMultipleAck is the ReadPropertyMultiple ComplexACK
// (Clause 15.7).
type BACnetReadPropertyMultipleAck struct {
	Results []BACnetReadAccessResult
}

// BACnetSubscribeCOV is the SubscribeCOV request (Clause 13.14). Without
// the two optional parameters it cancels the subscription.
type BACnetSubscribeCOV struct {
	ProcessID      uint32
	Object         BACnetObjectIdentifier
	Cancel         bool
	IssueConfirmed bool
	// Lifetime is in seconds; 0 is indefinite.
	Lifetime uint32
}

// BACnetPropertyValue is one changed property of a COV notification.
type BACnetPropertyValue struct {
	Property   BACnetPropertyIdentifier
	ArrayIndex uint32
	Value      []BACnetTag
	// Priority is 1 to 16, or 0 when absent.
	Priority uint8
}

// BACnetCOVNotification is the ConfirmedCOVNotification or
// UnconfirmedCOVNotification request (Clause 13.6, 13.7).
type BACnetCOVNotification struct {
	ProcessID uint32
	Device    BACnetObjectIdentifier
	Object    BACnetObjectIdentifier
	// TimeRemaining is the subscription time left, in seconds.
	TimeRemaining uint32
	Values        []BACnetPropertyValue
}

// BACnetTimeSynchronization is the TimeSynchronization or
// UTCTimeSynchronization request (Clause 16.7, 16.8).
type BACnetTimeSynchronization struct {
	Date BACnetDate
	Time BACnetTime
}

func (*BACnetWhoIs) bacnetServiceData()                   {}
func (*BACnetIAm) bacnetServiceData()                     {}
func (*BACnetWhoHas) bacnetServiceData()                  {}
func (*BACnetIHave) bacnetServiceData()                   {}
func (*BACnetReadProperty) bacnetServiceData()            {}
func (*BACnetReadPropertyAck) bacnetServiceData()         {}
func (*BACnetWriteProperty) bacnetServiceData()           {}
func (*BACnetReadPropertyMultiple) bacnetServiceData()    {}
func (*BACnetReadPropertyMultipleAck) bacnetServiceData() {}
func (*BACnetSubscribeCOV) bacnetServiceData()            {}
func (*BACnetCOVNotification) bacnetServiceData()         {}
func (*BACnetTimeSynchronization) bacnetServiceData()     {}

// decodeService fills ServiceData, and Error for an Error PDU. Parameters
// that do not fit leave both unset.
func (a *BACnetAPDU) decodeService() {
	if a.PDUType == BACnetPDUError {
		a.Error, _ = bacnetFirstError(a.Tags)
		a.decodeParameters()
		return
	}

	r := &bacnetTagReader{tags: a.Tags}
	var (
		data BACnetServiceData
		err  error
	)
	switch a.PDUType {
	case BACnetPDUUnconfirmedRequest:
		data, err = r.unconfirmed(a.UnconfirmedService)
	case BACnetPDUConfirmedRequest:
		data, err = r.confirmed(a.ConfirmedService)
	case BACnetPDUComplexACK:
		data, err = r.complexACK(a.ConfirmedService)
	}

	if err != nil {
		return
	}
	// The services without a type of their own are read by production.
	if data == nil {
		a.decodeParameters()
		return
	}

	// Leftover tags mean the parameters were not what the service expects.
	if r.more() {
		return
	}
	a.ServiceData = data
}

// decodeParameters sets ServiceData to the parameters read against the
// production of the service, when they match it.
func (a *BACnetAPDU) decodeParameters() {
	if vals := a.decodeProduction(); vals != nil {
		a.ServiceData = &BACnetParameters{Fields: vals}
	}
}

// bacnetFirstError returns the first two application Enumerated tags,
// which open the Error parameters of every service; complex errors nest
// them in a constructed first parameter.
func bacnetFirstError(tags []BACnetTag) (BACnetError, error) {
	var vals []uint32
	for i := range tags {
		if !tags[i].IsApplication(BACnetAppTagEnumerated) {
			continue
		}
		v, err := bacnetUint32(&tags[i])
		if err != nil {
			return BACnetError{}, err
		}
		vals = append(vals, v)
		if len(vals) == 2 {
			return BACnetError{Class: BACnetErrorClass(vals[0]), Code: BACnetErrorCode(vals[1])}, nil
		}
	}
	return BACnetError{}, errBACnetShape
}

// bacnetTagReader walks a tag list one parameter at a time. Constructed
// values are taken whole, so the reader only ever sees its own level.
type bacnetTagReader struct {
	tags []BACnetTag
	pos  int
}

func (r *bacnetTagReader) more() bool { return r.pos < len(r.tags) }

// nextIsContext reports whether the next tag is primitive context tag n.
func (r *bacnetTagReader) nextIsContext(n uint8) bool {
	return r.more() && r.tags[r.pos].IsContext(n)
}

// nextIsOpening reports whether the next tag opens constructed tag n.
func (r *bacnetTagReader) nextIsOpening(n uint8) bool {
	if !r.more() {
		return false
	}
	t := &r.tags[r.pos]
	return t.Class == BACnetTagClassContext && t.Kind == BACnetTagOpening && t.Number == n
}

// context takes primitive context tag n.
func (r *bacnetTagReader) context(n uint8) (*BACnetTag, error) {
	if !r.nextIsContext(n) {
		return nil, errBACnetShape
	}
	r.pos++
	return &r.tags[r.pos-1], nil
}

// application takes an application tag of type a.
func (r *bacnetTagReader) application(a BACnetApplicationTag) (*BACnetTag, error) {
	if !r.more() || !r.tags[r.pos].IsApplication(a) {
		return nil, errBACnetShape
	}
	r.pos++
	return &r.tags[r.pos-1], nil
}

// constructed takes opening tag n, its contents and its closing tag, and
// returns the contents. The tags are balanced, so the first closing tag
// back at the opening depth is the match.
func (r *bacnetTagReader) constructed(n uint8) ([]BACnetTag, error) {
	if !r.nextIsOpening(n) {
		return nil, errBACnetShape
	}
	depth := r.tags[r.pos].Depth

	for j := r.pos + 1; j < len(r.tags); j++ {
		t := &r.tags[j]
		if t.Kind != BACnetTagClosing || t.Depth != depth {
			continue
		}
		inner := r.tags[r.pos+1 : j]
		r.pos = j + 1
		return inner, nil
	}
	return nil, errBACnetShape
}

// contextUint32 takes context tag n as an Unsigned of at most 32 bits.
func (r *bacnetTagReader) contextUint32(n uint8) (uint32, error) {
	t, err := r.context(n)
	if err != nil {
		return 0, err
	}
	return bacnetUint32(t)
}

// contextObject takes context tag n as an ObjectIdentifier.
func (r *bacnetTagReader) contextObject(n uint8) (BACnetObjectIdentifier, error) {
	t, err := r.context(n)
	if err != nil {
		return BACnetObjectIdentifier{}, err
	}
	return t.ObjectIdentifier()
}

// optionalIndex takes context tag n as an array index, if present.
func (r *bacnetTagReader) optionalIndex(n uint8) (uint32, error) {
	if !r.nextIsContext(n) {
		return BACnetNoArrayIndex, nil
	}
	return r.contextUint32(n)
}

// optionalPriority takes context tag n as a priority, if present.
func (r *bacnetTagReader) optionalPriority(n uint8) (uint8, error) {
	const maxPriority = 16
	if !r.nextIsContext(n) {
		return 0, nil
	}
	v, err := r.contextUint32(n)
	if err != nil || v > maxPriority {
		return 0, errBACnetShape
	}
	return uint8(v), nil
}

// limits takes the optional device instance range of Who-Is and Who-Has.
func (r *bacnetTagReader) limits() (bool, uint32, uint32, error) {
	if !r.nextIsContext(0) {
		return false, 0, 0, nil
	}
	low, err := r.contextUint32(0)
	if err != nil {
		return false, 0, 0, err
	}
	high, err := r.contextUint32(1)
	if err != nil {
		return false, 0, 0, err
	}
	return true, low, high, nil
}

// bacnetUint32 reads an Unsigned or Enumerated that must fit 32 bits.
func bacnetUint32(t *BACnetTag) (uint32, error) {
	v, err := t.Unsigned()
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint32 {
		return 0, errBACnetShape
	}
	return uint32(v), nil
}

// unconfirmed decodes the parameters of an unconfirmed request.
func (r *bacnetTagReader) unconfirmed(s BACnetUnconfirmedService) (BACnetServiceData, error) {
	switch s {
	case BACnetUnconfirmedServiceWhoIs:
		w := &BACnetWhoIs{}
		var err error
		w.Limited, w.LowLimit, w.HighLimit, err = r.limits()
		return w, err

	case BACnetUnconfirmedServiceIAm:
		return r.iAm()

	case BACnetUnconfirmedServiceWhoHas:
		return r.whoHas()

	case BACnetUnconfirmedServiceIHave:
		return r.iHave()

	case BACnetUnconfirmedServiceUnconfirmedCOVNotification:
		return r.covNotification()

	case BACnetUnconfirmedServiceTimeSynchronization, BACnetUnconfirmedServiceUTCTimeSynchronization:
		return r.timeSync()
	}
	return nil, nil
}

// confirmed decodes the parameters of a confirmed request.
func (r *bacnetTagReader) confirmed(s BACnetConfirmedService) (BACnetServiceData, error) {
	switch s {
	case BACnetConfirmedServiceReadProperty:
		return r.readProperty()
	case BACnetConfirmedServiceWriteProperty:
		return r.writeProperty()
	case BACnetConfirmedServiceReadPropertyMultiple:
		return r.readPropertyMultiple()
	case BACnetConfirmedServiceSubscribeCOV:
		return r.subscribeCOV()
	case BACnetConfirmedServiceConfirmedCOVNotification:
		return r.covNotification()
	}
	return nil, nil
}

// complexACK decodes the parameters of a ComplexACK.
func (r *bacnetTagReader) complexACK(s BACnetConfirmedService) (BACnetServiceData, error) {
	switch s {
	case BACnetConfirmedServiceReadProperty:
		return r.readPropertyAck()
	case BACnetConfirmedServiceReadPropertyMultiple:
		return r.readPropertyMultipleAck()
	}
	return nil, nil
}

// iAm reads: device ObjectIdentifier, max APDU Unsigned, segmentation
// Enumerated, vendor Unsigned, all application tagged.
func (r *bacnetTagReader) iAm() (*BACnetIAm, error) {
	dev, err := r.application(BACnetAppTagObjectIdentifier)
	if err != nil {
		return nil, err
	}
	maxAPDU, err := r.application(BACnetAppTagUnsigned)
	if err != nil {
		return nil, err
	}
	seg, err := r.application(BACnetAppTagEnumerated)
	if err != nil {
		return nil, err
	}
	vendor, err := r.application(BACnetAppTagUnsigned)
	if err != nil {
		return nil, err
	}

	i := &BACnetIAm{}
	if i.Device, err = dev.ObjectIdentifier(); err != nil {
		return nil, err
	}
	if i.MaxAPDULength, err = bacnetUint32(maxAPDU); err != nil {
		return nil, err
	}
	s, err := bacnetUint32(seg)
	if err != nil || s > math.MaxUint8 {
		return nil, errBACnetShape
	}
	i.Segmentation = BACnetSegmentation(s)
	if i.VendorID, err = bacnetUint32(vendor); err != nil {
		return nil, err
	}
	return i, nil
}

// whoHas reads: optional [0] [1] limits, then [2] ObjectIdentifier or [3]
// object name.
func (r *bacnetTagReader) whoHas() (*BACnetWhoHas, error) {
	w := &BACnetWhoHas{}
	var err error
	if w.Limited, w.LowLimit, w.HighLimit, err = r.limits(); err != nil {
		return nil, err
	}

	if r.nextIsContext(2) {
		w.Object, err = r.contextObject(2)
		return w, err
	}
	t, err := r.context(3)
	if err != nil {
		return nil, err
	}
	w.ByName = true
	_, w.ObjectName, err = t.CharacterString()
	return w, err
}

// iHave reads: device and object ObjectIdentifiers, object name, all
// application tagged.
func (r *bacnetTagReader) iHave() (*BACnetIHave, error) {
	dev, err := r.application(BACnetAppTagObjectIdentifier)
	if err != nil {
		return nil, err
	}
	obj, err := r.application(BACnetAppTagObjectIdentifier)
	if err != nil {
		return nil, err
	}
	name, err := r.application(BACnetAppTagCharacterString)
	if err != nil {
		return nil, err
	}

	i := &BACnetIHave{}
	if i.Device, err = dev.ObjectIdentifier(); err != nil {
		return nil, err
	}
	if i.Object, err = obj.ObjectIdentifier(); err != nil {
		return nil, err
	}
	_, i.ObjectName, err = name.CharacterString()
	return i, err
}

// propertyRef reads a property identifier and optional array index from
// context tags p and p+1.
func (r *bacnetTagReader) propertyRef(p uint8) (BACnetPropertyReference, error) {
	prop, err := r.contextUint32(p)
	if err != nil {
		return BACnetPropertyReference{}, err
	}
	idx, err := r.optionalIndex(p + 1)
	if err != nil {
		return BACnetPropertyReference{}, err
	}
	return BACnetPropertyReference{Property: BACnetPropertyIdentifier(prop), ArrayIndex: idx}, nil
}

// objectProperty reads [0] object, [1] property, [2] optional index, the
// head that ReadProperty, its ACK and WriteProperty share.
func (r *bacnetTagReader) objectProperty() (BACnetObjectIdentifier, BACnetPropertyReference, error) {
	obj, err := r.contextObject(0)
	if err != nil {
		return obj, BACnetPropertyReference{}, err
	}
	ref, err := r.propertyRef(1)
	return obj, ref, err
}

func (r *bacnetTagReader) readProperty() (*BACnetReadProperty, error) {
	obj, ref, err := r.objectProperty()
	if err != nil {
		return nil, err
	}
	return &BACnetReadProperty{Object: obj, Property: ref.Property, ArrayIndex: ref.ArrayIndex}, nil
}

// readPropertyAck reads the ReadProperty head then [3] the value.
func (r *bacnetTagReader) readPropertyAck() (*BACnetReadPropertyAck, error) {
	obj, ref, err := r.objectProperty()
	if err != nil {
		return nil, err
	}
	val, err := r.constructed(3)
	if err != nil {
		return nil, err
	}
	return &BACnetReadPropertyAck{Object: obj, Property: ref.Property, ArrayIndex: ref.ArrayIndex, Value: val}, nil
}

// writeProperty reads the ReadProperty head, [3] the value, [4] the
// optional priority.
func (r *bacnetTagReader) writeProperty() (*BACnetWriteProperty, error) {
	obj, ref, err := r.objectProperty()
	if err != nil {
		return nil, err
	}
	val, err := r.constructed(3)
	if err != nil {
		return nil, err
	}
	prio, err := r.optionalPriority(4)
	if err != nil {
		return nil, err
	}
	return &BACnetWriteProperty{
		Object: obj, Property: ref.Property, ArrayIndex: ref.ArrayIndex, Value: val, Priority: prio,
	}, nil
}

// readPropertyMultiple reads specs of [0] object and [1] a list of
// property references.
func (r *bacnetTagReader) readPropertyMultiple() (*BACnetReadPropertyMultiple, error) {
	m := &BACnetReadPropertyMultiple{}
	for r.more() {
		obj, err := r.contextObject(0)
		if err != nil {
			return nil, err
		}
		list, err := r.constructed(1)
		if err != nil {
			return nil, err
		}

		spec := BACnetReadAccessSpec{Object: obj}
		lr := &bacnetTagReader{tags: list}
		for lr.more() {
			ref, err := lr.propertyRef(0)
			if err != nil {
				return nil, err
			}
			spec.Properties = append(spec.Properties, ref)
		}
		m.Specs = append(m.Specs, spec)
	}
	return m, nil
}

// readPropertyMultipleAck reads results of [0] object and [1] a list of
// [2] property, [3] index, then [4] value or [5] error.
func (r *bacnetTagReader) readPropertyMultipleAck() (*BACnetReadPropertyMultipleAck, error) {
	m := &BACnetReadPropertyMultipleAck{}
	for r.more() {
		obj, err := r.contextObject(0)
		if err != nil {
			return nil, err
		}
		res := BACnetReadAccessResult{Object: obj}

		// The list of results is optional.
		if !r.nextIsOpening(1) {
			m.Results = append(m.Results, res)
			continue
		}
		list, err := r.constructed(1)
		if err != nil {
			return nil, err
		}
		if res.Results, err = bacnetReadResults(list); err != nil {
			return nil, err
		}
		m.Results = append(m.Results, res)
	}
	return m, nil
}

// bacnetReadResults reads the property results of one object.
func bacnetReadResults(list []BACnetTag) ([]BACnetReadResult, error) {
	var out []BACnetReadResult
	lr := &bacnetTagReader{tags: list}
	for lr.more() {
		ref, err := lr.propertyRef(2)
		if err != nil {
			return nil, err
		}
		res := BACnetReadResult{Property: ref.Property, ArrayIndex: ref.ArrayIndex}

		if lr.nextIsOpening(4) {
			if res.Value, err = lr.constructed(4); err != nil {
				return nil, err
			}
			out = append(out, res)
			continue
		}
		errTags, err := lr.constructed(5)
		if err != nil {
			return nil, err
		}
		e, err := bacnetFirstError(errTags)
		if err != nil {
			return nil, err
		}
		res.Error = &e
		out = append(out, res)
	}
	return out, nil
}

// subscribeCOV reads [0] process, [1] object, then optional [2] confirmed
// flag and [3] lifetime.
func (r *bacnetTagReader) subscribeCOV() (*BACnetSubscribeCOV, error) {
	s := &BACnetSubscribeCOV{}
	var err error
	if s.ProcessID, err = r.contextUint32(0); err != nil {
		return nil, err
	}
	if s.Object, err = r.contextObject(1); err != nil {
		return nil, err
	}

	s.Cancel = !r.nextIsContext(2) && !r.nextIsContext(3)
	if r.nextIsContext(2) {
		t, _ := r.context(2)
		if s.IssueConfirmed, err = t.Boolean(); err != nil {
			return nil, err
		}
	}
	if r.nextIsContext(3) {
		if s.Lifetime, err = r.contextUint32(3); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// covNotification reads [0] process, [1] device, [2] object, [3] time
// remaining, [4] the list of property values.
func (r *bacnetTagReader) covNotification() (*BACnetCOVNotification, error) {
	c := &BACnetCOVNotification{}
	var err error
	if c.ProcessID, err = r.contextUint32(0); err != nil {
		return nil, err
	}
	if c.Device, err = r.contextObject(1); err != nil {
		return nil, err
	}
	if c.Object, err = r.contextObject(2); err != nil {
		return nil, err
	}
	if c.TimeRemaining, err = r.contextUint32(3); err != nil {
		return nil, err
	}
	list, err := r.constructed(4)
	if err != nil {
		return nil, err
	}

	// Each BACnetPropertyValue: [0] property, [1] index, [2] value, [3] priority.
	lr := &bacnetTagReader{tags: list}
	for lr.more() {
		ref, err := lr.propertyRef(0)
		if err != nil {
			return nil, err
		}
		v := BACnetPropertyValue{Property: ref.Property, ArrayIndex: ref.ArrayIndex}
		if v.Value, err = lr.constructed(2); err != nil {
			return nil, err
		}
		if v.Priority, err = lr.optionalPriority(3); err != nil {
			return nil, err
		}
		c.Values = append(c.Values, v)
	}
	return c, nil
}

// timeSync reads an application Date and Time.
func (r *bacnetTagReader) timeSync() (*BACnetTimeSynchronization, error) {
	d, err := r.application(BACnetAppTagDate)
	if err != nil {
		return nil, err
	}
	t, err := r.application(BACnetAppTagTime)
	if err != nil {
		return nil, err
	}

	ts := &BACnetTimeSynchronization{}
	if ts.Date, err = d.Date(); err != nil {
		return nil, err
	}
	ts.Time, err = t.Time()
	return ts, err
}
