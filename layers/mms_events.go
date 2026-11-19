// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

// MMS event management past event conditions: event actions, event
// enrollments, alarm summaries and the delete, alter and trigger
// requests (ISO 9506-2 clause 17). Best effort, like mms_services.go.

// mmsCount reads a response that is a bare Unsigned32.
func mmsCount(t osiBERTLV) (uint32, error) {
	b, err := mmsBody(t, osiBERPrimitive)
	if err != nil {
		return 0, err
	}
	return osiBERUint32(b)
}

// MMSEnhancementKind tells what a display enhancement holds.
type MMSEnhancementKind uint8

// Display enhancement alternatives.
const (
	MMSEnhancementNone MMSEnhancementKind = iota
	MMSEnhancementString
	MMSEnhancementIndex
)

// String returns the ASN.1 name of the alternative.
func (k MMSEnhancementKind) String() string {
	return mmsEnumName([]string{"noEnhancement", "string", "index"}, int64(k))
}

// MMSEnhancement is the display enhancement the companion standards add
// to events: a text or an index into a table of texts.
type MMSEnhancement struct {
	Kind   MMSEnhancementKind
	String string
	Index  int64
}

// Display enhancement CHOICE tags.
const (
	mmsTagEnhString uint32 = 0
	mmsTagEnhIndex  uint32 = 1
)

// decodeMMSEnhancement reads CHOICE { string [0] VisibleString, index [1]
// INTEGER, noEnhancement NULL } filling b. NULL is universal in some
// types and [2] in others.
func decodeMMSEnhancement(b []byte) (MMSEnhancement, error) {
	var e MMSEnhancement
	t, err := osiBERSingle(b)
	if err != nil {
		return e, err
	}
	if t.Form != osiBERPrimitive {
		return e, errMMSField
	}

	switch {
	case t.Class == osiBERContext && t.Tag == mmsTagEnhString:
		e.Kind, e.String = MMSEnhancementString, string(t.Value)
	case t.Class == osiBERContext && t.Tag == mmsTagEnhIndex:
		e.Kind = MMSEnhancementIndex
		e.Index, err = osiBERInt(t.Value)
	default:
		err = mmsNull(t.Value)
	}
	return e, err
}

// decodeMMSEnhancementIn reads an enhancement under one more EXPLICIT
// [0] tag (EN-Additional-Detail).
func decodeMMSEnhancementIn(b []byte) (MMSEnhancement, error) {
	t, err := osiBERSingle(b)
	if err != nil {
		return MMSEnhancement{}, err
	}
	if !t.is(osiBERContext, osiBERConstructed, 0) {
		return MMSEnhancement{}, errMMSField
	}
	return decodeMMSEnhancement(t.Value)
}

// MMSEventAlter is an AlterEventConditionMonitoring-Request or a
// TriggerEvent-Request (Name and Priority only). Each Has field tells
// the value before it was present.
type MMSEventAlter struct {
	Name                   MMSObjectName
	Enabled                bool
	HasEnabled             bool
	Priority               uint8
	HasPriority            bool
	AlarmSummaryReports    bool
	HasAlarmSummaryReports bool
	EvaluationInterval     uint32
	HasEvaluationInterval  bool
}

// Alter and trigger tags.
const (
	mmsTagAltECName     uint32 = 0
	mmsTagAltECEnabled  uint32 = 1
	mmsTagAltECPriority uint32 = 2
	mmsTagAltECSummary  uint32 = 3
	mmsTagAltECInterval uint32 = 4
	mmsTagTrigPriority  uint32 = 1
)

// decodeMMSEventAlter reads AlterEventConditionMonitoring-Request ([0]
// name, [1] enabled, [2] priority, [3] alarmSummaryReports, [4]
// evaluationInterval) or TriggerEvent-Request ([0] name, [1] priority).
func decodeMMSEventAlter(t osiBERTLV, s MMSConfirmedService) (*MMSEventAlter, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	a := &MMSEventAlter{}
	found := false
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagAltECName):
			a.Name, err = decodeMMSObjectNameIn(f.Value)
			found = true
		case s == MMSTriggerEvent && f.is(osiBERContext, osiBERPrimitive, mmsTagTrigPriority),
			s != MMSTriggerEvent && f.is(osiBERContext, osiBERPrimitive, mmsTagAltECPriority):
			a.Priority, err = mmsUint8(f.Value)
			a.HasPriority = true
		case s == MMSTriggerEvent:
		case f.is(osiBERContext, osiBERPrimitive, mmsTagAltECEnabled):
			a.Enabled, err = osiBERBool(f.Value)
			a.HasEnabled = true
		case f.is(osiBERContext, osiBERPrimitive, mmsTagAltECSummary):
			a.AlarmSummaryReports, err = osiBERBool(f.Value)
			a.HasAlarmSummaryReports = true
		case f.is(osiBERContext, osiBERPrimitive, mmsTagAltECInterval):
			a.EvaluationInterval, err = osiBERUint32(f.Value)
			a.HasEvaluationInterval = true
		}
		return err
	})
	if err == nil && !found {
		err = errMMSField
	}
	return mmsResult(a, err)
}

// MMSEventDeleteScope is the CHOICE of a delete event condition, action
// or enrollment request.
type MMSEventDeleteScope uint8

// Event delete scopes. Condition and Action only apply to event
// enrollments: every enrollment of that condition or action.
const (
	MMSEventDeleteSpecific MMSEventDeleteScope = iota
	MMSEventDeleteAA
	MMSEventDeleteDomain
	MMSEventDeleteVMD
	MMSEventDeleteCondition
	MMSEventDeleteAction
)

// String returns the ASN.1 name of the scope.
func (s MMSEventDeleteScope) String() string {
	return mmsEnumName([]string{"specific", "aa-specific", "domain", "vmd", "ec", "ea"}, int64(s))
}

// MMSEventDeleteRequest is a DeleteEventCondition-, DeleteEventAction- or
// DeleteEventEnrollment-Request: Names for the specific scope, DomainID
// for domain, Name for an event condition or action.
type MMSEventDeleteRequest struct {
	Scope    MMSEventDeleteScope
	Names    []MMSObjectName
	DomainID string
	Name     MMSObjectName
}

// MMSEventDeleteResponse is the response to them: how many candidates
// were not deleted.
type MMSEventDeleteResponse struct {
	NotDeleted uint32
}

// Delete request CHOICE tags. Event actions skip tag 2.
const (
	mmsTagEDSpecific uint32 = 0
	mmsTagEDAA       uint32 = 1
	mmsTagEDDomain   uint32 = 2
	mmsTagEDVMD      uint32 = 3
	mmsTagEDCond     uint32 = 1
	mmsTagEDAction   uint32 = 2
	mmsEventActShift uint32 = 1
)

// decodeMMSEventDelete reads the EXPLICIT CHOICE of a delete request.
func decodeMMSEventDelete(t osiBERTLV, s MMSConfirmedService) (*MMSEventDeleteRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}
	c, err := osiBERSingle(b)
	if err != nil {
		return nil, err
	}
	if c.Class != osiBERContext {
		return nil, errMMSField
	}

	r := &MMSEventDeleteRequest{}
	switch {
	case c.is(osiBERContext, osiBERConstructed, mmsTagEDSpecific):
		r.Names, err = decodeMMSObjectNames(c.Value)
	case s == MMSDeleteEventEnrollment:
		err = r.decodeEnrollment(c)
	default:
		err = r.decodeScope(c, s)
	}
	return mmsResult(r, err)
}

// decodeEnrollment reads ec [1] ObjectName or ea [2] ObjectName.
func (r *MMSEventDeleteRequest) decodeEnrollment(c osiBERTLV) error {
	switch {
	case c.is(osiBERContext, osiBERConstructed, mmsTagEDCond):
		r.Scope = MMSEventDeleteCondition
	case c.is(osiBERContext, osiBERConstructed, mmsTagEDAction):
		r.Scope = MMSEventDeleteAction
	default:
		return errMMSField
	}

	var err error
	r.Name, err = decodeMMSObjectNameIn(c.Value)
	return err
}

// decodeScope reads aa-specific [1] NULL, domain Identifier or vmd NULL.
// Conditions tag the last two [2] and [3], actions [3] and [4].
func (r *MMSEventDeleteRequest) decodeScope(c osiBERTLV, s MMSConfirmedService) error {
	tag := c.Tag
	if s == MMSDeleteEventAction && tag > mmsTagEDAA {
		tag -= mmsEventActShift
		if tag == mmsTagEDAA {
			return errMMSField
		}
	}
	if c.Form != osiBERPrimitive {
		return errMMSField
	}

	switch tag {
	case mmsTagEDAA:
		r.Scope = MMSEventDeleteAA
	case mmsTagEDDomain:
		r.Scope = MMSEventDeleteDomain
		r.DomainID = string(c.Value)
		return nil
	case mmsTagEDVMD:
		r.Scope = MMSEventDeleteVMD
	default:
		return errMMSField
	}
	return mmsNull(c.Value)
}

// decodeMMSEventDeleteResp reads the candidates not deleted.
func decodeMMSEventDeleteResp(t osiBERTLV) (*MMSEventDeleteResponse, error) {
	n, err := mmsCount(t)
	return mmsResult(&MMSEventDeleteResponse{NotDeleted: n}, err)
}

// MMSEventAction is a DefineEventAction-Request (Name) or a
// GetEventActionAttributes-Response (Deletable): the confirmed service
// request an event runs, with its modifiers.
//
// Service is the request's service and ServiceData its raw service
// element value; Request decodes it. Ext is the request's service-ext
// detail.
type MMSEventAction struct {
	Name              MMSObjectName
	Deletable         bool
	Modifiers         []MMSModifier
	HasService        bool
	Service           MMSConfirmedService
	ServiceData       []byte
	Ext               *MMSServiceExt
	AccessControlList string

	request osiBERTLV
}

// MMSEventActionStatus is a ReportEventActionStatus-Response.
type MMSEventActionStatus struct {
	Enrollments uint32
}

// Request decodes the confirmed service request of the action as a
// confirmed-RequestPDU without invokeID.
func (a *MMSEventAction) Request() (*MMS, error) {
	if !a.HasService {
		return nil, errMMSNoService
	}

	m := &MMS{Type: MMSConfirmedRequest, Service: a.Service, ServiceData: a.ServiceData, ServiceExt: a.Ext}
	if err := m.decodeRequest(a.request); err != nil {
		return nil, err
	}
	return m, nil
}

// Event action tags.
const (
	mmsTagEAName      uint32 = 0
	mmsTagEADeletable uint32 = 0
	mmsTagEAModifiers uint32 = 1
	mmsTagEARequest   uint32 = 2
	mmsTagEAACL       uint32 = 3
)

// decodeMMSEventAction reads DefineEventAction-Request or
// GetEventActionAttributes-Response. They differ in [0]: the name or
// mmsDeletable.
func decodeMMSEventAction(t osiBERTLV, enc mmsEventEncoding) (*MMSEventAction, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	a := &MMSEventAction{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case enc == mmsEventDefine && f.is(osiBERContext, osiBERConstructed, mmsTagEAName):
			a.Name, err = decodeMMSObjectNameIn(f.Value)
		case enc == mmsEventAttributes && f.is(osiBERContext, osiBERPrimitive, mmsTagEADeletable):
			a.Deletable, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagEAModifiers):
			a.Modifiers, err = decodeMMSModifiers(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagEARequest):
			err = a.decodeRequest(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagServiceExt):
			a.Ext, err = decodeMMSServiceExt(f.Value, mmsExtRequest)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagEAACL):
			a.AccessControlList = string(f.Value)
		}
		return err
	})
	if err == nil && !a.HasService {
		err = errMMSNoService
	}
	return mmsResult(a, err)
}

// decodeRequest keeps the EXPLICIT ConfirmedServiceRequest.
func (a *MMSEventAction) decodeRequest(b []byte) error {
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}
	if t.Class != osiBERContext || t.Tag == mmsTagServiceExt || t.Tag > mmsMaxServiceTag {
		return errMMSField
	}

	a.request = t
	a.HasService = true
	a.Service = MMSConfirmedService(t.Tag)
	a.ServiceData = t.Value
	return nil
}

// MMSEnrollmentClass is an EE-Class.
type MMSEnrollmentClass int64

// Event enrollment classes.
const (
	MMSEnrollmentModifier     MMSEnrollmentClass = 0
	MMSEnrollmentNotification MMSEnrollmentClass = 1
)

// String returns the ASN.1 name of the class.
func (c MMSEnrollmentClass) String() string {
	return mmsEnumName([]string{"modifier", "notification"}, int64(c))
}

// MMSEnrollmentDuration is an EE-Duration.
type MMSEnrollmentDuration int64

// Event enrollment durations.
const (
	MMSEnrollmentCurrent   MMSEnrollmentDuration = 0
	MMSEnrollmentPermanent MMSEnrollmentDuration = 1
)

// String returns the ASN.1 name of the duration.
func (d MMSEnrollmentDuration) String() string {
	return mmsEnumName([]string{"current", "permanent"}, int64(d))
}

// MMSEnrollmentState is an EE-State.
type MMSEnrollmentState int64

// Event enrollment states.
const (
	MMSEnrollmentDisabled     MMSEnrollmentState = 0
	MMSEnrollmentIdle         MMSEnrollmentState = 1
	MMSEnrollmentActive       MMSEnrollmentState = 2
	MMSEnrollmentActiveNoAckA MMSEnrollmentState = 3
	MMSEnrollmentIdleNoAckI   MMSEnrollmentState = 4
	MMSEnrollmentIdleNoAckA   MMSEnrollmentState = 5
	MMSEnrollmentIdleAcked    MMSEnrollmentState = 6
	MMSEnrollmentActiveAcked  MMSEnrollmentState = 7
	MMSEnrollmentUndefined    MMSEnrollmentState = 8
)

var mmsEnrollmentStateNames = []string{
	"disabled", "idle", "active", "activeNoAckA", "idleNoAckI", "idleNoAckA",
	"idleAcked", "activeAcked", "undefined",
}

// String returns the ASN.1 name of the state.
func (s MMSEnrollmentState) String() string { return mmsEnumName(mmsEnrollmentStateNames, int64(s)) }

// MMSEventEnrollment describes an event enrollment. It is a
// DefineEventEnrollment-Request, an AlterEventEnrollment-Request (Name,
// Transitions and AckRule) or one entry of a
// GetEventEnrollmentAttributes-Response, which adds the fields from
// Deletable on and may report the condition or action undefined.
type MMSEventEnrollment struct {
	Name               MMSObjectName
	ConditionName      MMSObjectName
	ConditionUndefined bool
	Transitions        MMSTransitions
	HasTransitions     bool
	AckRule            MMSAlarmAckRule
	HasAckRule         bool
	ActionName         MMSObjectName
	HasAction          bool
	ActionUndefined    bool
	// Client is the clientApplication, nil when absent or malformed.
	Client *MMSApplicationReference

	Deletable         bool
	Class             MMSEnrollmentClass
	Duration          MMSEnrollmentDuration
	InvokeID          uint32
	HasInvokeID       bool
	RemainingDelay    uint32
	HasRemainingDelay bool
	Enhancement       MMSEnhancement
}

// Event enrollment tags.
const (
	mmsTagEEName       uint32 = 0
	mmsTagEECondition  uint32 = 1
	mmsTagEETransition uint32 = 2
	mmsTagEEAckRule    uint32 = 3
	mmsTagEEAction     uint32 = 4
	mmsTagEEClient     uint32 = 5
	mmsTagAEETransit   uint32 = 1
	mmsTagAEEAckRule   uint32 = 2
	mmsTagEEAAction    uint32 = 2
	mmsTagEEAClient    uint32 = 3
	mmsTagEEADeletable uint32 = 4
	mmsTagEEAClass     uint32 = 5
	mmsTagEEADuration  uint32 = 6
	mmsTagEEAInvokeID  uint32 = 7
	mmsTagEEADelay     uint32 = 8
	mmsTagEEADisplay   uint32 = 9
	mmsTagEERefName    uint32 = 0
	mmsTagEERefUndef   uint32 = 1
)

// decodeMMSEnrollment reads DefineEventEnrollment-Request ([0] name, [1]
// condition, [2] transitions, [3] ackRule, [4] action, [5] client) or
// AlterEventEnrollment-Request ([0] name, [1] transitions, [2] ackRule).
func decodeMMSEnrollment(t osiBERTLV, s MMSConfirmedService) (*MMSEventEnrollment, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	e := &MMSEventEnrollment{}
	found := false
	err = mmsFields(b, func(f osiBERTLV) error {
		if f.is(osiBERContext, osiBERConstructed, mmsTagEEName) {
			found = true
			var err error
			e.Name, err = decodeMMSObjectNameIn(f.Value)
			return err
		}
		if s == MMSAlterEventEnrollment {
			return e.decodeAlter(f)
		}
		return e.decodeDefine(f)
	})
	if err == nil && !found {
		err = errMMSField
	}
	return mmsResult(e, err)
}

// decodeDefine stores one DefineEventEnrollment-Request field.
func (e *MMSEventEnrollment) decodeDefine(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERConstructed, mmsTagEECondition):
		e.ConditionName, err = decodeMMSObjectNameIn(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagEETransition):
		e.Transitions, err = decodeMMSTransitions(f.Value)
		e.HasTransitions = true
	case f.is(osiBERContext, osiBERPrimitive, mmsTagEEAckRule):
		err = e.decodeAckRule(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagEEAction):
		e.ActionName, err = decodeMMSObjectNameIn(f.Value)
		e.HasAction = true
	case f.is(osiBERContext, osiBERConstructed, mmsTagEEClient):
		e.Client, _ = decodeMMSAppRefIn(f.Value)
	}
	return err
}

// decodeAlter stores one AlterEventEnrollment-Request field.
func (e *MMSEventEnrollment) decodeAlter(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERPrimitive, mmsTagAEETransit):
		e.Transitions, err = decodeMMSTransitions(f.Value)
		e.HasTransitions = true
	case f.is(osiBERContext, osiBERPrimitive, mmsTagAEEAckRule):
		err = e.decodeAckRule(f.Value)
	}
	return err
}

// decodeAckRule stores an AlarmAckRule.
func (e *MMSEventEnrollment) decodeAckRule(v []byte) error {
	n, err := osiBERInt(v)
	e.AckRule, e.HasAckRule = MMSAlarmAckRule(n), true
	return err
}

// decodeAttribute stores one EEAttributes field.
func (e *MMSEventEnrollment) decodeAttribute(f osiBERTLV) error {
	var err error
	var n int64
	switch {
	case f.is(osiBERContext, osiBERConstructed, mmsTagEEName):
		e.Name, err = decodeMMSObjectNameIn(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagEECondition):
		e.ConditionName, e.ConditionUndefined, err = decodeMMSNameOrUndef(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagEEAAction):
		e.ActionName, e.ActionUndefined, err = decodeMMSNameOrUndef(f.Value)
		e.HasAction = !e.ActionUndefined
	case f.is(osiBERContext, osiBERConstructed, mmsTagEEAClient):
		e.Client, _ = decodeMMSAppRefIn(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagEEADeletable):
		e.Deletable, err = osiBERBool(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagEEAClass):
		n, err = osiBERInt(f.Value)
		e.Class = MMSEnrollmentClass(n)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagEEADuration):
		n, err = osiBERInt(f.Value)
		e.Duration = MMSEnrollmentDuration(n)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagEEAInvokeID):
		e.InvokeID, err = osiBERUint32(f.Value)
		e.HasInvokeID = true
	case f.is(osiBERContext, osiBERPrimitive, mmsTagEEADelay):
		e.RemainingDelay, err = osiBERUint32(f.Value)
		e.HasRemainingDelay = true
	case f.is(osiBERContext, osiBERConstructed, mmsTagEEADisplay):
		e.Enhancement, err = decodeMMSEnhancement(f.Value)
	}
	return err
}

// decodeMMSNameOrUndef reads CHOICE { [0] ObjectName, undefined [1] NULL }
// filling b.
func decodeMMSNameOrUndef(b []byte) (MMSObjectName, bool, error) {
	var n MMSObjectName
	t, err := osiBERSingle(b)
	if err != nil {
		return n, false, err
	}

	switch {
	case t.is(osiBERContext, osiBERConstructed, mmsTagEERefName):
		n, err = decodeMMSObjectNameIn(t.Value)
		return n, false, err
	case t.is(osiBERContext, osiBERPrimitive, mmsTagEERefUndef):
		return n, true, mmsNull(t.Value)
	}
	return n, false, errMMSField
}

// MMSEnrollmentScope is the scopeOfRequest of a
// getEventEnrollmentAttributes request.
type MMSEnrollmentScope int64

// Enrollment request scopes.
const (
	MMSEnrollmentScopeSpecific  MMSEnrollmentScope = 0
	MMSEnrollmentScopeClient    MMSEnrollmentScope = 1
	MMSEnrollmentScopeCondition MMSEnrollmentScope = 2
	MMSEnrollmentScopeAction    MMSEnrollmentScope = 3
)

// String returns the ASN.1 name of the scope.
func (s MMSEnrollmentScope) String() string {
	return mmsEnumName([]string{"specific", "client", "ec", "ea"}, int64(s))
}

// MMSEnrollmentQuery is a GetEventEnrollmentAttributes-Request. Scope
// defaults to client.
type MMSEnrollmentQuery struct {
	Scope            MMSEnrollmentScope
	Names            []MMSObjectName
	Client           *MMSApplicationReference
	ConditionName    MMSObjectName
	HasCondition     bool
	ActionName       MMSObjectName
	HasAction        bool
	ContinueAfter    MMSObjectName
	HasContinueAfter bool
}

// MMSEnrollmentList is a GetEventEnrollmentAttributes-Response.
type MMSEnrollmentList struct {
	Enrollments []MMSEventEnrollment
	MoreFollows bool
}

// Enrollment query and list tags.
const (
	mmsTagEQScope     uint32 = 0
	mmsTagEQNames     uint32 = 1
	mmsTagEQClient    uint32 = 2
	mmsTagEQCondition uint32 = 3
	mmsTagEQAction    uint32 = 4
	mmsTagEQContinue  uint32 = 5
	mmsTagELList      uint32 = 0
	mmsTagELMore      uint32 = 1
)

// decodeMMSEnrollQuery reads GetEventEnrollmentAttributes-Request.
func decodeMMSEnrollQuery(t osiBERTLV) (*MMSEnrollmentQuery, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	q := &MMSEnrollmentQuery{Scope: MMSEnrollmentScopeClient}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagEQScope):
			var n int64
			n, err = osiBERInt(f.Value)
			q.Scope = MMSEnrollmentScope(n)
		case f.is(osiBERContext, osiBERConstructed, mmsTagEQNames):
			q.Names, err = decodeMMSObjectNames(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagEQClient):
			q.Client, _ = decodeMMSAppRefIn(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagEQCondition):
			q.ConditionName, err = decodeMMSObjectNameIn(f.Value)
			q.HasCondition = true
		case f.is(osiBERContext, osiBERConstructed, mmsTagEQAction):
			q.ActionName, err = decodeMMSObjectNameIn(f.Value)
			q.HasAction = true
		case f.is(osiBERContext, osiBERConstructed, mmsTagEQContinue):
			q.ContinueAfter, err = decodeMMSObjectNameIn(f.Value)
			q.HasContinueAfter = true
		}
		return err
	})
	return mmsResult(q, err)
}

// decodeMMSEnrollList reads GetEventEnrollmentAttributes-Response: [0]
// listOfEventEnrollment, [1] moreFollows DEFAULT FALSE.
func decodeMMSEnrollList(t osiBERTLV) (*MMSEnrollmentList, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	l := &MMSEnrollmentList{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagELList):
			l.Enrollments, err = decodeMMSEnrollments(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagELMore):
			l.MoreFollows, err = osiBERBool(f.Value)
		}
		return err
	})
	return mmsResult(l, err)
}

// decodeMMSEnrollments decodes a SEQUENCE OF EventEnrollment body.
func decodeMMSEnrollments(b []byte) ([]MMSEventEnrollment, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSEventEnrollment, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		// An entry starts with its mandatory name.
		if _, _, err := osiBERExpect(item, osiBERContext, osiBERConstructed, mmsTagEEName); err != nil {
			return nil, err
		}

		var e MMSEventEnrollment
		if err := mmsFields(item, e.decodeAttribute); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// MMSEnrollmentStatus is a ReportEventEnrollmentStatus-Response
// (Transitions to State) or an AlterEventEnrollment-Response (State,
// StateUndefined and TransitionTime).
type MMSEnrollmentStatus struct {
	Transitions      MMSTransitions
	NotificationLost bool
	Duration         MMSEnrollmentDuration
	AckRule          MMSAlarmAckRule
	HasAckRule       bool
	State            MMSEnrollmentState
	StateUndefined   bool
	TransitionTime   MMSEventTime
}

// Enrollment status tags.
const (
	mmsTagESTransition uint32 = 0
	mmsTagESLost       uint32 = 1
	mmsTagESDuration   uint32 = 2
	mmsTagESAckRule    uint32 = 3
	mmsTagESState      uint32 = 4
	mmsTagAEState      uint32 = 0
	mmsTagAETime       uint32 = 1
	mmsTagAEStateValue uint32 = 0
	mmsTagAEStateUndef uint32 = 1
)

// decodeMMSEnrollStatus reads ReportEventEnrollmentStatus-Response.
func decodeMMSEnrollStatus(t osiBERTLV) (*MMSEnrollmentStatus, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	s := &MMSEnrollmentStatus{}
	err = mmsFields(b, func(f osiBERTLV) error {
		if f.Class != osiBERContext || f.Form != osiBERPrimitive {
			return nil
		}

		var err error
		var n int64
		switch f.Tag {
		case mmsTagESTransition:
			s.Transitions, err = decodeMMSTransitions(f.Value)
		case mmsTagESLost:
			s.NotificationLost, err = osiBERBool(f.Value)
		case mmsTagESDuration:
			n, err = osiBERInt(f.Value)
			s.Duration = MMSEnrollmentDuration(n)
		case mmsTagESAckRule:
			n, err = osiBERInt(f.Value)
			s.AckRule, s.HasAckRule = MMSAlarmAckRule(n), true
		case mmsTagESState:
			n, err = osiBERInt(f.Value)
			s.State = MMSEnrollmentState(n)
		}
		return err
	})
	return mmsResult(s, err)
}

// decodeMMSEnrollAltered reads AlterEventEnrollment-Response: [0]
// currentState CHOICE { state [0], undefined [1] }, [1] transitionTime.
func decodeMMSEnrollAltered(t osiBERTLV) (*MMSEnrollmentStatus, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	s := &MMSEnrollmentStatus{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagAEState):
			err = s.decodeState(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagAETime):
			s.TransitionTime, err = decodeMMSEventTimeIn(f.Value)
		}
		return err
	})
	return mmsResult(s, err)
}

// decodeState reads currentState: state [0] EE-State or undefined [1].
func (s *MMSEnrollmentStatus) decodeState(b []byte) error {
	c, err := osiBERSingle(b)
	if err != nil {
		return err
	}

	switch {
	case c.is(osiBERContext, osiBERPrimitive, mmsTagAEStateValue):
		var n int64
		n, err = osiBERInt(c.Value)
		s.State = MMSEnrollmentState(n)
	case c.is(osiBERContext, osiBERPrimitive, mmsTagAEStateUndef):
		s.StateUndefined = true
		err = mmsNull(c.Value)
	default:
		err = errMMSField
	}
	return err
}

// MMSUnackedState is the unacknowledgedState of an alarm summary.
type MMSUnackedState int64

// Unacknowledged states.
const (
	MMSUnackedNone   MMSUnackedState = 0
	MMSUnackedActive MMSUnackedState = 1
	MMSUnackedIdle   MMSUnackedState = 2
	MMSUnackedBoth   MMSUnackedState = 3
)

// String returns the ASN.1 name of the state.
func (s MMSUnackedState) String() string {
	return mmsEnumName([]string{"none", "active", "idle", "both"}, int64(s))
}

// MMSAlarmSummary is one AlarmSummary of a GetAlarmSummary-Response.
type MMSAlarmSummary struct {
	ConditionName  MMSObjectName
	Severity       uint8
	State          MMSEventState
	Unacknowledged MMSUnackedState
	Enhancement    MMSEnhancement
	ToActive       MMSEventTime
	HasToActive    bool
	ToIdle         MMSEventTime
	HasToIdle      bool
}

// MMSAlarmEnrollment is one AlarmEnrollmentSummary of a
// GetAlarmEnrollmentSummary-Response. Each Has field tells the value
// before it was present.
type MMSAlarmEnrollment struct {
	EnrollmentName     MMSObjectName
	Client             *MMSApplicationReference
	Severity           uint8
	State              MMSEventState
	Enhancement        MMSEnhancement
	NotificationLost   bool
	AckRule            MMSAlarmAckRule
	HasAckRule         bool
	EnrollmentState    MMSEnrollmentState
	HasEnrollmentState bool
	ToActive           MMSEventTime
	HasToActive        bool
	ActiveAcked        MMSEventTime
	HasActiveAcked     bool
	ToIdle             MMSEventTime
	HasToIdle          bool
	IdleAcked          MMSEventTime
	HasIdleAcked       bool
}

// Alarm summary entry tags.
const (
	mmsTagAlName       uint32 = 0
	mmsTagAlSeverity   uint32 = 1
	mmsTagAlState      uint32 = 2
	mmsTagAlUnacked    uint32 = 3
	mmsTagAlDisplay    uint32 = 4
	mmsTagAlToActive   uint32 = 5
	mmsTagAlToIdle     uint32 = 6
	mmsTagAEnClient    uint32 = 2
	mmsTagAEnSeverity  uint32 = 3
	mmsTagAEnState     uint32 = 4
	mmsTagAEnDisplay   uint32 = 5
	mmsTagAEnLost      uint32 = 6
	mmsTagAEnAckRule   uint32 = 7
	mmsTagAEnEEState   uint32 = 8
	mmsTagAEnToActive  uint32 = 9
	mmsTagAEnActAcked  uint32 = 10
	mmsTagAEnToIdle    uint32 = 11
	mmsTagAEnIdleAcked uint32 = 12
)

// mmsAlarmItems walks a SEQUENCE OF SEQUENCE body whose entries start
// with a mandatory [0] ObjectName: it calls start with entry i of count,
// then field for each of its fields.
func mmsAlarmItems(b []byte, start func(i, count int), field func(f osiBERTLV) error) error {
	count, err := osiBERCount(b)
	if err != nil {
		return err
	}

	for i := 0; len(b) > 0; i++ {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return err
		}
		b = rest

		if _, _, err := osiBERExpect(item, osiBERContext, osiBERConstructed, mmsTagAlName); err != nil {
			return err
		}
		start(i, count)
		if err := mmsFields(item, field); err != nil {
			return err
		}
	}
	return nil
}

// decodeMMSAlarms decodes a SEQUENCE OF AlarmSummary body.
func decodeMMSAlarms(b []byte) ([]MMSAlarmSummary, error) {
	var out []MMSAlarmSummary
	var a *MMSAlarmSummary
	err := mmsAlarmItems(b, func(i, count int) {
		if out == nil {
			out = make([]MMSAlarmSummary, count)
		}
		a = &out[i]
	}, func(f osiBERTLV) error {
		return a.decodeField(f)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decodeField stores one AlarmSummary field.
func (a *MMSAlarmSummary) decodeField(f osiBERTLV) error {
	var err error
	var n int64
	switch {
	case f.is(osiBERContext, osiBERConstructed, mmsTagAlName):
		a.ConditionName, err = decodeMMSObjectNameIn(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagAlSeverity):
		a.Severity, err = mmsUint8(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagAlState):
		n, err = osiBERInt(f.Value)
		a.State = MMSEventState(n)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagAlUnacked):
		n, err = osiBERInt(f.Value)
		a.Unacknowledged = MMSUnackedState(n)
	case f.is(osiBERContext, osiBERConstructed, mmsTagAlDisplay):
		a.Enhancement, err = decodeMMSEnhancementIn(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagAlToActive):
		a.ToActive, err = decodeMMSEventTimeIn(f.Value)
		a.HasToActive = true
	case f.is(osiBERContext, osiBERConstructed, mmsTagAlToIdle):
		a.ToIdle, err = decodeMMSEventTimeIn(f.Value)
		a.HasToIdle = true
	}
	return err
}

// decodeMMSAlarmEnrolls decodes a SEQUENCE OF AlarmEnrollmentSummary
// body.
func decodeMMSAlarmEnrolls(b []byte) ([]MMSAlarmEnrollment, error) {
	var out []MMSAlarmEnrollment
	var a *MMSAlarmEnrollment
	err := mmsAlarmItems(b, func(i, count int) {
		if out == nil {
			out = make([]MMSAlarmEnrollment, count)
		}
		a = &out[i]
	}, func(f osiBERTLV) error {
		if f.Form == osiBERPrimitive {
			return a.decodeValue(f)
		}
		return a.decodeNested(f)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decodeValue stores one primitive AlarmEnrollmentSummary field.
func (a *MMSAlarmEnrollment) decodeValue(f osiBERTLV) error {
	if f.Class != osiBERContext {
		return nil
	}

	var err error
	var n int64
	switch f.Tag {
	case mmsTagAEnSeverity:
		a.Severity, err = mmsUint8(f.Value)
	case mmsTagAEnState:
		n, err = osiBERInt(f.Value)
		a.State = MMSEventState(n)
	case mmsTagAEnLost:
		a.NotificationLost, err = osiBERBool(f.Value)
	case mmsTagAEnAckRule:
		n, err = osiBERInt(f.Value)
		a.AckRule, a.HasAckRule = MMSAlarmAckRule(n), true
	case mmsTagAEnEEState:
		n, err = osiBERInt(f.Value)
		a.EnrollmentState, a.HasEnrollmentState = MMSEnrollmentState(n), true
	}
	return err
}

// decodeNested stores one constructed AlarmEnrollmentSummary field: the
// name, the client, the enhancement or one of the four times.
func (a *MMSAlarmEnrollment) decodeNested(f osiBERTLV) error {
	if f.Class != osiBERContext {
		return nil
	}

	var err error
	var at *MMSEventTime
	var has *bool
	switch f.Tag {
	case mmsTagAlName:
		a.EnrollmentName, err = decodeMMSObjectNameIn(f.Value)
		return err
	case mmsTagAEnClient:
		a.Client, _ = decodeMMSAppRefIn(f.Value)
		return nil
	case mmsTagAEnDisplay:
		a.Enhancement, err = decodeMMSEnhancementIn(f.Value)
		return err
	case mmsTagAEnToActive:
		at, has = &a.ToActive, &a.HasToActive
	case mmsTagAEnActAcked:
		at, has = &a.ActiveAcked, &a.HasActiveAcked
	case mmsTagAEnToIdle:
		at, has = &a.ToIdle, &a.HasToIdle
	case mmsTagAEnIdleAcked:
		at, has = &a.IdleAcked, &a.HasIdleAcked
	default:
		return nil
	}

	*at, err = decodeMMSEventTimeIn(f.Value)
	*has = true
	return err
}
