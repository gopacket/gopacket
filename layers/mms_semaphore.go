// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import "fmt"

// MMS semaphore and operator station services, request modifiers and the
// ApplicationReference they share (ISO 9506-2 clauses 15 and 16). Like
// the decoders of mms_services.go these are best effort: they return nil
// with their error, which ends up in MMS.ServiceDecodeErr.

// MMSApplicationReference is an ApplicationReference: the AE title and
// invocation identifiers of another application process, e.g. the owner
// of a semaphore or the client of an event enrollment.
type MMSApplicationReference struct {
	Title ACSEAETitle
	Info  ACSEAEInfo
}

// ApplicationReference tags.
const (
	mmsTagARAPTitle uint32 = 0
	mmsTagARAPInv   uint32 = 1
	mmsTagARAEQual  uint32 = 2
	mmsTagARAEInv   uint32 = 3
)

// decodeMMSAppRef reads an ApplicationReference body: four EXPLICIT
// optional fields taken from ACSE.
func decodeMMSAppRef(b []byte) (*MMSApplicationReference, error) {
	r := &MMSApplicationReference{}
	err := mmsFields(b, func(f osiBERTLV) error {
		if f.Class != osiBERContext || f.Form != osiBERConstructed {
			return nil
		}

		var err error
		switch f.Tag {
		case mmsTagARAPTitle:
			err = r.Title.decodeAPTitle(f.Value)
			r.Info.decodeAPTitle(f.Value)
		case mmsTagARAEQual:
			err = r.Title.decodeAEQualifier(f.Value)
			r.Info.decodeAEQualifier(f.Value)
		case mmsTagARAPInv:
			r.Info.APInvocationID, r.Info.HasAPInvocationID = acseInvocation(f)
		case mmsTagARAEInv:
			r.Info.AEInvocationID, r.Info.HasAEInvocationID = acseInvocation(f)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSAppRefIn reads the ApplicationReference SEQUENCE that fills b,
// as found under an EXPLICIT tag.
func decodeMMSAppRefIn(b []byte) (*MMSApplicationReference, error) {
	t, err := osiBERSingle(b)
	if err != nil {
		return nil, err
	}
	if !t.is(osiBERUniversal, osiBERConstructed, osiBERTagSequence) {
		return nil, errMMSField
	}
	return decodeMMSAppRef(t.Value)
}

// MMSTransitions is the Transitions BIT STRING of event enrollments: the
// state changes of an event condition that matter.
type MMSTransitions uint8

// Transitions bits; bit 0 is the most significant bit of the octet.
const (
	MMSIdleToDisabled   MMSTransitions = 0x80
	MMSActiveToDisabled MMSTransitions = 0x40
	MMSDisabledToIdle   MMSTransitions = 0x20
	MMSActiveToIdle     MMSTransitions = 0x10
	MMSDisabledToActive MMSTransitions = 0x08
	MMSIdleToActive     MMSTransitions = 0x04
	MMSAnyToDeleted     MMSTransitions = 0x02
)

// decodeMMSTransitions reads a Transitions BIT STRING, e.g. 01 0c =
// disabled-to-active and idle-to-active.
func decodeMMSTransitions(v []byte) (MMSTransitions, error) {
	bits, unused, err := osiBERBits(v)
	if err != nil || len(bits) == 0 {
		return 0, err
	}

	// Padding bits of a one octet string carry no transition.
	first := bits[0]
	if len(bits) == 1 {
		first &^= 1<<unused - 1
	}
	return MMSTransitions(first), nil
}

// MMSModifierKind is the Modifier CHOICE tag.
type MMSModifierKind uint8

// Modifier alternatives.
const (
	MMSModifierEvent     MMSModifierKind = 0
	MMSModifierSemaphore MMSModifierKind = 1
)

// String returns the ASN.1 name of the alternative.
func (k MMSModifierKind) String() string {
	switch k {
	case MMSModifierEvent:
		return "attach-To-Event-Condition"
	case MMSModifierSemaphore:
		return "attach-To-Semaphore"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(k))
	}
}

// MMSAttachToEvent is an AttachToEventCondition modifier: the request
// runs when the event condition makes one of the transitions.
type MMSAttachToEvent struct {
	EnrollmentName     MMSObjectName
	ConditionName      MMSObjectName
	Transitions        MMSTransitions
	AcceptableDelay    uint32
	HasAcceptableDelay bool
}

// MMSModifier is one Modifier of a confirmed request or event action.
// Kind selects Event or Semaphore.
type MMSModifier struct {
	Kind      MMSModifierKind
	Event     *MMSAttachToEvent
	Semaphore *MMSSemaphoreRequest
}

// AttachToEventCondition tags.
const (
	mmsTagAECEnrollment uint32 = 0
	mmsTagAECCondition  uint32 = 1
	mmsTagAECTransition uint32 = 2
	mmsTagAECDelay      uint32 = 3
)

// decodeMMSModifiers decodes a SEQUENCE OF Modifier body.
func decodeMMSModifiers(b []byte) ([]MMSModifier, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSModifier, 0, count)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		var mod MMSModifier
		switch {
		case t.is(osiBERContext, osiBERConstructed, uint32(MMSModifierEvent)):
			mod.Event, err = decodeMMSAttachEvent(t.Value)
		case t.is(osiBERContext, osiBERConstructed, uint32(MMSModifierSemaphore)):
			mod.Semaphore, err = decodeMMSSemaphoreReq(t, MMSTakeControl)
		default:
			err = errMMSField
		}
		if err != nil {
			return nil, err
		}

		mod.Kind = MMSModifierKind(t.Tag)
		out = append(out, mod)
	}
	return out, nil
}

// decodeMMSAttachEvent reads AttachToEventCondition: [0] enrollment name,
// [1] condition name, [2] causingTransitions, [3] acceptableDelay
// OPTIONAL.
func decodeMMSAttachEvent(b []byte) (*MMSAttachToEvent, error) {
	a := &MMSAttachToEvent{}
	names := 0
	err := mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagAECEnrollment):
			a.EnrollmentName, err = decodeMMSObjectNameIn(f.Value)
			names++
		case f.is(osiBERContext, osiBERConstructed, mmsTagAECCondition):
			a.ConditionName, err = decodeMMSObjectNameIn(f.Value)
			names++
		case f.is(osiBERContext, osiBERPrimitive, mmsTagAECTransition):
			a.Transitions, err = decodeMMSTransitions(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagAECDelay):
			a.AcceptableDelay, err = osiBERUint32(f.Value)
			a.HasAcceptableDelay = true
		}
		return err
	})

	// Both names are mandatory.
	const wantNames = 2
	if err == nil && names < wantNames {
		err = errMMSField
	}
	return mmsResult(a, err)
}

// MMSSemaphoreState is the state filter of a reportSemaphoreEntryStatus
// request.
type MMSSemaphoreState int64

// Semaphore entry states.
const (
	MMSSemaphoreQueued MMSSemaphoreState = 0
	MMSSemaphoreOwner  MMSSemaphoreState = 1
	MMSSemaphoreHung   MMSSemaphoreState = 2
)

var mmsSemaphoreStateNames = []string{"queued", "owner", "hung"}

// String returns the ASN.1 name of the state.
func (s MMSSemaphoreState) String() string { return mmsEnumName(mmsSemaphoreStateNames, int64(s)) }

// MMSSemaphoreClass is the class of a semaphore.
type MMSSemaphoreClass int64

// Semaphore classes.
const (
	MMSSemaphoreToken MMSSemaphoreClass = 0
	MMSSemaphorePool  MMSSemaphoreClass = 1
)

var mmsSemaphoreClassNames = []string{"token", "pool"}

// String returns the ASN.1 name of the class.
func (c MMSSemaphoreClass) String() string { return mmsEnumName(mmsSemaphoreClassNames, int64(c)) }

// MMSSemaphoreRequest holds the arguments of the semaphore requests and
// of an attach-To-Semaphore modifier. Name is always set:
//
//	NamedToken                 takeControl, relinquishControl, modifier
//	Priority .. Preempt        takeControl, modifier (no Preempt)
//	Tokens                     defineSemaphore
//	StartAfter                 reportPoolSemaphoreStatus
//	State, EntryStartAfter     reportSemaphoreEntryStatus
//
// Priority defaults to 64 and RelinquishIfLost to true.
type MMSSemaphoreRequest struct {
	Name               MMSObjectName
	NamedToken         string
	Priority           uint8
	AcceptableDelay    uint32
	HasAcceptableDelay bool
	ControlTimeOut     uint32
	HasControlTimeOut  bool
	AbortOnTimeOut     bool
	HasAbortOnTimeOut  bool
	RelinquishIfLost   bool
	Preempt            *MMSApplicationReference

	Tokens          uint16
	StartAfter      string
	State           MMSSemaphoreState
	EntryStartAfter []byte
}

// MMSTokenState tells whether a named token is free, owned or hung.
type MMSTokenState uint8

// Named token states: the tags of the listOfNamedTokens CHOICE.
const (
	MMSTokenFree  MMSTokenState = 0
	MMSTokenOwned MMSTokenState = 1
	MMSTokenHung  MMSTokenState = 2
)

var mmsTokenStateNames = []string{"freeNamedToken", "ownedNamedToken", "hungNamedToken"}

// String returns the ASN.1 name of the state.
func (s MMSTokenState) String() string { return mmsEnumName(mmsTokenStateNames, int64(s)) }

// MMSNamedToken is one named token of a pool semaphore.
type MMSNamedToken struct {
	State MMSTokenState
	Name  string
}

// MMSSemaphoreEntryClass tells how a semaphore entry was made.
type MMSSemaphoreEntryClass int64

// Semaphore entry classes.
const (
	MMSEntrySimple   MMSSemaphoreEntryClass = 0
	MMSEntryModifier MMSSemaphoreEntryClass = 1
)

var mmsEntryClassNames = []string{"simple", "modifier"}

// String returns the ASN.1 name of the class.
func (c MMSSemaphoreEntryClass) String() string { return mmsEnumName(mmsEntryClassNames, int64(c)) }

// MMSSemaphoreEntry is one SemaphoreEntry: a queued, owning or hung
// request for a semaphore. Application is nil when malformed or absent.
type MMSSemaphoreEntry struct {
	EntryID             []byte
	Class               MMSSemaphoreEntryClass
	Application         *MMSApplicationReference
	NamedToken          string
	Priority            uint8
	RemainingTimeOut    uint32
	HasRemainingTimeOut bool
	AbortOnTimeOut      bool
	HasAbortOnTimeOut   bool
	RelinquishIfLost    bool
}

// MMSSemaphoreResponse holds a semaphore response:
//
//	NamedToken, HasNamedToken      takeControl (noResult when not set)
//	Deletable .. HungTokens        reportSemaphoreStatus
//	NamedTokens, MoreFollows       reportPoolSemaphoreStatus
//	Entries, MoreFollows           reportSemaphoreEntryStatus
type MMSSemaphoreResponse struct {
	NamedToken    string
	HasNamedToken bool

	Deletable   bool
	Class       MMSSemaphoreClass
	Tokens      uint16
	OwnedTokens uint16
	HungTokens  uint16

	NamedTokens []MMSNamedToken
	Entries     []MMSSemaphoreEntry
	MoreFollows bool
}

// Semaphore tags.
const (
	mmsTagSemName       uint32 = 0
	mmsTagSemToken      uint32 = 1
	mmsTagSemPriority   uint32 = 2
	mmsTagSemDelay      uint32 = 3
	mmsTagSemTimeOut    uint32 = 4
	mmsTagSemAbort      uint32 = 5
	mmsTagSemRelinquish uint32 = 6
	mmsTagSemPreempt    uint32 = 7
	mmsTagSemArg        uint32 = 1
	mmsTagSemEntryAfter uint32 = 2
	mmsTagSemNoResult   uint32 = 0
	mmsTagSemDeletable  uint32 = 0
	mmsTagSemClass      uint32 = 1
	mmsTagSemTokens     uint32 = 2
	mmsTagSemOwned      uint32 = 3
	mmsTagSemHung       uint32 = 4
	mmsTagSemList       uint32 = 0
	mmsTagSemMore       uint32 = 1
	mmsTagSEID          uint32 = 0
	mmsTagSEClass       uint32 = 1
	mmsTagSEApp         uint32 = 2
	mmsTagSEToken       uint32 = 3
	mmsTagSEPriority    uint32 = 4
	mmsTagSETimeOut     uint32 = 5
	mmsTagSEAbort       uint32 = 6
	mmsTagSERelinquish  uint32 = 7
)

// decodeMMSSemaphoreReq reads a semaphore request that is a SEQUENCE. All
// start with [0] semaphoreName; s tells what the other tags mean.
func decodeMMSSemaphoreReq(t osiBERTLV, s MMSConfirmedService) (*MMSSemaphoreRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSSemaphoreRequest{Priority: mmsDefaultPriority, RelinquishIfLost: true}
	found := false
	err = mmsFields(b, func(f osiBERTLV) error {
		if f.is(osiBERContext, osiBERConstructed, mmsTagSemName) {
			found = true
			var err error
			r.Name, err = decodeMMSObjectNameIn(f.Value)
			return err
		}
		if s == MMSTakeControl || s == MMSRelinquishControl {
			return r.decodeControl(f)
		}
		return r.decodeArg(f, s)
	})
	if err == nil && !found {
		err = errMMSField
	}
	return mmsResult(r, err)
}

// decodeControl stores one TakeControl-Request, RelinquishControl-Request
// or AttachToSemaphore field past the name.
func (r *MMSSemaphoreRequest) decodeControl(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSemToken):
		r.NamedToken = string(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSemPriority):
		r.Priority, err = mmsUint8(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSemDelay):
		r.AcceptableDelay, err = osiBERUint32(f.Value)
		r.HasAcceptableDelay = true
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSemTimeOut):
		r.ControlTimeOut, err = osiBERUint32(f.Value)
		r.HasControlTimeOut = true
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSemAbort):
		r.AbortOnTimeOut, err = osiBERBool(f.Value)
		r.HasAbortOnTimeOut = true
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSemRelinquish):
		r.RelinquishIfLost, err = osiBERBool(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagSemPreempt):
		r.Preempt, err = decodeMMSAppRef(f.Value)
	}
	return err
}

// decodeArg stores the [1] and [2] fields of the define and report
// requests.
func (r *MMSSemaphoreRequest) decodeArg(f osiBERTLV, s MMSConfirmedService) error {
	if f.Class != osiBERContext || f.Form != osiBERPrimitive {
		return nil
	}

	var err error
	switch {
	case s == MMSDefineSemaphore && f.Tag == mmsTagSemArg:
		r.Tokens, err = mmsUint16(f.Value)
	case s == MMSReportPoolSemaphoreStatus && f.Tag == mmsTagSemArg:
		r.StartAfter = string(f.Value)
	case s == MMSReportSemaphoreEntryStatus && f.Tag == mmsTagSemArg:
		var n int64
		n, err = osiBERInt(f.Value)
		r.State = MMSSemaphoreState(n)
	case s == MMSReportSemaphoreEntryStatus && f.Tag == mmsTagSemEntryAfter:
		r.EntryStartAfter = f.Value
	}
	return err
}

// decodeMMSTakeResp reads TakeControl-Response: an EXPLICIT CHOICE
// { noResult [0] NULL, namedToken [1] Identifier }.
func decodeMMSTakeResp(t osiBERTLV) (*MMSSemaphoreResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}
	c, err := osiBERSingle(b)
	if err != nil {
		return nil, err
	}

	r := &MMSSemaphoreResponse{}
	switch {
	case c.is(osiBERContext, osiBERPrimitive, mmsTagSemNoResult):
		err = mmsNull(c.Value)
	case c.is(osiBERContext, osiBERPrimitive, mmsTagSemToken):
		r.NamedToken, r.HasNamedToken = string(c.Value), true
	default:
		err = errMMSField
	}
	return mmsResult(r, err)
}

// decodeMMSSemStatus reads ReportSemaphoreStatus-Response.
func decodeMMSSemStatus(t osiBERTLV) (*MMSSemaphoreResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSSemaphoreResponse{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagSemDeletable):
			r.Deletable, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagSemClass):
			var n int64
			n, err = osiBERInt(f.Value)
			r.Class = MMSSemaphoreClass(n)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagSemTokens):
			r.Tokens, err = mmsUint16(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagSemOwned):
			r.OwnedTokens, err = mmsUint16(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagSemHung):
			r.HungTokens, err = mmsUint16(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSSemList reads ReportPoolSemaphoreStatus-Response or
// ReportSemaphoreEntryStatus-Response: [0] list, [1] moreFollows DEFAULT
// TRUE.
func decodeMMSSemList(t osiBERTLV, s MMSConfirmedService) (*MMSSemaphoreResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSSemaphoreResponse{MoreFollows: true}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case s == MMSReportPoolSemaphoreStatus && f.is(osiBERContext, osiBERConstructed, mmsTagSemList):
			r.NamedTokens, err = decodeMMSNamedTokens(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagSemList):
			r.Entries, err = decodeMMSSemEntries(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagSemMore):
			r.MoreFollows, err = osiBERBool(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSNamedTokens decodes listOfNamedTokens: SEQUENCE OF CHOICE
// { free [0], owned [1], hung [2] } Identifier.
func decodeMMSNamedTokens(b []byte) ([]MMSNamedToken, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSNamedToken, 0, count)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		if t.Class != osiBERContext || t.Form != osiBERPrimitive || t.Tag > uint32(MMSTokenHung) {
			return nil, errMMSField
		}
		out = append(out, MMSNamedToken{State: MMSTokenState(t.Tag), Name: string(t.Value)})
	}
	return out, nil
}

// decodeMMSSemEntries decodes a SEQUENCE OF SemaphoreEntry body.
func decodeMMSSemEntries(b []byte) ([]MMSSemaphoreEntry, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSSemaphoreEntry, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		e := MMSSemaphoreEntry{Priority: mmsDefaultPriority, RelinquishIfLost: true}
		if err := mmsFields(item, e.decodeField); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// decodeField stores one SemaphoreEntry field.
func (e *MMSSemaphoreEntry) decodeField(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSEID):
		e.EntryID = f.Value
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSEClass):
		var n int64
		n, err = osiBERInt(f.Value)
		e.Class = MMSSemaphoreEntryClass(n)
	case f.is(osiBERContext, osiBERConstructed, mmsTagSEApp):
		// Best effort, as the ACSE titles are.
		e.Application, _ = decodeMMSAppRefIn(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSEToken):
		e.NamedToken = string(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSEPriority):
		e.Priority, err = mmsUint8(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSETimeOut):
		e.RemainingTimeOut, err = osiBERUint32(f.Value)
		e.HasRemainingTimeOut = true
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSEAbort):
		e.AbortOnTimeOut, err = osiBERBool(f.Value)
		e.HasAbortOnTimeOut = true
	case f.is(osiBERContext, osiBERPrimitive, mmsTagSERelinquish):
		e.RelinquishIfLost, err = osiBERBool(f.Value)
	}
	return err
}

// MMSOperatorRequest is an Input-Request (Echo, Prompts, InputTimeOut) or
// an Output-Request (Output) for an operator station. Echo defaults to
// true.
type MMSOperatorRequest struct {
	Station         string
	Echo            bool
	Prompts         []string
	InputTimeOut    uint32
	HasInputTimeOut bool
	Output          []string
}

// MMSOperatorResponse is an Input-Response: what the operator typed.
type MMSOperatorResponse struct {
	Input string
}

// Operator station tags.
const (
	mmsTagOpStation uint32 = 0
	mmsTagOpEcho    uint32 = 1
	mmsTagOpPrompts uint32 = 2
	mmsTagOpTimeOut uint32 = 3
	mmsTagOpOutput  uint32 = 1
)

// decodeMMSOperatorReq reads Input-Request ([0] station, [1] echo, [2]
// listOfPromptData, [3] inputTimeOut) or Output-Request ([0] station, [1]
// listOfOutputData).
func decodeMMSOperatorReq(t osiBERTLV, s MMSConfirmedService) (*MMSOperatorRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSOperatorRequest{Echo: true}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagOpStation):
			r.Station = string(f.Value)
		case s == MMSOutput && f.is(osiBERContext, osiBERConstructed, mmsTagOpOutput):
			r.Output, err = decodeMMSStrings(f.Value, osiBERTagVisible)
		case s == MMSInput && f.is(osiBERContext, osiBERPrimitive, mmsTagOpEcho):
			r.Echo, err = osiBERBool(f.Value)
		case s == MMSInput && f.is(osiBERContext, osiBERConstructed, mmsTagOpPrompts):
			r.Prompts, err = decodeMMSStrings(f.Value, osiBERTagVisible)
		case s == MMSInput && f.is(osiBERContext, osiBERPrimitive, mmsTagOpTimeOut):
			r.InputTimeOut, err = osiBERUint32(f.Value)
			r.HasInputTimeOut = true
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSInputResp reads Input-Response: a bare VisibleString.
func decodeMMSInputResp(t osiBERTLV) (*MMSOperatorResponse, error) {
	b, err := mmsBody(t, osiBERPrimitive)
	if err != nil {
		return nil, err
	}
	return &MMSOperatorResponse{Input: string(b)}, nil
}
