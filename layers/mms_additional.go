// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

// The parts ISO 9506-2:2003 adds to the 1990 services: the service-ext
// detail of the companion standards, the additionalService CHOICE (VMD
// stop and reset, unit control, event condition lists) and the access
// control list services. Best effort, like mms_services.go: every value
// keeps its raw octets, so what fails to decode is still at hand.

// MMSStartCountKind is the StartCount (and running mode) CHOICE tag.
type MMSStartCountKind uint8

// StartCount alternatives.
const (
	MMSStartNoLimit    MMSStartCountKind = 0
	MMSStartCycleCount MMSStartCountKind = 1
	MMSStartStepCount  MMSStartCountKind = 2
)

// String returns the ASN.1 name of the alternative.
func (k MMSStartCountKind) String() string {
	return mmsEnumName([]string{"noLimit", "cycleCount", "stepCount"}, int64(k))
}

// MMSStartCount tells how long a controlling program invocation runs:
// without limit, or for Count cycles or steps. The default is one cycle.
type MMSStartCount struct {
	Kind  MMSStartCountKind
	Count int64
}

// decodeMMSStartCount reads the StartCount CHOICE that fills b.
func decodeMMSStartCount(b []byte) (MMSStartCount, error) {
	var c MMSStartCount
	t, err := osiBERSingle(b)
	if err != nil {
		return c, err
	}
	if t.Class != osiBERContext || t.Form != osiBERPrimitive || t.Tag > uint32(MMSStartStepCount) {
		return c, errMMSField
	}

	c.Kind = MMSStartCountKind(t.Tag)
	if c.Kind == MMSStartNoLimit {
		return c, mmsNull(t.Value)
	}
	c.Count, err = osiBERInt(t.Value)
	return c, err
}

// MMSControlState is the Control-State of a program invocation.
type MMSControlState int64

// Control states.
const (
	MMSControlNormal      MMSControlState = 0
	MMSControlControlling MMSControlState = 1
	MMSControlControlled  MMSControlState = 2
)

// String returns the ASN.1 name of the state.
func (s MMSControlState) String() string {
	return mmsEnumName([]string{"normal", "controlling", "controlled"}, int64(s))
}

// MMSCSStatus is the CS-Status-Response detail of a status response.
// ExtendedStatus and ExtendedStatusMask hold four bits, most significant
// first: safetyInterlocksViolated, anyPhysicalResourcePowerOn,
// allPhysicalResourcesCalibrated, localControl.
type MMSCSStatus struct {
	// OperationState is 0 idle, 1 loaded, 2 ready, 3 executing, 4
	// motion-paused, 5 manualInterventionRequired.
	OperationState     int64
	ExtendedStatus     uint8
	ExtendedStatusMask uint8
	SelectedProgram    string
	HasSelectedProgram bool
}

// MMSCSProgram is the CS-GetProgramInvocationAttributes-Response detail.
// A controlling program invocation lists Controlled, ProgramLocation and
// RunningMode; a controlled one names ControllingProgram, if any.
type MMSCSProgram struct {
	ErrorCode          int64
	Control            MMSControlState
	Controlled         []string
	ProgramLocation    string
	RunningMode        MMSStartCount
	ControllingProgram string
}

// MMSCSCondition is the CS-GetEventConditionAttributes-Response detail;
// its displayEnhancement is MMSServiceExt.Enhancement.
type MMSCSCondition struct {
	PriorityOverride    uint8
	HasPriorityOverride bool
	OverrideUndefined   bool
	Lists               []MMSObjectName
}

// MMSServiceExt is the service-ext [79] detail that follows the service
// of a confirmed or unconfirmed PDU. Other is set for otherRequests NULL.
// Otherwise Service is the tag of the detail, which is the service it
// extends (2, eventNotification, in an unconfirmed PDU), and Raw its
// value:
//
//	ControlState                  createProgramInvocation request
//	Controlling, StartLocation,
//	StartCount, ContinueMode      start and resume requests
//	Enhancement                   event condition and enrollment requests,
//	                              eventNotification
//	Status                        status response
//	Program                       getProgramInvocationAttributes response
//	Condition, Enhancement        getEventConditionAttributes response
type MMSServiceExt struct {
	Other   bool
	Service MMSConfirmedService
	Raw     []byte

	ControlState  MMSControlState
	Controlling   bool
	StartLocation string
	StartCount    MMSStartCount
	ContinueMode  bool
	Enhancement   MMSEnhancement
	Status        *MMSCSStatus
	Program       *MMSCSProgram
	Condition     *MMSCSCondition
}

// mmsExtKind tells which Detail CHOICE a service-ext holds.
type mmsExtKind uint8

const (
	mmsExtRequest mmsExtKind = iota
	mmsExtResponse
	mmsExtUnconfirmed
)

// Service-ext detail tags.
const (
	mmsTagCSStart       uint32 = 0
	mmsTagCSCount       uint32 = 1
	mmsTagCSContinue    uint32 = 0
	mmsTagCSNoEnhance   uint32 = 2
	mmsTagCSOperation   uint32 = 0
	mmsTagCSExtended    uint32 = 1
	mmsTagCSMask        uint32 = 2
	mmsTagCSSelected    uint32 = 3
	mmsTagCSErrorCode   uint32 = 0
	mmsTagCSControl     uint32 = 1
	mmsTagCSControlling uint32 = 0
	mmsTagCSControlled  uint32 = 1
	mmsTagCSNormal      uint32 = 2
	mmsTagCSPIs         uint32 = 0
	mmsTagCSLocation    uint32 = 1
	mmsTagCSRunning     uint32 = 2
	mmsTagCSByProgram   uint32 = 0
	mmsTagCSOverride    uint32 = 0
	mmsTagCSLists       uint32 = 1
	mmsTagCSDisplay     uint32 = 2
	mmsTagCSPriority    uint32 = 0
	mmsTagCSUndefined   uint32 = 1

	mmsCSStatusBits    = 4
	mmsCSStatusMaskAll = 0xf0
	mmsDefaultCycles   = 1
)

// decodeServiceExt decodes the optional service-ext that follows a
// service; anything else there is ignored.
func (m *MMS) decodeServiceExt(b []byte) {
	if len(b) == 0 {
		return
	}
	t, _, err := osiBERNext(b)
	if err != nil || !t.is(osiBERContext, osiBERConstructed, mmsTagServiceExt) {
		return
	}
	m.setServiceExt(t)
}

// setServiceExt decodes the service-ext element t.
func (m *MMS) setServiceExt(t osiBERTLV) {
	kind := mmsExtRequest
	switch m.Type {
	case MMSConfirmedResponse:
		kind = mmsExtResponse
	case MMSUnconfirmed:
		kind = mmsExtUnconfirmed
	}

	if t.Form != osiBERConstructed {
		m.softErr(errMMSField)
		return
	}
	var err error
	m.ServiceExt, err = decodeMMSServiceExt(t.Value, kind)
	m.softErr(err)
}

// decodeMMSServiceExt reads the Request-, Response- or Unconfirmed-Detail
// CHOICE that fills b. A detail it cannot decode keeps Service and Raw.
func decodeMMSServiceExt(b []byte, kind mmsExtKind) (*MMSServiceExt, error) {
	t, err := osiBERSingle(b)
	if err != nil {
		return nil, err
	}

	x := &MMSServiceExt{Raw: t.Value, StartCount: MMSStartCount{Kind: MMSStartCycleCount, Count: mmsDefaultCycles}}
	if t.is(osiBERUniversal, osiBERPrimitive, osiBERTagNull) {
		x.Other = true
		return x, mmsNull(t.Value)
	}
	if t.Class != osiBERContext || t.Tag > mmsMaxServiceTag {
		return nil, errMMSField
	}
	x.Service = MMSConfirmedService(t.Tag)

	switch kind {
	case mmsExtRequest:
		err = x.decodeRequest(t)
	case mmsExtResponse:
		err = x.decodeResponse(t)
	case mmsExtUnconfirmed:
		if MMSUnconfirmedService(t.Tag) == MMSUnconfirmedEvent && t.Form == osiBERConstructed {
			x.Enhancement, err = decodeMMSEnhancement(t.Value)
		}
	}
	return x, err
}

// decodeRequest reads a Request-Detail alternative.
func (x *MMSServiceExt) decodeRequest(t osiBERTLV) error {
	var err error
	switch x.Service {
	case MMSCreateProgramInvocation:
		var n int64
		n, err = osiBERInt(t.Value)
		x.ControlState = MMSControlState(n)
	case MMSStart, MMSResume:
		err = x.decodeStart(t)
	case MMSDefineEventCondition, MMSDefineEventEnrollment:
		x.Enhancement, err = decodeMMSEnhancement(t.Value)
	case MMSAlterEventConditionMonitoring, MMSAlterEventEnrollment:
		err = x.decodeChange(t.Value)
	}
	return err
}

// decodeStart reads CS-Start-Request or CS-Resume-Request: normal NULL,
// or controlling SEQUENCE { [0] startLocation, [1] startCount } for
// start and SEQUENCE { continueMode [0] NULL | changeMode [1] StartCount }
// for resume.
func (x *MMSServiceExt) decodeStart(t osiBERTLV) error {
	c, err := osiBERSingle(t.Value)
	if err != nil {
		return err
	}
	if c.is(osiBERUniversal, osiBERPrimitive, osiBERTagNull) {
		return mmsNull(c.Value)
	}
	if !c.is(osiBERUniversal, osiBERConstructed, osiBERTagSequence) {
		return errMMSField
	}

	x.Controlling = true
	return mmsFields(c.Value, func(f osiBERTLV) error {
		var err error
		switch {
		case x.Service == MMSStart && f.is(osiBERContext, osiBERPrimitive, mmsTagCSStart):
			x.StartLocation = string(f.Value)
		case x.Service == MMSResume && f.is(osiBERContext, osiBERPrimitive, mmsTagCSContinue):
			x.ContinueMode = true
			err = mmsNull(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagCSCount):
			x.StartCount, err = decodeMMSStartCount(f.Value)
		}
		return err
	})
}

// decodeChange reads SEQUENCE { changeDisplay CHOICE { string [0], index
// [1], noEnhancement [2] EXPLICIT NULL } OPTIONAL }.
func (x *MMSServiceExt) decodeChange(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}
	if t.is(osiBERContext, osiBERConstructed, mmsTagCSNoEnhance) {
		return nil
	}

	x.Enhancement, err = decodeMMSEnhancement(b)
	return err
}

// decodeResponse reads a Response-Detail alternative.
func (x *MMSServiceExt) decodeResponse(t osiBERTLV) error {
	if t.Form != osiBERConstructed {
		return errMMSField
	}

	var err error
	switch x.Service {
	case MMSStatus:
		x.Status, err = decodeMMSCSStatus(t.Value)
	case MMSGetProgramInvocationAttributes:
		x.Program, err = decodeMMSCSProgram(t.Value)
	case MMSGetEventConditionAttributes:
		x.Condition, err = x.decodeCondition(t.Value)
	}
	return err
}

// decodeMMSCSStatus reads CS-Status-Response: fullResponse SEQUENCE or
// noExtraResponse NULL (nil).
func decodeMMSCSStatus(b []byte) (*MMSCSStatus, error) {
	t, err := osiBERSingle(b)
	if err != nil {
		return nil, err
	}
	if t.is(osiBERUniversal, osiBERPrimitive, osiBERTagNull) {
		return nil, mmsNull(t.Value)
	}
	if !t.is(osiBERUniversal, osiBERConstructed, osiBERTagSequence) {
		return nil, errMMSField
	}

	s := &MMSCSStatus{ExtendedStatusMask: mmsCSStatusMaskAll >> mmsCSStatusBits}
	err = mmsFields(t.Value, func(f osiBERTLV) error {
		if f.Class != osiBERContext || f.Form != osiBERPrimitive {
			return nil
		}

		var err error
		switch f.Tag {
		case mmsTagCSOperation:
			s.OperationState, err = osiBERInt(f.Value)
		case mmsTagCSExtended:
			s.ExtendedStatus, err = mmsCSStatusBitsOf(f.Value)
		case mmsTagCSMask:
			s.ExtendedStatusMask, err = mmsCSStatusBitsOf(f.Value)
		case mmsTagCSSelected:
			s.SelectedProgram, s.HasSelectedProgram = string(f.Value), true
		}
		return err
	})
	return mmsResult(s, err)
}

// mmsCSStatusBitsOf returns the four ExtendedStatus bits, e.g. 04 a0 =
// 0b1010.
func mmsCSStatusBitsOf(v []byte) (uint8, error) {
	bits, _, err := osiBERBits(v)
	if err != nil || len(bits) == 0 {
		return 0, err
	}
	return bits[0] >> mmsCSStatusBits, nil
}

// decodeMMSCSProgram reads CS-GetProgramInvocationAttributes-Response:
// [0] errorCode, [1] control CHOICE.
func decodeMMSCSProgram(b []byte) (*MMSCSProgram, error) {
	p := &MMSCSProgram{}
	err := mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagCSErrorCode):
			p.ErrorCode, err = osiBERInt(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagCSControl):
			err = p.decodeControl(f.Value)
		}
		return err
	})
	return mmsResult(p, err)
}

// decodeControl reads control: controlling [0] SEQUENCE, controlled [1]
// CHOICE { controllingPI [0], none [1] } or normal [2] NULL.
func (p *MMSCSProgram) decodeControl(b []byte) error {
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}

	switch {
	case t.is(osiBERContext, osiBERConstructed, mmsTagCSControlling):
		p.Control = MMSControlControlling
		return mmsFields(t.Value, p.decodeControlling)
	case t.is(osiBERContext, osiBERConstructed, mmsTagCSControlled):
		p.Control = MMSControlControlled
		c, err := osiBERSingle(t.Value)
		if err == nil && c.is(osiBERContext, osiBERPrimitive, mmsTagCSByProgram) {
			p.ControllingProgram = string(c.Value)
		}
		return err
	case t.is(osiBERContext, osiBERPrimitive, mmsTagCSNormal):
		return mmsNull(t.Value)
	}
	return errMMSField
}

// decodeControlling stores one field of the controlling alternative.
func (p *MMSCSProgram) decodeControlling(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERConstructed, mmsTagCSPIs):
		p.Controlled, err = decodeMMSStrings(f.Value, osiBERTagVisible)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagCSLocation):
		p.ProgramLocation = string(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagCSRunning):
		p.RunningMode, err = decodeMMSStartCount(f.Value)
	}
	return err
}

// decodeCondition reads CS-GetEventConditionAttributes-Response: [0]
// groupPriorityOverride CHOICE { priority [0], undefined [1] }, [1]
// listOfReferencingECL, [2] displayEnhancement.
func (x *MMSServiceExt) decodeCondition(b []byte) (*MMSCSCondition, error) {
	c := &MMSCSCondition{}
	err := mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagCSOverride):
			err = c.decodeOverride(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagCSLists):
			c.Lists, err = decodeMMSObjectNames(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagCSDisplay):
			x.Enhancement, err = decodeMMSEnhancement(f.Value)
		}
		return err
	})
	return mmsResult(c, err)
}

// decodeOverride reads groupPriorityOverride.
func (c *MMSCSCondition) decodeOverride(b []byte) error {
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}

	switch {
	case t.is(osiBERContext, osiBERPrimitive, mmsTagCSPriority):
		c.PriorityOverride, err = mmsUint8(t.Value)
		c.HasPriorityOverride = true
	case t.is(osiBERContext, osiBERPrimitive, mmsTagCSUndefined):
		c.OverrideUndefined = true
		err = mmsNull(t.Value)
	default:
		err = errMMSField
	}
	return err
}

// MMSAdditionalKind is the AdditionalService-Request/Response CHOICE tag.
type MMSAdditionalKind uint8

// Additional services. UC is a unit control, ECL an event condition
// list.
const (
	MMSAddVMDStop            MMSAdditionalKind = 0
	MMSAddVMDReset           MMSAdditionalKind = 1
	MMSAddSelect             MMSAdditionalKind = 2
	MMSAddAlterPI            MMSAdditionalKind = 3
	MMSAddInitiateUCLoad     MMSAdditionalKind = 4
	MMSAddUCLoad             MMSAdditionalKind = 5
	MMSAddUCUpload           MMSAdditionalKind = 6
	MMSAddStartUC            MMSAdditionalKind = 7
	MMSAddStopUC             MMSAdditionalKind = 8
	MMSAddCreateUC           MMSAdditionalKind = 9
	MMSAddAddToUC            MMSAdditionalKind = 10
	MMSAddRemoveFromUC       MMSAdditionalKind = 11
	MMSAddGetUCAttributes    MMSAdditionalKind = 12
	MMSAddLoadUCFromFile     MMSAdditionalKind = 13
	MMSAddStoreUCToFile      MMSAdditionalKind = 14
	MMSAddDeleteUC           MMSAdditionalKind = 15
	MMSAddDefineECL          MMSAdditionalKind = 16
	MMSAddDeleteECL          MMSAdditionalKind = 17
	MMSAddAddECLReference    MMSAdditionalKind = 18
	MMSAddRemoveECLReference MMSAdditionalKind = 19
	MMSAddGetECLAttributes   MMSAdditionalKind = 20
	MMSAddReportECLStatus    MMSAdditionalKind = 21
	MMSAddAlterECLMonitoring MMSAdditionalKind = 22
)

var mmsAdditionalNames = []string{
	"vMDStop", "vMDReset", "select", "alterPI", "initiateUCLoad", "uCLoad",
	"uCUpload", "startUC", "stopUC", "createUC", "addToUC", "removeFromUC",
	"getUCAttributes", "loadUCFromFile", "storeUCToFile", "deleteUC",
	"defineECL", "deleteECL", "addECLReference", "removeECLReference",
	"getECLAttributes", "reportECLStatus", "alterECLMonitoring",
}

// String returns the ASN.1 name of the service.
func (k MMSAdditionalKind) String() string { return mmsEnumName(mmsAdditionalNames, int64(k)) }

// MMSLoadDataKind is the LoadData CHOICE alternative.
type MMSLoadDataKind uint8

// LoadData alternatives.
const (
	MMSLoadNonCoded MMSLoadDataKind = iota
	MMSLoadCoded
	MMSLoadEmbedded
)

// String returns the ASN.1 name of the alternative.
func (k MMSLoadDataKind) String() string {
	return mmsEnumName([]string{"non-coded", "coded", "embedded"}, int64(k))
}

// MMSLoadData is the content of a domain: non-coded octets, a coded
// EXTERNAL (also decoded in External) or an EMBEDDED PDV. Data is the
// value of the element.
type MMSLoadData struct {
	Kind     MMSLoadDataKind
	Data     []byte
	External *ISOPresentationPDV
}

// Universal tag of EMBEDDED PDV and context tag of non-coded data.
const (
	mmsTagEmbeddedPDV uint32 = 11
	mmsTagNonCoded    uint32 = 0
)

// decodeMMSLoadData decodes t when it is a LoadData element; ok tells
// whether it was.
func decodeMMSLoadData(t osiBERTLV) (MMSLoadData, bool, error) {
	l := MMSLoadData{Data: t.Value}
	switch {
	case t.is(osiBERContext, osiBERPrimitive, mmsTagNonCoded):
	case t.is(osiBERUniversal, osiBERConstructed, osiBERTagExternal):
		l.Kind = MMSLoadCoded
		ext, err := decodeISOPresPDV(t.Value)
		if err != nil {
			return l, true, err
		}
		l.External = &ext
	case t.is(osiBERUniversal, osiBERConstructed, mmsTagEmbeddedPDV):
		l.Kind = MMSLoadEmbedded
	default:
		return l, false, nil
	}
	return l, true, nil
}

// MMSControlElementKind is the ControlElement CHOICE tag.
type MMSControlElementKind uint8

// Control element alternatives.
const (
	MMSElementBeginDomain    MMSControlElementKind = 0
	MMSElementContinueDomain MMSControlElementKind = 1
	MMSElementEndDomain      MMSControlElementKind = 2
	MMSElementProgram        MMSControlElementKind = 3
)

// String returns the ASN.1 name of the alternative.
func (k MMSControlElementKind) String() string {
	return mmsEnumName([]string{"beginDomainDef", "continueDomainDef", "endDomainDef", "piDefinition"}, int64(k))
}

// MMSControlElement is one piece of a unit control being loaded or
// uploaded: the start, continuation or end of a domain, or a program
// invocation. Name is the domain or program invocation name.
type MMSControlElement struct {
	Kind         MMSControlElementKind
	Name         string
	Capabilities []string
	Sharable     bool
	Load         *MMSLoadData

	Domains    []string
	Reusable   bool
	Monitor    bool
	HasMonitor bool
	State      MMSProgramState
	HasState   bool
}

// MMSUnitPositionKind tells what a unit control upload continues with.
type MMSUnitPositionKind uint8

// Upload positions: the tags of the continueAfter and nextElement
// CHOICE.
const (
	MMSUnitDomain  MMSUnitPositionKind = 1
	MMSUnitULSM    MMSUnitPositionKind = 2
	MMSUnitProgram MMSUnitPositionKind = 3
)

// String returns the ASN.1 name of the alternative.
func (k MMSUnitPositionKind) String() string {
	return mmsEnumName([]string{"", "domain", "ulsmID", "programInvocation"}, int64(k))
}

// MMSUnitPosition is where a unit control upload continues: a domain or
// program invocation Name, or an upload state machine ULSMID.
type MMSUnitPosition struct {
	Kind   MMSUnitPositionKind
	Name   string
	ULSMID int64
}

// MMSListedCondition is the status of one event condition of an event
// condition list.
type MMSListedCondition struct {
	Name   MMSObjectName
	Status MMSEventConditionStatus
}

// MMSAdditional is an additionalService request or response. Kind
// selects the service and Data keeps the raw value of its element:
//
//	ExtendedDerivation          vMDReset request
//	Status                      vMDReset response
//	Name                        the unit control of the UC services, the
//	                            program invocation of alterPI, the
//	                            controlling one of select
//	Programs                    select (controlled), create/addTo/
//	                            removeFromUC, getUCAttributes response
//	Domains                     create/addTo/removeFromUC, getUCAttributes
//	                            response
//	StartCount                  alterPI
//	Position                    uCUpload: continueAfter or nextElement
//	ExecutionArgument,
//	ExecutionExternal           startUC
//	FileName, ThirdParty        loadUCFromFile, storeUCToFile
//	Elements, MoreFollows       uCLoad and uCUpload responses
//	ListName                    the event condition list of the ECL
//	                            services
//	Conditions, Lists           defineECL, add/removeECLReference,
//	                            getECLAttributes response
//	ContinueAfter               reportECLStatus request
//	ConditionStatus,
//	MoreFollows                 reportECLStatus response
//	Enabled, Priority,
//	HasPriority, PriorityReset  alterECLMonitoring
type MMSAdditional struct {
	Kind MMSAdditionalKind
	Data []byte

	ExtendedDerivation bool
	Status             *MMSVMDStatus
	Name               string
	Programs           []string
	Domains            []string
	StartCount         MMSStartCount
	Position           *MMSUnitPosition
	ExecutionArgument  string
	ExecutionExternal  *ISOPresentationPDV
	FileName           []string
	ThirdParty         *MMSApplicationReference
	Elements           []MMSControlElement
	MoreFollows        bool

	ListName        MMSObjectName
	Conditions      []MMSObjectName
	Lists           []MMSObjectName
	ContinueAfter   string
	ConditionStatus []MMSListedCondition
	Enabled         bool
	Priority        int64
	HasPriority     bool
	PriorityReset   bool
}

// Additional service field tags.
const (
	mmsTagAddName       uint32 = 0
	mmsTagAddSelected   uint32 = 1
	mmsTagAddCount      uint32 = 1
	mmsTagAddArgument   uint32 = 1
	mmsTagAddDomains    uint32 = 1
	mmsTagAddPrograms   uint32 = 2
	mmsTagAddFile       uint32 = 1
	mmsTagAddThird      uint32 = 2
	mmsTagAddElements   uint32 = 0
	mmsTagAddMore       uint32 = 1
	mmsTagAddRespDoms   uint32 = 0
	mmsTagAddRespPIs    uint32 = 1
	mmsTagECLName       uint32 = 0
	mmsTagECLConditions uint32 = 1
	mmsTagECLLists      uint32 = 2
	mmsTagECLContinue   uint32 = 1
	mmsTagECLEnabled    uint32 = 1
	mmsTagECLPriority   uint32 = 2
	mmsTagECLStatus     uint32 = 1
	mmsTagECLMore       uint32 = 2
	mmsTagECLValue      uint32 = 0
	mmsTagECLReset      uint32 = 1
	mmsTagCEName        uint32 = 1
	mmsTagCECaps        uint32 = 2
	mmsTagCESharable    uint32 = 3
	mmsTagCELoad        uint32 = 4
	mmsTagCEContLoad    uint32 = 3
	mmsTagCEPIState     uint32 = 4
	mmsListedStatusBase uint32 = 1
)

// decodeMMSAdditional reads the EXPLICIT AdditionalService CHOICE of a
// request or response. An alternative it cannot decode keeps Kind and
// Data.
func decodeMMSAdditional(t osiBERTLV, pdu MMSPDUType) (*MMSAdditional, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}
	c, err := osiBERSingle(b)
	if err != nil {
		return nil, err
	}
	if c.Class != osiBERContext || c.Tag > uint32(MMSAddAlterECLMonitoring) {
		return nil, errMMSField
	}

	a := &MMSAdditional{
		Kind:       MMSAdditionalKind(c.Tag),
		Data:       c.Value,
		StartCount: MMSStartCount{Kind: MMSStartCycleCount, Count: mmsDefaultCycles},
	}
	if pdu == MMSConfirmedRequest {
		return a, a.decodeRequest(c)
	}
	return a, a.decodeResponse(c)
}

// decodeRequest decodes the request of service a.Kind.
func (a *MMSAdditional) decodeRequest(c osiBERTLV) error {
	var err error
	switch a.Kind {
	case MMSAddVMDStop:
		return mmsNull(c.Value)
	case MMSAddVMDReset:
		a.ExtendedDerivation, err = osiBERBool(c.Value)
		return err
	case MMSAddInitiateUCLoad, MMSAddUCLoad, MMSAddStopUC, MMSAddGetUCAttributes, MMSAddDeleteUC:
		// A bare unit control name.
		if c.Form != osiBERPrimitive {
			return errMMSField
		}
		a.Name = string(c.Value)
		return nil
	case MMSAddDeleteECL, MMSAddGetECLAttributes:
		// A bare event condition list name.
		a.ListName, err = decodeMMSObjectNameIn(c.Value)
		return err
	}

	if c.Form != osiBERConstructed {
		return errMMSField
	}
	if a.Kind >= MMSAddDefineECL {
		return mmsFields(mmsUnwrapSeq(c.Value), a.decodeListField)
	}
	return mmsFields(c.Value, a.decodeUnitField)
}

// mmsUnwrapSeq returns the body of the SEQUENCE that fills b, or b: an
// EXPLICIT tag keeps the SEQUENCE header an IMPLICIT one drops.
func mmsUnwrapSeq(b []byte) []byte {
	t, err := osiBERSingle(b)
	if err != nil || !t.is(osiBERUniversal, osiBERConstructed, osiBERTagSequence) {
		return b
	}
	return t.Value
}

// decodeUnitField stores one field of the select, alterPI and unit
// control requests that are a SEQUENCE.
func (a *MMSAdditional) decodeUnitField(f osiBERTLV) error {
	// startUC may carry its argument as an untagged EXTERNAL.
	if a.Kind == MMSAddStartUC && f.is(osiBERUniversal, osiBERConstructed, osiBERTagExternal) {
		ext, err := decodeISOPresPDV(f.Value)
		a.ExecutionExternal = &ext
		return err
	}
	if f.Class != osiBERContext {
		return nil
	}
	if f.Tag == mmsTagAddName {
		a.Name = string(f.Value)
		return nil
	}

	var err error
	switch a.Kind {
	case MMSAddSelect:
		if f.is(osiBERContext, osiBERConstructed, mmsTagAddSelected) {
			a.Programs, err = decodeMMSStrings(f.Value, osiBERTagVisible)
		}
	case MMSAddAlterPI:
		if f.is(osiBERContext, osiBERConstructed, mmsTagAddCount) {
			a.StartCount, err = decodeMMSStartCount(f.Value)
		}
	case MMSAddUCUpload:
		a.Position, err = decodeMMSUnitPos(f)
	case MMSAddStartUC:
		if f.is(osiBERContext, osiBERPrimitive, mmsTagAddArgument) {
			a.ExecutionArgument = string(f.Value)
		}
	case MMSAddCreateUC, MMSAddAddToUC, MMSAddRemoveFromUC:
		err = a.decodeMembers(f, mmsTagAddDomains, mmsTagAddPrograms)
	case MMSAddLoadUCFromFile, MMSAddStoreUCToFile:
		err = a.decodeFile(f)
	}
	return err
}

// decodeMembers stores the domain and program invocation lists found
// under the tags doms and pis.
func (a *MMSAdditional) decodeMembers(f osiBERTLV, doms, pis uint32) error {
	if f.Class != osiBERContext || f.Form != osiBERConstructed {
		return nil
	}

	var err error
	switch f.Tag {
	case doms:
		a.Domains, err = decodeMMSStrings(f.Value, osiBERTagVisible)
	case pis:
		a.Programs, err = decodeMMSStrings(f.Value, osiBERTagVisible)
	}
	return err
}

// decodeFile stores [1] fileName or [2] thirdParty.
func (a *MMSAdditional) decodeFile(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERConstructed, mmsTagAddFile):
		a.FileName, err = decodeMMSFileName(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagAddThird):
		a.ThirdParty, _ = decodeMMSAppRef(f.Value)
	}
	return err
}

// decodeMMSUnitPos reads domain [1], ulsmID [2] or programInvocation [3].
func decodeMMSUnitPos(f osiBERTLV) (*MMSUnitPosition, error) {
	if f.Class != osiBERContext || f.Form != osiBERPrimitive || f.Tag < uint32(MMSUnitDomain) || f.Tag > uint32(MMSUnitProgram) {
		return nil, errMMSField
	}

	p := &MMSUnitPosition{Kind: MMSUnitPositionKind(f.Tag)}
	if p.Kind != MMSUnitULSM {
		p.Name = string(f.Value)
		return p, nil
	}

	var err error
	p.ULSMID, err = osiBERInt(f.Value)
	return mmsResult(p, err)
}

// decodeListField stores one field of the event condition list requests
// that are a SEQUENCE.
func (a *MMSAdditional) decodeListField(f osiBERTLV) error {
	if f.is(osiBERContext, osiBERConstructed, mmsTagECLName) {
		var err error
		a.ListName, err = decodeMMSObjectNameIn(f.Value)
		return err
	}

	var err error
	switch a.Kind {
	case MMSAddDefineECL, MMSAddAddECLReference, MMSAddRemoveECLReference:
		err = a.decodeRefs(f)
	case MMSAddReportECLStatus:
		if f.is(osiBERContext, osiBERPrimitive, mmsTagECLContinue) {
			a.ContinueAfter = string(f.Value)
		}
	case MMSAddAlterECLMonitoring:
		err = a.decodeMonitoring(f)
	}
	return err
}

// decodeRefs stores [1] listOfEventConditionName or [2]
// listOfEventConditionListName.
func (a *MMSAdditional) decodeRefs(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERConstructed, mmsTagECLConditions):
		a.Conditions, err = decodeMMSObjectNames(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagECLLists):
		a.Lists, err = decodeMMSObjectNames(f.Value)
	}
	return err
}

// decodeMonitoring stores [1] enabled or [2] priorityChange CHOICE
// { priorityValue [0] INTEGER, priorityReset [1] NULL }.
func (a *MMSAdditional) decodeMonitoring(f osiBERTLV) error {
	if f.is(osiBERContext, osiBERPrimitive, mmsTagECLEnabled) {
		var err error
		a.Enabled, err = osiBERBool(f.Value)
		return err
	}
	if !f.is(osiBERContext, osiBERConstructed, mmsTagECLPriority) {
		return nil
	}

	c, err := osiBERSingle(f.Value)
	if err != nil {
		return err
	}
	switch {
	case c.is(osiBERContext, osiBERPrimitive, mmsTagECLValue):
		a.Priority, err = osiBERInt(c.Value)
		a.HasPriority = true
	case c.is(osiBERContext, osiBERPrimitive, mmsTagECLReset):
		a.PriorityReset = true
		err = mmsNull(c.Value)
	default:
		err = errMMSField
	}
	return err
}

// decodeResponse decodes the response of service a.Kind. The services
// not listed answer NULL.
func (a *MMSAdditional) decodeResponse(c osiBERTLV) error {
	var err error
	switch a.Kind {
	case MMSAddVMDReset:
		a.Status, err = decodeMMSStatus(c)
	case MMSAddUCLoad, MMSAddUCUpload:
		a.MoreFollows = a.Kind == MMSAddUCLoad
		err = mmsConstructed(c, a.decodeElementsField)
	case MMSAddGetUCAttributes:
		err = mmsConstructed(c, func(f osiBERTLV) error {
			return a.decodeMembers(f, mmsTagAddRespDoms, mmsTagAddRespPIs)
		})
	case MMSAddGetECLAttributes:
		err = mmsConstructed(c, a.decodeRefs)
	case MMSAddReportECLStatus:
		a.MoreFollows = true
		err = mmsConstructed(c, a.decodeStatusField)
	default:
		err = mmsNull(c.Value)
	}
	return err
}

// mmsConstructed calls f for each field of the constructed element c.
func mmsConstructed(c osiBERTLV, f func(osiBERTLV) error) error {
	if c.Form != osiBERConstructed {
		return errMMSField
	}
	return mmsFields(c.Value, f)
}

// decodeElementsField stores one field of a uCLoad ([0] controlElements,
// [1] moreFollows) or uCUpload ([0] controlElements, nextElement [1..3])
// response.
func (a *MMSAdditional) decodeElementsField(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERConstructed, mmsTagAddElements):
		a.Elements, err = decodeMMSElements(f.Value)
	case a.Kind == MMSAddUCLoad && f.is(osiBERContext, osiBERPrimitive, mmsTagAddMore):
		a.MoreFollows, err = osiBERBool(f.Value)
	case a.Kind == MMSAddUCUpload:
		a.Position, err = decodeMMSUnitPos(f)
	}
	return err
}

// decodeStatusField stores one field of a reportECLStatus response: [1]
// listOfEventConditionStatus, [2] moreFollows.
func (a *MMSAdditional) decodeStatusField(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERConstructed, mmsTagECLStatus):
		a.ConditionStatus, err = decodeMMSListedConds(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagECLMore):
		a.MoreFollows, err = osiBERBool(f.Value)
	}
	return err
}

// decodeMMSListedConds decodes SEQUENCE OF EventConditionStatus: [0]
// eventConditionName, then the fields of a reportEventConditionStatus
// response with their tags shifted by one.
func decodeMMSListedConds(b []byte) ([]MMSListedCondition, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSListedCondition, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		name, fields, err := osiBERExpect(item, osiBERContext, osiBERConstructed, mmsTagECLName)
		if err != nil {
			return nil, err
		}
		var c MMSListedCondition
		if c.Name, err = decodeMMSObjectNameIn(name); err != nil {
			return nil, err
		}

		err = mmsFields(fields, func(f osiBERTLV) error {
			return c.Status.decodeField(f, mmsListedStatusBase)
		})
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// decodeMMSElements decodes a SEQUENCE OF ControlElement body.
func decodeMMSElements(b []byte) ([]MMSControlElement, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSControlElement, 0, count)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		if t.Class != osiBERContext || t.Tag > uint32(MMSElementProgram) {
			return nil, errMMSField
		}
		e := MMSControlElement{Kind: MMSControlElementKind(t.Tag), Reusable: true}
		if err := e.decode(t); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// decode reads one ControlElement alternative.
func (e *MMSControlElement) decode(t osiBERTLV) error {
	switch e.Kind {
	case MMSElementEndDomain:
		if t.Form != osiBERPrimitive {
			return errMMSField
		}
		e.Name = string(t.Value)
		return nil
	case MMSElementProgram:
		return mmsConstructed(t, e.decodeProgram)
	}

	// beginDomainDef and continueDomainDef are EXPLICIT SEQUENCEs.
	if t.Form != osiBERConstructed {
		return errMMSField
	}
	return mmsFields(mmsUnwrapSeq(t.Value), e.decodeDomain)
}

// decodeDomain stores one field of a domain definition: [1] domainName,
// [2] capabilities, [3] sharable and [4] loadData when it begins, [3]
// loadData when it continues.
func (e *MMSControlElement) decodeDomain(f osiBERTLV) error {
	load := mmsTagCELoad
	if e.Kind == MMSElementContinueDomain {
		load = mmsTagCEContLoad
	}

	var err error
	switch {
	case f.is(osiBERContext, osiBERPrimitive, mmsTagCEName):
		e.Name = string(f.Value)
	case f.is(osiBERContext, osiBERConstructed, load):
		err = e.decodeLoad(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagCECaps):
		e.Capabilities, err = decodeMMSStrings(f.Value, osiBERTagVisible)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagCESharable):
		e.Sharable, err = osiBERBool(f.Value)
	}
	return err
}

// decodeLoad reads the EXPLICIT LoadData of a domain definition.
func (e *MMSControlElement) decodeLoad(b []byte) error {
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}

	l, ok, err := decodeMMSLoadData(t)
	if err != nil {
		return err
	}
	if !ok {
		return errMMSField
	}
	e.Load = &l
	return nil
}

// decodeProgram stores one piDefinition field; its first four tags are
// those of a createProgramInvocation request.
func (e *MMSControlElement) decodeProgram(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERPrimitive, mmsTagPIName):
		e.Name = string(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagPIDomains):
		e.Domains, err = decodeMMSStrings(f.Value, osiBERTagVisible)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagPIReusable):
		e.Reusable, err = osiBERBool(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagPIMonitor):
		e.Monitor, err = osiBERBool(f.Value)
		e.HasMonitor = true
	case f.is(osiBERContext, osiBERPrimitive, mmsTagCEPIState):
		var n int64
		n, err = osiBERInt(f.Value)
		e.State, e.HasState = MMSProgramState(n), true
	}
	return err
}

// MMSAccessConditionKind is the AccessCondition CHOICE tag.
type MMSAccessConditionKind uint8

// Access condition alternatives.
const (
	MMSAccessNever     MMSAccessConditionKind = 0
	MMSAccessSemaphore MMSAccessConditionKind = 1
	MMSAccessUser      MMSAccessConditionKind = 2
	MMSAccessPassword  MMSAccessConditionKind = 3
	MMSAccessJoint     MMSAccessConditionKind = 4
	MMSAccessAlternate MMSAccessConditionKind = 5
)

// String returns the ASN.1 name of the alternative.
func (k MMSAccessConditionKind) String() string {
	return mmsEnumName([]string{"never", "semaphore", "user", "password", "joint", "alternate"}, int64(k))
}

// MMSAccessCondition is one AccessCondition: who may do an operation.
// Semaphore names the semaphore to own, User the application allowed (nil
// for any user), Password is the raw Authentication-value, and
// Conditions lists those that must all (joint) or any (alternate) hold.
type MMSAccessCondition struct {
	Kind       MMSAccessConditionKind
	Semaphore  string
	User       *MMSApplicationReference
	Password   []byte
	Conditions []MMSAccessCondition
}

// MMSAccessOperation is the operation an access condition guards: the
// tag of the accessControlListElements field.
type MMSAccessOperation uint8

// Guarded operations.
const (
	MMSAccessRead    MMSAccessOperation = 0
	MMSAccessStore   MMSAccessOperation = 1
	MMSAccessWrite   MMSAccessOperation = 2
	MMSAccessLoad    MMSAccessOperation = 3
	MMSAccessExecute MMSAccessOperation = 4
	MMSAccessDelete  MMSAccessOperation = 5
	MMSAccessEdit    MMSAccessOperation = 6
)

// String returns the name of the operation.
func (o MMSAccessOperation) String() string {
	return mmsEnumName([]string{"read", "store", "write", "load", "execute", "delete", "edit"}, int64(o))
}

// MMSAccessElement is the condition for one operation.
type MMSAccessElement struct {
	Operation MMSAccessOperation
	Condition MMSAccessCondition
}

// MMSAccessReference counts the objects of one class under an access
// control list.
type MMSAccessReference struct {
	Class MMSObjectClass
	Count int64
}

// MMSAccessControl holds the access control list services of ISO
// 9506-2:2003. Name is the access control list:
//
//	Elements                      defineAccessControlList request,
//	                              getAccessControlListAttributes response
//	VMD, HasObject, ObjectClass,
//	ObjectName                    getAccessControlListAttributes request:
//	                              by list name, for the VMD or for an object
//	VMDUse, References,
//	AccessControlList             getAccessControlListAttributes response
//	ObjectClass, ContinueAfter    reportAccessControlledObjects request
//	Names, MoreFollows            reportAccessControlledObjects response
//	VMD, ObjectClass, Scope,
//	Names, DomainID               changeAccessControl request
//	Matched, Changed              changeAccessControl response
type MMSAccessControl struct {
	Name     string
	Elements []MMSAccessElement

	VMD         bool
	HasObject   bool
	ObjectClass MMSObjectClass
	ObjectName  MMSObjectName

	VMDUse            bool
	References        []MMSAccessReference
	AccessControlList string

	ContinueAfter    MMSObjectName
	HasContinueAfter bool
	Names            []MMSObjectName
	MoreFollows      bool

	Scope    MMSDeleteScope
	DomainID string
	Matched  uint32
	Changed  uint32
}

// Access control tags.
const (
	mmsTagACName     uint32 = 0
	mmsTagACElements uint32 = 1
	mmsTagACVMD      uint32 = 1
	mmsTagACObject   uint32 = 2
	mmsTagACClass    uint32 = 0
	mmsTagACObjName  uint32 = 1
	mmsTagACVMDUse   uint32 = 2
	mmsTagACRefs     uint32 = 3
	mmsTagACList     uint32 = 4
	mmsTagACRefCount uint32 = 1
	mmsTagACRepClass uint32 = 1
	mmsTagACContinue uint32 = 2
	mmsTagACNames    uint32 = 0
	mmsTagACMore     uint32 = 1
	mmsTagACVMDOnly  uint32 = 0
	mmsTagACObjects  uint32 = 1
	mmsTagACNewList  uint32 = 2
	mmsTagACScope    uint32 = 1
	mmsTagACMatched  uint32 = 0
	mmsTagACChanged  uint32 = 1
)

// decodeMMSAccessCond decodes one AccessCondition CHOICE element.
func decodeMMSAccessCond(t osiBERTLV, depth int) (MMSAccessCondition, error) {
	var c MMSAccessCondition
	if depth > osiBERMaxDepth {
		return c, errOSIBERDepth
	}
	if t.Class != osiBERContext || t.Tag > uint32(MMSAccessAlternate) {
		return c, errMMSField
	}
	c.Kind = MMSAccessConditionKind(t.Tag)

	// Only never is primitive.
	if c.Kind == MMSAccessNever {
		if t.Form != osiBERPrimitive {
			return c, errMMSField
		}
		return c, mmsNull(t.Value)
	}
	if t.Form != osiBERConstructed {
		return c, errMMSField
	}

	var err error
	switch c.Kind {
	case MMSAccessSemaphore:
		var v []byte
		v, _, err = osiBERExpect(t.Value, osiBERUniversal, osiBERPrimitive, osiBERTagVisible)
		c.Semaphore = string(v)
	case MMSAccessUser:
		// association ApplicationReference, or none NULL.
		var u osiBERTLV
		if u, err = osiBERSingle(t.Value); err == nil && u.Form == osiBERConstructed {
			c.User, err = decodeMMSAppRefIn(t.Value)
		}
	case MMSAccessPassword:
		c.Password = t.Value
	case MMSAccessJoint, MMSAccessAlternate:
		c.Conditions, err = decodeMMSAccessConds(t.Value, depth+1)
	}
	return c, err
}

// decodeMMSAccessConds decodes a SEQUENCE OF AccessCondition body.
func decodeMMSAccessConds(b []byte, depth int) ([]MMSAccessCondition, error) {
	if depth > osiBERMaxDepth {
		return nil, errOSIBERDepth
	}

	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSAccessCondition, 0, count)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		c, err := decodeMMSAccessCond(t, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// decodeMMSAccessElems decodes accessControlListElements: up to seven
// EXPLICIT AccessConditions tagged by operation.
func decodeMMSAccessElems(b []byte) ([]MMSAccessElement, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSAccessElement, 0, count)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		if t.Class != osiBERContext || t.Form != osiBERConstructed || t.Tag > uint32(MMSAccessEdit) {
			return nil, errMMSField
		}
		c, err := osiBERSingle(t.Value)
		if err != nil {
			return nil, err
		}

		e := MMSAccessElement{Operation: MMSAccessOperation(t.Tag)}
		if e.Condition, err = decodeMMSAccessCond(c, 0); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// mmsObjectClassIn reads an EXPLICIT ObjectClass; a companion standard
// class is reported as a malformed field.
func mmsObjectClassIn(b []byte) (MMSObjectClass, error) {
	var g MMSGetNameListRequest
	if err := g.decodeClass(b); err != nil {
		return 0, err
	}
	if g.HasCSObjectClass {
		return 0, errMMSField
	}
	return g.ObjectClass, nil
}

// decodeMMSAccessReq decodes the request of an access control list
// service.
func decodeMMSAccessReq(t osiBERTLV, s MMSConfirmedService) (*MMSAccessControl, error) {
	a := &MMSAccessControl{}
	var err error
	switch s {
	case MMSDeleteAccessControlList:
		// A bare Identifier.
		var b []byte
		b, err = mmsBody(t, osiBERPrimitive)
		a.Name = string(b)
	case MMSGetAccessControlListAttributes:
		err = a.decodeTarget(t)
	case MMSDefineAccessControlList:
		err = mmsConstructed(t, a.decodeListField)
	case MMSReportAccessControlledObjects:
		err = mmsConstructed(t, a.decodeReportField)
	case MMSChangeAccessControl:
		err = mmsConstructed(t, a.decodeChangeField)
	}
	return mmsResult(a, err)
}

// decodeTarget reads GetAccessControlListAttributes-Request: an EXPLICIT
// CHOICE { accessControlListName [0], vMD [1] NULL, namedObject [2]
// SEQUENCE { [0] objectClass, [1] objectName } }.
func (a *MMSAccessControl) decodeTarget(t osiBERTLV) error {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return err
	}
	c, err := osiBERSingle(b)
	if err != nil {
		return err
	}

	switch {
	case c.is(osiBERContext, osiBERPrimitive, mmsTagACName):
		a.Name = string(c.Value)
	case c.is(osiBERContext, osiBERPrimitive, mmsTagACVMD):
		a.VMD = true
		err = mmsNull(c.Value)
	case c.is(osiBERContext, osiBERConstructed, mmsTagACObject):
		a.HasObject = true
		err = mmsFields(c.Value, a.decodeObjectField)
	default:
		err = errMMSField
	}
	return err
}

// decodeObjectField stores [0] objectClass or [1] objectName.
func (a *MMSAccessControl) decodeObjectField(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERConstructed, mmsTagACClass):
		a.ObjectClass, err = mmsObjectClassIn(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagACObjName):
		a.ObjectName, err = decodeMMSObjectNameIn(f.Value)
	}
	return err
}

// decodeListField stores one field of a DefineAccessControlList-Request
// or GetAccessControlListAttributes-Response: [0] name, [1] elements, [2]
// vMDuse, [3] references, [4] accessControlList.
func (a *MMSAccessControl) decodeListField(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERPrimitive, mmsTagACName):
		a.Name = string(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagACName):
		// The response tags the name EXPLICIT.
		var v []byte
		v, _, err = osiBERExpect(f.Value, osiBERUniversal, osiBERPrimitive, osiBERTagVisible)
		a.Name = string(v)
	case f.is(osiBERContext, osiBERConstructed, mmsTagACElements):
		a.Elements, err = decodeMMSAccessElems(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagACVMDUse):
		a.VMDUse, err = osiBERBool(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagACRefs):
		a.References, err = decodeMMSAccessRefs(f.Value)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagACList):
		a.AccessControlList = string(f.Value)
	}
	return err
}

// decodeMMSAccessRefs decodes references: SEQUENCE OF SEQUENCE { [0]
// objectClass, [1] objectCount }.
func decodeMMSAccessRefs(b []byte) ([]MMSAccessReference, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSAccessReference, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		var r MMSAccessReference
		err = mmsFields(item, func(f osiBERTLV) error {
			var err error
			switch {
			case f.is(osiBERContext, osiBERConstructed, mmsTagACClass):
				r.Class, err = mmsObjectClassIn(f.Value)
			case f.is(osiBERContext, osiBERPrimitive, mmsTagACRefCount):
				r.Count, err = osiBERInt(f.Value)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// decodeReportField stores one ReportAccessControlledObjects-Request
// field: [0] accessControlList, [1] objectClass, [2] continueAfter.
func (a *MMSAccessControl) decodeReportField(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERPrimitive, mmsTagACName):
		a.Name = string(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagACRepClass):
		a.ObjectClass, err = mmsObjectClassIn(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagACContinue):
		a.ContinueAfter, err = decodeMMSObjectNameIn(f.Value)
		a.HasContinueAfter = true
	}
	return err
}

// decodeChangeField stores one ChangeAccessControl-Request field:
// scopeOfChange vMDOnly [0] NULL or listOfObjects [1] SEQUENCE, then [2]
// accessControlListName.
func (a *MMSAccessControl) decodeChangeField(f osiBERTLV) error {
	var err error
	switch {
	case f.is(osiBERContext, osiBERPrimitive, mmsTagACVMDOnly):
		a.VMD = true
		err = mmsNull(f.Value)
	case f.is(osiBERContext, osiBERConstructed, mmsTagACObjects):
		a.HasObject = true
		err = mmsFields(f.Value, a.decodeScopeField)
	case f.is(osiBERContext, osiBERPrimitive, mmsTagACNewList):
		a.Name = string(f.Value)
	}
	return err
}

// decodeScopeField stores [0] objectClass or [1] objectScope CHOICE
// { specific [0] names, aa-specific [1], domain [2] Identifier, vmd [3] }.
func (a *MMSAccessControl) decodeScopeField(f osiBERTLV) error {
	if f.is(osiBERContext, osiBERConstructed, mmsTagACClass) {
		var err error
		a.ObjectClass, err = mmsObjectClassIn(f.Value)
		return err
	}
	if !f.is(osiBERContext, osiBERConstructed, mmsTagACScope) {
		return nil
	}

	c, err := osiBERSingle(f.Value)
	if err != nil {
		return err
	}
	if c.Class != osiBERContext || c.Tag > uint32(MMSDeleteScopeVMD) {
		return errMMSField
	}

	// The CHOICE tags are the scopeOfDelete values but for domain and
	// aa-specific, which swap places.
	switch c.Tag {
	case mmsTagEDSpecific:
		a.Scope = MMSDeleteScopeSpecific
		a.Names, err = decodeMMSObjectNames(c.Value)
	case mmsTagEDAA:
		a.Scope = MMSDeleteScopeAA
	case mmsTagEDDomain:
		a.Scope = MMSDeleteScopeDomain
		a.DomainID = string(c.Value)
	case mmsTagEDVMD:
		a.Scope = MMSDeleteScopeVMD
	}
	return err
}

// decodeMMSAccessResp decodes the response of an access control list
// service; define and delete answer NULL.
func decodeMMSAccessResp(t osiBERTLV, s MMSConfirmedService) (*MMSAccessControl, error) {
	a := &MMSAccessControl{}
	var err error
	switch s {
	case MMSGetAccessControlListAttributes:
		err = mmsConstructed(t, a.decodeListField)
	case MMSReportAccessControlledObjects:
		err = mmsConstructed(t, func(f osiBERTLV) error {
			var err error
			switch {
			case f.is(osiBERContext, osiBERConstructed, mmsTagACNames):
				a.Names, err = decodeMMSObjectNames(f.Value)
			case f.is(osiBERContext, osiBERPrimitive, mmsTagACMore):
				a.MoreFollows, err = osiBERBool(f.Value)
			}
			return err
		})
	case MMSChangeAccessControl:
		err = mmsConstructed(t, func(f osiBERTLV) error {
			var err error
			switch {
			case f.is(osiBERContext, osiBERPrimitive, mmsTagACMatched):
				a.Matched, err = osiBERUint32(f.Value)
			case f.is(osiBERContext, osiBERPrimitive, mmsTagACChanged):
				a.Changed, err = osiBERUint32(f.Value)
			}
			return err
		})
	default:
		// NULL is primitive and empty.
		if _, err := mmsBody(t, osiBERPrimitive); err != nil {
			return nil, err
		}
		return nil, mmsNull(t.Value)
	}
	return mmsResult(a, err)
}
