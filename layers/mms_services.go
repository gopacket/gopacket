// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"time"
)

// Typed decoding of the MMS services past the core read/write set: VMD
// status, rename, capabilities, domains and upload/download, program
// invocations, files, journals, events and error details.
//
// These decoders are best effort. Before them the services only kept
// their raw ServiceData, so a malformed service element must not make
// the PDU fail: the typed field stays nil and MMS.ServiceDecodeErr tells
// why. Every decoder returns nil with its error.

// mmsResult drops a partly decoded value when err is set.
func mmsResult[T any](v *T, err error) (*T, error) {
	if err != nil {
		return nil, err
	}
	return v, nil
}

// mmsFields calls f for each TLV of a SEQUENCE body.
func mmsFields(b []byte, f func(t osiBERTLV) error) error {
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return err
		}
		b = rest

		if err := f(t); err != nil {
			return err
		}
	}
	return nil
}

// mmsBody returns the value of a service element that must have form f.
func mmsBody(t osiBERTLV, f osiBERForm) ([]byte, error) {
	if t.Form != f {
		return nil, errMMSField
	}
	return t.Value, nil
}

// mmsEnumName names value v from a table indexed by value.
func mmsEnumName(names []string, v int64) string {
	if v >= 0 && v < int64(len(names)) {
		return names[v]
	}
	return fmt.Sprintf("Unknown(%d)", v)
}

// Universal string tag of FileName components.
const mmsTagGraphicString uint32 = 25

// decodeMMSStrings decodes a SEQUENCE OF a primitive string type.
func decodeMMSStrings(b []byte, tag uint32) ([]string, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, count)
	for len(b) > 0 {
		v, rest, err := osiBERExpect(b, osiBERUniversal, osiBERPrimitive, tag)
		if err != nil {
			return nil, err
		}
		b = rest
		out = append(out, string(v))
	}
	return out, nil
}

// decodeMMSFileName decodes a FileName: SEQUENCE OF GraphicString, e.g.
// {"/COMTRADE/", "fault1.cfg"}.
func decodeMMSFileName(b []byte) ([]string, error) {
	return decodeMMSStrings(b, mmsTagGraphicString)
}

// decodeMMSObjectNames decodes a SEQUENCE OF ObjectName body.
func decodeMMSObjectNames(b []byte) ([]MMSObjectName, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSObjectName, 0, count)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		n, err := decodeMMSObjectName(t)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// decodeMMSVarSpec decodes one VariableSpecification CHOICE element. Only
// the name must decode; the other alternatives are best effort and keep
// their raw encoding in Spec.
func decodeMMSVarSpec(spec osiBERTLV) (MMSVariable, error) {
	if spec.Class != osiBERContext || spec.Tag > uint32(MMSVariableInvalidated) {
		return MMSVariable{}, errMMSField
	}

	v := MMSVariable{Kind: MMSVariableKind(spec.Tag), Spec: spec.Value}
	if v.Kind == MMSVariableName {
		var err error
		v.Name, err = decodeMMSObjectNameIn(spec.Value)
		return v, err
	}

	// A malformed address or description leaves only the raw Spec.
	if err := v.decodeSpec(spec); err != nil {
		v.Address, v.Type = MMSAddress{}, nil
	}
	return v, nil
}

// Unsigned values of more than 32 bits are rejected where the ASN.1 type
// is Unsigned32; INTEGER enumerations are kept as int64.

// MMSVariableAttributes is a GetVariableAccessAttributes-Response.
type MMSVariableAttributes struct {
	Deletable  bool
	HasAddress bool
	Address    MMSAddress
	Type       MMSTypeSpec
}

// GetVariableAccessAttributes tags.
const (
	mmsTagGVAAAddress   uint32 = 1
	mmsTagGVAADeletable uint32 = 0
	mmsTagGVAARespAddr  uint32 = 1
	mmsTagGVAAType      uint32 = 2
)

// decodeMMSGVAAAddr reads the address [1] alternative of a
// GetVariableAccessAttributes-Request.
func decodeMMSGVAAAddr(b []byte) (*MMSAddress, error) {
	t, err := osiBERSingle(b)
	if err != nil {
		return nil, err
	}
	if !t.is(osiBERContext, osiBERConstructed, mmsTagGVAAAddress) {
		return nil, errMMSField
	}

	a, err := decodeMMSAddressIn(t.Value)
	return mmsResult(&a, err)
}

// decodeMMSGVAAResp reads GetVariableAccessAttributes-Response:
// [0] mmsDeletable, [1] Address OPTIONAL, [2] TypeSpecification.
func decodeMMSGVAAResp(t osiBERTLV) (*MMSVariableAttributes, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSVariableAttributes{}
	found := false
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagGVAADeletable):
			r.Deletable, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagGVAARespAddr):
			r.Address, err = decodeMMSAddressIn(f.Value)
			r.HasAddress = true
		case f.is(osiBERContext, osiBERConstructed, mmsTagGVAAType):
			r.Type, err = decodeMMSTypeIn(f.Value, 0)
			found = true
		}
		return err
	})
	if err == nil && !found {
		err = errMMSField
	}
	return mmsResult(r, err)
}

// MMSDeleteScope is the scopeOfDelete of a delete request.
type MMSDeleteScope int64

// Delete scopes.
const (
	MMSDeleteScopeSpecific MMSDeleteScope = 0
	MMSDeleteScopeAA       MMSDeleteScope = 1
	MMSDeleteScopeDomain   MMSDeleteScope = 2
	MMSDeleteScopeVMD      MMSDeleteScope = 3
)

var mmsDeleteScopeNames = []string{"specific", "aa-specific", "domain", "vmd"}

// String returns the ASN.1 name of the scope.
func (s MMSDeleteScope) String() string { return mmsEnumName(mmsDeleteScopeNames, int64(s)) }

// MMSDeleteRequest is a DeleteNamedVariableList-Request or a
// DeleteVariableAccess-Request.
type MMSDeleteRequest struct {
	Scope MMSDeleteScope
	Names []MMSObjectName
	// DomainID is set for the domain scope.
	DomainID string
}

// MMSDeleteResponse is a DeleteNamedVariableList-Response or a
// DeleteVariableAccess-Response.
type MMSDeleteResponse struct {
	Matched uint32
	Deleted uint32
}

// Delete request and response tags.
const (
	mmsTagDelScope   uint32 = 0
	mmsTagDelNames   uint32 = 1
	mmsTagDelDomain  uint32 = 2
	mmsTagDelMatched uint32 = 0
	mmsTagDelDeleted uint32 = 1
)

// decodeMMSDeleteReq reads [0] scopeOfDelete DEFAULT specific, [1] list
// of names OPTIONAL, [2] domainName OPTIONAL.
func decodeMMSDeleteReq(t osiBERTLV) (*MMSDeleteRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSDeleteRequest{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDelScope):
			var n int64
			n, err = osiBERInt(f.Value)
			r.Scope = MMSDeleteScope(n)
		case f.is(osiBERContext, osiBERConstructed, mmsTagDelNames):
			r.Names, err = decodeMMSObjectNames(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDelDomain):
			r.DomainID = string(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSDeleteResp reads [0] numberMatched, [1] numberDeleted.
func decodeMMSDeleteResp(t osiBERTLV) (*MMSDeleteResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSDeleteResponse{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDelMatched):
			r.Matched, err = osiBERUint32(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDelDeleted):
			r.Deleted, err = osiBERUint32(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// MMSLogicalStatus is the vmdLogicalStatus of a Status-Response.
type MMSLogicalStatus int64

// VMD logical states.
const (
	MMSStateChangesAllowed   MMSLogicalStatus = 0
	MMSNoStateChangesAllowed MMSLogicalStatus = 1
	MMSLimitedServices       MMSLogicalStatus = 2
	MMSSupportServices       MMSLogicalStatus = 3
)

var mmsLogicalNames = []string{
	"state-changes-allowed", "no-state-changes-allowed",
	"limited-services-allowed", "support-services-allowed",
}

// String returns the ASN.1 name of the state.
func (s MMSLogicalStatus) String() string { return mmsEnumName(mmsLogicalNames, int64(s)) }

// MMSPhysicalStatus is the vmdPhysicalStatus of a Status-Response.
type MMSPhysicalStatus int64

// VMD physical states.
const (
	MMSOperational          MMSPhysicalStatus = 0
	MMSPartiallyOperational MMSPhysicalStatus = 1
	MMSInoperable           MMSPhysicalStatus = 2
	MMSNeedsCommissioning   MMSPhysicalStatus = 3
)

var mmsPhysicalNames = []string{"operational", "partially-operational", "inoperable", "needs-commissioning"}

// String returns the ASN.1 name of the state.
func (s MMSPhysicalStatus) String() string { return mmsEnumName(mmsPhysicalNames, int64(s)) }

// MMSStatusRequest is a Status-Request.
type MMSStatusRequest struct {
	ExtendedDerivation bool
}

// MMSVMDStatus is a Status-Response or an unsolicitedStatus.
type MMSVMDStatus struct {
	Logical  MMSLogicalStatus
	Physical MMSPhysicalStatus
	// LocalDetail is the optional local detail BIT STRING.
	LocalDetail       []byte
	LocalDetailUnused uint8
}

// Status tags.
const (
	mmsTagStatLogical  uint32 = 0
	mmsTagStatPhysical uint32 = 1
	mmsTagStatLocal    uint32 = 2
)

// decodeMMSStatusReq reads Status-Request: BOOLEAN extendedDerivation.
func decodeMMSStatusReq(t osiBERTLV) (*MMSStatusRequest, error) {
	b, err := mmsBody(t, osiBERPrimitive)
	if err != nil {
		return nil, err
	}

	r := &MMSStatusRequest{}
	r.ExtendedDerivation, err = osiBERBool(b)
	return mmsResult(r, err)
}

// decodeMMSStatus reads Status-Response: [0] vmdLogicalStatus,
// [1] vmdPhysicalStatus, [2] localDetail OPTIONAL.
func decodeMMSStatus(t osiBERTLV) (*MMSVMDStatus, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	s := &MMSVMDStatus{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		var n int64
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagStatLogical):
			n, err = osiBERInt(f.Value)
			s.Logical = MMSLogicalStatus(n)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagStatPhysical):
			n, err = osiBERInt(f.Value)
			s.Physical = MMSPhysicalStatus(n)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagStatLocal):
			s.LocalDetail, s.LocalDetailUnused, err = osiBERBits(f.Value)
		}
		return err
	})
	return mmsResult(s, err)
}

// MMSRenameRequest is a Rename-Request.
type MMSRenameRequest struct {
	ObjectClass   MMSObjectClass
	CurrentName   MMSObjectName
	NewIdentifier string
}

// Rename tags.
const (
	mmsTagRenClass   uint32 = 0
	mmsTagRenCurrent uint32 = 1
	mmsTagRenNew     uint32 = 2
)

// decodeMMSRenameReq reads [0] extendedObjectClass, [1] currentName,
// [2] newIdentifier.
func decodeMMSRenameReq(t osiBERTLV) (*MMSRenameRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSRenameRequest{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagRenClass):
			// Reuse the getNameList objectClass reader.
			var g MMSGetNameListRequest
			err = g.decodeClass(f.Value)
			r.ObjectClass = g.ObjectClass
		case f.is(osiBERContext, osiBERConstructed, mmsTagRenCurrent):
			r.CurrentName, err = decodeMMSObjectNameIn(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagRenNew):
			r.NewIdentifier = string(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// MMSCapabilityList is a GetCapabilityList-Request (ContinueAfter) or
// -Response (Capabilities and MoreFollows).
type MMSCapabilityList struct {
	ContinueAfter string
	Capabilities  []string
	MoreFollows   bool
}

// GetCapabilityList response tags.
const (
	mmsTagCapList uint32 = 0
	mmsTagCapMore uint32 = 1
)

// decodeMMSCapReq reads GetCapabilityList-Request: continueAfter
// VisibleString OPTIONAL.
func decodeMMSCapReq(t osiBERTLV) (*MMSCapabilityList, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	c := &MMSCapabilityList{}
	if len(b) == 0 {
		return c, nil
	}
	v, _, err := osiBERExpect(b, osiBERUniversal, osiBERPrimitive, osiBERTagVisible)
	c.ContinueAfter = string(v)
	return mmsResult(c, err)
}

// decodeMMSCapResp reads GetCapabilityList-Response: [0] list,
// [1] moreFollows DEFAULT TRUE.
func decodeMMSCapResp(t osiBERTLV) (*MMSCapabilityList, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	c := &MMSCapabilityList{MoreFollows: true}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagCapList):
			c.Capabilities, err = decodeMMSStrings(f.Value, osiBERTagVisible)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagCapMore):
			c.MoreFollows, err = osiBERBool(f.Value)
		}
		return err
	})
	return mmsResult(c, err)
}

// MMSDomainState is the state of a domain.
type MMSDomainState int64

// Domain states; d1 to d9 (7 to 15) are transitional.
const (
	MMSDomainNonExistent MMSDomainState = 0
	MMSDomainLoading     MMSDomainState = 1
	MMSDomainReady       MMSDomainState = 2
	MMSDomainInUse       MMSDomainState = 3
	MMSDomainComplete    MMSDomainState = 4
	MMSDomainIncomplete  MMSDomainState = 5
)

var mmsDomainStateNames = []string{
	"non-existent", "loading", "ready", "in-use", "complete", "incomplete",
	"", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9",
}

// String returns the ASN.1 name of the state.
func (s MMSDomainState) String() string {
	if n := mmsEnumName(mmsDomainStateNames, int64(s)); n != "" {
		return n
	}
	return fmt.Sprintf("Unknown(%d)", int64(s))
}

// MMSDomainRequest holds the arguments of the domain management and
// upload/download requests:
//
//	DomainName    deleteDomain, getDomainAttributes, initiateUploadSequence,
//	              downloadSegment, initiate/terminateDownloadSequence
//	Capabilities  initiateDownloadSequence
//	Sharable      initiateDownloadSequence
//	Discard       terminateDownloadSequence, when the download failed
//	ULSMID        uploadSegment, terminateUploadSequence
type MMSDomainRequest struct {
	DomainName   string
	Capabilities []string
	Sharable     bool
	Discard      *MMSServiceError
	ULSMID       int32
}

// MMSDomainResponse holds a getDomainAttributes, initiateUploadSequence,
// downloadSegment or uploadSegment response. Segment data stays raw in
// LoadData; Coded tells it is an EXTERNAL rather than non-coded octets.
type MMSDomainResponse struct {
	Capabilities       []string
	State              MMSDomainState
	Deletable          bool
	Sharable           bool
	ProgramInvocations []string
	UploadInProgress   int64

	ULSMID int32

	LoadData    []byte
	Coded       bool
	MoreFollows bool
}

// Domain service tags.
const (
	mmsTagDomName     uint32 = 0
	mmsTagDomCaps     uint32 = 1
	mmsTagDomSharable uint32 = 2
	mmsTagDomDiscard  uint32 = 1
	mmsTagULSMID      uint32 = 0
	mmsTagULCaps      uint32 = 1
	mmsTagSegNonCoded uint32 = 0
	mmsTagSegMore     uint32 = 1
	mmsTagDACaps      uint32 = 0
	mmsTagDAState     uint32 = 1
	mmsTagDADeletable uint32 = 2
	mmsTagDASharable  uint32 = 3
	mmsTagDAPrograms  uint32 = 4
	mmsTagDAUpload    uint32 = 5
)

// decodeMMSDomainName reads a bare Identifier request.
func decodeMMSDomainName(t osiBERTLV) (*MMSDomainRequest, error) {
	b, err := mmsBody(t, osiBERPrimitive)
	if err != nil {
		return nil, err
	}
	return &MMSDomainRequest{DomainName: string(b)}, nil
}

// decodeMMSULSMID reads a bare Integer32 ULSM identifier request.
func decodeMMSULSMID(t osiBERTLV) (*MMSDomainRequest, error) {
	b, err := mmsBody(t, osiBERPrimitive)
	if err != nil {
		return nil, err
	}

	n, err := mmsInt32(b)
	return mmsResult(&MMSDomainRequest{ULSMID: int32(n)}, err)
}

// decodeMMSDownloadReq reads InitiateDownloadSequence-Request ([0] name,
// [1] capabilities, [2] sharable) or TerminateDownloadSequence-Request
// ([0] name, [1] discard ServiceError OPTIONAL).
func decodeMMSDownloadReq(t osiBERTLV, s MMSConfirmedService) (*MMSDomainRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSDomainRequest{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDomName):
			r.DomainName = string(f.Value)
		case s == MMSInitiateDownloadSequence && f.is(osiBERContext, osiBERConstructed, mmsTagDomCaps):
			r.Capabilities, err = decodeMMSStrings(f.Value, osiBERTagVisible)
		case s == MMSInitiateDownloadSequence && f.is(osiBERContext, osiBERPrimitive, mmsTagDomSharable):
			r.Sharable, err = osiBERBool(f.Value)
		case s == MMSTerminateDownloadSequence && f.is(osiBERContext, osiBERConstructed, mmsTagDomDiscard):
			r.Discard, err = decodeMMSServiceError(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSUploadResp reads InitiateUploadSequence-Response: [0] ulsmID,
// [1] listOfCapabilities.
func decodeMMSUploadResp(t osiBERTLV) (*MMSDomainResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSDomainResponse{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagULSMID):
			var n int64
			n, err = mmsInt32(f.Value)
			r.ULSMID = int32(n)
		case f.is(osiBERContext, osiBERConstructed, mmsTagULCaps):
			r.Capabilities, err = decodeMMSStrings(f.Value, osiBERTagVisible)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSSegmentResp reads Download/UploadSegment-Response: loadData
// CHOICE { [0] non-coded, EXTERNAL }, [1] moreFollows DEFAULT TRUE.
func decodeMMSSegmentResp(t osiBERTLV) (*MMSDomainResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSDomainResponse{MoreFollows: true}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagSegNonCoded):
			r.LoadData = f.Value
		case f.is(osiBERUniversal, osiBERConstructed, osiBERTagExternal):
			r.LoadData = f.Value
			r.Coded = true
		case f.is(osiBERContext, osiBERPrimitive, mmsTagSegMore):
			r.MoreFollows, err = osiBERBool(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSDomainAttrs reads GetDomainAttributes-Response.
func decodeMMSDomainAttrs(t osiBERTLV) (*MMSDomainResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSDomainResponse{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagDACaps):
			r.Capabilities, err = decodeMMSStrings(f.Value, osiBERTagVisible)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDAState):
			var n int64
			n, err = osiBERInt(f.Value)
			r.State = MMSDomainState(n)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDADeletable):
			r.Deletable, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDASharable):
			r.Sharable, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagDAPrograms):
			r.ProgramInvocations, err = decodeMMSStrings(f.Value, osiBERTagVisible)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagDAUpload):
			r.UploadInProgress, err = osiBERInt(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// MMSProgramState is a ProgramInvocationState.
type MMSProgramState int64

// Program invocation states.
const (
	MMSProgramNonExistent MMSProgramState = 0
	MMSProgramUnrunnable  MMSProgramState = 1
	MMSProgramIdle        MMSProgramState = 2
	MMSProgramRunning     MMSProgramState = 3
	MMSProgramStopped     MMSProgramState = 4
	MMSProgramStarting    MMSProgramState = 5
	MMSProgramStopping    MMSProgramState = 6
	MMSProgramResuming    MMSProgramState = 7
	MMSProgramResetting   MMSProgramState = 8
)

var mmsProgramStateNames = []string{
	"non-existent", "unrunable", "idle", "running", "stopped", "starting",
	"stopping", "resuming", "resetting",
}

// String returns the ASN.1 name of the state.
func (s MMSProgramState) String() string { return mmsEnumName(mmsProgramStateNames, int64(s)) }

// MMSProgramRequest holds the arguments of the program invocation
// requests. Name is always set; createProgramInvocation fills Domains,
// Reusable and Monitor, start and resume the ExecutionArgument string.
type MMSProgramRequest struct {
	Name              string
	Domains           []string
	Reusable          bool
	Monitor           bool
	HasMonitor        bool
	ExecutionArgument string
}

// MMSProgramAttributes is a GetProgramInvocationAttributes-Response.
type MMSProgramAttributes struct {
	State             MMSProgramState
	Domains           []string
	Deletable         bool
	Reusable          bool
	Monitor           bool
	StartArgument     string
	ExecutionArgument string
}

// Program invocation tags.
const (
	mmsTagPIName      uint32 = 0
	mmsTagPIDomains   uint32 = 1
	mmsTagPIReusable  uint32 = 2
	mmsTagPIMonitor   uint32 = 3
	mmsTagPIArgument  uint32 = 1
	mmsTagPIAState    uint32 = 0
	mmsTagPIADomains  uint32 = 1
	mmsTagPIADeletabl uint32 = 2
	mmsTagPIAReusable uint32 = 3
	mmsTagPIAMonitor  uint32 = 4
	mmsTagPIAStart    uint32 = 5
	mmsTagPIAExec     uint32 = 1
)

// decodeMMSProgramName reads a bare Identifier request.
func decodeMMSProgramName(t osiBERTLV) (*MMSProgramRequest, error) {
	b, err := mmsBody(t, osiBERPrimitive)
	if err != nil {
		return nil, err
	}
	return &MMSProgramRequest{Name: string(b), Reusable: true}, nil
}

// decodeMMSProgramReq reads CreateProgramInvocation-Request ([0] name,
// [1] domains, [2] reusable DEFAULT TRUE, [3] monitorType OPTIONAL) and
// the start, stop, resume, reset and kill requests ([0] name, [1]
// simpleString executionArgument OPTIONAL).
func decodeMMSProgramReq(t osiBERTLV) (*MMSProgramRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSProgramRequest{Reusable: true}
	found := false
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagPIName):
			r.Name = string(f.Value)
			found = true
		case f.is(osiBERContext, osiBERConstructed, mmsTagPIDomains):
			r.Domains, err = decodeMMSStrings(f.Value, osiBERTagVisible)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagPIArgument):
			r.ExecutionArgument = string(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagPIReusable):
			r.Reusable, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagPIMonitor):
			r.Monitor, err = osiBERBool(f.Value)
			r.HasMonitor = true
		}
		return err
	})
	if err == nil && !found {
		err = errMMSField
	}
	return mmsResult(r, err)
}

// decodeMMSProgramAttrs reads GetProgramInvocationAttributes-Response.
func decodeMMSProgramAttrs(t osiBERTLV) (*MMSProgramAttributes, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSProgramAttributes{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagPIAState):
			var n int64
			n, err = osiBERInt(f.Value)
			r.State = MMSProgramState(n)
		case f.is(osiBERContext, osiBERConstructed, mmsTagPIADomains):
			r.Domains, err = decodeMMSStrings(f.Value, osiBERTagVisible)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagPIAExec):
			r.ExecutionArgument = string(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagPIADeletabl):
			r.Deletable, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagPIAReusable):
			r.Reusable, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagPIAMonitor):
			r.Monitor, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagPIAStart):
			r.StartArgument = string(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// MMSFileRequest holds the arguments of the file service requests:
//
//	FileName         fileOpen, fileDelete, fileDirectory (fileSpecification),
//	                 fileRename (current name), obtainFile (source file)
//	NewFileName      fileRename, obtainFile (destination file)
//	InitialPosition  fileOpen
//	FRSMID           fileRead, fileClose
//	ContinueAfter    fileDirectory
//
// A file name is a list of GraphicString parts, e.g. {"/COMTRADE/a.cfg"}.
type MMSFileRequest struct {
	FileName        []string
	NewFileName     []string
	InitialPosition uint32
	FRSMID          int32
	ContinueAfter   []string
}

// MMSFileAttributes is FileAttributes. LastModified is the raw
// GeneralizedTime, e.g. "20231005120000.000Z", empty when absent.
type MMSFileAttributes struct {
	Size         uint32
	LastModified string
}

// MMSDirectoryEntry is one fileDirectory entry.
type MMSDirectoryEntry struct {
	FileName   []string
	Attributes MMSFileAttributes
}

// MMSFileResponse holds a fileOpen (FRSMID, Attributes), fileRead (Data,
// MoreFollows) or fileDirectory (Entries, MoreFollows) response.
// MoreFollows defaults to true for fileRead and false for fileDirectory.
type MMSFileResponse struct {
	FRSMID      int32
	Attributes  MMSFileAttributes
	Data        []byte
	MoreFollows bool
	Entries     []MMSDirectoryEntry
}

// File service tags.
const (
	mmsTagFOName     uint32 = 0
	mmsTagFOPosition uint32 = 1
	mmsTagFOFRSM     uint32 = 0
	mmsTagFOAttrs    uint32 = 1
	mmsTagFRData     uint32 = 0
	mmsTagFRMore     uint32 = 1
	mmsTagFRenCur    uint32 = 0
	mmsTagFRenNew    uint32 = 1
	mmsTagFDSpec     uint32 = 0
	mmsTagFDContinue uint32 = 1
	mmsTagFDEntries  uint32 = 0
	mmsTagFDMore     uint32 = 1
	mmsTagDEName     uint32 = 0
	mmsTagDEAttrs    uint32 = 1
	mmsTagFASize     uint32 = 0
	mmsTagFAModified uint32 = 1
	mmsTagOFServer   uint32 = 0
	mmsTagOFSource   uint32 = 1
	mmsTagOFDest     uint32 = 2
)

// decodeMMSFRSMID reads a bare Integer32 FRSM identifier request.
func decodeMMSFRSMID(t osiBERTLV) (*MMSFileRequest, error) {
	b, err := mmsBody(t, osiBERPrimitive)
	if err != nil {
		return nil, err
	}

	n, err := mmsInt32(b)
	return mmsResult(&MMSFileRequest{FRSMID: int32(n)}, err)
}

// decodeMMSFileDelete reads FileDelete-Request: a FileName.
func decodeMMSFileDelete(t osiBERTLV) (*MMSFileRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	name, err := decodeMMSFileName(b)
	return mmsResult(&MMSFileRequest{FileName: name}, err)
}

// decodeMMSFileReq reads FileOpen-Request ([0] fileName, [1]
// initialPosition), FileRename-Request ([0] current, [1] new),
// FileDirectory-Request ([0] fileSpecification, [1] continueAfter) or
// ObtainFile-Request ([0] server, [1] source, [2] destination).
func decodeMMSFileReq(t osiBERTLV, s MMSConfirmedService) (*MMSFileRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSFileRequest{}
	err = mmsFields(b, func(f osiBERTLV) error {
		if f.Class != osiBERContext {
			return nil
		}

		// Pick the slot of each tag for this service.
		var dst *[]string
		switch {
		case s == MMSObtainFile && f.Tag == mmsTagOFSource, s != MMSObtainFile && f.Tag == mmsTagFOName:
			dst = &r.FileName
		case s == MMSObtainFile && f.Tag == mmsTagOFDest, s == MMSFileRename && f.Tag == mmsTagFRenNew:
			dst = &r.NewFileName
		case s == MMSFileDirectory && f.Tag == mmsTagFDContinue:
			dst = &r.ContinueAfter
		case s == MMSFileOpen && f.is(osiBERContext, osiBERPrimitive, mmsTagFOPosition):
			var err error
			r.InitialPosition, err = osiBERUint32(f.Value)
			return err
		default:
			return nil
		}

		if f.Form != osiBERConstructed {
			return errMMSField
		}
		var err error
		*dst, err = decodeMMSFileName(f.Value)
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSFileAttrs reads FileAttributes: [0] sizeOfFile,
// [1] lastModified OPTIONAL.
func decodeMMSFileAttrs(b []byte) (MMSFileAttributes, error) {
	var a MMSFileAttributes
	err := mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagFASize):
			a.Size, err = osiBERUint32(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagFAModified):
			a.LastModified = string(f.Value)
		}
		return err
	})
	return a, err
}

// decodeMMSFileOpenResp reads FileOpen-Response: [0] frsmID,
// [1] fileAttributes.
func decodeMMSFileOpenResp(t osiBERTLV) (*MMSFileResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSFileResponse{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagFOFRSM):
			var n int64
			n, err = mmsInt32(f.Value)
			r.FRSMID = int32(n)
		case f.is(osiBERContext, osiBERConstructed, mmsTagFOAttrs):
			r.Attributes, err = decodeMMSFileAttrs(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSFileReadResp reads FileRead-Response: [0] fileData,
// [1] moreFollows DEFAULT TRUE.
func decodeMMSFileReadResp(t osiBERTLV) (*MMSFileResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSFileResponse{MoreFollows: true}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagFRData):
			r.Data = f.Value
		case f.is(osiBERContext, osiBERPrimitive, mmsTagFRMore):
			r.MoreFollows, err = osiBERBool(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSFileDirResp reads FileDirectory-Response: [0] EXPLICIT
// SEQUENCE OF DirectoryEntry, [1] moreFollows DEFAULT FALSE.
func decodeMMSFileDirResp(t osiBERTLV) (*MMSFileResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSFileResponse{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagFDEntries):
			var list []byte
			if list, _, err = osiBERExpect(f.Value, osiBERUniversal, osiBERConstructed, osiBERTagSequence); err == nil {
				r.Entries, err = decodeMMSDirEntries(list)
			}
		case f.is(osiBERContext, osiBERPrimitive, mmsTagFDMore):
			r.MoreFollows, err = osiBERBool(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSDirEntries decodes SEQUENCE OF DirectoryEntry { [0] filename,
// [1] fileAttributes }.
func decodeMMSDirEntries(b []byte) ([]MMSDirectoryEntry, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSDirectoryEntry, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		var e MMSDirectoryEntry
		err = mmsFields(item, func(f osiBERTLV) error {
			var err error
			switch {
			case f.is(osiBERContext, osiBERConstructed, mmsTagDEName):
				e.FileName, err = decodeMMSFileName(f.Value)
			case f.is(osiBERContext, osiBERConstructed, mmsTagDEAttrs):
				e.Attributes, err = decodeMMSFileAttrs(f.Value)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// MMSJournalRequest holds the journalName of the journal requests and,
// for writeJournal, the number of entries written. Entry contents and
// read ranges stay raw in ServiceData.
type MMSJournalRequest struct {
	Name    MMSObjectName
	Entries int
}

// MMSJournalResponse is a ReadJournal-Response (Entries, MoreFollows) or
// a ReportJournalStatus-Response (CurrentEntries, Deletable). Journal
// entries stay raw in ServiceData.
type MMSJournalResponse struct {
	Entries        int
	MoreFollows    bool
	CurrentEntries uint32
	Deletable      bool
}

// Journal tags.
const (
	mmsTagJouName      uint32 = 0
	mmsTagJouEntries   uint32 = 1
	mmsTagJouList      uint32 = 0
	mmsTagJouMore      uint32 = 1
	mmsTagJouCurrent   uint32 = 0
	mmsTagJouDeletable uint32 = 1
)

// decodeMMSJournalReq reads the [0] journalName of a journal request and
// counts the [1] entries of a WriteJournal-Request.
func decodeMMSJournalReq(t osiBERTLV, s MMSConfirmedService) (*MMSJournalRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSJournalRequest{}
	found := false
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagJouName):
			r.Name, err = decodeMMSObjectNameIn(f.Value)
			found = true
		case s == MMSWriteJournal && f.is(osiBERContext, osiBERConstructed, mmsTagJouEntries):
			r.Entries, err = osiBERCount(f.Value)
		}
		return err
	})
	if err == nil && !found {
		err = errMMSField
	}
	return mmsResult(r, err)
}

// decodeMMSJournalResp reads ReadJournal-Response ([0] entries, [1]
// moreFollows DEFAULT FALSE) or ReportJournalStatus-Response ([0]
// currentEntries, [1] mmsDeletable).
func decodeMMSJournalResp(t osiBERTLV, s MMSConfirmedService) (*MMSJournalResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSJournalResponse{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case s == MMSReadJournal && f.is(osiBERContext, osiBERConstructed, mmsTagJouList):
			r.Entries, err = osiBERCount(f.Value)
		case s == MMSReadJournal && f.is(osiBERContext, osiBERPrimitive, mmsTagJouMore):
			r.MoreFollows, err = osiBERBool(f.Value)
		case s == MMSReportJournalStatus && f.is(osiBERContext, osiBERPrimitive, mmsTagJouCurrent):
			r.CurrentEntries, err = osiBERUint32(f.Value)
		case s == MMSReportJournalStatus && f.is(osiBERContext, osiBERPrimitive, mmsTagJouDeletable):
			r.Deletable, err = osiBERBool(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// MMSEventState is an EC-State.
type MMSEventState int64

// Event condition states.
const (
	MMSEventDisabled MMSEventState = 0
	MMSEventIdle     MMSEventState = 1
	MMSEventActive   MMSEventState = 2
)

var mmsEventStateNames = []string{"disabled", "idle", "active"}

// String returns the ASN.1 name of the state.
func (s MMSEventState) String() string { return mmsEnumName(mmsEventStateNames, int64(s)) }

// MMSEventClass is an EC-Class.
type MMSEventClass int64

// Event condition classes.
const (
	MMSEventNetworkTriggered MMSEventClass = 0
	MMSEventMonitored        MMSEventClass = 1
)

var mmsEventClassNames = []string{"network-triggered", "monitored"}

// String returns the ASN.1 name of the class.
func (c MMSEventClass) String() string { return mmsEnumName(mmsEventClassNames, int64(c)) }

// MMSAlarmAckRule is an AlarmAckRule.
type MMSAlarmAckRule int64

// Alarm acknowledgment rules.
const (
	MMSAckNone      MMSAlarmAckRule = 0
	MMSAckSimple    MMSAlarmAckRule = 1
	MMSAckAckActive MMSAlarmAckRule = 2
	MMSAckAckAll    MMSAlarmAckRule = 3
)

var mmsAckRuleNames = []string{"none", "simple", "ack-active", "ack-all"}

// String returns the ASN.1 name of the rule.
func (r MMSAlarmAckRule) String() string { return mmsEnumName(mmsAckRuleNames, int64(r)) }

// MMSEventTimeKind is the EventTime CHOICE tag.
type MMSEventTimeKind uint8

// EventTime alternatives.
const (
	MMSEventTimeOfDay    MMSEventTimeKind = 0
	MMSEventTimeSequence MMSEventTimeKind = 1
	MMSEventTimeUndef    MMSEventTimeKind = 2
)

// String returns the ASN.1 name of the alternative.
func (k MMSEventTimeKind) String() string {
	return mmsEnumName([]string{"timeOfDayT", "timeSequenceIdentifier", "undefined"}, int64(k))
}

// MMSEventTime is an EventTime: a TimeOfDay (see MMSData.Time) or a
// time sequence identifier.
type MMSEventTime struct {
	Kind     MMSEventTimeKind
	Time     time.Time
	Sequence uint32
}

// decodeMMSEventTimeIn decodes the EventTime that fills b.
func decodeMMSEventTimeIn(b []byte) (MMSEventTime, error) {
	var e MMSEventTime
	t, err := osiBERSingle(b)
	if err != nil {
		return e, err
	}
	if t.Class != osiBERContext || t.Form != osiBERPrimitive || t.Tag > uint32(MMSEventTimeUndef) {
		return e, errMMSField
	}
	e.Kind = MMSEventTimeKind(t.Tag)

	switch e.Kind {
	case MMSEventTimeOfDay:
		e.Time, err = decodeMMSTimeOfDay(t.Value)
	case MMSEventTimeSequence:
		e.Sequence, err = osiBERUint32(t.Value)
	case MMSEventTimeUndef:
		err = mmsNull(t.Value)
	}
	return e, err
}

// mmsDefaultPriority is the default priority and severity of an event
// condition (normalPriority).
const mmsDefaultPriority = 64

// MMSEventCondition is a DefineEventCondition-Request (Name and the
// definition) or a GetEventConditionAttributes-Response (Deletable and
// the definition).
type MMSEventCondition struct {
	Name                MMSObjectName
	Deletable           bool
	Class               MMSEventClass
	Priority            uint8
	Severity            uint8
	AlarmSummaryReports bool
	// Monitored is the monitoredVariable; MonitoredUndefined is set when
	// a response reports it undefined.
	Monitored             *MMSVariable
	MonitoredUndefined    bool
	EvaluationInterval    uint32
	HasEvaluationInterval bool
}

// Event condition tags.
const (
	mmsTagECName       uint32 = 0
	mmsTagECDeletable  uint32 = 0
	mmsTagECClass      uint32 = 1
	mmsTagECPriority   uint32 = 2
	mmsTagECSeverity   uint32 = 3
	mmsTagECSummary    uint32 = 4
	mmsTagECMonitored  uint32 = 6
	mmsTagECInterval   uint32 = 7
	mmsTagECVarRef     uint32 = 0
	mmsTagECUndefined  uint32 = 1
	mmsTagECSState     uint32 = 0
	mmsTagECSCount     uint32 = 1
	mmsTagECSEnabled   uint32 = 2
	mmsTagECSToActive  uint32 = 3
	mmsTagECSToIdle    uint32 = 4
	mmsTagAckName      uint32 = 0
	mmsTagAckState     uint32 = 2
	mmsTagAckTime      uint32 = 3
	mmsTagASEnrolOnly  uint32 = 0
	mmsTagASActiveOnly uint32 = 1
	mmsTagASAckFilter  uint32 = 2
	mmsTagASSeverity   uint32 = 3
	mmsTagASContinue   uint32 = 5
	mmsTagASMost       uint32 = 0
	mmsTagASLeast      uint32 = 1
	mmsTagASList       uint32 = 0
	mmsTagASMore       uint32 = 1
)

// mmsEventEncoding tells which encoding of event condition fields to read.
type mmsEventEncoding uint8

const (
	mmsEventDefine mmsEventEncoding = iota
	mmsEventAttributes
)

// decodeMMSEventCond reads DefineEventCondition-Request or
// GetEventConditionAttributes-Response. They differ in [0] (name or
// mmsDeletable) and [6] (VariableSpecification or a CHOICE around it).
func decodeMMSEventCond(t osiBERTLV, enc mmsEventEncoding) (*MMSEventCondition, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	c := &MMSEventCondition{Priority: mmsDefaultPriority, Severity: mmsDefaultPriority}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case enc == mmsEventDefine && f.is(osiBERContext, osiBERConstructed, mmsTagECName):
			c.Name, err = decodeMMSObjectNameIn(f.Value)
		case enc == mmsEventAttributes && f.is(osiBERContext, osiBERPrimitive, mmsTagECDeletable):
			c.Deletable, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagECClass):
			var n int64
			n, err = osiBERInt(f.Value)
			c.Class = MMSEventClass(n)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagECPriority):
			c.Priority, err = mmsUint8(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagECSeverity):
			c.Severity, err = mmsUint8(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagECSummary):
			c.AlarmSummaryReports, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagECMonitored):
			err = c.decodeMonitored(f.Value, enc)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagECInterval):
			c.EvaluationInterval, err = osiBERUint32(f.Value)
			c.HasEvaluationInterval = true
		}
		return err
	})
	return mmsResult(c, err)
}

// decodeMonitored reads the monitoredVariable.
func (c *MMSEventCondition) decodeMonitored(b []byte, enc mmsEventEncoding) error {
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}

	// A response wraps it: [0] variableReference or [1] undefined.
	if enc == mmsEventAttributes {
		switch {
		case t.is(osiBERContext, osiBERPrimitive, mmsTagECUndefined):
			c.MonitoredUndefined = true
			return mmsNull(t.Value)
		case !t.is(osiBERContext, osiBERConstructed, mmsTagECVarRef):
			return errMMSField
		}
		if t, err = osiBERSingle(t.Value); err != nil {
			return err
		}
	}

	v, err := decodeMMSVarSpec(t)
	if err != nil {
		return err
	}
	c.Monitored = &v
	return nil
}

// MMSEventConditionStatus is a ReportEventConditionStatus-Response.
type MMSEventConditionStatus struct {
	State       MMSEventState
	Enrollments uint32
	Enabled     bool
	HasEnabled  bool
	// ToActive and ToIdle are the last transition times; HasToActive and
	// HasToIdle tell they were present.
	ToActive    MMSEventTime
	HasToActive bool
	ToIdle      MMSEventTime
	HasToIdle   bool
}

// decodeMMSEventStatus reads ReportEventConditionStatus-Response.
func decodeMMSEventStatus(t osiBERTLV) (*MMSEventConditionStatus, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	s := &MMSEventConditionStatus{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagECSState):
			var n int64
			n, err = osiBERInt(f.Value)
			s.State = MMSEventState(n)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagECSCount):
			s.Enrollments, err = osiBERUint32(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagECSEnabled):
			s.Enabled, err = osiBERBool(f.Value)
			s.HasEnabled = true
		case f.is(osiBERContext, osiBERConstructed, mmsTagECSToActive):
			s.ToActive, err = decodeMMSEventTimeIn(f.Value)
			s.HasToActive = true
		case f.is(osiBERContext, osiBERConstructed, mmsTagECSToIdle):
			s.ToIdle, err = decodeMMSEventTimeIn(f.Value)
			s.HasToIdle = true
		}
		return err
	})
	return mmsResult(s, err)
}

// MMSEventNotification is an EventNotification.
type MMSEventNotification struct {
	EnrollmentName MMSObjectName
	// ConditionName is the event condition, unless ConditionUndefined.
	ConditionName      MMSObjectName
	ConditionUndefined bool
	Severity           uint8
	State              MMSEventState
	HasState           bool
	TransitionTime     MMSEventTime
	NotificationLost   bool
	AckRule            MMSAlarmAckRule
	HasAckRule         bool
	// HasAction is set when an action result is attached: ActionName, and
	// the raw ConfirmedServiceResponse of a successful action or the
	// ServiceError of a failed one.
	HasAction      bool
	ActionName     MMSObjectName
	ActionResponse []byte
	ActionError    *MMSServiceError
}

// Event notification tags.
const (
	mmsTagENEnrollment uint32 = 0
	mmsTagENCondition  uint32 = 1
	mmsTagENSeverity   uint32 = 2
	mmsTagENState      uint32 = 3
	mmsTagENTime       uint32 = 4
	mmsTagENLost       uint32 = 6
	mmsTagENAckRule    uint32 = 7
	mmsTagENAction     uint32 = 8
	mmsTagENCondName   uint32 = 0
	mmsTagENCondUndef  uint32 = 1
	mmsTagENSuccess    uint32 = 0
	mmsTagENFailure    uint32 = 1
)

// decodeMMSEventNotif reads EventNotification.
func decodeMMSEventNotif(t osiBERTLV) (*MMSEventNotification, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	e := &MMSEventNotification{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagENEnrollment):
			e.EnrollmentName, err = decodeMMSObjectNameIn(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagENCondition):
			err = e.decodeCondition(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagENSeverity):
			e.Severity, err = mmsUint8(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagENState):
			var n int64
			n, err = osiBERInt(f.Value)
			e.State = MMSEventState(n)
			e.HasState = true
		case f.is(osiBERContext, osiBERConstructed, mmsTagENTime):
			e.TransitionTime, err = decodeMMSEventTimeIn(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagENLost):
			e.NotificationLost, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagENAckRule):
			var n int64
			n, err = osiBERInt(f.Value)
			e.AckRule = MMSAlarmAckRule(n)
			e.HasAckRule = true
		case f.is(osiBERContext, osiBERConstructed, mmsTagENAction):
			err = e.decodeAction(f.Value)
		}
		return err
	})
	return mmsResult(e, err)
}

// decodeCondition reads eventConditionName: CHOICE { [0] ObjectName,
// [1] undefined NULL }.
func (e *MMSEventNotification) decodeCondition(b []byte) error {
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}

	switch {
	case t.is(osiBERContext, osiBERConstructed, mmsTagENCondName):
		e.ConditionName, err = decodeMMSObjectNameIn(t.Value)
	case t.is(osiBERContext, osiBERPrimitive, mmsTagENCondUndef):
		e.ConditionUndefined = true
		err = mmsNull(t.Value)
	default:
		err = errMMSField
	}
	return err
}

// decodeAction reads actionResult: SEQUENCE { eventActionName ObjectName,
// CHOICE { success [0] ConfirmedServiceResponse, failure [1] ServiceError
// } }.
func (e *MMSEventNotification) decodeAction(b []byte) error {
	t, rest, err := osiBERNext(b)
	if err != nil {
		return err
	}
	if e.ActionName, err = decodeMMSObjectName(t); err != nil {
		return err
	}

	r, err := osiBERSingle(rest)
	if err != nil {
		return err
	}
	switch {
	case r.is(osiBERContext, osiBERConstructed, mmsTagENSuccess):
		e.ActionResponse = r.Value
	case r.is(osiBERContext, osiBERConstructed, mmsTagENFailure):
		e.ActionError, err = decodeMMSServiceError(r.Value)
	default:
		err = errMMSField
	}
	e.HasAction = err == nil
	return err
}

// MMSEventAck is an AcknowledgeEventNotification-Request.
type MMSEventAck struct {
	EnrollmentName MMSObjectName
	State          MMSEventState
	Time           MMSEventTime
}

// decodeMMSEventAck reads [0] eventEnrollmentName, [2] acknowledgedState,
// [3] timeOfAcknowledgedTransition.
func decodeMMSEventAck(t osiBERTLV) (*MMSEventAck, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	a := &MMSEventAck{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagAckName):
			a.EnrollmentName, err = decodeMMSObjectNameIn(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagAckState):
			var n int64
			n, err = osiBERInt(f.Value)
			a.State = MMSEventState(n)
		case f.is(osiBERContext, osiBERConstructed, mmsTagAckTime):
			a.Time, err = decodeMMSEventTimeIn(f.Value)
		}
		return err
	})
	return mmsResult(a, err)
}

// MMSAlarmSummaryRequest is a GetAlarmSummary-Request.
type MMSAlarmSummaryRequest struct {
	EnrollmentsOnly  bool
	ActiveAlarmsOnly bool
	// AckFilter is 0 not-acked, 1 acked, 2 all.
	AckFilter         int64
	HasSeverityFilter bool
	MostSevere        uint8
	LeastSevere       uint8
	HasContinueAfter  bool
	ContinueAfter     MMSObjectName
}

// MMSAlarmSummaryResponse is a GetAlarmSummary-Response, header only:
// the AlarmSummary entries stay raw in ServiceData.
type MMSAlarmSummaryResponse struct {
	Summaries   int
	MoreFollows bool
}

// decodeMMSAlarmReq reads GetAlarmSummary-Request.
func decodeMMSAlarmReq(t osiBERTLV) (*MMSAlarmSummaryRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSAlarmSummaryRequest{EnrollmentsOnly: true, ActiveAlarmsOnly: true}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagASEnrolOnly):
			r.EnrollmentsOnly, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagASActiveOnly):
			r.ActiveAlarmsOnly, err = osiBERBool(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagASAckFilter):
			r.AckFilter, err = osiBERInt(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagASSeverity):
			err = r.decodeSeverity(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagASContinue):
			r.ContinueAfter, err = decodeMMSObjectNameIn(f.Value)
			r.HasContinueAfter = true
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeSeverity reads severityFilter: [0] mostSevere, [1] leastSevere.
func (r *MMSAlarmSummaryRequest) decodeSeverity(b []byte) error {
	r.HasSeverityFilter = true
	return mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagASMost):
			r.MostSevere, err = mmsUint8(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagASLeast):
			r.LeastSevere, err = mmsUint8(f.Value)
		}
		return err
	})
}

// decodeMMSAlarmResp reads GetAlarmSummary-Response: [0] summaries,
// [1] moreFollows DEFAULT FALSE.
func decodeMMSAlarmResp(t osiBERTLV) (*MMSAlarmSummaryResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSAlarmSummaryResponse{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagASList):
			r.Summaries, err = osiBERCount(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagASMore):
			r.MoreFollows, err = osiBERBool(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// MMSErrorDetailKind is the serviceSpecificInformation CHOICE tag of a
// ServiceError.
type MMSErrorDetailKind uint8

// Service specific error alternatives.
const (
	MMSErrDetailObtainFile          MMSErrorDetailKind = 0
	MMSErrDetailStart               MMSErrorDetailKind = 1
	MMSErrDetailStop                MMSErrorDetailKind = 2
	MMSErrDetailResume              MMSErrorDetailKind = 3
	MMSErrDetailReset               MMSErrorDetailKind = 4
	MMSErrDetailDeleteVariable      MMSErrorDetailKind = 5
	MMSErrDetailDeleteNVL           MMSErrorDetailKind = 6
	MMSErrDetailDeleteNamedType     MMSErrorDetailKind = 7
	MMSErrDetailDefineEnrollment    MMSErrorDetailKind = 8
	MMSErrDetailFileRename          MMSErrorDetailKind = 9
	MMSErrDetailAdditionalService   MMSErrorDetailKind = 10
	MMSErrDetailChangeAccessControl MMSErrorDetailKind = 11
)

var mmsErrDetailNames = []string{
	"obtainFile", "start", "stop", "resume", "reset", "deleteVariableAccess",
	"deleteNamedVariableList", "deleteNamedType", "defineEventEnrollment-Error",
	"fileRename", "additionalService", "changeAccessControl",
}

// String returns the ASN.1 name of the alternative.
func (k MMSErrorDetailKind) String() string { return mmsEnumName(mmsErrDetailNames, int64(k)) }

// MMSErrorDetail is the serviceSpecificInformation of a ServiceError.
// Value holds the INTEGER alternatives: a ProgramInvocationState for
// start to reset, a number deleted for the delete services, 0 source or 1
// destination file for obtainFile and fileRename. Name is set for
// defineEventEnrollment-Error. Raw is the element value.
type MMSErrorDetail struct {
	Kind  MMSErrorDetailKind
	Value int64
	Name  MMSObjectName
	Raw   []byte
}

// ServiceError serviceSpecificInformation tag.
const mmsTagErrSpecific uint32 = 3

// decodeMMSErrorDetail finds and decodes the [3] serviceSpecificInformation
// of a ServiceError body; it returns nil when there is none.
func decodeMMSErrorDetail(b []byte) (*MMSErrorDetail, error) {
	var d *MMSErrorDetail
	err := mmsFields(b, func(f osiBERTLV) error {
		if !f.is(osiBERContext, osiBERConstructed, mmsTagErrSpecific) {
			return nil
		}

		t, err := osiBERSingle(f.Value)
		if err != nil {
			return err
		}
		if t.Class != osiBERContext || t.Tag > uint32(MMSErrDetailChangeAccessControl) {
			return errMMSField
		}

		d = &MMSErrorDetail{Kind: MMSErrorDetailKind(t.Tag), Raw: t.Value}
		switch {
		case d.Kind == MMSErrDetailAdditionalService:
		case d.Kind == MMSErrDetailDefineEnrollment:
			d.Name, err = decodeMMSObjectNameIn(t.Value)
		case t.Form == osiBERPrimitive:
			d.Value, err = osiBERInt(t.Value)
		default:
			err = errMMSField
		}
		return err
	})
	return mmsResult(d, err)
}

// setErrorDetail adds the serviceSpecificInformation of a ServiceError.
func (m *MMS) setErrorDetail(b []byte) {
	m.ErrorDetail, m.ServiceDecodeErr = decodeMMSErrorDetail(b)
}

// decodeMoreReq decodes the best effort typed requests. Services without
// one, or whose request is NULL, are left to ServiceData.
func (m *MMS) decodeMoreReq(t osiBERTLV) error {
	var err error
	switch s := m.Service; s {
	case MMSStatus:
		m.StatusReq, err = decodeMMSStatusReq(t)
	case MMSRename:
		m.RenameReq, err = decodeMMSRenameReq(t)
	case MMSDeleteVariableAccess, MMSDeleteNamedVariableList:
		m.DeleteReq, err = decodeMMSDeleteReq(t)
	case MMSInitiateDownloadSequence, MMSTerminateDownloadSequence:
		m.DomainReq, err = decodeMMSDownloadReq(t, s)
	case MMSDownloadSegment, MMSInitiateUploadSequence, MMSDeleteDomain, MMSGetDomainAttributes:
		m.DomainReq, err = decodeMMSDomainName(t)
	case MMSUploadSegment, MMSTerminateUploadSequence:
		m.DomainReq, err = decodeMMSULSMID(t)
	case MMSCreateProgramInvocation, MMSStart, MMSStop, MMSResume, MMSReset, MMSKill:
		m.ProgramReq, err = decodeMMSProgramReq(t)
	case MMSDeleteProgramInvocation, MMSGetProgramInvocationAttributes:
		m.ProgramReq, err = decodeMMSProgramName(t)
	case MMSObtainFile, MMSFileOpen, MMSFileRename, MMSFileDirectory:
		m.FileReq, err = decodeMMSFileReq(t, s)
	case MMSFileRead, MMSFileClose:
		m.FileReq, err = decodeMMSFRSMID(t)
	case MMSFileDelete:
		m.FileReq, err = decodeMMSFileDelete(t)
	case MMSDefineEventCondition:
		m.EventCondition, err = decodeMMSEventCond(t, mmsEventDefine)
	case MMSGetEventConditionAttributes, MMSReportEventConditionStatus, MMSReportJournalStatus:
		m.ObjectName, err = decodeMMSNameReq(t)
	case MMSAcknowledgeEventNotification:
		m.EventAck, err = decodeMMSEventAck(t)
	case MMSGetAlarmSummary:
		m.AlarmSummaryReq, err = decodeMMSAlarmReq(t)
	case MMSReadJournal, MMSWriteJournal, MMSInitializeJournal, MMSCreateJournal, MMSDeleteJournal:
		m.JournalReq, err = decodeMMSJournalReq(t, s)
	case MMSGetCapabilityList:
		m.CapabilityList, err = decodeMMSCapReq(t)
	}
	return err
}

// decodeMoreResp decodes the best effort typed responses.
func (m *MMS) decodeMoreResp(t osiBERTLV) error {
	var err error
	switch s := m.Service; s {
	case MMSStatus:
		m.Status, err = decodeMMSStatus(t)
	case MMSGetVariableAccessAttributes:
		m.VariableAttributes, err = decodeMMSGVAAResp(t)
	case MMSDeleteVariableAccess, MMSDeleteNamedVariableList:
		m.DeleteResp, err = decodeMMSDeleteResp(t)
	case MMSInitiateUploadSequence:
		m.DomainResp, err = decodeMMSUploadResp(t)
	case MMSDownloadSegment, MMSUploadSegment:
		m.DomainResp, err = decodeMMSSegmentResp(t)
	case MMSGetDomainAttributes:
		m.DomainResp, err = decodeMMSDomainAttrs(t)
	case MMSGetProgramInvocationAttributes:
		m.ProgramAttributes, err = decodeMMSProgramAttrs(t)
	case MMSFileOpen:
		m.FileResp, err = decodeMMSFileOpenResp(t)
	case MMSFileRead:
		m.FileResp, err = decodeMMSFileReadResp(t)
	case MMSFileDirectory:
		m.FileResp, err = decodeMMSFileDirResp(t)
	case MMSGetEventConditionAttributes:
		m.EventCondition, err = decodeMMSEventCond(t, mmsEventAttributes)
	case MMSReportEventConditionStatus:
		m.EventConditionStatus, err = decodeMMSEventStatus(t)
	case MMSGetAlarmSummary:
		m.AlarmSummary, err = decodeMMSAlarmResp(t)
	case MMSReadJournal, MMSReportJournalStatus:
		m.JournalResp, err = decodeMMSJournalResp(t, s)
	case MMSGetCapabilityList:
		m.CapabilityList, err = decodeMMSCapResp(t)
	}
	return err
}

// decodeMMSNameReq reads a request that is an EXPLICIT ObjectName.
func decodeMMSNameReq(t osiBERTLV) (*MMSObjectName, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	n, err := decodeMMSObjectNameIn(b)
	return mmsResult(&n, err)
}
