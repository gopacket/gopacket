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

// LayerTypeMMS is the ISO 9506 Manufacturing Message Specification layer.
var LayerTypeMMS = gopacket.RegisterLayerType(198, gopacket.LayerTypeMetadata{Name: "MMS", Decoder: gopacket.DecodeFunc(decodeMMS)})

// MMSPDUType is the MMSpdu CHOICE tag.
type MMSPDUType uint8

// MMSpdu alternatives.
const (
	MMSConfirmedRequest  MMSPDUType = 0
	MMSConfirmedResponse MMSPDUType = 1
	MMSConfirmedError    MMSPDUType = 2
	MMSUnconfirmed       MMSPDUType = 3
	MMSReject            MMSPDUType = 4
	MMSCancelRequest     MMSPDUType = 5
	MMSCancelResponse    MMSPDUType = 6
	MMSCancelError       MMSPDUType = 7
	MMSInitiateRequest   MMSPDUType = 8
	MMSInitiateResponse  MMSPDUType = 9
	MMSInitiateError     MMSPDUType = 10
	MMSConcludeRequest   MMSPDUType = 11
	MMSConcludeResponse  MMSPDUType = 12
	MMSConcludeError     MMSPDUType = 13
)

var mmsPDUNames = [...]string{
	"confirmed-RequestPDU", "confirmed-ResponsePDU", "confirmed-ErrorPDU",
	"unconfirmed-PDU", "rejectPDU", "cancel-RequestPDU", "cancel-ResponsePDU",
	"cancel-ErrorPDU", "initiate-RequestPDU", "initiate-ResponsePDU",
	"initiate-ErrorPDU", "conclude-RequestPDU", "conclude-ResponsePDU",
	"conclude-ErrorPDU",
}

// String returns the ASN.1 name of the PDU.
func (t MMSPDUType) String() string {
	if int(t) < len(mmsPDUNames) {
		return mmsPDUNames[t]
	}
	return fmt.Sprintf("Unknown(%d)", uint8(t))
}

// MMSConfirmedService is the ConfirmedServiceRequest/Response CHOICE tag.
type MMSConfirmedService uint16

// Confirmed services (ISO 9506-2 clause 7).
const (
	MMSStatus                         MMSConfirmedService = 0
	MMSGetNameList                    MMSConfirmedService = 1
	MMSIdentify                       MMSConfirmedService = 2
	MMSRename                         MMSConfirmedService = 3
	MMSRead                           MMSConfirmedService = 4
	MMSWrite                          MMSConfirmedService = 5
	MMSGetVariableAccessAttributes    MMSConfirmedService = 6
	MMSDefineNamedVariable            MMSConfirmedService = 7
	MMSDefineScatteredAccess          MMSConfirmedService = 8
	MMSGetScatteredAccessAttributes   MMSConfirmedService = 9
	MMSDeleteVariableAccess           MMSConfirmedService = 10
	MMSDefineNamedVariableList        MMSConfirmedService = 11
	MMSGetNamedVariableListAttributes MMSConfirmedService = 12
	MMSDeleteNamedVariableList        MMSConfirmedService = 13
	MMSDefineNamedType                MMSConfirmedService = 14
	MMSGetNamedTypeAttributes         MMSConfirmedService = 15
	MMSDeleteNamedType                MMSConfirmedService = 16
	MMSInput                          MMSConfirmedService = 17
	MMSOutput                         MMSConfirmedService = 18
	MMSTakeControl                    MMSConfirmedService = 19
	MMSRelinquishControl              MMSConfirmedService = 20
	MMSDefineSemaphore                MMSConfirmedService = 21
	MMSDeleteSemaphore                MMSConfirmedService = 22
	MMSReportSemaphoreStatus          MMSConfirmedService = 23
	MMSReportPoolSemaphoreStatus      MMSConfirmedService = 24
	MMSReportSemaphoreEntryStatus     MMSConfirmedService = 25
	MMSInitiateDownloadSequence       MMSConfirmedService = 26
	MMSDownloadSegment                MMSConfirmedService = 27
	MMSTerminateDownloadSequence      MMSConfirmedService = 28
	MMSInitiateUploadSequence         MMSConfirmedService = 29
	MMSUploadSegment                  MMSConfirmedService = 30
	MMSTerminateUploadSequence        MMSConfirmedService = 31
	MMSRequestDomainDownload          MMSConfirmedService = 32
	MMSRequestDomainUpload            MMSConfirmedService = 33
	MMSLoadDomainContent              MMSConfirmedService = 34
	MMSStoreDomainContent             MMSConfirmedService = 35
	MMSDeleteDomain                   MMSConfirmedService = 36
	MMSGetDomainAttributes            MMSConfirmedService = 37
	MMSCreateProgramInvocation        MMSConfirmedService = 38
	MMSDeleteProgramInvocation        MMSConfirmedService = 39
	MMSStart                          MMSConfirmedService = 40
	MMSStop                           MMSConfirmedService = 41
	MMSResume                         MMSConfirmedService = 42
	MMSReset                          MMSConfirmedService = 43
	MMSKill                           MMSConfirmedService = 44
	MMSGetProgramInvocationAttributes MMSConfirmedService = 45
	MMSObtainFile                     MMSConfirmedService = 46
	MMSDefineEventCondition           MMSConfirmedService = 47
	MMSDeleteEventCondition           MMSConfirmedService = 48
	MMSGetEventConditionAttributes    MMSConfirmedService = 49
	MMSReportEventConditionStatus     MMSConfirmedService = 50
	MMSAlterEventConditionMonitoring  MMSConfirmedService = 51
	MMSTriggerEvent                   MMSConfirmedService = 52
	MMSDefineEventAction              MMSConfirmedService = 53
	MMSDeleteEventAction              MMSConfirmedService = 54
	MMSGetEventActionAttributes       MMSConfirmedService = 55
	MMSReportEventActionStatus        MMSConfirmedService = 56
	MMSDefineEventEnrollment          MMSConfirmedService = 57
	MMSDeleteEventEnrollment          MMSConfirmedService = 58
	MMSAlterEventEnrollment           MMSConfirmedService = 59
	MMSReportEventEnrollmentStatus    MMSConfirmedService = 60
	MMSGetEventEnrollmentAttributes   MMSConfirmedService = 61
	MMSAcknowledgeEventNotification   MMSConfirmedService = 62
	MMSGetAlarmSummary                MMSConfirmedService = 63
	MMSGetAlarmEnrollmentSummary      MMSConfirmedService = 64
	MMSReadJournal                    MMSConfirmedService = 65
	MMSWriteJournal                   MMSConfirmedService = 66
	MMSInitializeJournal              MMSConfirmedService = 67
	MMSReportJournalStatus            MMSConfirmedService = 68
	MMSCreateJournal                  MMSConfirmedService = 69
	MMSDeleteJournal                  MMSConfirmedService = 70
	MMSGetCapabilityList              MMSConfirmedService = 71
	MMSFileOpen                       MMSConfirmedService = 72
	MMSFileRead                       MMSConfirmedService = 73
	MMSFileClose                      MMSConfirmedService = 74
	MMSFileRename                     MMSConfirmedService = 75
	MMSFileDelete                     MMSConfirmedService = 76
	MMSFileDirectory                  MMSConfirmedService = 77
)

// Confirmed services added by ISO 9506-2:2003. Tag 79 is reserved for the
// service-ext detail, see MMSServiceExt.
const (
	MMSAdditionalService              MMSConfirmedService = 78
	MMSGetDataExchangeAttributes      MMSConfirmedService = 80
	MMSExchangeData                   MMSConfirmedService = 81
	MMSDefineAccessControlList        MMSConfirmedService = 82
	MMSGetAccessControlListAttributes MMSConfirmedService = 83
	MMSReportAccessControlledObjects  MMSConfirmedService = 84
	MMSDeleteAccessControlList        MMSConfirmedService = 85
	MMSChangeAccessControl            MMSConfirmedService = 86
)

var mmsServiceNames = [...]string{
	"status", "getNameList", "identify", "rename", "read", "write",
	"getVariableAccessAttributes", "defineNamedVariable",
	"defineScatteredAccess", "getScatteredAccessAttributes",
	"deleteVariableAccess", "defineNamedVariableList",
	"getNamedVariableListAttributes", "deleteNamedVariableList",
	"defineNamedType", "getNamedTypeAttributes", "deleteNamedType", "input",
	"output", "takeControl", "relinquishControl", "defineSemaphore",
	"deleteSemaphore", "reportSemaphoreStatus", "reportPoolSemaphoreStatus",
	"reportSemaphoreEntryStatus", "initiateDownloadSequence",
	"downloadSegment", "terminateDownloadSequence", "initiateUploadSequence",
	"uploadSegment", "terminateUploadSequence", "requestDomainDownload",
	"requestDomainUpload", "loadDomainContent", "storeDomainContent",
	"deleteDomain", "getDomainAttributes", "createProgramInvocation",
	"deleteProgramInvocation", "start", "stop", "resume", "reset", "kill",
	"getProgramInvocationAttributes", "obtainFile", "defineEventCondition",
	"deleteEventCondition", "getEventConditionAttributes",
	"reportEventConditionStatus", "alterEventConditionMonitoring",
	"triggerEvent", "defineEventAction", "deleteEventAction",
	"getEventActionAttributes", "reportEventActionStatus",
	"defineEventEnrollment", "deleteEventEnrollment", "alterEventEnrollment",
	"reportEventEnrollmentStatus", "getEventEnrollmentAttributes",
	"acknowledgeEventNotification", "getAlarmSummary",
	"getAlarmEnrollmentSummary", "readJournal", "writeJournal",
	"initializeJournal", "reportJournalStatus", "createJournal",
	"deleteJournal", "getCapabilityList", "fileOpen", "fileRead", "fileClose",
	"fileRename", "fileDelete", "fileDirectory", "additionalService", "",
	"getDataExchangeAttributes", "exchangeData", "defineAccessControlList",
	"getAccessControlListAttributes", "reportAccessControlledObjects",
	"deleteAccessControlList", "changeAccessControl",
}

// String returns the ASN.1 name of the service.
func (s MMSConfirmedService) String() string {
	if int(s) < len(mmsServiceNames) && mmsServiceNames[s] != "" {
		return mmsServiceNames[s]
	}
	return fmt.Sprintf("Unknown(%d)", uint16(s))
}

// MMSUnconfirmedService is the UnconfirmedService CHOICE tag.
type MMSUnconfirmedService uint8

// Unconfirmed services.
const (
	MMSUnconfirmedInfoReport MMSUnconfirmedService = 0
	MMSUnconfirmedStatus     MMSUnconfirmedService = 1
	MMSUnconfirmedEvent      MMSUnconfirmedService = 2
)

// String returns the ASN.1 name of the service.
func (s MMSUnconfirmedService) String() string {
	switch s {
	case MMSUnconfirmedInfoReport:
		return "informationReport"
	case MMSUnconfirmedStatus:
		return "unsolicitedStatus"
	case MMSUnconfirmedEvent:
		return "eventNotification"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// MMSObjectScope is the ObjectName CHOICE (and getNameList objectScope).
type MMSObjectScope uint8

// Object name scopes.
const (
	MMSScopeVMD    MMSObjectScope = 0
	MMSScopeDomain MMSObjectScope = 1
	MMSScopeAA     MMSObjectScope = 2
)

// String returns the ASN.1 name of the scope.
func (s MMSObjectScope) String() string {
	switch s {
	case MMSScopeVMD:
		return "vmd-specific"
	case MMSScopeDomain:
		return "domain-specific"
	case MMSScopeAA:
		return "aa-specific"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// MMSObjectClass is the getNameList basicObjectClass.
type MMSObjectClass uint8

// Basic object classes.
const (
	MMSClassNamedVariable     MMSObjectClass = 0
	MMSClassScatteredAccess   MMSObjectClass = 1
	MMSClassNamedVariableList MMSObjectClass = 2
	MMSClassNamedType         MMSObjectClass = 3
	MMSClassSemaphore         MMSObjectClass = 4
	MMSClassEventCondition    MMSObjectClass = 5
	MMSClassEventAction       MMSObjectClass = 6
	MMSClassEventEnrollment   MMSObjectClass = 7
	MMSClassJournal           MMSObjectClass = 8
	MMSClassDomain            MMSObjectClass = 9
	MMSClassProgramInvocation MMSObjectClass = 10
	MMSClassOperatorStation   MMSObjectClass = 11
	MMSClassDataExchange      MMSObjectClass = 12
	MMSClassAccessControlList MMSObjectClass = 13
)

var mmsClassNames = [...]string{
	"namedVariable", "scatteredAccess", "namedVariableList", "namedType",
	"semaphore", "eventCondition", "eventAction", "eventEnrollment",
	"journal", "domain", "programInvocation", "operatorStation",
	"dataExchange", "accessControlList",
}

// String returns the ASN.1 name of the class.
func (c MMSObjectClass) String() string {
	if int(c) < len(mmsClassNames) {
		return mmsClassNames[c]
	}
	return fmt.Sprintf("Unknown(%d)", uint8(c))
}

// MMSCSObjectClass is the csObjectClass of the companion standards.
type MMSCSObjectClass uint8

// Companion standard object classes.
const (
	MMSClassEventConditionList MMSCSObjectClass = 0
	MMSClassUnitControl        MMSCSObjectClass = 1
)

// String returns the ASN.1 name of the class.
func (c MMSCSObjectClass) String() string {
	switch c {
	case MMSClassEventConditionList:
		return "eventConditionList"
	case MMSClassUnitControl:
		return "unitControl"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(c))
	}
}

// MMSDataAccessError is the DataAccessError of a failed read or write.
type MMSDataAccessError uint8

// Data access errors.
const (
	MMSObjectInvalidated           MMSDataAccessError = 0
	MMSHardwareFault               MMSDataAccessError = 1
	MMSTemporarilyUnavailable      MMSDataAccessError = 2
	MMSObjectAccessDenied          MMSDataAccessError = 3
	MMSObjectUndefined             MMSDataAccessError = 4
	MMSInvalidAddress              MMSDataAccessError = 5
	MMSTypeUnsupported             MMSDataAccessError = 6
	MMSTypeInconsistent            MMSDataAccessError = 7
	MMSObjectAttributeInconsistent MMSDataAccessError = 8
	MMSObjectAccessUnsupported     MMSDataAccessError = 9
	MMSObjectNonExistent           MMSDataAccessError = 10
	MMSObjectValueInvalid          MMSDataAccessError = 11
)

var mmsAccessErrorNames = [...]string{
	"object-invalidated", "hardware-fault", "temporarily-unavailable",
	"object-access-denied", "object-undefined", "invalid-address",
	"type-unsupported", "type-inconsistent", "object-attribute-inconsistent",
	"object-access-unsupported", "object-non-existent", "object-value-invalid",
}

// String returns the ASN.1 name of the error.
func (e MMSDataAccessError) String() string {
	if int(e) < len(mmsAccessErrorNames) {
		return mmsAccessErrorNames[e]
	}
	return fmt.Sprintf("Unknown(%d)", uint8(e))
}

// MMSErrorClass is the ServiceError errorClass CHOICE tag.
type MMSErrorClass uint8

// Service error classes.
const (
	MMSErrorVMDState       MMSErrorClass = 0
	MMSErrorAppReference   MMSErrorClass = 1
	MMSErrorDefinition     MMSErrorClass = 2
	MMSErrorResource       MMSErrorClass = 3
	MMSErrorService        MMSErrorClass = 4
	MMSErrorServicePreempt MMSErrorClass = 5
	MMSErrorTimeResolution MMSErrorClass = 6
	MMSErrorAccess         MMSErrorClass = 7
	MMSErrorInitiate       MMSErrorClass = 8
	MMSErrorConclude       MMSErrorClass = 9
	MMSErrorCancel         MMSErrorClass = 10
	MMSErrorFile           MMSErrorClass = 11
	MMSErrorOthers         MMSErrorClass = 12
)

var mmsErrorClassNames = [...]string{
	"vmd-state", "application-reference", "definition", "resource",
	"service", "service-preempt", "time-resolution", "access", "initiate",
	"conclude", "cancel", "file", "others",
}

// String returns the ASN.1 name of the class.
func (c MMSErrorClass) String() string {
	if int(c) < len(mmsErrorClassNames) {
		return mmsErrorClassNames[c]
	}
	return fmt.Sprintf("Unknown(%d)", uint8(c))
}

// MMSRejectType is the rejectReason CHOICE tag: which PDU was rejected.
type MMSRejectType uint8

// Reject reasons.
const (
	MMSRejectConfirmedRequest  MMSRejectType = 1
	MMSRejectConfirmedResponse MMSRejectType = 2
	MMSRejectConfirmedError    MMSRejectType = 3
	MMSRejectUnconfirmed       MMSRejectType = 4
	MMSRejectPDUError          MMSRejectType = 5
	MMSRejectCancelRequest     MMSRejectType = 6
	MMSRejectCancelResponse    MMSRejectType = 7
	MMSRejectCancelError       MMSRejectType = 8
	MMSRejectConcludeRequest   MMSRejectType = 9
	MMSRejectConcludeResponse  MMSRejectType = 10
	MMSRejectConcludeError     MMSRejectType = 11
)

var mmsRejectNames = [...]string{
	"", "confirmed-requestPDU", "confirmed-responsePDU", "confirmed-errorPDU",
	"unconfirmedPDU", "pdu-error", "cancel-requestPDU", "cancel-responsePDU",
	"cancel-errorPDU", "conclude-requestPDU", "conclude-responsePDU",
	"conclude-errorPDU",
}

// String returns the ASN.1 name of the reject reason.
func (r MMSRejectType) String() string {
	if r > 0 && int(r) < len(mmsRejectNames) {
		return mmsRejectNames[r]
	}
	return fmt.Sprintf("Unknown(%d)", uint8(r))
}

// MMSVariableKind is the VariableSpecification CHOICE tag.
type MMSVariableKind uint8

// Variable specification alternatives.
const (
	MMSVariableName        MMSVariableKind = 0
	MMSVariableAddress     MMSVariableKind = 1
	MMSVariableDescription MMSVariableKind = 2
	MMSVariableScattered   MMSVariableKind = 3
	MMSVariableInvalidated MMSVariableKind = 4
)

// String returns the ASN.1 name of the alternative.
func (k MMSVariableKind) String() string {
	switch k {
	case MMSVariableName:
		return "name"
	case MMSVariableAddress:
		return "address"
	case MMSVariableDescription:
		return "variableDescription"
	case MMSVariableScattered:
		return "scatteredAccessDescription"
	case MMSVariableInvalidated:
		return "invalidated"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(k))
	}
}

// MMSAccessKind is the VariableAccessSpecification CHOICE tag.
type MMSAccessKind uint8

// Variable access specification alternatives.
const (
	MMSAccessListOfVariable   MMSAccessKind = 0
	MMSAccessVariableListName MMSAccessKind = 1
)

// String returns the ASN.1 name of the alternative.
func (k MMSAccessKind) String() string {
	switch k {
	case MMSAccessListOfVariable:
		return "listOfVariable"
	case MMSAccessVariableListName:
		return "variableListName"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(k))
	}
}

// MMS field tags, named after the ASN.1 component they introduce.
const (
	mmsTagServiceExt     uint32 = 79
	mmsMaxServiceTag     uint32 = 0xffff
	mmsTagErrInvokeID    uint32 = 0
	mmsTagErrModifier    uint32 = 1
	mmsTagErrService     uint32 = 2
	mmsTagErrClass       uint32 = 0
	mmsTagErrAddCode     uint32 = 1
	mmsTagErrAddDesc     uint32 = 2
	mmsTagRejInvokeID    uint32 = 0
	mmsTagCancelInvokeID uint32 = 0
	mmsTagCancelError    uint32 = 1

	mmsTagInitLocal    uint32 = 0
	mmsTagInitCalling  uint32 = 1
	mmsTagInitCalled   uint32 = 2
	mmsTagInitNesting  uint32 = 3
	mmsTagInitDetail   uint32 = 4
	mmsTagInitVersion  uint32 = 0
	mmsTagInitCBB      uint32 = 1
	mmsTagInitServices uint32 = 2
	mmsTagInitAddSupp  uint32 = 3
	mmsTagInitAddCBB   uint32 = 4
	mmsTagInitPrivCls  uint32 = 5

	mmsTagObjVMD    uint32 = 0
	mmsTagObjDomain uint32 = 1
	mmsTagObjAA     uint32 = 2

	mmsTagListOfVariable uint32 = 0
	mmsTagVarListName    uint32 = 1
	mmsTagAltAccess      uint32 = 5

	mmsTagReadSpecResult uint32 = 0
	mmsTagReadSpec       uint32 = 1
	mmsTagReadRespSpec   uint32 = 0
	mmsTagReadResults    uint32 = 1
	mmsTagListOfData     uint32 = 0
	mmsTagFailure        uint32 = 0
	mmsTagSuccess        uint32 = 1
	mmsTagReportResults  uint32 = 0

	mmsTagGNLClass    uint32 = 0
	mmsTagGNLScope    uint32 = 1
	mmsTagGNLContinue uint32 = 2
	mmsTagGNLBasic    uint32 = 0
	mmsTagGNLCS       uint32 = 1
	mmsTagGNLIDs      uint32 = 0
	mmsTagGNLMore     uint32 = 1

	mmsTagVendor   uint32 = 0
	mmsTagModel    uint32 = 1
	mmsTagRevision uint32 = 2
	mmsTagSyntaxes uint32 = 3
	mmsTagGVAAName uint32 = 0

	mmsTagNVLVariables uint32 = 0
	mmsTagNVLDeletable uint32 = 0
	mmsTagNVLAttrVars  uint32 = 1
)

var (
	errMMSUnknown   = errors.New("MMS: unknown PDU")
	errMMSField     = errors.New("MMS: malformed field")
	errMMSNoService = errors.New("MMS: confirmed PDU without service")
)

// MMSObjectName is an ObjectName: a VMD or AA specific identifier, or a
// domain specific {domainId, itemId} pair. IEC 61850 maps logical devices
// to domains, e.g. {"IED1LD0", "LLN0$ST$Mod$stVal"}.
type MMSObjectName struct {
	Scope    MMSObjectScope
	DomainID string
	ItemID   string
}

// MMSVariable is one listOfVariable entry. Spec always keeps the raw
// VariableSpecification value and AlternateAccess the raw alternate
// access. The name alternative must decode; the others are best effort.
type MMSVariable struct {
	Kind            MMSVariableKind
	Name            MMSObjectName
	Spec            []byte
	AlternateAccess []byte

	// Address is set for the address and variableDescription
	// alternatives, Type for the variableDescription.
	Address MMSAddress
	Type    *MMSTypeSpec
	// Alternate is the decoded AlternateAccess, nil when it is absent or
	// malformed.
	Alternate []MMSAlternateAccess
	// Scattered lists the components of a scatteredAccessDescription, nil
	// when it is malformed or nested too deep.
	Scattered []MMSScatteredComponent
}

// MMSVariableAccess is a VariableAccessSpecification.
type MMSVariableAccess struct {
	Kind      MMSAccessKind
	Variables []MMSVariable
	ListName  MMSObjectName
}

// MMSAccessResult is one AccessResult: Data on success, or a
// DataAccessError when Failed is set.
type MMSAccessResult struct {
	Failed bool
	Error  MMSDataAccessError
	Data   MMSData
}

// MMSWriteResult is one Write-Response entry.
type MMSWriteResult struct {
	Failed bool
	Error  MMSDataAccessError
}

// MMSReadRequest is a Read-Request.
type MMSReadRequest struct {
	SpecificationWithResult bool
	Access                  MMSVariableAccess
}

// MMSReadResponse is a Read-Response. HasAccess tells whether the
// optional variable access specification was returned.
type MMSReadResponse struct {
	HasAccess bool
	Access    MMSVariableAccess
	Results   []MMSAccessResult
}

// MMSWriteRequest is a Write-Request.
type MMSWriteRequest struct {
	Access MMSVariableAccess
	Data   []MMSData
}

// MMSInformationReport is an InformationReport. IEC 61850 reports use a
// variableListName of "RPT" and put the report fields in Results.
type MMSInformationReport struct {
	Access  MMSVariableAccess
	Results []MMSAccessResult
}

// MMSNamedVariableList is a DefineNamedVariableList-Request (Name and
// Variables) or a GetNamedVariableListAttributes-Response (Deletable and
// Variables).
type MMSNamedVariableList struct {
	Name      MMSObjectName
	Deletable bool
	Variables []MMSVariable
}

// MMSGetNameListRequest is a GetNameList-Request. DomainID is set for the
// domain-specific scope.
type MMSGetNameListRequest struct {
	ObjectClass   MMSObjectClass
	Scope         MMSObjectScope
	DomainID      string
	ContinueAfter string

	// CSObjectClass is set, with HasCSObjectClass, when the request names
	// a companion standard class instead of ObjectClass.
	CSObjectClass    MMSCSObjectClass
	HasCSObjectClass bool
}

// MMSGetNameListResponse is a GetNameList-Response.
type MMSGetNameListResponse struct {
	Identifiers []string
	MoreFollows bool
}

// MMSIdentifyResponse is an Identify-Response.
type MMSIdentifyResponse struct {
	Vendor           string
	Model            string
	Revision         string
	AbstractSyntaxes []string
}

// MMSInitiate holds an Initiate-Request or Initiate-Response: proposed
// values in a request, negotiated values in a response.
type MMSInitiate struct {
	LocalDetail               int64
	HasLocalDetail            bool
	MaxServOutstandingCalling int64
	MaxServOutstandingCalled  int64
	NestingLevel              int64
	HasNestingLevel           bool
	Version                   int64
	// ParameterCBB and ServicesSupported are bit strings; services bit n
	// is MMSConfirmedService n (bits 78 and up are unconfirmed services,
	// conclude and cancel).
	ParameterCBB      []byte
	ServicesSupported []byte

	// AdditionalSupported, AdditionalCBB and PrivilegeClass are the ISO
	// 9506-2:2003 detail: additional services bit n is
	// MMSAdditionalKind n, the CBB bits are des, dei and recl.
	AdditionalSupported []byte
	AdditionalCBB       []byte
	PrivilegeClass      string

	// servicesUnused is the BIT STRING padding of ServicesSupported.
	servicesUnused uint8
}

// SupportsService reports whether the services supported bit string
// announces the confirmed service s.
func (in *MMSInitiate) SupportsService(s MMSConfirmedService) bool {
	// Bits past the BIT STRING length are padding, not services.
	n := int(s)
	if n >= len(in.ServicesSupported)*8-int(in.servicesUnused) {
		return false
	}
	return in.ServicesSupported[n/8]&(0x80>>uint(n%8)) != 0
}

// MMSServiceError is a ServiceError: an error class and its code.
type MMSServiceError struct {
	Class          MMSErrorClass
	Code           int64
	AdditionalCode int64
	Description    string
}

// MMSRejectInfo is a RejectPDU.
type MMSRejectInfo struct {
	HasInvokeID bool
	InvokeID    uint32
	Type        MMSRejectType
	Reason      int64
}

// MMS is an ISO 9506 MMSpdu. InvokeID is set for confirmed and cancel
// PDUs. Service and ServiceData are set for confirmed requests and
// responses, Unconfirmed and ServiceData for unconfirmed PDUs. Services
// with a typed decoding also fill the matching pointer field; the others
// only expose ServiceData, the raw service element value.
type MMS struct {
	BaseLayer
	Type        MMSPDUType
	InvokeID    uint32
	Service     MMSConfirmedService
	Unconfirmed MMSUnconfirmedService
	ServiceData []byte
	// NoService is set for a confirmed PDU that ends after its invokeID,
	// or goes on with a service-ext or, in a response, a universal
	// element. The service is mandatory, yet such responses are seen on
	// the wire; Service is then meaningless and ServiceDecodeErr tells
	// why.
	NoService bool

	Initiate          *MMSInitiate
	Error             *MMSServiceError
	ModifierPosition  int64
	Reject            *MMSRejectInfo
	ObjectName        *MMSObjectName
	GetNameListReq    *MMSGetNameListRequest
	GetNameListResp   *MMSGetNameListResponse
	ReadReq           *MMSReadRequest
	ReadResp          *MMSReadResponse
	WriteReq          *MMSWriteRequest
	WriteResp         []MMSWriteResult
	InformationReport *MMSInformationReport
	IdentifyResp      *MMSIdentifyResponse
	NamedVariableList *MMSNamedVariableList

	// The fields below are best effort: a malformed service element
	// leaves them nil and sets ServiceDecodeErr, and the PDU still
	// decodes with its raw ServiceData. ObjectName above is also set for
	// the other requests that are a bare ObjectName, e.g.
	// reportJournalStatus, deleteSemaphore or getNamedTypeAttributes.
	ServiceDecodeErr error
	// ErrorDetail is the serviceSpecificInformation of Error.
	ErrorDetail *MMSErrorDetail
	// VariableAddress is set for a getVariableAccessAttributes request
	// by address.
	VariableAddress      *MMSAddress
	VariableAttributes   *MMSVariableAttributes
	DeleteReq            *MMSDeleteRequest
	DeleteResp           *MMSDeleteResponse
	StatusReq            *MMSStatusRequest
	Status               *MMSVMDStatus
	RenameReq            *MMSRenameRequest
	CapabilityList       *MMSCapabilityList
	DomainReq            *MMSDomainRequest
	DomainResp           *MMSDomainResponse
	ProgramReq           *MMSProgramRequest
	ProgramAttributes    *MMSProgramAttributes
	FileReq              *MMSFileRequest
	FileResp             *MMSFileResponse
	JournalReq           *MMSJournalRequest
	JournalResp          *MMSJournalResponse
	EventCondition       *MMSEventCondition
	EventConditionStatus *MMSEventConditionStatus
	EventNotification    *MMSEventNotification
	EventAck             *MMSEventAck
	AlarmSummaryReq      *MMSAlarmSummaryRequest
	AlarmSummary         *MMSAlarmSummaryResponse

	// Modifiers is the listOfModifier of a confirmed request and
	// ServiceExt the service-ext detail that may follow any service.
	Modifiers  []MMSModifier
	ServiceExt *MMSServiceExt

	NamedVariable     *MMSNamedVariable
	ScatteredAccess   *MMSScatteredAccess
	NamedType         *MMSNamedType
	OperatorReq       *MMSOperatorRequest
	OperatorResp      *MMSOperatorResponse
	SemaphoreReq      *MMSSemaphoreRequest
	SemaphoreResp     *MMSSemaphoreResponse
	EventAlter        *MMSEventAlter
	EventAction       *MMSEventAction
	EventActionStatus *MMSEventActionStatus
	EventEnrollment   *MMSEventEnrollment
	EnrollmentQuery   *MMSEnrollmentQuery
	EnrollmentList    *MMSEnrollmentList
	EnrollmentStatus  *MMSEnrollmentStatus
	EventDeleteReq    *MMSEventDeleteRequest
	EventDeleteResp   *MMSEventDeleteResponse
	Additional        *MMSAdditional
	DataExchange      *MMSDataExchange
	AccessControl     *MMSAccessControl
}

// LayerType returns LayerTypeMMS.
func (m *MMS) LayerType() gopacket.LayerType { return LayerTypeMMS }

// CanDecode returns LayerTypeMMS.
func (m *MMS) CanDecode() gopacket.LayerClass { return LayerTypeMMS }

// NextLayerType returns LayerTypeZero: MMS is the application layer.
func (m *MMS) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// Payload returns nil.
func (m *MMS) Payload() []byte { return nil }

// DecodeFromBytes decodes one MMSpdu.
func (m *MMS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*m = MMS{}

	t, rest, err := osiBERNext(data)
	if err != nil {
		return err
	}
	if t.Class != osiBERContext || t.Tag > uint32(MMSConcludeError) {
		return errMMSUnknown
	}
	m.Type = MMSPDUType(t.Tag)
	m.BaseLayer = BaseLayer{Contents: data[:len(data)-len(rest)]}

	return m.decodePDU(t)
}

// decodePDU dispatches on the MMSpdu alternative.
func (m *MMS) decodePDU(t osiBERTLV) error {
	// cancel-Request/Response are a bare Unsigned32; conclude-Request/
	// Response are NULL. Everything else is constructed.
	switch m.Type {
	case MMSCancelRequest, MMSCancelResponse:
		return m.decodeInvokeID(t, osiBERPrimitive)
	case MMSConcludeRequest, MMSConcludeResponse:
		if t.Form != osiBERPrimitive || len(t.Value) != 0 {
			return errMMSField
		}
		return nil
	}
	if t.Form != osiBERConstructed {
		return errMMSField
	}

	var err error
	switch m.Type {
	case MMSConfirmedRequest, MMSConfirmedResponse:
		err = m.decodeConfirmed(t.Value)
	case MMSConfirmedError:
		err = m.decodeConfirmedError(t.Value)
	case MMSUnconfirmed:
		err = m.decodeUnconfirmed(t.Value)
	case MMSReject:
		m.Reject, err = decodeMMSReject(t.Value)
	case MMSCancelError:
		err = m.decodeCancelError(t.Value)
	case MMSInitiateRequest, MMSInitiateResponse:
		m.Initiate, err = decodeMMSInitiate(t.Value)
	case MMSInitiateError, MMSConcludeError:
		m.Error, err = decodeMMSServiceError(t.Value)
		m.setErrorDetail(t.Value)
	}
	return err
}

// decodeInvokeID reads a bare Unsigned32 invoke ID.
func (m *MMS) decodeInvokeID(t osiBERTLV, form osiBERForm) error {
	if t.Form != form {
		return errMMSField
	}
	var err error
	m.InvokeID, err = osiBERUint32(t.Value)
	return err
}

// decodeConfirmed reads Confirmed-Request/ResponsePDU: invokeID,
// [listOfModifier], service, [service-ext].
func (m *MMS) decodeConfirmed(b []byte) error {
	v, b, err := osiBERExpect(b, osiBERUniversal, osiBERPrimitive, osiBERTagInteger)
	if err != nil {
		return err
	}
	if m.InvokeID, err = osiBERUint32(v); err != nil {
		return err
	}

	// A PDU that stops here lacks its mandatory service. It is kept: the
	// invokeID still tells which request got an empty answer.
	if len(b) == 0 {
		m.setNoService()
		return nil
	}
	t, rest, err := osiBERNext(b)
	if err != nil {
		return err
	}

	// The request's optional listOfModifier.
	if m.Type == MMSConfirmedRequest && t.is(osiBERUniversal, osiBERConstructed, osiBERTagSequence) {
		m.Modifiers, m.ServiceDecodeErr = decodeMMSModifiers(t.Value)
		if t, rest, err = osiBERNext(rest); err != nil {
			return err
		}
	}

	// A response with a universal element in place of its service, e.g.
	// an empty SEQUENCE, is kept like one without.
	if m.Type == MMSConfirmedResponse && t.Class == osiBERUniversal {
		m.setNoService()
		return nil
	}
	if t.Class != osiBERContext || t.Tag > mmsMaxServiceTag {
		return errMMSField
	}

	// A service-ext without service.
	if t.Tag == mmsTagServiceExt {
		m.setNoService()
		m.setServiceExt(t)
		return nil
	}

	m.Service = MMSConfirmedService(t.Tag)
	m.ServiceData = t.Value
	if m.Type == MMSConfirmedRequest {
		err = m.decodeRequest(t)
	} else {
		err = m.decodeResponse(t)
	}
	if err != nil {
		return err
	}

	m.decodeServiceExt(rest)
	return nil
}

// setNoService marks a confirmed PDU without service.
func (m *MMS) setNoService() {
	m.NoService = true
	m.softErr(errMMSNoService)
}

// softErr records the first error of the best effort decoders.
func (m *MMS) softErr(err error) {
	if m.ServiceDecodeErr == nil {
		m.ServiceDecodeErr = err
	}
}

// decodeRequest decodes the confirmed services with a typed request.
func (m *MMS) decodeRequest(t osiBERTLV) error {
	var err error
	switch m.Service {
	case MMSGetNameList:
		m.GetNameListReq, err = decodeMMSGetNameListReq(t.Value)
	case MMSRead:
		m.ReadReq, err = decodeMMSReadReq(t.Value)
	case MMSWrite:
		m.WriteReq, err = decodeMMSWriteReq(t.Value)
	case MMSGetVariableAccessAttributes:
		m.ObjectName, err = decodeMMSGVAAReq(t.Value)
		if err == nil && m.ObjectName == nil {
			var aerr error
			m.VariableAddress, aerr = decodeMMSGVAAAddr(t.Value)
			m.softErr(aerr)
		}
	case MMSGetNamedVariableListAttributes:
		var n MMSObjectName
		n, err = decodeMMSObjectNameIn(t.Value)
		m.ObjectName = &n
	case MMSDefineNamedVariableList:
		m.NamedVariableList, err = decodeMMSDefineNVL(t.Value)
	default:
		m.softErr(m.decodeMoreReq(t))
		return nil
	}

	// Every typed service element is constructed.
	if err == nil && t.Form != osiBERConstructed {
		return errMMSField
	}
	return err
}

// decodeResponse decodes the confirmed services with a typed response.
func (m *MMS) decodeResponse(t osiBERTLV) error {
	var err error
	switch m.Service {
	case MMSGetNameList:
		m.GetNameListResp, err = decodeMMSGetNameListResp(t.Value)
	case MMSRead:
		m.ReadResp, err = decodeMMSReadResp(t.Value)
	case MMSWrite:
		m.WriteResp, err = decodeMMSWriteResp(t.Value)
	case MMSIdentify:
		m.IdentifyResp, err = decodeMMSIdentifyResp(t.Value)
	case MMSGetNamedVariableListAttributes:
		m.NamedVariableList, err = decodeMMSGetNVLAResp(t.Value)
	default:
		m.softErr(m.decodeMoreResp(t))
		return nil
	}

	// Every typed service element is constructed.
	if err == nil && t.Form != osiBERConstructed {
		return errMMSField
	}
	return err
}

// decodeConfirmedError reads Confirmed-ErrorPDU: [0] invokeID,
// [1] modifierPosition OPTIONAL, [2] ServiceError.
func (m *MMS) decodeConfirmedError(b []byte) error {
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERPrimitive, mmsTagErrInvokeID):
			m.InvokeID, err = osiBERUint32(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagErrModifier):
			m.ModifierPosition, err = osiBERInt(t.Value)
		case t.is(osiBERContext, osiBERConstructed, mmsTagErrService):
			m.Error, err = decodeMMSServiceError(t.Value)
			m.setErrorDetail(t.Value)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// decodeCancelError reads Cancel-ErrorPDU: [0] invokeID, [1] ServiceError.
func (m *MMS) decodeCancelError(b []byte) error {
	v, b, err := osiBERExpect(b, osiBERContext, osiBERPrimitive, mmsTagCancelInvokeID)
	if err != nil {
		return err
	}
	if m.InvokeID, err = osiBERUint32(v); err != nil {
		return err
	}

	v, _, err = osiBERExpect(b, osiBERContext, osiBERConstructed, mmsTagCancelError)
	if err != nil {
		return err
	}
	m.Error, err = decodeMMSServiceError(v)
	m.setErrorDetail(v)
	return err
}

// decodeUnconfirmed reads Unconfirmed-PDU: service, [service-ext].
func (m *MMS) decodeUnconfirmed(b []byte) error {
	t, rest, err := osiBERNext(b)
	if err != nil {
		return err
	}
	if t.Class != osiBERContext || t.Form != osiBERConstructed || t.Tag > uint32(MMSUnconfirmedEvent) {
		return errMMSField
	}

	m.Unconfirmed = MMSUnconfirmedService(t.Tag)
	m.ServiceData = t.Value
	switch m.Unconfirmed {
	case MMSUnconfirmedInfoReport:
		m.InformationReport, err = decodeMMSReport(t.Value)
	case MMSUnconfirmedStatus:
		m.Status, m.ServiceDecodeErr = decodeMMSStatus(t)
	case MMSUnconfirmedEvent:
		m.EventNotification, m.ServiceDecodeErr = decodeMMSEventNotif(t)
	}
	if err != nil {
		return err
	}

	m.decodeServiceExt(rest)
	return nil
}

// decodeMMSServiceError reads ServiceError: errorClass [0] CHOICE,
// additionalCode [1], additionalDescription [2], [3] ignored.
func decodeMMSServiceError(b []byte) (*MMSServiceError, error) {
	e := &MMSServiceError{}
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERConstructed, mmsTagErrClass):
			var c osiBERTLV
			if c, err = osiBERSingle(t.Value); err != nil {
				return nil, err
			}
			if c.Class != osiBERContext || c.Tag > uint32(MMSErrorOthers) {
				return nil, errMMSField
			}
			e.Class = MMSErrorClass(c.Tag)
			e.Code, err = osiBERInt(c.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagErrAddCode):
			e.AdditionalCode, err = osiBERInt(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagErrAddDesc):
			e.Description = string(t.Value)
		}
		if err != nil {
			return nil, err
		}
	}
	return e, nil
}

// decodeMMSReject reads RejectPDU: [0] originalInvokeID OPTIONAL and a
// rejectReason CHOICE [1..11] INTEGER.
func decodeMMSReject(b []byte) (*MMSRejectInfo, error) {
	r := &MMSRejectInfo{}
	t, rest, err := osiBERNext(b)
	if err != nil {
		return nil, err
	}
	if t.is(osiBERContext, osiBERPrimitive, mmsTagRejInvokeID) {
		if r.InvokeID, err = osiBERUint32(t.Value); err != nil {
			return nil, err
		}
		r.HasInvokeID = true
		if t, _, err = osiBERNext(rest); err != nil {
			return nil, err
		}
	}

	if t.Class != osiBERContext || t.Form != osiBERPrimitive || t.Tag < uint32(MMSRejectConfirmedRequest) || t.Tag > uint32(MMSRejectConcludeError) {
		return nil, errMMSField
	}
	r.Type = MMSRejectType(t.Tag)
	r.Reason, err = osiBERInt(t.Value)
	return r, err
}

// decodeMMSInitiate reads Initiate-Request/ResponsePDU.
func decodeMMSInitiate(b []byte) (*MMSInitiate, error) {
	in := &MMSInitiate{}
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERPrimitive, mmsTagInitLocal):
			in.LocalDetail, err = osiBERInt(t.Value)
			in.HasLocalDetail = true
		case t.is(osiBERContext, osiBERPrimitive, mmsTagInitCalling):
			in.MaxServOutstandingCalling, err = osiBERInt(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagInitCalled):
			in.MaxServOutstandingCalled, err = osiBERInt(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagInitNesting):
			in.NestingLevel, err = osiBERInt(t.Value)
			in.HasNestingLevel = true
		case t.is(osiBERContext, osiBERConstructed, mmsTagInitDetail):
			err = in.decodeDetail(t.Value)
		}
		if err != nil {
			return nil, err
		}
	}
	return in, nil
}

// decodeDetail reads InitRequestDetail / InitResponseDetail.
func (in *MMSInitiate) decodeDetail(b []byte) error {
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERPrimitive, mmsTagInitVersion):
			in.Version, err = osiBERInt(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagInitCBB):
			in.ParameterCBB, _, err = osiBERBits(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagInitServices):
			in.ServicesSupported, in.servicesUnused, err = osiBERBits(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagInitAddSupp):
			// Best effort: these two were skipped before they were read.
			in.AdditionalSupported, _, _ = osiBERBits(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagInitAddCBB):
			in.AdditionalCBB, _, _ = osiBERBits(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagInitPrivCls):
			in.PrivilegeClass = string(t.Value)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// decodeMMSObjectName decodes an ObjectName CHOICE element.
func decodeMMSObjectName(t osiBERTLV) (MMSObjectName, error) {
	var n MMSObjectName
	switch {
	case t.is(osiBERContext, osiBERPrimitive, mmsTagObjVMD):
		n.Scope = MMSScopeVMD
		n.ItemID = string(t.Value)
	case t.is(osiBERContext, osiBERPrimitive, mmsTagObjAA):
		n.Scope = MMSScopeAA
		n.ItemID = string(t.Value)
	case t.is(osiBERContext, osiBERConstructed, mmsTagObjDomain):
		n.Scope = MMSScopeDomain
		v, rest, err := osiBERExpect(t.Value, osiBERUniversal, osiBERPrimitive, osiBERTagVisible)
		if err != nil {
			return n, err
		}
		n.DomainID = string(v)
		if v, _, err = osiBERExpect(rest, osiBERUniversal, osiBERPrimitive, osiBERTagVisible); err != nil {
			return n, err
		}
		n.ItemID = string(v)
	default:
		return n, errMMSField
	}
	return n, nil
}

// decodeMMSObjectNameIn decodes the ObjectName that fills b, as found
// under an EXPLICIT tag.
func decodeMMSObjectNameIn(b []byte) (MMSObjectName, error) {
	t, err := osiBERSingle(b)
	if err != nil {
		return MMSObjectName{}, err
	}
	return decodeMMSObjectName(t)
}

// decodeMMSAccess decodes a VariableAccessSpecification CHOICE element:
// [0] listOfVariable or [1] variableListName.
func decodeMMSAccess(t osiBERTLV) (MMSVariableAccess, error) {
	var a MMSVariableAccess
	if t.Class != osiBERContext || t.Form != osiBERConstructed {
		return a, errMMSField
	}

	var err error
	switch t.Tag {
	case mmsTagListOfVariable:
		a.Kind = MMSAccessListOfVariable
		a.Variables, err = decodeMMSVariables(t.Value)
	case mmsTagVarListName:
		a.Kind = MMSAccessVariableListName
		a.ListName, err = decodeMMSObjectNameIn(t.Value)
	default:
		err = errMMSField
	}
	return a, err
}

// decodeMMSVariables decodes listOfVariable: SEQUENCE OF SEQUENCE {
// VariableSpecification, alternateAccess [5] OPTIONAL }.
func decodeMMSVariables(b []byte) ([]MMSVariable, error) {
	count, err := osiBERCount(b)
	if err != nil || count == 0 {
		return nil, err
	}

	out := make([]MMSVariable, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		spec, more, err := osiBERNext(item)
		if err != nil {
			return nil, err
		}
		v, err := decodeMMSVarSpec(spec)
		if err != nil {
			return nil, err
		}

		if len(more) > 0 {
			alt, _, err := osiBERExpect(more, osiBERContext, osiBERConstructed, mmsTagAltAccess)
			if err != nil {
				return nil, err
			}
			v.AlternateAccess = alt

			// Best effort: a malformed access only keeps the raw octets.
			v.Alternate, _ = decodeMMSAltAccess(alt, 0)
		}
		out = append(out, v)
	}
	return out, nil
}

// decodeMMSResults decodes a SEQUENCE OF AccessResult body: [0] failure
// DataAccessError, or a Data value (whose tags start at [1]).
func decodeMMSResults(b []byte) ([]MMSAccessResult, error) {
	var out []MMSAccessResult
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		var r MMSAccessResult
		if t.is(osiBERContext, osiBERPrimitive, mmsTagFailure) {
			code, err := osiBERUint(t.Value)
			if err != nil || code > uint64(MMSObjectValueInvalid) {
				return nil, errMMSField
			}
			r.Failed = true
			r.Error = MMSDataAccessError(code)
		} else if r.Data, err = decodeMMSData(t, 0); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// decodeMMSReadReq reads Read-Request: [0] specificationWithResult
// OPTIONAL, [1] EXPLICIT VariableAccessSpecification.
func decodeMMSReadReq(b []byte) (*MMSReadRequest, error) {
	r := &MMSReadRequest{}
	t, rest, err := osiBERNext(b)
	if err != nil {
		return nil, err
	}
	if t.is(osiBERContext, osiBERPrimitive, mmsTagReadSpecResult) {
		if r.SpecificationWithResult, err = osiBERBool(t.Value); err != nil {
			return nil, err
		}
		if t, _, err = osiBERNext(rest); err != nil {
			return nil, err
		}
	}
	if !t.is(osiBERContext, osiBERConstructed, mmsTagReadSpec) {
		return nil, errMMSField
	}

	inner, err := osiBERSingle(t.Value)
	if err != nil {
		return nil, err
	}
	r.Access, err = decodeMMSAccess(inner)
	return r, err
}

// decodeMMSReadResp reads Read-Response: [0] EXPLICIT
// VariableAccessSpecification OPTIONAL, [1] listOfAccessResult.
func decodeMMSReadResp(b []byte) (*MMSReadResponse, error) {
	r := &MMSReadResponse{}
	t, rest, err := osiBERNext(b)
	if err != nil {
		return nil, err
	}
	if t.is(osiBERContext, osiBERConstructed, mmsTagReadRespSpec) {
		inner, err := osiBERSingle(t.Value)
		if err != nil {
			return nil, err
		}
		if r.Access, err = decodeMMSAccess(inner); err != nil {
			return nil, err
		}
		r.HasAccess = true
		if t, _, err = osiBERNext(rest); err != nil {
			return nil, err
		}
	}
	if !t.is(osiBERContext, osiBERConstructed, mmsTagReadResults) {
		return nil, errMMSField
	}

	r.Results, err = decodeMMSResults(t.Value)
	return r, err
}

// decodeMMSWriteReq reads Write-Request: VariableAccessSpecification,
// [0] listOfData.
func decodeMMSWriteReq(b []byte) (*MMSWriteRequest, error) {
	w := &MMSWriteRequest{}
	t, rest, err := osiBERNext(b)
	if err != nil {
		return nil, err
	}
	if w.Access, err = decodeMMSAccess(t); err != nil {
		return nil, err
	}

	v, _, err := osiBERExpect(rest, osiBERContext, osiBERConstructed, mmsTagListOfData)
	if err != nil {
		return nil, err
	}
	w.Data, err = decodeMMSDataList(v, 0)
	return w, err
}

// decodeMMSWriteResp reads Write-Response: SEQUENCE OF CHOICE {
// failure [0] DataAccessError, success [1] NULL }.
func decodeMMSWriteResp(b []byte) ([]MMSWriteResult, error) {
	out := []MMSWriteResult{}
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERPrimitive, mmsTagSuccess) && len(t.Value) == 0:
			out = append(out, MMSWriteResult{})
		case t.is(osiBERContext, osiBERPrimitive, mmsTagFailure):
			code, err := osiBERUint(t.Value)
			if err != nil || code > uint64(MMSObjectValueInvalid) {
				return nil, errMMSField
			}
			out = append(out, MMSWriteResult{Failed: true, Error: MMSDataAccessError(code)})
		default:
			return nil, errMMSField
		}
	}
	return out, nil
}

// decodeMMSReport reads InformationReport: VariableAccessSpecification,
// [0] listOfAccessResult.
func decodeMMSReport(b []byte) (*MMSInformationReport, error) {
	r := &MMSInformationReport{}
	t, rest, err := osiBERNext(b)
	if err != nil {
		return nil, err
	}
	if r.Access, err = decodeMMSAccess(t); err != nil {
		return nil, err
	}

	v, _, err := osiBERExpect(rest, osiBERContext, osiBERConstructed, mmsTagReportResults)
	if err != nil {
		return nil, err
	}
	r.Results, err = decodeMMSResults(v)
	return r, err
}

// decodeMMSGetNameListReq reads GetNameList-Request: [0] objectClass,
// [1] objectScope, [2] continueAfter OPTIONAL.
func decodeMMSGetNameListReq(b []byte) (*MMSGetNameListRequest, error) {
	g := &MMSGetNameListRequest{}
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERConstructed, mmsTagGNLClass):
			err = g.decodeClass(t.Value)
		case t.is(osiBERContext, osiBERConstructed, mmsTagGNLScope):
			err = g.decodeScope(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagGNLContinue):
			g.ContinueAfter = string(t.Value)
		}
		if err != nil {
			return nil, err
		}
	}
	return g, nil
}

// decodeClass reads ObjectClass: basicObjectClass [0] INTEGER or
// csObjectClass [1] INTEGER.
func (g *MMSGetNameListRequest) decodeClass(b []byte) error {
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}
	if t.Class != osiBERContext || t.Form != osiBERPrimitive || t.Tag > mmsTagGNLCS {
		return nil
	}

	c, err := osiBERUint(t.Value)
	if err != nil || c > 0xff {
		return errMMSField
	}
	if t.Tag == mmsTagGNLCS {
		g.CSObjectClass, g.HasCSObjectClass = MMSCSObjectClass(c), true
		return nil
	}
	g.ObjectClass = MMSObjectClass(c)
	return nil
}

// decodeScope reads objectScope: vmdSpecific [0] NULL, domainSpecific
// [1] Identifier or aaSpecific [2] NULL.
func (g *MMSGetNameListRequest) decodeScope(b []byte) error {
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}
	if t.Class != osiBERContext || t.Form != osiBERPrimitive || t.Tag > uint32(MMSScopeAA) {
		return errMMSField
	}

	g.Scope = MMSObjectScope(t.Tag)
	if g.Scope == MMSScopeDomain {
		g.DomainID = string(t.Value)
	}
	return nil
}

// decodeMMSGetNameListResp reads GetNameList-Response: [0] listOfIdentifier,
// [1] moreFollows DEFAULT TRUE.
func decodeMMSGetNameListResp(b []byte) (*MMSGetNameListResponse, error) {
	g := &MMSGetNameListResponse{MoreFollows: true}
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERConstructed, mmsTagGNLIDs):
			g.Identifiers, err = decodeMMSIdentifiers(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagGNLMore):
			g.MoreFollows, err = osiBERBool(t.Value)
		}
		if err != nil {
			return nil, err
		}
	}
	return g, nil
}

// decodeMMSIdentifiers decodes a SEQUENCE OF Identifier body.
func decodeMMSIdentifiers(b []byte) ([]string, error) {
	out := []string{}
	for len(b) > 0 {
		v, rest, err := osiBERExpect(b, osiBERUniversal, osiBERPrimitive, osiBERTagVisible)
		if err != nil {
			return nil, err
		}
		b = rest
		out = append(out, string(v))
	}
	return out, nil
}

// decodeMMSIdentifyResp reads Identify-Response: [0] vendorName,
// [1] modelName, [2] revision, [3] listOfAbstractSyntaxes OPTIONAL.
func decodeMMSIdentifyResp(b []byte) (*MMSIdentifyResponse, error) {
	r := &MMSIdentifyResponse{}
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERPrimitive, mmsTagVendor):
			r.Vendor = string(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagModel):
			r.Model = string(t.Value)
		case t.is(osiBERContext, osiBERPrimitive, mmsTagRevision):
			r.Revision = string(t.Value)
		case t.is(osiBERContext, osiBERConstructed, mmsTagSyntaxes):
			r.AbstractSyntaxes, err = decodeISOPresOIDs(t.Value)
		}
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// decodeMMSGVAAReq reads GetVariableAccessAttributes-Request: name [0]
// ObjectName or address [1]; only the name is decoded.
func decodeMMSGVAAReq(b []byte) (*MMSObjectName, error) {
	t, err := osiBERSingle(b)
	if err != nil {
		return nil, err
	}
	if !t.is(osiBERContext, osiBERConstructed, mmsTagGVAAName) {
		return nil, nil
	}

	n, err := decodeMMSObjectNameIn(t.Value)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// decodeMMSDefineNVL reads DefineNamedVariableList-Request: ObjectName,
// [0] listOfVariable.
func decodeMMSDefineNVL(b []byte) (*MMSNamedVariableList, error) {
	l := &MMSNamedVariableList{}
	t, rest, err := osiBERNext(b)
	if err != nil {
		return nil, err
	}
	if l.Name, err = decodeMMSObjectName(t); err != nil {
		return nil, err
	}

	v, _, err := osiBERExpect(rest, osiBERContext, osiBERConstructed, mmsTagNVLVariables)
	if err != nil {
		return nil, err
	}
	l.Variables, err = decodeMMSVariables(v)
	return l, err
}

// decodeMMSGetNVLAResp reads GetNamedVariableListAttributes-Response:
// [0] mmsDeletable, [1] listOfVariable, [2] accessControlList ignored.
func decodeMMSGetNVLAResp(b []byte) (*MMSNamedVariableList, error) {
	l := &MMSNamedVariableList{}
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return nil, err
		}
		b = rest

		switch {
		case t.is(osiBERContext, osiBERPrimitive, mmsTagNVLDeletable):
			l.Deletable, err = osiBERBool(t.Value)
		case t.is(osiBERContext, osiBERConstructed, mmsTagNVLAttrVars):
			l.Variables, err = decodeMMSVariables(t.Value)
		}
		if err != nil {
			return nil, err
		}
	}
	return l, nil
}

func decodeMMS(data []byte, p gopacket.PacketBuilder) error {
	m := &MMS{}
	if err := m.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(m)
	p.SetApplicationLayer(m)
	return nil
}
