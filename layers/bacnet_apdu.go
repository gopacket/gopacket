// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// BACnet application layer (ASHRAE 135 Clause 20.1, 21).

package layers

import (
	"fmt"

	"github.com/gopacket/gopacket"
)

// APDU header layout (Clause 20.1).
const (
	bacnetPDUTypeShift     = 4
	bacnetPDUFlagSEG       = 0x08 // segmented message
	bacnetPDUFlagMOR       = 0x04 // more follows
	bacnetPDUFlagSA        = 0x02 // segmented response accepted
	bacnetPDUFlagNAK       = 0x02 // segment ACK is negative
	bacnetPDUFlagSRV       = 0x01 // sent by the server
	bacnetMaxSegmentsShift = 4
	bacnetMaxSegmentsMask  = 0x07
	bacnetMaxAPDUMask      = 0x0F
	bacnetSegmentHeaderLen = 2 // sequence number + window size

	// Context tags that bracket the vendor block of a private transfer
	// and of its Error.
	bacnetPrivateBlockTag      uint8 = 2
	bacnetPrivateErrorBlockTag uint8 = 3
	// bacnetPrivateMaxTags is the most tags around a vendor block: those
	// of an Error and its brackets.
	bacnetPrivateMaxTags = 8
)

// BACnetPDUType is the APDU type (Clause 20.1.1).
type BACnetPDUType uint8

// BACnetPDUType values.
const (
	BACnetPDUConfirmedRequest   BACnetPDUType = 0
	BACnetPDUUnconfirmedRequest BACnetPDUType = 1
	BACnetPDUSimpleACK          BACnetPDUType = 2
	BACnetPDUComplexACK         BACnetPDUType = 3
	BACnetPDUSegmentACK         BACnetPDUType = 4
	BACnetPDUError              BACnetPDUType = 5
	BACnetPDUReject             BACnetPDUType = 6
	BACnetPDUAbort              BACnetPDUType = 7
)

var bacnetPDUTypeNames = map[BACnetPDUType]string{
	BACnetPDUConfirmedRequest:   "Confirmed-Request",
	BACnetPDUUnconfirmedRequest: "Unconfirmed-Request",
	BACnetPDUSimpleACK:          "SimpleACK",
	BACnetPDUComplexACK:         "ComplexACK",
	BACnetPDUSegmentACK:         "SegmentACK",
	BACnetPDUError:              "Error",
	BACnetPDUReject:             "Reject",
	BACnetPDUAbort:              "Abort",
}

// String returns the Clause 20 name of the PDU type.
func (t BACnetPDUType) String() string { return bacnetName(bacnetPDUTypeNames, t) }

// BACnetMaxSegments is the encoded number of segments a client accepts
// in a response (Clause 20.1.2.4).
type BACnetMaxSegments uint8

// BACnetMaxSegments values.
const (
	BACnetMaxSegmentsUnspecified BACnetMaxSegments = 0
	BACnetMaxSegments2           BACnetMaxSegments = 1
	BACnetMaxSegments4           BACnetMaxSegments = 2
	BACnetMaxSegments8           BACnetMaxSegments = 3
	BACnetMaxSegments16          BACnetMaxSegments = 4
	BACnetMaxSegments32          BACnetMaxSegments = 5
	BACnetMaxSegments64          BACnetMaxSegments = 6
	BACnetMaxSegmentsMore64      BACnetMaxSegments = 7
)

// Segments returns the number of segments, 0 when unspecified and -1 for
// more than 64.
func (m BACnetMaxSegments) Segments() int {
	switch m {
	case BACnetMaxSegmentsUnspecified:
		return 0
	case BACnetMaxSegmentsMore64:
		return -1
	}
	return 1 << uint(m)
}

// String returns the segment count.
func (m BACnetMaxSegments) String() string {
	switch m {
	case BACnetMaxSegmentsUnspecified:
		return "Unspecified"
	case BACnetMaxSegmentsMore64:
		return "Greater than 64 segments"
	}
	return fmt.Sprintf("%d segments", m.Segments())
}

// BACnetMaxAPDU is the encoded maximum APDU length a client accepts
// (Clause 20.1.2.5).
type BACnetMaxAPDU uint8

// BACnetMaxAPDU values.
const (
	BACnetMaxAPDU50   BACnetMaxAPDU = 0
	BACnetMaxAPDU128  BACnetMaxAPDU = 1
	BACnetMaxAPDU206  BACnetMaxAPDU = 2
	BACnetMaxAPDU480  BACnetMaxAPDU = 3
	BACnetMaxAPDU1024 BACnetMaxAPDU = 4
	BACnetMaxAPDU1476 BACnetMaxAPDU = 5
)

var bacnetMaxAPDUOctets = map[BACnetMaxAPDU]int{
	BACnetMaxAPDU50:   50,
	BACnetMaxAPDU128:  128,
	BACnetMaxAPDU206:  206,
	BACnetMaxAPDU480:  480,
	BACnetMaxAPDU1024: 1024,
	BACnetMaxAPDU1476: 1476,
}

// Octets returns the length in octets, or 0 for a reserved value.
func (m BACnetMaxAPDU) Octets() int { return bacnetMaxAPDUOctets[m] }

// String returns the length in octets.
func (m BACnetMaxAPDU) String() string {
	if n := m.Octets(); n != 0 {
		return fmt.Sprintf("Up to %d octets", n)
	}
	return fmt.Sprintf("Reserved(%d)", uint8(m))
}

// BACnetConfirmedService is a confirmed service choice (Clause 21).
type BACnetConfirmedService uint8

// BACnetConfirmedService values.
const (
	BACnetConfirmedServiceAcknowledgeAlarm                 BACnetConfirmedService = 0
	BACnetConfirmedServiceConfirmedCOVNotification         BACnetConfirmedService = 1
	BACnetConfirmedServiceConfirmedEventNotification       BACnetConfirmedService = 2
	BACnetConfirmedServiceGetAlarmSummary                  BACnetConfirmedService = 3
	BACnetConfirmedServiceGetEnrollmentSummary             BACnetConfirmedService = 4
	BACnetConfirmedServiceSubscribeCOV                     BACnetConfirmedService = 5
	BACnetConfirmedServiceAtomicReadFile                   BACnetConfirmedService = 6
	BACnetConfirmedServiceAtomicWriteFile                  BACnetConfirmedService = 7
	BACnetConfirmedServiceAddListElement                   BACnetConfirmedService = 8
	BACnetConfirmedServiceRemoveListElement                BACnetConfirmedService = 9
	BACnetConfirmedServiceCreateObject                     BACnetConfirmedService = 10
	BACnetConfirmedServiceDeleteObject                     BACnetConfirmedService = 11
	BACnetConfirmedServiceReadProperty                     BACnetConfirmedService = 12
	BACnetConfirmedServiceReadPropertyConditional          BACnetConfirmedService = 13
	BACnetConfirmedServiceReadPropertyMultiple             BACnetConfirmedService = 14
	BACnetConfirmedServiceWriteProperty                    BACnetConfirmedService = 15
	BACnetConfirmedServiceWritePropertyMultiple            BACnetConfirmedService = 16
	BACnetConfirmedServiceDeviceCommunicationControl       BACnetConfirmedService = 17
	BACnetConfirmedServiceConfirmedPrivateTransfer         BACnetConfirmedService = 18
	BACnetConfirmedServiceConfirmedTextMessage             BACnetConfirmedService = 19
	BACnetConfirmedServiceReinitializeDevice               BACnetConfirmedService = 20
	BACnetConfirmedServiceVTOpen                           BACnetConfirmedService = 21
	BACnetConfirmedServiceVTClose                          BACnetConfirmedService = 22
	BACnetConfirmedServiceVTData                           BACnetConfirmedService = 23
	BACnetConfirmedServiceAuthenticate                     BACnetConfirmedService = 24
	BACnetConfirmedServiceRequestKey                       BACnetConfirmedService = 25
	BACnetConfirmedServiceReadRange                        BACnetConfirmedService = 26
	BACnetConfirmedServiceLifeSafetyOperation              BACnetConfirmedService = 27
	BACnetConfirmedServiceSubscribeCOVProperty             BACnetConfirmedService = 28
	BACnetConfirmedServiceGetEventInformation              BACnetConfirmedService = 29
	BACnetConfirmedServiceSubscribeCOVPropertyMultiple     BACnetConfirmedService = 30
	BACnetConfirmedServiceConfirmedCOVNotificationMultiple BACnetConfirmedService = 31
	BACnetConfirmedServiceConfirmedAuditNotification       BACnetConfirmedService = 32
	BACnetConfirmedServiceAuditLogQuery                    BACnetConfirmedService = 33
	BACnetConfirmedServiceAuthRequest                      BACnetConfirmedService = 34
)

var bacnetConfirmedServiceNames = map[BACnetConfirmedService]string{
	BACnetConfirmedServiceAcknowledgeAlarm:                 "acknowledgeAlarm",
	BACnetConfirmedServiceConfirmedCOVNotification:         "confirmedCOVNotification",
	BACnetConfirmedServiceConfirmedEventNotification:       "confirmedEventNotification",
	BACnetConfirmedServiceGetAlarmSummary:                  "getAlarmSummary",
	BACnetConfirmedServiceGetEnrollmentSummary:             "getEnrollmentSummary",
	BACnetConfirmedServiceSubscribeCOV:                     "subscribeCOV",
	BACnetConfirmedServiceAtomicReadFile:                   "atomicReadFile",
	BACnetConfirmedServiceAtomicWriteFile:                  "atomicWriteFile",
	BACnetConfirmedServiceAddListElement:                   "addListElement",
	BACnetConfirmedServiceRemoveListElement:                "removeListElement",
	BACnetConfirmedServiceCreateObject:                     "createObject",
	BACnetConfirmedServiceDeleteObject:                     "deleteObject",
	BACnetConfirmedServiceReadProperty:                     "readProperty",
	BACnetConfirmedServiceReadPropertyConditional:          "readPropertyConditional",
	BACnetConfirmedServiceReadPropertyMultiple:             "readPropertyMultiple",
	BACnetConfirmedServiceWriteProperty:                    "writeProperty",
	BACnetConfirmedServiceWritePropertyMultiple:            "writePropertyMultiple",
	BACnetConfirmedServiceDeviceCommunicationControl:       "deviceCommunicationControl",
	BACnetConfirmedServiceConfirmedPrivateTransfer:         "confirmedPrivateTransfer",
	BACnetConfirmedServiceConfirmedTextMessage:             "confirmedTextMessage",
	BACnetConfirmedServiceReinitializeDevice:               "reinitializeDevice",
	BACnetConfirmedServiceVTOpen:                           "vtOpen",
	BACnetConfirmedServiceVTClose:                          "vtClose",
	BACnetConfirmedServiceVTData:                           "vtData",
	BACnetConfirmedServiceAuthenticate:                     "authenticate",
	BACnetConfirmedServiceRequestKey:                       "requestKey",
	BACnetConfirmedServiceReadRange:                        "readRange",
	BACnetConfirmedServiceLifeSafetyOperation:              "lifeSafetyOperation",
	BACnetConfirmedServiceSubscribeCOVProperty:             "subscribeCOVProperty",
	BACnetConfirmedServiceGetEventInformation:              "getEventInformation",
	BACnetConfirmedServiceSubscribeCOVPropertyMultiple:     "subscribeCOVPropertyMultiple",
	BACnetConfirmedServiceConfirmedCOVNotificationMultiple: "confirmedCOVNotificationMultiple",
	BACnetConfirmedServiceConfirmedAuditNotification:       "confirmedAuditNotification",
	BACnetConfirmedServiceAuditLogQuery:                    "auditLogQuery",
	BACnetConfirmedServiceAuthRequest:                      "authRequest",
}

// String returns the Clause 21 name of the service.
func (s BACnetConfirmedService) String() string { return bacnetName(bacnetConfirmedServiceNames, s) }

// BACnetUnconfirmedService is an unconfirmed service choice (Clause 21).
type BACnetUnconfirmedService uint8

// BACnetUnconfirmedService values.
const (
	BACnetUnconfirmedServiceIAm                                BACnetUnconfirmedService = 0
	BACnetUnconfirmedServiceIHave                              BACnetUnconfirmedService = 1
	BACnetUnconfirmedServiceUnconfirmedCOVNotification         BACnetUnconfirmedService = 2
	BACnetUnconfirmedServiceUnconfirmedEventNotification       BACnetUnconfirmedService = 3
	BACnetUnconfirmedServiceUnconfirmedPrivateTransfer         BACnetUnconfirmedService = 4
	BACnetUnconfirmedServiceUnconfirmedTextMessage             BACnetUnconfirmedService = 5
	BACnetUnconfirmedServiceTimeSynchronization                BACnetUnconfirmedService = 6
	BACnetUnconfirmedServiceWhoHas                             BACnetUnconfirmedService = 7
	BACnetUnconfirmedServiceWhoIs                              BACnetUnconfirmedService = 8
	BACnetUnconfirmedServiceUTCTimeSynchronization             BACnetUnconfirmedService = 9
	BACnetUnconfirmedServiceWriteGroup                         BACnetUnconfirmedService = 10
	BACnetUnconfirmedServiceUnconfirmedCOVNotificationMultiple BACnetUnconfirmedService = 11
	BACnetUnconfirmedServiceUnconfirmedAuditNotification       BACnetUnconfirmedService = 12
	BACnetUnconfirmedServiceWhoAmI                             BACnetUnconfirmedService = 13
	BACnetUnconfirmedServiceYouAre                             BACnetUnconfirmedService = 14
)

var bacnetUnconfirmedServiceNames = map[BACnetUnconfirmedService]string{
	BACnetUnconfirmedServiceIAm:                                "i-Am",
	BACnetUnconfirmedServiceIHave:                              "i-Have",
	BACnetUnconfirmedServiceUnconfirmedCOVNotification:         "unconfirmedCOVNotification",
	BACnetUnconfirmedServiceUnconfirmedEventNotification:       "unconfirmedEventNotification",
	BACnetUnconfirmedServiceUnconfirmedPrivateTransfer:         "unconfirmedPrivateTransfer",
	BACnetUnconfirmedServiceUnconfirmedTextMessage:             "unconfirmedTextMessage",
	BACnetUnconfirmedServiceTimeSynchronization:                "timeSynchronization",
	BACnetUnconfirmedServiceWhoHas:                             "who-Has",
	BACnetUnconfirmedServiceWhoIs:                              "who-Is",
	BACnetUnconfirmedServiceUTCTimeSynchronization:             "utcTimeSynchronization",
	BACnetUnconfirmedServiceWriteGroup:                         "writeGroup",
	BACnetUnconfirmedServiceUnconfirmedCOVNotificationMultiple: "unconfirmedCOVNotificationMultiple",
	BACnetUnconfirmedServiceUnconfirmedAuditNotification:       "unconfirmedAuditNotification",
	BACnetUnconfirmedServiceWhoAmI:                             "who-Am-I",
	BACnetUnconfirmedServiceYouAre:                             "you-Are",
}

// String returns the Clause 21 name of the service.
func (s BACnetUnconfirmedService) String() string {
	return bacnetName(bacnetUnconfirmedServiceNames, s)
}

// BACnetRejectReason is the reason of a Reject PDU (Clause 18.8).
// Values from 64 are proprietary.
type BACnetRejectReason uint8

// BACnetRejectReason values.
const (
	BACnetRejectOther                    BACnetRejectReason = 0
	BACnetRejectBufferOverflow           BACnetRejectReason = 1
	BACnetRejectInconsistentParameters   BACnetRejectReason = 2
	BACnetRejectInvalidParameterDataType BACnetRejectReason = 3
	BACnetRejectInvalidTag               BACnetRejectReason = 4
	BACnetRejectMissingRequiredParameter BACnetRejectReason = 5
	BACnetRejectParameterOutOfRange      BACnetRejectReason = 6
	BACnetRejectTooManyArguments         BACnetRejectReason = 7
	BACnetRejectUndefinedEnumeration     BACnetRejectReason = 8
	BACnetRejectUnrecognizedService      BACnetRejectReason = 9
)

var bacnetRejectNames = map[BACnetRejectReason]string{
	BACnetRejectOther:                    "other",
	BACnetRejectBufferOverflow:           "buffer-overflow",
	BACnetRejectInconsistentParameters:   "inconsistent-parameters",
	BACnetRejectInvalidParameterDataType: "invalid-parameter-data-type",
	BACnetRejectInvalidTag:               "invalid-tag",
	BACnetRejectMissingRequiredParameter: "missing-required-parameter",
	BACnetRejectParameterOutOfRange:      "parameter-out-of-range",
	BACnetRejectTooManyArguments:         "too-many-arguments",
	BACnetRejectUndefinedEnumeration:     "undefined-enumeration",
	BACnetRejectUnrecognizedService:      "unrecognized-service",
}

// String returns the Clause 18 name of the reason.
func (r BACnetRejectReason) String() string { return bacnetName(bacnetRejectNames, r) }

// BACnetAbortReason is the reason of an Abort PDU (Clause 18.9).
// Values from 64 are proprietary.
type BACnetAbortReason uint8

// BACnetAbortReason values.
const (
	BACnetAbortOther                         BACnetAbortReason = 0
	BACnetAbortBufferOverflow                BACnetAbortReason = 1
	BACnetAbortInvalidAPDUInThisState        BACnetAbortReason = 2
	BACnetAbortPreemptedByHigherPriorityTask BACnetAbortReason = 3
	BACnetAbortSegmentationNotSupported      BACnetAbortReason = 4
	BACnetAbortSecurityError                 BACnetAbortReason = 5
	BACnetAbortInsufficientSecurity          BACnetAbortReason = 6
	BACnetAbortWindowSizeOutOfRange          BACnetAbortReason = 7
	BACnetAbortApplicationExceededReplyTime  BACnetAbortReason = 8
	BACnetAbortOutOfResources                BACnetAbortReason = 9
	BACnetAbortTSMTimeout                    BACnetAbortReason = 10
	BACnetAbortAPDUTooLong                   BACnetAbortReason = 11
)

var bacnetAbortNames = map[BACnetAbortReason]string{
	BACnetAbortOther:                         "other",
	BACnetAbortBufferOverflow:                "buffer-overflow",
	BACnetAbortInvalidAPDUInThisState:        "invalid-apdu-in-this-state",
	BACnetAbortPreemptedByHigherPriorityTask: "preempted-by-higher-priority-task",
	BACnetAbortSegmentationNotSupported:      "segmentation-not-supported",
	BACnetAbortSecurityError:                 "security-error",
	BACnetAbortInsufficientSecurity:          "insufficient-security",
	BACnetAbortWindowSizeOutOfRange:          "window-size-out-of-range",
	BACnetAbortApplicationExceededReplyTime:  "application-exceeded-reply-time",
	BACnetAbortOutOfResources:                "out-of-resources",
	BACnetAbortTSMTimeout:                    "tsm-timeout",
	BACnetAbortAPDUTooLong:                   "apdu-too-long",
}

// String returns the Clause 18 name of the reason.
func (r BACnetAbortReason) String() string { return bacnetName(bacnetAbortNames, r) }

// BACnetErrorClass is the class of a BACnet error (Clause 18).
type BACnetErrorClass uint32

// BACnetErrorClass values.
const (
	BACnetErrorClassDevice        BACnetErrorClass = 0
	BACnetErrorClassObject        BACnetErrorClass = 1
	BACnetErrorClassProperty      BACnetErrorClass = 2
	BACnetErrorClassResources     BACnetErrorClass = 3
	BACnetErrorClassSecurity      BACnetErrorClass = 4
	BACnetErrorClassServices      BACnetErrorClass = 5
	BACnetErrorClassVT            BACnetErrorClass = 6
	BACnetErrorClassCommunication BACnetErrorClass = 7
)

var bacnetErrorClassNames = map[BACnetErrorClass]string{
	BACnetErrorClassDevice:        "device",
	BACnetErrorClassObject:        "object",
	BACnetErrorClassProperty:      "property",
	BACnetErrorClassResources:     "resources",
	BACnetErrorClassSecurity:      "security",
	BACnetErrorClassServices:      "services",
	BACnetErrorClassVT:            "vt",
	BACnetErrorClassCommunication: "communication",
}

// String returns the Clause 18 name of the class.
func (c BACnetErrorClass) String() string { return bacnetName(bacnetErrorClassNames, c) }

// String returns the Clause 18 name of the code.
func (c BACnetErrorCode) String() string { return bacnetName(bacnetErrorCodeNames, c) }

// String returns the Clause 21 name of the object type; types from 128
// are proprietary.
func (t BACnetObjectType) String() string {
	const firstProprietary = 128
	if _, ok := bacnetObjectTypeNames[t]; !ok && t >= firstProprietary {
		return fmt.Sprintf("proprietary(%d)", uint16(t))
	}
	return bacnetName(bacnetObjectTypeNames, t)
}

// String returns the Clause 21 name of the property; identifiers 512 to
// 4194303 are proprietary.
func (p BACnetPropertyIdentifier) String() string {
	const firstProprietary, lastProprietary = 512, 4194303
	if p >= firstProprietary && p <= lastProprietary {
		return fmt.Sprintf("proprietary(%d)", uint32(p))
	}
	return bacnetName(bacnetPropertyIdentifierNames, p)
}

// BACnetError is an error class and code pair.
type BACnetError struct {
	Class BACnetErrorClass
	Code  BACnetErrorCode
}

// BACnetAPDU is a BACnet application layer PDU (Clause 20.1). Header
// fields are set according to PDUType. The service parameters are kept raw
// in Parameters and, unless the message is segmented, split into Tags;
// the common services are decoded further into ServiceData.
type BACnetAPDU struct {
	BaseLayer
	PDUType BACnetPDUType

	// Header flags: SEG, MOR and SA of requests and ComplexACK, NAK and SRV
	// of SegmentACK, SRV of Abort.
	Segmented                 bool
	MoreFollows               bool
	SegmentedResponseAccepted bool
	NegativeACK               bool
	Server                    bool

	MaxSegments BACnetMaxSegments
	MaxAPDU     BACnetMaxAPDU
	InvokeID    uint8
	// SequenceNumber and WindowSize are set by segmented messages (the
	// proposed window) and by SegmentACK (the actual window).
	SequenceNumber uint8
	WindowSize     uint8

	// ConfirmedService is the service of a confirmed request or of its
	// SimpleACK, ComplexACK or Error; UnconfirmedService that of an
	// unconfirmed request.
	ConfirmedService   BACnetConfirmedService
	UnconfirmedService BACnetUnconfirmedService

	RejectReason BACnetRejectReason
	AbortReason  BACnetAbortReason
	// Error is set by an Error PDU: its first error class and code.
	Error BACnetError

	Parameters []byte
	Tags       []BACnetTag
	// ServiceData holds the typed parameters of a decoded service, or nil.
	ServiceData BACnetServiceData

	// vendorBlock is the block of a private transfer that is not tag
	// encoded; Tags then holds the tags around it.
	vendorBlock []byte
}

// LayerType returns LayerTypeBACnetAPDU.
func (a *BACnetAPDU) LayerType() gopacket.LayerType { return LayerTypeBACnetAPDU }

// CanDecode returns LayerTypeBACnetAPDU.
func (a *BACnetAPDU) CanDecode() gopacket.LayerClass { return LayerTypeBACnetAPDU }

// NextLayerType returns LayerTypeZero: the APDU is the last BACnet layer.
func (a *BACnetAPDU) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// apduHeaderLen is the fixed header length of each PDU type, segmentation
// fields excluded.
var apduHeaderLen = map[BACnetPDUType]int{
	BACnetPDUConfirmedRequest:   4, // type, max segs/APDU, invoke ID, service
	BACnetPDUUnconfirmedRequest: 2, // type, service
	BACnetPDUSimpleACK:          3, // type, invoke ID, service
	BACnetPDUComplexACK:         3, // type, invoke ID, service
	BACnetPDUSegmentACK:         4, // type, invoke ID, sequence, window
	BACnetPDUError:              3, // type, invoke ID, service
	BACnetPDUReject:             3, // type, invoke ID, reason
	BACnetPDUAbort:              3, // type, invoke ID, reason
}

// DecodeFromBytes decodes an APDU. A malformed tag stream is an error;
// parameters that are well tagged but do not match the service leave
// ServiceData nil.
//
// The vendor block of a private transfer (request, ACK or Error) is the
// exception: when it is not tag encoded the vendor identifier and service
// number are still decoded, and the block is the []byte Value of the last
// parameter.
func (a *BACnetAPDU) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*a = BACnetAPDU{}
	if len(data) == 0 {
		return bacnetTruncated(df)
	}
	a.PDUType = BACnetPDUType(data[0] >> bacnetPDUTypeShift)
	flags := data[0]

	need, ok := apduHeaderLen[a.PDUType]
	if !ok {
		return ErrBACnetMalformed
	}
	if a.PDUType == BACnetPDUConfirmedRequest || a.PDUType == BACnetPDUComplexACK {
		a.Segmented = flags&bacnetPDUFlagSEG != 0
		a.MoreFollows = flags&bacnetPDUFlagMOR != 0
		if a.Segmented {
			need += bacnetSegmentHeaderLen
		}
	}
	if len(data) < need {
		return bacnetTruncated(df)
	}
	a.Contents = data[:need]
	a.Parameters = data[need:]
	a.decodeHeader(data, flags)

	// A segment holds a slice of the tag stream that may split a tag, so
	// only whole messages are tagged.
	if a.Segmented {
		return nil
	}
	switch a.PDUType {
	case BACnetPDUConfirmedRequest, BACnetPDUUnconfirmedRequest, BACnetPDUComplexACK, BACnetPDUError:
	default:
		return nil
	}

	// Services without parameters, such as an unlimited Who-Is, still
	// get their ServiceData.
	if len(a.Parameters) == 0 {
		a.decodeService()
		return nil
	}

	tags, err := decodeBACnetTags(a.Parameters)
	if err == nil {
		a.Tags = tags
		a.decodeService()
		return nil
	}

	// A vendor may fill a private transfer with anything. The fallback
	// only stands when the tags around the block are those of the service.
	if a.Tags, a.vendorBlock = a.privateBlock(); a.Tags != nil {
		a.decodeService()
	}
	if a.ServiceData == nil {
		a.Tags, a.vendorBlock = nil, nil
		return err
	}
	return nil
}

// privateBlock splits the parameters of a private transfer whose vendor
// block is not tag encoded:
//
//	09 07     1a 01 ff        2e        00 00 00 56 ...   2f
//	vendor    service number  opening   vendor block      closing
//
// It returns the tags around the block, the brackets included, and the
// block. The tags are nil when the APDU is not a private transfer or has
// no such block.
func (a *BACnetAPDU) privateBlock() ([]BACnetTag, []byte) {
	// An Error carries the block under [3], after the error and the
	// vendor and service number; the others under [2].
	bracket := bacnetPrivateBlockTag
	switch {
	case a.PDUType == BACnetPDUUnconfirmedRequest && a.UnconfirmedService == BACnetUnconfirmedServiceUnconfirmedPrivateTransfer:
	case a.PDUType == BACnetPDUError && a.ConfirmedService == BACnetConfirmedServiceConfirmedPrivateTransfer:
		bracket = bacnetPrivateErrorBlockTag
	case a.PDUType == BACnetPDUUnconfirmedRequest, a.ConfirmedService != BACnetConfirmedServiceConfirmedPrivateTransfer:
		return nil, nil
	}

	// The block runs to the closing tag that ends the APDU.
	data := a.Parameters
	end := len(data) - 1
	if data[end] != bracket<<bacnetTagNumberShift|bacnetTagClassBit|uint8(bacnetLVTClosing) {
		return nil, nil
	}

	tags := make([]BACnetTag, 0, bacnetPrivateMaxTags)
	nested := false
	for off := 0; off < end && len(tags) < bacnetPrivateMaxTags-1; {
		t, n, err := decodeBACnetTag(data[off:end])
		if err != nil {
			return nil, nil
		}
		off += n

		// Only the Error of an Error PDU is bracketed before the block.
		switch {
		case t.Kind == BACnetTagOpening && !nested && t.Number == bracket:
			tags = append(tags, t)
			return append(tags, BACnetTag{Class: BACnetTagClassContext, Kind: BACnetTagClosing, Number: bracket}), data[off:end]
		case t.Kind == BACnetTagOpening && nested, t.Kind == BACnetTagClosing && !nested:
			return nil, nil
		case t.Kind == BACnetTagOpening:
			nested = true
		case t.Kind == BACnetTagClosing:
			nested = false
		default:
			if nested {
				t.Depth = 1
			}
		}
		tags = append(tags, t)
	}
	return nil, nil
}

// decodeHeader reads the fixed fields of the PDU type; the caller checked
// the length.
func (a *BACnetAPDU) decodeHeader(data []byte, flags uint8) {
	switch a.PDUType {
	case BACnetPDUConfirmedRequest:
		a.SegmentedResponseAccepted = flags&bacnetPDUFlagSA != 0
		a.MaxSegments = BACnetMaxSegments(data[1] >> bacnetMaxSegmentsShift & bacnetMaxSegmentsMask)
		a.MaxAPDU = BACnetMaxAPDU(data[1] & bacnetMaxAPDUMask)
		a.InvokeID = data[2]
		a.ConfirmedService = BACnetConfirmedService(a.segmentFields(data, 3))

	case BACnetPDUUnconfirmedRequest:
		a.UnconfirmedService = BACnetUnconfirmedService(data[1])

	case BACnetPDUSimpleACK:
		a.InvokeID = data[1]
		a.ConfirmedService = BACnetConfirmedService(data[2])

	case BACnetPDUComplexACK:
		a.InvokeID = data[1]
		a.ConfirmedService = BACnetConfirmedService(a.segmentFields(data, 2))

	case BACnetPDUSegmentACK:
		a.NegativeACK = flags&bacnetPDUFlagNAK != 0
		a.Server = flags&bacnetPDUFlagSRV != 0
		a.InvokeID = data[1]
		a.SequenceNumber = data[2]
		a.WindowSize = data[3]

	case BACnetPDUError:
		a.InvokeID = data[1]
		a.ConfirmedService = BACnetConfirmedService(data[2])

	case BACnetPDUReject:
		a.InvokeID = data[1]
		a.RejectReason = BACnetRejectReason(data[2])

	case BACnetPDUAbort:
		a.Server = flags&bacnetPDUFlagSRV != 0
		a.InvokeID = data[1]
		a.AbortReason = BACnetAbortReason(data[2])
	}
}

// segmentFields reads the sequence number and window size of a segmented
// message at off and returns the service choice octet that follows.
func (a *BACnetAPDU) segmentFields(data []byte, off int) uint8 {
	if !a.Segmented {
		return data[off]
	}
	a.SequenceNumber = data[off]
	a.WindowSize = data[off+1]
	return data[off+bacnetSegmentHeaderLen]
}

func decodeBACnetAPDU(data []byte, p gopacket.PacketBuilder) error {
	return decodingLayerDecoder(&BACnetAPDU{}, data, p)
}
