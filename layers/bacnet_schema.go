// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// The ASN.1 productions of ASHRAE 135-2020 Clause 21 as tables: the
// constructed datatypes, and the parameters of each service.

package layers

// BACnetDataType values of the primitive and constructed datatypes. The
// enumerations and named bit strings follow from bacnetDataTypeNamedBase.
const (
	// BACnetDataTypeAny is data whose type is not known.
	BACnetDataTypeAny BACnetDataType = iota
	BACnetDataTypeNull
	BACnetDataTypeBoolean
	BACnetDataTypeUnsigned
	BACnetDataTypeSigned
	BACnetDataTypeReal
	BACnetDataTypeDouble
	BACnetDataTypeOctetString
	BACnetDataTypeCharacterString
	BACnetDataTypeBitString
	BACnetDataTypeEnumerated
	BACnetDataTypeDate
	BACnetDataTypeTime
	BACnetDataTypeObjectIdentifier
	// BACnetDataTypeSequence and BACnetDataTypeChoice are the SEQUENCE and
	// CHOICE productions that Clause 21 nests without naming them.
	BACnetDataTypeSequence
	BACnetDataTypeChoice
	BACnetDataTypeWeekNDay
	BACnetDataTypeDateTime
	BACnetDataTypeDateRange
	BACnetDataTypeCalendarEntry
	BACnetDataTypeTimeValue
	BACnetDataTypeDailySchedule
	BACnetDataTypeSpecialEvent
	BACnetDataTypeDeviceObjectReference
	BACnetDataTypeDeviceObjectPropertyReference
	BACnetDataTypeObjectPropertyReference
	BACnetDataTypeDeviceObjectPropertyValue
	BACnetDataTypePropertyReference
	BACnetDataTypePropertyValue
	BACnetDataTypeAddress
	BACnetDataTypeAddressBinding
	BACnetDataTypeRecipient
	BACnetDataTypeRecipientProcess
	BACnetDataTypeDestination
	BACnetDataTypeCOVSubscription
	BACnetDataTypePriorityValue
	BACnetDataTypeTimeStamp
	BACnetDataTypePropertyStates
	BACnetDataTypeEventParameter
	BACnetDataTypeNotificationParameters
	BACnetDataTypeFaultParameter
	BACnetDataTypeLogRecord
	BACnetDataTypeEventLogRecord
	BACnetDataTypeLogMultipleRecord
	BACnetDataTypeError
	BACnetDataTypeReadAccessSpecification
	BACnetDataTypeReadAccessResult
	BACnetDataTypeWriteAccessSpecification
	BACnetDataTypeScale
	BACnetDataTypePrescale
	BACnetDataTypeAccumulatorRecord
	BACnetDataTypeActionCommand
	BACnetDataTypeActionList
	BACnetDataTypeSetpointReference
	BACnetDataTypeShedLevel
	BACnetDataTypeVTSession
	BACnetDataTypeClientCOV
	BACnetDataTypeLightingCommand
	BACnetDataTypeHostNPort
	BACnetDataTypeBDTEntry
	BACnetDataTypeFDTEntry
	BACnetDataTypeVMACEntry
	BACnetDataTypeRouterEntry
	BACnetDataTypeValueSource
	BACnetDataTypeChannelValue
	BACnetDataTypeGroupChannelValue
	BACnetDataTypeEventNotification
	BACnetDataTypeEventNotificationSubscription
	BACnetDataTypeNameValue
	BACnetDataTypeAuditNotification
	BACnetDataTypeAuditLogRecord
	BACnetDataTypeColorCommand
	BACnetDataTypeXYColor
	BACnetDataTypeAuthenticationFactor
	BACnetDataTypeAuthorizationConstraint
	BACnetDataTypeAuthorizationScope
	BACnetDataTypeAccessToken

	// bacnetDataTypeApplication is one application tagged primitive of any
	// type; decoded, it takes the type of its tag.
	bacnetDataTypeApplication
	// bacnetDataTypeProperty is an ANY typed by the property in scope.
	bacnetDataTypeProperty
	// bacnetDataTypeNamedBase is the first datatype of bacnetNamedTypes.
	bacnetDataTypeNamedBase
)

// bacnetCtx describes a member under context tag n.
func bacnetCtx(n uint8, name string, typ BACnetDataType) bacnetMember {
	return bacnetMember{name: name, tag: n, typ: typ}
}

// bacnetBare describes an untagged member: an application tagged
// primitive, or a constructed value whose parts follow inline.
func bacnetBare(name string, typ BACnetDataType) bacnetMember {
	return bacnetMember{name: name, tag: bacnetNoTag, typ: typ}
}

// optional marks the member OPTIONAL.
func (f bacnetMember) optional() bacnetMember {
	f.flags |= bacnetOptional
	return f
}

// listOf turns the member into a SEQUENCE OF its type.
func (f bacnetMember) listOf() bacnetMember {
	f.flags |= bacnetList
	return f
}

// scope marks the member as naming the object, property or array index
// that types the ANY values after it.
func (f bacnetMember) scope(s bacnetFieldFlags) bacnetMember {
	f.flags |= s
	return f
}

// as types an ANY member by property p of the object in scope, the way
// the command-value of an event is a present-value.
func (f bacnetMember) as(p BACnetPropertyIdentifier) bacnetMember {
	f.flags |= bacnetFixedProperty
	f.prop = p
	return f
}

// of gives an anonymous SEQUENCE or CHOICE its members.
func (f bacnetMember) of(members ...bacnetMember) bacnetMember {
	f.sub = members
	return f
}

// Members shared by several productions.
var (
	bacnetObjectField   = bacnetCtx(0, "object-identifier", BACnetDataTypeObjectIdentifier).scope(bacnetObjectScope)
	bacnetPropertyField = bacnetCtx(1, "property-identifier", BACnetDataTypePropertyIdentifier).scope(bacnetPropertyScope)
	bacnetIndexField    = bacnetCtx(2, "property-array-index", BACnetDataTypeUnsigned).optional().scope(bacnetIndexScope)

	// bacnetErrorFields is the Error production, which most services
	// return as it is.
	bacnetErrorFields = []bacnetMember{
		bacnetBare("error-class", BACnetDataTypeErrorClass),
		bacnetBare("error-code", BACnetDataTypeErrorCode),
	}

	// bacnetUntypedFields stands for a service that is only decoded down
	// to its tags.
	bacnetUntypedFields = []bacnetMember{
		bacnetBare("service-parameters", BACnetDataTypeAny).optional(),
	}

	// bacnetExtendedParameters is the parameter list of the extended
	// event and fault choices.
	// bacnetNormalValue is a limit of fault-out-of-range.
	bacnetNormalValue = []bacnetMember{
		bacnetBare("real", BACnetDataTypeReal),
		bacnetBare("unsigned", BACnetDataTypeUnsigned),
		bacnetBare("double", BACnetDataTypeDouble),
		bacnetBare("integer", BACnetDataTypeSigned),
	}

	bacnetExtendedParameters = bacnetCtx(2, "parameters", BACnetDataTypeChoice).of(
		bacnetBare("value", bacnetDataTypeApplication),
		bacnetCtx(0, "reference", BACnetDataTypeDeviceObjectPropertyReference),
	).listOf()

	// bacnetExtendedValues is the parameter list of the extended
	// notification, which carries values where the event has references.
	bacnetExtendedValues = bacnetCtx(2, "parameters", BACnetDataTypeChoice).of(
		bacnetBare("value", bacnetDataTypeApplication),
		bacnetCtx(0, "property-value", BACnetDataTypeDeviceObjectPropertyValue),
	).listOf()
)

// bacnetTypes describes the datatypes below bacnetDataTypeNamedBase.
var bacnetTypes = [bacnetDataTypeNamedBase]bacnetType{
	BACnetDataTypeAny:              {name: "ANY", kind: bacnetKindAny},
	BACnetDataTypeNull:             {name: "Null", kind: bacnetKindPrimitive, app: BACnetAppTagNull},
	BACnetDataTypeBoolean:          {name: "Boolean", kind: bacnetKindPrimitive, app: BACnetAppTagBoolean},
	BACnetDataTypeUnsigned:         {name: "Unsigned", kind: bacnetKindPrimitive, app: BACnetAppTagUnsigned},
	BACnetDataTypeSigned:           {name: "Signed", kind: bacnetKindPrimitive, app: BACnetAppTagSigned},
	BACnetDataTypeReal:             {name: "Real", kind: bacnetKindPrimitive, app: BACnetAppTagReal},
	BACnetDataTypeDouble:           {name: "Double", kind: bacnetKindPrimitive, app: BACnetAppTagDouble},
	BACnetDataTypeOctetString:      {name: "OctetString", kind: bacnetKindPrimitive, app: BACnetAppTagOctetString},
	BACnetDataTypeCharacterString:  {name: "CharacterString", kind: bacnetKindPrimitive, app: BACnetAppTagCharacterString},
	BACnetDataTypeBitString:        {name: "BitString", kind: bacnetKindPrimitive, app: BACnetAppTagBitString},
	BACnetDataTypeEnumerated:       {name: "Enumerated", kind: bacnetKindPrimitive, app: BACnetAppTagEnumerated},
	BACnetDataTypeDate:             {name: "Date", kind: bacnetKindPrimitive, app: BACnetAppTagDate},
	BACnetDataTypeTime:             {name: "Time", kind: bacnetKindPrimitive, app: BACnetAppTagTime},
	BACnetDataTypeObjectIdentifier: {name: "ObjectIdentifier", kind: bacnetKindPrimitive, app: BACnetAppTagObjectIdentifier},
	BACnetDataTypeSequence:         {name: "SEQUENCE", kind: bacnetKindSequence},
	BACnetDataTypeChoice:           {name: "CHOICE", kind: bacnetKindChoice},
	BACnetDataTypeWeekNDay:         {name: "BACnetWeekNDay", kind: bacnetKindPrimitive, app: BACnetAppTagOctetString},
	bacnetDataTypeApplication:      {name: "ABSTRACT-SYNTAX", kind: bacnetKindApplication},
	bacnetDataTypeProperty:         {name: "ANY", kind: bacnetKindProperty},

	BACnetDataTypeDateTime: {name: "BACnetDateTime", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("date", BACnetDataTypeDate),
		bacnetBare("time", BACnetDataTypeTime),
	}},
	BACnetDataTypeDateRange: {name: "BACnetDateRange", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("start-date", BACnetDataTypeDate),
		bacnetBare("end-date", BACnetDataTypeDate),
	}},
	BACnetDataTypeCalendarEntry: {name: "BACnetCalendarEntry", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetCtx(0, "date", BACnetDataTypeDate),
		bacnetCtx(1, "date-range", BACnetDataTypeDateRange),
		bacnetCtx(2, "week-n-day", BACnetDataTypeWeekNDay),
	}},
	BACnetDataTypeTimeValue: {name: "BACnetTimeValue", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("time", BACnetDataTypeTime),
		bacnetBare("value", bacnetDataTypeApplication),
	}},
	BACnetDataTypeDailySchedule: {name: "BACnetDailySchedule", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "day-schedule", BACnetDataTypeTimeValue).listOf(),
	}},
	BACnetDataTypeSpecialEvent: {name: "BACnetSpecialEvent", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("period", BACnetDataTypeChoice).of(
			bacnetCtx(0, "calendar-entry", BACnetDataTypeCalendarEntry),
			bacnetCtx(1, "calendar-reference", BACnetDataTypeObjectIdentifier),
		),
		bacnetCtx(2, "list-of-time-values", BACnetDataTypeTimeValue).listOf(),
		bacnetCtx(3, "event-priority", BACnetDataTypeUnsigned),
	}},
	BACnetDataTypeDeviceObjectReference: {name: "BACnetDeviceObjectReference", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "device-identifier", BACnetDataTypeObjectIdentifier).optional(),
		bacnetCtx(1, "object-identifier", BACnetDataTypeObjectIdentifier),
	}},
	BACnetDataTypeDeviceObjectPropertyReference: {name: "BACnetDeviceObjectPropertyReference", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "object-identifier", BACnetDataTypeObjectIdentifier),
		bacnetCtx(1, "property-identifier", BACnetDataTypePropertyIdentifier),
		bacnetCtx(2, "property-array-index", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(3, "device-identifier", BACnetDataTypeObjectIdentifier).optional(),
	}},
	BACnetDataTypeObjectPropertyReference: {name: "BACnetObjectPropertyReference", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "object-identifier", BACnetDataTypeObjectIdentifier),
		bacnetCtx(1, "property-identifier", BACnetDataTypePropertyIdentifier),
		bacnetCtx(2, "property-array-index", BACnetDataTypeUnsigned).optional(),
	}},
	BACnetDataTypeDeviceObjectPropertyValue: {name: "BACnetDeviceObjectPropertyValue", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "device-identifier", BACnetDataTypeObjectIdentifier),
		bacnetCtx(1, "object-identifier", BACnetDataTypeObjectIdentifier).scope(bacnetObjectScope),
		bacnetCtx(2, "property-identifier", BACnetDataTypePropertyIdentifier).scope(bacnetPropertyScope),
		bacnetCtx(3, "property-array-index", BACnetDataTypeUnsigned).optional().scope(bacnetIndexScope),
		bacnetCtx(4, "property-value", bacnetDataTypeProperty),
	}},
	BACnetDataTypePropertyReference: {name: "BACnetPropertyReference", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "property-identifier", BACnetDataTypePropertyIdentifier).scope(bacnetPropertyScope),
		bacnetCtx(1, "property-array-index", BACnetDataTypeUnsigned).optional().scope(bacnetIndexScope),
	}},
	BACnetDataTypePropertyValue: {name: "BACnetPropertyValue", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "property-identifier", BACnetDataTypePropertyIdentifier).scope(bacnetPropertyScope),
		bacnetCtx(1, "property-array-index", BACnetDataTypeUnsigned).optional().scope(bacnetIndexScope),
		bacnetCtx(2, "property-value", bacnetDataTypeProperty),
		bacnetCtx(3, "priority", BACnetDataTypeUnsigned).optional(),
	}},
	BACnetDataTypeAddress: {name: "BACnetAddress", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("network-number", BACnetDataTypeUnsigned),
		bacnetBare("mac-address", BACnetDataTypeOctetString),
	}},
	BACnetDataTypeAddressBinding: {name: "BACnetAddressBinding", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("device-identifier", BACnetDataTypeObjectIdentifier),
		bacnetBare("device-address", BACnetDataTypeAddress),
	}},
	BACnetDataTypeRecipient: {name: "BACnetRecipient", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetCtx(0, "device", BACnetDataTypeObjectIdentifier),
		bacnetCtx(1, "address", BACnetDataTypeAddress),
	}},
	BACnetDataTypeRecipientProcess: {name: "BACnetRecipientProcess", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "recipient", BACnetDataTypeRecipient),
		bacnetCtx(1, "process-identifier", BACnetDataTypeUnsigned),
	}},
	BACnetDataTypeDestination: {name: "BACnetDestination", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("valid-days", BACnetDataTypeDaysOfWeek),
		bacnetBare("from-time", BACnetDataTypeTime),
		bacnetBare("to-time", BACnetDataTypeTime),
		bacnetBare("recipient", BACnetDataTypeRecipient),
		bacnetBare("process-identifier", BACnetDataTypeUnsigned),
		bacnetBare("issue-confirmed-notifications", BACnetDataTypeBoolean),
		bacnetBare("transitions", BACnetDataTypeEventTransitionBits),
	}},
	BACnetDataTypeCOVSubscription: {name: "BACnetCOVSubscription", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "recipient", BACnetDataTypeRecipientProcess),
		bacnetCtx(1, "monitored-property-reference", BACnetDataTypeObjectPropertyReference),
		bacnetCtx(2, "issue-confirmed-notifications", BACnetDataTypeBoolean),
		bacnetCtx(3, "time-remaining", BACnetDataTypeUnsigned),
		bacnetCtx(4, "cov-increment", BACnetDataTypeReal).optional(),
	}},
	BACnetDataTypePriorityValue: {name: "BACnetPriorityValue", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetBare("value", bacnetDataTypeApplication),
		bacnetCtx(0, "constructed-value", BACnetDataTypeAny),
		bacnetCtx(1, "date-time", BACnetDataTypeDateTime),
	}},
	BACnetDataTypeTimeStamp: {name: "BACnetTimeStamp", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetCtx(0, "time", BACnetDataTypeTime),
		bacnetCtx(1, "sequence-number", BACnetDataTypeUnsigned),
		bacnetCtx(2, "date-time", BACnetDataTypeDateTime),
	}},
	BACnetDataTypePropertyStates: {name: "BACnetPropertyStates", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetCtx(0, "boolean-value", BACnetDataTypeBoolean),
		bacnetCtx(1, "binary-value", BACnetDataTypeBinaryPV),
		bacnetCtx(2, "event-type", BACnetDataTypeEventType),
		bacnetCtx(3, "polarity", BACnetDataTypePolarity),
		bacnetCtx(4, "program-change", BACnetDataTypeProgramRequest),
		bacnetCtx(5, "program-state", BACnetDataTypeProgramState),
		bacnetCtx(6, "reason-for-halt", BACnetDataTypeProgramError),
		bacnetCtx(7, "reliability", BACnetDataTypeReliability),
		bacnetCtx(8, "state", BACnetDataTypeEventState),
		bacnetCtx(9, "system-status", BACnetDataTypeDeviceStatus),
		bacnetCtx(10, "units", BACnetDataTypeEngineeringUnits),
		bacnetCtx(11, "unsigned-value", BACnetDataTypeUnsigned),
		bacnetCtx(12, "life-safety-mode", BACnetDataTypeLifeSafetyMode),
		bacnetCtx(13, "life-safety-state", BACnetDataTypeLifeSafetyState),
		bacnetCtx(14, "restart-reason", BACnetDataTypeRestartReason),
		bacnetCtx(15, "door-alarm-state", BACnetDataTypeDoorAlarmState),
		bacnetCtx(16, "action", BACnetDataTypeAction),
		bacnetCtx(17, "door-secured-status", BACnetDataTypeDoorSecuredStatus),
		bacnetCtx(18, "door-status", BACnetDataTypeDoorStatus),
		bacnetCtx(19, "door-value", BACnetDataTypeDoorValue),
		bacnetCtx(20, "file-access-method", BACnetDataTypeFileAccessMethod),
		bacnetCtx(21, "lock-status", BACnetDataTypeLockStatus),
		bacnetCtx(22, "life-safety-operation", BACnetDataTypeLifeSafetyOperation),
		bacnetCtx(23, "maintenance", BACnetDataTypeMaintenance),
		bacnetCtx(24, "node-type", BACnetDataTypeNodeType),
		bacnetCtx(25, "notify-type", BACnetDataTypeNotifyType),
		bacnetCtx(26, "security-level", BACnetDataTypeSecurityLevel),
		bacnetCtx(27, "shed-state", BACnetDataTypeShedState),
		bacnetCtx(28, "silenced-state", BACnetDataTypeSilencedState),
		bacnetCtx(30, "access-event", BACnetDataTypeAccessEvent),
		bacnetCtx(31, "zone-occupancy-state", BACnetDataTypeAccessZoneOccupancyState),
		bacnetCtx(32, "access-credential-disable-reason", BACnetDataTypeAccessCredentialDisableReason),
		bacnetCtx(33, "access-credential-disable", BACnetDataTypeAccessCredentialDisable),
		bacnetCtx(34, "authentication-status", BACnetDataTypeAuthenticationStatus),
		bacnetCtx(36, "backup-state", BACnetDataTypeBackupState),
		bacnetCtx(37, "write-status", BACnetDataTypeWriteStatus),
		bacnetCtx(38, "lighting-in-progress", BACnetDataTypeLightingInProgress),
		bacnetCtx(39, "lighting-operation", BACnetDataTypeLightingOperation),
		bacnetCtx(40, "lighting-transition", BACnetDataTypeLightingTransition),
		bacnetCtx(41, "integer-value", BACnetDataTypeSigned),
		bacnetCtx(42, "binary-lighting-value", BACnetDataTypeBinaryLightingPV),
		bacnetCtx(43, "timer-state", BACnetDataTypeTimerState),
		bacnetCtx(44, "timer-transition", BACnetDataTypeTimerTransition),
		bacnetCtx(45, "bacnet-ip-mode", BACnetDataTypeIPMode),
		bacnetCtx(46, "network-port-command", BACnetDataTypeNetworkPortCommand),
		bacnetCtx(47, "network-type", BACnetDataTypeNetworkType),
		bacnetCtx(48, "network-number-quality", BACnetDataTypeNetworkNumberQuality),
		bacnetCtx(49, "escalator-operation-direction", BACnetDataTypeEscalatorOperationDirection),
		bacnetCtx(50, "escalator-fault", BACnetDataTypeEscalatorFault),
		bacnetCtx(51, "escalator-mode", BACnetDataTypeEscalatorMode),
		bacnetCtx(52, "lift-car-direction", BACnetDataTypeLiftCarDirection),
		bacnetCtx(53, "lift-car-door-command", BACnetDataTypeLiftCarDoorCommand),
		bacnetCtx(54, "lift-car-drive-status", BACnetDataTypeLiftCarDriveStatus),
		bacnetCtx(55, "lift-car-mode", BACnetDataTypeLiftCarMode),
		bacnetCtx(56, "lift-group-mode", BACnetDataTypeLiftGroupMode),
		bacnetCtx(57, "lift-fault", BACnetDataTypeLiftFault),
		bacnetCtx(58, "protocol-level", BACnetDataTypeProtocolLevel),
		bacnetCtx(59, "audit-level", BACnetDataTypeAuditLevel),
		bacnetCtx(60, "audit-operation", BACnetDataTypeAuditOperation),
		bacnetCtx(63, "extended-value", BACnetDataTypeUnsigned),
	}},

	BACnetDataTypeEventParameter: {name: "BACnetEventParameter", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetCtx(0, "change-of-bitstring", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "bitmask", BACnetDataTypeBitString),
			bacnetCtx(2, "list-of-bitstring-values", BACnetDataTypeBitString).listOf(),
		),
		bacnetCtx(1, "change-of-state", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "list-of-values", BACnetDataTypePropertyStates).listOf(),
		),
		bacnetCtx(2, "change-of-value", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "cov-criteria", BACnetDataTypeChoice).of(
				bacnetCtx(0, "bitmask", BACnetDataTypeBitString),
				bacnetCtx(1, "referenced-property-increment", BACnetDataTypeReal),
			),
		),
		bacnetCtx(3, "command-failure", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "feedback-property-reference", BACnetDataTypeDeviceObjectPropertyReference),
		),
		bacnetCtx(4, "floating-limit", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "setpoint-reference", BACnetDataTypeDeviceObjectPropertyReference),
			bacnetCtx(2, "low-diff-limit", BACnetDataTypeReal),
			bacnetCtx(3, "high-diff-limit", BACnetDataTypeReal),
			bacnetCtx(4, "deadband", BACnetDataTypeReal),
		),
		bacnetCtx(5, "out-of-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "low-limit", BACnetDataTypeReal),
			bacnetCtx(2, "high-limit", BACnetDataTypeReal),
			bacnetCtx(3, "deadband", BACnetDataTypeReal),
		),
		bacnetCtx(8, "change-of-life-safety", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "list-of-life-safety-alarm-values", BACnetDataTypeLifeSafetyState).listOf(),
			bacnetCtx(2, "list-of-alarm-values", BACnetDataTypeLifeSafetyState).listOf(),
			bacnetCtx(3, "mode-property-reference", BACnetDataTypeDeviceObjectPropertyReference),
		),
		bacnetCtx(9, "extended", BACnetDataTypeSequence).of(
			bacnetCtx(0, "vendor-id", BACnetDataTypeUnsigned),
			bacnetCtx(1, "extended-event-type", BACnetDataTypeUnsigned),
			bacnetExtendedParameters,
		),
		bacnetCtx(10, "buffer-ready", BACnetDataTypeSequence).of(
			bacnetCtx(0, "notification-threshold", BACnetDataTypeUnsigned),
			bacnetCtx(1, "previous-notification-count", BACnetDataTypeUnsigned),
		),
		bacnetCtx(11, "unsigned-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "low-limit", BACnetDataTypeUnsigned),
			bacnetCtx(2, "high-limit", BACnetDataTypeUnsigned),
		),
		bacnetCtx(13, "access-event", BACnetDataTypeSequence).of(
			bacnetCtx(0, "list-of-access-events", BACnetDataTypeAccessEvent).listOf(),
			bacnetCtx(1, "access-event-time-reference", BACnetDataTypeDeviceObjectPropertyReference),
		),
		bacnetCtx(14, "double-out-of-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "low-limit", BACnetDataTypeDouble),
			bacnetCtx(2, "high-limit", BACnetDataTypeDouble),
			bacnetCtx(3, "deadband", BACnetDataTypeDouble),
		),
		bacnetCtx(15, "signed-out-of-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "low-limit", BACnetDataTypeSigned),
			bacnetCtx(2, "high-limit", BACnetDataTypeSigned),
			bacnetCtx(3, "deadband", BACnetDataTypeUnsigned),
		),
		bacnetCtx(16, "unsigned-out-of-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "low-limit", BACnetDataTypeUnsigned),
			bacnetCtx(2, "high-limit", BACnetDataTypeUnsigned),
			bacnetCtx(3, "deadband", BACnetDataTypeUnsigned),
		),
		bacnetCtx(17, "change-of-characterstring", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "list-of-alarm-values", BACnetDataTypeCharacterString).listOf(),
		),
		bacnetCtx(18, "change-of-status-flags", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "selected-flags", BACnetDataTypeStatusFlags),
		),
		bacnetCtx(20, "none", BACnetDataTypeNull),
		bacnetCtx(21, "change-of-discrete-value", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
		),
		bacnetCtx(22, "change-of-timer", BACnetDataTypeSequence).of(
			bacnetCtx(0, "time-delay", BACnetDataTypeUnsigned),
			bacnetCtx(1, "alarm-values", BACnetDataTypeTimerState).listOf(),
			bacnetCtx(2, "update-time-reference", BACnetDataTypeDeviceObjectPropertyReference),
		),
	}},

	BACnetDataTypeNotificationParameters: {name: "BACnetNotificationParameters", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetCtx(0, "change-of-bitstring", BACnetDataTypeSequence).of(
			bacnetCtx(0, "referenced-bitstring", BACnetDataTypeBitString),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
		),
		bacnetCtx(1, "change-of-state", BACnetDataTypeSequence).of(
			bacnetCtx(0, "new-state", BACnetDataTypePropertyStates),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
		),
		bacnetCtx(2, "change-of-value", BACnetDataTypeSequence).of(
			bacnetCtx(0, "new-value", BACnetDataTypeChoice).of(
				bacnetCtx(0, "changed-bits", BACnetDataTypeBitString),
				bacnetCtx(1, "changed-value", BACnetDataTypeReal),
			),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
		),
		bacnetCtx(3, "command-failure", BACnetDataTypeSequence).of(
			bacnetCtx(0, "command-value", bacnetDataTypeProperty).as(BACnetPropertyPresentValue),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "feedback-value", bacnetDataTypeProperty).as(BACnetPropertyFeedbackValue),
		),
		bacnetCtx(4, "floating-limit", BACnetDataTypeSequence).of(
			bacnetCtx(0, "reference-value", BACnetDataTypeReal),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "setpoint-value", BACnetDataTypeReal),
			bacnetCtx(3, "error-limit", BACnetDataTypeReal),
		),
		bacnetCtx(5, "out-of-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "exceeding-value", BACnetDataTypeReal),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "deadband", BACnetDataTypeReal),
			bacnetCtx(3, "exceeded-limit", BACnetDataTypeReal),
		),
		bacnetCtx(6, "complex-event-type", BACnetDataTypePropertyValue).listOf(),
		bacnetCtx(8, "change-of-life-safety", BACnetDataTypeSequence).of(
			bacnetCtx(0, "new-state", BACnetDataTypeLifeSafetyState),
			bacnetCtx(1, "new-mode", BACnetDataTypeLifeSafetyMode),
			bacnetCtx(2, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(3, "operation-expected", BACnetDataTypeLifeSafetyOperation),
		),
		bacnetCtx(9, "extended", BACnetDataTypeSequence).of(
			bacnetCtx(0, "vendor-id", BACnetDataTypeUnsigned),
			bacnetCtx(1, "extended-event-type", BACnetDataTypeUnsigned),
			bacnetExtendedValues,
		),
		bacnetCtx(10, "buffer-ready", BACnetDataTypeSequence).of(
			bacnetCtx(0, "buffer-property", BACnetDataTypeDeviceObjectPropertyReference),
			bacnetCtx(1, "previous-notification", BACnetDataTypeUnsigned),
			bacnetCtx(2, "current-notification", BACnetDataTypeUnsigned),
		),
		bacnetCtx(11, "unsigned-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "exceeding-value", BACnetDataTypeUnsigned),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "exceeded-limit", BACnetDataTypeUnsigned),
		),
		bacnetCtx(13, "access-event", BACnetDataTypeSequence).of(
			bacnetCtx(0, "access-event", BACnetDataTypeAccessEvent),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "access-event-tag", BACnetDataTypeUnsigned),
			bacnetCtx(3, "access-event-time", BACnetDataTypeTimeStamp),
			bacnetCtx(4, "access-credential", BACnetDataTypeDeviceObjectReference),
			bacnetCtx(5, "authentication-factor", BACnetDataTypeAuthenticationFactor).optional(),
		),
		bacnetCtx(14, "double-out-of-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "exceeding-value", BACnetDataTypeDouble),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "deadband", BACnetDataTypeDouble),
			bacnetCtx(3, "exceeded-limit", BACnetDataTypeDouble),
		),
		bacnetCtx(15, "signed-out-of-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "exceeding-value", BACnetDataTypeSigned),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "deadband", BACnetDataTypeUnsigned),
			bacnetCtx(3, "exceeded-limit", BACnetDataTypeSigned),
		),
		bacnetCtx(16, "unsigned-out-of-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "exceeding-value", BACnetDataTypeUnsigned),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "deadband", BACnetDataTypeUnsigned),
			bacnetCtx(3, "exceeded-limit", BACnetDataTypeUnsigned),
		),
		bacnetCtx(17, "change-of-characterstring", BACnetDataTypeSequence).of(
			bacnetCtx(0, "changed-value", BACnetDataTypeCharacterString),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "alarm-value", BACnetDataTypeCharacterString),
		),
		bacnetCtx(18, "change-of-status-flags", BACnetDataTypeSequence).of(
			bacnetCtx(0, "present-value", bacnetDataTypeProperty).as(BACnetPropertyPresentValue).optional(),
			bacnetCtx(1, "referenced-flags", BACnetDataTypeStatusFlags),
		),
		bacnetCtx(19, "change-of-reliability", BACnetDataTypeSequence).of(
			bacnetCtx(0, "reliability", BACnetDataTypeReliability),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "property-values", BACnetDataTypePropertyValue).listOf(),
		),
		bacnetCtx(21, "change-of-discrete-value", BACnetDataTypeSequence).of(
			bacnetCtx(0, "new-value", BACnetDataTypeChoice).of(
				bacnetBare("value", bacnetDataTypeApplication),
				bacnetCtx(0, "date-time", BACnetDataTypeDateTime),
			),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
		),
		bacnetCtx(22, "change-of-timer", BACnetDataTypeSequence).of(
			bacnetCtx(0, "new-state", BACnetDataTypeTimerState),
			bacnetCtx(1, "status-flags", BACnetDataTypeStatusFlags),
			bacnetCtx(2, "update-time", BACnetDataTypeDateTime),
			bacnetCtx(3, "last-state-change", BACnetDataTypeTimerTransition).optional(),
			bacnetCtx(4, "initial-timeout", BACnetDataTypeUnsigned).optional(),
			bacnetCtx(5, "expiration-time", BACnetDataTypeDateTime).optional(),
		),
	}},

	BACnetDataTypeFaultParameter: {name: "BACnetFaultParameter", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetCtx(0, "none", BACnetDataTypeNull),
		bacnetCtx(1, "fault-characterstring", BACnetDataTypeSequence).of(
			bacnetCtx(0, "list-of-fault-values", BACnetDataTypeCharacterString).listOf(),
		),
		bacnetCtx(2, "fault-extended", BACnetDataTypeSequence).of(
			bacnetCtx(0, "vendor-id", BACnetDataTypeUnsigned),
			bacnetCtx(1, "extended-fault-type", BACnetDataTypeUnsigned),
			bacnetExtendedParameters,
		),
		bacnetCtx(3, "fault-life-safety", BACnetDataTypeSequence).of(
			bacnetCtx(0, "list-of-fault-values", BACnetDataTypeLifeSafetyState).listOf(),
			bacnetCtx(1, "mode-property-reference", BACnetDataTypeDeviceObjectPropertyReference),
		),
		bacnetCtx(4, "fault-state", BACnetDataTypeSequence).of(
			bacnetCtx(0, "list-of-fault-values", BACnetDataTypePropertyStates).listOf(),
		),
		bacnetCtx(5, "fault-status-flags", BACnetDataTypeSequence).of(
			bacnetCtx(0, "status-flags-reference", BACnetDataTypeDeviceObjectPropertyReference),
		),
		bacnetCtx(6, "fault-out-of-range", BACnetDataTypeSequence).of(
			bacnetCtx(0, "min-normal-value", BACnetDataTypeChoice).of(bacnetNormalValue...),
			bacnetCtx(1, "max-normal-value", BACnetDataTypeChoice).of(bacnetNormalValue...),
		),
		bacnetCtx(7, "fault-listed", BACnetDataTypeSequence).of(
			bacnetCtx(0, "fault-list-reference", BACnetDataTypeDeviceObjectPropertyReference),
		),
	}},

	BACnetDataTypeLogRecord: {name: "BACnetLogRecord", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "timestamp", BACnetDataTypeDateTime),
		bacnetCtx(1, "log-datum", BACnetDataTypeChoice).of(
			bacnetCtx(0, "log-status", BACnetDataTypeLogStatus),
			bacnetCtx(1, "boolean-value", BACnetDataTypeBoolean),
			bacnetCtx(2, "real-value", BACnetDataTypeReal),
			bacnetCtx(3, "enumerated-value", BACnetDataTypeEnumerated),
			bacnetCtx(4, "unsigned-value", BACnetDataTypeUnsigned),
			bacnetCtx(5, "integer-value", BACnetDataTypeSigned),
			bacnetCtx(6, "bitstring-value", BACnetDataTypeBitString),
			bacnetCtx(7, "null-value", BACnetDataTypeNull),
			bacnetCtx(8, "failure", BACnetDataTypeError),
			bacnetCtx(9, "time-change", BACnetDataTypeReal),
			bacnetCtx(10, "any-value", BACnetDataTypeAny),
		),
		bacnetCtx(2, "status-flags", BACnetDataTypeStatusFlags).optional(),
	}},
	BACnetDataTypeEventLogRecord: {name: "BACnetEventLogRecord", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "timestamp", BACnetDataTypeDateTime),
		bacnetCtx(1, "log-datum", BACnetDataTypeChoice).of(
			bacnetCtx(0, "log-status", BACnetDataTypeLogStatus),
			bacnetCtx(1, "notification", BACnetDataTypeEventNotification),
			bacnetCtx(2, "time-change", BACnetDataTypeReal),
		),
	}},
	BACnetDataTypeLogMultipleRecord: {name: "BACnetLogMultipleRecord", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "timestamp", BACnetDataTypeDateTime),
		bacnetCtx(1, "log-data", BACnetDataTypeChoice).of(
			bacnetCtx(0, "log-status", BACnetDataTypeLogStatus),
			bacnetCtx(1, "log-data", BACnetDataTypeChoice).of(
				bacnetCtx(0, "boolean-value", BACnetDataTypeBoolean),
				bacnetCtx(1, "real-value", BACnetDataTypeReal),
				bacnetCtx(2, "enumerated-value", BACnetDataTypeEnumerated),
				bacnetCtx(3, "unsigned-value", BACnetDataTypeUnsigned),
				bacnetCtx(4, "integer-value", BACnetDataTypeSigned),
				bacnetCtx(5, "bitstring-value", BACnetDataTypeBitString),
				bacnetCtx(6, "null-value", BACnetDataTypeNull),
				bacnetCtx(7, "failure", BACnetDataTypeError),
				bacnetCtx(8, "any-value", BACnetDataTypeAny),
			).listOf(),
			bacnetCtx(2, "time-change", BACnetDataTypeReal),
		),
	}},
	BACnetDataTypeError: {name: "Error", kind: bacnetKindSequence, fields: bacnetErrorFields},

	BACnetDataTypeReadAccessSpecification: {name: "ReadAccessSpecification", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetObjectField,
		bacnetCtx(1, "list-of-property-references", BACnetDataTypePropertyReference).listOf(),
	}},
	BACnetDataTypeReadAccessResult: {name: "ReadAccessResult", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetObjectField,
		bacnetCtx(1, "list-of-results", BACnetDataTypeSequence).of(
			bacnetCtx(2, "property-identifier", BACnetDataTypePropertyIdentifier).scope(bacnetPropertyScope),
			bacnetCtx(3, "property-array-index", BACnetDataTypeUnsigned).optional().scope(bacnetIndexScope),
			bacnetBare("read-result", BACnetDataTypeChoice).of(
				bacnetCtx(4, "property-value", bacnetDataTypeProperty),
				bacnetCtx(5, "property-access-error", BACnetDataTypeError),
			),
		).listOf().optional(),
	}},
	BACnetDataTypeWriteAccessSpecification: {name: "WriteAccessSpecification", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetObjectField,
		bacnetCtx(1, "list-of-properties", BACnetDataTypePropertyValue).listOf(),
	}},

	BACnetDataTypeScale: {name: "BACnetScale", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetCtx(0, "float-scale", BACnetDataTypeReal),
		bacnetCtx(1, "integer-scale", BACnetDataTypeSigned),
	}},
	BACnetDataTypePrescale: {name: "BACnetPrescale", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "multiplier", BACnetDataTypeUnsigned),
		bacnetCtx(1, "modulo-divide", BACnetDataTypeUnsigned),
	}},
	BACnetDataTypeAccumulatorRecord: {name: "BACnetAccumulatorRecord", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "timestamp", BACnetDataTypeDateTime),
		bacnetCtx(1, "present-value", BACnetDataTypeUnsigned),
		bacnetCtx(2, "accumulated-value", BACnetDataTypeUnsigned),
		bacnetCtx(3, "accumulator-status", BACnetDataTypeAccumulatorStatus),
	}},
	BACnetDataTypeActionCommand: {name: "BACnetActionCommand", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "device-identifier", BACnetDataTypeObjectIdentifier).optional(),
		bacnetCtx(1, "object-identifier", BACnetDataTypeObjectIdentifier).scope(bacnetObjectScope),
		bacnetCtx(2, "property-identifier", BACnetDataTypePropertyIdentifier).scope(bacnetPropertyScope),
		bacnetCtx(3, "property-array-index", BACnetDataTypeUnsigned).optional().scope(bacnetIndexScope),
		bacnetCtx(4, "property-value", bacnetDataTypeProperty),
		bacnetCtx(5, "priority", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(6, "post-delay", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(7, "quit-on-failure", BACnetDataTypeBoolean),
		bacnetCtx(8, "write-successful", BACnetDataTypeBoolean),
	}},
	BACnetDataTypeActionList: {name: "BACnetActionList", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "action", BACnetDataTypeActionCommand).listOf(),
	}},
	BACnetDataTypeSetpointReference: {name: "BACnetSetpointReference", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "setpoint-reference", BACnetDataTypeObjectPropertyReference).optional(),
	}},
	BACnetDataTypeShedLevel: {name: "BACnetShedLevel", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetCtx(0, "percent", BACnetDataTypeUnsigned),
		bacnetCtx(1, "level", BACnetDataTypeUnsigned),
		bacnetCtx(2, "amount", BACnetDataTypeReal),
	}},
	BACnetDataTypeVTSession: {name: "BACnetVTSession", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("local-vt-session-id", BACnetDataTypeUnsigned),
		bacnetBare("remote-vt-session-id", BACnetDataTypeUnsigned),
		bacnetBare("remote-vt-address", BACnetDataTypeAddress),
	}},
	BACnetDataTypeClientCOV: {name: "BACnetClientCOV", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetBare("real-increment", BACnetDataTypeReal),
		bacnetBare("default-increment", BACnetDataTypeNull),
	}},
	BACnetDataTypeLightingCommand: {name: "BACnetLightingCommand", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "operation", BACnetDataTypeLightingOperation),
		bacnetCtx(1, "target-level", BACnetDataTypeReal).optional(),
		bacnetCtx(2, "ramp-rate", BACnetDataTypeReal).optional(),
		bacnetCtx(3, "step-increment", BACnetDataTypeReal).optional(),
		bacnetCtx(4, "fade-time", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(5, "priority", BACnetDataTypeUnsigned).optional(),
	}},
	BACnetDataTypeHostNPort: {name: "BACnetHostNPort", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "host", BACnetDataTypeChoice).of(
			bacnetCtx(0, "none", BACnetDataTypeNull),
			bacnetCtx(1, "ip-address", BACnetDataTypeOctetString),
			bacnetCtx(2, "name", BACnetDataTypeCharacterString),
		),
		bacnetCtx(1, "port", BACnetDataTypeUnsigned),
	}},
	BACnetDataTypeBDTEntry: {name: "BACnetBDTEntry", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "bbmd-address", BACnetDataTypeHostNPort),
		bacnetCtx(1, "broadcast-mask", BACnetDataTypeOctetString).optional(),
	}},
	BACnetDataTypeFDTEntry: {name: "BACnetFDTEntry", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "bacnetip-address", BACnetDataTypeOctetString),
		bacnetCtx(1, "time-to-live", BACnetDataTypeUnsigned),
		bacnetCtx(2, "remaining-time-to-live", BACnetDataTypeUnsigned),
	}},
	BACnetDataTypeVMACEntry: {name: "BACnetVMACEntry", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "virtual-mac-address", BACnetDataTypeOctetString),
		bacnetCtx(1, "native-mac-address", BACnetDataTypeOctetString),
	}},
	BACnetDataTypeRouterEntry: {name: "BACnetRouterEntry", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "network-number", BACnetDataTypeUnsigned),
		bacnetCtx(1, "mac-address", BACnetDataTypeOctetString),
		bacnetCtx(2, "status", BACnetDataTypeEnumerated),
		bacnetCtx(3, "performance-index", BACnetDataTypeUnsigned).optional(),
	}},
	BACnetDataTypeValueSource: {name: "BACnetValueSource", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetCtx(0, "none", BACnetDataTypeNull),
		bacnetCtx(1, "object", BACnetDataTypeDeviceObjectReference),
		bacnetCtx(2, "address", BACnetDataTypeAddress),
	}},
	BACnetDataTypeChannelValue: {name: "BACnetChannelValue", kind: bacnetKindChoice, fields: []bacnetMember{
		bacnetBare("value", bacnetDataTypeApplication),
		bacnetCtx(0, "lighting-command", BACnetDataTypeLightingCommand),
		bacnetCtx(1, "xy-color", BACnetDataTypeXYColor),
		bacnetCtx(2, "color-command", BACnetDataTypeColorCommand),
	}},
	BACnetDataTypeColorCommand: {name: "BACnetColorCommand", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "operation", BACnetDataTypeColorOperation),
		bacnetCtx(1, "target-color", BACnetDataTypeXYColor).optional(),
		bacnetCtx(2, "target-color-temperature", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(3, "fade-time", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(4, "ramp-rate", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(5, "step-increment", BACnetDataTypeUnsigned).optional(),
	}},
	BACnetDataTypeXYColor: {name: "BACnetxyColor", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("x-coordinate", BACnetDataTypeReal),
		bacnetBare("y-coordinate", BACnetDataTypeReal),
	}},
	BACnetDataTypeAuthenticationFactor: {name: "BACnetAuthenticationFactor", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "format-type", BACnetDataTypeAuthenticationFactorType),
		bacnetCtx(1, "format-class", BACnetDataTypeUnsigned),
		bacnetCtx(2, "value", BACnetDataTypeOctetString),
	}},

	// The authorization datatypes of Addendum 135-2020cp.
	BACnetDataTypeAuthorizationConstraint: {name: "BACnetAuthorizationConstraint", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("origin", BACnetDataTypeAuthorizationOrigin),
		bacnetBare("authentication", BACnetDataTypeAuthorizationMethod),
	}},
	BACnetDataTypeAuthorizationScope: {name: "BACnetAuthorizationScope", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetBare("standard", BACnetDataTypeAuthorizationScopes),
		bacnetCtx(0, "extended", BACnetDataTypeCharacterString).listOf().optional(),
	}},
	BACnetDataTypeAccessToken: {name: "BACnetAccessToken", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "issuer", BACnetDataTypeUnsigned),
		bacnetCtx(1, "issued", BACnetDataTypeDateTime),
		bacnetCtx(2, "audience", BACnetDataTypeSigned).listOf(),
		bacnetCtx(3, "not-before", BACnetDataTypeDateTime).optional(),
		bacnetCtx(4, "not-after", BACnetDataTypeDateTime).optional(),
		bacnetCtx(5, "client", BACnetDataTypeUnsigned),
		bacnetCtx(6, "constraint", BACnetDataTypeAuthorizationConstraint),
		bacnetCtx(7, "scope", BACnetDataTypeAuthorizationScope),
		bacnetCtx(8, "key-id", BACnetDataTypeUnsigned),
		bacnetCtx(9, "signature", BACnetDataTypeOctetString),
	}},
	BACnetDataTypeGroupChannelValue: {name: "BACnetGroupChannelValue", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "channel", BACnetDataTypeUnsigned),
		bacnetCtx(1, "overriding-priority", BACnetDataTypeUnsigned).optional(),
		bacnetBare("value", BACnetDataTypeChannelValue),
	}},
	BACnetDataTypeEventNotification: {name: "ConfirmedEventNotification-Request", kind: bacnetKindSequence, fields: bacnetEventNotificationFields},
	BACnetDataTypeEventNotificationSubscription: {name: "BACnetEventNotificationSubscription", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "recipient", BACnetDataTypeRecipient),
		bacnetCtx(1, "process-identifier", BACnetDataTypeUnsigned),
		bacnetCtx(2, "issue-confirmed-notifications", BACnetDataTypeBoolean).optional(),
		bacnetCtx(3, "time-remaining", BACnetDataTypeUnsigned),
	}},
	// Receivers must cope with members a later revision adds or leaves
	// out, so every member is optional here.
	BACnetDataTypeAuditNotification: {name: "BACnetAuditNotification", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "source-timestamp", BACnetDataTypeTimeStamp).optional(),
		bacnetCtx(1, "target-timestamp", BACnetDataTypeTimeStamp).optional(),
		bacnetCtx(2, "source-device", BACnetDataTypeRecipient).optional(),
		bacnetCtx(3, "source-object", BACnetDataTypeObjectIdentifier).optional(),
		bacnetCtx(4, "operation", BACnetDataTypeAuditOperation).optional(),
		bacnetCtx(5, "source-comment", BACnetDataTypeCharacterString).optional(),
		bacnetCtx(6, "target-comment", BACnetDataTypeCharacterString).optional(),
		bacnetCtx(7, "invoke-id", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(8, "source-user-id", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(9, "source-user-role", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(10, "target-device", BACnetDataTypeRecipient).optional(),
		bacnetCtx(11, "target-object", BACnetDataTypeObjectIdentifier).optional().scope(bacnetObjectScope),
		bacnetCtx(12, "target-property", BACnetDataTypePropertyReference).optional().scope(bacnetPropertyScope),
		bacnetCtx(13, "target-priority", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(14, "target-value", bacnetDataTypeProperty).optional(),
		bacnetCtx(15, "current-value", bacnetDataTypeProperty).optional(),
		bacnetCtx(16, "result", BACnetDataTypeError).optional(),
	}},
	BACnetDataTypeAuditLogRecord: {name: "BACnetAuditLogRecord", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "timestamp", BACnetDataTypeDateTime),
		bacnetCtx(1, "log-datum", BACnetDataTypeChoice).of(
			bacnetCtx(0, "log-status", BACnetDataTypeLogStatus),
			bacnetCtx(1, "audit-notification", BACnetDataTypeAuditNotification),
			bacnetCtx(2, "time-change", BACnetDataTypeReal),
		),
	}},
	// The value is any primitive or a BACnetDateTime, whose Time then
	// follows the Date.
	BACnetDataTypeNameValue: {name: "BACnetNameValue", kind: bacnetKindSequence, fields: []bacnetMember{
		bacnetCtx(0, "name", BACnetDataTypeCharacterString),
		bacnetBare("value", bacnetDataTypeApplication).optional(),
		bacnetBare("value-time", BACnetDataTypeTime).optional(),
	}},
}

// Parameters that several services share.
var (
	// bacnetAuditNotificationFields is ConfirmedAuditNotification-Request,
	// which the unconfirmed service shares.
	bacnetAuditNotificationFields = []bacnetMember{
		bacnetCtx(0, "notifications", BACnetDataTypeAuditNotification).listOf(),
	}

	// bacnetEventNotificationFields is ConfirmedEventNotification-Request,
	// which the unconfirmed service and the Event Log reuse.
	bacnetEventNotificationFields = []bacnetMember{
		bacnetCtx(0, "process-identifier", BACnetDataTypeUnsigned),
		bacnetCtx(1, "initiating-device-identifier", BACnetDataTypeObjectIdentifier),
		bacnetCtx(2, "event-object-identifier", BACnetDataTypeObjectIdentifier).scope(bacnetObjectScope),
		bacnetCtx(3, "timestamp", BACnetDataTypeTimeStamp),
		bacnetCtx(4, "notification-class", BACnetDataTypeUnsigned),
		bacnetCtx(5, "priority", BACnetDataTypeUnsigned),
		bacnetCtx(6, "event-type", BACnetDataTypeEventType),
		bacnetCtx(7, "message-text", BACnetDataTypeCharacterString).optional(),
		bacnetCtx(8, "notify-type", BACnetDataTypeNotifyType),
		bacnetCtx(9, "ack-required", BACnetDataTypeBoolean).optional(),
		bacnetCtx(10, "from-state", BACnetDataTypeEventState).optional(),
		bacnetCtx(11, "to-state", BACnetDataTypeEventState),
		bacnetCtx(12, "event-values", BACnetDataTypeNotificationParameters).optional(),
	}

	bacnetCOVNotificationFields = []bacnetMember{
		bacnetCtx(0, "subscriber-process-identifier", BACnetDataTypeUnsigned),
		bacnetCtx(1, "initiating-device-identifier", BACnetDataTypeObjectIdentifier),
		bacnetCtx(2, "monitored-object-identifier", BACnetDataTypeObjectIdentifier).scope(bacnetObjectScope),
		bacnetCtx(3, "time-remaining", BACnetDataTypeUnsigned),
		bacnetCtx(4, "list-of-values", BACnetDataTypePropertyValue).listOf(),
	}

	bacnetCOVMultipleFields = []bacnetMember{
		bacnetCtx(0, "subscriber-process-identifier", BACnetDataTypeUnsigned),
		bacnetCtx(1, "initiating-device-identifier", BACnetDataTypeObjectIdentifier),
		bacnetCtx(2, "time-remaining", BACnetDataTypeUnsigned),
		bacnetCtx(3, "timestamp", BACnetDataTypeDateTime).optional(),
		bacnetCtx(4, "list-of-cov-notifications", BACnetDataTypeSequence).of(
			bacnetCtx(0, "monitored-object-identifier", BACnetDataTypeObjectIdentifier).scope(bacnetObjectScope),
			bacnetCtx(1, "list-of-values", BACnetDataTypeSequence).of(
				bacnetCtx(0, "property-identifier", BACnetDataTypePropertyIdentifier).scope(bacnetPropertyScope),
				bacnetCtx(1, "property-array-index", BACnetDataTypeUnsigned).optional().scope(bacnetIndexScope),
				bacnetCtx(2, "property-value", bacnetDataTypeProperty),
				bacnetCtx(3, "time-of-change", BACnetDataTypeTime).optional(),
			).listOf(),
		).listOf(),
	}

	bacnetPrivateTransferFields = []bacnetMember{
		bacnetCtx(0, "vendor-id", BACnetDataTypeUnsigned),
		bacnetCtx(1, "service-number", BACnetDataTypeUnsigned),
		bacnetCtx(2, "service-parameters", BACnetDataTypeAny).optional(),
	}

	bacnetTextMessageFields = []bacnetMember{
		bacnetCtx(0, "text-message-source-device", BACnetDataTypeObjectIdentifier),
		bacnetCtx(1, "message-class", BACnetDataTypeChoice).of(
			bacnetCtx(0, "numeric", BACnetDataTypeUnsigned),
			bacnetCtx(1, "character", BACnetDataTypeCharacterString),
		).optional(),
		bacnetCtx(2, "message-priority", BACnetDataTypeMessagePriority),
		bacnetCtx(3, "message", BACnetDataTypeCharacterString),
	}

	bacnetTimeSyncFields = []bacnetMember{
		bacnetBare("time", BACnetDataTypeDateTime),
	}

	// bacnetChangeListFields is the request of AddListElement and
	// RemoveListElement.
	bacnetChangeListFields = []bacnetMember{
		bacnetObjectField,
		bacnetPropertyField,
		bacnetIndexField,
		bacnetCtx(3, "list-of-elements", bacnetDataTypeProperty),
	}

	// bacnetChangeListErrorFields is ChangeList-Error, also the layout of
	// CreateObject-Error.
	bacnetChangeListErrorFields = []bacnetMember{
		bacnetCtx(0, "error-type", BACnetDataTypeError),
		bacnetCtx(1, "first-failed-element-number", BACnetDataTypeUnsigned),
	}

	// bacnetFileStream and bacnetFileRecords are the two access methods of
	// a file write, and of a file read ACK.
	bacnetFileStream = bacnetCtx(0, "stream-access", BACnetDataTypeSequence).of(
		bacnetBare("file-start-position", BACnetDataTypeSigned),
		bacnetBare("file-data", BACnetDataTypeOctetString),
	)
	bacnetFileRecords = bacnetCtx(1, "record-access", BACnetDataTypeSequence).of(
		bacnetBare("file-start-record", BACnetDataTypeSigned),
		bacnetBare("record-count", BACnetDataTypeUnsigned),
		bacnetBare("file-record-data", BACnetDataTypeOctetString).listOf(),
	)
)

// bacnetConfirmedRequests gives the parameters of each confirmed request
// (Clause 21, BACnetConfirmedServiceRequest).
var bacnetConfirmedRequests = map[BACnetConfirmedService][]bacnetMember{
	BACnetConfirmedServiceAcknowledgeAlarm: {
		bacnetCtx(0, "acknowledging-process-identifier", BACnetDataTypeUnsigned),
		bacnetCtx(1, "event-object-identifier", BACnetDataTypeObjectIdentifier),
		bacnetCtx(2, "event-state-acknowledged", BACnetDataTypeEventState),
		bacnetCtx(3, "timestamp", BACnetDataTypeTimeStamp),
		bacnetCtx(4, "acknowledgment-source", BACnetDataTypeCharacterString),
		bacnetCtx(5, "time-of-acknowledgment", BACnetDataTypeTimeStamp),
	},
	BACnetConfirmedServiceConfirmedCOVNotification:   bacnetCOVNotificationFields,
	BACnetConfirmedServiceConfirmedEventNotification: bacnetEventNotificationFields,
	BACnetConfirmedServiceGetAlarmSummary:            {},
	BACnetConfirmedServiceGetEnrollmentSummary: {
		bacnetCtx(0, "acknowledgment-filter", BACnetDataTypeAcknowledgmentFilter),
		bacnetCtx(1, "enrollment-filter", BACnetDataTypeRecipientProcess).optional(),
		bacnetCtx(2, "event-state-filter", BACnetDataTypeEventStateFilter).optional(),
		bacnetCtx(3, "event-type-filter", BACnetDataTypeEventType).optional(),
		bacnetCtx(4, "priority-filter", BACnetDataTypeSequence).of(
			bacnetCtx(0, "min-priority", BACnetDataTypeUnsigned),
			bacnetCtx(1, "max-priority", BACnetDataTypeUnsigned),
		).optional(),
		bacnetCtx(5, "notification-class-filter", BACnetDataTypeUnsigned).optional(),
	},
	BACnetConfirmedServiceSubscribeCOV: {
		bacnetCtx(0, "subscriber-process-identifier", BACnetDataTypeUnsigned),
		bacnetCtx(1, "monitored-object-identifier", BACnetDataTypeObjectIdentifier),
		bacnetCtx(2, "issue-confirmed-notifications", BACnetDataTypeBoolean).optional(),
		bacnetCtx(3, "lifetime", BACnetDataTypeUnsigned).optional(),
	},
	BACnetConfirmedServiceAtomicReadFile: {
		bacnetBare("file-identifier", BACnetDataTypeObjectIdentifier),
		bacnetBare("access-method", BACnetDataTypeChoice).of(
			bacnetCtx(0, "stream-access", BACnetDataTypeSequence).of(
				bacnetBare("file-start-position", BACnetDataTypeSigned),
				bacnetBare("requested-octet-count", BACnetDataTypeUnsigned),
			),
			bacnetCtx(1, "record-access", BACnetDataTypeSequence).of(
				bacnetBare("file-start-record", BACnetDataTypeSigned),
				bacnetBare("requested-record-count", BACnetDataTypeUnsigned),
			),
		),
	},
	BACnetConfirmedServiceAtomicWriteFile: {
		bacnetBare("file-identifier", BACnetDataTypeObjectIdentifier),
		bacnetBare("access-method", BACnetDataTypeChoice).of(bacnetFileStream, bacnetFileRecords),
	},
	BACnetConfirmedServiceAddListElement:    bacnetChangeListFields,
	BACnetConfirmedServiceRemoveListElement: bacnetChangeListFields,
	BACnetConfirmedServiceCreateObject: {
		bacnetCtx(0, "object-specifier", BACnetDataTypeChoice).of(
			bacnetCtx(0, "object-type", BACnetDataTypeObjectType).scope(bacnetObjectScope),
			bacnetCtx(1, "object-identifier", BACnetDataTypeObjectIdentifier).scope(bacnetObjectScope),
		).scope(bacnetObjectScope),
		bacnetCtx(1, "list-of-initial-values", BACnetDataTypePropertyValue).listOf().optional(),
	},
	BACnetConfirmedServiceDeleteObject: {
		bacnetBare("object-identifier", BACnetDataTypeObjectIdentifier),
	},
	BACnetConfirmedServiceReadProperty: {bacnetObjectField, bacnetPropertyField, bacnetIndexField},
	BACnetConfirmedServiceReadPropertyMultiple: {
		bacnetBare("list-of-read-access-specifications", BACnetDataTypeReadAccessSpecification).listOf(),
	},
	BACnetConfirmedServiceWriteProperty: {
		bacnetObjectField,
		bacnetPropertyField,
		bacnetIndexField,
		bacnetCtx(3, "property-value", bacnetDataTypeProperty),
		bacnetCtx(4, "priority", BACnetDataTypeUnsigned).optional(),
	},
	BACnetConfirmedServiceWritePropertyMultiple: {
		bacnetBare("list-of-write-access-specifications", BACnetDataTypeWriteAccessSpecification).listOf(),
	},
	BACnetConfirmedServiceDeviceCommunicationControl: {
		bacnetCtx(0, "time-duration", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(1, "enable-disable", BACnetDataTypeEnableDisable),
		bacnetCtx(2, "password", BACnetDataTypeCharacterString).optional(),
	},
	BACnetConfirmedServiceConfirmedPrivateTransfer: bacnetPrivateTransferFields,
	BACnetConfirmedServiceConfirmedTextMessage:     bacnetTextMessageFields,
	BACnetConfirmedServiceReinitializeDevice: {
		bacnetCtx(0, "reinitialized-state-of-device", BACnetDataTypeReinitializedState),
		bacnetCtx(1, "password", BACnetDataTypeCharacterString).optional(),
	},
	BACnetConfirmedServiceVTOpen: {
		bacnetBare("vt-class", BACnetDataTypeVTClass),
		bacnetBare("local-vt-session-identifier", BACnetDataTypeUnsigned),
	},
	BACnetConfirmedServiceVTClose: {
		bacnetBare("list-of-remote-vt-session-identifiers", BACnetDataTypeUnsigned).listOf(),
	},
	BACnetConfirmedServiceVTData: {
		bacnetBare("vt-session-identifier", BACnetDataTypeUnsigned),
		bacnetBare("vt-new-data", BACnetDataTypeOctetString),
		bacnetBare("vt-data-flag", BACnetDataTypeUnsigned),
	},
	// Authenticate and RequestKey left the standard with 135-2010.
	BACnetConfirmedServiceAuthenticate: {
		bacnetCtx(0, "pseudo-random-number", BACnetDataTypeUnsigned),
		bacnetCtx(1, "expected-invoke-id", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(2, "operator-name", BACnetDataTypeCharacterString).optional(),
		bacnetCtx(3, "operator-password", BACnetDataTypeCharacterString).optional(),
		bacnetCtx(4, "start-enciphered-session", BACnetDataTypeBoolean).optional(),
	},
	BACnetConfirmedServiceRequestKey: {
		bacnetBare("requesting-device-identifier", BACnetDataTypeObjectIdentifier),
		bacnetBare("requesting-device-address", BACnetDataTypeAddress),
		bacnetBare("remote-device-identifier", BACnetDataTypeObjectIdentifier),
		bacnetBare("remote-device-address", BACnetDataTypeAddress),
	},
	BACnetConfirmedServiceReadRange: {
		bacnetObjectField,
		bacnetPropertyField,
		bacnetIndexField,
		// Tags 4 and 5 are the time ranges of the first ReadRange.
		bacnetBare("range", BACnetDataTypeChoice).of(
			bacnetCtx(3, "by-position", BACnetDataTypeSequence).of(
				bacnetBare("reference-index", BACnetDataTypeUnsigned),
				bacnetBare("count", BACnetDataTypeSigned),
			),
			bacnetCtx(4, "by-time-deprecated", BACnetDataTypeSequence).of(
				bacnetBare("reference-time", BACnetDataTypeDateTime),
				bacnetBare("count", BACnetDataTypeSigned),
			),
			bacnetCtx(5, "time-range-deprecated", BACnetDataTypeSequence).of(
				bacnetBare("beginning-time", BACnetDataTypeDateTime),
				bacnetBare("ending-time", BACnetDataTypeDateTime),
			),
			bacnetCtx(6, "by-sequence-number", BACnetDataTypeSequence).of(
				bacnetBare("reference-sequence-number", BACnetDataTypeUnsigned),
				bacnetBare("count", BACnetDataTypeSigned),
			),
			bacnetCtx(7, "by-time", BACnetDataTypeSequence).of(
				bacnetBare("reference-time", BACnetDataTypeDateTime),
				bacnetBare("count", BACnetDataTypeSigned),
			),
		).optional(),
	},
	BACnetConfirmedServiceLifeSafetyOperation: {
		bacnetCtx(0, "requesting-process-identifier", BACnetDataTypeUnsigned),
		bacnetCtx(1, "requesting-source", BACnetDataTypeCharacterString),
		bacnetCtx(2, "request", BACnetDataTypeLifeSafetyOperation),
		bacnetCtx(3, "object-identifier", BACnetDataTypeObjectIdentifier).optional(),
	},
	BACnetConfirmedServiceSubscribeCOVProperty: {
		bacnetCtx(0, "subscriber-process-identifier", BACnetDataTypeUnsigned),
		bacnetCtx(1, "monitored-object-identifier", BACnetDataTypeObjectIdentifier),
		bacnetCtx(2, "issue-confirmed-notifications", BACnetDataTypeBoolean).optional(),
		bacnetCtx(3, "lifetime", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(4, "monitored-property-identifier", BACnetDataTypePropertyReference),
		bacnetCtx(5, "cov-increment", BACnetDataTypeReal).optional(),
	},
	BACnetConfirmedServiceGetEventInformation: {
		bacnetCtx(0, "last-received-object-identifier", BACnetDataTypeObjectIdentifier).optional(),
	},
	BACnetConfirmedServiceSubscribeCOVPropertyMultiple: {
		bacnetCtx(0, "subscriber-process-identifier", BACnetDataTypeUnsigned),
		bacnetCtx(1, "issue-confirmed-notifications", BACnetDataTypeBoolean).optional(),
		bacnetCtx(2, "lifetime", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(3, "max-notification-delay", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(4, "list-of-cov-subscription-specifications", BACnetDataTypeSequence).of(
			bacnetCtx(0, "monitored-object-identifier", BACnetDataTypeObjectIdentifier),
			bacnetCtx(1, "list-of-cov-references", BACnetDataTypeSequence).of(
				bacnetCtx(0, "monitored-property", BACnetDataTypePropertyReference),
				bacnetCtx(1, "cov-increment", BACnetDataTypeReal).optional(),
				bacnetCtx(2, "timestamped", BACnetDataTypeBoolean).optional(),
			).listOf(),
		).listOf(),
	},
	BACnetConfirmedServiceConfirmedCOVNotificationMultiple: bacnetCOVMultipleFields,
	BACnetConfirmedServiceConfirmedAuditNotification:       bacnetAuditNotificationFields,
	BACnetConfirmedServiceAuditLogQuery: {
		bacnetCtx(0, "audit-log", BACnetDataTypeObjectIdentifier),
		bacnetCtx(1, "query-parameters", BACnetDataTypeChoice).of(
			bacnetCtx(0, "by-target", BACnetDataTypeSequence).of(
				bacnetCtx(0, "target-device-identifier", BACnetDataTypeObjectIdentifier),
				bacnetCtx(1, "target-device-address", BACnetDataTypeAddress).optional(),
				bacnetCtx(2, "target-object-identifier", BACnetDataTypeObjectIdentifier).optional(),
				bacnetCtx(3, "target-property-identifier", BACnetDataTypePropertyIdentifier).optional(),
				bacnetCtx(4, "target-array-index", BACnetDataTypeUnsigned).optional(),
				bacnetCtx(5, "target-priority", BACnetDataTypeUnsigned).optional(),
				bacnetCtx(6, "operations", BACnetDataTypeBitString).optional(),
				bacnetCtx(7, "result-filter", BACnetDataTypeSuccessFilter).optional(),
			),
			bacnetCtx(1, "by-source", BACnetDataTypeSequence).of(
				bacnetCtx(0, "source-device-identifier", BACnetDataTypeObjectIdentifier),
				bacnetCtx(1, "source-device-address", BACnetDataTypeAddress).optional(),
				bacnetCtx(2, "source-object-identifier", BACnetDataTypeObjectIdentifier).optional(),
				bacnetCtx(3, "operations", BACnetDataTypeBitString).optional(),
				bacnetCtx(4, "result-filter", BACnetDataTypeSuccessFilter).optional(),
			),
		),
		bacnetCtx(2, "start-at-sequence-number", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(3, "requested-count", BACnetDataTypeUnsigned),
	},
	// AuthRequest is a CHOICE with one alternative so far (Addendum
	// 135-2020cp; its erratum makes scope optional).
	BACnetConfirmedServiceAuthRequest: {
		bacnetCtx(0, "token-request", BACnetDataTypeSequence).of(
			bacnetCtx(0, "client", BACnetDataTypeUnsigned),
			bacnetCtx(1, "audience", BACnetDataTypeSigned).listOf(),
			bacnetCtx(2, "scope", BACnetDataTypeAuthorizationScope).optional(),
		),
	},
}

// bacnetComplexACKs gives the parameters of each ComplexACK (Clause 21,
// BACnetConfirmedServiceACK).
var bacnetComplexACKs = map[BACnetConfirmedService][]bacnetMember{
	BACnetConfirmedServiceGetAlarmSummary: {
		bacnetBare("list-of-alarm-summaries", BACnetDataTypeSequence).of(
			bacnetBare("object-identifier", BACnetDataTypeObjectIdentifier),
			bacnetBare("alarm-state", BACnetDataTypeEventState),
			bacnetBare("acknowledged-transitions", BACnetDataTypeEventTransitionBits),
		).listOf(),
	},
	BACnetConfirmedServiceGetEnrollmentSummary: {
		bacnetBare("list-of-enrollment-summaries", BACnetDataTypeSequence).of(
			bacnetBare("object-identifier", BACnetDataTypeObjectIdentifier),
			bacnetBare("event-type", BACnetDataTypeEventType),
			bacnetBare("event-state", BACnetDataTypeEventState),
			bacnetBare("priority", BACnetDataTypeUnsigned),
			bacnetBare("notification-class", BACnetDataTypeUnsigned).optional(),
		).listOf(),
	},
	BACnetConfirmedServiceAtomicReadFile: {
		bacnetBare("end-of-file", BACnetDataTypeBoolean),
		bacnetBare("access-method", BACnetDataTypeChoice).of(
			bacnetFileStream,
			bacnetCtx(1, "record-access", BACnetDataTypeSequence).of(
				bacnetBare("file-start-record", BACnetDataTypeSigned),
				bacnetBare("returned-record-count", BACnetDataTypeUnsigned),
				bacnetBare("file-record-data", BACnetDataTypeOctetString).listOf(),
			),
		),
	},
	BACnetConfirmedServiceAtomicWriteFile: {
		bacnetBare("file-start", BACnetDataTypeChoice).of(
			bacnetCtx(0, "file-start-position", BACnetDataTypeSigned),
			bacnetCtx(1, "file-start-record", BACnetDataTypeSigned),
		),
	},
	BACnetConfirmedServiceCreateObject: {
		bacnetBare("object-identifier", BACnetDataTypeObjectIdentifier),
	},
	BACnetConfirmedServiceReadProperty: {
		bacnetObjectField,
		bacnetPropertyField,
		bacnetIndexField,
		bacnetCtx(3, "property-value", bacnetDataTypeProperty),
	},
	BACnetConfirmedServiceReadPropertyMultiple: {
		bacnetBare("list-of-read-access-results", BACnetDataTypeReadAccessResult).listOf(),
	},
	BACnetConfirmedServiceConfirmedPrivateTransfer: {
		bacnetCtx(0, "vendor-id", BACnetDataTypeUnsigned),
		bacnetCtx(1, "service-number", BACnetDataTypeUnsigned),
		bacnetCtx(2, "result-block", BACnetDataTypeAny).optional(),
	},
	BACnetConfirmedServiceVTOpen: {
		bacnetBare("remote-vt-session-identifier", BACnetDataTypeUnsigned),
	},
	BACnetConfirmedServiceVTData: {
		bacnetCtx(0, "all-new-data-accepted", BACnetDataTypeBoolean),
		bacnetCtx(1, "accepted-octet-count", BACnetDataTypeUnsigned).optional(),
	},
	BACnetConfirmedServiceAuthenticate: {
		bacnetBare("modified-random-number", BACnetDataTypeUnsigned),
	},
	BACnetConfirmedServiceReadRange: {
		bacnetObjectField,
		bacnetPropertyField,
		bacnetIndexField,
		bacnetCtx(3, "result-flags", BACnetDataTypeResultFlags),
		bacnetCtx(4, "item-count", BACnetDataTypeUnsigned),
		bacnetCtx(5, "item-data", bacnetDataTypeProperty),
		bacnetCtx(6, "first-sequence-number", BACnetDataTypeUnsigned).optional(),
	},
	BACnetConfirmedServiceGetEventInformation: {
		bacnetCtx(0, "list-of-event-summaries", BACnetDataTypeSequence).of(
			bacnetCtx(0, "object-identifier", BACnetDataTypeObjectIdentifier),
			bacnetCtx(1, "event-state", BACnetDataTypeEventState),
			bacnetCtx(2, "acknowledged-transitions", BACnetDataTypeEventTransitionBits),
			bacnetCtx(3, "event-timestamps", BACnetDataTypeTimeStamp).listOf(),
			bacnetCtx(4, "notify-type", BACnetDataTypeNotifyType),
			bacnetCtx(5, "event-enable", BACnetDataTypeEventTransitionBits),
			bacnetCtx(6, "event-priorities", BACnetDataTypeUnsigned).listOf(),
		).listOf(),
		bacnetCtx(1, "more-events", BACnetDataTypeBoolean),
	},
	BACnetConfirmedServiceAuditLogQuery: {
		bacnetCtx(0, "audit-log", BACnetDataTypeObjectIdentifier),
		bacnetCtx(1, "records", BACnetDataTypeSequence).of(
			bacnetCtx(0, "sequence-number", BACnetDataTypeUnsigned),
			bacnetCtx(1, "log-record", BACnetDataTypeAuditLogRecord),
		).listOf(),
		bacnetCtx(2, "no-more-items", BACnetDataTypeBoolean),
	},
	BACnetConfirmedServiceAuthRequest: {
		bacnetCtx(0, "token-response", BACnetDataTypeAccessToken),
	},
}

// bacnetUnconfirmedRequests gives the parameters of each unconfirmed
// request (Clause 21, BACnetUnconfirmedServiceRequest).
var bacnetUnconfirmedRequests = map[BACnetUnconfirmedService][]bacnetMember{
	BACnetUnconfirmedServiceIAm: {
		bacnetBare("i-am-device-identifier", BACnetDataTypeObjectIdentifier),
		bacnetBare("max-apdu-length-accepted", BACnetDataTypeUnsigned),
		bacnetBare("segmentation-supported", BACnetDataTypeSegmentation),
		bacnetBare("vendor-id", BACnetDataTypeUnsigned),
	},
	BACnetUnconfirmedServiceIHave: {
		bacnetBare("device-identifier", BACnetDataTypeObjectIdentifier),
		bacnetBare("object-identifier", BACnetDataTypeObjectIdentifier),
		bacnetBare("object-name", BACnetDataTypeCharacterString),
	},
	BACnetUnconfirmedServiceUnconfirmedCOVNotification:   bacnetCOVNotificationFields,
	BACnetUnconfirmedServiceUnconfirmedEventNotification: bacnetEventNotificationFields,
	BACnetUnconfirmedServiceUnconfirmedPrivateTransfer:   bacnetPrivateTransferFields,
	BACnetUnconfirmedServiceUnconfirmedTextMessage:       bacnetTextMessageFields,
	BACnetUnconfirmedServiceTimeSynchronization:          bacnetTimeSyncFields,
	BACnetUnconfirmedServiceWhoHas: {
		bacnetCtx(0, "device-instance-range-low-limit", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(1, "device-instance-range-high-limit", BACnetDataTypeUnsigned).optional(),
		bacnetBare("object", BACnetDataTypeChoice).of(
			bacnetCtx(2, "object-identifier", BACnetDataTypeObjectIdentifier),
			bacnetCtx(3, "object-name", BACnetDataTypeCharacterString),
		),
	},
	BACnetUnconfirmedServiceWhoIs: {
		bacnetCtx(0, "device-instance-range-low-limit", BACnetDataTypeUnsigned).optional(),
		bacnetCtx(1, "device-instance-range-high-limit", BACnetDataTypeUnsigned).optional(),
	},
	BACnetUnconfirmedServiceUTCTimeSynchronization: bacnetTimeSyncFields,
	BACnetUnconfirmedServiceWriteGroup: {
		bacnetCtx(0, "group-number", BACnetDataTypeUnsigned),
		bacnetCtx(1, "write-priority", BACnetDataTypeUnsigned),
		bacnetCtx(2, "change-list", BACnetDataTypeGroupChannelValue).listOf(),
		bacnetCtx(3, "inhibit-delay", BACnetDataTypeBoolean).optional(),
	},
	BACnetUnconfirmedServiceUnconfirmedCOVNotificationMultiple: bacnetCOVMultipleFields,
	BACnetUnconfirmedServiceUnconfirmedAuditNotification:       bacnetAuditNotificationFields,
	BACnetUnconfirmedServiceWhoAmI: {
		bacnetBare("vendor-id", BACnetDataTypeUnsigned),
		bacnetBare("model-name", BACnetDataTypeCharacterString),
		bacnetBare("serial-number", BACnetDataTypeCharacterString),
	},
	BACnetUnconfirmedServiceYouAre: {
		bacnetBare("vendor-id", BACnetDataTypeUnsigned),
		bacnetBare("model-name", BACnetDataTypeCharacterString),
		bacnetBare("serial-number", BACnetDataTypeCharacterString),
		bacnetBare("device-identifier", BACnetDataTypeObjectIdentifier).optional(),
		bacnetBare("device-mac-address", BACnetDataTypeOctetString).optional(),
	},
}

// bacnetServiceErrors gives the Error parameters of the services that
// return more than an Error (Clause 21, BACnetError).
var bacnetServiceErrors = map[BACnetConfirmedService][]bacnetMember{
	BACnetConfirmedServiceAddListElement:    bacnetChangeListErrorFields,
	BACnetConfirmedServiceRemoveListElement: bacnetChangeListErrorFields,
	BACnetConfirmedServiceCreateObject:      bacnetChangeListErrorFields,
	BACnetConfirmedServiceWritePropertyMultiple: {
		bacnetCtx(0, "error-type", BACnetDataTypeError),
		bacnetCtx(1, "first-failed-write-attempt", BACnetDataTypeObjectPropertyReference),
	},
	BACnetConfirmedServiceConfirmedPrivateTransfer: {
		bacnetCtx(0, "error-type", BACnetDataTypeError),
		bacnetCtx(1, "vendor-id", BACnetDataTypeUnsigned),
		bacnetCtx(2, "service-number", BACnetDataTypeUnsigned),
		bacnetCtx(3, "error-parameters", BACnetDataTypeAny).optional(),
	},
	BACnetConfirmedServiceAuthRequest: {
		bacnetCtx(0, "error", BACnetDataTypeError),
		bacnetCtx(1, "error-details", BACnetDataTypeCharacterString).optional(),
	},
	BACnetConfirmedServiceVTClose: {
		bacnetCtx(0, "error-type", BACnetDataTypeError),
		bacnetCtx(1, "list-of-vt-session-identifiers", BACnetDataTypeUnsigned).listOf().optional(),
	},
	BACnetConfirmedServiceSubscribeCOVPropertyMultiple: {
		bacnetCtx(0, "error-type", BACnetDataTypeError),
		bacnetCtx(1, "first-failed-subscription", BACnetDataTypeSequence).of(
			bacnetCtx(0, "monitored-object-identifier", BACnetDataTypeObjectIdentifier),
			bacnetCtx(1, "monitored-property-reference", BACnetDataTypePropertyReference),
			bacnetCtx(2, "error-type", BACnetDataTypeError),
		),
	},
}
