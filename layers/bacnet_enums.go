// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// Enumeration tables from ASHRAE 135 Clause 21 (BACnetObjectType,
// BACnetPropertyIdentifier, BACnetErrorCode).

package layers

// BACnetObjectType is the object type of a BACnetObjectIdentifier (Clause 21).
type BACnetObjectType uint16

// BACnetObjectType values (ASHRAE 135).
const (
	BACnetObjectTypeAnalogInput           BACnetObjectType = 0
	BACnetObjectTypeAnalogOutput          BACnetObjectType = 1
	BACnetObjectTypeAnalogValue           BACnetObjectType = 2
	BACnetObjectTypeBinaryInput           BACnetObjectType = 3
	BACnetObjectTypeBinaryOutput          BACnetObjectType = 4
	BACnetObjectTypeBinaryValue           BACnetObjectType = 5
	BACnetObjectTypeCalendar              BACnetObjectType = 6
	BACnetObjectTypeCommand               BACnetObjectType = 7
	BACnetObjectTypeDevice                BACnetObjectType = 8
	BACnetObjectTypeEventEnrollment       BACnetObjectType = 9
	BACnetObjectTypeFile                  BACnetObjectType = 10
	BACnetObjectTypeGroup                 BACnetObjectType = 11
	BACnetObjectTypeLoop                  BACnetObjectType = 12
	BACnetObjectTypeMultiStateInput       BACnetObjectType = 13
	BACnetObjectTypeMultiStateOutput      BACnetObjectType = 14
	BACnetObjectTypeNotificationClass     BACnetObjectType = 15
	BACnetObjectTypeProgram               BACnetObjectType = 16
	BACnetObjectTypeSchedule              BACnetObjectType = 17
	BACnetObjectTypeAveraging             BACnetObjectType = 18
	BACnetObjectTypeMultiStateValue       BACnetObjectType = 19
	BACnetObjectTypeTrendLog              BACnetObjectType = 20
	BACnetObjectTypeLifeSafetyPoint       BACnetObjectType = 21
	BACnetObjectTypeLifeSafetyZone        BACnetObjectType = 22
	BACnetObjectTypeAccumulator           BACnetObjectType = 23
	BACnetObjectTypePulseConverter        BACnetObjectType = 24
	BACnetObjectTypeEventLog              BACnetObjectType = 25
	BACnetObjectTypeGlobalGroup           BACnetObjectType = 26
	BACnetObjectTypeTrendLogMultiple      BACnetObjectType = 27
	BACnetObjectTypeLoadControl           BACnetObjectType = 28
	BACnetObjectTypeStructuredView        BACnetObjectType = 29
	BACnetObjectTypeAccessDoor            BACnetObjectType = 30
	BACnetObjectTypeTimer                 BACnetObjectType = 31
	BACnetObjectTypeAccessCredential      BACnetObjectType = 32
	BACnetObjectTypeAccessPoint           BACnetObjectType = 33
	BACnetObjectTypeAccessRights          BACnetObjectType = 34
	BACnetObjectTypeAccessUser            BACnetObjectType = 35
	BACnetObjectTypeAccessZone            BACnetObjectType = 36
	BACnetObjectTypeCredentialDataInput   BACnetObjectType = 37
	BACnetObjectTypeNetworkSecurity       BACnetObjectType = 38
	BACnetObjectTypeBitstringValue        BACnetObjectType = 39
	BACnetObjectTypeCharacterstringValue  BACnetObjectType = 40
	BACnetObjectTypeDatePatternValue      BACnetObjectType = 41
	BACnetObjectTypeDateValue             BACnetObjectType = 42
	BACnetObjectTypeDatetimePatternValue  BACnetObjectType = 43
	BACnetObjectTypeDatetimeValue         BACnetObjectType = 44
	BACnetObjectTypeIntegerValue          BACnetObjectType = 45
	BACnetObjectTypeLargeAnalogValue      BACnetObjectType = 46
	BACnetObjectTypeOctetstringValue      BACnetObjectType = 47
	BACnetObjectTypePositiveIntegerValue  BACnetObjectType = 48
	BACnetObjectTypeTimePatternValue      BACnetObjectType = 49
	BACnetObjectTypeTimeValue             BACnetObjectType = 50
	BACnetObjectTypeNotificationForwarder BACnetObjectType = 51
	BACnetObjectTypeAlertEnrollment       BACnetObjectType = 52
	BACnetObjectTypeChannel               BACnetObjectType = 53
	BACnetObjectTypeLightingOutput        BACnetObjectType = 54
	BACnetObjectTypeBinaryLightingOutput  BACnetObjectType = 55
	BACnetObjectTypeNetworkPort           BACnetObjectType = 56
	BACnetObjectTypeElevatorGroup         BACnetObjectType = 57
	BACnetObjectTypeEscalator             BACnetObjectType = 58
	BACnetObjectTypeLift                  BACnetObjectType = 59
	BACnetObjectTypeStaging               BACnetObjectType = 60
	BACnetObjectTypeAuditLog              BACnetObjectType = 61
	BACnetObjectTypeAuditReporter         BACnetObjectType = 62
	BACnetObjectTypeColor                 BACnetObjectType = 63
	BACnetObjectTypeColorTemperature      BACnetObjectType = 64
)

var bacnetObjectTypeNames = map[BACnetObjectType]string{
	0:  "analog-input",
	1:  "analog-output",
	2:  "analog-value",
	3:  "binary-input",
	4:  "binary-output",
	5:  "binary-value",
	6:  "calendar",
	7:  "command",
	8:  "device",
	9:  "event-enrollment",
	10: "file",
	11: "group",
	12: "loop",
	13: "multi-state-input",
	14: "multi-state-output",
	15: "notification-class",
	16: "program",
	17: "schedule",
	18: "averaging",
	19: "multi-state-value",
	20: "trend-log",
	21: "life-safety-point",
	22: "life-safety-zone",
	23: "accumulator",
	24: "pulse-converter",
	25: "event-log",
	26: "global-group",
	27: "trend-log-multiple",
	28: "load-control",
	29: "structured-view",
	30: "access-door",
	31: "timer",
	32: "access-credential",
	33: "access-point",
	34: "access-rights",
	35: "access-user",
	36: "access-zone",
	37: "credential-data-input",
	38: "network-security",
	39: "bitstring-value",
	40: "characterstring-value",
	41: "date-pattern-value",
	42: "date-value",
	43: "datetime-pattern-value",
	44: "datetime-value",
	45: "integer-value",
	46: "large-analog-value",
	47: "octetstring-value",
	48: "positive-integer-value",
	49: "time-pattern-value",
	50: "time-value",
	51: "notification-forwarder",
	52: "alert-enrollment",
	53: "channel",
	54: "lighting-output",
	55: "binary-lighting-output",
	56: "network-port",
	57: "elevator-group",
	58: "escalator",
	59: "lift",
	60: "staging",
	61: "audit-log",
	62: "audit-reporter",
	63: "color",
	64: "color-temperature",
}

// BACnetPropertyIdentifier is a BACnetPropertyIdentifier (Clause 21).
type BACnetPropertyIdentifier uint32

// BACnetPropertyIdentifier values (ASHRAE 135).
const (
	BACnetPropertyAckedTransition                  BACnetPropertyIdentifier = 0
	BACnetPropertyAckRequired                      BACnetPropertyIdentifier = 1
	BACnetPropertyAction                           BACnetPropertyIdentifier = 2
	BACnetPropertyActionText                       BACnetPropertyIdentifier = 3
	BACnetPropertyActiveText                       BACnetPropertyIdentifier = 4
	BACnetPropertyActiveVtSession                  BACnetPropertyIdentifier = 5
	BACnetPropertyAlarmValue                       BACnetPropertyIdentifier = 6
	BACnetPropertyAlarmValues                      BACnetPropertyIdentifier = 7
	BACnetPropertyAll                              BACnetPropertyIdentifier = 8
	BACnetPropertyAllWritesSuccessful              BACnetPropertyIdentifier = 9
	BACnetPropertyApduSegmentTimeout               BACnetPropertyIdentifier = 10
	BACnetPropertyApduTimeout                      BACnetPropertyIdentifier = 11
	BACnetPropertyApplicationSoftwareVersion       BACnetPropertyIdentifier = 12
	BACnetPropertyArchive                          BACnetPropertyIdentifier = 13
	BACnetPropertyBias                             BACnetPropertyIdentifier = 14
	BACnetPropertyChangeOfStateCount               BACnetPropertyIdentifier = 15
	BACnetPropertyChangeOfStateTime                BACnetPropertyIdentifier = 16
	BACnetPropertyNotificationClass                BACnetPropertyIdentifier = 17
	BACnetPropertyThePropertyInThisPlaceWasDeleted BACnetPropertyIdentifier = 18
	BACnetPropertyControlledVariableReference      BACnetPropertyIdentifier = 19
	BACnetPropertyControlledVariableUnits          BACnetPropertyIdentifier = 20
	BACnetPropertyControlledVariableValue          BACnetPropertyIdentifier = 21
	BACnetPropertyCovIncrement                     BACnetPropertyIdentifier = 22
	BACnetPropertyDatelist                         BACnetPropertyIdentifier = 23
	BACnetPropertyDaylightsSavingsStatus           BACnetPropertyIdentifier = 24
	BACnetPropertyDeadband                         BACnetPropertyIdentifier = 25
	BACnetPropertyDerivativeConstant               BACnetPropertyIdentifier = 26
	BACnetPropertyDerivativeConstantUnits          BACnetPropertyIdentifier = 27
	BACnetPropertyDescription                      BACnetPropertyIdentifier = 28
	BACnetPropertyDescriptionOfHalt                BACnetPropertyIdentifier = 29
	BACnetPropertyDeviceAddressBinding             BACnetPropertyIdentifier = 30
	BACnetPropertyDeviceType                       BACnetPropertyIdentifier = 31
	BACnetPropertyEffectivePeriod                  BACnetPropertyIdentifier = 32
	BACnetPropertyElapsedActiveTime                BACnetPropertyIdentifier = 33
	BACnetPropertyErrorLimit                       BACnetPropertyIdentifier = 34
	BACnetPropertyEventEnable                      BACnetPropertyIdentifier = 35
	BACnetPropertyEventState                       BACnetPropertyIdentifier = 36
	BACnetPropertyEventType                        BACnetPropertyIdentifier = 37
	BACnetPropertyExceptionSchedule                BACnetPropertyIdentifier = 38
	BACnetPropertyFaultValues                      BACnetPropertyIdentifier = 39
	BACnetPropertyFeedbackValue                    BACnetPropertyIdentifier = 40
	BACnetPropertyFileAccessMethod                 BACnetPropertyIdentifier = 41
	BACnetPropertyFileSize                         BACnetPropertyIdentifier = 42
	BACnetPropertyFileType                         BACnetPropertyIdentifier = 43
	BACnetPropertyFirmwareRevision                 BACnetPropertyIdentifier = 44
	BACnetPropertyHighLimit                        BACnetPropertyIdentifier = 45
	BACnetPropertyInactiveText                     BACnetPropertyIdentifier = 46
	BACnetPropertyInProcess                        BACnetPropertyIdentifier = 47
	BACnetPropertyInstanceOf                       BACnetPropertyIdentifier = 48
	BACnetPropertyIntegralConstant                 BACnetPropertyIdentifier = 49
	BACnetPropertyIntegralConstantUnits            BACnetPropertyIdentifier = 50
	BACnetPropertyIssueConfirmedNotifications      BACnetPropertyIdentifier = 51
	BACnetPropertyLimitEnable                      BACnetPropertyIdentifier = 52
	BACnetPropertyListOfGroupMembers               BACnetPropertyIdentifier = 53
	BACnetPropertyListOfObjectPropertyReferences   BACnetPropertyIdentifier = 54
	BACnetPropertyListOfSessionKeys                BACnetPropertyIdentifier = 55
	BACnetPropertyLocalDate                        BACnetPropertyIdentifier = 56
	BACnetPropertyLocalTime                        BACnetPropertyIdentifier = 57
	BACnetPropertyLocation                         BACnetPropertyIdentifier = 58
	BACnetPropertyLowLimit                         BACnetPropertyIdentifier = 59
	BACnetPropertyManipulatedVariableReference     BACnetPropertyIdentifier = 60
	BACnetPropertyMaximumOutput                    BACnetPropertyIdentifier = 61
	BACnetPropertyMaxApduLengthAccepted            BACnetPropertyIdentifier = 62
	BACnetPropertyMaxInfoFrames                    BACnetPropertyIdentifier = 63
	BACnetPropertyMaxMaster                        BACnetPropertyIdentifier = 64
	BACnetPropertyMaxPresValue                     BACnetPropertyIdentifier = 65
	BACnetPropertyMinimumOffTime                   BACnetPropertyIdentifier = 66
	BACnetPropertyMinimumOnTime                    BACnetPropertyIdentifier = 67
	BACnetPropertyMinimumOutput                    BACnetPropertyIdentifier = 68
	BACnetPropertyMinPresValue                     BACnetPropertyIdentifier = 69
	BACnetPropertyModelName                        BACnetPropertyIdentifier = 70
	BACnetPropertyModificationDate                 BACnetPropertyIdentifier = 71
	BACnetPropertyNotifyType                       BACnetPropertyIdentifier = 72
	BACnetPropertyNumberOfAPDURetries              BACnetPropertyIdentifier = 73
	BACnetPropertyNumberOfStates                   BACnetPropertyIdentifier = 74
	BACnetPropertyObjectIdentifier                 BACnetPropertyIdentifier = 75
	BACnetPropertyObjectList                       BACnetPropertyIdentifier = 76
	BACnetPropertyObjectName                       BACnetPropertyIdentifier = 77
	BACnetPropertyObjectPropertyReference          BACnetPropertyIdentifier = 78
	BACnetPropertyObjectType                       BACnetPropertyIdentifier = 79
	BACnetPropertyOptional                         BACnetPropertyIdentifier = 80
	BACnetPropertyOutOfService                     BACnetPropertyIdentifier = 81
	BACnetPropertyOutputUnits                      BACnetPropertyIdentifier = 82
	BACnetPropertyEventParameters                  BACnetPropertyIdentifier = 83
	BACnetPropertyPolarity                         BACnetPropertyIdentifier = 84
	BACnetPropertyPresentValue                     BACnetPropertyIdentifier = 85
	BACnetPropertyPriority                         BACnetPropertyIdentifier = 86
	BACnetPropertyPriorityArray                    BACnetPropertyIdentifier = 87
	BACnetPropertyPriorityForWriting               BACnetPropertyIdentifier = 88
	BACnetPropertyProcessIdentifier                BACnetPropertyIdentifier = 89
	BACnetPropertyProgramChange                    BACnetPropertyIdentifier = 90
	BACnetPropertyProgramLocation                  BACnetPropertyIdentifier = 91
	BACnetPropertyProgramState                     BACnetPropertyIdentifier = 92
	BACnetPropertyProportionalConstant             BACnetPropertyIdentifier = 93
	BACnetPropertyProportionalConstantUnits        BACnetPropertyIdentifier = 94
	BACnetPropertyProtocolConformanceClass         BACnetPropertyIdentifier = 95
	BACnetPropertyProtocolObjectTypesSupported     BACnetPropertyIdentifier = 96
	BACnetPropertyProtocolServicesSupported        BACnetPropertyIdentifier = 97
	BACnetPropertyProtocolVersion                  BACnetPropertyIdentifier = 98
	BACnetPropertyReadOnly                         BACnetPropertyIdentifier = 99
	BACnetPropertyReasonForHalt                    BACnetPropertyIdentifier = 100
	BACnetPropertyRecipient                        BACnetPropertyIdentifier = 101
	BACnetPropertyRecipientList                    BACnetPropertyIdentifier = 102
	BACnetPropertyReliability                      BACnetPropertyIdentifier = 103
	BACnetPropertyRelinquishDefault                BACnetPropertyIdentifier = 104
	BACnetPropertyRequired                         BACnetPropertyIdentifier = 105
	BACnetPropertyResolution                       BACnetPropertyIdentifier = 106
	BACnetPropertySegmentationSupported            BACnetPropertyIdentifier = 107
	BACnetPropertySetpoint                         BACnetPropertyIdentifier = 108
	BACnetPropertySetpointReference                BACnetPropertyIdentifier = 109
	BACnetPropertyStateText                        BACnetPropertyIdentifier = 110
	BACnetPropertyStatusFlags                      BACnetPropertyIdentifier = 111
	BACnetPropertySystemStatus                     BACnetPropertyIdentifier = 112
	BACnetPropertyTimeDelay                        BACnetPropertyIdentifier = 113
	BACnetPropertyTimeOfActiveTimeReset            BACnetPropertyIdentifier = 114
	BACnetPropertyTimeOfStateCountReset            BACnetPropertyIdentifier = 115
	BACnetPropertyTimeSynchronizationRecipients    BACnetPropertyIdentifier = 116
	BACnetPropertyUnits                            BACnetPropertyIdentifier = 117
	BACnetPropertyUpdateInterval                   BACnetPropertyIdentifier = 118
	BACnetPropertyUtcOffset                        BACnetPropertyIdentifier = 119
	BACnetPropertyVendorIdentifier                 BACnetPropertyIdentifier = 120
	BACnetPropertyVendorName                       BACnetPropertyIdentifier = 121
	BACnetPropertyVtClassSupported                 BACnetPropertyIdentifier = 122
	BACnetPropertyWeeklySchedule                   BACnetPropertyIdentifier = 123
	BACnetPropertyAttemptedSamples                 BACnetPropertyIdentifier = 124
	BACnetPropertyAverageValue                     BACnetPropertyIdentifier = 125
	BACnetPropertyBufferSize                       BACnetPropertyIdentifier = 126
	BACnetPropertyClientCovIncrement               BACnetPropertyIdentifier = 127
	BACnetPropertyCovResubscriptionInterval        BACnetPropertyIdentifier = 128
	BACnetPropertyCurrentNotifyTime                BACnetPropertyIdentifier = 129
	BACnetPropertyEventTimeStamp                   BACnetPropertyIdentifier = 130
	BACnetPropertyLogBuffer                        BACnetPropertyIdentifier = 131
	BACnetPropertyLogDeviceObjectProperty          BACnetPropertyIdentifier = 132
	BACnetPropertyEnable                           BACnetPropertyIdentifier = 133
	BACnetPropertyLogInterval                      BACnetPropertyIdentifier = 134
	BACnetPropertyMaximumValue                     BACnetPropertyIdentifier = 135
	BACnetPropertyMinimumValue                     BACnetPropertyIdentifier = 136
	BACnetPropertyNotificationThreshold            BACnetPropertyIdentifier = 137
	BACnetPropertyPreviousNotifyTime               BACnetPropertyIdentifier = 138
	BACnetPropertyProtocolRevision                 BACnetPropertyIdentifier = 139
	BACnetPropertyRecordsSinceNotification         BACnetPropertyIdentifier = 140
	BACnetPropertyRecordCount                      BACnetPropertyIdentifier = 141
	BACnetPropertyStartTime                        BACnetPropertyIdentifier = 142
	BACnetPropertyStopTime                         BACnetPropertyIdentifier = 143
	BACnetPropertyStopWhenFull                     BACnetPropertyIdentifier = 144
	BACnetPropertyTotalRecordCount                 BACnetPropertyIdentifier = 145
	BACnetPropertyValidSamples                     BACnetPropertyIdentifier = 146
	BACnetPropertyWindowInterval                   BACnetPropertyIdentifier = 147
	BACnetPropertyWindowSamples                    BACnetPropertyIdentifier = 148
	BACnetPropertyMaximumValueTimeStamp            BACnetPropertyIdentifier = 149
	BACnetPropertyMinimumValueTimeStamp            BACnetPropertyIdentifier = 150
	BACnetPropertyVarianceValue                    BACnetPropertyIdentifier = 151
	BACnetPropertyActiveCovSubscriptions           BACnetPropertyIdentifier = 152
	BACnetPropertyBackupFailureTimeout             BACnetPropertyIdentifier = 153
	BACnetPropertyConfigurationFiles               BACnetPropertyIdentifier = 154
	BACnetPropertyDatabaseRevision                 BACnetPropertyIdentifier = 155
	BACnetPropertyDirectReading                    BACnetPropertyIdentifier = 156
	BACnetPropertyLastRestoreTime                  BACnetPropertyIdentifier = 157
	BACnetPropertyMaintenanceRequired              BACnetPropertyIdentifier = 158
	BACnetPropertyMemberOf                         BACnetPropertyIdentifier = 159
	BACnetPropertyMode                             BACnetPropertyIdentifier = 160
	BACnetPropertyOperationExpected                BACnetPropertyIdentifier = 161
	BACnetPropertySetting                          BACnetPropertyIdentifier = 162
	BACnetPropertySilenced                         BACnetPropertyIdentifier = 163
	BACnetPropertyTrackingValue                    BACnetPropertyIdentifier = 164
	BACnetPropertyZoneMembers                      BACnetPropertyIdentifier = 165
	BACnetPropertyLifeSafetyAlarmValues            BACnetPropertyIdentifier = 166
	BACnetPropertyMaxSegmentsAccepted              BACnetPropertyIdentifier = 167
	BACnetPropertyProfileName                      BACnetPropertyIdentifier = 168
	BACnetPropertyAutoSlaveDiscovery               BACnetPropertyIdentifier = 169
	BACnetPropertyManualSlaveAddressBinding        BACnetPropertyIdentifier = 170
	BACnetPropertySlaveAddressBinding              BACnetPropertyIdentifier = 171
	BACnetPropertySlaveProxyEnable                 BACnetPropertyIdentifier = 172
	BACnetPropertyLastNotifyRecord                 BACnetPropertyIdentifier = 173
	BACnetPropertyScheduleDefault                  BACnetPropertyIdentifier = 174
	BACnetPropertyAcceptedModes                    BACnetPropertyIdentifier = 175
	BACnetPropertyAdjustValue                      BACnetPropertyIdentifier = 176
	BACnetPropertyCount                            BACnetPropertyIdentifier = 177
	BACnetPropertyCountBeforeChange                BACnetPropertyIdentifier = 178
	BACnetPropertyCountChangeTime                  BACnetPropertyIdentifier = 179
	BACnetPropertyCovPeriod                        BACnetPropertyIdentifier = 180
	BACnetPropertyInputReference                   BACnetPropertyIdentifier = 181
	BACnetPropertyLimitMonitoringInterval          BACnetPropertyIdentifier = 182
	BACnetPropertyLoggingObject                    BACnetPropertyIdentifier = 183
	BACnetPropertyLoggingRecord                    BACnetPropertyIdentifier = 184
	BACnetPropertyPrescale                         BACnetPropertyIdentifier = 185
	BACnetPropertyPulseRate                        BACnetPropertyIdentifier = 186
	BACnetPropertyScale                            BACnetPropertyIdentifier = 187
	BACnetPropertyScaleFactor                      BACnetPropertyIdentifier = 188
	BACnetPropertyUpdateTime                       BACnetPropertyIdentifier = 189
	BACnetPropertyValueBeforeChange                BACnetPropertyIdentifier = 190
	BACnetPropertyValueSet                         BACnetPropertyIdentifier = 191
	BACnetPropertyValueChangeTime                  BACnetPropertyIdentifier = 192
	BACnetPropertyAlignIntervals                   BACnetPropertyIdentifier = 193
	BACnetPropertyIntervalOffset                   BACnetPropertyIdentifier = 195
	BACnetPropertyLastRestartReason                BACnetPropertyIdentifier = 196
	BACnetPropertyLoggingType                      BACnetPropertyIdentifier = 197
	BACnetPropertyNotificationPeriod               BACnetPropertyIdentifier = 199
	BACnetPropertyPreviousNotifyRecord             BACnetPropertyIdentifier = 200
	BACnetPropertyRestartNotificationRecipients    BACnetPropertyIdentifier = 202
	BACnetPropertyTimeOfDeviceRestart              BACnetPropertyIdentifier = 203
	BACnetPropertyTimeSynchronizationInterval      BACnetPropertyIdentifier = 204
	BACnetPropertyTrigger                          BACnetPropertyIdentifier = 205
	BACnetPropertyUTCTimeSynchronizationRecipients BACnetPropertyIdentifier = 206
	BACnetPropertyNodeSubtype                      BACnetPropertyIdentifier = 207
	BACnetPropertyNodeType                         BACnetPropertyIdentifier = 208
	BACnetPropertyStructuredObjectList             BACnetPropertyIdentifier = 209
	BACnetPropertySubordinateAnnotations           BACnetPropertyIdentifier = 210
	BACnetPropertySubordinateList                  BACnetPropertyIdentifier = 211
	BACnetPropertyActualShedLevel                  BACnetPropertyIdentifier = 212
	BACnetPropertyDutyWindow                       BACnetPropertyIdentifier = 213
	BACnetPropertyExpectedShedLevel                BACnetPropertyIdentifier = 214
	BACnetPropertyFullDutyBaseline                 BACnetPropertyIdentifier = 215
	BACnetPropertyRequestedShedLevel               BACnetPropertyIdentifier = 218
	BACnetPropertyShedDuration                     BACnetPropertyIdentifier = 219
	BACnetPropertyShedLevelDescriptions            BACnetPropertyIdentifier = 220
	BACnetPropertyShedLevels                       BACnetPropertyIdentifier = 221
	BACnetPropertyStateDescription                 BACnetPropertyIdentifier = 222
	BACnetPropertyDoorAlarmState                   BACnetPropertyIdentifier = 226
	BACnetPropertyDoorExtendedPulseTime            BACnetPropertyIdentifier = 227
	BACnetPropertyDoorMembers                      BACnetPropertyIdentifier = 228
	BACnetPropertyDoorOpenTooLongTime              BACnetPropertyIdentifier = 229
	BACnetPropertyDoorPulseTime                    BACnetPropertyIdentifier = 230
	BACnetPropertyDoorStatus                       BACnetPropertyIdentifier = 231
	BACnetPropertyDoorUnlockDelayTime              BACnetPropertyIdentifier = 232
	BACnetPropertyLockStatus                       BACnetPropertyIdentifier = 233
	BACnetPropertyMaskedAlarmValues                BACnetPropertyIdentifier = 234
	BACnetPropertySecuredStatus                    BACnetPropertyIdentifier = 235
	BACnetPropertyAbsenteeLimit                    BACnetPropertyIdentifier = 244
	BACnetPropertyAccessAlarmEvents                BACnetPropertyIdentifier = 245
	BACnetPropertyAccessDoors                      BACnetPropertyIdentifier = 246
	BACnetPropertyAccessEvent                      BACnetPropertyIdentifier = 247
	BACnetPropertyAccessEventAuthenticationFactor  BACnetPropertyIdentifier = 248
	BACnetPropertyAccessEventCredential            BACnetPropertyIdentifier = 249
	BACnetPropertyAccessEventTime                  BACnetPropertyIdentifier = 250
	BACnetPropertyAccessTransactionEvents          BACnetPropertyIdentifier = 251
	BACnetPropertyAccompaniment                    BACnetPropertyIdentifier = 252
	BACnetPropertyAccompanimentTime                BACnetPropertyIdentifier = 253
	BACnetPropertyActivationTime                   BACnetPropertyIdentifier = 254
	BACnetPropertyActiveAuthenticationPolicy       BACnetPropertyIdentifier = 255
	BACnetPropertyAssignedAccessRights             BACnetPropertyIdentifier = 256
	BACnetPropertyAuthenticationFactors            BACnetPropertyIdentifier = 257
	BACnetPropertyAuthenticationPolicyList         BACnetPropertyIdentifier = 258
	BACnetPropertyAuthenticationPolicyNames        BACnetPropertyIdentifier = 259
	BACnetPropertyAuthenticationStatus             BACnetPropertyIdentifier = 260
	BACnetPropertyAuthorizationMode                BACnetPropertyIdentifier = 261
	BACnetPropertyBelongsTo                        BACnetPropertyIdentifier = 262
	BACnetPropertyCredentialDisable                BACnetPropertyIdentifier = 263
	BACnetPropertyCredentialStatus                 BACnetPropertyIdentifier = 264
	BACnetPropertyCredentials                      BACnetPropertyIdentifier = 265
	BACnetPropertyCredentialsInZone                BACnetPropertyIdentifier = 266
	BACnetPropertyDaysRemaining                    BACnetPropertyIdentifier = 267
	BACnetPropertyEntryPoints                      BACnetPropertyIdentifier = 268
	BACnetPropertyExitPoints                       BACnetPropertyIdentifier = 269
	BACnetPropertyExpirationTime                   BACnetPropertyIdentifier = 270
	BACnetPropertyExtendedTimeEnable               BACnetPropertyIdentifier = 271
	BACnetPropertyFailedAttemptEvents              BACnetPropertyIdentifier = 272
	BACnetPropertyFailedAttempts                   BACnetPropertyIdentifier = 273
	BACnetPropertyFailedAttemptsTime               BACnetPropertyIdentifier = 274
	BACnetPropertyLastAccessEvent                  BACnetPropertyIdentifier = 275
	BACnetPropertyLastAccessPoint                  BACnetPropertyIdentifier = 276
	BACnetPropertyLastCredentialAdded              BACnetPropertyIdentifier = 277
	BACnetPropertyLastCredentialAddedTime          BACnetPropertyIdentifier = 278
	BACnetPropertyLastCredentialRemoved            BACnetPropertyIdentifier = 279
	BACnetPropertyLastCredentialRemovedTime        BACnetPropertyIdentifier = 280
	BACnetPropertyLastUseTime                      BACnetPropertyIdentifier = 281
	BACnetPropertyLockout                          BACnetPropertyIdentifier = 282
	BACnetPropertyLockoutRelinquishTime            BACnetPropertyIdentifier = 283
	BACnetPropertyMasterExemption                  BACnetPropertyIdentifier = 284
	BACnetPropertyMaxFailedAttempts                BACnetPropertyIdentifier = 285
	BACnetPropertyMembers                          BACnetPropertyIdentifier = 286
	BACnetPropertyMusterPoint                      BACnetPropertyIdentifier = 287
	BACnetPropertyNegativeAccessRules              BACnetPropertyIdentifier = 288
	BACnetPropertyNumberOfAuthenticationPolicies   BACnetPropertyIdentifier = 289
	BACnetPropertyOccupancyCount                   BACnetPropertyIdentifier = 290
	BACnetPropertyOccupancyCountAdjust             BACnetPropertyIdentifier = 291
	BACnetPropertyOccupancyCountEnable             BACnetPropertyIdentifier = 292
	BACnetPropertyOccupancyExemption               BACnetPropertyIdentifier = 293
	BACnetPropertyOccupancyLowerLimit              BACnetPropertyIdentifier = 294
	BACnetPropertyOccupancyLowerLimitEnforced      BACnetPropertyIdentifier = 295
	BACnetPropertyOccupancyState                   BACnetPropertyIdentifier = 296
	BACnetPropertyOccupancyUpperLimit              BACnetPropertyIdentifier = 297
	BACnetPropertyOccupancyUpperLimitEnforced      BACnetPropertyIdentifier = 298
	BACnetPropertyPassbackExemption                BACnetPropertyIdentifier = 299
	BACnetPropertyPassbackMode                     BACnetPropertyIdentifier = 300
	BACnetPropertyPassbackTimeout                  BACnetPropertyIdentifier = 301
	BACnetPropertyPositiveAccessRules              BACnetPropertyIdentifier = 302
	BACnetPropertyReasonForDisable                 BACnetPropertyIdentifier = 303
	BACnetPropertySupportedFormats                 BACnetPropertyIdentifier = 304
	BACnetPropertySupportedFormatClasses           BACnetPropertyIdentifier = 305
	BACnetPropertyThreatAuthority                  BACnetPropertyIdentifier = 306
	BACnetPropertyThreatLevel                      BACnetPropertyIdentifier = 307
	BACnetPropertyTraceFlag                        BACnetPropertyIdentifier = 308
	BACnetPropertyTransactionNotificationClass     BACnetPropertyIdentifier = 309
	BACnetPropertyUserExternalIdentifier           BACnetPropertyIdentifier = 310
	BACnetPropertyUserInformationReference         BACnetPropertyIdentifier = 311
	BACnetPropertyUserName                         BACnetPropertyIdentifier = 317
	BACnetPropertyUserType                         BACnetPropertyIdentifier = 318
	BACnetPropertyUsesRemaining                    BACnetPropertyIdentifier = 319
	BACnetPropertyZoneFrom                         BACnetPropertyIdentifier = 320
	BACnetPropertyZoneTo                           BACnetPropertyIdentifier = 321
	BACnetPropertyAccessEventTag                   BACnetPropertyIdentifier = 322
	BACnetPropertyGlobalIdentifier                 BACnetPropertyIdentifier = 323
	BACnetPropertyVerificationTime                 BACnetPropertyIdentifier = 326
	BACnetPropertyBaseDeviceSecurityPolicy         BACnetPropertyIdentifier = 327
	BACnetPropertyDistributionKeyRevision          BACnetPropertyIdentifier = 328
	BACnetPropertyDoNotHide                        BACnetPropertyIdentifier = 329
	BACnetPropertyKeySets                          BACnetPropertyIdentifier = 330
	BACnetPropertyLastKeyServer                    BACnetPropertyIdentifier = 331
	BACnetPropertyNetworkAccessSecurityPolicies    BACnetPropertyIdentifier = 332
	BACnetPropertyPacketReorderTime                BACnetPropertyIdentifier = 333
	BACnetPropertySecurityPduTimeout               BACnetPropertyIdentifier = 334
	BACnetPropertySecurityTimeWindow               BACnetPropertyIdentifier = 335
	BACnetPropertySupportedSecurityAlgorithms      BACnetPropertyIdentifier = 336
	BACnetPropertyUpdateKeySetTimeout              BACnetPropertyIdentifier = 337
	BACnetPropertyBackupAndRestoreState            BACnetPropertyIdentifier = 338
	BACnetPropertyBackupPreparationTime            BACnetPropertyIdentifier = 339
	BACnetPropertyRestoreCompletionTime            BACnetPropertyIdentifier = 340
	BACnetPropertyRestorePreparationTime           BACnetPropertyIdentifier = 341
	BACnetPropertyBitMask                          BACnetPropertyIdentifier = 342
	BACnetPropertyBitText                          BACnetPropertyIdentifier = 343
	BACnetPropertyIsUtc                            BACnetPropertyIdentifier = 344
	BACnetPropertyGroupMembers                     BACnetPropertyIdentifier = 345
	BACnetPropertyGroupMemberNames                 BACnetPropertyIdentifier = 346
	BACnetPropertyMemberStatusFlags                BACnetPropertyIdentifier = 347
	BACnetPropertyRequestedUpdateInterval          BACnetPropertyIdentifier = 348
	BACnetPropertyCovuPeriod                       BACnetPropertyIdentifier = 349
	BACnetPropertyCovuRecipients                   BACnetPropertyIdentifier = 350
	BACnetPropertyEventMessageTexts                BACnetPropertyIdentifier = 351
	BACnetPropertyEventMessageTextsConfig          BACnetPropertyIdentifier = 352
	BACnetPropertyEventDetectionEnable             BACnetPropertyIdentifier = 353
	BACnetPropertyEventAlgorithmInhibit            BACnetPropertyIdentifier = 354
	BACnetPropertyEventAlgorithmInhibitRef         BACnetPropertyIdentifier = 355
	BACnetPropertyTimeDelayNormal                  BACnetPropertyIdentifier = 356
	BACnetPropertyReliabilityEvaluationInhibit     BACnetPropertyIdentifier = 357
	BACnetPropertyFaultParameters                  BACnetPropertyIdentifier = 358
	BACnetPropertyFaultType                        BACnetPropertyIdentifier = 359
	BACnetPropertyLocalForwardingOnly              BACnetPropertyIdentifier = 360
	BACnetPropertyProcessIdentifierFilter          BACnetPropertyIdentifier = 361
	BACnetPropertySubscribedRecipients             BACnetPropertyIdentifier = 362
	BACnetPropertyPortFilter                       BACnetPropertyIdentifier = 363
	BACnetPropertyAuthorizationExemptions          BACnetPropertyIdentifier = 364
	BACnetPropertyAllowGroupDelayInhibit           BACnetPropertyIdentifier = 365
	BACnetPropertyChannelNumber                    BACnetPropertyIdentifier = 366
	BACnetPropertyControlGroups                    BACnetPropertyIdentifier = 367
	BACnetPropertyExecutionDelay                   BACnetPropertyIdentifier = 368
	BACnetPropertyLastPriority                     BACnetPropertyIdentifier = 369
	BACnetPropertyWriteStatus                      BACnetPropertyIdentifier = 370
	BACnetPropertyPropertyList                     BACnetPropertyIdentifier = 371
	BACnetPropertySerialNumber                     BACnetPropertyIdentifier = 372
	BACnetPropertyBlinkWarnEnable                  BACnetPropertyIdentifier = 373
	BACnetPropertyDefaultFadeTime                  BACnetPropertyIdentifier = 374
	BACnetPropertyDefaultRampRate                  BACnetPropertyIdentifier = 375
	BACnetPropertyDefaultStepIncrement             BACnetPropertyIdentifier = 376
	BACnetPropertyEgressTime                       BACnetPropertyIdentifier = 377
	BACnetPropertyInProgress                       BACnetPropertyIdentifier = 378
	BACnetPropertyInstantaneousPower               BACnetPropertyIdentifier = 379
	BACnetPropertyLightingCommand                  BACnetPropertyIdentifier = 380
	BACnetPropertyLightingCommandDefaultPriority   BACnetPropertyIdentifier = 381
	BACnetPropertyMaxActualValue                   BACnetPropertyIdentifier = 382
	BACnetPropertyMinActualValue                   BACnetPropertyIdentifier = 383
	BACnetPropertyPower                            BACnetPropertyIdentifier = 384
	BACnetPropertyTransition                       BACnetPropertyIdentifier = 385
	BACnetPropertyEgressActive                     BACnetPropertyIdentifier = 386
	BACnetPropertyInterfaceValue                   BACnetPropertyIdentifier = 387
	BACnetPropertyFaultHighLimit                   BACnetPropertyIdentifier = 388
	BACnetPropertyFaultLowLimit                    BACnetPropertyIdentifier = 389
	BACnetPropertyLowDiffLimit                     BACnetPropertyIdentifier = 390
	BACnetPropertyStrikeCount                      BACnetPropertyIdentifier = 391
	BACnetPropertyTimeOfStrikeCountReset           BACnetPropertyIdentifier = 392
	BACnetPropertyDefaultTimeout                   BACnetPropertyIdentifier = 393
	BACnetPropertyInitialTimeout                   BACnetPropertyIdentifier = 394
	BACnetPropertyLastStateChange                  BACnetPropertyIdentifier = 395
	BACnetPropertyStateChangeValues                BACnetPropertyIdentifier = 396
	BACnetPropertyTimerRunning                     BACnetPropertyIdentifier = 397
	BACnetPropertyTimerState                       BACnetPropertyIdentifier = 398
	BACnetPropertyApduLength                       BACnetPropertyIdentifier = 399
	BACnetPropertyBACnetIPAddress                  BACnetPropertyIdentifier = 400
	BACnetPropertyBACnetIPDefaultGateway           BACnetPropertyIdentifier = 401
	BACnetPropertyBACnetIPDhcpEnable               BACnetPropertyIdentifier = 402
	BACnetPropertyBACnetIPDhcpLeaseTime            BACnetPropertyIdentifier = 403
	BACnetPropertyBACnetIPDhcpLeaseTimeRemaining   BACnetPropertyIdentifier = 404
	BACnetPropertyBACnetIPDhcpServer               BACnetPropertyIdentifier = 405
	BACnetPropertyBACnetIPDNSServer                BACnetPropertyIdentifier = 406
	BACnetPropertyBACnetIPGlobalAddress            BACnetPropertyIdentifier = 407
	BACnetPropertyBACnetIPMode                     BACnetPropertyIdentifier = 408
	BACnetPropertyBACnetIPMulticastAddress         BACnetPropertyIdentifier = 409
	BACnetPropertyBACnetIPNatTraversal             BACnetPropertyIdentifier = 410
	BACnetPropertyBACnetIPSubnetMask               BACnetPropertyIdentifier = 411
	BACnetPropertyBACnetIPUDPPort                  BACnetPropertyIdentifier = 412
	BACnetPropertyBbmdAcceptFdRegistrations        BACnetPropertyIdentifier = 413
	BACnetPropertyBbmdBroadcastDistributionTable   BACnetPropertyIdentifier = 414
	BACnetPropertyBbmdForeignDeviceTable           BACnetPropertyIdentifier = 415
	BACnetPropertyChangesPending                   BACnetPropertyIdentifier = 416
	BACnetPropertyCommand                          BACnetPropertyIdentifier = 417
	BACnetPropertyFdBbmdAddress                    BACnetPropertyIdentifier = 418
	BACnetPropertyFdSubscriptionLifetime           BACnetPropertyIdentifier = 419
	BACnetPropertyLinkSpeed                        BACnetPropertyIdentifier = 420
	BACnetPropertyLinkSpeeds                       BACnetPropertyIdentifier = 421
	BACnetPropertyLinkSpeedAutonegotiate           BACnetPropertyIdentifier = 422
	BACnetPropertyMacAddress                       BACnetPropertyIdentifier = 423
	BACnetPropertyNetworkInterfaceName             BACnetPropertyIdentifier = 424
	BACnetPropertyNetworkNumber                    BACnetPropertyIdentifier = 425
	BACnetPropertyNetworkNumberQuality             BACnetPropertyIdentifier = 426
	BACnetPropertyNetworkType                      BACnetPropertyIdentifier = 427
	BACnetPropertyRoutingTable                     BACnetPropertyIdentifier = 428
	BACnetPropertyVirtualMacAddressTable           BACnetPropertyIdentifier = 429
	BACnetPropertyCommandTimeArray                 BACnetPropertyIdentifier = 430
	BACnetPropertyCurrentCommandPriority           BACnetPropertyIdentifier = 431
	BACnetPropertyLastCommandTime                  BACnetPropertyIdentifier = 432
	BACnetPropertyValueSource                      BACnetPropertyIdentifier = 433
	BACnetPropertyValueSourceArray                 BACnetPropertyIdentifier = 434
	BACnetPropertyBACnetIpv6Mode                   BACnetPropertyIdentifier = 435
	BACnetPropertyIpv6Address                      BACnetPropertyIdentifier = 436
	BACnetPropertyIpv6PrefixLength                 BACnetPropertyIdentifier = 437
	BACnetPropertyBACnetIpv6UDPPort                BACnetPropertyIdentifier = 438
	BACnetPropertyIpv6DefaultGateway               BACnetPropertyIdentifier = 439
	BACnetPropertyBACnetIpv6MulticastAddress       BACnetPropertyIdentifier = 440
	BACnetPropertyIpv6DNSServer                    BACnetPropertyIdentifier = 441
	BACnetPropertyIpv6AutoAddressingEnable         BACnetPropertyIdentifier = 442
	BACnetPropertyIpv6DhcpLeaseTime                BACnetPropertyIdentifier = 443
	BACnetPropertyIpv6DhcpLeaseTimeRemaining       BACnetPropertyIdentifier = 444
	BACnetPropertyIpv6DhcpServer                   BACnetPropertyIdentifier = 445
	BACnetPropertyIpv6ZoneIndex                    BACnetPropertyIdentifier = 446
	BACnetPropertyAssignedLandingCalls             BACnetPropertyIdentifier = 447
	BACnetPropertyCarAssignedDirection             BACnetPropertyIdentifier = 448
	BACnetPropertyCarDoorCommand                   BACnetPropertyIdentifier = 449
	BACnetPropertyCarDoorStatus                    BACnetPropertyIdentifier = 450
	BACnetPropertyCarDoorText                      BACnetPropertyIdentifier = 451
	BACnetPropertyCarDoorZone                      BACnetPropertyIdentifier = 452
	BACnetPropertyCarDriveStatus                   BACnetPropertyIdentifier = 453
	BACnetPropertyCarLoad                          BACnetPropertyIdentifier = 454
	BACnetPropertyCarLoadUnits                     BACnetPropertyIdentifier = 455
	BACnetPropertyCarMode                          BACnetPropertyIdentifier = 456
	BACnetPropertyCarMovingDirection               BACnetPropertyIdentifier = 457
	BACnetPropertyCarPosition                      BACnetPropertyIdentifier = 458
	BACnetPropertyElevatorGroup                    BACnetPropertyIdentifier = 459
	BACnetPropertyEnergyMeter                      BACnetPropertyIdentifier = 460
	BACnetPropertyEnergyMeterRef                   BACnetPropertyIdentifier = 461
	BACnetPropertyEscalatorMode                    BACnetPropertyIdentifier = 462
	BACnetPropertyFaultSignals                     BACnetPropertyIdentifier = 463
	BACnetPropertyFloorText                        BACnetPropertyIdentifier = 464
	BACnetPropertyGroupID                          BACnetPropertyIdentifier = 465
	BACnetPropertyEnumerationValue466IsUnassigned  BACnetPropertyIdentifier = 466
	BACnetPropertyGroupMode                        BACnetPropertyIdentifier = 467
	BACnetPropertyHigherDeck                       BACnetPropertyIdentifier = 468
	BACnetPropertyInstallationID                   BACnetPropertyIdentifier = 469
	BACnetPropertyLandingCalls                     BACnetPropertyIdentifier = 470
	BACnetPropertyLandingCallControl               BACnetPropertyIdentifier = 471
	BACnetPropertyLandingDoorStatus                BACnetPropertyIdentifier = 472
	BACnetPropertyLowerDeck                        BACnetPropertyIdentifier = 473
	BACnetPropertyMachineRoomID                    BACnetPropertyIdentifier = 474
	BACnetPropertyMakingCarCall                    BACnetPropertyIdentifier = 475
	BACnetPropertyNextStoppingFloor                BACnetPropertyIdentifier = 476
	BACnetPropertyOperationDirection               BACnetPropertyIdentifier = 477
	BACnetPropertyPassengerAlarm                   BACnetPropertyIdentifier = 478
	BACnetPropertyPowerMode                        BACnetPropertyIdentifier = 479
	BACnetPropertyRegisteredCarCall                BACnetPropertyIdentifier = 480
	BACnetPropertyActiveCovMultipleSubscriptions   BACnetPropertyIdentifier = 481
	BACnetPropertyProtocolLevel                    BACnetPropertyIdentifier = 482
	BACnetPropertyReferencePort                    BACnetPropertyIdentifier = 483
	BACnetPropertyDeployedProfileLocation          BACnetPropertyIdentifier = 484
	BACnetPropertyProfileLocation                  BACnetPropertyIdentifier = 485
	BACnetPropertyTags                             BACnetPropertyIdentifier = 486
	BACnetPropertySubordinateNodeTypes             BACnetPropertyIdentifier = 487
	BACnetPropertySubordinateTags                  BACnetPropertyIdentifier = 488
	BACnetPropertySubordinateRelationship          BACnetPropertyIdentifier = 489
	BACnetPropertyDefaultSubordinateRelationship   BACnetPropertyIdentifier = 490
	BACnetPropertyRepresents                       BACnetPropertyIdentifier = 491
	BACnetPropertyDefaultPresentValue              BACnetPropertyIdentifier = 492
	BACnetPropertyPresentStage                     BACnetPropertyIdentifier = 493
	BACnetPropertyStages                           BACnetPropertyIdentifier = 494
	BACnetPropertyStageNames                       BACnetPropertyIdentifier = 495
	BACnetPropertyTargetReferences                 BACnetPropertyIdentifier = 496
	BACnetPropertyAuditSourceReporter              BACnetPropertyIdentifier = 497
	BACnetPropertyAuditLevel                       BACnetPropertyIdentifier = 498
	BACnetPropertyAuditNotificationRecipient       BACnetPropertyIdentifier = 499
	BACnetPropertyAuditPriorityFilter              BACnetPropertyIdentifier = 500
	BACnetPropertyAuditableOperations              BACnetPropertyIdentifier = 501
	BACnetPropertyDeleteOnForward                  BACnetPropertyIdentifier = 502
	BACnetPropertyMaximumSendDelay                 BACnetPropertyIdentifier = 503
	BACnetPropertyMonitoredObjects                 BACnetPropertyIdentifier = 504
	BACnetPropertySendNow                          BACnetPropertyIdentifier = 505
	BACnetPropertyFloorNumber                      BACnetPropertyIdentifier = 506
	BACnetPropertyDeviceUUID                       BACnetPropertyIdentifier = 507
	BACnetPropertyAdditionalReferencePorts         BACnetPropertyIdentifier = 508
	BACnetPropertyCertificateSigningRequestFile    BACnetPropertyIdentifier = 509
	BACnetPropertyCommandValidationResult          BACnetPropertyIdentifier = 510
	BACnetPropertyIssuerCertificateFiles           BACnetPropertyIdentifier = 511
	BACnetPropertyMaxBvlcLengthAccepted            BACnetPropertyIdentifier = 4194304
	BACnetPropertyMaxNpduLengthAccepted            BACnetPropertyIdentifier = 4194305
	BACnetPropertyOperationalCertificateFile       BACnetPropertyIdentifier = 4194306
	BACnetPropertyCurrentHealth                    BACnetPropertyIdentifier = 4194307
	BACnetPropertyScConnectWaitTimeout             BACnetPropertyIdentifier = 4194308
	BACnetPropertyScDirectConnectAcceptEnable      BACnetPropertyIdentifier = 4194309
	BACnetPropertyScDirectConnectAcceptUris        BACnetPropertyIdentifier = 4194310
	BACnetPropertySscDirectConnectBinding          BACnetPropertyIdentifier = 4194311
	BACnetPropertyScDirectConnectConnectionStatus  BACnetPropertyIdentifier = 4194312
	BACnetPropertyScDirectConnectInitiateEnable    BACnetPropertyIdentifier = 4194313
	BACnetPropertyScDisconnectWaitTimeout          BACnetPropertyIdentifier = 4194314
	BACnetPropertyScFailedConnectionRequest        BACnetPropertyIdentifier = 4194315
	BACnetPropertyScFailoverHubConnectionStatus    BACnetPropertyIdentifier = 4194316
	BACnetPropertyScFailoverHubURI                 BACnetPropertyIdentifier = 4194317
	BACnetPropertyScHubConnectorState              BACnetPropertyIdentifier = 4194318
	BACnetPropertyScHubFunctionAcceptUris          BACnetPropertyIdentifier = 4194319
	BACnetPropertyScHubFunctionBinding             BACnetPropertyIdentifier = 4194320
	BACnetPropertyScHubFunctionConnectionStatus    BACnetPropertyIdentifier = 4194321
	BACnetPropertyScHubFunctionEnable              BACnetPropertyIdentifier = 4194322
	BACnetPropertyScHeartbeatTimeout               BACnetPropertyIdentifier = 4194323
	BACnetPropertyScPrimaryHubConnectionStatus     BACnetPropertyIdentifier = 4194324
	BACnetPropertyScPrimaryHubURI                  BACnetPropertyIdentifier = 4194325
	BACnetPropertyScMaximumReconnectTime           BACnetPropertyIdentifier = 4194326
	BACnetPropertyScMinimumReconnectTime           BACnetPropertyIdentifier = 4194327
	BACnetPropertyColorOverride                    BACnetPropertyIdentifier = 4194328
	BACnetPropertyColorReference                   BACnetPropertyIdentifier = 4194329
	BACnetPropertyDefaultColor                     BACnetPropertyIdentifier = 4194330
	BACnetPropertyDefaultColorTemperature          BACnetPropertyIdentifier = 4194331
	BACnetPropertyOverrideColorReference           BACnetPropertyIdentifier = 4194332
	BACnetPropertyColorCommand                     BACnetPropertyIdentifier = 4194334
	BACnetPropertyHighEndTrim                      BACnetPropertyIdentifier = 4194335
	BACnetPropertyLowEndTrim                       BACnetPropertyIdentifier = 4194336
	BACnetPropertyTrimFadeTime                     BACnetPropertyIdentifier = 4194337
	BACnetPropertyDeviceAddressProxyEnable         BACnetPropertyIdentifier = 4194338
	BACnetPropertyDeviceAddressProxyTable          BACnetPropertyIdentifier = 4194339
	BACnetPropertyDeviceAddressProxyTimeout        BACnetPropertyIdentifier = 4194340
	BACnetPropertyDefaultOnValue                   BACnetPropertyIdentifier = 4194341
	BACnetPropertyLastOnValue                      BACnetPropertyIdentifier = 4194342
	BACnetPropertyAuthorizationCache               BACnetPropertyIdentifier = 4194343
	BACnetPropertyAuthorizationGroups              BACnetPropertyIdentifier = 4194344
	BACnetPropertyAuthorizationPolicy              BACnetPropertyIdentifier = 4194345
	BACnetPropertyAuthorizationScope               BACnetPropertyIdentifier = 4194346
	BACnetPropertyAuthorizationServer              BACnetPropertyIdentifier = 4194347
	BACnetPropertyAuthorizationStatus              BACnetPropertyIdentifier = 4194348
	BACnetPropertyMaxProxiedIAmsPerSecond          BACnetPropertyIdentifier = 4194349
)

var bacnetPropertyIdentifierNames = map[BACnetPropertyIdentifier]string{
	0:       "acked-transition",
	1:       "ack-required",
	2:       "action",
	3:       "action-text",
	4:       "active-text",
	5:       "active-vt-session",
	6:       "alarm-value",
	7:       "alarm-values",
	8:       "all",
	9:       "all-writes-successful",
	10:      "apdu-segment-timeout",
	11:      "apdu-timeout",
	12:      "application-software-version",
	13:      "archive",
	14:      "bias",
	15:      "change-of-state-count",
	16:      "change-of-state-time",
	17:      "notification-class",
	18:      "the property in this place was deleted",
	19:      "controlled-variable-reference",
	20:      "controlled-variable-units",
	21:      "controlled-variable-value",
	22:      "cov-increment",
	23:      "datelist",
	24:      "daylights-savings-status",
	25:      "deadband",
	26:      "derivative-constant",
	27:      "derivative-constant-units",
	28:      "description",
	29:      "description-of-halt",
	30:      "device-address-binding",
	31:      "device-type",
	32:      "effective-period",
	33:      "elapsed-active-time",
	34:      "error-limit",
	35:      "event-enable",
	36:      "event-state",
	37:      "event-type",
	38:      "exception-schedule",
	39:      "fault-values",
	40:      "feedback-value",
	41:      "file-access-method",
	42:      "file-size",
	43:      "file-type",
	44:      "firmware-revision",
	45:      "high-limit",
	46:      "inactive-text",
	47:      "in-process",
	48:      "instance-of",
	49:      "integral-constant",
	50:      "integral-constant-units",
	51:      "issue-confirmed-notifications",
	52:      "limit-enable",
	53:      "list-of-group-members",
	54:      "list-of-object-property-references",
	55:      "list-of-session-keys",
	56:      "local-date",
	57:      "local-time",
	58:      "location",
	59:      "low-limit",
	60:      "manipulated-variable-reference",
	61:      "maximum-output",
	62:      "max-apdu-length-accepted",
	63:      "max-info-frames",
	64:      "max-master",
	65:      "max-pres-value",
	66:      "minimum-off-time",
	67:      "minimum-on-time",
	68:      "minimum-output",
	69:      "min-pres-value",
	70:      "model-name",
	71:      "modification-date",
	72:      "notify-type",
	73:      "number-of-APDU-retries",
	74:      "number-of-states",
	75:      "object-identifier",
	76:      "object-list",
	77:      "object-name",
	78:      "object-property-reference",
	79:      "object-type",
	80:      "optional",
	81:      "out-of-service",
	82:      "output-units",
	83:      "event-parameters",
	84:      "polarity",
	85:      "present-value",
	86:      "priority",
	87:      "priority-array",
	88:      "priority-for-writing",
	89:      "process-identifier",
	90:      "program-change",
	91:      "program-location",
	92:      "program-state",
	93:      "proportional-constant",
	94:      "proportional-constant-units",
	95:      "protocol-conformance-class",
	96:      "protocol-object-types-supported",
	97:      "protocol-services-supported",
	98:      "protocol-version",
	99:      "read-only",
	100:     "reason-for-halt",
	101:     "recipient",
	102:     "recipient-list",
	103:     "reliability",
	104:     "relinquish-default",
	105:     "required",
	106:     "resolution",
	107:     "segmentation-supported",
	108:     "setpoint",
	109:     "setpoint-reference",
	110:     "state-text",
	111:     "status-flags",
	112:     "system-status",
	113:     "time-delay",
	114:     "time-of-active-time-reset",
	115:     "time-of-state-count-reset",
	116:     "time-synchronization-recipients",
	117:     "units",
	118:     "update-interval",
	119:     "utc-offset",
	120:     "vendor-identifier",
	121:     "vendor-name",
	122:     "vt-class-supported",
	123:     "weekly-schedule",
	124:     "attempted-samples",
	125:     "average-value",
	126:     "buffer-size",
	127:     "client-cov-increment",
	128:     "cov-resubscription-interval",
	129:     "current-notify-time",
	130:     "event-time-stamp",
	131:     "log-buffer",
	132:     "log-device-object-property",
	133:     "enable",
	134:     "log-interval",
	135:     "maximum-value",
	136:     "minimum-value",
	137:     "notification-threshold",
	138:     "previous-notify-time",
	139:     "protocol-revision",
	140:     "records-since-notification",
	141:     "record-count",
	142:     "start-time",
	143:     "stop-time",
	144:     "stop-when-full",
	145:     "total-record-count",
	146:     "valid-samples",
	147:     "window-interval",
	148:     "window-samples",
	149:     "maximum-value-time-stamp",
	150:     "minimum-value-time-stamp",
	151:     "variance-value",
	152:     "active-cov-subscriptions",
	153:     "backup-failure-timeout",
	154:     "configuration-files",
	155:     "database-revision",
	156:     "direct-reading",
	157:     "last-restore-time",
	158:     "maintenance-required",
	159:     "member-of",
	160:     "mode",
	161:     "operation-expected",
	162:     "setting",
	163:     "silenced",
	164:     "tracking-value",
	165:     "zone-members",
	166:     "life-safety-alarm-values",
	167:     "max-segments-accepted",
	168:     "profile-name",
	169:     "auto-slave-discovery",
	170:     "manual-slave-address-binding",
	171:     "slave-address-binding",
	172:     "slave-proxy-enable",
	173:     "last-notify-record",
	174:     "schedule-default",
	175:     "accepted-modes",
	176:     "adjust-value",
	177:     "count",
	178:     "count-before-change",
	179:     "count-change-time",
	180:     "cov-period",
	181:     "input-reference",
	182:     "limit-monitoring-interval",
	183:     "logging-object",
	184:     "logging-record",
	185:     "prescale",
	186:     "pulse-rate",
	187:     "scale",
	188:     "scale-factor",
	189:     "update-time",
	190:     "value-before-change",
	191:     "value-set",
	192:     "value-change-time",
	193:     "align-intervals",
	194:     "group-member-names",
	195:     "interval-offset",
	196:     "last-restart-reason",
	197:     "logging-type",
	198:     "member-status-flags",
	199:     "notification-period",
	200:     "previous-notify-record",
	201:     "requested-update-interval",
	202:     "restart-notification-recipients",
	203:     "time-of-device-restart",
	204:     "time-synchronization-interval",
	205:     "trigger",
	206:     "UTC-time-synchronization-recipients",
	207:     "node-subtype",
	208:     "node-type",
	209:     "structured-object-list",
	210:     "subordinate-annotations",
	211:     "subordinate-list",
	212:     "actual-shed-level",
	213:     "duty-window",
	214:     "expected-shed-level",
	215:     "full-duty-baseline",
	216:     "node-subtype",
	217:     "node-type",
	218:     "requested-shed-level",
	219:     "shed-duration",
	220:     "shed-level-descriptions",
	221:     "shed-levels",
	222:     "state-description",
	226:     "door-alarm-state",
	227:     "door-extended-pulse-time",
	228:     "door-members",
	229:     "door-open-too-long-time",
	230:     "door-pulse-time",
	231:     "door-status",
	232:     "door-unlock-delay-time",
	233:     "lock-status",
	234:     "masked-alarm-values",
	235:     "secured-status",
	244:     "absentee-limit",
	245:     "access-alarm-events",
	246:     "access-doors",
	247:     "access-event",
	248:     "access-event-authentication-factor",
	249:     "access-event-credential",
	250:     "access-event-time",
	251:     "access-transaction-events",
	252:     "accompaniment",
	253:     "accompaniment-time",
	254:     "activation-time",
	255:     "active-authentication-policy",
	256:     "assigned-access-rights",
	257:     "authentication-factors",
	258:     "authentication-policy-list",
	259:     "authentication-policy-names",
	260:     "authentication-status",
	261:     "authorization-mode",
	262:     "belongs-to",
	263:     "credential-disable",
	264:     "credential-status",
	265:     "credentials",
	266:     "credentials-in-zone",
	267:     "days-remaining",
	268:     "entry-points",
	269:     "exit-points",
	270:     "expiration-time",
	271:     "extended-time-enable",
	272:     "failed-attempt-events",
	273:     "failed-attempts",
	274:     "failed-attempts-time",
	275:     "last-access-event",
	276:     "last-access-point",
	277:     "last-credential-added",
	278:     "last-credential-added-time",
	279:     "last-credential-removed",
	280:     "last-credential-removed-time",
	281:     "last-use-time",
	282:     "lockout",
	283:     "lockout-relinquish-time",
	284:     "master-exemption",
	285:     "max-failed-attempts",
	286:     "members",
	287:     "muster-point",
	288:     "negative-access-rules",
	289:     "number-of-authentication-policies",
	290:     "occupancy-count",
	291:     "occupancy-count-adjust",
	292:     "occupancy-count-enable",
	293:     "occupancy-exemption",
	294:     "occupancy-lower-limit",
	295:     "occupancy-lower-limit-enforced",
	296:     "occupancy-state",
	297:     "occupancy-upper-limit",
	298:     "occupancy-upper-limit-enforced",
	299:     "passback-exemption",
	300:     "passback-mode",
	301:     "passback-timeout",
	302:     "positive-access-rules",
	303:     "reason-for-disable",
	304:     "supported-formats",
	305:     "supported-format-classes",
	306:     "threat-authority",
	307:     "threat-level",
	308:     "trace-flag",
	309:     "transaction-notification-class",
	310:     "user-external-identifier",
	311:     "user-information-reference",
	317:     "user-name",
	318:     "user-type",
	319:     "uses-remaining",
	320:     "zone-from",
	321:     "zone-to",
	322:     "access-event-tag",
	323:     "global-identifier",
	326:     "verification-time",
	327:     "base-device-security-policy",
	328:     "distribution-key-revision",
	329:     "do-not-hide",
	330:     "key-sets",
	331:     "last-key-server",
	332:     "network-access-security-policies",
	333:     "packet-reorder-time",
	334:     "security-pdu-timeout",
	335:     "security-time-window",
	336:     "supported-security-algorithms",
	337:     "update-key-set-timeout",
	338:     "backup-and-restore-state",
	339:     "backup-preparation-time",
	340:     "restore-completion-time",
	341:     "restore-preparation-time",
	342:     "bit-mask",
	343:     "bit-text",
	344:     "is-utc",
	345:     "group-members",
	346:     "group-member-names",
	347:     "member-status-flags",
	348:     "requested-update-interval",
	349:     "covu-period",
	350:     "covu-recipients",
	351:     "event-message-texts",
	352:     "event-message-texts-config",
	353:     "event-detection-enable",
	354:     "event-algorithm-inhibit",
	355:     "event-algorithm-inhibit-ref",
	356:     "time-delay-normal",
	357:     "reliability-evaluation-inhibit",
	358:     "fault-parameters",
	359:     "fault-type",
	360:     "local-forwarding-only",
	361:     "process-identifier-filter",
	362:     "subscribed-recipients",
	363:     "port-filter",
	364:     "authorization-exemptions",
	365:     "allow-group-delay-inhibit",
	366:     "channel-number",
	367:     "control-groups",
	368:     "execution-delay",
	369:     "last-priority",
	370:     "write-status",
	371:     "property-list",
	372:     "serial-number",
	373:     "blink-warn-enable",
	374:     "default-fade-time",
	375:     "default-ramp-rate",
	376:     "default-step-increment",
	377:     "egress-time",
	378:     "in-progress",
	379:     "instantaneous-power",
	380:     "lighting-command",
	381:     "lighting-command-default-priority",
	382:     "max-actual-value",
	383:     "min-actual-value",
	384:     "power",
	385:     "transition",
	386:     "egress-active",
	387:     "interface-value",
	388:     "fault-high-limit",
	389:     "fault-low-limit",
	390:     "low-diff-limit",
	391:     "strike-count",
	392:     "time-of-strike-count-reset",
	393:     "default-timeout",
	394:     "initial-timeout",
	395:     "last-state-change",
	396:     "state-change-values",
	397:     "timer-running",
	398:     "timer-state",
	399:     "apdu-length",
	400:     "bacnet-ip-address",
	401:     "bacnet-ip-default-gateway",
	402:     "bacnet-ip-dhcp-enable",
	403:     "bacnet-ip-dhcp-lease-time",
	404:     "bacnet-ip-dhcp-lease-time-remaining",
	405:     "bacnet-ip-dhcp-server",
	406:     "bacnet-ip-dns-server",
	407:     "bacnet-ip-global-address",
	408:     "bacnet-ip-mode",
	409:     "bacnet-ip-multicast-address",
	410:     "bacnet-ip-nat-traversal",
	411:     "bacnet-ip-subnet-mask",
	412:     "bacnet-ip-udp-port",
	413:     "bbmd-accept-fd-registrations",
	414:     "bbmd-broadcast-distribution-table",
	415:     "bbmd-foreign-device-table",
	416:     "changes-pending",
	417:     "command",
	418:     "fd-bbmd-address",
	419:     "fd-subscription-lifetime",
	420:     "link-speed",
	421:     "link-speeds",
	422:     "link-speed-autonegotiate",
	423:     "mac-address",
	424:     "network-interface-name",
	425:     "network-number",
	426:     "network-number-quality",
	427:     "network-type",
	428:     "routing-table",
	429:     "virtual-mac-address-table",
	430:     "command-time-array",
	431:     "current-command-priority",
	432:     "last-command-time",
	433:     "value-source",
	434:     "value-source-array",
	435:     "bacnet-ipv6-mode",
	436:     "ipv6-address",
	437:     "ipv6-prefix-length",
	438:     "bacnet-ipv6-udp-port",
	439:     "ipv6-default-gateway",
	440:     "bacnet-ipv6-multicast-address",
	441:     "ipv6-dns-server",
	442:     "ipv6-auto-addressing-enable",
	443:     "ipv6-dhcp-lease-time",
	444:     "ipv6-dhcp-lease-time-remaining",
	445:     "ipv6-dhcp-server",
	446:     "ipv6-zone-index",
	447:     "assigned-landing-calls",
	448:     "car-assigned-direction",
	449:     "car-door-command",
	450:     "car-door-status",
	451:     "car-door-text",
	452:     "car-door-zone",
	453:     "car-drive-status",
	454:     "car-load",
	455:     "car-load-units",
	456:     "car-mode",
	457:     "car-moving-direction",
	458:     "car-position",
	459:     "elevator-group",
	460:     "energy-meter",
	461:     "energy-meter-ref",
	462:     "escalator-mode",
	463:     "fault-signals",
	464:     "floor-text",
	465:     "group-id",
	466:     "enumeration value 466 is unassigned",
	467:     "group-mode",
	468:     "higher-deck",
	469:     "installation-id",
	470:     "landing-calls",
	471:     "landing-call-control",
	472:     "landing-door-status",
	473:     "lower-deck",
	474:     "machine-room-id",
	475:     "making-car-call",
	476:     "next-stopping-floor",
	477:     "operation-direction",
	478:     "passenger-alarm",
	479:     "power-mode",
	480:     "registered-car-call",
	481:     "active-cov-multiple-subscriptions",
	482:     "protocol-level",
	483:     "reference-port",
	484:     "deployed-profile-location",
	485:     "profile-location",
	486:     "tags",
	487:     "subordinate-node-types",
	488:     "subordinate-tags",
	489:     "subordinate-relationship",
	490:     "default-subordinate-relationship",
	491:     "represents",
	492:     "default-present-value",
	493:     "present-stage",
	494:     "stages",
	495:     "stage-names",
	496:     "target-references",
	497:     "audit-source-reporter",
	498:     "audit-level",
	499:     "audit-notification-recipient",
	500:     "audit-priority-filter",
	501:     "auditable-operations",
	502:     "delete-on-forward",
	503:     "maximum-send-delay",
	504:     "monitored-objects",
	505:     "send-now",
	506:     "floor-number",
	507:     "device-uuid",
	508:     "additional-reference-ports",
	509:     "certificate-signing-request-file",
	510:     "command-validation-result",
	511:     "issuer-certificate-files",
	4194304: "max-bvlc-length-accepted",
	4194305: "max-npdu-length-accepted",
	4194306: "operational-certificate-file",
	4194307: "current-health",
	4194308: "sc-connect-wait-timeout",
	4194309: "sc-direct-connect-accept-enable",
	4194310: "sc-direct-connect-accept-uris",
	4194311: "ssc-direct-connect-binding",
	4194312: "sc-direct-connect-connection-status",
	4194313: "sc-direct-connect-initiate-enable",
	4194314: "sc-disconnect-wait-timeout",
	4194315: "sc-failed-connection-request",
	4194316: "sc-failover-hub-connection-status",
	4194317: "sc-failover-hub-uri",
	4194318: "sc-hub-connector-state",
	4194319: "sc-hub-function-accept-uris",
	4194320: "sc-hub-function-binding",
	4194321: "sc-hub-function-connection-status",
	4194322: "sc-hub-function-enable",
	4194323: "sc-heartbeat-timeout",
	4194324: "sc-primary-hub-connection-status",
	4194325: "sc-primary-hub-uri",
	4194326: "sc-maximum-reconnect-time",
	4194327: "sc-minimum-reconnect-time",
	4194328: "color-override",
	4194329: "color-reference",
	4194330: "default-color",
	4194331: "default-color-temperature",
	4194332: "override-color-reference",
	4194334: "color-command",
	4194335: "high-end-trim",
	4194336: "low-end-trim",
	4194337: "trim-fade-time",
	4194338: "device-address-proxy-enable",
	4194339: "device-address-proxy-table",
	4194340: "device-address-proxy-timeout",
	4194341: "default-on-value",
	4194342: "last-on-value",
	4194343: "authorization-cache",
	4194344: "authorization-groups",
	4194345: "authorization-policy",
	4194346: "authorization-scope",
	4194347: "authorization-server",
	4194348: "authorization-status",
	4194349: "max-proxied-i-ams-per-second",
}

// BACnetErrorCode is the error code of a BACnet Error PDU (Clause 18).
type BACnetErrorCode uint32

// BACnetErrorCode values (ASHRAE 135).
const (
	BACnetErrorCodeOther                              BACnetErrorCode = 0
	BACnetErrorCodeAuthenticationFailed               BACnetErrorCode = 1
	BACnetErrorCodeConfigurationInProgress            BACnetErrorCode = 2
	BACnetErrorCodeDeviceBusy                         BACnetErrorCode = 3
	BACnetErrorCodeDynamicCreationNotSupported        BACnetErrorCode = 4
	BACnetErrorCodeFileAccessDenied                   BACnetErrorCode = 5
	BACnetErrorCodeIncompatibleSecurityLevels         BACnetErrorCode = 6
	BACnetErrorCodeInconsistentParameters             BACnetErrorCode = 7
	BACnetErrorCodeInconsistentSelectionCriterion     BACnetErrorCode = 8
	BACnetErrorCodeInvalidDataType                    BACnetErrorCode = 9
	BACnetErrorCodeInvalidFileAccessMethod            BACnetErrorCode = 10
	BACnetErrorCodeInvalidFileStartPosition           BACnetErrorCode = 11
	BACnetErrorCodeInvalidOperatorName                BACnetErrorCode = 12
	BACnetErrorCodeInvalidParameterDataType           BACnetErrorCode = 13
	BACnetErrorCodeInvalidTimeStamp                   BACnetErrorCode = 14
	BACnetErrorCodeKeyGenerationError                 BACnetErrorCode = 15
	BACnetErrorCodeMissingRequiredParameter           BACnetErrorCode = 16
	BACnetErrorCodeNoObjectsOfSpecifiedType           BACnetErrorCode = 17
	BACnetErrorCodeNoSpaceForObject                   BACnetErrorCode = 18
	BACnetErrorCodeNoSpaceToAddListElement            BACnetErrorCode = 19
	BACnetErrorCodeNoSpaceToWriteProperty             BACnetErrorCode = 20
	BACnetErrorCodeNoVtSessionsAvailable              BACnetErrorCode = 21
	BACnetErrorCodePropertyIsNotAList                 BACnetErrorCode = 22
	BACnetErrorCodeObjectDeletionNotPermitted         BACnetErrorCode = 23
	BACnetErrorCodeObjectIdentifierAlreadyExists      BACnetErrorCode = 24
	BACnetErrorCodeOperationalProblem                 BACnetErrorCode = 25
	BACnetErrorCodePasswordFailure                    BACnetErrorCode = 26
	BACnetErrorCodeReadAccessDenied                   BACnetErrorCode = 27
	BACnetErrorCodeSecurityNotSupported               BACnetErrorCode = 28
	BACnetErrorCodeServiceRequestDenied               BACnetErrorCode = 29
	BACnetErrorCodeTimeout                            BACnetErrorCode = 30
	BACnetErrorCodeUnknownObject                      BACnetErrorCode = 31
	BACnetErrorCodeUnknownProperty                    BACnetErrorCode = 32
	BACnetErrorCodeUnknownVtClass                     BACnetErrorCode = 34
	BACnetErrorCodeUnknownVtSession                   BACnetErrorCode = 35
	BACnetErrorCodeUnsupportedObjectType              BACnetErrorCode = 36
	BACnetErrorCodeValueOutOfRange                    BACnetErrorCode = 37
	BACnetErrorCodeVtSessionAlreadyClosed             BACnetErrorCode = 38
	BACnetErrorCodeVtSessionTerminationFailure        BACnetErrorCode = 39
	BACnetErrorCodeWriteAccessDenied                  BACnetErrorCode = 40
	BACnetErrorCodeCharacterSetNotSupported           BACnetErrorCode = 41
	BACnetErrorCodeInvalidArrayIndex                  BACnetErrorCode = 42
	BACnetErrorCodeCovSubscriptionFailed              BACnetErrorCode = 43
	BACnetErrorCodeNotCovProperty                     BACnetErrorCode = 44
	BACnetErrorCodeOptionalFunctionalityNotSupported  BACnetErrorCode = 45
	BACnetErrorCodeInvalidConfigurationData           BACnetErrorCode = 46
	BACnetErrorCodeDatatypeNotSupported               BACnetErrorCode = 47
	BACnetErrorCodeDuplicateName                      BACnetErrorCode = 48
	BACnetErrorCodeDuplicateObjectID                  BACnetErrorCode = 49
	BACnetErrorCodePropertyIsNotAnArray               BACnetErrorCode = 50
	BACnetErrorCodeAbortBufferOverflow                BACnetErrorCode = 51
	BACnetErrorCodeAbortInvalidApduInThisState        BACnetErrorCode = 52
	BACnetErrorCodeAbortPreemptedByHigherPriorityTask BACnetErrorCode = 53
	BACnetErrorCodeAbortSegmentationNotSupported      BACnetErrorCode = 54
	BACnetErrorCodeAbortProprietary                   BACnetErrorCode = 55
	BACnetErrorCodeAbortOther                         BACnetErrorCode = 56
	BACnetErrorCodeInvalidTag                         BACnetErrorCode = 57
	BACnetErrorCodeNetworkDown                        BACnetErrorCode = 58
	BACnetErrorCodeRejectBufferOverflow               BACnetErrorCode = 59
	BACnetErrorCodeRejectInconsistentParameters       BACnetErrorCode = 60
	BACnetErrorCodeRejectInvalidParameterDataType     BACnetErrorCode = 61
	BACnetErrorCodeRejectInvalidTag                   BACnetErrorCode = 62
	BACnetErrorCodeRejectMissingRequiredParameter     BACnetErrorCode = 63
	BACnetErrorCodeRejectParameterOutOfRange          BACnetErrorCode = 64
	BACnetErrorCodeRejectTooManyArguments             BACnetErrorCode = 65
	BACnetErrorCodeRejectUndefinedEnumeration         BACnetErrorCode = 66
	BACnetErrorCodeRejectUnrecognizedService          BACnetErrorCode = 67
	BACnetErrorCodeRejectProprietary                  BACnetErrorCode = 68
	BACnetErrorCodeRejectOther                        BACnetErrorCode = 69
	BACnetErrorCodeUnknownDevice                      BACnetErrorCode = 70
	BACnetErrorCodeUnknownRoute                       BACnetErrorCode = 71
	BACnetErrorCodeValueNotInitialized                BACnetErrorCode = 72
	BACnetErrorCodeInvalidEventState                  BACnetErrorCode = 73
	BACnetErrorCodeNoAlarmConfigured                  BACnetErrorCode = 74
	BACnetErrorCodeLogBufferFull                      BACnetErrorCode = 75
	BACnetErrorCodeLoggedValuePurged                  BACnetErrorCode = 76
	BACnetErrorCodeNoPropertySpecified                BACnetErrorCode = 77
	BACnetErrorCodeNotConfiguredForTriggeredLogging   BACnetErrorCode = 78
	BACnetErrorCodeUnknownSubscription                BACnetErrorCode = 79
	BACnetErrorCodeParameterOutOfRange                BACnetErrorCode = 80
	BACnetErrorCodeListElementNotFound                BACnetErrorCode = 81
	BACnetErrorCodeBusy                               BACnetErrorCode = 82
	BACnetErrorCodeCommunicationDisabled              BACnetErrorCode = 83
	BACnetErrorCodeSuccess                            BACnetErrorCode = 84
	BACnetErrorCodeAccessDenied                       BACnetErrorCode = 85
	BACnetErrorCodeBadDestinationAddress              BACnetErrorCode = 86
	BACnetErrorCodeBadDestinationDeviceID             BACnetErrorCode = 87
	BACnetErrorCodeBadSignature                       BACnetErrorCode = 88
	BACnetErrorCodeBadSourceAddress                   BACnetErrorCode = 89
	BACnetErrorCodeBadTimestamp                       BACnetErrorCode = 90
	BACnetErrorCodeCannotUseKey                       BACnetErrorCode = 91
	BACnetErrorCodeCannotVerifyMessageID              BACnetErrorCode = 92
	BACnetErrorCodeCorrectKeyRevision                 BACnetErrorCode = 93
	BACnetErrorCodeDestinationDeviceIDRequired        BACnetErrorCode = 94
	BACnetErrorCodeDuplicateMessage                   BACnetErrorCode = 95
	BACnetErrorCodeEncryptionNotConfigured            BACnetErrorCode = 96
	BACnetErrorCodeEncryptionRequired                 BACnetErrorCode = 97
	BACnetErrorCodeIncorrectKey                       BACnetErrorCode = 98
	BACnetErrorCodeInvalidKeyData                     BACnetErrorCode = 99
	BACnetErrorCodeKeyUpdateInProgress                BACnetErrorCode = 100
	BACnetErrorCodeMalformedMessage                   BACnetErrorCode = 101
	BACnetErrorCodeNotKeyServer                       BACnetErrorCode = 102
	BACnetErrorCodeSecurityNotConfigured              BACnetErrorCode = 103
	BACnetErrorCodeSourceSecurityRequired             BACnetErrorCode = 104
	BACnetErrorCodeTooManyKeys                        BACnetErrorCode = 105
	BACnetErrorCodeUnknownAuthenticationType          BACnetErrorCode = 106
	BACnetErrorCodeUnknownKey                         BACnetErrorCode = 107
	BACnetErrorCodeUnknownKeyRevision                 BACnetErrorCode = 108
	BACnetErrorCodeUnknownSourceMessage               BACnetErrorCode = 109
	BACnetErrorCodeNotRouterToDnet                    BACnetErrorCode = 110
	BACnetErrorCodeRouterBusy                         BACnetErrorCode = 111
	BACnetErrorCodeUnknownNetworkMessage              BACnetErrorCode = 112
	BACnetErrorCodeMessageTooLong                     BACnetErrorCode = 113
	BACnetErrorCodeSecurityError                      BACnetErrorCode = 114
	BACnetErrorCodeAddressingError                    BACnetErrorCode = 115
	BACnetErrorCodeWriteBdtFailed                     BACnetErrorCode = 116
	BACnetErrorCodeReadBdtFailed                      BACnetErrorCode = 117
	BACnetErrorCodeRegisterForeignDeviceFailed        BACnetErrorCode = 118
	BACnetErrorCodeReadFdtFailed                      BACnetErrorCode = 119
	BACnetErrorCodeDeleteFdtEntryFailed               BACnetErrorCode = 120
	BACnetErrorCodeDistributeBroadcastFailed          BACnetErrorCode = 121
	BACnetErrorCodeUnknownFileSize                    BACnetErrorCode = 122
	BACnetErrorCodeAbortApduTooLong                   BACnetErrorCode = 123
	BACnetErrorCodeAbortApplicationExceededReplyTime  BACnetErrorCode = 124
	BACnetErrorCodeAbortOutOfResources                BACnetErrorCode = 125
	BACnetErrorCodeAbortTsmTimeout                    BACnetErrorCode = 126
	BACnetErrorCodeAbortWindowSizeOutOfRange          BACnetErrorCode = 127
	BACnetErrorCodeFileFull                           BACnetErrorCode = 128
	BACnetErrorCodeInconsistentConfiguration          BACnetErrorCode = 129
	BACnetErrorCodeInconsistentObjectType             BACnetErrorCode = 130
	BACnetErrorCodeInternalError                      BACnetErrorCode = 131
	BACnetErrorCodeNotConfigured                      BACnetErrorCode = 132
	BACnetErrorCodeOutOfMemory                        BACnetErrorCode = 133
	BACnetErrorCodeValueTooLong                       BACnetErrorCode = 134
	BACnetErrorCodeAbortInsufficientSecurity          BACnetErrorCode = 135
	BACnetErrorCodeAbortSecurityError                 BACnetErrorCode = 136
	BACnetErrorCodeDuplicateEntry                     BACnetErrorCode = 137
	BACnetErrorCodeInvalidValueInThisState            BACnetErrorCode = 138
	BACnetErrorCodeInvalidOperationInThisState        BACnetErrorCode = 139
	BACnetErrorCodeListItemNotNumbered                BACnetErrorCode = 140
	BACnetErrorCodeListItemNotTimestamped             BACnetErrorCode = 141
	BACnetErrorCodeInvalidDataEncoding                BACnetErrorCode = 142
	BACnetErrorCodeBvlcFunctionUnknown                BACnetErrorCode = 143
	BACnetErrorCodeBvlcProprietaryFunctionUnknown     BACnetErrorCode = 144
	BACnetErrorCodeHeaderEncodingError                BACnetErrorCode = 145
	BACnetErrorCodeHeaderNotUnderstood                BACnetErrorCode = 146
	BACnetErrorCodeMessageIncomplete                  BACnetErrorCode = 147
	BACnetErrorCodeNotABACnetScHub                    BACnetErrorCode = 148
	BACnetErrorCodePayloadExpected                    BACnetErrorCode = 149
	BACnetErrorCodeUnexpectedData                     BACnetErrorCode = 150
	BACnetErrorCodeNodeDuplicateVmac                  BACnetErrorCode = 151
	BACnetErrorCodeHTTPUnexpectedResponseCode         BACnetErrorCode = 152
	BACnetErrorCodeHTTPNoUpgrade                      BACnetErrorCode = 153
	BACnetErrorCodeHTTPResourceNotLocal               BACnetErrorCode = 154
	BACnetErrorCodeHTTPProxyAuthenticationFailed      BACnetErrorCode = 155
	BACnetErrorCodeHTTPResponseTimeout                BACnetErrorCode = 156
	BACnetErrorCodeHTTPResponseSyntaxError            BACnetErrorCode = 157
	BACnetErrorCodeHTTPResponseValueError             BACnetErrorCode = 158
	BACnetErrorCodeHTTPResponseMissingHeader          BACnetErrorCode = 159
	BACnetErrorCodeHTTPWebsocketHeaderError           BACnetErrorCode = 160
	BACnetErrorCodeHTTPUpgradeRequired                BACnetErrorCode = 161
	BACnetErrorCodeHTTPUpgradeError                   BACnetErrorCode = 162
	BACnetErrorCodeHTTPTemporaryUnavailable           BACnetErrorCode = 163
	BACnetErrorCodeHTTPNotAServer                     BACnetErrorCode = 164
	BACnetErrorCodeHTTPError                          BACnetErrorCode = 165
	BACnetErrorCodeWebsocketSchemeNotSupported        BACnetErrorCode = 166
	BACnetErrorCodeWebsocketUnknownControlMessage     BACnetErrorCode = 167
	BACnetErrorCodeWebsocketCloseError                BACnetErrorCode = 168
	BACnetErrorCodeWebsocketClosedByPeer              BACnetErrorCode = 169
	BACnetErrorCodeWebsocketEndpointLeaves            BACnetErrorCode = 170
	BACnetErrorCodeWebsocketProtocolError             BACnetErrorCode = 171
	BACnetErrorCodeWebsocketDataNotAccepted           BACnetErrorCode = 172
	BACnetErrorCodeWebsocketClosedAbnormally          BACnetErrorCode = 173
	BACnetErrorCodeWebsocketDataInconsistent          BACnetErrorCode = 174
	BACnetErrorCodeWebsocketDataAgainstPolicy         BACnetErrorCode = 175
	BACnetErrorCodeWebsocketFrameTooLong              BACnetErrorCode = 176
	BACnetErrorCodeWebsocketExtensionMissing          BACnetErrorCode = 177
	BACnetErrorCodeWebsocketRequestUnavailable        BACnetErrorCode = 178
	BACnetErrorCodeWebsocketError                     BACnetErrorCode = 179
	BACnetErrorCodeTLSClientCertificateError          BACnetErrorCode = 180
	BACnetErrorCodeTLSServerCertificateError          BACnetErrorCode = 181
	BACnetErrorCodeTLSClientAuthenticationFailed      BACnetErrorCode = 182
	BACnetErrorCodeTLSServerAuthenticationFailed      BACnetErrorCode = 183
	BACnetErrorCodeTLSClientCertificateExpired        BACnetErrorCode = 184
	BACnetErrorCodeTLSServerCertificateExpired        BACnetErrorCode = 185
	BACnetErrorCodeTLSClientCertificateRevoked        BACnetErrorCode = 186
	BACnetErrorCodeTLSServerCertificateRevoked        BACnetErrorCode = 187
	BACnetErrorCodeTLSError                           BACnetErrorCode = 188
	BACnetErrorCodeDNSUnavailable                     BACnetErrorCode = 189
	BACnetErrorCodeDNSNameResolutionFailed            BACnetErrorCode = 190
	BACnetErrorCodeDNSResolverFailure                 BACnetErrorCode = 191
	BACnetErrorCodeDNSError                           BACnetErrorCode = 192
	BACnetErrorCodeTCPConnectTimeout                  BACnetErrorCode = 193
	BACnetErrorCodeTCPConnectionRefused               BACnetErrorCode = 194
	BACnetErrorCodeTCPClosedByLocal                   BACnetErrorCode = 195
	BACnetErrorCodeTCPClosedOther                     BACnetErrorCode = 196
	BACnetErrorCodeTCPError                           BACnetErrorCode = 197
	BACnetErrorCodeIPAddressNotReachable              BACnetErrorCode = 198
	BACnetErrorCodeIPError                            BACnetErrorCode = 199
	BACnetErrorCodeCertificateExpired                 BACnetErrorCode = 200
	BACnetErrorCodeCertificateInvalid                 BACnetErrorCode = 201
	BACnetErrorCodeCertificateMalformed               BACnetErrorCode = 202
	BACnetErrorCodeCertificateRevoked                 BACnetErrorCode = 203
	BACnetErrorCodeReferencedPortInError              BACnetErrorCode = 205
	BACnetErrorCodeNotEnabled                         BACnetErrorCode = 206
	BACnetErrorCodeAdjustScopeRequired                BACnetErrorCode = 207
	BACnetErrorCodeAuthScopeRequired                  BACnetErrorCode = 208
	BACnetErrorCodeBindScopeRequired                  BACnetErrorCode = 209
	BACnetErrorCodeConfigScopeRequired                BACnetErrorCode = 210
	BACnetErrorCodeControlScopeRequired               BACnetErrorCode = 211
	BACnetErrorCodeExtendedScopeRequired              BACnetErrorCode = 212
	BACnetErrorCodeIncorrectClient                    BACnetErrorCode = 213
	BACnetErrorCodeInstallScopeRequired               BACnetErrorCode = 214
	BACnetErrorCodeInsufficientScope                  BACnetErrorCode = 215
	BACnetErrorCodeNoDefaultScope                     BACnetErrorCode = 216
	BACnetErrorCodeNoPolicy                           BACnetErrorCode = 217
	BACnetErrorCodeRevokedToken                       BACnetErrorCode = 218
	BACnetErrorCodeOverrideScopeRequired              BACnetErrorCode = 219
	BACnetErrorCodeInactiveToken                      BACnetErrorCode = 220
	BACnetErrorCodeUnknownAudience                    BACnetErrorCode = 221
	BACnetErrorCodeUnknownClient                      BACnetErrorCode = 222
	BACnetErrorCodeUnknownScope                       BACnetErrorCode = 223
	BACnetErrorCodeViewScopeRequired                  BACnetErrorCode = 224
	BACnetErrorCodeIncorrectAudience                  BACnetErrorCode = 225
	BACnetErrorCodeIncorrectClientOrigin              BACnetErrorCode = 226
	BACnetErrorCodeInvalidArraySize                   BACnetErrorCode = 227
	BACnetErrorCodeIncorrectIssuer                    BACnetErrorCode = 228
	BACnetErrorCodeInvalidToken                       BACnetErrorCode = 229
)

var bacnetErrorCodeNames = map[BACnetErrorCode]string{
	0:   "other",
	1:   "authentication-failed",
	2:   "configuration-in-progress",
	3:   "device-busy",
	4:   "dynamic-creation-not-supported",
	5:   "file-access-denied",
	6:   "incompatible-security-levels",
	7:   "inconsistent-parameters",
	8:   "inconsistent-selection-criterion",
	9:   "invalid-data-type",
	10:  "invalid-file-access-method",
	11:  "invalid-file-start-position",
	12:  "invalid-operator-name",
	13:  "invalid-parameter-data-type",
	14:  "invalid-time-stamp",
	15:  "key-generation-error",
	16:  "missing-required-parameter",
	17:  "no-objects-of-specified-type",
	18:  "no-space-for-object",
	19:  "no-space-to-add-list-element",
	20:  "no-space-to-write-property",
	21:  "no-vt-sessions-available",
	22:  "property-is-not-a-list",
	23:  "object-deletion-not-permitted",
	24:  "object-identifier-already-exists",
	25:  "operational-problem",
	26:  "password-failure",
	27:  "read-access-denied",
	28:  "security-not-supported",
	29:  "service-request-denied",
	30:  "timeout",
	31:  "unknown-object",
	32:  "unknown-property",
	33:  "removed enumeration",
	34:  "unknown-vt-class",
	35:  "unknown-vt-session",
	36:  "unsupported-object-type",
	37:  "value-out-of-range",
	38:  "vt-session-already-closed",
	39:  "vt-session-termination-failure",
	40:  "write-access-denied",
	41:  "character-set-not-supported",
	42:  "invalid-array-index",
	43:  "cov-subscription-failed",
	44:  "not-cov-property",
	45:  "optional-functionality-not-supported",
	46:  "invalid-configuration-data",
	47:  "datatype-not-supported",
	48:  "duplicate-name",
	49:  "duplicate-object-id",
	50:  "property-is-not-an-array",
	51:  "abort-buffer-overflow",
	52:  "abort-invalid-apdu-in-this-state",
	53:  "abort-preempted-by-higher-priority-task",
	54:  "abort-segmentation-not-supported",
	55:  "abort-proprietary",
	56:  "abort-other",
	57:  "invalid-tag",
	58:  "network-down",
	59:  "reject-buffer-overflow",
	60:  "reject-inconsistent-parameters",
	61:  "reject-invalid-parameter-data-type",
	62:  "reject-invalid-tag",
	63:  "reject-missing-required-parameter",
	64:  "reject-parameter-out-of-range",
	65:  "reject-too-many-arguments",
	66:  "reject-undefined-enumeration",
	67:  "reject-unrecognized-service",
	68:  "reject-proprietary",
	69:  "reject-other",
	70:  "unknown-device",
	71:  "unknown-route",
	72:  "value-not-initialized",
	73:  "invalid-event-state",
	74:  "no-alarm-configured",
	75:  "log-buffer-full",
	76:  "logged-value-purged",
	77:  "no-property-specified",
	78:  "not-configured-for-triggered-logging",
	79:  "unknown-subscription",
	80:  "parameter-out-of-range",
	81:  "list-element-not-found",
	82:  "busy",
	83:  "communication-disabled",
	84:  "success",
	85:  "access-denied",
	86:  "bad-destination-address",
	87:  "bad-destination-device-id",
	88:  "bad-signature",
	89:  "bad-source-address",
	90:  "bad-timestamp",
	91:  "cannot-use-key",
	92:  "cannot-verify-message-id",
	93:  "correct-key-revision",
	94:  "destination-device-id-required",
	95:  "duplicate-message",
	96:  "encryption-not-configured",
	97:  "encryption-required",
	98:  "incorrect-key",
	99:  "invalid-key-data",
	100: "key-update-in-progress",
	101: "malformed-message",
	102: "not-key-server",
	103: "security-not-configured",
	104: "source-security-required",
	105: "too-many-keys",
	106: "unknown-authentication-type",
	107: "unknown-key",
	108: "unknown-key-revision",
	109: "unknown-source-message",
	110: "not-router-to-dnet",
	111: "router-busy",
	112: "unknown-network-message",
	113: "message-too-long",
	114: "security-error",
	115: "addressing-error",
	116: "write-bdt-failed",
	117: "read-bdt-failed",
	118: "register-foreign-device-failed",
	119: "read-fdt-failed",
	120: "delete-fdt-entry-failed",
	121: "distribute-broadcast-failed",
	122: "unknown-file-size",
	123: "abort-apdu-too-long",
	124: "abort-application-exceeded-reply-time",
	125: "abort-out-of-resources",
	126: "abort-tsm-timeout",
	127: "abort-window-size-out-of-range",
	128: "file-full",
	129: "inconsistent-configuration",
	130: "inconsistent-object-type",
	131: "internal-error",
	132: "not-configured",
	133: "out-of-memory",
	134: "value-too-long",
	135: "abort-insufficient-security",
	136: "abort-security-error",
	137: "duplicate-entry",
	138: "invalid-value-in-this-state",
	139: "invalid-operation-in-this-state",
	140: "list-item-not-numbered",
	141: "list-item-not-timestamped",
	142: "invalid-data-encoding",
	143: "bvlc-function-unknown",
	144: "bvlc-proprietary-function-unknown",
	145: "header-encoding-error",
	146: "header-not-understood",
	147: "message-incomplete",
	148: "not-a-bacnet-sc-hub",
	149: "payload-expected",
	150: "unexpected-data",
	151: "node-duplicate-vmac",
	152: "http-unexpected-response-code",
	153: "http-no-upgrade",
	154: "http-resource-not-local",
	155: "http-proxy-authentication-failed",
	156: "http-response-timeout",
	157: "http-response-syntax-error",
	158: "http-response-value-error",
	159: "http-response-missing-header",
	160: "http-websocket-header-error",
	161: "http-upgrade-required",
	162: "http-upgrade-error",
	163: "http-temporary-unavailable",
	164: "http-not-a-server",
	165: "http-error",
	166: "websocket-scheme-not-supported",
	167: "websocket-unknown-control-message",
	168: "websocket-close-error",
	169: "websocket-closed-by-peer",
	170: "websocket-endpoint-leaves",
	171: "websocket-protocol-error",
	172: "websocket-data-not-accepted",
	173: "websocket-closed-abnormally",
	174: "websocket-data-inconsistent",
	175: "websocket-data-against-policy",
	176: "websocket-frame-too-long",
	177: "websocket-extension-missing",
	178: "websocket-request-unavailable",
	179: "websocket-error",
	180: "tls-client-certificate-error",
	181: "tls-server-certificate-error",
	182: "tls-client-authentication-failed",
	183: "tls-server-authentication-failed",
	184: "tls-client-certificate-expired",
	185: "tls-server-certificate-expired",
	186: "tls-client-certificate-revoked",
	187: "tls-server-certificate-revoked",
	188: "tls-error",
	189: "dns-unavailable",
	190: "dns-name-resolution-failed",
	191: "dns-resolver-failure",
	192: "dns-error",
	193: "tcp-connect-timeout",
	194: "tcp-connection-refused",
	195: "tcp-closed-by-local",
	196: "tcp-closed-other",
	197: "tcp-error",
	198: "ip-address-not-reachable",
	199: "ip-error",
	200: "certificate-expired",
	201: "certificate-invalid",
	202: "certificate-malformed",
	203: "certificate-revoked",
	204: "unknown-key",
	205: "referenced-port-in-error",
	206: "not-enabled",
	207: "adjust-scope-required",
	208: "auth-scope-required",
	209: "bind-scope-required",
	210: "config-scope-required",
	211: "control-scope-required",
	212: "extended-scope-required",
	213: "incorrect-client",
	214: "install-scope-required",
	215: "insufficient-scope",
	216: "no-default-scope",
	217: "no-policy",
	218: "revoked-token",
	219: "override-scope-required",
	220: "inactive-token",
	221: "unknown-audience",
	222: "unknown-client",
	223: "unknown-scope",
	224: "view-scope-required",
	225: "incorrect-audience",
	226: "incorrect-client-origin",
	227: "invalid-array-size",
	228: "incorrect-issuer",
	229: "invalid-token",
}
