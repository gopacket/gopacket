// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// Names of the enumerations and bit strings of ASHRAE 135 Clause 21 that
// property values and service parameters are typed with.
//
// The tables are maintained by hand from ASHRAE 135-2020 and its addenda;
// no generator belongs to them.

package layers

// BACnetDataType values of the enumerations and the named bit strings.
const (
	BACnetDataTypePropertyIdentifier BACnetDataType = bacnetDataTypeNamedBase + iota
	BACnetDataTypeObjectType
	BACnetDataTypeErrorClass
	BACnetDataTypeErrorCode
	BACnetDataTypeSegmentation
	BACnetDataTypeEngineeringUnits
	BACnetDataTypeReliability
	BACnetDataTypeEventState
	BACnetDataTypeEventType
	BACnetDataTypeNotifyType
	BACnetDataTypeDeviceStatus
	BACnetDataTypePolarity
	BACnetDataTypeBinaryPV
	BACnetDataTypeAction
	BACnetDataTypeProgramError
	BACnetDataTypeProgramRequest
	BACnetDataTypeProgramState
	BACnetDataTypeFileAccessMethod
	BACnetDataTypeLifeSafetyMode
	BACnetDataTypeLifeSafetyOperation
	BACnetDataTypeLifeSafetyState
	BACnetDataTypeSilencedState
	BACnetDataTypeMaintenance
	BACnetDataTypeNodeType
	BACnetDataTypeLoggingType
	BACnetDataTypeDoorStatus
	BACnetDataTypeDoorValue
	BACnetDataTypeLockStatus
	BACnetDataTypeDoorSecuredStatus
	BACnetDataTypeDoorAlarmState
	BACnetDataTypeShedState
	BACnetDataTypeRestartReason
	BACnetDataTypeBackupState
	BACnetDataTypeWriteStatus
	BACnetDataTypeLightingOperation
	BACnetDataTypeLightingInProgress
	BACnetDataTypeLightingTransition
	BACnetDataTypeBinaryLightingPV
	BACnetDataTypeTimerState
	BACnetDataTypeTimerTransition
	BACnetDataTypeIPMode
	BACnetDataTypeNetworkPortCommand
	BACnetDataTypeNetworkType
	BACnetDataTypeNetworkNumberQuality
	BACnetDataTypeProtocolLevel
	BACnetDataTypeAccessEvent
	BACnetDataTypeAccessZoneOccupancyState
	BACnetDataTypeAccessPassbackMode
	BACnetDataTypeAccessCredentialDisableReason
	BACnetDataTypeAccessCredentialDisable
	BACnetDataTypeAccessUserType
	BACnetDataTypeAuthenticationStatus
	BACnetDataTypeAuthorizationMode
	BACnetDataTypeAuthorizationExemption
	BACnetDataTypeSecurityLevel
	BACnetDataTypeFaultType
	BACnetDataTypeAccumulatorStatus
	BACnetDataTypeVTClass
	BACnetDataTypeEnableDisable
	BACnetDataTypeReinitializedState
	BACnetDataTypeMessagePriority
	BACnetDataTypeAcknowledgmentFilter
	BACnetDataTypeEventStateFilter
	BACnetDataTypeEscalatorFault
	BACnetDataTypeEscalatorMode
	BACnetDataTypeEscalatorOperationDirection
	BACnetDataTypeLiftCarDirection
	BACnetDataTypeLiftCarDoorCommand
	BACnetDataTypeLiftCarDriveStatus
	BACnetDataTypeLiftCarMode
	BACnetDataTypeLiftFault
	BACnetDataTypeLiftGroupMode
	BACnetDataTypeRelationship
	BACnetDataTypeAuditLevel
	BACnetDataTypeAuditOperation
	BACnetDataTypeSuccessFilter
	BACnetDataTypeStatusFlags
	BACnetDataTypeEventTransitionBits
	BACnetDataTypeLimitEnable
	BACnetDataTypeDaysOfWeek
	BACnetDataTypeLogStatus
	BACnetDataTypeResultFlags
	BACnetDataTypeServicesSupported
	BACnetDataTypeObjectTypesSupported
	BACnetDataTypeColorOperation
	BACnetDataTypeAuthenticationFactorType
	BACnetDataTypeAuthorizationOrigin
	BACnetDataTypeAuthorizationMethod
	BACnetDataTypeAuthorizationScopes
)

// bacnetNamedTypes describes the datatypes from bacnetDataTypeNamedBase on,
// in the order of their constants.
var bacnetNamedTypes = [...]bacnetType{
	{name: "BACnetPropertyIdentifier", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated},
	{name: "BACnetObjectType", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated},
	{name: "BACnetErrorClass", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated},
	{name: "BACnetErrorCode", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated},
	{name: "BACnetSegmentation", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesSegmentation},
	{name: "BACnetEngineeringUnits", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesEngineeringUnits},
	{name: "BACnetReliability", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesReliability},
	{name: "BACnetEventState", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesEventState},
	{name: "BACnetEventType", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesEventType},
	{name: "BACnetNotifyType", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesNotifyType},
	{name: "BACnetDeviceStatus", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesDeviceStatus},
	{name: "BACnetPolarity", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesPolarity},
	{name: "BACnetBinaryPV", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesBinaryPV},
	{name: "BACnetAction", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAction},
	{name: "BACnetProgramError", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesProgramError},
	{name: "BACnetProgramRequest", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesProgramRequest},
	{name: "BACnetProgramState", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesProgramState},
	{name: "BACnetFileAccessMethod", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesFileAccessMethod},
	{name: "BACnetLifeSafetyMode", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLifeSafetyMode},
	{name: "BACnetLifeSafetyOperation", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLifeSafetyOperation},
	{name: "BACnetLifeSafetyState", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLifeSafetyState},
	{name: "BACnetSilencedState", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesSilencedState},
	{name: "BACnetMaintenance", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesMaintenance},
	{name: "BACnetNodeType", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesNodeType},
	{name: "BACnetLoggingType", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLoggingType},
	{name: "BACnetDoorStatus", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesDoorStatus},
	{name: "BACnetDoorValue", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesDoorValue},
	{name: "BACnetLockStatus", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLockStatus},
	{name: "BACnetDoorSecuredStatus", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesDoorSecuredStatus},
	{name: "BACnetDoorAlarmState", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesDoorAlarmState},
	{name: "BACnetShedState", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesShedState},
	{name: "BACnetRestartReason", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesRestartReason},
	{name: "BACnetBackupState", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesBackupState},
	{name: "BACnetWriteStatus", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesWriteStatus},
	{name: "BACnetLightingOperation", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLightingOperation},
	{name: "BACnetLightingInProgress", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLightingInProgress},
	{name: "BACnetLightingTransition", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLightingTransition},
	{name: "BACnetBinaryLightingPV", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesBinaryLightingPV},
	{name: "BACnetTimerState", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesTimerState},
	{name: "BACnetTimerTransition", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesTimerTransition},
	{name: "BACnetIPMode", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesIPMode},
	{name: "BACnetNetworkPortCommand", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesNetworkPortCommand},
	{name: "BACnetNetworkType", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesNetworkType},
	{name: "BACnetNetworkNumberQuality", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesNetworkNumberQuality},
	{name: "BACnetProtocolLevel", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesProtocolLevel},
	{name: "BACnetAccessEvent", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAccessEvent},
	{name: "BACnetAccessZoneOccupancyState", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAccessZoneOccupancyState},
	{name: "BACnetAccessPassbackMode", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAccessPassbackMode},
	{name: "BACnetAccessCredentialDisableReason", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAccessCredentialDisableReason},
	{name: "BACnetAccessCredentialDisable", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAccessCredentialDisable},
	{name: "BACnetAccessUserType", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAccessUserType},
	{name: "BACnetAuthenticationStatus", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAuthenticationStatus},
	{name: "BACnetAuthorizationMode", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAuthorizationMode},
	{name: "BACnetAuthorizationExemption", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAuthorizationExemption},
	{name: "BACnetSecurityLevel", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesSecurityLevel},
	{name: "BACnetFaultType", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesFaultType},
	{name: "BACnetAccumulatorStatus", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAccumulatorStatus},
	{name: "BACnetVTClass", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesVTClass},
	{name: "BACnetEnableDisable", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesEnableDisable},
	{name: "BACnetReinitializedStateOfDevice", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesReinitializedState},
	{name: "BACnetMessagePriority", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesMessagePriority},
	{name: "BACnetAcknowledgementFilter", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAcknowledgmentFilter},
	{name: "BACnetEventStateFilter", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesEventStateFilter},
	{name: "BACnetEscalatorFault", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesEscalatorFault},
	{name: "BACnetEscalatorMode", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesEscalatorMode},
	{name: "BACnetEscalatorOperationDirection", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesEscalatorOperationDirection},
	{name: "BACnetLiftCarDirection", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLiftCarDirection},
	{name: "BACnetLiftCarDoorCommand", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLiftCarDoorCommand},
	{name: "BACnetLiftCarDriveStatus", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLiftCarDriveStatus},
	{name: "BACnetLiftCarMode", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLiftCarMode},
	{name: "BACnetLiftFault", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLiftFault},
	{name: "BACnetLiftGroupMode", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesLiftGroupMode},
	{name: "BACnetRelationship", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesRelationship},
	{name: "BACnetAuditLevel", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAuditLevel},
	{name: "BACnetAuditOperation", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAuditOperation},
	{name: "BACnetSuccessFilter", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesSuccessFilter},
	{name: "BACnetStatusFlags", kind: bacnetKindBitString, app: BACnetAppTagBitString, bits: bacnetBitsStatusFlags},
	{name: "BACnetEventTransitionBits", kind: bacnetKindBitString, app: BACnetAppTagBitString, bits: bacnetBitsEventTransitionBits},
	{name: "BACnetLimitEnable", kind: bacnetKindBitString, app: BACnetAppTagBitString, bits: bacnetBitsLimitEnable},
	{name: "BACnetDaysOfWeek", kind: bacnetKindBitString, app: BACnetAppTagBitString, bits: bacnetBitsDaysOfWeek},
	{name: "BACnetLogStatus", kind: bacnetKindBitString, app: BACnetAppTagBitString, bits: bacnetBitsLogStatus},
	{name: "BACnetResultFlags", kind: bacnetKindBitString, app: BACnetAppTagBitString, bits: bacnetBitsResultFlags},
	{name: "BACnetServicesSupported", kind: bacnetKindBitString, app: BACnetAppTagBitString, bits: bacnetBitsServicesSupported},
	{name: "BACnetObjectTypesSupported", kind: bacnetKindBitString, app: BACnetAppTagBitString, bits: bacnetBitsObjectTypesSupported},
	{name: "BACnetColorOperation", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesColorOperation},
	{name: "BACnetAuthenticationFactorType", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAuthFactorType},
	{name: "BACnetAuthorizationConstraint.origin", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAuthOrigin},
	{name: "BACnetAuthorizationConstraint.authentication", kind: bacnetKindEnumerated, app: BACnetAppTagEnumerated, names: bacnetNamesAuthMethod},
	{name: "BACnetAuthorizationScope.standard", kind: bacnetKindBitString, app: BACnetAppTagBitString, bits: bacnetBitsAuthScopes},
}

var bacnetNamesColorOperation = map[uint32]string{
	0: "none",
	1: "fade-to-color",
	2: "fade-to-cct",
	3: "ramp-to-cct",
	4: "step-up-cct",
	5: "step-down-cct",
	6: "stop",
}

var bacnetNamesAuthFactorType = map[uint32]string{
	0:  "undefined",
	1:  "error",
	2:  "custom",
	3:  "simple-number16",
	4:  "simple-number32",
	5:  "simple-number56",
	6:  "simple-alpha-numeric",
	7:  "aba-track2",
	8:  "wiegand26",
	9:  "wiegand37",
	10: "wiegand37-facility",
	11: "facility16-card32",
	12: "facility32-card32",
	13: "fasc-n",
	14: "fasc-n-bcd",
	15: "fasc-n-large",
	16: "fasc-n-large-bcd",
	17: "gsa75",
	18: "chuid",
	19: "chuid-full",
	20: "guid",
	21: "cbeff-a",
	22: "cbeff-b",
	23: "cbeff-c",
	24: "user-password",
}

var bacnetNamesAuthOrigin = map[uint32]string{
	0: "direct-connect",
	1: "same-network",
	2: "any-network",
}

var bacnetNamesAuthMethod = map[uint32]string{
	0: "certified",
	1: "secure-path",
	2: "any-method",
}

var bacnetBitsAuthScopes = []string{
	"view",
	"adjust",
	"control",
	"override",
	"config",
	"bind",
	"install",
	"auth",
	"infrastructure",
}

var bacnetNamesSegmentation = map[uint32]string{
	0: "segmented-both",
	1: "segmented-transmit",
	2: "segmented-receive",
	3: "no-segmentation",
}

var bacnetNamesEngineeringUnits = map[uint32]string{
	0:     "square-meters",
	1:     "square-feet",
	2:     "milliamperes",
	3:     "amperes",
	4:     "ohms",
	5:     "volts",
	6:     "kilovolts",
	7:     "megavolts",
	8:     "volt-amperes",
	9:     "kilovolt-amperes",
	10:    "megavolt-amperes",
	11:    "volt-amperes-reactive",
	12:    "kilovolt-amperes-reactive",
	13:    "megavolt-amperes-reactive",
	14:    "degrees-phase",
	15:    "power-factor",
	16:    "joules",
	17:    "kilojoules",
	18:    "watt-hours",
	19:    "kilowatt-hours",
	20:    "btus",
	21:    "therms",
	22:    "ton-hours",
	23:    "joules-per-kg-dry-air",
	24:    "btus-per-pound-dry-air",
	25:    "cycles-per-hour",
	26:    "cycles-per-minute",
	27:    "hertz",
	28:    "grams-of-water-per-kilogram-dry-air",
	29:    "relative-humidity",
	30:    "millimeters",
	31:    "meters",
	32:    "inches",
	33:    "feed",
	34:    "watts-per-sq-foot",
	35:    "watts-per-sq-meter",
	36:    "lumens",
	37:    "lux",
	38:    "foot-candles",
	39:    "kilograms",
	40:    "pounds-mass",
	41:    "tons",
	42:    "kgs-per-second",
	43:    "kgs-per-minute",
	44:    "kgs-per-hour",
	45:    "pounds-mass-per-minute",
	46:    "pounds-mass-per-hour",
	47:    "watt",
	48:    "kilowatts",
	49:    "megawatts",
	50:    "btus-per-hour",
	51:    "horsepower",
	52:    "tons-refrigeration",
	53:    "pascals",
	54:    "kilopascals",
	55:    "bars",
	56:    "pounds-force-per-square-inch",
	57:    "centimeters-of-water",
	58:    "inches-of-water",
	59:    "millimeters-of-mercury",
	60:    "centimeters-of-mercury",
	61:    "inches-of-mercury",
	62:    "degrees-celsius",
	63:    "degrees-kelvin",
	64:    "degrees-fahrenheit",
	65:    "degree-days-celsius",
	66:    "degree-days-fahrenheit",
	67:    "years",
	68:    "months",
	69:    "weeks",
	70:    "days",
	71:    "hours",
	72:    "minutes",
	73:    "seconds",
	74:    "meters-per-second",
	75:    "kilometers-per-hour",
	76:    "feed-per-second",
	77:    "feet-per-minute",
	78:    "miles-per-hour",
	79:    "cubic-feet",
	80:    "cubic-meters",
	81:    "imperial-gallons",
	82:    "liters",
	83:    "us-gallons",
	84:    "cubic-feet-per-minute",
	85:    "cubic-meters-per-second",
	86:    "imperial-gallons-per-minute",
	87:    "liters-per-second",
	88:    "liters-per-minute",
	89:    "us-gallons-per-minute",
	90:    "degrees-angular",
	91:    "degrees-celsius-per-hour",
	92:    "degrees-celsius-per-minute",
	93:    "degrees-fahrenheit-per-hour",
	94:    "degrees-fahrenheit-per-minute",
	95:    "no-units",
	96:    "parts-per-million",
	97:    "parts-per-billion",
	98:    "percent",
	99:    "percent-per-second",
	100:   "per-minute",
	101:   "per-second",
	102:   "psi-per-degree-fahrenheit",
	103:   "radians",
	104:   "revolutions-per-min",
	105:   "currency1",
	106:   "currency2",
	107:   "currency3",
	108:   "currency4",
	109:   "currency5",
	110:   "currency6",
	111:   "currency7",
	112:   "currency8",
	113:   "currency9",
	114:   "currency10",
	115:   "square-inches",
	116:   "square-centimeters",
	117:   "btus-per-pound",
	118:   "centimeters",
	119:   "pounds-mass-per-second",
	120:   "delta-degrees-fahrenheit",
	121:   "delta-degrees-kelvin",
	122:   "kilohms",
	123:   "megohms",
	124:   "millivolts",
	125:   "kilojoules-per-kg",
	126:   "megajoules",
	127:   "joules-per-degree-kelvin",
	128:   "joules-per-kg-degree-kelvin",
	129:   "kilohertz",
	130:   "megahertz",
	131:   "per-hour",
	132:   "milliwatts",
	133:   "hectopascals",
	134:   "millibars",
	135:   "cubic-meters-per-hour",
	136:   "liters-per-hour",
	137:   "kwatt-hours-per-square-meter",
	138:   "kwatt-hours-per-square-foot",
	139:   "megajoules-per-square-meter",
	140:   "megajoules-per-square-foot",
	141:   "watts-per-sq-meter-degree-kelvin",
	142:   "cubic-feet-per-second",
	143:   "percent-obstruction-per-foot",
	144:   "percent-obstruction-per-meter",
	145:   "milliohms",
	146:   "megawatt-hours",
	147:   "kilo-btus",
	148:   "mega-btus",
	149:   "kilojoules-per-kilogram-dry-air",
	150:   "megajoules-per-kilogram-dry-air",
	151:   "kilojoules-per-degree-kelvin",
	152:   "megajoules-per-degree-kelvin",
	153:   "newton",
	154:   "grams-per-second",
	155:   "grams-per-minute",
	156:   "tons-per-hour",
	157:   "kilo-btus-per-hour",
	158:   "hundredths-seconds",
	159:   "milliseconds",
	160:   "newton-meters",
	161:   "millimeters-per-second",
	162:   "millimeters-per-minute",
	163:   "meters-per-minute",
	164:   "meters-per-hour",
	165:   "cubic-meters-per-minute",
	166:   "meters-per-second-per-second",
	167:   "amperes-per-meter",
	168:   "amperes-per-square-meter",
	169:   "ampere-square-meters",
	170:   "farads",
	171:   "henrys",
	172:   "ohm-meters",
	173:   "siemens",
	174:   "siemens-per-meter",
	175:   "teslas",
	176:   "volts-per-degree-kelvin",
	177:   "volts-per-meter",
	178:   "webers",
	179:   "candelas",
	180:   "candelas-per-square-meter",
	181:   "degrees-kelvin-per-hour",
	182:   "degrees-kelvin-per-minute",
	183:   "joule-seconds",
	184:   "radians-per-second",
	185:   "square-meters-per-newton",
	186:   "kilograms-per-cubic-meter",
	187:   "newton-seconds",
	188:   "newtons-per-meter",
	189:   "watts-per-meter-per-degree-kelvin",
	190:   "micro-siemens",
	191:   "cubic-feet-per-hour",
	192:   "us-gallons-per-hour",
	193:   "kilometers",
	194:   "micrometers",
	195:   "grams",
	196:   "milligrams",
	197:   "milliliters",
	198:   "milliliters-per-second",
	199:   "decibels",
	200:   "decibels-millivolt",
	201:   "decibels-volt",
	202:   "millisiemens",
	203:   "watt-hours-reactive",
	204:   "kilowatt-hours-reactive",
	205:   "megawatt-hours-reactive",
	206:   "millimeters-of-water",
	207:   "per-mille",
	208:   "grams-per-gram",
	209:   "kilograms-per-kilogram",
	210:   "grams-per-kilogram",
	211:   "milligrams-per-gram",
	212:   "milligrams-per-kilogram",
	213:   "grams-per-milliliter",
	214:   "grams-per-liter",
	215:   "milligrams-per-liter",
	216:   "micrograms-per-liter",
	217:   "grams-per-cubic-meter",
	218:   "milligrams-per-cubic-meter",
	219:   "micrograms-per-cubic-meter",
	220:   "nanograms-per-cubic-meter",
	221:   "grams-per-cubic-centimeter",
	222:   "becquerels",
	223:   "kilobecquerels",
	224:   "megabecquerels",
	225:   "gray",
	226:   "milligray",
	227:   "microgray",
	228:   "sieverts",
	229:   "millisieverts",
	230:   "microsieverts",
	231:   "microsieverts-per-hour",
	232:   "decibels-a",
	233:   "nephelometric-turbidity-unit",
	234:   "ph",
	235:   "grams-per-square-meter",
	236:   "minutes-per-degree-kelvin",
	237:   "ohm-meter-squared-per-meter",
	238:   "ampere-seconds",
	239:   "volt-ampere-hours",
	240:   "kilovolt-ampere-hours",
	241:   "megavolt-ampere-hours",
	242:   "volt-ampere-hours-reactive",
	243:   "kilovolt-ampere-hours-reactive",
	244:   "megavolt-ampere-hours-reactive",
	245:   "volt-square-hours",
	246:   "ampere-square-hours",
	247:   "joule-per-hours",
	248:   "cubic-feet-per-day",
	249:   "cubic-meters-per-day",
	250:   "watt-hours-per-cubic-meter",
	251:   "joules-per-cubic-meter",
	252:   "mole-percent",
	253:   "pascal-seconds",
	254:   "million-standard-cubic-feet-per-minute",
	255:   "unassigned-unit-value-255",
	47808: "standard-cubic-feet-per-day",
	47809: "million-standard-cubic-feet-per-day",
	47810: "thousand-cubic-feet-per-day",
	47811: "thousand-standard-cubic-feet-per-day",
	47812: "pounds-mass-per-day",
	47813: "reserved-unit-47813",
	47814: "millirems",
	47815: "millirems-per-hour",
	47816: "degrees-lovibond",
	47817: "alcohol-by-volume",
	47818: "international-bittering-units",
	47819: "european-bitterness-units",
	47820: "degrees-plato",
	47821: "specific-gravity",
	47822: "european-brewing-convention",
}

var bacnetNamesReliability = map[uint32]string{
	0:  "no-fault-detected",
	1:  "no-sensor",
	2:  "over-range",
	3:  "under-range",
	4:  "open-loop",
	5:  "shorted-loop",
	6:  "no-output",
	7:  "unreliable-other",
	8:  "process-error",
	9:  "multi-state-fault",
	10: "configuration-error",
	11: "reserved-for-a-future-addendum",
	12: "communication-failure",
	13: "member-fault",
	14: "monitored-object-fault",
	15: "tripped",
	16: "lamp-failure",
	17: "activation-failure",
	18: "renew-dhcp-failure",
	19: "renew-fd-registration-failure",
	20: "restart-auto-negotiation-failure",
	21: "restart-failure",
	22: "proprietary-command-failure",
	23: "faults-listed",
	24: "referenced-object-fault",
	25: "multi-state-out-of-range",
}

var bacnetNamesEventState = map[uint32]string{
	0: "normal",
	1: "fault",
	2: "offnormal",
	3: "high-limit",
	4: "low-limit",
	5: "life-safety-alarm",
}

var bacnetNamesEventType = map[uint32]string{
	0:  "change-of-bitstring",
	1:  "change-of-state",
	2:  "change-of-value",
	3:  "command-failure",
	4:  "floating-limit",
	5:  "out-of-range",
	6:  "complex-event-type",
	8:  "change-of-life-safety",
	9:  "extended",
	10: "buffer-ready",
	11: "unsigned-range",
	13: "access-event",
	14: "double-out-of-range",
	15: "signed-out-of-range",
	16: "unsigned-out-of-range",
	17: "change-of-characterstring",
	18: "change-of-status-flags",
	19: "change-of-reliability",
	20: "none",
	21: "change-of-discrete-value",
	22: "change-of-timer",
}

var bacnetNamesNotifyType = map[uint32]string{
	0: "alarm",
	1: "event",
	2: "ack-notification",
}

var bacnetNamesDeviceStatus = map[uint32]string{
	0: "operational",
	1: "operational-read-only",
	2: "download-required",
	3: "download-in-progress",
	4: "non-operational",
	5: "backup-in-progress",
}

var bacnetNamesPolarity = map[uint32]string{
	0: "normal",
	1: "reverse",
}

var bacnetNamesBinaryPV = map[uint32]string{
	0: "inactive",
	1: "active",
}

var bacnetNamesAction = map[uint32]string{
	0: "direct",
	1: "reverse",
}

var bacnetNamesProgramError = map[uint32]string{
	0: "normal",
	1: "load-failed",
	2: "internal",
	3: "program",
	4: "other",
}

var bacnetNamesProgramRequest = map[uint32]string{
	0: "ready",
	1: "load",
	2: "run",
	3: "halt",
	4: "restart",
	5: "unload",
}

var bacnetNamesProgramState = map[uint32]string{
	0: "idle",
	1: "loading",
	2: "running",
	3: "waiting",
	4: "halted",
	5: "unloading",
}

var bacnetNamesFileAccessMethod = map[uint32]string{
	0: "record-access",
	1: "stream-access",
}

var bacnetNamesLifeSafetyMode = map[uint32]string{
	0:  "off",
	1:  "on",
	2:  "test",
	3:  "manned",
	4:  "unmanned",
	5:  "armed",
	6:  "disarmed",
	7:  "prearmed",
	8:  "slow",
	9:  "fast",
	10: "disconnected",
	11: "enabled",
	12: "disabled",
	13: "atomic-release-disabled",
	14: "default",
	15: "activated-oeo-alarm",
	16: "activated-oeo-evacuate",
	17: "activated-oeo-phase1-recall",
	18: "activated-oeo-unavailable",
	19: "deactivated",
}

var bacnetNamesLifeSafetyOperation = map[uint32]string{
	0: "none",
	1: "silence",
	2: "silence-audible",
	3: "silence-visual",
	4: "reset",
	5: "reset-alarm",
	6: "reset-fault",
	7: "unsilence",
	8: "unsilence-audible",
	9: "unsilence-visual",
}

var bacnetNamesLifeSafetyState = map[uint32]string{
	0:  "quiet",
	1:  "pre-alarm",
	2:  "alarm",
	3:  "fault",
	4:  "fault-pre-alarm",
	5:  "fault-alarm",
	6:  "not-ready",
	7:  "active",
	8:  "tamper",
	9:  "test-alarm",
	10: "test-active",
	11: "test-fault",
	12: "test-fault-alarm",
	13: "holdup",
	14: "duress",
	15: "tamper-alarm",
	16: "abnormal",
	17: "emergency-power",
	18: "delayed",
	19: "blocked",
	20: "local-alarm",
	21: "general-alarm",
	22: "supervisory",
	23: "test-supervisory",
	24: "non-default-mode",
	25: "oeo-unavailable",
	26: "oeo-alarm",
	27: "oeo-phase1-recall",
	28: "oeo-evacuate",
	29: "oeo-unaffected",
	30: "test-oeo-unavailable",
	31: "test-oeo-alarm",
	32: "test-oeo-phase1-recall",
	33: "test-oeo-evacuate",
	34: "test-oeo-unaffected",
}

var bacnetNamesSilencedState = map[uint32]string{
	0: "unsilenced",
	1: "audible-silenced",
	2: "visible-silenced",
	3: "all-silenced",
}

var bacnetNamesMaintenance = map[uint32]string{
	0: "none",
	1: "periodic-test",
	2: "need-service-operational",
	3: "need-service-inoperative",
}

var bacnetNamesNodeType = map[uint32]string{
	0:  "unknown",
	1:  "system",
	2:  "network",
	3:  "device",
	4:  "organizational",
	5:  "area",
	6:  "equipment",
	7:  "point",
	8:  "collection",
	9:  "property",
	10: "functional",
	11: "other",
	12: "subsystem",
	13: "building",
	14: "floor",
	15: "section",
	16: "module",
	17: "tree",
	18: "member",
	19: "protocol",
	20: "room",
	21: "zone",
}

var bacnetNamesLoggingType = map[uint32]string{
	0: "polled",
	1: "cov",
	2: "triggered",
}

var bacnetNamesDoorStatus = map[uint32]string{
	0: "closed",
	1: "opened",
	2: "unknown",
	3: "door-fault",
	4: "unused",
	5: "none",
	6: "closing",
	7: "opening",
	8: "safety-locked",
	9: "limited-opened",
}

var bacnetNamesDoorValue = map[uint32]string{
	0: "lock",
	1: "unlock",
	2: "pulse-unlock",
	3: "extended-pulse-unlock",
}

var bacnetNamesLockStatus = map[uint32]string{
	0: "locked",
	1: "unlocked",
	2: "fault",
	3: "unknown",
}

var bacnetNamesDoorSecuredStatus = map[uint32]string{
	0: "secured",
	1: "unsecured",
	2: "unknown",
}

var bacnetNamesDoorAlarmState = map[uint32]string{
	0: "normal",
	1: "alarm",
	2: "door-open-too-long",
	3: "forced-open",
	4: "tamper",
	5: "door-fault",
	6: "lock-down",
	7: "free-access",
	8: "egress-open",
}

var bacnetNamesShedState = map[uint32]string{
	0: "shed-inactive",
	1: "shed-request-pending",
	2: "shed-compliant",
	3: "shed-non-compliant",
}

var bacnetNamesRestartReason = map[uint32]string{
	0: "unknown",
	1: "coldstart",
	2: "warmstart",
	3: "detected-power-lost",
	4: "detected-powered-off",
	5: "hardware-watchdog",
	6: "software-watchdog",
	7: "suspended",
	8: "activate-changes",
}

var bacnetNamesBackupState = map[uint32]string{
	0: "idle",
	1: "preparing-for-backup",
	2: "preparing-for-restore",
	3: "performing-a-backup",
	4: "performing-a-restore",
	5: "backup-failure",
	6: "restore-failure",
}

var bacnetNamesWriteStatus = map[uint32]string{
	0: "idle",
	1: "in-progress",
	2: "successful",
	3: "failed",
}

var bacnetNamesLightingOperation = map[uint32]string{
	0:  "none",
	1:  "fade-to",
	2:  "ramp-to",
	3:  "step-up",
	4:  "step-down",
	5:  "step-on",
	6:  "step-off",
	7:  "warn",
	8:  "warn-off",
	9:  "warn-relinquish",
	10: "stop",
	11: "restore-on",
	12: "default-on",
	13: "toggle-restore",
	14: "toggle-default",
}

var bacnetNamesLightingInProgress = map[uint32]string{
	0: "idle",
	1: "fade-active",
	2: "ramp-active",
	3: "not-controlled",
	4: "other",
	5: "trim-active",
}

var bacnetNamesLightingTransition = map[uint32]string{
	0: "none",
	1: "fade",
	2: "ramp",
}

var bacnetNamesBinaryLightingPV = map[uint32]string{
	0: "off",
	1: "on",
	2: "warn",
	3: "warn-off",
	4: "warn-relinquish",
	5: "stop",
	6: "toggle",
}

var bacnetNamesTimerState = map[uint32]string{
	0: "idle",
	1: "running",
	2: "expired",
}

var bacnetNamesTimerTransition = map[uint32]string{
	0: "none",
	1: "idle-to-running",
	2: "running-to-idle",
	3: "running-to-running",
	4: "running-to-expired",
	5: "forced-to-expired",
	6: "expired-to-idle",
	7: "expired-to-running",
}

var bacnetNamesIPMode = map[uint32]string{
	0: "normal",
	1: "foreign",
	2: "bbmd",
}

var bacnetNamesNetworkPortCommand = map[uint32]string{
	0:  "idle",
	1:  "discard-changes",
	2:  "renew-fd-registration",
	3:  "restart-slave-discovery",
	4:  "renew-dhcp",
	5:  "restart-autonegotiation",
	6:  "disconnect",
	7:  "restart-port",
	8:  "generate-csr-file",
	9:  "validate-changes",
	10: "restart-device-discovery",
}

var bacnetNamesNetworkType = map[uint32]string{
	0:  "ethernet",
	1:  "arcnet",
	2:  "mstp",
	3:  "ptp",
	4:  "lontalk",
	5:  "bacnet-ipv4",
	6:  "zigbee",
	7:  "virtual",
	8:  "non-bacnet",
	9:  "bacnet-ipv6",
	10: "serial",
	11: "secure-connect",
}

var bacnetNamesNetworkNumberQuality = map[uint32]string{
	0: "unknown",
	1: "learned",
	2: "learned-configured",
	3: "configured",
}

var bacnetNamesProtocolLevel = map[uint32]string{
	0: "physical",
	1: "protocol",
	2: "bacnet-application",
	3: "non-bacnet-application",
}

var bacnetNamesAccessEvent = map[uint32]string{
	0:   "none",
	1:   "granted",
	2:   "muster",
	3:   "passback-detected",
	4:   "duress",
	5:   "trace",
	6:   "lockout-max-attempts",
	7:   "lockout-other",
	8:   "lockout-relinquished",
	9:   "lockout-by-higher-priority",
	10:  "out-of-service",
	11:  "out-of-service-relinquished",
	12:  "accompaniment-by",
	13:  "authentication-factor-read",
	14:  "authorization-delayed",
	15:  "verification-required",
	128: "denied-deny-all",
	129: "denied-unknown-credential",
	130: "denied-authentication-unavailable",
	131: "denied-authentication-factor-timeout",
	132: "denied-incorrect-authentication-factor",
	133: "denied-zone-no-access-rights",
	134: "denied-point-no-access-rights",
	135: "denied-no-access-rights",
	136: "denied-out-of-time-range",
	137: "denied-threat-level",
	138: "denied-passback",
	139: "denied-unexpected-location-usage",
	140: "denied-max-attempts",
	141: "denied-lower-occupancy-limit",
	142: "denied-upper-occupancy-limit",
	143: "denied-authentication-factor-lost",
	144: "denied-authentication-factor-stolen",
	145: "denied-authentication-factor-damaged",
	146: "denied-authentication-factor-destroyed",
	147: "denied-authentication-factor-disabled",
	148: "denied-authentication-factor-error",
	149: "denied-credential-unassigned",
	150: "denied-credential-not-provisioned",
	151: "denied-credential-not-yet-active",
	152: "denied-credential-expired",
	153: "denied-credential-manual-disable",
	154: "denied-credential-lockout",
	155: "denied-credential-max-days",
	156: "denied-credential-max-uses",
	157: "denied-credential-inactivity",
	158: "denied-credential-disabled",
	159: "denied-no-accompaniment",
	160: "denied-incorrect-accompaniment",
	161: "denied-lockout",
	162: "denied-verification-failed",
	163: "denied-verification-timeout",
	164: "denied-other",
}

var bacnetNamesAccessZoneOccupancyState = map[uint32]string{
	0: "normal",
	1: "below-lower-limit",
	2: "at-lower-limit",
	3: "at-upper-limit",
	4: "above-upper-limit",
	5: "disabled",
	6: "not-supported",
}

var bacnetNamesAccessPassbackMode = map[uint32]string{
	0: "passback-off",
	1: "hard-passback",
	2: "soft-passback",
}

var bacnetNamesAccessCredentialDisableReason = map[uint32]string{
	0: "disabled",
	1: "disabled-needs-provisioning",
	2: "disabled-unassigned",
	3: "disabled-not-yet-active",
	4: "disabled-expired",
	5: "disabled-lockout",
	6: "disabled-max-days",
	7: "disabled-max-uses",
	8: "disabled-inactivity",
	9: "disabled-manual",
}

var bacnetNamesAccessCredentialDisable = map[uint32]string{
	0: "none",
	1: "disable",
	2: "disable-manual",
	3: "disable-lockout",
}

var bacnetNamesAccessUserType = map[uint32]string{
	0: "asset",
	1: "group",
	2: "person",
}

var bacnetNamesAuthenticationStatus = map[uint32]string{
	0: "not-ready",
	1: "ready",
	2: "disabled",
	3: "waiting-for-authentication-factor",
	4: "waiting-for-accompaniment",
	5: "waiting-for-verification",
	6: "in-progress",
}

var bacnetNamesAuthorizationMode = map[uint32]string{
	0: "authorize",
	1: "grant-active",
	2: "deny-all",
	3: "verification-required",
	4: "authorization-delayed",
	5: "none",
}

var bacnetNamesAuthorizationExemption = map[uint32]string{
	0: "passback",
	1: "occupancy-check",
	2: "access-rights",
	3: "lockout",
	4: "deny",
	5: "verification",
	6: "authorization-delay",
}

var bacnetNamesSecurityLevel = map[uint32]string{
	0: "incapable",
	1: "plain",
	2: "signed",
	3: "encrypted",
	4: "signed-end-to-end",
	5: "encrypted-end-to-end",
}

var bacnetNamesFaultType = map[uint32]string{
	0: "none",
	1: "fault-characterstring",
	2: "fault-extended",
	3: "fault-life-safety",
	4: "fault-state",
	5: "fault-status-flags",
	6: "fault-out-of-range",
	7: "fault-listed",
}

var bacnetNamesAccumulatorStatus = map[uint32]string{
	0: "normal",
	1: "starting",
	2: "recovered",
	3: "abnormal",
	4: "failed",
}

var bacnetNamesVTClass = map[uint32]string{
	0: "default-terminal",
	1: "ansi-x3-64",
	2: "dec-vt52",
	3: "dec-vt100",
	4: "dec-vt200",
	5: "hp-700-94",
	6: "ibm-3130",
}

var bacnetNamesEnableDisable = map[uint32]string{
	0: "enable",
	1: "disable",
	2: "disable-initiation",
}

var bacnetNamesReinitializedState = map[uint32]string{
	0: "coldstart",
	1: "warmstart",
	2: "start-backup",
	3: "end-backup",
	4: "start-restore",
	5: "end-restore",
	6: "abort-restore",
	7: "activate-changes",
}

var bacnetNamesMessagePriority = map[uint32]string{
	0: "normal",
	1: "urgent",
}

var bacnetNamesAcknowledgmentFilter = map[uint32]string{
	0: "all",
	1: "acked",
	2: "not-acked",
}

var bacnetNamesEventStateFilter = map[uint32]string{
	0: "offnormal",
	1: "fault",
	2: "normal",
	3: "all",
	4: "active",
}

var bacnetNamesEscalatorFault = map[uint32]string{
	0: "controller-fault",
	1: "drive-and-motor-fault",
	2: "mechanical-component-fault",
	3: "overspeed-fault",
	4: "power-supply-fault",
	5: "safety-device-fault",
	6: "controller-supply-fault",
	7: "drive-temperature-exceeded",
	8: "comb-plate-fault",
}

var bacnetNamesEscalatorMode = map[uint32]string{
	0: "unknown",
	1: "stop",
	2: "up",
	3: "down",
	4: "inspection",
	5: "out-of-service",
}

var bacnetNamesEscalatorOperationDirection = map[uint32]string{
	0: "unknown",
	1: "stopped",
	2: "up-rated-speed",
	3: "up-reduced-speed",
	4: "down-rated-speed",
	5: "down-reduced-speed",
}

var bacnetNamesLiftCarDirection = map[uint32]string{
	0: "unknown",
	1: "none",
	2: "stopped",
	3: "up",
	4: "down",
	5: "up-and-down",
}

var bacnetNamesLiftCarDoorCommand = map[uint32]string{
	0: "none",
	1: "open",
	2: "close",
}

var bacnetNamesLiftCarDriveStatus = map[uint32]string{
	0: "unknown",
	1: "stationary",
	2: "braking",
	3: "accelerate",
	4: "decelerate",
	5: "rated-speed",
	6: "single-floor-jump",
	7: "two-floor-jump",
	8: "three-floor-jump",
	9: "multi-floor-jump",
}

var bacnetNamesLiftCarMode = map[uint32]string{
	0:  "unknown",
	1:  "normal",
	2:  "vip",
	3:  "homing",
	4:  "parking",
	5:  "attendant-control",
	6:  "firefighter-control",
	7:  "emergency-power",
	8:  "inspection",
	9:  "cabinet-recall",
	10: "earthquake-operation",
	11: "fire-operation",
	12: "out-of-service",
	13: "occupant-evacuation",
}

var bacnetNamesLiftFault = map[uint32]string{
	0:  "controller-fault",
	1:  "drive-and-motor-fault",
	2:  "governor-and-safety-gear-fault",
	3:  "lift-shaft-device-fault",
	4:  "power-supply-fault",
	5:  "safety-interlock-fault",
	6:  "door-closing-fault",
	7:  "door-opening-fault",
	8:  "car-stopped-outside-landing-zone",
	9:  "call-button-stuck",
	10: "start-failure",
	11: "controller-supply-fault",
	12: "self-test-failure",
	13: "runtime-limit-exceeded",
	14: "position-lost",
	15: "drive-temperature-exceeded",
	16: "load-measurement-fault",
}

var bacnetNamesLiftGroupMode = map[uint32]string{
	0: "unknown",
	1: "normal",
	2: "down-peak",
	3: "two-way",
	4: "four-way",
	5: "emergency-power",
	6: "up-peak",
}

var bacnetNamesRelationship = map[uint32]string{
	0:  "unknown",
	1:  "default",
	2:  "contains",
	3:  "contained-by",
	4:  "uses",
	5:  "used-by",
	6:  "commands",
	7:  "commanded-by",
	8:  "adjusts",
	9:  "adjusted-by",
	10: "ingress",
	11: "egress",
	12: "supplies-air",
	13: "receives-air",
	14: "supplies-hot-air",
	15: "receives-hot-air",
	16: "supplies-cool-air",
	17: "receives-cool-air",
	18: "supplies-power",
	19: "receives-power",
	20: "supplies-gas",
	21: "receives-gas",
	22: "supplies-water",
	23: "receives-water",
	24: "supplies-hot-water",
	25: "receives-hot-water",
	26: "supplies-cool-water",
	27: "receives-cool-water",
	28: "supplies-steam",
	29: "receives-steam",
}

var bacnetNamesAuditLevel = map[uint32]string{
	0: "none",
	1: "audit-all",
	2: "audit-config",
	3: "default",
}

var bacnetNamesAuditOperation = map[uint32]string{
	0:  "read",
	1:  "write",
	2:  "create",
	3:  "delete",
	4:  "life-safety",
	5:  "acknowledge-alarm",
	6:  "device-disable-comm",
	7:  "device-enable-comm",
	8:  "device-reset",
	9:  "device-backup",
	10: "device-restore",
	11: "subscription",
	12: "notification",
	13: "auditing-failure",
	14: "network-changes",
	15: "general",
}

var bacnetNamesSuccessFilter = map[uint32]string{
	0: "all",
	1: "successes-only",
	2: "failures-only",
}

var bacnetBitsStatusFlags = []string{
	"in-alarm",
	"fault",
	"overridden",
	"out-of-service",
}

var bacnetBitsEventTransitionBits = []string{
	"to-offnormal",
	"to-fault",
	"to-normal",
}

var bacnetBitsLimitEnable = []string{
	"low-limit-enable",
	"high-limit-enable",
}

var bacnetBitsDaysOfWeek = []string{
	"monday",
	"tuesday",
	"wednesday",
	"thursday",
	"friday",
	"saturday",
	"sunday",
}

var bacnetBitsLogStatus = []string{
	"log-disabled",
	"buffer-purged",
	"log-interrupted",
}

var bacnetBitsResultFlags = []string{
	"first-item",
	"last-item",
	"more-items",
}

var bacnetBitsServicesSupported = []string{
	"acknowledge-alarm",
	"confirmed-cov-notification",
	"confirmed-event-notification",
	"get-alarm-summary",
	"get-enrollment-summary",
	"subscribe-cov",
	"atomic-read-file",
	"atomic-write-file",
	"add-list-element",
	"remove-list-element",
	"create-object",
	"delete-object",
	"read-property",
	"read-property-conditional",
	"read-property-multiple",
	"write-property",
	"write-property-multiple",
	"device-communication-control",
	"confirmed-private-transfer",
	"confirmed-text-message",
	"reinitialize-device",
	"vt-open",
	"vt-close",
	"vt-data",
	"authenticate",
	"request-key",
	"i-am",
	"i-have",
	"unconfirmed-cov-notification",
	"unconfirmed-event-notification",
	"unconfirmed-private-transfer",
	"unconfirmed-text-message",
	"time-synchronization",
	"who-has",
	"who-is",
	"read-range",
	"utc-time-synchronization",
	"life-safety-operation",
	"subscribe-cov-property",
	"get-event-information",
	"write-group",
	"subscribe-cov-property-multiple",
	"confirmed-cov-notification-multiple",
	"unconfirmed-cov-notification-multiple",
	"confirmed-audit-notification",
	"audit-log-query",
	"unconfirmed-audit-notification",
	"who-am-i",
	"you-are",
	"auth-request",
}

var bacnetBitsObjectTypesSupported = []string{
	"analog-input",
	"analog-output",
	"analog-value",
	"binary-input",
	"binary-output",
	"binary-value",
	"calendar",
	"command",
	"device",
	"event-enrollment",
	"file",
	"group",
	"loop",
	"multi-state-input",
	"multi-state-output",
	"notification-class",
	"program",
	"schedule",
	"averaging",
	"multi-state-value",
	"trend-log",
	"life-safety-point",
	"life-safety-zone",
	"accumulator",
	"pulse-converter",
	"event-log",
	"global-group",
	"trend-log-multiple",
	"load-control",
	"structured-view",
	"access-door",
	"timer",
	"access-credential",
	"access-point",
	"access-rights",
	"access-user",
	"access-zone",
	"credential-data-input",
	"network-security",
	"bitstring-value",
	"characterstring-value",
	"date-pattern-value",
	"date-value",
	"datetime-pattern-value",
	"datetime-value",
	"integer-value",
	"large-analog-value",
	"octetstring-value",
	"positive-integer-value",
	"time-pattern-value",
	"time-value",
	"notification-forwarder",
	"alert-enrollment",
	"channel",
	"lighting-output",
	"binary-lighting-output",
	"network-port",
	"elevator-group",
	"escalator",
	"lift",
	"staging",
	"audit-log",
	"audit-reporter",
	"color",
	"color-temperature",
}
