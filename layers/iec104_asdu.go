// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The IEC 60870-5-101/104 ASDU: data unit identifier, information objects
// and their information elements, in the IEC 104 field sizes (2-octet
// cause of transmission, 2-octet common address, 3-octet object address).
//
//	+---------+-----+-----+----+--------+---------------------------+
//	| type ID | VSQ | COT | OA | CA (2) | information objects ...   |
//	+---------+-----+-----+----+--------+---------------------------+
//
//	SQ=0: IOA element IOA element ...  each object has its own address
//	SQ=1: IOA element element ...      addresses count up from the first

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Data unit identifier layout. IEC 104 fixes the sizes of the cause of
// transmission, common address and object address; IEC 101 lets a system
// pick them, see IEC104ASDUOptions.
const (
	iec104TypeVSQLen = 2 // type identification and structure qualifier
	iec104COTLen     = 2
	iec104CALen      = 2
	iec104IOALen     = 3
	iec104DUILen     = iec104TypeVSQLen + iec104COTLen + iec104CALen

	iec104SQBit       = 0x80 // variable structure qualifier: sequence
	iec104NumMask     = 0x7F // variable structure qualifier: object count
	iec104CauseMask   = 0x3F
	iec104NegativeBit = 0x40
	iec104TestBit     = 0x80

	iec104BitsPerOctet = 8
)

// Information element bit fields (IEC 60870-5-101, 7.2.6).
const (
	iec104SPIMask      = 0x01 // SIQ single point
	iec104DPIMask      = 0x03 // DIQ double point, SEP event state
	iec104PointQuality = 0xF0 // SIQ/DIQ: BL SB NT IV
	iec104QDSQuality   = 0xF1 // QDS: OV BL SB NT IV
	iec104QDPQuality   = 0xF8 // QDP/SEP: EI BL SB NT IV

	iec104VTIValueMask = 0x7F
	iec104VTISignBit   = 0x40
	iec104VTITransient = 0x80

	iec104BCRSeqMask  = 0x1F
	iec104BCRCarry    = 0x20
	iec104BCRAdjusted = 0x40
	iec104BCRInvalid  = 0x80

	iec104SCSMask      = 0x01 // SCO state
	iec104DCSMask      = 0x03 // DCO/RCO state
	iec104QUShift      = 2    // command qualifier QU
	iec104QUMask       = 0x1F
	iec104QLMask       = 0x7F // setpoint qualifier QL
	iec104SelectBit    = 0x80 // S/E of commands and setpoints
	iec104NormalizedFS = 32768
)

// Time tag layout (CP24Time2a, CP56Time2a).
const (
	iec104MinuteMask       = 0x3F
	iec104SubstitutedBit   = 0x40
	iec104InvalidBit       = 0x80
	iec104HourMask         = 0x1F
	iec104SummerBit        = 0x80
	iec104DayMask          = 0x1F
	iec104WeekdayShift     = 5
	iec104MonthMask        = 0x0F
	iec104YearMask         = 0x7F
	iec104CenturyBase      = 2000
	iec104MsPerSecond      = 1000
	iec104NsPerMillisecond = 1000000

	// Largest values of the time tag fields (IEC 60870-5-4, 6.8).
	iec104MaxMilliseconds = 59999
	iec104MaxMinute       = 59
	iec104MaxHour         = 23
	iec104MaxMonth        = 12
	iec104MaxYear         = 99
)

var (
	// ErrIEC104ASDUTooShort is returned when an I-format frame is too short
	// for a data unit identifier.
	ErrIEC104ASDUTooShort = errors.New("IEC 104 ASDU too short")
	// ErrIEC104ObjectsTooLong is returned when the information objects an
	// ASDU announces do not fit in it.
	ErrIEC104ObjectsTooLong = errors.New("IEC 104 information objects exceed ASDU")
	// ErrIEC104BadSequence is returned when SQ is set on a run of objects
	// whose type has no information elements, such as C_RD_NA_1.
	ErrIEC104BadSequence = errors.New("IEC 104 SQ set on objects without elements")
)

// IEC104TypeID is the ASDU type identification.
type IEC104TypeID uint8

// Type identifications of IEC 60870-5-101 and 60870-5-104. The comment of
// each names its mnemonic, which String returns.
const (
	IEC104TypeSinglePoint              IEC104TypeID = 1   // M_SP_NA_1
	IEC104TypeSinglePointTime24        IEC104TypeID = 2   // M_SP_TA_1
	IEC104TypeDoublePoint              IEC104TypeID = 3   // M_DP_NA_1
	IEC104TypeDoublePointTime24        IEC104TypeID = 4   // M_DP_TA_1
	IEC104TypeStepPosition             IEC104TypeID = 5   // M_ST_NA_1
	IEC104TypeStepPositionTime24       IEC104TypeID = 6   // M_ST_TA_1
	IEC104TypeBitstring                IEC104TypeID = 7   // M_BO_NA_1
	IEC104TypeBitstringTime24          IEC104TypeID = 8   // M_BO_TA_1
	IEC104TypeNormalized               IEC104TypeID = 9   // M_ME_NA_1
	IEC104TypeNormalizedTime24         IEC104TypeID = 10  // M_ME_TA_1
	IEC104TypeScaled                   IEC104TypeID = 11  // M_ME_NB_1
	IEC104TypeScaledTime24             IEC104TypeID = 12  // M_ME_TB_1
	IEC104TypeFloat                    IEC104TypeID = 13  // M_ME_NC_1
	IEC104TypeFloatTime24              IEC104TypeID = 14  // M_ME_TC_1
	IEC104TypeTotals                   IEC104TypeID = 15  // M_IT_NA_1
	IEC104TypeTotalsTime24             IEC104TypeID = 16  // M_IT_TA_1
	IEC104TypeProtEventTime24          IEC104TypeID = 17  // M_EP_TA_1
	IEC104TypeProtStartTime24          IEC104TypeID = 18  // M_EP_TB_1
	IEC104TypeProtCircuitTime24        IEC104TypeID = 19  // M_EP_TC_1
	IEC104TypePackedSinglePoint        IEC104TypeID = 20  // M_PS_NA_1
	IEC104TypeNormalizedNoQuality      IEC104TypeID = 21  // M_ME_ND_1
	IEC104TypeSinglePointTime56        IEC104TypeID = 30  // M_SP_TB_1
	IEC104TypeDoublePointTime56        IEC104TypeID = 31  // M_DP_TB_1
	IEC104TypeStepPositionTime56       IEC104TypeID = 32  // M_ST_TB_1
	IEC104TypeBitstringTime56          IEC104TypeID = 33  // M_BO_TB_1
	IEC104TypeNormalizedTime56         IEC104TypeID = 34  // M_ME_TD_1
	IEC104TypeScaledTime56             IEC104TypeID = 35  // M_ME_TE_1
	IEC104TypeFloatTime56              IEC104TypeID = 36  // M_ME_TF_1
	IEC104TypeTotalsTime56             IEC104TypeID = 37  // M_IT_TB_1
	IEC104TypeProtEventTime56          IEC104TypeID = 38  // M_EP_TD_1
	IEC104TypeProtStartTime56          IEC104TypeID = 39  // M_EP_TE_1
	IEC104TypeProtCircuitTime56        IEC104TypeID = 40  // M_EP_TF_1
	IEC104TypeSecurityStatistics       IEC104TypeID = 41  // S_IT_TC_1
	IEC104TypeSingleCommand            IEC104TypeID = 45  // C_SC_NA_1
	IEC104TypeDoubleCommand            IEC104TypeID = 46  // C_DC_NA_1
	IEC104TypeStepCommand              IEC104TypeID = 47  // C_RC_NA_1
	IEC104TypeSetpointNormalized       IEC104TypeID = 48  // C_SE_NA_1
	IEC104TypeSetpointScaled           IEC104TypeID = 49  // C_SE_NB_1
	IEC104TypeSetpointFloat            IEC104TypeID = 50  // C_SE_NC_1
	IEC104TypeBitstringCommand         IEC104TypeID = 51  // C_BO_NA_1
	IEC104TypeSingleCommandTime56      IEC104TypeID = 58  // C_SC_TA_1
	IEC104TypeDoubleCommandTime56      IEC104TypeID = 59  // C_DC_TA_1
	IEC104TypeStepCommandTime56        IEC104TypeID = 60  // C_RC_TA_1
	IEC104TypeSetpointNormalizedTime56 IEC104TypeID = 61  // C_SE_TA_1
	IEC104TypeSetpointScaledTime56     IEC104TypeID = 62  // C_SE_TB_1
	IEC104TypeSetpointFloatTime56      IEC104TypeID = 63  // C_SE_TC_1
	IEC104TypeBitstringCommandTime56   IEC104TypeID = 64  // C_BO_TA_1
	IEC104TypeEndOfInit                IEC104TypeID = 70  // M_EI_NA_1
	IEC104TypeInterrogation            IEC104TypeID = 100 // C_IC_NA_1
	IEC104TypeCounterInterrogation     IEC104TypeID = 101 // C_CI_NA_1
	IEC104TypeRead                     IEC104TypeID = 102 // C_RD_NA_1
	IEC104TypeClockSync                IEC104TypeID = 103 // C_CS_NA_1
	IEC104TypeTest                     IEC104TypeID = 104 // C_TS_NA_1
	IEC104TypeResetProcess             IEC104TypeID = 105 // C_RP_NA_1
	IEC104TypeDelayAcquisition         IEC104TypeID = 106 // C_CD_NA_1
	IEC104TypeTestTime56               IEC104TypeID = 107 // C_TS_TA_1
	IEC104TypeParamNormalized          IEC104TypeID = 110 // P_ME_NA_1
	IEC104TypeParamScaled              IEC104TypeID = 111 // P_ME_NB_1
	IEC104TypeParamFloat               IEC104TypeID = 112 // P_ME_NC_1
	IEC104TypeParamActivation          IEC104TypeID = 113 // P_AC_NA_1
	IEC104TypeFileReady                IEC104TypeID = 120 // F_FR_NA_1
	IEC104TypeSectionReady             IEC104TypeID = 121 // F_SR_NA_1
	IEC104TypeCallFile                 IEC104TypeID = 122 // F_SC_NA_1
	IEC104TypeLastSection              IEC104TypeID = 123 // F_LS_NA_1
	IEC104TypeAckFile                  IEC104TypeID = 124 // F_AF_NA_1
	IEC104TypeSegment                  IEC104TypeID = 125 // F_SG_NA_1
	IEC104TypeDirectory                IEC104TypeID = 126 // F_DR_TA_1
	IEC104TypeQueryLog                 IEC104TypeID = 127 // F_SC_NB_1
)

// iec104Part is one information element within an information object.
type iec104Part uint8

const (
	partSIQ       iec104Part = iota // single-point information with quality
	partDIQ                         // double-point information with quality
	partVTI                         // value with transient state
	partQDS                         // quality descriptor
	partQDP                         // quality descriptor for protection
	partBSI                         // bitstring of 32 bits
	partSCD                         // status and status change detection
	partNVA                         // normalized value
	partSVA                         // scaled value
	partFloat                       // IEEE 754 short float
	partBCR                         // binary counter reading
	partSEP                         // single event of protection
	partSPE                         // start events of protection
	partOCI                         // output circuit information
	partCP16                        // elapsed time, milliseconds
	partCP24                        // three-octet time tag
	partCP56                        // seven-octet time tag
	partCP56Stop                    // second CP56 of a range
	partSCO                         // single command
	partDCO                         // double command
	partRCO                         // regulating step command
	partQOS                         // qualifier of set-point command
	partQualifier                   // COI, QOI, QCC, QRP, QPM or QPA
	partTest                        // FBP test pattern or TSC counter
	partNOF                         // name of file
	partLOF                         // length of file
	partNOS                         // name of section
	partFileQual                    // FRQ, SRQ, SCQ, LSQ, AFQ or SOF
	partCHS                         // checksum
	partSegment                     // LOS and that many octets of segment
	partAID                         // association ID of security statistics
)

// iec104PartSize is the octet size of each part; partSegment gives its
// smallest size, the LOS octet alone.
var iec104PartSize = [...]int{
	partSIQ: 1, partDIQ: 1, partVTI: 1, partQDS: 1, partQDP: 1,
	partBSI: 4, partSCD: 4, partNVA: 2, partSVA: 2, partFloat: 4,
	partBCR: 5, partSEP: 1, partSPE: 1, partOCI: 1,
	partCP16: 2, partCP24: 3, partCP56: 7, partCP56Stop: 7,
	partSCO: 1, partDCO: 1, partRCO: 1, partQOS: 1, partQualifier: 1,
	partTest: 2, partNOF: 2, partLOF: 3, partNOS: 1, partFileQual: 1,
	partCHS: 1, partSegment: 1, partAID: 2,
}

// iec104Type describes a type identification: its mnemonic and the parts
// of one information element.
type iec104Type struct {
	name  string
	parts []iec104Part
}

// iec104Types holds every standard type identification of IEC 60870-5-101
// and 60870-5-104 (7.3 of each).
var iec104Types = map[IEC104TypeID]iec104Type{
	IEC104TypeSinglePoint:              {"M_SP_NA_1", []iec104Part{partSIQ}},
	IEC104TypeSinglePointTime24:        {"M_SP_TA_1", []iec104Part{partSIQ, partCP24}},
	IEC104TypeDoublePoint:              {"M_DP_NA_1", []iec104Part{partDIQ}},
	IEC104TypeDoublePointTime24:        {"M_DP_TA_1", []iec104Part{partDIQ, partCP24}},
	IEC104TypeStepPosition:             {"M_ST_NA_1", []iec104Part{partVTI, partQDS}},
	IEC104TypeStepPositionTime24:       {"M_ST_TA_1", []iec104Part{partVTI, partQDS, partCP24}},
	IEC104TypeBitstring:                {"M_BO_NA_1", []iec104Part{partBSI, partQDS}},
	IEC104TypeBitstringTime24:          {"M_BO_TA_1", []iec104Part{partBSI, partQDS, partCP24}},
	IEC104TypeNormalized:               {"M_ME_NA_1", []iec104Part{partNVA, partQDS}},
	IEC104TypeNormalizedTime24:         {"M_ME_TA_1", []iec104Part{partNVA, partQDS, partCP24}},
	IEC104TypeScaled:                   {"M_ME_NB_1", []iec104Part{partSVA, partQDS}},
	IEC104TypeScaledTime24:             {"M_ME_TB_1", []iec104Part{partSVA, partQDS, partCP24}},
	IEC104TypeFloat:                    {"M_ME_NC_1", []iec104Part{partFloat, partQDS}},
	IEC104TypeFloatTime24:              {"M_ME_TC_1", []iec104Part{partFloat, partQDS, partCP24}},
	IEC104TypeTotals:                   {"M_IT_NA_1", []iec104Part{partBCR}},
	IEC104TypeTotalsTime24:             {"M_IT_TA_1", []iec104Part{partBCR, partCP24}},
	IEC104TypeProtEventTime24:          {"M_EP_TA_1", []iec104Part{partSEP, partCP16, partCP24}},
	IEC104TypeProtStartTime24:          {"M_EP_TB_1", []iec104Part{partSPE, partQDP, partCP16, partCP24}},
	IEC104TypeProtCircuitTime24:        {"M_EP_TC_1", []iec104Part{partOCI, partQDP, partCP16, partCP24}},
	IEC104TypePackedSinglePoint:        {"M_PS_NA_1", []iec104Part{partSCD, partQDS}},
	IEC104TypeNormalizedNoQuality:      {"M_ME_ND_1", []iec104Part{partNVA}},
	IEC104TypeSinglePointTime56:        {"M_SP_TB_1", []iec104Part{partSIQ, partCP56}},
	IEC104TypeDoublePointTime56:        {"M_DP_TB_1", []iec104Part{partDIQ, partCP56}},
	IEC104TypeStepPositionTime56:       {"M_ST_TB_1", []iec104Part{partVTI, partQDS, partCP56}},
	IEC104TypeBitstringTime56:          {"M_BO_TB_1", []iec104Part{partBSI, partQDS, partCP56}},
	IEC104TypeNormalizedTime56:         {"M_ME_TD_1", []iec104Part{partNVA, partQDS, partCP56}},
	IEC104TypeScaledTime56:             {"M_ME_TE_1", []iec104Part{partSVA, partQDS, partCP56}},
	IEC104TypeFloatTime56:              {"M_ME_TF_1", []iec104Part{partFloat, partQDS, partCP56}},
	IEC104TypeTotalsTime56:             {"M_IT_TB_1", []iec104Part{partBCR, partCP56}},
	IEC104TypeProtEventTime56:          {"M_EP_TD_1", []iec104Part{partSEP, partCP16, partCP56}},
	IEC104TypeProtStartTime56:          {"M_EP_TE_1", []iec104Part{partSPE, partQDP, partCP16, partCP56}},
	IEC104TypeProtCircuitTime56:        {"M_EP_TF_1", []iec104Part{partOCI, partQDP, partCP16, partCP56}},
	IEC104TypeSecurityStatistics:       {"S_IT_TC_1", []iec104Part{partAID, partBCR, partCP56}},
	IEC104TypeSingleCommand:            {"C_SC_NA_1", []iec104Part{partSCO}},
	IEC104TypeDoubleCommand:            {"C_DC_NA_1", []iec104Part{partDCO}},
	IEC104TypeStepCommand:              {"C_RC_NA_1", []iec104Part{partRCO}},
	IEC104TypeSetpointNormalized:       {"C_SE_NA_1", []iec104Part{partNVA, partQOS}},
	IEC104TypeSetpointScaled:           {"C_SE_NB_1", []iec104Part{partSVA, partQOS}},
	IEC104TypeSetpointFloat:            {"C_SE_NC_1", []iec104Part{partFloat, partQOS}},
	IEC104TypeBitstringCommand:         {"C_BO_NA_1", []iec104Part{partBSI}},
	IEC104TypeSingleCommandTime56:      {"C_SC_TA_1", []iec104Part{partSCO, partCP56}},
	IEC104TypeDoubleCommandTime56:      {"C_DC_TA_1", []iec104Part{partDCO, partCP56}},
	IEC104TypeStepCommandTime56:        {"C_RC_TA_1", []iec104Part{partRCO, partCP56}},
	IEC104TypeSetpointNormalizedTime56: {"C_SE_TA_1", []iec104Part{partNVA, partQOS, partCP56}},
	IEC104TypeSetpointScaledTime56:     {"C_SE_TB_1", []iec104Part{partSVA, partQOS, partCP56}},
	IEC104TypeSetpointFloatTime56:      {"C_SE_TC_1", []iec104Part{partFloat, partQOS, partCP56}},
	IEC104TypeBitstringCommandTime56:   {"C_BO_TA_1", []iec104Part{partBSI, partCP56}},
	IEC104TypeEndOfInit:                {"M_EI_NA_1", []iec104Part{partQualifier}},
	IEC104TypeInterrogation:            {"C_IC_NA_1", []iec104Part{partQualifier}},
	IEC104TypeCounterInterrogation:     {"C_CI_NA_1", []iec104Part{partQualifier}},
	IEC104TypeRead:                     {"C_RD_NA_1", nil},
	IEC104TypeClockSync:                {"C_CS_NA_1", []iec104Part{partCP56}},
	IEC104TypeTest:                     {"C_TS_NA_1", []iec104Part{partTest}},
	IEC104TypeResetProcess:             {"C_RP_NA_1", []iec104Part{partQualifier}},
	IEC104TypeDelayAcquisition:         {"C_CD_NA_1", []iec104Part{partCP16}},
	IEC104TypeTestTime56:               {"C_TS_TA_1", []iec104Part{partTest, partCP56}},
	IEC104TypeParamNormalized:          {"P_ME_NA_1", []iec104Part{partNVA, partQualifier}},
	IEC104TypeParamScaled:              {"P_ME_NB_1", []iec104Part{partSVA, partQualifier}},
	IEC104TypeParamFloat:               {"P_ME_NC_1", []iec104Part{partFloat, partQualifier}},
	IEC104TypeParamActivation:          {"P_AC_NA_1", []iec104Part{partQualifier}},
	IEC104TypeFileReady:                {"F_FR_NA_1", []iec104Part{partNOF, partLOF, partFileQual}},
	IEC104TypeSectionReady:             {"F_SR_NA_1", []iec104Part{partNOF, partNOS, partLOF, partFileQual}},
	IEC104TypeCallFile:                 {"F_SC_NA_1", []iec104Part{partNOF, partNOS, partFileQual}},
	IEC104TypeLastSection:              {"F_LS_NA_1", []iec104Part{partNOF, partNOS, partFileQual, partCHS}},
	IEC104TypeAckFile:                  {"F_AF_NA_1", []iec104Part{partNOF, partNOS, partFileQual}},
	IEC104TypeSegment:                  {"F_SG_NA_1", []iec104Part{partNOF, partNOS, partSegment}},
	IEC104TypeDirectory:                {"F_DR_TA_1", []iec104Part{partNOF, partLOF, partFileQual, partCP56}},
	IEC104TypeQueryLog:                 {"F_SC_NB_1", []iec104Part{partNOF, partCP56, partCP56Stop}},
}

// String returns the type's mnemonic, e.g. "M_SP_NA_1".
func (t IEC104TypeID) String() string {
	if info, ok := iec104Types[t]; ok {
		return info.name
	}
	if name, ok := iec104SecurityNames[t]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", uint8(t))
}

// IEC104Cause is the cause of transmission, without its P/N and T bits.
type IEC104Cause uint8

// Causes of transmission (IEC 60870-5-101, 7.2.3).
const (
	IEC104CausePeriodic         IEC104Cause = 1
	IEC104CauseBackground       IEC104Cause = 2
	IEC104CauseSpontaneous      IEC104Cause = 3
	IEC104CauseInitialized      IEC104Cause = 4
	IEC104CauseRequest          IEC104Cause = 5
	IEC104CauseActivation       IEC104Cause = 6
	IEC104CauseActivationCon    IEC104Cause = 7
	IEC104CauseDeactivation     IEC104Cause = 8
	IEC104CauseDeactivationCon  IEC104Cause = 9
	IEC104CauseActivationTerm   IEC104Cause = 10
	IEC104CauseRemoteCommand    IEC104Cause = 11
	IEC104CauseLocalCommand     IEC104Cause = 12
	IEC104CauseFileTransfer     IEC104Cause = 13
	IEC104CauseInterrogated     IEC104Cause = 20 // station interrogation
	IEC104CauseInterrogatedG1   IEC104Cause = 21 // group 1; groups 2-16 follow
	IEC104CauseInterrogatedG16  IEC104Cause = 36
	IEC104CauseCounterRequest   IEC104Cause = 37 // general counter request
	IEC104CauseCounterRequestG1 IEC104Cause = 38 // group 1; groups 2-4 follow
	IEC104CauseCounterRequestG4 IEC104Cause = 41
	IEC104CauseUnknownType      IEC104Cause = 44
	IEC104CauseUnknownCause     IEC104Cause = 45
	IEC104CauseUnknownAddress   IEC104Cause = 46
	IEC104CauseUnknownObject    IEC104Cause = 47
)

// iec104CauseNames holds the causes Wireshark names, outside the groups.
var iec104CauseNames = map[IEC104Cause]string{
	IEC104CausePeriodic:        "Per/Cyc",
	IEC104CauseBackground:      "Back",
	IEC104CauseSpontaneous:     "Spont",
	IEC104CauseInitialized:     "Init",
	IEC104CauseRequest:         "Req",
	IEC104CauseActivation:      "Act",
	IEC104CauseActivationCon:   "ActCon",
	IEC104CauseDeactivation:    "Deact",
	IEC104CauseDeactivationCon: "DeactCon",
	IEC104CauseActivationTerm:  "ActTerm",
	IEC104CauseRemoteCommand:   "Retrem",
	IEC104CauseLocalCommand:    "Retloc",
	IEC104CauseFileTransfer:    "File",
	IEC104CauseInterrogated:    "Inrogen",
	IEC104CauseCounterRequest:  "Reqcogen",
	IEC104CauseUnknownType:     "UkTypeId",
	IEC104CauseUnknownCause:    "UkCauseTx",
	IEC104CauseUnknownAddress:  "UkComAdrASDU",
	IEC104CauseUnknownObject:   "UkIOA",
}

// String returns the cause as Wireshark abbreviates it, e.g. "Spont" or
// "Inro3".
func (c IEC104Cause) String() string {
	if name, ok := iec104CauseNames[c]; ok {
		return name
	}
	if c >= IEC104CauseInterrogatedG1 && c <= IEC104CauseInterrogatedG16 {
		return fmt.Sprintf("Inro%d", c-IEC104CauseInterrogatedG1+1)
	}
	if c >= IEC104CauseCounterRequestG1 && c <= IEC104CauseCounterRequestG4 {
		return fmt.Sprintf("Reqco%d", c-IEC104CauseCounterRequestG1+1)
	}
	return fmt.Sprintf("Unknown(%d)", uint8(c))
}

// IEC104Quality holds the quality bits of QDS, QDP, SIQ, DIQ and SEP.
type IEC104Quality uint8

// Quality bits. Each element type carries a subset: SIQ and DIQ have BL,
// SB, NT and IV; QDS adds OV; QDP and SEP add EI.
const (
	IEC104QualityOverflow       IEC104Quality = 0x01 // OV
	IEC104QualityElapsedInvalid IEC104Quality = 0x08 // EI
	IEC104QualityBlocked        IEC104Quality = 0x10 // BL
	IEC104QualitySubstituted    IEC104Quality = 0x20 // SB
	IEC104QualityNotTopical     IEC104Quality = 0x40 // NT
	IEC104QualityInvalid        IEC104Quality = 0x80 // IV
)

// String lists the set bits, e.g. "BL|IV", or "OK" when none is set.
func (q IEC104Quality) String() string {
	names := []struct {
		bit  IEC104Quality
		name string
	}{
		{IEC104QualityOverflow, "OV"},
		{IEC104QualityElapsedInvalid, "EI"},
		{IEC104QualityBlocked, "BL"},
		{IEC104QualitySubstituted, "SB"},
		{IEC104QualityNotTopical, "NT"},
		{IEC104QualityInvalid, "IV"},
	}

	var set []string
	for _, n := range names {
		if q&n.bit != 0 {
			set = append(set, n.name)
		}
	}
	if len(set) == 0 {
		return "OK"
	}
	return strings.Join(set, "|")
}

// IEC104DoublePoint is the state of a DIQ double point or a SEP event.
type IEC104DoublePoint uint8

// Double point states.
const (
	IEC104DoublePointIntermediate  IEC104DoublePoint = 0
	IEC104DoublePointOff           IEC104DoublePoint = 1
	IEC104DoublePointOn            IEC104DoublePoint = 2
	IEC104DoublePointIndeterminate IEC104DoublePoint = 3
)

// String returns the state name.
func (d IEC104DoublePoint) String() string {
	switch d {
	case IEC104DoublePointIntermediate:
		return "Intermediate"
	case IEC104DoublePointOff:
		return "Off"
	case IEC104DoublePointOn:
		return "On"
	case IEC104DoublePointIndeterminate:
		return "Indeterminate"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(d))
}

// IEC104Event holds the bits of SPE (start events of protection) or OCI
// (output circuit information).
type IEC104Event uint8

// Protection event bits. OCI uses the first four: general command and the
// phase L1 to L3 commands.
const (
	IEC104EventGeneral IEC104Event = 0x01 // GS / GC
	IEC104EventPhaseL1 IEC104Event = 0x02 // SL1 / CL1
	IEC104EventPhaseL2 IEC104Event = 0x04 // SL2 / CL2
	IEC104EventPhaseL3 IEC104Event = 0x08 // SL3 / CL3
	IEC104EventEarth   IEC104Event = 0x10 // SIE, earth current
	IEC104EventReverse IEC104Event = 0x20 // SRD, reverse direction
)

// IEC104TimeFormat tells which time tag an object carries.
type IEC104TimeFormat uint8

// Time tag formats.
const (
	// IEC104TimeNone means the object has no time tag.
	IEC104TimeNone IEC104TimeFormat = iota
	// IEC104TimeCP24 is CP24Time2a: milliseconds and minutes only.
	IEC104TimeCP24
	// IEC104TimeCP56 is CP56Time2a: a full date and time.
	IEC104TimeCP56
)

// IEC104Time is a CP24Time2a or CP56Time2a time tag. Fields CP24Time2a
// lacks stay zero.
type IEC104Time struct {
	Format IEC104TimeFormat
	// Milliseconds counts from the start of the minute, 0 to 59999.
	Milliseconds uint16
	Minute       uint8
	Hour         uint8
	Day          uint8 // day of month, 1 to 31
	Weekday      uint8 // 1 (Monday) to 7, or 0 when unused
	Month        uint8
	Year         uint8 // years past 2000, 0 to 99
	Invalid      bool  // IV
	Substituted  bool  // GEN: time substituted, not genuine
	Summer       bool  // SU: daylight saving time
}

// Time returns the CP56Time2a tag as a time.Time in loc, the zone the
// station keeps its clock in; nil means UTC. Two-digit years count from
// 2000. It returns the zero time for a CP24Time2a tag or no tag, since
// those carry no date.
func (t IEC104Time) Time(loc *time.Location) time.Time {
	if t.Format != IEC104TimeCP56 {
		return time.Time{}
	}
	if loc == nil {
		loc = time.UTC
	}

	sec := int(t.Milliseconds) / iec104MsPerSecond
	nsec := (int(t.Milliseconds) % iec104MsPerSecond) * iec104NsPerMillisecond
	return time.Date(iec104CenturyBase+int(t.Year), time.Month(t.Month), int(t.Day),
		int(t.Hour), int(t.Minute), sec, nsec, loc)
}

// IEC104TimeFault flags the fields of a time tag that are out of range.
// A tag with such a field still decodes: the fields hold what was sent.
type IEC104TimeFault uint8

// Time tag faults.
const (
	// IEC104TimeBadMilliseconds: above 59999.
	IEC104TimeBadMilliseconds IEC104TimeFault = 1 << iota
	// IEC104TimeBadMinute: above 59.
	IEC104TimeBadMinute
	// IEC104TimeBadHour: above 23.
	IEC104TimeBadHour
	// IEC104TimeBadDay: 0, or past the end of the month, e.g. 30
	// February.
	IEC104TimeBadDay
	// IEC104TimeBadMonth: 0 or above 12.
	IEC104TimeBadMonth
	// IEC104TimeBadYear: above 99.
	IEC104TimeBadYear
)

var iec104TimeFaultNames = [...]string{"Milliseconds", "Minute", "Hour", "Day", "Month", "Year"}

// String lists the fields out of range, e.g. "Hour|Day", or "None".
func (f IEC104TimeFault) String() string {
	if f == 0 {
		return "None"
	}

	var out []byte
	for k, name := range iec104TimeFaultNames {
		if f&(1<<uint(k)) == 0 {
			continue
		}
		if len(out) > 0 {
			out = append(out, '|')
		}
		out = append(out, name...)
	}

	// Bits above the named ones.
	rest := f >> uint(len(iec104TimeFaultNames)) << uint(len(iec104TimeFaultNames))
	if rest == 0 {
		return string(out)
	}
	if len(out) > 0 {
		out = append(out, '|')
	}
	return fmt.Sprintf("%sUnknown(0x%02X)", out, uint8(rest))
}

// RangeFaults returns the fields of the tag that are out of range, 0
// when all are valid. It is apart from Invalid, the IV bit the sender
// sets. A CP24Time2a tag has milliseconds and minutes to check only.
func (t IEC104Time) RangeFaults() IEC104TimeFault {
	var f IEC104TimeFault
	if t.Format == IEC104TimeNone {
		return f
	}

	if t.Milliseconds > iec104MaxMilliseconds {
		f |= IEC104TimeBadMilliseconds
	}
	if t.Minute > iec104MaxMinute {
		f |= IEC104TimeBadMinute
	}
	if t.Format != IEC104TimeCP56 {
		return f
	}

	if t.Hour > iec104MaxHour {
		f |= IEC104TimeBadHour
	}
	if t.Month == 0 || t.Month > iec104MaxMonth {
		f |= IEC104TimeBadMonth
	}
	if t.Year > iec104MaxYear {
		f |= IEC104TimeBadYear
	}
	if t.Day == 0 || int(t.Day) > iec104MonthDays(t.Year, t.Month) {
		f |= IEC104TimeBadDay
	}
	return f
}

// iec104MonthDays returns the days of a month of year 2000+year, or 31
// when the month itself is out of range.
func iec104MonthDays(year, month uint8) int {
	const longest = 31
	if month == 0 || month > iec104MaxMonth {
		return longest
	}

	// Day 0 of the next month is the last day of this one.
	return time.Date(iec104CenturyBase+int(year), time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// IEC104Counter is a BCR binary counter reading.
type IEC104Counter struct {
	Value    int32
	Sequence uint8 // SQ, 0 to 31
	Carry    bool  // CY
	Adjusted bool  // CA
	Invalid  bool  // IV
}

// IEC104Command is the command or set-point qualifier: SCO, DCO, RCO or
// QOS.
type IEC104Command struct {
	// State is SCS (0 off, 1 on), DCS (1 off, 2 on) or RCS (1 lower,
	// 2 higher); zero for a set-point.
	State uint8
	// Qualifier is QU for commands, see QU, and QL for set-points.
	Qualifier uint8
	// Select is S/E: select rather than execute.
	Select bool
}

// IEC104File holds the file transfer elements of F_* types.
type IEC104File struct {
	Name    uint16 // NOF
	Section uint8  // NOS
	// Length is LOF, or LOS for a segment.
	Length uint32
	// Qualifier is the raw FRQ, SRQ, SCQ, LSQ, AFQ or SOF octet; the
	// methods of the same names split it.
	Qualifier uint8
	Checksum  uint8  // CHS
	Segment   []byte // F_SG_NA_1 segment data
	// Stop is the end of the F_SC_NB_1 range; Time of the object holds
	// its start.
	Stop IEC104Time
}

// IEC104Object is one information object. Which fields are set depends on
// the ASDU type identification; the others stay zero.
type IEC104Object struct {
	// IOA is the information object address.
	IOA uint32
	// Raw holds the object's element octets, address excluded.
	Raw []byte

	// Quality is QDS, QDP, or the quality bits of SIQ, DIQ or SEP.
	Quality IEC104Quality
	// SinglePoint is SPI of SIQ.
	SinglePoint bool
	// DoublePoint is DPI of DIQ or ES of SEP.
	DoublePoint IEC104DoublePoint
	// Step is the VTI value, -64 to 63; Transient its T bit.
	Step      int8
	Transient bool
	// Bitstring is BSI.
	Bitstring uint32
	// Status and Changed are ST and CD of SCD.
	Status  uint16
	Changed uint16
	// Normalized is NVA as a raw fraction of 32768; see NormalizedValue.
	Normalized int16
	// Scaled is SVA.
	Scaled int16
	// Float is an IEEE 754 short floating point value.
	Float float32
	// Counter is BCR.
	Counter IEC104Counter
	// Event is SPE or OCI.
	Event IEC104Event
	// Elapsed is a CP16Time2a duration in milliseconds: relay duration,
	// operating time, or the delay of C_CD_NA_1.
	Elapsed uint16
	// Command is SCO, DCO, RCO or QOS.
	Command IEC104Command
	// Qualifier is the raw COI, QOI, QCC, QRP, QPM or QPA octet; the
	// methods of the same names give it its type.
	Qualifier uint8
	// Test is the FBP test pattern of C_TS_NA_1 or the TSC counter of
	// C_TS_TA_1.
	Test uint16
	// Time is the object's time tag.
	Time IEC104Time
	// File holds the file transfer elements.
	File IEC104File
	// AssociationID is AID of S_IT_TC_1 security statistics.
	AssociationID uint16
}

// NormalizedValue returns NVA as a fraction in [-1, 1).
func (o *IEC104Object) NormalizedValue() float64 {
	return float64(o.Normalized) / iec104NormalizedFS
}

// IEC104ASDU is an application service data unit.
type IEC104ASDU struct {
	TypeID IEC104TypeID
	// Sequence is SQ: one address for a run of consecutive objects.
	Sequence bool
	// NumObjects is the object count of the variable structure qualifier.
	NumObjects uint8
	Cause      IEC104Cause
	// Negative is P/N: a negative confirmation.
	Negative bool
	// Test is T: a test transmission.
	Test       bool
	Originator uint8
	CommonAddr uint16
	Objects    []IEC104Object
	// Raw holds the object octets left undecoded: all of them for a type
	// this decoder does not know, else any past the last object.
	Raw []byte
	// Security holds the body of the IEC 62351-5 types S_CH_NA_1 to
	// S_ER_NA_1, which carry no information objects.
	Security IEC104Security
}

// decode reads an ASDU from data, the octets after the APCI, with the
// field sizes of f.
func (a *IEC104ASDU) decode(data []byte, f iec104Fields) error {
	dui := iec104TypeVSQLen + f.cot + f.ca
	a.decodeDUI(data, f)
	if len(data) < dui {
		return ErrIEC104ASDUTooShort
	}
	body := data[dui:]

	// Secure authentication ASDUs have a body of their own, not objects.
	if a.TypeID.hasSecurityBody() {
		rest, err := a.Security.decode(a.TypeID, body, f)
		a.Raw = rest
		return err
	}

	// Keep the objects of an unknown type as raw octets.
	info, ok := iec104Types[a.TypeID]
	if !ok {
		a.Raw = body
		return nil
	}

	rest, err := a.decodeObjects(body, info.parts, f.ioa)
	if err != nil {
		return err
	}
	a.Raw = rest
	return nil
}

// decodeDUI reads the data unit identifier, or as many of its fields as
// data holds whole, so that a cut ASDU still tells its type:
//
//	| type | SQ, number | T, P/N, cause | originator | common address |
func (a *IEC104ASDU) decodeDUI(data []byte, f iec104Fields) {
	if len(data) > 0 {
		a.TypeID = IEC104TypeID(data[0])
	}
	if len(data) < iec104TypeVSQLen {
		return
	}
	a.Sequence = data[1]&iec104SQBit != 0
	a.NumObjects = data[1] & iec104NumMask

	if len(data) < iec104TypeVSQLen+1 {
		return
	}
	a.Cause = IEC104Cause(data[2] & iec104CauseMask)
	a.Negative = data[2]&iec104NegativeBit != 0
	a.Test = data[2]&iec104TestBit != 0

	// The originator address is the second octet of a 2-octet COT.
	addr := iec104TypeVSQLen + f.cot
	if len(data) < addr {
		return
	}
	if f.cot == iec104COTLen {
		a.Originator = data[3]
	}

	if len(data) < addr+f.ca {
		return
	}
	a.CommonAddr = uint16(iec104UintLE(data[addr : addr+f.ca]))
}

// decodeObjects reads NumObjects objects of parts each, their addresses
// ioaLen octets long, and returns the octets after them.
func (a *IEC104ASDU) decodeObjects(data []byte, parts []iec104Part, ioaLen int) ([]byte, error) {
	n := int(a.NumObjects)
	if n == 0 {
		return data, nil
	}

	// Check the smallest size the objects need before allocating for them.
	size := 0
	for _, part := range parts {
		size += iec104PartSize[part]
	}
	need := n * (ioaLen + size)
	if a.Sequence {
		need = ioaLen + n*size
	}
	if len(data) < need {
		return nil, ErrIEC104ObjectsTooLong
	}

	// Objects without elements would cost no octets after the first, so
	// three octets could claim 127 objects.
	if a.Sequence && size == 0 && n > 1 {
		return nil, ErrIEC104BadSequence
	}

	if cap(a.Objects) < n {
		a.Objects = make([]IEC104Object, 0, n)
	}

	// With SQ set only the first object carries an address; the others
	// follow it, e.g. IOA 100 then 101, 102, wrapping at the address size.
	ioaMask := uint32(1)<<(uint(ioaLen)*iec104BitsPerOctet) - 1
	var ioa uint32
	for k := 0; k < n; k++ {
		if k == 0 || !a.Sequence {
			if len(data) < ioaLen {
				return nil, ErrIEC104ObjectsTooLong
			}
			ioa = iec104UintLE(data[:ioaLen])
			data = data[ioaLen:]
		} else {
			ioa = (ioa + 1) & ioaMask
		}

		obj := IEC104Object{IOA: ioa}
		used, err := obj.decode(data, parts)
		if err != nil {
			return nil, err
		}
		obj.Raw = data[:used]
		data = data[used:]
		a.Objects = append(a.Objects, obj)
	}
	return data, nil
}

// decode fills the object from its element octets and returns how many it
// used.
func (o *IEC104Object) decode(data []byte, parts []iec104Part) (int, error) {
	off := 0
	for _, part := range parts {
		size := iec104PartSize[part]
		if len(data)-off < size {
			return 0, ErrIEC104ObjectsTooLong
		}
		b := data[off : off+size]

		// The segment's length octet says how much data follows it.
		if part == partSegment {
			end := off + size + int(b[0])
			if len(data) < end {
				return 0, ErrIEC104ObjectsTooLong
			}
			o.File.Length = uint32(b[0])
			o.File.Segment = data[off+size : end]
			off = end
			continue
		}

		o.decodePart(part, b)
		off += size
	}
	return off, nil
}

// decodePart decodes one fixed-size element from b, exactly its size.
func (o *IEC104Object) decodePart(part iec104Part, b []byte) {
	switch part {
	case partSIQ:
		o.SinglePoint = b[0]&iec104SPIMask != 0
		o.Quality = IEC104Quality(b[0] & iec104PointQuality)
	case partDIQ:
		o.DoublePoint = IEC104DoublePoint(b[0] & iec104DPIMask)
		o.Quality = IEC104Quality(b[0] & iec104PointQuality)
	case partSEP:
		o.DoublePoint = IEC104DoublePoint(b[0] & iec104DPIMask)
		o.Quality = IEC104Quality(b[0] & iec104QDPQuality)
	case partVTI:
		o.Step = iec104VTI(b[0])
		o.Transient = b[0]&iec104VTITransient != 0
	case partQDS:
		o.Quality = IEC104Quality(b[0] & iec104QDSQuality)
	case partQDP:
		o.Quality = IEC104Quality(b[0] & iec104QDPQuality)
	case partBSI:
		o.Bitstring = binary.LittleEndian.Uint32(b)
	case partSCD:
		o.Status = binary.LittleEndian.Uint16(b[0:2])
		o.Changed = binary.LittleEndian.Uint16(b[2:4])
	case partNVA:
		o.Normalized = int16(binary.LittleEndian.Uint16(b))
	case partSVA:
		o.Scaled = int16(binary.LittleEndian.Uint16(b))
	case partFloat:
		o.Float = math.Float32frombits(binary.LittleEndian.Uint32(b))
	case partBCR:
		o.Counter = iec104BCR(b)
	case partSPE, partOCI:
		o.Event = IEC104Event(b[0])
	case partCP16:
		o.Elapsed = binary.LittleEndian.Uint16(b)
	case partCP24, partCP56:
		o.Time = iec104DecodeTime(b)
	case partCP56Stop:
		o.File.Stop = iec104DecodeTime(b)
	default:
		o.decodeControl(part, b)
	}
}

// decodeControl decodes the command, qualifier and file elements.
func (o *IEC104Object) decodeControl(part iec104Part, b []byte) {
	switch part {
	case partSCO:
		o.Command = iec104Cmd(b[0], iec104SCSMask)
	case partDCO, partRCO:
		o.Command = iec104Cmd(b[0], iec104DCSMask)
	case partQOS:
		o.Command = IEC104Command{
			Qualifier: b[0] & iec104QLMask,
			Select:    b[0]&iec104SelectBit != 0,
		}
	case partQualifier:
		o.Qualifier = b[0]
	case partTest:
		o.Test = binary.LittleEndian.Uint16(b)
	case partNOF:
		o.File.Name = binary.LittleEndian.Uint16(b)
	case partLOF:
		o.File.Length = iec104UintLE(b)
	case partNOS:
		o.File.Section = b[0]
	case partFileQual:
		o.File.Qualifier = b[0]
	case partCHS:
		o.File.Checksum = b[0]
	case partAID:
		o.AssociationID = binary.LittleEndian.Uint16(b)
	}
}

// iec104Cmd splits a SCO, DCO or RCO octet; stateMask selects the state
// bits.
func iec104Cmd(b, stateMask uint8) IEC104Command {
	return IEC104Command{
		State:     b & stateMask,
		Qualifier: (b >> iec104QUShift) & iec104QUMask,
		Select:    b&iec104SelectBit != 0,
	}
}

// iec104VTI sign-extends the 7-bit VTI value, e.g. 0x7F to -1.
func iec104VTI(b uint8) int8 {
	v := b & iec104VTIValueMask
	if v&iec104VTISignBit != 0 {
		v |= iec104VTITransient
	}
	return int8(v)
}

// iec104BCR reads a binary counter reading: a little endian int32 then
// the sequence and status octet.
func iec104BCR(b []byte) IEC104Counter {
	flags := b[4]
	return IEC104Counter{
		Value:    int32(binary.LittleEndian.Uint32(b[0:4])),
		Sequence: flags & iec104BCRSeqMask,
		Carry:    flags&iec104BCRCarry != 0,
		Adjusted: flags&iec104BCRAdjusted != 0,
		Invalid:  flags&iec104BCRInvalid != 0,
	}
}

// iec104DecodeTime reads a CP24Time2a (3 octets) or CP56Time2a (7 octets)
// time tag.
func iec104DecodeTime(b []byte) IEC104Time {
	t := IEC104Time{
		Format:       IEC104TimeCP24,
		Milliseconds: binary.LittleEndian.Uint16(b[0:2]),
		Minute:       b[2] & iec104MinuteMask,
		Substituted:  b[2]&iec104SubstitutedBit != 0,
		Invalid:      b[2]&iec104InvalidBit != 0,
	}
	if len(b) < iec104PartSize[partCP56] {
		return t
	}

	t.Format = IEC104TimeCP56
	t.Hour = b[3] & iec104HourMask
	t.Summer = b[3]&iec104SummerBit != 0
	t.Day = b[4] & iec104DayMask
	t.Weekday = b[4] >> iec104WeekdayShift
	t.Month = b[5] & iec104MonthMask
	t.Year = b[6] & iec104YearMask
	return t
}

// iec104UintLE reads a little endian value of up to four octets, e.g. the
// 3-octet object address 0x01 0x02 0x03 as 0x030201.
func iec104UintLE(b []byte) uint32 {
	var v uint32
	for k := len(b) - 1; k >= 0; k-- {
		v = v<<iec104BitsPerOctet | uint32(b[k])
	}
	return v
}
