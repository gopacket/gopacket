// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Precision Time Protocol version 2 (IEEE 1588-2008, and the 2019 edition
// it is compatible with) over UDP ports 319/320 or EtherType 0x88F7.
//
//	+----------------------+--------------------------+----------------+
//	| common header (34)   | body (by message type)   | TLVs ...       |
//	+----------------------+--------------------------+----------------+
//	 \_____________________ messageLength octets _____________________/
//
// TLVs are kept raw; PTPTLV.Decode in ptp_tlv.go types their values.
// Over Ethernet, majorSdoId 1 marks IEEE 802.1AS (gPTP), which reserves
// the origin timestamp of some messages; see PTP.IsGPTP.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
)

// PTP transports.
const (
	// UDPPortPTPEvent carries timestamped PTP event messages.
	UDPPortPTPEvent uint16 = 319
	// UDPPortPTPGeneral carries PTP general messages.
	UDPPortPTPGeneral uint16 = 320
	// EthernetTypePTP carries PTP directly over Ethernet (IEEE 1588 Annex F).
	EthernetTypePTP EthernetType = 0x88F7
)

// Message layout (IEEE 1588-2008, clause 13).
const (
	ptpHeaderLen       = 34
	ptpVersion2        = 2
	ptpNibbleShift     = 4
	ptpNibbleMask      = 0x0F
	ptpTimestampLen    = 10
	ptpSecondsLen      = 6
	ptpPortIdentityLen = 10
	ptpClockIDLen      = 8
	ptpTLVHeaderLen    = 4
	ptpSecondsHighLen  = 2 // the 48-bit seconds field, read as 16 + 32 bits

	// Bodies after the common header.
	ptpEventBodyLen      = ptpTimestampLen                      // Sync, Delay_Req, Follow_Up
	ptpResponseBodyLen   = ptpTimestampLen + ptpPortIdentityLen // Delay_Resp, Pdelay_*
	ptpAnnounceBodyLen   = 30
	ptpSignalingBodyLen  = ptpPortIdentityLen
	ptpManagementBodyLen = ptpPortIdentityLen + 4

	// Management TLV values open with these IDs.
	ptpManagementIDLen  = 2
	ptpManagementErrLen = 4
)

// LayerTypePTP is a PTPv2 message.
var LayerTypePTP = gopacket.RegisterLayerType(171, gopacket.LayerTypeMetadata{Name: "PTP", Decoder: gopacket.DecodeFunc(decodePTP)})

var (
	// ErrPTPTooShort is returned when the data ends before the message does.
	ErrPTPTooShort = errors.New("PTP message truncated")
	// ErrPTPVersion is returned for a message that is not PTP version 2.
	ErrPTPVersion = errors.New("PTP version not 2")
	// ErrPTPBadLength is returned when messageLength is too small for the
	// message type.
	ErrPTPBadLength = errors.New("PTP messageLength too small")
	// ErrPTPBadTLV is returned when a TLV runs past the message.
	ErrPTPBadTLV = errors.New("PTP TLV exceeds message")
)

// PTPMessageType is the messageType of the common header.
type PTPMessageType uint8

// Message types.
const (
	PTPMessageSync               PTPMessageType = 0x0
	PTPMessageDelayReq           PTPMessageType = 0x1
	PTPMessagePdelayReq          PTPMessageType = 0x2
	PTPMessagePdelayResp         PTPMessageType = 0x3
	PTPMessageFollowUp           PTPMessageType = 0x8
	PTPMessageDelayResp          PTPMessageType = 0x9
	PTPMessagePdelayRespFollowUp PTPMessageType = 0xA
	PTPMessageAnnounce           PTPMessageType = 0xB
	PTPMessageSignaling          PTPMessageType = 0xC
	PTPMessageManagement         PTPMessageType = 0xD
)

// String returns the message type as the standard spells it.
func (m PTPMessageType) String() string {
	switch m {
	case PTPMessageSync:
		return "Sync"
	case PTPMessageDelayReq:
		return "Delay_Req"
	case PTPMessagePdelayReq:
		return "Pdelay_Req"
	case PTPMessagePdelayResp:
		return "Pdelay_Resp"
	case PTPMessageFollowUp:
		return "Follow_Up"
	case PTPMessageDelayResp:
		return "Delay_Resp"
	case PTPMessagePdelayRespFollowUp:
		return "Pdelay_Resp_Follow_Up"
	case PTPMessageAnnounce:
		return "Announce"
	case PTPMessageSignaling:
		return "Signaling"
	case PTPMessageManagement:
		return "Management"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(m))
}

// PTPFlags is the flagField, its first octet in the high byte.
type PTPFlags uint16

// Flag bits.
const (
	PTPFlagAlternateMaster  PTPFlags = 0x0100
	PTPFlagTwoStep          PTPFlags = 0x0200
	PTPFlagUnicast          PTPFlags = 0x0400
	PTPFlagProfileSpecific1 PTPFlags = 0x2000
	PTPFlagProfileSpecific2 PTPFlags = 0x4000
	PTPFlagSecurity         PTPFlags = 0x8000
	PTPFlagLeap61           PTPFlags = 0x0001
	PTPFlagLeap59           PTPFlags = 0x0002
	PTPFlagUTCOffsetValid   PTPFlags = 0x0004
	PTPFlagPTPTimescale     PTPFlags = 0x0008
	PTPFlagTimeTraceable    PTPFlags = 0x0010
	PTPFlagFreqTraceable    PTPFlags = 0x0020
	PTPFlagSyncUncertain    PTPFlags = 0x0040 // IEEE 1588-2019
)

// ptpFlagNames orders the flag bits for String.
var ptpFlagNames = []struct {
	flag PTPFlags
	name string
}{
	{PTPFlagAlternateMaster, "alternateMaster"},
	{PTPFlagTwoStep, "twoStep"},
	{PTPFlagUnicast, "unicast"},
	{PTPFlagProfileSpecific1, "profileSpecific1"},
	{PTPFlagProfileSpecific2, "profileSpecific2"},
	{PTPFlagSecurity, "security"},
	{PTPFlagLeap61, "leap61"},
	{PTPFlagLeap59, "leap59"},
	{PTPFlagUTCOffsetValid, "currentUtcOffsetValid"},
	{PTPFlagPTPTimescale, "ptpTimescale"},
	{PTPFlagTimeTraceable, "timeTraceable"},
	{PTPFlagFreqTraceable, "frequencyTraceable"},
	{PTPFlagSyncUncertain, "synchronizationUncertain"},
}

// String lists the set flags, e.g. "twoStep|ptpTimescale".
func (f PTPFlags) String() string {
	if f == 0 {
		return "none"
	}

	var set []string
	for _, n := range ptpFlagNames {
		if f&n.flag != 0 {
			set = append(set, n.name)
		}
	}
	return strings.Join(set, "|")
}

// PTPControl is the controlField, kept for PTPv1 compatibility.
type PTPControl uint8

// Control field values.
const (
	PTPControlSync       PTPControl = 0
	PTPControlDelayReq   PTPControl = 1
	PTPControlFollowUp   PTPControl = 2
	PTPControlDelayResp  PTPControl = 3
	PTPControlManagement PTPControl = 4
	PTPControlOther      PTPControl = 5
)

// String returns the control field name.
func (c PTPControl) String() string {
	switch c {
	case PTPControlSync:
		return "Sync"
	case PTPControlDelayReq:
		return "Delay_Req"
	case PTPControlFollowUp:
		return "Follow_Up"
	case PTPControlDelayResp:
		return "Delay_Resp"
	case PTPControlManagement:
		return "Management"
	case PTPControlOther:
		return "Other"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(c))
}

// PTPClockIdentity is an 8-octet clockIdentity, usually an EUI-64.
type PTPClockIdentity [ptpClockIDLen]byte

// String returns the identity as colon separated hex octets.
func (c PTPClockIdentity) String() string {
	parts := make([]string, len(c))
	for i, b := range c {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// PTPPortIdentity is a portIdentity: a clock and one of its ports.
type PTPPortIdentity struct {
	ClockIdentity PTPClockIdentity
	PortNumber    uint16
}

// PTPTimestamp is a PTP Timestamp: 48-bit seconds and nanoseconds.
type PTPTimestamp struct {
	Seconds     uint64
	Nanoseconds uint32
}

// Time returns the timestamp as a time.Time in UTC. It does not apply
// currentUtcOffset: with the ptpTimescale flag set, the seconds count TAI.
func (t PTPTimestamp) Time() time.Time {
	return time.Unix(int64(t.Seconds), int64(t.Nanoseconds)).UTC()
}

// UTC returns a PTP timescale (TAI) timestamp as UTC, by taking off
// currentUtcOffset seconds, e.g. 37 since 2017. The offset comes from an
// Announce message or a time properties data set and is only good when
// their currentUtcOffsetValid flag is set. With the ptpTimescale flag
// clear the timescale is arbitrary and Time is the best reading.
func (t PTPTimestamp) UTC(currentUTCOffset int16) time.Time {
	return t.Time().Add(-time.Duration(currentUTCOffset) * time.Second)
}

// PTPClockAccuracy is the clockAccuracy of a clockQuality.
type PTPClockAccuracy uint8

// Clock accuracies: the clock is accurate to within the named bound.
const (
	PTPAccuracy1ps     PTPClockAccuracy = 0x17 // IEEE 1588-2019
	PTPAccuracy2500fs  PTPClockAccuracy = 0x18 // IEEE 1588-2019
	PTPAccuracy10ps    PTPClockAccuracy = 0x19 // IEEE 1588-2019
	PTPAccuracy25ps    PTPClockAccuracy = 0x1A // IEEE 1588-2019
	PTPAccuracy100ps   PTPClockAccuracy = 0x1B // IEEE 1588-2019
	PTPAccuracy250ps   PTPClockAccuracy = 0x1C // IEEE 1588-2019
	PTPAccuracy1ns     PTPClockAccuracy = 0x1D // IEEE 1588-2019
	PTPAccuracy2500ps  PTPClockAccuracy = 0x1E // IEEE 1588-2019
	PTPAccuracy10ns    PTPClockAccuracy = 0x1F // IEEE 1588-2019
	PTPAccuracy25ns    PTPClockAccuracy = 0x20
	PTPAccuracy100ns   PTPClockAccuracy = 0x21
	PTPAccuracy250ns   PTPClockAccuracy = 0x22
	PTPAccuracy1us     PTPClockAccuracy = 0x23
	PTPAccuracy2500ns  PTPClockAccuracy = 0x24
	PTPAccuracy10us    PTPClockAccuracy = 0x25
	PTPAccuracy25us    PTPClockAccuracy = 0x26
	PTPAccuracy100us   PTPClockAccuracy = 0x27
	PTPAccuracy250us   PTPClockAccuracy = 0x28
	PTPAccuracy1ms     PTPClockAccuracy = 0x29
	PTPAccuracy2500us  PTPClockAccuracy = 0x2A
	PTPAccuracy10ms    PTPClockAccuracy = 0x2B
	PTPAccuracy25ms    PTPClockAccuracy = 0x2C
	PTPAccuracy100ms   PTPClockAccuracy = 0x2D
	PTPAccuracy250ms   PTPClockAccuracy = 0x2E
	PTPAccuracy1s      PTPClockAccuracy = 0x2F
	PTPAccuracy10s     PTPClockAccuracy = 0x30
	PTPAccuracyOver10s PTPClockAccuracy = 0x31
	PTPAccuracyUnknown PTPClockAccuracy = 0xFE
)

// ptpAccuracyNames gives each accuracy its bound.
var ptpAccuracyNames = map[PTPClockAccuracy]string{
	PTPAccuracy1ps: "1ps", PTPAccuracy2500fs: "2.5ps", PTPAccuracy10ps: "10ps",
	PTPAccuracy25ps: "25ps", PTPAccuracy100ps: "100ps", PTPAccuracy250ps: "250ps",
	PTPAccuracy1ns: "1ns", PTPAccuracy2500ps: "2.5ns", PTPAccuracy10ns: "10ns",
	PTPAccuracy25ns: "25ns", PTPAccuracy100ns: "100ns", PTPAccuracy250ns: "250ns",
	PTPAccuracy1us: "1us", PTPAccuracy2500ns: "2.5us", PTPAccuracy10us: "10us",
	PTPAccuracy25us: "25us", PTPAccuracy100us: "100us", PTPAccuracy250us: "250us",
	PTPAccuracy1ms: "1ms", PTPAccuracy2500us: "2.5ms", PTPAccuracy10ms: "10ms",
	PTPAccuracy25ms: "25ms", PTPAccuracy100ms: "100ms", PTPAccuracy250ms: "250ms",
	PTPAccuracy1s: "1s", PTPAccuracy10s: "10s", PTPAccuracyOver10s: ">10s",
	PTPAccuracyUnknown: "unknown",
}

// String returns the accuracy bound, e.g. "100ns".
func (a PTPClockAccuracy) String() string {
	if name, ok := ptpAccuracyNames[a]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(a))
}

// PTPClockQuality is a clockQuality.
type PTPClockQuality struct {
	Class                   uint8
	Accuracy                PTPClockAccuracy
	OffsetScaledLogVariance uint16
}

// PTPTimeSource is the timeSource of an Announce message.
type PTPTimeSource uint8

// Time sources.
const (
	PTPTimeSourceAtomicClock        PTPTimeSource = 0x10
	PTPTimeSourceGNSS               PTPTimeSource = 0x20 // GPS in IEEE 1588-2008
	PTPTimeSourceTerrestrialRadio   PTPTimeSource = 0x30
	PTPTimeSourceSerialTimeCode     PTPTimeSource = 0x39 // IEEE 1588-2019
	PTPTimeSourcePTP                PTPTimeSource = 0x40
	PTPTimeSourceNTP                PTPTimeSource = 0x50
	PTPTimeSourceHandSet            PTPTimeSource = 0x60
	PTPTimeSourceOther              PTPTimeSource = 0x90
	PTPTimeSourceInternalOscillator PTPTimeSource = 0xA0
)

// String returns the time source name.
func (s PTPTimeSource) String() string {
	switch s {
	case PTPTimeSourceAtomicClock:
		return "ATOMIC_CLOCK"
	case PTPTimeSourceGNSS:
		return "GNSS"
	case PTPTimeSourceTerrestrialRadio:
		return "TERRESTRIAL_RADIO"
	case PTPTimeSourceSerialTimeCode:
		return "SERIAL_TIME_CODE"
	case PTPTimeSourcePTP:
		return "PTP"
	case PTPTimeSourceNTP:
		return "NTP"
	case PTPTimeSourceHandSet:
		return "HAND_SET"
	case PTPTimeSourceOther:
		return "OTHER"
	case PTPTimeSourceInternalOscillator:
		return "INTERNAL_OSCILLATOR"
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(s))
}

// PTPAnnounce is the body of an Announce message after its timestamp.
type PTPAnnounce struct {
	CurrentUTCOffset        int16
	GrandmasterPriority1    uint8
	GrandmasterClockQuality PTPClockQuality
	GrandmasterPriority2    uint8
	GrandmasterIdentity     PTPClockIdentity
	StepsRemoved            uint16
	TimeSource              PTPTimeSource
}

// PTPTLVType is a tlvType.
type PTPTLVType uint16

// TLV types.
const (
	PTPTLVManagement                PTPTLVType = 0x0001
	PTPTLVManagementErrorStatus     PTPTLVType = 0x0002
	PTPTLVOrganizationExtension     PTPTLVType = 0x0003
	PTPTLVRequestUnicast            PTPTLVType = 0x0004
	PTPTLVGrantUnicast              PTPTLVType = 0x0005
	PTPTLVCancelUnicast             PTPTLVType = 0x0006
	PTPTLVAckCancelUnicast          PTPTLVType = 0x0007
	PTPTLVPathTrace                 PTPTLVType = 0x0008
	PTPTLVAlternateTimeOffset       PTPTLVType = 0x0009
	PTPTLVAuthentication            PTPTLVType = 0x2000 // IEEE 1588-2008 Annex K
	PTPTLVAuthenticationChallenge   PTPTLVType = 0x2001 // IEEE 1588-2008 Annex K
	PTPTLVSecurityAssociationUpdate PTPTLVType = 0x2002 // IEEE 1588-2008 Annex K
	PTPTLVCumFreqScaleFactorOffset  PTPTLVType = 0x2003 // IEEE 1588-2008 Annex L
	PTPTLVOrgExtensionPropagate     PTPTLVType = 0x4000 // IEEE 1588-2019
	PTPTLVEnhancedAccuracyMetrics   PTPTLVType = 0x4001 // IEEE 1588-2019
	PTPTLVOrgExtensionNoPropagate   PTPTLVType = 0x8000 // IEEE 1588-2019
	PTPTLVL1Sync                    PTPTLVType = 0x8001 // IEEE 1588-2019
	PTPTLVPortAvailability          PTPTLVType = 0x8002 // IEEE 1588-2019
	PTPTLVProtocolAddress           PTPTLVType = 0x8003 // IEEE 1588-2019
	PTPTLVSlaveRxSyncTimingData     PTPTLVType = 0x8004 // IEEE 1588-2019
	PTPTLVSlaveRxSyncComputedData   PTPTLVType = 0x8005 // IEEE 1588-2019
	PTPTLVSlaveTxEventTimestamps    PTPTLVType = 0x8006 // IEEE 1588-2019
	PTPTLVCumulativeRateRatio       PTPTLVType = 0x8007 // IEEE 1588-2019
	PTPTLVPad                       PTPTLVType = 0x8008 // IEEE 1588-2019
	PTPTLVAuthentication2019        PTPTLVType = 0x8009 // IEEE 1588-2019, 16.14
)

// ptpTLVNames names the TLV types.
var ptpTLVNames = map[PTPTLVType]string{
	PTPTLVManagement:                "MANAGEMENT",
	PTPTLVManagementErrorStatus:     "MANAGEMENT_ERROR_STATUS",
	PTPTLVOrganizationExtension:     "ORGANIZATION_EXTENSION",
	PTPTLVRequestUnicast:            "REQUEST_UNICAST_TRANSMISSION",
	PTPTLVGrantUnicast:              "GRANT_UNICAST_TRANSMISSION",
	PTPTLVCancelUnicast:             "CANCEL_UNICAST_TRANSMISSION",
	PTPTLVAckCancelUnicast:          "ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION",
	PTPTLVPathTrace:                 "PATH_TRACE",
	PTPTLVAlternateTimeOffset:       "ALTERNATE_TIME_OFFSET_INDICATOR",
	PTPTLVAuthentication:            "AUTHENTICATION",
	PTPTLVAuthenticationChallenge:   "AUTHENTICATION_CHALLENGE",
	PTPTLVSecurityAssociationUpdate: "SECURITY_ASSOCIATION_UPDATE",
	PTPTLVCumFreqScaleFactorOffset:  "CUM_FREQ_SCALE_FACTOR_OFFSET",
	PTPTLVOrgExtensionPropagate:     "ORGANIZATION_EXTENSION_PROPAGATE",
	PTPTLVEnhancedAccuracyMetrics:   "ENHANCED_ACCURACY_METRICS",
	PTPTLVOrgExtensionNoPropagate:   "ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE",
	PTPTLVL1Sync:                    "L1_SYNC",
	PTPTLVPortAvailability:          "PORT_COMMUNICATION_AVAILABILITY",
	PTPTLVProtocolAddress:           "PROTOCOL_ADDRESS",
	PTPTLVSlaveRxSyncTimingData:     "SLAVE_RX_SYNC_TIMING_DATA",
	PTPTLVSlaveRxSyncComputedData:   "SLAVE_RX_SYNC_COMPUTED_DATA",
	PTPTLVSlaveTxEventTimestamps:    "SLAVE_TX_EVENT_TIMESTAMPS",
	PTPTLVCumulativeRateRatio:       "CUMULATIVE_RATE_RATIO",
	PTPTLVPad:                       "PAD",
	PTPTLVAuthentication2019:        "AUTHENTICATION",
}

// String returns the TLV type name, e.g. "PATH_TRACE".
func (t PTPTLVType) String() string {
	if name, ok := ptpTLVNames[t]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04X)", uint16(t))
}

// PTPTLV is one TLV. Value is the raw value; Decode gives its typed form.
type PTPTLV struct {
	Type   PTPTLVType
	Length uint16
	Value  []byte
}

// PTPManagementAction is the actionField of a Management message.
type PTPManagementAction uint8

// Management actions.
const (
	PTPActionGet         PTPManagementAction = 0
	PTPActionSet         PTPManagementAction = 1
	PTPActionResponse    PTPManagementAction = 2
	PTPActionCommand     PTPManagementAction = 3
	PTPActionAcknowledge PTPManagementAction = 4
)

// String returns the action name.
func (a PTPManagementAction) String() string {
	switch a {
	case PTPActionGet:
		return "GET"
	case PTPActionSet:
		return "SET"
	case PTPActionResponse:
		return "RESPONSE"
	case PTPActionCommand:
		return "COMMAND"
	case PTPActionAcknowledge:
		return "ACKNOWLEDGE"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(a))
}

// PTPManagementID is a managementId (IEEE 1588-2008, Table 40).
type PTPManagementID uint16

// Management IDs.
const (
	PTPMgmtNullManagement            PTPManagementID = 0x0000
	PTPMgmtClockDescription          PTPManagementID = 0x0001
	PTPMgmtUserDescription           PTPManagementID = 0x0002
	PTPMgmtSaveInNonVolatileStorage  PTPManagementID = 0x0003
	PTPMgmtResetNonVolatileStorage   PTPManagementID = 0x0004
	PTPMgmtInitialize                PTPManagementID = 0x0005
	PTPMgmtFaultLog                  PTPManagementID = 0x0006
	PTPMgmtFaultLogReset             PTPManagementID = 0x0007
	PTPMgmtDefaultDataSet            PTPManagementID = 0x2000
	PTPMgmtCurrentDataSet            PTPManagementID = 0x2001
	PTPMgmtParentDataSet             PTPManagementID = 0x2002
	PTPMgmtTimePropertiesDataSet     PTPManagementID = 0x2003
	PTPMgmtPortDataSet               PTPManagementID = 0x2004
	PTPMgmtPriority1                 PTPManagementID = 0x2005
	PTPMgmtPriority2                 PTPManagementID = 0x2006
	PTPMgmtDomain                    PTPManagementID = 0x2007
	PTPMgmtSlaveOnly                 PTPManagementID = 0x2008
	PTPMgmtLogAnnounceInterval       PTPManagementID = 0x2009
	PTPMgmtAnnounceReceiptTimeout    PTPManagementID = 0x200A
	PTPMgmtLogSyncInterval           PTPManagementID = 0x200B
	PTPMgmtVersionNumber             PTPManagementID = 0x200C
	PTPMgmtEnablePort                PTPManagementID = 0x200D
	PTPMgmtDisablePort               PTPManagementID = 0x200E
	PTPMgmtTime                      PTPManagementID = 0x200F
	PTPMgmtClockAccuracy             PTPManagementID = 0x2010
	PTPMgmtUTCProperties             PTPManagementID = 0x2011
	PTPMgmtTraceabilityProperties    PTPManagementID = 0x2012
	PTPMgmtTimescaleProperties       PTPManagementID = 0x2013
	PTPMgmtUnicastNegotiationEnable  PTPManagementID = 0x2014
	PTPMgmtPathTraceList             PTPManagementID = 0x2015
	PTPMgmtPathTraceEnable           PTPManagementID = 0x2016
	PTPMgmtGrandmasterClusterTable   PTPManagementID = 0x2017
	PTPMgmtUnicastMasterTable        PTPManagementID = 0x2018
	PTPMgmtUnicastMasterMaxTableSize PTPManagementID = 0x2019
	PTPMgmtAcceptableMasterTable     PTPManagementID = 0x201A
	PTPMgmtAcceptableMasterEnabled   PTPManagementID = 0x201B
	PTPMgmtAcceptableMasterMaxSize   PTPManagementID = 0x201C
	PTPMgmtAlternateMaster           PTPManagementID = 0x201D
	PTPMgmtAlternateTimeOffsetEnable PTPManagementID = 0x201E
	PTPMgmtAlternateTimeOffsetName   PTPManagementID = 0x201F
	PTPMgmtAlternateTimeOffsetMaxKey PTPManagementID = 0x2020
	PTPMgmtAlternateTimeOffsetProps  PTPManagementID = 0x2021
	PTPMgmtExternalPortConfigEnabled PTPManagementID = 0x3000 // IEEE 1588-2019
	PTPMgmtMasterOnly                PTPManagementID = 0x3001 // IEEE 1588-2019
	PTPMgmtHoldoverUpgradeEnable     PTPManagementID = 0x3002 // IEEE 1588-2019
	PTPMgmtExtPortConfigPortDataSet  PTPManagementID = 0x3003 // IEEE 1588-2019
	PTPMgmtTransparentClockDefaultDS PTPManagementID = 0x4000
	PTPMgmtTransparentClockPortDS    PTPManagementID = 0x4001
	PTPMgmtPrimaryDomain             PTPManagementID = 0x4002
	PTPMgmtDelayMechanism            PTPManagementID = 0x6000
	PTPMgmtLogMinPdelayReqInterval   PTPManagementID = 0x6001
)

// ptpManagementNames names the management IDs.
var ptpManagementNames = map[PTPManagementID]string{
	PTPMgmtNullManagement:            "NULL_MANAGEMENT",
	PTPMgmtClockDescription:          "CLOCK_DESCRIPTION",
	PTPMgmtUserDescription:           "USER_DESCRIPTION",
	PTPMgmtSaveInNonVolatileStorage:  "SAVE_IN_NON_VOLATILE_STORAGE",
	PTPMgmtResetNonVolatileStorage:   "RESET_NON_VOLATILE_STORAGE",
	PTPMgmtInitialize:                "INITIALIZE",
	PTPMgmtFaultLog:                  "FAULT_LOG",
	PTPMgmtFaultLogReset:             "FAULT_LOG_RESET",
	PTPMgmtDefaultDataSet:            "DEFAULT_DATA_SET",
	PTPMgmtCurrentDataSet:            "CURRENT_DATA_SET",
	PTPMgmtParentDataSet:             "PARENT_DATA_SET",
	PTPMgmtTimePropertiesDataSet:     "TIME_PROPERTIES_DATA_SET",
	PTPMgmtPortDataSet:               "PORT_DATA_SET",
	PTPMgmtPriority1:                 "PRIORITY1",
	PTPMgmtPriority2:                 "PRIORITY2",
	PTPMgmtDomain:                    "DOMAIN",
	PTPMgmtSlaveOnly:                 "SLAVE_ONLY",
	PTPMgmtLogAnnounceInterval:       "LOG_ANNOUNCE_INTERVAL",
	PTPMgmtAnnounceReceiptTimeout:    "ANNOUNCE_RECEIPT_TIMEOUT",
	PTPMgmtLogSyncInterval:           "LOG_SYNC_INTERVAL",
	PTPMgmtVersionNumber:             "VERSION_NUMBER",
	PTPMgmtEnablePort:                "ENABLE_PORT",
	PTPMgmtDisablePort:               "DISABLE_PORT",
	PTPMgmtTime:                      "TIME",
	PTPMgmtClockAccuracy:             "CLOCK_ACCURACY",
	PTPMgmtUTCProperties:             "UTC_PROPERTIES",
	PTPMgmtTraceabilityProperties:    "TRACEABILITY_PROPERTIES",
	PTPMgmtTimescaleProperties:       "TIMESCALE_PROPERTIES",
	PTPMgmtUnicastNegotiationEnable:  "UNICAST_NEGOTIATION_ENABLE",
	PTPMgmtPathTraceList:             "PATH_TRACE_LIST",
	PTPMgmtPathTraceEnable:           "PATH_TRACE_ENABLE",
	PTPMgmtGrandmasterClusterTable:   "GRANDMASTER_CLUSTER_TABLE",
	PTPMgmtUnicastMasterTable:        "UNICAST_MASTER_TABLE",
	PTPMgmtUnicastMasterMaxTableSize: "UNICAST_MASTER_MAX_TABLE_SIZE",
	PTPMgmtAcceptableMasterTable:     "ACCEPTABLE_MASTER_TABLE",
	PTPMgmtAcceptableMasterEnabled:   "ACCEPTABLE_MASTER_TABLE_ENABLED",
	PTPMgmtAcceptableMasterMaxSize:   "ACCEPTABLE_MASTER_MAX_TABLE_SIZE",
	PTPMgmtAlternateMaster:           "ALTERNATE_MASTER",
	PTPMgmtAlternateTimeOffsetEnable: "ALTERNATE_TIME_OFFSET_ENABLE",
	PTPMgmtAlternateTimeOffsetName:   "ALTERNATE_TIME_OFFSET_NAME",
	PTPMgmtAlternateTimeOffsetMaxKey: "ALTERNATE_TIME_OFFSET_MAX_KEY",
	PTPMgmtAlternateTimeOffsetProps:  "ALTERNATE_TIME_OFFSET_PROPERTIES",
	PTPMgmtExternalPortConfigEnabled: "EXTERNAL_PORT_CONFIGURATION_ENABLED",
	PTPMgmtMasterOnly:                "MASTER_ONLY",
	PTPMgmtHoldoverUpgradeEnable:     "HOLDOVER_UPGRADE_ENABLE",
	PTPMgmtExtPortConfigPortDataSet:  "EXT_PORT_CONFIG_PORT_DATA_SET",
	PTPMgmtTransparentClockDefaultDS: "TRANSPARENT_CLOCK_DEFAULT_DATA_SET",
	PTPMgmtTransparentClockPortDS:    "TRANSPARENT_CLOCK_PORT_DATA_SET",
	PTPMgmtPrimaryDomain:             "PRIMARY_DOMAIN",
	PTPMgmtDelayMechanism:            "DELAY_MECHANISM",
	PTPMgmtLogMinPdelayReqInterval:   "LOG_MIN_PDELAY_REQ_INTERVAL",
}

// String returns the management ID name, e.g. "CURRENT_DATA_SET".
func (m PTPManagementID) String() string {
	if name, ok := ptpManagementNames[m]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%04X)", uint16(m))
}

// PTPManagementError is a managementErrorId.
type PTPManagementError uint16

// Management error IDs.
const (
	PTPMgmtErrResponseTooBig PTPManagementError = 0x0001
	PTPMgmtErrNoSuchID       PTPManagementError = 0x0002
	PTPMgmtErrWrongLength    PTPManagementError = 0x0003
	PTPMgmtErrWrongValue     PTPManagementError = 0x0004
	PTPMgmtErrNotSetable     PTPManagementError = 0x0005
	PTPMgmtErrNotSupported   PTPManagementError = 0x0006
	PTPMgmtErrGeneralError   PTPManagementError = 0xFFFE
)

// String returns the error name, e.g. "NO_SUCH_ID".
func (e PTPManagementError) String() string {
	switch e {
	case PTPMgmtErrResponseTooBig:
		return "RESPONSE_TOO_BIG"
	case PTPMgmtErrNoSuchID:
		return "NO_SUCH_ID"
	case PTPMgmtErrWrongLength:
		return "WRONG_LENGTH"
	case PTPMgmtErrWrongValue:
		return "WRONG_VALUE"
	case PTPMgmtErrNotSetable:
		return "NOT_SETABLE"
	case PTPMgmtErrNotSupported:
		return "NOT_SUPPORTED"
	case PTPMgmtErrGeneralError:
		return "GENERAL_ERROR"
	}
	return fmt.Sprintf("Unknown(0x%04X)", uint16(e))
}

// PTPManagement is the body of a Management message, with the IDs of its
// first TLV.
type PTPManagement struct {
	StartingBoundaryHops uint8
	BoundaryHops         uint8
	Action               PTPManagementAction
	// ID is the managementId of the MANAGEMENT or MANAGEMENT_ERROR_STATUS
	// TLV.
	ID PTPManagementID
	// Error is the managementErrorId of a MANAGEMENT_ERROR_STATUS TLV.
	Error PTPManagementError
}

// PTPTransport says what carried a PTP message.
type PTPTransport uint8

// PTP transports.
const (
	// PTPTransportUnknown is the zero value: the message is read as plain
	// IEEE 1588, as it is over UDP.
	PTPTransportUnknown PTPTransport = iota
	// PTPTransportEthernet is PTP over EtherType 0x88F7, the only transport
	// of IEEE 802.1AS.
	PTPTransportEthernet
)

// ptpMajorSdoGPTP is the majorSdoId bit IEEE 802.1AS sets.
const ptpMajorSdoGPTP = 0x1

// PTP is a PTPv2 message. Body fields are set by message type; the others
// stay zero. Payload holds octets past messageLength, such as Ethernet
// padding.
type PTP struct {
	BaseLayer

	// Transport is an input: DecodeFromBytes keeps it. The EtherType
	// decoder sets PTPTransportEthernet; set it yourself when you feed
	// Ethernet payloads to DecodeFromBytes and want IEEE 802.1AS handling.
	Transport PTPTransport

	// MajorSdoID is transportSpecific in IEEE 1588-2008, e.g. 1 for
	// IEEE 802.1AS.
	MajorSdoID    uint8
	MessageType   PTPMessageType
	MinorVersion  uint8
	Version       uint8
	MessageLength uint16
	Domain        uint8
	// MinorSdoID is reserved in IEEE 1588-2008.
	MinorSdoID uint8
	Flags      PTPFlags
	// Correction is correctionField in units of 2^-16 ns; see
	// CorrectionNs.
	Correction int64
	// MessageTypeSpecific is reserved in IEEE 1588-2008.
	MessageTypeSpecific uint32
	SourcePort          PTPPortIdentity
	SequenceID          uint16
	Control             PTPControl
	LogMessageInterval  int8

	// Timestamp is the origin timestamp (Sync, Delay_Req, Pdelay_Req,
	// Announce), preciseOriginTimestamp (Follow_Up), receiveTimestamp
	// (Delay_Resp), requestReceiptTimestamp (Pdelay_Resp) or
	// responseOriginTimestamp (Pdelay_Resp_Follow_Up). IEEE 802.1AS
	// reserves these octets in Announce, Pdelay_Req and two-step Sync
	// messages, so Timestamp stays zero there; see IsGPTP.
	Timestamp PTPTimestamp
	// RequestingPort is set for Delay_Resp, Pdelay_Resp and
	// Pdelay_Resp_Follow_Up.
	RequestingPort PTPPortIdentity
	// Announce is set for Announce.
	Announce PTPAnnounce
	// TargetPort is set for Signaling and Management.
	TargetPort PTPPortIdentity
	// Management is set for Management.
	Management PTPManagement
	// TLVs follow the body of any known message type.
	TLVs []PTPTLV
}

// CorrectionNs returns the correction field in nanoseconds.
func (p *PTP) CorrectionNs() float64 {
	return float64(p.Correction) / (1 << 16)
}

// IsGPTP reports whether the message is IEEE 802.1AS (gPTP): majorSdoId
// bit 0 set on a message known to come over Ethernet. This is Wireshark's
// rule; over UDP the same bit leaves the message plain IEEE 1588.
func (p *PTP) IsGPTP() bool {
	return p.MajorSdoID&ptpMajorSdoGPTP != 0 && p.Transport == PTPTransportEthernet
}

// gptpNoTimestamp reports whether IEEE 802.1AS reserves the ten octets
// where IEEE 1588 has the origin timestamp of this message (802.1AS-2020,
// 10.6.3, 11.4.3 and 11.4.5).
func (p *PTP) gptpNoTimestamp() bool {
	if !p.IsGPTP() {
		return false
	}

	switch p.MessageType {
	case PTPMessageAnnounce, PTPMessagePdelayReq:
		return true
	case PTPMessageSync:
		return p.Flags&PTPFlagTwoStep != 0
	}
	return false
}

// LayerType returns LayerTypePTP.
func (p *PTP) LayerType() gopacket.LayerType {
	return LayerTypePTP
}

// CanDecode returns LayerTypePTP.
func (p *PTP) CanDecode() gopacket.LayerClass {
	return LayerTypePTP
}

// NextLayerType returns LayerTypeZero.
func (p *PTP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// ptpBodyLen gives the body size of each known message type.
var ptpBodyLen = map[PTPMessageType]int{
	PTPMessageSync:               ptpEventBodyLen,
	PTPMessageDelayReq:           ptpEventBodyLen,
	PTPMessageFollowUp:           ptpEventBodyLen,
	PTPMessagePdelayReq:          ptpResponseBodyLen, // timestamp, 10 reserved
	PTPMessagePdelayResp:         ptpResponseBodyLen,
	PTPMessageDelayResp:          ptpResponseBodyLen,
	PTPMessagePdelayRespFollowUp: ptpResponseBodyLen,
	PTPMessageAnnounce:           ptpAnnounceBodyLen,
	PTPMessageSignaling:          ptpSignalingBodyLen,
	PTPMessageManagement:         ptpManagementBodyLen,
}

// DecodeFromBytes decodes a PTPv2 message, up to its messageLength.
func (p *PTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < ptpHeaderLen {
		df.SetTruncated()
		return ErrPTPTooShort
	}
	if data[1]&ptpNibbleMask != ptpVersion2 {
		return ErrPTPVersion
	}

	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length < ptpHeaderLen {
		return ErrPTPBadLength
	}
	if len(data) < length {
		df.SetTruncated()
		return ErrPTPTooShort
	}

	*p = PTP{TLVs: p.TLVs[:0], Transport: p.Transport}
	p.decodeHeader(data)
	p.Contents = data[:length]
	p.Payload = data[length:]

	// Leave the body of a reserved message type undecoded.
	bodyLen, ok := ptpBodyLen[p.MessageType]
	if !ok {
		return nil
	}
	if length < ptpHeaderLen+bodyLen {
		return ErrPTPBadLength
	}

	body := data[ptpHeaderLen:length]
	p.decodeBody(body)
	return p.decodeTLVs(body[bodyLen:])
}

// decodeHeader reads the 34-octet common header.
func (p *PTP) decodeHeader(data []byte) {
	p.MajorSdoID = data[0] >> ptpNibbleShift
	p.MessageType = PTPMessageType(data[0] & ptpNibbleMask)
	p.MinorVersion = data[1] >> ptpNibbleShift
	p.Version = data[1] & ptpNibbleMask
	p.MessageLength = binary.BigEndian.Uint16(data[2:4])
	p.Domain = data[4]
	p.MinorSdoID = data[5]
	p.Flags = PTPFlags(binary.BigEndian.Uint16(data[6:8]))
	p.Correction = int64(binary.BigEndian.Uint64(data[8:16]))
	p.MessageTypeSpecific = binary.BigEndian.Uint32(data[16:20])
	p.SourcePort = ptpPortID(data[20:30])
	p.SequenceID = binary.BigEndian.Uint16(data[30:32])
	p.Control = PTPControl(data[32])
	p.LogMessageInterval = int8(data[33])
}

// decodeBody reads the fixed body of a known message type; the caller
// checked its size.
func (p *PTP) decodeBody(body []byte) {
	switch p.MessageType {
	case PTPMessageSignaling:
		p.TargetPort = ptpPortID(body)
		return
	case PTPMessageManagement:
		p.TargetPort = ptpPortID(body)
		m := body[ptpPortIdentityLen:]
		p.Management.StartingBoundaryHops = m[0]
		p.Management.BoundaryHops = m[1]
		p.Management.Action = PTPManagementAction(m[2] & ptpNibbleMask)
		return
	}

	// Every other message opens with a timestamp, or with reserved octets
	// in its place.
	if !p.gptpNoTimestamp() {
		p.Timestamp = ptpTime(body)
	}
	rest := body[ptpTimestampLen:]

	switch p.MessageType {
	case PTPMessageDelayResp, PTPMessagePdelayResp, PTPMessagePdelayRespFollowUp:
		p.RequestingPort = ptpPortID(rest)
	case PTPMessageAnnounce:
		p.Announce = ptpDecodeAnnounce(rest)
	}
}

// ptpDecodeAnnounce reads the 20 octets after an Announce timestamp.
func ptpDecodeAnnounce(b []byte) PTPAnnounce {
	return PTPAnnounce{
		CurrentUTCOffset:     int16(binary.BigEndian.Uint16(b[0:2])),
		GrandmasterPriority1: b[3], // after a reserved octet
		GrandmasterClockQuality: PTPClockQuality{
			Class:                   b[4],
			Accuracy:                PTPClockAccuracy(b[5]),
			OffsetScaledLogVariance: binary.BigEndian.Uint16(b[6:8]),
		},
		GrandmasterPriority2: b[8],
		GrandmasterIdentity:  ptpClockID(b[9:17]),
		StepsRemoved:         binary.BigEndian.Uint16(b[17:19]),
		TimeSource:           PTPTimeSource(b[19]),
	}
}

// decodeTLVs reads the TLVs that fill the rest of the message. Each pass
// consumes at least a TLV header, and a TLV may not run past the message.
// Fewer octets than a TLV header at the end are left alone, as padding.
func (p *PTP) decodeTLVs(data []byte) error {
	for len(data) >= ptpTLVHeaderLen {
		length := binary.BigEndian.Uint16(data[2:4])
		end := ptpTLVHeaderLen + int(length)
		if len(data) < end {
			return ErrPTPBadTLV
		}

		p.TLVs = append(p.TLVs, PTPTLV{
			Type:   PTPTLVType(binary.BigEndian.Uint16(data[0:2])),
			Length: length,
			Value:  data[ptpTLVHeaderLen:end],
		})
		data = data[end:]
	}

	if p.MessageType == PTPMessageManagement && len(p.TLVs) > 0 {
		p.decodeMgmtIDs(p.TLVs[0])
	}
	return nil
}

// decodeMgmtIDs reads the IDs a management TLV opens with.
func (p *PTP) decodeMgmtIDs(tlv PTPTLV) {
	v := tlv.Value
	switch {
	case tlv.Type == PTPTLVManagement && len(v) >= ptpManagementIDLen:
		p.Management.ID = PTPManagementID(binary.BigEndian.Uint16(v[0:2]))
	case tlv.Type == PTPTLVManagementErrorStatus && len(v) >= ptpManagementErrLen:
		p.Management.Error = PTPManagementError(binary.BigEndian.Uint16(v[0:2]))
		p.Management.ID = PTPManagementID(binary.BigEndian.Uint16(v[2:4]))
	}
}

// ptpTime reads a 10-octet Timestamp.
func ptpTime(b []byte) PTPTimestamp {
	high := uint64(binary.BigEndian.Uint16(b[0:ptpSecondsHighLen]))
	low := uint64(binary.BigEndian.Uint32(b[ptpSecondsHighLen:ptpSecondsLen]))
	return PTPTimestamp{
		Seconds:     high<<32 | low,
		Nanoseconds: binary.BigEndian.Uint32(b[ptpSecondsLen:ptpTimestampLen]),
	}
}

// ptpPortID reads a 10-octet portIdentity.
func ptpPortID(b []byte) PTPPortIdentity {
	return PTPPortIdentity{
		ClockIdentity: ptpClockID(b[0:ptpClockIDLen]),
		PortNumber:    binary.BigEndian.Uint16(b[ptpClockIDLen:ptpPortIdentityLen]),
	}
}

// ptpClockID copies an 8-octet clockIdentity.
func ptpClockID(b []byte) PTPClockIdentity {
	var id PTPClockIdentity
	copy(id[:], b)
	return id
}

func decodePTP(data []byte, p gopacket.PacketBuilder) error {
	return ptpDecodeOver(PTPTransportUnknown, data, p)
}

// decodePTPEthernet decodes PTP carried by EtherType 0x88F7, where
// majorSdoId 1 means IEEE 802.1AS.
func decodePTPEthernet(data []byte, p gopacket.PacketBuilder) error {
	return ptpDecodeOver(PTPTransportEthernet, data, p)
}

func ptpDecodeOver(transport PTPTransport, data []byte, p gopacket.PacketBuilder) error {
	ptp := &PTP{Transport: transport}
	if err := ptp.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(ptp)
	return nil
}

// registerPTPDecoders routes UDP ports 319 and 320 and EtherType 0x88F7 to
// the PTP decoder.
func registerPTPDecoders() {
	RegisterUDPPortLayerType(UDPPort(UDPPortPTPEvent), LayerTypePTP)
	RegisterUDPPortLayerType(UDPPort(UDPPortPTPGeneral), LayerTypePTP)
	EthernetTypeMetadata[EthernetTypePTP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePTPEthernet), Name: "PTP", LayerType: LayerTypePTP}
}
