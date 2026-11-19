// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The IEEE 1588-2019 TLVs past the unicast and path trace ones (clause 16
// and Annex L), the fields of its AUTHENTICATION TLV, and the organization
// extensions of SMPTE ST 2059-2, CERN White Rabbit, ITU-T G.8275 and IANA.
// PTPTLV.Decode and PTPOrganizationExtension.Decode hand them out.

package layers

import (
	"fmt"
	"math"
)

// Value layout of the TLVs in this file.
const (
	ptpL1SyncExtFlagsLen = 1
	ptpFloat64Len        = 8

	// Records of the slave event monitoring TLVs (IEEE 1588-2019, 16.11).
	ptpRxTimingRecordLen   = 2 + ptpTimestampLen + 8 + 4 + ptpTimestampLen
	ptpRxComputedRecordLen = 2 + 8 + 8 + 4
	ptpTxEventRecordLen    = 2 + ptpTimestampLen

	// White Rabbit puts a magic number and a version where others put
	// the organizationSubType.
	ptpSubWhiteRabbit = 0xDEAD01

	ptpSubSMPTESync     = 1 // synchronization metadata
	ptpSubITUTIfaceRate = 2
	ptpSubIANANTP       = 1
)

func (r *ptpReader) f64() float64 {
	return math.Float64frombits(r.u64())
}

// PTPL1SyncFlags holds the two flag octets every L1_SYNC TLV opens with,
// the first in the high byte.
type PTPL1SyncFlags uint16

// L1_SYNC flags: what the port requires, then what it has.
const (
	PTPL1TxCoherentRequired PTPL1SyncFlags = 0x0100 // TCR
	PTPL1RxCoherentRequired PTPL1SyncFlags = 0x0200 // RCR
	PTPL1CongruentRequired  PTPL1SyncFlags = 0x0400 // CR
	// PTPL1OptParamsEnabled marks the extended format.
	PTPL1OptParamsEnabled PTPL1SyncFlags = 0x0800 // OPE
	PTPL1TxCoherent       PTPL1SyncFlags = 0x0001 // ITC
	PTPL1RxCoherent       PTPL1SyncFlags = 0x0002 // IRC
	PTPL1Congruent        PTPL1SyncFlags = 0x0004 // IC
)

// PTPL1SyncExtFlags is the third flag octet, of the extended format only.
type PTPL1SyncExtFlags uint8

// Extended L1_SYNC flags.
const (
	PTPL1TimestampsCorrectedTx PTPL1SyncExtFlags = 0x01 // TCT
	PTPL1PhaseOffsetTxValid    PTPL1SyncExtFlags = 0x02 // POV
	PTPL1FreqOffsetTxValid     PTPL1SyncExtFlags = 0x04 // FOV
)

// PTPL1Sync is the value of an L1_SYNC TLV (IEEE 1588-2019, Annex L). The
// fields after Flags are those of the extended format, which a port
// sends when PTPL1OptParamsEnabled is set; Extended tells.
type PTPL1Sync struct {
	Flags    PTPL1SyncFlags
	Extended bool

	ExtFlags               PTPL1SyncExtFlags
	PhaseOffsetTx          PTPTimeInterval
	PhaseOffsetTxTimestamp PTPTimestamp
	FreqOffsetTx           PTPTimeInterval
	FreqOffsetTxTimestamp  PTPTimestamp
}

// PTPMessageAvailability tells how a port can send one message type.
type PTPMessageAvailability uint8

// Message availability flags.
const (
	PTPAvailMulticast        PTPMessageAvailability = 0x01
	PTPAvailUnicast          PTPMessageAvailability = 0x02
	PTPAvailUnicastNegotiate PTPMessageAvailability = 0x04
	// PTPAvailUnicastNegotiateOn is unicast negotiation capable and
	// enabled.
	PTPAvailUnicastNegotiateOn PTPMessageAvailability = 0x08
)

// PTPPortAvailability is the value of a PORT_COMMUNICATION_AVAILABILITY
// TLV (IEEE 1588-2019, 16.9).
type PTPPortAvailability struct {
	Sync      PTPMessageAvailability
	DelayResp PTPMessageAvailability
}

// PTPProtocolAddress is the value of a PROTOCOL_ADDRESS TLV (IEEE
// 1588-2019, 16.9): the address the port sends from.
type PTPProtocolAddress PTPPortAddress

// PTPRxSyncTimingRecord is what a slave port saw of one Sync message.
type PTPRxSyncTimingRecord struct {
	SequenceID          uint16
	SyncOriginTimestamp PTPTimestamp
	TotalCorrection     PTPTimeInterval
	// ScaledCumulativeRateOffset is (rateRatio - 1) * 2^41.
	ScaledCumulativeRateOffset int32
	SyncEventIngressTimestamp  PTPTimestamp
}

// PTPSlaveRxSyncTiming is the value of a SLAVE_RX_SYNC_TIMING_DATA TLV
// (IEEE 1588-2019, 16.11.4).
type PTPSlaveRxSyncTiming struct {
	// SourcePort is the port the Sync messages came from.
	SourcePort PTPPortIdentity
	Records    []PTPRxSyncTimingRecord
}

// PTPComputedFlags tells which fields of the computed records hold a
// value.
type PTPComputedFlags uint8

// Computed data flags.
const (
	PTPComputedRateRatioValid PTPComputedFlags = 0x01 // scaledNeighborRateRatio
	PTPComputedPathDelayValid PTPComputedFlags = 0x02 // meanPathDelay
	PTPComputedOffsetValid    PTPComputedFlags = 0x04 // offsetFromMaster
)

// PTPRxSyncComputedRecord is what a slave port computed from one Sync
// message.
type PTPRxSyncComputedRecord struct {
	SequenceID       uint16
	OffsetFromMaster PTPTimeInterval
	MeanPathDelay    PTPTimeInterval
	// ScaledNeighborRateRatio is (rateRatio - 1) * 2^41.
	ScaledNeighborRateRatio int32
}

// PTPSlaveRxSyncComputed is the value of a SLAVE_RX_SYNC_COMPUTED_DATA
// TLV (IEEE 1588-2019, 16.11.5).
type PTPSlaveRxSyncComputed struct {
	SourcePort PTPPortIdentity
	Flags      PTPComputedFlags
	Records    []PTPRxSyncComputedRecord
}

// PTPTxEventRecord is the egress time of one event message.
type PTPTxEventRecord struct {
	SequenceID           uint16
	EventEgressTimestamp PTPTimestamp
}

// PTPSlaveTxEventTimestamps is the value of a SLAVE_TX_EVENT_TIMESTAMPS
// TLV (IEEE 1588-2019, 16.11.6). EventMessageType is read from the high
// nibble of its octet, where the unicast TLVs keep theirs.
type PTPSlaveTxEventTimestamps struct {
	SourcePort       PTPPortIdentity
	EventMessageType PTPMessageType
	Records          []PTPTxEventRecord
}

// PTPCumulativeRateRatio is the value of a CUMULATIVE_RATE_RATIO TLV
// (IEEE 1588-2019, 16.10).
type PTPCumulativeRateRatio struct {
	// Scaled is (rateRatio - 1) * 2^41; see RateRatio.
	Scaled int32
}

// RateRatio returns the grandmaster to local clock frequency ratio.
func (c PTPCumulativeRateRatio) RateRatio() float64 {
	return 1 + float64(c.Scaled)/(1<<ptpRateRatioBits)
}

// PTPCumFreqScaleFactorOffset is the value of a
// CUM_FREQ_SCALE_FACTOR_OFFSET TLV (IEEE 1588-2008, Annex L): the
// frequency ratio of the grandmaster to the sender, less one, times 2^41.
type PTPCumFreqScaleFactorOffset int32

// PTPEnhancedAccuracyMetrics is the value of an ENHANCED_ACCURACY_METRICS
// TLV (IEEE 1588-2019, 16.12). Each inaccuracy is a maximum in seconds
// and a variance in seconds squared.
type PTPEnhancedAccuracyMetrics struct {
	BCHopCount uint8
	TCHopCount uint8

	MaxGMInaccuracy             float64
	VarGMInaccuracy             float64
	MaxTransientInaccuracy      float64
	VarTransientInaccuracy      float64
	MaxDynamicInaccuracy        float64
	VarDynamicInaccuracy        float64
	MaxStaticInstanceInaccuracy float64
	VarStaticInstanceInaccuracy float64
	MaxStaticMediumInaccuracy   float64
	VarStaticMediumInaccuracy   float64
}

// PTPAuthLayout sizes the optional fields of an AUTHENTICATION TLV. The
// security association the SPP points to fixes them; none is on the
// wire. A zero length means the field is absent.
type PTPAuthLayout struct {
	DisclosedKeyLen int
	SequenceNoLen   int
	RESLen          int
}

// PTPAuthFields is what follows the key ID of an AUTHENTICATION TLV.
type PTPAuthFields struct {
	DisclosedKey []byte
	SequenceNo   []byte
	RES          []byte
	// ICV is the integrity check value: all that is left.
	ICV []byte
}

// Fields cuts Rest into the optional fields and the ICV (IEEE 1588-2019,
// 16.14.3). The zero layout gives the whole of Rest as the ICV, which is
// what a TLV with a zero SecParamIndicator holds. A layout larger than
// Rest gives ErrPTPTLVValue. The slices alias the packet data.
func (a PTPAuthentication) Fields(layout PTPAuthLayout) (PTPAuthFields, error) {
	r := &ptpReader{data: a.Rest}

	v := PTPAuthFields{
		DisclosedKey: r.take(layout.DisclosedKeyLen),
		SequenceNo:   r.take(layout.SequenceNoLen),
		RES:          r.take(layout.RESLen),
	}
	if err := r.err(); err != nil {
		return PTPAuthFields{}, err
	}

	v.ICV = r.data
	return v, nil
}

// ptpDecode2019 types the TLVs IEEE 1588-2019 added, and the one of IEEE
// 1588-2008 Annex L.
func ptpDecode2019(typ PTPTLVType, r *ptpReader) (any, error) {
	var v any

	switch typ {
	case PTPTLVL1Sync:
		v = ptpL1Sync(r)
	case PTPTLVPortAvailability:
		v = PTPPortAvailability{
			Sync:      PTPMessageAvailability(r.u8()),
			DelayResp: PTPMessageAvailability(r.u8()),
		}
	case PTPTLVProtocolAddress:
		v = PTPProtocolAddress(r.portAddress())
	case PTPTLVSlaveRxSyncTimingData:
		v = ptpRxSyncTiming(r)
	case PTPTLVSlaveRxSyncComputedData:
		v = ptpRxSyncComputed(r)
	case PTPTLVSlaveTxEventTimestamps:
		v = ptpTxEventTimestamps(r)
	case PTPTLVCumulativeRateRatio:
		v = PTPCumulativeRateRatio{Scaled: int32(r.u32())}
	case PTPTLVCumFreqScaleFactorOffset:
		v = PTPCumFreqScaleFactorOffset(r.u32())
	case PTPTLVEnhancedAccuracyMetrics:
		v = ptpAccuracyMetrics(r)
	default:
		return nil, nil
	}
	return ptpValue(v, r)
}

// ptpL1Sync reads the basic format, then the extended one when the
// flags announce it.
func ptpL1Sync(r *ptpReader) PTPL1Sync {
	v := PTPL1Sync{Flags: PTPL1SyncFlags(r.u16())}
	if v.Flags&PTPL1OptParamsEnabled == 0 {
		return v
	}

	v.Extended = true
	v.ExtFlags = PTPL1SyncExtFlags(r.u8())
	v.PhaseOffsetTx = r.interval()
	v.PhaseOffsetTxTimestamp = r.timestamp()
	v.FreqOffsetTx = r.interval()
	v.FreqOffsetTxTimestamp = r.timestamp()
	r.u8() // reserved
	return v
}

// ptpRecordCount gives how many whole records the rest of the value
// holds, so that a list is sized from the data; a shorter tail is left
// out.
func ptpRecordCount(r *ptpReader, size int) int {
	return len(r.data) / size
}

func ptpRxSyncTiming(r *ptpReader) PTPSlaveRxSyncTiming {
	v := PTPSlaveRxSyncTiming{SourcePort: r.portID()}

	count := ptpRecordCount(r, ptpRxTimingRecordLen)
	if count == 0 {
		return v
	}

	v.Records = make([]PTPRxSyncTimingRecord, count)
	for i := range v.Records {
		v.Records[i] = PTPRxSyncTimingRecord{
			SequenceID:                 r.u16(),
			SyncOriginTimestamp:        r.timestamp(),
			TotalCorrection:            r.interval(),
			ScaledCumulativeRateOffset: int32(r.u32()),
			SyncEventIngressTimestamp:  r.timestamp(),
		}
	}
	return v
}

func ptpRxSyncComputed(r *ptpReader) PTPSlaveRxSyncComputed {
	v := PTPSlaveRxSyncComputed{SourcePort: r.portID(), Flags: PTPComputedFlags(r.u8())}
	r.u8() // reserved

	count := ptpRecordCount(r, ptpRxComputedRecordLen)
	if count == 0 {
		return v
	}

	v.Records = make([]PTPRxSyncComputedRecord, count)
	for i := range v.Records {
		v.Records[i] = PTPRxSyncComputedRecord{
			SequenceID:              r.u16(),
			OffsetFromMaster:        r.interval(),
			MeanPathDelay:           r.interval(),
			ScaledNeighborRateRatio: int32(r.u32()),
		}
	}
	return v
}

func ptpTxEventTimestamps(r *ptpReader) PTPSlaveTxEventTimestamps {
	v := PTPSlaveTxEventTimestamps{
		SourcePort:       r.portID(),
		EventMessageType: PTPMessageType(r.u8() >> ptpUnicastTypeShift),
	}
	r.u8() // reserved

	count := ptpRecordCount(r, ptpTxEventRecordLen)
	if count == 0 {
		return v
	}

	v.Records = make([]PTPTxEventRecord, count)
	for i := range v.Records {
		v.Records[i] = PTPTxEventRecord{SequenceID: r.u16(), EventEgressTimestamp: r.timestamp()}
	}
	return v
}

func ptpAccuracyMetrics(r *ptpReader) PTPEnhancedAccuracyMetrics {
	v := PTPEnhancedAccuracyMetrics{BCHopCount: r.u8(), TCHopCount: r.u8()}
	r.u16() // reserved

	v.MaxGMInaccuracy = r.f64()
	v.VarGMInaccuracy = r.f64()
	v.MaxTransientInaccuracy = r.f64()
	v.VarTransientInaccuracy = r.f64()
	v.MaxDynamicInaccuracy = r.f64()
	v.VarDynamicInaccuracy = r.f64()
	v.MaxStaticInstanceInaccuracy = r.f64()
	v.VarStaticInstanceInaccuracy = r.f64()
	v.MaxStaticMediumInaccuracy = r.f64()
	v.VarStaticMediumInaccuracy = r.f64()
	return v
}

// PTPSMPTELockStatus is the gmLockingStatus of the SMPTE TLV, which the
// 2015 edition called masterLockingStatus.
type PTPSMPTELockStatus uint8

// Grandmaster locking states (SMPTE ST 2059-2:2021, Table 2).
const (
	PTPSMPTEUnavailable PTPSMPTELockStatus = 0
	PTPSMPTEInternal    PTPSMPTELockStatus = 1
	PTPSMPTEColdLocking PTPSMPTELockStatus = 2
	PTPSMPTEWarmLocking PTPSMPTELockStatus = 3
	PTPSMPTELocked      PTPSMPTELockStatus = 4
)

// String returns the state name, e.g. "Externally locked".
func (s PTPSMPTELockStatus) String() string {
	switch s {
	case PTPSMPTEUnavailable:
		return "Unavailable"
	case PTPSMPTEInternal:
		return "Internal"
	case PTPSMPTEColdLocking:
		return "Cold Locking"
	case PTPSMPTEWarmLocking:
		return "Warm Locking"
	case PTPSMPTELocked:
		return "Externally locked"
	}
	return fmt.Sprintf("Reserved(%d)", uint8(s))
}

// PTPSMPTETimeFlags is the timeAddressFlags octet of the SMPTE TLV.
type PTPSMPTETimeFlags uint8

// Time address flags.
const (
	PTPSMPTEDropFrame  PTPSMPTETimeFlags = 0x01
	PTPSMPTEColorFrame PTPSMPTETimeFlags = 0x02
)

// PTPSMPTEDaylight is the daylightSaving octet of the SMPTE TLV.
type PTPSMPTEDaylight uint8

// Daylight saving flags: in effect now, at the next discontinuity, and
// at the previous daily jam.
const (
	PTPSMPTEDaylightCurrent  PTPSMPTEDaylight = 0x01
	PTPSMPTEDaylightNext     PTPSMPTEDaylight = 0x02
	PTPSMPTEDaylightPrevious PTPSMPTEDaylight = 0x04
)

// PTPSMPTELeapChange is the bit of leapSecondJump that announces a
// change in the number of leap seconds.
const PTPSMPTELeapChange = 0x01

// PTPSMPTE is the SMPTE ST 2059-2 synchronization metadata (SM) TLV a
// grandmaster sends in a Management message (ST 2059-2:2021, Table 2).
// Offsets and jumps are in seconds; the times are seconds of the PTP
// timescale.
type PTPSMPTE struct {
	// The default system frame rate is Numerator/Denominator Hz.
	FrameRateNumerator   uint32
	FrameRateDenominator uint32
	LockingStatus        PTPSMPTELockStatus
	TimeAddressFlags     PTPSMPTETimeFlags
	// CurrentLocalOffset is local time minus PTP time.
	CurrentLocalOffset     int32
	JumpSeconds            int32
	TimeOfNextJump         uint64
	TimeOfNextJam          uint64
	TimeOfPreviousJam      uint64
	PreviousJamLocalOffset int32
	DaylightSaving         PTPSMPTEDaylight
	LeapSecondJump         uint8
}

// PTPWRMessageID is the wrMessageID of a White Rabbit TLV.
type PTPWRMessageID uint16

// White Rabbit messages (WRPTP 2.0). All but the Announce suffix travel
// in Signaling messages.
const (
	PTPWRSlavePresent   PTPWRMessageID = 0x1000
	PTPWRLock           PTPWRMessageID = 0x1001
	PTPWRLocked         PTPWRMessageID = 0x1002
	PTPWRCalibrate      PTPWRMessageID = 0x1003
	PTPWRCalibrated     PTPWRMessageID = 0x1004
	PTPWRModeOn         PTPWRMessageID = 0x1005
	PTPWRAnnounceSuffix PTPWRMessageID = 0x2000
)

// String returns the message name, e.g. "CALIBRATE".
func (m PTPWRMessageID) String() string {
	switch m {
	case PTPWRSlavePresent:
		return "SLAVE_PRESENT"
	case PTPWRLock:
		return "LOCK"
	case PTPWRLocked:
		return "LOCKED"
	case PTPWRCalibrate:
		return "CALIBRATE"
	case PTPWRCalibrated:
		return "CALIBRATED"
	case PTPWRModeOn:
		return "WR_MODE_ON"
	case PTPWRAnnounceSuffix:
		return "ANN_SUFIX"
	}
	return fmt.Sprintf("Unknown(0x%04X)", uint16(m))
}

// PTPWRFlags is the wrFlags field of a White Rabbit Announce suffix.
type PTPWRFlags uint16

// White Rabbit flags. The low two bits are the wrConfig; see Config.
const (
	PTPWRConfigMask PTPWRFlags = 0x0003
	PTPWRCalibDone  PTPWRFlags = 0x0004 // calibrated
	PTPWRModeIsOn   PTPWRFlags = 0x0008 // wrModeOn
)

// PTPWRConfig tells which White Rabbit roles a port can take.
type PTPWRConfig uint8

// White Rabbit port configurations.
const (
	PTPWRNonWR      PTPWRConfig = 0
	PTPWRMasterOnly PTPWRConfig = 1
	PTPWRSlaveOnly  PTPWRConfig = 2
	PTPWRMasterAndS PTPWRConfig = 3
)

// String returns the configuration name, e.g. "WR_M_AND_S".
func (c PTPWRConfig) String() string {
	switch c {
	case PTPWRNonWR:
		return "NON_WR"
	case PTPWRMasterOnly:
		return "WR_M_ONLY"
	case PTPWRSlaveOnly:
		return "WR_S_ONLY"
	}
	return "WR_M_AND_S"
}

// Config returns the wrConfig bits of the flags.
func (f PTPWRFlags) Config() PTPWRConfig {
	return PTPWRConfig(f & PTPWRConfigMask)
}

// PTPWhiteRabbit is a CERN White Rabbit TLV. Flags is set in an Announce
// suffix, the calibration fields in CALIBRATE and the deltas in
// CALIBRATED; the other messages carry the ID alone.
type PTPWhiteRabbit struct {
	MessageID PTPWRMessageID
	Flags     PTPWRFlags

	CalSendPattern bool
	CalRetry       uint8
	// CalPeriod is the calibration period in microseconds.
	CalPeriod uint32

	// DeltaTx and DeltaRx are the fixed delays of the port, in
	// picoseconds scaled by 2^16; see PTPWRDelayPs.
	DeltaTx uint64
	DeltaRx uint64
}

// PTPWRDelayPs converts a White Rabbit fixed delay to picoseconds.
func PTPWRDelayPs(scaled uint64) float64 {
	return float64(scaled) / (1 << ptpSubNsBits)
}

// PTPInterfaceRate is the ITU-T G.8275.1 and G.8275.2 interface rate TLV
// of a Signaling message.
type PTPInterfaceRate struct {
	// BitPeriod is the period of one bit of the interface, in attoseconds.
	BitPeriod uint64
	// The bits a frame holds before and after its timestamp point.
	BitsBeforeTimestamp uint16
	BitsAfterTimestamp  uint16
}

// PTPNTPMessage is the IANA TLV that carries an NTP message inside PTP
// (NTP over PTP). The NTP layer decodes it.
type PTPNTPMessage []byte

// ptpDecodeSMPTE reads the synchronization metadata TLV.
func ptpDecodeSMPTE(r *ptpReader) (any, error) {
	v := PTPSMPTE{
		FrameRateNumerator:     r.u32(),
		FrameRateDenominator:   r.u32(),
		LockingStatus:          PTPSMPTELockStatus(r.u8()),
		TimeAddressFlags:       PTPSMPTETimeFlags(r.u8()),
		CurrentLocalOffset:     int32(r.u32()),
		JumpSeconds:            int32(r.u32()),
		TimeOfNextJump:         r.u48(),
		TimeOfNextJam:          r.u48(),
		TimeOfPreviousJam:      r.u48(),
		PreviousJamLocalOffset: int32(r.u32()),
		DaylightSaving:         PTPSMPTEDaylight(r.u8()),
		LeapSecondJump:         r.u8(),
	}
	return ptpValue(v, r)
}

// ptpDecodeWR reads a White Rabbit TLV; the message ID tells what
// follows it.
func ptpDecodeWR(r *ptpReader) (any, error) {
	const calSendPattern = 0x01

	v := PTPWhiteRabbit{MessageID: PTPWRMessageID(r.u16())}

	switch v.MessageID {
	case PTPWRAnnounceSuffix:
		v.Flags = PTPWRFlags(r.u16())
	case PTPWRCalibrate:
		v.CalSendPattern = r.u8()&calSendPattern != 0
		v.CalRetry = r.u8()
		v.CalPeriod = r.u32()
	case PTPWRCalibrated:
		v.DeltaTx = r.u64()
		v.DeltaRx = r.u64()
	}
	return ptpValue(v, r)
}

// ptpDecodeOrgOther types the extensions of the organizations other
// than IEEE 802.1 and IEEE C37.238. All are plain
// ORGANIZATION_EXTENSION TLVs.
func ptpDecodeOrgOther(o PTPOrganizationExtension, r *ptpReader) (any, error) {
	switch {
	case o.OrganizationID == PTPOrgSMPTE && o.SubType == ptpSubSMPTESync:
		return ptpDecodeSMPTE(r)
	case o.OrganizationID == PTPOrgCERN && o.SubType == ptpSubWhiteRabbit:
		return ptpDecodeWR(r)
	case o.OrganizationID == PTPOrgITUT && o.SubType == ptpSubITUTIfaceRate:
		v := PTPInterfaceRate{
			BitPeriod:           r.u64(),
			BitsBeforeTimestamp: r.u16(),
			BitsAfterTimestamp:  r.u16(),
		}
		return ptpValue(v, r)
	case o.OrganizationID == PTPOrgIANA && o.SubType == ptpSubIANANTP:
		return PTPNTPMessage(o.Data), nil
	}
	return nil, nil
}
