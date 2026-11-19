// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Typed PTP TLV values (IEEE 1588-2019 clause 14 to 16, IEEE 802.1AS-2020
// clause 10 and 11, IEEE C37.238), laid out as Wireshark's packet-ptp.c
// reads them.
//
// The PTP layer keeps every TLV raw. PTPTLV.Decode types one on demand, so
// decoding a message costs nothing for callers that only want its header:
//
//	for _, tlv := range ptp.TLVs {
//		v, err := tlv.Decode()
//		switch v := v.(type) {
//		case PTPManagementTLV:      // v.Decode() types the data set
//		case PTPFollowUpInfo:       // 802.1AS rate ratio
//		case PTPPathTrace:          // clocks the Announce went through
//		}
//	}

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrPTPTLVValue is returned when a TLV value is shorter than its type
// needs.
var ErrPTPTLVValue = errors.New("PTP TLV value too short")

// TLV value layout.
const (
	ptpOUILen        = 3
	ptpOrgHeaderLen  = 2 * ptpOUILen // organizationId, organizationSubType
	ptpScaledNsLen   = 12
	ptpSubNsBits     = 16 // scaled values count 2^-16 ns
	ptpRateRatioBits = 41 // scaled rate offsets count 2^-41
	ptpPPM           = 1e6

	ptpUnicastTypeShift    = 4    // messageType sits in the high nibble
	ptpUnicastRenewal      = 0x01 // renewalInvited
	ptpUnicastMaintainReq  = 0x01
	ptpUnicastMaintainGrnt = 0x02

	ptpOrgNameWidth = 2 * ptpOUILen // hex digits of an OUI
)

// ptpReader walks a TLV value. A read past the end sets short and returns
// zeros, so decoders read straight through and check once at the end.
type ptpReader struct {
	data  []byte
	short bool
}

// take returns the next n octets, or nil when fewer are left.
func (r *ptpReader) take(n int) []byte {
	if n < 0 || len(r.data) < n {
		r.short = true
		r.data = nil
		return nil
	}

	b := r.data[:n]
	r.data = r.data[n:]
	return b
}

func (r *ptpReader) u8() uint8 {
	b := r.take(1)
	if len(b) < 1 {
		return 0
	}
	return b[0]
}

func (r *ptpReader) u16() uint16 {
	b := r.take(2)
	if len(b) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *ptpReader) u32() uint32 {
	b := r.take(4)
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// u48 reads a 48-bit count, such as the seconds of a Timestamp.
func (r *ptpReader) u48() uint64 {
	b := r.take(ptpSecondsLen)
	if len(b) < ptpSecondsLen {
		return 0
	}

	high := uint64(binary.BigEndian.Uint16(b[0:ptpSecondsHighLen]))
	return high<<32 | uint64(binary.BigEndian.Uint32(b[ptpSecondsHighLen:]))
}

func (r *ptpReader) u64() uint64 {
	b := r.take(8)
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// text reads a PTPText: a length octet, then that many characters.
func (r *ptpReader) text() string {
	return string(r.take(int(r.u8())))
}

func (r *ptpReader) clockID() PTPClockIdentity {
	var id PTPClockIdentity
	copy(id[:], r.take(ptpClockIDLen))
	return id
}

func (r *ptpReader) portID() PTPPortIdentity {
	return PTPPortIdentity{ClockIdentity: r.clockID(), PortNumber: r.u16()}
}

func (r *ptpReader) timestamp() PTPTimestamp {
	return PTPTimestamp{Seconds: r.u48(), Nanoseconds: r.u32()}
}

func (r *ptpReader) interval() PTPTimeInterval {
	return PTPTimeInterval(r.u64())
}

func (r *ptpReader) scaledNs() PTPScaledNs {
	var s PTPScaledNs
	copy(s[:], r.take(ptpScaledNsLen))
	return s
}

func (r *ptpReader) quality() PTPClockQuality {
	return PTPClockQuality{
		Class:                   r.u8(),
		Accuracy:                PTPClockAccuracy(r.u8()),
		OffsetScaledLogVariance: r.u16(),
	}
}

// err reports whether any read ran past the value.
func (r *ptpReader) err() error {
	if r.short {
		return ErrPTPTLVValue
	}
	return nil
}

// PTPTimeInterval is a TimeInterval: nanoseconds scaled by 2^16.
type PTPTimeInterval int64

// Ns returns the interval in nanoseconds.
func (i PTPTimeInterval) Ns() float64 {
	return float64(i) / (1 << ptpSubNsBits)
}

// PTPScaledNs is a 96-bit IEEE 802.1AS ScaledNs or UScaledNs, big endian:
// nanoseconds scaled by 2^16.
type PTPScaledNs [ptpScaledNsLen]byte

// Ns returns the value in nanoseconds, read as signed. A UScaledNs above
// 2^95 would come out negative; none fits a real link delay or timestamp.
func (s PTPScaledNs) Ns() float64 {
	const two64 = 1 << 64

	high := int16(binary.BigEndian.Uint16(s[0:2]))
	low := binary.BigEndian.Uint64(s[2:10])
	frac := float64(binary.BigEndian.Uint16(s[10:12])) / (1 << ptpSubNsBits)

	// Nearly every value fits its low 64 bits, high being only the sign;
	// convert those in one step to keep their precision.
	if int64(low)>>63 == int64(high) {
		return float64(int64(low)) + frac
	}
	return float64(high)*two64 + float64(low) + frac
}

// PTPOrganizationID is the 24-bit OUI or CID of an organization extension.
type PTPOrganizationID uint32

// Organizations with typed extensions, and the others Wireshark knows.
const (
	PTPOrgIEEE8021 PTPOrganizationID = 0x0080C2
	PTPOrgIEEEC37  PTPOrganizationID = 0x1C129D // IEEE C37.238 power profile
	PTPOrgSMPTE    PTPOrganizationID = 0x6897E8
	PTPOrgCERN     PTPOrganizationID = 0x080030 // White Rabbit
	PTPOrgITUT     PTPOrganizationID = 0x0019A7
	PTPOrgIANA     PTPOrganizationID = 0x00005E
)

// String returns the organization name, or its OUI in hex.
func (o PTPOrganizationID) String() string {
	switch o {
	case PTPOrgIEEE8021:
		return "IEEE 802.1"
	case PTPOrgIEEEC37:
		return "IEEE C37.238"
	case PTPOrgSMPTE:
		return "SMPTE"
	case PTPOrgCERN:
		return "CERN"
	case PTPOrgITUT:
		return "ITU-T"
	case PTPOrgIANA:
		return "IANA"
	}
	return fmt.Sprintf("0x%0*X", ptpOrgNameWidth, uint32(o))
}

// Organization sub types with a typed form.
const (
	// IEEE 802.1AS, in ORGANIZATION_EXTENSION.
	ptpSub8021FollowUpInfo    = 1
	ptpSub8021IntervalRequest = 2
	ptpSub8021CSN             = 3
	ptpSub8021DriftTracking   = 6

	// IEEE 802.1AS, in ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE.
	ptpSub8021GPTPCapable         = 4
	ptpSub8021GPTPCapableInterval = 5

	// IEEE C37.238.
	ptpSubC37v2011 = 1
	ptpSubC37v2017 = 2
)

// PTPManagementTLV is the value of a MANAGEMENT TLV. Data is empty in a
// GET; Decode types it.
type PTPManagementTLV struct {
	ID   PTPManagementID
	Data []byte
}

// PTPManagementErrorStatus is the value of a MANAGEMENT_ERROR_STATUS TLV.
type PTPManagementErrorStatus struct {
	Error PTPManagementError
	// ID is the managementId the error is about.
	ID          PTPManagementID
	DisplayData string
}

// PTPOrganizationExtension is the value of an ORGANIZATION_EXTENSION TLV,
// in any of its three propagation forms. Decode types Data for the
// organizations this package knows.
type PTPOrganizationExtension struct {
	// Type is the tlvType: sub types are numbered apart for
	// ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE.
	Type           PTPTLVType
	OrganizationID PTPOrganizationID
	SubType        uint32
	Data           []byte
}

// PTPFollowUpInfo is the IEEE 802.1AS Follow_Up information TLV
// (802.1AS-2020, 11.4.4.3).
type PTPFollowUpInfo struct {
	// CumulativeScaledRateOffset is (rateRatio - 1) * 2^41; see RateRatio.
	CumulativeScaledRateOffset int32
	GMTimeBaseIndicator        uint16
	LastGMPhaseChange          PTPScaledNs
	// ScaledLastGMFreqChange is the fractional frequency change * 2^41.
	ScaledLastGMFreqChange int32
}

// RateRatio returns the grandmaster to local clock frequency ratio.
func (f PTPFollowUpInfo) RateRatio() float64 {
	return 1 + float64(f.CumulativeScaledRateOffset)/(1<<ptpRateRatioBits)
}

// PTPIntervalFlags is the flags octet of the IEEE 802.1AS message interval
// request TLV.
type PTPIntervalFlags uint8

// Message interval request flags. The masks are Wireshark's.
const (
	PTPIntervalComputeRateRatio PTPIntervalFlags = 0x02
	PTPIntervalComputeLinkDelay PTPIntervalFlags = 0x04
	PTPIntervalOneStepReceive   PTPIntervalFlags = 0x08
)

// PTPIntervalRequest is the IEEE 802.1AS message interval request TLV
// (802.1AS-2020, 10.6.4.3). The intervals are log2 seconds; 127 stops
// sending and -128 asks for no change.
type PTPIntervalRequest struct {
	LinkDelayInterval int8
	TimeSyncInterval  int8
	AnnounceInterval  int8
	Flags             PTPIntervalFlags
}

// PTPCSN is the IEEE 802.1AS CSN TLV for coordinated shared networks
// (802.1AS-2020, 16.6.4.3).
type PTPCSN struct {
	UpstreamTxTime PTPScaledNs
	// NeighborRateRatio is (rateRatio - 1) * 2^41.
	NeighborRateRatio int32
	MeanLinkDelay     PTPScaledNs
	DelayAsymmetry    PTPScaledNs
	Domain            uint8
}

// PTPDriftTracking is the IEEE 802.1AS drift tracking TLV of a Follow_Up
// (802.1ASdm).
type PTPDriftTracking struct {
	SyncEgressSeconds uint64
	// SyncEgressNs and SyncEgressSubNs are nanoseconds and 2^-16 ns.
	SyncEgressNs            uint32
	SyncEgressSubNs         uint16
	SyncGrandmasterIdentity PTPClockIdentity
	SyncStepsRemoved        uint16
	// RateRatioDrift is the drift * 2^41 per second; see DriftPPM.
	RateRatioDrift int32
}

// DriftPPM returns the rate ratio drift in parts per million per second.
func (d PTPDriftTracking) DriftPPM() float64 {
	return float64(d.RateRatioDrift) / (1 << ptpRateRatioBits) * ptpPPM
}

// PTPGPTPCapable is the IEEE 802.1AS gPTP-capable TLV (802.1AS-2020,
// 10.6.4.4).
type PTPGPTPCapable struct {
	LogMessageInterval int8
	Flags              uint8
}

// PTPGPTPCapableInterval is the IEEE 802.1AS gPTP-capable message
// interval request TLV (802.1AS-2020, 10.6.4.5).
type PTPGPTPCapableInterval struct {
	LogMessageInterval int8
}

// PTPC37238 is the IEEE C37.238 power profile TLV. The 2011 edition
// carries GrandmasterTimeInaccuracy and NetworkTimeInaccuracy, the 2017
// edition TotalTimeInaccuracy; all are in nanoseconds.
type PTPC37238 struct {
	// Edition is 2011 or 2017.
	Edition                   uint16
	GrandmasterID             uint16
	GrandmasterTimeInaccuracy uint32
	NetworkTimeInaccuracy     uint32
	TotalTimeInaccuracy       uint32
}

// IEEE C37.238 editions.
const (
	ptpC37Edition2011 = 2011
	ptpC37Edition2017 = 2017
)

// PTPUnicastRequest is the value of a REQUEST_UNICAST_TRANSMISSION TLV.
type PTPUnicastRequest struct {
	MessageType PTPMessageType
	// LogInterMessagePeriod is log2 of the seconds between messages.
	LogInterMessagePeriod int8
	// Duration is durationField, in seconds.
	Duration uint32
}

// PTPUnicastGrant is the value of a GRANT_UNICAST_TRANSMISSION TLV. A
// zero Duration denies the request.
type PTPUnicastGrant struct {
	MessageType           PTPMessageType
	LogInterMessagePeriod int8
	Duration              uint32
	RenewalInvited        bool
}

// PTPUnicastCancel is the value of a CANCEL_UNICAST_TRANSMISSION or
// ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION TLV; Acknowledge tells them
// apart.
type PTPUnicastCancel struct {
	Acknowledge     bool
	MessageType     PTPMessageType
	MaintainRequest bool // IEEE 1588-2019
	MaintainGrant   bool // IEEE 1588-2019
}

// PTPPathTrace is the value of a PATH_TRACE TLV: the clocks an Announce
// message went through.
type PTPPathTrace []PTPClockIdentity

// PTPAlternateTimeOffset is the value of an
// ALTERNATE_TIME_OFFSET_INDICATOR TLV.
type PTPAlternateTimeOffset struct {
	KeyField uint8
	// CurrentOffset is the alternate time minus the node time, in seconds.
	CurrentOffset int32
	JumpSeconds   int32
	// TimeOfNextJump is in seconds of the node time.
	TimeOfNextJump uint64
	DisplayName    string
}

// PTPAuthentication is an IEEE 1588-2019 AUTHENTICATION TLV (16.14).
// Rest holds what follows the key ID: the optional disclosed key,
// sequence number and reserved fields, then the ICV. Their sizes come
// from the security association, which is not on the wire; Fields cuts
// Rest with sizes the caller knows.
type PTPAuthentication struct {
	// SPP is the security parameter pointer.
	SPP uint8
	// SecParamIndicator flags which optional fields are present.
	SecParamIndicator uint8
	KeyID             uint32
	Rest              []byte
}

// PTPPad is the value of a PAD TLV: filler to ignore.
type PTPPad []byte

// Decode returns the typed value of the TLV:
//
//	MANAGEMENT                               PTPManagementTLV
//	MANAGEMENT_ERROR_STATUS                  PTPManagementErrorStatus
//	ORGANIZATION_EXTENSION, all three forms  PTPOrganizationExtension
//	REQUEST_UNICAST_TRANSMISSION             PTPUnicastRequest
//	GRANT_UNICAST_TRANSMISSION               PTPUnicastGrant
//	CANCEL_ and ACKNOWLEDGE_CANCEL_UNICAST   PTPUnicastCancel
//	PATH_TRACE                               PTPPathTrace
//	ALTERNATE_TIME_OFFSET_INDICATOR          PTPAlternateTimeOffset
//	AUTHENTICATION (0x8009)                  PTPAuthentication
//	PAD                                      PTPPad
//	L1_SYNC                                  PTPL1Sync
//	PORT_COMMUNICATION_AVAILABILITY          PTPPortAvailability
//	PROTOCOL_ADDRESS                         PTPProtocolAddress
//	SLAVE_RX_SYNC_TIMING_DATA                PTPSlaveRxSyncTiming
//	SLAVE_RX_SYNC_COMPUTED_DATA              PTPSlaveRxSyncComputed
//	SLAVE_TX_EVENT_TIMESTAMPS                PTPSlaveTxEventTimestamps
//	CUMULATIVE_RATE_RATIO                    PTPCumulativeRateRatio
//	ENHANCED_ACCURACY_METRICS                PTPEnhancedAccuracyMetrics
//	CUM_FREQ_SCALE_FACTOR_OFFSET             PTPCumFreqScaleFactorOffset
//
// Any other type gives nil and no error. A value too short for its type
// gives ErrPTPTLVValue. Slices alias the packet data.
func (t PTPTLV) Decode() (any, error) {
	r := &ptpReader{data: t.Value}

	switch t.Type {
	case PTPTLVManagement:
		v := PTPManagementTLV{ID: PTPManagementID(r.u16())}
		v.Data = r.data
		return ptpValue(v, r)
	case PTPTLVManagementErrorStatus:
		return ptpDecodeMgmtError(r)
	case PTPTLVOrganizationExtension, PTPTLVOrgExtensionPropagate, PTPTLVOrgExtensionNoPropagate:
		return ptpDecodeOrgExt(t.Type, r)
	case PTPTLVRequestUnicast:
		v := PTPUnicastRequest{
			MessageType:           PTPMessageType(r.u8() >> ptpUnicastTypeShift),
			LogInterMessagePeriod: int8(r.u8()),
			Duration:              r.u32(),
		}
		return ptpValue(v, r)
	case PTPTLVGrantUnicast:
		v := PTPUnicastGrant{
			MessageType:           PTPMessageType(r.u8() >> ptpUnicastTypeShift),
			LogInterMessagePeriod: int8(r.u8()),
			Duration:              r.u32(),
		}
		r.u8() // reserved
		v.RenewalInvited = r.u8()&ptpUnicastRenewal != 0
		return ptpValue(v, r)
	case PTPTLVCancelUnicast, PTPTLVAckCancelUnicast:
		b := r.u8()
		v := PTPUnicastCancel{
			Acknowledge:     t.Type == PTPTLVAckCancelUnicast,
			MessageType:     PTPMessageType(b >> ptpUnicastTypeShift),
			MaintainRequest: b&ptpUnicastMaintainReq != 0,
			MaintainGrant:   b&ptpUnicastMaintainGrnt != 0,
		}
		r.u8() // reserved
		return ptpValue(v, r)
	case PTPTLVPathTrace:
		return PTPPathTrace(ptpClockIDs(t.Value)), nil
	case PTPTLVAlternateTimeOffset:
		v := PTPAlternateTimeOffset{
			KeyField:       r.u8(),
			CurrentOffset:  int32(r.u32()),
			JumpSeconds:    int32(r.u32()),
			TimeOfNextJump: r.u48(),
			DisplayName:    r.text(),
		}
		return ptpValue(v, r)
	case PTPTLVAuthentication2019:
		v := PTPAuthentication{SPP: r.u8(), SecParamIndicator: r.u8(), KeyID: r.u32()}
		v.Rest = r.data
		return ptpValue(v, r)
	case PTPTLVPad:
		return PTPPad(t.Value), nil
	}
	return ptpDecode2019(t.Type, r)
}

// ptpValue returns v, or the reader's error when v was read past the end.
func ptpValue(v any, r *ptpReader) (any, error) {
	if err := r.err(); err != nil {
		return nil, err
	}
	return v, nil
}

// ptpClockIDs reads the whole clock identities in data; a shorter tail is
// left out. The list is sized from the data, not from a count on the wire.
func ptpClockIDs(data []byte) []PTPClockIdentity {
	ids := make([]PTPClockIdentity, len(data)/ptpClockIDLen)
	for i := range ids {
		copy(ids[i][:], data[i*ptpClockIDLen:])
	}
	return ids
}

// ptpDecodeMgmtError reads a MANAGEMENT_ERROR_STATUS value: the two IDs,
// four reserved octets, then an optional text.
func ptpDecodeMgmtError(r *ptpReader) (any, error) {
	v := PTPManagementErrorStatus{
		Error: PTPManagementError(r.u16()),
		ID:    PTPManagementID(r.u16()),
	}
	r.u32() // reserved

	if err := r.err(); err != nil {
		return nil, err
	}
	if len(r.data) == 0 {
		return v, nil
	}

	v.DisplayData = r.text()
	return ptpValue(v, r)
}

// ptpDecodeOrgExt reads the organization ID and sub type that open every
// organization extension.
func ptpDecodeOrgExt(typ PTPTLVType, r *ptpReader) (any, error) {
	h := r.take(ptpOrgHeaderLen)
	if err := r.err(); err != nil {
		return nil, err
	}

	return PTPOrganizationExtension{
		Type:           typ,
		OrganizationID: PTPOrganizationID(ptpUint24(h)),
		SubType:        ptpUint24(h[ptpOUILen:]),
		Data:           r.data,
	}, nil
}

// ptpUint24 reads a 24-bit big endian number.
func ptpUint24(b []byte) uint32 {
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

// Decode returns the typed form of the extension:
//
//	IEEE 802.1, ORGANIZATION_EXTENSION, sub type 1   PTPFollowUpInfo
//	                                    sub type 2   PTPIntervalRequest
//	                                    sub type 3   PTPCSN
//	                                    sub type 6   PTPDriftTracking
//	IEEE 802.1, DO_NOT_PROPAGATE, sub type 4         PTPGPTPCapable
//	                              sub type 5         PTPGPTPCapableInterval
//	IEEE C37.238, ORGANIZATION_EXTENSION, 1 and 2    PTPC37238
//	SMPTE, ORGANIZATION_EXTENSION, sub type 1        PTPSMPTE
//	CERN, ORGANIZATION_EXTENSION, sub type 0xDEAD01  PTPWhiteRabbit
//	ITU-T, ORGANIZATION_EXTENSION, sub type 2        PTPInterfaceRate
//	IANA, ORGANIZATION_EXTENSION, sub type 1         PTPNTPMessage
//
// Anything else gives nil and no error; a short value gives
// ErrPTPTLVValue. Like Wireshark, it reads ORGANIZATION_EXTENSION_PROPAGATE
// no further than the organization and sub type.
func (o PTPOrganizationExtension) Decode() (any, error) {
	r := &ptpReader{data: o.Data}

	switch {
	case o.Type == PTPTLVOrganizationExtension && o.OrganizationID == PTPOrgIEEE8021:
		return ptpDecode8021(o.SubType, r)
	case o.Type == PTPTLVOrgExtensionNoPropagate && o.OrganizationID == PTPOrgIEEE8021:
		return ptpDecode8021Local(o.SubType, r)
	case o.Type == PTPTLVOrganizationExtension && o.OrganizationID == PTPOrgIEEEC37:
		return ptpDecodeC37(o.SubType, r)
	case o.Type == PTPTLVOrganizationExtension:
		return ptpDecodeOrgOther(o, r)
	}
	return nil, nil
}

// ptpDecode8021 reads the IEEE 802.1AS TLVs that propagate.
func ptpDecode8021(subType uint32, r *ptpReader) (any, error) {
	switch subType {
	case ptpSub8021FollowUpInfo:
		v := PTPFollowUpInfo{
			CumulativeScaledRateOffset: int32(r.u32()),
			GMTimeBaseIndicator:        r.u16(),
			LastGMPhaseChange:          r.scaledNs(),
			ScaledLastGMFreqChange:     int32(r.u32()),
		}
		return ptpValue(v, r)
	case ptpSub8021IntervalRequest:
		v := PTPIntervalRequest{
			LinkDelayInterval: int8(r.u8()),
			TimeSyncInterval:  int8(r.u8()),
			AnnounceInterval:  int8(r.u8()),
			Flags:             PTPIntervalFlags(r.u8()),
		}
		return ptpValue(v, r)
	case ptpSub8021CSN:
		v := PTPCSN{
			UpstreamTxTime:    r.scaledNs(),
			NeighborRateRatio: int32(r.u32()),
			MeanLinkDelay:     r.scaledNs(),
			DelayAsymmetry:    r.scaledNs(),
			Domain:            r.u8(),
		}
		return ptpValue(v, r)
	case ptpSub8021DriftTracking:
		v := PTPDriftTracking{
			SyncEgressSeconds:       r.u48(),
			SyncEgressNs:            r.u32(),
			SyncEgressSubNs:         r.u16(),
			SyncGrandmasterIdentity: r.clockID(),
			SyncStepsRemoved:        r.u16(),
			RateRatioDrift:          int32(r.u32()),
		}
		return ptpValue(v, r)
	}
	return nil, nil
}

// ptpDecode8021Local reads the IEEE 802.1AS TLVs that do not propagate.
func ptpDecode8021Local(subType uint32, r *ptpReader) (any, error) {
	switch subType {
	case ptpSub8021GPTPCapable:
		v := PTPGPTPCapable{LogMessageInterval: int8(r.u8()), Flags: r.u8()}
		return ptpValue(v, r)
	case ptpSub8021GPTPCapableInterval:
		v := PTPGPTPCapableInterval{LogMessageInterval: int8(r.u8())}
		return ptpValue(v, r)
	}
	return nil, nil
}

// ptpDecodeC37 reads the IEEE C37.238 TLV of either edition.
func ptpDecodeC37(subType uint32, r *ptpReader) (any, error) {
	switch subType {
	case ptpSubC37v2011:
		v := PTPC37238{
			Edition:                   ptpC37Edition2011,
			GrandmasterID:             r.u16(),
			GrandmasterTimeInaccuracy: r.u32(),
			NetworkTimeInaccuracy:     r.u32(),
		}
		return ptpValue(v, r)
	case ptpSubC37v2017:
		v := PTPC37238{Edition: ptpC37Edition2017, GrandmasterID: r.u16()}
		r.u32() // reserved
		v.TotalTimeInaccuracy = r.u32()
		return ptpValue(v, r)
	}
	return nil, nil
}
