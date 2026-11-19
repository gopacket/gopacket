// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// Values shared by the vectors below.
var (
	ptpTestPort = PTPPortIdentity{
		ClockIdentity: PTPClockIdentity{0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55}, PortNumber: 1,
	}
	ptpTestStamp1 = PTPTimestamp{Seconds: 0x65530001, Nanoseconds: 10}
	ptpTestStamp2 = PTPTimestamp{Seconds: 0x65530002, Nanoseconds: 20}

	// An NTPv4 client request: the first word, then eleven empty ones.
	ptpTestNTPHex = "230006ec" + strings.Repeat("00000000", 11)
	ptpTestNTP    = append([]byte{0x23, 0x00, 0x06, 0xec}, make([]byte, 44)...)
)

// ptpSigVector builds a Signaling message with one TLV.
func ptpSigVector(name string, typ PTPTLVType, valueHex string, want any) ptpTLVVector {
	return ptpOneTLVVector(name, PTPMessageSignaling, ptpBodySignaling, typ, valueHex, want)
}

// ptpOneTLVVector builds a message of the given type with one TLV.
func ptpOneTLVVector(name string, msgType PTPMessageType, body string, typ PTPTLVType, valueHex string, want any) ptpTLVVector {
	return ptpTLVVector{
		name:     name,
		ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 0, msgType, 0, body, ptpTestTLV(tb, typ, valueHex))
		},
		want: []any{want},
	}
}

// ptpExtVectors are hand-built: no public capture carries these TLVs.
// tshark 4.7.4 types L1_SYNC, AUTHENTICATION and the organization
// extensions, and agrees with want on every field it shows. It has no
// dissector for the values of PORT_COMMUNICATION_AVAILABILITY,
// PROTOCOL_ADDRESS, the three SLAVE_ monitoring TLVs,
// CUMULATIVE_RATE_RATIO, CUM_FREQ_SCALE_FACTOR_OFFSET and
// ENHANCED_ACCURACY_METRICS; those follow the standard alone.
var ptpExtVectors = []ptpTLVVector{
	ptpSigVector("L1 sync basic", PTPTLVL1Sync, "0503",
		PTPL1Sync{Flags: PTPL1TxCoherentRequired | PTPL1CongruentRequired | PTPL1TxCoherent | PTPL1RxCoherent}),
	ptpSigVector("L1 sync extended", PTPTLVL1Sync,
		// Flags, 1.5 ns at stamp 1, -0.5 ns at stamp 2, reserved.
		"0f07 05 0000000000018000 000065530001 0000000a ffffffffffff8000 000065530002 00000014 00",
		PTPL1Sync{
			Flags: PTPL1TxCoherentRequired | PTPL1RxCoherentRequired | PTPL1CongruentRequired | PTPL1OptParamsEnabled |
				PTPL1TxCoherent | PTPL1RxCoherent | PTPL1Congruent,
			Extended:      true,
			ExtFlags:      PTPL1TimestampsCorrectedTx | PTPL1FreqOffsetTxValid,
			PhaseOffsetTx: 0x18000, PhaseOffsetTxTimestamp: ptpTestStamp1,
			FreqOffsetTx: -0x8000, FreqOffsetTxTimestamp: ptpTestStamp2,
		}),
	ptpSigVector("port communication availability", PTPTLVPortAvailability, "0f05",
		PTPPortAvailability{
			Sync:      PTPAvailMulticast | PTPAvailUnicast | PTPAvailUnicastNegotiate | PTPAvailUnicastNegotiateOn,
			DelayResp: PTPAvailMulticast | PTPAvailUnicastNegotiate,
		}),
	ptpSigVector("protocol address", PTPTLVProtocolAddress, "0001 0004 0a000001",
		PTPProtocolAddress{NetworkProtocol: PTPNetworkUDPv4, Address: []byte{10, 0, 0, 1}}),
	ptpSigVector("slave rx sync timing", PTPTLVSlaveRxSyncTimingData,
		"001122fffe334455 0001"+
			"0007 000065530001 0000000a 0000000000018000 00000400 000065530002 00000014"+
			"0008 000065530002 00000014 ffffffffffff8000 fffffc00 000065530001 0000000a",
		PTPSlaveRxSyncTiming{
			SourcePort: ptpTestPort,
			Records: []PTPRxSyncTimingRecord{
				{
					SequenceID: 7, SyncOriginTimestamp: ptpTestStamp1, TotalCorrection: 0x18000,
					ScaledCumulativeRateOffset: 1024, SyncEventIngressTimestamp: ptpTestStamp2,
				},
				{
					SequenceID: 8, SyncOriginTimestamp: ptpTestStamp2, TotalCorrection: -0x8000,
					ScaledCumulativeRateOffset: -1024, SyncEventIngressTimestamp: ptpTestStamp1,
				},
			},
		}),
	ptpSigVector("slave rx sync timing, no record", PTPTLVSlaveRxSyncTimingData, "001122fffe334455 0001",
		PTPSlaveRxSyncTiming{SourcePort: ptpTestPort}),
	ptpSigVector("slave rx sync computed", PTPTLVSlaveRxSyncComputedData,
		"001122fffe334455 0001 05 00 0007 ffffffffffff8000 0000000000018000 00000100",
		PTPSlaveRxSyncComputed{
			SourcePort: ptpTestPort,
			Flags:      PTPComputedRateRatioValid | PTPComputedOffsetValid,
			Records: []PTPRxSyncComputedRecord{
				{SequenceID: 7, OffsetFromMaster: -0x8000, MeanPathDelay: 0x18000, ScaledNeighborRateRatio: 256},
			},
		}),
	ptpSigVector("slave tx event timestamps", PTPTLVSlaveTxEventTimestamps,
		"001122fffe334455 0001 10 00 0007 000065530001 0000000a 0008 000065530002 00000014",
		PTPSlaveTxEventTimestamps{
			SourcePort:       ptpTestPort,
			EventMessageType: PTPMessageDelayReq,
			Records: []PTPTxEventRecord{
				{SequenceID: 7, EventEgressTimestamp: ptpTestStamp1},
				{SequenceID: 8, EventEgressTimestamp: ptpTestStamp2},
			},
		}),
	ptpSigVector("cumulative rate ratio", PTPTLVCumulativeRateRatio, "fffffc00", PTPCumulativeRateRatio{Scaled: -1024}),
	ptpOneTLVVector("cumulative frequency scale factor offset", PTPMessageFollowUp, ptpBodyTime,
		PTPTLVCumFreqScaleFactorOffset, "00000400", PTPCumFreqScaleFactorOffset(1024)),
	ptpOneTLVVector("enhanced accuracy metrics", PTPMessageAnnounce, ptpBodyAnnounce, PTPTLVEnhancedAccuracyMetrics,
		// Hop counts, reserved, then 1, 2, 3, 4, 5, 6, 7, 8, 9 and -0.5.
		"01 02 0000 3ff0000000000000 4000000000000000 4008000000000000 4010000000000000 4014000000000000"+
			"4018000000000000 401c000000000000 4020000000000000 4022000000000000 bfe0000000000000",
		PTPEnhancedAccuracyMetrics{
			BCHopCount: 1, TCHopCount: 2,
			MaxGMInaccuracy: 1, VarGMInaccuracy: 2,
			MaxTransientInaccuracy: 3, VarTransientInaccuracy: 4,
			MaxDynamicInaccuracy: 5, VarDynamicInaccuracy: 6,
			MaxStaticInstanceInaccuracy: 7, VarStaticInstanceInaccuracy: 8,
			MaxStaticMediumInaccuracy: 9, VarStaticMediumInaccuracy: -0.5,
		}),
	ptpSigVector("authentication with optional fields", PTPTLVAuthentication2019,
		"02 07 0000 0009 a1a2a3a4 b1b2 c1c2 d1d2d3d4d5d6d7d8",
		PTPAuthentication{
			SPP: 2, SecParamIndicator: 7, KeyID: 9,
			Rest: []byte{0xa1, 0xa2, 0xa3, 0xa4, 0xb1, 0xb2, 0xc1, 0xc2, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8},
		}),
	ptpOneTLVVector("SMPTE synchronization metadata", PTPMessageManagement, ptpBodyMgmtCommand, PTPTLVOrganizationExtension,
		// 30000/1001 Hz, locked, drop frame and color frame, +3600 s, a
		// jump of 1 s, three times, -3600 s, daylight now and before,
		// a leap second change.
		"6897e8 000001 00007530 000003e9 04 03 00000e10 00000001"+
			"000065530100 000065530200 000065530300 fffff1f0 05 01",
		PTPSMPTE{
			FrameRateNumerator: 30000, FrameRateDenominator: 1001,
			LockingStatus: PTPSMPTELocked, TimeAddressFlags: PTPSMPTEDropFrame | PTPSMPTEColorFrame,
			CurrentLocalOffset: 3600, JumpSeconds: 1,
			TimeOfNextJump: 0x65530100, TimeOfNextJam: 0x65530200, TimeOfPreviousJam: 0x65530300,
			PreviousJamLocalOffset: -3600,
			DaylightSaving:         PTPSMPTEDaylightCurrent | PTPSMPTEDaylightPrevious,
			LeapSecondJump:         PTPSMPTELeapChange,
		}),
	ptpOneTLVVector("White Rabbit announce suffix", PTPMessageAnnounce, ptpBodyAnnounce, PTPTLVOrganizationExtension,
		"080030 dead01 2000 000b",
		PTPWhiteRabbit{MessageID: PTPWRAnnounceSuffix, Flags: PTPWRModeIsOn | PTPWRFlags(PTPWRMasterAndS)}),
	ptpSigVector("White Rabbit slave present", PTPTLVOrganizationExtension, "080030 dead01 1000",
		PTPWhiteRabbit{MessageID: PTPWRSlavePresent}),
	ptpSigVector("White Rabbit lock", PTPTLVOrganizationExtension, "080030 dead01 1001",
		PTPWhiteRabbit{MessageID: PTPWRLock}),
	ptpSigVector("White Rabbit locked", PTPTLVOrganizationExtension, "080030 dead01 1002",
		PTPWhiteRabbit{MessageID: PTPWRLocked}),
	ptpSigVector("White Rabbit calibrate", PTPTLVOrganizationExtension, "080030 dead01 1003 01 03 000003e8",
		PTPWhiteRabbit{MessageID: PTPWRCalibrate, CalSendPattern: true, CalRetry: 3, CalPeriod: 1000}),
	ptpSigVector("White Rabbit calibrated", PTPTLVOrganizationExtension,
		"080030 dead01 1004 0000000000100000 0000000000208000",
		PTPWhiteRabbit{MessageID: PTPWRCalibrated, DeltaTx: 0x100000, DeltaRx: 0x208000}),
	ptpSigVector("White Rabbit mode on", PTPTLVOrganizationExtension, "080030 dead01 1005",
		PTPWhiteRabbit{MessageID: PTPWRModeOn}),
	ptpSigVector("ITU-T interface rate", PTPTLVOrganizationExtension, "0019a7 000002 00000000000f4240 0040 0080",
		PTPInterfaceRate{BitPeriod: 1000000, BitsBeforeTimestamp: 64, BitsAfterTimestamp: 128}),
	ptpOneTLVVector("C37.238-2017", PTPMessageAnnounce, ptpBodyAnnounce, PTPTLVOrganizationExtension,
		"1c129d 000002 0005 00000000 000000c8 0000",
		PTPC37238{Edition: ptpC37Edition2017, GrandmasterID: 5, TotalTimeInaccuracy: 200}),
	ptpOneTLVVector("NTP over PTP", PTPMessageAnnounce, ptpBodyAnnounce, PTPTLVOrganizationExtension,
		"00005e 000001"+ptpTestNTPHex, PTPNTPMessage(ptpTestNTP)),
}

// ptpTLVVectors is every hand-built TLV vector; the truncation tests
// and the fuzz corpus run over them all.
var ptpTLVVectors = append(ptpCoreVectors[:len(ptpCoreVectors):len(ptpCoreVectors)], ptpExtVectors...)

func TestPTPAuthFields(t *testing.T) {
	rest := []byte{0xa1, 0xa2, 0xa3, 0xa4, 0xb1, 0xb2, 0xc1, 0xc2, 0xd1, 0xd2, 0xd3, 0xd4}
	auth := PTPAuthentication{SPP: 2, SecParamIndicator: 7, KeyID: 9, Rest: rest}

	for _, tc := range []struct {
		name   string
		layout PTPAuthLayout
		want   PTPAuthFields
	}{
		{"ICV alone", PTPAuthLayout{}, PTPAuthFields{ICV: rest}},
		{"all fields", PTPAuthLayout{DisclosedKeyLen: 4, SequenceNoLen: 2, RESLen: 2},
			PTPAuthFields{DisclosedKey: rest[0:4], SequenceNo: rest[4:6], RES: rest[6:8], ICV: rest[8:]}},
		{"sequence number", PTPAuthLayout{SequenceNoLen: 4},
			PTPAuthFields{SequenceNo: rest[0:4], ICV: rest[4:]}},
		{"no ICV left", PTPAuthLayout{DisclosedKeyLen: 12}, PTPAuthFields{DisclosedKey: rest}},
	} {
		got, err := auth.Fields(tc.layout)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}

		// An absent field and an empty one are the same to a caller.
		for _, pair := range [][2][]byte{
			{got.DisclosedKey, tc.want.DisclosedKey}, {got.SequenceNo, tc.want.SequenceNo},
			{got.RES, tc.want.RES}, {got.ICV, tc.want.ICV},
		} {
			if string(pair[0]) != string(pair[1]) {
				t.Errorf("%s: got %x, want %x", tc.name, pair[0], pair[1])
			}
		}
	}

	// A layout the value cannot hold, or a nonsense one, is an error.
	for _, layout := range []PTPAuthLayout{
		{DisclosedKeyLen: 13},
		{DisclosedKeyLen: 8, SequenceNoLen: 4, RESLen: 1},
		{SequenceNoLen: -1},
		{RESLen: int(^uint(0) >> 1)},
	} {
		if v, err := auth.Fields(layout); !errors.Is(err, ErrPTPTLVValue) || !reflect.DeepEqual(v, PTPAuthFields{}) {
			t.Errorf("%+v: %+v, %v", layout, v, err)
		}
	}
}

func TestPTPExtHelpers(t *testing.T) {
	// 2^-41 * 2^20 is 2^-21.
	if r := (PTPCumulativeRateRatio{Scaled: -1 << 20}).RateRatio(); r != 1-1.0/(1<<21) {
		t.Errorf("RateRatio: %v", r)
	}
	if ps := PTPWRDelayPs(0x208000); ps != 32.5 {
		t.Errorf("PTPWRDelayPs: %v", ps)
	}
	if c := (PTPWRModeIsOn | PTPWRFlags(PTPWRSlaveOnly)).Config(); c != PTPWRSlaveOnly {
		t.Errorf("Config: %v", c)
	}

	for got, want := range map[string]string{
		PTPSMPTELocked.String():         "Externally locked",
		PTPSMPTEUnavailable.String():    "Unavailable",
		PTPSMPTEInternal.String():       "Internal",
		PTPSMPTEColdLocking.String():    "Cold Locking",
		PTPSMPTEWarmLocking.String():    "Warm Locking",
		PTPSMPTELockStatus(9).String():  "Reserved(9)",
		PTPWRSlavePresent.String():      "SLAVE_PRESENT",
		PTPWRLock.String():              "LOCK",
		PTPWRLocked.String():            "LOCKED",
		PTPWRCalibrate.String():         "CALIBRATE",
		PTPWRCalibrated.String():        "CALIBRATED",
		PTPWRModeOn.String():            "WR_MODE_ON",
		PTPWRAnnounceSuffix.String():    "ANN_SUFIX",
		PTPWRMessageID(0x3000).String(): "Unknown(0x3000)",
		PTPWRNonWR.String():             "NON_WR",
		PTPWRMasterOnly.String():        "WR_M_ONLY",
		PTPWRSlaveOnly.String():         "WR_S_ONLY",
		PTPWRMasterAndS.String():        "WR_M_AND_S",
	} {
		if got != want {
			t.Errorf("String: %q, want %q", got, want)
		}
	}
}

// TestPTPExtFixedCuts checks that a fixed layout reports every cut, and
// that a list drops a short tail instead.
func TestPTPExtFixedCuts(t *testing.T) {
	for _, v := range ptpExtVectors {
		var m PTP
		if err := m.DecodeFromBytes(v.msg(t), gopacket.NilDecodeFeedback); err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}
		tlv := m.TLVs[0]

		// What a value must hold before its list or free-form tail.
		fixed := len(tlv.Value)
		switch tlv.Type {
		case PTPTLVSlaveRxSyncTimingData:
			fixed = ptpPortIdentityLen
		case PTPTLVSlaveRxSyncComputedData, PTPTLVSlaveTxEventTimestamps:
			fixed = ptpPortIdentityLen + 2
		case PTPTLVAuthentication2019:
			fixed = 6
		case PTPTLVOrganizationExtension:
			switch v.want[0].(type) {
			case PTPNTPMessage:
				fixed = ptpOrgHeaderLen
			case PTPC37238:
				fixed -= 2 // the reserved octets that end it are not read
			}
		}

		for n := 0; n < len(tlv.Value); n++ {
			got, err := ptpDecodeDeep(PTPTLV{Type: tlv.Type, Value: tlv.Value[:n:n]})
			if short := errors.Is(err, ErrPTPTLVValue); short != (n < fixed) || (short && got != nil) {
				t.Errorf("%s cut to %d of %d: %#v, %v", v.name, n, len(tlv.Value), got, err)
			}
		}
	}

	// One record and most of a second: the second is left out.
	timing := ptpExtVectors[4]
	var m PTP
	if err := m.DecodeFromBytes(timing.msg(t), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	value := m.TLVs[0].Value
	v, err := (PTPTLV{Type: PTPTLVSlaveRxSyncTimingData, Value: value[:len(value)-1]}).Decode()
	if err != nil || len(v.(PTPSlaveRxSyncTiming).Records) != 1 {
		t.Errorf("short second record: %#v, %v", v, err)
	}

	// An extension of a known organization with an unknown sub type, or
	// in a TLV type that organization does not use, is left raw.
	for _, tlv := range []PTPTLV{
		{Type: PTPTLVOrganizationExtension, Value: ptpHex(t, "6897e8 000002 0102")},
		{Type: PTPTLVOrganizationExtension, Value: ptpHex(t, "080030 dead02 1001")},
		{Type: PTPTLVOrganizationExtension, Value: ptpHex(t, "0019a7 000001 0102")},
		{Type: PTPTLVOrgExtensionPropagate, Value: ptpHex(t, "080030 dead01 1001")},
		{Type: PTPTLVOrgExtensionNoPropagate, Value: ptpHex(t, "0019a7 000002 00000000000f4240 0040 0080")},
	} {
		if v, err := ptpDecodeDeep(tlv); v != nil || err != nil {
			t.Errorf("%x: %#v, %v", tlv.Value, v, err)
		}
	}
}

// TestPTPExtAllocBound checks that a record list is sized by the value
// it came in: the largest TLV a message can carry decodes into one
// allocation of the list, plus the boxing of the result.
func TestPTPExtAllocBound(t *testing.T) {
	// The largest TLV value a Signaling message can carry.
	const maxValue = 1<<16 - 1 - ptpHeaderLen - ptpSignalingBodyLen - ptpTLVHeaderLen

	for _, tc := range []struct {
		typ     PTPTLVType
		head    int     // octets before the records
		record  int     // octets of one record on the wire
		perItem uintptr // bytes one decoded record takes
	}{
		{PTPTLVSlaveRxSyncTimingData, ptpPortIdentityLen, ptpRxTimingRecordLen, reflect.TypeOf(PTPRxSyncTimingRecord{}).Size()},
		{PTPTLVSlaveRxSyncComputedData, ptpPortIdentityLen + 2, ptpRxComputedRecordLen, reflect.TypeOf(PTPRxSyncComputedRecord{}).Size()},
		{PTPTLVSlaveTxEventTimestamps, ptpPortIdentityLen + 2, ptpTxEventRecordLen, reflect.TypeOf(PTPTxEventRecord{}).Size()},
	} {
		tlv := PTPTLV{Type: tc.typ, Value: make([]byte, maxValue)}
		records := (maxValue - tc.head) / tc.record

		// Room for the list, rounded up as the allocator does, plus the
		// boxing of the result and the reader.
		const slack = 512
		limit := float64(records*int(tc.perItem)*5/4 + slack)

		const runs = 20
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := 0; i < runs; i++ {
			tlv.Decode()
		}
		runtime.ReadMemStats(&after)

		perRun := float64(after.TotalAlloc-before.TotalAlloc) / runs
		if perRun > limit {
			t.Errorf("%v: %.0f bytes per decode, limit %.0f", tc.typ, perRun, limit)
		}

		// No decoded record outgrows a small multiple of its wire form.
		const maxPerByte = 4
		if perByte := perRun / maxValue; perByte > maxPerByte {
			t.Errorf("%v: %.1f bytes allocated per input octet", tc.typ, perByte)
		}
	}

	// The fixed layouts allocate nothing but their boxed result.
	for _, v := range ptpExtVectors {
		var m PTP
		if err := m.DecodeFromBytes(v.msg(t), gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}

		tlv := m.TLVs[0]
		const boxes = 4 // reader, first level, second level, list
		if n := testing.AllocsPerRun(50, func() { ptpDecodeDeep(tlv) }); n > boxes {
			t.Errorf("%s: %.0f allocations", v.name, n)
		}
	}
}
