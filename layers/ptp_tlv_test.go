// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// ptpHex decodes a hex string that may hold spaces.
func ptpHex(tb testing.TB, s string) []byte {
	tb.Helper()

	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		tb.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// ptpTestTLV builds one TLV from its type and hex value.
func ptpTestTLV(tb testing.TB, typ PTPTLVType, valueHex string) []byte {
	tb.Helper()

	value := ptpHex(tb, valueHex)
	tlv := binary.BigEndian.AppendUint16(nil, uint16(typ))
	tlv = binary.BigEndian.AppendUint16(tlv, uint16(len(value)))
	return append(tlv, value...)
}

// ptpTestMsg builds a PTPv2 message: the common header, the hex body of
// the message type, then the TLVs.
func ptpTestMsg(tb testing.TB, majorSdo uint8, typ PTPMessageType, flags PTPFlags, bodyHex string, tlvs ...[]byte) []byte {
	tb.Helper()

	msg := make([]byte, ptpHeaderLen)
	msg[0] = majorSdo<<ptpNibbleShift | uint8(typ)
	msg[1] = ptpVersion2
	binary.BigEndian.PutUint16(msg[6:8], uint16(flags))
	copy(msg[20:30], ptpHex(tb, "0011 22ff fe33 4455 0001")) // sourcePortIdentity
	binary.BigEndian.PutUint16(msg[30:32], 7)                // sequenceId

	msg = append(msg, ptpHex(tb, bodyHex)...)
	for _, tlv := range tlvs {
		msg = append(msg, tlv...)
	}
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(msg)))
	return msg
}

// Message bodies for the vectors.
const (
	// Management: targetPortIdentity, hops, action, reserved.
	ptpBodyMgmtGet      = "ffffffffffffffff ffff 01 01 00 00"
	ptpBodyMgmtSet      = "ffffffffffffffff ffff 01 01 01 00"
	ptpBodyMgmtResponse = "ffffffffffffffff ffff 01 01 02 00"
	ptpBodyMgmtCommand  = "ffffffffffffffff ffff 01 01 03 00"
	// Signaling: targetPortIdentity.
	ptpBodySignaling = "0011 22ff fe66 7788 0002"
	// Sync, Follow_Up: a timestamp.
	ptpBodyTime = "0000 6553 f100 075b cd15"
	// Pdelay_Req: a timestamp and ten reserved octets.
	ptpBodyPdelayReq = ptpBodyTime + "0000 0000 0000 0000 0000"
	// Announce: timestamp, currentUtcOffset 37, priorities 128, clock
	// quality 6/0x21/0x4e5d, grandmaster identity, stepsRemoved 1, GNSS.
	ptpBodyAnnounce = ptpBodyTime + "0025 00 80 06 21 4e5d 80 0011 22ff fe33 4455 0001 20"
)

// ptpTLVVector is a hand-built message and what its TLVs must decode to.
// tshark 4.7.4 dissects every vector without a malformed-packet note, and
// its field values match want; see the cross-check notes in the commit.
type ptpTLVVector struct {
	name     string
	ethernet bool // carried by EtherType 0x88F7, not UDP
	msg      func(tb testing.TB) []byte
	// want lists, per TLV, the typed value; a management or organization
	// TLV lists the value its own Decode gives.
	want []any
}

// ptpMgmtVector builds a management message with one MANAGEMENT TLV.
func ptpMgmtVector(name string, body string, id PTPManagementID, dataHex string, want any) ptpTLVVector {
	return ptpTLVVector{
		name:     name,
		ethernet: true,
		msg: func(tb testing.TB) []byte {
			value := fmt.Sprintf("%04x %s", uint16(id), dataHex)
			return ptpTestMsg(tb, 0, PTPMessageManagement, 0, body, ptpTestTLV(tb, PTPTLVManagement, value))
		},
		want: []any{want},
	}
}

var ptpCoreVectors = []ptpTLVVector{
	ptpMgmtVector("null get", ptpBodyMgmtGet, PTPMgmtNullManagement, "", nil),
	ptpMgmtVector("clock description", ptpBodyMgmtResponse, PTPMgmtClockDescription,
		// clockType OC+BC, "IEEE 802.3", MAC, UDP/IPv4 10.0.0.9, OUI,
		// reserved, "pump;7;A1", "1.2;;", "plc-7", profile, pad.
		"c000 0a 49454545203830322e33 0006 001122334455 0001 0004 0a000009 001b19 00"+
			"09 70756d703b373b4131 05 312e323b3b 05 706c632d37 001b19000100 00",
		PTPClockDescription{
			ClockType:             PTPClockOrdinary | PTPClockBoundary,
			PhysicalLayerProtocol: "IEEE 802.3",
			PhysicalAddress:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			ProtocolAddress:       PTPPortAddress{NetworkProtocol: PTPNetworkUDPv4, Address: []byte{10, 0, 0, 9}},
			ManufacturerIdentity:  [3]byte{0x00, 0x1b, 0x19},
			ProductDescription:    "pump;7;A1",
			RevisionData:          "1.2;;",
			UserDescription:       "plc-7",
			ProfileIdentity:       [6]byte{0x00, 0x1b, 0x19, 0x00, 0x01, 0x00},
		}),
	ptpMgmtVector("user description", ptpBodyMgmtSet, PTPMgmtUserDescription,
		"06 70756d702d37 00", PTPUserDescription("pump-7")),
	ptpMgmtVector("initialize", ptpBodyMgmtCommand, PTPMgmtInitialize, "0001", PTPMgmtUint16(1)),
	ptpMgmtVector("fault log", ptpBodyMgmtResponse, PTPMgmtFaultLog,
		// Two records: length, time, severity, name, value, description.
		"0002"+
			"0015 0000 6553 f100 0000 0001 03 02 6f73 03 313233 02 6f6b"+
			"0010 0000 6553 f101 0000 0002 07 00 00 00 00",
		PTPFaultLog{
			{Time: PTPTimestamp{Seconds: 0x6553f100, Nanoseconds: 1}, Severity: 3, Name: "os", Value: "123", Description: "ok"},
			{Time: PTPTimestamp{Seconds: 0x6553f101, Nanoseconds: 2}, Severity: 7},
		}),
	ptpMgmtVector("default data set", ptpBodyMgmtResponse, PTPMgmtDefaultDataSet,
		"03 00 0002 80 f8 fe ffff 81 0011 22ff fe33 4455 18 00",
		PTPDefaultDataSet{
			TwoStep: true, SlaveOnly: true, NumberPorts: 2, Priority1: 128,
			ClockQuality:  PTPClockQuality{Class: 248, Accuracy: PTPAccuracyUnknown, OffsetScaledLogVariance: 0xffff},
			Priority2:     129,
			ClockIdentity: PTPClockIdentity{0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55},
			Domain:        24,
		}),
	ptpMgmtVector("current data set", ptpBodyMgmtResponse, PTPMgmtCurrentDataSet,
		// stepsRemoved 3, offset -1.5 ns, delay 1000.25 ns.
		"0003 ffff ffff fffe 8000 0000 0000 03e8 4000",
		PTPCurrentDataSet{StepsRemoved: 3, OffsetFromMaster: -0x18000, MeanPathDelay: 0x3e84000}),
	ptpMgmtVector("parent data set", ptpBodyMgmtResponse, PTPMgmtParentDataSet,
		"0011 22ff fe66 7788 0002 01 00 1234 ffff fffe 7f 06 21 4e5d 80 0011 22ff fe66 7788",
		PTPParentDataSet{
			ParentPort:              PTPPortIdentity{ClockIdentity: PTPClockIdentity{0x00, 0x11, 0x22, 0xff, 0xfe, 0x66, 0x77, 0x88}, PortNumber: 2},
			ParentStats:             true,
			ObservedVariance:        0x1234,
			ObservedPhaseChangeRate: -2,
			GrandmasterPriority1:    127,
			GrandmasterClockQuality: PTPClockQuality{Class: 6, Accuracy: PTPAccuracy100ns, OffsetScaledLogVariance: 0x4e5d},
			GrandmasterPriority2:    128,
			GrandmasterIdentity:     PTPClockIdentity{0x00, 0x11, 0x22, 0xff, 0xfe, 0x66, 0x77, 0x88},
		}),
	ptpMgmtVector("time properties data set", ptpBodyMgmtResponse, PTPMgmtTimePropertiesDataSet,
		"0025 3c 20",
		PTPTimePropertiesDataSet{
			CurrentUTCOffset: 37,
			Flags:            PTPFlagUTCOffsetValid | PTPFlagPTPTimescale | PTPFlagTimeTraceable | PTPFlagFreqTraceable,
			TimeSource:       PTPTimeSourceGNSS,
		}),
	ptpMgmtVector("port data set", ptpBodyMgmtResponse, PTPMgmtPortDataSet,
		"0011 22ff fe33 4455 0001 09 fd 0000 0000 0064 8000 01 03 ff 02 fe 12",
		PTPPortDataSet{
			PortIdentity:            PTPPortIdentity{ClockIdentity: PTPClockIdentity{0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55}, PortNumber: 1},
			PortState:               PTPPortSlave,
			LogMinDelayReqInterval:  -3,
			PeerMeanPathDelay:       0x648000,
			LogAnnounceInterval:     1,
			AnnounceReceiptTimeout:  3,
			LogSyncInterval:         -1,
			DelayMechanism:          PTPDelayP2P,
			LogMinPdelayReqInterval: -2,
			VersionNumber:           2,
		}),
	ptpMgmtVector("priority1", ptpBodyMgmtSet, PTPMgmtPriority1, "80 00", PTPMgmtUint8(128)),
	ptpMgmtVector("priority2", ptpBodyMgmtSet, PTPMgmtPriority2, "81 00", PTPMgmtUint8(129)),
	ptpMgmtVector("domain", ptpBodyMgmtSet, PTPMgmtDomain, "18 00", PTPMgmtUint8(24)),
	ptpMgmtVector("slave only", ptpBodyMgmtSet, PTPMgmtSlaveOnly, "01 00", PTPMgmtBool(true)),
	ptpMgmtVector("log announce interval", ptpBodyMgmtSet, PTPMgmtLogAnnounceInterval, "fe 00", PTPMgmtInt8(-2)),
	ptpMgmtVector("announce receipt timeout", ptpBodyMgmtSet, PTPMgmtAnnounceReceiptTimeout, "03 00", PTPMgmtUint8(3)),
	ptpMgmtVector("log sync interval", ptpBodyMgmtSet, PTPMgmtLogSyncInterval, "fd 00", PTPMgmtInt8(-3)),
	ptpMgmtVector("version number", ptpBodyMgmtSet, PTPMgmtVersionNumber, "12 00", PTPMgmtUint8(2)),
	ptpMgmtVector("time", ptpBodyMgmtSet, PTPMgmtTime, "0001 6553 f100 3b9a c9ff",
		PTPTimestamp{Seconds: 0x16553f100, Nanoseconds: 999999999}),
	ptpMgmtVector("clock accuracy", ptpBodyMgmtSet, PTPMgmtClockAccuracy, "21 00", PTPAccuracy100ns),
	ptpMgmtVector("utc properties", ptpBodyMgmtSet, PTPMgmtUTCProperties, "ffdb 05 00",
		PTPUTCProperties{CurrentUTCOffset: -37, Flags: PTPFlagLeap61 | PTPFlagUTCOffsetValid}),
	ptpMgmtVector("traceability properties", ptpBodyMgmtSet, PTPMgmtTraceabilityProperties, "30 00",
		PTPTraceabilityProperties{Flags: PTPFlagTimeTraceable | PTPFlagFreqTraceable}),
	ptpMgmtVector("timescale properties", ptpBodyMgmtSet, PTPMgmtTimescaleProperties, "08 a0",
		PTPTimescaleProperties{Flags: PTPFlagPTPTimescale, TimeSource: PTPTimeSourceInternalOscillator}),
	ptpMgmtVector("unicast negotiation enable", ptpBodyMgmtSet, PTPMgmtUnicastNegotiationEnable, "01 00", PTPMgmtBool(true)),
	ptpMgmtVector("path trace list", ptpBodyMgmtResponse, PTPMgmtPathTraceList,
		"0011 22ff fe33 4455 0011 22ff fe66 7788",
		PTPPathTrace{
			{0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55},
			{0x00, 0x11, 0x22, 0xff, 0xfe, 0x66, 0x77, 0x88},
		}),
	ptpMgmtVector("path trace enable", ptpBodyMgmtSet, PTPMgmtPathTraceEnable, "01 00", PTPMgmtBool(true)),
	ptpMgmtVector("grandmaster cluster table", ptpBodyMgmtSet, PTPMgmtGrandmasterClusterTable,
		"02 02 0001 0004 0a000001 0003 0006 001122334455",
		PTPAddressTable{LogQueryInterval: 2, Addresses: []PTPPortAddress{
			{NetworkProtocol: PTPNetworkUDPv4, Address: []byte{10, 0, 0, 1}},
			{NetworkProtocol: PTPNetworkIEEE8023, Address: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
		}}),
	ptpMgmtVector("unicast master table", ptpBodyMgmtSet, PTPMgmtUnicastMasterTable,
		"fc 0002 0001 0004 0a000001 0001 0004 0a000002 00",
		PTPAddressTable{LogQueryInterval: -4, Addresses: []PTPPortAddress{
			{NetworkProtocol: PTPNetworkUDPv4, Address: []byte{10, 0, 0, 1}},
			{NetworkProtocol: PTPNetworkUDPv4, Address: []byte{10, 0, 0, 2}},
		}}),
	ptpMgmtVector("unicast master max table size", ptpBodyMgmtResponse, PTPMgmtUnicastMasterMaxTableSize, "0010", PTPMgmtUint16(16)),
	ptpMgmtVector("acceptable master table", ptpBodyMgmtSet, PTPMgmtAcceptableMasterTable,
		"0002 0011 22ff fe33 4455 0001 80 0011 22ff fe66 7788 0002 81",
		PTPAcceptableMasterTable{
			{PortIdentity: PTPPortIdentity{ClockIdentity: PTPClockIdentity{0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55}, PortNumber: 1}, AlternatePriority1: 128},
			{PortIdentity: PTPPortIdentity{ClockIdentity: PTPClockIdentity{0x00, 0x11, 0x22, 0xff, 0xfe, 0x66, 0x77, 0x88}, PortNumber: 2}, AlternatePriority1: 129},
		}),
	ptpMgmtVector("acceptable master table enabled", ptpBodyMgmtSet, PTPMgmtAcceptableMasterEnabled, "01 00", PTPMgmtBool(true)),
	ptpMgmtVector("acceptable master max table size", ptpBodyMgmtResponse, PTPMgmtAcceptableMasterMaxSize, "0008", PTPMgmtUint16(8)),
	ptpMgmtVector("alternate master", ptpBodyMgmtSet, PTPMgmtAlternateMaster, "01 02 fd 00",
		PTPAlternateMaster{TransmitSync: true, NumberOfAlternateMasters: 2, LogSyncInterval: -3}),
	ptpMgmtVector("alternate time offset enable", ptpBodyMgmtSet, PTPMgmtAlternateTimeOffsetEnable, "01 01",
		PTPAltTimeOffsetEnable{KeyField: 1, Enable: true}),
	ptpMgmtVector("alternate time offset name", ptpBodyMgmtSet, PTPMgmtAlternateTimeOffsetName, "01 03 434554 00",
		PTPAltTimeOffsetName{KeyField: 1, DisplayName: "CET"}),
	ptpMgmtVector("alternate time offset max key", ptpBodyMgmtResponse, PTPMgmtAlternateTimeOffsetMaxKey, "04 00", PTPMgmtUint8(4)),
	ptpMgmtVector("alternate time offset properties", ptpBodyMgmtSet, PTPMgmtAlternateTimeOffsetProps,
		"01 0000 0e10 ffff f1f0 0001 6553 f100 00",
		PTPAltTimeOffsetProperties{KeyField: 1, CurrentOffset: 3600, JumpSeconds: -3600, TimeOfNextJump: 0x16553f100}),
	ptpMgmtVector("external port configuration enabled", ptpBodyMgmtSet, PTPMgmtExternalPortConfigEnabled, "01 00", PTPMgmtBool(true)),
	ptpMgmtVector("master only", ptpBodyMgmtSet, PTPMgmtMasterOnly, "01 00", PTPMgmtBool(true)),
	ptpMgmtVector("holdover upgrade enable", ptpBodyMgmtSet, PTPMgmtHoldoverUpgradeEnable, "01 00", PTPMgmtBool(true)),
	ptpMgmtVector("ext port config port data set", ptpBodyMgmtSet, PTPMgmtExtPortConfigPortDataSet, "01 06",
		PTPExtPortConfig{DesiredState: PTPPortMaster}),
	ptpMgmtVector("transparent clock default data set", ptpBodyMgmtResponse, PTPMgmtTransparentClockDefaultDS,
		"0011 22ff fe33 4455 0004 02 18",
		PTPTransparentDefaultDS{
			ClockIdentity: PTPClockIdentity{0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55}, NumberPorts: 4,
			DelayMechanism: PTPDelayP2P, PrimaryDomain: 24,
		}),
	ptpMgmtVector("transparent clock port data set", ptpBodyMgmtResponse, PTPMgmtTransparentClockPortDS,
		"0011 22ff fe33 4455 0003 01 fd 0000 0000 0064 8000",
		PTPTransparentPortDS{
			PortIdentity: PTPPortIdentity{ClockIdentity: PTPClockIdentity{0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55}, PortNumber: 3},
			Faulty:       true, LogMinPdelayReqInterval: -3, PeerMeanPathDelay: 0x648000,
		}),
	ptpMgmtVector("primary domain", ptpBodyMgmtSet, PTPMgmtPrimaryDomain, "18 00", PTPMgmtUint8(24)),
	ptpMgmtVector("delay mechanism", ptpBodyMgmtSet, PTPMgmtDelayMechanism, "02 00", PTPDelayP2P),
	ptpMgmtVector("log min pdelay req interval", ptpBodyMgmtSet, PTPMgmtLogMinPdelayReqInterval, "fc 00", PTPMgmtInt8(-4)),
	{
		name: "management error status", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 0, PTPMessageManagement, 0, ptpBodyMgmtResponse,
				ptpTestTLV(tb, PTPTLVManagementErrorStatus, "0004 2005 0000 0000 07 6e6f2073756368"))
		},
		want: []any{PTPManagementErrorStatus{Error: PTPMgmtErrWrongValue, ID: PTPMgmtPriority1, DisplayData: "no such"}},
	},
	{
		name: "management error status, no text", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 0, PTPMessageManagement, 0, ptpBodyMgmtResponse,
				ptpTestTLV(tb, PTPTLVManagementErrorStatus, "0002 2099 0000 0000"))
		},
		want: []any{PTPManagementErrorStatus{Error: PTPMgmtErrNoSuchID, ID: 0x2099}},
	},
	{
		name: "unicast negotiation",
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 0, PTPMessageSignaling, PTPFlagUnicast, ptpBodySignaling,
				ptpTestTLV(tb, PTPTLVRequestUnicast, "b0 fd 0000 012c"),
				ptpTestTLV(tb, PTPTLVGrantUnicast, "00 fc 0000 003c 00 01"),
				ptpTestTLV(tb, PTPTLVCancelUnicast, "91 00"),
				ptpTestTLV(tb, PTPTLVAckCancelUnicast, "b2 00"))
		},
		want: []any{
			PTPUnicastRequest{MessageType: PTPMessageAnnounce, LogInterMessagePeriod: -3, Duration: 300},
			PTPUnicastGrant{MessageType: PTPMessageSync, LogInterMessagePeriod: -4, Duration: 60, RenewalInvited: true},
			PTPUnicastCancel{MessageType: PTPMessageDelayResp, MaintainRequest: true},
			PTPUnicastCancel{Acknowledge: true, MessageType: PTPMessageAnnounce, MaintainGrant: true},
		},
	},
	{
		name: "announce path trace and alternate time", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 0, PTPMessageAnnounce, PTPFlagPTPTimescale|PTPFlagUTCOffsetValid, ptpBodyAnnounce,
				ptpTestTLV(tb, PTPTLVPathTrace, "0011 22ff fe33 4455 0011 22ff fe66 7788"),
				ptpTestTLV(tb, PTPTLVAlternateTimeOffset, "01 0000 0e10 ffff f1f0 0001 6553 f100 03 434554"))
		},
		want: []any{
			PTPPathTrace{
				{0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55},
				{0x00, 0x11, 0x22, 0xff, 0xfe, 0x66, 0x77, 0x88},
			},
			PTPAlternateTimeOffset{KeyField: 1, CurrentOffset: 3600, JumpSeconds: -3600, TimeOfNextJump: 0x16553f100, DisplayName: "CET"},
		},
	},
	{
		name: "announce power profile", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 0, PTPMessageAnnounce, PTPFlagPTPTimescale, ptpBodyAnnounce,
				ptpTestTLV(tb, PTPTLVOrganizationExtension, "1c129d 000001 00fe 0000 0064 0000 00c8 0000"),
				ptpTestTLV(tb, PTPTLVOrganizationExtension, "1c129d 000002 00fe 0000 0000 0000 012c 0000"),
				ptpTestTLV(tb, PTPTLVOrganizationExtension, "aabbcc 000009 0102"),
				ptpTestTLV(tb, PTPTLVOrgExtensionPropagate, "0080c2 000001 0102"))
		},
		want: []any{
			PTPC37238{Edition: 2011, GrandmasterID: 254, GrandmasterTimeInaccuracy: 100, NetworkTimeInaccuracy: 200},
			PTPC37238{Edition: 2017, GrandmasterID: 254, TotalTimeInaccuracy: 300},
			nil,
			nil,
		},
	},
	{
		name: "gPTP announce", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 1, PTPMessageAnnounce, PTPFlagPTPTimescale, ptpBodyAnnounce,
				ptpTestTLV(tb, PTPTLVPathTrace, "0011 22ff fe33 4455"))
		},
		want: []any{PTPPathTrace{{0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55}}},
	},
	{
		name: "majorSdoId 1 announce over UDP",
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 1, PTPMessageAnnounce, PTPFlagPTPTimescale, ptpBodyAnnounce,
				ptpTestTLV(tb, PTPTLVPathTrace, "0011 22ff fe33 4455"))
		},
		want: []any{PTPPathTrace{{0x00, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55}}},
	},
	{
		name: "gPTP two-step sync", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 1, PTPMessageSync, PTPFlagTwoStep, ptpBodyTime)
		},
	},
	{
		name: "gPTP one-step sync", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 1, PTPMessageSync, 0, ptpBodyTime,
				ptpTestTLV(tb, PTPTLVOrganizationExtension, "0080c2 000001 0000 0400 0001 0000 0000 0000 0000 0001 8000 ffff fc00"))
		},
		want: []any{PTPFollowUpInfo{
			CumulativeScaledRateOffset: 1024, GMTimeBaseIndicator: 1,
			LastGMPhaseChange:      PTPScaledNs{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x80, 0},
			ScaledLastGMFreqChange: -1024,
		}},
	},
	{
		name: "gPTP pdelay request", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 1, PTPMessagePdelayReq, 0, ptpBodyPdelayReq)
		},
	},
	{
		name: "gPTP follow up", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 1, PTPMessageFollowUp, 0, ptpBodyTime,
				ptpTestTLV(tb, PTPTLVOrganizationExtension, "0080c2 000001 ffff f800 0002 ffff ffff ffff ffff fffe 8000 0000 0200"),
				ptpTestTLV(tb, PTPTLVOrganizationExtension, "0080c2 000006 0000 6553 f100 075b cd15 4000 0011 22ff fe66 7788 0002 ffff ff00"))
		},
		want: []any{
			PTPFollowUpInfo{
				CumulativeScaledRateOffset: -2048, GMTimeBaseIndicator: 2,
				LastGMPhaseChange:      PTPScaledNs{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x80, 0},
				ScaledLastGMFreqChange: 512,
			},
			PTPDriftTracking{
				SyncEgressSeconds: 0x6553f100, SyncEgressNs: 123456789, SyncEgressSubNs: 0x4000,
				SyncGrandmasterIdentity: PTPClockIdentity{0x00, 0x11, 0x22, 0xff, 0xfe, 0x66, 0x77, 0x88},
				SyncStepsRemoved:        2, RateRatioDrift: -256,
			},
		},
	},
	{
		name: "gPTP signaling", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 1, PTPMessageSignaling, 0, ptpBodySignaling,
				ptpTestTLV(tb, PTPTLVOrganizationExtension, "0080c2 000002 fd 7f 80 06 0000"),
				ptpTestTLV(tb, PTPTLVOrgExtensionNoPropagate, "0080c2 000004 03 01 0000 0000"),
				ptpTestTLV(tb, PTPTLVOrgExtensionNoPropagate, "0080c2 000005 fe 000000"),
				ptpTestTLV(tb, PTPTLVOrganizationExtension,
					"0080c2 000003 0000 0000 0000 0000 0001 0000 0000 0100"+
						"0000 0000 0000 0000 01f4 8000 ffff ffff ffff ffff fff6 0000 05"))
		},
		want: []any{
			PTPIntervalRequest{
				LinkDelayInterval: -3, TimeSyncInterval: 127, AnnounceInterval: -128,
				Flags: PTPIntervalComputeRateRatio | PTPIntervalComputeLinkDelay,
			},
			PTPGPTPCapable{LogMessageInterval: 3, Flags: 1},
			PTPGPTPCapableInterval{LogMessageInterval: -2},
			PTPCSN{
				UpstreamTxTime:    PTPScaledNs{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0},
				NeighborRateRatio: 256,
				MeanLinkDelay:     PTPScaledNs{0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xf4, 0x80, 0},
				DelayAsymmetry:    PTPScaledNs{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6, 0, 0},
				Domain:            5,
			},
		},
	},
	{
		name: "authentication and pad", ethernet: true,
		msg: func(tb testing.TB) []byte {
			return ptpTestMsg(tb, 0, PTPMessageSync, 0, ptpBodyTime,
				ptpTestTLV(tb, PTPTLVPad, "0000 0000"),
				ptpTestTLV(tb, PTPTLVAuthentication2019, "01 00 0000 0007 0102 0304 0506 0708 090a 0b0c 0d0e 0f10"))
		},
		want: []any{
			PTPPad{0, 0, 0, 0},
			PTPAuthentication{
				SPP: 1, KeyID: 7,
				Rest: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
		},
	},
}

// ptpDecodeDeep types a TLV as far as it goes: a management or
// organization TLV gives what its own Decode returns.
func ptpDecodeDeep(tlv PTPTLV) (any, error) {
	v, err := tlv.Decode()
	if err != nil {
		return nil, err
	}

	switch v := v.(type) {
	case PTPManagementTLV:
		return v.Decode()
	case PTPOrganizationExtension:
		return v.Decode()
	}
	return v, nil
}

// ptpVectorTransport gives the transport a vector is decoded with.
func ptpVectorTransport(v ptpTLVVector) PTPTransport {
	if v.ethernet {
		return PTPTransportEthernet
	}
	return PTPTransportUnknown
}

func TestPTPTLVVectors(t *testing.T) {
	for _, v := range ptpTLVVectors {
		m := PTP{Transport: ptpVectorTransport(v)}
		if err := m.DecodeFromBytes(v.msg(t), gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", v.name, err)
			continue
		}
		if len(m.TLVs) != len(v.want) {
			t.Errorf("%s: %d TLVs, want %d", v.name, len(m.TLVs), len(v.want))
			continue
		}

		for i, tlv := range m.TLVs {
			got, err := ptpDecodeDeep(tlv)
			if err != nil {
				t.Errorf("%s: TLV %d: %v", v.name, i, err)
			}
			if !reflect.DeepEqual(got, v.want[i]) {
				t.Errorf("%s: TLV %d:\n got %#v\nwant %#v", v.name, i, got, v.want[i])
			}
		}
	}
}

// TestPTPTLVHeaders checks the first level of the TLVs that have a second.
func TestPTPTLVHeaders(t *testing.T) {
	mgmt := PTPTLV{Type: PTPTLVManagement, Value: []byte{0x20, 0x05, 0x80, 0x00}}
	if v, err := mgmt.Decode(); err != nil || !reflect.DeepEqual(v, PTPManagementTLV{ID: PTPMgmtPriority1, Data: []byte{0x80, 0x00}}) {
		t.Errorf("management: %#v, %v", v, err)
	}

	for _, typ := range []PTPTLVType{PTPTLVOrganizationExtension, PTPTLVOrgExtensionPropagate, PTPTLVOrgExtensionNoPropagate} {
		org := PTPTLV{Type: typ, Value: []byte{0x00, 0x80, 0xc2, 0x00, 0x00, 0x02, 0xaa}}
		want := PTPOrganizationExtension{Type: typ, OrganizationID: PTPOrgIEEE8021, SubType: 2, Data: []byte{0xaa}}
		if v, err := org.Decode(); err != nil || !reflect.DeepEqual(v, want) {
			t.Errorf("%v: %#v, %v", typ, v, err)
		}
	}

	// A type without a typed form is not an error.
	if v, err := (PTPTLV{Type: PTPTLVAuthenticationChallenge, Value: []byte{1, 2}}).Decode(); v != nil || err != nil {
		t.Errorf("AUTHENTICATION_CHALLENGE: %#v, %v", v, err)
	}
	// Nor is a management ID without one, or a GET without data.
	for _, m := range []PTPManagementTLV{
		{ID: PTPMgmtPriority1},
		{ID: 0x7777, Data: []byte{1, 2}},
		{ID: PTPMgmtEnablePort, Data: []byte{1, 2}},
	} {
		if v, err := m.Decode(); v != nil || err != nil {
			t.Errorf("%v: %#v, %v", m.ID, v, err)
		}
	}
}

// TestPTPGPTP checks the IEEE 802.1AS differences: reserved octets where
// IEEE 1588 has an origin timestamp, and only over Ethernet.
func TestPTPGPTP(t *testing.T) {
	stamp := PTPTimestamp{Seconds: 0x6553f100, Nanoseconds: 123456789}

	for _, tc := range []struct {
		name      string
		majorSdo  uint8
		typ       PTPMessageType
		flags     PTPFlags
		body      string
		transport PTPTransport
		gptp      bool
		want      PTPTimestamp
	}{
		{"1588 announce", 0, PTPMessageAnnounce, 0, ptpBodyAnnounce, PTPTransportEthernet, false, stamp},
		{"gPTP announce", 1, PTPMessageAnnounce, 0, ptpBodyAnnounce, PTPTransportEthernet, true, PTPTimestamp{}},
		{"majorSdoId 1 over UDP", 1, PTPMessageAnnounce, 0, ptpBodyAnnounce, PTPTransportUnknown, false, stamp},
		{"gPTP pdelay request", 1, PTPMessagePdelayReq, 0, ptpBodyPdelayReq, PTPTransportEthernet, true, PTPTimestamp{}},
		{"gPTP two-step sync", 1, PTPMessageSync, PTPFlagTwoStep, ptpBodyTime, PTPTransportEthernet, true, PTPTimestamp{}},
		{"gPTP one-step sync", 1, PTPMessageSync, 0, ptpBodyTime, PTPTransportEthernet, true, stamp},
		{"gPTP follow up", 1, PTPMessageFollowUp, 0, ptpBodyTime, PTPTransportEthernet, true, stamp},
		{"CMLDS pdelay request", 2, PTPMessagePdelayReq, 0, ptpBodyPdelayReq, PTPTransportEthernet, false, stamp},
	} {
		m := PTP{Transport: tc.transport}
		if err := m.DecodeFromBytes(ptpTestMsg(t, tc.majorSdo, tc.typ, tc.flags, tc.body), gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if m.IsGPTP() != tc.gptp || m.Timestamp != tc.want || m.Transport != tc.transport {
			t.Errorf("%s: gPTP %v, timestamp %+v, transport %d", tc.name, m.IsGPTP(), m.Timestamp, m.Transport)
		}
	}

	// The rest of a gPTP Announce body still decodes.
	m := PTP{Transport: PTPTransportEthernet}
	if err := m.DecodeFromBytes(ptpTestMsg(t, 1, PTPMessageAnnounce, 0, ptpBodyAnnounce), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if m.Announce.CurrentUTCOffset != 37 || m.Announce.StepsRemoved != 1 || m.Announce.TimeSource != PTPTimeSourceGNSS {
		t.Errorf("gPTP announce body: %+v", m.Announce)
	}
}

// ptpTestFrame wraps a message in Ethernet, or in Ethernet, IPv4 and UDP.
func ptpTestFrame(msg []byte, ethernet bool) []byte {
	eth := []byte{0x01, 0x1b, 0x19, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	if ethernet {
		eth = binary.BigEndian.AppendUint16(eth, uint16(EthernetTypePTP))
		return append(eth, msg...)
	}

	const ipHeader, udpHeader = 20, 8
	eth = binary.BigEndian.AppendUint16(eth, uint16(EthernetTypeIPv4))

	ip := []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 1, 17, 0, 0, 10, 0, 0, 1, 224, 0, 1, 129}
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipHeader+udpHeader+len(msg)))

	udp := binary.BigEndian.AppendUint16(nil, UDPPortPTPGeneral)
	udp = binary.BigEndian.AppendUint16(udp, UDPPortPTPGeneral)
	udp = binary.BigEndian.AppendUint16(udp, uint16(udpHeader+len(msg)))
	udp = append(udp, 0, 0) // no checksum

	return append(append(append(eth, ip...), udp...), msg...)
}

// TestPTPTransportRouting checks that the registered decoders tell
// Ethernet from UDP, which is what makes majorSdoId 1 mean gPTP.
func TestPTPTransportRouting(t *testing.T) {
	registerPTPDecoders()

	msg := ptpTestMsg(t, 1, PTPMessageAnnounce, 0, ptpBodyAnnounce)
	for _, ethernet := range []bool{true, false} {
		p := gopacket.NewPacket(ptpTestFrame(msg, ethernet), LayerTypeEthernet, gopacket.Default)
		m, ok := p.Layer(LayerTypePTP).(*PTP)
		if !ok {
			t.Fatalf("ethernet %v: no PTP layer: %v", ethernet, p.ErrorLayer())
		}
		if m.IsGPTP() != ethernet || (m.Timestamp == PTPTimestamp{}) != ethernet {
			t.Errorf("ethernet %v: gPTP %v, timestamp %+v", ethernet, m.IsGPTP(), m.Timestamp)
		}
	}
}

func TestPTPTLVHelpers(t *testing.T) {
	// 2023-11-14 22:13:20 TAI is 37 s ahead of UTC.
	stamp := PTPTimestamp{Seconds: 1700000037, Nanoseconds: 5}
	if got, want := stamp.UTC(37), time.Unix(1700000000, 5).UTC(); !got.Equal(want) {
		t.Errorf("UTC: %v, want %v", got, want)
	}
	if got := stamp.UTC(0); !got.Equal(stamp.Time()) {
		t.Errorf("UTC(0): %v", got)
	}

	if ns := PTPTimeInterval(-0x18000).Ns(); ns != -1.5 {
		t.Errorf("TimeInterval: %v", ns)
	}
	if ns := (PTPScaledNs{0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xf4, 0x80, 0}).Ns(); ns != 500.5 {
		t.Errorf("ScaledNs: %v", ns)
	}
	if ns := (PTPScaledNs{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6, 0, 0}).Ns(); ns != -10 {
		t.Errorf("negative ScaledNs: %v", ns)
	}

	// 2^-41 * 2^20 is 2^-21.
	if r := (PTPFollowUpInfo{CumulativeScaledRateOffset: 1 << 20}).RateRatio(); r != 1+1.0/(1<<21) {
		t.Errorf("RateRatio: %v", r)
	}
	if d := (PTPDriftTracking{RateRatioDrift: 1 << 21}).DriftPPM(); d != 1e6/(1<<20) {
		t.Errorf("DriftPPM: %v", d)
	}

	for got, want := range map[string]string{
		PTPPortSlave.String():                          "SLAVE",
		PTPPortState(0).String():                       "Unknown(0)",
		PTPDelayCommonP2P.String():                     "COMMON_P2P",
		PTPDelayMechanism(9).String():                  "Unknown(0x09)",
		PTPNetworkPROFINET.String():                    "PROFINET",
		PTPNetworkProtocol(7).String():                 "Reserved(0x0007)",
		(PTPClockOrdinary | PTPClockBoundary).String(): "ordinary|boundary",
		PTPClockType(0).String():                       "none",
		PTPOrgIEEE8021.String():                        "IEEE 802.1",
		PTPOrganizationID(0xaabbcc).String():           "0xAABBCC",
		PTPTLVPad.String():                             "PAD",
		PTPTLVAuthentication2019.String():              "AUTHENTICATION",
		PTPMgmtMasterOnly.String():                     "MASTER_ONLY",
		PTPMgmtExtPortConfigPortDataSet.String():       "EXT_PORT_CONFIG_PORT_DATA_SET",
		PTPTLVCumulativeRateRatio.String():             "CUMULATIVE_RATE_RATIO",
		(PTPClockP2PTransparent | PTPClockE2ETransparent | PTPClockManagementNode).String(): "p2pTransparent|e2eTransparent|management",
	} {
		if got != want {
			t.Errorf("String: %q, want %q", got, want)
		}
	}
}

// TestPTPTLVTruncated cuts every TLV value at every length: a decoder
// must return ErrPTPTLVValue or a value, and never panic.
func TestPTPTLVTruncated(t *testing.T) {
	for _, v := range ptpTLVVectors {
		var m PTP
		if err := m.DecodeFromBytes(v.msg(t), gopacket.NilDecodeFeedback); err != nil {
			t.Fatalf("%s: %v", v.name, err)
		}

		for i, tlv := range m.TLVs {
			for n := 0; n < len(tlv.Value); n++ {
				cut := PTPTLV{Type: tlv.Type, Length: uint16(n), Value: tlv.Value[:n:n]}
				if _, err := ptpDecodeDeep(cut); err != nil && !errors.Is(err, ErrPTPTLVValue) {
					t.Errorf("%s: TLV %d cut to %d: %v", v.name, i, n, err)
				}
			}
		}

		// The message cut at every offset is an error. With messageLength
		// lowered to match, whatever TLVs still parse must type or fail
		// cleanly.
		msg := v.msg(t)
		for n := 0; n < len(msg); n++ {
			cut := PTP{Transport: ptpVectorTransport(v)}
			if err := cut.DecodeFromBytes(msg[:n:n], gopacket.NilDecodeFeedback); err == nil {
				t.Errorf("%s: cut to %d: no error", v.name, n)
			}
			if n < ptpHeaderLen {
				continue
			}

			lie := append([]byte(nil), msg[:n]...)
			binary.BigEndian.PutUint16(lie[2:4], uint16(n))
			if err := cut.DecodeFromBytes(lie, gopacket.NilDecodeFeedback); err != nil {
				continue
			}
			for i, tlv := range cut.TLVs {
				if _, err := ptpDecodeDeep(tlv); err != nil && !errors.Is(err, ErrPTPTLVValue) {
					t.Errorf("%s: length %d, TLV %d: %v", v.name, n, i, err)
				}
			}
		}
	}

	// Fixed layouts must report every cut.
	fixed := PTPTLV{Type: PTPTLVGrantUnicast, Value: []byte{0x00, 0xfc, 0, 0, 0, 0x3c, 0, 1}}
	for n := 0; n < len(fixed.Value); n++ {
		fixed := PTPTLV{Type: fixed.Type, Value: fixed.Value[:n]}
		if v, err := fixed.Decode(); v != nil || !errors.Is(err, ErrPTPTLVValue) {
			t.Errorf("grant cut to %d: %#v, %v", n, v, err)
		}
	}
}

// TestPTPTLVLengthLies feeds counts and lengths larger than the data.
func TestPTPTLVLengthLies(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   PTPManagementID
		data string
	}{
		{"fault record count", PTPMgmtFaultLog, "ffff 0015 0000 6553 f100 0000 0001 03 00 00 00"},
		{"fault text length", PTPMgmtFaultLog, "0001 0015 0000 6553 f100 0000 0001 03 ff 00 00"},
		{"cluster table size", PTPMgmtGrandmasterClusterTable, "02 ff 0001 0004 0a000001"},
		{"unicast table size", PTPMgmtUnicastMasterTable, "02 ffff 0001 0004 0a000001"},
		{"port address length", PTPMgmtUnicastMasterTable, "02 0001 0001 ffff 0a000001"},
		{"acceptable table size", PTPMgmtAcceptableMasterTable, "ffff 0011 22ff fe33 4455 0001 80"},
		{"physical address length", PTPMgmtClockDescription, "8000 00 ffff 0011"},
		{"text length", PTPMgmtUserDescription, "ff 41"},
	} {
		m := PTPManagementTLV{ID: tc.id, Data: ptpHex(t, tc.data)}
		if v, err := m.Decode(); v != nil || !errors.Is(err, ErrPTPTLVValue) {
			t.Errorf("%s: %#v, %v", tc.name, v, err)
		}
	}

	atoi := PTPTLV{Type: PTPTLVAlternateTimeOffset, Value: ptpHex(t, "01 0000 0e10 ffff f1f0 0001 6553 f100 ff 43")}
	if v, err := atoi.Decode(); v != nil || !errors.Is(err, ErrPTPTLVValue) {
		t.Errorf("display name length: %#v, %v", v, err)
	}

	// A PATH_TRACE keeps whole identities and drops a short tail.
	trace := PTPTLV{Type: PTPTLVPathTrace, Value: ptpHex(t, "0011 22ff fe33 4455 0011 22")}
	if v, err := trace.Decode(); err != nil || len(v.(PTPPathTrace)) != 1 {
		t.Errorf("path trace tail: %#v, %v", v, err)
	}
}

// TestPTPTLVAllocBound checks that a count on the wire cannot make a
// decoder allocate more than the data it came in can back.
func TestPTPTLVAllocBound(t *testing.T) {
	// The largest management data a message can carry.
	const maxData = 1<<16 - 1 - ptpHeaderLen - ptpManagementBodyLen - ptpTLVHeaderLen - ptpManagementIDLen

	u16 := func(n int) []byte { return binary.BigEndian.AppendUint16(nil, uint16(n)) }

	for _, tc := range []struct {
		id       PTPManagementID
		head     func(count int) []byte // what precedes the entries
		maxCount int                    // largest count the field holds
		entry    int                    // smallest entry on the wire
		perItem  uintptr                // bytes one decoded entry takes
	}{
		{PTPMgmtFaultLog, u16, 0xffff, ptpFaultRecordMin, reflect.TypeOf(PTPFaultRecord{}).Size()},
		{PTPMgmtUnicastMasterTable, func(n int) []byte { return append([]byte{0}, u16(n)...) }, 0xffff,
			ptpPortAddressMin, reflect.TypeOf(PTPPortAddress{}).Size()},
		{PTPMgmtGrandmasterClusterTable, func(n int) []byte { return []byte{0, uint8(n)} }, 0xff,
			ptpPortAddressMin, reflect.TypeOf(PTPPortAddress{}).Size()},
		{PTPMgmtAcceptableMasterTable, u16, 0xffff, ptpAcceptableEntry, reflect.TypeOf(PTPAcceptableMaster{}).Size()},
		{PTPMgmtPathTraceList, func(int) []byte { return nil }, 0xffff, ptpClockIDLen, ptpClockIDLen},
	} {
		// honest is the most entries the data can hold; the lie claims
		// the most the count field can.
		honest := min((maxData-len(tc.head(0)))/tc.entry, tc.maxCount)

		for _, count := range []int{honest, tc.maxCount} {
			data := make([]byte, maxData)
			copy(data, tc.head(count))
			m := PTPManagementTLV{ID: tc.id, Data: data}

			// Room for the list, rounded up as the allocator does,
			// plus the boxing of the result and the reader.
			const slack = 512
			limit := float64(honest*int(tc.perItem)*5/4 + slack)

			const runs = 20
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for i := 0; i < runs; i++ {
				m.Decode()
			}
			runtime.ReadMemStats(&after)

			if perRun := float64(after.TotalAlloc-before.TotalAlloc) / runs; perRun > limit {
				t.Errorf("%v, count %d: %.0f bytes per decode, limit %.0f", tc.id, count, perRun, limit)
			}
		}
	}

	// A count the data cannot hold allocates no list at all.
	lie := PTPManagementTLV{ID: PTPMgmtFaultLog, Data: ptpHex(t, "ffff 0000")}
	if n := testing.AllocsPerRun(50, func() { lie.Decode() }); n > 1 {
		t.Errorf("lying fault count: %.0f allocations", n)
	}
}

// TestPTPPcapManagement types the management responses of the tcpdump
// capture; the values are what tshark 4.7 shows for the same frames.
func TestPTPPcapManagement(t *testing.T) {
	packets, err := ptpReadPcap("testdata/ptp_tcpdump_management.pcap")
	if err != nil {
		t.Fatal(err)
	}

	clock := PTPClockIdentity{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x12}
	quality := PTPClockQuality{Class: 248, Accuracy: PTPAccuracyUnknown, OffsetScaledLogVariance: 0xffff}
	mac := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x12}

	// Frame numbers as tshark counts them, from 1.
	for frame, want := range map[int]any{
		2: PTPCurrentDataSet{},
		4: PTPPortDataSet{
			PortIdentity: PTPPortIdentity{ClockIdentity: clock, PortNumber: 1}, PortState: PTPPortMaster,
			LogAnnounceInterval: 1, AnnounceReceiptTimeout: 3, DelayMechanism: PTPDelayP2P, VersionNumber: 2,
		},
		6: PTPDefaultDataSet{
			TwoStep: true, NumberPorts: 1, Priority1: 128, ClockQuality: quality, Priority2: 128, ClockIdentity: clock,
		},
		8: PTPParentDataSet{
			ParentPort: PTPPortIdentity{ClockIdentity: clock}, ObservedVariance: 0xffff, ObservedPhaseChangeRate: 0x7fffffff,
			GrandmasterPriority1: 128, GrandmasterClockQuality: quality, GrandmasterPriority2: 128, GrandmasterIdentity: clock,
		},
		10: PTPClockDescription{
			ClockType: PTPClockOrdinary, PhysicalLayerProtocol: "IEEE 802.3", PhysicalAddress: mac,
			ProtocolAddress:    PTPPortAddress{NetworkProtocol: PTPNetworkIEEE8023, Address: mac},
			ProductDescription: ";;", RevisionData: ";;",
			ProfileIdentity: [6]byte{0x00, 0x1b, 0x19, 0x00, 0x02, 0x00},
		},
	} {
		const ethHeader = 14

		var m PTP
		if err := m.DecodeFromBytes(packets[frame-1][ethHeader:], gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("frame %d: %v", frame, err)
			continue
		}
		if len(m.TLVs) != 1 {
			t.Errorf("frame %d: %d TLVs", frame, len(m.TLVs))
			continue
		}
		if got, err := ptpDecodeDeep(m.TLVs[0]); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("frame %d: %v\n got %#v\nwant %#v", frame, err, got, want)
		}
	}
}
