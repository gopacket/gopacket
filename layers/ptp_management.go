// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Typed PTP management TLV data (IEEE 1588-2019, clause 15.5), one type
// per managementId, laid out as Wireshark's packet-ptp.c reads them.

package layers

import (
	"fmt"
	"strings"
)

// Management data layout.
const (
	ptpProfileIDLen  = 6
	ptpVersionMask   = 0x0F // versionNumber shares its octet with reserved bits
	ptpMgmtFlagBit0  = 0x01
	ptpMgmtFlagBit1  = 0x02
	ptpMgmtFlagsMask = 0x00FF // the flagField octet a data set repeats

	// Smallest table entries, to bound a table by the data that holds it.
	ptpFaultRecordMin  = 2 + ptpTimestampLen + 1 + 3 // length, time, severity, 3 empty texts
	ptpPortAddressMin  = 4                           // networkProtocol, addressLength
	ptpAcceptableEntry = ptpPortIdentityLen + 1      // portIdentity, alternatePriority1
)

// PTPPortState is a portState.
type PTPPortState uint8

// Port states.
const (
	PTPPortInitializing PTPPortState = 1
	PTPPortFaulty       PTPPortState = 2
	PTPPortDisabled     PTPPortState = 3
	PTPPortListening    PTPPortState = 4
	PTPPortPreMaster    PTPPortState = 5
	PTPPortMaster       PTPPortState = 6
	PTPPortPassive      PTPPortState = 7
	PTPPortUncalibrated PTPPortState = 8
	PTPPortSlave        PTPPortState = 9
)

// String returns the state name, e.g. "SLAVE".
func (s PTPPortState) String() string {
	switch s {
	case PTPPortInitializing:
		return "INITIALIZING"
	case PTPPortFaulty:
		return "FAULTY"
	case PTPPortDisabled:
		return "DISABLED"
	case PTPPortListening:
		return "LISTENING"
	case PTPPortPreMaster:
		return "PRE_MASTER"
	case PTPPortMaster:
		return "MASTER"
	case PTPPortPassive:
		return "PASSIVE"
	case PTPPortUncalibrated:
		return "UNCALIBRATED"
	case PTPPortSlave:
		return "SLAVE"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(s))
}

// PTPDelayMechanism is a delayMechanism.
type PTPDelayMechanism uint8

// Delay mechanisms.
const (
	PTPDelayE2E         PTPDelayMechanism = 0x01
	PTPDelayP2P         PTPDelayMechanism = 0x02
	PTPDelayCommonP2P   PTPDelayMechanism = 0x03 // IEEE 1588-2019
	PTPDelaySpecial     PTPDelayMechanism = 0x04 // IEEE 1588-2019
	PTPDelayNoMechanism PTPDelayMechanism = 0xFE
)

// String returns the mechanism name, e.g. "E2E".
func (d PTPDelayMechanism) String() string {
	switch d {
	case PTPDelayE2E:
		return "E2E"
	case PTPDelayP2P:
		return "P2P"
	case PTPDelayCommonP2P:
		return "COMMON_P2P"
	case PTPDelaySpecial:
		return "SPECIAL"
	case PTPDelayNoMechanism:
		return "NO_MECHANISM"
	}
	return fmt.Sprintf("Unknown(0x%02X)", uint8(d))
}

// PTPNetworkProtocol is the networkProtocol of a PortAddress.
type PTPNetworkProtocol uint16

// Network protocols.
const (
	PTPNetworkUDPv4      PTPNetworkProtocol = 0x0001
	PTPNetworkUDPv6      PTPNetworkProtocol = 0x0002
	PTPNetworkIEEE8023   PTPNetworkProtocol = 0x0003
	PTPNetworkDeviceNet  PTPNetworkProtocol = 0x0004
	PTPNetworkControlNet PTPNetworkProtocol = 0x0005
	PTPNetworkPROFINET   PTPNetworkProtocol = 0x0006
	PTPNetworkUnknown    PTPNetworkProtocol = 0xFFFE
)

// String returns the protocol name, e.g. "UDP/IPv4".
func (n PTPNetworkProtocol) String() string {
	switch n {
	case PTPNetworkUDPv4:
		return "UDP/IPv4"
	case PTPNetworkUDPv6:
		return "UDP/IPv6"
	case PTPNetworkIEEE8023:
		return "IEEE 802.3"
	case PTPNetworkDeviceNet:
		return "DeviceNet"
	case PTPNetworkControlNet:
		return "ControlNet"
	case PTPNetworkPROFINET:
		return "PROFINET"
	case PTPNetworkUnknown:
		return "Unknown Protocol"
	}
	return fmt.Sprintf("Reserved(0x%04X)", uint16(n))
}

// PTPPortAddress is a PortAddress. Address aliases the packet data.
type PTPPortAddress struct {
	NetworkProtocol PTPNetworkProtocol
	Address         []byte
}

// PTPClockType is the clockType of a CLOCK_DESCRIPTION, a bit per kind of
// clock the node implements.
type PTPClockType uint16

// Clock type bits.
const (
	PTPClockOrdinary       PTPClockType = 0x8000
	PTPClockBoundary       PTPClockType = 0x4000
	PTPClockP2PTransparent PTPClockType = 0x2000
	PTPClockE2ETransparent PTPClockType = 0x1000
	PTPClockManagementNode PTPClockType = 0x0800
)

// ptpClockTypeNames orders the clock type bits for String.
var ptpClockTypeNames = []struct {
	bit  PTPClockType
	name string
}{
	{PTPClockOrdinary, "ordinary"},
	{PTPClockBoundary, "boundary"},
	{PTPClockP2PTransparent, "p2pTransparent"},
	{PTPClockE2ETransparent, "e2eTransparent"},
	{PTPClockManagementNode, "management"},
}

// String lists the set bits, e.g. "ordinary|boundary".
func (c PTPClockType) String() string {
	var set []string
	for _, n := range ptpClockTypeNames {
		if c&n.bit != 0 {
			set = append(set, n.name)
		}
	}

	if len(set) == 0 {
		return "none"
	}
	return strings.Join(set, "|")
}

// PTPClockDescription is the data of CLOCK_DESCRIPTION.
type PTPClockDescription struct {
	ClockType             PTPClockType
	PhysicalLayerProtocol string
	PhysicalAddress       []byte
	ProtocolAddress       PTPPortAddress
	// ManufacturerIdentity is an OUI.
	ManufacturerIdentity [ptpOUILen]byte
	ProductDescription   string
	RevisionData         string
	UserDescription      string
	ProfileIdentity      [ptpProfileIDLen]byte
}

// PTPUserDescription is the data of USER_DESCRIPTION.
type PTPUserDescription string

// PTPFaultSeverity is the severityCode of a fault record, numbered like
// syslog: 0 emergency to 7 debug.
type PTPFaultSeverity uint8

// PTPFaultRecord is one record of a FAULT_LOG.
type PTPFaultRecord struct {
	Time        PTPTimestamp
	Severity    PTPFaultSeverity
	Name        string
	Value       string
	Description string
}

// PTPFaultLog is the data of FAULT_LOG.
type PTPFaultLog []PTPFaultRecord

// PTPDefaultDataSet is the data of DEFAULT_DATA_SET.
type PTPDefaultDataSet struct {
	TwoStep       bool
	SlaveOnly     bool
	NumberPorts   uint16
	Priority1     uint8
	ClockQuality  PTPClockQuality
	Priority2     uint8
	ClockIdentity PTPClockIdentity
	Domain        uint8
}

// PTPCurrentDataSet is the data of CURRENT_DATA_SET.
type PTPCurrentDataSet struct {
	StepsRemoved     uint16
	OffsetFromMaster PTPTimeInterval
	MeanPathDelay    PTPTimeInterval
}

// PTPParentDataSet is the data of PARENT_DATA_SET.
type PTPParentDataSet struct {
	ParentPort  PTPPortIdentity
	ParentStats bool
	// ObservedVariance is observedParentOffsetScaledLogVariance.
	ObservedVariance uint16
	// ObservedPhaseChangeRate is observedParentClockPhaseChangeRate.
	ObservedPhaseChangeRate int32
	GrandmasterPriority1    uint8
	GrandmasterClockQuality PTPClockQuality
	GrandmasterPriority2    uint8
	GrandmasterIdentity     PTPClockIdentity
}

// PTPTimePropertiesDataSet is the data of TIME_PROPERTIES_DATA_SET. Flags
// holds the leap, UTC offset valid, timescale and traceable bits, as the
// low octet of a header flagField does.
type PTPTimePropertiesDataSet struct {
	CurrentUTCOffset int16
	Flags            PTPFlags
	TimeSource       PTPTimeSource
}

// PTPPortDataSet is the data of PORT_DATA_SET. The intervals are log2
// seconds.
type PTPPortDataSet struct {
	PortIdentity            PTPPortIdentity
	PortState               PTPPortState
	LogMinDelayReqInterval  int8
	PeerMeanPathDelay       PTPTimeInterval
	LogAnnounceInterval     int8
	AnnounceReceiptTimeout  uint8
	LogSyncInterval         int8
	DelayMechanism          PTPDelayMechanism
	LogMinPdelayReqInterval int8
	VersionNumber           uint8
}

// PTPUTCProperties is the data of UTC_PROPERTIES. Flags holds the leap
// and UTC offset valid bits.
type PTPUTCProperties struct {
	CurrentUTCOffset int16
	Flags            PTPFlags
}

// PTPTraceabilityProperties is the data of TRACEABILITY_PROPERTIES. Flags
// holds the time and frequency traceable bits.
type PTPTraceabilityProperties struct {
	Flags PTPFlags
}

// PTPTimescaleProperties is the data of TIMESCALE_PROPERTIES. Flags holds
// the ptpTimescale bit.
type PTPTimescaleProperties struct {
	Flags      PTPFlags
	TimeSource PTPTimeSource
}

// PTPAddressTable is the data of GRANDMASTER_CLUSTER_TABLE and
// UNICAST_MASTER_TABLE.
type PTPAddressTable struct {
	LogQueryInterval int8
	Addresses        []PTPPortAddress
}

// PTPAcceptableMaster is one entry of an ACCEPTABLE_MASTER_TABLE.
type PTPAcceptableMaster struct {
	PortIdentity       PTPPortIdentity
	AlternatePriority1 uint8
}

// PTPAcceptableMasterTable is the data of ACCEPTABLE_MASTER_TABLE.
type PTPAcceptableMasterTable []PTPAcceptableMaster

// PTPAlternateMaster is the data of ALTERNATE_MASTER.
type PTPAlternateMaster struct {
	TransmitSync bool
	// NumberOfAlternateMasters is how many alternates the port accepts.
	NumberOfAlternateMasters uint8
	LogSyncInterval          int8
}

// PTPAltTimeOffsetEnable is the data of ALTERNATE_TIME_OFFSET_ENABLE.
type PTPAltTimeOffsetEnable struct {
	KeyField uint8
	Enable   bool
}

// PTPAltTimeOffsetName is the data of ALTERNATE_TIME_OFFSET_NAME.
type PTPAltTimeOffsetName struct {
	KeyField    uint8
	DisplayName string
}

// PTPAltTimeOffsetProperties is the data of
// ALTERNATE_TIME_OFFSET_PROPERTIES.
type PTPAltTimeOffsetProperties struct {
	KeyField       uint8
	CurrentOffset  int32
	JumpSeconds    int32
	TimeOfNextJump uint64
}

// PTPExtPortConfig is the data of EXT_PORT_CONFIG_PORT_DATA_SET.
type PTPExtPortConfig struct {
	DesiredState PTPPortState
}

// PTPTransparentDefaultDS is the data of
// TRANSPARENT_CLOCK_DEFAULT_DATA_SET.
type PTPTransparentDefaultDS struct {
	ClockIdentity  PTPClockIdentity
	NumberPorts    uint16
	DelayMechanism PTPDelayMechanism
	PrimaryDomain  uint8
}

// PTPTransparentPortDS is the data of TRANSPARENT_CLOCK_PORT_DATA_SET.
type PTPTransparentPortDS struct {
	PortIdentity            PTPPortIdentity
	Faulty                  bool
	LogMinPdelayReqInterval int8
	PeerMeanPathDelay       PTPTimeInterval
}

// PTPMgmtUint8 is the data of a managementId holding one unsigned octet:
// PRIORITY1, PRIORITY2, DOMAIN, ANNOUNCE_RECEIPT_TIMEOUT, VERSION_NUMBER,
// ALTERNATE_TIME_OFFSET_MAX_KEY and PRIMARY_DOMAIN.
type PTPMgmtUint8 uint8

// PTPMgmtInt8 is the data of a managementId holding a log2 interval in
// seconds: LOG_ANNOUNCE_INTERVAL, LOG_SYNC_INTERVAL and
// LOG_MIN_PDELAY_REQ_INTERVAL.
type PTPMgmtInt8 int8

// PTPMgmtUint16 is the data of a managementId holding two octets:
// INITIALIZE (the initialization key), UNICAST_MASTER_MAX_TABLE_SIZE and
// ACCEPTABLE_MASTER_MAX_TABLE_SIZE.
type PTPMgmtUint16 uint16

// PTPMgmtBool is the data of a managementId holding one flag: SLAVE_ONLY,
// UNICAST_NEGOTIATION_ENABLE, PATH_TRACE_ENABLE,
// ACCEPTABLE_MASTER_TABLE_ENABLED, EXTERNAL_PORT_CONFIGURATION_ENABLED,
// MASTER_ONLY and HOLDOVER_UPGRADE_ENABLE.
type PTPMgmtBool bool

// ptpMgmtKind sorts the managementIds whose data is a single value.
type ptpMgmtKind uint8

const (
	ptpMgmtKindUint8 ptpMgmtKind = iota + 1
	ptpMgmtKindInt8
	ptpMgmtKindUint16
	ptpMgmtKindBool
	ptpMgmtKindVersion
	ptpMgmtKindAccuracy
	ptpMgmtKindDelay
)

// ptpMgmtKinds maps the single value managementIds to their kind.
var ptpMgmtKinds = map[PTPManagementID]ptpMgmtKind{
	PTPMgmtInitialize:                ptpMgmtKindUint16,
	PTPMgmtPriority1:                 ptpMgmtKindUint8,
	PTPMgmtPriority2:                 ptpMgmtKindUint8,
	PTPMgmtDomain:                    ptpMgmtKindUint8,
	PTPMgmtSlaveOnly:                 ptpMgmtKindBool,
	PTPMgmtLogAnnounceInterval:       ptpMgmtKindInt8,
	PTPMgmtAnnounceReceiptTimeout:    ptpMgmtKindUint8,
	PTPMgmtLogSyncInterval:           ptpMgmtKindInt8,
	PTPMgmtVersionNumber:             ptpMgmtKindVersion,
	PTPMgmtClockAccuracy:             ptpMgmtKindAccuracy,
	PTPMgmtUnicastNegotiationEnable:  ptpMgmtKindBool,
	PTPMgmtPathTraceEnable:           ptpMgmtKindBool,
	PTPMgmtUnicastMasterMaxTableSize: ptpMgmtKindUint16,
	PTPMgmtAcceptableMasterEnabled:   ptpMgmtKindBool,
	PTPMgmtAcceptableMasterMaxSize:   ptpMgmtKindUint16,
	PTPMgmtAlternateTimeOffsetMaxKey: ptpMgmtKindUint8,
	PTPMgmtExternalPortConfigEnabled: ptpMgmtKindBool,
	PTPMgmtMasterOnly:                ptpMgmtKindBool,
	PTPMgmtHoldoverUpgradeEnable:     ptpMgmtKindBool,
	PTPMgmtPrimaryDomain:             ptpMgmtKindUint8,
	PTPMgmtDelayMechanism:            ptpMgmtKindDelay,
	PTPMgmtLogMinPdelayReqInterval:   ptpMgmtKindInt8,
}

// Decode returns the typed data of the management TLV:
//
//	CLOCK_DESCRIPTION                   PTPClockDescription
//	USER_DESCRIPTION                    PTPUserDescription
//	FAULT_LOG                           PTPFaultLog
//	DEFAULT_DATA_SET                    PTPDefaultDataSet
//	CURRENT_DATA_SET                    PTPCurrentDataSet
//	PARENT_DATA_SET                     PTPParentDataSet
//	TIME_PROPERTIES_DATA_SET            PTPTimePropertiesDataSet
//	PORT_DATA_SET                       PTPPortDataSet
//	TIME                                PTPTimestamp
//	CLOCK_ACCURACY                      PTPClockAccuracy
//	UTC_PROPERTIES                      PTPUTCProperties
//	TRACEABILITY_PROPERTIES             PTPTraceabilityProperties
//	TIMESCALE_PROPERTIES                PTPTimescaleProperties
//	PATH_TRACE_LIST                     PTPPathTrace
//	GRANDMASTER_CLUSTER_TABLE           PTPAddressTable
//	UNICAST_MASTER_TABLE                PTPAddressTable
//	ACCEPTABLE_MASTER_TABLE             PTPAcceptableMasterTable
//	ALTERNATE_MASTER                    PTPAlternateMaster
//	ALTERNATE_TIME_OFFSET_ENABLE        PTPAltTimeOffsetEnable
//	ALTERNATE_TIME_OFFSET_NAME          PTPAltTimeOffsetName
//	ALTERNATE_TIME_OFFSET_PROPERTIES    PTPAltTimeOffsetProperties
//	EXT_PORT_CONFIG_PORT_DATA_SET       PTPExtPortConfig
//	TRANSPARENT_CLOCK_DEFAULT_DATA_SET  PTPTransparentDefaultDS
//	TRANSPARENT_CLOCK_PORT_DATA_SET     PTPTransparentPortDS
//	DELAY_MECHANISM                     PTPDelayMechanism
//	single value IDs                    PTPMgmtUint8, PTPMgmtInt8,
//	                                    PTPMgmtUint16 or PTPMgmtBool
//
// Empty data, as in a GET or for an ID that carries none, gives nil and
// no error, and so does an unknown ID. Data too short for its ID gives
// ErrPTPTLVValue. Slices alias the packet data.
func (m PTPManagementTLV) Decode() (any, error) {
	if len(m.Data) == 0 {
		return nil, nil
	}

	r := &ptpReader{data: m.Data}
	if kind, ok := ptpMgmtKinds[m.ID]; ok {
		return ptpValue(ptpMgmtScalar(kind, r), r)
	}

	switch m.ID {
	case PTPMgmtClockDescription:
		return ptpValue(ptpClockDescription(r), r)
	case PTPMgmtUserDescription:
		return ptpValue(PTPUserDescription(r.text()), r)
	case PTPMgmtFaultLog:
		return ptpValue(ptpFaultLog(r), r)
	case PTPMgmtPathTraceList:
		return PTPPathTrace(ptpClockIDs(m.Data)), nil
	case PTPMgmtGrandmasterClusterTable:
		v := PTPAddressTable{LogQueryInterval: int8(r.u8())}
		v.Addresses = ptpAddresses(int(r.u8()), r)
		return ptpValue(v, r)
	case PTPMgmtUnicastMasterTable:
		v := PTPAddressTable{LogQueryInterval: int8(r.u8())}
		v.Addresses = ptpAddresses(int(r.u16()), r)
		return ptpValue(v, r)
	case PTPMgmtAcceptableMasterTable:
		return ptpValue(ptpAcceptableMasters(r), r)
	}
	return ptpMgmtDataSet(m.ID, r)
}

// ptpMgmtScalar reads the data of a single value managementId.
func ptpMgmtScalar(kind ptpMgmtKind, r *ptpReader) any {
	switch kind {
	case ptpMgmtKindUint16:
		return PTPMgmtUint16(r.u16())
	case ptpMgmtKindInt8:
		return PTPMgmtInt8(r.u8())
	case ptpMgmtKindBool:
		return PTPMgmtBool(r.u8()&ptpMgmtFlagBit0 != 0)
	case ptpMgmtKindVersion:
		return PTPMgmtUint8(r.u8() & ptpVersionMask)
	case ptpMgmtKindAccuracy:
		return PTPClockAccuracy(r.u8())
	case ptpMgmtKindDelay:
		return PTPDelayMechanism(r.u8())
	}
	return PTPMgmtUint8(r.u8())
}

// ptpMgmtDataSet reads the data of the fixed layout managementIds.
func ptpMgmtDataSet(id PTPManagementID, r *ptpReader) (any, error) {
	switch id {
	case PTPMgmtDefaultDataSet:
		return ptpValue(ptpDefaultDataSet(r), r)
	case PTPMgmtCurrentDataSet:
		v := PTPCurrentDataSet{
			StepsRemoved:     r.u16(),
			OffsetFromMaster: r.interval(),
			MeanPathDelay:    r.interval(),
		}
		return ptpValue(v, r)
	case PTPMgmtParentDataSet:
		return ptpValue(ptpParentDataSet(r), r)
	case PTPMgmtTimePropertiesDataSet:
		v := PTPTimePropertiesDataSet{
			CurrentUTCOffset: int16(r.u16()),
			Flags:            r.flags(),
			TimeSource:       PTPTimeSource(r.u8()),
		}
		return ptpValue(v, r)
	case PTPMgmtPortDataSet:
		return ptpValue(ptpPortDataSet(r), r)
	case PTPMgmtTime:
		return ptpValue(r.timestamp(), r)
	case PTPMgmtUTCProperties:
		v := PTPUTCProperties{CurrentUTCOffset: int16(r.u16()), Flags: r.flags()}
		return ptpValue(v, r)
	case PTPMgmtTraceabilityProperties:
		return ptpValue(PTPTraceabilityProperties{Flags: r.flags()}, r)
	case PTPMgmtTimescaleProperties:
		v := PTPTimescaleProperties{Flags: r.flags(), TimeSource: PTPTimeSource(r.u8())}
		return ptpValue(v, r)
	}
	return ptpMgmtOptional(id, r)
}

// ptpMgmtOptional reads the data sets of the optional features.
func ptpMgmtOptional(id PTPManagementID, r *ptpReader) (any, error) {
	switch id {
	case PTPMgmtAlternateMaster:
		v := PTPAlternateMaster{
			TransmitSync:             r.u8()&ptpMgmtFlagBit0 != 0,
			NumberOfAlternateMasters: r.u8(),
			LogSyncInterval:          int8(r.u8()),
		}
		return ptpValue(v, r)
	case PTPMgmtAlternateTimeOffsetEnable:
		v := PTPAltTimeOffsetEnable{KeyField: r.u8(), Enable: r.u8()&ptpMgmtFlagBit0 != 0}
		return ptpValue(v, r)
	case PTPMgmtAlternateTimeOffsetName:
		v := PTPAltTimeOffsetName{KeyField: r.u8(), DisplayName: r.text()}
		return ptpValue(v, r)
	case PTPMgmtAlternateTimeOffsetProps:
		v := PTPAltTimeOffsetProperties{
			KeyField:       r.u8(),
			CurrentOffset:  int32(r.u32()),
			JumpSeconds:    int32(r.u32()),
			TimeOfNextJump: r.u48(),
		}
		return ptpValue(v, r)
	case PTPMgmtExtPortConfigPortDataSet:
		r.u8() // flags
		return ptpValue(PTPExtPortConfig{DesiredState: PTPPortState(r.u8())}, r)
	case PTPMgmtTransparentClockDefaultDS:
		v := PTPTransparentDefaultDS{
			ClockIdentity:  r.clockID(),
			NumberPorts:    r.u16(),
			DelayMechanism: PTPDelayMechanism(r.u8()),
			PrimaryDomain:  r.u8(),
		}
		return ptpValue(v, r)
	case PTPMgmtTransparentClockPortDS:
		v := PTPTransparentPortDS{
			PortIdentity:            r.portID(),
			Faulty:                  r.u8()&ptpMgmtFlagBit0 != 0,
			LogMinPdelayReqInterval: int8(r.u8()),
			PeerMeanPathDelay:       r.interval(),
		}
		return ptpValue(v, r)
	}
	return nil, nil
}

// flags reads the octet a data set shares with the low flagField octet.
func (r *ptpReader) flags() PTPFlags {
	return PTPFlags(r.u8()) & ptpMgmtFlagsMask
}

// portAddress reads a PortAddress: protocol, length, then the address.
func (r *ptpReader) portAddress() PTPPortAddress {
	return PTPPortAddress{
		NetworkProtocol: PTPNetworkProtocol(r.u16()),
		Address:         r.take(int(r.u16())),
	}
}

// ptpClockDescription reads a CLOCK_DESCRIPTION, whose fields have no
// fixed offsets: four are texts and two are sized addresses.
func ptpClockDescription(r *ptpReader) PTPClockDescription {
	v := PTPClockDescription{
		ClockType:             PTPClockType(r.u16()),
		PhysicalLayerProtocol: r.text(),
	}
	v.PhysicalAddress = r.take(int(r.u16()))
	v.ProtocolAddress = r.portAddress()
	copy(v.ManufacturerIdentity[:], r.take(ptpOUILen))
	r.u8() // reserved

	v.ProductDescription = r.text()
	v.RevisionData = r.text()
	v.UserDescription = r.text()
	copy(v.ProfileIdentity[:], r.take(ptpProfileIDLen))
	return v
}

// ptpFaultLog reads the fault records. The record count on the wire is
// capped by what the data can hold before the list is allocated.
func ptpFaultLog(r *ptpReader) PTPFaultLog {
	count := int(r.u16())
	if count > len(r.data)/ptpFaultRecordMin {
		r.short = true
		return nil
	}

	log := make(PTPFaultLog, 0, count)
	for i := 0; i < count; i++ {
		r.u16() // faultRecordLength
		log = append(log, PTPFaultRecord{
			Time:        r.timestamp(),
			Severity:    PTPFaultSeverity(r.u8()),
			Name:        r.text(),
			Value:       r.text(),
			Description: r.text(),
		})
	}
	return log
}

// ptpAddresses reads count PortAddresses, capping count by what the data
// can hold before the list is allocated.
func ptpAddresses(count int, r *ptpReader) []PTPPortAddress {
	if count > len(r.data)/ptpPortAddressMin {
		r.short = true
		return nil
	}

	addrs := make([]PTPPortAddress, 0, count)
	for i := 0; i < count; i++ {
		addrs = append(addrs, r.portAddress())
	}
	return addrs
}

// ptpAcceptableMasters reads an ACCEPTABLE_MASTER_TABLE, capping its
// count the same way.
func ptpAcceptableMasters(r *ptpReader) PTPAcceptableMasterTable {
	count := int(r.u16())
	if count > len(r.data)/ptpAcceptableEntry {
		r.short = true
		return nil
	}

	table := make(PTPAcceptableMasterTable, 0, count)
	for i := 0; i < count; i++ {
		table = append(table, PTPAcceptableMaster{PortIdentity: r.portID(), AlternatePriority1: r.u8()})
	}
	return table
}

func ptpDefaultDataSet(r *ptpReader) PTPDefaultDataSet {
	flags := r.u8()
	r.u8() // reserved

	v := PTPDefaultDataSet{
		TwoStep:      flags&ptpMgmtFlagBit0 != 0,
		SlaveOnly:    flags&ptpMgmtFlagBit1 != 0,
		NumberPorts:  r.u16(),
		Priority1:    r.u8(),
		ClockQuality: r.quality(),
	}
	v.Priority2 = r.u8()
	v.ClockIdentity = r.clockID()
	v.Domain = r.u8()
	return v
}

func ptpParentDataSet(r *ptpReader) PTPParentDataSet {
	v := PTPParentDataSet{
		ParentPort:  r.portID(),
		ParentStats: r.u8()&ptpMgmtFlagBit0 != 0,
	}
	r.u8() // reserved

	v.ObservedVariance = r.u16()
	v.ObservedPhaseChangeRate = int32(r.u32())
	v.GrandmasterPriority1 = r.u8()
	v.GrandmasterClockQuality = r.quality()
	v.GrandmasterPriority2 = r.u8()
	v.GrandmasterIdentity = r.clockID()
	return v
}

func ptpPortDataSet(r *ptpReader) PTPPortDataSet {
	return PTPPortDataSet{
		PortIdentity:            r.portID(),
		PortState:               PTPPortState(r.u8()),
		LogMinDelayReqInterval:  int8(r.u8()),
		PeerMeanPathDelay:       r.interval(),
		LogAnnounceInterval:     int8(r.u8()),
		AnnounceReceiptTimeout:  r.u8(),
		LogSyncInterval:         int8(r.u8()),
		DelayMechanism:          PTPDelayMechanism(r.u8()),
		LogMinPdelayReqInterval: int8(r.u8()),
		VersionNumber:           r.u8() & ptpVersionMask,
	}
}
