// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO diagnosis (IEC 61158-6-10, "Coding section related to
// Diagnosis Data").
//
// A DiagnosisData block describes one submodule. The user structure
// identifier says what follows its head:
//
//	0x8000  ChannelDiagnosisData*           6 bytes each
//	0x8002  ExtChannelDiagnosisData*       12 bytes each
//	0x8003  QualifiedChannelDiagnosisData* 16 bytes each
//	other   manufacturer specific data
//
//	ChannelNumber (2), ChannelProperties (2), ChannelErrorType (2),
//	ExtChannelErrorType (2), ExtChannelAddValue (4),    extended, qualified
//	QualifiedChannelQualifier (4)                       qualified
//
// Alarm notifications carry the same entries behind the same identifiers.

package layers

import "fmt"

// ProfinetBlockDiagnosisData is the DiagnosisData block; its Value is a
// *ProfinetDiagnosisData.
const ProfinetBlockDiagnosisData ProfinetBlockType = 0x0010

const (
	profinetDiagHeadLen    = 10 // slot .. user structure identifier
	profinetDiagHeadAPILen = profinetDiagHeadLen + 4

	// profinetChannelWhole is the ChannelNumber of a diagnosis that covers
	// the whole submodule.
	profinetChannelWhole = 0x8000

	// QualifiedChannelQualifier: bit n is Qualifier_n. Bits 3-6 are advice,
	// 7-16 maintenance required, 17-26 maintenance demanded, 27-31 fault.
	profinetQualAdviceMask   uint32 = 0x00000078
	profinetQualRequiredMask uint32 = 0x0001FF80
	profinetQualDemandedMask uint32 = 0x07FE0000
	profinetQualFaultMask    uint32 = 0xF8000000

	// Ranges of the error type codes.
	profinetErrTypeManufFirst   = 0x0100
	profinetErrTypeStdFirst     = 0x8000
	profinetErrTypeProfileFirst = 0x9000
	profinetErrTypeProfileLast  = 0x9FFF
)

// ProfinetChannelDataType is ChannelProperties.Type: the width of the
// channel.
type ProfinetChannelDataType uint8

// String names the channel width.
func (t ProfinetChannelDataType) String() string {
	names := [...]string{"Submodule or unspecific", "1 Bit", "2 Bit", "4 Bit", "8 Bit", "16 Bit", "32 Bit", "64 Bit"}
	if int(t) < len(names) {
		return names[t]
	}
	return fmt.Sprintf("Reserved(%d)", uint8(t))
}

// ProfinetChannelMaintenance is ChannelProperties.Maintenance: the
// severity of a diagnosis.
type ProfinetChannelMaintenance uint8

// Severities.
const (
	ProfinetMaintenanceFault     ProfinetChannelMaintenance = 0
	ProfinetMaintenanceRequired  ProfinetChannelMaintenance = 1
	ProfinetMaintenanceDemanded  ProfinetChannelMaintenance = 2
	ProfinetMaintenanceQualified ProfinetChannelMaintenance = 3 // see QualifiedChannelQualifier
)

// String names the severity.
func (m ProfinetChannelMaintenance) String() string {
	names := [...]string{"Fault", "Maintenance required", "Maintenance demanded", "Qualified diagnosis"}
	if int(m) < len(names) {
		return names[m]
	}
	return fmt.Sprintf("Unknown(%d)", uint8(m))
}

// ProfinetChannelSpecifier is ChannelProperties.Specifier: whether the
// diagnosis comes or goes.
type ProfinetChannelSpecifier uint8

// Specifiers.
const (
	ProfinetSpecifierAllDisappear    ProfinetChannelSpecifier = 0
	ProfinetSpecifierAppears         ProfinetChannelSpecifier = 1
	ProfinetSpecifierDisappears      ProfinetChannelSpecifier = 2
	ProfinetSpecifierDisappearsOther ProfinetChannelSpecifier = 3 // others remain
)

// String names the specifier.
func (s ProfinetChannelSpecifier) String() string {
	names := [...]string{"All subsequent disappear", "Appears", "Disappears", "Disappears but others remain"}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("Unknown(%d)", uint8(s))
}

// ProfinetChannelDirection is ChannelProperties.Direction.
type ProfinetChannelDirection uint8

// Directions.
const (
	ProfinetDirectionManufacturer ProfinetChannelDirection = 0
	ProfinetDirectionInput        ProfinetChannelDirection = 1
	ProfinetDirectionOutput       ProfinetChannelDirection = 2
	ProfinetDirectionInputOutput  ProfinetChannelDirection = 3
)

// String names the direction.
func (d ProfinetChannelDirection) String() string {
	names := [...]string{"Manufacturer specific", "Input", "Output", "Input/Output"}
	if int(d) < len(names) {
		return names[d]
	}
	return fmt.Sprintf("Reserved(%d)", uint8(d))
}

// ProfinetChannelErrorType is the ChannelErrorType of a diagnosis.
type ProfinetChannelErrorType uint16

// Channel error types. 0x0100 to 0x7FFF are manufacturer specific, 0x9000
// to 0x9FFF belong to profiles.
const (
	ProfinetChannelErrShortCircuit    ProfinetChannelErrorType = 0x0001
	ProfinetChannelErrUndervoltage    ProfinetChannelErrorType = 0x0002
	ProfinetChannelErrOvervoltage     ProfinetChannelErrorType = 0x0003
	ProfinetChannelErrOverload        ProfinetChannelErrorType = 0x0004
	ProfinetChannelErrOvertemperature ProfinetChannelErrorType = 0x0005
	ProfinetChannelErrLineBreak       ProfinetChannelErrorType = 0x0006
	ProfinetChannelErrUpperLimit      ProfinetChannelErrorType = 0x0007
	ProfinetChannelErrLowerLimit      ProfinetChannelErrorType = 0x0008
	ProfinetChannelErrError           ProfinetChannelErrorType = 0x0009
	ProfinetChannelErrSimulation      ProfinetChannelErrorType = 0x000A
	ProfinetChannelErrParamMissing    ProfinetChannelErrorType = 0x000F
	ProfinetChannelErrParamFault      ProfinetChannelErrorType = 0x0010
	ProfinetChannelErrPowerSupply     ProfinetChannelErrorType = 0x0011
	ProfinetChannelErrFuse            ProfinetChannelErrorType = 0x0012
	ProfinetChannelErrCommunication   ProfinetChannelErrorType = 0x0013
	ProfinetChannelErrGround          ProfinetChannelErrorType = 0x0014
	ProfinetChannelErrReferencePoint  ProfinetChannelErrorType = 0x0015
	ProfinetChannelErrSampling        ProfinetChannelErrorType = 0x0016
	ProfinetChannelErrThreshold       ProfinetChannelErrorType = 0x0017
	ProfinetChannelErrOutputDisabled  ProfinetChannelErrorType = 0x0018
	ProfinetChannelErrSafetyEvent     ProfinetChannelErrorType = 0x0019
	ProfinetChannelErrExternal        ProfinetChannelErrorType = 0x001A
	ProfinetChannelErrTemporary       ProfinetChannelErrorType = 0x001F

	ProfinetChannelErrDataTransmission ProfinetChannelErrorType = 0x8000
	ProfinetChannelErrRemoteMismatch   ProfinetChannelErrorType = 0x8001
	ProfinetChannelErrMediaRedundancy  ProfinetChannelErrorType = 0x8002
	ProfinetChannelErrSyncMismatch     ProfinetChannelErrorType = 0x8003
	ProfinetChannelErrIsochronous      ProfinetChannelErrorType = 0x8004
	ProfinetChannelErrMulticastCR      ProfinetChannelErrorType = 0x8005
	ProfinetChannelErrFiberOptic       ProfinetChannelErrorType = 0x8007
	ProfinetChannelErrNetworkComponent ProfinetChannelErrorType = 0x8008
	ProfinetChannelErrTimeMismatch     ProfinetChannelErrorType = 0x8009
	ProfinetChannelErrFramePacking     ProfinetChannelErrorType = 0x800A
	ProfinetChannelErrMRPD             ProfinetChannelErrorType = 0x800B
	ProfinetChannelErrSystemRedundancy ProfinetChannelErrorType = 0x800C
	ProfinetChannelErrMultipleIface    ProfinetChannelErrorType = 0x800D
)

// String names the error type.
func (t ProfinetChannelErrorType) String() string {
	if name, ok := profinetChannelErrNames[t]; ok {
		return name
	}

	switch {
	case t >= profinetErrTypeManufFirst && t < profinetErrTypeStdFirst:
		return fmt.Sprintf("Manufacturer specific(0x%04x)", uint16(t))
	case t >= profinetErrTypeProfileFirst && t <= profinetErrTypeProfileLast:
		return fmt.Sprintf("Profile specific(0x%04x)", uint16(t))
	}
	return fmt.Sprintf("Reserved(0x%04x)", uint16(t))
}

var profinetChannelErrNames = map[ProfinetChannelErrorType]string{
	ProfinetChannelErrShortCircuit:     "Short circuit",
	ProfinetChannelErrUndervoltage:     "Undervoltage",
	ProfinetChannelErrOvervoltage:      "Overvoltage",
	ProfinetChannelErrOverload:         "Overload",
	ProfinetChannelErrOvertemperature:  "Overtemperature",
	ProfinetChannelErrLineBreak:        "Line break",
	ProfinetChannelErrUpperLimit:       "Upper limit value exceeded",
	ProfinetChannelErrLowerLimit:       "Lower limit value exceeded",
	ProfinetChannelErrError:            "Error",
	ProfinetChannelErrSimulation:       "Simulation active",
	ProfinetChannelErrParamMissing:     "Parameter missing",
	ProfinetChannelErrParamFault:       "Parameterization fault",
	ProfinetChannelErrPowerSupply:      "Power supply fault",
	ProfinetChannelErrFuse:             "Fuse blown or open",
	ProfinetChannelErrCommunication:    "Communication fault",
	ProfinetChannelErrGround:           "Ground fault",
	ProfinetChannelErrReferencePoint:   "Reference point lost",
	ProfinetChannelErrSampling:         "Process event lost or sampling error",
	ProfinetChannelErrThreshold:        "Threshold warning",
	ProfinetChannelErrOutputDisabled:   "Output disabled",
	ProfinetChannelErrSafetyEvent:      "Functional safety event",
	ProfinetChannelErrExternal:         "External fault",
	ProfinetChannelErrTemporary:        "Temporary fault",
	ProfinetChannelErrDataTransmission: "Data transmission impossible",
	ProfinetChannelErrRemoteMismatch:   "Remote mismatch",
	ProfinetChannelErrMediaRedundancy:  "Media redundancy mismatch",
	ProfinetChannelErrSyncMismatch:     "Sync mismatch",
	ProfinetChannelErrIsochronous:      "Isochronous mode mismatch",
	ProfinetChannelErrMulticastCR:      "Multicast CR mismatch",
	ProfinetChannelErrFiberOptic:       "Fiber optic mismatch",
	ProfinetChannelErrNetworkComponent: "Network component function mismatch",
	ProfinetChannelErrTimeMismatch:     "Time mismatch",
	ProfinetChannelErrFramePacking:     "Dynamic frame packing function mismatch",
	ProfinetChannelErrMRPD:             "Media redundancy with planned duplication mismatch",
	ProfinetChannelErrSystemRedundancy: "System redundancy mismatch",
	ProfinetChannelErrMultipleIface:    "Multiple interface mismatch",
}

// ProfinetExtChannelErrorType is the ExtChannelErrorType of an extended
// diagnosis. Its meaning depends on the ChannelErrorType next to it.
type ProfinetExtChannelErrorType uint16

// profinetExtErrAccumulative is the one extended error type every
// manufacturer and profile specific channel error type shares.
const profinetExtErrAccumulative ProfinetExtChannelErrorType = 0x8000

// profinetExtErrKey selects one extended error type of one channel error
// type.
type profinetExtErrKey struct {
	channel ProfinetChannelErrorType
	ext     ProfinetExtChannelErrorType
}

// profinetExtErrNames names the extended error types of the channel error
// types the standard defines.
var profinetExtErrNames = map[profinetExtErrKey]string{
	{ProfinetChannelErrDataTransmission, 0x8000}: "Link state mismatch - link down",
	{ProfinetChannelErrDataTransmission, 0x8001}: "MAUType mismatch",
	{ProfinetChannelErrDataTransmission, 0x8002}: "Line delay mismatch",
	{ProfinetChannelErrRemoteMismatch, 0x8000}:   "Peer name of station mismatch",
	{ProfinetChannelErrRemoteMismatch, 0x8001}:   "Peer name of port mismatch",
	{ProfinetChannelErrRemoteMismatch, 0x8002}:   "Peer RT_CLASS_3 mismatch",
	{ProfinetChannelErrRemoteMismatch, 0x8003}:   "Peer MAUType mismatch",
	{ProfinetChannelErrRemoteMismatch, 0x8004}:   "Peer MRP domain mismatch",
	{ProfinetChannelErrRemoteMismatch, 0x8005}:   "No peer detected",
	{ProfinetChannelErrRemoteMismatch, 0x8007}:   "Peer line delay mismatch",
	{ProfinetChannelErrRemoteMismatch, 0x8008}:   "Peer PTCP mismatch",
	{ProfinetChannelErrRemoteMismatch, 0x8009}:   "Peer preamble length mismatch",
	{ProfinetChannelErrRemoteMismatch, 0x800A}:   "Peer fragmentation mismatch",
	{ProfinetChannelErrMediaRedundancy, 0x8000}:  "Manager role fail",
	{ProfinetChannelErrMediaRedundancy, 0x8001}:  "MRP ring open",
	{ProfinetChannelErrMediaRedundancy, 0x8003}:  "Multiple manager",
	{ProfinetChannelErrSyncMismatch, 0x8000}:     "No sync message received",
	{ProfinetChannelErrSyncMismatch, 0x8003}:     "Jitter out of boundary",
	{ProfinetChannelErrIsochronous, 0x8000}:      "Output time failure",
	{ProfinetChannelErrIsochronous, 0x8001}:      "Input time failure",
	{ProfinetChannelErrIsochronous, 0x8002}:      "Master life sign failure",
	{ProfinetChannelErrMulticastCR, 0x8000}:      "Multicast consumer CR timed out",
	{ProfinetChannelErrMulticastCR, 0x8001}:      "Address resolution failed",
	{ProfinetChannelErrFiberOptic, 0x8000}:       "Power budget",
	{ProfinetChannelErrNetworkComponent, 0x8000}: "Frame dropped - no resource",
}

// Name names the extended error type in the context of its channel error
// type. Manufacturer and profile specific channel error types share one
// standard value, the accumulative info.
func (e ProfinetExtChannelErrorType) Name(channel ProfinetChannelErrorType) string {
	if name, ok := profinetExtErrNames[profinetExtErrKey{channel, e}]; ok {
		return name
	}

	switch {
	case e == profinetExtErrAccumulative && channel < profinetErrTypeStdFirst:
		return "Accumulative info"
	case e == 0:
		return "Unspecified"
	case e < profinetErrTypeStdFirst:
		return fmt.Sprintf("Manufacturer specific(0x%04x)", uint16(e))
	case e >= profinetErrTypeProfileFirst && e <= profinetErrTypeProfileLast:
		return fmt.Sprintf("Profile specific(0x%04x)", uint16(e))
	}
	return fmt.Sprintf("Reserved(0x%04x)", uint16(e))
}

// ProfinetChannelQualifier is QualifiedChannelQualifier: one bit per
// qualifier, grouped by severity.
type ProfinetChannelQualifier uint32

// Advice reports whether one of Qualifier_3 to Qualifier_6 is set.
func (q ProfinetChannelQualifier) Advice() bool { return uint32(q)&profinetQualAdviceMask != 0 }

// MaintenanceRequired reports whether one of Qualifier_7 to Qualifier_16
// is set.
func (q ProfinetChannelQualifier) MaintenanceRequired() bool {
	return uint32(q)&profinetQualRequiredMask != 0
}

// MaintenanceDemanded reports whether one of Qualifier_17 to Qualifier_26
// is set.
func (q ProfinetChannelQualifier) MaintenanceDemanded() bool {
	return uint32(q)&profinetQualDemandedMask != 0
}

// Fault reports whether one of Qualifier_27 to Qualifier_31 is set.
func (q ProfinetChannelQualifier) Fault() bool { return uint32(q)&profinetQualFaultMask != 0 }

// String names the severity groups that have a qualifier set.
func (q ProfinetChannelQualifier) String() string {
	s := ""
	for _, g := range []struct {
		set  bool
		name string
	}{{q.Fault(), "Fault"}, {q.MaintenanceDemanded(), "Maintenance demanded"}, {q.MaintenanceRequired(), "Maintenance required"}, {q.Advice(), "Advice"}} {
		if !g.set {
			continue
		}
		if s != "" {
			s += "|"
		}
		s += g.name
	}

	if s == "" {
		return fmt.Sprintf("0x%08x", uint32(q))
	}
	return s
}

// ProfinetChannelDiagnosis is one entry of a DiagnosisData block. The
// extended fields are set in extended and qualified diagnoses, the
// qualifier in qualified ones.
type ProfinetChannelDiagnosis struct {
	ChannelNumber             uint16
	ChannelProperties         ProfinetChannelProperties
	ChannelErrorType          ProfinetChannelErrorType
	ExtChannelErrorType       ProfinetExtChannelErrorType
	ExtChannelAddValue        uint32
	QualifiedChannelQualifier ProfinetChannelQualifier
}

// ExtErrorName names ExtChannelErrorType for this entry's channel error
// type.
func (d *ProfinetChannelDiagnosis) ExtErrorName() string {
	return d.ExtChannelErrorType.Name(d.ChannelErrorType)
}

// channelDiag reads one diagnosis entry of the given size.
func (r *profinetReader) channelDiag(size int) (d ProfinetChannelDiagnosis) {
	d.ChannelNumber = r.u16()
	d.ChannelProperties = ProfinetChannelProperties(r.u16())
	d.ChannelErrorType = ProfinetChannelErrorType(r.u16())
	if size == profinetChannelDiagLen {
		return d
	}

	d.ExtChannelErrorType = ProfinetExtChannelErrorType(r.u16())
	d.ExtChannelAddValue = r.u32()
	if size == profinetExtChannelDiagLen {
		return d
	}

	d.QualifiedChannelQualifier = ProfinetChannelQualifier(r.u32())
	return d
}

// diagEntryLen returns the entry size of a user structure identifier, or
// zero when it is not a channel diagnosis.
func (u ProfinetUSI) diagEntryLen() int {
	switch u {
	case ProfinetUSIChannelDiagnosis:
		return profinetChannelDiagLen
	case ProfinetUSIExtChannelDiagnosis:
		return profinetExtChannelDiagLen
	case ProfinetUSIQualifiedDiagnosis:
		return profinetQualChannelLen
	}
	return 0
}

// ProfinetDiagnosisData is the body of a DiagnosisData block: the
// diagnoses of one submodule. Version 1.0 has no API.
//
// Channels holds the entries of a channel, extended or qualified
// diagnosis; every other user structure is raw in Data.
type ProfinetDiagnosisData struct {
	API               uint32
	Slot              uint16
	Subslot           uint16
	ChannelNumber     uint16 // 0x8000: the whole submodule
	ChannelProperties ProfinetChannelProperties
	USI               ProfinetUSI
	Channels          []ProfinetChannelDiagnosis
	Data              []byte
}

// WholeSubmodule reports whether the block is about the submodule rather
// than one channel.
func (d *ProfinetDiagnosisData) WholeSubmodule() bool {
	return d.ChannelNumber == profinetChannelWhole
}

func decodeProfinetDiagnosis(r *profinetReader, low uint8) interface{} {
	min := profinetDiagHeadLen
	if low == profinetBlockVersionLowAPI {
		min = profinetDiagHeadAPILen
	}
	if low > profinetBlockVersionLowAPI || r.left() < min {
		return nil
	}

	d := &ProfinetDiagnosisData{}
	if low == profinetBlockVersionLowAPI {
		d.API = r.u32()
	}
	d.Slot = r.u16()
	d.Subslot = r.u16()
	d.ChannelNumber = r.u16()
	d.ChannelProperties = ProfinetChannelProperties(r.u16())
	d.USI = ProfinetUSI(r.u16())

	size := d.USI.diagEntryLen()
	if size == 0 {
		d.Data = r.rest()
		return d
	}

	// Whole entries only; a cut one stays in Data.
	d.Channels = make([]ProfinetChannelDiagnosis, r.left()/size)
	for i := range d.Channels {
		d.Channels[i] = r.channelDiag(size)
	}
	d.Data = r.rest()
	return d
}
