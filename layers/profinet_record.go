// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO record data.
//
// The record data of a read response or a write request follows its
// header block. What it holds depends on the record index (IEC 61158-6-10,
// "Coding of the field Index"):
//
//	0x0000-0x7FFF  user specific, raw
//	0x8000-0xAFFF  one subslot       0xB000-0xBFFF  profile, raw
//	0xC000-0xCFFF  one slot          0xD000-0xDFFF  profile, raw
//	0xE000-0xEBFF  one AR            0xEC00-0xEFFF  profile, raw
//	0xF000-0xF3FF  one API           0xF400-0xF7FF  profile, raw
//	0xF800-0xFBFF  the device
//
// The indices of the standard carry a run of blocks, which is decoded
// into ProfinetRecordBlock.Blocks.

package layers

import "fmt"

// ProfinetRecordIndex is the Index of a record.
type ProfinetRecordIndex uint16

// Record indices. Diagnosis indices exist once per scope: add the low
// byte to the base of the subslot, slot, AR or API range.
const (
	ProfinetIndexExpectedIdent    ProfinetRecordIndex = 0x8000
	ProfinetIndexRealIdent        ProfinetRecordIndex = 0x8001
	ProfinetIndexDiagChannel      ProfinetRecordIndex = 0x800A
	ProfinetIndexDiagAll          ProfinetRecordIndex = 0x800B
	ProfinetIndexDiagMaintQual    ProfinetRecordIndex = 0x800C
	ProfinetIndexMaintReqChannel  ProfinetRecordIndex = 0x8010
	ProfinetIndexMaintDemChannel  ProfinetRecordIndex = 0x8011
	ProfinetIndexMaintReqAll      ProfinetRecordIndex = 0x8012
	ProfinetIndexMaintDemAll      ProfinetRecordIndex = 0x8013
	ProfinetIndexSubstituteValue  ProfinetRecordIndex = 0x801E
	ProfinetIndexPDIRSubframeData ProfinetRecordIndex = 0x8020
	ProfinetIndexPDPortRealExt    ProfinetRecordIndex = 0x8027
	ProfinetIndexRecordInput      ProfinetRecordIndex = 0x8028
	ProfinetIndexRecordOutput     ProfinetRecordIndex = 0x8029
	ProfinetIndexPDPortDataReal   ProfinetRecordIndex = 0x802A
	ProfinetIndexPDPortDataCheck  ProfinetRecordIndex = 0x802B
	ProfinetIndexPDIRData         ProfinetRecordIndex = 0x802C
	ProfinetIndexPDSyncData       ProfinetRecordIndex = 0x802D
	ProfinetIndexPDPortDataAdjust ProfinetRecordIndex = 0x802F
	ProfinetIndexIsochronousMode  ProfinetRecordIndex = 0x8030
	ProfinetIndexPDTimeData       ProfinetRecordIndex = 0x8031
	ProfinetIndexPDIfMrpReal      ProfinetRecordIndex = 0x8050
	ProfinetIndexPDIfMrpCheck     ProfinetRecordIndex = 0x8051
	ProfinetIndexPDIfMrpAdjust    ProfinetRecordIndex = 0x8052
	ProfinetIndexPDPortMrpAdjust  ProfinetRecordIndex = 0x8053
	ProfinetIndexPDPortMrpReal    ProfinetRecordIndex = 0x8054
	ProfinetIndexPDPortMrpIcAdj   ProfinetRecordIndex = 0x8055
	ProfinetIndexPDPortMrpIcCheck ProfinetRecordIndex = 0x8056
	ProfinetIndexPDPortMrpIcReal  ProfinetRecordIndex = 0x8057
	ProfinetIndexPDPortFOReal     ProfinetRecordIndex = 0x8060
	ProfinetIndexPDPortFOCheck    ProfinetRecordIndex = 0x8061
	ProfinetIndexPDPortFOAdjust   ProfinetRecordIndex = 0x8062
	ProfinetIndexPDPortSFPCheck   ProfinetRecordIndex = 0x8063
	ProfinetIndexPDNCDataCheck    ProfinetRecordIndex = 0x8070
	ProfinetIndexPDIfAdjust       ProfinetRecordIndex = 0x8071
	ProfinetIndexPDPortStatistic  ProfinetRecordIndex = 0x8072
	ProfinetIndexPDIfDataReal     ProfinetRecordIndex = 0x8080
	ProfinetIndexPDIfFSUAdjust    ProfinetRecordIndex = 0x8090
	ProfinetIndexPROFIenergy      ProfinetRecordIndex = 0x80A0
	ProfinetIndexPEEntityStatus   ProfinetRecordIndex = 0x80AF
	ProfinetIndexCombinedObject   ProfinetRecordIndex = 0x80B0
	ProfinetIndexRSAdjustObserver ProfinetRecordIndex = 0x80CF
	ProfinetIndexIM0              ProfinetRecordIndex = 0xAFF0
	ProfinetIndexIM1              ProfinetRecordIndex = 0xAFF1
	ProfinetIndexIM2              ProfinetRecordIndex = 0xAFF2
	ProfinetIndexIM3              ProfinetRecordIndex = 0xAFF3
	ProfinetIndexIM4              ProfinetRecordIndex = 0xAFF4
	ProfinetIndexIM5              ProfinetRecordIndex = 0xAFF5
	ProfinetIndexModuleDiff       ProfinetRecordIndex = 0xE002
	ProfinetIndexMultipleWrite    ProfinetRecordIndex = 0xE040
	ProfinetIndexARFSUDataAdjust  ProfinetRecordIndex = 0xE050
	ProfinetIndexRSGetEvent       ProfinetRecordIndex = 0xE060
	ProfinetIndexRSAckEvent       ProfinetRecordIndex = 0xE061
	ProfinetIndexARDataAPI        ProfinetRecordIndex = 0xF020
	ProfinetIndexDiagDevice       ProfinetRecordIndex = 0xF80C
	ProfinetIndexARData           ProfinetRecordIndex = 0xF820
	ProfinetIndexAPIData          ProfinetRecordIndex = 0xF821
	ProfinetIndexLogBookData      ProfinetRecordIndex = 0xF830
	ProfinetIndexPDevData         ProfinetRecordIndex = 0xF831
	ProfinetIndexIM0FilterData    ProfinetRecordIndex = 0xF840
	ProfinetIndexPDRealData       ProfinetRecordIndex = 0xF841
	ProfinetIndexPDExpectedData   ProfinetRecordIndex = 0xF842
	ProfinetIndexAutoConfig       ProfinetRecordIndex = 0xF850
	ProfinetIndexGSDUpload        ProfinetRecordIndex = 0xF860
	ProfinetIndexPEEntityFilter   ProfinetRecordIndex = 0xF870
	ProfinetIndexPEEntityStatusAR ProfinetRecordIndex = 0xF871
	ProfinetIndexAssetManagement  ProfinetRecordIndex = 0xF880
	ProfinetIndexRPCTrigger       ProfinetRecordIndex = 0xFBFF
)

// Bounds of the index ranges.
const (
	profinetIndexStandardFirst ProfinetRecordIndex = 0x8000
	profinetIndexSlotFirst     ProfinetRecordIndex = 0xC000
	profinetIndexARFirst       ProfinetRecordIndex = 0xE000
	profinetIndexAPIFirst      ProfinetRecordIndex = 0xF000
	profinetIndexDeviceFirst   ProfinetRecordIndex = 0xF800
	profinetIndexReservedFirst ProfinetRecordIndex = 0xFC00

	// The profile ranges inside each scope.
	profinetIndexSubslotProfile ProfinetRecordIndex = 0xB000
	profinetIndexSlotProfile    ProfinetRecordIndex = 0xD000
	profinetIndexARProfile      ProfinetRecordIndex = 0xEC00
	profinetIndexAPIProfile     ProfinetRecordIndex = 0xF400

	// profinetIndexScopeMask selects the part of a diagnosis index that
	// is the same in every scope.
	profinetIndexScopeMask ProfinetRecordIndex = 0x0FFF
)

// IsUser reports whether the index is user specific: the record data has
// no layout the standard knows.
func (i ProfinetRecordIndex) IsUser() bool { return i < profinetIndexStandardFirst }

// IsProfile reports whether the index belongs to a profile range.
func (i ProfinetRecordIndex) IsProfile() bool {
	switch {
	case i >= profinetIndexSubslotProfile && i < profinetIndexSlotFirst,
		i >= profinetIndexSlotProfile && i < profinetIndexARFirst,
		i >= profinetIndexARProfile && i < profinetIndexAPIFirst,
		i >= profinetIndexAPIProfile && i < profinetIndexDeviceFirst:
		return true
	}
	return false
}

// HoldsBlocks reports whether the record data of the index is a run of
// blocks. MultipleWrite is not: its write headers follow as blocks of the
// PDU itself.
func (i ProfinetRecordIndex) HoldsBlocks() bool {
	if i.IsUser() || i.IsProfile() || i >= profinetIndexReservedFirst {
		return false
	}
	return i != ProfinetIndexMultipleWrite && i != ProfinetIndexRPCTrigger
}

// scope names the range of the index and returns the index moved into
// the subslot range, where the shared names are defined.
func (i ProfinetRecordIndex) scope() (string, ProfinetRecordIndex) {
	base := profinetIndexStandardFirst | i&profinetIndexScopeMask

	switch {
	case i >= profinetIndexDeviceFirst:
		return "device", i
	case i >= profinetIndexAPIFirst:
		return "one API", base
	case i >= profinetIndexARFirst:
		return "one AR", base
	case i >= profinetIndexSlotFirst:
		return "one slot", base
	}
	return "one subslot", i
}

// String names the index after the record it addresses.
func (i ProfinetRecordIndex) String() string {
	if name, ok := profinetIndexNames[i]; ok {
		return name
	}

	// The identification and diagnosis records repeat in every scope.
	scope, base := i.scope()
	switch base {
	case ProfinetIndexExpectedIdent, ProfinetIndexRealIdent, ProfinetIndexDiagChannel, ProfinetIndexDiagAll,
		ProfinetIndexDiagMaintQual, ProfinetIndexMaintReqChannel, ProfinetIndexMaintDemChannel,
		ProfinetIndexMaintReqAll, ProfinetIndexMaintDemAll:
		return profinetIndexNames[base] + " for " + scope
	}

	switch {
	case i.IsUser():
		return fmt.Sprintf("User specific(0x%04x)", uint16(i))
	case i.IsProfile():
		return fmt.Sprintf("Profile specific(0x%04x)", uint16(i))
	}
	return fmt.Sprintf("Reserved(0x%04x)", uint16(i))
}

// profinetIndexNames names the record indices.
var profinetIndexNames = map[ProfinetRecordIndex]string{
	ProfinetIndexExpectedIdent:    "ExpectedIdentificationData",
	ProfinetIndexRealIdent:        "RealIdentificationData",
	ProfinetIndexDiagChannel:      "Diagnosis in channel coding",
	ProfinetIndexDiagAll:          "Diagnosis in all codings",
	ProfinetIndexDiagMaintQual:    "Diagnosis, Maintenance, Qualified and Status",
	ProfinetIndexMaintReqChannel:  "Maintenance required in channel coding",
	ProfinetIndexMaintDemChannel:  "Maintenance demanded in channel coding",
	ProfinetIndexMaintReqAll:      "Maintenance required in all codings",
	ProfinetIndexMaintDemAll:      "Maintenance demanded in all codings",
	ProfinetIndexSubstituteValue:  "SubstituteValue",
	ProfinetIndexPDIRSubframeData: "PDIRSubframeData",
	ProfinetIndexPDPortRealExt:    "PDPortDataRealExtended",
	ProfinetIndexRecordInput:      "RecordInputDataObjectElement",
	ProfinetIndexRecordOutput:     "RecordOutputDataObjectElement",
	ProfinetIndexPDPortDataReal:   "PDPortDataReal",
	ProfinetIndexPDPortDataCheck:  "PDPortDataCheck",
	ProfinetIndexPDIRData:         "PDIRData",
	ProfinetIndexPDSyncData:       "PDSyncData",
	ProfinetIndexPDPortDataAdjust: "PDPortDataAdjust",
	ProfinetIndexIsochronousMode:  "IsochronousModeData",
	ProfinetIndexPDTimeData:       "PDTimeData",
	ProfinetIndexPDIfMrpReal:      "PDInterfaceMrpDataReal",
	ProfinetIndexPDIfMrpCheck:     "PDInterfaceMrpDataCheck",
	ProfinetIndexPDIfMrpAdjust:    "PDInterfaceMrpDataAdjust",
	ProfinetIndexPDPortMrpAdjust:  "PDPortMrpDataAdjust",
	ProfinetIndexPDPortMrpReal:    "PDPortMrpDataReal",
	ProfinetIndexPDPortMrpIcAdj:   "PDPortMrpIcDataAdjust",
	ProfinetIndexPDPortMrpIcCheck: "PDPortMrpIcDataCheck",
	ProfinetIndexPDPortMrpIcReal:  "PDPortMrpIcDataReal",
	ProfinetIndexPDPortFOReal:     "PDPortFODataReal",
	ProfinetIndexPDPortFOCheck:    "PDPortFODataCheck",
	ProfinetIndexPDPortFOAdjust:   "PDPortFODataAdjust",
	ProfinetIndexPDPortSFPCheck:   "PDPortSFPDataCheck",
	ProfinetIndexPDNCDataCheck:    "PDNCDataCheck",
	ProfinetIndexPDIfAdjust:       "PDInterfaceAdjust",
	ProfinetIndexPDPortStatistic:  "PDPortStatistic",
	ProfinetIndexPDIfDataReal:     "PDInterfaceDataReal",
	ProfinetIndexPDIfFSUAdjust:    "PDInterfaceFSUDataAdjust",
	ProfinetIndexPROFIenergy:      "PROFIenergy",
	ProfinetIndexPEEntityStatus:   "PE_EntityStatusData for one subslot",
	ProfinetIndexCombinedObject:   "CombinedObjectContainer",
	ProfinetIndexRSAdjustObserver: "RS_AdjustObserver",
	ProfinetIndexIM0:              "I&M0",
	ProfinetIndexIM1:              "I&M1",
	ProfinetIndexIM2:              "I&M2",
	ProfinetIndexIM3:              "I&M3",
	ProfinetIndexIM4:              "I&M4",
	ProfinetIndexIM5:              "I&M5",
	ProfinetIndexModuleDiff:       "ModuleDiffBlock for one AR",
	ProfinetIndexMultipleWrite:    "MultipleWrite",
	ProfinetIndexARFSUDataAdjust:  "ARFSUDataAdjust",
	ProfinetIndexRSGetEvent:       "RS_GetEvent",
	ProfinetIndexRSAckEvent:       "RS_AckEvent",
	ProfinetIndexARDataAPI:        "ARData for one API",
	ProfinetIndexDiagDevice:       "Diagnosis, Maintenance, Qualified and Status for one device",
	ProfinetIndexARData:           "ARData",
	ProfinetIndexAPIData:          "APIData",
	ProfinetIndexLogBookData:      "LogBookData",
	ProfinetIndexPDevData:         "PDevData",
	ProfinetIndexIM0FilterData:    "I&M0FilterData",
	ProfinetIndexPDRealData:       "PDRealData",
	ProfinetIndexPDExpectedData:   "PDExpectedData",
	ProfinetIndexAutoConfig:       "AutoConfiguration",
	ProfinetIndexGSDUpload:        "GSD upload",
	ProfinetIndexPEEntityFilter:   "PE_EntityFilterData",
	ProfinetIndexPEEntityStatusAR: "PE_EntityStatusData",
	ProfinetIndexAssetManagement:  "AssetManagementData",
	ProfinetIndexRPCTrigger:       "Trigger index for the RPC connection monitoring",
}
