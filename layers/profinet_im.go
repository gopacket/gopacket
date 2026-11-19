// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO identification blocks: I&M records, the identification
// data of the real and the expected configuration, and asset management
// (IEC 61158-6-10, "Coding section related to I&M Records" and
// "... related to Identification Data").
//
// Visible strings have a fixed size and are padded with spaces; they are
// kept as sent.

package layers

// Block types of the identification records. Each names the type of
// ProfinetBlock.Value.
const (
	ProfinetBlockExpectedIdent   ProfinetBlockType = 0x0012 // *ProfinetIdentification
	ProfinetBlockRealIdent       ProfinetBlockType = 0x0013 // *ProfinetIdentification
	ProfinetBlockIM0             ProfinetBlockType = 0x0020 // *ProfinetIM0
	ProfinetBlockIM1             ProfinetBlockType = 0x0021 // *ProfinetIM1
	ProfinetBlockIM2             ProfinetBlockType = 0x0022 // *ProfinetIM2
	ProfinetBlockIM3             ProfinetBlockType = 0x0023 // *ProfinetIM3
	ProfinetBlockIM4             ProfinetBlockType = 0x0024 // *ProfinetIM4
	ProfinetBlockIM5             ProfinetBlockType = 0x0025 // *ProfinetEntryCount, I&M5Data in Blocks
	ProfinetBlockIM0FilterSubmod ProfinetBlockType = 0x0030 // *ProfinetIdentification
	ProfinetBlockIM0FilterModule ProfinetBlockType = 0x0031 // *ProfinetIdentification
	ProfinetBlockIM0FilterDevice ProfinetBlockType = 0x0032 // *ProfinetIdentification
	ProfinetBlockIM5Data         ProfinetBlockType = 0x0034 // *ProfinetIM5Data
	ProfinetBlockAssetManagement ProfinetBlockType = 0x0035 // *ProfinetEntryCount, AM_* in Blocks
	ProfinetBlockAMFullInfo      ProfinetBlockType = 0x0036 // *ProfinetAssetInfo
	ProfinetBlockAMHardwareOnly  ProfinetBlockType = 0x0037 // *ProfinetAssetInfo
	ProfinetBlockAMFirmwareOnly  ProfinetBlockType = 0x0038 // *ProfinetAssetInfo
)

// profinetBlockVersionLowAPI is the BlockVersionLow that adds the API
// level to identification and diagnosis data.
const profinetBlockVersionLowAPI = 1

// Sizes of the I&M fields and the smallest bodies and list elements.
const (
	profinetIMOrderIDLen     = 20
	profinetIMSerialLen      = 16
	profinetIMTagFunctionLen = 32
	profinetIMTagLocationLen = 22
	profinetIMDateLen        = 16
	profinetIMDescriptorLen  = 54
	profinetIMSignatureLen   = 54
	profinetIMLongStringLen  = 64 // IM_Annotation, IM_OrderID, AM revisions
	profinetAMLocationLen    = 16

	profinetIM0Len      = 54
	profinetIM1Len      = profinetIMTagFunctionLen + profinetIMTagLocationLen
	profinetIM5DataLen  = 2*profinetIMLongStringLen + 24
	profinetAMCommonLen = 2 + profinetUUIDLen + profinetAMLocationLen + 2*profinetIMLongStringLen
	profinetAMFullLen   = profinetAMCommonLen + 2*profinetIMLongStringLen + 32
	profinetAMHWOnlyLen = profinetAMCommonLen + profinetIMLongStringLen + 28
	profinetAMFWOnlyLen = profinetAMCommonLen + profinetIMLongStringLen + 32

	profinetIdentSubmoduleLen = 6 // subslot, ident number
	profinetIdentModuleMinLen = 8 // slot, ident number, count
	profinetIdentAPIMinLen    = 6 // API, count

	profinetIMSupportedMax      = 15 // I&M1 .. I&M15
	profinetAMLocationLevels    = 12
	profinetAMLocationLevelBits = 10
	profinetAMLevelMask         = 0x3FF
)

// ProfinetEntryCount is the body of a block that only counts the blocks
// nested in it: I&M5 and AssetManagementData.
type ProfinetEntryCount struct {
	NumberOfEntries uint16
}

// decodeProfinetEntries reads NumberOfEntries and the blocks behind it.
func decodeProfinetEntries(r *profinetReader, b *ProfinetBlock) interface{} {
	if r.left() < 2 {
		return nil
	}

	v := &ProfinetEntryCount{NumberOfEntries: r.u16()}
	b.Blocks = r.blocks()
	return v
}

// ProfinetSWRevision is IM_Software_Revision: a prefix letter (V released,
// R revision, P prototype, U under test, T test device) and three numbers.
type ProfinetSWRevision struct {
	Prefix                byte
	FunctionalEnhancement uint8
	BugFix                uint8
	InternalChange        uint8
}

func (r *profinetReader) swRevision() ProfinetSWRevision {
	return ProfinetSWRevision{Prefix: r.u8(), FunctionalEnhancement: r.u8(), BugFix: r.u8(), InternalChange: r.u8()}
}

// ProfinetIMSupported is IM_Supported: bit n set means I&Mn is supported.
type ProfinetIMSupported uint16

// Supports reports whether record I&Mn (1 to 15) is supported.
func (s ProfinetIMSupported) Supports(n int) bool {
	if n < 1 || n > profinetIMSupportedMax {
		return false
	}
	return s&(1<<uint(n)) != 0
}

// ProfinetIM0 is the I&M0 record: who made the submodule and which
// revision it is.
type ProfinetIM0 struct {
	VendorID            uint16 // VendorIDHigh, VendorIDLow
	OrderID             string
	SerialNumber        string
	HardwareRevision    uint16
	SoftwareRevision    ProfinetSWRevision
	RevisionCounter     uint16
	ProfileID           uint16
	ProfileSpecificType uint16
	VersionMajor        uint8
	VersionMinor        uint8
	Supported           ProfinetIMSupported
}

func decodeProfinetIM0(r *profinetReader) interface{} {
	if r.left() < profinetIM0Len {
		return nil
	}

	return &ProfinetIM0{
		VendorID:            r.u16(),
		OrderID:             r.str(profinetIMOrderIDLen),
		SerialNumber:        r.str(profinetIMSerialLen),
		HardwareRevision:    r.u16(),
		SoftwareRevision:    r.swRevision(),
		RevisionCounter:     r.u16(),
		ProfileID:           r.u16(),
		ProfileSpecificType: r.u16(),
		VersionMajor:        r.u8(),
		VersionMinor:        r.u8(),
		Supported:           ProfinetIMSupported(r.u16()),
	}
}

// ProfinetIM1 is the I&M1 record.
type ProfinetIM1 struct {
	TagFunction string
	TagLocation string
}

// ProfinetIM2 is the I&M2 record: the installation date, "YYYY-MM-DD HH:MM".
type ProfinetIM2 struct {
	Date string
}

// ProfinetIM3 is the I&M3 record.
type ProfinetIM3 struct {
	Descriptor string
}

// ProfinetIM4 is the I&M4 record: a signature set by the profile.
type ProfinetIM4 struct {
	Signature []byte
}

func decodeProfinetIM1(r *profinetReader) interface{} {
	if r.left() < profinetIM1Len {
		return nil
	}
	return &ProfinetIM1{TagFunction: r.str(profinetIMTagFunctionLen), TagLocation: r.str(profinetIMTagLocationLen)}
}

func decodeProfinetIM2(r *profinetReader) interface{} {
	if r.left() < profinetIMDateLen {
		return nil
	}
	return &ProfinetIM2{Date: r.str(profinetIMDateLen)}
}

func decodeProfinetIM3(r *profinetReader) interface{} {
	if r.left() < profinetIMDescriptorLen {
		return nil
	}
	return &ProfinetIM3{Descriptor: r.str(profinetIMDescriptorLen)}
}

func decodeProfinetIM4(r *profinetReader) interface{} {
	if r.left() < profinetIMSignatureLen {
		return nil
	}
	return &ProfinetIM4{Signature: r.bytes(profinetIMSignatureLen)}
}

// ProfinetIM5Data is one I&M5Data block: the identification of one
// communication module.
type ProfinetIM5Data struct {
	Annotation       string
	OrderID          string
	VendorID         uint16
	SerialNumber     string
	HardwareRevision uint16
	SoftwareRevision ProfinetSWRevision
}

func decodeProfinetIM5Data(r *profinetReader) interface{} {
	if r.left() < profinetIM5DataLen {
		return nil
	}

	return &ProfinetIM5Data{
		Annotation:       r.str(profinetIMLongStringLen),
		OrderID:          r.str(profinetIMLongStringLen),
		VendorID:         r.u16(),
		SerialNumber:     r.str(profinetIMSerialLen),
		HardwareRevision: r.u16(),
		SoftwareRevision: r.swRevision(),
	}
}

// ProfinetIdentSubmodule is one submodule of an identification list.
type ProfinetIdentSubmodule struct {
	Subslot              uint16
	SubmoduleIdentNumber uint32
}

// ProfinetIdentModule is one module of an identification list.
type ProfinetIdentModule struct {
	Slot              uint16
	ModuleIdentNumber uint32
	Submodules        []ProfinetIdentSubmodule
}

// ProfinetIdentAPI is the modules of one API.
type ProfinetIdentAPI struct {
	API     uint32
	Modules []ProfinetIdentModule
}

// ProfinetIdentification is the body of RealIdentificationData,
// ExpectedIdentificationData and the three I&M0FilterData blocks: modules
// and submodules by API. Version 1.0 of the identification data has no API
// level; its modules are returned under API 0.
type ProfinetIdentification struct {
	APIs []ProfinetIdentAPI
}

// profinetIdentLevels says whether a block opens with the API list.
type profinetIdentLevels uint8

const (
	profinetIdentWithAPI profinetIdentLevels = iota
	profinetIdentNoAPI
)

func decodeProfinetIdent(r *profinetReader, levels profinetIdentLevels) interface{} {
	if r.left() < 2 {
		return nil
	}

	id := &ProfinetIdentification{}
	if levels == profinetIdentNoAPI {
		id.APIs = []ProfinetIdentAPI{{Modules: r.identModules()}}
		return id
	}

	id.APIs = make([]ProfinetIdentAPI, r.count(profinetIdentAPIMinLen))
	for i := range id.APIs {
		id.APIs[i].API = r.u32()
		id.APIs[i].Modules = r.identModules()
	}
	return id
}

// identModules reads a counted list of modules and their submodules.
func (r *profinetReader) identModules() []ProfinetIdentModule {
	mods := make([]ProfinetIdentModule, r.count(profinetIdentModuleMinLen))
	for i := range mods {
		m := &mods[i]
		m.Slot = r.u16()
		m.ModuleIdentNumber = r.u32()

		m.Submodules = make([]ProfinetIdentSubmodule, r.count(profinetIdentSubmoduleLen))
		for j := range m.Submodules {
			m.Submodules[j] = ProfinetIdentSubmodule{Subslot: r.u16(), SubmoduleIdentNumber: r.u32()}
		}
	}
	return mods
}

// ProfinetAMLocation is AM_Location: where an asset sits. The low byte
// selects the structure: 1 a tree of up to twelve 10-bit levels, 2 the
// slot and subslot of a submodule.
type ProfinetAMLocation [profinetAMLocationLen]byte

// Structure returns AM_Location.Structure: 1 level tree, 2 slot and
// subslot.
func (l ProfinetAMLocation) Structure() uint8 { return l[profinetAMLocationLen-1] }

// Level returns level n (0 to 11) of a level tree location; 0x3FF marks an
// unused level. The levels follow the structure byte, 10 bits each, from
// the low end of the 128-bit value.
func (l ProfinetAMLocation) Level(n int) uint16 {
	if n < 0 || n >= profinetAMLocationLevels {
		return 0
	}

	// Collect the three bytes that can hold the level, low byte first.
	bit := 8 + n*profinetAMLocationLevelBits
	var v uint32
	for i := 0; i < 3; i++ {
		idx := profinetAMLocationLen - 1 - bit/8 - i
		if idx >= 0 {
			v |= uint32(l[idx]) << (8 * uint(i))
		}
	}
	return uint16(v>>(uint(bit)%8)) & profinetAMLevelMask
}

// Levels returns the twelve levels of a level tree location.
func (l ProfinetAMLocation) Levels() [profinetAMLocationLevels]uint16 {
	var levels [profinetAMLocationLevels]uint16
	for i := range levels {
		levels[i] = l.Level(i)
	}
	return levels
}

// Offsets of the fields of a slot and subslot location. A reserved byte
// sits between the structure byte and BeginSlotNumber.
const (
	profinetAMBeginSlotOff    = 12
	profinetAMBeginSubslotOff = 10
	profinetAMEndSlotOff      = 8
	profinetAMEndSubslotOff   = 6
)

func (l ProfinetAMLocation) word(off int) uint16 { return uint16(l[off])<<8 | uint16(l[off+1]) }

// BeginSlot returns the first slot of a slot and subslot location.
func (l ProfinetAMLocation) BeginSlot() uint16 { return l.word(profinetAMBeginSlotOff) }

// BeginSubslot returns the first subslot of a slot and subslot location.
func (l ProfinetAMLocation) BeginSubslot() uint16 { return l.word(profinetAMBeginSubslotOff) }

// EndSlot returns the last slot of a slot and subslot location.
func (l ProfinetAMLocation) EndSlot() uint16 { return l.word(profinetAMEndSlotOff) }

// EndSubslot returns the last subslot of a slot and subslot location.
func (l ProfinetAMLocation) EndSubslot() uint16 { return l.word(profinetAMEndSubslotOff) }

// ProfinetAMDeviceID is AM_DeviceIdentification: the organization that
// assigned the vendor ID (0 PROFINET) and the IDs it scopes.
type ProfinetAMDeviceID struct {
	Organization uint16
	VendorID     uint16
	DeviceID     uint16
	DeviceSubID  uint16
}

// ProfinetAssetInfo is one asset: the body of AM_FullInformation,
// AM_HardwareOnlyInformation and AM_FirmwareOnlyInformation. The hardware
// only block has no software revisions, the firmware only block no
// hardware revisions.
type ProfinetAssetInfo struct {
	UniqueIdentifier   ProfinetUUID
	Location           ProfinetAMLocation
	Annotation         string
	OrderID            string
	SoftwareRevision   string // AM_SoftwareRevision
	HardwareRevision   string // AM_HardwareRevision
	SerialNumber       string
	IMSoftwareRevision ProfinetSWRevision
	DeviceID           ProfinetAMDeviceID
	TypeIdentification uint16
	IMHardwareRevision uint16
}

func decodeProfinetAssetInfo(r *profinetReader, t ProfinetBlockType) interface{} {
	min := profinetAMFullLen
	switch t {
	case ProfinetBlockAMHardwareOnly:
		min = profinetAMHWOnlyLen
	case ProfinetBlockAMFirmwareOnly:
		min = profinetAMFWOnlyLen
	}
	if r.left() < min {
		return nil
	}

	r.skip(2)
	a := &ProfinetAssetInfo{UniqueIdentifier: r.uuid()}
	copy(a.Location[:], r.bytes(profinetAMLocationLen))
	a.Annotation = r.str(profinetIMLongStringLen)
	a.OrderID = r.str(profinetIMLongStringLen)

	if t != ProfinetBlockAMHardwareOnly {
		a.SoftwareRevision = r.str(profinetIMLongStringLen)
	}
	if t != ProfinetBlockAMFirmwareOnly {
		a.HardwareRevision = r.str(profinetIMLongStringLen)
	}

	a.SerialNumber = r.str(profinetIMSerialLen)
	if t != ProfinetBlockAMHardwareOnly {
		a.IMSoftwareRevision = r.swRevision()
	}

	a.DeviceID = ProfinetAMDeviceID{Organization: r.u16(), VendorID: r.u16(), DeviceID: r.u16(), DeviceSubID: r.u16()}
	a.TypeIdentification = r.u16()
	if t != ProfinetBlockAMFirmwareOnly {
		a.IMHardwareRevision = r.u16()
	}
	return a
}
