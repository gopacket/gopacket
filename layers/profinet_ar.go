// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO blocks about application relations: the optional blocks of
// a connect request and the records that describe ARs, IO data and
// PROFIenergy entities (IEC 61158-6-10, "Coding section related to AR
// establishment" and "... related to Read and Write").

package layers

import "fmt"

// AR block types. Each names the type of ProfinetBlock.Value; "+Blocks"
// marks the containers.
const (
	ProfinetBlockSubstituteValue ProfinetBlockType = 0x0014 // *ProfinetSubstituteValue
	ProfinetBlockRecordInput     ProfinetBlockType = 0x0015 // *ProfinetRecordIOData
	ProfinetBlockRecordOutput    ProfinetBlockType = 0x0016 // *ProfinetRecordIOData +Blocks
	ProfinetBlockARData          ProfinetBlockType = 0x0018 // *ProfinetARData
	ProfinetBlockLogBookData     ProfinetBlockType = 0x0019 // *ProfinetLogBookData
	ProfinetBlockAPIData         ProfinetBlockType = 0x001A // *ProfinetAPIData
	ProfinetBlockSRLData         ProfinetBlockType = 0x001B // *ProfinetSRLData
	ProfinetBlockPrmServerReq    ProfinetBlockType = 0x0105 // *ProfinetPrmServerBlock
	ProfinetBlockMCRReq          ProfinetBlockType = 0x0106 // *ProfinetMCRBlock
	ProfinetBlockARRPCReq        ProfinetBlockType = 0x0107 // *ProfinetARRPCBlock
	ProfinetBlockARVendorReq     ProfinetBlockType = 0x0108 // *ProfinetARVendorBlock
	ProfinetBlockIRInfo          ProfinetBlockType = 0x0109 // *ProfinetIRInfoBlock
	ProfinetBlockSRInfo          ProfinetBlockType = 0x010A // *ProfinetSRInfoBlock
	ProfinetBlockARFSU           ProfinetBlockType = 0x010B // Blocks only
	ProfinetBlockRSInfo          ProfinetBlockType = 0x010C // *ProfinetRSInfoBlock
	ProfinetBlockSubmoduleList   ProfinetBlockType = 0x0119 // *ProfinetSubmoduleList
	ProfinetBlockARUUIDReq       ProfinetBlockType = 0x011B // *ProfinetARUUIDBlock
	ProfinetBlockARUUID          ProfinetBlockType = 0x06E1 // *ProfinetARUUIDBlock
	ProfinetBlockPERequest       ProfinetBlockType = 0x0800 // *ProfinetPEService
	ProfinetBlockPEResponse      ProfinetBlockType = 0x0801 // *ProfinetPEService
	ProfinetBlockPEEntityFilter  ProfinetBlockType = 0x0810 // *ProfinetIdentification
	ProfinetBlockPEEntityStatus  ProfinetBlockType = 0x0811 // *ProfinetPEEntityStatus
	ProfinetBlockPrmServerRes    ProfinetBlockType = 0x8105 // *ProfinetPrmServerBlock
	ProfinetBlockARRPCRes        ProfinetBlockType = 0x8107 // *ProfinetARRPCBlock
	ProfinetBlockARVendorRes     ProfinetBlockType = 0x8108 // *ProfinetARVendorBlock
)

// Smallest bodies and list elements.
const (
	profinetARDataARMinLen   = 60 // version 1.0, empty names, no lists
	profinetARDataAR11MinLen = 72
	profinetARDataIOCRLen    = 16
	profinetARDataIOCR11Len  = 12
	profinetLogBookHeadLen   = 10
	profinetLogEntryLen      = 32
	profinetPrmServerMinLen  = 24
	profinetMCRMinLen        = 10
	profinetARVendorMinLen   = 6
	profinetIRInfoMinLen     = 22
	profinetIRInfoIOCRLen    = 8
	profinetSRInfoLen        = 6
	profinetRSInfoLen        = 6
	profinetSubmodEntryLen   = 8
	profinetRecordInputMin   = 6
	profinetRecordOutputMin  = 8
	profinetPEServiceLen     = 4
	profinetPEModuleMinLen   = 4
	profinetPESubmoduleLen   = 4
	profinetPEAPIMinLen      = 6
)

// Bits and fields of the AR bit fields.
const (
	profinetARPropSupervisor   uint32 = 0x8
	profinetARPropPrmServer    uint32 = 0x10
	profinetARPropCompanionSh         = 9
	profinetARPropAckCompanion uint32 = 0x800
	profinetARPropRejectDCPSet uint32 = 0x08000000
	profinetARPropTimeAware    uint32 = 0x10000000
	profinetARPropCombinedObj  uint32 = 0x20000000

	profinetSubmodSharedInput   = 0x4
	profinetSubmodReduceInput   = 0x8
	profinetSubmodReduceOutput  = 0x10
	profinetSubmodDiscardIOXS   = 0x20
	profinetSubStateFormat      = 0x8000
	profinetSubStateAdvice      = 0x8
	profinetSubStateMaintReq    = 0x10
	profinetSubStateMaintDem    = 0x20
	profinetSubStateFault       = 0x40
	profinetSubStateARInfoShift = 7
	profinetSubStateIdentShift  = 11
	profinetFourBitMask         = 0xF

	profinetTagVLANMask      = 0x0FFF
	profinetTagPriorityShift = 13

	profinetIOxSGood      = 0x80
	profinetIOxSInstShift = 5
	profinetIOxSExtension = 0x01

	profinetSelectorARNumMask  = 0x7
	profinetSelectorResShift   = 3
	profinetARUUIDConfigOff    = 6
	profinetARUUIDSelectorOff  = 14
	profinetSRPropInputValid   = 0x1
	profinetSRPropMode         = 0x4
	profinetRedundancyEndpoint = 0x3
	profinetRSSeqMask          = 0x07FF
	profinetRSSpecifierShift   = 14
)

// SupervisorTakeoverAllowed reports whether an IO supervisor may take the
// AR over (bit 3).
func (p ProfinetARProperties) SupervisorTakeoverAllowed() bool {
	return uint32(p)&profinetARPropSupervisor != 0
}

// ParameterizationServer reports who parameterizes: false an external
// parameter server, true the CM initiator (bit 4).
func (p ProfinetARProperties) ParameterizationServer() bool {
	return uint32(p)&profinetARPropPrmServer != 0
}

// CompanionAR returns bits 9-10: 0 single AR, 1 first AR of a companion
// pair, 2 companion AR.
func (p ProfinetARProperties) CompanionAR() uint8 {
	return uint8(uint32(p)>>profinetARPropCompanionSh) & profinetTwoBitMask
}

// AcknowledgeCompanionAR reports whether the companion AR needs an
// acknowledge (bit 11).
func (p ProfinetARProperties) AcknowledgeCompanionAR() bool {
	return uint32(p)&profinetARPropAckCompanion != 0
}

// RejectDCPSetRequests reports whether the device rejects DCP Set while
// the AR is up (bit 27).
func (p ProfinetARProperties) RejectDCPSetRequests() bool {
	return uint32(p)&profinetARPropRejectDCPSet != 0
}

// TimeAwareSystem reports whether the AR belongs to a time aware system
// (bit 28).
func (p ProfinetARProperties) TimeAwareSystem() bool {
	return uint32(p)&profinetARPropTimeAware != 0
}

// CombinedObjectContainer reports whether the AR uses the
// CombinedObjectContainer (bit 29).
func (p ProfinetARProperties) CombinedObjectContainer() bool {
	return uint32(p)&profinetARPropCombinedObj != 0
}

// ProfinetARSelector is the last two bytes of the ARUUID of a system
// redundancy AR (ARType 0x0020). The six bytes before the eight of the
// configuration ID discriminate the AR set.
type ProfinetARSelector uint16

// ARNumber returns the number of the AR in its AR set (bits 0-2).
func (s ProfinetARSelector) ARNumber() uint8 { return uint8(s) & profinetSelectorARNumMask }

// ARResource returns bits 3-4: 2 a communication endpoint shall be
// possible for the AR.
func (s ProfinetARSelector) ARResource() uint8 {
	return uint8(s>>profinetSelectorResShift) & profinetTwoBitMask
}

// Discriminator returns ARUUID.Discriminator of a system redundancy AR.
func (u ProfinetUUID) Discriminator() []byte { return u[:profinetARUUIDConfigOff] }

// ConfigID returns ARUUID.ConfigID of a system redundancy AR.
func (u ProfinetUUID) ConfigID() []byte { return u[profinetARUUIDConfigOff:profinetARUUIDSelectorOff] }

// Selector returns ARUUID.Selector of a system redundancy AR.
func (u ProfinetUUID) Selector() ProfinetARSelector {
	return ProfinetARSelector(uint16(u[profinetARUUIDSelectorOff])<<8 | uint16(u[profinetARUUIDSelectorOff+1]))
}

// ProfinetSubmoduleProperties is SubmoduleProperties of an expected
// submodule.
type ProfinetSubmoduleProperties uint16

// Type returns bits 0-1: 0 no IO data, 1 input, 2 output, 3 input and
// output.
func (p ProfinetSubmoduleProperties) Type() uint8 { return uint8(p) & profinetSubmodulePropTypeMask }

// SharedInput reports whether the input is shared with other controllers.
func (p ProfinetSubmoduleProperties) SharedInput() bool { return p&profinetSubmodSharedInput != 0 }

// ReduceInputLength reports ReduceInputSubmoduleDataLength: the input
// data length is zero.
func (p ProfinetSubmoduleProperties) ReduceInputLength() bool {
	return p&profinetSubmodReduceInput != 0
}

// ReduceOutputLength reports ReduceOutputSubmoduleDataLength.
func (p ProfinetSubmoduleProperties) ReduceOutputLength() bool {
	return p&profinetSubmodReduceOutput != 0
}

// DiscardIOXS reports whether the IOxS bytes are left out of the frame.
func (p ProfinetSubmoduleProperties) DiscardIOXS() bool { return p&profinetSubmodDiscardIOXS != 0 }

// ProfinetModuleState is the ModuleState of a ModuleDiffBlock.
type ProfinetModuleState uint16

// Module states.
const (
	ProfinetModuleNone       ProfinetModuleState = 0
	ProfinetModuleWrong      ProfinetModuleState = 1
	ProfinetModuleProper     ProfinetModuleState = 2
	ProfinetModuleSubstitute ProfinetModuleState = 3
)

// String names the module state.
func (s ProfinetModuleState) String() string {
	names := [...]string{"No module", "Wrong module", "Proper module", "Substitute"}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("Reserved(0x%04x)", uint16(s))
}

// ProfinetSubmoduleState is the SubmoduleState of a ModuleDiffBlock. The
// accessors read the current coding, which FormatIndicator marks.
type ProfinetSubmoduleState uint16

// FormatIndicator reports whether the state uses the coding with
// IdentInfo and ARInfo (bit 15); the accessors below are valid then.
func (s ProfinetSubmoduleState) FormatIndicator() bool { return s&profinetSubStateFormat != 0 }

// AddInfo returns bits 0-2: 1 takeover is not allowed.
func (s ProfinetSubmoduleState) AddInfo() uint8 { return uint8(s) & profinetThreeBitMask }

// Advice reports whether an advice is available (bit 3).
func (s ProfinetSubmoduleState) Advice() bool { return s&profinetSubStateAdvice != 0 }

// MaintenanceRequired reports bit 4.
func (s ProfinetSubmoduleState) MaintenanceRequired() bool { return s&profinetSubStateMaintReq != 0 }

// MaintenanceDemanded reports bit 5.
func (s ProfinetSubmoduleState) MaintenanceDemanded() bool { return s&profinetSubStateMaintDem != 0 }

// Fault reports whether a diagnosis of severity fault is pending (bit 6).
func (s ProfinetSubmoduleState) Fault() bool { return s&profinetSubStateFault != 0 }

// ARInfo returns bits 7-10: 0 own, 1 application ready pending, 2
// superordinated locked, 3 locked by IO controller, 4 locked by IO
// supervisor.
func (s ProfinetSubmoduleState) ARInfo() uint8 {
	return uint8(s>>profinetSubStateARInfoShift) & profinetFourBitMask
}

// IdentInfo returns bits 11-14: 0 ok, 1 substitute, 2 wrong, 3 no
// submodule.
func (s ProfinetSubmoduleState) IdentInfo() uint8 {
	return uint8(s>>profinetSubStateIdentShift) & profinetFourBitMask
}

// ProfinetTagHeader is an IOCRTagHeader or an AlarmCRTagHeader: the VLAN
// tag the frames of the CR carry.
type ProfinetTagHeader uint16

// VLANID returns the VLAN ID (bits 0-11); 0 means no VLAN.
func (t ProfinetTagHeader) VLANID() uint16 { return uint16(t) & profinetTagVLANMask }

// UserPriority returns the IEEE 802.1Q priority (bits 13-15): 6 for IO
// and high priority alarms, 5 for low priority alarms.
func (t ProfinetTagHeader) UserPriority() uint8 { return uint8(t >> profinetTagPriorityShift) }

// ProfinetIOxS is an IOPS or IOCS byte: the state of the IO data of a
// submodule as its provider or consumer sees it.
type ProfinetIOxS uint8

// Good reports DataState: the data is good.
func (s ProfinetIOxS) Good() bool { return s&profinetIOxSGood != 0 }

// Instance returns who detected bad data (bits 5-6): 0 subslot, 1 slot,
// 2 IO device, 3 IO controller.
func (s ProfinetIOxS) Instance() uint8 { return uint8(s>>profinetIOxSInstShift) & profinetTwoBitMask }

// Extension reports whether another IOxS byte follows.
func (s ProfinetIOxS) Extension() bool { return s&profinetIOxSExtension != 0 }

// ProfinetSubstituteValue is the body of SubstituteValue: what an output
// submodule applies when its controller is gone.
//
// Data is the SubstituteDataObjectElement: the substitute values and,
// last, SubstituteDataValid, coded like an IOPS.
type ProfinetSubstituteValue struct {
	Mode uint16 // SubstitutionMode: 0 zero, 1 last value, 2 replacement value
	IOCS ProfinetIOxS
	Data []byte
}

// DataValid returns SubstituteDataValid, the last byte of Data.
func (s *ProfinetSubstituteValue) DataValid() ProfinetIOxS {
	if len(s.Data) == 0 {
		return 0
	}
	return ProfinetIOxS(s.Data[len(s.Data)-1])
}

func decodeProfinetSubstitute(r *profinetReader) interface{} {
	if r.left() < 2+1 {
		return nil
	}
	return &ProfinetSubstituteValue{Mode: r.u16(), IOCS: ProfinetIOxS(r.u8()), Data: r.rest()}
}

// ProfinetRecordIOData is the body of RecordInputDataObjectElement and
// RecordOutputDataObjectElement: the IO data of a submodule read as a
// record. SubstituteActiveFlag exists for outputs, whose block also nests
// the SubstituteValue block.
type ProfinetRecordIOData struct {
	SubstituteActiveFlag uint16 // 0 operation, 1 substitute
	LengthIOCS           uint8
	LengthIOPS           uint8
	IOCS                 ProfinetIOxS
	IOPS                 ProfinetIOxS
	Data                 []byte
}

// clipBytes reads n bytes, or what is left of the body when n lies.
func (r *profinetReader) clipBytes(n int) []byte {
	if n > r.left() {
		r.short = true
		n = r.left()
	}
	return r.bytes(n)
}

func decodeProfinetRecordIn(r *profinetReader) interface{} {
	if r.left() < profinetRecordInputMin {
		return nil
	}

	d := &ProfinetRecordIOData{}
	d.LengthIOCS = r.u8()
	d.IOCS = ProfinetIOxS(r.u8())
	d.LengthIOPS = r.u8()
	d.IOPS = ProfinetIOxS(r.u8())
	d.Data = r.clipBytes(int(r.u16()))
	return d
}

func decodeProfinetRecordOut(r *profinetReader, b *ProfinetBlock) interface{} {
	if r.left() < profinetRecordOutputMin {
		return nil
	}

	d := &ProfinetRecordIOData{SubstituteActiveFlag: r.u16(), LengthIOCS: r.u8(), LengthIOPS: r.u8()}
	n := int(r.u16())

	// DataItem: IOCS, the data, IOPS.
	d.IOCS = ProfinetIOxS(r.u8())
	d.Data = r.clipBytes(n)
	d.IOPS = ProfinetIOxS(r.u8())
	b.Blocks = r.blocks()
	return d
}

// ProfinetARDataIOCR is one IOCR of an AR in ARData. The UDP ports exist
// per IOCR in version 1.0 and per AR in version 1.1.
type ProfinetARDataIOCR struct {
	IOCRType           ProfinetIOCRType
	Properties         ProfinetIOCRProperties
	FrameID            ProfinetFrameID
	CycleCounter       uint16
	DataStatus         ProfinetDataStatus
	TransferStatus     uint8
	InitiatorUDPRTPort uint16
	ResponderUDPRTPort uint16
}

// ProfinetARDataAR is one AR of ARData.
type ProfinetARDataAR struct {
	ARUUID               ProfinetUUID
	ARType               ProfinetARType
	Properties           ProfinetARProperties
	InitiatorObjectUUID  ProfinetUUID // CMInitiatorObjectUUID
	InitiatorStationName string
	IOCRs                []ProfinetARDataIOCR
	AlarmCRType          uint16
	LocalAlarmReference  uint16
	RemoteAlarmReference uint16
	PrmServerObjectUUID  ProfinetUUID // ParameterServerObjectUUID
	PrmServerStationName string
	APIs                 []uint32
	InitiatorUDPRTPort   uint16          // version 1.1
	ResponderUDPRTPort   uint16          // version 1.1
	NumberOfARDataInfo   uint16          // version 1.1
	Info                 []ProfinetBlock // version 1.1: IRInfoBlock, SRInfoBlock, ...
}

// ProfinetARData is the body of ARData: the ARs a device has.
type ProfinetARData struct {
	ARs []ProfinetARDataAR
}

func decodeProfinetARData(r *profinetReader, low uint8) interface{} {
	min := profinetARDataARMinLen
	if low == 1 {
		min = profinetARDataAR11MinLen
	}
	if low > 1 || r.left() < 2 {
		return nil
	}

	d := &ProfinetARData{ARs: make([]ProfinetARDataAR, r.count(min))}
	for i := range d.ARs {
		if low == 0 {
			r.arData10(&d.ARs[i])
			continue
		}
		r.arData11(&d.ARs[i])
	}
	return d
}

// apis reads a counted list of API numbers.
func (r *profinetReader) apis() []uint32 {
	apis := make([]uint32, r.count(4))
	for i := range apis {
		apis[i] = r.u32()
	}
	return apis
}

// arData10 reads one AR of ARData version 1.0.
func (r *profinetReader) arData10(a *ProfinetARDataAR) {
	a.ARUUID = r.uuid()
	a.ARType = ProfinetARType(r.u16())
	a.Properties = ProfinetARProperties(r.u32())
	a.InitiatorObjectUUID = r.uuid()
	a.InitiatorStationName = r.str16()

	a.IOCRs = make([]ProfinetARDataIOCR, r.count(profinetARDataIOCRLen))
	for i := range a.IOCRs {
		c := &a.IOCRs[i]
		c.IOCRType = ProfinetIOCRType(r.u16())
		c.Properties = ProfinetIOCRProperties(r.u32())
		c.FrameID = ProfinetFrameID(r.u16())
		c.CycleCounter = r.u16()
		c.DataStatus = ProfinetDataStatus(r.u8())
		c.TransferStatus = r.u8()
		c.InitiatorUDPRTPort = r.u16()
		c.ResponderUDPRTPort = r.u16()
	}

	a.AlarmCRType = r.u16()
	a.LocalAlarmReference = r.u16()
	a.RemoteAlarmReference = r.u16()
	a.PrmServerObjectUUID = r.uuid()
	a.PrmServerStationName = r.str16()
	a.APIs = r.apis()
}

// arData11 reads one AR of ARData version 1.1, which pads every list to
// four bytes and ends with the info blocks of the AR.
func (r *profinetReader) arData11(a *ProfinetARDataAR) {
	a.ARUUID = r.uuid()
	a.InitiatorObjectUUID = r.uuid()
	a.PrmServerObjectUUID = r.uuid()
	a.Properties = ProfinetARProperties(r.u32())
	a.ARType = ProfinetARType(r.u16())
	a.AlarmCRType = r.u16()
	a.LocalAlarmReference = r.u16()
	a.RemoteAlarmReference = r.u16()
	a.InitiatorUDPRTPort = r.u16()
	a.ResponderUDPRTPort = r.u16()
	a.InitiatorStationName = r.str16()
	r.align()
	a.PrmServerStationName = r.str16()
	r.align()

	a.IOCRs = make([]ProfinetARDataIOCR, r.count(profinetARDataIOCR11Len))
	r.align()
	for i := range a.IOCRs {
		c := &a.IOCRs[i]
		c.Properties = ProfinetIOCRProperties(r.u32())
		c.IOCRType = ProfinetIOCRType(r.u16())
		c.FrameID = ProfinetFrameID(r.u16())
		c.CycleCounter = r.u16()
		c.DataStatus = ProfinetDataStatus(r.u8())
		c.TransferStatus = r.u8()
	}

	n := r.count(4)
	r.align()
	a.APIs = make([]uint32, n)
	for i := range a.APIs {
		a.APIs[i] = r.u32()
	}

	a.NumberOfARDataInfo = r.u16()
	r.align()
	a.Info = r.counted(int(a.NumberOfARDataInfo))
}

// counted decodes up to n blocks and leaves the reader behind them. It
// stops early at a bad header or the nesting limit.
func (r *profinetReader) counted(n int) []ProfinetBlock {
	if max := r.left() / profinetBlockHeaderLen; n > max {
		n = max
	}
	if n == 0 || r.depth >= profinetMaxDepth {
		return nil
	}

	blocks := make([]ProfinetBlock, 0, n)
	for len(blocks) < n {
		b, size, err := decodeProfinetBlock(r.data[r.off:], r.depth+1)
		if err != nil {
			break
		}
		r.bytes(size)
		blocks = append(blocks, b)
	}
	return blocks
}

// ProfinetLogEntry is one entry of the log book.
type ProfinetLogEntry struct {
	LocalTimeStamp uint64
	ARUUID         ProfinetUUID
	Status         ProfinetPNIOStatus
	EntryDetail    uint32
}

// ProfinetLogBookData is the body of LogBookData. Time stamps count from
// an arbitrary start, in units the device chooses.
type ProfinetLogBookData struct {
	ActualLocalTimeStamp uint64
	Entries              []ProfinetLogEntry
}

func decodeProfinetLogBook(r *profinetReader) interface{} {
	if r.left() < profinetLogBookHeadLen {
		return nil
	}

	l := &ProfinetLogBookData{ActualLocalTimeStamp: r.u64()}
	l.Entries = make([]ProfinetLogEntry, r.count(profinetLogEntryLen))
	for i := range l.Entries {
		l.Entries[i] = ProfinetLogEntry{LocalTimeStamp: r.u64(), ARUUID: r.uuid(), Status: r.status(), EntryDetail: r.u32()}
	}
	return l
}

// ProfinetAPIData is the body of APIData: the APIs a device has.
type ProfinetAPIData struct {
	APIs []uint32
}

// ProfinetSRLData is the body of SRLData. Bits 0-1 of RedundancyInfo say
// which end of the system redundancy layer answered: 1 left or below,
// 2 right or above.
type ProfinetSRLData struct {
	RedundancyInfo uint16
}

// EndPoint returns RedundancyInfo.EndPoint.
func (s *ProfinetSRLData) EndPoint() uint8 {
	return uint8(s.RedundancyInfo) & profinetRedundancyEndpoint
}

// ProfinetPrmServerBlock is the body of PrmServerBlockReq and
// PrmServerBlockRes. The response carries the station name only.
type ProfinetPrmServerBlock struct {
	ObjectUUID            ProfinetUUID // ParameterServerObjectUUID
	Properties            uint32       // ParameterServerProperties
	ActivityTimeoutFactor uint16       // CMInitiatorActivityTimeoutFactor
	StationName           string       // ParameterServerStationName
}

func decodeProfinetPrmServer(r *profinetReader, t ProfinetBlockType) interface{} {
	if t == ProfinetBlockPrmServerRes {
		if r.left() < 2 {
			return nil
		}
		return &ProfinetPrmServerBlock{StationName: r.str16()}
	}

	if r.left() < profinetPrmServerMinLen {
		return nil
	}
	return &ProfinetPrmServerBlock{ObjectUUID: r.uuid(), Properties: r.u32(), ActivityTimeoutFactor: r.u16(), StationName: r.str16()}
}

// ProfinetMCRBlock is the body of MCRBlockReq: how a multicast consumer
// finds its provider.
type ProfinetMCRBlock struct {
	IOCRReference               uint16
	AddressResolutionProperties uint32 // bits 0-2 protocol: 1 DNS, 2 DCP; bits 16-31 resolution timeout factor
	MCITimeoutFactor            uint16
	ProviderStationName         string
}

func decodeProfinetMCR(r *profinetReader) interface{} {
	if r.left() < profinetMCRMinLen {
		return nil
	}
	return &ProfinetMCRBlock{IOCRReference: r.u16(), AddressResolutionProperties: r.u32(), MCITimeoutFactor: r.u16(), ProviderStationName: r.str16()}
}

// ProfinetARRPCBlock is the body of ARRPCBlockReq and ARRPCBlockRes: the
// UDP port of the RPC server of the initiator or the responder.
type ProfinetARRPCBlock struct {
	RPCServerPort uint16
}

// ProfinetARVendorBlock is the body of ARVendorBlockReq and
// ARVendorBlockRes.
type ProfinetARVendorBlock struct {
	APStructureIdentifier uint16
	API                   uint32
	Data                  []byte
}

// ProfinetIRInfoIOCR places one IOCR in a dynamic frame packing frame.
type ProfinetIRInfoIOCR struct {
	IOCRReference  uint16
	SubframeOffset uint16
	SubframeData   ProfinetSubframeData
}

// ProfinetIRInfoBlock is the body of IRInfoBlock.
type ProfinetIRInfoBlock struct {
	IRDataUUID ProfinetUUID
	IOCRs      []ProfinetIRInfoIOCR
}

func decodeProfinetIRInfo(r *profinetReader) interface{} {
	if r.left() < profinetIRInfoMinLen {
		return nil
	}

	r.skip(2)
	i := &ProfinetIRInfoBlock{IRDataUUID: r.uuid()}
	r.skip(2)

	i.IOCRs = make([]ProfinetIRInfoIOCR, r.count(profinetIRInfoIOCRLen))
	for j := range i.IOCRs {
		i.IOCRs[j] = ProfinetIRInfoIOCR{IOCRReference: r.u16(), SubframeOffset: r.u16(), SubframeData: ProfinetSubframeData(r.u32())}
	}
	return i
}

// ProfinetSRInfoBlock is the body of SRInfoBlock: the timing of a system
// redundancy AR.
type ProfinetSRInfoBlock struct {
	RedundancyDataHoldFactor uint16
	SRProperties             uint32
}

// InputValidOnBackupAR reports whether the controller reads the inputs
// of the backup AR (bit 0).
func (s *ProfinetSRInfoBlock) InputValidOnBackupAR() bool {
	return s.SRProperties&profinetSRPropInputValid != 0
}

// Mode reports bit 2: the controller supports data marked invalid while
// the inputs of the backup AR are not valid.
func (s *ProfinetSRInfoBlock) Mode() bool { return s.SRProperties&profinetSRPropMode != 0 }

// ProfinetRSInfoBlock is the body of RSInfoBlock. Bit 0 of RSProperties
// asks for an alarm on each reporting system event.
type ProfinetRSInfoBlock struct {
	RSProperties uint32
}

// ProfinetSubmoduleRef addresses one submodule.
type ProfinetSubmoduleRef struct {
	API     uint32
	Slot    uint16
	Subslot uint16
}

// ProfinetSubmoduleList is the body of SubmoduleListBlock: the submodules
// a PrmBegin applies to.
type ProfinetSubmoduleList struct {
	Entries []ProfinetSubmoduleRef
}

func decodeProfinetSubmodList(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	l := &ProfinetSubmoduleList{Entries: make([]ProfinetSubmoduleRef, r.count(profinetSubmodEntryLen))}
	for i := range l.Entries {
		l.Entries[i] = ProfinetSubmoduleRef{API: r.u32(), Slot: r.u16(), Subslot: r.u16()}
	}
	return l
}

// ProfinetARUUIDBlock is the body of ARUUIDBlock.
type ProfinetARUUIDBlock struct {
	ARUUID ProfinetUUID
}

// ProfinetPEService is the head of a PROFIenergy ServiceRequest or
// ServiceResponse. Modifier exists in requests, Status in responses;
// Data depends on the service.
type ProfinetPEService struct {
	ServiceID  uint8 // 1 Start_Pause, 2 End_Pause, 3 Query_Modes, 4 PEM_Status, 5 PE_Identify, 16 Query_Measurement
	RequestRef uint8
	Modifier   uint8
	Status     uint8 // 1 ready, 2 ready with error, 3 data incomplete
	StructID   uint8
	Data       []byte
}

func decodeProfinetPEService(r *profinetReader, t ProfinetBlockType) interface{} {
	if r.left() < profinetPEServiceLen {
		return nil
	}

	p := &ProfinetPEService{ServiceID: r.u8(), RequestRef: r.u8()}
	if t == ProfinetBlockPERequest {
		p.Modifier = r.u8()
	} else {
		p.Status = r.u8()
	}
	p.StructID = r.u8()
	p.Data = r.rest()
	return p
}

// ProfinetPESubmodule is the PROFIenergy mode of one submodule.
type ProfinetPESubmodule struct {
	Subslot         uint16
	OperationalMode uint8 // PE_OperationalMode: 0 power off, 0xF0 operate, 0xFF ready to operate
}

// ProfinetPEModule is one slot of PE_EntityStatusData.
type ProfinetPEModule struct {
	Slot       uint16
	Submodules []ProfinetPESubmodule
}

// ProfinetPEAPI is one API of PE_EntityStatusData.
type ProfinetPEAPI struct {
	API     uint32
	Modules []ProfinetPEModule
}

// ProfinetPEEntityStatus is the body of PE_EntityStatusData.
type ProfinetPEEntityStatus struct {
	APIs []ProfinetPEAPI
}

func decodeProfinetPEStatus(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	s := &ProfinetPEEntityStatus{APIs: make([]ProfinetPEAPI, r.count(profinetPEAPIMinLen))}
	for i := range s.APIs {
		api := &s.APIs[i]
		api.API = r.u32()

		api.Modules = make([]ProfinetPEModule, r.count(profinetPEModuleMinLen))
		for j := range api.Modules {
			m := &api.Modules[j]
			m.Slot = r.u16()

			m.Submodules = make([]ProfinetPESubmodule, r.count(profinetPESubmoduleLen))
			for k := range m.Submodules {
				m.Submodules[k] = ProfinetPESubmodule{Subslot: r.u16(), OperationalMode: r.u8()}
				r.skip(1)
			}
		}
	}
	return s
}

// decodeARValue decodes the AR blocks. They exist in version 1.0 only,
// except ARData.
func (b *ProfinetBlock) decodeARValue(r *profinetReader, low uint8) interface{} {
	if b.Type == ProfinetBlockARData {
		return decodeProfinetARData(r, low)
	}
	if low != 0 {
		return nil
	}

	switch b.Type {
	case ProfinetBlockSubstituteValue:
		return decodeProfinetSubstitute(r)
	case ProfinetBlockRecordInput:
		return decodeProfinetRecordIn(r)
	case ProfinetBlockRecordOutput:
		return decodeProfinetRecordOut(r, b)
	case ProfinetBlockLogBookData:
		return decodeProfinetLogBook(r)
	case ProfinetBlockPrmServerReq, ProfinetBlockPrmServerRes:
		return decodeProfinetPrmServer(r, b.Type)
	case ProfinetBlockMCRReq:
		return decodeProfinetMCR(r)
	case ProfinetBlockIRInfo:
		return decodeProfinetIRInfo(r)
	case ProfinetBlockSubmoduleList:
		return decodeProfinetSubmodList(r)
	case ProfinetBlockPERequest, ProfinetBlockPEResponse:
		return decodeProfinetPEService(r, b.Type)
	case ProfinetBlockPEEntityFilter:
		return decodeProfinetIdent(r, profinetIdentWithAPI)
	case ProfinetBlockPEEntityStatus:
		return decodeProfinetPEStatus(r)
	}
	return b.decodeARScalar(r)
}

// decodeARScalar decodes the AR blocks that are a few fixed fields.
func (b *ProfinetBlock) decodeARScalar(r *profinetReader) interface{} {
	switch b.Type {
	case ProfinetBlockAPIData:
		if r.left() >= 2 {
			return &ProfinetAPIData{APIs: r.apis()}
		}
	case ProfinetBlockSRLData:
		if r.left() >= 2 {
			return &ProfinetSRLData{RedundancyInfo: r.u16()}
		}
	case ProfinetBlockARRPCReq, ProfinetBlockARRPCRes:
		if r.left() >= 2 {
			return &ProfinetARRPCBlock{RPCServerPort: r.u16()}
		}
	case ProfinetBlockARVendorReq, ProfinetBlockARVendorRes:
		if r.left() >= profinetARVendorMinLen {
			return &ProfinetARVendorBlock{APStructureIdentifier: r.u16(), API: r.u32(), Data: r.rest()}
		}
	case ProfinetBlockSRInfo:
		if r.left() >= profinetSRInfoLen {
			return &ProfinetSRInfoBlock{RedundancyDataHoldFactor: r.u16(), SRProperties: r.u32()}
		}
	case ProfinetBlockRSInfo:
		if r.left() >= profinetRSInfoLen {
			r.skip(2)
			return &ProfinetRSInfoBlock{RSProperties: r.u32()}
		}
	case ProfinetBlockARUUID, ProfinetBlockARUUIDReq:
		if r.left() >= 2+profinetUUIDLen {
			r.skip(2)
			return &ProfinetARUUIDBlock{ARUUID: r.uuid()}
		}
	}
	return nil
}
