// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO physical device (PDev) blocks: port, interface, sync and
// IRT data (IEC 61158-6-10, "Coding section related to PDev").
//
// Several of them are containers: a short head, then the blocks that hold
// the settings.
//
//	PDPortDataCheck   Padding (2), SlotNumber (2), SubslotNumber (2),
//	                  { CheckPeers, CheckLineDelay, CheckMAUType, ... }
//	PDPortDataAdjust  the same head, { AdjustDomainBoundary, ... }
//	PDIRData          the same head, PDIRGlobalData, PDIRFrameData,
//	                  [ PDIRBeginEndData ]
//
// The head is in ProfinetBlock.Value, the nested blocks in
// ProfinetBlock.Blocks. Padding aligns fields to four bytes from the block
// start.

package layers

import (
	"fmt"
	"net"
)

// PDev block types. Each names the type of ProfinetBlock.Value; "+Blocks"
// marks the containers.
const (
	ProfinetBlockPDPortDataCheck   ProfinetBlockType = 0x0200 // *ProfinetSubslot +Blocks
	ProfinetBlockPDevData          ProfinetBlockType = 0x0201 // Blocks only
	ProfinetBlockPDPortDataAdjust  ProfinetBlockType = 0x0202 // *ProfinetSubslot +Blocks
	ProfinetBlockPDSyncData        ProfinetBlockType = 0x0203 // *ProfinetPDSyncData
	ProfinetBlockIsochronousMode   ProfinetBlockType = 0x0204 // *ProfinetIsochronousMode
	ProfinetBlockPDIRData          ProfinetBlockType = 0x0205 // *ProfinetSubslot +Blocks
	ProfinetBlockPDIRGlobalData    ProfinetBlockType = 0x0206 // *ProfinetPDIRGlobalData
	ProfinetBlockPDIRFrameData     ProfinetBlockType = 0x0207 // *ProfinetPDIRFrameData
	ProfinetBlockPDIRBeginEndData  ProfinetBlockType = 0x0208 // *ProfinetPDIRBeginEnd
	ProfinetBlockAdjDomainBoundary ProfinetBlockType = 0x0209 // *ProfinetAdjustBoundary
	ProfinetBlockCheckPeers        ProfinetBlockType = 0x020A // *ProfinetCheckPeers
	ProfinetBlockCheckLineDelay    ProfinetBlockType = 0x020B // *ProfinetCheckLineDelay
	ProfinetBlockCheckMAUType      ProfinetBlockType = 0x020C // *ProfinetCheckValue
	ProfinetBlockAdjustMAUType     ProfinetBlockType = 0x020E // *ProfinetAdjustValue
	ProfinetBlockPDPortDataReal    ProfinetBlockType = 0x020F // *ProfinetPDPortDataReal
	ProfinetBlockAdjMulticastBound ProfinetBlockType = 0x0210 // *ProfinetAdjustBoundary
	ProfinetBlockAdjustLinkState   ProfinetBlockType = 0x021B // *ProfinetAdjustValue
	ProfinetBlockCheckLinkState    ProfinetBlockType = 0x021C // *ProfinetCheckValue
	ProfinetBlockCheckSyncDiff     ProfinetBlockType = 0x021E // *ProfinetCheckValue
	ProfinetBlockCheckMAUTypeDiff  ProfinetBlockType = 0x021F // *ProfinetCheckValue
	ProfinetBlockPDPortFODataReal  ProfinetBlockType = 0x0220 // *ProfinetFiberOptic +Blocks
	ProfinetBlockFOManufacturer    ProfinetBlockType = 0x0221 // *ProfinetFOManufacturer
	ProfinetBlockPDPortFOAdjust    ProfinetBlockType = 0x0222 // *ProfinetFiberOptic
	ProfinetBlockPDPortFOCheck     ProfinetBlockType = 0x0223 // *ProfinetBudgetCheck
	ProfinetBlockAdjP2PBoundary    ProfinetBlockType = 0x0224 // *ProfinetAdjustBoundary
	ProfinetBlockAdjDCPBoundary    ProfinetBlockType = 0x0225 // *ProfinetAdjustBoundary
	ProfinetBlockAdjPreambleLength ProfinetBlockType = 0x0226 // *ProfinetAdjustValue
	ProfinetBlockCheckMAUTypeExt   ProfinetBlockType = 0x0227 // *ProfinetCheckValue
	ProfinetBlockFODiagnosisInfo   ProfinetBlockType = 0x0228 // *ProfinetFODiagnosisInfo
	ProfinetBlockAdjustMAUTypeExt  ProfinetBlockType = 0x0229 // *ProfinetAdjustValue
	ProfinetBlockPDIRSubframeData  ProfinetBlockType = 0x022A // *ProfinetEntryCount +Blocks
	ProfinetBlockSubframe          ProfinetBlockType = 0x022B // *ProfinetSubframeBlock
	ProfinetBlockPDPortRealExt     ProfinetBlockType = 0x022C // *ProfinetSubslot +Blocks
	ProfinetBlockPDNCDataCheck     ProfinetBlockType = 0x0230 // *ProfinetBudgetCheck
	ProfinetBlockPDIfDataReal      ProfinetBlockType = 0x0240 // *ProfinetPDInterfaceReal
	ProfinetBlockPDIfAdjust        ProfinetBlockType = 0x0250 // *ProfinetPDInterfaceAdjust
	ProfinetBlockPDPortStatistic   ProfinetBlockType = 0x0251 // *ProfinetPDPortStatistic
	ProfinetBlockOwnPort           ProfinetBlockType = 0x0260 // *ProfinetOwnPort
	ProfinetBlockNeighbors         ProfinetBlockType = 0x0261 // *ProfinetNeighbors
	ProfinetBlockPDRsiInstances    ProfinetBlockType = 0x0241 // *ProfinetPDRsiInstances
	ProfinetBlockMultipleHeader    ProfinetBlockType = 0x0400 // *ProfinetMultipleHeader +Blocks
	ProfinetBlockCOContainer       ProfinetBlockType = 0x0401 // *ProfinetCOContainer +Blocks
	ProfinetBlockFSHello           ProfinetBlockType = 0x0600 // *ProfinetFSHello
	ProfinetBlockFSParameter       ProfinetBlockType = 0x0601 // *ProfinetFSParameter
	ProfinetBlockPDIfFSUAdjust     ProfinetBlockType = 0x0608 // Blocks only
	ProfinetBlockARFSUDataAdjust   ProfinetBlockType = 0x0609 // Blocks only
)

// Block versions that change a PDev layout.
const (
	profinetVersionLowSync    = 2 // PDSyncData exists as version 1.2 only
	profinetVersionLowYellow  = 2 // PDIRGlobalData 1.2 adds two delays per port
	profinetVersionLowEgress  = 1 // AdjustDomainBoundary 1.1 splits the boundary
	profinetVersionLowStatus  = 1 // PDPortStatistic 1.1 adds CounterStatus
	profinetVersionLowFrameDP = 1 // PDIRFrameData 1.1 adds FrameDataProperties
)

// Smallest bodies and list elements.
const (
	profinetSubslotHeadLen  = 6  // padding, slot, subslot
	profinetPortRealMinLen  = 30 // empty names, no peers
	profinetPeerMinLen      = 12 // two lengths, line delay, MAC
	profinetNeighborMinLen  = 16 // delay, MAU types, MAC, two lengths
	profinetCheckPeerMinLen = 2  // two lengths
	profinetIfRealMinLen    = 20 // empty chassis ID
	profinetStatisticLen    = 26
	profinetSyncDataMinLen  = 47 // empty subdomain name
	profinetIsoModeLen      = 26
	profinetIRGlobalMinLen  = 26 // padding .. NumberOfPorts
	profinetIRPortLen       = 8  // two delays
	profinetIRPortYellowLen = 16 // four delays
	profinetIRFrameMinLen   = 17 // FrameSendOffset .. NumberOfTxPortGroups
	profinetIRBeginEndLen   = 10 // padding .. NumberOfPorts
	profinetIRAssignmentLen = 24 // six period begins
	profinetIRPhaseLen      = 4
	profinetIRPortMinLen    = 8 // two counts
	profinetBoundaryLen     = 8 // padding, boundary, properties
	profinetBoundary2Len    = 12
	profinetAdjustValueLen  = 6 // padding, value, properties
	profinetFiberOpticLen   = 10
	profinetBudgetCheckLen  = 14
	profinetOwnPortMinLen   = 26
	profinetMultiHeadLen    = 10
	profinetCOContainerLen  = 14
	profinetFSHelloLen      = 18
	profinetFSParameterLen  = 22
	profinetSubframeMinLen  = 6

	// profinetHighBit is bit 31, the format or enable flag of a 32-bit
	// delay or budget.
	profinetHighBit uint32 = 0x80000000
)

// container returns the blocks that fill the rest of the body: never nil,
// so that an empty container still counts as decoded, except at the
// nesting limit.
func (r *profinetReader) container() []ProfinetBlock {
	if r.depth >= profinetMaxDepth {
		return nil
	}

	blocks := r.blocks()
	if blocks == nil {
		return []ProfinetBlock{}
	}
	return blocks
}

// decodeProfinetBlockList reads a container with no fields of its own:
// two padding bytes, then blocks.
func decodeProfinetBlockList(r *profinetReader, b *ProfinetBlock) {
	if r.left() < 2 {
		return
	}

	r.skip(2)
	b.Blocks = r.container()
}

// ProfinetSubslot is the head of the containers that address one
// submodule: PDPortDataCheck, PDPortDataAdjust, PDPortDataRealExtended and
// PDIRData.
type ProfinetSubslot struct {
	Slot    uint16
	Subslot uint16
}

func decodeProfinetSubslot(r *profinetReader, b *ProfinetBlock) interface{} {
	if r.left() < profinetSubslotHeadLen {
		return nil
	}

	r.skip(2)
	v := &ProfinetSubslot{Slot: r.u16(), Subslot: r.u16()}
	b.Blocks = r.container()
	return v
}

// ProfinetLineDelay is a LineDelay: bit 31 says whether the low 31 bits
// are the cable delay (set) or the line delay (clear), in nanoseconds.
type ProfinetLineDelay uint32

// IsCableDelay reports whether the value is a cable delay.
func (d ProfinetLineDelay) IsCableDelay() bool { return uint32(d)&profinetHighBit != 0 }

// Nanoseconds returns the delay.
func (d ProfinetLineDelay) Nanoseconds() uint32 { return uint32(d) &^ profinetHighBit }

// ProfinetMAUType is a MAUType: the IEEE 802.3 medium attachment unit
// type of dot3MauType.
type ProfinetMAUType uint16

// Common MAU types.
const (
	ProfinetMAU10BaseTHD   ProfinetMAUType = 0x000A
	ProfinetMAU10BaseTFD   ProfinetMAUType = 0x000B
	ProfinetMAU100BaseTXHD ProfinetMAUType = 0x000F
	ProfinetMAU100BaseTXFD ProfinetMAUType = 0x0010
	ProfinetMAU100BaseFXHD ProfinetMAUType = 0x0011
	ProfinetMAU100BaseFXFD ProfinetMAUType = 0x0012
	ProfinetMAU1000BaseXFD ProfinetMAUType = 0x0016
	ProfinetMAU1000BaseTFD ProfinetMAUType = 0x001E
	ProfinetMAU10GBaseT    ProfinetMAUType = 0x0030
	ProfinetMAU100BasePXFD ProfinetMAUType = 0x0036 // POF and PCF
)

// String names the MAU type.
func (m ProfinetMAUType) String() string {
	switch m {
	case 0:
		return "Unknown"
	case ProfinetMAU10BaseTHD:
		return "10BASE-T half duplex"
	case ProfinetMAU10BaseTFD:
		return "10BASE-T full duplex"
	case ProfinetMAU100BaseTXHD:
		return "100BASE-TX half duplex"
	case ProfinetMAU100BaseTXFD:
		return "100BASE-TX full duplex"
	case ProfinetMAU100BaseFXHD:
		return "100BASE-FX half duplex"
	case ProfinetMAU100BaseFXFD:
		return "100BASE-FX full duplex"
	case ProfinetMAU1000BaseXFD:
		return "1000BASE-X full duplex"
	case ProfinetMAU1000BaseTFD:
		return "1000BASE-T full duplex"
	case ProfinetMAU10GBaseT:
		return "10GBASE-T"
	case ProfinetMAU100BasePXFD:
		return "100BASE-PX full duplex"
	}
	return fmt.Sprintf("MAUType(0x%04x)", uint16(m))
}

// ProfinetLinkState is a LinkState: Port in the high byte, Link in the
// low byte.
type ProfinetLinkState uint16

// Port returns LinkState.Port: 0 unknown, 1 disabled or discarding,
// 2 blocking, 3 listening, 4 learning, 5 forwarding, 6 broken.
func (s ProfinetLinkState) Port() uint8 { return uint8(s >> 8) }

// Link returns LinkState.Link: 1 up, 2 down, 3 testing, 4 unknown,
// 5 dormant, 6 not present, 7 lower layer down.
func (s ProfinetLinkState) Link() uint8 { return uint8(s) }

// ProfinetPeer is one neighbour of a port.
type ProfinetPeer struct {
	PortID     string // PeerPortID, the LLDP port ID
	ChassisID  string // PeerChassisID, the LLDP chassis ID
	LineDelay  ProfinetLineDelay
	MACAddress net.HardwareAddr

	// Neighbors blocks only.
	MAUType          ProfinetMAUType
	MAUTypeExtension uint16
}

// ProfinetPDPortDataReal is the body of PDPortDataReal: the state of a
// port and what LLDP learned about its neighbours.
type ProfinetPDPortDataReal struct {
	Slot              uint16
	Subslot           uint16
	OwnPortID         string
	Peers             []ProfinetPeer
	MAUType           ProfinetMAUType
	DomainBoundary    uint32
	MulticastBoundary uint32
	LinkState         ProfinetLinkState
	MediaType         uint32 // 1 copper, 2 fiber optic, 3 radio
}

func decodeProfinetPortReal(r *profinetReader) interface{} {
	if r.left() < profinetPortRealMinLen {
		return nil
	}

	r.skip(2)
	p := &ProfinetPDPortDataReal{Slot: r.u16(), Subslot: r.u16(), OwnPortID: r.str8()}

	// NumberOfPeers is one byte; clip it like the 16-bit counts.
	n := int(r.u8())
	r.align()
	if max := r.left() / profinetPeerMinLen; n > max {
		r.short = true
		n = max
	}

	p.Peers = make([]ProfinetPeer, n)
	for i := range p.Peers {
		peer := &p.Peers[i]
		peer.PortID = r.str8()
		peer.ChassisID = r.str8()
		r.align()
		peer.LineDelay = ProfinetLineDelay(r.u32())
		peer.MACAddress = r.mac()
		r.align()
	}

	p.MAUType = ProfinetMAUType(r.u16())
	r.align()
	p.DomainBoundary = r.u32()
	p.MulticastBoundary = r.u32()
	p.LinkState = ProfinetLinkState(r.u16())
	r.align()
	p.MediaType = r.u32()
	return p
}

// ProfinetOwnPort is the body of an OwnPort block of
// PDPortDataRealExtended.
type ProfinetOwnPort struct {
	OwnPortID         string
	LineDelay         ProfinetLineDelay
	MediaType         uint32
	MulticastBoundary uint32
	MAUType           ProfinetMAUType
	MAUTypeExtension  uint16
	LinkState         ProfinetLinkState
	RTClass3Status    uint16 // RTClass3_PortStatus
}

func decodeProfinetOwnPort(r *profinetReader) interface{} {
	if r.left() < profinetOwnPortMinLen {
		return nil
	}

	r.skip(2)
	p := &ProfinetOwnPort{OwnPortID: r.str8()}
	r.align()
	p.LineDelay = ProfinetLineDelay(r.u32())
	p.MediaType = r.u32()
	p.MulticastBoundary = r.u32()
	p.MAUType = ProfinetMAUType(r.u16())
	p.MAUTypeExtension = r.u16()
	p.LinkState = ProfinetLinkState(r.u16())
	p.RTClass3Status = r.u16()
	return p
}

// ProfinetNeighbors is the body of a Neighbors block of
// PDPortDataRealExtended.
type ProfinetNeighbors struct {
	Peers []ProfinetPeer
}

func decodeProfinetNeighbors(r *profinetReader) interface{} {
	if r.left() < 3 {
		return nil
	}

	r.skip(2)
	n := int(r.u8())
	r.align()
	if max := r.left() / profinetNeighborMinLen; n > max {
		r.short = true
		n = max
	}

	v := &ProfinetNeighbors{Peers: make([]ProfinetPeer, n)}
	for i := range v.Peers {
		peer := &v.Peers[i]
		peer.LineDelay = ProfinetLineDelay(r.u32())
		peer.MAUType = ProfinetMAUType(r.u16())
		peer.MAUTypeExtension = r.u16()
		peer.MACAddress = r.mac()
		peer.PortID = r.str8()
		peer.ChassisID = r.str8()
		r.align()
	}
	return v
}

// ProfinetPDInterfaceReal is the body of PDInterfaceDataReal: the name
// and the addresses of an interface.
type ProfinetPDInterfaceReal struct {
	OwnChassisID    string
	MACAddress      net.HardwareAddr
	IPAddress       net.IP
	Subnetmask      net.IP
	StandardGateway net.IP
}

func decodeProfinetIfReal(r *profinetReader) interface{} {
	if r.left() < profinetIfRealMinLen {
		return nil
	}

	p := &ProfinetPDInterfaceReal{OwnChassisID: r.str8()}
	r.align()
	p.MACAddress = r.mac()
	r.align()
	p.IPAddress = r.ip()
	p.Subnetmask = r.ip()
	p.StandardGateway = r.ip()
	return p
}

// ProfinetPDInterfaceAdjust is the body of PDInterfaceAdjust. Bit 0 of
// MultipleInterfaceMode makes the LLDP port ID carry the station name too.
type ProfinetPDInterfaceAdjust struct {
	MultipleInterfaceMode uint32
}

// NameOfDevice reports whether the LLDP port ID holds the name of the
// port and the name of the station.
func (p *ProfinetPDInterfaceAdjust) NameOfDevice() bool { return p.MultipleInterfaceMode&1 != 0 }

// ProfinetPDPortStatistic is the body of PDPortStatistic: the interface
// counters of the MIB-II ifTable. CounterStatus exists in version 1.1; a
// set bit marks the counter at that position (ifInOctets first) invalid.
type ProfinetPDPortStatistic struct {
	CounterStatus uint16
	InOctets      uint32
	OutOctets     uint32
	InDiscards    uint32
	OutDiscards   uint32
	InErrors      uint32
	OutErrors     uint32
}

func decodeProfinetStatistic(r *profinetReader, low uint8) interface{} {
	if low > profinetVersionLowStatus || r.left() < profinetStatisticLen {
		return nil
	}

	// Version 1.0 has padding where 1.1 has the status.
	p := &ProfinetPDPortStatistic{CounterStatus: r.u16()}
	if low == 0 {
		p.CounterStatus = 0
	}

	p.InOctets = r.u32()
	p.OutOctets = r.u32()
	p.InDiscards = r.u32()
	p.OutDiscards = r.u32()
	p.InErrors = r.u32()
	p.OutErrors = r.u32()
	return p
}

// ProfinetPDSyncData is the body of PDSyncData (version 1.2): the PTCP
// sync domain a device joins.
type ProfinetPDSyncData struct {
	PTCPSubdomainUUID     ProfinetUUID
	ReservedIntervalBegin uint32
	ReservedIntervalEnd   uint32
	PLLWindow             uint32
	SyncSendFactor        uint32
	SendClockFactor       uint16
	PTCPTimeoutFactor     uint16
	PTCPTakeoverFactor    uint16 // PTCPTakeoverTimeoutFactor
	PTCPMasterStartupTime uint16
	SyncProperties        uint16 // bits 0-1 role: 1 slave, 2 master; bits 8-12 sync ID
	MasterPriority1       uint8
	MasterPriority2       uint8
	PTCPSubdomainName     string
}

func decodeProfinetSyncData(r *profinetReader, low uint8) interface{} {
	if low != profinetVersionLowSync || r.left() < profinetSyncDataMinLen {
		return nil
	}

	r.skip(2)
	return &ProfinetPDSyncData{
		PTCPSubdomainUUID:     r.uuid(),
		ReservedIntervalBegin: r.u32(),
		ReservedIntervalEnd:   r.u32(),
		PLLWindow:             r.u32(),
		SyncSendFactor:        r.u32(),
		SendClockFactor:       r.u16(),
		PTCPTimeoutFactor:     r.u16(),
		PTCPTakeoverFactor:    r.u16(),
		PTCPMasterStartupTime: r.u16(),
		SyncProperties:        r.u16(),
		MasterPriority1:       r.u8(),
		MasterPriority2:       r.u8(),
		PTCPSubdomainName:     r.str8(),
	}
}

// ProfinetIsochronousMode is the body of IsochronousModeData. Times are
// in nanoseconds; the cycle is ControllerApplicationCycleFactor times the
// send cycle.
type ProfinetIsochronousMode struct {
	Slot                             uint16
	Subslot                          uint16
	ControllerApplicationCycleFactor uint16
	TimeDataCycle                    uint16
	TimeIOInput                      uint32
	TimeIOOutput                     uint32
	TimeIOInputValid                 uint32
	TimeIOOutputValid                uint32
}

func decodeProfinetIsoMode(r *profinetReader) interface{} {
	if r.left() < profinetIsoModeLen {
		return nil
	}

	r.skip(2)
	return &ProfinetIsochronousMode{
		Slot: r.u16(), Subslot: r.u16(),
		ControllerApplicationCycleFactor: r.u16(), TimeDataCycle: r.u16(),
		TimeIOInput: r.u32(), TimeIOOutput: r.u32(),
		TimeIOInputValid: r.u32(), TimeIOOutputValid: r.u32(),
	}
}

// ProfinetIRPortDelay is the delays of one port in PDIRGlobalData, in
// nanoseconds. The last two exist in version 1.2.
type ProfinetIRPortDelay struct {
	MaxPortTxDelay uint32
	MaxPortRxDelay uint32
	MaxLineRxDelay uint32
	YellowTime     uint32
}

// ProfinetPDIRGlobalData is the body of PDIRGlobalData.
type ProfinetPDIRGlobalData struct {
	IRDataUUID     ProfinetUUID
	MaxBridgeDelay uint32
	Ports          []ProfinetIRPortDelay
}

// count32 reads a 32-bit element count and clips it to what the unread
// bytes can hold.
func (r *profinetReader) count32(elemLen int) int {
	n := r.u32()
	if max := r.left() / elemLen; n > uint32(max) {
		r.short = true
		return max
	}
	return int(n)
}

func decodeProfinetIRGlobal(r *profinetReader, low uint8) interface{} {
	if low > profinetVersionLowYellow || r.left() < profinetIRGlobalMinLen {
		return nil
	}

	r.skip(2)
	g := &ProfinetPDIRGlobalData{IRDataUUID: r.uuid(), MaxBridgeDelay: r.u32()}

	elem := profinetIRPortLen
	if low == profinetVersionLowYellow {
		elem = profinetIRPortYellowLen
	}

	g.Ports = make([]ProfinetIRPortDelay, r.count32(elem))
	for i := range g.Ports {
		p := &g.Ports[i]
		p.MaxPortTxDelay = r.u32()
		p.MaxPortRxDelay = r.u32()
		if low == profinetVersionLowYellow {
			p.MaxLineRxDelay = r.u32()
			p.YellowTime = r.u32()
		}
	}
	return g
}

// ProfinetIRFrame is one frame of PDIRFrameData: when an RT_CLASS_3 frame
// is sent and where it is forwarded.
type ProfinetIRFrame struct {
	FrameSendOffset uint32
	DataLength      uint16
	ReductionRatio  uint16
	Phase           uint16
	FrameID         ProfinetFrameID
	EtherType       EthernetType
	RxPort          uint8
	FrameDetails    uint8  // bits 0-1 sync frame, bits 2-3 meaning
	TxPortGroups    []byte // one bit per port, bit 0 of byte 0 the local interface
}

// ProfinetPDIRFrameData is the body of PDIRFrameData. FrameDataProperties
// exists in version 1.1.
type ProfinetPDIRFrameData struct {
	FrameDataProperties uint32
	Frames              []ProfinetIRFrame
}

func decodeProfinetIRFrames(r *profinetReader, low uint8) interface{} {
	if low > profinetVersionLowFrameDP || r.left() < 2 {
		return nil
	}

	r.skip(2)
	d := &ProfinetPDIRFrameData{}
	if low == profinetVersionLowFrameDP {
		d.FrameDataProperties = r.u32()
	}

	// Frames until the body ends; each takes at least 17 bytes.
	d.Frames = make([]ProfinetIRFrame, 0, r.left()/profinetIRFrameMinLen)
	for r.left() >= profinetIRFrameMinLen {
		f := ProfinetIRFrame{
			FrameSendOffset: r.u32(), DataLength: r.u16(), ReductionRatio: r.u16(), Phase: r.u16(),
			FrameID: ProfinetFrameID(r.u16()), EtherType: EthernetType(r.u16()), RxPort: r.u8(), FrameDetails: r.u8(),
		}

		n := int(r.u8())
		if n > r.left() {
			n = r.left()
		}
		f.TxPortGroups = r.bytes(n)
		r.align()
		d.Frames = append(d.Frames, f)
	}
	return d
}

// ProfinetIRAssignment is the begin of the red, orange and green periods
// of one phase, for sending and for receiving, in nanoseconds.
type ProfinetIRAssignment struct {
	TxRedOrangePeriodBegin uint32
	TxOrangePeriodBegin    uint32
	TxGreenPeriodBegin     uint32
	RxRedOrangePeriodBegin uint32
	RxOrangePeriodBegin    uint32
	RxGreenPeriodBegin     uint32
}

// ProfinetIRPhase picks the assignment of one phase.
type ProfinetIRPhase struct {
	TxPhaseAssignment uint16
	RxPhaseAssignment uint16
}

// ProfinetIRPortPeriods is one port of PDIRBeginEndData.
type ProfinetIRPortPeriods struct {
	Assignments []ProfinetIRAssignment
	Phases      []ProfinetIRPhase
}

// ProfinetPDIRBeginEnd is the body of PDIRBeginEndData.
type ProfinetPDIRBeginEnd struct {
	StartOfRedFrameID ProfinetFrameID
	EndOfRedFrameID   ProfinetFrameID
	Ports             []ProfinetIRPortPeriods
}

func decodeProfinetIRBeginEnd(r *profinetReader) interface{} {
	if r.left() < profinetIRBeginEndLen {
		return nil
	}

	r.skip(2)
	d := &ProfinetPDIRBeginEnd{StartOfRedFrameID: ProfinetFrameID(r.u16()), EndOfRedFrameID: ProfinetFrameID(r.u16())}

	d.Ports = make([]ProfinetIRPortPeriods, r.count32(profinetIRPortMinLen))
	for i := range d.Ports {
		p := &d.Ports[i]

		p.Assignments = make([]ProfinetIRAssignment, r.count32(profinetIRAssignmentLen))
		for j := range p.Assignments {
			p.Assignments[j] = ProfinetIRAssignment{r.u32(), r.u32(), r.u32(), r.u32(), r.u32(), r.u32()}
		}

		p.Phases = make([]ProfinetIRPhase, r.count32(profinetIRPhaseLen))
		for j := range p.Phases {
			p.Phases[j] = ProfinetIRPhase{TxPhaseAssignment: r.u16(), RxPhaseAssignment: r.u16()}
		}
	}
	return d
}

// ProfinetSubframeData places one subframe in a dynamic frame packing
// frame.
type ProfinetSubframeData uint32

// Position returns the number of the subframe in the frame (bits 0-6).
func (d ProfinetSubframeData) Position() uint8 { return uint8(d) & profinetSubframePosMask }

// DataLength returns the length of the subframe data (bits 8-15).
func (d ProfinetSubframeData) DataLength() uint8 { return uint8(d >> 8) }

// ProfinetSubframeBlock is the body of a SubframeBlock of
// PDIRSubframeData: the layout of one dynamic frame packing frame.
type ProfinetSubframeBlock struct {
	FrameID          ProfinetFrameID
	SFIOCRProperties uint32
	SubframeData     []ProfinetSubframeData
}

func decodeProfinetSubframe(r *profinetReader) interface{} {
	if r.left() < profinetSubframeMinLen {
		return nil
	}

	s := &ProfinetSubframeBlock{FrameID: ProfinetFrameID(r.u16()), SFIOCRProperties: r.u32()}
	s.SubframeData = make([]ProfinetSubframeData, r.left()/4)
	for i := range s.SubframeData {
		s.SubframeData[i] = ProfinetSubframeData(r.u32())
	}
	return s
}

// ProfinetFiberOptic is the body of PDPortFODataReal and
// PDPortFODataAdjust. PDPortFODataReal nests the manufacturer specific
// and the diagnosis block.
type ProfinetFiberOptic struct {
	FiberOpticType      uint32
	FiberOpticCableType uint32
}

func decodeProfinetFiberOptic(r *profinetReader, b *ProfinetBlock) interface{} {
	if r.left() < profinetFiberOpticLen {
		return nil
	}

	r.skip(2)
	f := &ProfinetFiberOptic{FiberOpticType: r.u32(), FiberOpticCableType: r.u32()}
	if b.Type == ProfinetBlockPDPortFODataReal {
		b.Blocks = r.blocks()
	}
	return f
}

// ProfinetFOManufacturer is the body of FiberOpticManufacturerSpecific.
type ProfinetFOManufacturer struct {
	VendorID        uint16
	VendorBlockType uint16
	Data            []byte
}

// ProfinetPowerBudget is a power or drop budget: bit 31 enables the
// check, the low 31 bits are the value (0.1 dB, or frames).
type ProfinetPowerBudget uint32

// Enabled reports whether the check is on.
func (p ProfinetPowerBudget) Enabled() bool { return uint32(p)&profinetHighBit != 0 }

// Value returns the budget.
func (p ProfinetPowerBudget) Value() uint32 { return uint32(p) &^ profinetHighBit }

// ProfinetFODiagnosisInfo is the body of FiberOpticDiagnosisInfo.
type ProfinetFODiagnosisInfo struct {
	FiberOpticPowerBudgetReal ProfinetPowerBudget
}

// ProfinetBudgetCheck is the body of PDPortFODataCheck (power budgets)
// and PDNCDataCheck (frame drop budgets).
type ProfinetBudgetCheck struct {
	MaintenanceRequired ProfinetPowerBudget
	MaintenanceDemanded ProfinetPowerBudget
	Error               ProfinetPowerBudget
}

func decodeProfinetBudgetCheck(r *profinetReader) interface{} {
	if r.left() < profinetBudgetCheckLen {
		return nil
	}

	r.skip(2)
	return &ProfinetBudgetCheck{ProfinetPowerBudget(r.u32()), ProfinetPowerBudget(r.u32()), ProfinetPowerBudget(r.u32())}
}

// ProfinetCheckPeer is one expected neighbour.
type ProfinetCheckPeer struct {
	PortID    string
	ChassisID string
}

// ProfinetCheckPeers is the body of CheckPeers.
type ProfinetCheckPeers struct {
	Peers []ProfinetCheckPeer
}

func decodeProfinetCheckPeers(r *profinetReader) interface{} {
	if r.left() < 1 {
		return nil
	}

	n := int(r.u8())
	if max := r.left() / profinetCheckPeerMinLen; n > max {
		r.short = true
		n = max
	}

	c := &ProfinetCheckPeers{Peers: make([]ProfinetCheckPeer, n)}
	for i := range c.Peers {
		c.Peers[i] = ProfinetCheckPeer{PortID: r.str8(), ChassisID: r.str8()}
	}
	return c
}

// ProfinetCheckLineDelay is the body of CheckLineDelay.
type ProfinetCheckLineDelay struct {
	LineDelay ProfinetLineDelay
}

// ProfinetCheckValue is the body of the check blocks that hold one
// 16-bit value: MAUType in CheckMAUType, LinkState in CheckLinkState,
// CheckSyncMode in CheckSyncDifference (bit 0 cable delay, bit 1 sync
// master), MAUTypeMode in CheckMAUTypeDifference and MAUTypeExtension in
// CheckMAUTypeExtension.
type ProfinetCheckValue struct {
	Value uint16
}

// ProfinetAdjustValue is the body of the adjust blocks that hold one
// 16-bit value: MAUType in AdjustMAUType, LinkState in AdjustLinkState,
// PreambleLength in AdjustPreambleLength and MAUTypeExtension in
// AdjustMAUTypeExtension.
type ProfinetAdjustValue struct {
	Value            uint16
	AdjustProperties uint16
}

func decodeProfinetAdjustValue(r *profinetReader) interface{} {
	if r.left() < profinetAdjustValueLen {
		return nil
	}

	r.skip(2)
	return &ProfinetAdjustValue{Value: r.u16(), AdjustProperties: r.u16()}
}

// ProfinetAdjustBoundary is the body of the adjust blocks that hold a
// 32-bit boundary: AdjustDomainBoundary, AdjustMulticastBoundary,
// AdjustPeerToPeerBoundary and AdjustDCPBoundary. A set bit blocks the
// multicast address or the protocol of that position.
//
// AdjustDomainBoundary 1.1 has one boundary per direction: Boundary is
// DomainBoundaryIngress and Egress DomainBoundaryEgress.
type ProfinetAdjustBoundary struct {
	Boundary         uint32
	Egress           uint32
	AdjustProperties uint16
}

// profinetBoundaryForm says how many boundaries an adjust block holds.
type profinetBoundaryForm uint8

const (
	profinetBoundaryOne profinetBoundaryForm = iota
	profinetBoundarySplit
)

func decodeProfinetBoundary(r *profinetReader, form profinetBoundaryForm) interface{} {
	split := form == profinetBoundarySplit
	min := profinetBoundaryLen
	if split {
		min = profinetBoundary2Len
	}
	if r.left() < min {
		return nil
	}

	r.skip(2)
	a := &ProfinetAdjustBoundary{Boundary: r.u32()}
	if split {
		a.Egress = r.u32()
	}
	a.AdjustProperties = r.u16()
	return a
}

// ProfinetMultipleHeader is the head of a MultipleBlockHeader: the
// submodule the nested blocks belong to.
type ProfinetMultipleHeader struct {
	API     uint32
	Slot    uint16
	Subslot uint16
}

func decodeProfinetMultiHead(r *profinetReader, b *ProfinetBlock) interface{} {
	if r.left() < profinetMultiHeadLen {
		return nil
	}

	r.skip(2)
	m := &ProfinetMultipleHeader{API: r.u32(), Slot: r.u16(), Subslot: r.u16()}
	b.Blocks = r.container()
	return m
}

// ProfinetCOContainer is the head of a COContainerContent block of a
// CombinedObjectContainer: the record it stands for. The record data
// follows as blocks.
type ProfinetCOContainer struct {
	API     uint32
	Slot    uint16
	Subslot uint16
	Index   ProfinetRecordIndex
}

func decodeProfinetCOContainer(r *profinetReader, b *ProfinetBlock) interface{} {
	if r.left() < profinetCOContainerLen {
		return nil
	}

	r.skip(2)
	c := &ProfinetCOContainer{API: r.u32(), Slot: r.u16(), Subslot: r.u16()}
	r.skip(2)
	c.Index = ProfinetRecordIndex(r.u16())

	if c.Index.HoldsBlocks() {
		b.Blocks = r.blocks()
	}
	return c
}

// ProfinetFSHello is the body of FSHelloBlock: how a fast start up device
// announces itself with DCP Hello. Interval and delay are in milliseconds.
type ProfinetFSHello struct {
	Mode     uint32 // 0 off, 1 send Hello on link up, 2 after HelloDelay
	Interval uint32
	Retry    uint32
	Delay    uint32
}

// ProfinetFSParameter is the body of FSParameterBlock.
type ProfinetFSParameter struct {
	Mode uint32 // 0 off, 1 on
	UUID ProfinetUUID
}

// ProfinetRsiInstance is one PDRsiInstance: a remote service interface
// the device offers.
type ProfinetRsiInstance struct {
	VendorID   uint16
	DeviceID   uint16
	InstanceID uint16
	Interface  uint8 // RsiInterface
}

// ProfinetPDRsiInstances is the body of PDRsiInstances: the instances and
// the SystemIdentification of the device, whose fixed-size strings keep
// their padding.
//
//	| DeviceType | OrderID | IM_Serial_Number | HWRevision | Prefix | SWRevision |
//	| 25         | 20      | 16               | 5          | 1      | 9          |
//
// One blank separates the fields, but not the prefix from the revision.
type ProfinetPDRsiInstances struct {
	Instances        []ProfinetRsiInstance
	DeviceType       string
	OrderID          string
	SerialNumber     string // IM_Serial_Number
	HardwareRevision string // HWRevision, five digits
	SoftwarePrefix   byte   // SWRevisionPrefix
	SoftwareRevision string // SWRevision, three numbers of three digits
}

const (
	profinetRsiInstanceLen   = 8
	profinetRsiDeviceTypeLen = 25
	profinetRsiHWRevisionLen = 5
	profinetRsiSWRevisionLen = 9

	// profinetSystemIdentLen counts the six fields and four blanks.
	profinetSystemIdentLen = profinetRsiDeviceTypeLen + profinetIMOrderIDLen + profinetIMSerialLen +
		profinetRsiHWRevisionLen + 1 + profinetRsiSWRevisionLen + 4
)

func decodeProfinetRsi(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	v := &ProfinetPDRsiInstances{Instances: make([]ProfinetRsiInstance, r.count(profinetRsiInstanceLen))}
	for i := range v.Instances {
		v.Instances[i] = ProfinetRsiInstance{VendorID: r.u16(), DeviceID: r.u16(), InstanceID: r.u16(), Interface: r.u8()}
		r.skip(1)
	}

	// The count lied or the identification is cut: nothing to trust.
	if r.short || r.left() < profinetSystemIdentLen {
		return nil
	}

	v.DeviceType = r.str(profinetRsiDeviceTypeLen)
	r.skip(1)
	v.OrderID = r.str(profinetIMOrderIDLen)
	r.skip(1)
	v.SerialNumber = r.str(profinetIMSerialLen)
	r.skip(1)
	v.HardwareRevision = r.str(profinetRsiHWRevisionLen)
	r.skip(1)
	v.SoftwarePrefix = r.u8()
	v.SoftwareRevision = r.str(profinetRsiSWRevisionLen)
	return v
}

// decodePDValue decodes the PDev blocks.
func (b *ProfinetBlock) decodePDValue(r *profinetReader, low uint8) interface{} {
	// Blocks with more than one version check it themselves.
	switch b.Type {
	case ProfinetBlockPDSyncData:
		return decodeProfinetSyncData(r, low)
	case ProfinetBlockPDIRGlobalData:
		return decodeProfinetIRGlobal(r, low)
	case ProfinetBlockPDIRFrameData:
		return decodeProfinetIRFrames(r, low)
	case ProfinetBlockPDPortStatistic:
		return decodeProfinetStatistic(r, low)
	case ProfinetBlockPDIRData:
		if low <= 1 {
			return decodeProfinetSubslot(r, b)
		}
		return nil
	case ProfinetBlockAdjDomainBoundary:
		switch low {
		case 0:
			return decodeProfinetBoundary(r, profinetBoundaryOne)
		case profinetVersionLowEgress:
			return decodeProfinetBoundary(r, profinetBoundarySplit)
		}
		return nil
	}
	if low != 0 {
		return nil
	}

	switch b.Type {
	case ProfinetBlockPDPortDataCheck, ProfinetBlockPDPortDataAdjust, ProfinetBlockPDPortRealExt:
		return decodeProfinetSubslot(r, b)
	case ProfinetBlockPDevData, ProfinetBlockPDIfFSUAdjust, ProfinetBlockARFSUDataAdjust, ProfinetBlockARFSU:
		decodeProfinetBlockList(r, b)
	case ProfinetBlockIsochronousMode:
		return decodeProfinetIsoMode(r)
	case ProfinetBlockPDIRBeginEndData:
		return decodeProfinetIRBeginEnd(r)
	case ProfinetBlockPDIRSubframeData:
		return decodeProfinetEntries(r, b)
	case ProfinetBlockSubframe:
		return decodeProfinetSubframe(r)
	case ProfinetBlockPDPortDataReal:
		return decodeProfinetPortReal(r)
	case ProfinetBlockOwnPort:
		return decodeProfinetOwnPort(r)
	case ProfinetBlockNeighbors:
		return decodeProfinetNeighbors(r)
	case ProfinetBlockPDIfDataReal:
		return decodeProfinetIfReal(r)
	case ProfinetBlockPDPortFODataReal, ProfinetBlockPDPortFOAdjust:
		return decodeProfinetFiberOptic(r, b)
	case ProfinetBlockPDPortFOCheck, ProfinetBlockPDNCDataCheck:
		return decodeProfinetBudgetCheck(r)
	case ProfinetBlockCheckPeers:
		return decodeProfinetCheckPeers(r)
	case ProfinetBlockAdjMulticastBound, ProfinetBlockAdjP2PBoundary, ProfinetBlockAdjDCPBoundary:
		return decodeProfinetBoundary(r, profinetBoundaryOne)
	case ProfinetBlockAdjustMAUType, ProfinetBlockAdjustLinkState, ProfinetBlockAdjPreambleLength,
		ProfinetBlockAdjustMAUTypeExt:
		return decodeProfinetAdjustValue(r)
	case ProfinetBlockMultipleHeader:
		return decodeProfinetMultiHead(r, b)
	case ProfinetBlockCOContainer:
		return decodeProfinetCOContainer(r, b)
	case ProfinetBlockPDRsiInstances:
		return decodeProfinetRsi(r)
	}
	return b.decodePDScalar(r)
}

// decodePDScalar decodes the PDev blocks that are a few fixed fields.
func (b *ProfinetBlock) decodePDScalar(r *profinetReader) interface{} {
	switch b.Type {
	case ProfinetBlockCheckMAUType, ProfinetBlockCheckLinkState, ProfinetBlockCheckSyncDiff,
		ProfinetBlockCheckMAUTypeDiff, ProfinetBlockCheckMAUTypeExt:
		if r.left() >= 2 {
			return &ProfinetCheckValue{Value: r.u16()}
		}
	case ProfinetBlockCheckLineDelay:
		if r.left() >= 2+4 {
			r.skip(2)
			return &ProfinetCheckLineDelay{LineDelay: ProfinetLineDelay(r.u32())}
		}
	case ProfinetBlockPDIfAdjust:
		if r.left() >= 2+4 {
			r.skip(2)
			return &ProfinetPDInterfaceAdjust{MultipleInterfaceMode: r.u32()}
		}
	case ProfinetBlockFODiagnosisInfo:
		if r.left() >= 2+4 {
			r.skip(2)
			return &ProfinetFODiagnosisInfo{FiberOpticPowerBudgetReal: ProfinetPowerBudget(r.u32())}
		}
	case ProfinetBlockFOManufacturer:
		if r.left() >= 4 {
			return &ProfinetFOManufacturer{VendorID: r.u16(), VendorBlockType: r.u16(), Data: r.rest()}
		}
	case ProfinetBlockFSHello:
		if r.left() >= profinetFSHelloLen {
			r.skip(2)
			return &ProfinetFSHello{Mode: r.u32(), Interval: r.u32(), Retry: r.u32(), Delay: r.u32()}
		}
	case ProfinetBlockFSParameter:
		if r.left() >= profinetFSParameterLen {
			r.skip(2)
			return &ProfinetFSParameter{Mode: r.u32(), UUID: r.uuid()}
		}
	}
	return nil
}
