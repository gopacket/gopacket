// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO blocks of the TSN network configuration (CIMNetConf...,
// CIMStation...) and of the CIM records that count entries: calling home,
// capabilities and the record access policy.
//
// CIMNetConfDataReal and CIMNetConfDataAdjust stay raw: Wireshark 4.7
// stops with a dissector bug behind their NetworkDeadline, so the rest of
// their layout is not established.
//
// The layouts are the ones Wireshark 4.7 dissects; the standard is not
// public. Most blocks are a 16-bit count and that many fixed entries:
//
//	+-----------------+-------+-------+-----+
//	| NumberOfEntries | Entry | Entry | ... |
//	| 2               | n     | n     |     |
//	+-----------------+-------+-------+-----+
//
// Entries that pack bit fields into one word keep the word and name the
// fields with methods.

package layers

import "net"

// TSN network configuration block types and the type of their
// ProfinetBlock.Value.
const (
	ProfinetBlockCIMPortConfig       ProfinetBlockType = 0x0272 // *ProfinetCIMPortConfig +Blocks
	ProfinetBlockCIMQueueConfig      ProfinetBlockType = 0x0273 // *ProfinetCIMQueueConfig
	ProfinetBlockCIMStreamPath       ProfinetBlockType = 0x0275 // *ProfinetCIMStreamPath
	ProfinetBlockCIMSyncTree         ProfinetBlockType = 0x0276 // *ProfinetCIMSyncTree
	ProfinetBlockCIMUploadNetAttr    ProfinetBlockType = 0x0277 // *ProfinetCIMUploadAttributes +Blocks
	ProfinetBlockCIMForwardingDelay  ProfinetBlockType = 0x0278 // *ProfinetCIMForwardingDelay
	ProfinetBlockCIMExpectedNetAttr  ProfinetBlockType = 0x0279 // Blocks only
	ProfinetBlockCIMStreamPathReal   ProfinetBlockType = 0x027A // *ProfinetCIMStreamPath
	ProfinetBlockCIMIngressLimiter   ProfinetBlockType = 0x027B // *ProfinetCIMIngressLimiter
	ProfinetBlockCIMEgressLimiter    ProfinetBlockType = 0x027C // *ProfinetCIMEgressLimiter
	ProfinetBlockCIMPortCapabilities ProfinetBlockType = 0x027D // *ProfinetCIMPortCapabilities
	ProfinetBlockCIMExpectedNeighbor ProfinetBlockType = 0x027E // *ProfinetCIMExpectedNeighbors
	ProfinetBlockCIMCallingHomeAdj   ProfinetBlockType = 0x0310 // *ProfinetCIMCallingHome
	ProfinetBlockCIMCallingHomeReal  ProfinetBlockType = 0x0311 // *ProfinetCIMCallingHome
	ProfinetBlockCIMCapabilities     ProfinetBlockType = 0x0312 // *ProfinetCIMCapabilities
	ProfinetBlockRecordPolicyAdjust  ProfinetBlockType = 0x0313 // *ProfinetRecordAccessPolicy
	ProfinetBlockRecordPolicyReal    ProfinetBlockType = 0x0314 // *ProfinetRecordAccessPolicy
)

// Sizes of the fixed parts and of the list elements.
const (
	profinetCIMPortConfigLen  = 2 + 8 // count, one entry head
	profinetCIMUploadMinLen   = 2 + 2*profinetBlockHeaderLen + 22
	profinetCIMStreamHeadLen  = 6 // padding, command, padding, count
	profinetCIMStreamEntryLen = 16
	profinetCIMSyncEntryLen   = 8
	profinetCIMDelayEntryLen  = 8
	profinetCIMWordLen        = 8
	profinetCIMPortCapLen     = 12
	profinetCIMNeighborMinLen = 8 // slot, subslot, padding, peer count
	profinetCIMPeerMinLen     = 6 // two empty names, line delay
	profinetCIMHomeHeadLen    = 10
	profinetCIMHomeReserved   = 6
	profinetCIMCapEntryLen    = 8
	profinetRecordPolicyLen   = 16
)

// Bit fields of the TSN words.
const (
	profinet24BitMask  = 0xFFFFFF
	profinetSevenBits  = 0x7F
	profinetQueueIDLow = 0xF

	profinetQueuePcpShift     = 4
	profinetQueueShaperShift  = 7
	profinetQueuePreemptShift = 14
	profinetQueueUnmaskShift  = 16
	profinetQueueMaskShift    = 40

	profinetLimiterCBSShift      = 16
	profinetLimiterEnvelopeShift = 32
	profinetIngressRankShift     = 48
	profinetEgressRankShift      = 40
	profinetEgressQueueShift     = 48

	profinetFwdIndependentMask = 0x000FFFFF
	profinetFwdDependentShift  = 28

	profinetPortStatusPreempt   = 0x01
	profinetPortStatusBoundary  = 1 // shift of bits 1-3
	profinetPortCapTimeAware    = 0x01
	profinetPortCapPreemption   = 0x02
	profinetPortCapQueueMasking = 0x04

	profinetCallingHomeLayer3 = 0x0001
	profinetCallingHomeLayer2 = 0x0002
)

// ProfinetCIMPortStatus is CIMStationPortStatus.
type ProfinetCIMPortStatus uint8

// Preemption reports whether frame preemption is active on the link.
func (s ProfinetCIMPortStatus) Preemption() bool { return s&profinetPortStatusPreempt != 0 }

// BoundaryPort returns BoundaryPortStatus (bits 1-3).
func (s ProfinetCIMPortStatus) BoundaryPort() uint8 {
	return uint8(s>>profinetPortStatusBoundary) & profinetThreeBitMask
}

// ProfinetCIMPortConfig is the head of CIMStationPortConfigBlock with one
// entry; the rate limiter blocks of the port follow in
// ProfinetBlock.Blocks.
//
// Wireshark reads one entry and then blocks to the end of the body, so
// the layout of a block with another count is not established and such a
// block stays raw.
type ProfinetCIMPortConfig struct {
	NumberOfEntries uint16
	Slot            uint16
	Subslot         uint16
	Status          ProfinetCIMPortStatus
}

func decodeProfinetCIMPortConf(r *profinetReader, b *ProfinetBlock) interface{} {
	if r.left() < profinetCIMPortConfigLen {
		return nil
	}

	v := &ProfinetCIMPortConfig{NumberOfEntries: r.u16()}
	if v.NumberOfEntries != 1 {
		return nil
	}

	v.Slot = r.u16()
	v.Subslot = r.u16()
	v.Status = ProfinetCIMPortStatus(r.u8())
	r.skip(3)
	b.Blocks = r.container()
	return v
}

// ProfinetNMEQueueConfig is NMEDomainQueueConfig: one egress queue.
type ProfinetNMEQueueConfig uint64

// QueueID returns bits 0-3.
func (q ProfinetNMEQueueConfig) QueueID() uint8 { return uint8(q) & profinetQueueIDLow }

// TciPcp returns the priority code point mapped to the queue (bits 4-6).
func (q ProfinetNMEQueueConfig) TciPcp() uint8 {
	return uint8(q>>profinetQueuePcpShift) & profinetThreeBitMask
}

// Shaper returns the traffic shaper (bits 7-13).
func (q ProfinetNMEQueueConfig) Shaper() uint8 {
	return uint8(q>>profinetQueueShaperShift) & profinetSevenBits
}

// PreemptionMode returns bits 14-15.
func (q ProfinetNMEQueueConfig) PreemptionMode() uint8 {
	return uint8(q>>profinetQueuePreemptShift) & profinetTwoBitMask
}

// UnmaskTimeOffset returns bits 16-39.
func (q ProfinetNMEQueueConfig) UnmaskTimeOffset() uint32 {
	return uint32(q>>profinetQueueUnmaskShift) & profinet24BitMask
}

// MaskTimeOffset returns bits 40-63.
func (q ProfinetNMEQueueConfig) MaskTimeOffset() uint32 {
	return uint32(q>>profinetQueueMaskShift) & profinet24BitMask
}

// ProfinetCIMQueueConfig is the body of CIMStationQueueConfigBlock.
type ProfinetCIMQueueConfig struct {
	Queues []ProfinetNMEQueueConfig
}

// words reads a counted list of 64-bit words.
func (r *profinetReader) words() []uint64 {
	w := make([]uint64, r.count(profinetCIMWordLen))
	for i := range w {
		w[i] = r.u64()
	}
	return w
}

func decodeProfinetCIMQueues(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	v := &ProfinetCIMQueueConfig{Queues: make([]ProfinetNMEQueueConfig, r.count(profinetCIMWordLen))}
	for i := range v.Queues {
		v.Queues[i] = ProfinetNMEQueueConfig(r.u64())
	}
	return v
}

// ProfinetCIMStreamEntry is one stream of a stream path. Wireshark shows
// the two station elements as slot and subslot without naming their
// role.
type ProfinetCIMStreamEntry struct {
	DestinationAddress net.HardwareAddr
	StreamClass        uint16
	Elements           [2]ProfinetSubslot
}

// ProfinetCIMStreamPath is the body of CIMNetConfStreamPathData and
// CIMNetConfStreamPathDataReal. FDBCommand (1 adds, 2 removes stream
// entries) is zero in the real data, which has padding in its place.
type ProfinetCIMStreamPath struct {
	FDBCommand           uint8
	Entries              []ProfinetCIMStreamEntry
	StreamCollectionUUID ProfinetUUID
}

func decodeProfinetCIMStreams(r *profinetReader, t ProfinetBlockType) interface{} {
	if r.left() < profinetCIMStreamHeadLen {
		return nil
	}

	v := &ProfinetCIMStreamPath{}
	r.skip(1)
	if cmd := r.u8(); t == ProfinetBlockCIMStreamPath {
		v.FDBCommand = cmd
	}
	r.skip(2)

	v.Entries = make([]ProfinetCIMStreamEntry, r.count(profinetCIMStreamEntryLen))
	for i := range v.Entries {
		e := &v.Entries[i]
		e.DestinationAddress = r.mac()
		e.StreamClass = r.u16()
		e.Elements[0] = ProfinetSubslot{Slot: r.u16(), Subslot: r.u16()}
		e.Elements[1] = ProfinetSubslot{Slot: r.u16(), Subslot: r.u16()}
	}

	if r.left() >= profinetUUIDLen {
		v.StreamCollectionUUID = r.uuid()
	}
	return v
}

// ProfinetCIMUploadAttributes is the body of
// CIMNetConfUploadNetworkAttributes: what a station can do, for the
// engineering of a TSN domain. ProfinetBlock.Blocks holds its two blocks,
// the port capabilities and the forwarding delays.
//
//	Padding (2), CIMStationPortCapabilitiesBlock, MaxSupportedRecordSize,
//	TransferTimeTX, TransferTimeRX, ForwardingDelayBlock,
//	SupportedBurstSize, MinIPGBreakingPoint, MinIPGFrameSize,
//	FrameSendOffsetDeviation
type ProfinetCIMUploadAttributes struct {
	MaxSupportedRecordSize   uint32
	TransferTimeTX           uint32
	TransferTimeRX           uint32
	SupportedBurstSize       uint32
	MinIPGBreakingPoint      uint16
	MinIPGFrameSize          uint16
	FrameSendOffsetDeviation uint16
}

func decodeProfinetCIMUpload(r *profinetReader, b *ProfinetBlock) interface{} {
	if r.left() < profinetCIMUploadMinLen || r.depth >= profinetMaxDepth {
		return nil
	}

	r.skip(2)
	caps := r.counted(1)
	v := &ProfinetCIMUploadAttributes{MaxSupportedRecordSize: r.u32(), TransferTimeTX: r.u32(), TransferTimeRX: r.u32()}

	delays := r.counted(1)
	v.SupportedBurstSize = r.u32()
	v.MinIPGBreakingPoint = r.u16()
	v.MinIPGFrameSize = r.u16()
	v.FrameSendOffsetDeviation = r.u16()

	// A block or a field cut off: the offsets cannot be trusted.
	if r.short || len(caps) != 1 || len(delays) != 1 {
		return nil
	}

	b.Blocks = append(caps, delays...)
	return v
}

// ProfinetCIMSyncPort is one port of a sync tree.
type ProfinetCIMSyncPort struct {
	Slot             uint16 // CIMStationElementID
	Subslot          uint16
	TimeDomainNumber uint16
	SyncPortRole     uint8
}

// ProfinetCIMSyncTree is the body of CIMNetConfSyncTreeData.
type ProfinetCIMSyncTree struct {
	Ports            []ProfinetCIMSyncPort
	SyncTreeDataUUID ProfinetUUID
}

func decodeProfinetCIMSyncTree(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	v := &ProfinetCIMSyncTree{Ports: make([]ProfinetCIMSyncPort, r.count(profinetCIMSyncEntryLen))}
	for i := range v.Ports {
		v.Ports[i] = ProfinetCIMSyncPort{Slot: r.u16(), Subslot: r.u16(), TimeDomainNumber: r.u16(), SyncPortRole: r.u8()}
		r.skip(1)
	}

	if r.left() >= profinetUUIDLen {
		v.SyncTreeDataUUID = r.uuid()
	}
	return v
}

// ProfinetForwardingDelay is ForwardingDelay.
type ProfinetForwardingDelay uint32

// Independent returns the frame length independent port to port delay
// (bits 0-19).
func (d ProfinetForwardingDelay) Independent() uint32 {
	return uint32(d) & profinetFwdIndependentMask
}

// Dependent returns the frame length dependent part (bits 28-31); zero
// stands for cut-through forwarding.
func (d ProfinetForwardingDelay) Dependent() uint8 { return uint8(d >> profinetFwdDependentShift) }

// ProfinetCIMDelayEntry is one entry of ForwardingDelayBlock: the delay
// between two groups of ports for one stream class.
type ProfinetCIMDelayEntry struct {
	ForwardingGroupIngress uint8
	ForwardingGroupEgress  uint8
	StreamClass            uint16
	ForwardingDelay        ProfinetForwardingDelay
}

// ProfinetCIMForwardingDelay is the body of ForwardingDelayBlock.
type ProfinetCIMForwardingDelay struct {
	Entries []ProfinetCIMDelayEntry
}

func decodeProfinetCIMDelays(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	v := &ProfinetCIMForwardingDelay{Entries: make([]ProfinetCIMDelayEntry, r.count(profinetCIMDelayEntryLen))}
	for i := range v.Entries {
		v.Entries[i] = ProfinetCIMDelayEntry{r.u8(), r.u8(), r.u16(), ProfinetForwardingDelay(r.u32())}
	}
	return v
}

// ProfinetIngressRateLimiter is PortIngressRateLimiter.
type ProfinetIngressRateLimiter uint64

// CIR returns the committed information rate in 0.1 Mbit/s (bits 0-15).
func (l ProfinetIngressRateLimiter) CIR() uint16 { return uint16(l) }

// CBS returns the committed burst size in octets (bits 16-31).
func (l ProfinetIngressRateLimiter) CBS() uint16 { return uint16(l >> profinetLimiterCBSShift) }

// Envelope returns bits 32-47.
func (l ProfinetIngressRateLimiter) Envelope() uint16 {
	return uint16(l >> profinetLimiterEnvelopeShift)
}

// Rank returns bits 48-63.
func (l ProfinetIngressRateLimiter) Rank() uint16 { return uint16(l >> profinetIngressRankShift) }

// ProfinetCIMIngressLimiter is the body of
// CIMStationPortIngressRateLimiterBlock.
type ProfinetCIMIngressLimiter struct {
	Limiters []ProfinetIngressRateLimiter
}

// ProfinetEgressRateLimiter is PortQueueEgressRateLimiter.
type ProfinetEgressRateLimiter uint64

// CIR returns the committed information rate in 0.1 Mbit/s (bits 0-15).
func (l ProfinetEgressRateLimiter) CIR() uint16 { return uint16(l) }

// CBS returns the committed burst size in octets (bits 16-31).
func (l ProfinetEgressRateLimiter) CBS() uint16 { return uint16(l >> profinetLimiterCBSShift) }

// Envelope returns bits 32-39.
func (l ProfinetEgressRateLimiter) Envelope() uint8 {
	return uint8(l >> profinetLimiterEnvelopeShift)
}

// Rank returns bits 40-47.
func (l ProfinetEgressRateLimiter) Rank() uint8 { return uint8(l >> profinetEgressRankShift) }

// QueueID returns the queue the limiter belongs to (bits 48-55).
func (l ProfinetEgressRateLimiter) QueueID() uint8 { return uint8(l >> profinetEgressQueueShift) }

// ProfinetCIMEgressLimiter is the body of
// CIMStationEgressRateLimiterBlock.
type ProfinetCIMEgressLimiter struct {
	Limiters []ProfinetEgressRateLimiter
}

func decodeProfinetCIMLimiters(r *profinetReader, t ProfinetBlockType) interface{} {
	if r.left() < 2 {
		return nil
	}

	words := r.words()
	if t == ProfinetBlockCIMIngressLimiter {
		v := &ProfinetCIMIngressLimiter{Limiters: make([]ProfinetIngressRateLimiter, len(words))}
		for i, w := range words {
			v.Limiters[i] = ProfinetIngressRateLimiter(w)
		}
		return v
	}

	v := &ProfinetCIMEgressLimiter{Limiters: make([]ProfinetEgressRateLimiter, len(words))}
	for i, w := range words {
		v.Limiters[i] = ProfinetEgressRateLimiter(w)
	}
	return v
}

// ProfinetPortCapabilities is PortCapabilities.
type ProfinetPortCapabilities uint8

// TimeAware reports whether the port is usable in a time aware system.
func (c ProfinetPortCapabilities) TimeAware() bool { return c&profinetPortCapTimeAware != 0 }

// Preemption reports whether the port supports frame preemption.
func (c ProfinetPortCapabilities) Preemption() bool { return c&profinetPortCapPreemption != 0 }

// QueueMasking reports whether the port supports queue masking.
func (c ProfinetPortCapabilities) QueueMasking() bool { return c&profinetPortCapQueueMasking != 0 }

// ProfinetCIMPortCapability is one port of
// CIMStationPortCapabilitiesBlock.
type ProfinetCIMPortCapability struct {
	Slot             uint16
	Subslot          uint16
	MAUType          ProfinetMAUType
	MAUTypeExtension uint16
	NumberOfQueues   uint8
	Capabilities     ProfinetPortCapabilities
	ForwardingGroup  uint8
}

// ProfinetCIMPortCapabilities is the body of
// CIMStationPortCapabilitiesBlock.
type ProfinetCIMPortCapabilities struct {
	Ports []ProfinetCIMPortCapability
}

func decodeProfinetCIMPortCaps(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	v := &ProfinetCIMPortCapabilities{Ports: make([]ProfinetCIMPortCapability, r.count(profinetCIMPortCapLen))}
	for i := range v.Ports {
		v.Ports[i] = ProfinetCIMPortCapability{
			Slot:             r.u16(),
			Subslot:          r.u16(),
			MAUType:          ProfinetMAUType(r.u16()),
			MAUTypeExtension: r.u16(),
			NumberOfQueues:   r.u8(),
			Capabilities:     ProfinetPortCapabilities(r.u8()),
			ForwardingGroup:  r.u8(),
		}
		r.skip(1)
	}
	return v
}

// ProfinetCIMExpectedPeer is one neighbor a port expects.
type ProfinetCIMExpectedPeer struct {
	PortName    string
	StationName string
	LineDelay   ProfinetLineDelay
}

// ProfinetCIMNeighborPort is one port of CIMStationExpectedNeighborBlock.
type ProfinetCIMNeighborPort struct {
	Slot    uint16
	Subslot uint16
	Peers   []ProfinetCIMExpectedPeer
}

// ProfinetCIMExpectedNeighbors is the body of
// CIMStationExpectedNeighborBlock.
type ProfinetCIMExpectedNeighbors struct {
	Ports []ProfinetCIMNeighborPort
}

func decodeProfinetCIMNeighbors(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	v := &ProfinetCIMExpectedNeighbors{Ports: make([]ProfinetCIMNeighborPort, r.count(profinetCIMNeighborMinLen))}
	for i := range v.Ports {
		port := &v.Ports[i]
		port.Slot = r.u16()
		port.Subslot = r.u16()
		r.skip(3)

		// The peer count is clipped to what the body can hold.
		n := int(r.u8())
		if max := r.left() / profinetCIMPeerMinLen; n > max {
			r.short = true
			n = max
		}

		port.Peers = make([]ProfinetCIMExpectedPeer, n)
		for j := range port.Peers {
			peer := &port.Peers[j]
			peer.PortName = r.str8()
			peer.StationName = r.str8()
			r.align()
			peer.LineDelay = ProfinetLineDelay(r.u32())
		}
	}
	return v
}

// ProfinetCIMCallingHome is the body of CIMCallingHomeAdjust and
// CIMCallingHomeReal with one entry: the station a device calls to have
// its SXP connection opened.
//
// Wireshark dissects the first entry only and skips its first six bytes,
// which stay raw in Reserved. A block with another count stays raw.
type ProfinetCIMCallingHome struct {
	NumberOfEntries uint16
	Reserved        []byte
	Flags           uint16 // CallingHomeFlags
	StationName     string // CH_StationName
	StationIP       net.IP // CH_StationIP
}

// UseLayer3 reports whether SXP runs over TCP/IP.
func (c *ProfinetCIMCallingHome) UseLayer3() bool { return c.Flags&profinetCallingHomeLayer3 != 0 }

// UseLayer2 reports whether SXP runs over RTA.
func (c *ProfinetCIMCallingHome) UseLayer2() bool { return c.Flags&profinetCallingHomeLayer2 != 0 }

func decodeProfinetCIMHome(r *profinetReader) interface{} {
	if r.left() < 2+profinetCIMHomeHeadLen+net.IPv4len {
		return nil
	}

	v := &ProfinetCIMCallingHome{NumberOfEntries: r.u16()}
	if v.NumberOfEntries != 1 {
		return nil
	}

	v.Reserved = r.bytes(profinetCIMHomeReserved)
	v.Flags = r.u16()
	v.StationName = r.str16()
	r.align()
	v.StationIP = r.ip()
	if r.short {
		return nil
	}
	return v
}

// ProfinetCIMCapability is one CIM_CapabilityEntry. Wireshark reads
// eight bytes whatever EntryLength says.
type ProfinetCIMCapability struct {
	EntryLength     uint8  // CapEntryLength
	NamespaceFormat uint8  // 1 profile capability, 2 vendor capability
	NamespaceID     uint16 // CapNamespaceID
	CapabilityID    uint32 // CIMCapabilityID
}

// ProfinetCIMCapabilities is the body of CIM_Capabilities.
type ProfinetCIMCapabilities struct {
	Entries []ProfinetCIMCapability
}

func decodeProfinetCIMCaps(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	v := &ProfinetCIMCapabilities{Entries: make([]ProfinetCIMCapability, r.count(profinetCIMCapEntryLen))}
	for i := range v.Entries {
		v.Entries[i] = ProfinetCIMCapability{r.u8(), r.u8(), r.u16(), r.u32()}
	}
	return v
}

// ProfinetRange is a range of slots, subslots or record indexes: the end
// in the high and the start in the low 16 bits.
type ProfinetRange uint32

// Start returns the first number of the range.
func (g ProfinetRange) Start() uint16 { return uint16(g) }

// End returns the last number of the range.
func (g ProfinetRange) End() uint16 { return uint16(g >> 16) }

// ProfinetRecordPolicy is one RecordPolicySetData: the access an AR type
// has to a range of records.
type ProfinetRecordPolicy struct {
	Condition uint16 // RACondition: bits 0-1 the AR type
	Access    uint16 // RAAccess: bits 0-1 the permission
	Slot      ProfinetRange
	Subslot   ProfinetRange
	Index     ProfinetRange
}

// ARType returns the AR type the policy applies to (RACondition bits
// 0-1).
func (p ProfinetRecordPolicy) ARType() uint8 { return uint8(p.Condition) & profinetTwoBitMask }

// AccessType returns the permission (RAAccess bits 0-1); zero permits
// reading and writing.
func (p ProfinetRecordPolicy) AccessType() uint8 { return uint8(p.Access) & profinetTwoBitMask }

// ProfinetRecordAccessPolicy is the body of ARRecordAccessPolicyAdjust
// and ARRecordAccessPolicyReal.
type ProfinetRecordAccessPolicy struct {
	Entries []ProfinetRecordPolicy
}

func decodeProfinetRecPolicy(r *profinetReader) interface{} {
	if r.left() < 2 {
		return nil
	}

	v := &ProfinetRecordAccessPolicy{Entries: make([]ProfinetRecordPolicy, r.count(profinetRecordPolicyLen))}
	for i := range v.Entries {
		v.Entries[i] = ProfinetRecordPolicy{
			Condition: r.u16(),
			Access:    r.u16(),
			Slot:      ProfinetRange(r.u32()),
			Subslot:   ProfinetRange(r.u32()),
			Index:     ProfinetRange(r.u32()),
		}
	}
	return v
}

// decodeCIMValue decodes the TSN network configuration and the counted
// CIM blocks, version 1.0.
func (b *ProfinetBlock) decodeCIMValue(r *profinetReader) interface{} {
	switch b.Type {
	case ProfinetBlockCIMPortConfig:
		return decodeProfinetCIMPortConf(r, b)
	case ProfinetBlockCIMQueueConfig:
		return decodeProfinetCIMQueues(r)
	case ProfinetBlockCIMStreamPath, ProfinetBlockCIMStreamPathReal:
		return decodeProfinetCIMStreams(r, b.Type)
	case ProfinetBlockCIMSyncTree:
		return decodeProfinetCIMSyncTree(r)
	case ProfinetBlockCIMUploadNetAttr:
		return decodeProfinetCIMUpload(r, b)
	case ProfinetBlockCIMExpectedNetAttr:
		decodeProfinetBlockList(r, b)
	case ProfinetBlockCIMForwardingDelay:
		return decodeProfinetCIMDelays(r)
	case ProfinetBlockCIMIngressLimiter, ProfinetBlockCIMEgressLimiter:
		return decodeProfinetCIMLimiters(r, b.Type)
	case ProfinetBlockCIMPortCapabilities:
		return decodeProfinetCIMPortCaps(r)
	case ProfinetBlockCIMExpectedNeighbor:
		return decodeProfinetCIMNeighbors(r)
	case ProfinetBlockCIMCallingHomeAdj, ProfinetBlockCIMCallingHomeReal:
		return decodeProfinetCIMHome(r)
	case ProfinetBlockCIMCapabilities:
		return decodeProfinetCIMCaps(r)
	case ProfinetBlockRecordPolicyAdjust, ProfinetBlockRecordPolicyReal:
		return decodeProfinetRecPolicy(r)
	}
	return nil
}
