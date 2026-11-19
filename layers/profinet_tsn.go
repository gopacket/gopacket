// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO blocks of the network management engine (TSN domains) and
// of the communication interface management (CIM) records that switch
// protocols of a station on and off.
//
// Only the blocks with fixed fields are decoded here. The CIM and NME
// blocks that count entries or mix fields with nested blocks stay raw.

package layers

// TSN and CIM block types and the type of their ProfinetBlock.Value.
const (
	ProfinetBlockNMEDomainTime     ProfinetBlockType = 0x0274 // *ProfinetNMEDomainTime
	ProfinetBlockNMEDomainConfReal ProfinetBlockType = 0x027F // *ProfinetNMEDomainConfig
	ProfinetBlockCIMSNMPAdjust     ProfinetBlockType = 0x0300 // *ProfinetCIMSNMP
	ProfinetBlockCIMSNMPReal       ProfinetBlockType = 0x0302 // *ProfinetCIMSNMP
	ProfinetBlockCIMCLRPCAdjust    ProfinetBlockType = 0x0303 // *ProfinetCIMControl
	ProfinetBlockCIMCLRPCReal      ProfinetBlockType = 0x0304 // *ProfinetCIMControl
	ProfinetBlockCIMDCPAdjust      ProfinetBlockType = 0x0305 // *ProfinetCIMDCP
	ProfinetBlockCIMDCPReal        ProfinetBlockType = 0x0306 // *ProfinetCIMDCP
	ProfinetBlockCIMLockdownAdjust ProfinetBlockType = 0x0307 // *ProfinetCIMControl
	ProfinetBlockCIMLockdownReal   ProfinetBlockType = 0x0308 // *ProfinetCIMControl
	ProfinetBlockCIMPortSAPAdjust  ProfinetBlockType = 0x0309 // *ProfinetCIMControl
	ProfinetBlockCIMPortSAPReal    ProfinetBlockType = 0x030A // *ProfinetCIMControl
)

const (
	profinetNMETimeMinLen    = 31
	profinetNMEDomainConfLen = 2 + 3*profinetUUIDLen
	profinetCIMDCPLen        = 6
)

// ProfinetNMEDomainTime is the body of NMEDomainTimeDataBlock: the time
// synchronization of a TSN domain.
type ProfinetNMEDomainTime struct {
	TimeDomainNumber      uint16 // 0 global time, 0x20 working clock
	TimePLLWindow         uint32 // nanoseconds
	MessageIntervalFactor uint32
	MessageTimeoutFactor  uint16
	TimeSyncProperties    uint16 // bits 0-1 role: 1 external, 2 internal sync
	TimeDomainUUID        ProfinetUUID
	TimeDomainName        string
}

func decodeProfinetNMETime(r *profinetReader) interface{} {
	if r.left() < profinetNMETimeMinLen {
		return nil
	}

	return &ProfinetNMEDomainTime{
		TimeDomainNumber:      r.u16(),
		TimePLLWindow:         r.u32(),
		MessageIntervalFactor: r.u32(),
		MessageTimeoutFactor:  r.u16(),
		TimeSyncProperties:    r.u16(),
		TimeDomainUUID:        r.uuid(),
		TimeDomainName:        r.str8(),
	}
}

// ProfinetNMEDomainConfig is the body of NMEDomainConfigRealBlock: the
// configuration sets a TSN domain runs with.
type ProfinetNMEDomainConfig struct {
	StreamCollectionUUID          ProfinetUUID // CIMStreamCollectionUUID
	SyncTreeDataUUID              ProfinetUUID // CIMSyncTreeDataUUID
	ExpectedNetworkAttributesUUID ProfinetUUID // CIMExpectedNetworkAttributesUUID
}

// ProfinetCIMSNMP is the body of CIMSNMPAdjust and CIMSNMPReal. The real
// record has SNMPControl only.
type ProfinetCIMSNMP struct {
	SNMPControl        uint16 // 0 disabled, 1 read only, 2 read and write
	ReadCommunity      string
	ReadWriteCommunity string
}

func decodeProfinetCIMSNMP(r *profinetReader, t ProfinetBlockType) interface{} {
	if r.left() < 2 {
		return nil
	}

	s := &ProfinetCIMSNMP{SNMPControl: r.u16()}
	if t == ProfinetBlockCIMSNMPAdjust && r.left() >= 2 {
		s.ReadCommunity = r.str8()
		s.ReadWriteCommunity = r.str8()
	}
	return s
}

// ProfinetCIMControl is the body of the CIM records that hold one control
// word: CLRPCControl, LockdownControl or PortControl. Bit 0 of
// CLRPCControl enables CLRPC, bit 1 the IO device interface, bit 2 the IO
// controller interface.
type ProfinetCIMControl struct {
	Control uint16
}

// ProfinetCIMDCP is the body of CIMDCPAdjust and CIMDCPReal. Bit 0 of
// each word enables the service.
type ProfinetCIMDCP struct {
	SetControl       uint16 // DCPSetControl
	GetControl       uint16 // DCPGetControl
	MulticastControl uint16 // DCPMulticastControl: bit 0 identify, bit 8 hello
}

// decodeTSNValue decodes the TSN and CIM blocks, version 1.0.
func (b *ProfinetBlock) decodeTSNValue(r *profinetReader, low uint8) interface{} {
	if low != 0 {
		return nil
	}

	switch b.Type {
	case ProfinetBlockNMEDomainTime:
		return decodeProfinetNMETime(r)
	case ProfinetBlockNMEDomainConfReal:
		if r.left() >= profinetNMEDomainConfLen {
			r.skip(2)
			return &ProfinetNMEDomainConfig{r.uuid(), r.uuid(), r.uuid()}
		}
	case ProfinetBlockCIMSNMPAdjust, ProfinetBlockCIMSNMPReal:
		return decodeProfinetCIMSNMP(r, b.Type)
	case ProfinetBlockCIMCLRPCAdjust, ProfinetBlockCIMCLRPCReal, ProfinetBlockCIMLockdownAdjust,
		ProfinetBlockCIMLockdownReal, ProfinetBlockCIMPortSAPAdjust, ProfinetBlockCIMPortSAPReal:
		if r.left() >= 2 {
			return &ProfinetCIMControl{Control: r.u16()}
		}
	case ProfinetBlockCIMDCPAdjust, ProfinetBlockCIMDCPReal:
		if r.left() >= profinetCIMDCPLen {
			return &ProfinetCIMDCP{SetControl: r.u16(), GetControl: r.u16(), MulticastControl: r.u16()}
		}
	}
	return nil
}
