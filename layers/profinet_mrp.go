// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET IO media redundancy (MRP) records (IEC 61158-6-10, "Coding
// section related to PDev", MRP parameters of IEC 62439-2).
//
// The interface records describe one ring in version 1.0 and count
// MrpInstanceData blocks, one per ring, in version 1.1:
//
//	1.0  Padding (2), MRP_DomainUUID (16), MRP_Role (2), ...,
//	     [ MrpManagerParams | MrpClientParams ], [ MrpRingStateData ]
//	1.1  Padding (1), MRP_NumberOfEntries (1), MrpInstanceData*

package layers

import "fmt"

// MRP block types. Each names the type of ProfinetBlock.Value; "+Blocks"
// marks the containers.
const (
	ProfinetBlockPDIfMrpAdjust    ProfinetBlockType = 0x0211 // *ProfinetMrpInterface +Blocks
	ProfinetBlockPDIfMrpReal      ProfinetBlockType = 0x0212 // *ProfinetMrpInterface +Blocks
	ProfinetBlockPDIfMrpCheck     ProfinetBlockType = 0x0213 // *ProfinetMrpInterface +Blocks
	ProfinetBlockPDPortMrpAdjust  ProfinetBlockType = 0x0214 // *ProfinetMrpPort
	ProfinetBlockPDPortMrpReal    ProfinetBlockType = 0x0215 // *ProfinetMrpPort
	ProfinetBlockMrpManagerParams ProfinetBlockType = 0x0216 // *ProfinetMrpManagerParams
	ProfinetBlockMrpClientParams  ProfinetBlockType = 0x0217 // *ProfinetMrpClientParams
	ProfinetBlockMrpRTModeManager ProfinetBlockType = 0x0218 // *ProfinetMrpRTMode
	ProfinetBlockMrpRingState     ProfinetBlockType = 0x0219 // *ProfinetCheckValue (MRP_RingState: 0 open, 1 closed)
	ProfinetBlockMrpRTState       ProfinetBlockType = 0x021A // *ProfinetCheckValue (MRP_RTState)
	ProfinetBlockMrpRTModeClient  ProfinetBlockType = 0x021D // *ProfinetMrpRTMode
	ProfinetBlockMrpInstAdjust    ProfinetBlockType = 0x0231 // *ProfinetMrpInterface +Blocks
	ProfinetBlockMrpInstReal      ProfinetBlockType = 0x0232 // *ProfinetMrpInterface +Blocks
	ProfinetBlockMrpInstCheck     ProfinetBlockType = 0x0233 // *ProfinetMrpInterface
)

const (
	profinetVersionLowMrpInst = 1 // version 1.1 counts instances

	profinetMrpHeadLen     = 2 + profinetUUIDLen // padding or instance, domain UUID
	profinetMrpAdjustMin   = profinetMrpHeadLen + 5
	profinetMrpRealMin     = profinetMrpHeadLen + 5
	profinetMrpCheckLen    = profinetMrpHeadLen + 4
	profinetMrpManagerLen  = 12
	profinetMrpClientLen   = 6
	profinetMrpRTManagerLn = 10
	profinetMrpRTClientLen = 6

	profinetMrpCheckManager uint32 = 0x1
	profinetMrpCheckUUID    uint32 = 0x2
)

// ProfinetMrpRole is MRP_Role.
type ProfinetMrpRole uint16

// MRP roles.
const (
	ProfinetMrpRoleOff         ProfinetMrpRole = 0
	ProfinetMrpRoleClient      ProfinetMrpRole = 1
	ProfinetMrpRoleManager     ProfinetMrpRole = 2
	ProfinetMrpRoleAutoManager ProfinetMrpRole = 3
)

// String names the role.
func (m ProfinetMrpRole) String() string {
	names := [...]string{"Off", "Client", "Manager", "Auto manager"}
	if int(m) < len(names) {
		return names[m]
	}
	return fmt.Sprintf("Reserved(0x%04x)", uint16(m))
}

// ProfinetMrpCheck is MRP_Check: what the device shall diagnose.
type ProfinetMrpCheck uint32

// Manager reports whether the media redundancy manager is checked.
func (c ProfinetMrpCheck) Manager() bool { return uint32(c)&profinetMrpCheckManager != 0 }

// DomainUUID reports whether the MRP domain UUID is checked.
func (c ProfinetMrpCheck) DomainUUID() bool { return uint32(c)&profinetMrpCheckUUID != 0 }

// ProfinetMrpInterface is the body of the MRP records of an interface:
// PDInterfaceMrpDataAdjust, Real and Check, and the MrpInstanceData blocks
// their version 1.1 nests.
//
// Version 1.1 of the interface records sets only NumberOfEntries; the
// rings are in the nested blocks. Role and DomainName do not exist in the
// check records, Version only in the real ones, Check only in the check
// ones, Instance only in the MrpInstanceData blocks.
type ProfinetMrpInterface struct {
	NumberOfEntries uint8
	Instance        uint8
	DomainUUID      ProfinetUUID
	Role            ProfinetMrpRole
	Version         uint16
	DomainName      string
	Check           ProfinetMrpCheck
}

// profinetMrpKind tells the three MRP interface records apart.
type profinetMrpKind uint8

const (
	profinetMrpAdjust profinetMrpKind = iota
	profinetMrpReal
	profinetMrpCheck
)

// decodeProfinetMrpIf reads an MRP interface record or one instance of
// it. An instance block has the instance number where the record has a
// second padding byte.
func decodeProfinetMrpIf(r *profinetReader, b *ProfinetBlock, kind profinetMrpKind, low uint8) interface{} {
	instance := b.Type == ProfinetBlockMrpInstAdjust || b.Type == ProfinetBlockMrpInstReal || b.Type == ProfinetBlockMrpInstCheck
	if low > profinetVersionLowMrpInst || instance && low != 0 {
		return nil
	}

	if !instance && low == profinetVersionLowMrpInst && r.mrpCounted(kind) {
		if r.left() < 2 {
			return nil
		}

		r.skip(1)
		m := &ProfinetMrpInterface{NumberOfEntries: r.u8()}
		b.Blocks = r.container()
		return m
	}

	min := profinetMrpAdjustMin
	if kind == profinetMrpCheck {
		min = profinetMrpCheckLen
	}
	if r.left() < min {
		return nil
	}

	r.skip(1)
	m := &ProfinetMrpInterface{Instance: r.u8(), DomainUUID: r.uuid()}
	if !instance {
		m.Instance = 0
	}

	switch kind {
	case profinetMrpCheck:
		m.Check = ProfinetMrpCheck(r.u32())
		return m
	case profinetMrpAdjust:
		m.Role = ProfinetMrpRole(r.u16())
		r.skip(2)
		m.DomainName = r.str8()
	case profinetMrpReal:
		m.Role = ProfinetMrpRole(r.u16())

		// The version follows the name in version 1.0 of the interface
		// record and precedes it everywhere else.
		if !instance && low == 0 {
			m.DomainName = r.str8()
			m.Version = r.u16()
			break
		}
		m.Version = r.u16()
		m.DomainName = r.str8()
	}

	r.align()
	b.Blocks = r.blocks()
	return m
}

// mrpCounted reports whether a version 1.1 interface record counts
// instance blocks. The real record also occurs as version 1.1 with the
// fields of one ring; an instance block behind the count tells them apart.
func (r *profinetReader) mrpCounted(kind profinetMrpKind) bool {
	if kind != profinetMrpReal {
		return true
	}

	const typeOff = 2
	if r.left() < typeOff+2 {
		return true
	}
	return ProfinetBlockType(uint16(r.data[typeOff])<<8|uint16(r.data[typeOff+1])) == ProfinetBlockMrpInstReal
}

// ProfinetMrpPort is the body of PDPortMrpDataAdjust and
// PDPortMrpDataReal: the ring a port belongs to. Instance exists in
// version 1.1.
type ProfinetMrpPort struct {
	Instance   uint8
	DomainUUID ProfinetUUID
}

func decodeProfinetMrpPort(r *profinetReader, low uint8) interface{} {
	if low > profinetVersionLowMrpInst || r.left() < profinetMrpHeadLen {
		return nil
	}

	r.skip(1)
	p := &ProfinetMrpPort{Instance: r.u8(), DomainUUID: r.uuid()}
	if low == 0 {
		p.Instance = 0
	}
	return p
}

// ProfinetMrpManagerParams is the body of MrpManagerParams. Times are in
// milliseconds.
type ProfinetMrpManagerParams struct {
	Prio        uint16 // MRP_Prio: 0 highest
	TOPchgT     uint16 // topology change interval
	TOPNRmax    uint16 // topology change repeat count
	TSTshortT   uint16 // short test interval
	TSTdefaultT uint16 // default test interval
	TSTNRmax    uint16 // test monitoring count
}

// ProfinetMrpClientParams is the body of MrpClientParams.
type ProfinetMrpClientParams struct {
	LNKdownT uint16 // link down interval, ms
	LNKupT   uint16 // link up interval, ms
	LNKNRmax uint16 // link change count
}

// ProfinetMrpRTMode is the body of MrpRTModeManagerData and
// MrpRTModeClientData. The test parameters exist for the manager only.
// RTMode bit 0 enables RT_CLASS_1 and 2 redundancy, bit 1 RT_CLASS_3.
type ProfinetMrpRTMode struct {
	TSTNRmax    uint16
	TSTdefaultT uint16
	RTMode      uint32
}

// decodeMrpValue decodes the MRP blocks.
func (b *ProfinetBlock) decodeMrpValue(r *profinetReader, low uint8) interface{} {
	switch b.Type {
	case ProfinetBlockPDIfMrpAdjust, ProfinetBlockMrpInstAdjust:
		return decodeProfinetMrpIf(r, b, profinetMrpAdjust, low)
	case ProfinetBlockPDIfMrpReal, ProfinetBlockMrpInstReal:
		return decodeProfinetMrpIf(r, b, profinetMrpReal, low)
	case ProfinetBlockPDIfMrpCheck, ProfinetBlockMrpInstCheck:
		return decodeProfinetMrpIf(r, b, profinetMrpCheck, low)
	case ProfinetBlockPDPortMrpAdjust, ProfinetBlockPDPortMrpReal:
		return decodeProfinetMrpPort(r, low)
	}
	if low != 0 {
		return nil
	}

	switch b.Type {
	case ProfinetBlockMrpManagerParams:
		if r.left() >= profinetMrpManagerLen {
			return &ProfinetMrpManagerParams{r.u16(), r.u16(), r.u16(), r.u16(), r.u16(), r.u16()}
		}
	case ProfinetBlockMrpClientParams:
		if r.left() >= profinetMrpClientLen {
			return &ProfinetMrpClientParams{r.u16(), r.u16(), r.u16()}
		}
	case ProfinetBlockMrpRTModeManager:
		if r.left() >= profinetMrpRTManagerLn {
			m := &ProfinetMrpRTMode{TSTNRmax: r.u16(), TSTdefaultT: r.u16()}
			r.skip(2)
			m.RTMode = r.u32()
			return m
		}
	case ProfinetBlockMrpRTModeClient:
		if r.left() >= profinetMrpRTClientLen {
			r.skip(2)
			return &ProfinetMrpRTMode{RTMode: r.u32()}
		}
	case ProfinetBlockMrpRingState, ProfinetBlockMrpRTState:
		if r.left() >= 2 {
			return &ProfinetCheckValue{Value: r.u16()}
		}
	}
	return nil
}
