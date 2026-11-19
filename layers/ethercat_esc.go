// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// EtherCAT slave controller (ESC) registers (ETG.1000.4, Wireshark
// packet-ethercat-datagram.c).
//
// A datagram with a physical command (everything but NOP and the logical
// LRD, LWR, LRW) addresses the slave's memory by ADO. Offsets below
// 0x1000 are ESC registers:
//
//	0x0000  ESC information      0x0500  EEPROM interface
//	0x0010  station address      0x0510  MII management
//	0x0100  DL control, status   0x0600  16 FMMUs, 16 bytes each
//	0x0120  AL control, status   0x0800  8 sync managers, 8 bytes each
//	0x0200  interrupts           0x0900  distributed clocks
//	0x0300  error counters       0x0980  DC cyclic unit, latches
//	0x0400  watchdogs            0x0E00  ESC specific (product, vendor)
//	                             0x0F00  digital and general purpose I/O
//	                             0x0F80  user RAM
//
// One datagram often spans several registers, e.g. a read of 0x0130
// length 6 covers AL status and the AL status code. Registers() lists
// every register the data covers in full.

package layers

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// ESCRegister is the offset of an EtherCAT slave controller register.
type ESCRegister uint16

// ESC registers.
const (
	ESCRegisterType            ESCRegister = 0x0000
	ESCRegisterRevision        ESCRegister = 0x0001
	ESCRegisterBuild           ESCRegister = 0x0002
	ESCRegisterFMMUCount       ESCRegister = 0x0004
	ESCRegisterSMCount         ESCRegister = 0x0005
	ESCRegisterRAMSize         ESCRegister = 0x0006
	ESCRegisterPorts           ESCRegister = 0x0007
	ESCRegisterFeatures        ESCRegister = 0x0008
	ESCRegisterStationAddress  ESCRegister = 0x0010
	ESCRegisterStationAlias    ESCRegister = 0x0012
	ESCRegisterWriteProtect    ESCRegister = 0x0020
	ESCRegisterAccessProtect   ESCRegister = 0x0030
	ESCRegisterResetECAT       ESCRegister = 0x0040
	ESCRegisterResetPDI        ESCRegister = 0x0041
	ESCRegisterDLControl       ESCRegister = 0x0100
	ESCRegisterDLControl1      ESCRegister = 0x0101
	ESCRegisterDLControl2      ESCRegister = 0x0102
	ESCRegisterDLControl3      ESCRegister = 0x0103
	ESCRegisterPhysRWOffset    ESCRegister = 0x0108
	ESCRegisterDLStatus        ESCRegister = 0x0110
	ESCRegisterDLStatus1       ESCRegister = 0x0111
	ESCRegisterALControl       ESCRegister = 0x0120
	ESCRegisterALStatus        ESCRegister = 0x0130
	ESCRegisterALStatusCode    ESCRegister = 0x0134
	ESCRegisterPDIControl      ESCRegister = 0x0140
	ESCRegisterPDIConfig       ESCRegister = 0x0141
	ESCRegisterECATIRQMask     ESCRegister = 0x0200
	ESCRegisterPDIIRQMaskLow   ESCRegister = 0x0204
	ESCRegisterPDIIRQMaskHigh  ESCRegister = 0x0206
	ESCRegisterECATIRQ         ESCRegister = 0x0210
	ESCRegisterPDIIRQLow       ESCRegister = 0x0220
	ESCRegisterPDIIRQHigh      ESCRegister = 0x0222
	ESCRegisterCRCError0       ESCRegister = 0x0300
	ESCRegisterCRCError1       ESCRegister = 0x0302
	ESCRegisterCRCError2       ESCRegister = 0x0304
	ESCRegisterCRCError3       ESCRegister = 0x0306
	ESCRegisterForwardedCRC0   ESCRegister = 0x0308
	ESCRegisterForwardedCRC1   ESCRegister = 0x0309
	ESCRegisterForwardedCRC2   ESCRegister = 0x030A
	ESCRegisterForwardedCRC3   ESCRegister = 0x030B
	ESCRegisterProcessUnitErr  ESCRegister = 0x030C
	ESCRegisterPDIError        ESCRegister = 0x030D
	ESCRegisterLinkLost0       ESCRegister = 0x0310
	ESCRegisterLinkLost1       ESCRegister = 0x0311
	ESCRegisterLinkLost2       ESCRegister = 0x0312
	ESCRegisterLinkLost3       ESCRegister = 0x0313
	ESCRegisterWDDivider       ESCRegister = 0x0400
	ESCRegisterWDTimePDI       ESCRegister = 0x0410
	ESCRegisterWDTimeSM        ESCRegister = 0x0420
	ESCRegisterWDStatus        ESCRegister = 0x0440
	ESCRegisterWDCounterSM     ESCRegister = 0x0442
	ESCRegisterWDCounterPDI    ESCRegister = 0x0443
	ESCRegisterEEPROMAssign    ESCRegister = 0x0500
	ESCRegisterEEPROMControl   ESCRegister = 0x0502
	ESCRegisterEEPROMAddrLow   ESCRegister = 0x0504
	ESCRegisterEEPROMAddrHigh  ESCRegister = 0x0506
	ESCRegisterEEPROMData0     ESCRegister = 0x0508
	ESCRegisterEEPROMData1     ESCRegister = 0x050A
	ESCRegisterEEPROMData2     ESCRegister = 0x050C
	ESCRegisterEEPROMData3     ESCRegister = 0x050E
	ESCRegisterMIIControl      ESCRegister = 0x0510
	ESCRegisterMIIAddress      ESCRegister = 0x0512
	ESCRegisterMIIData         ESCRegister = 0x0514
	ESCRegisterMIIAccess       ESCRegister = 0x0516
	ESCRegisterMIIPortStatus0  ESCRegister = 0x0518
	ESCRegisterMIIPortStatus1  ESCRegister = 0x0519
	ESCRegisterMIIPortStatus2  ESCRegister = 0x051A
	ESCRegisterMIIPortStatus3  ESCRegister = 0x051B
	ESCRegisterFMMU            ESCRegister = 0x0600 // first of 16
	ESCRegisterSyncManager     ESCRegister = 0x0800 // first of 8
	ESCRegisterDCRecvTime0     ESCRegister = 0x0900
	ESCRegisterDCRecvTime1     ESCRegister = 0x0904
	ESCRegisterDCRecvTime2     ESCRegister = 0x0908
	ESCRegisterDCRecvTime3     ESCRegister = 0x090C
	ESCRegisterDCSystemTime    ESCRegister = 0x0910
	ESCRegisterDCSystemTimeHi  ESCRegister = 0x0914
	ESCRegisterDCRecvTimeUnit  ESCRegister = 0x0918
	ESCRegisterDCTimeOffset    ESCRegister = 0x0920
	ESCRegisterDCTimeOffsetHi  ESCRegister = 0x0924
	ESCRegisterDCTimeDelay     ESCRegister = 0x0928
	ESCRegisterDCControlError  ESCRegister = 0x092C
	ESCRegisterDCSpeedStart    ESCRegister = 0x0930
	ESCRegisterDCSpeedDiff     ESCRegister = 0x0932
	ESCRegisterDCFilterTime    ESCRegister = 0x0934
	ESCRegisterDCFilterSpeed   ESCRegister = 0x0935
	ESCRegisterDCCyclicControl ESCRegister = 0x0980
	ESCRegisterDCActivation    ESCRegister = 0x0981
	ESCRegisterDCPulseLength   ESCRegister = 0x0982
	ESCRegisterDCActivationSt  ESCRegister = 0x0984
	ESCRegisterDCSync0Status   ESCRegister = 0x098E
	ESCRegisterDCSync1Status   ESCRegister = 0x098F
	ESCRegisterDCStartTime0    ESCRegister = 0x0990
	ESCRegisterDCStartTime1    ESCRegister = 0x0998
	ESCRegisterDCCycleTime0    ESCRegister = 0x09A0
	ESCRegisterDCCycleTime1    ESCRegister = 0x09A4
	ESCRegisterDCLatch0Control ESCRegister = 0x09A8
	ESCRegisterDCLatch1Control ESCRegister = 0x09A9
	ESCRegisterDCLatch0Status  ESCRegister = 0x09AE
	ESCRegisterDCLatch1Status  ESCRegister = 0x09AF
	ESCRegisterDCLatch0Pos     ESCRegister = 0x09B0
	ESCRegisterDCLatch0Neg     ESCRegister = 0x09B8
	ESCRegisterDCLatch1Pos     ESCRegister = 0x09C0
	ESCRegisterDCLatch1Neg     ESCRegister = 0x09C8
	ESCRegisterDCSMChangeTime  ESCRegister = 0x09F0
	ESCRegisterDCPDISMStart    ESCRegister = 0x09F8
	ESCRegisterDCPDISMChange   ESCRegister = 0x09FC
	ESCRegisterProductID       ESCRegister = 0x0E00
	ESCRegisterVendorID        ESCRegister = 0x0E08
	ESCRegisterDigitalOutput   ESCRegister = 0x0F00
	ESCRegisterGPOutput        ESCRegister = 0x0F10
	ESCRegisterGPInput         ESCRegister = 0x0F18
	ESCRegisterUserRAM         ESCRegister = 0x0F80
)

const (
	escFMMULen   = 16
	escFMMUCount = 16
	escSMLen     = 8
	escSMCount   = 8
	escWordLen   = 2
	escQuadLen   = 8

	// escUserRAMLen is the user RAM at the end of the register area,
	// 0x0F80 to 0x0FFF.
	escUserRAMLen = 128

	// escMemoryStart is where the registers end and the process data
	// memory (mailboxes, PDO buffers) begins.
	escMemoryStart ESCRegister = 0x1000
)

// escRegisterInfo describes one register, or a block of repeat equal
// registers that follow each other.
type escRegisterInfo struct {
	reg    ESCRegister
	size   uint16
	repeat uint16
	name   string
}

// escRegisters is sorted by offset. Where a 64-bit register can also be
// read in halves, the full register comes first and its high half has an
// entry of its own; Registers() skips halves already covered.
var escRegisters = [...]escRegisterInfo{
	{ESCRegisterType, 1, 1, "ESC Type"},
	{ESCRegisterRevision, 1, 1, "ESC Revision"},
	{ESCRegisterBuild, 2, 1, "ESC Build"},
	{ESCRegisterFMMUCount, 1, 1, "ESC FMMU Count"},
	{ESCRegisterSMCount, 1, 1, "ESC SM Count"},
	{ESCRegisterRAMSize, 1, 1, "ESC DPRAM Size"},
	{ESCRegisterPorts, 1, 1, "ESC Ports"},
	{ESCRegisterFeatures, 2, 1, "ESC Features"},
	{ESCRegisterStationAddress, 2, 1, "Station Address"},
	{ESCRegisterStationAlias, 2, 1, "Station Alias"},
	{ESCRegisterWriteProtect, 2, 1, "Write Register Protect"},
	{ESCRegisterAccessProtect, 2, 1, "Access Protect"},
	{ESCRegisterResetECAT, 1, 1, "ESC Reset ECAT"},
	{ESCRegisterResetPDI, 1, 1, "ESC Reset PDI"},
	{ESCRegisterDLControl, 1, 1, "DL Control 0"},
	{ESCRegisterDLControl1, 1, 1, "DL Control 1"},
	{ESCRegisterDLControl2, 1, 1, "DL Control 2"},
	{ESCRegisterDLControl3, 1, 1, "DL Control 3"},
	{ESCRegisterPhysRWOffset, 2, 1, "Physical RW Offset"},
	{ESCRegisterDLStatus, 1, 1, "DL Status 0"},
	{ESCRegisterDLStatus1, 1, 1, "DL Status 1"},
	{ESCRegisterALControl, 2, 1, "AL Control"},
	{ESCRegisterALStatus, 2, 1, "AL Status"},
	{ESCRegisterALStatusCode, 2, 1, "AL Status Code"},
	{ESCRegisterPDIControl, 1, 1, "PDI Control"},
	{ESCRegisterPDIConfig, 1, 1, "PDI Configuration"},
	{ESCRegisterECATIRQMask, 2, 1, "ECAT IRQ Mask"},
	{ESCRegisterPDIIRQMaskLow, 2, 1, "PDI IRQ Mask L"},
	{ESCRegisterPDIIRQMaskHigh, 2, 1, "PDI IRQ Mask H"},
	{ESCRegisterECATIRQ, 2, 1, "ECAT IRQ"},
	{ESCRegisterPDIIRQLow, 2, 1, "PDI IRQ 1"},
	{ESCRegisterPDIIRQHigh, 2, 1, "PDI IRQ 2"},
	{ESCRegisterCRCError0, 2, 1, "CRC Error 0"},
	{ESCRegisterCRCError1, 2, 1, "CRC Error 1"},
	{ESCRegisterCRCError2, 2, 1, "CRC Error 2"},
	{ESCRegisterCRCError3, 2, 1, "CRC Error 3"},
	{ESCRegisterForwardedCRC0, 1, 1, "Forwarded CRC Error 0"},
	{ESCRegisterForwardedCRC1, 1, 1, "Forwarded CRC Error 1"},
	{ESCRegisterForwardedCRC2, 1, 1, "Forwarded CRC Error 2"},
	{ESCRegisterForwardedCRC3, 1, 1, "Forwarded CRC Error 3"},
	{ESCRegisterProcessUnitErr, 1, 1, "Processing Unit Error"},
	{ESCRegisterPDIError, 1, 1, "PDI Error"},
	{ESCRegisterLinkLost0, 1, 1, "Link Lost 0"},
	{ESCRegisterLinkLost1, 1, 1, "Link Lost 1"},
	{ESCRegisterLinkLost2, 1, 1, "Link Lost 2"},
	{ESCRegisterLinkLost3, 1, 1, "Link Lost 3"},
	{ESCRegisterWDDivider, 2, 1, "Watchdog Divider"},
	{ESCRegisterWDTimePDI, 2, 1, "Watchdog Time PDI"},
	{ESCRegisterWDTimeSM, 2, 1, "Watchdog Time SM"},
	{ESCRegisterWDStatus, 1, 1, "Watchdog Status"},
	{ESCRegisterWDCounterSM, 1, 1, "Watchdog Counter SM"},
	{ESCRegisterWDCounterPDI, 1, 1, "Watchdog Counter PDI"},
	{ESCRegisterEEPROMAssign, 2, 1, "EEPROM Assign"},
	{ESCRegisterEEPROMControl, 2, 1, "EEPROM Control/Status"},
	{ESCRegisterEEPROMAddrLow, 2, 1, "EEPROM Address Lo"},
	{ESCRegisterEEPROMAddrHigh, 2, 1, "EEPROM Address Hi"},
	{ESCRegisterEEPROMData0, 2, 1, "EEPROM Data 0"},
	{ESCRegisterEEPROMData1, 2, 1, "EEPROM Data 1"},
	{ESCRegisterEEPROMData2, 2, 1, "EEPROM Data 2"},
	{ESCRegisterEEPROMData3, 2, 1, "EEPROM Data 3"},
	{ESCRegisterMIIControl, 2, 1, "MII Control/Status"},
	{ESCRegisterMIIAddress, 2, 1, "MII Address"},
	{ESCRegisterMIIData, 2, 1, "MII Data"},
	{ESCRegisterMIIAccess, 2, 1, "MII Access"},
	{ESCRegisterMIIPortStatus0, 1, 1, "MII Port Status 0"},
	{ESCRegisterMIIPortStatus1, 1, 1, "MII Port Status 1"},
	{ESCRegisterMIIPortStatus2, 1, 1, "MII Port Status 2"},
	{ESCRegisterMIIPortStatus3, 1, 1, "MII Port Status 3"},
	{ESCRegisterFMMU, escFMMULen, escFMMUCount, "FMMU"},
	{ESCRegisterSyncManager, escSMLen, escSMCount, "SyncManager"},
	{ESCRegisterDCRecvTime0, 4, 1, "DC Receive Time 0"},
	{ESCRegisterDCRecvTime1, 4, 1, "DC Receive Time 1"},
	{ESCRegisterDCRecvTime2, 4, 1, "DC Receive Time 2"},
	{ESCRegisterDCRecvTime3, 4, 1, "DC Receive Time 3"},
	{ESCRegisterDCSystemTime, 8, 1, "DC System Time"},
	{ESCRegisterDCSystemTime, 4, 1, "DC System Time L"},
	{ESCRegisterDCSystemTimeHi, 4, 1, "DC System Time H"},
	{ESCRegisterDCRecvTimeUnit, 8, 1, "DC Receive Time Processing Unit"},
	{ESCRegisterDCTimeOffset, 8, 1, "DC System Time Offset"},
	{ESCRegisterDCTimeOffset, 4, 1, "DC System Time Offset L"},
	{ESCRegisterDCTimeOffsetHi, 4, 1, "DC System Time Offset H"},
	{ESCRegisterDCTimeDelay, 4, 1, "DC System Time Delay"},
	{ESCRegisterDCControlError, 4, 1, "DC Control Error"},
	{ESCRegisterDCSpeedStart, 2, 1, "DC Speed Counter Start"},
	{ESCRegisterDCSpeedDiff, 2, 1, "DC Speed Counter Diff"},
	{ESCRegisterDCFilterTime, 1, 1, "DC Filter Depth System Time"},
	{ESCRegisterDCFilterSpeed, 1, 1, "DC Filter Depth Speed Counter"},
	{ESCRegisterDCCyclicControl, 1, 1, "DC Cyclic Unit Control"},
	{ESCRegisterDCActivation, 1, 1, "DC Activation"},
	{ESCRegisterDCPulseLength, 2, 1, "DC Pulse Length"},
	{ESCRegisterDCActivationSt, 1, 1, "DC Activation Status"},
	{ESCRegisterDCSync0Status, 1, 1, "DC Sync0 Status"},
	{ESCRegisterDCSync1Status, 1, 1, "DC Sync1 Status"},
	{ESCRegisterDCStartTime0, 8, 1, "DC Start Time 0"},
	{ESCRegisterDCStartTime1, 8, 1, "DC Start Time 1"},
	{ESCRegisterDCCycleTime0, 4, 1, "DC Cycle Time 0"},
	{ESCRegisterDCCycleTime1, 4, 1, "DC Cycle Time 1"},
	{ESCRegisterDCLatch0Control, 1, 1, "DC Latch0 Control"},
	{ESCRegisterDCLatch1Control, 1, 1, "DC Latch1 Control"},
	{ESCRegisterDCLatch0Status, 1, 1, "DC Latch0 Status"},
	{ESCRegisterDCLatch1Status, 1, 1, "DC Latch1 Status"},
	{ESCRegisterDCLatch0Pos, 8, 1, "DC Latch0 Positive Edge"},
	{ESCRegisterDCLatch0Neg, 8, 1, "DC Latch0 Negative Edge"},
	{ESCRegisterDCLatch1Pos, 8, 1, "DC Latch1 Positive Edge"},
	{ESCRegisterDCLatch1Neg, 8, 1, "DC Latch1 Negative Edge"},
	{ESCRegisterDCSMChangeTime, 4, 1, "DC ECAT Buffer Change Event Time"},
	{ESCRegisterDCPDISMStart, 4, 1, "DC PDI Buffer Start Event Time"},
	{ESCRegisterDCPDISMChange, 4, 1, "DC PDI Buffer Change Event Time"},
	{ESCRegisterProductID, 8, 1, "ESC Product ID"},
	{ESCRegisterVendorID, 8, 1, "ESC Vendor ID"},
	{ESCRegisterDigitalOutput, 4, 1, "Digital I/O Output Data"},
	{ESCRegisterGPOutput, 8, 1, "General Purpose Outputs"},
	{ESCRegisterGPInput, 8, 1, "General Purpose Inputs"},
	{ESCRegisterUserRAM, escUserRAMLen, 1, "User RAM"},
}

// escRegisterMax is the most values Registers() can return: every table
// entry once, with the FMMU and sync manager blocks expanded.
const escRegisterMax = len(escRegisters) + escFMMUCount + escSMCount

// String returns the register name, or the hex offset of an unnamed one.
// FMMU and sync manager registers are named by their start, e.g.
// "FMMU 2" for 0x0620; offsets inside a block are unnamed.
func (r ESCRegister) String() string {
	for i := range escRegisters {
		info := &escRegisters[i]
		if r < info.reg {
			break
		}

		if info.repeat == 1 {
			if r == info.reg {
				return info.name
			}
			continue
		}

		off := uint16(r - info.reg)
		if off < info.size*info.repeat && off%info.size == 0 {
			return fmt.Sprintf("%s %d", info.name, off/info.size)
		}
	}
	return fmt.Sprintf("0x%04x", uint16(r))
}

// IsMemory reports whether the offset lies in the process data memory
// (0x1000 and up) instead of the register area.
func (r ESCRegister) IsMemory() bool { return r >= escMemoryStart }

// ESCRegisterValue is one register found in the data of a datagram.
// Data aliases the packet data and has the register's size.
type ESCRegisterValue struct {
	Register ESCRegister
	Data     []byte
}

// Uint returns the little-endian value of a register of up to 8 bytes,
// and 0 for longer ones (FMMU and sync manager blocks, user RAM).
func (v ESCRegisterValue) Uint() uint64 {
	if len(v.Data) > escQuadLen {
		return 0
	}

	var out uint64
	for i, b := range v.Data {
		out |= uint64(b) << (ethercatBitsPerByte * uint(i))
	}
	return out
}

// Register returns the first register the datagram addresses: its ADO.
// It means nothing for NOP and the logical commands.
func (d *EtherCATDatagram) Register() ESCRegister { return ESCRegister(d.ADO()) }

// IsPhysical reports whether the command addresses slave memory by ADO.
func (c EtherCATCommand) IsPhysical() bool {
	return c >= EtherCATCommandAPRD && c <= EtherCATCommandFRMW && !c.IsLogical()
}

// registerData returns the datagram data when it holds register values,
// nil otherwise. Like Wireshark it takes written data as is and read
// data only once a slave has answered (working counter above zero): a
// read request leaves the master filled with zeros.
func (d *EtherCATDatagram) registerData() []byte {
	if !d.Command.IsPhysical() {
		return nil
	}

	switch d.Command {
	case EtherCATCommandAPRD, EtherCATCommandFPRD, EtherCATCommandBRD:
		if d.WorkingCounter == 0 {
			return nil
		}
	}
	return d.Data
}

// RegisterBytes returns the size bytes at register reg when the datagram
// carries valid data for all of them, nil otherwise.
func (d *EtherCATDatagram) RegisterBytes(reg ESCRegister, size int) []byte {
	data := d.registerData()
	start := int(reg) - int(d.ADO())
	if size <= 0 || start < 0 || start+size > len(data) {
		return nil
	}
	return data[start : start+size]
}

// Registers lists the named registers the datagram data covers in full,
// in offset order. It returns nil when the datagram carries no valid
// register data; see RegisterBytes. The list is built on each call and
// is bounded by the register table, not by the packet.
func (d *EtherCATDatagram) Registers() []ESCRegisterValue {
	data := d.registerData()
	if len(data) == 0 {
		return nil
	}

	first := int(d.ADO())
	end := first + len(data)
	var out []ESCRegisterValue
	covered := -1 // end of the last 64-bit register, to skip its halves

	for i := range escRegisters {
		info := &escRegisters[i]
		if int(info.reg) >= end {
			break
		}

		for r := 0; r < int(info.repeat); r++ {
			start := int(info.reg) + r*int(info.size)
			stop := start + int(info.size)
			if start < first || stop > end || stop <= covered {
				continue
			}

			if out == nil {
				out = make([]ESCRegisterValue, 0, escRegisterMax)
			}
			out = append(out, ESCRegisterValue{
				Register: ESCRegister(start),
				Data:     data[start-first : stop-first],
			})
			if info.size == escQuadLen {
				covered = stop
			}
		}
	}
	return out
}

// ESCALState is an EtherCAT state machine state.
type ESCALState uint8

// EtherCAT state machine states.
const (
	ESCALStateInit      ESCALState = 1
	ESCALStatePreOp     ESCALState = 2
	ESCALStateBootstrap ESCALState = 3
	ESCALStateSafeOp    ESCALState = 4
	ESCALStateOp        ESCALState = 8
)

// String returns the state name.
func (s ESCALState) String() string {
	switch s {
	case ESCALStateInit:
		return "INIT"
	case ESCALStatePreOp:
		return "PREOP"
	case ESCALStateBootstrap:
		return "BOOTSTRAP"
	case ESCALStateSafeOp:
		return "SAFEOP"
	case ESCALStateOp:
		return "OP"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(s))
}

const (
	escALStateMask = 0x000F
	escALErrorBit  = 0x0010
	escALIDBit     = 0x0020
)

// ESCALControl is the AL control register (0x0120): the state the master
// requests.
type ESCALControl uint16

// State returns the requested state.
func (c ESCALControl) State() ESCALState { return ESCALState(c & escALStateMask) }

// ErrorAck reports whether the master acknowledges an error.
func (c ESCALControl) ErrorAck() bool { return c&escALErrorBit != 0 }

// IDRequest reports whether the master requests the device ID.
func (c ESCALControl) IDRequest() bool { return c&escALIDBit != 0 }

// ESCALStatus is the AL status register (0x0130): the state the slave is
// in.
type ESCALStatus uint16

// State returns the current state.
func (s ESCALStatus) State() ESCALState { return ESCALState(s & escALStateMask) }

// Error reports whether the slave signals an error; the AL status code
// register says which.
func (s ESCALStatus) Error() bool { return s&escALErrorBit != 0 }

// IDLoaded reports whether the device ID is in the AL status code.
func (s ESCALStatus) IDLoaded() bool { return s&escALIDBit != 0 }

const (
	escDLOperational   = 0x0001
	escDLWatchdog      = 0x0002
	escDLEnhancedLink  = 0x0004
	escDLPhysLinkShift = 4
	escDLLoopShift     = 8
	escDLPortBits      = 2
	escDLPortCount     = 4
	escDLLoopClosed    = 0x01
	escDLCommunication = 0x02
)

// ESCDLStatus is the DL status register (0x0110, 2 bytes): the link
// state of the four ports.
type ESCDLStatus uint16

// PDIOperational reports whether the EEPROM is loaded and the PDI runs.
func (s ESCDLStatus) PDIOperational() bool { return s&escDLOperational != 0 }

// PDIWatchdog reports whether the PDI watchdog is reloaded (not expired).
func (s ESCDLStatus) PDIWatchdog() bool { return s&escDLWatchdog != 0 }

// EnhancedLinkDetection reports whether enhanced link detection is on.
func (s ESCDLStatus) EnhancedLinkDetection() bool { return s&escDLEnhancedLink != 0 }

// PhysicalLink reports whether port 0-3 has a physical link.
func (s ESCDLStatus) PhysicalLink(port int) bool {
	if port < 0 || port >= escDLPortCount {
		return false
	}
	return s>>(escDLPhysLinkShift+uint(port))&1 != 0
}

// LoopClosed reports whether port 0-3 forwards frames back (no neighbour).
func (s ESCDLStatus) LoopClosed(port int) bool { return s.portBits(port)&escDLLoopClosed != 0 }

// Communication reports whether port 0-3 has a stable link to a neighbour.
func (s ESCDLStatus) Communication(port int) bool { return s.portBits(port)&escDLCommunication != 0 }

// portBits returns the two loop bits of a port, 0 for a bad port number.
func (s ESCDLStatus) portBits(port int) uint16 {
	if port < 0 || port >= escDLPortCount {
		return 0
	}
	return uint16(s) >> (escDLLoopShift + escDLPortBits*uint(port))
}

const (
	escFMMUReadBit  = 0x01
	escFMMUWriteBit = 0x02
	escEnableBit    = 0x01
)

// ESCFMMU is one fieldbus memory management unit configuration block
// (0x0600 + 16n): it maps a logical address range onto slave memory.
type ESCFMMU struct {
	LogicalStart     uint32
	Length           uint16
	LogicalStartBit  uint8
	LogicalEndBit    uint8
	PhysicalStart    uint16
	PhysicalStartBit uint8
	Type             uint8
	Activate         uint8
}

// Read reports whether the mapping serves logical reads.
func (f ESCFMMU) Read() bool { return f.Type&escFMMUReadBit != 0 }

// Write reports whether the mapping serves logical writes.
func (f ESCFMMU) Write() bool { return f.Type&escFMMUWriteBit != 0 }

// Enabled reports whether the FMMU is activated.
func (f ESCFMMU) Enabled() bool { return f.Activate&escEnableBit != 0 }

// ESCSMMode is the buffer mode of a sync manager.
type ESCSMMode uint8

// Sync manager modes.
const (
	ESCSMModeBuffered ESCSMMode = 0 // 3 buffers, process data
	ESCSMModeMailbox  ESCSMMode = 2 // 1 buffer, handshake
)

const (
	escSMModeMask    = 0x03
	escSMAccessShift = 2
	escSMAccessMask  = 0x03
	escSMWriteAccess = 1
)

// ESCSyncManager is one sync manager configuration block (0x0800 + 8n).
type ESCSyncManager struct {
	Start      uint16
	Length     uint16
	Control    uint8
	Status     uint8
	Activate   uint8
	PDIControl uint8
}

// Mode returns the buffer mode.
func (s ESCSyncManager) Mode() ESCSMMode { return ESCSMMode(s.Control & escSMModeMask) }

// MasterWrites reports the direction: true when the master writes the
// buffer (outputs, mailbox out), false when it reads it.
func (s ESCSyncManager) MasterWrites() bool {
	return s.Control>>escSMAccessShift&escSMAccessMask == escSMWriteAccess
}

// Enabled reports whether the sync manager is activated.
func (s ESCSyncManager) Enabled() bool { return s.Activate&escEnableBit != 0 }

// ALControl returns the AL control register when the datagram carries it.
func (d *EtherCATDatagram) ALControl() (ESCALControl, bool) {
	b := d.RegisterBytes(ESCRegisterALControl, escWordLen)
	if b == nil {
		return 0, false
	}
	return ESCALControl(binary.LittleEndian.Uint16(b)), true
}

// ALStatus returns the AL status register when the datagram carries it.
func (d *EtherCATDatagram) ALStatus() (ESCALStatus, bool) {
	b := d.RegisterBytes(ESCRegisterALStatus, escWordLen)
	if b == nil {
		return 0, false
	}
	return ESCALStatus(binary.LittleEndian.Uint16(b)), true
}

// DLStatus returns the DL status register when the datagram carries it.
func (d *EtherCATDatagram) DLStatus() (ESCDLStatus, bool) {
	b := d.RegisterBytes(ESCRegisterDLStatus, escWordLen)
	if b == nil {
		return 0, false
	}
	return ESCDLStatus(binary.LittleEndian.Uint16(b)), true
}

// FMMU returns the configuration of FMMU n (0-15) when the datagram
// carries all of it.
func (d *EtherCATDatagram) FMMU(n int) (ESCFMMU, bool) {
	if n < 0 || n >= escFMMUCount {
		return ESCFMMU{}, false
	}

	b := d.RegisterBytes(ESCRegisterFMMU+ESCRegister(n*escFMMULen), escFMMULen)
	if b == nil {
		return ESCFMMU{}, false
	}

	return ESCFMMU{
		LogicalStart:     binary.LittleEndian.Uint32(b[0:4]),
		Length:           binary.LittleEndian.Uint16(b[4:6]),
		LogicalStartBit:  b[6],
		LogicalEndBit:    b[7],
		PhysicalStart:    binary.LittleEndian.Uint16(b[8:10]),
		PhysicalStartBit: b[10],
		Type:             b[11],
		Activate:         b[12],
	}, true
}

// SyncManager returns the configuration of sync manager n (0-7) when the
// datagram carries all of it.
func (d *EtherCATDatagram) SyncManager(n int) (ESCSyncManager, bool) {
	if n < 0 || n >= escSMCount {
		return ESCSyncManager{}, false
	}

	b := d.RegisterBytes(ESCRegisterSyncManager+ESCRegister(n*escSMLen), escSMLen)
	if b == nil {
		return ESCSyncManager{}, false
	}

	return ESCSyncManager{
		Start:      binary.LittleEndian.Uint16(b[0:2]),
		Length:     binary.LittleEndian.Uint16(b[2:4]),
		Control:    b[4],
		Status:     b[5],
		Activate:   b[6],
		PDIControl: b[7],
	}, true
}

// escDCEpoch is the start of the distributed clock time scale.
var escDCEpoch = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// DCSystemTime returns the distributed clock system time register
// (0x0910): nanoseconds since 2000-01-01. A 4-byte access yields the low
// half only, which wraps every 4.29 s; ok is false for it.
func (d *EtherCATDatagram) DCSystemTime() (ns uint64, ok bool) {
	b := d.RegisterBytes(ESCRegisterDCSystemTime, escQuadLen)
	if b == nil {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

// ESCDCTime converts a 64-bit distributed clock time to wall time. Times
// too far out for time.Duration (after the year 2292) saturate.
func ESCDCTime(ns uint64) time.Time {
	if ns > math.MaxInt64 {
		ns = math.MaxInt64
	}
	return escDCEpoch.Add(time.Duration(ns))
}
