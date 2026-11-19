// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Typed views of the EtherCAT slave controller registers that are not
// plain numbers (ETG.1000.4, ETG.1000.6 and the Beckhoff ESC register
// description):
//
//	0x0134  AL status code       0x0502  EEPROM control/status
//	0x0400  watchdog divider     0x0504  EEPROM address
//	0x0410  watchdog time PDI    0x0508  EEPROM data (4 or 8 bytes)
//	0x0420  watchdog time SM     0x0510  MII management
//	0x0440  watchdog status      0x0980  DC sync activation, start
//	                                     and cycle times, latches
//
// Every accessor returns false unless the datagram carries the whole
// register with valid data, as RegisterBytes defines it.

package layers

import (
	"encoding/binary"
	"fmt"
	"time"
)

// ESCArea is a block of the slave controller address space.
type ESCArea uint8

// Address space areas, in address order.
const (
	ESCAreaInformation ESCArea = iota
	ESCAreaStation
	ESCAreaProtection
	ESCAreaDataLink
	ESCAreaApplication
	ESCAreaInterrupt
	ESCAreaErrorCounter
	ESCAreaWatchdog
	ESCAreaEEPROM
	ESCAreaMII
	ESCAreaFMMU
	ESCAreaSyncManager
	ESCAreaDC
	ESCAreaSpecific
	ESCAreaDigitalIO
	ESCAreaUserRAM
	ESCAreaMemory
	ESCAreaReserved
)

// Offsets where the unused gaps of the register area begin.
const (
	escGapProtection  ESCRegister = 0x0050
	escGapMII         ESCRegister = 0x0520
	escGapFMMU        ESCRegister = 0x0700
	escGapSyncManager ESCRegister = 0x0880
	escGapDC          ESCRegister = 0x0A00
)

// escAreas lists the first offset of every area, sorted.
var escAreas = [...]struct {
	start ESCRegister
	area  ESCArea
	name  string
}{
	{ESCRegisterType, ESCAreaInformation, "ESC information"},
	{ESCRegisterStationAddress, ESCAreaStation, "Station address"},
	{ESCRegisterWriteProtect, ESCAreaProtection, "Write protection and reset"},
	{escGapProtection, ESCAreaReserved, "Reserved"},
	{ESCRegisterDLControl, ESCAreaDataLink, "Data link layer"},
	{ESCRegisterALControl, ESCAreaApplication, "Application layer"},
	{ESCRegisterECATIRQMask, ESCAreaInterrupt, "Interrupts"},
	{ESCRegisterCRCError0, ESCAreaErrorCounter, "Error counters"},
	{ESCRegisterWDDivider, ESCAreaWatchdog, "Watchdogs"},
	{ESCRegisterEEPROMAssign, ESCAreaEEPROM, "EEPROM interface"},
	{ESCRegisterMIIControl, ESCAreaMII, "MII management"},
	{escGapMII, ESCAreaReserved, "Reserved"},
	{ESCRegisterFMMU, ESCAreaFMMU, "FMMU"},
	{escGapFMMU, ESCAreaReserved, "Reserved"},
	{ESCRegisterSyncManager, ESCAreaSyncManager, "Sync managers"},
	{escGapSyncManager, ESCAreaReserved, "Reserved"},
	{ESCRegisterDCRecvTime0, ESCAreaDC, "Distributed clocks"},
	{escGapDC, ESCAreaReserved, "Reserved"},
	{ESCRegisterProductID, ESCAreaSpecific, "ESC specific"},
	{ESCRegisterDigitalOutput, ESCAreaDigitalIO, "Digital and general purpose I/O"},
	{ESCRegisterUserRAM, ESCAreaUserRAM, "User RAM"},
	{escMemoryStart, ESCAreaMemory, "Process data memory"},
}

// String returns the area name.
func (a ESCArea) String() string {
	for i := range escAreas {
		if escAreas[i].area == a {
			return escAreas[i].name
		}
	}
	return fmt.Sprintf("Unknown(%d)", uint8(a))
}

// Area returns the block of the address space the offset lies in. Every
// offset has one, named register or not: e.g. 0x0E10 is ESC specific and
// 0x0FA4 user RAM.
func (r ESCRegister) Area() ESCArea {
	area := ESCAreaInformation
	for i := range escAreas {
		if r < escAreas[i].start {
			break
		}
		area = escAreas[i].area
	}
	return area
}

// ESCALStatusCode is the AL status code register (0x0134): why a slave
// refused a state change or left a state.
type ESCALStatusCode uint16

// AL status codes (ETG.1000.6 table 11).
const (
	ESCALNoError              ESCALStatusCode = 0x0000
	ESCALUnspecifiedError     ESCALStatusCode = 0x0001
	ESCALNoMemory             ESCALStatusCode = 0x0002
	ESCALInvalidDeviceSetup   ESCALStatusCode = 0x0003
	ESCALSIIMismatch          ESCALStatusCode = 0x0006
	ESCALFirmwareUpdateFailed ESCALStatusCode = 0x0007
	ESCALLicenseError         ESCALStatusCode = 0x000E
	ESCALInvalidStateChange   ESCALStatusCode = 0x0011
	ESCALUnknownState         ESCALStatusCode = 0x0012
	ESCALNoBootstrap          ESCALStatusCode = 0x0013
	ESCALNoValidFirmware      ESCALStatusCode = 0x0014
	ESCALMailboxConfigBoot    ESCALStatusCode = 0x0015
	ESCALMailboxConfigPreOp   ESCALStatusCode = 0x0016
	ESCALSyncManagerConfig    ESCALStatusCode = 0x0017
	ESCALNoValidInputs        ESCALStatusCode = 0x0018
	ESCALNoValidOutputs       ESCALStatusCode = 0x0019
	ESCALSyncError            ESCALStatusCode = 0x001A
	ESCALSyncManagerWatchdog  ESCALStatusCode = 0x001B
	ESCALSyncManagerTypes     ESCALStatusCode = 0x001C
	ESCALOutputConfig         ESCALStatusCode = 0x001D
	ESCALInputConfig          ESCALStatusCode = 0x001E
	ESCALWatchdogConfig       ESCALStatusCode = 0x001F
	ESCALNeedColdStart        ESCALStatusCode = 0x0020
	ESCALNeedInit             ESCALStatusCode = 0x0021
	ESCALNeedPreOp            ESCALStatusCode = 0x0022
	ESCALNeedSafeOp           ESCALStatusCode = 0x0023
	ESCALInputMapping         ESCALStatusCode = 0x0024
	ESCALOutputMapping        ESCALStatusCode = 0x0025
	ESCALInconsistentSettings ESCALStatusCode = 0x0026
	ESCALNoFreeRun            ESCALStatusCode = 0x0027
	ESCALNoSyncMode           ESCALStatusCode = 0x0028
	ESCALFreeRunThreeBuffer   ESCALStatusCode = 0x0029
	ESCALBackgroundWatchdog   ESCALStatusCode = 0x002A
	ESCALNoValidIO            ESCALStatusCode = 0x002B
	ESCALFatalSyncError       ESCALStatusCode = 0x002C
	ESCALNoSyncError          ESCALStatusCode = 0x002D
	ESCALCycleTimeTooSmall    ESCALStatusCode = 0x002E
	ESCALDCSyncConfig         ESCALStatusCode = 0x0030
	ESCALDCLatchConfig        ESCALStatusCode = 0x0031
	ESCALPLLError             ESCALStatusCode = 0x0032
	ESCALDCSyncIOError        ESCALStatusCode = 0x0033
	ESCALDCSyncTimeout        ESCALStatusCode = 0x0034
	ESCALDCSyncCycleTime      ESCALStatusCode = 0x0035
	ESCALDCSync0CycleTime     ESCALStatusCode = 0x0036
	ESCALDCSync1CycleTime     ESCALStatusCode = 0x0037
	ESCALMailboxAoE           ESCALStatusCode = 0x0041
	ESCALMailboxEoE           ESCALStatusCode = 0x0042
	ESCALMailboxCoE           ESCALStatusCode = 0x0043
	ESCALMailboxFoE           ESCALStatusCode = 0x0044
	ESCALMailboxSoE           ESCALStatusCode = 0x0045
	ESCALMailboxVoE           ESCALStatusCode = 0x004F
	ESCALEEPROMNoAccess       ESCALStatusCode = 0x0050
	ESCALEEPROMError          ESCALStatusCode = 0x0051
	ESCALHardwareNotReady     ESCALStatusCode = 0x0052
	ESCALRestartedLocally     ESCALStatusCode = 0x0060
	ESCALDeviceIDUpdated      ESCALStatusCode = 0x0061
	ESCALModuleIdentMismatch  ESCALStatusCode = 0x0070
	ESCALAppControllerReady   ESCALStatusCode = 0x00F0

	// escALVendorStart is where the vendor specific codes begin.
	escALVendorStart ESCALStatusCode = 0x8000
)

// escALStatusNames is sorted by code.
var escALStatusNames = [...]struct {
	code ESCALStatusCode
	name string
}{
	{ESCALNoError, "No error"},
	{ESCALUnspecifiedError, "Unspecified error"},
	{ESCALNoMemory, "No memory"},
	{ESCALInvalidDeviceSetup, "Invalid device setup"},
	{ESCALSIIMismatch, "SII/EEPROM information does not match firmware"},
	{ESCALFirmwareUpdateFailed, "Firmware update not successful"},
	{ESCALLicenseError, "License error"},
	{ESCALInvalidStateChange, "Invalid requested state change"},
	{ESCALUnknownState, "Unknown requested state"},
	{ESCALNoBootstrap, "Bootstrap not supported"},
	{ESCALNoValidFirmware, "No valid firmware"},
	{ESCALMailboxConfigBoot, "Invalid mailbox configuration (bootstrap)"},
	{ESCALMailboxConfigPreOp, "Invalid mailbox configuration (pre-operational)"},
	{ESCALSyncManagerConfig, "Invalid sync manager configuration"},
	{ESCALNoValidInputs, "No valid inputs available"},
	{ESCALNoValidOutputs, "No valid outputs"},
	{ESCALSyncError, "Synchronization error"},
	{ESCALSyncManagerWatchdog, "Sync manager watchdog"},
	{ESCALSyncManagerTypes, "Invalid sync manager types"},
	{ESCALOutputConfig, "Invalid output configuration"},
	{ESCALInputConfig, "Invalid input configuration"},
	{ESCALWatchdogConfig, "Invalid watchdog configuration"},
	{ESCALNeedColdStart, "Slave needs cold start"},
	{ESCALNeedInit, "Slave needs INIT"},
	{ESCALNeedPreOp, "Slave needs PREOP"},
	{ESCALNeedSafeOp, "Slave needs SAFEOP"},
	{ESCALInputMapping, "Invalid input mapping"},
	{ESCALOutputMapping, "Invalid output mapping"},
	{ESCALInconsistentSettings, "Inconsistent settings"},
	{ESCALNoFreeRun, "Free run not supported"},
	{ESCALNoSyncMode, "Synchronization mode not supported"},
	{ESCALFreeRunThreeBuffer, "Free run needs 3-buffer mode"},
	{ESCALBackgroundWatchdog, "Background watchdog"},
	{ESCALNoValidIO, "No valid inputs and outputs"},
	{ESCALFatalSyncError, "Fatal sync error"},
	{ESCALNoSyncError, "No sync error"},
	{ESCALCycleTimeTooSmall, "Cycle time too small"},
	{ESCALDCSyncConfig, "Invalid DC SYNC configuration"},
	{ESCALDCLatchConfig, "Invalid DC latch configuration"},
	{ESCALPLLError, "PLL error"},
	{ESCALDCSyncIOError, "DC sync IO error"},
	{ESCALDCSyncTimeout, "DC sync timeout error"},
	{ESCALDCSyncCycleTime, "DC invalid sync cycle time"},
	{ESCALDCSync0CycleTime, "DC Sync0 cycle time"},
	{ESCALDCSync1CycleTime, "DC Sync1 cycle time"},
	{ESCALMailboxAoE, "Mailbox AoE"},
	{ESCALMailboxEoE, "Mailbox EoE"},
	{ESCALMailboxCoE, "Mailbox CoE"},
	{ESCALMailboxFoE, "Mailbox FoE"},
	{ESCALMailboxSoE, "Mailbox SoE"},
	{ESCALMailboxVoE, "Mailbox VoE"},
	{ESCALEEPROMNoAccess, "EEPROM no access"},
	{ESCALEEPROMError, "EEPROM error"},
	{ESCALHardwareNotReady, "External hardware not ready"},
	{ESCALRestartedLocally, "Slave restarted locally"},
	{ESCALDeviceIDUpdated, "Device identification value updated"},
	{ESCALModuleIdentMismatch, "Detected module ident list does not match"},
	{ESCALAppControllerReady, "Application controller available"},
}

// String returns the status code name. Codes from 0x8000 are vendor
// specific.
func (c ESCALStatusCode) String() string {
	for i := range escALStatusNames {
		if escALStatusNames[i].code == c {
			return escALStatusNames[i].name
		}
	}

	if c >= escALVendorStart {
		return fmt.Sprintf("Vendor specific(0x%04x)", uint16(c))
	}
	return fmt.Sprintf("Unknown(0x%04x)", uint16(c))
}

// ALStatusCode returns the AL status code register when the datagram
// carries it.
func (d *EtherCATDatagram) ALStatusCode() (ESCALStatusCode, bool) {
	v, ok := d.registerWord(ESCRegisterALStatusCode)
	return ESCALStatusCode(v), ok
}

// registerWord returns a 16-bit register when the datagram carries it.
func (d *EtherCATDatagram) registerWord(reg ESCRegister) (uint16, bool) {
	b := d.RegisterBytes(reg, escWordLen)
	if b == nil {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b), true
}

// registerByte returns an 8-bit register when the datagram carries it.
func (d *EtherCATDatagram) registerByte(reg ESCRegister) (uint8, bool) {
	b := d.RegisterBytes(reg, 1)
	if b == nil {
		return 0, false
	}
	return b[0], true
}

// Watchdog timing: the divider register counts 40 ns steps less two, and
// both watchdog times count divider periods.
const (
	escWDStep       = 40 * time.Nanosecond
	escWDDividerOff = 2
	escWDStatusOK   = 0x01
)

// ESCWatchdogDivider is the watchdog divider register (0x0400).
type ESCWatchdogDivider uint16

// Period returns the length of one watchdog tick: 100 us for the
// default divider 2498.
func (w ESCWatchdogDivider) Period() time.Duration {
	return time.Duration(int(w)+escWDDividerOff) * escWDStep
}

// WatchdogDivider returns the watchdog divider register when the
// datagram carries it.
func (d *EtherCATDatagram) WatchdogDivider() (ESCWatchdogDivider, bool) {
	v, ok := d.registerWord(ESCRegisterWDDivider)
	return ESCWatchdogDivider(v), ok
}

// WatchdogTimePDI returns the PDI watchdog time (0x0410), in ticks of
// the watchdog divider.
func (d *EtherCATDatagram) WatchdogTimePDI() (uint16, bool) {
	return d.registerWord(ESCRegisterWDTimePDI)
}

// WatchdogTimeSM returns the process data (sync manager) watchdog time
// (0x0420), in ticks of the watchdog divider.
func (d *EtherCATDatagram) WatchdogTimeSM() (uint16, bool) {
	return d.registerWord(ESCRegisterWDTimeSM)
}

// ESCWatchdogStatus is the process data watchdog status (0x0440).
type ESCWatchdogStatus uint8

// Running reports whether the process data watchdog is active or
// disabled; false means it expired.
func (s ESCWatchdogStatus) Running() bool { return s&escWDStatusOK != 0 }

// WatchdogStatus returns the process data watchdog status when the
// datagram carries it.
func (d *EtherCATDatagram) WatchdogStatus() (ESCWatchdogStatus, bool) {
	v, ok := d.registerByte(ESCRegisterWDStatus)
	return ESCWatchdogStatus(v), ok
}

// EEPROM control/status bits (0x0502).
const (
	escEEWriteEnable  = 0x0001
	escEEEmulated     = 0x0020
	escEERead8        = 0x0040
	escEETwoAddrBytes = 0x0080
	escEECommandShift = 8
	escEECommandMask  = 0x07
	escEEChecksumErr  = 0x0800
	escEELoadErr      = 0x1000
	escEEAckErr       = 0x2000
	escEEWriteErr     = 0x4000
	escEEBusy         = 0x8000
	escEEAddressLen   = 4
	escEEDataShort    = 4
)

// ESCEEPROMCommand is the command field of the EEPROM control register.
type ESCEEPROMCommand uint8

// EEPROM commands.
const (
	ESCEEPROMNop    ESCEEPROMCommand = 0
	ESCEEPROMRead   ESCEEPROMCommand = 1
	ESCEEPROMWrite  ESCEEPROMCommand = 2
	ESCEEPROMReload ESCEEPROMCommand = 4
)

// String returns the command name.
func (c ESCEEPROMCommand) String() string {
	switch c {
	case ESCEEPROMNop:
		return "No command"
	case ESCEEPROMRead:
		return "Read"
	case ESCEEPROMWrite:
		return "Write"
	case ESCEEPROMReload:
		return "Reload"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(c))
}

// ESCEEPROMControl is the EEPROM control/status register (0x0502).
type ESCEEPROMControl uint16

// WriteEnable reports whether write requests are enabled.
func (c ESCEEPROMControl) WriteEnable() bool { return c&escEEWriteEnable != 0 }

// Emulated reports whether the PDI emulates the EEPROM.
func (c ESCEEPROMControl) Emulated() bool { return c&escEEEmulated != 0 }

// ReadSize returns how many data bytes one read yields: 4 or 8.
func (c ESCEEPROMControl) ReadSize() int {
	if c&escEERead8 != 0 {
		return escQuadLen
	}
	return escEEDataShort
}

// TwoAddressBytes reports whether the EEPROM takes two address bytes.
func (c ESCEEPROMControl) TwoAddressBytes() bool { return c&escEETwoAddrBytes != 0 }

// Command returns the command a write starts or a read finds pending.
func (c ESCEEPROMControl) Command() ESCEEPROMCommand {
	return ESCEEPROMCommand(c >> escEECommandShift & escEECommandMask)
}

// ChecksumError reports a checksum error in the ESC configuration area.
func (c ESCEEPROMControl) ChecksumError() bool { return c&escEEChecksumErr != 0 }

// LoadError reports that the device information was not loaded.
func (c ESCEEPROMControl) LoadError() bool { return c&escEELoadErr != 0 }

// AckError reports a missing acknowledge or an invalid command.
func (c ESCEEPROMControl) AckError() bool { return c&escEEAckErr != 0 }

// WriteError reports a write command without write enable.
func (c ESCEEPROMControl) WriteError() bool { return c&escEEWriteErr != 0 }

// Busy reports whether the EEPROM interface is busy.
func (c ESCEEPROMControl) Busy() bool { return c&escEEBusy != 0 }

// EEPROMControl returns the EEPROM control/status register when the
// datagram carries it.
func (d *EtherCATDatagram) EEPROMControl() (ESCEEPROMControl, bool) {
	v, ok := d.registerWord(ESCRegisterEEPROMControl)
	return ESCEEPROMControl(v), ok
}

// EEPROMAddress returns the EEPROM address register (0x0504): a word
// address into the slave information interface. Masters often access
// the low word only; it is returned when the datagram stops there.
func (d *EtherCATDatagram) EEPROMAddress() (uint32, bool) {
	if b := d.RegisterBytes(ESCRegisterEEPROMAddrLow, escEEAddressLen); b != nil {
		return binary.LittleEndian.Uint32(b), true
	}

	v, ok := d.registerWord(ESCRegisterEEPROMAddrLow)
	return uint32(v), ok
}

// EEPROMData returns the EEPROM data register (0x0508): 8 bytes when the
// datagram carries them all, else 4, else nil. It aliases the packet
// data.
func (d *EtherCATDatagram) EEPROMData() []byte {
	if b := d.RegisterBytes(ESCRegisterEEPROMData0, escQuadLen); b != nil {
		return b
	}
	return d.RegisterBytes(ESCRegisterEEPROMData0, escEEDataShort)
}

// MII management bits (0x0510) and layout.
const (
	escMIIWriteEnable  = 0x0001
	escMIIPDIControl   = 0x0002
	escMIILinkDetect   = 0x0004
	escMIIOffsetShift  = 3
	escMIIFiveBits     = 0x1F
	escMIICommandShift = 8
	escMIICommandMask  = 0x03
	escMIIReadErr      = 0x2000
	escMIICommandErr   = 0x4000
	escMIIBusy         = 0x8000
	escMIILen          = 6 // control, PHY address, register, data
)

// ESCMIICommand is the command field of the MII control register.
type ESCMIICommand uint8

// MII management commands.
const (
	ESCMIINop   ESCMIICommand = 0
	ESCMIIRead  ESCMIICommand = 1
	ESCMIIWrite ESCMIICommand = 2
)

// String returns the command name.
func (c ESCMIICommand) String() string {
	switch c {
	case ESCMIINop:
		return "No command"
	case ESCMIIRead:
		return "Read"
	case ESCMIIWrite:
		return "Write"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(c))
}

// ESCMIIControl is the MII management control/status register (0x0510).
type ESCMIIControl uint16

// WriteEnable reports whether PHY register writes are enabled.
func (c ESCMIIControl) WriteEnable() bool { return c&escMIIWriteEnable != 0 }

// PDIControl reports whether the PDI may take over the interface.
func (c ESCMIIControl) PDIControl() bool { return c&escMIIPDIControl != 0 }

// LinkDetection reports whether MI link detection is active.
func (c ESCMIIControl) LinkDetection() bool { return c&escMIILinkDetect != 0 }

// PHYOffset returns the PHY address of port 0.
func (c ESCMIIControl) PHYOffset() uint8 { return uint8(c>>escMIIOffsetShift) & escMIIFiveBits }

// Command returns the command a write starts or a read finds pending.
func (c ESCMIIControl) Command() ESCMIICommand {
	return ESCMIICommand(c >> escMIICommandShift & escMIICommandMask)
}

// ReadError reports a failed PHY read.
func (c ESCMIIControl) ReadError() bool { return c&escMIIReadErr != 0 }

// CommandError reports an invalid command or a write without enable.
func (c ESCMIIControl) CommandError() bool { return c&escMIICommandErr != 0 }

// Busy reports whether the MII management interface is busy.
func (c ESCMIIControl) Busy() bool { return c&escMIIBusy != 0 }

// ESCMII is the MII management interface, registers 0x0510 to 0x0515:
// one access to a PHY register.
type ESCMII struct {
	Control     ESCMIIControl
	PHYAddress  uint8
	PHYRegister uint8
	Data        uint16
}

// MIIControl returns the MII control/status register when the datagram
// carries it.
func (d *EtherCATDatagram) MIIControl() (ESCMIIControl, bool) {
	v, ok := d.registerWord(ESCRegisterMIIControl)
	return ESCMIIControl(v), ok
}

// MII returns the MII management interface when the datagram carries
// control, address and data, as one PHY access does.
func (d *EtherCATDatagram) MII() (ESCMII, bool) {
	b := d.RegisterBytes(ESCRegisterMIIControl, escMIILen)
	if b == nil {
		return ESCMII{}, false
	}

	return ESCMII{
		Control:     ESCMIIControl(binary.LittleEndian.Uint16(b)),
		PHYAddress:  b[2] & escMIIFiveBits,
		PHYRegister: b[3] & escMIIFiveBits,
		Data:        binary.LittleEndian.Uint16(b[4:]),
	}, true
}

// Distributed clock sync and latch unit bits.
const (
	escDCCyclicEnable = 0x01
	escDCSync0Enable  = 0x02
	escDCSync1Enable  = 0x04
	escDCLatchPos     = 0x01
	escDCLatchNeg     = 0x02
	escDCLatchPin     = 0x04
	escDCUnitCount    = 2 // SYNC0 and SYNC1, latch 0 and latch 1
	escDCCycleLen     = 4
	escDCLatchTimeLen = 2 * escQuadLen // positive and negative edge
)

// ESCDCActivation is the DC activation register (0x0981).
type ESCDCActivation uint8

// CyclicOperation reports whether the sync out unit runs.
func (a ESCDCActivation) CyclicOperation() bool { return a&escDCCyclicEnable != 0 }

// Sync0 reports whether SYNC0 pulses are generated.
func (a ESCDCActivation) Sync0() bool { return a&escDCSync0Enable != 0 }

// Sync1 reports whether SYNC1 pulses are generated.
func (a ESCDCActivation) Sync1() bool { return a&escDCSync1Enable != 0 }

// DCActivation returns the DC activation register when the datagram
// carries it.
func (d *EtherCATDatagram) DCActivation() (ESCDCActivation, bool) {
	v, ok := d.registerByte(ESCRegisterDCActivation)
	return ESCDCActivation(v), ok
}

// DCStartTime returns the start time of the cyclic operation (0x0990),
// in nanoseconds of DC system time; see ESCDCTime.
func (d *EtherCATDatagram) DCStartTime() (ns uint64, ok bool) {
	b := d.RegisterBytes(ESCRegisterDCStartTime0, escQuadLen)
	if b == nil {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}

// DCCycleTime returns the cycle time of SYNC0 (n = 0, register 0x09A0)
// or SYNC1 (n = 1, 0x09A4). For SYNC1 it is the delay after SYNC0.
func (d *EtherCATDatagram) DCCycleTime(n int) (time.Duration, bool) {
	if n < 0 || n >= escDCUnitCount {
		return 0, false
	}

	b := d.RegisterBytes(ESCRegisterDCCycleTime0+ESCRegister(n*escDCCycleLen), escDCCycleLen)
	if b == nil {
		return 0, false
	}
	return time.Duration(binary.LittleEndian.Uint32(b)), true
}

// ESCDCLatchControl is a latch control register (0x09A8, 0x09A9).
type ESCDCLatchControl uint8

// PositiveSingle reports whether only the first positive edge latches;
// otherwise every edge does.
func (c ESCDCLatchControl) PositiveSingle() bool { return c&escDCLatchPos != 0 }

// NegativeSingle reports whether only the first negative edge latches.
func (c ESCDCLatchControl) NegativeSingle() bool { return c&escDCLatchNeg != 0 }

// ESCDCLatchStatus is a latch status register (0x09AE, 0x09AF).
type ESCDCLatchStatus uint8

// PositiveEvent reports a latched positive edge.
func (s ESCDCLatchStatus) PositiveEvent() bool { return s&escDCLatchPos != 0 }

// NegativeEvent reports a latched negative edge.
func (s ESCDCLatchStatus) NegativeEvent() bool { return s&escDCLatchNeg != 0 }

// PinState returns the level of the latch input pin.
func (s ESCDCLatchStatus) PinState() bool { return s&escDCLatchPin != 0 }

// DCLatchControl returns the control register of latch n (0 or 1).
func (d *EtherCATDatagram) DCLatchControl(n int) (ESCDCLatchControl, bool) {
	if n < 0 || n >= escDCUnitCount {
		return 0, false
	}

	v, ok := d.registerByte(ESCRegisterDCLatch0Control + ESCRegister(n))
	return ESCDCLatchControl(v), ok
}

// DCLatchStatus returns the status register of latch n (0 or 1).
func (d *EtherCATDatagram) DCLatchStatus(n int) (ESCDCLatchStatus, bool) {
	if n < 0 || n >= escDCUnitCount {
		return 0, false
	}

	v, ok := d.registerByte(ESCRegisterDCLatch0Status + ESCRegister(n))
	return ESCDCLatchStatus(v), ok
}

// ESCDCEdge selects the edge of a latch time.
type ESCDCEdge uint8

// Latch edges.
const (
	ESCDCEdgePositive ESCDCEdge = iota
	ESCDCEdgeNegative
)

// DCLatchTime returns the DC system time latch n (0 or 1) took at the
// given edge (0x09B0 to 0x09CF), in nanoseconds; see ESCDCTime.
func (d *EtherCATDatagram) DCLatchTime(n int, edge ESCDCEdge) (ns uint64, ok bool) {
	if n < 0 || n >= escDCUnitCount || edge > ESCDCEdgeNegative {
		return 0, false
	}

	reg := ESCRegisterDCLatch0Pos + ESCRegister(n*escDCLatchTimeLen+int(edge)*escQuadLen)
	b := d.RegisterBytes(reg, escQuadLen)
	if b == nil {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b), true
}
