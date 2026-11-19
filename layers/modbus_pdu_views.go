// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Typed views of the PDUs whose data ModbusPDU keeps raw: Diagnostics
// (0x08), Report Server ID (0x11) and the CANopen General Reference
// (0x2B, MEI 0x0D). Each is a method that reads the raw fields, so
// decoding a PDU costs and fails no more than before.

// ErrModbusPDUNoView is returned by a view asked of a PDU of another
// function, direction or MEI type, or of an exception.
var ErrModbusPDUNoView = errors.New("modbus PDU does not hold what was asked for")

// Sizes and values of the views.
const (
	modbusDiagDataLen     = 2      // data field of every sub-function but 0
	modbusDiagClearLog    = 0xFF00 // restart: also clear the event log
	modbusDiagFirstRsv    = 0x05   // sub-functions 5 to 9 are reserved
	modbusDiagLastRsv     = 0x09
	modbusDiagRsv13       = 0x13
	modbusRunOff          = 0x00
	modbusRunOn           = 0xFF
	modbusCANFixedLen     = 8 // node, index, sub-index, address, quantity
	modbusCANExtend       = 0x80
	modbusCANExtControl   = 0x40
	modbusCANCounter      = 0x20
	modbusCANNetworkID    = 0x04
	modbusCANEncodedData  = 0x02
	modbusCANWrite        = 0x01
	modbusCANMaxQuantity  = 0x00FD
	modbusCANMaxNode      = 0x7F
	modbusCANControlBytes = 1
)

// Reserved reports whether c is a sub-function the spec reserves:
// 5 to 9, 0x13 and everything above 0x14.
func (c ModbusDiagCode) Reserved() bool {
	return c >= modbusDiagFirstRsv && c <= modbusDiagLastRsv || c == modbusDiagRsv13 || c > ModbusDiagClearOverrun
}

// ModbusDiagKind says what the data field of a Diagnostics PDU means.
type ModbusDiagKind uint8

// ModbusDiagKind values.
const (
	// ModbusDiagEcho: Return Query Data. The data is free and echoed.
	ModbusDiagEcho ModbusDiagKind = iota
	// ModbusDiagRestart: Restart Communications Option. ClearLog says
	// whether the event log is cleared too.
	ModbusDiagRestart
	// ModbusDiagRegister: Return Diagnostic Register. Value is the
	// register in a response.
	ModbusDiagRegister
	// ModbusDiagDelimiter: Change ASCII Input Delimiter. Delimiter is
	// the new end of message character.
	ModbusDiagDelimiter
	// ModbusDiagCommand: a command without data: Force Listen Only
	// Mode, Clear Counters and Diagnostic Register, Clear Overrun
	// Counter and Flag.
	ModbusDiagCommand
	// ModbusDiagCounter: one of the Return ... Count sub-functions.
	// Value is the counter in a response.
	ModbusDiagCounter
	// ModbusDiagReserved: a reserved sub-function. Its data is not
	// checked.
	ModbusDiagReserved
)

// String returns the kind name.
func (k ModbusDiagKind) String() string {
	switch k {
	case ModbusDiagEcho:
		return "Echo"
	case ModbusDiagRestart:
		return "Restart"
	case ModbusDiagRegister:
		return "Register"
	case ModbusDiagDelimiter:
		return "Delimiter"
	case ModbusDiagCommand:
		return "Command"
	case ModbusDiagCounter:
		return "Counter"
	case ModbusDiagReserved:
		return "Reserved"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(k))
	}
}

// Kind returns what the data field of sub-function c means.
func (c ModbusDiagCode) Kind() ModbusDiagKind {
	switch {
	case c == ModbusDiagReturnQueryData:
		return ModbusDiagEcho
	case c == ModbusDiagRestartComm:
		return ModbusDiagRestart
	case c == ModbusDiagReturnDiagRegister:
		return ModbusDiagRegister
	case c == ModbusDiagChangeASCIIDelimiter:
		return ModbusDiagDelimiter
	case c.Reserved():
		return ModbusDiagReserved
	case c >= ModbusDiagBusMessageCount && c <= ModbusDiagBusCharOverrunCount:
		return ModbusDiagCounter
	}
	return ModbusDiagCommand
}

// ModbusDiagnostic is the data field of a Diagnostics PDU, read as its
// sub-function defines (spec section 6.8).
type ModbusDiagnostic struct {
	Code      ModbusDiagCode
	Kind      ModbusDiagKind
	Value     uint16 // the 16 bit data field; 0 for ModbusDiagEcho
	ClearLog  bool   // ModbusDiagRestart: data field 0xFF00
	Delimiter byte   // ModbusDiagDelimiter
}

// Diagnostic reads the data of a Diagnostics PDU as its sub-function
// defines. It errors, with the fields read so far, when the data is
// not the two bytes every sub-function but Return Query Data carries,
// or holds a value the spec does not allow: a request for a register
// or a counter must send 0x0000, a restart 0x0000 or 0xFF00, a
// delimiter its character then 0x00.
func (p *ModbusPDU) Diagnostic() (ModbusDiagnostic, error) {
	if p.Exception || p.Function != ModbusFuncCodeDiagnostics {
		return ModbusDiagnostic{}, ErrModbusPDUNoView
	}

	d := ModbusDiagnostic{Code: p.SubFunction, Kind: p.SubFunction.Kind()}
	if d.Kind == ModbusDiagEcho {
		return d, nil
	}

	if len(p.Data) != modbusDiagDataLen {
		return d, fmt.Errorf("%w: %d data bytes in %v, want 2", ErrModbusPDULength, len(p.Data), d.Code)
	}
	d.Value = binary.BigEndian.Uint16(p.Data)

	// A response to these carries the register or the counter.
	reads := d.Kind == ModbusDiagRegister || d.Kind == ModbusDiagCounter
	switch {
	case d.Kind == ModbusDiagReserved, reads && p.Direction == ModbusResponse:
		return d, nil
	case d.Kind == ModbusDiagRestart:
		d.ClearLog = d.Value == modbusDiagClearLog
		if d.Value != 0 && !d.ClearLog {
			return d, fmt.Errorf("%w: restart option 0x%04X", ErrModbusPDUValue, d.Value)
		}
	case d.Kind == ModbusDiagDelimiter:
		d.Delimiter = p.Data[0]
		if p.Data[1] != 0 {
			return d, fmt.Errorf("%w: delimiter followed by 0x%02X", ErrModbusPDUValue, p.Data[1])
		}
	case d.Value != 0:
		return d, fmt.Errorf("%w: data 0x%04X in %v, want 0", ErrModbusPDUValue, d.Value, d.Code)
	}
	return d, nil
}

// ModbusRunStatus is the run indicator of a Report Server ID response.
type ModbusRunStatus uint8

// ModbusRunStatus values.
const (
	ModbusRunUnknown ModbusRunStatus = iota // no run indicator found
	ModbusRunOff                            // 0x00
	ModbusRunOn                             // 0xFF
)

// String returns the run status name.
func (s ModbusRunStatus) String() string {
	switch s {
	case ModbusRunOff:
		return "OFF"
	case ModbusRunOn:
		return "ON"
	default:
		return "Unknown"
	}
}

// ModbusServerID is a Report Server ID response split into its parts.
type ModbusServerID struct {
	ID         []byte
	Run        ModbusRunStatus
	Additional []byte
}

// ServerID splits the data of a Report Server ID response into the
// server ID, the run indicator and the additional data.
//
// It is a best effort. The spec fixes the order of the three but not
// the length of the server ID, which is device specific, so the split
// is a guess: the run indicator is taken to be the first byte past the
// first that is 0x00 (OFF) or 0xFF (ON). A one byte ID, by far the
// most common, always splits right; an ID with such a byte inside it
// does not. Without a run indicator everything is the ID. The raw
// bytes stay in Data.
func (p *ModbusPDU) ServerID() (ModbusServerID, error) {
	if p.Exception || p.Function != ModbusFuncCodeReportSlaveID || p.Direction != ModbusResponse {
		return ModbusServerID{}, ErrModbusPDUNoView
	}

	for i := 1; i < len(p.Data); i++ {
		run := ModbusRunOff
		switch p.Data[i] {
		case modbusRunOn:
			run = ModbusRunOn
		case modbusRunOff:
		default:
			continue
		}
		return ModbusServerID{ID: p.Data[:i], Run: run, Additional: p.Data[i+1:]}, nil
	}
	return ModbusServerID{ID: p.Data}, nil
}

// ModbusCANopen is the header of a CANopen General Reference PDU (MEI
// type 0x0D), which carries an access to the object dictionary of a
// CANopen node behind a gateway.
//
// The layout follows CiA 309-2 as vendor manuals summarise it; the
// Modbus specification only names the MEI type and Wireshark does not
// dissect it, so nothing here was checked against a second decoder:
//
//	control [control 2] reserved [counter] [network] [encoded]
//	node  index(2)  sub-index  address(2)  quantity(2)  data ...
//
// The fields in brackets are present when the matching bit of Control
// is set.
type ModbusCANopen struct {
	Control     uint8
	Control2    uint8 // extended protocol control, when HasControl2
	Reserved    uint8
	Counter     uint8 // when HasCounter
	NetworkID   uint8 // when HasNetworkID
	EncodedData uint8 // when HasEncodedData
	NodeID      uint8
	Index       uint16
	SubIndex    uint8
	Address     uint16 // starting address within the object
	Quantity    uint16 // data bytes to read or write
	Data        []byte
}

// Extend reports whether the PDU is one of several that carry the
// object.
func (c *ModbusCANopen) Extend() bool { return c.Control&modbusCANExtend != 0 }

// HasControl2 reports whether a second protocol control byte follows.
func (c *ModbusCANopen) HasControl2() bool { return c.Control&modbusCANExtControl != 0 }

// HasCounter reports whether the counter byte is present.
func (c *ModbusCANopen) HasCounter() bool { return c.Control&modbusCANCounter != 0 }

// HasNetworkID reports whether the network ID is present.
func (c *ModbusCANopen) HasNetworkID() bool { return c.Control&modbusCANNetworkID != 0 }

// HasEncodedData reports whether the encoded data byte is present.
func (c *ModbusCANopen) HasEncodedData() bool { return c.Control&modbusCANEncodedData != 0 }

// Write reports whether the access writes the object. It reads it
// otherwise.
func (c *ModbusCANopen) Write() bool { return c.Control&modbusCANWrite != 0 }

// Valid reports whether the node ID and quantity lie in the ranges
// CiA 309-2 allows: node 1 to 127, at most 253 data bytes.
func (c *ModbusCANopen) Valid() bool {
	return c.NodeID >= 1 && c.NodeID <= modbusCANMaxNode && c.Quantity <= modbusCANMaxQuantity
}

// CANopen reads the header of a CANopen General Reference PDU from
// Data. It errors when Data is too short for the header its control
// byte announces; it does not judge the values, which Valid does.
func (p *ModbusPDU) CANopen() (*ModbusCANopen, error) {
	if p.Exception || p.Function != ModbusFuncCodeEncapsulatedInterface || p.MEIType != ModbusMEICANopen {
		return nil, ErrModbusPDUNoView
	}

	b := p.Data
	if len(b) < modbusCANControlBytes {
		return nil, fmt.Errorf("%w: CANopen reference without a control byte", ErrModbusPDULength)
	}
	c := &ModbusCANopen{Control: b[0]}

	// One byte for each optional field the control byte announces.
	optional := []struct {
		present bool
		field   *uint8
	}{
		{c.HasControl2(), &c.Control2},
		{true, &c.Reserved},
		{c.HasCounter(), &c.Counter},
		{c.HasNetworkID(), &c.NetworkID},
		{c.HasEncodedData(), &c.EncodedData},
	}

	b = b[modbusCANControlBytes:]
	for _, o := range optional {
		if !o.present {
			continue
		}

		if len(b) == 0 {
			return c, fmt.Errorf("%w: CANopen reference header cut short", ErrModbusPDULength)
		}
		*o.field, b = b[0], b[1:]
	}

	if len(b) < modbusCANFixedLen {
		return c, fmt.Errorf("%w: CANopen reference of %d bytes, want %d", ErrModbusPDULength, len(b), modbusCANFixedLen)
	}

	c.NodeID = b[0]
	c.Index = binary.BigEndian.Uint16(b[1:3])
	c.SubIndex = b[3]
	c.Address = binary.BigEndian.Uint16(b[4:6])
	c.Quantity = binary.BigEndian.Uint16(b[6:8])
	c.Data = b[modbusCANFixedLen:]
	return c, nil
}
