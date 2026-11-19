// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"time"
)

// SZL record layouts, by SZL ID (and index where it selects the
// layout). Records of other IDs and indexes stay raw in Records.
//
//	xy11 module ID (28):        index, order number(20), type, version,
//	                            release
//	xy12 characteristic (2)
//	xy1C component ID (34):     index, then by index: name, tag,
//	                            copyright, serial... (text) or IDs
//	0131/1 comm capability (40): index, PDU, connections, MPI rate(4),
//	                            bus rate(4), reserved
//	0132/1 comm status (40):    index, 9 connection counters, reserved
//	0132/4 protection (40):     index, 11 protection words, reserved
//	0132/8 time system (40):    index, sync cycle, correction,
//	                            8 run-time meters, time(8), reserved
//	xy74 LED (4):               LED ID(2), on, flashing
//	xy24 mode transition (20):  event(2), ae, bzu ID, reserved(4),
//	                            info 1-4, time(8)
//	xyA0 diagnostic buffer (20): diagnostic message

const (
	s7commSZLHeadLen      = 2 // index octets starting most records
	s7commSZLModuleLen    = 28
	s7commSZLOrderLen     = 20
	s7commSZLCharLen      = 2
	s7commSZLCompLen      = 34
	s7commSZLIdxRecLen    = 40
	s7commSZLLEDLen       = 4
	s7commSZLModeLen      = 20
	s7commSZLRunMeters    = 8
	s7commSZLCompIdxMask  = 0x000F
	s7commSZLIDNumberMask = 0x00FF
)

// SZL partial list numbers (low octet of the ID) and full IDs with a
// decoded record layout.
const (
	s7commSZLModuleID    = 0x11
	s7commSZLCPUChars    = 0x12
	s7commSZLComponentID = 0x1C
	s7commSZLModeEvents  = 0x24
	s7commSZLLEDs        = 0x74
	s7commSZLDiagBuffer  = 0xA0

	s7commSZLCommCaps   = 0x0131
	s7commSZLCommStatus = 0x0132
	s7commSZLModeLast   = 0x0124
	s7commSZLModeAll    = 0x0424
	s7commSZLLEDOne     = 0x0174
	s7commSZLLEDAll     = 0x0074
	s7commSZLLEDSel     = 0x0019
	s7commSZLLEDSel1    = 0x0119
)

// SZL component ID (xy1C) indexes with a non-text layout.
const (
	s7commSZLCompProfile = 0x9
	s7commSZLCompOEM     = 0xA
	s7commSZLCompOEMText = 26
)

// s7commSZLCompText maps component ID indexes to their text size:
// PLC name, module name, tag, copyright, serial number, CPU type name,
// memory card serial number, location.
var s7commSZLCompText = map[uint16]int{1: 24, 2: 24, 3: 32, 4: 26, 5: 24, 7: 32, 8: 32, 0xB: 32}

// SZL 0x0132 indexes with a decoded layout.
const (
	s7commSZLIdxCommStatus = 0x0001
	s7commSZLIdxProtection = 0x0004
	s7commSZLIdxTimeSystem = 0x0008
	s7commSZLIdxCommCaps   = 0x0001
)

// S7CommSZLModuleID is an SZL xy11 record (module identification).
type S7CommSZLModuleID struct {
	Index       uint16
	OrderNumber string // MLFB, e.g. "6ES7 315-2EH14-0AB0"
	ModuleType  uint16
	Version     uint16
	Release     uint16
}

// S7CommSZLComponent is an SZL xy1C record (component identification).
// Text holds the name, tag, copyright, serial number, CPU type, memory
// card serial or location for the indexes carrying text (1-5, 7, 8,
// 0xB); index 9 sets the profile IDs and index 0xA the OEM copyright
// (in Text) and IDs. Other indexes set Index only.
type S7CommSZLComponent struct {
	Index           uint16
	Text            string
	ManufacturerID  uint16
	ProfileID       uint16
	ProfileSpecType uint16
	OEMID           uint16
	OEMAddID        uint32
}

// S7CommSZLCommCaps is an SZL 0x0131 index 1 record (general
// communication capabilities).
type S7CommSZLCommCaps struct {
	Index    uint16
	MaxPDU   uint16
	MaxConns uint16
	MPIRate  uint32
	BusRate  uint32
}

// S7CommSZLCommStatus is an SZL 0x0132 index 1 record (communication
// status): guaranteed and current PG/OS connections, configured and
// established connections, free and used free connections, and the
// maximum communication load in percent.
type S7CommSZLCommStatus struct {
	Index          uint16
	GuaranteedPG   uint16
	GuaranteedOS   uint16
	CurrentPG      uint16
	CurrentOS      uint16
	Configured     uint16
	Established    uint16
	Free           uint16
	FreeUsed       uint16
	MaxCommLoadPct uint16
}

// S7CommSZLProtection is an SZL 0x0132 index 4 record (protection
// levels and switch positions).
type S7CommSZLProtection struct {
	Index        uint16
	KeySwitch    uint16 // protection level of the key switch
	Assigned     uint16 // assigned protection level
	Effective    uint16 // valid protection level of the CPU
	ModeSwitch   uint16 // position of the mode switch
	StartSwitch  uint16 // CRST/WRST switch
	Reserved     uint16
	VersionValid uint16 // which version IDs below are valid
	HWVersion1   uint16 // the version IDs are little-endian on the wire
	HWVersion2   uint16
	ProgVersion1 uint16
	ProgVersion2 uint16
}

// S7CommSZLTimeSystem is an SZL 0x0132 index 8 record (time system).
// Time is zero if it is not a valid date.
type S7CommSZLTimeSystem struct {
	Index      uint16
	SyncCycle  uint16
	Correction uint16
	RunMeters  [s7commSZLRunMeters]uint16 // hours
	Time       time.Time
}

// S7CommSZLLED is an SZL xy74 (or xy19) record.
type S7CommSZLLED struct {
	ID       uint16 // rack in bits 8-10, master in bit 11, LED in 0-7
	On       uint8
	Flashing uint8
}

// S7CommSZLModeEvent is an SZL xy24 record (mode transition). Time is
// zero if it is not a valid date.
type S7CommSZLModeEvent struct {
	Event    uint16
	AE       uint8
	BZUID    uint8 // previous mode << 4 | requested mode
	Reserved []byte
	Info     [4]uint8
	Time     time.Time
}

// s7commSZLLayout selects a record decoder by SZL ID and index.
type s7commSZLLayout uint8

const (
	s7commSZLRaw s7commSZLLayout = iota
	s7commSZLLayModule
	s7commSZLLayChars
	s7commSZLLayComponent
	s7commSZLLayCommCaps
	s7commSZLLayCommStatus
	s7commSZLLayProtection
	s7commSZLLayTimeSystem
	s7commSZLLayLED
	s7commSZLLayMode
	s7commSZLLayDiag
)

// layout returns the record layout Wireshark decodes for the ID.
func (z *S7CommSZL) layout() s7commSZLLayout {
	switch z.ID {
	case s7commSZLCommCaps:
		if z.Index == s7commSZLIdxCommCaps {
			return s7commSZLLayCommCaps
		}
		return s7commSZLRaw
	case s7commSZLCommStatus:
		switch z.Index {
		case s7commSZLIdxCommStatus:
			return s7commSZLLayCommStatus
		case s7commSZLIdxProtection:
			return s7commSZLLayProtection
		case s7commSZLIdxTimeSystem:
			return s7commSZLLayTimeSystem
		}
		return s7commSZLRaw
	case s7commSZLLEDAll, s7commSZLLEDOne, s7commSZLLEDSel, s7commSZLLEDSel1:
		return s7commSZLLayLED
	case s7commSZLModeLast, s7commSZLModeAll:
		if z.Index == 0 {
			return s7commSZLLayMode
		}
		return s7commSZLRaw
	}

	// Wireshark keys these on the extract numbers it has seen.
	extract := z.ID >> s7commSZLExtractShift
	switch z.ID & s7commSZLIDNumberMask {
	case s7commSZLModuleID:
		if extract <= 1 {
			return s7commSZLLayModule
		}
	case s7commSZLCPUChars:
		if extract <= 1 {
			return s7commSZLLayChars
		}
	case s7commSZLComponentID:
		if extract <= 3 {
			return s7commSZLLayComponent
		}
	case s7commSZLDiagBuffer:
		if extract <= 1 || (extract >= 4 && extract <= 0xE) {
			return s7commSZLLayDiag
		}
	}
	return s7commSZLRaw
}

// recordLen returns the record size of a layout.
func (l s7commSZLLayout) recordLen() int {
	switch l {
	case s7commSZLLayModule:
		return s7commSZLModuleLen
	case s7commSZLLayChars:
		return s7commSZLCharLen
	case s7commSZLLayComponent:
		return s7commSZLCompLen
	case s7commSZLLayCommCaps, s7commSZLLayCommStatus, s7commSZLLayProtection, s7commSZLLayTimeSystem:
		return s7commSZLIdxRecLen
	case s7commSZLLayLED:
		return s7commSZLLEDLen
	case s7commSZLLayMode:
		return s7commSZLModeLen
	case s7commSZLLayDiag:
		return s7commDiagMsgLen
	}
	return 0
}

// decodeRecords sets the record view of a known SZL ID. Records shorter
// than the layout are an error; longer ones are decoded from their
// start.
func (z *S7CommSZL) decodeRecords() error {
	l := z.layout()
	if l == s7commSZLRaw || len(z.Records) == 0 {
		return nil
	}
	if int(z.RecordLength) < l.recordLen() {
		return fmt.Errorf("%w: SZL 0x%04X record %d octets, want %d", ErrS7CommMalformed, z.ID, z.RecordLength, l.recordLen())
	}

	n := len(z.Records)
	switch l {
	case s7commSZLLayModule:
		z.ModuleIDs = make([]S7CommSZLModuleID, n)
	case s7commSZLLayChars:
		z.Characteristics = make([]uint16, n)
	case s7commSZLLayComponent:
		z.Components = make([]S7CommSZLComponent, n)
	case s7commSZLLayCommCaps:
		z.CommCaps = make([]S7CommSZLCommCaps, n)
	case s7commSZLLayCommStatus:
		z.CommStatus = make([]S7CommSZLCommStatus, n)
	case s7commSZLLayProtection:
		z.Protection = make([]S7CommSZLProtection, n)
	case s7commSZLLayTimeSystem:
		z.TimeSystem = make([]S7CommSZLTimeSystem, n)
	case s7commSZLLayLED:
		z.LEDs = make([]S7CommSZLLED, n)
	case s7commSZLLayMode:
		z.ModeEvents = make([]S7CommSZLModeEvent, n)
	case s7commSZLLayDiag:
		z.DiagEvents = make([]S7CommDiagMessage, n)
	}

	for i, r := range z.Records {
		z.decodeRecord(l, i, r)
	}
	return nil
}

// decodeRecord decodes record i, at least recordLen octets, into the
// slice decodeRecords allocated for its layout.
func (z *S7CommSZL) decodeRecord(l s7commSZLLayout, i int, r []byte) {
	be := binary.BigEndian
	switch l {
	case s7commSZLLayModule:
		o := s7commSZLHeadLen
		z.ModuleIDs[i] = S7CommSZLModuleID{
			Index:       be.Uint16(r[0:2]),
			OrderNumber: s7commCString(r[o : o+s7commSZLOrderLen]),
			ModuleType:  be.Uint16(r[22:24]),
			Version:     be.Uint16(r[24:26]),
			Release:     be.Uint16(r[26:28]),
		}
	case s7commSZLLayChars:
		z.Characteristics[i] = be.Uint16(r[0:2])
	case s7commSZLLayComponent:
		z.Components[i] = s7commSZLComp(r)
	case s7commSZLLayCommCaps:
		z.CommCaps[i] = S7CommSZLCommCaps{
			Index:    be.Uint16(r[0:2]),
			MaxPDU:   be.Uint16(r[2:4]),
			MaxConns: be.Uint16(r[4:6]),
			MPIRate:  be.Uint32(r[6:10]),
			BusRate:  be.Uint32(r[10:14]),
		}
	case s7commSZLLayCommStatus:
		w := s7commSZLWords(r, 10)
		z.CommStatus[i] = S7CommSZLCommStatus{w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9]}
	case s7commSZLLayProtection:
		// The four version IDs are little-endian, as Wireshark reads them.
		w := s7commSZLWords(r, 8)
		le := binary.LittleEndian
		z.Protection[i] = S7CommSZLProtection{w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
			le.Uint16(r[16:18]), le.Uint16(r[18:20]), le.Uint16(r[20:22]), le.Uint16(r[22:24])}
	case s7commSZLLayTimeSystem:
		w := s7commSZLWords(r, 3+s7commSZLRunMeters)
		ts := S7CommSZLTimeSystem{Index: w[0], SyncCycle: w[1], Correction: w[2]}
		copy(ts.RunMeters[:], w[3:])
		ts.Time, _ = s7commBCDTime(r[22:30], s7commBCDShort)
		z.TimeSystem[i] = ts
	case s7commSZLLayLED:
		z.LEDs[i] = S7CommSZLLED{ID: be.Uint16(r[0:2]), On: r[2], Flashing: r[3]}
	case s7commSZLLayMode:
		ev := S7CommSZLModeEvent{Event: be.Uint16(r[0:2]), AE: r[2], BZUID: r[3], Reserved: r[4:8]}
		copy(ev.Info[:], r[8:12])
		ev.Time, _ = s7commBCDTime(r[12:20], s7commBCDShort)
		z.ModeEvents[i] = ev
	case s7commSZLLayDiag:
		z.DiagEvents[i], _ = s7commDiagMessage(r)
	}
}

// s7commSZLWords reads n big-endian words from the start of r.
func s7commSZLWords(r []byte, n int) []uint16 {
	w := make([]uint16, n)
	for k := range w {
		w[k] = binary.BigEndian.Uint16(r[2*k:])
	}
	return w
}

// s7commSZLComp decodes a component ID record by the low nibble of its
// index.
func s7commSZLComp(r []byte) S7CommSZLComponent {
	be := binary.BigEndian
	c := S7CommSZLComponent{Index: be.Uint16(r[0:2])}
	body := r[s7commSZLHeadLen:s7commSZLCompLen]

	switch c.Index & s7commSZLCompIdxMask {
	case s7commSZLCompProfile:
		c.ManufacturerID = be.Uint16(body[0:2])
		c.ProfileID = be.Uint16(body[2:4])
		c.ProfileSpecType = be.Uint16(body[4:6])
	case s7commSZLCompOEM:
		c.Text = s7commCString(body[:s7commSZLCompOEMText])
		c.OEMID = be.Uint16(body[26:28])
		c.OEMAddID = be.Uint32(body[28:32])
	default:
		if n, ok := s7commSZLCompText[c.Index&s7commSZLCompIdxMask]; ok {
			c.Text = s7commCString(body[:n])
		}
	}
	return c
}
