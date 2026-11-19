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
	"math"
	"strings"
	"time"
	"unicode/utf16"
)

// Object values (IEEE 1815-2012 annex A). DNP3ObjectHeader.Value decodes
// one object of a header into a typed value, chosen by group and
// variation. Point objects share one layout, each part optional:
//
//	+-------------------+---------------------+------------------------+
//	| flags or status   | value               | time                   |
//	| 1 octet           | 2, 4 or 8 octets    | 6 absolute, 2 relative |
//	+-------------------+---------------------+------------------------+
//
// e.g. g32v3 (analog event, 32 bit, with time) is flags, int32, time:
// 11 octets. Relative times count from the CTO (g51) that precedes them
// in the fragment; DNP3Application.ResolveTime adds the two.

// Errors returned by value accessors.
var (
	ErrDNP3NoValue      = errors.New("DNP3 object carries no value")
	ErrDNP3ValueShort   = errors.New("DNP3 object value cut short")
	ErrDNP3UnknownValue = errors.New("DNP3 object type has no value decoder")
	ErrDNP3BadObject    = errors.New("DNP3 object or header number out of range")
	ErrDNP3NoCTO        = errors.New("DNP3 fragment has no CTO before this header")
	ErrDNP3NoTime       = errors.New("DNP3 object carries no time")
	ErrDNP3AttrType     = errors.New("DNP3 attribute holds another type or width")
	ErrDNP3BadBCD       = errors.New("DNP3 BCD value holds a digit above 9")
)

// Octet masks and sizes of object values.
const (
	dnp3StateBit      = 0x80 // binary state in a flags or status octet
	dnp3DoubleBitPos  = 6    // double-bit state in flags bits 6-7
	dnp3DoubleBitMask = 0x03
	dnp3StatusMask    = 0x7F // control status, bit 7 reserved or state
	dnp3OpMask        = 0x0F
	dnp3QueueBit      = 0x10
	dnp3ClearBit      = 0x20
	dnp3TripClosePos  = 6
	dnp3LastBlockBit  = 0x80000000 // g70 block number: last block
	dnp3AttrHeaderLen = 2          // data type code, length
	dnp3AttrListEntry = 2          // variation, properties
	dnp3UTF16Len      = 2
	dnp3AttrAll       = 254 // g0v254: all attributes, read only
	dnp3SignBit64     = 64
	dnp3Float32Len    = 4
	dnp3Float64Len    = 8
	dnp3AuthMACVar    = 9
)

// DNP3Value is the value of one object: one of the DNP3 value types of
// this file, e.g. DNP3Analog. Type switch on it to read its fields.
type DNP3Value interface {
	dnp3Value()
}

// DNP3FlagFamily says which flag names a flags octet carries: the bits
// past LOCAL_FORCED mean different things per group family.
type DNP3FlagFamily uint8

// DNP3FlagFamily values.
const (
	DNP3FlagsAbsent       DNP3FlagFamily = iota // the object has no flags octet
	DNP3FlagsBinaryInput                        // g1, g2
	DNP3FlagsDoubleBit                          // g3, g4: state in bits 6-7
	DNP3FlagsBinaryOutput                       // g10, g11
	DNP3FlagsCounter                            // g20 to g23
	DNP3FlagsAnalogInput                        // g30 to g33
	DNP3FlagsAnalogOutput                       // g40, g42
)

// DNP3Flag is one bit of a flags octet. Constants that share a bit name
// it for different families.
type DNP3Flag uint8

// DNP3Flag values.
const (
	DNP3FlagOnline        DNP3Flag = 0x01
	DNP3FlagRestart       DNP3Flag = 0x02
	DNP3FlagCommLost      DNP3Flag = 0x04
	DNP3FlagRemoteForced  DNP3Flag = 0x08
	DNP3FlagLocalForced   DNP3Flag = 0x10
	DNP3FlagChatterFilter DNP3Flag = 0x20 // binary and double-bit inputs
	DNP3FlagRollover      DNP3Flag = 0x20 // counters, obsolete
	DNP3FlagOverRange     DNP3Flag = 0x20 // analog inputs
	DNP3FlagDiscontinuity DNP3Flag = 0x40 // counters
	DNP3FlagReferenceErr  DNP3Flag = 0x40 // analog inputs
	DNP3FlagState         DNP3Flag = 0x80 // binary inputs and outputs
)

// DNP3Flags is a flags octet and the family that names its bits.
type DNP3Flags struct {
	Family DNP3FlagFamily
	Raw    uint8
}

// dnp3FlagName names one bit of a flags octet.
type dnp3FlagName struct {
	bit  DNP3Flag
	name string
}

// dnp3CommonFlags are the bits every family shares.
var dnp3CommonFlags = []dnp3FlagName{
	{DNP3FlagOnline, "Online"},
	{DNP3FlagRestart, "Restart"},
	{DNP3FlagCommLost, "CommLost"},
	{DNP3FlagRemoteForced, "RemoteForced"},
	{DNP3FlagLocalForced, "LocalForced"},
}

// dnp3FamilyFlags are the bits each family adds to the common ones.
// DoubleBit leaves out bits 6-7, which hold its state.
var dnp3FamilyFlags = map[DNP3FlagFamily][]dnp3FlagName{
	DNP3FlagsBinaryInput:  {{DNP3FlagChatterFilter, "ChatterFilter"}, {DNP3FlagState, "State"}},
	DNP3FlagsDoubleBit:    {{DNP3FlagChatterFilter, "ChatterFilter"}},
	DNP3FlagsBinaryOutput: {{DNP3FlagState, "State"}},
	DNP3FlagsCounter:      {{DNP3FlagRollover, "Rollover"}, {DNP3FlagDiscontinuity, "Discontinuity"}},
	DNP3FlagsAnalogInput:  {{DNP3FlagOverRange, "OverRange"}, {DNP3FlagReferenceErr, "ReferenceErr"}},
	DNP3FlagsAnalogOutput: nil,
}

// defined returns the bits the family of f gives a name: none without a
// flags octet, and never the state bits of a double-bit input.
func (f DNP3Flags) defined() DNP3Flag {
	if f.Family == DNP3FlagsAbsent {
		return 0
	}

	var mask DNP3Flag
	for _, set := range [][]dnp3FlagName{dnp3CommonFlags, dnp3FamilyFlags[f.Family]} {
		for _, n := range set {
			mask |= n.bit
		}
	}
	return mask
}

// Has reports whether every bit of flag is set and defined for the
// family: DNP3FlagState is never reported for an analog input, whatever
// its reserved bit 7 holds. It is false when the object has no flags
// octet.
func (f DNP3Flags) Has(flag DNP3Flag) bool {
	return flag != 0 && f.defined()&flag == flag && DNP3Flag(f.Raw)&flag == flag
}

// String lists the set bits in wire order, e.g. "Online|Restart", and
// any reserved bit as Reserved(0x40).
func (f DNP3Flags) String() string {
	if f.Family == DNP3FlagsAbsent {
		return ""
	}

	var names []string
	rest := DNP3Flag(f.Raw)
	if f.Family == DNP3FlagsDoubleBit {
		rest &^= dnp3DoubleBitMask << dnp3DoubleBitPos
	}

	for _, set := range [][]dnp3FlagName{dnp3CommonFlags, dnp3FamilyFlags[f.Family]} {
		for _, n := range set {
			if rest&n.bit == 0 {
				continue
			}
			names = append(names, n.name)
			rest &^= n.bit
		}
	}

	if rest != 0 {
		names = append(names, fmt.Sprintf("Reserved(%#02x)", uint8(rest)))
	}
	return strings.Join(names, "|")
}

// DNP3TimeKind says what time an object carries.
type DNP3TimeKind uint8

// DNP3TimeKind values.
const (
	DNP3TimeNone     DNP3TimeKind = iota
	DNP3TimeAbsolute              // 48 bit milliseconds since 1970
	DNP3TimeRelative              // 16 bit milliseconds since the CTO
)

// DNP3Timestamp is the time of an object: Time for an absolute time,
// Relative for a time relative to the fragment's CTO.
type DNP3Timestamp struct {
	Kind     DNP3TimeKind
	Time     time.Time
	Relative time.Duration
}

// DNP3NumFormat is the wire format of a numeric value.
type DNP3NumFormat uint8

// DNP3NumFormat values.
const (
	DNP3NumNone DNP3NumFormat = iota
	DNP3NumInt16
	DNP3NumInt32
	DNP3NumUint16
	DNP3NumUint32
	DNP3NumFloat32
	DNP3NumFloat64
	DNP3NumUint8
)

// DNP3DoubleBit is the state of a double-bit binary input.
type DNP3DoubleBit uint8

// DNP3DoubleBit values.
const (
	DNP3DoubleBitIntermediate  DNP3DoubleBit = 0
	DNP3DoubleBitOff           DNP3DoubleBit = 1
	DNP3DoubleBitOn            DNP3DoubleBit = 2
	DNP3DoubleBitIndeterminate DNP3DoubleBit = 3
)

// String returns the state name.
func (d DNP3DoubleBit) String() string {
	switch d {
	case DNP3DoubleBitIntermediate:
		return "Intermediate"
	case DNP3DoubleBitOff:
		return "Determined Off"
	case DNP3DoubleBitOn:
		return "Determined On"
	case DNP3DoubleBitIndeterminate:
		return "Indeterminate"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(d))
}

// DNP3ControlStatus is the status code of a control or command event
// (IEEE 1815-2012 table 11-21).
type DNP3ControlStatus uint8

// DNP3ControlStatus values.
const (
	DNP3StatusSuccess            DNP3ControlStatus = 0
	DNP3StatusTimeout            DNP3ControlStatus = 1
	DNP3StatusNoSelect           DNP3ControlStatus = 2
	DNP3StatusFormatError        DNP3ControlStatus = 3
	DNP3StatusNotSupported       DNP3ControlStatus = 4
	DNP3StatusAlreadyActive      DNP3ControlStatus = 5
	DNP3StatusHardwareError      DNP3ControlStatus = 6
	DNP3StatusLocal              DNP3ControlStatus = 7
	DNP3StatusTooManyObjs        DNP3ControlStatus = 8
	DNP3StatusNotAuthorized      DNP3ControlStatus = 9
	DNP3StatusAutomationInhibit  DNP3ControlStatus = 10
	DNP3StatusProcessingLimited  DNP3ControlStatus = 11
	DNP3StatusOutOfRange         DNP3ControlStatus = 12
	DNP3StatusDownstreamLocal    DNP3ControlStatus = 13
	DNP3StatusAlreadyComplete    DNP3ControlStatus = 14
	DNP3StatusBlocked            DNP3ControlStatus = 15
	DNP3StatusCanceled           DNP3ControlStatus = 16
	DNP3StatusBlockedOtherMaster DNP3ControlStatus = 17
	DNP3StatusDownstreamFail     DNP3ControlStatus = 18
	DNP3StatusNonParticipating   DNP3ControlStatus = 126
	DNP3StatusUndefined          DNP3ControlStatus = 127
)

// dnp3StatusNames maps status codes to their spec names.
var dnp3StatusNames = map[DNP3ControlStatus]string{
	DNP3StatusSuccess:            "SUCCESS",
	DNP3StatusTimeout:            "TIMEOUT",
	DNP3StatusNoSelect:           "NO_SELECT",
	DNP3StatusFormatError:        "FORMAT_ERROR",
	DNP3StatusNotSupported:       "NOT_SUPPORTED",
	DNP3StatusAlreadyActive:      "ALREADY_ACTIVE",
	DNP3StatusHardwareError:      "HARDWARE_ERROR",
	DNP3StatusLocal:              "LOCAL",
	DNP3StatusTooManyObjs:        "TOO_MANY_OBJS",
	DNP3StatusNotAuthorized:      "NOT_AUTHORIZED",
	DNP3StatusAutomationInhibit:  "AUTOMATION_INHIBIT",
	DNP3StatusProcessingLimited:  "PROCESSING_LIMITED",
	DNP3StatusOutOfRange:         "OUT_OF_RANGE",
	DNP3StatusDownstreamLocal:    "DOWNSTREAM_LOCAL",
	DNP3StatusAlreadyComplete:    "ALREADY_COMPLETE",
	DNP3StatusBlocked:            "BLOCKED",
	DNP3StatusCanceled:           "CANCELLED",
	DNP3StatusBlockedOtherMaster: "BLOCKED_OTHER_MASTER",
	DNP3StatusDownstreamFail:     "DOWNSTREAM_FAIL",
	DNP3StatusNonParticipating:   "NON_PARTICIPATING",
	DNP3StatusUndefined:          "UNDEFINED",
}

// String returns the status name.
func (s DNP3ControlStatus) String() string {
	if name, ok := dnp3StatusNames[s]; ok {
		return name
	}
	return fmt.Sprintf("Reserved(%d)", uint8(s))
}

// DNP3OpType is the operation of a CROB control code.
type DNP3OpType uint8

// DNP3OpType values.
const (
	DNP3OpNul      DNP3OpType = 0
	DNP3OpPulseOn  DNP3OpType = 1
	DNP3OpPulseOff DNP3OpType = 2
	DNP3OpLatchOn  DNP3OpType = 3
	DNP3OpLatchOff DNP3OpType = 4
)

// String returns the operation name.
func (o DNP3OpType) String() string {
	switch o {
	case DNP3OpNul:
		return "NUL"
	case DNP3OpPulseOn:
		return "PULSE_ON"
	case DNP3OpPulseOff:
		return "PULSE_OFF"
	case DNP3OpLatchOn:
		return "LATCH_ON"
	case DNP3OpLatchOff:
		return "LATCH_OFF"
	}
	return fmt.Sprintf("Reserved(%d)", uint8(o))
}

// DNP3TripClose is the trip-close code of a CROB control code.
type DNP3TripClose uint8

// DNP3TripClose values.
const (
	DNP3TripCloseNul      DNP3TripClose = 0
	DNP3TripCloseClose    DNP3TripClose = 1
	DNP3TripCloseTrip     DNP3TripClose = 2
	DNP3TripCloseReserved DNP3TripClose = 3
)

// String returns the trip-close code name.
func (t DNP3TripClose) String() string {
	switch t {
	case DNP3TripCloseNul:
		return "NUL"
	case DNP3TripCloseClose:
		return "CLOSE"
	case DNP3TripCloseTrip:
		return "TRIP"
	}
	return "RESERVED"
}

// DNP3ControlCode is the control code octet of a CROB or PCB.
type DNP3ControlCode uint8

// Op returns the operation type, bits 0-3.
func (c DNP3ControlCode) Op() DNP3OpType {
	return DNP3OpType(c & dnp3OpMask)
}

// Queue reports the queue bit (obsolete).
func (c DNP3ControlCode) Queue() bool {
	return c&dnp3QueueBit != 0
}

// Clear reports the clear bit.
func (c DNP3ControlCode) Clear() bool {
	return c&dnp3ClearBit != 0
}

// TripClose returns the trip-close code, bits 6-7.
func (c DNP3ControlCode) TripClose() DNP3TripClose {
	return DNP3TripClose(c >> dnp3TripClosePos)
}

// String returns e.g. "LATCH_ON" or "PULSE_ON|CLOSE|Clear".
func (c DNP3ControlCode) String() string {
	parts := []string{c.Op().String()}
	if tc := c.TripClose(); tc != DNP3TripCloseNul {
		parts = append(parts, tc.String())
	}
	if c.Queue() {
		parts = append(parts, "Queue")
	}
	if c.Clear() {
		parts = append(parts, "Clear")
	}
	return strings.Join(parts, "|")
}

// DNP3IntervalUnit is the unit of a g50v4 interval.
type DNP3IntervalUnit uint8

// DNP3IntervalUnit values.
const (
	DNP3IntervalNone          DNP3IntervalUnit = 0 // no repeat
	DNP3IntervalMilliseconds  DNP3IntervalUnit = 1
	DNP3IntervalSeconds       DNP3IntervalUnit = 2
	DNP3IntervalMinutes       DNP3IntervalUnit = 3
	DNP3IntervalHours         DNP3IntervalUnit = 4
	DNP3IntervalDays          DNP3IntervalUnit = 5
	DNP3IntervalWeeks         DNP3IntervalUnit = 6
	DNP3IntervalMonths        DNP3IntervalUnit = 7  // same day of month
	DNP3IntervalMonthsWeekday DNP3IntervalUnit = 8  // same weekday, from month start
	DNP3IntervalMonthsLastDay DNP3IntervalUnit = 9  // same weekday, from month end
	DNP3IntervalSeasons       DNP3IntervalUnit = 10 // defined by the device
	DNP3IntervalDeviceDefined DNP3IntervalUnit = 128
)

// dnp3IntervalNames maps interval units to their names.
var dnp3IntervalNames = map[DNP3IntervalUnit]string{
	DNP3IntervalNone:          "None",
	DNP3IntervalMilliseconds:  "Milliseconds",
	DNP3IntervalSeconds:       "Seconds",
	DNP3IntervalMinutes:       "Minutes",
	DNP3IntervalHours:         "Hours",
	DNP3IntervalDays:          "Days",
	DNP3IntervalWeeks:         "Weeks",
	DNP3IntervalMonths:        "Months",
	DNP3IntervalMonthsWeekday: "Months (weekday from start)",
	DNP3IntervalMonthsLastDay: "Months (weekday from end)",
	DNP3IntervalSeasons:       "Seasons",
	DNP3IntervalDeviceDefined: "Device Defined",
}

// String returns the unit name.
func (u DNP3IntervalUnit) String() string {
	if name, ok := dnp3IntervalNames[u]; ok {
		return name
	}
	return fmt.Sprintf("Reserved(%d)", uint8(u))
}

// DNP3Binary is a binary input or output point (g1, g2, g10, g11), a
// pattern mask bit (g12v3) or an internal indication bit (g80v1).
// Packed objects have no flags: Flags.Family is DNP3FlagsAbsent.
type DNP3Binary struct {
	Flags DNP3Flags
	State bool
	Time  DNP3Timestamp
}

// DNP3DoubleBitInput is a double-bit binary input point (g3, g4).
type DNP3DoubleBitInput struct {
	Flags DNP3Flags
	State DNP3DoubleBit
	Time  DNP3Timestamp
}

// DNP3Counter is a counter, frozen counter or counter event (g20 to
// g23). 16 bit values are widened.
type DNP3Counter struct {
	Flags  DNP3Flags
	Value  uint32
	Format DNP3NumFormat
	Time   DNP3Timestamp
}

// DNP3Analog is an analog input, frozen input, event or deadband (g30
// to g34), or an analog output status or event (g40, g42). Value holds
// any format exactly: int32 and float32 fit a float64.
type DNP3Analog struct {
	Flags  DNP3Flags
	Value  float64
	Format DNP3NumFormat
	Time   DNP3Timestamp
}

// DNP3AnalogCommand is an analog output block (g41) or an analog output
// command event (g43).
type DNP3AnalogCommand struct {
	Value  float64
	Format DNP3NumFormat
	Status DNP3ControlStatus
	Time   DNP3Timestamp
}

// DNP3BinaryCommandEvent is a binary output command event (g13): the
// commanded state and the control status.
type DNP3BinaryCommandEvent struct {
	State  bool
	Status DNP3ControlStatus
	Time   DNP3Timestamp
}

// DNP3CROB is a control relay output block (g12v1) or pattern control
// block (g12v2). On and off times are in milliseconds.
type DNP3CROB struct {
	Code    DNP3ControlCode
	Count   uint8
	OnTime  uint32
	OffTime uint32
	Status  DNP3ControlStatus
}

// DNP3TimeDate is a time and date (g50) or a CTO (g51). Interval and
// Units are set by g50v2 (milliseconds) and g50v4.
type DNP3TimeDate struct {
	Time     time.Time
	Interval uint32
	Units    DNP3IntervalUnit
}

// DNP3TimeDelay is a time delay (g52): seconds for v1, milliseconds
// for v2.
type DNP3TimeDelay struct {
	Delay time.Duration
}

// DNP3OctetString is an octet string or virtual terminal object (g110
// to g113).
type DNP3OctetString []byte

// DNP3AttrType is the data type code of a device attribute.
type DNP3AttrType uint8

// DNP3AttrType values.
const (
	DNP3AttrNone       DNP3AttrType = 0
	DNP3AttrVString    DNP3AttrType = 1 // visible ASCII string
	DNP3AttrUint       DNP3AttrType = 2
	DNP3AttrInt        DNP3AttrType = 3
	DNP3AttrFloat      DNP3AttrType = 4
	DNP3AttrOctets     DNP3AttrType = 5
	DNP3AttrBits       DNP3AttrType = 6
	DNP3AttrTime       DNP3AttrType = 7
	DNP3AttrUnicode    DNP3AttrType = 8
	DNP3AttrList       DNP3AttrType = 254 // variation and properties pairs
	DNP3AttrListExtend DNP3AttrType = 255
)

// dnp3AttrTypeNames maps attribute data type codes to their spec names.
var dnp3AttrTypeNames = map[DNP3AttrType]string{
	DNP3AttrNone:       "NONE",
	DNP3AttrVString:    "VSTR",
	DNP3AttrUint:       "UINT",
	DNP3AttrInt:        "INT",
	DNP3AttrFloat:      "FLT",
	DNP3AttrOctets:     "OSTR",
	DNP3AttrBits:       "BSTR",
	DNP3AttrTime:       "TIME",
	DNP3AttrUnicode:    "UNCD",
	DNP3AttrList:       "U8BS8LIST",
	DNP3AttrListExtend: "U8BS8EXLIST",
}

// String returns the data type name.
func (t DNP3AttrType) String() string {
	if name, ok := dnp3AttrTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("Reserved(%d)", uint8(t))
}

// DNP3Attribute is a device attribute (g0): the variation of its header
// is the attribute number.
type DNP3Attribute struct {
	Type DNP3AttrType
	Data []byte
}

// DNP3AttrEntry is one entry of a list of attribute variations (g0v255).
type DNP3AttrEntry struct {
	Variation  uint8
	Properties uint8 // bit 0: writable
}

// Text returns the value octets as a string, as for VSTR.
func (a DNP3Attribute) Text() string {
	return string(a.Data)
}

// Octets returns an OSTR value.
func (a DNP3Attribute) Octets() ([]byte, error) {
	if a.Type != DNP3AttrOctets {
		return nil, ErrDNP3AttrType
	}
	return a.Data, nil
}

// Bits returns a BSTR value: bit n of the string is bit n%8 of octet
// n/8. Bit reads one of them.
func (a DNP3Attribute) Bits() ([]byte, error) {
	if a.Type != DNP3AttrBits {
		return nil, ErrDNP3AttrType
	}
	return a.Data, nil
}

// Bit returns bit n of a BSTR value.
func (a DNP3Attribute) Bit(n int) (bool, error) {
	if a.Type != DNP3AttrBits || n < 0 || n/dnp3BitsPerByte >= len(a.Data) {
		return false, ErrDNP3AttrType
	}
	return a.Data[n/dnp3BitsPerByte]>>(n%dnp3BitsPerByte)&1 != 0, nil
}

// Unicode returns a UNCD value. The octets are read as UTF-16, low
// octet first; this decoder has no capture that confirms the encoding.
func (a DNP3Attribute) Unicode() (string, error) {
	if a.Type != DNP3AttrUnicode || len(a.Data)%dnp3UTF16Len != 0 {
		return "", ErrDNP3AttrType
	}

	units := make([]uint16, len(a.Data)/dnp3UTF16Len)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(a.Data[i*dnp3UTF16Len:])
	}
	return string(utf16.Decode(units)), nil
}

// Uint returns a UINT value of 1 to 8 octets.
func (a DNP3Attribute) Uint() (uint64, error) {
	if a.Type != DNP3AttrUint || len(a.Data) == 0 || len(a.Data) > dnp3Float64Len {
		return 0, ErrDNP3AttrType
	}

	var v uint64
	for i := len(a.Data) - 1; i >= 0; i-- {
		v = v<<dnp3BitsPerByte | uint64(a.Data[i])
	}
	return v, nil
}

// Int returns an INT value of 1 to 8 octets, sign extended.
func (a DNP3Attribute) Int() (int64, error) {
	u, err := DNP3Attribute{Type: DNP3AttrUint, Data: a.Data}.Uint()
	if a.Type != DNP3AttrInt || err != nil {
		return 0, ErrDNP3AttrType
	}

	// Shift the sign bit to bit 63 and back, e.g. 0xff of 1 octet is -1.
	shift := uint(dnp3SignBit64 - len(a.Data)*dnp3BitsPerByte)
	return int64(u<<shift) >> shift, nil
}

// Float returns a FLT value of 4 or 8 octets.
func (a DNP3Attribute) Float() (float64, error) {
	if a.Type != DNP3AttrFloat {
		return 0, ErrDNP3AttrType
	}

	switch len(a.Data) {
	case dnp3Float32Len:
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(a.Data))), nil
	case dnp3Float64Len:
		return math.Float64frombits(binary.LittleEndian.Uint64(a.Data)), nil
	}
	return 0, ErrDNP3AttrType
}

// Time returns a TIME value.
func (a DNP3Attribute) Time() (time.Time, error) {
	if a.Type != DNP3AttrTime || len(a.Data) != dnp3TimeLen {
		return time.Time{}, ErrDNP3AttrType
	}
	return DNP3Time(a.Data), nil
}

// List returns the entries of a U8BS8LIST value, as g0v255 carries, or
// of a U8BS8EXLIST value, read as the same pairs.
func (a DNP3Attribute) List() ([]DNP3AttrEntry, error) {
	if a.Type != DNP3AttrList && a.Type != DNP3AttrListExtend || len(a.Data)%dnp3AttrListEntry != 0 {
		return nil, ErrDNP3AttrType
	}

	out := make([]DNP3AttrEntry, 0, len(a.Data)/dnp3AttrListEntry)
	for i := 0; i < len(a.Data); i += dnp3AttrListEntry {
		out = append(out, DNP3AttrEntry{Variation: a.Data[i], Properties: a.Data[i+1]})
	}
	return out, nil
}

// DNP3FileAuth is a file authentication object (g70v2).
type DNP3FileAuth struct {
	AuthKey  uint32
	UserName string
	Password string
}

// DNP3FileCommand is a file command (g70v3): open, create or delete.
type DNP3FileCommand struct {
	Created     time.Time
	Permissions uint16
	AuthKey     uint32
	Size        uint32
	Mode        uint16 // 0 NULL, 1 READ, 2 WRITE, 3 APPEND
	MaxBlock    uint16
	RequestID   uint16
	Name        string
}

// DNP3FileStatus is a file command status (g70v4).
type DNP3FileStatus struct {
	Handle    uint32
	Size      uint32
	MaxBlock  uint16
	RequestID uint16
	Status    uint8
	Text      []byte
}

// DNP3FileTransport is a block of file data (g70v5).
type DNP3FileTransport struct {
	Handle uint32
	Block  uint32 // bits 0-30 of the block number
	Last   bool   // bit 31: the last block
	Data   []byte
}

// DNP3FileTransportStatus is a file transport status (g70v6).
type DNP3FileTransportStatus struct {
	Handle uint32
	Block  uint32
	Last   bool
	Status uint8
	Text   []byte
}

// DNP3FileDescriptor is a file descriptor (g70v7).
type DNP3FileDescriptor struct {
	FileType    uint16 // 0 directory, 1 simple file
	Size        uint32
	Created     time.Time
	Permissions uint16
	RequestID   uint16
	Name        string
}

// DNP3FileSpec is a file specification string (g70v8).
type DNP3FileSpec struct {
	Name string
}

// DNP3AuthChallenge is a secure authentication challenge (g120v1).
type DNP3AuthChallenge struct {
	Seq          uint32 // CSQ
	User         uint16
	MACAlgorithm uint8
	Reason       uint8
	Data         []byte
}

// DNP3AuthReply is a secure authentication reply (g120v2).
type DNP3AuthReply struct {
	Seq  uint32
	User uint16
	MAC  []byte
}

// DNP3AuthAggressive is an aggressive mode request (g120v3).
type DNP3AuthAggressive struct {
	Seq  uint32
	User uint16
}

// DNP3AuthKeyStatusReq is a session key status request (g120v4).
type DNP3AuthKeyStatusReq struct {
	User uint16
}

// DNP3AuthKeyStatus is a session key status (g120v5).
type DNP3AuthKeyStatus struct {
	Seq          uint32 // KSQ
	User         uint16
	KeyWrap      uint8
	KeyStatus    uint8
	MACAlgorithm uint8
	Challenge    []byte
	MAC          []byte
}

// DNP3AuthKeyChange is a session key change (g120v6).
type DNP3AuthKeyChange struct {
	Seq     uint32 // KSQ
	User    uint16
	KeyData []byte
}

// DNP3AuthError is a secure authentication error (g120v7).
type DNP3AuthError struct {
	Seq         uint32
	User        uint16
	Association uint16
	Code        uint8
	Time        time.Time
	Text        []byte
}

// DNP3AuthMAC is a message authentication code (g120v9).
type DNP3AuthMAC struct {
	MAC []byte
}

func (DNP3Binary) dnp3Value()              {}
func (DNP3DoubleBitInput) dnp3Value()      {}
func (DNP3Counter) dnp3Value()             {}
func (DNP3Analog) dnp3Value()              {}
func (DNP3AnalogCommand) dnp3Value()       {}
func (DNP3BinaryCommandEvent) dnp3Value()  {}
func (DNP3CROB) dnp3Value()                {}
func (DNP3TimeDate) dnp3Value()            {}
func (DNP3TimeDelay) dnp3Value()           {}
func (DNP3OctetString) dnp3Value()         {}
func (DNP3Attribute) dnp3Value()           {}
func (DNP3FileAuth) dnp3Value()            {}
func (DNP3FileCommand) dnp3Value()         {}
func (DNP3FileStatus) dnp3Value()          {}
func (DNP3FileTransport) dnp3Value()       {}
func (DNP3FileTransportStatus) dnp3Value() {}
func (DNP3FileDescriptor) dnp3Value()      {}
func (DNP3FileSpec) dnp3Value()            {}
func (DNP3AuthChallenge) dnp3Value()       {}
func (DNP3AuthReply) dnp3Value()           {}
func (DNP3AuthAggressive) dnp3Value()      {}
func (DNP3AuthKeyStatusReq) dnp3Value()    {}
func (DNP3AuthKeyStatus) dnp3Value()       {}
func (DNP3AuthKeyChange) dnp3Value()       {}
func (DNP3AuthError) dnp3Value()           {}
func (DNP3AuthMAC) dnp3Value()             {}

// Value decodes object i of the header: the i-th entry of Objects, or
// the i-th packed point when BitsPerObject is set. It errors, never
// panics, on an object cut short or a type it cannot decode.
func (h *DNP3ObjectHeader) Value(i int) (DNP3Value, error) {
	if h.BitsPerObject != 0 {
		return h.packed(i)
	}

	if i < 0 || i >= len(h.Objects) {
		return nil, ErrDNP3BadObject
	}
	return dnp3Decode(h.Group, h.Variation, h.Objects[i].Data)
}

// packed reads point i of a packed header (g1v1, g3v1, g10v1, g12v3,
// g80v1). Points are packed from the low bits of the first octet.
func (h *DNP3ObjectHeader) packed(i int) (DNP3Value, error) {
	if i < 0 || uint64(i) >= h.Count {
		return nil, ErrDNP3BadObject
	}

	bits := uint64(h.BitsPerObject)
	if (uint64(i)*bits)/dnp3BitsPerByte >= uint64(len(h.Data)) {
		return nil, ErrDNP3ValueShort
	}

	v := h.PackedValue(uint64(i))
	if h.Group == DNP3GroupDoubleBitInput {
		return DNP3DoubleBitInput{State: DNP3DoubleBit(v)}, nil
	}
	return DNP3Binary{State: v != 0}, nil
}

// dnp3Reader reads little endian fields off an object. A read past the
// end sets short and yields zeros, so a decoder checks once at its end.
type dnp3Reader struct {
	b     []byte
	short bool
}

// has reports whether n more bytes are there, and marks the read short
// when they are not.
func (r *dnp3Reader) has(n int) bool {
	if n >= 0 && len(r.b) >= n {
		return true
	}
	r.short = true
	r.b = nil
	return false
}

func (r *dnp3Reader) u8() uint8 {
	if !r.has(1) {
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *dnp3Reader) u16() uint16 {
	if !r.has(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *dnp3Reader) u32() uint32 {
	if !r.has(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *dnp3Reader) u64() uint64 {
	if !r.has(dnp3Float64Len) {
		return 0
	}
	v := binary.LittleEndian.Uint64(r.b)
	r.b = r.b[dnp3Float64Len:]
	return v
}

func (r *dnp3Reader) time() time.Time {
	if !r.has(dnp3TimeLen) {
		return time.Time{}
	}
	t := DNP3Time(r.b)
	r.b = r.b[dnp3TimeLen:]
	return t
}

func (r *dnp3Reader) bytes(n int) []byte {
	if !r.has(n) {
		return nil
	}
	v := r.b[:n:n]
	r.b = r.b[n:]
	return v
}

// rest returns what is left, e.g. the MAC that ends an object.
func (r *dnp3Reader) rest() []byte {
	v := r.b
	r.b = nil
	return v
}

// num reads a value of format f.
func (r *dnp3Reader) num(f DNP3NumFormat) float64 {
	switch f {
	case DNP3NumInt16:
		return float64(int16(r.u16()))
	case DNP3NumInt32:
		return float64(int32(r.u32()))
	case DNP3NumUint8:
		return float64(r.u8())
	case DNP3NumUint16:
		return float64(r.u16())
	case DNP3NumUint32:
		return float64(r.u32())
	case DNP3NumFloat32:
		return float64(math.Float32frombits(r.u32()))
	case DNP3NumFloat64:
		return math.Float64frombits(r.u64())
	}
	return 0
}

// stamp reads a time of kind k.
func (r *dnp3Reader) stamp(k DNP3TimeKind) DNP3Timestamp {
	switch k {
	case DNP3TimeAbsolute:
		return DNP3Timestamp{Kind: k, Time: r.time()}
	case DNP3TimeRelative:
		return DNP3Timestamp{Kind: k, Relative: time.Duration(r.u16()) * time.Millisecond}
	}
	return DNP3Timestamp{}
}

// err returns ErrDNP3ValueShort when a read ran past the object.
func (r *dnp3Reader) err() error {
	if r.short {
		return ErrDNP3ValueShort
	}
	return nil
}

// dnp3Kind is which value type a point layout builds.
type dnp3Kind uint8

const (
	dnp3KindBinary dnp3Kind = iota
	dnp3KindDoubleBit
	dnp3KindCounter
	dnp3KindAnalog
	dnp3KindAnalogBlock    // g41: value, then status
	dnp3KindAnalogCmdEvent // g43: status, value
	dnp3KindBinaryCmdEvent // g13: state and status in one octet
)

// dnp3Layout is the layout of a point object: an optional leading
// flags or status octet, an optional value, an optional time.
type dnp3Layout struct {
	kind  dnp3Kind
	flags DNP3FlagFamily
	num   DNP3NumFormat
	time  DNP3TimeKind
}

// Shorthands for the layout table.
const (
	dnp3I16 = DNP3NumInt16
	dnp3I32 = DNP3NumInt32
	dnp3U16 = DNP3NumUint16
	dnp3U32 = DNP3NumUint32
	dnp3F32 = DNP3NumFloat32
	dnp3F64 = DNP3NumFloat64
	dnp3Abs = DNP3TimeAbsolute
	dnp3Rel = DNP3TimeRelative
)

// dnp3Layouts lists the point objects of annex A by group/variation.
var dnp3Layouts = map[uint16]dnp3Layout{
	dnp3GV(1, 2): {kind: dnp3KindBinary, flags: DNP3FlagsBinaryInput},
	dnp3GV(2, 1): {kind: dnp3KindBinary, flags: DNP3FlagsBinaryInput},
	dnp3GV(2, 2): {kind: dnp3KindBinary, flags: DNP3FlagsBinaryInput, time: dnp3Abs},
	dnp3GV(2, 3): {kind: dnp3KindBinary, flags: DNP3FlagsBinaryInput, time: dnp3Rel},

	dnp3GV(3, 2): {kind: dnp3KindDoubleBit, flags: DNP3FlagsDoubleBit},
	dnp3GV(4, 1): {kind: dnp3KindDoubleBit, flags: DNP3FlagsDoubleBit},
	dnp3GV(4, 2): {kind: dnp3KindDoubleBit, flags: DNP3FlagsDoubleBit, time: dnp3Abs},
	dnp3GV(4, 3): {kind: dnp3KindDoubleBit, flags: DNP3FlagsDoubleBit, time: dnp3Rel},

	dnp3GV(10, 2): {kind: dnp3KindBinary, flags: DNP3FlagsBinaryOutput},
	dnp3GV(11, 1): {kind: dnp3KindBinary, flags: DNP3FlagsBinaryOutput},
	dnp3GV(11, 2): {kind: dnp3KindBinary, flags: DNP3FlagsBinaryOutput, time: dnp3Abs},

	dnp3GV(13, 1): {kind: dnp3KindBinaryCmdEvent},
	dnp3GV(13, 2): {kind: dnp3KindBinaryCmdEvent, time: dnp3Abs},

	// Counters: variations 3, 4, 7, 8 (and 11, 12 of g21) are the
	// obsolete delta counters, laid out as the ones before them.
	dnp3GV(20, 1): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32},
	dnp3GV(20, 2): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16},
	dnp3GV(20, 3): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32},
	dnp3GV(20, 4): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16},
	dnp3GV(20, 5): {kind: dnp3KindCounter, num: dnp3U32},
	dnp3GV(20, 6): {kind: dnp3KindCounter, num: dnp3U16},
	dnp3GV(20, 7): {kind: dnp3KindCounter, num: dnp3U32},
	dnp3GV(20, 8): {kind: dnp3KindCounter, num: dnp3U16},

	dnp3GV(21, 1):  {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32},
	dnp3GV(21, 2):  {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16},
	dnp3GV(21, 3):  {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32},
	dnp3GV(21, 4):  {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16},
	dnp3GV(21, 5):  {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32, time: dnp3Abs},
	dnp3GV(21, 6):  {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16, time: dnp3Abs},
	dnp3GV(21, 7):  {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32, time: dnp3Abs},
	dnp3GV(21, 8):  {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16, time: dnp3Abs},
	dnp3GV(21, 9):  {kind: dnp3KindCounter, num: dnp3U32},
	dnp3GV(21, 10): {kind: dnp3KindCounter, num: dnp3U16},
	dnp3GV(21, 11): {kind: dnp3KindCounter, num: dnp3U32},
	dnp3GV(21, 12): {kind: dnp3KindCounter, num: dnp3U16},

	dnp3GV(22, 1): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32},
	dnp3GV(22, 2): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16},
	dnp3GV(22, 3): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32},
	dnp3GV(22, 4): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16},
	dnp3GV(22, 5): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32, time: dnp3Abs},
	dnp3GV(22, 6): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16, time: dnp3Abs},
	dnp3GV(22, 7): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32, time: dnp3Abs},
	dnp3GV(22, 8): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16, time: dnp3Abs},

	dnp3GV(23, 1): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32},
	dnp3GV(23, 2): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16},
	dnp3GV(23, 3): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32},
	dnp3GV(23, 4): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16},
	dnp3GV(23, 5): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32, time: dnp3Abs},
	dnp3GV(23, 6): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16, time: dnp3Abs},
	dnp3GV(23, 7): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U32, time: dnp3Abs},
	dnp3GV(23, 8): {kind: dnp3KindCounter, flags: DNP3FlagsCounter, num: dnp3U16, time: dnp3Abs},

	dnp3GV(30, 1): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I32},
	dnp3GV(30, 2): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I16},
	dnp3GV(30, 3): {kind: dnp3KindAnalog, num: dnp3I32},
	dnp3GV(30, 4): {kind: dnp3KindAnalog, num: dnp3I16},
	dnp3GV(30, 5): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F32},
	dnp3GV(30, 6): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F64},

	dnp3GV(31, 1): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I32},
	dnp3GV(31, 2): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I16},
	dnp3GV(31, 3): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I32, time: dnp3Abs},
	dnp3GV(31, 4): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I16, time: dnp3Abs},
	dnp3GV(31, 5): {kind: dnp3KindAnalog, num: dnp3I32},
	dnp3GV(31, 6): {kind: dnp3KindAnalog, num: dnp3I16},
	dnp3GV(31, 7): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F32},
	dnp3GV(31, 8): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F64},

	dnp3GV(32, 1): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I32},
	dnp3GV(32, 2): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I16},
	dnp3GV(32, 3): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I32, time: dnp3Abs},
	dnp3GV(32, 4): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I16, time: dnp3Abs},
	dnp3GV(32, 5): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F32},
	dnp3GV(32, 6): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F64},
	dnp3GV(32, 7): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F32, time: dnp3Abs},
	dnp3GV(32, 8): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F64, time: dnp3Abs},

	dnp3GV(33, 1): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I32},
	dnp3GV(33, 2): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I16},
	dnp3GV(33, 3): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I32, time: dnp3Abs},
	dnp3GV(33, 4): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3I16, time: dnp3Abs},
	dnp3GV(33, 5): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F32},
	dnp3GV(33, 6): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F64},
	dnp3GV(33, 7): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F32, time: dnp3Abs},
	dnp3GV(33, 8): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogInput, num: dnp3F64, time: dnp3Abs},

	dnp3GV(34, 1): {kind: dnp3KindAnalog, num: dnp3U16},
	dnp3GV(34, 2): {kind: dnp3KindAnalog, num: dnp3U32},
	dnp3GV(34, 3): {kind: dnp3KindAnalog, num: dnp3F32},

	dnp3GV(40, 1): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3I32},
	dnp3GV(40, 2): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3I16},
	dnp3GV(40, 3): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3F32},
	dnp3GV(40, 4): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3F64},

	dnp3GV(41, 1): {kind: dnp3KindAnalogBlock, num: dnp3I32},
	dnp3GV(41, 2): {kind: dnp3KindAnalogBlock, num: dnp3I16},
	dnp3GV(41, 3): {kind: dnp3KindAnalogBlock, num: dnp3F32},
	dnp3GV(41, 4): {kind: dnp3KindAnalogBlock, num: dnp3F64},

	dnp3GV(42, 1): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3I32},
	dnp3GV(42, 2): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3I16},
	dnp3GV(42, 3): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3I32, time: dnp3Abs},
	dnp3GV(42, 4): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3I16, time: dnp3Abs},
	dnp3GV(42, 5): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3F32},
	dnp3GV(42, 6): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3F64},
	dnp3GV(42, 7): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3F32, time: dnp3Abs},
	dnp3GV(42, 8): {kind: dnp3KindAnalog, flags: DNP3FlagsAnalogOutput, num: dnp3F64, time: dnp3Abs},

	dnp3GV(43, 1): {kind: dnp3KindAnalogCmdEvent, num: dnp3I32},
	dnp3GV(43, 2): {kind: dnp3KindAnalogCmdEvent, num: dnp3I16},
	dnp3GV(43, 3): {kind: dnp3KindAnalogCmdEvent, num: dnp3I32, time: dnp3Abs},
	dnp3GV(43, 4): {kind: dnp3KindAnalogCmdEvent, num: dnp3I16, time: dnp3Abs},
	dnp3GV(43, 5): {kind: dnp3KindAnalogCmdEvent, num: dnp3F32},
	dnp3GV(43, 6): {kind: dnp3KindAnalogCmdEvent, num: dnp3F64},
	dnp3GV(43, 7): {kind: dnp3KindAnalogCmdEvent, num: dnp3F32, time: dnp3Abs},
	dnp3GV(43, 8): {kind: dnp3KindAnalogCmdEvent, num: dnp3F64, time: dnp3Abs},

	dnp3GV(102, 1): {kind: dnp3KindAnalog, num: DNP3NumUint8},
}

// decode builds the value of one point object.
func (l dnp3Layout) decode(b []byte) (DNP3Value, error) {
	r := dnp3Reader{b: b}

	// Flags lead most points; command events lead with their status.
	var lead uint8
	if l.flags != DNP3FlagsAbsent || l.kind == dnp3KindAnalogCmdEvent || l.kind == dnp3KindBinaryCmdEvent {
		lead = r.u8()
	}

	num := r.num(l.num)
	if l.kind == dnp3KindAnalogBlock {
		lead = r.u8()
	}

	ts := r.stamp(l.time)
	if err := r.err(); err != nil {
		return nil, err
	}

	flags := DNP3Flags{Family: l.flags}
	if l.flags != DNP3FlagsAbsent {
		flags.Raw = lead
	}
	status := DNP3ControlStatus(lead & dnp3StatusMask)

	switch l.kind {
	case dnp3KindBinary:
		return DNP3Binary{Flags: flags, State: lead&dnp3StateBit != 0, Time: ts}, nil
	case dnp3KindDoubleBit:
		state := DNP3DoubleBit(lead >> dnp3DoubleBitPos & dnp3DoubleBitMask)
		return DNP3DoubleBitInput{Flags: flags, State: state, Time: ts}, nil
	case dnp3KindCounter:
		return DNP3Counter{Flags: flags, Value: uint32(num), Format: l.num, Time: ts}, nil
	case dnp3KindAnalog:
		return DNP3Analog{Flags: flags, Value: num, Format: l.num, Time: ts}, nil
	case dnp3KindBinaryCmdEvent:
		return DNP3BinaryCommandEvent{State: lead&dnp3StateBit != 0, Status: status, Time: ts}, nil
	}
	return DNP3AnalogCommand{Value: num, Format: l.num, Status: status, Time: ts}, nil
}

// dnp3Decode decodes the value of one object of group g variation v.
func dnp3Decode(g DNP3Group, v uint8, b []byte) (DNP3Value, error) {
	if len(b) == 0 {
		return nil, ErrDNP3NoValue
	}

	if l, ok := dnp3Layouts[dnp3GV(g, v)]; ok {
		return l.decode(b)
	}

	r := dnp3Reader{b: b}
	var val DNP3Value
	switch g {
	case DNP3GroupDeviceAttributes:
		val = dnp3Attr(&r)
	case DNP3GroupBinaryCommand:
		val = dnp3CROB(&r, v)
	case DNP3GroupTime, DNP3GroupCTO:
		val = dnp3TimeDate(&r, g, v)
	case DNP3GroupTimeDelay:
		val = dnp3Delay(&r, v)
	case DNP3GroupOctetString, DNP3GroupOctetStringEvent, DNP3GroupVTOutput, DNP3GroupVTEvent:
		val = DNP3OctetString(r.bytes(int(v)))
	case DNP3GroupFile:
		val = dnp3File(&r, v)
	case DNP3GroupDeviceStorage, DNP3GroupDeviceProfile:
		val = dnp3Storage(&r, g, v)
	case DNP3GroupPrivateObject:
		val = dnp3Private(&r, v)
	case DNP3GroupDataSetPrototype, DNP3GroupDataSetDescriptor, DNP3GroupDataSet, DNP3GroupDataSetEvent:
		val = dnp3DataSet(&r, g, v)
	case DNP3GroupApplication:
		val = dnp3AppID(&r, v)
	case DNP3GroupOperationStatus:
		val = dnp3Activate(&r, v)
	case DNP3GroupBCD:
		val = dnp3BCD(&r, v)
	case DNP3GroupAuthentication:
		val = dnp3Auth(&r, v)
	case DNP3GroupSecurityStat, DNP3GroupSecurityStatEvent:
		val = dnp3SecStat(&r, g, v)
	}

	if val == nil {
		return nil, ErrDNP3UnknownValue
	}

	if err := r.err(); err != nil {
		return nil, err
	}
	return val, nil
}

// dnp3Attr reads a device attribute: type code, length, value.
func dnp3Attr(r *dnp3Reader) DNP3Value {
	t := DNP3AttrType(r.u8())
	n := r.u8()
	return DNP3Attribute{Type: t, Data: r.bytes(int(n))}
}

// dnp3CROB reads a CROB or PCB; g12v3 is packed and read apart.
func dnp3CROB(r *dnp3Reader, v uint8) DNP3Value {
	if v != 1 && v != 2 {
		return nil
	}

	return DNP3CROB{
		Code:    DNP3ControlCode(r.u8()),
		Count:   r.u8(),
		OnTime:  r.u32(),
		OffTime: r.u32(),
		Status:  DNP3ControlStatus(r.u8() & dnp3StatusMask),
	}
}

// Time and date variations.
const (
	dnp3TimeAbs      = 1
	dnp3TimeInterval = 2
	dnp3TimeLast     = 3
	dnp3TimeIndexed  = 4
	dnp3CTOSynced    = 1
	dnp3CTOUnsynced  = 2
)

// dnp3TimeDate reads g50v1 to v4 and g51v1, v2.
func dnp3TimeDate(r *dnp3Reader, g DNP3Group, v uint8) DNP3Value {
	if g == DNP3GroupCTO {
		if v != dnp3CTOSynced && v != dnp3CTOUnsynced {
			return nil
		}
		return DNP3TimeDate{Time: r.time()}
	}

	switch v {
	case dnp3TimeAbs, dnp3TimeLast:
		return DNP3TimeDate{Time: r.time()}
	case dnp3TimeInterval:
		return DNP3TimeDate{Time: r.time(), Interval: r.u32(), Units: DNP3IntervalMilliseconds}
	case dnp3TimeIndexed:
		return DNP3TimeDate{Time: r.time(), Interval: r.u32(), Units: DNP3IntervalUnit(r.u8())}
	}
	return nil
}

// Time delay variations.
const (
	dnp3DelayCoarse = 1 // seconds
	dnp3DelayFine   = 2 // milliseconds
)

// dnp3Delay reads g52v1 or v2.
func dnp3Delay(r *dnp3Reader, v uint8) DNP3Value {
	switch v {
	case dnp3DelayCoarse:
		return DNP3TimeDelay{Delay: time.Duration(r.u16()) * time.Second}
	case dnp3DelayFine:
		return DNP3TimeDelay{Delay: time.Duration(r.u16()) * time.Millisecond}
	}
	return nil
}

// File object variations (g70).
const (
	dnp3FileIDVar         = 1
	dnp3FileAuthVar       = 2
	dnp3FileCommandVar    = 3
	dnp3FileStatusVar     = 4
	dnp3FileTransportVar  = 5
	dnp3FileTrStatusVar   = 6
	dnp3FileDescriptorVar = 7
	dnp3FileSpecVar       = 8
)

// dnp3File reads a file object. Names follow the fixed fields: their
// offset fields are skipped, as Wireshark does.
func dnp3File(r *dnp3Reader, v uint8) DNP3Value {
	switch v {
	case dnp3FileIDVar:
		return dnp3FileID(r)
	case dnp3FileAuthVar:
		r.u16() // user name offset
		user := r.u16()
		r.u16() // password offset
		pass := r.u16()
		key := r.u32()
		return DNP3FileAuth{AuthKey: key, UserName: string(r.bytes(int(user))), Password: string(r.bytes(int(pass)))}
	case dnp3FileCommandVar:
		return dnp3FileCmd(r)
	case dnp3FileStatusVar:
		return DNP3FileStatus{Handle: r.u32(), Size: r.u32(), MaxBlock: r.u16(), RequestID: r.u16(), Status: r.u8(), Text: r.rest()}
	case dnp3FileTransportVar:
		h, blk := r.u32(), r.u32()
		return DNP3FileTransport{Handle: h, Block: blk &^ dnp3LastBlockBit, Last: blk&dnp3LastBlockBit != 0, Data: r.rest()}
	case dnp3FileTrStatusVar:
		h, blk := r.u32(), r.u32()
		return DNP3FileTransportStatus{Handle: h, Block: blk &^ dnp3LastBlockBit, Last: blk&dnp3LastBlockBit != 0, Status: r.u8(), Text: r.rest()}
	case dnp3FileDescriptorVar:
		return dnp3FileDesc(r)
	case dnp3FileSpecVar:
		return DNP3FileSpec{Name: string(r.rest())}
	}
	return nil
}

// dnp3FileCmd reads a g70v3 file command.
func dnp3FileCmd(r *dnp3Reader) DNP3Value {
	r.u16() // name offset
	n := r.u16()

	c := DNP3FileCommand{Created: r.time(), Permissions: r.u16(), AuthKey: r.u32(), Size: r.u32()}
	c.Mode, c.MaxBlock, c.RequestID = r.u16(), r.u16(), r.u16()
	c.Name = string(r.bytes(int(n)))
	return c
}

// dnp3FileDesc reads a g70v7 file descriptor.
func dnp3FileDesc(r *dnp3Reader) DNP3Value {
	r.u16() // name offset
	n := r.u16()

	d := DNP3FileDescriptor{FileType: r.u16(), Size: r.u32(), Created: r.time(), Permissions: r.u16(), RequestID: r.u16()}
	d.Name = string(r.bytes(int(n)))
	return d
}

// Secure authentication variations (g120).
const (
	dnp3AuthChallengeVar = 1
	dnp3AuthReplyVar     = 2
	dnp3AuthAggrVar      = 3
	dnp3AuthKeyReqVar    = 4
	dnp3AuthKeyStatVar   = 5
	dnp3AuthKeyChgVar    = 6
	dnp3AuthErrorVar     = 7
)

// dnp3Auth reads a secure authentication object. Free format objects
// end with data that fills the object, as sized by its prefix.
func dnp3Auth(r *dnp3Reader, v uint8) DNP3Value {
	switch v {
	case dnp3AuthChallengeVar:
		return DNP3AuthChallenge{Seq: r.u32(), User: r.u16(), MACAlgorithm: r.u8(), Reason: r.u8(), Data: r.rest()}
	case dnp3AuthReplyVar:
		return DNP3AuthReply{Seq: r.u32(), User: r.u16(), MAC: r.rest()}
	case dnp3AuthAggrVar:
		return DNP3AuthAggressive{Seq: r.u32(), User: r.u16()}
	case dnp3AuthKeyReqVar:
		return DNP3AuthKeyStatusReq{User: r.u16()}
	case dnp3AuthKeyStatVar:
		s := DNP3AuthKeyStatus{Seq: r.u32(), User: r.u16(), KeyWrap: r.u8(), KeyStatus: r.u8(), MACAlgorithm: r.u8()}
		n := r.u16()
		s.Challenge = r.bytes(int(n))
		s.MAC = r.rest()
		return s
	case dnp3AuthKeyChgVar:
		return DNP3AuthKeyChange{Seq: r.u32(), User: r.u16(), KeyData: r.rest()}
	case dnp3AuthErrorVar:
		e := DNP3AuthError{Seq: r.u32(), User: r.u16(), Association: r.u16(), Code: r.u8()}
		e.Time = r.time()
		e.Text = r.rest()
		return e
	case dnp3AuthMACVar:
		return DNP3AuthMAC{MAC: r.rest()}
	}
	return dnp3AuthUpdate(r, v)
}

// CTO returns the common time of occurrence for header h of the
// fragment: the last g51 object of the nearest g51 header before it.
func (a *DNP3Application) CTO(h int) (time.Time, error) {
	if h < 0 || h >= len(a.Objects) {
		return time.Time{}, ErrDNP3BadObject
	}

	for j := h - 1; j >= 0; j-- {
		cto := &a.Objects[j]
		if cto.Group != DNP3GroupCTO || len(cto.Objects) == 0 {
			continue
		}

		v, err := cto.Value(len(cto.Objects) - 1)
		if err != nil {
			return time.Time{}, err
		}

		td, ok := v.(DNP3TimeDate)
		if !ok {
			return time.Time{}, ErrDNP3UnknownValue
		}
		return td.Time, nil
	}
	return time.Time{}, ErrDNP3NoCTO
}

// ResolveTime returns the absolute time of t, a timestamp of an object
// of header h: t.Time, or the fragment's CTO plus t.Relative. For
// example a g2v3 event 1011 ms after a CTO of 10:16:34.018 happened at
// 10:16:35.029.
func (a *DNP3Application) ResolveTime(h int, t DNP3Timestamp) (time.Time, error) {
	switch t.Kind {
	case DNP3TimeAbsolute:
		return t.Time, nil
	case DNP3TimeRelative:
		cto, err := a.CTO(h)
		if err != nil {
			return time.Time{}, err
		}
		return cto.Add(t.Relative), nil
	}
	return time.Time{}, ErrDNP3NoTime
}
