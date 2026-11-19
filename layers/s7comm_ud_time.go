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

// S7comm carries two time encodings.
//
// BCD timestamp, one BCD byte per field. The 10-octet form is used by
// the clock functions, the 8-octet form (S7 DATE_AND_TIME) by alarms,
// diagnostic messages and SZL records:
//
//	[reserved, century,] year, month, day, hour, minute, second,
//	msec (2 high digits), msec low digit << 4 | weekday
//
// S7 time, 6 octets: milliseconds of the day (4), days since
// 1984-01-01 (2). Used in block info.
//
// Both carry no zone; they are returned as UTC.
//
// A BCD timestamp is decoded as the DATE_AND_TIME type defines it and
// is an error otherwise:
//
//   - every digit is 0-9, the low nibble of the last octet (weekday)
//     excepted, which is ignored;
//   - year 90-99 is 1990-1999, 00-89 is 2000-2089. The century octet
//     of the 10-octet form counts only where it can add something:
//     20 with a year of 90-99 gives 2090-2099. Some CPUs send 19 for
//     20xx;
//   - month 1-12, a day the month has, hour 0-23, minute and second
//     0-59.
//
// Wireshark 4.7 differs: it reads digits above 9 as numbers (0x1A is
// 20), takes year 89 as 1989, uses any century octet for years from
// 89 on, and shows whatever date results, normalising a day or hour
// out of range and showing only a month outside 1-12 as invalid.

const (
	s7commBCDLongLen  = 10
	s7commBCDShortLen = 8
	s7commS7TimeLen   = 6

	// Years below 90 are 20xx, the others 19xx.
	s7commCenturyPivot = 90
	s7commCentury19    = 19
	s7commCentury20    = 20
	s7commYearsPerCent = 100

	s7commMonthsPerYear = 12
	s7commHoursPerDay   = 24
	s7commMinutesPerHr  = 60
	s7commSecondsPerMin = 60
	s7commBCDMsecHigh   = 10
	s7commNibbleShift   = 4
	s7commNibbleMask    = 0x0F
	s7commBCDDigits     = 10
)

// s7commEpoch is the S7 time origin, 1984-01-01 00:00 UTC.
var s7commEpoch = time.Date(1984, time.January, 1, 0, 0, 0, 0, time.UTC)

// s7commBCDForm selects the BCD timestamp layout.
type s7commBCDForm uint8

const (
	s7commBCDLong  s7commBCDForm = iota // 10 octets, with century
	s7commBCDShort                      // 8 octets, DATE_AND_TIME
)

// s7commBCD converts one BCD octet, e.g. 0x59 -> 59.
func s7commBCD(b byte) int {
	return int(b>>s7commNibbleShift)*s7commBCDDigits + int(b&s7commNibbleMask)
}

// s7commIsBCD reports whether every digit of the date, time and
// millisecond octets is 0-9. b holds the 8 octets of the short form;
// the weekday nibble of the last one is not looked at.
func s7commIsBCD(b []byte) bool {
	for i, c := range b[:s7commBCDShortLen] {
		if c>>s7commNibbleShift >= s7commBCDDigits {
			return false
		}
		if i < s7commBCDShortLen-1 && c&s7commNibbleMask >= s7commBCDDigits {
			return false
		}
	}
	return true
}

// s7commBCDTime decodes a BCD timestamp. Anything DATE_AND_TIME does
// not allow (a digit above 9, month 13, 30 February, minute 60) is an
// error rather than normalised into another date.
func s7commBCDTime(b []byte, form s7commBCDForm) (time.Time, error) {
	givenCentury := s7commCentury19
	if form == s7commBCDLong {
		if len(b) < s7commBCDLongLen {
			return time.Time{}, fmt.Errorf("%w: timestamp %d octets", ErrS7CommMalformed, len(b))
		}
		givenCentury = s7commBCD(b[1])
		b = b[2:]
	}
	if len(b) < s7commBCDShortLen {
		return time.Time{}, fmt.Errorf("%w: timestamp %d octets", ErrS7CommMalformed, len(b))
	}
	b = b[:s7commBCDShortLen]
	if !s7commIsBCD(b) {
		return time.Time{}, fmt.Errorf("%w: timestamp % x is not BCD", ErrS7CommMalformed, b)
	}

	year, month, day := s7commBCD(b[0]), s7commBCD(b[1]), s7commBCD(b[2])
	hour, minute, sec := s7commBCD(b[3]), s7commBCD(b[4]), s7commBCD(b[5])
	msec := s7commBCD(b[6])*s7commBCDMsecHigh + int(b[7]>>s7commNibbleShift)

	// 90-99 is 19xx unless the long form says 20xx.
	century := s7commCentury20
	if year >= s7commCenturyPivot && givenCentury != s7commCentury20 {
		century = s7commCentury19
	}
	year += century * s7commYearsPerCent

	if month < 1 || month > s7commMonthsPerYear || day < 1 ||
		hour >= s7commHoursPerDay || minute >= s7commMinutesPerHr || sec >= s7commSecondsPerMin {
		return time.Time{}, fmt.Errorf("%w: timestamp % x", ErrS7CommMalformed, b)
	}

	// time.Date rolls a day the month lacks over into the next month.
	t := time.Date(year, time.Month(month), day, hour, minute, sec, msec*int(time.Millisecond), time.UTC)
	if t.Day() != day {
		return time.Time{}, fmt.Errorf("%w: timestamp % x: no day %d in month %d", ErrS7CommMalformed, b, day, month)
	}
	return t, nil
}

// s7commS7Time decodes the 6-octet S7 time; b must hold 6 octets.
func s7commS7Time(b []byte) time.Time {
	ms := binary.BigEndian.Uint32(b[0:4])
	days := binary.BigEndian.Uint16(b[4:6])
	return s7commEpoch.AddDate(0, 0, int(days)).Add(time.Duration(ms) * time.Millisecond)
}

// decodeClock reads the timestamp of a clock read response or clock
// set request.
func (u *S7CommUserdata) decodeClock() error {
	switch {
	case u.Type == S7CommUDTypeResponse && (u.Subfunction == S7CommTimeReadClock || u.Subfunction == S7CommTimeReadClockFol):
	case u.Type == S7CommUDTypeRequest && (u.Subfunction == S7CommTimeSetClock || u.Subfunction == S7CommTimeSetClock2):
	default:
		return nil
	}

	t, err := s7commBCDTime(u.Data, s7commBCDLong)
	if err != nil {
		return err
	}
	u.Clock = &t
	return nil
}
