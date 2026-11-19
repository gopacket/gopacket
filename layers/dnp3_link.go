// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"strings"
)

// DNP3LinkIssue is a set of link layer inconsistencies of one frame.
// They are the conditions for which a device discards a frame (DNP3
// application note AN2013-004b table 1, IEEE 1815-2012 clause 9.2.4)
// that can be told from the frame alone. A passive decoder still
// decodes such a frame: none of them is a decoding error.
type DNP3LinkIssue uint16

// DNP3LinkIssue bits.
const (
	// DNP3LinkBadFunction: the function code is not defined for the PRM
	// bit of the frame, or is obsolete.
	DNP3LinkBadFunction DNP3LinkIssue = 1 << iota
	// DNP3LinkBadFCV: the FCV bit of a primary frame is not the one its
	// function requires, e.g. clear in CONFIRMED_USER_DATA.
	DNP3LinkBadFCV
	// DNP3LinkReservedBit: bit 5 is set in a secondary frame, which has
	// no FCB.
	DNP3LinkReservedBit
	// DNP3LinkUnexpectedData: user data follows a function that carries
	// none, e.g. an ACK with LENGTH above 5.
	DNP3LinkUnexpectedData
	// DNP3LinkMissingData: a user data function carries no user data.
	DNP3LinkMissingData
	// DNP3LinkBadDestination: the destination is reserved (0xFFF0 to
	// 0xFFFB).
	DNP3LinkBadDestination
	// DNP3LinkBadSource: the source is reserved or a broadcast address
	// (0xFFF0 to 0xFFFF).
	DNP3LinkBadSource
	// DNP3LinkBadBroadcast: a frame to a broadcast address is not user
	// data.
	DNP3LinkBadBroadcast
	// DNP3LinkBadDirection: the DIR bit disagrees with the application
	// function of the fragment the frame begins: a request with DIR
	// clear, or a response with DIR set.
	DNP3LinkBadDirection
)

// Reserved and special link addresses.
const (
	dnp3AddrReserved  = 0xFFF0 // first reserved address
	dnp3AddrSelf      = 0xFFFC
	dnp3AddrBroadcast = 0xFFFD // first of the three broadcast addresses
)

// dnp3LinkIssueNames names the issues in bit order.
var dnp3LinkIssueNames = []string{
	"BadFunction",
	"BadFCV",
	"ReservedBit",
	"UnexpectedData",
	"MissingData",
	"BadDestination",
	"BadSource",
	"BadBroadcast",
	"BadDirection",
}

// Has reports whether every bit of issue is set.
func (i DNP3LinkIssue) Has(issue DNP3LinkIssue) bool {
	return i&issue == issue
}

// String lists the issues, e.g. "BadFCV|UnexpectedData". It is empty
// for a consistent frame.
func (i DNP3LinkIssue) String() string {
	var names []string
	for bit, name := range dnp3LinkIssueNames {
		if i&(1<<uint(bit)) != 0 {
			names = append(names, name)
		}
	}

	if rest := i >> uint(len(dnp3LinkIssueNames)); rest != 0 {
		names = append(names, fmt.Sprintf("Unknown(%#x)", uint16(rest)<<uint(len(dnp3LinkIssueNames))))
	}
	return strings.Join(names, "|")
}

// dnp3LinkFCV is the FCV bit each primary function requires (IEEE
// 1815-2012 table 9-1).
var dnp3LinkFCV = map[DNP3LinkFunc]bool{
	DNP3LinkResetLinkStates: false,
	DNP3LinkTestLinkStates:  true,
	DNP3LinkConfirmedData:   true,
	DNP3LinkUnconfirmedData: false,
	DNP3LinkRequestStatus:   false,
}

// carriesData reports whether f is a function that carries user data.
func (f DNP3LinkFunc) carriesData() bool {
	return f == DNP3LinkConfirmedData || f == DNP3LinkUnconfirmedData
}

// issues checks the link header against the rules a receiver applies.
func (l *DNP3Link) issues() DNP3LinkIssue {
	var out DNP3LinkIssue

	fcv, primary := dnp3LinkFCV[l.Function]
	secondary := l.Function == DNP3LinkAck || l.Function == DNP3LinkNack || l.Function == DNP3LinkStatus || l.Function == DNP3LinkNotSupported
	switch {
	case !primary && !secondary:
		out |= DNP3LinkBadFunction
	case primary && fcv != l.FCV:
		out |= DNP3LinkBadFCV
	case secondary && l.Control&dnp3CtlFCB != 0:
		out |= DNP3LinkReservedBit
	}

	// LENGTH counts the 5 header octets, then the user data.
	hasData := l.Length > dnp3MinLength
	if l.Function.carriesData() && !hasData {
		out |= DNP3LinkMissingData
	}
	if !l.Function.carriesData() && hasData {
		out |= DNP3LinkUnexpectedData
	}

	if l.Destination >= dnp3AddrReserved && l.Destination < dnp3AddrSelf {
		out |= DNP3LinkBadDestination
	}
	if l.Destination >= dnp3AddrBroadcast && !l.Function.carriesData() {
		out |= DNP3LinkBadBroadcast
	}
	if l.Source >= dnp3AddrReserved {
		out |= DNP3LinkBadSource
	}
	return out
}
