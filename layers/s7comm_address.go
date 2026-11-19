// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import "encoding/binary"

// Read/Write Var item addresses other than S7ANY. Address holds the
// octets after the syntax ID:
//
//	DBREAD (0xB0, length >= 7):  count, {length, DB(2), start(2)}...
//	NCK (0x82-0x84, length 8):   area<<5|unit, column(2), line(2),
//	                             module, line count
//	DRIVEESANY (0xA2, length 10): unknown(1), unknown(2), unknown(2),
//	                             parameter(2), index(2)

const (
	s7commDBReadMinLen  = 7
	s7commDBReadAreaLen = 5
	s7commNCKLen        = 8
	s7commDriveESLen    = 10
	s7commNCKAreaShift  = 5
	s7commNCKUnitMask   = 0x1F
)

// S7CommDBReadArea is one area of a DBREAD address.
type S7CommDBReadArea struct {
	Length   uint8
	DBNumber uint16
	Start    uint16 // byte address
}

// S7CommNCKAddress is a Sinumerik NCK variable address.
type S7CommNCKAddress struct {
	Area      uint8 // 3 bits
	Unit      uint8 // 5 bits
	Column    uint16
	Line      uint16
	Module    uint8
	LineCount uint8
}

// S7CommDriveESAddress addresses a drive parameter routed through the
// PLC (Drive ES).
type S7CommDriveESAddress struct {
	Unknown1  uint8
	Unknown2  uint16
	Unknown3  uint16
	Parameter uint16
	Index     uint16
}

// decodeAddress sets the DBREAD, NCK or Drive ES view for the
// specification, syntax ID and length Wireshark accepts. Other
// addresses, or a DBREAD whose area count overruns, set no view.
func (i *S7CommVarItem) decodeAddress() {
	if i.VarSpec != s7commVarSpecIdentifier {
		return
	}

	a := i.Address
	be := binary.BigEndian
	switch {
	case i.SyntaxID == S7CommSyntaxDBRead && i.Length >= s7commDBReadMinLen:
		i.DBRead = s7commDBReadAreas(a)
	case (i.SyntaxID == S7CommSyntaxNCK || i.SyntaxID == S7CommSyntaxNCKMetric || i.SyntaxID == S7CommSyntaxNCKInch) &&
		i.Length == s7commNCKLen:
		i.NCK = &S7CommNCKAddress{
			Area:      a[0] >> s7commNCKAreaShift,
			Unit:      a[0] & s7commNCKUnitMask,
			Column:    be.Uint16(a[1:3]),
			Line:      be.Uint16(a[3:5]),
			Module:    a[5],
			LineCount: a[6],
		}
	case i.SyntaxID == S7CommSyntaxDriveESAny && i.Length == s7commDriveESLen:
		i.DriveES = &S7CommDriveESAddress{
			Unknown1:  a[0],
			Unknown2:  be.Uint16(a[1:3]),
			Unknown3:  be.Uint16(a[3:5]),
			Parameter: be.Uint16(a[5:7]),
			Index:     be.Uint16(a[7:9]),
		}
	}
}

// s7commDBReadAreas reads a DBREAD area list, nil if the count overruns.
func s7commDBReadAreas(a []byte) []S7CommDBReadArea {
	n := int(a[0])
	a = a[1:]
	if n*s7commDBReadAreaLen > len(a) {
		return nil
	}

	areas := make([]S7CommDBReadArea, n)
	for k := range areas {
		b := a[k*s7commDBReadAreaLen:]
		areas[k] = S7CommDBReadArea{
			Length:   b[0],
			DBNumber: binary.BigEndian.Uint16(b[1:3]),
			Start:    binary.BigEndian.Uint16(b[3:5]),
		}
	}
	return areas
}
