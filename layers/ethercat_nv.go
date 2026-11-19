// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// EtherCAT frame types other than datagrams (Wireshark packet-nv.c,
// packet-ioraw.c, packet-ams.c, packet-ecatmb.c):
//
//	type 2  ADS              an AMS packet, see ethercat_ams.go
//	type 3  raw IO           Header (4) | data
//	type 4  network vars     Publisher (6) | Count (2) | Cycle (2) |
//	                         reserved (2) | variables
//	                         variable: ID (2) | Hash (2) | Length (2) |
//	                                   Quality (2) | data
//	type 5  mailbox gateway  a mailbox, see ethercat_mailbox.go
//
// Fields are little endian.

package layers

import "encoding/binary"

const (
	ethercatNVHeaderLen    = 12
	ethercatNVVarHeaderLen = 8
	ethercatRawIOHeaderLen = 4
)

// EtherCATNVVariable is one published network variable.
type EtherCATNVVariable struct {
	ID      uint16
	Hash    uint16
	Length  uint16
	Quality uint16
	Data    []byte
}

// EtherCATNV is a network variables frame (EtherCAT frame type 4).
//
// Count is the announced number of variables; Variables holds those that
// fit the frame.
type EtherCATNV struct {
	Publisher EtherCATAMSNetID
	Count     uint16
	Cycle     uint16
	Variables []EtherCATNVVariable
}

// decodeEtherCATNV decodes a network variables frame body, nil when the
// header is cut.
func decodeEtherCATNV(data []byte) *EtherCATNV {
	if len(data) < ethercatNVHeaderLen {
		return nil
	}

	nv := &EtherCATNV{
		Count: binary.LittleEndian.Uint16(data[6:8]),
		Cycle: binary.LittleEndian.Uint16(data[8:10]),
	}
	copy(nv.Publisher[:], data[:ethercatAMSNetIDLen])
	body := data[ethercatNVHeaderLen:]

	// Count the variables that fit before allocating: Count is not
	// trusted. Each one takes at least its 8-byte header.
	fit := 0
	for rest := body; fit < int(nv.Count); fit++ {
		size, ok := ethercatNVVarSize(rest)
		if !ok {
			break
		}
		rest = rest[size:]
	}
	if fit == 0 {
		return nv
	}

	nv.Variables = make([]EtherCATNVVariable, fit)
	for i := range nv.Variables {
		size, _ := ethercatNVVarSize(body)
		nv.Variables[i] = EtherCATNVVariable{
			ID:      binary.LittleEndian.Uint16(body[0:2]),
			Hash:    binary.LittleEndian.Uint16(body[2:4]),
			Length:  binary.LittleEndian.Uint16(body[4:6]),
			Quality: binary.LittleEndian.Uint16(body[6:8]),
			Data:    body[ethercatNVVarHeaderLen:size],
		}
		body = body[size:]
	}
	return nv
}

// ethercatNVVarSize returns the size of the variable at the start of b,
// header included, and whether all of it is there.
func ethercatNVVarSize(b []byte) (int, bool) {
	if len(b) < ethercatNVVarHeaderLen {
		return 0, false
	}

	size := ethercatNVVarHeaderLen + int(binary.LittleEndian.Uint16(b[4:6]))
	return size, size <= len(b)
}

// EtherCATRawIO is a raw IO frame (EtherCAT frame type 3).
type EtherCATRawIO struct {
	Header uint32
	Data   []byte
}

// decodeEtherCATRawIO decodes a raw IO frame body, nil when the header
// is cut.
func decodeEtherCATRawIO(data []byte) *EtherCATRawIO {
	if len(data) < ethercatRawIOHeaderLen {
		return nil
	}

	return &EtherCATRawIO{
		Header: binary.LittleEndian.Uint32(data),
		Data:   data[ethercatRawIOHeaderLen:],
	}
}
