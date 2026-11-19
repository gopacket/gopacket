// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/gopacket/gopacket"
)

// IEC 61850-8-1 GOOSE and IEC 61850-9-2 Sampled Values EtherTypes. They are
// not decoded unless registerIEC61850Decoders has run.
const (
	EthernetTypeGOOSE EthernetType = 0x88B8
	EthernetTypeSV    EthernetType = 0x88BA
)

const (
	iec61850HeaderLen = 8
	// iec61850SimBit is the simulation bit of Reserved1 (IEC 61850-8-1 Ed2).
	iec61850SimBit = 0x8000
)

var errIEC61850Length = errors.New("IEC 61850: length field out of range")

// IEC61850Header is the header GOOSE and SV share in front of their APDU.
// Length counts from AppID to the end of the APDU.
type IEC61850Header struct {
	AppID     uint16
	Length    uint16
	Reserved1 uint16
	Reserved2 uint16
}

// Simulated reports whether the simulation bit of Reserved1 is set.
func (h *IEC61850Header) Simulated() bool {
	return h.Reserved1&iec61850SimBit != 0
}

// decodeIEC61850Header parses the header and returns the APDU bytes the
// Length field covers. Ethernet padding past Length is ignored.
func decodeIEC61850Header(data []byte, h *IEC61850Header) ([]byte, error) {
	if len(data) < iec61850HeaderLen {
		return nil, errIEC61850Length
	}

	h.AppID = binary.BigEndian.Uint16(data[0:2])
	h.Length = binary.BigEndian.Uint16(data[2:4])
	h.Reserved1 = binary.BigEndian.Uint16(data[4:6])
	h.Reserved2 = binary.BigEndian.Uint16(data[6:8])

	n := int(h.Length)
	if n < iec61850HeaderLen || n > len(data) {
		return nil, errIEC61850Length
	}
	return data[iec61850HeaderLen:n], nil
}

// registerIEC61850Decoders makes Ethernet and Dot1Q hand GOOSE and SV
// frames to their decoders. It is idempotent.
func registerIEC61850Decoders() {
	EthernetTypeMetadata[EthernetTypeGOOSE] = EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeGOOSE),
		Name:       "GOOSE",
		LayerType:  LayerTypeGOOSE,
	}
	EthernetTypeMetadata[EthernetTypeSV] = EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeSV),
		Name:       "SV",
		LayerType:  LayerTypeSV,
	}
}
