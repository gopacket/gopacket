// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"

	"github.com/gopacket/gopacket"
)

// LayerTypeGOOSE is the IEC 61850-8-1 GOOSE layer (EtherType 0x88B8).
var LayerTypeGOOSE = gopacket.RegisterLayerType(199, gopacket.LayerTypeMetadata{Name: "GOOSE", Decoder: gopacket.DecodeFunc(decodeGOOSE)})

// goosePdu [APPLICATION 1] field tags (IEC 61850-8-1 Annex A).
const (
	gooseTagPDU               uint32 = 1
	gooseTagGocbRef           uint32 = 0
	gooseTagTimeAllowedToLive uint32 = 1
	gooseTagDatSet            uint32 = 2
	gooseTagGoID              uint32 = 3
	gooseTagT                 uint32 = 4
	gooseTagStNum             uint32 = 5
	gooseTagSqNum             uint32 = 6
	gooseTagSimulation        uint32 = 7
	gooseTagConfRev           uint32 = 8
	gooseTagNdsCom            uint32 = 9
	gooseTagNumDatSetEntries  uint32 = 10
	gooseTagAllData           uint32 = 11
	gooseTagSecurity          uint32 = 12
)

// gooseRequired lists the fields goosePdu must carry, as a bit per tag.
const gooseRequired = 1<<gooseTagGocbRef | 1<<gooseTagTimeAllowedToLive |
	1<<gooseTagDatSet | 1<<gooseTagT | 1<<gooseTagStNum | 1<<gooseTagSqNum |
	1<<gooseTagConfRev | 1<<gooseTagNumDatSetEntries | 1<<gooseTagAllData

var (
	errGOOSEPDU     = errors.New("GOOSE: not a goosePdu")
	errGOOSEField   = errors.New("GOOSE: unexpected or out of order field")
	errGOOSEMissing = errors.New("GOOSE: mandatory field missing")
)

// GOOSE is an IEC 61850-8-1 Generic Object Oriented Substation Event. It
// is usually sent 802.1Q tagged with priority 4.
type GOOSE struct {
	BaseLayer
	IEC61850Header

	GocbRef           string
	TimeAllowedToLive uint32
	DatSet            string
	GoID              string
	Timestamp         MMSUTCTime
	StNum             uint32
	SqNum             uint32
	// Simulation is the "test" field of IEC 61850-8-1 Ed1.
	Simulation       bool
	ConfRev          uint32
	NdsCom           bool
	NumDatSetEntries uint32
	AllData          []MMSData
	Security         []byte
}

// LayerType returns LayerTypeGOOSE.
func (g *GOOSE) LayerType() gopacket.LayerType { return LayerTypeGOOSE }

// CanDecode returns LayerTypeGOOSE.
func (g *GOOSE) CanDecode() gopacket.LayerClass { return LayerTypeGOOSE }

// NextLayerType returns LayerTypeZero: GOOSE carries no further layer.
func (g *GOOSE) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// Payload returns nil.
func (g *GOOSE) Payload() []byte { return nil }

// EntriesMatch reports whether numDatSetEntries equals the number of
// allData members. A mismatch is not a decode error.
func (g *GOOSE) EntriesMatch() bool {
	return uint64(g.NumDatSetEntries) == uint64(len(g.AllData))
}

// DecodeFromBytes decodes a GOOSE frame starting at the APPID.
func (g *GOOSE) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*g = GOOSE{}

	apdu, err := decodeIEC61850Header(data, &g.IEC61850Header)
	if err != nil {
		df.SetTruncated()
		return err
	}

	pdu, _, err := osiBERExpect(apdu, osiBERApplication, osiBERConstructed, gooseTagPDU)
	if err == errOSIBERUnexpected {
		return errGOOSEPDU
	}
	if err != nil {
		return err
	}
	if err := g.decodePDU(pdu); err != nil {
		return err
	}

	g.BaseLayer = BaseLayer{Contents: data[:g.Length]}
	return nil
}

// decodePDU walks the goosePdu SEQUENCE. Fields must come in tag order.
func (g *GOOSE) decodePDU(b []byte) error {
	var seen uint32
	next := uint32(0)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return err
		}
		b = rest

		if t.Class != osiBERContext || t.Tag < next || t.Tag > gooseTagSecurity {
			return errGOOSEField
		}
		next = t.Tag + 1
		seen |= 1 << t.Tag

		if err := g.decodeField(t); err != nil {
			return err
		}
	}

	if seen&gooseRequired != gooseRequired {
		return errGOOSEMissing
	}
	return nil
}

// decodeField stores one goosePdu field.
func (g *GOOSE) decodeField(t osiBERTLV) error {
	// allData and security are the only constructed fields.
	switch t.Tag {
	case gooseTagAllData:
		if t.Form != osiBERConstructed {
			return errGOOSEField
		}
		var err error
		g.AllData, err = decodeMMSDataList(t.Value, 0)
		return err
	case gooseTagSecurity:
		g.Security = t.Value
		return nil
	}
	if t.Form != osiBERPrimitive {
		return errGOOSEField
	}

	var err error
	v := t.Value
	switch t.Tag {
	case gooseTagGocbRef:
		g.GocbRef = string(v)
	case gooseTagTimeAllowedToLive:
		g.TimeAllowedToLive, err = osiBERUint32(v)
	case gooseTagDatSet:
		g.DatSet = string(v)
	case gooseTagGoID:
		g.GoID = string(v)
	case gooseTagT:
		g.Timestamp, err = decodeMMSUTCTime(v)
	case gooseTagStNum:
		g.StNum, err = osiBERUint32(v)
	case gooseTagSqNum:
		g.SqNum, err = osiBERUint32(v)
	case gooseTagSimulation:
		g.Simulation, err = osiBERBool(v)
	case gooseTagConfRev:
		g.ConfRev, err = osiBERUint32(v)
	case gooseTagNdsCom:
		g.NdsCom, err = osiBERBool(v)
	case gooseTagNumDatSetEntries:
		g.NumDatSetEntries, err = osiBERUint32(v)
	}
	return err
}

func decodeGOOSE(data []byte, p gopacket.PacketBuilder) error {
	g := &GOOSE{}
	if err := g.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(g)
	p.SetApplicationLayer(g)
	return nil
}
