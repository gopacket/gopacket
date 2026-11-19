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

	"github.com/gopacket/gopacket"
)

// LayerTypeSV is the IEC 61850-9-2 Sampled Values layer (EtherType 0x88BA).
var LayerTypeSV = gopacket.RegisterLayerType(200, gopacket.LayerTypeMetadata{Name: "SV", Decoder: gopacket.DecodeFunc(decodeSV)})

// savPdu [APPLICATION 0] and ASDU field tags (IEC 61850-9-2 clause 8).
const (
	svTagPDU      uint32 = 0
	svTagNoASDU   uint32 = 0
	svTagSecurity uint32 = 1
	svTagSeqASDU  uint32 = 2

	svTagSvID       uint32 = 0
	svTagDatSet     uint32 = 1
	svTagSmpCnt     uint32 = 2
	svTagConfRev    uint32 = 3
	svTagRefrTm     uint32 = 4
	svTagSmpSynch   uint32 = 5
	svTagSmpRate    uint32 = 6
	svTagSample     uint32 = 7
	svTagSmpMod     uint32 = 8
	svTagGmIdentity uint32 = 9
)

const (
	// svRequired lists the ASDU fields that must be present.
	svRequired = 1<<svTagSvID | 1<<svTagSmpCnt | 1<<svTagConfRev |
		1<<svTagSmpSynch | 1<<svTagSample

	// IEC 61850-9-2LE: 8 channels of INT32 value + 32 bit quality.
	svLEChannels  = 8
	svLESampleLen = svLEChannels * 8
)

var (
	errSVPDU     = errors.New("SV: not a savPdu")
	errSVField   = errors.New("SV: unexpected or out of order field")
	errSVMissing = errors.New("SV: mandatory field missing")
	errSVWidth   = errors.New("SV: fixed size field has wrong length")
	errSVLE      = errors.New("SV: sample is not 9-2LE sized")
)

// SVSmpSynch is the smpSynch value of an ASDU. Values 5 to 254 name a
// grandmaster clock (IEC 61850-9-2 Ed2.1).
type SVSmpSynch uint8

// smpSynch values.
const (
	SVSmpSynchNone   SVSmpSynch = 0
	SVSmpSynchLocal  SVSmpSynch = 1
	SVSmpSynchGlobal SVSmpSynch = 2
)

// String returns the smpSynch meaning.
func (s SVSmpSynch) String() string {
	switch s {
	case SVSmpSynchNone:
		return "none"
	case SVSmpSynchLocal:
		return "local"
	case SVSmpSynchGlobal:
		return "global"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// SVLESample is one IEC 61850-9-2LE channel: a scaled value and its
// IEC 61850 quality bits.
type SVLESample struct {
	Value   int32
	Quality uint32
}

// SVASDU is one Application Service Data Unit of a savPdu. The Has*
// fields tell whether an OPTIONAL field was present.
type SVASDU struct {
	SvID       string
	DatSet     string
	SmpCnt     uint16
	ConfRev    uint32
	RefrTm     MMSUTCTime
	HasRefrTm  bool
	SmpSynch   SVSmpSynch
	SmpRate    uint16
	HasSmpRate bool
	Sample     []byte
	SmpMod     uint16
	HasSmpMod  bool
	GmIdentity []byte
}

// Samples92LE decodes Sample as the 9-2LE dataset of 4 currents and 4
// voltages. It fails unless Sample is 64 octets long.
func (a *SVASDU) Samples92LE() ([svLEChannels]SVLESample, error) {
	var out [svLEChannels]SVLESample
	if len(a.Sample) != svLESampleLen {
		return out, errSVLE
	}

	for i := range out {
		b := a.Sample[i*8:]
		out[i].Value = int32(binary.BigEndian.Uint32(b))
		out[i].Quality = binary.BigEndian.Uint32(b[4:])
	}
	return out, nil
}

// SV is an IEC 61850-9-2 Sampled Values frame. It is usually sent 802.1Q
// tagged with priority 4.
type SV struct {
	BaseLayer
	IEC61850Header

	NoASDU   uint16
	Security []byte
	ASDUs    []SVASDU
}

// LayerType returns LayerTypeSV.
func (s *SV) LayerType() gopacket.LayerType { return LayerTypeSV }

// CanDecode returns LayerTypeSV.
func (s *SV) CanDecode() gopacket.LayerClass { return LayerTypeSV }

// NextLayerType returns LayerTypeZero: SV carries no further layer.
func (s *SV) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// Payload returns nil.
func (s *SV) Payload() []byte { return nil }

// ASDUCountMatch reports whether noASDU equals the number of decoded
// ASDUs. A mismatch is not a decode error.
func (s *SV) ASDUCountMatch() bool {
	return int(s.NoASDU) == len(s.ASDUs)
}

// DecodeFromBytes decodes an SV frame starting at the APPID.
func (s *SV) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*s = SV{ASDUs: s.ASDUs[:0]}

	apdu, err := decodeIEC61850Header(data, &s.IEC61850Header)
	if err != nil {
		df.SetTruncated()
		return err
	}

	pdu, _, err := osiBERExpect(apdu, osiBERApplication, osiBERConstructed, svTagPDU)
	if err == errOSIBERUnexpected {
		return errSVPDU
	}
	if err != nil {
		return err
	}
	if err := s.decodePDU(pdu); err != nil {
		return err
	}

	s.BaseLayer = BaseLayer{Contents: data[:s.Length]}
	return nil
}

// decodePDU walks savPdu: noASDU, optional security, seqASDU.
func (s *SV) decodePDU(b []byte) error {
	v, b, err := osiBERExpect(b, osiBERContext, osiBERPrimitive, svTagNoASDU)
	if err != nil {
		return errSVPDU
	}
	n, err := osiBERUint(v)
	if err != nil {
		return err
	}
	if n > 0xffff {
		return errSVWidth
	}
	s.NoASDU = uint16(n)

	t, rest, err := osiBERNext(b)
	if err != nil {
		return err
	}
	if t.Class == osiBERContext && t.Tag == svTagSecurity {
		s.Security = t.Value
		if t, rest, err = osiBERNext(rest); err != nil {
			return err
		}
	}
	if !t.is(osiBERContext, osiBERConstructed, svTagSeqASDU) || len(rest) != 0 {
		return errSVPDU
	}

	// seqASDU is a SEQUENCE OF ASDU, each a universal SEQUENCE.
	for seq := t.Value; len(seq) > 0; {
		var asdu []byte
		asdu, seq, err = osiBERExpect(seq, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return err
		}

		var a SVASDU
		if err := a.decode(asdu); err != nil {
			return err
		}
		s.ASDUs = append(s.ASDUs, a)
	}
	return nil
}

// decode walks one ASDU. Fields must come in tag order.
func (a *SVASDU) decode(b []byte) error {
	var seen uint32
	next := uint32(0)
	for len(b) > 0 {
		t, rest, err := osiBERNext(b)
		if err != nil {
			return err
		}
		b = rest

		if t.Class != osiBERContext || t.Form != osiBERPrimitive || t.Tag < next || t.Tag > svTagGmIdentity {
			return errSVField
		}
		next = t.Tag + 1
		seen |= 1 << t.Tag

		if err := a.decodeField(t.Tag, t.Value); err != nil {
			return err
		}
	}

	if seen&svRequired != svRequired {
		return errSVMissing
	}
	return nil
}

// decodeField stores one ASDU field.
func (a *SVASDU) decodeField(tag uint32, v []byte) error {
	var n uint64
	var err error
	switch tag {
	case svTagSvID:
		a.SvID = string(v)
	case svTagDatSet:
		a.DatSet = string(v)
	case svTagSmpCnt:
		n, err = svFixedUint(v, 2)
		a.SmpCnt = uint16(n)
	case svTagConfRev:
		n, err = svFixedUint(v, 4)
		a.ConfRev = uint32(n)
	case svTagRefrTm:
		a.RefrTm, err = decodeMMSUTCTime(v)
		a.HasRefrTm = true
	case svTagSmpSynch:
		n, err = svFixedUint(v, 1)
		a.SmpSynch = SVSmpSynch(n)
	case svTagSmpRate:
		n, err = svFixedUint(v, 2)
		a.SmpRate = uint16(n)
		a.HasSmpRate = true
	case svTagSample:
		a.Sample = v
	case svTagSmpMod:
		n, err = svFixedUint(v, 2)
		a.SmpMod = uint16(n)
		a.HasSmpMod = true
	case svTagGmIdentity:
		a.GmIdentity = v
	}
	return err
}

// svFixedUint reads a big-endian unsigned field of 1 to width octets.
// 9-2 defines these as fixed size OCTET STRINGs; shorter encodings seen
// in the wild are accepted, longer ones are not.
func svFixedUint(v []byte, width int) (uint64, error) {
	if len(v) == 0 || len(v) > width {
		return 0, errSVWidth
	}

	var n uint64
	for _, b := range v {
		n = n<<8 | uint64(b)
	}
	return n, nil
}

func decodeSV(data []byte, p gopacket.PacketBuilder) error {
	s := &SV{}
	if err := s.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(s)
	p.SetApplicationLayer(s)
	return nil
}
