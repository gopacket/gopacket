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

// COTP is the ISO 8073 / X.224 connection-oriented transport protocol,
// class 0 in practice when it rides on TPKT. Layout of a TPDU:
//
//	+----+------+-------------------+---------------------+-----------+
//	| LI | type | fixed part        | variable parameters | user data |
//	+----+------+-------------------+---------------------+-----------+
//	      <------------- LI octets ------------------------>

// LayerTypeCOTP is the layer type of an ISO 8073 transport TPDU.
var LayerTypeCOTP = gopacket.RegisterLayerType(161, gopacket.LayerTypeMetadata{Name: "COTP", Decoder: gopacket.DecodeFunc(decodeCOTP)})

const (
	// LI octet plus type octet.
	cotpMinLen = 2

	// An LI of 255 is reserved (ISO 8073 13.2.1).
	cotpReservedLI = 255

	// Fixed part sizes after the type octet, per TPDU type.
	cotpConnFixedLen  = 5 // CR, CC, DR: dst-ref, src-ref, class or reason
	cotpDCFixedLen    = 4 // dst-ref, src-ref
	cotpRefNRFixedLen = 3 // ED, AK, EA, RJ, ER, DT normal: dst-ref, octet
	cotpDTShortLI     = 2 // class 0/1 DT: type, EOT+NR
	cotpDTExtFixedLen = 6 // extended DT: dst-ref, 4-octet EOT+NR

	cotpTypeMask   = 0xF0
	cotpCreditMask = 0x0F
	cotpEOTMask    = 0x80
	cotpNRMask     = 0x7F
	cotpExtNRMask  = 0x7FFFFFFF
	cotpParamHdr   = 2 // code, length

	// TPDU size parameter values are log2 of the size: 7 (128) to 13 (8192).
	cotpMinTPDUSizeExp = 7
	cotpMaxTPDUSizeExp = 13
)

var (
	// ErrCOTPTooShort is returned when data is shorter than the header
	// its length indicator announces.
	ErrCOTPTooShort = errors.New("COTP TPDU truncated")
	// ErrCOTPBadLength is returned when the length indicator cannot hold
	// the fixed part of the TPDU type, or is the reserved value 255.
	ErrCOTPBadLength = errors.New("COTP length indicator invalid for TPDU type")
	// ErrCOTPUnknownType is returned for a TPDU code ISO 8073 does not define.
	ErrCOTPUnknownType = errors.New("COTP unknown TPDU type")
	// ErrCOTPBadParameter is returned when a variable parameter overruns
	// the header.
	ErrCOTPBadParameter = errors.New("COTP parameter overruns header")
)

// COTPType is the TPDU code, the high nibble of the type octet.
type COTPType uint8

// TPDU codes from ISO 8073 table 8.
const (
	COTPTypeED COTPType = 0x10 // expedited data
	COTPTypeEA COTPType = 0x20 // expedited data acknowledgement
	COTPTypeRJ COTPType = 0x50 // reject
	COTPTypeAK COTPType = 0x60 // data acknowledgement
	COTPTypeER COTPType = 0x70 // TPDU error
	COTPTypeDR COTPType = 0x80 // disconnect request
	COTPTypeDC COTPType = 0xC0 // disconnect confirm
	COTPTypeCC COTPType = 0xD0 // connection confirm
	COTPTypeCR COTPType = 0xE0 // connection request
	COTPTypeDT COTPType = 0xF0 // data
)

// String returns the ISO 8073 abbreviation of the TPDU type.
func (t COTPType) String() string {
	switch t {
	case COTPTypeED:
		return "ED"
	case COTPTypeEA:
		return "EA"
	case COTPTypeRJ:
		return "RJ"
	case COTPTypeAK:
		return "AK"
	case COTPTypeER:
		return "ER"
	case COTPTypeDR:
		return "DR"
	case COTPTypeDC:
		return "DC"
	case COTPTypeCC:
		return "CC"
	case COTPTypeCR:
		return "CR"
	case COTPTypeDT:
		return "DT"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(t))
	}
}

// fixedLen returns the fixed part size after the type octet, or false
// for a code ISO 8073 does not define.
func (t COTPType) fixedLen() (int, bool) {
	switch t {
	case COTPTypeCR, COTPTypeCC, COTPTypeDR:
		return cotpConnFixedLen, true
	case COTPTypeDC:
		return cotpDCFixedLen, true
	case COTPTypeED, COTPTypeEA, COTPTypeRJ, COTPTypeAK, COTPTypeER, COTPTypeDT:
		return cotpRefNRFixedLen, true
	default:
		return 0, false
	}
}

// COTPParamCode identifies a COTP variable part parameter.
type COTPParamCode uint8

// Variable part parameter codes from ISO 8073 13.3.4 and later clauses.
const (
	COTPParamAckTime            COTPParamCode = 0x85
	COTPParamResidualErrorRate  COTPParamCode = 0x86
	COTPParamPriority           COTPParamCode = 0x87
	COTPParamTransitDelay       COTPParamCode = 0x88
	COTPParamThroughput         COTPParamCode = 0x89
	COTPParamSubsequenceNumber  COTPParamCode = 0x8A
	COTPParamReassignmentTime   COTPParamCode = 0x8B
	COTPParamFlowControlConfirm COTPParamCode = 0x8C
	COTPParamSelectiveAck       COTPParamCode = 0x8F
	COTPParamTPDUSize           COTPParamCode = 0xC0
	COTPParamCallingTSAP        COTPParamCode = 0xC1 // invalid TPDU in an ER
	COTPParamCalledTSAP         COTPParamCode = 0xC2
	COTPParamChecksum           COTPParamCode = 0xC3
	COTPParamVersion            COTPParamCode = 0xC4
	COTPParamProtection         COTPParamCode = 0xC5
	COTPParamAdditionalOptions  COTPParamCode = 0xC6
	COTPParamAlternativeClasses COTPParamCode = 0xC7
	COTPParamAdditionalInfo     COTPParamCode = 0xE0
	COTPParamPreferredTPDUSize  COTPParamCode = 0xF0
	COTPParamInactivityTimer    COTPParamCode = 0xF2
)

// String returns a human-readable name of the parameter code.
func (c COTPParamCode) String() string {
	switch c {
	case COTPParamAckTime:
		return "Acknowledgement Time"
	case COTPParamResidualErrorRate:
		return "Residual Error Rate"
	case COTPParamPriority:
		return "Priority"
	case COTPParamTransitDelay:
		return "Transit Delay"
	case COTPParamThroughput:
		return "Throughput"
	case COTPParamSubsequenceNumber:
		return "Subsequence Number"
	case COTPParamReassignmentTime:
		return "Reassignment Time"
	case COTPParamFlowControlConfirm:
		return "Flow Control Confirmation"
	case COTPParamSelectiveAck:
		return "Selective Acknowledgement"
	case COTPParamTPDUSize:
		return "TPDU Size"
	case COTPParamCallingTSAP:
		return "Calling TSAP"
	case COTPParamCalledTSAP:
		return "Called TSAP"
	case COTPParamChecksum:
		return "Checksum"
	case COTPParamVersion:
		return "Version"
	case COTPParamProtection:
		return "Protection"
	case COTPParamAdditionalOptions:
		return "Additional Option Selection"
	case COTPParamAlternativeClasses:
		return "Alternative Protocol Classes"
	case COTPParamAdditionalInfo:
		return "Additional Information"
	case COTPParamPreferredTPDUSize:
		return "Preferred Maximum TPDU Size"
	case COTPParamInactivityTimer:
		return "Inactivity Timer"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(c))
	}
}

// COTPParameter is one variable part TLV. Value aliases the packet data.
type COTPParameter struct {
	Code  COTPParamCode
	Value []byte
}

// COTP is an ISO 8073 TPDU. Which fixed fields are set depends on Type:
//
//	CR, CC     DstRef, SrcRef, Class, Options
//	DR         DstRef, SrcRef, Reason
//	DC         DstRef, SrcRef
//	ER         DstRef, Reason (reject cause)
//	DT         TPDUNumber, EOT (and DstRef above class 1; Extended and
//	           ExtTPDUNumber in extended format)
//	ED         DstRef, TPDUNumber, EOT
//	AK, EA, RJ DstRef, TPDUNumber
//
// Payload is the user data. A DT without EOT is one segment of a longer
// TSDU and goes to LayerTypeFragment rather than to an upper layer;
// COTPAssembler joins the segments.
type COTP struct {
	BaseLayer
	Length     uint8 // length indicator: header octets after this one
	Type       COTPType
	Credit     uint8 // low nibble of the type octet: CDT, or ROA for DT
	DstRef     uint16
	SrcRef     uint16
	Class      uint8 // CR, CC: preferred or selected protocol class
	Options    uint8 // CR, CC: option bits, low nibble of the class octet
	Reason     uint8 // DR: disconnect reason; ER: reject cause
	TPDUNumber uint8 // DT, ED, AK, EA, RJ: 7-bit sequence number
	EOT        bool  // DT, ED: last TPDU of the TSDU
	Parameters []COTPParameter

	// Extended is set for a DT in extended format (classes 2 to 4,
	// ISO 8073 13.7.3), whose 31-bit number is ExtTPDUNumber;
	// TPDUNumber holds its low 7 bits.
	Extended      bool
	ExtTPDUNumber uint32
}

// LayerType returns LayerTypeCOTP.
func (c *COTP) LayerType() gopacket.LayerType { return LayerTypeCOTP }

// CanDecode returns LayerTypeCOTP.
func (c *COTP) CanDecode() gopacket.LayerClass { return LayerTypeCOTP }

// NextLayerType picks the decoder for the user data. A complete DT
// goes to S7comm, S7comm-plus or the ISO session layer by its first
// octets; a DT segment goes to LayerTypeFragment.
func (c *COTP) NextLayerType() gopacket.LayerType {
	if len(c.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	if c.Type != COTPTypeDT {
		return gopacket.LayerTypePayload
	}
	if !c.EOT {
		return gopacket.LayerTypeFragment
	}
	return cotpUserLayer(c.Payload)
}

// cotpUserLayer picks the decoder of a whole, non-empty TSDU by its
// first octets.
func cotpUserLayer(tsdu []byte) gopacket.LayerType {
	switch {
	case isS7Comm(tsdu):
		return LayerTypeS7Comm
	case isS7CommPlus(tsdu):
		return LayerTypeS7CommPlus
	default:
		return LayerTypeISOSession
	}
}

// Parameter returns the value of the first parameter with code.
func (c *COTP) Parameter(code COTPParamCode) ([]byte, bool) {
	for _, p := range c.Parameters {
		if p.Code == code {
			return p.Value, true
		}
	}
	return nil, false
}

// TPDUSize returns the size in octets the TPDU size parameter announces,
// or 0 when it is absent or out of the 128-8192 range.
func (c *COTP) TPDUSize() int {
	v, ok := c.Parameter(COTPParamTPDUSize)
	if !ok || len(v) != 1 {
		return 0
	}
	if v[0] < cotpMinTPDUSizeExp || v[0] > cotpMaxTPDUSizeExp {
		return 0
	}
	return 1 << v[0]
}

// DecodeFromBytes decodes a COTP TPDU from data.
func (c *COTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*c = COTP{}
	if len(data) < cotpMinLen {
		df.SetTruncated()
		return ErrCOTPTooShort
	}

	c.Length = data[0]
	c.Type = COTPType(data[1] & cotpTypeMask)
	c.Credit = data[1] & cotpCreditMask
	hdrEnd := int(c.Length) + 1
	if c.Length == cotpReservedLI {
		return ErrCOTPBadLength
	}
	if hdrEnd > len(data) {
		df.SetTruncated()
		return ErrCOTPTooShort
	}

	fixed, ok := c.Type.fixedLen()
	if !ok {
		return ErrCOTPUnknownType
	}

	// Class 0 and 1 DT has no dst-ref: LI 2, then a single EOT/NR octet.
	if c.Type == COTPTypeDT && c.Length == cotpDTShortLI {
		c.setNR(data[2])
		c.Contents = data[:hdrEnd]
		c.Payload = data[hdrEnd:]
		return nil
	}

	if int(c.Length) < 1+fixed {
		return ErrCOTPBadLength
	}
	c.decodeFixed(data[cotpMinLen : cotpMinLen+fixed])

	err := c.decodeParams(data[cotpMinLen+fixed : hdrEnd])
	if err != nil && c.Type == COTPTypeDT {
		err = c.decodeDTExt(data[cotpMinLen:hdrEnd], err)
	}
	if err != nil {
		return err
	}

	c.Contents = data[:hdrEnd]
	c.Payload = data[hdrEnd:]
	return nil
}

// decodeFixed reads the fixed part that follows the type octet; f is
// exactly as long as fixedLen reports for c.Type.
func (c *COTP) decodeFixed(f []byte) {
	c.DstRef = binary.BigEndian.Uint16(f[0:2])

	switch c.Type {
	case COTPTypeCR, COTPTypeCC:
		c.SrcRef = binary.BigEndian.Uint16(f[2:4])
		c.Class = f[4] >> 4
		c.Options = f[4] & cotpCreditMask
	case COTPTypeDR:
		c.SrcRef = binary.BigEndian.Uint16(f[2:4])
		c.Reason = f[4]
	case COTPTypeDC:
		c.SrcRef = binary.BigEndian.Uint16(f[2:4])
	case COTPTypeER:
		c.Reason = f[2]
	case COTPTypeDT, COTPTypeED:
		c.setNR(f[2])
	default:
		c.TPDUNumber = f[2] & cotpNRMask
	}
}

// decodeDTExt re-reads a DT whose variable part is no parameter list
// in normal format as extended format, where the number takes four
// octets:
//
//	normal:   dst-ref(2) | EOT+NR(1) | parameters
//	extended: dst-ref(2) | EOT+NR(4) | parameters
//
// The format is negotiated in CR and CC, which a single TPDU does not
// show, so it is told by which layout parses. An extended DT whose
// number octets happen to form a parameter (third octet 1, no
// checksum) reads as normal format; EOT and user data are the same
// either way. h is the header after the type octet; normErr is returned
// when h is not extended format either.
func (c *COTP) decodeDTExt(h []byte, normErr error) error {
	if len(h) < cotpDTExtFixedLen {
		return normErr
	}

	c.Parameters = nil
	if c.decodeParams(h[cotpDTExtFixedLen:]) != nil {
		c.Parameters = nil
		return normErr
	}

	c.Extended = true
	c.ExtTPDUNumber = binary.BigEndian.Uint32(h[2:cotpDTExtFixedLen]) & cotpExtNRMask
	c.EOT = h[2]&cotpEOTMask != 0
	c.TPDUNumber = uint8(c.ExtTPDUNumber) & cotpNRMask
	return nil
}

// setNR splits a DT or ED octet into EOT flag and TPDU number.
func (c *COTP) setNR(b byte) {
	c.EOT = b&cotpEOTMask != 0
	c.TPDUNumber = b & cotpNRMask
}

// decodeParams splits the variable part into TLVs. The part is at most
// 253 octets, so the loop is short and every parameter is backed by data.
func (c *COTP) decodeParams(v []byte) error {
	for len(v) > 0 {
		if len(v) < cotpParamHdr {
			return ErrCOTPBadParameter
		}

		n := int(v[1])
		if cotpParamHdr+n > len(v) {
			return ErrCOTPBadParameter
		}

		c.Parameters = append(c.Parameters, COTPParameter{
			Code:  COTPParamCode(v[0]),
			Value: v[cotpParamHdr : cotpParamHdr+n],
		})
		v = v[cotpParamHdr+n:]
	}
	return nil
}

func decodeCOTP(data []byte, p gopacket.PacketBuilder) error {
	c := &COTP{}
	if err := c.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(c)

	next := c.NextLayerType()
	if next == gopacket.LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}
