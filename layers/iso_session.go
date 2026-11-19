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

// LayerTypeISOSession is the ISO 8327 session layer carried in COTP data.
var LayerTypeISOSession = gopacket.RegisterLayerType(195, gopacket.LayerTypeMetadata{Name: "ISOSession", Decoder: gopacket.DecodeFunc(decodeISOSession)})

// ISOSessionSPDUType is the SPDU identifier (SI) of an ISO 8327-1 SPDU.
// SI 1 means Give Tokens when it opens a concatenated TSDU and Data
// Transfer in second place: "01 00 01 00 <data>" is GT followed by DT.
type ISOSessionSPDUType uint8

// ISO 8327-1 SPDU identifiers.
const (
	ISOSessionGiveTokens          ISOSessionSPDUType = 1
	ISOSessionDataTransfer        ISOSessionSPDUType = 1
	ISOSessionPleaseTokens        ISOSessionSPDUType = 2
	ISOSessionExpedited           ISOSessionSPDUType = 5
	ISOSessionPrepare             ISOSessionSPDUType = 7
	ISOSessionNotFinished         ISOSessionSPDUType = 8
	ISOSessionFinish              ISOSessionSPDUType = 9
	ISOSessionDisconnect          ISOSessionSPDUType = 10
	ISOSessionRefuse              ISOSessionSPDUType = 12
	ISOSessionConnect             ISOSessionSPDUType = 13
	ISOSessionAccept              ISOSessionSPDUType = 14
	ISOSessionConnectDataOverflow ISOSessionSPDUType = 15
	ISOSessionOverflowAccept      ISOSessionSPDUType = 16
	ISOSessionGiveTokensConfirm   ISOSessionSPDUType = 21
	ISOSessionGiveTokensAck       ISOSessionSPDUType = 22
	ISOSessionAbort               ISOSessionSPDUType = 25
	ISOSessionAbortAccept         ISOSessionSPDUType = 26
	ISOSessionActivityResume      ISOSessionSPDUType = 29
	ISOSessionTypedData           ISOSessionSPDUType = 33
	ISOSessionResyncAck           ISOSessionSPDUType = 34
	ISOSessionMajorSync           ISOSessionSPDUType = 41
	ISOSessionMajorSyncAck        ISOSessionSPDUType = 42
	ISOSessionActivityStart       ISOSessionSPDUType = 45
	ISOSessionExceptionData       ISOSessionSPDUType = 48
	ISOSessionMinorSync           ISOSessionSPDUType = 49
	ISOSessionMinorSyncAck        ISOSessionSPDUType = 50
	ISOSessionResync              ISOSessionSPDUType = 53
	ISOSessionActivityDiscard     ISOSessionSPDUType = 57
	ISOSessionActivityDiscardAck  ISOSessionSPDUType = 58
	ISOSessionCapabilityData      ISOSessionSPDUType = 61
	ISOSessionCapabilityDataAck   ISOSessionSPDUType = 62
)

// String returns the SPDU abbreviation used by ISO 8327-1.
func (t ISOSessionSPDUType) String() string {
	switch t {
	case ISOSessionDataTransfer:
		return "DT/GT"
	case ISOSessionPleaseTokens:
		return "PT"
	case ISOSessionExpedited:
		return "EX"
	case ISOSessionPrepare:
		return "PR"
	case ISOSessionNotFinished:
		return "NF"
	case ISOSessionFinish:
		return "FN"
	case ISOSessionDisconnect:
		return "DN"
	case ISOSessionRefuse:
		return "RF"
	case ISOSessionConnect:
		return "CN"
	case ISOSessionAccept:
		return "AC"
	case ISOSessionConnectDataOverflow:
		return "CDO"
	case ISOSessionOverflowAccept:
		return "OA"
	case ISOSessionGiveTokensConfirm:
		return "GTC"
	case ISOSessionGiveTokensAck:
		return "GTA"
	case ISOSessionAbort:
		return "AB"
	case ISOSessionAbortAccept:
		return "AA"
	case ISOSessionActivityResume:
		return "AR"
	case ISOSessionTypedData:
		return "TD"
	case ISOSessionResyncAck:
		return "RA"
	case ISOSessionMajorSync:
		return "MAP"
	case ISOSessionMajorSyncAck:
		return "MAA"
	case ISOSessionActivityStart:
		return "AS"
	case ISOSessionExceptionData:
		return "ED"
	case ISOSessionMinorSync:
		return "MIP"
	case ISOSessionMinorSyncAck:
		return "MIA"
	case ISOSessionResync:
		return "RS"
	case ISOSessionActivityDiscard:
		return "AD"
	case ISOSessionActivityDiscardAck:
		return "ADA"
	case ISOSessionCapabilityData:
		return "CD"
	case ISOSessionCapabilityDataAck:
		return "CDA"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(t))
	}
}

// ISOSessionParamID is a parameter (PI) or parameter group (PGI)
// identifier.
type ISOSessionParamID uint8

// ISO 8327-1 parameter and parameter group identifiers.
const (
	ISOSessionParamConnectionID     ISOSessionParamID = 1
	ISOSessionParamConnectAccept    ISOSessionParamID = 5
	ISOSessionParamCalledSSUserRef  ISOSessionParamID = 9
	ISOSessionParamCallingSSUserRef ISOSessionParamID = 10
	ISOSessionParamCommonRef        ISOSessionParamID = 11
	ISOSessionParamAdditionalRef    ISOSessionParamID = 12
	ISOSessionParamSyncType         ISOSessionParamID = 15
	ISOSessionParamTokenItem        ISOSessionParamID = 16
	ISOSessionParamTransportDisc    ISOSessionParamID = 17
	ISOSessionParamProtocolOptions  ISOSessionParamID = 19
	ISOSessionParamSessionUserReq   ISOSessionParamID = 20
	ISOSessionParamTSDUMaxSize      ISOSessionParamID = 21
	ISOSessionParamVersion          ISOSessionParamID = 22
	ISOSessionParamInitialSerial    ISOSessionParamID = 23
	ISOSessionParamPrepareType      ISOSessionParamID = 24
	ISOSessionParamEnclosure        ISOSessionParamID = 25
	ISOSessionParamTokenSetting     ISOSessionParamID = 26
	ISOSessionParamResyncType       ISOSessionParamID = 27
	ISOSessionParamLinkingInfo      ISOSessionParamID = 33
	ISOSessionParamActivityID       ISOSessionParamID = 41
	ISOSessionParamSerialNumber     ISOSessionParamID = 42
	ISOSessionParamReflect          ISOSessionParamID = 49
	ISOSessionParamReasonCode       ISOSessionParamID = 50
	ISOSessionParamCallingSelector  ISOSessionParamID = 51
	ISOSessionParamCalledSelector   ISOSessionParamID = 52
	ISOSessionParamDataOverflow     ISOSessionParamID = 60
	ISOSessionParamUserData         ISOSessionParamID = 193
	ISOSessionParamExtendedUserData ISOSessionParamID = 194
)

// String returns the parameter name.
func (id ISOSessionParamID) String() string {
	switch id {
	case ISOSessionParamConnectionID:
		return "Connection Identifier"
	case ISOSessionParamConnectAccept:
		return "Connect/Accept Item"
	case ISOSessionParamCalledSSUserRef:
		return "Called SS-user Reference"
	case ISOSessionParamCallingSSUserRef:
		return "Calling SS-user Reference"
	case ISOSessionParamCommonRef:
		return "Common Reference"
	case ISOSessionParamAdditionalRef:
		return "Additional Reference Information"
	case ISOSessionParamSyncType:
		return "Sync Type Item"
	case ISOSessionParamTokenItem:
		return "Token Item"
	case ISOSessionParamTransportDisc:
		return "Transport Disconnect"
	case ISOSessionParamProtocolOptions:
		return "Protocol Options"
	case ISOSessionParamSessionUserReq:
		return "Session User Requirements"
	case ISOSessionParamTSDUMaxSize:
		return "TSDU Maximum Size"
	case ISOSessionParamVersion:
		return "Version Number"
	case ISOSessionParamInitialSerial:
		return "Initial Serial Number"
	case ISOSessionParamPrepareType:
		return "Prepare Type"
	case ISOSessionParamEnclosure:
		return "Enclosure Item"
	case ISOSessionParamTokenSetting:
		return "Token Setting Item"
	case ISOSessionParamResyncType:
		return "Resync Type"
	case ISOSessionParamLinkingInfo:
		return "Linking Information"
	case ISOSessionParamActivityID:
		return "Activity Identifier"
	case ISOSessionParamSerialNumber:
		return "Serial Number"
	case ISOSessionParamReflect:
		return "Reflect Parameter"
	case ISOSessionParamReasonCode:
		return "Reason Code"
	case ISOSessionParamCallingSelector:
		return "Calling Session Selector"
	case ISOSessionParamCalledSelector:
		return "Called Session Selector"
	case ISOSessionParamDataOverflow:
		return "Data Overflow"
	case ISOSessionParamUserData:
		return "User Data"
	case ISOSessionParamExtendedUserData:
		return "Extended User Data"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(id))
	}
}

// isGroup reports whether id is a PGI whose value holds further PIs.
func (id ISOSessionParamID) isGroup() bool {
	switch id {
	case ISOSessionParamConnectionID, ISOSessionParamConnectAccept, ISOSessionParamLinkingInfo:
		return true
	}
	return false
}

const (
	isoSessionMinLen = 2
	// isoSessionLongLI introduces a 2 octet length indicator.
	isoSessionLongLI = 0xff
)

var (
	errISOSessionTruncated = errors.New("ISO session: SPDU truncated")
	errISOSessionGroup     = errors.New("ISO session: parameter group nested in a group")
)

// ISOSessionParam is one PI or PGI unit. Params holds the PIs of a PGI.
type ISOSessionParam struct {
	ID     ISOSessionParamID
	Value  []byte
	Params []ISOSessionParam
}

// ISOSessionSPDU is one SPDU: its identifier, length indicator and
// parameters.
type ISOSessionSPDU struct {
	Type   ISOSessionSPDUType
	Length int
	Params []ISOSessionParam
}

// Param returns the first parameter with the given id, searching inside
// parameter groups too, or nil.
func (s *ISOSessionSPDU) Param(id ISOSessionParamID) *ISOSessionParam {
	for i := range s.Params {
		p := &s.Params[i]
		if p.ID == id {
			return p
		}
		for j := range p.Params {
			if p.Params[j].ID == id {
				return &p.Params[j]
			}
		}
	}
	return nil
}

// ISOSession is an ISO 8327-1 session TSDU. SPDUs holds one SPDU, or a
// category 0 SPDU (Give or Please Tokens) followed by the SPDU it is
// concatenated with. The layer payload is the session user data: the
// User Data parameter of connection SPDUs, the bytes that follow a DT,
// or the SS-user data trailing a Refuse reason code.
type ISOSession struct {
	BaseLayer
	SPDUs []ISOSessionSPDU
}

// Type returns the type of the last (main) SPDU.
func (s *ISOSession) Type() ISOSessionSPDUType {
	if len(s.SPDUs) == 0 {
		return 0
	}
	return s.SPDUs[len(s.SPDUs)-1].Type
}

// LayerType returns LayerTypeISOSession.
func (s *ISOSession) LayerType() gopacket.LayerType { return LayerTypeISOSession }

// CanDecode returns LayerTypeISOSession.
func (s *ISOSession) CanDecode() gopacket.LayerClass { return LayerTypeISOSession }

// NextLayerType returns LayerTypeISOPresentation when there is user data.
func (s *ISOSession) NextLayerType() gopacket.LayerType {
	if len(s.Payload) == 0 {
		return gopacket.LayerTypeZero
	}
	return LayerTypeISOPresentation
}

// DecodeFromBytes decodes a session TSDU (one COTP DT user data unit).
func (s *ISOSession) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*s = ISOSession{SPDUs: s.SPDUs[:0]}

	first, rest, err := decodeISOSessionSPDU(data)
	if err != nil {
		isoSessionFeedback(err, df)
		return err
	}
	s.SPDUs = append(s.SPDUs, first)

	// A category 0 SPDU (GT, PT) must be followed by another SPDU. When the
	// next octet is no category 2 SPDU, the first one is a lone DT.
	if isoSessionCategory0(first.Type) && isoSessionCategory2(rest) {
		second, more, err := decodeISOSessionSPDU(rest)
		if err != nil {
			isoSessionFeedback(err, df)
			return err
		}
		s.SPDUs = append(s.SPDUs, second)
		rest = more
	}

	s.Contents = data[:len(data)-len(rest)]
	s.Payload = s.userData(rest)
	return nil
}

// isoSessionFeedback flags the packet truncated when an SPDU ran past
// the data.
func isoSessionFeedback(err error, df gopacket.DecodeFeedback) {
	if err == errISOSessionTruncated {
		df.SetTruncated()
	}
}

// userData picks the session user data of the main SPDU. trailing is
// what follows the SPDU in the TSDU: the user information of a DT.
func (s *ISOSession) userData(trailing []byte) []byte {
	main := &s.SPDUs[len(s.SPDUs)-1]
	switch main.Type {
	case ISOSessionDataTransfer, ISOSessionTypedData, ISOSessionExpedited,
		ISOSessionCapabilityData, ISOSessionCapabilityDataAck:
		return trailing
	}

	if p := main.Param(ISOSessionParamUserData); p != nil {
		return p.Value
	}
	if p := main.Param(ISOSessionParamExtendedUserData); p != nil {
		return p.Value
	}

	// A Refuse reason code may carry SS-user data after its first octet.
	if p := main.Param(ISOSessionParamReasonCode); main.Type == ISOSessionRefuse && p != nil && len(p.Value) > 1 {
		return p.Value[1:]
	}
	return nil
}

// isoSessionCategory0 reports whether t is a token SPDU that must be
// concatenated with a following SPDU.
func isoSessionCategory0(t ISOSessionSPDUType) bool {
	return t == ISOSessionGiveTokens || t == ISOSessionPleaseTokens
}

// isoSessionCategory2 reports whether b starts with an SPDU that may follow
// a category 0 SPDU (ISO 8327-1 table 7).
func isoSessionCategory2(b []byte) bool {
	if len(b) < isoSessionMinLen {
		return false
	}

	switch ISOSessionSPDUType(b[0]) {
	case ISOSessionDataTransfer, ISOSessionMajorSync, ISOSessionMajorSyncAck,
		ISOSessionMinorSync, ISOSessionMinorSyncAck, ISOSessionResync,
		ISOSessionResyncAck, ISOSessionActivityStart, ISOSessionActivityResume,
		ISOSessionActivityDiscard, ISOSessionActivityDiscardAck,
		ISOSessionAbort, ISOSessionAbortAccept, ISOSessionCapabilityData,
		ISOSessionCapabilityDataAck, ISOSessionExceptionData:
		return true
	}
	return false
}

// isoSessionLI reads a length indicator: one octet, or 0xff and two more.
func isoSessionLI(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, errISOSessionTruncated
	}
	if b[0] != isoSessionLongLI {
		return int(b[0]), 1, nil
	}
	if len(b) < 3 {
		return 0, 0, errISOSessionTruncated
	}
	return int(binary.BigEndian.Uint16(b[1:])), 3, nil
}

// decodeISOSessionSPDU reads SI, LI and the parameter field.
func decodeISOSessionSPDU(b []byte) (ISOSessionSPDU, []byte, error) {
	var s ISOSessionSPDU
	if len(b) < isoSessionMinLen {
		return s, nil, errISOSessionTruncated
	}
	s.Type = ISOSessionSPDUType(b[0])

	li, used, err := isoSessionLI(b[1:])
	if err != nil {
		return s, nil, err
	}
	off := 1 + used
	if li > len(b)-off {
		return s, nil, errISOSessionTruncated
	}
	s.Length = li

	s.Params, err = decodeISOSessionParams(b[off:off+li], isoSessionTop)
	return s, b[off+li:], err
}

// isoSessionLevel tells whether parameters sit in an SPDU or inside a PGI.
type isoSessionLevel uint8

const (
	isoSessionTop isoSessionLevel = iota
	isoSessionInGroup
)

// decodeISOSessionParams reads PI/PGI units until b is exhausted.
func decodeISOSessionParams(b []byte, level isoSessionLevel) ([]ISOSessionParam, error) {
	var out []ISOSessionParam
	for len(b) > 0 {
		if len(b) < isoSessionMinLen {
			return nil, errISOSessionTruncated
		}
		p := ISOSessionParam{ID: ISOSessionParamID(b[0])}

		li, used, err := isoSessionLI(b[1:])
		if err != nil {
			return nil, err
		}
		off := 1 + used
		if li > len(b)-off {
			return nil, errISOSessionTruncated
		}
		p.Value = b[off : off+li]
		b = b[off+li:]

		// A PGI holds PIs, never another PGI.
		if p.ID.isGroup() {
			if level == isoSessionInGroup {
				return nil, errISOSessionGroup
			}
			if p.Params, err = decodeISOSessionParams(p.Value, isoSessionInGroup); err != nil {
				return nil, err
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// decodeISOSession decodes the session layer and hands the user data to
// the presentation decoder, telling it which SPDU carried it so that it
// can tell CP, CPA, CPR and ARU/ARP PPDUs apart.
func decodeISOSession(data []byte, p gopacket.PacketBuilder) error {
	s := &ISOSession{}
	if err := s.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(s)

	if len(s.Payload) == 0 {
		return nil
	}
	return p.NextDecoder(isoPresDecoder{spdu: s.Type()})
}
