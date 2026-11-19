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
	"strings"

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
	// isoSessionMaxSPDUs caps the SPDUs of one TSDU; the sequences ISO
	// 8327-1 allows are shorter.
	isoSessionMaxSPDUs = 8
	// Lengths of the Session User Requirements and TSDU Maximum Size
	// parameters.
	isoSessionReqLen  = 2
	isoSessionTSDULen = 4
	// isoSessionLongLI introduces a 2 octet length indicator.
	isoSessionLongLI = 0xff
)

var (
	errISOSessionTruncated = errors.New("ISO session: SPDU truncated")
	errISOSessionGroup     = errors.New("ISO session: parameter group nested in a group")
)

// ISOSessionFlaws flags what is wrong with a TSDU that still decodes.
type ISOSessionFlaws uint8

// Flaws of a session TSDU.
const (
	// ISOSessionLengthOverrun: the length indicator of an SPDU runs past
	// the TSDU, yet the octets present are whole parameters. The SPDU is
	// decoded from those; ISOSessionSPDU.Length keeps the indicator.
	ISOSessionLengthOverrun ISOSessionFlaws = 1 << iota
	// ISOSessionBadConcat: what follows the concatenated SPDUs starts
	// like another one and does not decode. It is left undecoded.
	ISOSessionBadConcat
	// ISOSessionTooManySPDUs: more SPDUs are concatenated than the
	// decoder reads. The others are left undecoded.
	ISOSessionTooManySPDUs
)

// String lists the flaws, e.g. "length-overrun|bad-concatenation".
func (f ISOSessionFlaws) String() string {
	if f == 0 {
		return "none"
	}

	var parts []string
	for i, name := range isoSessionFlawNames {
		if f&(1<<uint(i)) != 0 {
			parts = append(parts, name)
		}
	}

	// Bits without a name.
	if rest := f &^ (1<<uint(len(isoSessionFlawNames)) - 1); rest != 0 {
		parts = append(parts, fmt.Sprintf("Unknown(%#x)", uint8(rest)))
	}
	return strings.Join(parts, "|")
}

// isoSessionFlawNames is indexed by flaw bit.
var isoSessionFlawNames = [...]string{"length-overrun", "bad-concatenation", "too-many-spdus"}

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

// ISOSessionOptions is the Protocol Options parameter.
type ISOSessionOptions uint8

// ISOSessionExtendedConcat tells the sender can receive extended
// concatenated SPDUs.
const ISOSessionExtendedConcat ISOSessionOptions = 0x01

// ISOSessionRequirements is the Session User Requirements parameter: the
// functional units proposed or selected.
type ISOSessionRequirements uint16

// ISO 8327-1 functional units.
const (
	ISOSessionFUHalfDuplex        ISOSessionRequirements = 1 << 0
	ISOSessionFUDuplex            ISOSessionRequirements = 1 << 1
	ISOSessionFUExpedited         ISOSessionRequirements = 1 << 2
	ISOSessionFUMinorSync         ISOSessionRequirements = 1 << 3
	ISOSessionFUMajorSync         ISOSessionRequirements = 1 << 4
	ISOSessionFUResync            ISOSessionRequirements = 1 << 5
	ISOSessionFUActivity          ISOSessionRequirements = 1 << 6
	ISOSessionFUNegotiatedRelease ISOSessionRequirements = 1 << 7
	ISOSessionFUCapabilityData    ISOSessionRequirements = 1 << 8
	ISOSessionFUExceptions        ISOSessionRequirements = 1 << 9
	ISOSessionFUTypedData         ISOSessionRequirements = 1 << 10
	ISOSessionFUSymmetricSync     ISOSessionRequirements = 1 << 11
	ISOSessionFUDataSeparation    ISOSessionRequirements = 1 << 12
)

// ISOSessionVersions is the Version Number parameter: a bit per protocol
// version supported.
type ISOSessionVersions uint8

// ISO 8327-1 protocol versions.
const (
	ISOSessionVersion1 ISOSessionVersions = 0x01
	ISOSessionVersion2 ISOSessionVersions = 0x02
)

// ISOSessionEnclosure is the Enclosure Item parameter of a segmented
// SSDU.
type ISOSessionEnclosure uint8

// Enclosure Item bits.
const (
	ISOSessionEnclosureBegin ISOSessionEnclosure = 0x01
	ISOSessionEnclosureEnd   ISOSessionEnclosure = 0x02
)

// ISOSessionTransportDisc is the Transport Disconnect parameter.
type ISOSessionTransportDisc uint8

// Transport Disconnect bits. The reason bits are only set in an Abort.
const (
	ISOSessionTransportReleased ISOSessionTransportDisc = 0x01
	ISOSessionUserAbort         ISOSessionTransportDisc = 0x02
	ISOSessionProtocolError     ISOSessionTransportDisc = 0x04
	ISOSessionNoReason          ISOSessionTransportDisc = 0x08
	ISOSessionImplRestriction   ISOSessionTransportDisc = 0x10
)

// octet returns the value of the one octet parameter id.
func (s *ISOSessionSPDU) octet(id ISOSessionParamID) (uint8, bool) {
	p := s.Param(id)
	if p == nil || len(p.Value) != 1 {
		return 0, false
	}
	return p.Value[0], true
}

// ProtocolOptions returns the Protocol Options parameter; ok is false
// when it is absent or malformed, as for the accessors below.
func (s *ISOSessionSPDU) ProtocolOptions() (opts ISOSessionOptions, ok bool) {
	v, ok := s.octet(ISOSessionParamProtocolOptions)
	return ISOSessionOptions(v), ok
}

// Versions returns the Version Number parameter.
func (s *ISOSessionSPDU) Versions() (v ISOSessionVersions, ok bool) {
	b, ok := s.octet(ISOSessionParamVersion)
	return ISOSessionVersions(b), ok
}

// Requirements returns the Session User Requirements parameter.
func (s *ISOSessionSPDU) Requirements() (r ISOSessionRequirements, ok bool) {
	p := s.Param(ISOSessionParamSessionUserReq)
	if p == nil || len(p.Value) != isoSessionReqLen {
		return 0, false
	}
	return ISOSessionRequirements(binary.BigEndian.Uint16(p.Value)), true
}

// Enclosure returns the Enclosure Item parameter.
func (s *ISOSessionSPDU) Enclosure() (e ISOSessionEnclosure, ok bool) {
	b, ok := s.octet(ISOSessionParamEnclosure)
	return ISOSessionEnclosure(b), ok
}

// TransportDisconnect returns the Transport Disconnect parameter.
func (s *ISOSessionSPDU) TransportDisconnect() (d ISOSessionTransportDisc, ok bool) {
	b, ok := s.octet(ISOSessionParamTransportDisc)
	return ISOSessionTransportDisc(b), ok
}

// TokenItem returns the Token Item parameter: two bits per token (data,
// synchronize-minor, major/activity, release from the least significant
// pair up).
func (s *ISOSessionSPDU) TokenItem() (tokens uint8, ok bool) {
	return s.octet(ISOSessionParamTokenItem)
}

// TokenSetting returns the Token Setting Item parameter, laid out as the
// Token Item.
func (s *ISOSessionSPDU) TokenSetting() (tokens uint8, ok bool) {
	return s.octet(ISOSessionParamTokenSetting)
}

// ReasonCode returns the first octet of the Reason Code parameter of a
// Refuse SPDU, e.g. 2 for a rejection by the called SS-user with user
// data.
func (s *ISOSessionSPDU) ReasonCode() (code uint8, ok bool) {
	p := s.Param(ISOSessionParamReasonCode)
	if p == nil || len(p.Value) == 0 {
		return 0, false
	}
	return p.Value[0], true
}

// MaxTSDUSize returns the TSDU Maximum Size parameter: the largest TSDU
// from the initiator to the responder and back, 0 for no limit.
func (s *ISOSessionSPDU) MaxTSDUSize() (toResponder, toInitiator uint16, ok bool) {
	p := s.Param(ISOSessionParamTSDUMaxSize)
	if p == nil || len(p.Value) != isoSessionTSDULen {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(p.Value), binary.BigEndian.Uint16(p.Value[isoSessionReqLen:]), true
}

// CallingSelector returns the Calling Session Selector, nil when absent.
func (s *ISOSessionSPDU) CallingSelector() []byte {
	return s.value(ISOSessionParamCallingSelector)
}

// CalledSelector returns the Called (or Responding) Session Selector,
// nil when absent.
func (s *ISOSessionSPDU) CalledSelector() []byte {
	return s.value(ISOSessionParamCalledSelector)
}

// SerialNumber returns the digits of the Serial Number parameter of a
// synchronization SPDU, e.g. "42", or "" when absent.
func (s *ISOSessionSPDU) SerialNumber() string {
	return string(s.value(ISOSessionParamSerialNumber))
}

// value returns the value of parameter id, nil when absent.
func (s *ISOSessionSPDU) value(id ISOSessionParamID) []byte {
	p := s.Param(id)
	if p == nil {
		return nil
	}
	return p.Value
}

// ISOSession is an ISO 8327-1 session TSDU. SPDUs holds one SPDU, or a
// category 0 SPDU (Give or Please Tokens) followed by the SPDU it is
// concatenated with. Extended concatenation puts several category 2
// SPDUs after it, e.g. GT, MIP and DT; all are listed, the last one
// being the main SPDU. The layer payload is the session user data: the
// User Data parameter of connection SPDUs, the bytes that follow a DT,
// or the SS-user data trailing a Refuse reason code.
//
// Flaws tells what was tolerated to decode the TSDU. No flaw is an error:
// the layers above still get the user data found.
type ISOSession struct {
	BaseLayer
	SPDUs []ISOSessionSPDU
	Flaws ISOSessionFlaws
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

	first, rest, err := s.decodeSPDU(data, df)
	if err != nil {
		isoSessionFeedback(err, df)
		return err
	}
	s.SPDUs = append(s.SPDUs, first)

	// A category 0 SPDU (GT, PT) must be followed by another SPDU. When the
	// next octet is no category 2 SPDU, the first one is a lone DT.
	if isoSessionCategory0(first.Type) && isoSessionCategory2(rest) {
		second, more, err := s.decodeSPDU(rest, df)
		if err != nil {
			isoSessionFeedback(err, df)
			return err
		}
		s.SPDUs = append(s.SPDUs, second)
		rest = s.decodeExtended(more, df)
	}

	s.Contents = data[:len(data)-len(rest)]
	s.Payload = s.userData(rest)
	return nil
}

// decodeSPDU reads one SPDU and records a tolerated length overrun: the
// data then ends before the SPDU does, so the packet is flagged truncated.
func (s *ISOSession) decodeSPDU(b []byte, df gopacket.DecodeFeedback) (ISOSessionSPDU, []byte, error) {
	spdu, rest, fit, err := decodeISOSessionSPDU(b)
	if err == nil && fit == isoSessionClamped {
		s.Flaws |= ISOSessionLengthOverrun
		df.SetTruncated()
	}
	return spdu, rest, err
}

// decodeExtended adds the category 2 SPDUs extended concatenation puts
// after the second one and returns what follows them. An SPDU with a
// user information field ends the TSDU. What does not decode, or comes
// after isoSessionMaxSPDUs SPDUs, is left alone and flagged.
func (s *ISOSession) decodeExtended(rest []byte, df gopacket.DecodeFeedback) []byte {
	for {
		last := s.SPDUs[len(s.SPDUs)-1].Type
		if isoSessionHasUserInfo(last) || !isoSessionCategory2(rest) {
			return rest
		}
		if len(s.SPDUs) >= isoSessionMaxSPDUs {
			s.Flaws |= ISOSessionTooManySPDUs
			return rest
		}

		// A failed SPDU must not leave its own flaw behind.
		flaws := s.Flaws
		next, more, err := s.decodeSPDU(rest, df)
		if err != nil {
			s.Flaws = flaws | ISOSessionBadConcat
			return rest
		}
		s.SPDUs = append(s.SPDUs, next)
		rest = more
	}
}

// isoSessionHasUserInfo reports whether the SPDU carries its user data
// after its parameters, up to the end of the TSDU.
func isoSessionHasUserInfo(t ISOSessionSPDUType) bool {
	switch t {
	case ISOSessionDataTransfer, ISOSessionTypedData, ISOSessionExpedited,
		ISOSessionCapabilityData, ISOSessionCapabilityDataAck:
		return true
	}
	return false
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
	if isoSessionHasUserInfo(main.Type) {
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

// isoSessionFit tells whether an SPDU fits the data that holds it.
type isoSessionFit uint8

const (
	isoSessionWhole isoSessionFit = iota
	// isoSessionClamped: the length indicator overran the data and the
	// parameter field was cut to what is there.
	isoSessionClamped
)

// decodeISOSessionSPDU reads SI, LI and the parameter field.
//
// A length indicator past the end of the data is tolerated when the
// octets present are whole PI units, as in an AC SPDU seen on the wire
// whose LI is one too many: 0e 89 followed by 136 octets of parameters.
// ISO 8327-1 8.2 does not allow it: the LI is the length of the parameter
// field. A truncated capture, cut inside a parameter, still fails.
func decodeISOSessionSPDU(b []byte) (ISOSessionSPDU, []byte, isoSessionFit, error) {
	var s ISOSessionSPDU
	if len(b) < isoSessionMinLen {
		return s, nil, isoSessionWhole, errISOSessionTruncated
	}
	s.Type = ISOSessionSPDUType(b[0])

	li, used, err := isoSessionLI(b[1:])
	if err != nil {
		return s, nil, isoSessionWhole, err
	}
	off := 1 + used
	s.Length = li

	fit := isoSessionWhole
	if li > len(b)-off {
		// Without a single parameter there is nothing to go by.
		if len(b) == off {
			return s, nil, fit, errISOSessionTruncated
		}
		fit = isoSessionClamped
		li = len(b) - off
	}

	s.Params, err = decodeISOSessionParams(b[off:off+li], isoSessionTop)
	return s, b[off+li:], fit, err
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
