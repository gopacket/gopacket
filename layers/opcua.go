// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA Binary over TCP (UA TCP and UA Secure Conversation), after
// OPC 10000-6 §6.7 and §7.1.
//
//	TCP 4840
//	  └─ OPCUA (one layer per message in the segment)
//	       HEL ACK ERR RHE   connection setup, decoded in full
//	       OPN               secure channel id, asymmetric security header,
//	                         sequence header, then the service body
//	       MSG CLO           secure channel id, token id, sequence header,
//	                         then the service body
//
// A service body starts with the ExpandedNodeId of its binary encoding,
// then a request or response header. Bodies are only plaintext on a
// channel with security policy None or mode Sign; the decoder cannot know
// the mode of a MSG, so it decodes the body when it parses as a known
// service and leaves it raw otherwise.
//
// Nothing is ever decrypted. A message known to be encrypted has
// Encrypted set and its ciphertext in EncryptedData: an OPN under any
// policy but None, and what an OPCUAChunkAssembler returns for a channel
// it found to be in mode SignAndEncrypt.
//
// Null and empty are told apart where Go allows it: a null array or
// ByteString decodes to nil, an empty one to an empty slice. Strings
// decode to "" either way; OPCUA.NullStrings lists the null ones.
//
// PubSub messages (UADP, OPC 10000-14) are a layer of their own,
// OPCUAPubSub.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
)

// TCPPortOPCUA is the IANA registered OPC UA TCP port.
const TCPPortOPCUA uint16 = 4840

// OPCUASecurityPolicyNone is the URI of the policy without security, the
// one policy whose OpenSecureChannel body is plaintext.
const OPCUASecurityPolicyNone = "http://opcfoundation.org/UA/SecurityPolicy#None"

// LayerTypeOPCUA is one OPC UA Binary transport message.
var LayerTypeOPCUA = gopacket.RegisterLayerType(179, gopacket.LayerTypeMetadata{Name: "OPCUA", Decoder: gopacket.DecodeFunc(decodeOPCUA)})

// registerOPCUADecoders maps TCP port 4840 to the OPCUA layer, and UDP
// port 4840 and EtherType 0xB62C to the OPCUAPubSub layer. It is opt-in
// so callers who never asked for OPC UA keep seeing them as payload.
// Calling it more than once is harmless.
func registerOPCUADecoders() {
	RegisterTCPPortLayerType(TCPPort(TCPPortOPCUA), LayerTypeOPCUA)
	RegisterUDPPortLayerType(UDPPort(UDPPortOPCUAPubSub), LayerTypeOPCUAPubSub)
	EthernetTypeMetadata[EthernetTypeOPCUAPubSub] = EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeOPCUAPubSub),
		Name:       "OPCUAPubSub",
		LayerType:  LayerTypeOPCUAPubSub,
	}
}

// OPC UA decoding errors.
var (
	// ErrOPCUATruncated is returned when a message is shorter than its
	// header or than the size it declares.
	ErrOPCUATruncated = errors.New("OPC UA message truncated")
	// ErrOPCUAMalformed is returned for an unknown message type, a field
	// that overruns its message, or a length that breaks the encoding rules.
	ErrOPCUAMalformed = errors.New("OPC UA message malformed")
)

// Message framing (OPC 10000-6 §7.1.2).
const (
	opcuaHeaderLen       = 8 // type (3), chunk type (1), size (4)
	opcuaMessageTypeLen  = 3
	opcuaMessageTypeBits = 8
)

// OPCUAMessageType is the three-letter transport message type, packed
// big endian into the low 24 bits.
type OPCUAMessageType uint32

// OPCUAMessageType values.
const (
	OPCUAMessageHello              OPCUAMessageType = 'H'<<16 | 'E'<<8 | 'L'
	OPCUAMessageAcknowledge        OPCUAMessageType = 'A'<<16 | 'C'<<8 | 'K'
	OPCUAMessageError              OPCUAMessageType = 'E'<<16 | 'R'<<8 | 'R'
	OPCUAMessageReverseHello       OPCUAMessageType = 'R'<<16 | 'H'<<8 | 'E'
	OPCUAMessageOpenSecureChannel  OPCUAMessageType = 'O'<<16 | 'P'<<8 | 'N'
	OPCUAMessageSecure             OPCUAMessageType = 'M'<<16 | 'S'<<8 | 'G'
	OPCUAMessageCloseSecureChannel OPCUAMessageType = 'C'<<16 | 'L'<<8 | 'O'
)

// String returns the three letters of the type.
func (t OPCUAMessageType) String() string {
	b := []byte{byte(t >> 16), byte(t >> 8), byte(t)}
	return string(b)
}

// OPCUAChunkType tells a final chunk from an intermediate or aborted one.
type OPCUAChunkType uint8

// OPCUAChunkType values.
const (
	OPCUAChunkFinal        OPCUAChunkType = 'F'
	OPCUAChunkIntermediate OPCUAChunkType = 'C'
	OPCUAChunkAbort        OPCUAChunkType = 'A'
)

// String returns the chunk type letter.
func (c OPCUAChunkType) String() string { return string(rune(c)) }

// OPCUAConnectionLimits are the buffer and message limits that Hello
// proposes and Acknowledge settles (OPC 10000-6 §7.1.2.3, 7.1.2.4).
type OPCUAConnectionLimits struct {
	ProtocolVersion   uint32
	ReceiveBufferSize uint32
	SendBufferSize    uint32
	// MaxMessageSize and MaxChunkCount are 0 for no limit.
	MaxMessageSize uint32
	MaxChunkCount  uint32
}

// OPCUAHello is the body of a HEL message.
type OPCUAHello struct {
	OPCUAConnectionLimits
	EndpointURL string
}

// OPCUAError is the body of an ERR message or of an abort chunk.
type OPCUAError struct {
	Error  OPCUAStatusCode
	Reason string
}

// OPCUAReverseHello is the body of an RHE message (OPC 10000-6 §7.1.2.6).
type OPCUAReverseHello struct {
	ServerURI   string
	EndpointURL string
}

// OPCUAAsymmetricSecurityHeader opens an OPN message (OPC 10000-6 §6.7.2.3).
// The certificate and thumbprint are nil when null.
type OPCUAAsymmetricSecurityHeader struct {
	SecurityPolicyURI string
	// SenderCertificate is the DER certificate of the sender, followed
	// by those of its issuers when it sends its chain; Certificates
	// splits it.
	SenderCertificate []byte
	// ReceiverCertificateThumbprint is the SHA-1 of the DER certificate
	// the message is encrypted for, 20 bytes.
	ReceiverCertificateThumbprint []byte
}

// opcuaMaxCertChain is the count of certificates Certificates returns at
// most; a longer chain is not one a server would accept.
const opcuaMaxCertChain = 16

// DER framing of a certificate: a SEQUENCE with a definite length.
const (
	opcuaDERSequence   = 0x30
	opcuaDERLongForm   = 0x80
	opcuaDERMaxLenSize = 4
)

// Certificates splits SenderCertificate into its DER certificates: the
// sender's first, then its issuers'. It stops at the first byte that is
// not the start of a DER SEQUENCE that fits, and returns at most 16
// certificates. The slices alias SenderCertificate.
func (h OPCUAAsymmetricSecurityHeader) Certificates() [][]byte {
	var out [][]byte
	rest := h.SenderCertificate
	for len(out) < opcuaMaxCertChain {
		n := opcuaDERLen(rest)
		if n == 0 {
			break
		}
		out = append(out, rest[:n:n])
		rest = rest[n:]
	}
	return out
}

// opcuaDERLen returns the size of the DER SEQUENCE that opens b, header
// included, or 0 when b does not open with one that fits.
func opcuaDERLen(b []byte) int {
	const minLen = 2
	if len(b) < minLen || b[0] != opcuaDERSequence {
		return 0
	}

	// Short form: the length is the octet itself.
	if b[1] < opcuaDERLongForm {
		return opcuaDERFit(minLen, uint64(b[1]), len(b))
	}

	// Long form: the low bits count the length octets that follow.
	size := int(b[1] &^ opcuaDERLongForm)
	if size == 0 || size > opcuaDERMaxLenSize || len(b) < minLen+size {
		return 0
	}
	var n uint64
	for _, c := range b[minLen : minLen+size] {
		n = n<<opcuaMessageTypeBits | uint64(c)
	}
	return opcuaDERFit(minLen+size, n, len(b))
}

// opcuaDERFit returns header+n when that fits in have bytes, else 0.
func opcuaDERFit(header int, n uint64, have int) int {
	if n > uint64(have-header) {
		return 0
	}
	return header + int(n)
}

// OPCUA is one OPC UA Binary transport message. Header fields are set by
// message type: Hello, Acknowledge, Error and ReverseHello for the
// connection messages; SecureChannelID, the security header, the sequence
// header and Body for OPN, MSG and CLO.
type OPCUA struct {
	BaseLayer
	MessageType OPCUAMessageType
	ChunkType   OPCUAChunkType
	// MessageSize is the message length, header included.
	MessageSize uint32

	Hello        OPCUAHello
	Acknowledge  OPCUAConnectionLimits
	Error        OPCUAError
	ReverseHello OPCUAReverseHello

	SecureChannelID uint32
	// SecurityHeader is set by OPN; TokenID by MSG and CLO.
	SecurityHeader OPCUAAsymmetricSecurityHeader
	TokenID        uint32
	// SequenceNumber and RequestID are ciphertext on an encrypted channel.
	SequenceNumber uint32
	RequestID      uint32

	// Body is the message after the sequence header: the service, its
	// padding and signature, all encrypted on an encrypting channel.
	Body []byte
	// Service is the decoded body, nil when it was not decoded.
	Service *OPCUAService

	// Encrypted is set when the message is known to be ciphertext from
	// the sequence header on: by the decoder for an OPN under a policy
	// other than None, and by an OPCUAChunkAssembler for the MSG and CLO
	// of a channel in mode SignAndEncrypt. The decoder alone cannot know
	// the mode of a MSG and leaves it false. SequenceNumber and RequestID
	// are then ciphertext too.
	Encrypted bool
	// EncryptedData is the ciphertext of an Encrypted message: sequence
	// header, body, padding and signature, as sent. It is not decrypted.
	EncryptedData []byte

	// secured is the message from the sequence header on.
	secured []byte
}

// LayerType returns LayerTypeOPCUA.
func (o *OPCUA) LayerType() gopacket.LayerType { return LayerTypeOPCUA }

// CanDecode returns LayerTypeOPCUA.
func (o *OPCUA) CanDecode() gopacket.LayerClass { return LayerTypeOPCUA }

// NextLayerType returns LayerTypeZero. Further messages in the same
// segment are added as their own layers by the packet decoder; a
// DecodingLayerParser sees them in Payload.
func (o *OPCUA) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// DecodeFromBytes decodes the message at the start of data.
func (o *OPCUA) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	*o = OPCUA{}
	if len(data) < opcuaHeaderLen {
		df.SetTruncated()
		return ErrOPCUATruncated
	}

	for _, c := range data[:opcuaMessageTypeLen] {
		o.MessageType = o.MessageType<<opcuaMessageTypeBits | OPCUAMessageType(c)
	}
	o.ChunkType = OPCUAChunkType(data[opcuaMessageTypeLen])
	o.MessageSize = binary.LittleEndian.Uint32(data[opcuaMessageTypeLen+1:])

	if o.MessageSize < opcuaHeaderLen {
		return ErrOPCUAMalformed
	}
	if uint64(o.MessageSize) > uint64(len(data)) {
		df.SetTruncated()
		return ErrOPCUATruncated
	}
	msg := data[:o.MessageSize]
	o.Contents = msg
	o.Payload = data[o.MessageSize:]

	// The message size bounds every field: one that overruns it is
	// malformed rather than truncated.
	r := &opcuaReader{b: msg, off: opcuaHeaderLen}
	if err := o.decodeMessage(r); err != nil {
		return err
	}
	if r.err != nil {
		return ErrOPCUAMalformed
	}
	return nil
}

// decodeMessage reads the fields that follow the header.
func (o *OPCUA) decodeMessage(r *opcuaReader) error {
	switch o.MessageType {
	case OPCUAMessageHello:
		o.Hello.OPCUAConnectionLimits = r.limits()
		o.Hello.EndpointURL = r.str()

	case OPCUAMessageAcknowledge:
		o.Acknowledge = r.limits()

	case OPCUAMessageError:
		o.Error = OPCUAError{Error: OPCUAStatusCode(r.u32()), Reason: r.str()}

	case OPCUAMessageReverseHello:
		o.ReverseHello = OPCUAReverseHello{ServerURI: r.str(), EndpointURL: r.str()}

	case OPCUAMessageOpenSecureChannel:
		o.SecureChannelID = r.u32()
		o.SecurityHeader = OPCUAAsymmetricSecurityHeader{
			SecurityPolicyURI:             r.str(),
			SenderCertificate:             r.byteString(),
			ReceiverCertificateThumbprint: r.byteString(),
		}
		o.decodeSequence(r)

	case OPCUAMessageSecure, OPCUAMessageCloseSecureChannel:
		o.SecureChannelID = r.u32()
		o.TokenID = r.u32()
		o.decodeSequence(r)

	default:
		return ErrOPCUAMalformed
	}
	return nil
}

// limits reads the five uint32 of Hello and Acknowledge.
func (r *opcuaReader) limits() OPCUAConnectionLimits {
	return OPCUAConnectionLimits{
		ProtocolVersion:   r.u32(),
		ReceiveBufferSize: r.u32(),
		SendBufferSize:    r.u32(),
		MaxMessageSize:    r.u32(),
		MaxChunkCount:     r.u32(),
	}
}

// decodeSequence reads the sequence header, keeps the body and decodes
// it when it can be plaintext.
func (o *OPCUA) decodeSequence(r *opcuaReader) {
	if r.err != nil {
		return
	}
	o.secured = r.b[r.off:]

	// An OPN is encrypted from here on under any policy but None.
	if o.MessageType == OPCUAMessageOpenSecureChannel && o.SecurityHeader.SecurityPolicyURI != OPCUASecurityPolicyNone {
		o.Encrypted, o.EncryptedData = true, o.secured
	}

	o.SequenceNumber = r.u32()
	o.RequestID = r.u32()
	if r.err != nil {
		return
	}
	o.Body = r.b[r.off:]

	// An abort chunk replaces the body with the reason (§6.7.3).
	if o.ChunkType == OPCUAChunkAbort {
		br := &opcuaReader{b: o.Body}
		o.Error = OPCUAError{Error: OPCUAStatusCode(br.u32()), Reason: br.str()}
		return
	}

	if o.Encrypted {
		return
	}
	o.Service = decodeOPCUAService(o.Body)
}

// NullStrings tells the null Strings of the message from the empty
// ones, which both decode to "". It returns the offset of the length of
// every null String: those of the transport header (EndpointURL, Reason,
// SecurityPolicyURI and the like) as offsets into LayerContents, those
// of the decoded Service, the ExtensionObjects with a Value included,
// as offsets into Body. A String of the service that is not listed is
// not null. The message is walked again on every call.
func (o *OPCUA) NullStrings() (header, body []int) {
	r := &opcuaReader{b: o.Contents, off: opcuaHeaderLen, mode: opcuaReadProbe, nulls: &header}
	if len(o.Contents) < opcuaHeaderLen {
		return nil, nil
	}

	switch o.MessageType {
	case OPCUAMessageHello:
		r.limits()
		r.str()
	case OPCUAMessageError:
		r.u32()
		r.str()
	case OPCUAMessageReverseHello:
		r.str()
		r.str()
	case OPCUAMessageOpenSecureChannel:
		r.u32()
		r.str()
	}

	// The reason of an abort chunk stands in for the body.
	if o.ChunkType == OPCUAChunkAbort && !o.Encrypted {
		br := &opcuaReader{b: o.Body, mode: opcuaReadProbe, nulls: &body}
		br.u32()
		br.str()
		return header, body
	}
	if o.Service == nil {
		return header, nil
	}

	br := &opcuaReader{b: o.Body, mode: opcuaReadProbe, nulls: &body}
	s := &OPCUAService{}
	if !s.decodeHeader(br) {
		return header, nil
	}

	// Parameters that do not parse stay raw in Params: no Strings.
	mark := len(body)
	s.decodeParams(br)
	if br.err != nil {
		body = body[:mark]
	}
	return header, body
}

// ServiceNodeID returns the type NodeId that opens the body of an OPN, MSG
// or CLO message, the binary encoding id of its service. It fails when the
// body is too short, or encrypted into something that is not a NodeId.
func (o *OPCUA) ServiceNodeID() (OPCUANodeID, error) {
	if o.Service != nil {
		return o.Service.TypeID, nil
	}
	r := &opcuaReader{b: o.Body}
	n := r.expandedNodeID()
	return n, r.err
}

func decodeOPCUA(data []byte, p gopacket.PacketBuilder) error {
	// A segment may carry several messages back to back. Each gets its own
	// layer, in a loop rather than through NextDecoder so a large segment
	// does not cost a stack frame per message.
	ua := &OPCUA{}
	if err := ua.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(ua)

	// A message cut short by segmentation stays the previous layer's
	// payload: it is not an error, so its decode feedback goes nowhere.
	for len(ua.Payload) > 0 {
		next := &OPCUA{}
		if err := next.DecodeFromBytes(ua.Payload, gopacket.NilDecodeFeedback); err != nil {
			break
		}
		p.AddLayer(next)
		ua = next
	}
	return nil
}

// OPCUAMessageSecurityMode is a MessageSecurityMode (OPC 10000-4 §7.20).
type OPCUAMessageSecurityMode uint32

// OPCUAMessageSecurityMode values.
const (
	OPCUASecurityModeInvalid        OPCUAMessageSecurityMode = 0
	OPCUASecurityModeNone           OPCUAMessageSecurityMode = 1
	OPCUASecurityModeSign           OPCUAMessageSecurityMode = 2
	OPCUASecurityModeSignAndEncrypt OPCUAMessageSecurityMode = 3
)

var opcuaSecurityModeNames = map[OPCUAMessageSecurityMode]string{
	OPCUASecurityModeInvalid:        "Invalid",
	OPCUASecurityModeNone:           "None",
	OPCUASecurityModeSign:           "Sign",
	OPCUASecurityModeSignAndEncrypt: "SignAndEncrypt",
}

// String returns the mode name.
func (m OPCUAMessageSecurityMode) String() string { return opcuaName(opcuaSecurityModeNames, m) }

// OPCUASecurityTokenRequestType asks for a new token or a renewal.
type OPCUASecurityTokenRequestType uint32

// OPCUASecurityTokenRequestType values.
const (
	OPCUASecurityTokenIssue OPCUASecurityTokenRequestType = 0
	OPCUASecurityTokenRenew OPCUASecurityTokenRequestType = 1
)

// String returns the request type name.
func (t OPCUASecurityTokenRequestType) String() string {
	switch t {
	case OPCUASecurityTokenIssue:
		return "Issue"
	case OPCUASecurityTokenRenew:
		return "Renew"
	}
	return fmt.Sprintf("Unknown(%d)", uint32(t))
}

// String returns the service message name, such as "ReadRequest".
func (s OPCUAServiceID) String() string { return opcuaName(opcuaServiceNames, s) }

// IsRequest reports whether the message is a service request, which opens
// with a RequestHeader; responses and ServiceFault open with a
// ResponseHeader.
func (s OPCUAServiceID) IsRequest() bool {
	return strings.HasSuffix(opcuaServiceNames[s], "Request")
}

// OPCUARequestHeader opens every service request (OPC 10000-4 §7.33).
type OPCUARequestHeader struct {
	AuthenticationToken OPCUANodeID
	Timestamp           time.Time
	RequestHandle       uint32
	ReturnDiagnostics   uint32
	AuditEntryID        string
	// TimeoutHint is in milliseconds; 0 is none.
	TimeoutHint      uint32
	AdditionalHeader OPCUAExtensionObject
}

// OPCUAResponseHeader opens every service response (OPC 10000-4 §7.34).
type OPCUAResponseHeader struct {
	Timestamp          time.Time
	RequestHandle      uint32
	ServiceResult      OPCUAStatusCode
	ServiceDiagnostics OPCUADiagnosticInfo
	StringTable        []string
	AdditionalHeader   OPCUAExtensionObject
}

// opcuaName looks v up in a name table, falling back to its number.
func opcuaName[K ~uint8 | ~uint16 | ~uint32](names map[K]string, v K) string {
	if n, ok := names[v]; ok {
		return n
	}
	return fmt.Sprintf("Unknown(%d)", uint32(v))
}
