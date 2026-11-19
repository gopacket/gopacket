// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// Reassembly of OPC UA messages sent in several chunks (OPC 10000-6
// §6.7.2).
//
//	MSG C  req 7 ─┐
//	MSG C  req 7 ─┼─ bodies joined ─► MSG F req 7, Service decoded
//	MSG F  req 7 ─┘
//	MSG A  req 7 ───► the chunks of request 7 are dropped
//
// Every chunk of a channel carries the next sequence number, whatever
// its request, so a hole in the numbers is a lost chunk:
//
//	MSG C seq 51 ─┐
//	MSG C seq 53 ─┼─ 52 is missing ─► ErrOPCUAChunkLost on the final chunk
//	MSG F seq 54 ─┘

package layers

import (
	"errors"
	"math"
)

// Chunk reassembly limits.
const (
	// OPCUADefaultMaxMessageSize is the joined body size an
	// OPCUAChunkAssembler accepts when MaxMessageSize is 0.
	OPCUADefaultMaxMessageSize = 4 << 20
	// OPCUADefaultMaxPending is the count of unfinished messages an
	// OPCUAChunkAssembler keeps when MaxPending is 0.
	OPCUADefaultMaxPending = 8
)

// Sequence numbers wrap before the end of their range: after a number
// above the limit the next one is below the restart bound (OPC 10000-6
// §6.7.2.4).
const (
	opcuaSeqWrapLimit = math.MaxUint32 - 1024
	opcuaSeqRestart   = 1024
)

// Chunk reassembly errors.
var (
	// ErrOPCUAMessageTooLarge is returned for a chunk that takes its
	// message past the size limit of the assembler.
	ErrOPCUAMessageTooLarge = errors.New("OPC UA chunked message too large")
	// ErrOPCUAChunkLost is returned for the final chunk of a message that
	// lost a chunk, by the sequence numbers.
	ErrOPCUAChunkLost = errors.New("OPC UA chunk lost")
)

// Security policy URIs of OPC 10000-7, beside OPCUASecurityPolicyNone.
const (
	OPCUASecurityPolicyBasic128Rsa15   = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
	OPCUASecurityPolicyBasic256        = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
	OPCUASecurityPolicyBasic256Sha256  = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
	OPCUASecurityPolicyAes128Sha256Oae = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
	OPCUASecurityPolicyAes256Sha256Pss = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"
	OPCUASecurityPolicyECCNistP256     = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256"
	OPCUASecurityPolicyECCNistP384     = "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384"
	OPCUASecurityPolicyECCBrainpool256 = "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1"
	OPCUASecurityPolicyECCBrainpool384 = "http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1"
	OPCUASecurityPolicyECCCurve25519   = "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519"
	OPCUASecurityPolicyECCCurve448     = "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448"
)

// Sizes of the symmetric signatures of the standard policies.
const (
	opcuaSigHMACSHA1   = 20
	opcuaSigHMACSHA256 = 32
	opcuaSigHMACSHA384 = 48
	opcuaSigPoly1305   = 16
)

// opcuaSignatureSizes is the size of the symmetric signature that ends
// every MSG and CLO chunk, by security policy (OPC 10000-7 §6.6:
// SymmetricSignatureAlgorithm).
var opcuaSignatureSizes = map[string]int{
	OPCUASecurityPolicyNone:            0,
	OPCUASecurityPolicyBasic128Rsa15:   opcuaSigHMACSHA1,
	OPCUASecurityPolicyBasic256:        opcuaSigHMACSHA1,
	OPCUASecurityPolicyBasic256Sha256:  opcuaSigHMACSHA256,
	OPCUASecurityPolicyAes128Sha256Oae: opcuaSigHMACSHA256,
	OPCUASecurityPolicyAes256Sha256Pss: opcuaSigHMACSHA256,
	OPCUASecurityPolicyECCNistP256:     opcuaSigHMACSHA256,
	OPCUASecurityPolicyECCNistP384:     opcuaSigHMACSHA384,
	OPCUASecurityPolicyECCBrainpool256: opcuaSigHMACSHA256,
	OPCUASecurityPolicyECCBrainpool384: opcuaSigHMACSHA384,
	OPCUASecurityPolicyECCCurve25519:   opcuaSigPoly1305,
	OPCUASecurityPolicyECCCurve448:     opcuaSigPoly1305,
}

// OPCUASignatureSize returns the size in bytes of the symmetric
// signature that ends the chunks of a channel with the given security
// policy, and whether the policy is one of the standard ones.
func OPCUASignatureSize(policyURI string) (int, bool) {
	n, ok := opcuaSignatureSizes[policyURI]
	return n, ok
}

// opcuaChannelMode is what an assembler knows of the security mode of
// its channel.
type opcuaChannelMode uint8

const (
	// opcuaChannelUnknown: no OPN seen, or no MSG since. Chunks are
	// taken as plaintext.
	opcuaChannelUnknown opcuaChannelMode = iota
	// opcuaChannelPlain: policy None, or mode Sign.
	opcuaChannelPlain
	// opcuaChannelEncrypted: mode SignAndEncrypt.
	opcuaChannelEncrypted
)

// opcuaChunkKey names one message in flight on a connection.
type opcuaChunkKey struct {
	messageType     OPCUAMessageType
	secureChannelID uint32
	requestID       uint32
}

// opcuaChunkBuffer is the body of an unfinished message.
type opcuaChunkBuffer struct {
	body []byte
	// started orders the buffers by age.
	started uint64
	// tooLarge marks a message that passed the limit: its body is gone
	// and its later chunks are refused.
	tooLarge bool
	// lost marks a message with a chunk missing: its body is gone and
	// its final chunk reports the loss.
	lost bool
}

// OPCUAChunkAssembler joins the chunks of long messages. It serves one
// direction of one connection: feed Add the OPN, MSG and CLO layers of
// that direction in the order they were sent, after TCP reassembly.
// Chunks are matched by message type, SecureChannelID and RequestID.
//
// Memory is bounded by MaxPending bodies of MaxMessageSize bytes. A
// joined body is then decoded like any other, which can take up to 130
// times its size (an array of empty DataValues, 1 byte each on the
// wire), so MaxMessageSize also bounds that.
//
// Only plaintext joins, and nothing is decrypted. The assembler learns
// the security policy from the OPN it is fed:
//
//   - Policy None: chunks are plaintext without signature.
//   - Any other policy: the mode is Sign or SignAndEncrypt, which the
//     OPN does not show. The first MSG after it decides: a body that
//     opens with the type id of a known service is plaintext with a
//     signature at its end, sized by the policy (OPCUASignatureSize);
//     anything else is ciphertext. The MSG and CLO of an encrypted channel are returned
//     one by one, unjoined, as copies with Encrypted set and
//     EncryptedData holding the ciphertext.
//   - No OPN seen: chunks are taken as plaintext, with SignatureSize
//     bytes of signature.
//
// A lost chunk shows as a hole in the sequence numbers of the plaintext
// chunks. The numbers do not say which message lost it, so every
// message then pending is dropped: its final chunk returns
// ErrOPCUAChunkLost. Lost counts the holes.
//
// The zero value is ready to use. An assembler is not safe for
// concurrent use.
type OPCUAChunkAssembler struct {
	// MaxMessageSize is the largest joined body, in bytes; 0 means
	// OPCUADefaultMaxMessageSize.
	MaxMessageSize int
	// MaxPending is the count of unfinished messages kept; 0 means
	// OPCUADefaultMaxPending. One more evicts the oldest.
	MaxPending int
	// SignatureSize is the count of bytes at the end of every chunk body
	// that are a signature rather than message. 0 derives it from the
	// security policy of the OPN seen, and is no signature when none
	// was; any other value overrides the policy.
	SignatureSize int

	pending map[opcuaChunkKey]*opcuaChunkBuffer
	clock   uint64

	// policy is the SecurityPolicyURI of the last OPN, when sawOPN.
	policy string
	sawOPN bool
	mode   opcuaChannelMode

	// lastSeq is the sequence number of the last plaintext chunk, when
	// haveSeq.
	lastSeq uint32
	haveSeq bool
	lost    int
}

// Add takes the next layer and returns the message it completes.
//
//   - A final chunk with nothing pending is a whole message: it is
//     returned as it is.
//
//   - An intermediate chunk is copied and kept; Add returns nil.
//
//   - A final chunk that ends a pending message returns a copy of it
//     whose Body is the joined body and whose Service is decoded from
//     it. The other fields, MessageSize and SequenceNumber among them,
//     are those of the final chunk.
//
//   - An abort chunk drops the pending message and is returned as it is;
//     its Error tells why the sender gave up.
//
//   - HEL, ACK, ERR and RHE are never chunked and are returned as they
//     are.
//
//   - An encrypted message, an OPN under a policy other than None or
//     any MSG or CLO of a channel in mode SignAndEncrypt, is returned at
//     once with Encrypted set, whatever its chunk type.
//
// ErrOPCUAMessageTooLarge is returned for the chunk that passes
// MaxMessageSize and for every later chunk of that message, which is
// dropped. ErrOPCUAChunkLost is returned for the final chunk of a
// message that lost a chunk. ErrOPCUAMalformed is returned for an
// unknown chunk type and for a chunk shorter than its signature.
func (a *OPCUAChunkAssembler) Add(ua *OPCUA) (*OPCUA, error) {
	if ua == nil {
		return nil, nil
	}
	switch ua.MessageType {
	case OPCUAMessageOpenSecureChannel:
		a.policy, a.sawOPN, a.mode = ua.SecurityHeader.SecurityPolicyURI, true, opcuaChannelUnknown
	case OPCUAMessageSecure, OPCUAMessageCloseSecureChannel:
	default:
		return ua, nil
	}

	if a.encrypted(ua) {
		return opcuaCiphertext(ua), nil
	}
	gap := a.sequenceGap(ua.SequenceNumber)

	key := opcuaChunkKey{ua.MessageType, ua.SecureChannelID, ua.RequestID}
	buf := a.pending[key]

	// A chunk right after a hole that neither continues a pending
	// message nor opens one is what is left of a message whose start
	// was lost.
	orphan := gap && buf == nil && !opcuaOpensService(ua)

	switch ua.ChunkType {
	case OPCUAChunkAbort:
		delete(a.pending, key)
		return ua, nil

	case OPCUAChunkIntermediate:
		if buf == nil {
			buf = a.open(key)
			buf.lost = orphan
		}
		return nil, a.extend(buf, ua.Body)

	case OPCUAChunkFinal:
		if orphan {
			return nil, ErrOPCUAChunkLost
		}
		if buf == nil {
			return ua, nil
		}
		delete(a.pending, key)
		if err := a.extend(buf, ua.Body); err != nil {
			return nil, err
		}
		if buf.lost {
			return nil, ErrOPCUAChunkLost
		}
		return joinOPCUAChunks(ua, buf.body), nil
	}
	return nil, ErrOPCUAMalformed
}

// Pending returns the count of unfinished messages.
func (a *OPCUAChunkAssembler) Pending() int { return len(a.pending) }

// Lost returns the count of holes seen in the sequence numbers, each one
// or more lost chunks.
func (a *OPCUAChunkAssembler) Lost() int { return a.lost }

// SecurityPolicyURI returns the policy of the last OPN fed to Add, and
// whether there was one.
func (a *OPCUAChunkAssembler) SecurityPolicyURI() (string, bool) { return a.policy, a.sawOPN }

// signatureSize returns the count of signature bytes that end a chunk
// body: the caller's when set, else that of the policy seen.
func (a *OPCUAChunkAssembler) signatureSize() int {
	if a.SignatureSize != 0 || !a.sawOPN {
		return a.SignatureSize
	}
	return opcuaSignatureSizes[a.policy]
}

// encrypted reports whether ua is ciphertext, settling the mode of the
// channel on the first MSG or CLO after an OPN.
//
//	OPN policy None ──────────────────────────► plain
//	OPN other policy ─ next MSG ─┬─ known service ─► plain (mode Sign)
//	                             └─ anything else ─► encrypted
func (a *OPCUAChunkAssembler) encrypted(ua *OPCUA) bool {
	if ua.MessageType == OPCUAMessageOpenSecureChannel {
		return ua.Encrypted
	}
	if !a.sawOPN || a.mode != opcuaChannelUnknown {
		return a.mode == opcuaChannelEncrypted
	}

	a.mode = opcuaChannelPlain
	if a.policy == OPCUASecurityPolicyNone {
		return false
	}

	// An abort carries no service; it does not settle the mode.
	if ua.ChunkType == OPCUAChunkAbort {
		a.mode = opcuaChannelUnknown
		return false
	}
	if !opcuaOpensService(ua) {
		a.mode = opcuaChannelEncrypted
	}
	return a.mode == opcuaChannelEncrypted
}

// opcuaOpensService reports whether the body of ua opens with the type
// id of a known service, as the first chunk of a plaintext message
// does. Ciphertext passes about once in twenty million.
func opcuaOpensService(ua *OPCUA) bool {
	id, err := ua.ServiceNodeID()
	s := OPCUAService{TypeID: id}
	return err == nil && s.knownType()
}

// opcuaCiphertext returns ua marked as encrypted, a copy unless it
// already is.
func opcuaCiphertext(ua *OPCUA) *OPCUA {
	if ua.Encrypted {
		return ua
	}
	out := *ua
	out.Encrypted, out.EncryptedData, out.Service = true, ua.secured, nil
	return &out
}

// sequenceGap takes the sequence number of the next plaintext chunk and
// reports whether chunks were lost before it. Every pending message is
// then marked: any of them may be the one with the hole.
func (a *OPCUAChunkAssembler) sequenceGap(seq uint32) bool {
	last, have := a.lastSeq, a.haveSeq
	a.lastSeq, a.haveSeq = seq, true
	if !have || seq == last+1 {
		return false
	}

	// The numbers restart low instead of running to the end.
	if last >= opcuaSeqWrapLimit && seq < opcuaSeqRestart {
		return false
	}

	a.lost++
	for _, b := range a.pending {
		b.body, b.lost = nil, true
	}
	return true
}

// open starts the buffer of a new message, evicting the oldest one when
// MaxPending are already open.
func (a *OPCUAChunkAssembler) open(key opcuaChunkKey) *opcuaChunkBuffer {
	limit := a.MaxPending
	if limit <= 0 {
		limit = OPCUADefaultMaxPending
	}
	if a.pending == nil {
		a.pending = make(map[opcuaChunkKey]*opcuaChunkBuffer)
	}

	// At most limit entries are scanned, and one leaves.
	if len(a.pending) >= limit {
		var oldest opcuaChunkKey
		first := true
		for k, b := range a.pending {
			if first || b.started < a.pending[oldest].started {
				oldest, first = k, false
			}
		}
		delete(a.pending, oldest)
	}

	a.clock++
	buf := &opcuaChunkBuffer{started: a.clock}
	a.pending[key] = buf
	return buf
}

// extend appends a chunk body, less its signature, to buf. Past the
// limit the body is freed and the message stays refused.
func (a *OPCUAChunkAssembler) extend(buf *opcuaChunkBuffer, body []byte) error {
	if buf.tooLarge {
		return ErrOPCUAMessageTooLarge
	}
	sig := a.signatureSize()
	if sig < 0 || len(body) < sig {
		return ErrOPCUAMalformed
	}
	if buf.lost {
		return nil
	}
	body = body[:len(body)-sig]

	limit := a.MaxMessageSize
	if limit <= 0 {
		limit = OPCUADefaultMaxMessageSize
	}
	// Compared this way round, the sum cannot overflow an int.
	if len(body) > limit-len(buf.body) {
		buf.body, buf.tooLarge = nil, true
		return ErrOPCUAMessageTooLarge
	}

	buf.body = append(buf.body, body...)
	return nil
}

// joinOPCUAChunks returns the message that final ends, with the joined
// body and the service decoded from it.
func joinOPCUAChunks(final *OPCUA, body []byte) *OPCUA {
	out := *final
	out.Body = body
	out.Service = decodeOPCUAService(body)
	return &out
}
