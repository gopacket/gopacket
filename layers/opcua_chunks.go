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

package layers

import "errors"

// Chunk reassembly limits.
const (
	// OPCUADefaultMaxMessageSize is the joined body size an
	// OPCUAChunkAssembler accepts when MaxMessageSize is 0.
	OPCUADefaultMaxMessageSize = 4 << 20
	// OPCUADefaultMaxPending is the count of unfinished messages an
	// OPCUAChunkAssembler keeps when MaxPending is 0.
	OPCUADefaultMaxPending = 8
)

// ErrOPCUAMessageTooLarge is returned for a chunk that takes its message
// past the size limit of the assembler.
var ErrOPCUAMessageTooLarge = errors.New("OPC UA chunked message too large")

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
// Only plaintext joins: on an encrypting channel the sequence header and
// the body are ciphertext. On a channel that signs, set SignatureSize.
// Lost chunks are not detected; a message with one missing joins into a
// body that does not decode.
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
	// that are a signature rather than message: 0 for security mode None,
	// the size of the symmetric signature for mode Sign, 32 for
	// HMAC-SHA256.
	SignatureSize int

	pending map[opcuaChunkKey]*opcuaChunkBuffer
	clock   uint64
}

// Add takes the next layer and returns the message it completes.
//
//   - A final chunk with nothing pending is a whole message: it is
//     returned as it is.
//   - An intermediate chunk is copied and kept; Add returns nil.
//   - A final chunk that ends a pending message returns a copy of it
//     whose Body is the joined body and whose Service is decoded from
//     it. The other fields, MessageSize and SequenceNumber among them,
//     are those of the final chunk.
//   - An abort chunk drops the pending message and is returned as it is;
//     its Error tells why the sender gave up.
//   - HEL, ACK, ERR and RHE are never chunked and are returned as they
//     are.
//
// ErrOPCUAMessageTooLarge is returned for the chunk that passes
// MaxMessageSize and for every later chunk of that message, which is
// dropped. ErrOPCUAMalformed is returned for an unknown chunk type and
// for a chunk shorter than SignatureSize.
func (a *OPCUAChunkAssembler) Add(ua *OPCUA) (*OPCUA, error) {
	if ua == nil {
		return nil, nil
	}
	switch ua.MessageType {
	case OPCUAMessageOpenSecureChannel, OPCUAMessageSecure, OPCUAMessageCloseSecureChannel:
	default:
		return ua, nil
	}

	key := opcuaChunkKey{ua.MessageType, ua.SecureChannelID, ua.RequestID}
	buf := a.pending[key]

	switch ua.ChunkType {
	case OPCUAChunkAbort:
		delete(a.pending, key)
		return ua, nil

	case OPCUAChunkIntermediate:
		if buf == nil {
			buf = a.open(key)
		}
		return nil, a.extend(buf, ua.Body)

	case OPCUAChunkFinal:
		if buf == nil {
			return ua, nil
		}
		delete(a.pending, key)
		if err := a.extend(buf, ua.Body); err != nil {
			return nil, err
		}
		return joinOPCUAChunks(ua, buf.body), nil
	}
	return nil, ErrOPCUAMalformed
}

// Pending returns the count of unfinished messages.
func (a *OPCUAChunkAssembler) Pending() int { return len(a.pending) }

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
	if a.SignatureSize < 0 || len(body) < a.SignatureSize {
		return ErrOPCUAMalformed
	}
	body = body[:len(body)-a.SignatureSize]

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
	out.Service = nil

	// An OPN body is encrypted under any policy but None.
	if out.MessageType == OPCUAMessageOpenSecureChannel && out.SecurityHeader.SecurityPolicyURI != OPCUASecurityPolicyNone {
		return &out
	}
	out.Service = decodeOPCUAService(body)
	return &out
}
