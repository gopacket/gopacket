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

// TPKT (RFC 1006) frames ISO transport TPDUs over TCP, port 102 by
// convention. It carries COTP, which in turn carries S7comm, S7comm-plus
// or the ISO session layer (IEC 61850 MMS, ICCP).
//
//	TCP payload
//	+-----------------------+-----------------------+----
//	| TPKT | COTP | S7/ISO  | TPKT | COTP | S7/ISO  | ...
//	+-----------------------+-----------------------+----
//	 <---- TPKT.Length ---->

// LayerTypeTPKT is the layer type of an RFC 1006 TPKT frame.
var LayerTypeTPKT = gopacket.RegisterLayerType(160, gopacket.LayerTypeMetadata{Name: "TPKT", Decoder: gopacket.DecodeFunc(decodeTPKT)})

const (
	// TCPPortTPKT is the TCP port RFC 1006 assigns to ISO transport.
	TCPPortTPKT uint16 = 102

	// TPKTVersion is the only TPKT version RFC 1006 defines.
	TPKTVersion uint8 = 3

	tpktHeaderLen = 4

	// A TPKT must hold at least a COTP length indicator, type and one more
	// octet (RFC 1006 section 6: minimum length 7).
	tpktMinLen = 7

	// tpktMaxStackDepth bounds how many layers one inline TPKT stack may
	// nest, mirroring the depth limit eager packets apply.
	tpktMaxStackDepth = 64
)

var (
	// ErrTPKTTooShort is returned when data cannot hold a TPKT header or
	// the frame its length announces.
	ErrTPKTTooShort = errors.New("TPKT frame truncated")
	// ErrTPKTBadVersion is returned when the version octet is not 3.
	ErrTPKTBadVersion = errors.New("TPKT version is not 3")
	// ErrTPKTBadLength is returned when the length field is below the
	// RFC 1006 minimum of 7.
	ErrTPKTBadLength = errors.New("TPKT length below minimum")

	errTPKTNilDecoder   = errors.New("TPKT stack: nil decoder")
	errTPKTStackTooDeep = errors.New("TPKT stack nests too many layers")
	errTPKTNoLayer      = errors.New("TPKT stack: NextDecoder before AddLayer")
)

// TPKT is an RFC 1006 frame header. Payload holds the COTP TPDU; bytes
// past Length belong to the next TPKT of the segment.
//
// gopacket.NewPacket decodes every TPKT of a segment. A
// DecodingLayerParser holds one TPKT value and decodes only the first;
// to read the rest, call DecodeFromBytes again on data[Length:].
type TPKT struct {
	BaseLayer
	Version  uint8
	Reserved uint8
	Length   uint16
}

// LayerType returns LayerTypeTPKT.
func (t *TPKT) LayerType() gopacket.LayerType { return LayerTypeTPKT }

// CanDecode returns LayerTypeTPKT.
func (t *TPKT) CanDecode() gopacket.LayerClass { return LayerTypeTPKT }

// NextLayerType returns LayerTypeCOTP.
func (t *TPKT) NextLayerType() gopacket.LayerType { return LayerTypeCOTP }

// DecodeFromBytes decodes one TPKT frame from the start of data.
func (t *TPKT) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < tpktHeaderLen {
		df.SetTruncated()
		return ErrTPKTTooShort
	}

	t.Version = data[0]
	t.Reserved = data[1]
	t.Length = binary.BigEndian.Uint16(data[2:4])
	if t.Version != TPKTVersion {
		return ErrTPKTBadVersion
	}
	if t.Length < tpktMinLen {
		return ErrTPKTBadLength
	}
	if int(t.Length) > len(data) {
		df.SetTruncated()
		return fmt.Errorf("%w: length %d, have %d", ErrTPKTTooShort, t.Length, len(data))
	}

	t.Contents = data[:tpktHeaderLen]
	t.Payload = data[tpktHeaderLen:t.Length]
	return nil
}

// decodeTPKT decodes every TPKT of a segment. All but the last decode
// their stack inline; the last chains through NextDecoder so lazy
// packets and Payload handling work as for any other layer. Every pass
// consumes at least tpktMinLen bytes, so the loop is bounded by data.
func decodeTPKT(data []byte, p gopacket.PacketBuilder) error {
	for {
		t := &TPKT{}
		if err := t.DecodeFromBytes(data, p); err != nil {
			return err
		}
		p.AddLayer(t)

		rest := data[t.Length:]
		if len(rest) == 0 {
			return p.NextDecoder(LayerTypeCOTP)
		}

		stack := &tpktStack{PacketBuilder: p, last: t}
		if err := stack.NextDecoder(LayerTypeCOTP); err != nil {
			return err
		}
		data = rest
	}
}

// tpktStack decodes one TPKT body eagerly on behalf of the real builder,
// so a TPKT followed by another in the same segment still gets its whole
// layer stack, whether the packet is lazy or eager.
type tpktStack struct {
	gopacket.PacketBuilder
	last  gopacket.Layer
	depth int
}

// AddLayer records l as the layer the next decoder reads from.
func (s *tpktStack) AddLayer(l gopacket.Layer) {
	s.last = l
	s.PacketBuilder.AddLayer(l)
}

// NextDecoder decodes the last layer's payload immediately.
func (s *tpktStack) NextDecoder(next gopacket.Decoder) error {
	if next == nil {
		return errTPKTNilDecoder
	}
	if s.last == nil {
		return errTPKTNoLayer
	}

	d := s.last.LayerPayload()
	if len(d) == 0 {
		return nil
	}
	if s.depth >= tpktMaxStackDepth {
		return errTPKTStackTooDeep
	}

	s.depth++
	err := next.Decode(d, s)
	s.depth--
	return err
}

// registerS7Decoders maps TCP port 102 to TPKT. It is opt-in so callers
// that decode port 102 as payload today keep doing so. Calling it again
// is harmless.
func registerS7Decoders() {
	RegisterTCPPortLayerType(TCPPort(TCPPortTPKT), LayerTypeTPKT)
}
