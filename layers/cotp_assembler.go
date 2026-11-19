// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// A TSDU too large for one TPDU is sent as DT TPDUs without EOT, then
// one with it (ISO 8073 6.3, segmenting). MMS does so for large
// responses; S7comm never does.
//
//	TPKT|DT      |seg 1   TPKT|DT      |seg 2   TPKT|DT EOT|seg 3
//	      \________________ COTPAssembler.Feed ________________/
//	                    |seg 1 seg 2 seg 3| -> ISO session
//
// The decoders work on one packet, so COTP hands a segment to
// LayerTypeFragment; joining segments is the caller's step, after TCP
// reassembly and ScanTPKT.

// COTPDefaultMaxTSDU is the TSDU size cap of a COTPAssembler whose
// MaxSize is zero: 1 MiB, far above what MMS negotiates.
const COTPDefaultMaxTSDU = 1 << 20

// ErrCOTPTSDUTooLong is returned by COTPAssembler.Feed when the
// segments of a TSDU exceed the assembler's size cap.
var ErrCOTPTSDUTooLong = errors.New("COTP TSDU above the assembler size cap")

// COTPAssembler joins the DT TPDUs of one direction of a transport
// connection into TSDUs. The zero value is ready to use. It holds at
// most MaxSize octets and is not safe for concurrent use.
//
// Classes 2 to 4 may multiplex transport connections over one network
// connection; use one assembler per DST-REF then. TPDU numbers are not
// checked: class 0 does not use them, class 2 without flow control may
// send any value, and over TPKT the order is that of the TCP stream.
type COTPAssembler struct {
	// MaxSize caps a TSDU in octets. Zero or less means
	// COTPDefaultMaxTSDU.
	MaxSize int

	// buf holds the segments of the unfinished TSDU.
	buf []byte

	// skipping is set after an overflow, until the DT with EOT that
	// ends the oversized TSDU.
	skipping bool
}

// Feed takes the next TPDU of the direction, in order. When c is the
// last DT of a TSDU, Feed returns the TSDU and the layer type that
// decodes it: LayerTypeS7Comm, LayerTypeS7CommPlus or
// LayerTypeISOSession, chosen as COTP.NextLayerType does. Otherwise,
// and for an empty TSDU, it returns nil and gopacket.LayerTypeZero.
//
// A TSDU carried by a single DT aliases c.Payload. A joined TSDU is a
// new buffer owned by the caller.
//
// TPDUs other than DT leave an unfinished TSDU alone, except CR, CC, DR
// and DC, which open or close the connection and drop it. A TSDU above
// the size cap returns ErrCOTPTSDUTooLong once; its remaining segments
// are then skipped.
func (a *COTPAssembler) Feed(c *COTP) ([]byte, gopacket.LayerType, error) {
	if c == nil {
		return nil, gopacket.LayerTypeZero, nil
	}

	switch c.Type {
	case COTPTypeDT:
	case COTPTypeCR, COTPTypeCC, COTPTypeDR, COTPTypeDC:
		a.Reset()
		return nil, gopacket.LayerTypeZero, nil
	default:
		return nil, gopacket.LayerTypeZero, nil
	}

	if a.skipping {
		a.skipping = !c.EOT
		return nil, gopacket.LayerTypeZero, nil
	}

	// Check before appending, so the buffer never passes the cap.
	if size := len(a.buf) + len(c.Payload); size > a.limit() {
		a.buf = nil
		a.skipping = !c.EOT
		return nil, gopacket.LayerTypeZero, fmt.Errorf("%w: %d octets, cap %d", ErrCOTPTSDUTooLong, size, a.limit())
	}

	// The common case: a whole TSDU in one TPDU, returned as is.
	if c.EOT && len(a.buf) == 0 {
		return cotpTSDU(c.Payload)
	}

	a.buf = append(a.buf, c.Payload...)
	if !c.EOT {
		return nil, gopacket.LayerTypeZero, nil
	}

	// Hand the buffer over, so the next TSDU cannot overwrite it.
	tsdu := a.buf
	a.buf = nil
	return cotpTSDU(tsdu)
}

// Pending returns how many octets of an unfinished TSDU are held.
func (a *COTPAssembler) Pending() int {
	return len(a.buf)
}

// Reset drops the unfinished TSDU, e.g. after a gap in the TCP stream.
func (a *COTPAssembler) Reset() {
	a.buf = nil
	a.skipping = false
}

// limit returns the effective size cap.
func (a *COTPAssembler) limit() int {
	if a.MaxSize <= 0 {
		return COTPDefaultMaxTSDU
	}
	return a.MaxSize
}

// cotpTSDU returns a complete TSDU with its layer type, or nothing for
// an empty one.
func cotpTSDU(tsdu []byte) ([]byte, gopacket.LayerType, error) {
	if len(tsdu) == 0 {
		return nil, gopacket.LayerTypeZero, nil
	}
	return tsdu, cotpUserLayer(tsdu), nil
}
