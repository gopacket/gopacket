// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"fmt"
)

// A Userdata value too large for one PDU (an SZL list, a block list, an
// NC file) is sent as several data units. The first response carries a
// data unit reference and "more follow"; the requester asks for each
// further unit with the sequence number of that response:
//
//	PG  -> PLC  request   seq 0
//	PLC -> PG   response  seq 1  ref 3  more   data unit 1
//	PG  -> PLC  request   seq 1                (no data)
//	PLC -> PG   response  seq 1  ref 3  last   data unit 2
//	                 \_ S7CommUDAssembler.Feed _/
//	                 value = unit 1 | unit 2 -> SZL records...
//
// Only the joined value has the structure the views decode, so
// DecodeFromBytes leaves such PDUs raw and the caller joins them.

// S7CommUDDefaultMaxSize is the cap on the octets an S7CommUDAssembler
// holds when its MaxSize is zero: 1 MiB. An S7 PDU carries at most
// 64 KiB and a list takes a handful of them.
const S7CommUDDefaultMaxSize = 1 << 20

// ErrS7CommUDTooLong is returned by S7CommUDAssembler.Feed when the
// data units it holds would exceed its size cap.
var ErrS7CommUDTooLong = errors.New("S7comm Userdata above the assembler size cap")

// s7commUDKey identifies a transfer: the direction, as the Userdata
// type, and the sequence number the responder assigned.
type s7commUDKey struct {
	typ S7CommUserdataType
	seq uint8
}

// s7commUDTransfer is the unfinished value of one transfer.
type s7commUDTransfer struct {
	group S7CommFuncGroup
	sub   S7CommSubfunction
	ref   uint8
	units int
	data  []byte

	// skipping is set once the transfer passed the size cap; its
	// remaining data units are dropped.
	skipping bool
}

// S7CommUDAssembler joins the data units of Userdata values that span
// several PDUs. Feed it the S7comm layers of one connection in order,
// either direction or both. The zero value is ready to use; it is not
// safe for concurrent use.
//
// Transfers are keyed by Userdata type (request, response, push) and
// sequence number, so at most 768 are open at once, and all of them
// together hold at most MaxSize octets. Data units carry no position:
// their order is the order of the calls, i.e. of the TCP stream.
type S7CommUDAssembler struct {
	// MaxSize caps the octets held over all unfinished transfers. Zero
	// or less means S7CommUDDefaultMaxSize.
	MaxSize int

	held    int
	pending map[s7commUDKey]*s7commUDTransfer
}

// Feed takes the next S7comm PDU. It returns the Userdata view to use:
//
//   - s.Userdata itself for a PDU that is not part of a multi-PDU
//     value;
//   - nil while data units of the value are still to come;
//   - a new view on the last data unit, with the parameter and data
//     header of that PDU, Data holding the joined value (owned by the
//     caller), Fragments the number of units and the value views
//     decoded from the whole.
//
// It returns nil for a nil layer or one that is not Userdata. A
// transfer above the size cap returns ErrS7CommUDTooLong once and is
// dropped up to its last unit.
//
// A capture that starts inside a transfer yields its tail as if it
// were whole; the view's DecodeErr then usually says so.
func (a *S7CommUDAssembler) Feed(s *S7Comm) (*S7CommUserdata, error) {
	if s == nil || s.Userdata == nil {
		return nil, nil
	}

	u := s.Userdata
	key := s7commUDKey{u.Type, u.Sequence}
	t := a.pending[key]

	// A transfer of another service or data unit reference under the
	// same key means the old one was abandoned.
	if t != nil && !t.continuedBy(u) {
		a.drop(key)
		t = nil
	}
	if !u.isDataUnit() {
		a.drop(key)
		return u, nil
	}

	more := u.LastDataUnit != 0
	unit := u.Data
	if t == nil {
		// Whole in one PDU: decode in place, nothing to hold.
		if !more {
			return u.joined(unit, 1), nil
		}
		t = &s7commUDTransfer{group: u.FunctionGroup, sub: u.Subfunction, ref: u.DataUnitRef}
		a.add(key, t)
	}

	if err := a.hold(t, unit); err != nil {
		if !more {
			a.drop(key)
		}
		return nil, err
	}
	if more || t.skipping {
		if !more {
			a.drop(key)
		}
		return nil, nil
	}

	// Hand the buffer over with the view.
	a.drop(key)
	return u.joined(t.data, t.units), nil
}

// Pending returns how many octets of unfinished transfers are held.
func (a *S7CommUDAssembler) Pending() int {
	return a.held
}

// Reset drops every unfinished transfer, e.g. after a gap in the TCP
// stream.
func (a *S7CommUDAssembler) Reset() {
	a.pending = nil
	a.held = 0
}

// limit returns the effective size cap.
func (a *S7CommUDAssembler) limit() int {
	if a.MaxSize <= 0 {
		return S7CommUDDefaultMaxSize
	}
	return a.MaxSize
}

// add opens a transfer. The map is created on first use so the zero
// assembler costs nothing for connections without multi-PDU values.
func (a *S7CommUDAssembler) add(key s7commUDKey, t *s7commUDTransfer) {
	if a.pending == nil {
		a.pending = map[s7commUDKey]*s7commUDTransfer{}
	}
	a.pending[key] = t
}

// drop closes a transfer and releases what it held.
func (a *S7CommUDAssembler) drop(key s7commUDKey) {
	t := a.pending[key]
	if t == nil {
		return
	}

	a.held -= len(t.data)
	delete(a.pending, key)
}

// hold appends a data unit to a transfer. The cap is checked before
// anything is copied; a transfer passing it gives up its data and
// skips the units that follow.
func (a *S7CommUDAssembler) hold(t *s7commUDTransfer, unit []byte) error {
	if t.skipping {
		return nil
	}

	if a.held+len(unit) > a.limit() {
		a.held -= len(t.data)
		t.data = nil
		t.skipping = true
		return fmt.Errorf("%w: %d octets held, %d more, cap %d", ErrS7CommUDTooLong, a.held, len(unit), a.limit())
	}

	t.data = append(t.data, unit...)
	t.units++
	a.held += len(unit)
	return nil
}

// continuedBy reports whether u can be the next data unit of t. NC
// programming counts the data unit reference up with every PDU, so
// only the sequence number ties its units together.
func (t *s7commUDTransfer) continuedBy(u *S7CommUserdata) bool {
	if u.FunctionGroup != t.group || u.Subfunction != t.sub {
		return false
	}
	return u.FunctionGroup == S7CommGroupNCProgramming || u.DataUnitRef == t.ref
}

// isDataUnit reports whether the PDU carries a data unit of a value
// that may span PDUs, as Wireshark decides it: at least two data
// octets and a data unit reference. NC programming transfers count as
// such even without one, as their reference wraps to zero.
func (u *S7CommUserdata) isDataUnit() bool {
	if len(u.Data) < s7commUDMinUnit {
		return false
	}
	return u.DataUnitRef != 0 || u.LastDataUnit != 0 || u.FunctionGroup == S7CommGroupNCProgramming
}

// joined returns the view of a whole value: u's parameter and data
// header with the joined data, decoded like an unfragmented value.
func (u *S7CommUserdata) joined(data []byte, units int) *S7CommUserdata {
	v := &S7CommUserdata{
		VarSpec:       u.VarSpec,
		ParamLength:   u.ParamLength,
		SyntaxID:      u.SyntaxID,
		Type:          u.Type,
		FunctionGroup: u.FunctionGroup,
		Subfunction:   u.Subfunction,
		Sequence:      u.Sequence,
		DataUnitRef:   u.DataUnitRef,
		LastDataUnit:  u.LastDataUnit,
		ErrorCode:     u.ErrorCode,
		ReturnCode:    u.ReturnCode,
		TransportSize: u.TransportSize,
		Length:        u.Length,
		UnitHeader:    u.UnitHeader,
		Data:          data,
		Fragments:     units,
	}

	// A malformed joined value is reported like any other view error:
	// the PDUs themselves were well formed.
	if err := v.decodeView(); err != nil {
		v.DecodeErr = err
	}
	return v
}
