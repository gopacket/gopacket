// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Cyclic data (function group 2) subscribes Read Var items for periodic
// push:
//
//	transfer/change request: reserved, count, timebase, factor, items
//	transfer/change push and response: reserved, count, read data
//	unsubscribe request: function, job ID
//	read record request: reserved, count, item
//	read record response: reserved, count, return code,
//	  [transport size,] status length, status or fill octet,
//	  [record length(2), record]
//
// The bracketed parts of a read record response come with return code
// 0xFF only. Only its first item is read, as in Wireshark.

// Subfunctions of the cyclic data group.
const (
	S7CommCyclicTransfer    S7CommSubfunction = 0x01
	S7CommCyclicUnsubscribe S7CommSubfunction = 0x04
	S7CommCyclicChange      S7CommSubfunction = 0x05
	S7CommCyclicChangeMod   S7CommSubfunction = 0x07
	S7CommCyclicReadRecord  S7CommSubfunction = 0x08
)

const (
	// Reserved and item count before the items or values.
	s7commCyclicHead = 2
	// Timebase and factor before the request items.
	s7commCyclicTiming = 2
	// Record length of a read record response.
	s7commReadRecLenLen = 2

	// Transport sizes announcing a list of NCK addresses instead of
	// values in read data.
	s7commDataTSNCKAddr1 S7CommDataTransportSize = 0x11
	s7commDataTSNCKAddr2 S7CommDataTransportSize = 0x12
)

// S7CommCycleTimebase is the unit of the cyclic interval factor.
type S7CommCycleTimebase uint8

// Cyclic interval timebases.
const (
	S7CommTimebase100ms S7CommCycleTimebase = 0
	S7CommTimebase1s    S7CommCycleTimebase = 1
	S7CommTimebase10s   S7CommCycleTimebase = 2
)

// Duration returns the timebase unit, or 0 when unknown.
func (t S7CommCycleTimebase) Duration() time.Duration {
	switch t {
	case S7CommTimebase100ms:
		return 100 * time.Millisecond
	case S7CommTimebase1s:
		return time.Second
	case S7CommTimebase10s:
		return 10 * time.Second
	}
	return 0
}

// S7CommCyclic is a cyclic data subscription, push or unsubscribe.
// Items holds request addresses, or the NCK addresses some responses
// carry instead of values; Values holds the pushed data.
type S7CommCyclic struct {
	Reserved  uint8
	ItemCount uint8
	Timebase  S7CommCycleTimebase
	Factor    uint8
	Items     []S7CommVarItem
	Values    []S7CommDataItem
	Function  uint8 // unsubscribe request
	JobID     uint8 // unsubscribe request

	Record *S7CommReadRecord // read record
}

// S7CommReadRecord is the first item of a read record (SFB 52 RDREC)
// request or response. Item is the request address; the other fields
// belong to the response. Status and Data alias the packet data.
type S7CommReadRecord struct {
	Item          *S7CommVarItem
	ReturnCode    S7CommReturnCode
	TransportSize S7CommDataTransportSize // with return code 0xFF
	Status        []byte                  // STATUS output of the block
	Length        uint16                  // with return code 0xFF
	Data          []byte
}

// Interval returns the requested cycle time, or 0 when the timebase is
// unknown.
func (c *S7CommCyclic) Interval() time.Duration {
	return c.Timebase.Duration() * time.Duration(c.Factor)
}

// decodeCyclic reads the cyclic data services.
func (u *S7CommUserdata) decodeCyclic() error {
	d := u.Data
	switch u.Subfunction {
	case S7CommCyclicTransfer, S7CommCyclicChange, S7CommCyclicChangeMod, S7CommCyclicUnsubscribe,
		S7CommCyclicReadRecord:
	default:
		return nil
	}
	if len(d) < s7commCyclicHead {
		return fmt.Errorf("%w: cyclic data %d octets", ErrS7CommMalformed, len(d))
	}
	if u.Subfunction == S7CommCyclicReadRecord {
		return u.decodeReadRecord()
	}

	if u.Subfunction == S7CommCyclicUnsubscribe {
		if u.Type == S7CommUDTypeRequest {
			u.Cyclic = &S7CommCyclic{Function: d[0], JobID: d[1]}
		}
		return nil
	}

	c := &S7CommCyclic{Reserved: d[0], ItemCount: d[1]}
	d = d[s7commCyclicHead:]

	var err error
	switch u.Type {
	case S7CommUDTypeRequest:
		if len(d) < s7commCyclicTiming {
			return fmt.Errorf("%w: cyclic request %d octets", ErrS7CommMalformed, len(d))
		}
		c.Timebase = S7CommCycleTimebase(d[0])
		c.Factor = d[1]
		c.Items, err = s7commParamItems(d[s7commCyclicTiming:], int(c.ItemCount))
	default:
		c.Items, c.Values, err = s7commCyclicValues(d, int(c.ItemCount))
	}
	if err != nil {
		return err
	}
	u.Cyclic = c
	return nil
}

// s7commCyclicValues reads pushed values, or the NCK address list a
// transport size of 0x11/0x12 announces in place of values.
func s7commCyclicValues(d []byte, count int) ([]S7CommVarItem, []S7CommDataItem, error) {
	if len(d) < s7commItemHead {
		return nil, nil, fmt.Errorf("%w: cyclic values %d octets", ErrS7CommMalformed, len(d))
	}

	ts := S7CommDataTransportSize(d[1])
	if ts == s7commDataTSNCKAddr1 || ts == s7commDataTSNCKAddr2 {
		items, err := s7commParamItems(d[s7commItemHead:], count)
		return items, nil, err
	}

	vals, _, err := s7commReadData(d, count)
	return nil, vals, err
}

// s7commParamItems reads count Read Var style items, each followed by
// a fill octet when odd-sized and not the last.
func s7commParamItems(p []byte, count int) ([]S7CommVarItem, error) {
	// Each item takes at least its head and syntax ID.
	if count*(s7commItemHead+1) > len(p) {
		return nil, fmt.Errorf("%w: %d items in %d octets", ErrS7CommMalformed, count, len(p))
	}

	items := make([]S7CommVarItem, 0, count)
	for i := 0; i < count; i++ {
		if len(p) < s7commItemHead+1 {
			return nil, fmt.Errorf("%w: item %d of %d truncated", ErrS7CommMalformed, i, count)
		}

		item := S7CommVarItem{VarSpec: p[0], Length: p[1]}
		end := s7commItemHead + int(item.Length)
		if item.Length == 0 || end > len(p) {
			return nil, fmt.Errorf("%w: item %d address length %d", ErrS7CommMalformed, i, item.Length)
		}
		item.SyntaxID = S7CommSyntaxID(p[2])
		item.Address = p[s7commItemHead+1 : end]

		if item.SyntaxID == S7CommSyntaxS7Any {
			if err := item.decodeS7Any(); err != nil {
				return nil, err
			}
		} else {
			item.decodeAddress()
		}
		items = append(items, item)

		// Fill octet keeps the next item on an even offset.
		if end%2 == 1 && i < count-1 {
			end++
		}
		if end > len(p) {
			end = len(p)
		}
		p = p[end:]
	}
	return items, nil
}

// s7commReadData reads count read data items as Wireshark does: the
// length is in bits for BIT, BYTE and INT; data follows for return codes
// 0x00 and 0xFF only; odd data is padded except after the last item.
func s7commReadData(d []byte, count int) ([]S7CommDataItem, []byte, error) {
	if count*s7commDataItemHead > len(d) {
		return nil, nil, fmt.Errorf("%w: %d values in %d octets", ErrS7CommMalformed, count, len(d))
	}

	vals := make([]S7CommDataItem, 0, count)
	for i := 0; i < count; i++ {
		if len(d) < s7commDataItemHead {
			return nil, nil, fmt.Errorf("%w: value %d of %d truncated", ErrS7CommMalformed, i, count)
		}

		v := S7CommDataItem{
			ReturnCode:    S7CommReturnCode(d[0]),
			TransportSize: S7CommDataTransportSize(d[1]),
			Length:        binary.BigEndian.Uint16(d[2:4]),
		}
		n := 0
		if v.ReturnCode.hasData() {
			n = v.TransportSize.ByteLength(v.Length)
		}
		end := s7commDataItemHead + n
		if end > len(d) {
			return nil, nil, fmt.Errorf("%w: value %d length %d", ErrS7CommMalformed, i, n)
		}
		v.Data = d[s7commDataItemHead:end]
		vals = append(vals, v)

		if n%2 == 1 && i < count-1 {
			end++
		}
		if end > len(d) {
			end = len(d)
		}
		d = d[end:]
	}
	return vals, d, nil
}

// decodeReadRecord reads a read record request or response.
func (u *S7CommUserdata) decodeReadRecord() error {
	d := u.Data
	c := &S7CommCyclic{Reserved: d[0], ItemCount: d[1]}
	d = d[s7commCyclicHead:]
	if u.Type == S7CommUDTypePush {
		return nil
	}
	u.Cyclic = c
	if c.ItemCount == 0 {
		return nil
	}

	r := &S7CommReadRecord{}
	if u.Type == S7CommUDTypeRequest {
		items, err := s7commParamItems(d, 1)
		if err != nil {
			u.Cyclic = nil
			return err
		}
		r.Item = &items[0]
		c.Record = r
		return nil
	}

	if err := r.decodeResponse(d); err != nil {
		u.Cyclic = nil
		return err
	}
	c.Record = r
	return nil
}

// decodeResponse reads the first item of a read record response.
func (r *S7CommReadRecord) decodeResponse(d []byte) error {
	short := fmt.Errorf("%w: read record response %d octets", ErrS7CommMalformed, len(d))
	if len(d) < 1 {
		return short
	}
	r.ReturnCode = S7CommReturnCode(d[0])
	d = d[1:]
	ok := r.ReturnCode == S7CommRetSuccess

	if ok {
		if len(d) < 1 {
			return short
		}
		r.TransportSize = S7CommDataTransportSize(d[0])
		d = d[1:]
	}

	// Status length, then the status or a fill octet in its place.
	if len(d) < 1 {
		return short
	}
	n := int(d[0])
	d = d[1:]
	if n == 0 {
		n = 1
	} else if n <= len(d) {
		r.Status = d[:n]
	}
	if n > len(d) {
		return short
	}
	d = d[n:]
	if !ok {
		return nil
	}

	if len(d) < s7commReadRecLenLen {
		return short
	}
	r.Length = binary.BigEndian.Uint16(d)
	d = d[s7commReadRecLenLen:]
	if int(r.Length) > len(d) {
		return short
	}
	r.Data = d[:r.Length]
	return nil
}
