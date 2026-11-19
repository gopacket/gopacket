// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
)

// State kept across Modbus PDUs: which request a response answers, the
// device identification objects a server sends over several responses,
// and a guess at the direction of a PDU when its ports do not tell.

// ModbusMaxTransactions is the default number of requests a
// ModbusTransactions keeps waiting for their response.
const ModbusMaxTransactions = 1024

// Errors returned by ModbusDeviceInfo.Add.
var (
	ErrModbusDevIDDone  = errors.New("modbus device identification already complete")
	ErrModbusDevIDOrder = errors.New("modbus device identification response out of order")
)

// ModbusExchange is one Modbus/TCP PDU and the PDU it pairs with.
// Request is nil for a response whose request was not seen; Response is
// nil for a request.
type ModbusExchange struct {
	TransactionID uint16
	UnitID        uint8
	Request       *ModbusPDU
	Response      *ModbusPDU
}

// Address returns the starting address the exchange is about, taken
// from the request: a read response carries values, not where they
// were read from. ok is false without a request or for a function that
// has no starting address.
func (e *ModbusExchange) Address() (addr uint16, ok bool) {
	if e.Request == nil || e.Request.Exception {
		return 0, false
	}

	switch e.Request.Function {
	case ModbusFuncCodeReadCoils, ModbusFuncCodeReadDiscreteInputs,
		ModbusFuncCodeReadHoldingRegisters, ModbusFuncCodeReadInputRegisters,
		ModbusFuncCodeWriteSingleCoil, ModbusFuncCodeWriteSingleRegister,
		ModbusFuncCodeWriteMultipleCoils, ModbusFuncCodeWriteMultipleRegisters,
		ModbusFuncCodeMaskWriteRegister, ModbusFuncCodeReadWriteMultipleRegs,
		ModbusFuncCodeReadFIFOQueue:
		return e.Request.Address, true
	}
	return 0, false
}

// modbusTxKey names a pending request of one connection.
type modbusTxKey struct {
	id   uint16
	unit uint8
}

// modbusTx is a request waiting for its response.
type modbusTx struct {
	key modbusTxKey
	pdu *ModbusPDU
}

// ModbusTransactions pairs the requests and responses of one Modbus/TCP
// connection by transaction and unit identifier, so a response can be
// read with the addresses of its request. Use one per connection: the
// identifiers are only unique within it. The zero value is ready to
// use. It is not safe for concurrent use.
//
// Memory is bounded: at most Max requests wait, each a copy of at most
// one PDU, and the oldest is dropped to make room.
type ModbusTransactions struct {
	// Max caps the requests waiting for a response. 0 means
	// ModbusMaxTransactions.
	Max int

	pending map[modbusTxKey]*list.Element
	order   list.List // of *modbusTx, oldest first
}

// Pending returns how many requests wait for a response.
func (t *ModbusTransactions) Pending() int {
	return len(t.pending)
}

// Add decodes the PDU of m, the layer TCP port 502 decodes to, sent in
// direction dir, and pairs it. A request is kept until its response
// comes; a response is returned with its request, when one with the
// same identifiers and function waits. The error is that of decoding
// the PDU; the exchange is returned with it.
//
// A kept request is decoded from a copy of its bytes, so m and its
// buffer may be reused.
func (t *ModbusTransactions) Add(m *Modbus, dir ModbusDirection) (*ModbusExchange, error) {
	if m == nil {
		return nil, ErrModbusPDUTooShort
	}
	return t.add(modbusTxKey{id: m.TransactionID, unit: m.UnitID}, m.FunctionCode, m.ReqResp, dir)
}

// AddTCP is Add for a ModbusTCP layer, whose payload is the PDU. It
// returns no exchange when the payload is empty.
func (t *ModbusTransactions) AddTCP(m *ModbusTCP, dir ModbusDirection) (*ModbusExchange, error) {
	if m == nil || len(m.Payload()) == 0 {
		return nil, ErrModbusPDUTooShort
	}

	pdu := m.Payload()
	return t.add(modbusTxKey{id: m.TransactionIdentifier, unit: m.UnitIdentifier}, pdu[0], pdu[1:], dir)
}

// add decodes function fc with its data and pairs the PDU under key.
func (t *ModbusTransactions) add(key modbusTxKey, fc byte, data []byte, dir ModbusDirection) (*ModbusExchange, error) {
	ex := &ModbusExchange{TransactionID: key.id, UnitID: key.unit}
	if dir == ModbusResponse {
		pdu, err := decodeModbusPDU(fc, data, dir)
		ex.Response = pdu
		ex.Request = t.take(key, pdu.Function)
		return ex, err
	}

	pdu, err := decodeModbusPDU(fc, bytes.Clone(data), dir)
	ex.Request = pdu
	t.put(key, pdu)
	return ex, err
}

// put keeps a request, replacing one with the same identifiers and
// dropping the oldest at the cap.
func (t *ModbusTransactions) put(key modbusTxKey, pdu *ModbusPDU) {
	if t.pending == nil {
		t.pending = make(map[modbusTxKey]*list.Element)
	}

	if e, ok := t.pending[key]; ok {
		t.order.Remove(e)
		delete(t.pending, key)
	}

	limit := t.Max
	if limit <= 0 {
		limit = ModbusMaxTransactions
	}

	for len(t.pending) >= limit {
		oldest := t.order.Front()
		delete(t.pending, oldest.Value.(*modbusTx).key)
		t.order.Remove(oldest)
	}
	t.pending[key] = t.order.PushBack(&modbusTx{key: key, pdu: pdu})
}

// take removes and returns the request waiting under key. A response
// to another function answers something else: the request is dropped
// and nil returned.
func (t *ModbusTransactions) take(key modbusTxKey, fc ModbusFunctionCode) *ModbusPDU {
	e, ok := t.pending[key]
	if !ok {
		return nil
	}

	t.order.Remove(e)
	delete(t.pending, key)

	req := e.Value.(*modbusTx).pdu
	if req.Function != fc {
		return nil
	}
	return req
}

// ModbusDeviceInfo joins the objects of a Read Device Identification
// that a server sends over several responses. When a response has
// MoreFollows set, the client asks again from NextObjectID; Add takes
// each response in turn:
//
//	resp 1: MoreFollows, NextObjectID 2, objects 0, 1
//	resp 2: last,                        objects 2      -> Complete
//
// The zero value is ready to use. Object values are copied. Object IDs
// must ascend, so at most 256 objects are kept, one per ID.
type ModbusDeviceInfo struct {
	ReadCode   ModbusDevIDCode
	Conformity uint8
	Objects    []ModbusDeviceObject
	Complete   bool

	started bool
	next    ModbusDevObjectID
}

// Next returns the request that continues the read: the read code and
// the object ID to ask for. ok is false before the first response and
// once the read is complete.
func (d *ModbusDeviceInfo) Next() (code ModbusDevIDCode, id ModbusDevObjectID, ok bool) {
	if !d.started || d.Complete {
		return 0, 0, false
	}
	return d.ReadCode, d.next, true
}

// Object returns the value of object id, when it was received.
func (d *ModbusDeviceInfo) Object(id ModbusDevObjectID) ([]byte, bool) {
	for _, o := range d.Objects {
		if o.ID == id {
			return o.Value, true
		}
	}
	return nil, false
}

// Add appends the objects of the next response. It returns
// ErrModbusDevIDDone after the last response, and ErrModbusDevIDOrder,
// leaving d as it was, for a response that does not continue the read:
// another read code, objects that do not start at the ID announced or
// do not ascend, or a next object ID that does not move forward.
func (d *ModbusDeviceInfo) Add(id *ModbusDeviceID) error {
	if d.Complete {
		return ErrModbusDevIDDone
	}

	if d.started && id.ReadCode != d.ReadCode {
		return fmt.Errorf("%w: read code %v, want %v", ErrModbusDevIDOrder, id.ReadCode, d.ReadCode)
	}

	// Ascending IDs bound the objects kept to one per ID and stop a
	// server that announces the same continuation forever.
	last := -1
	if n := len(d.Objects); n > 0 {
		last = int(d.Objects[n-1].ID)
	}

	for i, o := range id.Objects {
		if i == 0 && d.started && o.ID != d.next {
			return fmt.Errorf("%w: object 0x%02X, want 0x%02X", ErrModbusDevIDOrder, uint8(o.ID), uint8(d.next))
		}

		if int(o.ID) <= last {
			return fmt.Errorf("%w: object 0x%02X after 0x%02X", ErrModbusDevIDOrder, uint8(o.ID), last)
		}
		last = int(o.ID)
	}

	if id.MoreFollows && int(id.NextObjectID) <= last {
		return fmt.Errorf("%w: next object 0x%02X after 0x%02X", ErrModbusDevIDOrder, uint8(id.NextObjectID), last)
	}

	for _, o := range id.Objects {
		d.Objects = append(d.Objects, ModbusDeviceObject{ID: o.ID, Value: bytes.Clone(o.Value)})
	}

	d.started = true
	d.ReadCode, d.Conformity = id.ReadCode, id.Conformity
	d.next = id.NextObjectID
	d.Complete = !id.MoreFollows
	return nil
}

// ModbusDirConfidence says how a direction was told.
type ModbusDirConfidence uint8

// ModbusDirConfidence values, weakest first.
const (
	// ModbusDirUnknown: the PDU decodes as neither a request nor a
	// response. The direction returned is ModbusRequest.
	ModbusDirUnknown ModbusDirConfidence = iota
	// ModbusDirAmbiguous: the PDU is valid both ways, as the echo of a
	// write is. The direction returned is ModbusRequest.
	ModbusDirAmbiguous
	// ModbusDirByShape: the PDU is valid one way only, or has the
	// exception bit set.
	ModbusDirByShape
	// ModbusDirByPort: one port is the Modbus port, 502.
	ModbusDirByPort
)

// String returns the confidence name.
func (c ModbusDirConfidence) String() string {
	switch c {
	case ModbusDirUnknown:
		return "Unknown"
	case ModbusDirAmbiguous:
		return "Ambiguous"
	case ModbusDirByShape:
		return "By Shape"
	case ModbusDirByPort:
		return "By Port"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(c))
	}
}

// ModbusGuessDir guesses the direction of a raw PDU from its shape
// alone: it is decoded both ways and the way that fits wins. It is a
// best effort for traffic on other ports than 502. Many PDUs fit both
// ways, e.g. a write single register and its echo, or five bytes that
// are a read request and a read response of three data bytes; pairing
// by transaction, or the side that opened the connection, tells more.
func ModbusGuessDir(pdu []byte) (ModbusDirection, ModbusDirConfidence) {
	if len(pdu) == 0 {
		return ModbusRequest, ModbusDirUnknown
	}

	// Only a server sets the exception bit.
	if ModbusFunctionCode(pdu[0])&ModbusFuncCodeExceptionMask != 0 {
		return ModbusResponse, ModbusDirByShape
	}

	// A function without a decoder keeps any data both ways.
	if _, ok := modbusPDUCodecs[ModbusFunctionCode(pdu[0])]; !ok {
		return ModbusRequest, ModbusDirUnknown
	}

	_, reqErr := DecodeModbusPDU(pdu, ModbusRequest)
	_, respErr := DecodeModbusPDU(pdu, ModbusResponse)
	switch {
	case reqErr == nil && respErr == nil:
		return ModbusRequest, ModbusDirAmbiguous
	case reqErr == nil:
		return ModbusRequest, ModbusDirByShape
	case respErr == nil:
		return ModbusResponse, ModbusDirByShape
	}
	return ModbusRequest, ModbusDirUnknown
}

// ModbusDirOf tells the direction of a Modbus/TCP PDU: from its ports
// when exactly one is 502, as ModbusDirFromPorts does, else from the
// shape of the PDU, as ModbusGuessDir does.
func ModbusDirOf(src, dst TCPPort, pdu []byte) (ModbusDirection, ModbusDirConfidence) {
	port := TCPPort(ModbusPort)
	if (src == port) != (dst == port) {
		return ModbusDirFromPorts(src, dst), ModbusDirByPort
	}
	return ModbusGuessDir(pdu)
}
