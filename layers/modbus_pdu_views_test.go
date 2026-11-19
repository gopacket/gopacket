// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

// mbPDU decodes a hex PDU and fails the test when it does not decode.
func mbPDU(t *testing.T, pdu string, dir ModbusDirection) *ModbusPDU {
	t.Helper()

	p, err := DecodeModbusPDU(mbHex(pdu), dir)
	if err != nil {
		t.Fatalf("%s: %v", pdu, err)
	}
	return p
}

// Diagnostics data per sub-function, spec section 6.8.1. tshark 4.7
// shows the same register, counter and delimiter values for the
// exchanges of sub-functions 0, 1, 2, 3, 0x0A, 0x0B, 0x12 and 0x14.
func TestModbusDiagnostic(t *testing.T) {
	tests := []struct {
		name string
		pdu  string
		dir  ModbusDirection
		want ModbusDiagnostic
		err  error
	}{
		{"query data", "08 00 00 A5 37", ModbusRequest, ModbusDiagnostic{Code: 0x00, Kind: ModbusDiagEcho}, nil},
		{"query data, any length", "08 00 00 01 02 03 04 05", ModbusResponse, ModbusDiagnostic{Code: 0x00, Kind: ModbusDiagEcho}, nil},
		{"restart", "08 00 01 00 00", ModbusRequest, ModbusDiagnostic{Code: 0x01, Kind: ModbusDiagRestart}, nil},
		{"restart, clear log", "08 00 01 FF 00", ModbusRequest, ModbusDiagnostic{Code: 0x01, Kind: ModbusDiagRestart, Value: 0xFF00, ClearLog: true}, nil},
		{"restart echo", "08 00 01 FF 00", ModbusResponse, ModbusDiagnostic{Code: 0x01, Kind: ModbusDiagRestart, Value: 0xFF00, ClearLog: true}, nil},
		{"register req", "08 00 02 00 00", ModbusRequest, ModbusDiagnostic{Code: 0x02, Kind: ModbusDiagRegister}, nil},
		{"register resp", "08 00 02 12 34", ModbusResponse, ModbusDiagnostic{Code: 0x02, Kind: ModbusDiagRegister, Value: 0x1234}, nil},
		{"delimiter", "08 00 03 0D 00", ModbusRequest, ModbusDiagnostic{Code: 0x03, Kind: ModbusDiagDelimiter, Value: 0x0D00, Delimiter: 0x0D}, nil},
		{"listen only", "08 00 04 00 00", ModbusRequest, ModbusDiagnostic{Code: 0x04, Kind: ModbusDiagCommand}, nil},
		{"clear counters", "08 00 0A 00 00", ModbusResponse, ModbusDiagnostic{Code: 0x0A, Kind: ModbusDiagCommand}, nil},
		{"bus message count req", "08 00 0B 00 00", ModbusRequest, ModbusDiagnostic{Code: 0x0B, Kind: ModbusDiagCounter}, nil},
		{"bus message count resp", "08 00 0B 01 02", ModbusResponse, ModbusDiagnostic{Code: 0x0B, Kind: ModbusDiagCounter, Value: 258}, nil},
		{"overrun count resp", "08 00 12 FF FF", ModbusResponse, ModbusDiagnostic{Code: 0x12, Kind: ModbusDiagCounter, Value: 0xFFFF}, nil},
		{"clear overrun", "08 00 14 00 00", ModbusRequest, ModbusDiagnostic{Code: 0x14, Kind: ModbusDiagCommand}, nil},
		{"reserved 5", "08 00 05 12 34", ModbusRequest, ModbusDiagnostic{Code: 0x05, Kind: ModbusDiagReserved, Value: 0x1234}, nil},
		{"reserved 0x13", "08 00 13 00 01", ModbusRequest, ModbusDiagnostic{Code: 0x13, Kind: ModbusDiagReserved, Value: 1}, nil},
		{"reserved 0x15", "08 00 15 00 01", ModbusResponse, ModbusDiagnostic{Code: 0x15, Kind: ModbusDiagReserved, Value: 1}, nil},

		{"restart option 1", "08 00 01 00 01", ModbusRequest, ModbusDiagnostic{Code: 0x01, Kind: ModbusDiagRestart, Value: 1}, ErrModbusPDUValue},
		{"register req with data", "08 00 02 12 34", ModbusRequest, ModbusDiagnostic{Code: 0x02, Kind: ModbusDiagRegister, Value: 0x1234}, ErrModbusPDUValue},
		{"counter req with data", "08 00 0E 00 01", ModbusRequest, ModbusDiagnostic{Code: 0x0E, Kind: ModbusDiagCounter, Value: 1}, ErrModbusPDUValue},
		{"delimiter low byte", "08 00 03 0D 01", ModbusRequest, ModbusDiagnostic{Code: 0x03, Kind: ModbusDiagDelimiter, Value: 0x0D01, Delimiter: 0x0D}, ErrModbusPDUValue},
		{"listen only with data", "08 00 04 00 01", ModbusRequest, ModbusDiagnostic{Code: 0x04, Kind: ModbusDiagCommand, Value: 1}, ErrModbusPDUValue},
		{"clear counters echo with data", "08 00 0A 00 01", ModbusResponse, ModbusDiagnostic{Code: 0x0A, Kind: ModbusDiagCommand, Value: 1}, ErrModbusPDUValue},
		{"counter without data", "08 00 0B", ModbusResponse, ModbusDiagnostic{Code: 0x0B, Kind: ModbusDiagCounter}, ErrModbusPDULength},
		{"counter with 3 bytes", "08 00 0B 00 00 00", ModbusResponse, ModbusDiagnostic{Code: 0x0B, Kind: ModbusDiagCounter}, ErrModbusPDULength},
	}

	for _, tc := range tests {
		got, err := mbPDU(t, tc.pdu, tc.dir).Diagnostic()
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%s: %+v, %v; want %+v, %v", tc.name, got, err, tc.want, tc.err)
		}
	}

	// Every sub-function 0x00 to 0x14 has a name or is reserved.
	for c := ModbusDiagCode(0); c <= 0x15; c++ {
		reserved := c >= 5 && c <= 9 || c == 0x13 || c == 0x15
		if c.Reserved() != reserved || (c.String() == "Reserved(0x00"+mbHexByte(byte(c))+")") != reserved {
			t.Errorf("sub-function 0x%02X: reserved %v, name %q", uint16(c), c.Reserved(), c.String())
		}
	}

	if ModbusDiagCounter.String() != "Counter" || ModbusDiagKind(99).String() != "Unknown(99)" {
		t.Error("kind names")
	}
}

// mbHexByte is b as two upper case hex digits.
func mbHexByte(b byte) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[b>>4], digits[b&0x0F]})
}

func TestModbusServerID(t *testing.T) {
	tests := []struct {
		name string
		pdu  string
		want ModbusServerID
	}{
		{"one byte ID, ON, extra", "11 03 42 FF 01", ModbusServerID{ID: mbHex("42"), Run: ModbusRunOn, Additional: mbHex("01")}},
		{"one byte ID, OFF", "11 02 09 00", ModbusServerID{ID: mbHex("09"), Run: ModbusRunOff, Additional: []byte{}}},
		{"text ID, ON", "11 06 50 4D 37 31 30 FF", ModbusServerID{ID: []byte("PM710"), Run: ModbusRunOn, Additional: []byte{}}},
		{"ID 0x00, ON", "11 03 00 FF 41", ModbusServerID{ID: mbHex("00"), Run: ModbusRunOn, Additional: []byte("A")}},
		{"no run indicator", "11 03 41 42 43", ModbusServerID{ID: []byte("ABC")}},
		{"ID alone", "11 01 41", ModbusServerID{ID: []byte("A")}},
		{"empty", "11 00", ModbusServerID{ID: []byte{}}},
	}

	for _, tc := range tests {
		got, err := mbPDU(t, tc.pdu, ModbusResponse).ServerID()
		if err != nil || !bytes.Equal(got.ID, tc.want.ID) || got.Run != tc.want.Run || !bytes.Equal(got.Additional, tc.want.Additional) {
			t.Errorf("%s: %+v, %v; want %+v", tc.name, got, err, tc.want)
		}
	}

	if ModbusRunOn.String() != "ON" || ModbusRunOff.String() != "OFF" || ModbusRunUnknown.String() != "Unknown" {
		t.Error("run status names")
	}
}

// The views refuse PDUs of another function, direction or MEI type.
func TestModbusNoView(t *testing.T) {
	read := mbPDU(t, "03 00 6B 00 03", ModbusRequest)
	exc := mbPDU(t, "88 01", ModbusResponse)
	idReq := mbPDU(t, "11", ModbusRequest)
	devID := mbPDU(t, "2B 0E 01 00", ModbusRequest)

	for name, err := range map[string]error{
		"diagnostic of a read":       func() error { _, err := read.Diagnostic(); return err }(),
		"diagnostic of an exception": func() error { _, err := exc.Diagnostic(); return err }(),
		"server ID of a read":        func() error { _, err := read.ServerID(); return err }(),
		"server ID of a request":     func() error { _, err := idReq.ServerID(); return err }(),
		"CANopen of a read":          func() error { _, err := read.CANopen(); return err }(),
		"CANopen of a device ID":     func() error { _, err := devID.CANopen(); return err }(),
	} {
		if !errors.Is(err, ErrModbusPDUNoView) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// CANopen General Reference headers, built from the CiA 309-2 layout.
// No other decoder was available to check them against.
func TestModbusCANopen(t *testing.T) {
	// Read of 4 bytes of object 0x1018 sub-index 1 on node 5.
	p := mbPDU(t, "2B 0D 00 00 05 10 18 01 00 00 00 04", ModbusRequest)
	c, err := p.CANopen()
	want := &ModbusCANopen{NodeID: 5, Index: 0x1018, SubIndex: 1, Quantity: 4, Data: []byte{}}
	if err != nil || !reflect.DeepEqual(c, want) || c.Write() || !c.Valid() {
		t.Errorf("read: %+v, %v", c, err)
	}

	// Its response carries the four bytes.
	p = mbPDU(t, "2B 0D 00 00 05 10 18 01 00 00 00 04 DE AD BE EF", ModbusResponse)
	if c, err = p.CANopen(); err != nil || !bytes.Equal(c.Data, mbHex("DE AD BE EF")) || c.Quantity != 4 {
		t.Errorf("read response: %+v, %v", c, err)
	}

	// Every optional field: second control byte, counter, network ID,
	// encoded data; a write, in a sequence of PDUs.
	p = mbPDU(t, "2B 0D E7 AA 00 03 02 01 7F 60 40 00 00 10 00 02 11 22", ModbusRequest)
	c, err = p.CANopen()
	want = &ModbusCANopen{Control: 0xE7, Control2: 0xAA, Counter: 3, NetworkID: 2, EncodedData: 1,
		NodeID: 0x7F, Index: 0x6040, Address: 0x10, Quantity: 2, Data: mbHex("11 22")}
	if err != nil || !reflect.DeepEqual(c, want) || !c.Write() || !c.Extend() || !c.HasControl2() || !c.HasCounter() || !c.HasNetworkID() || !c.HasEncodedData() {
		t.Errorf("all options: %+v, %v", c, err)
	}

	// Values out of range decode; Valid tells.
	for _, pdu := range []string{"2B 0D 00 00 00 10 18 01 00 00 00 04", "2B 0D 00 00 80 10 18 01 00 00 00 04", "2B 0D 00 00 05 10 18 01 00 00 00 FE"} {
		if c, err = mbPDU(t, pdu, ModbusRequest).CANopen(); err != nil || c.Valid() {
			t.Errorf("%s: %+v, %v", pdu, c, err)
		}
	}

	// Every cut of the header errors, never panics.
	full := mbHex("2B 0D E7 AA 00 03 02 01 7F 60 40 00 00 10 00 02")
	for n := 2; n < len(full); n++ {
		if c, err = mbPDU(t, mbHexOf(full[:n]), ModbusRequest).CANopen(); !errors.Is(err, ErrModbusPDULength) {
			t.Errorf("cut to %d bytes: %+v, %v", n, c, err)
		}
	}
}

// mbHexOf is b as the hex string mbHex reads.
func mbHexOf(b []byte) string {
	out := ""
	for _, c := range b {
		out += mbHexByte(c) + " "
	}
	return out
}

// mbTCP builds the Modbus layer of a PDU.
func mbTCP(tid uint16, unit uint8, pdu string) *Modbus {
	b := mbHex(pdu)
	return &Modbus{MBAP: MBAP{TransactionID: tid, UnitID: unit}, FunctionCode: b[0], ReqResp: b[1:]}
}

func TestModbusTransactions(t *testing.T) {
	var tx ModbusTransactions

	// A read response gets the address of its request.
	req := mbTCP(7, 1, "03 00 6B 00 03")
	ex, err := tx.Add(req, ModbusRequest)
	if err != nil || ex.Request == nil || ex.Response != nil || tx.Pending() != 1 {
		t.Fatalf("request: %+v, %v", ex, err)
	}

	// The request is kept as a copy: its buffer may be reused.
	req.ReqResp[1] = 0xFF

	ex, err = tx.Add(mbTCP(7, 1, "03 06 02 2B 00 00 00 64"), ModbusResponse)
	addr, ok := ex.Address()
	if err != nil || ex.Request == nil || ex.TransactionID != 7 || ex.UnitID != 1 || !ok || addr != 107 || ex.Request.Quantity != 3 || len(ex.Response.Registers) != 3 || tx.Pending() != 0 {
		t.Fatalf("response: %+v, %v", ex, err)
	}

	// Answered once only.
	if ex, _ = tx.Add(mbTCP(7, 1, "03 06 02 2B 00 00 00 64"), ModbusResponse); ex.Request != nil {
		t.Error("response paired twice")
	}

	// An exception pairs with the request of its function.
	_, _ = tx.Add(mbTCP(8, 1, "01 00 13 00 13"), ModbusRequest)
	ex, err = tx.Add(mbTCP(8, 1, "81 02"), ModbusResponse)
	if addr, ok = ex.Address(); err != nil || !ex.Response.Exception || !ok || addr != 19 {
		t.Errorf("exception: %+v, %v", ex, err)
	}

	// Another unit, transaction or function is another exchange.
	_, _ = tx.Add(mbTCP(9, 1, "03 00 01 00 01"), ModbusRequest)
	for name, m := range map[string]*Modbus{"unit": mbTCP(9, 2, "03 02 00 01"), "transaction": mbTCP(10, 1, "03 02 00 01")} {
		if ex, _ = tx.Add(m, ModbusResponse); ex.Request != nil || tx.Pending() != 1 {
			t.Errorf("other %s paired", name)
		}
	}
	if ex, _ = tx.Add(mbTCP(9, 1, "04 02 00 01"), ModbusResponse); ex.Request != nil || tx.Pending() != 0 {
		t.Error("other function paired, or its request kept")
	}

	// A PDU that fails to decode is returned with its error and still
	// pairs; one without a function code is not.
	ex, err = tx.Add(mbTCP(11, 1, "03 00 01 00 00"), ModbusRequest)
	if !errors.Is(err, ErrModbusPDUQuantity) || ex == nil || tx.Pending() != 1 {
		t.Errorf("bad request: %+v, %v", ex, err)
	}
	if ex, err = tx.AddTCP(&ModbusTCP{}, ModbusRequest); !errors.Is(err, ErrModbusPDUTooShort) || ex != nil {
		t.Errorf("empty: %+v, %v", ex, err)
	}
	if ex, err = tx.AddTCP(nil, ModbusRequest); !errors.Is(err, ErrModbusPDUTooShort) || ex != nil {
		t.Errorf("nil ModbusTCP: %+v, %v", ex, err)
	}

	// The ModbusTCP layer pairs the same way.
	tcpReq := &ModbusTCP{BaseLayer: BaseLayer{Payload: mbHex("04 00 08 00 01")}, TransactionIdentifier: 20, UnitIdentifier: 3}
	tcpResp := &ModbusTCP{BaseLayer: BaseLayer{Payload: mbHex("04 02 00 0A")}, TransactionIdentifier: 20, UnitIdentifier: 3}
	_, _ = tx.AddTCP(tcpReq, ModbusRequest)
	ex, err = tx.AddTCP(tcpResp, ModbusResponse)
	if addr, ok = ex.Address(); err != nil || !ok || addr != 8 || ex.UnitID != 3 {
		t.Errorf("ModbusTCP: %+v, %v", ex, err)
	}
	if ex, err = tx.Add(nil, ModbusRequest); !errors.Is(err, ErrModbusPDUTooShort) || ex != nil {
		t.Errorf("nil: %+v, %v", ex, err)
	}

	// No address without a request, or for a function that has none.
	if _, ok = (&ModbusExchange{}).Address(); ok {
		t.Error("address without a request")
	}
	if _, ok = (&ModbusExchange{Request: mbPDU(t, "11", ModbusRequest)}).Address(); ok {
		t.Error("address of a Report Server ID")
	}
}

// Requests never answered are capped: the oldest goes first.
func TestModbusTransactionsCap(t *testing.T) {
	tx := ModbusTransactions{Max: 4}
	for id := uint16(0); id < 1000; id++ {
		if _, err := tx.Add(mbTCP(id, 1, "03 00 01 00 01"), ModbusRequest); err != nil || tx.Pending() > 4 {
			t.Fatalf("request %d: %v, %d pending", id, err, tx.Pending())
		}
	}

	for id, want := range map[uint16]bool{995: false, 996: true, 999: true} {
		ex, _ := tx.Add(mbTCP(id, 1, "03 02 00 01"), ModbusResponse)
		if (ex.Request != nil) != want {
			t.Errorf("transaction %d: paired %v", id, ex.Request != nil)
		}
	}

	// The same identifiers again replace the request, not add one.
	tx = ModbusTransactions{}
	for i := 0; i < 10; i++ {
		_, _ = tx.Add(mbTCP(1, 1, "03 00 01 00 01"), ModbusRequest)
	}
	if tx.Pending() != 1 {
		t.Errorf("%d pending", tx.Pending())
	}

	// The default cap.
	for id := 0; id < 2*ModbusMaxTransactions; id++ {
		_, _ = tx.Add(mbTCP(uint16(id), 2, "03 00 01 00 01"), ModbusRequest)
	}
	if tx.Pending() != ModbusMaxTransactions {
		t.Errorf("%d pending", tx.Pending())
	}
}

// mbDevID decodes a Read Device Identification response.
func mbDevID(t *testing.T, pdu string) *ModbusDeviceID {
	t.Helper()
	return &mbPDU(t, pdu, ModbusResponse).DeviceID
}

// A regular read answered in three responses, as the spec describes in
// section 6.21: each but the last has More Follows set and names the
// object the next request starts from.
func TestModbusDeviceInfo(t *testing.T) {
	var info ModbusDeviceInfo
	if _, _, ok := info.Next(); ok {
		t.Error("next before the first response")
	}

	first := mbDevID(t, "2B 0E 02 82 FF 02 02 00 02 41 42 01 01 43")
	if err := info.Add(first); err != nil || info.Complete {
		t.Fatalf("first: %v", err)
	}

	// Values are copies: the packet buffer may be reused.
	first.Objects[0].Value[0] = 'z'

	if code, id, ok := info.Next(); !ok || code != ModbusDevIDRegular || id != 2 {
		t.Errorf("next: %v, %v, %v", code, id, ok)
	}

	// A response that does not continue is refused and changes nothing.
	for name, pdu := range map[string]string{
		"wrong first object": "2B 0E 02 82 00 00 01 03 01 44",
		"other read code":    "2B 0E 01 82 00 00 01 02 01 44",
		"descending objects": "2B 0E 02 82 00 00 02 02 01 44 01 01 45",
		"next not forward":   "2B 0E 02 82 FF 02 01 02 01 44",
	} {
		if err := info.Add(mbDevID(t, pdu)); !errors.Is(err, ErrModbusDevIDOrder) || len(info.Objects) != 2 || info.Complete {
			t.Errorf("%s: %v, %d objects", name, err, len(info.Objects))
		}
	}

	if err := info.Add(mbDevID(t, "2B 0E 02 82 FF 04 02 02 01 44 03 01 45")); err != nil || info.Complete {
		t.Fatalf("second: %v", err)
	}
	if err := info.Add(mbDevID(t, "2B 0E 02 82 00 00 01 04 02 46 47")); err != nil || !info.Complete {
		t.Fatalf("third: %v", err)
	}

	want := []ModbusDeviceObject{{0, []byte("AB")}, {1, []byte("C")}, {2, []byte("D")}, {3, []byte("E")}, {4, []byte("FG")}}
	if !reflect.DeepEqual(info.Objects, want) || info.Conformity != 0x82 || info.ReadCode != ModbusDevIDRegular {
		t.Errorf("objects %+v", info.Objects)
	}

	if v, ok := info.Object(ModbusDevObjProductName); !ok || string(v) != "FG" {
		t.Errorf("product name %q, %v", v, ok)
	}
	if _, ok := info.Object(ModbusDevObjUserAppName); ok {
		t.Error("object never sent")
	}

	if _, _, ok := info.Next(); ok {
		t.Error("next after the last response")
	}
	if err := info.Add(first); !errors.Is(err, ErrModbusDevIDDone) {
		t.Errorf("after the last response: %v", err)
	}

	// One response is a whole read.
	var one ModbusDeviceInfo
	if err := one.Add(&mbPDU(t, mbHexOf(mbDeviceIDResp()), ModbusResponse).DeviceID); err != nil || !one.Complete || len(one.Objects) != 3 {
		t.Errorf("single response: %v, %+v", err, one)
	}
}

func TestModbusGuessDir(t *testing.T) {
	tests := []struct {
		name string
		pdu  string
		dir  ModbusDirection
		conf ModbusDirConfidence
	}{
		{"exception", "83 02", ModbusResponse, ModbusDirByShape},
		{"read holding request of 3", "03 00 6B 00 03", ModbusRequest, ModbusDirByShape},
		{"read holding response of 3 registers", "03 06 02 2B 00 00 00 64", ModbusResponse, ModbusDirByShape},
		{"write registers request", "10 00 01 00 02 04 00 0A 01 02", ModbusRequest, ModbusDirByShape},
		{"write registers response", "10 00 01 00 02", ModbusResponse, ModbusDirByShape},
		{"exception status request", "07", ModbusRequest, ModbusDirByShape},
		{"exception status response", "07 6D", ModbusResponse, ModbusDirByShape},
		{"device ID request", "2B 0E 01 00", ModbusRequest, ModbusDirByShape},
		{"FIFO response", "18 00 06 00 02 01 B8 12 84", ModbusResponse, ModbusDirByShape},

		// A read of 1 coil from address 0x0300 and a response of 3
		// bytes of coils at once.
		{"read both ways", "01 03 00 00 01", ModbusRequest, ModbusDirAmbiguous},
		{"write single register and its echo", "06 00 01 00 03", ModbusRequest, ModbusDirAmbiguous},
		{"diagnostics", "08 00 00 A5 37", ModbusRequest, ModbusDirAmbiguous},
		{"mask write", "16 00 04 00 F2 00 25", ModbusRequest, ModbusDirAmbiguous},

		{"read request, quantity 0", "03 00 00 00 00", ModbusRequest, ModbusDirUnknown},
		{"user defined function", "41 01 02", ModbusRequest, ModbusDirUnknown},
		{"empty", "", ModbusRequest, ModbusDirUnknown},
	}

	for _, tc := range tests {
		dir, conf := ModbusGuessDir(mbHex(tc.pdu))
		if dir != tc.dir || conf != tc.conf {
			t.Errorf("%s: %v, %v; want %v, %v", tc.name, dir, conf, tc.dir, tc.conf)
		}
	}

	// Ports win when exactly one is 502.
	resp := mbHex("03 06 02 2B 00 00 00 64")
	for _, tc := range []struct {
		src, dst TCPPort
		dir      ModbusDirection
		conf     ModbusDirConfidence
	}{
		{502, 49152, ModbusResponse, ModbusDirByPort},
		{49152, 502, ModbusRequest, ModbusDirByPort},
		{5020, 49152, ModbusResponse, ModbusDirByShape},
		{502, 502, ModbusResponse, ModbusDirByShape},
	} {
		if dir, conf := ModbusDirOf(tc.src, tc.dst, resp); dir != tc.dir || conf != tc.conf {
			t.Errorf("ports %d to %d: %v, %v", tc.src, tc.dst, dir, conf)
		}
	}

	if ModbusDirByShape.String() != "By Shape" || ModbusDirByPort.String() != "By Port" || ModbusDirAmbiguous.String() != "Ambiguous" || ModbusDirConfidence(9).String() != "Unknown(9)" {
		t.Error("confidence names")
	}
}

// The views and the direction guess read any prefix of any PDU, either
// way, without panicking, and never return more than the PDU holds.
func TestModbusViewsTruncated(t *testing.T) {
	pdus := [][]byte{mbHex("2B 0D E7 AA 00 03 02 01 7F 60 40 00 00 10 00 02 11 22"), mbHex("11 06 50 4D 37 31 30 FF"), mbHex("08 00 0B 01 02")}
	for _, tc := range testModbusPDUs {
		pdus = append(pdus, tc.pdu)
	}

	for _, pdu := range pdus {
		for n := 0; n <= len(pdu); n++ {
			_, _ = ModbusGuessDir(pdu[:n])
			for _, dir := range []ModbusDirection{ModbusRequest, ModbusResponse} {
				p, _ := DecodeModbusPDU(pdu[:n], dir)
				if p == nil {
					continue
				}

				_, _ = p.Diagnostic()
				id, _ := p.ServerID()
				c, _ := p.CANopen()
				if len(id.ID)+len(id.Additional) > n || c != nil && len(c.Data) > n {
					t.Fatalf("%x cut to %d: view larger than the PDU", pdu, n)
				}
			}
		}
	}
}
