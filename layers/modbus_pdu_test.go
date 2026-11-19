// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// mbHex decodes a hex string with spaces, e.g. "01 00 13".
func mbHex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// mbDeviceIDResp is a Read Device Identification response with the three
// basic objects, built as in the spec example of section 6.21.
func mbDeviceIDResp() []byte {
	pdu := mbHex("2B 0E 01 01 00 00 03")
	for i, v := range []string{"Company identification", "Product code XX", "V2.11"} {
		pdu = append(pdu, byte(i), byte(len(v)))
		pdu = append(pdu, v...)
	}
	return pdu
}

// testModbusPDUs are the examples of the Modbus Application Protocol
// Specification V1.1b3, one request and one response per function.
var testModbusPDUs = []struct {
	name string
	pdu  []byte
	dir  ModbusDirection
	want ModbusPDU
}{
	{"read coils req", mbHex("01 00 13 00 13"), ModbusRequest, ModbusPDU{Function: 0x01, Address: 19, Quantity: 19}},
	{"read coils resp", mbHex("01 03 CD 6B 05"), ModbusResponse, ModbusPDU{Function: 0x01, ByteCount: 3, Bits: mbHex("CD 6B 05")}},
	{"read inputs req", mbHex("02 00 C4 00 16"), ModbusRequest, ModbusPDU{Function: 0x02, Address: 196, Quantity: 22}},
	{"read inputs resp", mbHex("02 03 AC DB 35"), ModbusResponse, ModbusPDU{Function: 0x02, ByteCount: 3, Bits: mbHex("AC DB 35")}},
	{"read holding req", mbHex("03 00 6B 00 03"), ModbusRequest, ModbusPDU{Function: 0x03, Address: 107, Quantity: 3}},
	{"read holding resp", mbHex("03 06 02 2B 00 00 00 64"), ModbusResponse, ModbusPDU{Function: 0x03, ByteCount: 6, Registers: []uint16{555, 0, 100}}},
	{"read input regs req", mbHex("04 00 08 00 01"), ModbusRequest, ModbusPDU{Function: 0x04, Address: 8, Quantity: 1}},
	{"read input regs resp", mbHex("04 02 00 0A"), ModbusResponse, ModbusPDU{Function: 0x04, ByteCount: 2, Registers: []uint16{10}}},
	{"write coil req", mbHex("05 00 AC FF 00"), ModbusRequest, ModbusPDU{Function: 0x05, Address: 172, Value: 0xFF00}},
	{"write coil resp", mbHex("05 00 AC FF 00"), ModbusResponse, ModbusPDU{Function: 0x05, Address: 172, Value: 0xFF00}},
	{"write register req", mbHex("06 00 01 00 03"), ModbusRequest, ModbusPDU{Function: 0x06, Address: 1, Value: 3}},
	{"write register resp", mbHex("06 00 01 00 03"), ModbusResponse, ModbusPDU{Function: 0x06, Address: 1, Value: 3}},
	{"exception status req", mbHex("07"), ModbusRequest, ModbusPDU{Function: 0x07}},
	{"exception status resp", mbHex("07 6D"), ModbusResponse, ModbusPDU{Function: 0x07, Status: 0x6D}},
	{"diagnostics req", mbHex("08 00 00 A5 37"), ModbusRequest, ModbusPDU{Function: 0x08, SubFunction: ModbusDiagReturnQueryData, Data: mbHex("A5 37")}},
	{"diagnostics resp", mbHex("08 00 00 A5 37"), ModbusResponse, ModbusPDU{Function: 0x08, SubFunction: ModbusDiagReturnQueryData, Data: mbHex("A5 37")}},
	{"event counter req", mbHex("0B"), ModbusRequest, ModbusPDU{Function: 0x0B}},
	{"event counter resp", mbHex("0B FF FF 01 08"), ModbusResponse, ModbusPDU{Function: 0x0B, Status: 0xFFFF, EventCount: 264}},
	{"event log req", mbHex("0C"), ModbusRequest, ModbusPDU{Function: 0x0C}},
	{"event log resp", mbHex("0C 08 00 00 01 08 01 21 20 00"), ModbusResponse, ModbusPDU{Function: 0x0C, ByteCount: 8, EventCount: 264, MessageCount: 289, Events: mbHex("20 00")}},
	{"write coils req", mbHex("0F 00 13 00 0A 02 CD 01"), ModbusRequest, ModbusPDU{Function: 0x0F, Address: 19, Quantity: 10, ByteCount: 2, Bits: mbHex("CD 01")}},
	{"write coils resp", mbHex("0F 00 13 00 0A"), ModbusResponse, ModbusPDU{Function: 0x0F, Address: 19, Quantity: 10}},
	{"write registers req", mbHex("10 00 01 00 02 04 00 0A 01 02"), ModbusRequest, ModbusPDU{Function: 0x10, Address: 1, Quantity: 2, ByteCount: 4, Registers: []uint16{10, 258}}},
	{"write registers resp", mbHex("10 00 01 00 02"), ModbusResponse, ModbusPDU{Function: 0x10, Address: 1, Quantity: 2}},
	{"server ID req", mbHex("11"), ModbusRequest, ModbusPDU{Function: 0x11}},
	{"server ID resp", mbHex("11 03 42 FF 01"), ModbusResponse, ModbusPDU{Function: 0x11, ByteCount: 3, Data: mbHex("42 FF 01")}},
	{"read file req", mbHex("14 0E 06 00 04 00 01 00 02 06 00 03 00 09 00 02"), ModbusRequest, ModbusPDU{Function: 0x14, ByteCount: 14, FileRecords: []ModbusFileRecord{
		{RefType: 6, FileNumber: 4, RecordNumber: 1, RecordLength: 2},
		{RefType: 6, FileNumber: 3, RecordNumber: 9, RecordLength: 2},
	}}},
	{"read file resp", mbHex("14 0C 05 06 0D FE 00 20 05 06 33 CD 00 40"), ModbusResponse, ModbusPDU{Function: 0x14, ByteCount: 12, FileRecords: []ModbusFileRecord{
		{RefType: 6, RecordLength: 2, Data: mbHex("0D FE 00 20")},
		{RefType: 6, RecordLength: 2, Data: mbHex("33 CD 00 40")},
	}}},
	{"write file req", mbHex("15 0D 06 00 04 00 07 00 03 06 AF 04 BE 10 0D"), ModbusRequest, ModbusPDU{Function: 0x15, ByteCount: 13, FileRecords: []ModbusFileRecord{
		{RefType: 6, FileNumber: 4, RecordNumber: 7, RecordLength: 3, Data: mbHex("06 AF 04 BE 10 0D")},
	}}},
	{"write file resp", mbHex("15 0D 06 00 04 00 07 00 03 06 AF 04 BE 10 0D"), ModbusResponse, ModbusPDU{Function: 0x15, ByteCount: 13, FileRecords: []ModbusFileRecord{
		{RefType: 6, FileNumber: 4, RecordNumber: 7, RecordLength: 3, Data: mbHex("06 AF 04 BE 10 0D")},
	}}},
	{"mask write req", mbHex("16 00 04 00 F2 00 25"), ModbusRequest, ModbusPDU{Function: 0x16, Address: 4, AndMask: 0xF2, OrMask: 0x25}},
	{"mask write resp", mbHex("16 00 04 00 F2 00 25"), ModbusResponse, ModbusPDU{Function: 0x16, Address: 4, AndMask: 0xF2, OrMask: 0x25}},
	{"read/write req", mbHex("17 00 03 00 06 00 0E 00 03 06 00 FF 00 FF 00 FF"), ModbusRequest, ModbusPDU{Function: 0x17, Address: 3, Quantity: 6, WriteAddress: 14, WriteQuantity: 3, ByteCount: 6, Registers: []uint16{255, 255, 255}}},
	{"read/write resp", mbHex("17 0C 00 FE 0A CD 00 01 00 03 00 0D 00 FF"), ModbusResponse, ModbusPDU{Function: 0x17, ByteCount: 12, Registers: []uint16{254, 2765, 1, 3, 13, 255}}},
	{"FIFO req", mbHex("18 04 DE"), ModbusRequest, ModbusPDU{Function: 0x18, Address: 1246}},
	{"FIFO resp", mbHex("18 00 06 00 02 01 B8 12 84"), ModbusResponse, ModbusPDU{Function: 0x18, ByteCount: 6, FIFOCount: 2, Registers: []uint16{440, 4740}}},
	{"device ID req", mbHex("2B 0E 01 00"), ModbusRequest, ModbusPDU{Function: 0x2B, MEIType: ModbusMEIDeviceID, DeviceID: ModbusDeviceID{ReadCode: ModbusDevIDBasic}}},
	{"device ID resp", mbDeviceIDResp(), ModbusResponse, ModbusPDU{Function: 0x2B, MEIType: ModbusMEIDeviceID, DeviceID: ModbusDeviceID{
		ReadCode: ModbusDevIDBasic, Conformity: 1, NumObjects: 3,
		Objects: []ModbusDeviceObject{
			{ID: ModbusDevObjVendorName, Value: []byte("Company identification")},
			{ID: ModbusDevObjProductCode, Value: []byte("Product code XX")},
			{ID: ModbusDevObjRevision, Value: []byte("V2.11")},
		},
	}}},
	{"device ID resp more follows", mbHex("2B 0E 02 02 FF 05 00"), ModbusResponse, ModbusPDU{Function: 0x2B, MEIType: ModbusMEIDeviceID, DeviceID: ModbusDeviceID{
		ReadCode: ModbusDevIDRegular, Conformity: 2, MoreFollows: true, NextObjectID: ModbusDevObjModelName, Objects: []ModbusDeviceObject{},
	}}},
	{"CANopen req", mbHex("2B 0D 01 02 03"), ModbusRequest, ModbusPDU{Function: 0x2B, MEIType: ModbusMEICANopen, Data: mbHex("01 02 03")}},
	{"exception", mbHex("81 02"), ModbusResponse, ModbusPDU{Function: 0x01, Exception: true, ExceptionCode: ModbusExceptionIllegalDataAddress}},
	{"exception of unknown function", mbHex("C1 01"), ModbusResponse, ModbusPDU{Function: 0x41, Exception: true, ExceptionCode: ModbusExceptionIllegalFunction}},
	{"user defined function", mbHex("41 01 02 03"), ModbusRequest, ModbusPDU{Function: 0x41, Data: mbHex("01 02 03")}},
}

func TestModbusPDU(t *testing.T) {
	for _, tc := range testModbusPDUs {
		got, err := DecodeModbusPDU(tc.pdu, tc.dir)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}

		tc.want.Direction = tc.dir
		if !reflect.DeepEqual(*got, tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.name, *got, tc.want)
		}
	}
}

func TestModbusDecodePDU(t *testing.T) {
	// Through the Modbus layer: the Read Coils request of modbus_test.go.
	p := gopacket.NewPacket(testPacketModbusReadCoils, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
	m := p.Layer(LayerTypeModbus).(*Modbus)
	tcp := p.Layer(LayerTypeTCP).(*TCP)

	dir := ModbusDirFromPorts(tcp.SrcPort, tcp.DstPort)
	if dir != ModbusRequest {
		t.Errorf("direction %v, want request", dir)
	}

	pdu, err := m.DecodePDU(dir)
	if err != nil || pdu.Function != ModbusFuncCodeReadCoils || pdu.Address != 2 || pdu.Quantity != 2 {
		t.Errorf("PDU %+v, err %v", pdu, err)
	}

	// The exception response of modbus_test.go.
	p = gopacket.NewPacket(testPacketModbusExceptionResponse, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
	m = p.Layer(LayerTypeModbus).(*Modbus)
	tcp = p.Layer(LayerTypeTCP).(*TCP)
	pdu, err = m.DecodePDU(ModbusDirFromPorts(tcp.SrcPort, tcp.DstPort))
	if err != nil || !pdu.Exception || pdu.Function != ModbusFuncCodeDiagnostics || pdu.ExceptionCode != ModbusExceptionGatewayTargetDeviceFailedToRespond || pdu.Direction != ModbusResponse {
		t.Errorf("PDU %+v, err %v", pdu, err)
	}

	// ModbusTCP payload is a whole PDU.
	var mt ModbusTCP
	if err := mt.DecodeFromBytes(mbHex("00 01 00 00 00 06 0A 03 00 6B 00 03"), gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}

	pdu, err = DecodeModbusPDU(mt.Payload(), ModbusRequest)
	if err != nil || pdu.Address != 107 || pdu.Quantity != 3 {
		t.Errorf("PDU %+v, err %v", pdu, err)
	}
}

func TestModbusDirFromPorts(t *testing.T) {
	tests := []struct {
		src, dst TCPPort
		want     ModbusDirection
	}{
		{50000, 502, ModbusRequest},
		{502, 50000, ModbusResponse},
		{502, 502, ModbusRequest},
		{1000, 2000, ModbusRequest},
	}

	for _, tc := range tests {
		if got := ModbusDirFromPorts(tc.src, tc.dst); got != tc.want {
			t.Errorf("%d->%d: %v, want %v", tc.src, tc.dst, got, tc.want)
		}
	}
}

func TestModbusPDUErrors(t *testing.T) {
	tests := []struct {
		name string
		pdu  string
		dir  ModbusDirection
		err  error
	}{
		{"no function code", "", ModbusRequest, ErrModbusPDUTooShort},
		{"read coils qty 0", "01 00 00 00 00", ModbusRequest, ErrModbusPDUQuantity},
		{"read coils qty 2001", "01 00 00 07 D1", ModbusRequest, ErrModbusPDUQuantity},
		{"read holding qty 126", "03 00 00 00 7E", ModbusRequest, ErrModbusPDUQuantity},
		{"read req cut", "03 00 00 00", ModbusRequest, ErrModbusPDULength},
		{"read req trailing", "03 00 00 00 01 00", ModbusRequest, ErrModbusPDUTrailing},
		{"read bits count lies", "01 05 CD 6B", ModbusResponse, ErrModbusPDUByteCount},
		{"read bits count 0", "01 00", ModbusResponse, ErrModbusPDUByteCount},
		{"read regs odd count", "03 03 00 01 02", ModbusResponse, ErrModbusPDUByteCount},
		{"read regs count 252", "03 FC" + strings.Repeat(" 00", 252), ModbusResponse, ErrModbusPDUByteCount},
		{"coil value", "05 00 01 12 34", ModbusRequest, ErrModbusPDUValue},
		{"exception cut", "81", ModbusResponse, ErrModbusPDULength},
		{"exception trailing", "81 02 00", ModbusResponse, ErrModbusPDUTrailing},
		{"no-data request trailing", "0B 00", ModbusRequest, ErrModbusPDUTrailing},
		{"diagnostics cut", "08 00", ModbusRequest, ErrModbusPDULength},
		{"event log short", "0C 05 00 00 00 00 00", ModbusResponse, ErrModbusPDUByteCount},
		{"event log too many events", "0C 47" + strings.Repeat(" 00", 0x47), ModbusResponse, ErrModbusPDUByteCount},
		{"write coils qty 1969", "0F 00 00 07 B1 F7" + strings.Repeat(" 00", 0xF7), ModbusRequest, ErrModbusPDUQuantity},
		{"write coils count mismatch", "0F 00 13 00 0A 01 CD", ModbusRequest, ErrModbusPDUByteCount},
		{"write coils count lies", "0F 00 13 00 0A 02 CD", ModbusRequest, ErrModbusPDUByteCount},
		{"write regs qty 124", "10 00 00 00 7C F8" + strings.Repeat(" 00", 0xF8), ModbusRequest, ErrModbusPDUQuantity},
		{"write regs count mismatch", "10 00 01 00 02 02 00 0A", ModbusRequest, ErrModbusPDUByteCount},
		{"write multi resp qty 0", "10 00 01 00 00", ModbusResponse, ErrModbusPDUQuantity},
		{"server ID count lies", "11 05 01", ModbusResponse, ErrModbusPDUByteCount},
		{"read file count below 7", "14 06 06 00 04 00 01 00", ModbusRequest, ErrModbusPDUByteCount},
		{"read file partial sub-request", "14 08 06 00 04 00 01 00 02 06", ModbusRequest, ErrModbusPDUByteCount},
		{"read file ref type", "14 07 05 00 04 00 01 00 02", ModbusRequest, ErrModbusPDUValue},
		{"read file record number", "14 07 06 00 04 27 10 00 02", ModbusRequest, ErrModbusPDUValue},
		{"read file number 0", "14 07 06 00 00 00 01 00 02", ModbusRequest, ErrModbusPDUValue},
		{"read file resp sub length lies", "14 04 09 06 00 01", ModbusResponse, ErrModbusPDUByteCount},
		{"read file resp sub length even", "14 03 02 06 00", ModbusResponse, ErrModbusPDUByteCount},
		{"read file resp header cut", "14 05 03 06 00 01 05", ModbusResponse, ErrModbusPDULength},
		{"read file resp below one register", "14 01 03", ModbusResponse, ErrModbusPDUByteCount},
		{"read file resp sub length 1", "14 04 01 06 00 01", ModbusResponse, ErrModbusPDUByteCount},
		{"read file record length 0", "14 07 06 00 04 00 01 00 00", ModbusRequest, ErrModbusPDUQuantity},
		{"read file past record 9999", "14 07 06 00 04 27 0F 00 02", ModbusRequest, ErrModbusPDUQuantity},
		{"read file response would not fit", "14 0E 06 00 04 00 01 00 3D 06 00 03 00 09 00 3D", ModbusRequest, ErrModbusPDUQuantity},
		{"write file record past data", "15 09 06 00 04 00 07 00 03 06 AF", ModbusRequest, ErrModbusPDUByteCount},
		{"write file sub-request cut", "15 0B 06 00 04 00 07 00 01 06 AF 06 00", ModbusRequest, ErrModbusPDULength},
		{"write file record length 0", "15 09 06 00 04 00 07 00 00 06 AF", ModbusRequest, ErrModbusPDUQuantity},
		{"write file past record 9999", "15 0D 06 00 04 27 0E 00 03 06 AF 04 BE 10 0D", ModbusRequest, ErrModbusPDUQuantity},
		{"write file number 0", "15 09 06 00 00 00 07 00 01 06 AF", ModbusRequest, ErrModbusPDUValue},
		{"mask write cut", "16 00 04 00 F2", ModbusRequest, ErrModbusPDULength},
		{"read/write write qty 122", "17 00 03 00 06 00 0E 00 7A F4" + strings.Repeat(" 00", 0xF4), ModbusRequest, ErrModbusPDUQuantity},
		{"read/write count mismatch", "17 00 03 00 06 00 0E 00 03 04 00 FF 00 FF", ModbusRequest, ErrModbusPDUByteCount},
		{"FIFO count 32", "18 00 42 00 20" + strings.Repeat(" 00", 64), ModbusResponse, ErrModbusPDUQuantity},
		{"FIFO byte count lies", "18 00 08 00 02 01 B8 12 84", ModbusResponse, ErrModbusPDUByteCount},
		{"MEI cut", "2B", ModbusRequest, ErrModbusPDULength},
		{"device ID code 5", "2B 0E 05 00", ModbusRequest, ErrModbusPDUValue},
		{"device ID req trailing", "2B 0E 03 01 00", ModbusRequest, ErrModbusPDUTrailing},
		{"device ID more follows 01", "2B 0E 01 01 01 00 00", ModbusResponse, ErrModbusPDUValue},
		{"device ID object past data", "2B 0E 01 01 00 00 01 00 09 41", ModbusResponse, ErrModbusPDULength},
		{"device ID claims 255 objects", "2B 0E 01 01 00 00 FF 00 01 41", ModbusResponse, ErrModbusPDULength},
		{"device ID trailing", "2B 0E 01 01 00 00 01 00 01 41 42", ModbusResponse, ErrModbusPDUTrailing},
	}

	for _, tc := range tests {
		_, err := DecodeModbusPDU(mbHex(tc.pdu), tc.dir)
		if !errors.Is(err, tc.err) {
			t.Errorf("%s: error %v, want %v", tc.name, err, tc.err)
		}
	}
}

func TestModbusPDUPartial(t *testing.T) {
	// A fault after the fixed fields still returns them, e.g. the device
	// ID request of modbus-2.pcap frame 32 with a stray trailing byte.
	pdu, err := DecodeModbusPDU(mbHex("2B 0E 03 01 00"), ModbusRequest)
	if !errors.Is(err, ErrModbusPDUTrailing) || pdu.DeviceID.ReadCode != ModbusDevIDExtended || pdu.DeviceID.ObjectID != ModbusDevObjProductCode {
		t.Errorf("PDU %+v, err %v", pdu, err)
	}

	// A read with quantity 0 keeps its address.
	pdu, err = DecodeModbusPDU(mbHex("03 00 2A 00 00"), ModbusRequest)
	if !errors.Is(err, ErrModbusPDUQuantity) || pdu.Address != 42 {
		t.Errorf("PDU %+v, err %v", pdu, err)
	}
}

func TestModbusPDUTruncated(t *testing.T) {
	// Every prefix of every valid PDU decodes without panicking.
	for _, tc := range testModbusPDUs {
		for i := 0; i <= len(tc.pdu); i++ {
			_, _ = DecodeModbusPDU(tc.pdu[:i], tc.dir)
			_, _ = DecodeModbusPDU(tc.pdu[:i], 1-tc.dir)
		}
	}
}

func TestModbusPDUBit(t *testing.T) {
	// Spec example: coils 27..20 = CD, so coil 20 (bit 0) is on, 21 off.
	pdu, _ := DecodeModbusPDU(mbHex("01 03 CD 6B 05"), ModbusResponse)
	want := []bool{true, false, true, true, false, false, true, true, true, true}
	for i, w := range want {
		if pdu.Bit(i) != w {
			t.Errorf("bit %d = %v, want %v", i, pdu.Bit(i), w)
		}
	}

	if pdu.Bit(-1) || pdu.Bit(24) {
		t.Error("Bit out of range is not false")
	}
}

func TestModbusPDUStrings(t *testing.T) {
	tests := []struct {
		got, want string
	}{
		{ModbusRequest.String(), "Request"},
		{ModbusDirection(7).String(), "Unknown(7)"},
		{ModbusDiagServerBusyCount.String(), "Return Server Busy Count"},
		{ModbusDiagCode(0x99).String(), "Reserved(0x0099)"},
		{ModbusMEIDeviceID.String(), "Read Device Identification"},
		{ModbusDevIDSpecific.String(), "Specific"},
		{ModbusDevObjUserAppName.String(), "UserApplicationName"},
		{ModbusDevObjectID(0x80).String(), "Object(0x80)"},
	}

	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}

// testModbusPcapErrors counts, per pcap, the PDUs that fail to decode and
// why. All other PDUs decode cleanly. tshark 4.7 accepts the ones it
// decodes except the two modbus-3.pcap mask write and read/write requests
// that are cut short, which it marks malformed. modbus-3.pcap comes from a
// scanner that sends zero quantities and stray bytes, which the spec does
// not allow.
var testModbusPcapErrors = map[string]map[error]int{
	"testdata/modbus.pcap": {},
	"testdata/modbus-2.pcap": {
		// Frames 32, 34: device ID request plus one byte. Frames 91 to
		// 99: exception 0x81 code 06 plus one byte, on a connection
		// opened from port 502 that tshark does not decode as Modbus.
		ErrModbusPDUTrailing: 7,
	},
	"testdata/modbus-3.pcap": {
		ErrModbusPDUQuantity:  6,
		ErrModbusPDUTrailing:  5,
		ErrModbusPDUByteCount: 2,
		ErrModbusPDULength:    2,
	},
}

func TestModbusPDUPcap(t *testing.T) {
	sentinels := []error{ErrModbusPDUTooShort, ErrModbusPDULength, ErrModbusPDUByteCount, ErrModbusPDUQuantity, ErrModbusPDUValue, ErrModbusPDUTrailing}
	for path, want := range testModbusPcapErrors {
		got := map[error]int{}
		decoded := 0
		for _, data := range mbReadPcap(t, path) {
			p := gopacket.NewPacket(data, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
			tcp, ok := p.Layer(LayerTypeTCP).(*TCP)
			if !ok {
				continue
			}

			for _, l := range p.Layers() {
				m, ok := l.(*Modbus)
				if !ok {
					continue
				}

				_, err := m.DecodePDU(ModbusDirFromPorts(tcp.SrcPort, tcp.DstPort))
				if err == nil {
					decoded++
					continue
				}

				for _, s := range sentinels {
					if errors.Is(err, s) {
						got[s]++
					}
				}
			}
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: errors %v, want %v", path, got, want)
		}

		if decoded == 0 {
			t.Errorf("%s: nothing decoded", path)
		}
	}
}

func TestModbusPDUPcapValues(t *testing.T) {
	// Spot checks against tshark 4.7 field values.
	tests := []struct {
		path  string
		frame int
		check func(p *ModbusPDU) bool
	}{
		// Read Holding Registers request: reference 1, word count 1.
		{"testdata/modbus.pcap", 1, func(p *ModbusPDU) bool { return p.Address == 1 && p.Quantity == 1 }},
		// Its response: byte count 2, register value 0.
		{"testdata/modbus.pcap", 2, func(p *ModbusPDU) bool { return p.ByteCount == 2 && reflect.DeepEqual(p.Registers, []uint16{0}) }},
		// Diagnostics sub-function 4, then exception 11.
		{"testdata/modbus-2.pcap", 8, func(p *ModbusPDU) bool { return p.SubFunction == ModbusDiagForceListenOnly }},
		{"testdata/modbus-2.pcap", 9, func(p *ModbusPDU) bool { return p.Exception && p.ExceptionCode == 11 }},
		// Report Server ID: byte count 18, ID 0x00, run indicator ON.
		{"testdata/modbus-2.pcap", 41, func(p *ModbusPDU) bool {
			return p.ByteCount == 18 && p.Data[1] == 0xFF && string(p.Data[2:]) == "Wingpath Limited"
		}},
		// Read Holding Registers response: values 9, 24.
		{"testdata/modbus-2.pcap", 58, func(p *ModbusPDU) bool { return reflect.DeepEqual(p.Registers, []uint16{9, 24}) }},
		// Write Single Register: address 5, value 11.
		{"testdata/modbus-2.pcap", 66, func(p *ModbusPDU) bool { return p.Address == 5 && p.Value == 11 }},
		// Scanner: exception 1 for function 0, exception 3 for function 1.
		{"testdata/modbus-3.pcap", 9, func(p *ModbusPDU) bool { return p.Function == 0 && p.ExceptionCode == 1 }},
		{"testdata/modbus-3.pcap", 13, func(p *ModbusPDU) bool { return p.Function == 1 && p.ExceptionCode == 3 }},
	}

	packets := map[string][][]byte{}
	for _, tc := range tests {
		if packets[tc.path] == nil {
			packets[tc.path] = mbReadPcap(t, tc.path)
		}

		p := gopacket.NewPacket(packets[tc.path][tc.frame-1], LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
		m := p.Layer(LayerTypeModbus).(*Modbus)
		tcp := p.Layer(LayerTypeTCP).(*TCP)
		pdu, err := m.DecodePDU(ModbusDirFromPorts(tcp.SrcPort, tcp.DstPort))
		if err != nil || !tc.check(pdu) {
			t.Errorf("%s frame %d: %+v, err %v", tc.path, tc.frame, pdu, err)
		}
	}
}

// mbReadPcap returns every packet of a pcap in testdata.
func mbReadPcap(t testing.TB, path string) [][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	r, err := newSimplePcapReader(f)
	if err != nil {
		t.Fatal(err)
	}

	var out [][]byte
	for {
		data, err := r.readPacketData()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, data)
	}
}

func FuzzModbusPDU(f *testing.F) {
	for _, tc := range testModbusPDUs {
		f.Add(tc.pdu, uint8(tc.dir))
	}

	f.Fuzz(func(t *testing.T, pdu []byte, dir uint8) {
		p, err := DecodeModbusPDU(pdu, ModbusDirection(dir%2))
		if p == nil {
			if err == nil {
				t.Fatal("nil PDU without an error")
			}
			return
		}

		// The views and the guess read the same bytes: none may panic.
		_, _ = p.Diagnostic()
		_, _ = p.ServerID()
		if c, _ := p.CANopen(); c != nil {
			_ = c.Valid()
			if len(c.Data) > len(pdu) {
				t.Fatalf("CANopen data of %d bytes in a PDU of %d", len(c.Data), len(pdu))
			}
		}
		_, _ = ModbusGuessDir(pdu)

		var info ModbusDeviceInfo
		_ = info.Add(&p.DeviceID)
		_ = info.Add(&p.DeviceID)
		if len(info.Objects) > len(p.DeviceID.Objects) {
			t.Fatalf("%d objects joined from %d", len(info.Objects), len(p.DeviceID.Objects))
		}

		// Nothing decoded may claim more than the PDU holds.
		if len(p.Bits) > len(pdu) || 2*len(p.Registers) > len(pdu) || len(p.Data) > len(pdu) || len(p.FileRecords) > len(pdu) || len(p.DeviceID.Objects) > len(pdu) {
			t.Fatalf("PDU %+v larger than its %d bytes", p, len(pdu))
		}
	})
}
