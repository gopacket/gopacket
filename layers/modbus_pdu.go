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
)

// Modbus PDU decoding: the function specific data that follows the function
// code, per the Modbus Application Protocol Specification V1.1b3.
//
//	+---------------+------------------------------------+
//	| function code | data (layout set by code+direction) |
//	+---------------+------------------------------------+
//
// The same function code has a different data layout in a request and in a
// response, and nothing in the PDU says which one it is, so the caller passes
// a ModbusDirection. This file leaves the Modbus layer itself untouched: a
// caller asks for the PDU with Modbus.DecodePDU or DecodeModbusPDU.

// Spec limits and sizes used to check a PDU.
const (
	modbusAddrQtyLen     = 4      // address + quantity (or value), 2 bytes each
	modbusMaskWriteLen   = 6      // address + AND mask + OR mask
	modbusRWHeaderLen    = 9      // read addr/qty, write addr/qty, byte count
	modbusWriteMultiHdr  = 5      // address + quantity + byte count
	modbusFIFOHeaderLen  = 4      // FIFO byte count + FIFO count
	modbusEventLogHdr    = 6      // status + event count + message count
	modbusMaxReadBits    = 2000   // 0x07D0, read coils / discrete inputs
	modbusMaxReadRegs    = 125    // 0x007D, read holding / input registers
	modbusMaxWriteBits   = 1968   // 0x07B0, write multiple coils
	modbusMaxWriteRegs   = 123    // 0x007B, write multiple registers
	modbusMaxRWWriteRegs = 121    // 0x0079, write part of read/write multiple
	modbusMaxBitBytes    = 250    // 2000 coils packed 8 per byte
	modbusMaxRegBytes    = 250    // 125 registers of 2 bytes
	modbusMaxFIFOCount   = 31     // registers in a FIFO queue
	modbusMaxEvents      = 64     // bytes of events in a comm event log
	modbusCoilOn         = 0xFF00 // write single coil ON
	modbusCoilOff        = 0x0000 // write single coil OFF
	modbusFileRefType    = 6      // only reference type defined for files
	modbusFileSubReqLen  = 7      // ref type + file + record + length
	modbusFileSubRespHdr = 2      // file response length + ref type
	modbusMinFileReadLen = 0x07   // read file record request byte count
	modbusMaxFileReadLen = 0xF5
	modbusMinFileWrite   = 0x09 // write file record request data length
	modbusMaxFileWrite   = 0xFB
	modbusMaxRecordNum   = 0x270F
	modbusFileRecords    = 10000 // records of a file, numbered 0 to 9999
	modbusMinFileResp    = 4     // one sub-response of one register
	modbusMinSubResp     = 3     // ref type + one register
	modbusDevIDReqLen    = 2     // read device ID code + object ID
	modbusDevIDRespHdr   = 5     // code, conformity, more, next, number
	modbusDevObjHdrLen   = 2     // object ID + object length
	modbusMoreFollows    = 0xFF  // device ID response continues
	modbusNoMoreFollows  = 0x00
	modbusBitsPerByte    = 8
	modbusRegisterLen    = 2
)

// Errors returned by Modbus PDU decoding. Each is wrapped with detail, so
// test for them with errors.Is.
var (
	ErrModbusPDUTooShort  = errors.New("modbus PDU has no function code")
	ErrModbusPDULength    = errors.New("modbus PDU length does not fit its function")
	ErrModbusPDUByteCount = errors.New("modbus PDU byte count does not match its data")
	ErrModbusPDUQuantity  = errors.New("modbus PDU quantity out of range")
	ErrModbusPDUValue     = errors.New("modbus PDU field value not allowed")
	ErrModbusPDUTrailing  = errors.New("modbus PDU has bytes past its function data")
)

// ModbusDirection says whether a PDU is a request (client to server) or a
// response. A PDU does not carry this itself.
type ModbusDirection uint8

// ModbusDirection values.
const (
	ModbusRequest ModbusDirection = iota
	ModbusResponse
)

// String returns the direction name.
func (d ModbusDirection) String() string {
	switch d {
	case ModbusRequest:
		return "Request"
	case ModbusResponse:
		return "Response"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(d))
	}
}

// ModbusDirFromPorts infers the direction of a Modbus/TCP PDU from its TCP
// ports: a PDU sent from port 502 is a response, anything else (normally
// sent to port 502) is a request.
func ModbusDirFromPorts(src, dst TCPPort) ModbusDirection {
	if src == TCPPort(ModbusPort) && dst != TCPPort(ModbusPort) {
		return ModbusResponse
	}
	return ModbusRequest
}

// ModbusDiagCode is the sub-function code of a Diagnostics (0x08) PDU.
type ModbusDiagCode uint16

// ModbusDiagCode values from the spec, section 6.8.1.
const (
	ModbusDiagReturnQueryData      ModbusDiagCode = 0x00
	ModbusDiagRestartComm          ModbusDiagCode = 0x01
	ModbusDiagReturnDiagRegister   ModbusDiagCode = 0x02
	ModbusDiagChangeASCIIDelimiter ModbusDiagCode = 0x03
	ModbusDiagForceListenOnly      ModbusDiagCode = 0x04
	ModbusDiagClearCounters        ModbusDiagCode = 0x0A
	ModbusDiagBusMessageCount      ModbusDiagCode = 0x0B
	ModbusDiagBusCommErrorCount    ModbusDiagCode = 0x0C
	ModbusDiagBusExceptionCount    ModbusDiagCode = 0x0D
	ModbusDiagServerMessageCount   ModbusDiagCode = 0x0E
	ModbusDiagServerNoRespCount    ModbusDiagCode = 0x0F
	ModbusDiagServerNAKCount       ModbusDiagCode = 0x10
	ModbusDiagServerBusyCount      ModbusDiagCode = 0x11
	ModbusDiagBusCharOverrunCount  ModbusDiagCode = 0x12
	ModbusDiagClearOverrun         ModbusDiagCode = 0x14
)

// String returns the sub-function name.
func (c ModbusDiagCode) String() string {
	switch c {
	case ModbusDiagReturnQueryData:
		return "Return Query Data"
	case ModbusDiagRestartComm:
		return "Restart Communications Option"
	case ModbusDiagReturnDiagRegister:
		return "Return Diagnostic Register"
	case ModbusDiagChangeASCIIDelimiter:
		return "Change ASCII Input Delimiter"
	case ModbusDiagForceListenOnly:
		return "Force Listen Only Mode"
	case ModbusDiagClearCounters:
		return "Clear Counters and Diagnostic Register"
	case ModbusDiagBusMessageCount:
		return "Return Bus Message Count"
	case ModbusDiagBusCommErrorCount:
		return "Return Bus Communication Error Count"
	case ModbusDiagBusExceptionCount:
		return "Return Bus Exception Error Count"
	case ModbusDiagServerMessageCount:
		return "Return Server Message Count"
	case ModbusDiagServerNoRespCount:
		return "Return Server No Response Count"
	case ModbusDiagServerNAKCount:
		return "Return Server NAK Count"
	case ModbusDiagServerBusyCount:
		return "Return Server Busy Count"
	case ModbusDiagBusCharOverrunCount:
		return "Return Bus Character Overrun Count"
	case ModbusDiagClearOverrun:
		return "Clear Overrun Counter and Flag"
	default:
		return fmt.Sprintf("Reserved(0x%04X)", uint16(c))
	}
}

// ModbusMEIType is the MEI type of an Encapsulated Interface Transport
// (0x2B) PDU.
type ModbusMEIType uint8

// ModbusMEIType values.
const (
	ModbusMEICANopen  ModbusMEIType = 0x0D // CANopen General Reference
	ModbusMEIDeviceID ModbusMEIType = 0x0E // Read Device Identification
)

// String returns the MEI type name.
func (t ModbusMEIType) String() string {
	switch t {
	case ModbusMEICANopen:
		return "CANopen General Reference"
	case ModbusMEIDeviceID:
		return "Read Device Identification"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(t))
	}
}

// ModbusDevIDCode is the Read Device ID code of a Read Device
// Identification PDU: which category of objects is asked for.
type ModbusDevIDCode uint8

// ModbusDevIDCode values.
const (
	ModbusDevIDBasic    ModbusDevIDCode = 0x01 // stream access, basic objects
	ModbusDevIDRegular  ModbusDevIDCode = 0x02 // stream access, regular objects
	ModbusDevIDExtended ModbusDevIDCode = 0x03 // stream access, extended objects
	ModbusDevIDSpecific ModbusDevIDCode = 0x04 // one specific object
)

// String returns the read device ID code name.
func (c ModbusDevIDCode) String() string {
	switch c {
	case ModbusDevIDBasic:
		return "Basic"
	case ModbusDevIDRegular:
		return "Regular"
	case ModbusDevIDExtended:
		return "Extended"
	case ModbusDevIDSpecific:
		return "Specific"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(c))
	}
}

// ModbusDevObjectID identifies one device identification object.
type ModbusDevObjectID uint8

// ModbusDevObjectID values for the basic and regular objects.
const (
	ModbusDevObjVendorName  ModbusDevObjectID = 0x00
	ModbusDevObjProductCode ModbusDevObjectID = 0x01
	ModbusDevObjRevision    ModbusDevObjectID = 0x02
	ModbusDevObjVendorURL   ModbusDevObjectID = 0x03
	ModbusDevObjProductName ModbusDevObjectID = 0x04
	ModbusDevObjModelName   ModbusDevObjectID = 0x05
	ModbusDevObjUserAppName ModbusDevObjectID = 0x06
)

// String returns the object name.
func (o ModbusDevObjectID) String() string {
	switch o {
	case ModbusDevObjVendorName:
		return "VendorName"
	case ModbusDevObjProductCode:
		return "ProductCode"
	case ModbusDevObjRevision:
		return "MajorMinorRevision"
	case ModbusDevObjVendorURL:
		return "VendorUrl"
	case ModbusDevObjProductName:
		return "ProductName"
	case ModbusDevObjModelName:
		return "ModelName"
	case ModbusDevObjUserAppName:
		return "UserApplicationName"
	default:
		return fmt.Sprintf("Object(0x%02X)", uint8(o))
	}
}

// ModbusFileRecord is one sub-request or sub-response of a Read File Record
// (0x14) or Write File Record (0x15) PDU.
type ModbusFileRecord struct {
	RefType      uint8
	FileNumber   uint16 // not present in a read response
	RecordNumber uint16 // not present in a read response
	RecordLength uint16 // in registers
	Data         []byte // record registers, big endian; empty in a read request
}

// ModbusDeviceObject is one object of a Read Device Identification response.
type ModbusDeviceObject struct {
	ID    ModbusDevObjectID
	Value []byte
}

// ModbusDeviceID holds a Read Device Identification (MEI 0x0E) PDU.
type ModbusDeviceID struct {
	ReadCode     ModbusDevIDCode
	ObjectID     ModbusDevObjectID // request: first object to read
	Conformity   uint8             // response: conformity level
	MoreFollows  bool              // response: another transaction is needed
	NextObjectID ModbusDevObjectID // response: object to ask for next
	NumObjects   uint8             // response: object count field
	Objects      []ModbusDeviceObject
}

// ModbusPDU is a decoded Modbus PDU. Which fields are set depends on the
// function code and the direction:
//
//	0x01,0x02 req: Address, Quantity          resp: ByteCount, Bits
//	0x03,0x04 req: Address, Quantity          resp: ByteCount, Registers
//	0x05,0x06 req/resp: Address, Value
//	0x07      resp: Status (output data byte)
//	0x08      req/resp: SubFunction, Data (Diagnostic reads it by type)
//	0x0B      resp: Status, EventCount
//	0x0C      resp: ByteCount, Status, EventCount, MessageCount, Events
//	0x0F      req: Address, Quantity, ByteCount, Bits  resp: Address, Quantity
//	0x10      req: Address, Quantity, ByteCount, Registers  resp: Address, Quantity
//	0x11      resp: ByteCount, Data (server ID, run indicator, extra data;
//	          ServerID splits them)
//	0x14,0x15 req/resp: ByteCount, FileRecords
//	0x16      req/resp: Address, AndMask, OrMask
//	0x17      req: Address, Quantity (read), WriteAddress, WriteQuantity,
//	          ByteCount, Registers (write values)  resp: ByteCount, Registers
//	0x18      req: Address (FIFO pointer)  resp: ByteCount, FIFOCount, Registers
//	0x2B      req/resp: MEIType, then DeviceID (0x0E) or Data (others;
//	          CANopen reads the header of 0x0D)
//	exception resp: ExceptionCode
//	unknown function: Data
type ModbusPDU struct {
	Direction     ModbusDirection
	Function      ModbusFunctionCode // exception bit cleared
	Exception     bool
	ExceptionCode ModbusExceptionCode

	Address       uint16
	Quantity      uint16
	Value         uint16
	WriteAddress  uint16
	WriteQuantity uint16
	AndMask       uint16
	OrMask        uint16

	ByteCount int
	Bits      []byte // packed coil or input status, LSB of byte 0 first
	Registers []uint16

	SubFunction  ModbusDiagCode
	Status       uint16
	EventCount   uint16
	MessageCount uint16
	Events       []byte
	FIFOCount    uint16
	FileRecords  []ModbusFileRecord

	MEIType  ModbusMEIType
	DeviceID ModbusDeviceID

	Data []byte
}

// Bit returns coil or input i of Bits, counting from the first one
// addressed. It returns false past the end of Bits.
func (p *ModbusPDU) Bit(i int) bool {
	if i < 0 || i/modbusBitsPerByte >= len(p.Bits) {
		return false
	}
	return p.Bits[i/modbusBitsPerByte]&(1<<uint(i%modbusBitsPerByte)) != 0
}

// DecodePDU decodes the function specific data of m. On error the returned
// PDU holds the fields decoded before the fault was found.
func (m *Modbus) DecodePDU(dir ModbusDirection) (*ModbusPDU, error) {
	return decodeModbusPDU(m.FunctionCode, m.ReqResp, dir)
}

// DecodeModbusPDU decodes a raw PDU: a function code followed by its data,
// such as ModbusTCP.Payload(). On error the returned PDU, when not nil,
// holds the fields decoded before the fault was found.
func DecodeModbusPDU(pdu []byte, dir ModbusDirection) (*ModbusPDU, error) {
	if len(pdu) == 0 {
		return nil, ErrModbusPDUTooShort
	}
	return decodeModbusPDU(pdu[0], pdu[1:], dir)
}

// modbusPDUFunc decodes the data of one function in one direction.
type modbusPDUFunc func(p *ModbusPDU, data []byte) error

// modbusPDUCodec pairs the request and response decoders of a function.
type modbusPDUCodec struct {
	req  modbusPDUFunc
	resp modbusPDUFunc
}

// modbusPDUCodecs maps each public function code to its decoders.
var modbusPDUCodecs = map[ModbusFunctionCode]modbusPDUCodec{
	ModbusFuncCodeReadCoils:              {(*ModbusPDU).readReq, (*ModbusPDU).readBitsResp},
	ModbusFuncCodeReadDiscreteInputs:     {(*ModbusPDU).readReq, (*ModbusPDU).readBitsResp},
	ModbusFuncCodeReadHoldingRegisters:   {(*ModbusPDU).readReq, (*ModbusPDU).readRegsResp},
	ModbusFuncCodeReadInputRegisters:     {(*ModbusPDU).readReq, (*ModbusPDU).readRegsResp},
	ModbusFuncCodeWriteSingleCoil:        {(*ModbusPDU).writeCoil, (*ModbusPDU).writeCoil},
	ModbusFuncCodeWriteSingleRegister:    {(*ModbusPDU).writeReg, (*ModbusPDU).writeReg},
	ModbusFuncCodeReadExceptionStatus:    {(*ModbusPDU).noData, (*ModbusPDU).excStatusResp},
	ModbusFuncCodeDiagnostics:            {(*ModbusPDU).diagnostics, (*ModbusPDU).diagnostics},
	ModbusFuncCodeGetCommEventCounter:    {(*ModbusPDU).noData, (*ModbusPDU).eventCounterResp},
	ModbusFuncCodeGetCommEventLog:        {(*ModbusPDU).noData, (*ModbusPDU).eventLogResp},
	ModbusFuncCodeWriteMultipleCoils:     {(*ModbusPDU).writeCoilsReq, (*ModbusPDU).writeMultiResp},
	ModbusFuncCodeWriteMultipleRegisters: {(*ModbusPDU).writeRegsReq, (*ModbusPDU).writeMultiResp},
	ModbusFuncCodeReportSlaveID:          {(*ModbusPDU).noData, (*ModbusPDU).serverIDResp},
	ModbusFuncCodeReadFileRecord:         {(*ModbusPDU).readFileReq, (*ModbusPDU).readFileResp},
	ModbusFuncCodeWriteFileRecord:        {(*ModbusPDU).writeFile, (*ModbusPDU).writeFile},
	ModbusFuncCodeMaskWriteRegister:      {(*ModbusPDU).maskWrite, (*ModbusPDU).maskWrite},
	ModbusFuncCodeReadWriteMultipleRegs:  {(*ModbusPDU).readWriteReq, (*ModbusPDU).readRegsResp},
	ModbusFuncCodeReadFIFOQueue:          {(*ModbusPDU).fifoReq, (*ModbusPDU).fifoResp},
	ModbusFuncCodeEncapsulatedInterface:  {(*ModbusPDU).meiReq, (*ModbusPDU).meiResp},
}

// decodeModbusPDU splits off the exception bit, then hands the data to the
// decoder of the function and direction. Unknown functions keep raw data.
func decodeModbusPDU(fc byte, data []byte, dir ModbusDirection) (*ModbusPDU, error) {
	code := ModbusFunctionCode(fc)
	p := &ModbusPDU{
		Direction: dir,
		Function:  code &^ ModbusFuncCodeExceptionMask,
		Exception: code&ModbusFuncCodeExceptionMask != 0,
	}

	if p.Exception {
		return p, p.exception(data)
	}

	codec, ok := modbusPDUCodecs[p.Function]
	if !ok {
		p.Data = data
		return p, nil
	}

	dec := codec.req
	if dir == ModbusResponse {
		dec = codec.resp
	}
	return p, dec(p, data)
}

// modbusTrailing checks nothing follows the first n bytes of data. Fixed
// size functions decode their fields first and check this last, so a PDU
// with stray bytes still yields its fields along with the error.
func modbusTrailing(data []byte, n int) error {
	if len(data) > n {
		return fmt.Errorf("%w: %d bytes, want %d", ErrModbusPDUTrailing, len(data), n)
	}
	return nil
}

// modbusMinLen checks data holds at least n bytes.
func modbusMinLen(data []byte, n int) error {
	if len(data) < n {
		return fmt.Errorf("%w: %d bytes, want at least %d", ErrModbusPDULength, len(data), n)
	}
	return nil
}

// modbusQuantity checks q lies in 1..limit.
func modbusQuantity(q uint16, limit int) error {
	if q == 0 || int(q) > limit {
		return fmt.Errorf("%w: %d, want 1..%d", ErrModbusPDUQuantity, q, limit)
	}
	return nil
}

// modbusRegisters converts big endian register bytes to values. The caller
// has checked len(b) is even and bounded by a one byte count.
func modbusRegisters(b []byte) []uint16 {
	regs := make([]uint16, len(b)/modbusRegisterLen)
	for i := range regs {
		regs[i] = binary.BigEndian.Uint16(b[i*modbusRegisterLen:])
	}
	return regs
}

// modbusCountedData splits a one byte count from the data that follows it
// and checks the count covers exactly the rest of the PDU.
func modbusCountedData(data []byte) (int, []byte, error) {
	if err := modbusMinLen(data, 1); err != nil {
		return 0, nil, err
	}

	count := int(data[0])
	if count != len(data)-1 {
		return count, nil, fmt.Errorf("%w: count %d, %d bytes follow", ErrModbusPDUByteCount, count, len(data)-1)
	}
	return count, data[1:], nil
}

// exception decodes an exception response: one exception code byte.
func (p *ModbusPDU) exception(data []byte) error {
	if err := modbusMinLen(data, 1); err != nil {
		return err
	}
	p.ExceptionCode = ModbusExceptionCode(data[0])
	return modbusTrailing(data, 1)
}

// noData decodes a request that carries nothing after the function code.
func (p *ModbusPDU) noData(data []byte) error {
	return modbusTrailing(data, 0)
}

// readReq decodes a read request: starting address and quantity, e.g.
// 00 13 00 13 reads 19 coils from address 19.
func (p *ModbusPDU) readReq(data []byte) error {
	if err := modbusMinLen(data, modbusAddrQtyLen); err != nil {
		return err
	}
	p.Address = binary.BigEndian.Uint16(data[0:2])
	p.Quantity = binary.BigEndian.Uint16(data[2:4])

	limit := modbusMaxReadRegs
	if p.Function == ModbusFuncCodeReadCoils || p.Function == ModbusFuncCodeReadDiscreteInputs {
		limit = modbusMaxReadBits
	}

	if err := modbusQuantity(p.Quantity, limit); err != nil {
		return err
	}
	return modbusTrailing(data, modbusAddrQtyLen)
}

// readBitsResp decodes packed coil or input status after a byte count.
func (p *ModbusPDU) readBitsResp(data []byte) error {
	count, bits, err := modbusCountedData(data)
	p.ByteCount = count
	if err != nil {
		return err
	}

	if count == 0 || count > modbusMaxBitBytes {
		return fmt.Errorf("%w: %d status bytes", ErrModbusPDUByteCount, count)
	}
	p.Bits = bits
	return nil
}

// readRegsResp decodes register values after a byte count.
func (p *ModbusPDU) readRegsResp(data []byte) error {
	count, regs, err := modbusCountedData(data)
	p.ByteCount = count
	if err != nil {
		return err
	}

	if count == 0 || count > modbusMaxRegBytes || count%modbusRegisterLen != 0 {
		return fmt.Errorf("%w: %d register bytes", ErrModbusPDUByteCount, count)
	}
	p.Registers = modbusRegisters(regs)
	return nil
}

// addrValue decodes an address followed by a 16 bit value.
func (p *ModbusPDU) addrValue(data []byte) error {
	if err := modbusMinLen(data, modbusAddrQtyLen); err != nil {
		return err
	}
	p.Address = binary.BigEndian.Uint16(data[0:2])
	p.Value = binary.BigEndian.Uint16(data[2:4])
	return nil
}

// writeCoil decodes write single coil: the value must be ON or OFF.
func (p *ModbusPDU) writeCoil(data []byte) error {
	if err := p.addrValue(data); err != nil {
		return err
	}

	if p.Value != modbusCoilOn && p.Value != modbusCoilOff {
		return fmt.Errorf("%w: coil value 0x%04X", ErrModbusPDUValue, p.Value)
	}
	return modbusTrailing(data, modbusAddrQtyLen)
}

// writeReg decodes write single register: any value is allowed.
func (p *ModbusPDU) writeReg(data []byte) error {
	if err := p.addrValue(data); err != nil {
		return err
	}
	return modbusTrailing(data, modbusAddrQtyLen)
}

// excStatusResp decodes the eight exception status outputs.
func (p *ModbusPDU) excStatusResp(data []byte) error {
	if err := modbusMinLen(data, 1); err != nil {
		return err
	}
	p.Status = uint16(data[0])
	return modbusTrailing(data, 1)
}

// diagnostics decodes a sub-function code and the data that follows it.
func (p *ModbusPDU) diagnostics(data []byte) error {
	if err := modbusMinLen(data, modbusRegisterLen); err != nil {
		return err
	}
	p.SubFunction = ModbusDiagCode(binary.BigEndian.Uint16(data[0:2]))
	p.Data = data[2:]
	return nil
}

// eventCounterResp decodes status word and event count.
func (p *ModbusPDU) eventCounterResp(data []byte) error {
	if err := modbusMinLen(data, modbusAddrQtyLen); err != nil {
		return err
	}
	p.Status = binary.BigEndian.Uint16(data[0:2])
	p.EventCount = binary.BigEndian.Uint16(data[2:4])
	return modbusTrailing(data, modbusAddrQtyLen)
}

// eventLogResp decodes status, event and message counts, then up to 64
// event bytes, all after a byte count.
func (p *ModbusPDU) eventLogResp(data []byte) error {
	count, log, err := modbusCountedData(data)
	p.ByteCount = count
	if err != nil {
		return err
	}

	if count < modbusEventLogHdr || count > modbusEventLogHdr+modbusMaxEvents {
		return fmt.Errorf("%w: event log of %d bytes", ErrModbusPDUByteCount, count)
	}
	p.Status = binary.BigEndian.Uint16(log[0:2])
	p.EventCount = binary.BigEndian.Uint16(log[2:4])
	p.MessageCount = binary.BigEndian.Uint16(log[4:6])
	p.Events = log[modbusEventLogHdr:]
	return nil
}

// writeMultiHeader decodes address, quantity and byte count of a write
// multiple request and checks the count covers the rest of the PDU.
func (p *ModbusPDU) writeMultiHeader(data []byte, limit int) ([]byte, error) {
	if err := modbusMinLen(data, modbusWriteMultiHdr); err != nil {
		return nil, err
	}
	p.Address = binary.BigEndian.Uint16(data[0:2])
	p.Quantity = binary.BigEndian.Uint16(data[2:4])
	p.ByteCount = int(data[4])

	if err := modbusQuantity(p.Quantity, limit); err != nil {
		return nil, err
	}

	values := data[modbusWriteMultiHdr:]
	if p.ByteCount != len(values) {
		return nil, fmt.Errorf("%w: count %d, %d bytes follow", ErrModbusPDUByteCount, p.ByteCount, len(values))
	}
	return values, nil
}

// writeCoilsReq decodes write multiple coils: one bit per coil.
func (p *ModbusPDU) writeCoilsReq(data []byte) error {
	values, err := p.writeMultiHeader(data, modbusMaxWriteBits)
	if err != nil {
		return err
	}

	want := (int(p.Quantity) + modbusBitsPerByte - 1) / modbusBitsPerByte
	if p.ByteCount != want {
		return fmt.Errorf("%w: %d coils need %d bytes, got %d", ErrModbusPDUByteCount, p.Quantity, want, p.ByteCount)
	}
	p.Bits = values
	return nil
}

// writeRegsReq decodes write multiple registers: two bytes per register.
func (p *ModbusPDU) writeRegsReq(data []byte) error {
	values, err := p.writeMultiHeader(data, modbusMaxWriteRegs)
	if err != nil {
		return err
	}

	want := int(p.Quantity) * modbusRegisterLen
	if p.ByteCount != want {
		return fmt.Errorf("%w: %d registers need %d bytes, got %d", ErrModbusPDUByteCount, p.Quantity, want, p.ByteCount)
	}
	p.Registers = modbusRegisters(values)
	return nil
}

// writeMultiResp decodes the address and quantity a write multiple echoes.
func (p *ModbusPDU) writeMultiResp(data []byte) error {
	if err := modbusMinLen(data, modbusAddrQtyLen); err != nil {
		return err
	}
	p.Address = binary.BigEndian.Uint16(data[0:2])
	p.Quantity = binary.BigEndian.Uint16(data[2:4])

	limit := modbusMaxWriteRegs
	if p.Function == ModbusFuncCodeWriteMultipleCoils {
		limit = modbusMaxWriteBits
	}

	if err := modbusQuantity(p.Quantity, limit); err != nil {
		return err
	}
	return modbusTrailing(data, modbusAddrQtyLen)
}

// serverIDResp keeps the device specific server ID data after its count.
// Its layout (ID, run indicator, extra data) varies by device.
func (p *ModbusPDU) serverIDResp(data []byte) error {
	count, id, err := modbusCountedData(data)
	p.ByteCount = count
	if err != nil {
		return err
	}
	p.Data = id
	return nil
}

// modbusFileRef checks the reference type of a file sub-request.
func modbusFileRef(ref uint8) error {
	if ref != modbusFileRefType {
		return fmt.Errorf("%w: file reference type %d", ErrModbusPDUValue, ref)
	}
	return nil
}

// modbusFileAddr checks the file number, record number and record length
// of a sub-request (spec sections 6.14, 6.15): files are numbered from 1,
// and a file holds records 0 to 9999, one register each, so a read or
// write of n registers from record r must end by record 9999.
func modbusFileAddr(rec *ModbusFileRecord) error {
	if rec.FileNumber == 0 {
		return fmt.Errorf("%w: file number 0", ErrModbusPDUValue)
	}

	if rec.RecordNumber > modbusMaxRecordNum {
		return fmt.Errorf("%w: record number %d", ErrModbusPDUValue, rec.RecordNumber)
	}

	if rec.RecordLength == 0 {
		return fmt.Errorf("%w: record length 0", ErrModbusPDUQuantity)
	}

	if end := int(rec.RecordNumber) + int(rec.RecordLength); end > modbusFileRecords {
		return fmt.Errorf("%w: records %d to %d, file ends at %d", ErrModbusPDUQuantity, rec.RecordNumber, end-1, modbusMaxRecordNum)
	}
	return nil
}

// fileCount reads the byte count of a file record PDU and checks it lies
// in lo..hi and covers exactly the rest of the PDU.
func (p *ModbusPDU) fileCount(data []byte, lo, hi int) ([]byte, error) {
	count, subs, err := modbusCountedData(data)
	p.ByteCount = count
	if err != nil {
		return nil, err
	}

	if count < lo || count > hi {
		return nil, fmt.Errorf("%w: file data length %d, want %d..%d", ErrModbusPDUByteCount, count, lo, hi)
	}
	return subs, nil
}

// readFileReq decodes 7 byte sub-requests: ref type, file, record, length.
func (p *ModbusPDU) readFileReq(data []byte) error {
	subs, err := p.fileCount(data, modbusMinFileReadLen, modbusMaxFileReadLen)
	if err != nil {
		return err
	}

	if len(subs)%modbusFileSubReqLen != 0 {
		return fmt.Errorf("%w: %d bytes of 7 byte sub-requests", ErrModbusPDUByteCount, len(subs))
	}

	// The response sends, per sub-request, a length, the reference type
	// and the registers: together they must fit a response.
	respLen := 0
	p.FileRecords = make([]ModbusFileRecord, 0, len(subs)/modbusFileSubReqLen)
	for ; len(subs) > 0; subs = subs[modbusFileSubReqLen:] {
		rec := ModbusFileRecord{
			RefType:      subs[0],
			FileNumber:   binary.BigEndian.Uint16(subs[1:3]),
			RecordNumber: binary.BigEndian.Uint16(subs[3:5]),
			RecordLength: binary.BigEndian.Uint16(subs[5:7]),
		}
		p.FileRecords = append(p.FileRecords, rec)

		if err := modbusFileRef(rec.RefType); err != nil {
			return err
		}

		if err := modbusFileAddr(&rec); err != nil {
			return err
		}

		respLen += modbusFileSubRespHdr + int(rec.RecordLength)*modbusRegisterLen
		if respLen > modbusMaxFileReadLen {
			return fmt.Errorf("%w: response of %d bytes, at most %d fit", ErrModbusPDUQuantity, respLen, modbusMaxFileReadLen)
		}
	}
	return nil
}

// readFileResp decodes sub-responses: length, ref type, record data. The
// length counts the ref type byte plus the data, e.g. 05 06 0D FE 00 20.
//
// The spec tables give 0x07 as the least data length and sub-response
// length, yet its own example above has sub-responses of 5. The least a
// read can return is one register, so that is the minimum checked: a
// data length of 4 and a sub-response length of 3.
func (p *ModbusPDU) readFileResp(data []byte) error {
	subs, err := p.fileCount(data, modbusMinFileResp, modbusMaxFileReadLen)
	if err != nil {
		return err
	}

	for len(subs) > 0 {
		if len(subs) < modbusFileSubRespHdr {
			return fmt.Errorf("%w: sub-response header cut short", ErrModbusPDULength)
		}

		n := int(subs[0])
		if n < modbusMinSubResp || (n-1)%modbusRegisterLen != 0 || n > len(subs)-1 {
			return fmt.Errorf("%w: sub-response length %d", ErrModbusPDUByteCount, n)
		}

		rec := ModbusFileRecord{
			RefType:      subs[1],
			RecordLength: uint16((n - 1) / modbusRegisterLen),
			Data:         subs[modbusFileSubRespHdr : 1+n],
		}
		p.FileRecords = append(p.FileRecords, rec)

		if err := modbusFileRef(rec.RefType); err != nil {
			return err
		}
		subs = subs[1+n:]
	}
	return nil
}

// writeFile decodes sub-requests of ref type, file, record, length and
// record data. A response echoes its request.
func (p *ModbusPDU) writeFile(data []byte) error {
	subs, err := p.fileCount(data, modbusMinFileWrite, modbusMaxFileWrite)
	if err != nil {
		return err
	}

	for len(subs) > 0 {
		if len(subs) < modbusFileSubReqLen {
			return fmt.Errorf("%w: sub-request header cut short", ErrModbusPDULength)
		}

		rec := ModbusFileRecord{
			RefType:      subs[0],
			FileNumber:   binary.BigEndian.Uint16(subs[1:3]),
			RecordNumber: binary.BigEndian.Uint16(subs[3:5]),
			RecordLength: binary.BigEndian.Uint16(subs[5:7]),
		}

		end := modbusFileSubReqLen + int(rec.RecordLength)*modbusRegisterLen
		if end > len(subs) {
			return fmt.Errorf("%w: record of %d registers, %d bytes left", ErrModbusPDUByteCount, rec.RecordLength, len(subs)-modbusFileSubReqLen)
		}
		rec.Data = subs[modbusFileSubReqLen:end]
		p.FileRecords = append(p.FileRecords, rec)

		if err := modbusFileRef(rec.RefType); err != nil {
			return err
		}

		if err := modbusFileAddr(&rec); err != nil {
			return err
		}
		subs = subs[end:]
	}
	return nil
}

// maskWrite decodes reference address, AND mask and OR mask.
func (p *ModbusPDU) maskWrite(data []byte) error {
	if err := modbusMinLen(data, modbusMaskWriteLen); err != nil {
		return err
	}
	p.Address = binary.BigEndian.Uint16(data[0:2])
	p.AndMask = binary.BigEndian.Uint16(data[2:4])
	p.OrMask = binary.BigEndian.Uint16(data[4:6])
	return modbusTrailing(data, modbusMaskWriteLen)
}

// readWriteReq decodes read/write multiple registers: the read range, the
// write range, then the values to write.
func (p *ModbusPDU) readWriteReq(data []byte) error {
	if err := modbusMinLen(data, modbusRWHeaderLen); err != nil {
		return err
	}
	p.Address = binary.BigEndian.Uint16(data[0:2])
	p.Quantity = binary.BigEndian.Uint16(data[2:4])
	p.WriteAddress = binary.BigEndian.Uint16(data[4:6])
	p.WriteQuantity = binary.BigEndian.Uint16(data[6:8])
	p.ByteCount = int(data[8])

	if err := modbusQuantity(p.Quantity, modbusMaxReadRegs); err != nil {
		return err
	}

	if err := modbusQuantity(p.WriteQuantity, modbusMaxRWWriteRegs); err != nil {
		return err
	}

	values := data[modbusRWHeaderLen:]
	want := int(p.WriteQuantity) * modbusRegisterLen
	if p.ByteCount != want || len(values) != want {
		return fmt.Errorf("%w: %d registers need %d bytes, count %d, %d follow", ErrModbusPDUByteCount, p.WriteQuantity, want, p.ByteCount, len(values))
	}
	p.Registers = modbusRegisters(values)
	return nil
}

// fifoReq decodes the FIFO pointer address.
func (p *ModbusPDU) fifoReq(data []byte) error {
	if err := modbusMinLen(data, modbusRegisterLen); err != nil {
		return err
	}
	p.Address = binary.BigEndian.Uint16(data)
	return modbusTrailing(data, modbusRegisterLen)
}

// fifoResp decodes a two byte byte count, the FIFO count and up to 31
// queued registers. The byte count includes the FIFO count field.
func (p *ModbusPDU) fifoResp(data []byte) error {
	if err := modbusMinLen(data, modbusFIFOHeaderLen); err != nil {
		return err
	}
	p.ByteCount = int(binary.BigEndian.Uint16(data[0:2]))
	p.FIFOCount = binary.BigEndian.Uint16(data[2:4])

	if p.FIFOCount > modbusMaxFIFOCount {
		return fmt.Errorf("%w: FIFO count %d, want at most %d", ErrModbusPDUQuantity, p.FIFOCount, modbusMaxFIFOCount)
	}

	want := modbusRegisterLen + int(p.FIFOCount)*modbusRegisterLen
	if p.ByteCount != want || len(data)-modbusRegisterLen != want {
		return fmt.Errorf("%w: FIFO of %d registers, count %d, %d bytes follow", ErrModbusPDUByteCount, p.FIFOCount, p.ByteCount, len(data)-modbusRegisterLen)
	}
	p.Registers = modbusRegisters(data[modbusFIFOHeaderLen:])
	return nil
}

// meiType reads the MEI type and returns the data after it.
func (p *ModbusPDU) meiType(data []byte) ([]byte, error) {
	if err := modbusMinLen(data, 1); err != nil {
		return nil, err
	}
	p.MEIType = ModbusMEIType(data[0])
	return data[1:], nil
}

// meiReq decodes an encapsulated interface request. Only Read Device
// Identification is parsed; other MEI types keep their data raw.
func (p *ModbusPDU) meiReq(data []byte) error {
	rest, err := p.meiType(data)
	if err != nil {
		return err
	}

	if p.MEIType != ModbusMEIDeviceID {
		p.Data = rest
		return nil
	}

	if err := modbusMinLen(rest, modbusDevIDReqLen); err != nil {
		return err
	}
	p.DeviceID.ReadCode = ModbusDevIDCode(rest[0])
	p.DeviceID.ObjectID = ModbusDevObjectID(rest[1])

	if err := modbusDevIDCodeOK(p.DeviceID.ReadCode); err != nil {
		return err
	}
	return modbusTrailing(rest, modbusDevIDReqLen)
}

// modbusDevIDCodeOK checks a Read Device ID code is one of 1..4.
func modbusDevIDCodeOK(c ModbusDevIDCode) error {
	if c < ModbusDevIDBasic || c > ModbusDevIDSpecific {
		return fmt.Errorf("%w: read device ID code %d", ErrModbusPDUValue, c)
	}
	return nil
}

// meiResp decodes an encapsulated interface response. For Read Device
// Identification that is a 5 byte header then id/length/value objects:
//
//	01 01 00 00 03 | 00 06 "Vendor" | 01 04 "Code" | 02 03 "1.0"
func (p *ModbusPDU) meiResp(data []byte) error {
	rest, err := p.meiType(data)
	if err != nil {
		return err
	}

	if p.MEIType != ModbusMEIDeviceID {
		p.Data = rest
		return nil
	}

	if err := modbusMinLen(rest, modbusDevIDRespHdr); err != nil {
		return err
	}
	id := &p.DeviceID
	id.ReadCode = ModbusDevIDCode(rest[0])
	id.Conformity = rest[1]
	id.MoreFollows = rest[2] == modbusMoreFollows
	id.NextObjectID = ModbusDevObjectID(rest[3])
	id.NumObjects = rest[4]

	if err := modbusDevIDCodeOK(id.ReadCode); err != nil {
		return err
	}

	if rest[2] != modbusMoreFollows && rest[2] != modbusNoMoreFollows {
		return fmt.Errorf("%w: more follows 0x%02X", ErrModbusPDUValue, rest[2])
	}

	// Each object takes at least its 2 byte header, which bounds the
	// allocation by the bytes present rather than the claimed count.
	objs := rest[modbusDevIDRespHdr:]
	id.Objects = make([]ModbusDeviceObject, 0, min(int(id.NumObjects), len(objs)/modbusDevObjHdrLen))
	for i := 0; i < int(id.NumObjects); i++ {
		if len(objs) < modbusDevObjHdrLen {
			return fmt.Errorf("%w: object %d header cut short", ErrModbusPDULength, i)
		}

		n := int(objs[1])
		if modbusDevObjHdrLen+n > len(objs) {
			return fmt.Errorf("%w: object %d of %d bytes, %d left", ErrModbusPDULength, i, n, len(objs)-modbusDevObjHdrLen)
		}

		obj := ModbusDeviceObject{ID: ModbusDevObjectID(objs[0]), Value: objs[modbusDevObjHdrLen : modbusDevObjHdrLen+n]}
		id.Objects = append(id.Objects, obj)
		objs = objs[modbusDevObjHdrLen+n:]
	}

	if len(objs) != 0 {
		return fmt.Errorf("%w: %d bytes after the last object", ErrModbusPDUTrailing, len(objs))
	}
	return nil
}
