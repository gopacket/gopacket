// Modbus protocol support for gopacket.
// This implements Modbus TCP (port 502) decoding according to the
// Modbus Application Protocol Specification V1.1b3.
// See: https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/gopacket/gopacket"
)

const (
	MBAPHeaderLen      int    = 7
	MinModbusPacketLen int    = MBAPHeaderLen + 1
	ModbusPort         uint16 = 502
)

var (
	ErrModbusDataTooSmall    = errors.New("data too small for Modbus")
	ErrModbusInvalidProtocol = errors.New("invalid Modbus protocol ID (expected 0)")
)

// FC represents a Modbus function code
type FC byte

// MBAP represents the Modbus Application Protocol header
type MBAP struct {
	TransactionID uint16 // Transaction identifier
	ProtocolID    uint16 // Protocol identifier (0 for Modbus)
	Length        uint16 // Length of remaining data
	UnitID        uint8  // Unit identifier
}

// Modbus represents a Modbus TCP packet
type Modbus struct {
	BaseLayer
	MBAP
	FunctionCode uint8  // Modbus function code
	Exception    bool   // True if this is an exception response
	ReqResp      []byte // Request/Response data
}

func init() {
	RegisterTCPPortLayerType(TCPPort(ModbusPort), LayerTypeModbus)
}

func (m *Modbus) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < MinModbusPacketLen {
		df.SetTruncated()
		return ErrModbusDataTooSmall
	}
	m.TransactionID = binary.BigEndian.Uint16(data[0:2])
	m.ProtocolID = binary.BigEndian.Uint16(data[2:4])
	m.Length = binary.BigEndian.Uint16(data[4:6])
	m.UnitID = data[6]
	m.Exception = FC(data[7]).exception()
	m.FunctionCode = data[7] & 0x7f
	end := int(m.Length) + 6
	if len(data) < end || end < 8 {
		df.SetTruncated()
		return ErrModbusDataTooSmall
	}
	m.ReqResp = data[8:end]
	m.Contents = data[:end]
	m.Payload = data[end:]
	return nil
}

func (m *Modbus) LayerType() gopacket.LayerType {
	return LayerTypeModbus
}

func (m *Modbus) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (m *Modbus) CanDecode() gopacket.LayerClass {
	return LayerTypeModbus
}

func decodeModbus(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < MinModbusPacketLen {
		p.SetTruncated()
		return ErrModbusDataTooSmall
	}
	modbus := &Modbus{}
	return decodingLayerDecoder(modbus, data, p)
}

func (fc FC) exception() bool {
	return (byte(fc) & 0x80) != 0
}

func (fc FC) masked() FC {
	return fc & 0x7F
}

// String returns a human-readable representation of the function code
func (fc FC) String() (s string) {
	if fc.exception() {
		s = `Exception: `
		// We aren't passing by pointer, so it's safe to modify fc
		fc = fc.masked()
	}

	switch fc {
	case 1:
		s += `Read Coil`
	case 2:
		s += `Read Discrete Inputs`
	case 3:
		s += `Read Holding Registers`
	case 4:
		s += `Read Input Registers`
	case 5:
		s += `Write Single Coil`
	case 6:
		s += `Write Single Register`
	case 7:
		s += `Read Exception Status`
	case 8:
		s += `Diagnostics`
	case 0xb:
		s += `Get Comm Event Counter`
	case 0xc:
		s += `Get Comm Event Log`
	case 0xF:
		s += `Write Multiple Coils`
	case 0x10:
		s += `Write Multiple Registers`
	case 0x11:
		s += `Report Slave ID`
	case 0x14:
		s += `Read File Record`
	case 0x15:
		s += `Write File Record`
	case 0x16:
		s += `Mask Write Register`
	case 0x17:
		s += `Read/Write Multiple Registers`
	case 0x18:
		s += `Read FIFO Queue`
	case 0x2B:
		s += `General References Request`
	default:
		s += `UNKNOWN`
	}
	return
}

// Validate checks if the Modbus packet is valid according to the protocol specification
func (m *Modbus) Validate() error {
	if m.ProtocolID != 0 {
		return ErrModbusInvalidProtocol
	}
	// Length should include UnitID (1 byte) + FunctionCode (1 byte) + Data
	expectedLength := 1 + 1 + len(m.ReqResp)
	if int(m.Length) != expectedLength {
		return errors.New("Modbus length field mismatch")
	}
	return nil
}

// IsException returns true if this is a Modbus exception response
func (m *Modbus) IsException() bool {
	return m.Exception
}

// GetFunctionCode returns the Modbus function code as an FC type
func (m *Modbus) GetFunctionCode() FC {
	return FC(m.FunctionCode)
}
