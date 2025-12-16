package layers

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

// Pulled from a modbus test data dump at https://github.com/automayt/ICS-pcap
// 10.0.0.9	10.0.0.3	Modbus/TCP	66	   Query: Trans:     1; Unit:  10, Func:   1: Read Coils
var testPacketModbusReadCoils = []byte{
	0x00, 0x02, 0xb3, 0xce, 0x70, 0x51, 0x00, 0x50, 0x04, 0x93, 0x70, 0x67, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x34, 0x03, 0xab, 0x40, 0x00, 0x80, 0x06, 0xe3, 0x0d, 0x0a, 0x00, 0x00, 0x09, 0x0a, 0x00,
	0x00, 0x03, 0x0c, 0x0a, 0x01, 0xf6, 0x48, 0x3c, 0xbe, 0x92, 0x7a, 0x8a, 0xa5, 0x21, 0x50, 0x18,
	0xfa, 0xe6, 0x62, 0x47, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x0a, 0x01, 0x00, 0x02,
	0x00, 0x02,
}

func TestModbusReadCoilRequest(t *testing.T) {
	p := gopacket.NewPacket(testPacketModbusReadCoils, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode modbus packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeModbus}, t)

	if got, ok := p.Layer(LayerTypeModbus).(*Modbus); ok {
		want := &Modbus{
			BaseLayer: BaseLayer{
				Contents: []uint8{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x0a, 0x01, 0x00, 0x02, 0x00, 0x02},
				Payload:  []uint8{},
			},
			MBAP: MBAP{
				TransactionID: 1,
				ProtocolID:    0,
				Length:        6,
				UnitID:        10,
			},
			FunctionCode: 0x01,
			ReqResp:      []byte{0x00, 0x02, 0x00, 0x02},
		}
		if !reflect.DeepEqual(got, want) {
			t.Error("Modbus Read Coil request packet does not match")
		}
	} else {
		t.Error("Failed to get modbus layer")
	}
}

// Pulled from a modbus test data dump at https://github.com/automayt/ICS-pcap
// 10.0.0.3	10.0.0.57	Modbus/TCP	63	Response: Trans:     0; Unit:  10, Func:   8: Diagnostics. Exception returned
// 0000   00 20 78 00 62 0d 00 02 b3 ce 70 51 08 00 45 00  . x.b.....pQ..E.
// 0010   00 31 ff e5 40 00 80 06 e6 a5 0a 00 00 03 0a 00  .1..@...........
// 0020   00 39 01 f6 0a 12 70 f1 ad 1b 61 97 f1 8f 50 18  .9....p...a...P.
// 0030   ff f3 08 cd 00 00 00 00 00 00 00 03 0a 88 0b     ...............
var testPacketModbusExceptionResponse = []byte{
	0x00, 0x20, 0x78, 0x00, 0x62, 0x0d, 0x00, 0x02, 0xb3, 0xce, 0x70, 0x51, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x31, 0xff, 0xe5, 0x40, 0x00, 0x80, 0x06, 0xe6, 0xa5, 0x0a, 0x00, 0x00, 0x03, 0x0a, 0x00,
	0x00, 0x39, 0x01, 0xf6, 0x0a, 0x12, 0x70, 0xf1, 0xad, 0x1b, 0x61, 0x97, 0xf1, 0x8f, 0x50, 0x18,
	0xff, 0xf3, 0x08, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0a, 0x88, 0x0b,
}

func TestModbusExceptionResponse(t *testing.T) {
	p := gopacket.NewPacket(testPacketModbusExceptionResponse, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode modbus exception packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeModbus}, t)

	if got, ok := p.Layer(LayerTypeModbus).(*Modbus); ok {
		want := &Modbus{
			BaseLayer: BaseLayer{
				Contents: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0a, 0x88, 0x0b},
				Payload:  []uint8{},
			},
			MBAP: MBAP{
				TransactionID: 0,
				ProtocolID:    0,
				Length:        3,
				UnitID:        10,
			},
			FunctionCode: 0x88,
			Exception:    true,
			ReqResp:      []uint8{0x0b},
		}
		if !reflect.DeepEqual(got, want) {
			fmt.Println(got)
			fmt.Println(want)
			t.Fatal("Modbus Exception packet does not match")
		}
	} else {
		t.Error("Failed to get modbus layer")
	}
}

// simplePcapReader is a minimal PCAP file reader to avoid import cycles with pcapgo
type simplePcapReader struct {
	r         io.Reader
	byteOrder binary.ByteOrder
	linkType  LinkType
	snaplen   uint32
}

// newSimplePcapReader creates a new PCAP reader
func newSimplePcapReader(r io.Reader) (*simplePcapReader, error) {
	var buf [24]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}

	reader := &simplePcapReader{r: r}

	// Read magic number to determine byte order
	magic := binary.LittleEndian.Uint32(buf[0:4])
	switch magic {
	case 0xA1B2C3D4: // Microsecond resolution
		reader.byteOrder = binary.LittleEndian
	case 0xD4C3B2A1: // Microsecond resolution, big endian
		reader.byteOrder = binary.BigEndian
	default:
		return nil, fmt.Errorf("unknown magic number: %x", magic)
	}

	reader.snaplen = reader.byteOrder.Uint32(buf[16:20])
	reader.linkType = LinkType(reader.byteOrder.Uint32(buf[20:24]))

	return reader, nil
}

// readPacketData reads the next packet from the PCAP file
func (r *simplePcapReader) readPacketData() ([]byte, error) {
	var buf [16]byte
	if _, err := io.ReadFull(r.r, buf[:]); err != nil {
		return nil, err
	}

	captureLen := r.byteOrder.Uint32(buf[8:12])
	if captureLen > r.snaplen {
		return nil, fmt.Errorf("capture length exceeds snaplen")
	}

	data := make([]byte, captureLen)
	if _, err := io.ReadFull(r.r, data); err != nil {
		return nil, err
	}

	return data, nil
}

// TestModbusPcap tests parsing the Modbus PCAP file
func TestModbusPcap(t *testing.T) {
	f, err := os.Open("testdata/modbus.pcap")
	if err != nil {
		t.Skip("Skipping test - modbus.pcap not available:", err)
		return
	}
	defer f.Close()

	r, err := newSimplePcapReader(f)
	if err != nil {
		t.Fatal("Failed to create pcap reader:", err)
	}

	packetCount := 0
	modbusPacketCount := 0
	var lastModbus *Modbus

	for {
		data, err := r.readPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal("Failed to read packet:", err)
		}

		packetCount++
		packet := gopacket.NewPacket(data, r.linkType, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})

		if modbusLayer := packet.Layer(LayerTypeModbus); modbusLayer != nil {
			modbusPacketCount++
			modbus := modbusLayer.(*Modbus)
			lastModbus = modbus

			// Validate all Modbus packets have ProtocolID = 0
			if modbus.ProtocolID != 0 {
				t.Errorf("Packet %d: Expected ProtocolID 0, got %d", packetCount, modbus.ProtocolID)
			}

			// Validate packet structure
			if err := modbus.Validate(); err != nil {
				t.Errorf("Packet %d: Validation failed: %v", packetCount, err)
			}

			// Check function code is in valid range (base function code cannot be 0)
			if (modbus.FunctionCode & 0x7f) == 0 {
				t.Errorf("Packet %d: Invalid function code 0x%02X", packetCount, modbus.FunctionCode)
			}

			// Test helper methods
			if modbus.Exception {
				if !modbus.IsException() {
					t.Errorf("Packet %d: IsException() returned false for exception packet", packetCount)
				}
				fc := modbus.GetFunction()
				if fc.String() == "UNKNOWN" {
					t.Logf("Packet %d: Unknown exception function code: %d", packetCount, modbus.FunctionCode)
				}
			}
		}
	}

	if packetCount == 0 {
		t.Fatal("No packets read from PCAP file")
	}

	if modbusPacketCount == 0 {
		t.Fatal("No Modbus packets found in PCAP file")
	}

	t.Logf("Parsed %d packets, found %d Modbus packets", packetCount, modbusPacketCount)
	if lastModbus != nil {
		t.Logf("Last Modbus packet: TransID=%d, FuncCode=%d (%s), Exception=%v",
			lastModbus.TransactionID, lastModbus.FunctionCode,
			lastModbus.GetFunction().String(), lastModbus.Exception)
	}
}

// TestModbus2Pcap tests parsing the Modbus-2 PCAP file
func TestModbus2Pcap(t *testing.T) {
	f, err := os.Open("testdata/modbus-2.pcap")
	if err != nil {
		t.Skip("Skipping test - modbus-2.pcap not available:", err)
		return
	}
	defer f.Close()

	r, err := newSimplePcapReader(f)
	if err != nil {
		t.Fatal("Failed to create pcap reader:", err)
	}

	packetCount := 0
	modbusPacketCount := 0
	functionCodesSeen := make(map[uint8]int)
	exceptionCount := 0

	for {
		data, err := r.readPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal("Failed to read packet:", err)
		}

		packetCount++
		packet := gopacket.NewPacket(data, r.linkType, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})

		if modbusLayer := packet.Layer(LayerTypeModbus); modbusLayer != nil {
			modbusPacketCount++
			modbus := modbusLayer.(*Modbus)

			// Validate all Modbus packets have ProtocolID = 0
			// Note: Some PCAPs may have false positives (port 502 but not actually Modbus)
			if modbus.ProtocolID != 0 {
				t.Logf("Packet %d: Non-standard ProtocolID %d (expected 0) - may not be Modbus", packetCount, modbus.ProtocolID)
				continue // Skip validation for non-Modbus packets
			}

			// Validate packet structure
			if err := modbus.Validate(); err != nil {
				t.Errorf("Packet %d: Validation failed: %v", packetCount, err)
			}

			// Track function codes
			functionCodesSeen[modbus.FunctionCode]++

			// Track exceptions
			if modbus.Exception {
				exceptionCount++
				if !modbus.IsException() {
					t.Errorf("Packet %d: IsException() returned false for exception packet", packetCount)
				}
			}

			// Verify Contents field is set
			if len(modbus.Contents) < MinModbusPacketLen {
				t.Errorf("Packet %d: Contents field too small: %d bytes", packetCount, len(modbus.Contents))
			}

			// Verify MBAP header is within Contents
			if len(modbus.Contents) >= MBAPHeaderLen {
				// The first 7 bytes should be the MBAP header
				expectedLen := int(modbus.Length) + 6 // Length field doesn't include transaction ID and protocol ID
				if len(modbus.Contents) != expectedLen {
					t.Errorf("Packet %d: Contents length mismatch: got %d, expected %d",
						packetCount, len(modbus.Contents), expectedLen)
				}
			}
		}
	}

	if packetCount == 0 {
		t.Fatal("No packets read from PCAP file")
	}

	if modbusPacketCount == 0 {
		t.Fatal("No Modbus packets found in PCAP file")
	}

	t.Logf("Parsed %d packets, found %d Modbus packets", packetCount, modbusPacketCount)
	t.Logf("Found %d exception responses", exceptionCount)
	t.Logf("Function codes seen: %v", functionCodesSeen)

	// Verify we saw some common function codes
	if len(functionCodesSeen) == 0 {
		t.Error("No function codes were parsed from Modbus packets")
	}
}

// TestModbusPcapDetailedValidation performs detailed validation on both PCAP files
func TestModbusPcapDetailedValidation(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
	}{
		{"Modbus", "testdata/modbus.pcap"},
		{"Modbus2", "testdata/modbus-2.pcap"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.filename)
			if err != nil {
				t.Skip("Skipping test - file not available:", err)
				return
			}
			defer f.Close()

			r, err := newSimplePcapReader(f)
			if err != nil {
				t.Fatal("Failed to create pcap reader:", err)
			}

			transactionIDs := make(map[uint16]int)
			unitIDs := make(map[uint8]int)

			for {
				data, err := r.readPacketData()
				if err != nil {
					if err == io.EOF {
						break
					}
					t.Fatal("Failed to read packet:", err)
				}

				packet := gopacket.NewPacket(data, r.linkType, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})

				if modbusLayer := packet.Layer(LayerTypeModbus); modbusLayer != nil {
					modbus := modbusLayer.(*Modbus)

					// Track transaction IDs and unit IDs
					transactionIDs[modbus.TransactionID]++
					unitIDs[modbus.UnitID]++

					// Verify layer methods work correctly
					if modbus.LayerType() != LayerTypeModbus {
						t.Error("LayerType() returned incorrect value")
					}

					if modbus.CanDecode() != LayerTypeModbus {
						t.Error("CanDecode() returned incorrect value")
					}

					if modbus.NextLayerType() != gopacket.LayerTypeZero {
						t.Error("NextLayerType() should return LayerTypeZero")
					}

					// Verify GetFunction helper
					fc := modbus.GetFunction()
					fcStr := fc.String()
					if fcStr == "" {
						t.Error("GetFunction().String() returned empty string")
					}

					// For non-exception packets, verify data length is reasonable
					if !modbus.Exception {
						// Most Modbus function requests/responses have some data
						// but some can be empty, so we just check it's not absurdly large
						if len(modbus.ReqResp) > 256 {
							t.Errorf("ReqResp data suspiciously large: %d bytes (TransID=%d, Func=%d)",
								len(modbus.ReqResp), modbus.TransactionID, modbus.FunctionCode)
						}
					}
				}
			}

			t.Logf("%s: Unique Transaction IDs: %d", tc.name, len(transactionIDs))
			t.Logf("%s: Unique Unit IDs: %d", tc.name, len(unitIDs))

			if len(transactionIDs) == 0 {
				t.Error("No transaction IDs found")
			}
		})
	}
}
