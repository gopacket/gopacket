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

// Pulled from an ENIP test data dump at https://github.com/automayt/ICS-pcap
// 0000   00 00 bc d1 60 da 78 e7 d1 e0 02 5e 08 00 45 00  ....`.x....^..E.
// 0010   00 7a 70 26 40 00 80 06 00 00 8d 51 00 0a 8d 51  .zp&@......Q...Q
// 0020   00 53 c4 63 af 12 dd 88 8d 87 94 95 43 51 50 18  .S.c........CQP.
// 0030   f9 74 1b 6c 00 00 70 00 3a 00 00 01 02 10 00 00  .t.l..p.:.......
// 0040   00 00 1a 39 2f 00 00 00 00 00 00 00 00 00 00 00  ...9/...........
// 0050   00 00 0a 00 02 00 a1 00 04 00 09 13 35 00 b1 00  ............5...
// 0060   26 00 e4 6a 0a 02 20 02 24 01 02 00 06 00 12 00  &..j.. .$.......
// 0070   4c 02 20 72 24 00 00 ce 04 00 01 00 4c 02 20 72  L. r$.......L. r
// 0080   24 00 2c 3d 04 00 01 00                          $.,=....
//
//	141.81.0.10	141.81.0.83	CIP	136	Multiple Service Packet: Service (0x4c), Service (0x4c)
var testPacketCIPRequest = []byte{
	0x00, 0x00, 0xbc, 0xd1, 0x60, 0xda, 0x78, 0xe7, 0xd1, 0xe0, 0x02, 0x5e, 0x08, 0x00, 0x45, 0x00, 0x00, 0x7a, 0x70, 0x26, 0x40, 0x00, 0x80, 0x06, 0x00, 0x00, 0x8d, 0x51, 0x00, 0x0a, 0x8d, 0x51, 0x00, 0x53, 0xc4, 0x63, 0xaf, 0x12, 0xdd, 0x88, 0x8d, 0x87, 0x94, 0x95, 0x43, 0x51, 0x50, 0x18, 0xf9, 0x74, 0x1b, 0x6c, 0x00, 0x00, 0x70, 0x00, 0x3a, 0x00, 0x00, 0x01, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x39, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00, 0xa1, 0x00, 0x04, 0x00, 0x09, 0x13, 0x35, 0x00, 0xb1, 0x00, 0x26, 0x00, 0xe4, 0x6a, 0x0a, 0x02, 0x20, 0x02, 0x24, 0x01, 0x02, 0x00, 0x06, 0x00, 0x12, 0x00, 0x4c, 0x02, 0x20, 0x72, 0x24, 0x00, 0x00, 0xce, 0x04, 0x00, 0x01, 0x00, 0x4c, 0x02, 0x20, 0x72, 0x24, 0x00, 0x2c, 0x3d, 0x04, 0x00, 0x01, 0x00,
}

func TestCIPRequest(t *testing.T) {
	p := gopacket.NewPacket(testPacketCIPRequest, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode CIP packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeENIP, LayerTypeCIP}, t)

	if got, ok := p.Layer(LayerTypeCIP).(*CIP); ok {
		want := &CIP{
			Response:   false,
			ServiceID:  0x0a,
			ClassID:    0x2,
			InstanceID: 0x1,
			Data:       []byte{0x02, 0x00, 0x06, 0x00, 0x12, 0x00, 0x4c, 0x02, 0x20, 0x72, 0x24, 0x00, 0x00, 0xce, 0x04, 0x00, 0x01, 0x00, 0x4c, 0x02, 0x20, 0x72, 0x24, 0x00, 0x2c, 0x3d, 0x04, 0x00, 0x01, 0x00},
		}
		if !reflect.DeepEqual(got, want) {
			t.Error("CIP packet does not match")
		}
	} else {
		t.Error("Failed to get CIP layer")
	}

}

var testPacketCIPResponse = []byte{
	0x78, 0xe7, 0xd1, 0xe0, 0x02, 0x5e, 0x00, 0x00, 0xbc, 0xc7, 0xce, 0x56, 0x08, 0x00, 0x45, 0x00, 0x00, 0x70, 0x93, 0x54, 0x40, 0x00, 0x40, 0x06, 0x8c, 0x48, 0x8d, 0x51, 0x00, 0x3f, 0x8d, 0x51, 0x00, 0x0a, 0xaf, 0x12, 0xcd, 0x71, 0x7d, 0x74, 0x27, 0xe6, 0x13, 0xe7, 0x9f, 0xd1, 0x50, 0x18, 0x10, 0x00, 0x89, 0x69, 0x00, 0x00, 0x70, 0x00, 0x30, 0x00, 0x00, 0x05, 0x02, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xa1, 0x00, 0x04, 0x00, 0x9d, 0xc6, 0x00, 0x80, 0xb1, 0x00, 0x1c, 0x00, 0x33, 0x35, 0x8a, 0x00, 0x00, 0x00, 0x02, 0x00, 0x06, 0x00, 0x0e, 0x00, 0xcc, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xcc, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
}

func TestCIPResponse(t *testing.T) {
	p := gopacket.NewPacket(testPacketCIPResponse, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode CIP packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeENIP, LayerTypeCIP}, t)

	if got, ok := p.Layer(LayerTypeCIP).(*CIP); ok {
		want := &CIP{
			Response:  true,
			ServiceID: 0x0a,
			Status:    0x0,
			Data:      []byte{0x02, 0x00, 0x06, 0x00, 0x0e, 0x00, 0xcc, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xcc, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00},
		}
		if !reflect.DeepEqual(got, want) {
			t.Error("CIP packet does not match")
		}
	} else {
		t.Error("Failed to get CIP layer")
	}

}

// TestCIPPcap tests parsing the CIP PCAP file
func TestCIPPcap(t *testing.T) {
	f, err := os.Open("testdata/cip.pcap")
	if err != nil {
		t.Skip("Skipping test - cip.pcap not available:", err)
		return
	}
	defer f.Close()

	r, err := newCIPPcapReader(f)
	if err != nil {
		t.Fatal("Failed to create pcap reader:", err)
	}

	packetCount := 0
	enipPacketCount := 0
	cipPacketCount := 0
	requestCount := 0
	responseCount := 0
	successCount := 0
	serviceIDs := make(map[uint8]int)

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

		// Count ENIP packets
		if enipLayer := packet.Layer(LayerTypeENIP); enipLayer != nil {
			enipPacketCount++
		}

		// Analyze CIP packets
		if cipLayer := packet.Layer(LayerTypeCIP); cipLayer != nil {
			cipPacketCount++
			cip := cipLayer.(*CIP)

			// Track service IDs
			serviceIDs[cip.ServiceID]++

			// Test helper methods
			if cip.IsRequest() {
				requestCount++
				if cip.Response {
					t.Errorf("Packet %d: IsRequest() returned true but Response flag is true", packetCount)
				}
			}

			if cip.IsResponse() {
				responseCount++
				if !cip.Response {
					t.Errorf("Packet %d: IsResponse() returned true but Response flag is false", packetCount)
				}

				// Test IsSuccess for responses
				if cip.IsSuccess() {
					successCount++
					if cip.Status != 0 {
						t.Errorf("Packet %d: IsSuccess() returned true but Status is %d", packetCount, cip.Status)
					}
				}
			}

			// Verify layer interface methods
			if cip.LayerType() != LayerTypeCIP {
				t.Errorf("Packet %d: LayerType() returned incorrect value", packetCount)
			}

			if cip.CanDecode() != LayerTypeCIP {
				t.Errorf("Packet %d: CanDecode() returned incorrect value", packetCount)
			}

			if cip.NextLayerType() != gopacket.LayerTypePayload {
				t.Errorf("Packet %d: NextLayerType() should return LayerTypePayload", packetCount)
			}
		}
	}

	if packetCount == 0 {
		t.Fatal("No packets read from PCAP file")
	}

	t.Logf("Parsed %d packets, found %d ENIP packets, %d CIP packets", packetCount, enipPacketCount, cipPacketCount)
	t.Logf("CIP Requests: %d, Responses: %d (Successful: %d)", requestCount, responseCount, successCount)
	t.Logf("Service IDs seen: %v", serviceIDs)

	if cipPacketCount == 0 {
		t.Fatal("No CIP packets found in PCAP file")
	}

	// Verify we saw both requests and responses
	if requestCount == 0 {
		t.Error("No CIP requests found")
	}
	if responseCount == 0 {
		t.Error("No CIP responses found")
	}
}

// newCIPPcapReader creates a minimal PCAP reader to avoid import cycles
func newCIPPcapReader(r io.Reader) (*cipPcapReader, error) {
	var buf [24]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}

	reader := &cipPcapReader{r: r}

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

type cipPcapReader struct {
	r         io.Reader
	byteOrder binary.ByteOrder
	linkType  LinkType
	snaplen   uint32
}

func (r *cipPcapReader) readPacketData() ([]byte, error) {
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
