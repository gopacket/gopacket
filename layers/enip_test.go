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

// Pulled from a ENIP test data dump at https://github.com/automayt/ICS-pcap
// 0000   00 00 bc 21 ca c2 00 08 a1 60 70 59 08 00 45 00  ...!.....`pY..E.
// 0010   00 44 a6 0f 40 00 80 06 d2 c0 c0 a8 00 2e c0 a8  .D..@...........
// 0020   00 65 0c d6 af 12 6d 9c 74 16 b0 7e b1 be 50 18  .e....m.t..~..P.
// 0030   ff ff c3 f3 00 00 65 00 04 00 00 00 00 00 00 00  ......e.........
// 0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00  ................
// 0050   00 00                                            ..
// 192.168.0.46	192.168.0.101	ENIP	82	Register Session (Req), Session: 0x00000000
var testPacketENIPRegisterSession = []byte{
	0x00, 0x00, 0xbc, 0x21, 0xca, 0xc2, 0x00, 0x08, 0xa1, 0x60, 0x70, 0x59, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x44, 0xa6, 0x0f, 0x40, 0x00, 0x80, 0x06, 0xd2, 0xc0, 0xc0, 0xa8, 0x00, 0x2e, 0xc0, 0xa8,
	0x00, 0x65, 0x0c, 0xd6, 0xaf, 0x12, 0x6d, 0x9c, 0x74, 0x16, 0xb0, 0x7e, 0xb1, 0xbe, 0x50, 0x18,
	0xff, 0xff, 0xc3, 0xf3, 0x00, 0x00, 0x65, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00,
}

func TestENIPRegisterSession(t *testing.T) {
	p := gopacket.NewPacket(testPacketENIPRegisterSession, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode ENIP packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeENIP}, t)

	if got, ok := p.Layer(LayerTypeENIP).(*ENIP); ok {
		want := &ENIP{
			BaseLayer: BaseLayer{
				Contents: []uint8{0x65, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x01, 0x00, 0x00, 0x00,
				},
				Payload: []uint8{},
			},
			Command:       0x0065,
			Length:        4,
			SessionHandle: 0,
			Status:        0,
			SenderContext: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			Options:       0,
			CommandSpecific: ENIPCommandSpecificData{
				Cmd:  0x0065,
				Data: []byte{0x01, 0x00, 0x00, 0x00},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Error("ENIP registration packet does not match")
		}
	} else {
		t.Error("Failed to get ENIP layer")
	}

}

// Pulled from ENIP test data dump at https://github.com/automayt/ICS-pcap
// 0000   00 00 bc 21 ca c2 00 08 a1 60 70 59 08 00 45 00  ...!.....`pY..E.
// 0010   00 82 a6 10 40 00 80 06 d2 81 c0 a8 00 2e c0 a8  ....@...........
// 0020   00 65 0c d6 af 12 6d 9c 74 32 b0 7e b1 da 50 18  .e....m.t2.~..P.
// 0030   ff e3 a8 b7 00 00 6f 00 42 00 00 11 02 0a 00 00  ......o.B.......
// 0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
// 0050   00 00 00 00 02 00 00 00 00 00 b2 00 32 00 54 02  ............2.T.
// 0060   20 06 24 01 05 f7 02 00 00 00 01 00 00 00 02 00   .$.............
// 0070   4c 54 c0 a8 00 2e 02 00 00 00 80 84 1e 00 f4 43  LT.............C
// 0080   80 84 1e 00 f4 43 a3 04 01 00 20 02 24 01 2c 01  .....C.... .$.,.
// 192.168.0.46	192.168.0.101	CIP CM	144	Connection Manager - Forward Open (Message Router)
var testPacketENIPSendRRDataCIP = []byte{
	0x00, 0x00, 0xbc, 0x21, 0xca, 0xc2, 0x00, 0x08, 0xa1, 0x60, 0x70, 0x59, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x82, 0xa6, 0x10, 0x40, 0x00, 0x80, 0x06, 0xd2, 0x81, 0xc0, 0xa8, 0x00, 0x2e, 0xc0, 0xa8,
	0x00, 0x65, 0x0c, 0xd6, 0xaf, 0x12, 0x6d, 0x9c, 0x74, 0x32, 0xb0, 0x7e, 0xb1, 0xda, 0x50, 0x18,
	0xff, 0xe3, 0xa8, 0xb7, 0x00, 0x00, 0x6f, 0x00, 0x42, 0x00, 0x00, 0x11, 0x02, 0x0a, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x32, 0x00, 0x54, 0x02,
	0x20, 0x06, 0x24, 0x01, 0x05, 0xf7, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00,
	0x4c, 0x54, 0xc0, 0xa8, 0x00, 0x2e, 0x02, 0x00, 0x00, 0x00, 0x80, 0x84, 0x1e, 0x00, 0xf4, 0x43,
	0x80, 0x84, 0x1e, 0x00, 0xf4, 0x43, 0xa3, 0x04, 0x01, 0x00, 0x20, 0x02, 0x24, 0x01, 0x2c, 0x01,
}

func TestENIPSendRRData(t *testing.T) {
	p := gopacket.NewPacket(testPacketENIPSendRRDataCIP, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode ENIP packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeENIP, LayerTypeCIP}, t)
	if got, ok := p.Layer(LayerTypeENIP).(*ENIP); ok {
		want := &ENIP{
			BaseLayer: BaseLayer{
				Contents: []byte{
					0x6f, 0x00, 0x42, 0x00, 0x00, 0x11, 0x02, 0x0a, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x32, 0x00,
				},
				Payload: []byte{
					0x54, 0x02, 0x20, 0x06, 0x24, 0x01, 0x05, 0xf7, 0x02, 0x00,
					0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x4c, 0x54,
					0xc0, 0xa8, 0x00, 0x2e, 0x02, 0x00, 0x00, 0x00, 0x80, 0x84,
					0x1e, 0x00, 0xf4, 0x43, 0x80, 0x84, 0x1e, 0x00, 0xf4, 0x43,
					0xa3, 0x04, 0x01, 0x00, 0x20, 0x02, 0x24, 0x01, 0x2c, 0x01,
				},
			},
			Command:       0x006f,
			Length:        66,
			SessionHandle: 0x0a021100,
			Status:        0,
			SenderContext: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			Options:       0,
			CommandSpecific: ENIPCommandSpecificData{
				Cmd: 0x6f,
				Data: []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
					0x00, 0x00, 0xb2, 0x00, 0x32, 0x00,
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Error("ENIP packet does not match")
		}
	} else {
		t.Error("Failed to get ENIP layer")
	}
}

// Pulled from ENIP test data dump at https://github.com/automayt/ICS-pcap
// 0000   00 00 bc 21 ca c2 00 08 a1 60 70 59 08 00 45 00  ...!.....`pY..E.
// 0010   00 86 a6 2c 40 00 80 06 d2 61 c0 a8 00 2e c0 a8  ...,@....a......
// 0020   00 65 0c d6 af 12 6d 9c 7b 3c b0 7e bc 5b 50 18  .e....m.{<.~.[P.
// 0030   fb 4d 91 8f 00 00 70 00 46 00 00 11 02 0a 00 00  .M....p.F.......
// 0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
// 0050   00 00 00 00 02 00 a1 00 04 00 c1 11 94 00 b1 00  ................
// 0060   32 00 1d 00 0a 02 20 02 24 01 03 00 08 00 12 00  2..... .$.......
// 0070   1e 00 03 02 20 ac 24 01 01 00 01 00 4c 02 20 72  .... .$.....L. r
// 0080   24 00 54 a1 10 00 01 00 4c 02 20 72 24 00 70 a2  $.T.....L. r$.p.
// 0090   10 00 01 00                                      ....
// 192.168.0.46	192.168.0.101	CIP	148	Multiple Service Packet: Get Attribute List, Service (0x4c), Service (0x4c)
var testPacketENIPSendUnitDataCIP = []byte{
	0x00, 0x00, 0xbc, 0x21, 0xca, 0xc2, 0x00, 0x08, 0xa1, 0x60, 0x70, 0x59, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x86, 0xa6, 0x2c, 0x40, 0x00, 0x80, 0x06, 0xd2, 0x61, 0xc0, 0xa8, 0x00, 0x2e, 0xc0, 0xa8,
	0x00, 0x65, 0x0c, 0xd6, 0xaf, 0x12, 0x6d, 0x9c, 0x7b, 0x3c, 0xb0, 0x7e, 0xbc, 0x5b, 0x50, 0x18,
	0xfb, 0x4d, 0x91, 0x8f, 0x00, 0x00, 0x70, 0x00, 0x46, 0x00, 0x00, 0x11, 0x02, 0x0a, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xa1, 0x00, 0x04, 0x00, 0xc1, 0x11, 0x94, 0x00, 0xb1, 0x00,
	0x32, 0x00, 0x1d, 0x00, 0x0a, 0x02, 0x20, 0x02, 0x24, 0x01, 0x03, 0x00, 0x08, 0x00, 0x12, 0x00,
	0x1e, 0x00, 0x03, 0x02, 0x20, 0xac, 0x24, 0x01, 0x01, 0x00, 0x01, 0x00, 0x4c, 0x02, 0x20, 0x72,
	0x24, 0x00, 0x54, 0xa1, 0x10, 0x00, 0x01, 0x00, 0x4c, 0x02, 0x20, 0x72, 0x24, 0x00, 0x70, 0xa2,
	0x10, 0x00, 0x01, 0x00,
}

func TestENIPSendUnitData(t *testing.T) {
	p := gopacket.NewPacket(testPacketENIPSendUnitDataCIP, LinkTypeEthernet, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode ENIP packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeENIP, LayerTypeCIP}, t)
	if got, ok := p.Layer(LayerTypeENIP).(*ENIP); ok {
		want := &ENIP{
			BaseLayer: BaseLayer{
				Contents: []byte{
					0x70, 0x00, 0x46, 0x00, 0x00, 0x11, 0x02, 0x0a, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x02, 0x00, 0xa1, 0x00, 0x04, 0x00, 0xc1, 0x11, 0x94, 0x00,
					0xb1, 0x00, 0x32, 0x00, 0x1d, 0x00,
				},
				Payload: []byte{
					0x0a, 0x02, 0x20, 0x02, 0x24, 0x01, 0x03, 0x00, 0x08, 0x00,
					0x12, 0x00, 0x1e, 0x00, 0x03, 0x02, 0x20, 0xac, 0x24, 0x01,
					0x01, 0x00, 0x01, 0x00, 0x4c, 0x02, 0x20, 0x72, 0x24, 0x00,
					0x54, 0xa1, 0x10, 0x00, 0x01, 0x00, 0x4c, 0x02, 0x20, 0x72,
					0x24, 0x00, 0x70, 0xa2, 0x10, 0x00, 0x01, 0x00,
				},
			},
			Command:       0x0070,
			Length:        70,
			SessionHandle: 0x0a021100,
			Status:        0,
			SenderContext: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			Options:       0,
			CommandSpecific: ENIPCommandSpecificData{
				Cmd: 0x70,
				Data: []byte{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xa1, 0x00,
					0x04, 0x00, 0xc1, 0x11, 0x94, 0x00, 0xb1, 0x00, 0x32, 0x00,
					0x1d, 0x00,
				},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Error("ENIP packet does not match")
		}
	} else {
		t.Error("Failed to get ENIP layer")
	}
}

// TestENIPPcap tests parsing the EtherNet/IP PCAP file
func TestENIPPcap(t *testing.T) {
	f, err := os.Open("testdata/ethernetIP.pcap")
	if err != nil {
		t.Skip("Skipping test - ethernetIP.pcap not available:", err)
		return
	}
	defer f.Close()

	r, err := newENIPPcapReader(f)
	if err != nil {
		t.Fatal("Failed to create pcap reader:", err)
	}

	packetCount := 0
	enipPacketCount := 0
	cipPacketCount := 0
	commands := make(map[ENIPCommand]int)
	sessionHandles := make(map[uint32]int)

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

		// Analyze ENIP packets
		if enipLayer := packet.Layer(LayerTypeENIP); enipLayer != nil {
			enipPacketCount++
			enip := enipLayer.(*ENIP)

			// Track commands
			commands[enip.Command]++

			// Track session handles
			if enip.SessionHandle != 0 {
				sessionHandles[enip.SessionHandle]++
			}

			// Verify layer interface methods
			if enip.LayerType() != LayerTypeENIP {
				t.Errorf("Packet %d: LayerType() returned incorrect value", packetCount)
			}

			if enip.CanDecode() != LayerTypeENIP {
				t.Errorf("Packet %d: CanDecode() returned incorrect value", packetCount)
			}

			// Verify CommandSpecific is properly set
			if enip.CommandSpecific.Cmd != enip.Command {
				t.Errorf("Packet %d: CommandSpecific.Cmd (%x) doesn't match Command (%x)",
					packetCount, enip.CommandSpecific.Cmd, enip.Command)
			}

			// Verify Contents includes header
			if len(enip.Contents) < 24 {
				t.Errorf("Packet %d: Contents too small: %d bytes", packetCount, len(enip.Contents))
			}
		}

		// Count CIP packets
		if cipLayer := packet.Layer(LayerTypeCIP); cipLayer != nil {
			cipPacketCount++
		}
	}

	if packetCount == 0 {
		t.Fatal("No packets read from PCAP file")
	}

	if enipPacketCount == 0 {
		t.Fatal("No ENIP packets found in PCAP file")
	}

	t.Logf("Parsed %d packets, found %d ENIP packets, %d CIP packets", packetCount, enipPacketCount, cipPacketCount)
	t.Logf("ENIP Commands seen: %v", commands)
	t.Logf("Unique session handles: %d", len(sessionHandles))

	// Verify we saw some CIP packets (EtherNet/IP typically carries CIP)
	if cipPacketCount == 0 {
		t.Log("Warning: No CIP packets found - unusual for EtherNet/IP traffic")
	}
}

// newENIPPcapReader creates a minimal PCAP reader to avoid import cycles
func newENIPPcapReader(r io.Reader) (*enipPcapReader, error) {
	var buf [24]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}

	reader := &enipPcapReader{r: r}

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

type enipPcapReader struct {
	r         io.Reader
	byteOrder binary.ByteOrder
	linkType  LinkType
	snaplen   uint32
}

func (r *enipPcapReader) readPacketData() ([]byte, error) {
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
