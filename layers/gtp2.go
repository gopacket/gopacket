package layers

import (
	"encoding/binary"
	"fmt"

	"github.com/gopacket/gopacket"
)

const gtp2MinimumSizeInBytes int = 4

// IE represents an Information Element in GTPv2, a key component for message structure
type IE struct {
	Type    uint8
	Content []byte
}

// GTPv2 is designed for the control plane of the Evolved Packet System,
// facilitating various control and mobility management messages between gateways and MME/S-GW.
// Defined in the 3GPP TS 29.274 specification
type GTPv2 struct {
	BaseLayer
	Version          uint8
	PiggybackingFlag bool
	TEIDflag         bool
	MessagePriority  uint8
	MessageType      uint8
	MessageLength    uint16
	TEID             uint32
	SequenceNumber   uint32
	Spare            uint8
	IEs              []IE
}

// DecodeFromBytes analyses a byte slice and attempts to decode it as a GTPv2 packet
func (g *GTPv2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	hLen := gtp2MinimumSizeInBytes
	dLen := len(data)
	if dLen < hLen {
		df.SetTruncated()
		return fmt.Errorf("GTP packet too small: %d bytes", dLen)
	}
	g.Version = (data[0] >> 5) & 0x07
	g.PiggybackingFlag = ((data[0] >> 4) & 0x01) == 1
	g.TEIDflag = ((data[0] >> 3) & 0x01) == 1
	g.MessagePriority = (data[0] >> 2) & 0x01
	g.MessageType = data[1]
	g.MessageLength = binary.BigEndian.Uint16(data[2:4])

	pLen := 4 + int(g.MessageLength)
	if dLen < pLen {
		df.SetTruncated()
		return fmt.Errorf("GTP packet too small: %d bytes", dLen)
	}

	cIndex := hLen
	if g.TEIDflag {
		hLen += 4
		cIndex += 4
		if dLen < hLen {
			df.SetTruncated()
			return fmt.Errorf("GTP packet too small: %d bytes", dLen)
		}
		g.TEID = binary.BigEndian.Uint32(data[4:8])
	}

	// SequenceNumber is 3 bytes and is followed by a 1-byte Spare field, so
	// four bytes must be present from cIndex.
	if dLen < cIndex+4 {
		df.SetTruncated()
		return fmt.Errorf("GTP packet too small for SequenceNumber: %d bytes", dLen)
	}
	g.SequenceNumber = uint32(data[cIndex])<<16 | uint32(data[cIndex+1])<<8 | uint32(data[cIndex+2])
	g.Spare = data[cIndex+3]
	hLen += 4
	cIndex += 4

	for cIndex < dLen {
		// Every Information Element carries a 4-byte header (1-byte Type,
		// 2-byte Length, 1-byte Spare/Instance) ahead of its content.
		if cIndex+4 > dLen {
			df.SetTruncated()
			return fmt.Errorf("GTP IE header truncated at offset %d", cIndex)
		}
		ieType := data[cIndex]
		// Compute bounds in int; cIndex, and the 16-bit IE length can each
		// approach 65535, so uint16 arithmetic here would wrap and defeat the
		// check below.
		ieLength := int(binary.BigEndian.Uint16(data[cIndex+1 : cIndex+3]))
		if cIndex+4+ieLength > dLen {
			df.SetTruncated()
			return fmt.Errorf("IE %d exceeds packet length", ieType)
		}
		ieContent := data[cIndex+4 : cIndex+4+ieLength]
		g.IEs = append(g.IEs, IE{Type: ieType, Content: ieContent})
		cIndex += 4 + ieLength
	}

	g.BaseLayer = BaseLayer{Contents: data[:cIndex], Payload: data[cIndex:]}
	return nil

}

// decodeGTPv2 is a utility function to facilitate the decoding of GTPv2 packets within GoPacket's framework
func decodeGTPv2(data []byte, p gopacket.PacketBuilder) error {
	gtp := &GTPv2{}

	if err := gtp.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(gtp)
	return p.NextDecoder(gtp.NextLayerType())
}

// LayerType returns LayerTypeGTPv2
func (g *GTPv2) LayerType() gopacket.LayerType {
	return LayerTypeGTPv2
}

// LayerContents returns the contents of the GTPv2 layer.
func (g *GTPv2) LayerContents() []byte {
	return g.Contents
}

// LayerPayload returns the payload of the GTPv2 layer.
func (g *GTPv2) LayerPayload() []byte {
	return g.Payload
}

// CanDecode returns a set of layers that GTP objects can decode
func (g *GTPv2) CanDecode() gopacket.LayerClass {
	return LayerTypeGTPv2
}

// NextLayerType specifies the next layer that GoPacket should attempt to
func (g *GTPv2) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}
