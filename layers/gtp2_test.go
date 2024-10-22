package gtp2

import (
	"reflect"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// testGTPv2Packet packet is:
//0000   84 b5 d1 58 1f a3 84 b5 9c 67 9d 29 08 00 45 a0  ...X.....g.)..E.
//0010   00 33 eb 90 00 00 3f 11 1d 54 0a b4 5d 03 d9 94  .3....?..T..]...
//0020   30 ea 08 4b 88 30 00 1f 00 00 48 25 00 13 6a 0e  0..K.0....H%..j.
//0030   5e 21 3c ea 9b 00 02 00 02 00 10 00 03 00 01 00  ^!<.............
//0040   13                                               .

var testGTPv2Packet = []byte{
	0x84, 0xb5, 0xd1, 0x58, 0x1f, 0xa3, 0x84, 0xb5,
	0x9c, 0x67, 0x9d, 0x29, 0x08, 0x00, 0x45, 0xa0,
	0x00, 0x33, 0xeb, 0x90, 0x00, 0x00, 0x3f, 0x11,
	0x1d, 0x54, 0x0a, 0xb4, 0x5d, 0x03, 0xd9, 0x94,
	0x30, 0xea, 0x08, 0x4b, 0x88, 0x30, 0x00, 0x1f,
	0x00, 0x00, 0x48, 0x25, 0x00, 0x13, 0x6a, 0x0e,
	0x5e, 0x21, 0x3c, 0xea, 0x9b, 0x00, 0x02, 0x00,
	0x02, 0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0x00,
	0x13,
}

func TestGTPv2Packet(t *testing.T) {
	p := gopacket.NewPacket(testGTPv2Packet, layers.LayerTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}

	if got, ok := p.Layer(LayerTypeGTPv2).(*GTPv2); ok {
		want := &GTPv2{
			Version:          2,
			PiggybackingFlag: false,
			TEIDflag:         true,
			MessagePriority:  0,
			MessageType:      37,
			MessageLength:    19,
			TEID:             1779326497,
			SequenceNumber:   3992219,
			Spare:            0,
			IEs:              []IE{{2, []byte{0x10, 0x00}}, {3, []byte{0x13}}},

			Contents: testGTPv2Packet[42:65],
			Payload:  []uint8{},
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("GTP packet mismatch:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("Incorrect gtp packet")
	}
}
