package layers

import (
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
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
	p := gopacket.NewPacket(testGTPv2Packet, LayerTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal("Failed to decode packet:", p.ErrorLayer().Error())
	}

	gtpLayer := p.Layer(LayerTypeGTPv2)
	if gtpLayer == nil {
		t.Fatal("GTPv2 layer not found")
	}
	got, ok := gtpLayer.(*GTPv2)
	if !ok {
		t.Fatal("Incorrect type for GTPv2 layer")
	}

	want := &GTPv2{
		Version:          2,
		PiggybackingFlag: false,
		TEIDflag:         true,
		MessagePriority:  0,
		MessageType:      37,
		MessageLength:    19,
		TEID:             1779326497, // from bytes 4:8
		SequenceNumber:   3992219,    // from bytes 8:11
		Spare:            0,
		IEs: []IE{
			{Type: 2, Content: []byte{0x10, 0x00}},
			{Type: 3, Content: []byte{0x13}},
		},
	}

	if got.Version != want.Version ||
		got.PiggybackingFlag != want.PiggybackingFlag ||
		got.TEIDflag != want.TEIDflag ||
		got.MessagePriority != want.MessagePriority ||
		got.MessageType != want.MessageType ||
		got.MessageLength != want.MessageLength ||
		got.TEID != want.TEID ||
		got.SequenceNumber != want.SequenceNumber ||
		got.Spare != want.Spare ||
		!reflect.DeepEqual(got.IEs, want.IEs) {
		t.Errorf("GTPv2 header mismatch:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
	}

	wantContents := testGTPv2Packet[42:65]
	if !reflect.DeepEqual(got.LayerContents(), wantContents) {
		t.Errorf("Contents mismatch:\ngot  : %v\nwant : %v", got.LayerContents(), wantContents)
	}

	if len(got.LayerPayload()) != 0 {
		t.Errorf("Expected empty payload, got: %v", got.LayerPayload())
	}
}
