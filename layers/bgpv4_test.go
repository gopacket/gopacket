package layers

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/gopacket/gopacket"
)

func FuzzBGPv4DecodeFromBytes(f *testing.F) {
	f.Fuzz(func(t *testing.T, bytes []byte) {
		bgpv4 := BGPv4{}
		bgpv4.DecodeFromBytes(bytes, gopacket.NilDecodeFeedback)
	})
}

// testPacketBGPv4KeepAlive is a BGPv4 Keep Alive message.
// Keep Alive sends only a BGPv4 header.
//
//	0000   aa bb cc 02 c2 01 aa bb cc 02 c0 01 08 00 45 c0   ..............E.
//	0010   00 3b 3f fe 40 00 ff 06 26 f5 0a 00 00 04 0a 00   .;?.@...&.......
//	0020   00 06 00 b3 ed f5 02 7e 86 24 53 8b a2 72 50 18   .......~.$S..rP.
//	0030   3f bf ea 94 00 00 ff ff ff ff ff ff ff ff ff ff   ?...............
//	0040   ff ff ff ff ff ff 00 13 04                        .........
var testPacketBGPv4KeepAlive = []byte{
	0xaa, 0xbb, 0xcc, 0x02, 0xc2, 0x01, 0xaa, 0xbb, 0xcc, 0x02, 0xc0, 0x01, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x3b, 0x3f, 0xfe, 0x40, 0x00, 0xff, 0x06, 0x26, 0xf5, 0x0a, 0x00, 0x00, 0x04, 0x0a, 0x00,
	0x00, 0x06, 0x00, 0xb3, 0xed, 0xf5, 0x02, 0x7e, 0x86, 0x24, 0x53, 0x8b, 0xa2, 0x72, 0x50, 0x18,
	0x3f, 0xbf, 0xea, 0x94, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x13, 0x04,
}

func TestPacketBGPv4KeepAlive(t *testing.T) {
	p := gopacket.NewPacket(testPacketBGPv4KeepAlive, LinkTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet: %s", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeBGPv4}, t)

	want := &BGPv4{
		BaseLayer: BaseLayer{Contents: p.Layer(LayerTypeTCP).(*TCP).Payload, Payload: []byte{}},
		Marker:    BGPv4Marker,
		Length:    19,
		Type:      BGPv4TypeKeepAlive,
		Data:      nil,
	}

	bgp := p.Layer(LayerTypeBGPv4).(*BGPv4)
	if d := cmp.Diff(want, bgp); len(d) != 0 {
		t.Errorf("BGPv4 differs from the expected structure, \n%s", d)
	}
}

// testPacketBGPv4Open is a BGPv4 Open message.
//
//	0000   aa bb cc 02 c2 01 aa bb cc 02 c0 01 08 00 45 c0   ..............E.
//	0010   00 69 3f fd 40 00 ff 06 26 c8 0a 00 00 04 0a 00   .i?.@...&.......
//	0020   00 06 00 b3 ed f5 02 7e 85 e3 53 8b a2 72 50 18   .......~..S..rP.
//	0030   3f bf 74 64 00 00 ff ff ff ff ff ff ff ff ff ff   ?.td............
//	0040   ff ff ff ff ff ff 00 41 01 04 fc 00 00 b4 0a 00   .......A........
//	0050   22 04 24 02 06 01 04 00 01 00 01 02 02 80 00 02   ".$.............
//	0060   02 02 00 02 02 46 00 02 06 45 04 00 01 01 03 02   .....F...E......
//	0070   06 41 04 00 00 fc 00                              .A.....
var testPacketBGPv4Open = []byte{
	0xaa, 0xbb, 0xcc, 0x02, 0xc2, 0x01, 0xaa, 0xbb, 0xcc, 0x02, 0xc0, 0x01, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x69, 0x3f, 0xfd, 0x40, 0x00, 0xff, 0x06, 0x26, 0xc8, 0x0a, 0x00, 0x00, 0x04, 0x0a, 0x00,
	0x00, 0x06, 0x00, 0xb3, 0xed, 0xf5, 0x02, 0x7e, 0x85, 0xe3, 0x53, 0x8b, 0xa2, 0x72, 0x50, 0x18,
	0x3f, 0xbf, 0x74, 0x64, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x41, 0x01, 0x04, 0xfc, 0x00, 0x00, 0xb4, 0x0a, 0x00,
	0x22, 0x04, 0x24, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02,
	0x02, 0x02, 0x00, 0x02, 0x02, 0x46, 0x00, 0x02, 0x06, 0x45, 0x04, 0x00, 0x01, 0x01, 0x03, 0x02,
	0x06, 0x41, 0x04, 0x00, 0x00, 0xfc, 0x00,
}

func TestPacketBGPv4Open(t *testing.T) {
	p := gopacket.NewPacket(testPacketBGPv4Open, LinkTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet: %s", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeBGPv4}, t)

	want := &BGPv4{
		BaseLayer: BaseLayer{Contents: p.Layer(LayerTypeTCP).(*TCP).Payload, Payload: []byte{}},
		Marker:    BGPv4Marker,
		Length:    65,
		Type:      BGPv4TypeOpen,
		Data: BGPv4Open{
			Version:       4,
			MyAS:          64512,
			HoldTime:      180,
			BGPIdentifier: net.IP{0x0a, 0x00, 0x22, 0x04},
			ParamLength:   36,
			Parameters: []BGPv4Parameter{
				{
					Type:   2,
					Length: 6,
					Value:  []byte{0x01, 0x04, 0x00, 0x01, 0x00, 0x01},
				},
				{
					Type:   2,
					Length: 2,
					Value:  []byte{0x80, 0x00},
				},
				{
					Type:   2,
					Length: 2,
					Value:  []byte{0x02, 0x00},
				},
				{
					Type:   2,
					Length: 2,
					Value:  []byte{0x46, 0x00},
				},
				{
					Type:   2,
					Length: 6,
					Value:  []byte{0x45, 0x04, 0x00, 0x01, 0x01, 0x03},
				},
				{
					Type:   2,
					Length: 6,
					Value:  []byte{0x41, 0x04, 0x00, 0x00, 0xfc, 0x00},
				},
			},
		},
	}

	bgp := p.Layer(LayerTypeBGPv4).(*BGPv4)
	if d := cmp.Diff(want, bgp); len(d) != 0 {
		t.Errorf("BGPv4 differs from the expected structure, \n%s", d)
	}
}

// testPacketBGPv4UpdateWithoutWithdrawRoutes is a BGPv4 Update message without
// withdraw routes.
//
//	0000   c2 01 1e 8c 00 00 c2 00 1e 8c 00 00 08 00 45 c0   ..............E.
//	0010   00 5f 90 1a 00 00 02 06 21 ba 01 01 01 01 02 02   ._......!.......
//	0020   02 02 4b 34 00 b3 cb fe 1d 99 bc c7 2d a2 50 18   ..K4........-.P.
//	0030   3e a0 c7 bf 00 00 ff ff ff ff ff ff ff ff ff ff   >...............
//	0040   ff ff ff ff ff ff 00 37 02 00 00 00 14 40 01 01   .......7.....@..
//	0050   00 40 02 06 02 02 fe 4c fe b0 40 03 04 01 01 01   .@.....L..@.....
//	0060   01 18 0a 14 01 18 0a 14 02 18 0a 14 03            .............
var testPacketBGPv4UpdateWithoutWithdrawRoutes = []byte{
	0xc2, 0x01, 0x1e, 0x8c, 0x00, 0x00, 0xc2, 0x00, 0x1e, 0x8c, 0x00, 0x00, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x5f, 0x90, 0x1a, 0x00, 0x00, 0x02, 0x06, 0x21, 0xba, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02,
	0x02, 0x02, 0x4b, 0x34, 0x00, 0xb3, 0xcb, 0xfe, 0x1d, 0x99, 0xbc, 0xc7, 0x2d, 0xa2, 0x50, 0x18,
	0x3e, 0xa0, 0xc7, 0xbf, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x37, 0x02, 0x00, 0x00, 0x00, 0x14, 0x40, 0x01, 0x01,
	0x00, 0x40, 0x02, 0x06, 0x02, 0x02, 0xfe, 0x4c, 0xfe, 0xb0, 0x40, 0x03, 0x04, 0x01, 0x01, 0x01,
	0x01, 0x18, 0x0a, 0x14, 0x01, 0x18, 0x0a, 0x14, 0x02, 0x18, 0x0a, 0x14, 0x03,
}

func TestPacketBGPv4UpdateWithoutWithdrawRoutes(t *testing.T) {
	p := gopacket.NewPacket(testPacketBGPv4UpdateWithoutWithdrawRoutes, LinkTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet: %s", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeBGPv4}, t)

	want := &BGPv4{
		BaseLayer: BaseLayer{Contents: p.Layer(LayerTypeTCP).(*TCP).Payload, Payload: []byte{}},
		Marker:    BGPv4Marker,
		Length:    55,
		Type:      BGPv4TypeUpdate,
		Data: BGPv4Update{
			RoutesLength:        0,
			PathAttributeLength: 20,
			PathAttribute: []BGPv4Attribute{
				{
					Flag: BGPv4AttributeFlags{
						Optional:       false,
						Transitive:     true,
						Partial:        false,
						ExtendedLength: false,
						Unused:         0x00,
					},
					Code:   BGPv4AttributeOriginCode,
					Length: 1,
					Value:  []byte{0x00},
				},
				{
					Flag: BGPv4AttributeFlags{
						Optional:       false,
						Transitive:     true,
						Partial:        false,
						ExtendedLength: false,
						Unused:         0x00,
					},
					Code:   BGPv4AttributeAsPathCode,
					Length: 6,
					Value:  []byte{0x02, 0x02, 0xfe, 0x4c, 0xfe, 0xb0},
				},
				{
					Flag: BGPv4AttributeFlags{

						Optional:       false,
						Transitive:     true,
						Partial:        false,
						ExtendedLength: false,
						Unused:         0x00,
					},
					Code:   BGPv4AttributeNextHopCode,
					Length: 4,
					Value:  []byte{0x01, 0x01, 0x01, 0x01},
				},
			},
			NLRI: []BGPv4IPAddressPrefix{
				{
					Length: 24,
					Prefix: []byte{0x0a, 0x14, 0x01},
				},
				{
					Length: 24,
					Prefix: []byte{0x0a, 0x14, 0x02},
				},
				{
					Length: 24,
					Prefix: []byte{0x0a, 0x14, 0x03},
				},
			},
		},
	}

	bgp := p.Layer(LayerTypeBGPv4).(*BGPv4)
	if d := cmp.Diff(bgp, want); len(d) != 0 {
		t.Errorf("BGPv4 differs from the expected structure, \n%s", d)
	}
}

// testPacketBGPv4UpdateWithoutWithdrawRoutesOrPathAttribute is a BGPv4 Update
// message without withdraw or path attribute (as path attribute is not present,
// neither is NLRI).
//
//	0000   aa bb cc 02 c2 01 aa bb cc 02 c0 01 08 00 45 c0   ..............E.
//	0010   01 08 40 00 40 00 ff 06 26 26 0a 00 00 04 0a 00   ..@.@...&&......
//	0020   00 06 00 b3 ed f5 02 7e 86 4e 53 8b a2 85 50 18   .......~.NS...P.
//	0030   3f ac e3 2c 00 00 ff ff ff ff ff ff ff ff ff ff   ?..,............
//	0040   ff ff ff ff ff ff 00 17 02 00 00 00 00            .............
var testPacketBGPv4UpdateWithoutWithdrawRoutesOrPathAttribute = []byte{
	0xaa, 0xbb, 0xcc, 0x02, 0xc2, 0x01, 0xaa, 0xbb, 0xcc, 0x02, 0xc0, 0x01, 0x08, 0x00, 0x45, 0xc0,
	0x01, 0x08, 0x40, 0x00, 0x40, 0x00, 0xff, 0x06, 0x26, 0x26, 0x0a, 0x00, 0x00, 0x04, 0x0a, 0x00,
	0x00, 0x06, 0x00, 0xb3, 0xed, 0xf5, 0x02, 0x7e, 0x86, 0x4e, 0x53, 0x8b, 0xa2, 0x85, 0x50, 0x18,
	0x3f, 0xac, 0xe3, 0x2c, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00,
}

func TestPacketBGPv4UpdateWithoutWithdrawRoutesOrPathAttribute(t *testing.T) {
	p := gopacket.NewPacket(testPacketBGPv4UpdateWithoutWithdrawRoutesOrPathAttribute, LinkTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet: %s", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeBGPv4}, t)

	want := &BGPv4{
		BaseLayer: BaseLayer{Contents: p.Layer(LayerTypeTCP).(*TCP).Payload, Payload: []byte{}},
		Marker:    BGPv4Marker,
		Length:    23,
		Type:      BGPv4TypeUpdate,
		Data: BGPv4Update{
			RoutesLength:        0,
			PathAttributeLength: 0,
		},
	}

	bgp := p.Layer(LayerTypeBGPv4).(*BGPv4)
	if d := cmp.Diff(want, bgp); len(d) != 0 {
		t.Errorf("BGPv4 differs from the expected structure, \n%s", d)
	}
}

// testPacketBGPv4RouteRefreshed is a BGPv4 Route Refreshed message.
//
//	0000   aa bb cc 02 c2 01 aa bb cc 02 c0 01 08 00 45 c0   ..............E.
//	0010   00 3f 3f ff 40 00 ff 06 26 f0 0a 00 00 04 0a 00   .??.@...&.......
//	0020   00 06 00 b3 ed f5 02 7e 86 37 53 8b a2 85 50 18   .......~.7S...P.
//	0030   3f ac e7 78 00 00 ff ff ff ff ff ff ff ff ff ff   ?..x............
//	0040   ff ff ff ff ff ff 00 17 05 00 01 01 01            .............
var testPacketBGPv4RouteRefreshed = []byte{
	0xaa, 0xbb, 0xcc, 0x02, 0xc2, 0x01, 0xaa, 0xbb, 0xcc, 0x02, 0xc0, 0x01, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x3f, 0x3f, 0xff, 0x40, 0x00, 0xff, 0x06, 0x26, 0xf0, 0x0a, 0x00, 0x00, 0x04, 0x0a, 0x00,
	0x00, 0x06, 0x00, 0xb3, 0xed, 0xf5, 0x02, 0x7e, 0x86, 0x37, 0x53, 0x8b, 0xa2, 0x85, 0x50, 0x18,
	0x3f, 0xac, 0xe7, 0x78, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x17, 0x05, 0x00, 0x01, 0x01, 0x01,
}

func TestPacketBGPv4RouteRefreshed(t *testing.T) {
	p := gopacket.NewPacket(testPacketBGPv4RouteRefreshed, LinkTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet: %s", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeBGPv4}, t)

	want := &BGPv4{
		BaseLayer: BaseLayer{Contents: p.Layer(LayerTypeTCP).(*TCP).Payload, Payload: []byte{}},
		Marker:    BGPv4Marker,
		Length:    23,
		Type:      BGPv4TypeRouteRefreshed,
		Data: BGPv4RouteRefreshed{
			AFI:  1,
			Res:  1,
			SAFI: 1,
		},
	}

	bgp := p.Layer(LayerTypeBGPv4).(*BGPv4)
	if d := cmp.Diff(want, bgp); len(d) != 0 {
		t.Errorf("BGPv4 differs from the expected structure, \n%s", d)
	}
}

// testPacketBGPv4Notification is a BGPv4 Notification messsage.
//
//	0000   	00 50 56 89 67 86 00 50 56 89 2e 9c 81 00 01 f5   .PV.g..PV.......
//	0010	08 00 45 c0 00 9c fe 05 40 00 fd 06 8b 93 78 00   ..E.....@.....x.
//	0020	02 01 78 00 01 01 00 b3 f1 09 e0 f5 cd 40 11 59   ..x..........@.Y
//	0030 	9f 48 d0 18 40 00 ec 87 00 00 01 01 08 0a 0d cf   .H..@...........
//	0040	38 3b 08 d4 30 68 01 01 13 12 6e 4e 08 dd 74 e7   8;..0h....nN..t.
//	0050	27 40 8c 9e 1e 0b 36 c5 18 6d ff ff ff ff ff ff   '@..............
//	0060	ff ff ff ff ff ff ff ff ff ff 00 15 03 06 07      ...............
var testPacketBGPv4Notification = []byte{
	0x00, 0x50, 0x56, 0x89, 0x67, 0x86, 0x00, 0x50, 0x56, 0x89, 0x2e, 0x9c, 0x81, 0x00, 0x01, 0xf5,
	0x08, 0x00, 0x45, 0xc0, 0x00, 0x9c, 0xfe, 0x05, 0x40, 0x00, 0xfd, 0x06, 0x8b, 0x93, 0x78, 0x00,
	0x02, 0x01, 0x78, 0x00, 0x01, 0x01, 0x00, 0xb3, 0xf1, 0x09, 0xe0, 0xf5, 0xcd, 0x40, 0x11, 0x59,
	0x9f, 0x48, 0xd0, 0x18, 0x40, 0x00, 0xec, 0x87, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x0d, 0xcf,
	0x38, 0x3b, 0x08, 0xd4, 0x30, 0x68, 0x01, 0x01, 0x13, 0x12, 0x6e, 0x4e, 0x08, 0xdd, 0x74, 0xe7,
	0x27, 0x40, 0x8c, 0x9e, 0x1e, 0x0b, 0x36, 0xc5, 0x18, 0x6d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x15, 0x03, 0x06, 0x07,
}

func TestPacketBGPv4Notification(t *testing.T) {
	p := gopacket.NewPacket(testPacketBGPv4Notification, LinkTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet: %s", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeDot1Q, LayerTypeIPv4, LayerTypeTCP, LayerTypeBGPv4}, t)

	want := &BGPv4{
		BaseLayer: BaseLayer{Contents: p.Layer(LayerTypeTCP).(*TCP).Payload, Payload: []byte{}},
		Marker:    BGPv4Marker,
		Length:    21,
		Type:      BGPv4TypeNotification,
		Data: BGPv4Notification{
			ErrorCode:    BGPv4CeaseError,
			ErrorSubCode: BGPv4ErrorDefaultSubCode(7), // Connection Collision Resolution
			Message:      []byte{},
		},
	}

	bgp := p.Layer(LayerTypeBGPv4).(*BGPv4)
	if d := cmp.Diff(want, bgp); len(d) != 0 {
		t.Errorf("BGPv4 differs from the expected structure, \n%s", d)
	}
}

// testPacketBGPv4NotificationWrongErrorCode is a BGPv4 Notification messsage
// with an invalid error code 42.
//
//	0000   	00 50 56 89 67 86 00 50 56 89 2e 9c 81 00 01 f5   .PV.g..PV.......
//	0010	08 00 45 c0 00 9c fe 05 40 00 fd 06 8b 93 78 00   ..E.....@.....x.
//	0020	02 01 78 00 01 01 00 b3 f1 09 e0 f5 cd 40 11 59   ..x..........@.Y
//	0030 	9f 48 d0 18 40 00 ec 87 00 00 01 01 08 0a 0d cf   .H..@...........
//	0040	38 3b 08 d4 30 68 01 01 13 12 6e 4e 08 dd 74 e7   8;..0h....nN..t.
//	0050	27 40 8c 9e 1e 0b 36 c5 18 6d ff ff ff ff ff ff   '@..............
//	0060	ff ff ff ff ff ff ff ff ff ff 00 15 03 2a 07      ...............
var testPacketBGPv4NotificationWrongErrorCode = []byte{
	0x00, 0x50, 0x56, 0x89, 0x67, 0x86, 0x00, 0x50, 0x56, 0x89, 0x2e, 0x9c, 0x81, 0x00, 0x01, 0xf5,
	0x08, 0x00, 0x45, 0xc0, 0x00, 0x9c, 0xfe, 0x05, 0x40, 0x00, 0xfd, 0x06, 0x8b, 0x93, 0x78, 0x00,
	0x02, 0x01, 0x78, 0x00, 0x01, 0x01, 0x00, 0xb3, 0xf1, 0x09, 0xe0, 0xf5, 0xcd, 0x40, 0x11, 0x59,
	0x9f, 0x48, 0xd0, 0x18, 0x40, 0x00, 0xec, 0x87, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x0d, 0xcf,
	0x38, 0x3b, 0x08, 0xd4, 0x30, 0x68, 0x01, 0x01, 0x13, 0x12, 0x6e, 0x4e, 0x08, 0xdd, 0x74, 0xe7,
	0x27, 0x40, 0x8c, 0x9e, 0x1e, 0x0b, 0x36, 0xc5, 0x18, 0x6d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x15, 0x03, 0x2a, 0x07,
}

func TestPacketBGPv4NotificationWrongErrorCode(t *testing.T) {
	p := gopacket.NewPacket(testPacketBGPv4NotificationWrongErrorCode, LinkTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
	if p.ErrorLayer() != nil {
		if !strings.Contains(p.ErrorLayer().Error().Error(), "error code") {
			t.Errorf("Wrong expected error: %s", p.ErrorLayer().Error())
		}
	}
}

// testPacketBGPv4OpenWithRemainingBytes is a BGPv4 Open message with some
// remaining bytes after DecodeFromBytes. These bytes are actually an other
// BGPv4 layer (Keep Alive message).
//
//	0000   c2 00 1e 8c 00 00 c2 01 1e 8c 00 00 08 00 45 c0   ..............E.
//	0010   00 68 9a d1 00 00 02 06 16 fa 02 02 02 02 01 01   .h..............
//	0020   01 01 00 b3 4b 34 bc c7 2c 42 cb fe 1c 66 50 18   ....K4..,B...fP.
//	0030   3f d3 0b 26 00 00 ff ff ff ff ff ff ff ff ff ff   ?..&............
//	0040   ff ff ff ff ff ff 00 2d 01 04 fe b0 00 b4 0a 14   .......-........
//	0050   03 01 10 02 06 01 04 00 01 00 01 02 02 80 00 02   ................
//	0060   02 02 00 ff ff ff ff ff ff ff ff ff ff ff ff ff   ................
//	0070   ff ff ff 00 13 04                                 ......
var testPacketBGPv4OpenWithRemainingBytes = []byte{
	0xc2, 0x00, 0x1e, 0x8c, 0x00, 0x00, 0xc2, 0x01, 0x1e, 0x8c, 0x00, 0x00, 0x08, 0x00, 0x45, 0xc0,
	0x00, 0x68, 0x9a, 0xd1, 0x00, 0x00, 0x02, 0x06, 0x16, 0xfa, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01,
	0x01, 0x01, 0x00, 0xb3, 0x4b, 0x34, 0xbc, 0xc7, 0x2c, 0x42, 0xcb, 0xfe, 0x1c, 0x66, 0x50, 0x18,
	0x3f, 0xd3, 0x0b, 0x26, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x2d, 0x01, 0x04, 0xfe, 0xb0, 0x00, 0xb4, 0x0a, 0x14,
	0x03, 0x01, 0x10, 0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02,
	0x02, 0x02, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0x00, 0x13, 0x04,
}

func TestPacketBGPv4OpenWithRemainingBytes(t *testing.T) {
	p := gopacket.NewPacket(testPacketBGPv4OpenWithRemainingBytes, LinkTypeEthernet, gopacket.DecodeStreamsAsDatagrams)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet: %s", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeBGPv4}, t)

	bgp := p.Layer(LayerTypeBGPv4).(*BGPv4)
	if !bytes.Equal(testPacketBGPv4OpenWithRemainingBytes[99:], bgp.Payload()) {
		t.Errorf("BGPv4 remaining bytes differ from expected, want %v but got %v", testPacketBGPv4OpenWithRemainingBytes[99:], bgp.Payload())
	}
}
