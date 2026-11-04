// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//
//******************************************************************************

package layers

import (
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

//******************************************************************************

// checkBFD() uses the bfd.go code to analyse the packet bytes as an BFD Control
// packet and generate an BFD object. It then compares the generated BFD object
// with the one provided and throws an error if there is any difference.
// The desc argument is output with any failure message to identify the test.
func checkBFD(desc string, t *testing.T, packetBytes []byte, pExpectedBFD *BFD) {

	// Analyse the packet bytes, yielding a new packet object p.
	p := gopacket.NewPacket(packetBytes, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet %s: %v", desc, p.ErrorLayer().Error())
	}

	// Ensure that the packet analysis yielded the correct set of layers:
	//    Link Layer        = Ethernet.
	//    Network Layer     = IPv4.
	//    Transport Layer   = UDP.
	//    Application Layer = BFD.
	checkLayers(p, []gopacket.LayerType{
		LayerTypeEthernet,
		LayerTypeIPv4,
		LayerTypeUDP,
		LayerTypeBFD}, t)

	// Select the Application (BFD) layer.
	pResultBFD, ok := p.ApplicationLayer().(*BFD)
	if !ok {
		t.Error("No BFD layer type found in packet in " + desc + ".")
	}

	// Compare the generated BFD object with the expected BFD object.
	if !reflect.DeepEqual(pResultBFD, pExpectedBFD) {
		t.Errorf("BFD packet processing failed for packet "+desc+
			":\ngot  :\n%#v\n\nwant :\n%#v\n\n", pResultBFD, pExpectedBFD)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := pResultBFD.SerializeTo(buf, opts)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(pResultBFD.Contents, buf.Bytes()) {
		t.Errorf("BFD packet serialization failed for packet "+desc+
			":\ngot  :\n%+v\n\nwant :\n%+v\n\n", buf.Bytes(), pResultBFD.Contents)
	}

}

func TestBFDNoAuth(t *testing.T) {
	// This test packet is based off of the first BFD packet in the BFD sample capture
	// pcap file bfd-raw-auth-simple.pcap on the Wireshark sample captures page:
	//
	//    https://wiki.wireshark.org/SampleCaptures
	//    https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=bfd-raw-auth-simple.pcap
	//
	// Changed to remove the authentication header, and adjust all of the lengths
	var testPacketBFD = []byte{
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x10, 0x94, 0x00, 0x00, 0x02, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x11, 0x2f, 0x58, 0xc0, 0x55, 0x01, 0x02, 0xc0, 0x00,
		0x00, 0x01, 0xc0, 0x00, 0x0e, 0xc8, 0x00, 0x20, 0x72, 0x31, 0x20, 0x40, 0x05, 0x18, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x4e, 0x0a, 0x90, 0x40,
	}

	// Assemble the BFD object that we expect to emerge from this test.
	pExpectedBFD := &BFD{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x20, 0x40, 0x05, 0x18, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40,
				0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
			},
			Payload: nil,
		},
		Version:                   1,
		Diagnostic:                BFDDiagnosticNone,
		State:                     BFDStateDown,
		Poll:                      false,
		Final:                     false,
		ControlPlaneIndependent:   false,
		AuthPresent:               false,
		Demand:                    false,
		Multipoint:                false,
		DetectMultiplier:          5,
		MyDiscriminator:           1,
		YourDiscriminator:         0,
		DesiredMinTxInterval:      1000000,
		RequiredMinRxInterval:     1000000,
		RequiredMinEchoRxInterval: 0,
		AuthHeader:                nil,
	}

	checkBFD("testNoAuth", t, testPacketBFD, pExpectedBFD)
}

//******************************************************************************

func TestBFDAuthTypePassword(t *testing.T) {

	// This test packet is the first BFD packet in the BFD sample capture
	// pcap file bfd-raw-auth-simple.pcap on the Wireshark sample captures page:
	//
	//    https://wiki.wireshark.org/SampleCaptures
	//    https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=bfd-raw-auth-simple.pcap
	var testPacketBFD = []byte{
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x10, 0x94, 0x00, 0x00, 0x02, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x11, 0x2f, 0x58, 0xc0, 0x55, 0x01, 0x02, 0xc0, 0x00,
		0x00, 0x01, 0xc0, 0x00, 0x0e, 0xc8, 0x00, 0x29, 0x72, 0x31, 0x20, 0x44, 0x05, 0x21, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x09, 0x02, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4e, 0x0a, 0x90, 0x40,
	}

	// Assemble the BFD object that we expect to emerge from this test.
	pExpectedBFD := &BFD{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x20, 0x44, 0x05, 0x21, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40,
				0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
				0x01, 0x09, 0x02, 0x73, 0x65, 0x63, 0x72, 0x65,
				0x74,
			},
			Payload: nil,
		},
		Version:                   1,
		Diagnostic:                BFDDiagnosticNone,
		State:                     BFDStateDown,
		Poll:                      false,
		Final:                     false,
		ControlPlaneIndependent:   false,
		AuthPresent:               true,
		Demand:                    false,
		Multipoint:                false,
		DetectMultiplier:          5,
		MyDiscriminator:           1,
		YourDiscriminator:         0,
		DesiredMinTxInterval:      1000000,
		RequiredMinRxInterval:     1000000,
		RequiredMinEchoRxInterval: 0,
		AuthHeader: &BFDAuthHeader{
			AuthType:       BFDAuthTypePassword,
			KeyID:          2,
			SequenceNumber: 0,
			Data:           []byte{'s', 'e', 'c', 'r', 'e', 't'},
		},
	}

	checkBFD("testBFDAuthTypePassword", t, testPacketBFD, pExpectedBFD)
}

//******************************************************************************

func TestBFDAuthTypeKeyedMD5(t *testing.T) {

	// This test packet is the first BFD packet in the BFD sample capture
	// pcap file bfd-raw-auth-md5.pcap on the Wireshark sample captures page:
	//
	//    https://wiki.wireshark.org/SampleCaptures
	//    https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=bfd-raw-auth-md5.pcap
	var testPacketBFD = []byte{
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x10, 0x94, 0x00, 0x00, 0x02, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x4c, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x11, 0x2f, 0x48, 0xc0, 0x55, 0x01, 0x02, 0xc0, 0x00,
		0x00, 0x01, 0x04, 0x00, 0x0e, 0xc8, 0x00, 0x38, 0x6a, 0xcc, 0x20, 0x44, 0x05, 0x30, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00,
		0x00, 0x00, 0x02, 0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x3c, 0xc3, 0xf8, 0x21,
	}

	// Assemble the BFD object that we expect to emerge from this test.
	pExpectedBFD := &BFD{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x20, 0x44, 0x05, 0x30, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40,
				0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
				0x02, 0x18, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
			},
			Payload: nil,
		},
		Version:                   1,
		Diagnostic:                BFDDiagnosticNone,
		State:                     BFDStateDown,
		Poll:                      false,
		Final:                     false,
		ControlPlaneIndependent:   false,
		AuthPresent:               true,
		Demand:                    false,
		Multipoint:                false,
		DetectMultiplier:          5,
		MyDiscriminator:           1,
		YourDiscriminator:         0,
		DesiredMinTxInterval:      1000000,
		RequiredMinRxInterval:     1000000,
		RequiredMinEchoRxInterval: 0,
		AuthHeader: &BFDAuthHeader{
			AuthType:       BFDAuthTypeKeyedMD5,
			KeyID:          2,
			SequenceNumber: 5,
			Data: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
			},
		},
	}

	checkBFD("testBFDAuthTypeKeyedMD5", t, testPacketBFD, pExpectedBFD)
}

//******************************************************************************

func TestBFDAuthTypeMeticulousKeyedSHA1(t *testing.T) {

	// This test packet is the first BFD packet in the BFD sample capture
	// pcap file bfd-raw-auth-sha1.pcap on the Wireshark sample captures page:
	//
	//    https://wiki.wireshark.org/SampleCaptures
	//    https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=bfd-raw-auth-sha1.pcap
	var testPacketBFD = []byte{
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x10, 0x94, 0x00, 0x00, 0x02, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x11, 0x2f, 0x45, 0xc0, 0x55, 0x01, 0x02, 0xc0, 0x00,
		0x00, 0x01, 0x04, 0x00, 0x0e, 0xc8, 0x00, 0x3c, 0x37, 0x8a, 0x20, 0x44, 0x05, 0x34, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00,
		0x00, 0x00, 0x05, 0x1c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0xea, 0x6d,
		0x1f, 0x21,
	}

	// Assemble the BFD object that we expect to emerge from this test.
	pExpectedBFD := &BFD{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x20, 0x44, 0x05, 0x34, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40,
				0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
				0x05, 0x1c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
				0x17, 0x18, 0x19, 0x1a,
			},
			Payload: nil,
		},
		Version:                   1,
		Diagnostic:                BFDDiagnosticNone,
		State:                     BFDStateDown,
		Poll:                      false,
		Final:                     false,
		ControlPlaneIndependent:   false,
		AuthPresent:               true,
		Demand:                    false,
		Multipoint:                false,
		DetectMultiplier:          5,
		MyDiscriminator:           1,
		YourDiscriminator:         0,
		DesiredMinTxInterval:      1000000,
		RequiredMinRxInterval:     1000000,
		RequiredMinEchoRxInterval: 0,
		AuthHeader: &BFDAuthHeader{
			AuthType:       BFDAuthTypeMeticulousKeyedSHA1,
			KeyID:          2,
			SequenceNumber: 5,
			Data: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
				0x17, 0x18, 0x19, 0x1a,
			},
		},
	}

	checkBFD("TestBFDAuthTypeMeticulousKeyedSHA1", t, testPacketBFD, pExpectedBFD)
}

//******************************************************************************

// TestBFDSerializeUnknownAuthType checks that a BFD Control packet with the
// A bit set and an authentication type other than 1-5 decodes, and that
// serializing the result returns an error instead of panicking.
func TestBFDSerializeUnknownAuthType(t *testing.T) {
	for _, authType := range []byte{0, 6, 255} {
		testPacketBFD := []byte{
			0x20, 0xc4, 0x03, 0x21, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0f, 0x42, 0x40,
			0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00, authType, 0x09, 0x01, 0x73, 0x65, 0x63, 0x72, 0x65,
			0x74,
		}

		p := gopacket.NewPacket(testPacketBFD, LayerTypeBFD, gopacket.Default)
		if p.ErrorLayer() != nil {
			t.Fatalf("Failed to decode packet with auth type %d: %v", authType, p.ErrorLayer().Error())
		}

		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializePacket(buf, gopacket.SerializeOptions{}, p); err == nil {
			t.Errorf("Serializing auth type %d must return an error", authType)
		}
		if len(buf.Bytes()) != 0 {
			t.Errorf("Serializing auth type %d left %d bytes in the buffer", authType, len(buf.Bytes()))
		}
	}
}

//******************************************************************************

// TestBFDKeyedAuthTooShort: a keyed MD5/SHA1 authentication section that ends
// before the end of its sequence number must yield an error, not a panic.
func TestBFDKeyedAuthTooShort(t *testing.T) {
	for authType := BFDAuthTypeKeyedMD5; authType <= BFDAuthTypeMeticulousKeyedSHA1; authType++ {
		for authLen := 3; authLen < 8; authLen++ {
			data := make([]byte, bfdMinimumRecordSizeInBytes+authLen)
			data[0] = 0x20 // Version 1
			data[1] = 0x04 // AuthPresent
			data[3] = byte(len(data))
			data[bfdMinimumRecordSizeInBytes] = byte(authType)
			data[bfdMinimumRecordSizeInBytes+1] = byte(authLen)

			if err := (&BFD{}).DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
				t.Errorf("%v with a %d byte authentication section decoded without error", authType, authLen)
			}
		}
	}
}

func TestBFDTrailingBytes(t *testing.T) {
	// The packet of TestBFDNoAuth with the UDP length raised by one, so the
	// UDP payload carries one byte more than the BFD Length field covers.
	// RFC 5880 section 6.8.6 does not discard such a packet; the extra byte
	// is simply not part of the BFD packet.
	var testPacketBFD = []byte{
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x10, 0x94, 0x00, 0x00, 0x02, 0x08, 0x00, 0x45, 0x00,
		0x00, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x11, 0x2f, 0x58, 0xc0, 0x55, 0x01, 0x02, 0xc0, 0x00,
		0x00, 0x01, 0xc0, 0x00, 0x0e, 0xc8, 0x00, 0x21, 0x72, 0x31, 0x20, 0x40, 0x05, 0x18, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x4e, 0x0a, 0x90, 0x40,
	}

	pExpectedBFD := &BFD{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x20, 0x40, 0x05, 0x18, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40,
				0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0x00, 0x00,
			},
			Payload: nil,
		},
		Version:                   1,
		Diagnostic:                BFDDiagnosticNone,
		State:                     BFDStateDown,
		DetectMultiplier:          5,
		MyDiscriminator:           1,
		YourDiscriminator:         0,
		DesiredMinTxInterval:      1000000,
		RequiredMinRxInterval:     1000000,
		RequiredMinEchoRxInterval: 0,
		AuthHeader:                nil,
	}

	checkBFD("testTrailingBytes", t, testPacketBFD, pExpectedBFD)
}

func TestBFDInvalidLength(t *testing.T) {
	// A Length field below the minimum or beyond the available data is
	// still rejected.
	for _, pLen := range []int{0, bfdMinimumRecordSizeInBytes - 1, bfdMinimumRecordSizeInBytes + 2} {
		data := make([]byte, bfdMinimumRecordSizeInBytes+1)
		data[0] = 0x20
		data[3] = byte(pLen)
		if err := (&BFD{}).DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("BFD packet with Length %d in %d bytes of data decoded without error", pLen, len(data))
		}
	}
}
