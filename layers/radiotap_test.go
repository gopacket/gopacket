// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"
)

// testPacketRadiotap0 is the packet:
//
//	09:34:34.799438 1.0 Mb/s 2412 MHz 11b -58dB signal antenna 7 Acknowledgment RA:88:1f:a1:ae:9d:cb
//	   0x0000:  0000 1200 2e48 0000 1002 6c09 a000 c607  .....H....l.....
//	   0x0010:  0000 d400 0000 881f a1ae 9dcb c630 4b4b  .............0KK
var testPacketRadiotap0 = []byte{
	0x00, 0x00, 0x12, 0x00, 0x2e, 0x48, 0x00, 0x00, 0x10, 0x02, 0x6c, 0x09, 0xa0, 0x00, 0xc6, 0x07,
	0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x88, 0x1f, 0xa1, 0xae, 0x9d, 0xcb, 0xc6, 0x30, 0x4b, 0x4b,
}

func TestPacketRadiotap0(t *testing.T) {
	p := gopacket.NewPacket(testPacketRadiotap0, LayerTypeRadioTap, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11}, t)
	rt := p.Layer(LayerTypeRadioTap).(*RadioTap)
	if rt.RadioTapValues[0].ChannelFrequency != 2412 || rt.RadioTapValues[0].DBMAntennaSignal != -58 || rt.RadioTapValues[0].Antenna != 7 {
		t.Error("Radiotap decode error")
	}
	if rt.RadioTapValues[0].Rate != 2 { // 500Kbps unit
		t.Error("Radiotap Rate decode error")
	}
}
func BenchmarkDecodePacketRadiotap0(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketRadiotap0, LayerTypeRadioTap, gopacket.NoCopy)
	}
}

// testPacketRadiotap1 is the packet:
//
//	05:24:21.380948 2412 MHz 11g -36dB signal antenna 5 65.0 Mb/s MCS 7 20 MHz lon GI
//		0x0000:  0000 1500 2a48 0800 1000 6c09 8004 dc05  ....*H....l.....
//		0x0010:  0000 0700 0748 112c 0000 3a9d aaf0 191c  .....H.,..:.....
//		0x0020:  aba7 f213 9d00 3a9d aaf0 1970 b2ee a9f1  ......:....p....
//		0x0030:  16                                       .
var testPacketRadiotap1 = []byte{
	0x00, 0x00, 0x15, 0x00, 0x2a, 0x48, 0x08, 0x00, 0x10, 0x00, 0x6c, 0x09, 0x80, 0x04, 0xdc, 0x05,
	0x00, 0x00, 0x07, 0x00, 0x07, 0x48, 0x11, 0x2c, 0x00, 0x00, 0x3a, 0x9d, 0xaa, 0xf0, 0x19, 0x1c,
	0xab, 0xa7, 0xf2, 0x13, 0x9d, 0x00, 0x3a, 0x9d, 0xaa, 0xf0, 0x19, 0x70, 0xb2, 0xee, 0xa9, 0xf1,
	0x16,
}

func TestPacketRadiotap1(t *testing.T) {
	p := gopacket.NewPacket(testPacketRadiotap1, LayerTypeRadioTap, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11}, t)
	rt := p.Layer(LayerTypeRadioTap).(*RadioTap)
	if rt.RadioTapValues[0].ChannelFrequency != 2412 || rt.RadioTapValues[0].DBMAntennaSignal != -36 || rt.RadioTapValues[0].Antenna != 5 {
		t.Error("Radiotap decode error")
	}
	if !rt.RadioTapValues[0].MCS.Known.MCSIndex() || rt.RadioTapValues[0].MCS.MCS != 7 {
		t.Error("Radiotap MCS error")
	}
	if !rt.RadioTapValues[0].MCS.Known.Bandwidth() || rt.RadioTapValues[0].MCS.Flags.Bandwidth() != 0 {
		t.Error("Radiotap bandwidth error")
	}
	if !rt.RadioTapValues[0].MCS.Known.GuardInterval() || rt.RadioTapValues[0].MCS.Flags.ShortGI() {
		t.Error("Radiotap GI error")
	}
}
func BenchmarkDecodePacketRadiotap1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketRadiotap1, LayerTypeRadioTap, gopacket.NoCopy)
	}
}

// testPacketRadiotap2 is the packet:
//
//	09:34:34.799438 1.0 Mb/s 2412 MHz 11b -58dB signal antenna 7 Acknowledgment RA:88:1f:a1:ae:9d:cb
//	   0x0000:  0000 ff00 2e48 0000 1002 6c09 a000 c607  .....H....l.....
//	   0x0010:  0000 d400 0000 881f a1ae 9dcb c630 4b4b  .............0KK
//
// Test when the RadioTap size is too large, but still process the RadioTap
var testPacketRadiotap2 = []byte{
	0x00, 0x00, 0xff, 0x00, 0x2e, 0x48, 0x00, 0x00, 0x10, 0x02, 0x6c, 0x09, 0xa0, 0x00, 0xc6, 0x07,
	0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x88, 0x1f, 0xa1, 0xae, 0x9d, 0xcb, 0xc6, 0x30, 0x4b, 0x4b,
}

func TestPacketRadiotap2(t *testing.T) {
	p := gopacket.NewPacket(testPacketRadiotap2, LayerTypeRadioTap, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap}, t)
	rt := p.Layer(LayerTypeRadioTap).(*RadioTap)
	if rt.RadioTapValues[0].ChannelFrequency != 2412 || rt.RadioTapValues[0].DBMAntennaSignal != -58 || rt.RadioTapValues[0].Antenna != 7 {
		t.Error("Radiotap decode error")
	}
	if rt.RadioTapValues[0].Rate != 2 { // 500Kbps unit
		t.Error("Radiotap Rate decode error")
	}
}

// testPacketRadiotap3 is a HE-SU packet with a timestamp field
var testPacketRadiotap3 = []byte{
	0x00, 0x00, 0x4c, 0x00, 0x2b, 0x40, 0xd0, 0xa0, 0x20, 0x08, 0x00, 0xa0, 0x20, 0x08, 0x00, 0x00,
	0x27, 0xd7, 0x74, 0xdc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x14, 0x40, 0x01, 0xd8, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x4f, 0x22, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x27, 0xd7, 0x74, 0xdc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xfc, 0xc7, 0x72, 0x00,
	0xc0, 0x28, 0x00, 0x00, 0x92, 0x80, 0x02, 0x0e, 0xd0, 0x00, 0xd8, 0x01, 0x88, 0x41, 0x38, 0x00,
	0x5c, 0xe9, 0x31, 0xff, 0xc3, 0x29, 0x84, 0x7b, 0x57, 0xfb, 0x4d, 0x11, 0x5c, 0xe9, 0x31, 0xff,
	0xc3, 0x27, 0x40, 0x9d, 0x10, 0xb8, 0xd3, 0x49, 0x00, 0x20, 0x4b, 0x00, 0x00, 0x00, 0x95, 0xcd,
	0xbe, 0xfd, 0xa5, 0xd2, 0xc9, 0x60, 0xd7, 0x0a, 0xdf, 0x7f, 0x21, 0xca, 0x38, 0xc4, 0xd4, 0x66,
	0x4c, 0xe0, 0xda, 0xc0, 0x01, 0x8b, 0x2a, 0xc1, 0x7f, 0xbf, 0xb4, 0x5d, 0x8b, 0xdb, 0xba, 0x83,
	0x76, 0x2f, 0x79, 0xd0, 0xc3, 0xf7, 0x08, 0xf1, 0xc9, 0x36, 0xbf, 0xb3, 0x24, 0x2d, 0xc9, 0xe8,
	0x53, 0x93, 0x85, 0x91, 0xe3, 0xfb,
}

func TestPacketRadiotap3(t *testing.T) {
	p := gopacket.NewPacket(testPacketRadiotap3, LayerTypeRadioTap, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap}, t)
	rt := p.Layer(LayerTypeRadioTap).(*RadioTap)

	if !rt.RadioTapValues[0].HE.Data1.DataMCSKnown() {
		t.Error("Radiotap HE Data1 MCS unknown")
	} else if rt.RadioTapValues[0].HE.Data3.DataMCS() != 8 {
		t.Error("Radiotap HE MCS error")
	}

	if !rt.RadioTapValues[0].HE.Data1.CodingKnown() {
		t.Error("Radiotap HE Data1 Coding unknown")
	} else if rt.RadioTapValues[0].HE.Data3.Coding() != RadiotapHECodingLDPC {
		t.Error("Radiotap HE Coding error")
	}

	if !rt.RadioTapValues[0].HE.Data1.BeamChangeKnown() {
		t.Error("Radiotap HE Data1 Beam Change unknown")
	} else if !rt.RadioTapValues[0].HE.Data3.BeamChange() {
		t.Error("Radiotap HE Beam Change error")
	}

	if rt.RadioTapValues[0].HE.Data5.DataBandwidth() != DataBandwidth80 {
		t.Error("Radiotap HE Bandwidth error")
	}

	if rt.RadioTapValues[0].HE.Data1.HE_PPDUFormat() != RadiotapHePpduFormatHE_SU {
		t.Error("Radiotap HE PPDU Format error")
	}
}

// testPacketRadiotap4 is a beacon packet with multiple radiotap namespaces
var testPacketRadiotap4 = []byte{
	0x0, 0x0, 0x30, 0x0, 0x2e, 0x40, 0x40, 0xa0, 0x20, 0x8, 0x0, 0xa0, 0x20, 0x8, 0x0, 0x0, 0x10,
	0x2, 0x71, 0x9, 0xa0, 0x0, 0xea, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xf4, 0x0, 0xf0,
	0x23, 0x0, 0x0, 0x0, 0x0, 0x16, 0x0, 0x11, 0x3, 0xe9, 0x0, 0xea, 0x1, 0x80, 0x0, 0x0, 0x0, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0x60, 0x38, 0xe0, 0x30, 0x77, 0xf5, 0x60, 0x38, 0xe0, 0x30, 0x77,
	0xf5, 0xd0, 0x7f, 0x9b, 0x61, 0xb4, 0xaf, 0xe9, 0x1, 0x0, 0x0, 0x64, 0x0, 0x11, 0x4, 0x0, 0xc,
	0x4c, 0x69, 0x6e, 0x6b, 0x73, 0x79, 0x73, 0x31, 0x35, 0x37, 0x34, 0x33, 0x1, 0x8, 0x82, 0x84, 0x8b,
	0x96, 0x12, 0x24, 0x48, 0x6c, 0x3, 0x1, 0x2, 0x5, 0x4, 0x0, 0x1, 0x1, 0x0, 0x7, 0x6, 0x55, 0x53,
	0x20, 0x1, 0xb, 0x1e, 0x33, 0x8, 0x20, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x33, 0x8, 0x21, 0x5, 0x6,
	0x7, 0x8, 0x9, 0xa, 0xb, 0x2a, 0x1, 0x6, 0x32, 0x4, 0xc, 0x18, 0x30, 0x60, 0x30, 0x14, 0x1, 0x0, 0x0,
	0xf, 0xac, 0x4, 0x1, 0x0, 0x0, 0xf, 0xac, 0x4, 0x1, 0x0, 0x0, 0xf, 0xac, 0x2, 0x0, 0x0, 0xdd, 0x31,
	0x0, 0x50, 0xf2, 0x4, 0x10, 0x4a, 0x0, 0x1, 0x10, 0x10, 0x44, 0x0, 0x1, 0x2, 0x10, 0x47, 0x0, 0x10,
	0x85, 0xdc, 0x1, 0x97, 0x91, 0x2e, 0x11, 0xe6, 0x80, 0x0, 0x60, 0x38, 0xe0, 0x30, 0x77, 0xf4, 0x10,
	0x3c, 0x0, 0x1, 0x1, 0x10, 0x49, 0x0, 0x6, 0x0, 0x37, 0x2a, 0x0, 0x1, 0x20, 0xb, 0x5, 0x7, 0x0, 0x0,
	0x12, 0x7a, 0x2d, 0x1a, 0x6f, 0x10, 0x17, 0xff, 0xff, 0xff, 0xff, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x18, 0x4, 0x87, 0x19, 0x0, 0x3d, 0x16, 0x2, 0x0, 0x4, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x4a, 0xe, 0x14,
	0x0, 0xa, 0x0, 0x2c, 0x1, 0xc8, 0x0, 0x14, 0x0, 0x5, 0x0, 0x19, 0x0, 0x7f, 0x8, 0x1, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0xdd, 0x18, 0x0, 0x50, 0xf2, 0x2, 0x1, 0x1, 0x0, 0x0, 0x3, 0xa4, 0x0, 0x0, 0x27,
	0xa4, 0x0, 0x0, 0x42, 0x43, 0x5e, 0x0, 0x62, 0x32, 0x2f, 0x0, 0xdd, 0x7, 0x0, 0xc, 0x43, 0xf, 0x0,
	0x0, 0x0, 0xdd, 0x21, 0x0, 0xc, 0xe7, 0x8, 0x0, 0x0, 0x0, 0xbf, 0xc, 0xb1, 0x1, 0xc0, 0x33, 0x2a,
	0xff, 0x92, 0x4, 0x2a, 0xff, 0x92, 0x4, 0xc0, 0x5, 0x0, 0x0, 0x0, 0x2a, 0xff, 0xc3, 0x3, 0x1, 0x2,
	0x2, 0x80, 0x50, 0x82, 0x4,
}

func TestPacketRadiotap4(t *testing.T) {
	p := gopacket.NewPacket(testPacketRadiotap4, LayerTypeRadioTap, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap}, t)
	rt := p.Layer(LayerTypeRadioTap).(*RadioTap)

	if len(rt.Present) != 3 {
		t.Errorf("Expected 3 Present bitmap sets in packet, got %d", len(rt.Present))
	}
	if len(rt.RadioTapValues) != 3 {
		t.Errorf("Expected 3 RadioTap namespaces in packet, got %d", len(rt.RadioTapValues))
	}

	// all three present bitmaps should have antenna dbm
	for presentInd, present := range rt.Present {
		if presentInd != 0 && !present.Antenna() {
			t.Errorf("Expected RadioTap namespace %d to have antenna number present", presentInd)
		}
		if !present.DBMAntennaSignal() {
			t.Errorf("Expected RadioTap namespace %d to have dBm antenna signal field present", presentInd)
		}
		if rt.RadioTapValues[presentInd].DBMAntennaSignal == 0 {
			t.Errorf("Expected RadioTap namespace %d to have non-zero dBm antenna signal field", presentInd)
		}
		if presentInd == 2 && rt.RadioTapValues[presentInd].Antenna != 1 {
			t.Errorf("Expected antenna ID in RadioTap namespace %d to be 1, but got %d", presentInd, rt.RadioTapValues[presentInd].Antenna)
		}
	}
}

func TestSerializeRadioTapRoundTrip(t *testing.T) {
	cases := [][]byte{
		testPacketRadiotap0,
		testPacketRadiotap1,
		//testPacketRadiotap3,
		testPacketRadiotap4,
	}

	for i, testPacket := range cases {
		t.Run(fmt.Sprintf("RoundTrip_radiotapPacket%d", i), func(t *testing.T) {
			p := gopacket.NewPacket(testPacket, LayerTypeRadioTap, gopacket.Default)
			if p.ErrorLayer() != nil {
				t.Fatal("Failed to decode packet:", p.ErrorLayer().Error())
			}
			rt := p.Layer(LayerTypeRadioTap).(*RadioTap)

			// Serialize the RadioTap layer
			buf := gopacket.NewSerializeBuffer()
			err := rt.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true})
			if err != nil {
				t.Fatal("Failed to serialize RadioTap layer:", err)
			}

			serialized := buf.Bytes()
			if len(serialized) != int(rt.Length) {
				t.Fatalf("Expected serialized RadioTap length %d, got %d", rt.Length, len(serialized))
			}

			// Create a new packet from the serialized data
			newP := gopacket.NewPacket(serialized, LayerTypeRadioTap, gopacket.Default)
			if newP.ErrorLayer() != nil {
				t.Fatal("Failed to decode serialized packet:", newP.ErrorLayer().Error())
			}

			// Check if the original and new RadioTap layers are equal
			newRt := newP.Layer(LayerTypeRadioTap).(*RadioTap)

			if rt.Length != newRt.Length {
				t.Errorf("Expected serialized RadioTap length %d, got %d", rt.Length, newRt.Length)
			}
			if len(rt.RadioTapValues) != len(newRt.RadioTapValues) {
				t.Errorf("Expected %d RadioTap values, got %d", len(rt.RadioTapValues), len(newRt.RadioTapValues))
			}
			for i := range rt.RadioTapValues {
				if rt.RadioTapValues[i].ChannelFrequency != newRt.RadioTapValues[i].ChannelFrequency ||
					rt.RadioTapValues[i].DBMAntennaSignal != newRt.RadioTapValues[i].DBMAntennaSignal ||
					rt.RadioTapValues[i].Antenna != newRt.RadioTapValues[i].Antenna ||
					rt.RadioTapValues[i].Rate != newRt.RadioTapValues[i].Rate {
					t.Errorf("RadioTap value mismatch at index %d", i)
				}
			}
		})
	}
}

// radiotapHeader builds a RadioTap header from its present words and the
// fields that follow them.
func radiotapHeader(present []RadioTapPresent, fields []byte) []byte {
	data := []byte{0, 0, 0, 0}
	for _, p := range present {
		data = binary.LittleEndian.AppendUint32(data, uint32(p))
	}
	data = append(data, fields...)
	binary.LittleEndian.PutUint16(data[2:], uint16(len(data)))
	return data
}

// Headers longer than the 1024 bytes SerializeTo starts with must serialize
// back to the bytes they were decoded from.
func TestSerializeRadioTapLongHeader(t *testing.T) {
	const radioTapNamespaceMaxLength = 128

	// 256 present words, the last one holding a Rate past the 1024th byte
	manyPresent := make([]RadioTapPresent, 256)
	for i := range manyPresent[:255] {
		manyPresent[i] = RadioTapPresentEXT
	}
	manyPresent[0] |= RadioTapPresentRate

	// two vendor namespaces, the first one ends past 1024 bytes
	vendor := RadioTapPresentEXT | RadioTapPresentVendorNamespace
	vendorFields := append([]byte{1, 2, 3, 0, 4, 0, 0x4c, 0x04}, bytes.Repeat([]byte{0xaa}, 1100)...)
	vendorFields = append(vendorFields, 1, 2, 3, 0, 5, 0, 2, 0, 0xbb, 0xbb)

	// 16 RadioTap namespaces with every field, a Rate in between moves their alignment
	all := RadioTapPresentHEMU - 1
	var fullPresent []RadioTapPresent
	for i := 0; i < 16; i++ {
		fullPresent = append(fullPresent, all, RadioTapPresentRate)
	}
	for i := range fullPresent[:31] {
		fullPresent[i] |= RadioTapPresentEXT | RadioTapPresentRadioTapNamespace
	}

	for name, data := range map[string][]byte{
		"present": radiotapHeader(manyPresent, []byte{2}),
		"vendor":  radiotapHeader([]RadioTapPresent{vendor, vendor, 0}, vendorFields),
		"full":    radiotapHeader(fullPresent, make([]byte, 16*(radioTapNamespaceMaxLength+1))),
	} {
		t.Run(name, func(t *testing.T) {
			var rt RadioTap
			if err := rt.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
				t.Fatal("Failed to decode packet:", err)
			}
			// leave something behind in the buffer that must not end up in the header
			buf := gopacket.NewSerializeBuffer()
			dirt, _ := buf.PrependBytes(len(data))
			copy(dirt, bytes.Repeat([]byte{0xff}, len(dirt)))
			buf.Clear()
			if err := rt.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
				t.Fatal("Failed to serialize RadioTap layer:", err)
			}
			serialized := buf.Bytes()
			if name == "full" {
				// the zero fields above are longer than what the namespaces take
				if len(serialized) <= 1024 {
					t.Fatalf("Expected a header longer than 1024 bytes, got %d", len(serialized))
				}
				data = data[:len(serialized)]
			}
			if !bytes.Equal(serialized, data) {
				t.Errorf("Serialized RadioTap header differs from the decoded one:\ngot  %x\nwant %x", serialized, data)
			}
		})
	}
}

// A header that does not fit the 16-bit length field is an error, not a panic.
func TestSerializeRadioTapTooLong(t *testing.T) {
	vendor := RadioTapPresentEXT | RadioTapPresentVendorNamespace
	for name, rt := range map[string]RadioTap{
		"present": {
			Present:        make([]RadioTapPresent, 16384),
			RadioTapValues: make([]RadioTapNamespace, 1),
		},
		"vendor": {
			Present:        []RadioTapPresent{vendor, vendor, 0},
			RadioTapValues: make([]RadioTapNamespace, 1),
			VendorValues: []VendorNamespace{
				{OUI: []uint8{1, 2, 3}, SkipLength: 0xffff},
				{OUI: []uint8{1, 2, 3}, SkipLength: 0xffff},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := rt.SerializeTo(gopacket.NewSerializeBuffer(), gopacket.SerializeOptions{FixLengths: true}); err == nil {
				t.Error("Expected an error for a RadioTap header that does not fit its length field")
			}
		})
	}
}

// TestRadioTapTruncatedFields cuts a header short at every position behind its
// present words. The fields these announce no longer fit then, which has to be
// an error instead of a read behind the end of the data.
func TestRadioTapTruncatedFields(t *testing.T) {
	fields := RadioTapPresentHEMU - 1 // every field up to and including HE
	rt := RadioTap{
		Present: []RadioTapPresent{
			fields | RadioTapPresentRadioTapNamespace | RadioTapPresentEXT,
			fields | RadioTapPresentVendorNamespace | RadioTapPresentEXT,
			0,
		},
		RadioTapValues: make([]RadioTapNamespace, 2),
		VendorValues:   []VendorNamespace{{OUI: []uint8{1, 2, 3}, SkipLength: 4, Contents: []uint8{4, 5, 6, 7}}},
	}
	buf := gopacket.NewSerializeBuffer()
	if err := rt.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal("Failed to serialize RadioTap layer:", err)
	}
	header := buf.Bytes()
	if err := (&RadioTap{}).DecodeFromBytes(header, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal("Failed to decode the whole header:", err)
	}

	for n := 4 + 4*len(rt.Present); n < len(header); n++ {
		if err := (&RadioTap{}).DecodeFromBytes(header[:n:n], gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("Expected an error for the first %d of %d bytes", n, len(header))
		}
		// The capacity of a record in a reused read buffer exceeds its length.
		if err := (&RadioTap{}).DecodeFromBytes(header[:n], gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("Expected an error for the first %d of %d bytes with spare capacity", n, len(header))
		}
	}
}

// TestRadioTapVendorSkipLengthWrap has a vendor namespace whose contents end
// inside the data, but behind the last offset a uint16 can hold, so that
// offset+SkipLength wraps.
func TestRadioTapVendorSkipLengthWrap(t *testing.T) {
	data := make([]byte, 1<<16+32)
	binary.LittleEndian.PutUint32(data[4:], uint32(RadioTapPresentVendorNamespace|RadioTapPresentEXT))
	binary.LittleEndian.PutUint16(data[18:], 0xffff) // SkipLength
	if err := (&RadioTap{}).DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
		t.Error("Expected an error for a vendor namespace that ends at offset 0x10013")
	}
}

// TestRadioTapDatapadShortPayload cuts a QoS data frame whose 802.11 header is
// padded to 28 bytes (Datapad flag set) at every length. The padding is only
// removed when it was captured; shorter frames are passed on unchanged.
func TestRadioTapDatapadShortPayload(t *testing.T) {
	header := []byte{0x00, 0x00, 0x09, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20} // Flags present, Flags = Datapad
	dot11 := []byte{
		0x88, 0x01, 0x30, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x02, 0x00, 0x00, 0x00, 0x00, 0xbb,
		0x02, 0x00, 0x00, 0x00, 0x00, 0xcc, 0x10, 0x00, 0x00, 0x00, // QoS data header
		0x00, 0x00, // padding
		0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, // LLC, SNAP
	}
	for n := 0; n <= len(dot11); n++ {
		data := append(append([]byte{}, header...), dot11[:n]...)
		var rt RadioTap
		if err := rt.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Fatalf("%d bytes of 802.11: %v", n, err)
		}
		want := n + 4 // no FCS flag, so a checksum is appended
		if n >= 28 {
			want -= 2 // padding removed
		}
		if len(rt.Payload) != want {
			t.Errorf("%d bytes of 802.11: got %d bytes of payload, want %d", n, len(rt.Payload), want)
		}
	}
}

// TestRadioTapPresentBitmapNeverEnds checks that a chain of it_present words
// which all have the EXT bit set is rejected when it runs into the end of the
// data, also where offset+4 no longer fits into a uint16.
func TestRadioTapPresentBitmapNeverEnds(t *testing.T) {
	for _, size := range []int{65531, 65532, 65535, 65536, 65536 + 64} {
		data := make([]byte, size)
		data[2], data[3] = 0xff, 0xff
		for i := 7; i < size; i += 4 {
			data[i] = 0x80
		}
		if err := (&RadioTap{}).DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("Expected an error for %d bytes of present bitmap", size)
		}
	}
}

// TestRadioTapLargeData checks that the length of the data is not cut down to
// 16 bits, which shortened the header of anything larger than 64 KiB.
func TestRadioTapLargeData(t *testing.T) {
	for _, size := range []int{65535, 65536, 65536 + 8} {
		data := make([]byte, size)
		copy(data, testPacketRadiotap0)
		var rt RadioTap
		if err := rt.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("Failed to decode %d bytes: %v", size, err)
			continue
		}
		if rt.Length != 18 || len(rt.Contents) != 18 {
			t.Errorf("Expected an 18 byte header in %d bytes, got Length %d and %d bytes", size, rt.Length, len(rt.Contents))
		}
	}
}

// TestRadioTapTimestampTruncated cuts a header inside its 12 byte Timestamp
// field. The field is skipped without being read, but the check has to
// cover it so the offset never passes the end of the data.
func TestRadioTapTimestampTruncated(t *testing.T) {
	data := make([]byte, 8+4)
	binary.LittleEndian.PutUint16(data[2:], uint16(len(data)))
	binary.LittleEndian.PutUint32(data[4:], uint32(RadioTapPresentTimestamp))
	if err := (&RadioTap{}).DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
		t.Error("Expected an error for a header cut inside the Timestamp field")
	}
}

// TestRadioTapDatapadAddress4 strips the driver padding after a 4-address
// data header, not two bytes out of Address4.
func TestRadioTapDatapadAddress4(t *testing.T) {
	data := []byte{
		0x00, 0x00, 0x09, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20, // radiotap, Flags = Datapad
		0x08, 0x03, 0x30, 0x00, // data frame, ToDS|FromDS
		0x02, 0x00, 0x00, 0x00, 0x00, 0xa1,
		0x02, 0x00, 0x00, 0x00, 0x00, 0xa2,
		0x02, 0x00, 0x00, 0x00, 0x00, 0xa3,
		0x10, 0x00,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // Address4
		0x00, 0x00, // padding
		0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
		0x9c, 0x40, 0x9c, 0x41, 0x00, 0x0c, 0x00, 0x00, 'd', 'a', 't', 'a',
	}
	p := gopacket.NewPacket(data, LayerTypeRadioTap, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal(p.ErrorLayer().Error())
	}
	dot11, ok := p.Layer(LayerTypeDot11).(*Dot11)
	if !ok {
		t.Fatal("no Dot11 layer")
	}
	if got, want := dot11.Address4.String(), "0a:0b:0c:0d:0e:0f"; got != want {
		t.Errorf("Address4 = %s, want %s", got, want)
	}
	if p.Layer(LayerTypeUDP) == nil {
		t.Error("no UDP layer")
	}
}
