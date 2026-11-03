// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

type reuseDecoder interface {
	DecodeFromBytes([]byte, gopacket.DecodeFeedback) error
}

// bytesOf returns the header and payload of the first want layer in frame.
func bytesOf(t *testing.T, frame []byte, want gopacket.LayerType) []byte {
	t.Helper()
	for _, first := range []gopacket.LayerType{LayerTypeEthernet, LayerTypeRadioTap, LayerTypeDot11, LayerTypeUSB, want} {
		p := gopacket.NewPacket(frame, first, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true})
		for k, l := range p.Layers() {
			if l.LayerType() != want {
				continue
			}
			b := append(append([]byte(nil), l.LayerContents()...), l.LayerPayload()...)
			// a layer that doesn't record its bytes is the previous layer's payload
			if len(b) == 0 && k > 0 {
				b = append([]byte(nil), p.Layers()[k-1].LayerPayload()...)
			}
			return b
		}
	}
	t.Fatalf("no %v layer in %d byte frame", want, len(frame))
	return nil
}

// scratch lists fields that only back a slice, so entries past its length
// are never read and may differ.
var scratch = map[string]bool{"TCP.opts": true}

// sameState reports whether two decoded values are equal, treating nil and
// empty slices and maps alike, and names the first field that differs.
func sameState(a, b reflect.Value, path string) (bool, string) {
	if a.Kind() != b.Kind() {
		return false, path
	}
	switch a.Kind() {
	case reflect.Ptr, reflect.Interface:
		if a.IsNil() || b.IsNil() {
			return a.IsNil() == b.IsNil(), path
		}
		return sameState(a.Elem(), b.Elem(), path)
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			if scratch[path+"."+a.Type().Field(i).Name] {
				continue
			}
			if ok, p := sameState(a.Field(i), b.Field(i), path+"."+a.Type().Field(i).Name); !ok {
				return false, p
			}
		}
		return true, path
	case reflect.Slice, reflect.Array:
		if a.Len() != b.Len() {
			return false, fmt.Sprintf("%s (len %d vs %d)", path, a.Len(), b.Len())
		}
		for i := 0; i < a.Len(); i++ {
			if ok, p := sameState(a.Index(i), b.Index(i), fmt.Sprintf("%s[%d]", path, i)); !ok {
				return false, p
			}
		}
		return true, path
	case reflect.Map:
		if a.Len() != b.Len() {
			return false, fmt.Sprintf("%s (len %d vs %d)", path, a.Len(), b.Len())
		}
		for _, k := range a.MapKeys() {
			bv := b.MapIndex(k)
			if !bv.IsValid() {
				return false, fmt.Sprintf("%s[%v]", path, k)
			}
			if ok, p := sameState(a.MapIndex(k), bv, fmt.Sprintf("%s[%v]", path, k)); !ok {
				return false, p
			}
		}
		return true, path
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return true, path
	case reflect.String:
		return a.String() == b.String(), path
	case reflect.Bool:
		return a.Bool() == b.Bool(), path
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return a.Int() == b.Int(), path
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return a.Uint() == b.Uint(), path
	case reflect.Float32, reflect.Float64:
		return a.Float() == b.Float(), path
	}
	return true, path
}

// duidDecoder adapts DHCPv6DUID, whose DecodeFromBytes takes no feedback.
type duidDecoder struct{ DHCPv6DUID }

func (d *duidDecoder) DecodeFromBytes(data []byte, _ gopacket.DecodeFeedback) error {
	return d.DHCPv6DUID.DecodeFromBytes(data)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestDecodeFromBytesReuse checks the DecodingLayer contract: decoding into a
// layer that already holds a packet gives the same state as decoding into a
// fresh one. DecodingLayerParser reuses one layer per type for every packet.
func TestDecodeFromBytesReuse(t *testing.T) {
	of := func(frame []byte, lt gopacket.LayerType) []byte { return bytesOf(t, frame, lt) }

	tcpPlain := []byte{0x00, 0x50, 0x1f, 0x90, 0, 0, 0, 1, 0, 0, 0, 2, 0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0}
	tcpMPTCP := append(append([]byte(nil), tcpPlain...), 0x1e, 0x04, 0x00, 0x81)
	tcpMPTCP[12] = 0x60

	bfdAuth := []byte{0x20, 0xc4, 0x05, 24 + 7, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0x0f, 0x42, 0x40, 0, 0x0f, 0x42, 0x40, 0, 0, 0, 0, 1, 7, 1, 'p', 'a', 's', 's'}
	bfdPlain := []byte{0x20, 0xc0, 0x05, 24, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0x0f, 0x42, 0x40, 0, 0x0f, 0x42, 0x40, 0, 0, 0, 0}

	ip4Opts := []byte{0x46, 0, 0, 24, 0, 0, 0x40, 0, 0x40, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 1, 1, 0, 0}
	ip4Plain := []byte{0x45, 0, 0, 20, 0, 0, 0x40, 0, 0x40, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}

	dhcp4Plain := make([]byte, 240)
	dhcp4Plain[0], dhcp4Plain[1], dhcp4Plain[2] = 1, 1, 6
	copy(dhcp4Plain[236:], []byte{0x63, 0x82, 0x53, 0x63})
	dhcp4Opts := append(append([]byte(nil), dhcp4Plain...), 53, 1, 1, 255)

	dhcp6Relay := append([]byte{12, 1}, make([]byte, 32)...)
	dhcp6Relay[2], dhcp6Relay[18] = 0xfe, 0xfe
	dhcp6Solicit := []byte{1, 0x11, 0x22, 0x33}

	lcmShort := append([]byte{0x4c, 0x43, 0x30, 0x32, 0, 0, 0, 1, 'c', 'h', 0}, 1, 2, 3, 4, 5, 6, 7, 8, 9)
	lcmFrag := []byte{0x4c, 0x43, 0x30, 0x33, 0, 0, 0, 2, 0, 0, 0, 16, 0, 0, 0, 8, 0, 1, 0, 2, 9, 9, 9, 9}

	radiusAttr := append([]byte{1, 7, 0, 24}, make([]byte, 16)...)
	radiusAttr = append(radiusAttr, 1, 4, 'a', 'b')
	radiusPlain := append([]byte{2, 7, 0, 20}, make([]byte, 16)...)

	eapolKeyMin := make([]byte, 95)
	eapolKeyMin[0] = 2

	duidLL := []byte{0, 3, 0, 1, 1, 2, 3, 4, 5, 6}
	duidEN := []byte{0, 2, 0, 0, 0, 9, 0xaa, 0xbb}

	ip6DstPadN := []byte{59, 0, 1, 4, 0, 0, 0, 0}
	usbPlain := make([]byte, 48)
	gtp2Echo := []byte{0x40, 1, 0, 4, 0, 0, 0, 0}
	mdpBare := make([]byte, 28)
	ospf2Unknown := append([]byte{2, 9, 0, 24}, make([]byte, 20)...)
	ospf3Unknown := append([]byte{3, 9, 0, 16}, make([]byte, 12)...)

	cases := []struct {
		name  string
		fresh func() reuseDecoder
		pkts  [][]byte
	}{
		{"IGMP", func() reuseDecoder { return &IGMP{} }, [][]byte{of(igmp3v3MembershipQueryPacket, LayerTypeIGMP), of(igmpv3MembershipReport2Records, LayerTypeIGMP), of(igmpv1MembershipReportPacket, LayerTypeIGMP)}},
		{"MLDv2 query", func() reuseDecoder { return &MLDv2MulticastListenerQueryMessage{} }, [][]byte{of(testPacketMulticastListenerQueryMessageV2, LayerTypeMLDv2MulticastListenerQuery)}},
		{"MLDv2 report", func() reuseDecoder { return &MLDv2MulticastListenerReportMessage{} }, [][]byte{of(testPacketMulticastListenerReportMessageV2, LayerTypeMLDv2MulticastListenerReport)}},
		{"SFlow", func() reuseDecoder { return &SFlowDatagram{} }, [][]byte{of(SFlowTestPacket1, LayerTypeSFlow), of(SFlowTestPacket9, LayerTypeSFlow), of(SFlowTestPacket2, LayerTypeSFlow)}},
		{"GTPv1U", func() reuseDecoder { return &GTPv1U{} }, [][]byte{of(testGTPPacket, LayerTypeGTPv1U), of(testGTPPacketWithEH, LayerTypeGTPv1U)}},
		{"GTPv2", func() reuseDecoder { return &GTPv2{} }, [][]byte{of(testGTPv2Packet, LayerTypeGTPv2), gtp2Echo}},
		{"RadioTap", func() reuseDecoder { return &RadioTap{} }, [][]byte{of(testPacketRadiotap0, LayerTypeRadioTap), of(testPacketRadiotap1, LayerTypeRadioTap), of(testPacketRadiotap3, LayerTypeRadioTap)}},
		{"SIP", func() reuseDecoder { return NewSIP() }, [][]byte{of(testPacketSIPRequest, LayerTypeSIP), of(testPacketSIPResponse, LayerTypeSIP), of(testPacketSIPOnlyInviteNoContentLength, LayerTypeSIP)}},
		{"RADIUS", func() reuseDecoder { return &RADIUS{} }, [][]byte{radiusAttr, radiusPlain}},
		{"CIP", func() reuseDecoder { return &CIP{} }, [][]byte{of(testPacketCIPRequest, LayerTypeCIP), of(testPacketCIPResponse, LayerTypeCIP)}},
		{"Dot11", func() reuseDecoder { return &Dot11{} }, [][]byte{of(testPacketDot11DataQOSData, LayerTypeDot11), of(testPacketDot11CtrlAck, LayerTypeDot11), of(testPacketDot11CtrlCTS, LayerTypeDot11), of(testPacketDot11HTControl, LayerTypeDot11), of(testPacketDot11DataARP, LayerTypeDot11)}},
		{"Dot11InformationElement", func() reuseDecoder { return &Dot11InformationElement{} }, [][]byte{of(testPacketDot11MgmtBeacon, LayerTypeDot11InformationElement), of(testPacketDot11BeaconExtension, LayerTypeDot11InformationElement)}},
		{"BFD", func() reuseDecoder { return &BFD{} }, [][]byte{bfdAuth, bfdPlain}},
		{"DHCPv6", func() reuseDecoder { return &DHCPv6{} }, [][]byte{dhcp6Relay, dhcp6Solicit}},
		{"MDP", func() reuseDecoder { return &MDP{} }, [][]byte{of(testMDPFrame, LayerTypeMDP), mdpBare}},
		{"LCM", func() reuseDecoder { return &LCM{} }, [][]byte{lcmShort, lcmFrag}},
		{"TCP", func() reuseDecoder { return &TCP{} }, [][]byte{tcpMPTCP, tcpPlain}},
		{"OSPFv2", func() reuseDecoder { return &OSPFv2{} }, [][]byte{of(testPacketOSPF2Hello, LayerTypeOSPF), of(testPacketOSPF2LSUpdate, LayerTypeOSPF), ospf2Unknown}},
		{"OSPFv3", func() reuseDecoder { return &OSPFv3{} }, [][]byte{of(testPacketOSPF3Hello, LayerTypeOSPF), of(testPacketOSPF3LSUpdate, LayerTypeOSPF), ospf3Unknown}},
		{"IPv4", func() reuseDecoder { return &IPv4{} }, [][]byte{ip4Opts, ip4Plain}},
		{"DHCPv4", func() reuseDecoder { return &DHCPv4{} }, [][]byte{dhcp4Opts, dhcp4Plain}},
		{"IPv6Destination", func() reuseDecoder { return &IPv6Destination{} }, [][]byte{of(testPacketIPv6Destination0, LayerTypeIPv6Destination), ip6DstPadN}},
		{"EAPOLKey", func() reuseDecoder { return &EAPOLKey{} }, [][]byte{of(testPacketEAPOLKey, LayerTypeEAPOLKey), eapolKeyMin}},
		{"USB", func() reuseDecoder { return &USB{} }, [][]byte{of(testPacketUSB0, LayerTypeUSB), usbPlain}},
		{"DHCPv6DUID", func() reuseDecoder { return &duidDecoder{} }, [][]byte{duidLL, duidEN}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for i, before := range c.pkts {
				for j, pkt := range c.pkts {
					want := c.fresh()
					wantErr := want.DecodeFromBytes(pkt, gopacket.NilDecodeFeedback)

					got := c.fresh()
					got.DecodeFromBytes(before, gopacket.NilDecodeFeedback)
					gotErr := got.DecodeFromBytes(pkt, gopacket.NilDecodeFeedback)

					if errString(gotErr) != errString(wantErr) {
						t.Errorf("packet %d after %d: error %q, fresh decode gives %q", j, i, errString(gotErr), errString(wantErr))
						continue
					}
					if ok, path := sameState(reflect.ValueOf(got).Elem(), reflect.ValueOf(want).Elem(), c.name); !ok {
						t.Errorf("packet %d after %d: %s differs from a fresh decode", j, i, path)
					}
				}
			}
		})
	}
}
