// Copyright 2016, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

func TestDHCPv4EncodeRequest(t *testing.T) {
	dhcp := &DHCPv4{Operation: DHCPOpRequest, HardwareType: LinkTypeEthernet, Xid: 0x12345678,
		ClientIP: net.IP{0, 0, 0, 0}, YourClientIP: net.IP{0, 0, 0, 0}, NextServerIP: net.IP{0, 0, 0, 0}, RelayAgentIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: net.HardwareAddr{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
		ServerName:   make([]byte, 64), File: make([]byte, 128)}

	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptMessageType, []byte{byte(DHCPMsgTypeDiscover)}))
	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptHostname, []byte{'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}))
	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptPad, nil))
	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptParamsRequest,
		[]byte{byte(DHCPOptSubnetMask), byte(DHCPOptBroadcastAddr), byte(DHCPOptTimeOffset),
			byte(DHCPOptRouter), byte(DHCPOptDomainName), byte(DHCPOptDNS), byte(DHCPOptDomainSearch),
			byte(DHCPOptHostname), byte(DHCPOptNetBIOSTCPNS), byte(DHCPOptInterfaceMTU), byte(DHCPOptClasslessStaticRoute),
			byte(DHCPOptNTPServers)}))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, dhcp)
	if err != nil {
		t.Fatal(err)
	}

	p2 := gopacket.NewPacket(buf.Bytes(), LayerTypeDHCPv4, testDecodeOptions)
	dhcp2 := p2.Layer(LayerTypeDHCPv4).(*DHCPv4)
	testDHCPEqual(t, dhcp, dhcp2)
}

func TestDHCPv4EncodeRequestNoOptions(t *testing.T) {
	dhcp := &DHCPv4{Operation: DHCPOpRequest, HardwareType: LinkTypeEthernet, Xid: 0x12345678,
		ClientIP: net.IP{0, 0, 0, 0}, YourClientIP: net.IP{0, 0, 0, 0}, NextServerIP: net.IP{0, 0, 0, 0}, RelayAgentIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: net.HardwareAddr{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
		ServerName:   make([]byte, 64), File: make([]byte, 128)}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, dhcp)
	if err != nil {
		t.Fatal(err)
	}

	p2 := gopacket.NewPacket(buf.Bytes(), LayerTypeDHCPv4, testDecodeOptions)
	dhcp2 := p2.Layer(LayerTypeDHCPv4).(*DHCPv4)
	testDHCPEqual(t, dhcp, dhcp2)
}

func TestDHCPv4EncodeResponse(t *testing.T) {
	dhcp := &DHCPv4{Operation: DHCPOpReply, HardwareType: LinkTypeEthernet, Xid: 0x12345678,
		ClientIP: net.IP{0, 0, 0, 0}, YourClientIP: net.IP{192, 168, 0, 123}, NextServerIP: net.IP{192, 168, 0, 1}, RelayAgentIP: net.IP{0, 0, 0, 0},
		ClientHWAddr: net.HardwareAddr{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
		ServerName:   make([]byte, 64), File: make([]byte, 128)}

	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptMessageType, []byte{byte(DHCPMsgTypeOffer)}))
	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptSubnetMask, []byte{255, 255, 255, 0}))
	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptPad, nil))
	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptT1, []byte{0x00, 0x00, 0x0e, 0x10}))
	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptT2, []byte{0x00, 0x00, 0x0e, 0x10}))
	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptLeaseTime, []byte{0x00, 0x00, 0x0e, 0x10}))
	dhcp.Options = append(dhcp.Options, NewDHCPOption(DHCPOptServerID, []byte{192, 168, 0, 1}))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, dhcp)
	if err != nil {
		t.Fatal(err)
	}

	p2 := gopacket.NewPacket(buf.Bytes(), LayerTypeDHCPv4, testDecodeOptions)
	dhcp2 := p2.Layer(LayerTypeDHCPv4).(*DHCPv4)
	testDHCPEqual(t, dhcp, dhcp2)
}

// TestDHCPv4SerializeOversized: a message carried by a UDP jumbogram can be
// longer than the uint16 Len() counts; SerializeTo used to size its buffer
// with the wrapped value and index past it.
func TestDHCPv4SerializeOversized(t *testing.T) {
	for _, optlen := range []int{65294, 65295, 65600} {
		data := make([]byte, 240+optlen)
		data[0] = byte(DHCPOpRequest)
		binary.BigEndian.PutUint32(data[236:240], DHCPMagic)

		var dhcp DHCPv4
		if err := dhcp.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Fatalf("[%d] %v", optlen, err)
		}

		buf := gopacket.NewSerializeBuffer()
		if err := dhcp.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
			t.Fatalf("[%d] %v", optlen, err)
		}
		if want := append(data, byte(DHCPOptEnd)); !bytes.Equal(want, buf.Bytes()) {
			t.Errorf("[%d] serialized %d bytes differ from the %d expected", optlen, len(buf.Bytes()), len(want))
		}
	}
}

func TestDHCPv4DecodeOption(t *testing.T) {
	var tests = []struct {
		msg string
		buf []byte
		err error
	}{
		{
			msg: "DHCPOptPad",
			buf: []byte{0},
			err: nil,
		},
		{
			msg: "Option with zero length",
			buf: []byte{119, 0},
			err: nil,
		},
		{
			msg: "Option with maximum length",
			buf: bytes.Join([][]byte{
				{119, 255},
				bytes.Repeat([]byte{0}, 255),
			}, nil),
			err: nil,
		},
		{
			msg: "Too short option",
			buf: []byte{},
			err: DecOptionNotEnoughData,
		},
		{
			msg: "Too short option when option is not 0 or 255",
			buf: []byte{119},
			err: DecOptionNotEnoughData,
		},
		{
			msg: "Malformed option",
			buf: []byte{119, 1},
			err: DecOptionMalformed,
		},
	}

	for i := range tests {
		var (
			opt = new(DHCPOption)
			err = opt.decode(tests[i].buf)
		)
		if want, got := tests[i].err, err; want != got {
			t.Errorf("[#%v %v] Unexpected error want: %v, got: %v\n", i, tests[i].msg, want, err)
		}
	}
}

// Option Overload (RFC 2131 section 4.1) continues the option list in the
// 'file' and then the 'sname' field; the two fields themselves stay as read.
func TestDHCPv4DecodeOptionOverload(t *testing.T) {
	msgType := []byte{byte(DHCPOptMessageType), 1, byte(DHCPMsgTypeAck)}
	router := []byte{byte(DHCPOptRouter), 4, 192, 168, 1, 66}
	end := []byte{byte(DHCPOptEnd)}
	overload := func(value byte) []byte {
		return []byte{byte(DHCPOptExtOptions), 1, value, byte(DHCPOptEnd)}
	}

	var tests = []struct {
		msg     string
		options []byte
		file    []byte
		sname   []byte
		want    []DHCPOpt
	}{
		{
			msg:     "No overload",
			options: end,
			file:    bytes.Join([][]byte{msgType, end}, nil),
			sname:   bytes.Join([][]byte{router, end}, nil),
		},
		{
			msg:     "Overload file",
			options: overload(1),
			file:    bytes.Join([][]byte{msgType, end}, nil),
			sname:   bytes.Join([][]byte{router, end}, nil),
			want:    []DHCPOpt{DHCPOptExtOptions, DHCPOptMessageType},
		},
		{
			msg:     "Overload sname",
			options: overload(2),
			file:    bytes.Join([][]byte{msgType, end}, nil),
			sname:   bytes.Join([][]byte{router, end}, nil),
			want:    []DHCPOpt{DHCPOptExtOptions, DHCPOptRouter},
		},
		{
			msg:     "Overload both, file before sname",
			options: overload(3),
			file:    bytes.Join([][]byte{msgType, end}, nil),
			sname:   bytes.Join([][]byte{router, end}, nil),
			want:    []DHCPOpt{DHCPOptExtOptions, DHCPOptMessageType, DHCPOptRouter},
		},
		{
			msg:     "Overload inside file is not followed",
			options: overload(1),
			file:    overload(2),
			sname:   bytes.Join([][]byte{router, end}, nil),
			want:    []DHCPOpt{DHCPOptExtOptions, DHCPOptExtOptions},
		},
		{
			msg:     "Malformed option in sname ends that field without failing",
			options: overload(3),
			file:    bytes.Join([][]byte{msgType, end}, nil),
			sname:   bytes.Join([][]byte{router, {byte(DHCPOptHostname), 63}}, nil),
			want:    []DHCPOpt{DHCPOptExtOptions, DHCPOptMessageType, DHCPOptRouter},
		},
	}

	for i := range tests {
		data := make([]byte, 240, 240+len(tests[i].options))
		copy(data[44:108], tests[i].sname)
		copy(data[108:236], tests[i].file)
		binary.BigEndian.PutUint32(data[236:240], DHCPMagic)
		data = append(data, tests[i].options...)

		var d DHCPv4
		if err := d.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("[#%v %v] Unexpected error: %v", i, tests[i].msg, err)
			continue
		}
		var got []DHCPOpt
		for _, o := range d.Options {
			got = append(got, o.Type)
		}
		if want := tests[i].want; !reflect.DeepEqual(want, got) {
			t.Errorf("[#%v %v] Unexpected options want: %v, got: %v", i, tests[i].msg, want, got)
		}
		if !bytes.Equal(d.File, data[108:236]) || !bytes.Equal(d.ServerName, data[44:108]) {
			t.Errorf("[#%v %v] File or ServerName changed", i, tests[i].msg)
		}

		// The overloaded options live in File and ServerName already, so a
		// round trip must not write them a second time.
		buf := gopacket.NewSerializeBuffer()
		if err := d.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
			t.Errorf("[#%v %v] SerializeTo: %v", i, tests[i].msg, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), data) {
			t.Errorf("[#%v %v] round trip changed the message:\n got %x\nwant %x", i, tests[i].msg, buf.Bytes(), data)
		}
		if int(d.Len()) != len(data) {
			t.Errorf("[#%v %v] Len() = %d, want %d", i, tests[i].msg, d.Len(), len(data))
		}
	}
}

func testDHCPEqual(t *testing.T, d1, d2 *DHCPv4) {
	if d1.Operation != d2.Operation {
		t.Errorf("expected Operation=%s, got %s", d1.Operation, d2.Operation)
	}
	if d1.HardwareType != d2.HardwareType {
		t.Errorf("expected HardwareType=%s, got %s", d1.HardwareType, d2.HardwareType)
	}
	if d1.HardwareLen != d2.HardwareLen {
		t.Errorf("expected HardwareLen=%v, got %v", d1.HardwareLen, d2.HardwareLen)
	}
	if d1.RelayHops != d2.RelayHops {
		t.Errorf("expected RelayHops=%v, got %v", d1.RelayHops, d2.RelayHops)
	}
	if d1.Xid != d2.Xid {
		t.Errorf("expected Xid=%v, got %v", d1.Xid, d2.Xid)
	}
	if d1.Secs != d2.Secs {
		t.Errorf("expected Secs=%v, got %v", d1.Secs, d2.Secs)
	}
	if d1.Flags != d2.Flags {
		t.Errorf("expected Flags=%v, got %v", d1.Flags, d2.Flags)
	}
	if !d1.ClientIP.Equal(d2.ClientIP) {
		t.Errorf("expected ClientIP=%v, got %v", d1.ClientIP, d2.ClientIP)
	}
	if !d1.YourClientIP.Equal(d2.YourClientIP) {
		t.Errorf("expected YourClientIP=%v, got %v", d1.YourClientIP, d2.YourClientIP)
	}
	if !d1.NextServerIP.Equal(d2.NextServerIP) {
		t.Errorf("expected NextServerIP=%v, got %v", d1.NextServerIP, d2.NextServerIP)
	}
	if !d1.RelayAgentIP.Equal(d2.RelayAgentIP) {
		t.Errorf("expected RelayAgentIP=%v, got %v", d1.RelayAgentIP, d2.RelayAgentIP)
	}
	if !bytes.Equal(d1.ClientHWAddr, d2.ClientHWAddr) {
		t.Errorf("expected ClientHWAddr=%v, got %v", d1.ClientHWAddr, d2.ClientHWAddr)
	}
	if !bytes.Equal(d1.ServerName, d2.ServerName) {
		t.Errorf("expected ServerName=%v, got %v", d1.ServerName, d2.ServerName)
	}
	if !bytes.Equal(d1.File, d2.File) {
		t.Errorf("expected File=%v, got %v", d1.File, d2.File)
	}
	if len(d1.Options) != len(d2.Options) {
		t.Errorf("expected %d options, got %d", len(d1.Options), len(d2.Options))
	}

	for i, o := range d1.Options {
		testDHCPOptionEqual(t, i, o, d2.Options[i])
	}
}

func testDHCPOptionEqual(t *testing.T, idx int, d1, d2 DHCPOption) {
	if d1.Type != d2.Type {
		t.Errorf("expection Options[%d].Type = %s, got %s", idx, d1.Type, d2.Type)
	}
	if !bytes.Equal(d1.Data, d2.Data) {
		t.Errorf("expection Options[%d].Data to be = %v, got %v", idx, d1.Data, d2.Data)
	}
}

// Fixed-width BOOTP fields shorter than their slot must not keep the bytes
// a reused SerializeBuffer still holds from the previous packet.
func TestDHCPv4EncodeReusedBuffer(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	dirty, _ := buf.PrependBytes(241)
	for i := range dirty {
		dirty[i] = 0xff
	}

	dhcp := &DHCPv4{Operation: DHCPOpRequest, HardwareType: LinkTypeEthernet, Xid: 0x12345678,
		ClientHWAddr: net.HardwareAddr{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
		ServerName:   []byte("srv"), File: []byte("boot")}
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, dhcp); err != nil {
		t.Fatal(err)
	}

	want := make([]byte, 224)
	copy(want[16:], dhcp.ClientHWAddr)
	copy(want[32:], dhcp.ServerName)
	copy(want[96:], dhcp.File)
	if got := buf.Bytes()[12:236]; !bytes.Equal(got, want) {
		t.Errorf("stale buffer bytes in serialized header:\ngot  %x\nwant %x", got, want)
	}
}
