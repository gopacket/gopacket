// Copyright 2017, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
)

func TestNewIPEndpoint(t *testing.T) {
	cases := []struct {
		ip           net.IP
		endpointType gopacket.EndpointType
	}{
		{net.ParseIP("192.168.0.1").To4(), EndpointIPv4},
		{net.ParseIP("192.168.0.1").To16(), EndpointIPv4},
		{net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), EndpointIPv6},
	}

	for _, c := range cases {
		endpoint := NewIPEndpoint(c.ip)
		if endpoint == gopacket.InvalidEndpoint {
			t.Errorf("Failed to create an IP endpoint for %s (%d-bytes)",
				c.ip, len(c.ip))
		}
		if endpoint.EndpointType() != c.endpointType {
			t.Errorf("Wrong endpoint type created for %s (%d-bytes): expected %s, got %s",
				c.ip, len(c.ip), c.endpointType, endpoint.EndpointType())
		}
	}
}

// A transport header shorter than its fixed size still produces a transport
// layer, but one whose ports were never decoded.  Formatting its endpoints
// must not panic.
func TestTruncatedTransportEndpointString(t *testing.T) {
	for _, c := range []struct {
		name  string
		proto IPProtocol
		hdr   []byte
	}{
		{"TCP", IPProtocolTCP, []byte{0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00}},
		{"UDP", IPProtocolUDP, []byte{0x04, 0xd2, 0x00, 0x35}},
		{"SCTP", IPProtocolSCTP, []byte{0x04, 0xd2, 0x00, 0x50}},
	} {
		ip := []byte{
			0x45, 0x00, 0x00, byte(20 + len(c.hdr)), 0x00, 0x00, 0x00, 0x00, 0x40, byte(c.proto), 0x00, 0x00,
			0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02,
		}
		p := gopacket.NewPacket(append(ip, c.hdr...), LayerTypeIPv4, gopacket.Default)
		tl := p.TransportLayer()
		if tl == nil {
			t.Errorf("%s: no transport layer", c.name)
			continue
		}
		src, dst := tl.TransportFlow().Endpoints()
		if s, d := src.String(), dst.String(); s != "" || d != "" {
			t.Errorf("%s: truncated ports formatted as %q, %q, want empty", c.name, s, d)
		}
	}
}
