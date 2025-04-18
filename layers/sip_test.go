// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// First packet is a REGISTER Request
//
// REGISTER sip:sip.provider.com SIP/2.0
// Via:SIP/2.0/UDP 172.16.254.66:5060;branch=z9hG4bK3e5380d454981e88702eb2269669462;rport
// From:"Bob" <sip:bob@sip.provider.com>;tag=3718850509
// To:"Alice" <sip:alice@sip.provider.com>
// Call-ID:306366781@172_16_254_66
// CSeq:3 REGISTER
// Max-Forwards:70
// Allow:INVITE,ACK,CANCEL,BYE,OPTIONS,INFO,SUBSCRIBE,NOTIFY,REFER,UPDATE
// Contact: <sip:bob@172.16.254.66:5060>
// Expires:1800
// User-Agent:C530 IP/42.245.00.000.000
// Content-Length:0
var testPacketSIPRequest = []byte{
	0x00, 0x07, 0x7d, 0x41, 0x2e, 0x40, 0x00, 0xd0, 0x03, 0x75, 0xe0, 0x00, 0x08, 0x00, 0x45, 0x00,
	0x01, 0xf4, 0x73, 0x74, 0x00, 0x00, 0x75, 0x11, 0xca, 0x7f, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02,
	0x02, 0x02, 0x13, 0xc4, 0x13, 0xc4, 0x01, 0xe0, 0x86, 0xa0, 0x52, 0x45, 0x47, 0x49, 0x53, 0x54,
	0x45, 0x52, 0x20, 0x73, 0x69, 0x70, 0x3a, 0x73, 0x69, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x64, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d,
	0x0a, 0x56, 0x69, 0x61, 0x3a, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x2f, 0x55, 0x44, 0x50,
	0x20, 0x31, 0x37, 0x32, 0x2e, 0x31, 0x36, 0x2e, 0x32, 0x35, 0x34, 0x2e, 0x36, 0x36, 0x3a, 0x35,
	0x30, 0x36, 0x30, 0x3b, 0x62, 0x72, 0x61, 0x6e, 0x63, 0x68, 0x3d, 0x7a, 0x39, 0x68, 0x47, 0x34,
	0x62, 0x4b, 0x33, 0x65, 0x35, 0x33, 0x38, 0x30, 0x64, 0x34, 0x35, 0x34, 0x39, 0x38, 0x31, 0x65,
	0x38, 0x38, 0x37, 0x30, 0x32, 0x65, 0x62, 0x32, 0x32, 0x36, 0x39, 0x36, 0x36, 0x39, 0x34, 0x36,
	0x32, 0x3b, 0x72, 0x70, 0x6f, 0x72, 0x74, 0x0d, 0x0a, 0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x22, 0x42,
	0x6f, 0x62, 0x22, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a, 0x62, 0x6f, 0x62, 0x40, 0x73, 0x69, 0x70,
	0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x3e, 0x3b, 0x74,
	0x61, 0x67, 0x3d, 0x33, 0x37, 0x31, 0x38, 0x38, 0x35, 0x30, 0x35, 0x30, 0x39, 0x0d, 0x0a, 0x54,
	0x6f, 0x3a, 0x22, 0x41, 0x6c, 0x69, 0x63, 0x65, 0x22, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a, 0x61,
	0x6c, 0x69, 0x63, 0x65, 0x40, 0x73, 0x69, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65,
	0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x3e, 0x0d, 0x0a, 0x43, 0x61, 0x6c, 0x6c, 0x2d, 0x49, 0x44, 0x3a,
	0x33, 0x30, 0x36, 0x33, 0x36, 0x36, 0x37, 0x38, 0x31, 0x40, 0x31, 0x37, 0x32, 0x5f, 0x31, 0x36,
	0x5f, 0x32, 0x35, 0x34, 0x5f, 0x36, 0x36, 0x0d, 0x0a, 0x43, 0x53, 0x65, 0x71, 0x3a, 0x33, 0x20,
	0x52, 0x45, 0x47, 0x49, 0x53, 0x54, 0x45, 0x52, 0x0d, 0x0a, 0x4d, 0x61, 0x78, 0x2d, 0x46, 0x6f,
	0x72, 0x77, 0x61, 0x72, 0x64, 0x73, 0x3a, 0x37, 0x30, 0x0d, 0x0a, 0x41, 0x6c, 0x6c, 0x6f, 0x77,
	0x3a, 0x49, 0x4e, 0x56, 0x49, 0x54, 0x45, 0x2c, 0x41, 0x43, 0x4b, 0x2c, 0x43, 0x41, 0x4e, 0x43,
	0x45, 0x4c, 0x2c, 0x42, 0x59, 0x45, 0x2c, 0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 0x2c, 0x49,
	0x4e, 0x46, 0x4f, 0x2c, 0x53, 0x55, 0x42, 0x53, 0x43, 0x52, 0x49, 0x42, 0x45, 0x2c, 0x4e, 0x4f,
	0x54, 0x49, 0x46, 0x59, 0x2c, 0x52, 0x45, 0x46, 0x45, 0x52, 0x2c, 0x55, 0x50, 0x44, 0x41, 0x54,
	0x45, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74, 0x3a, 0x20, 0x3c, 0x73, 0x69, 0x70,
	0x3a, 0x62, 0x6f, 0x62, 0x40, 0x31, 0x37, 0x32, 0x2e, 0x31, 0x36, 0x2e, 0x32, 0x35, 0x34, 0x2e,
	0x36, 0x36, 0x3a, 0x35, 0x30, 0x36, 0x30, 0x3e, 0x0d, 0x0a, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65,
	0x73, 0x3a, 0x31, 0x38, 0x30, 0x30, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65,
	0x6e, 0x74, 0x3a, 0x43, 0x35, 0x33, 0x30, 0x20, 0x49, 0x50, 0x2f, 0x34, 0x32, 0x2e, 0x32, 0x34,
	0x35, 0x2e, 0x30, 0x30, 0x2e, 0x30, 0x30, 0x30, 0x2e, 0x30, 0x30, 0x30, 0x0d, 0x0a, 0x43, 0x6f,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x30, 0x0d, 0x0a,
	0x0d, 0x0a,
}

// Second packet is a REGISTER Response
//
// SIP/2.0 200 OK
// Via:SIP/2.0/UDP 172.16.254.66:5060;received=8.8.8.8;rport=5060;branch=z9hG4bK3e5380d454981e88702eb2269669462
// From:"Bob" <sip:bob@sip.provider.com>;tag=3718850509
// To:"Alice" <sip:alice@sip.provider.com>;tag=02-32748-1417c4ac-24835dbf3
// Call-ID:306366781@172_16_254_66
// CSeq:3 REGISTER
// Contact: <sip:bob@172.16.254.66:5060>;expires=1800
// P-Associated-URI: <sip:bob@sip.provider.com>
// Content-Length:0
var testPacketSIPResponse = []byte{
	0x00, 0xd0, 0x00, 0x4a, 0x2c, 0x00, 0x00, 0x07, 0x7d, 0x41, 0x2e, 0x40, 0x08, 0x00, 0x45, 0x00,
	0x01, 0xc1, 0x00, 0x00, 0x40, 0x00, 0x3f, 0x11, 0x34, 0x27, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01,
	0x01, 0x01, 0x13, 0xc4, 0x13, 0xc4, 0x01, 0xad, 0x60, 0x36, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e,
	0x30, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a, 0x56, 0x69, 0x61, 0x3a, 0x53, 0x49,
	0x50, 0x2f, 0x32, 0x2e, 0x30, 0x2f, 0x55, 0x44, 0x50, 0x20, 0x31, 0x37, 0x32, 0x2e, 0x31, 0x36,
	0x2e, 0x32, 0x35, 0x34, 0x2e, 0x36, 0x36, 0x3a, 0x35, 0x30, 0x36, 0x30, 0x3b, 0x72, 0x65, 0x63,
	0x65, 0x69, 0x76, 0x65, 0x64, 0x3d, 0x38, 0x2e, 0x38, 0x2e, 0x38, 0x2e, 0x38, 0x3b, 0x72, 0x70,
	0x6f, 0x72, 0x74, 0x3d, 0x35, 0x30, 0x36, 0x30, 0x3b, 0x62, 0x72, 0x61, 0x6e, 0x63, 0x68, 0x3d,
	0x7a, 0x39, 0x68, 0x47, 0x34, 0x62, 0x4b, 0x33, 0x65, 0x35, 0x33, 0x38, 0x30, 0x64, 0x34, 0x35,
	0x34, 0x39, 0x38, 0x31, 0x65, 0x38, 0x38, 0x37, 0x30, 0x32, 0x65, 0x62, 0x32, 0x32, 0x36, 0x39,
	0x36, 0x36, 0x39, 0x34, 0x36, 0x32, 0x0d, 0x0a, 0x46, 0x72, 0x6f, 0x6d, 0x3a, 0x22, 0x42, 0x6f,
	0x62, 0x22, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a, 0x62, 0x6f, 0x62, 0x40, 0x73, 0x69, 0x70, 0x2e,
	0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x3e, 0x3b, 0x74, 0x61,
	0x67, 0x3d, 0x33, 0x37, 0x31, 0x38, 0x38, 0x35, 0x30, 0x35, 0x30, 0x39, 0x0d, 0x0a, 0x54, 0x6f,
	0x3a, 0x22, 0x41, 0x6c, 0x69, 0x63, 0x65, 0x22, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a, 0x61, 0x6c,
	0x69, 0x63, 0x65, 0x40, 0x73, 0x69, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72,
	0x2e, 0x63, 0x6f, 0x6d, 0x3e, 0x3b, 0x74, 0x61, 0x67, 0x3d, 0x30, 0x32, 0x2d, 0x33, 0x32, 0x37,
	0x34, 0x38, 0x2d, 0x31, 0x34, 0x31, 0x37, 0x63, 0x34, 0x61, 0x63, 0x2d, 0x32, 0x34, 0x38, 0x33,
	0x35, 0x64, 0x62, 0x66, 0x33, 0x0d, 0x0a, 0x43, 0x61, 0x6c, 0x6c, 0x2d, 0x49, 0x44, 0x3a, 0x33,
	0x30, 0x36, 0x33, 0x36, 0x36, 0x37, 0x38, 0x31, 0x40, 0x31, 0x37, 0x32, 0x5f, 0x31, 0x36, 0x5f,
	0x32, 0x35, 0x34, 0x5f, 0x36, 0x36, 0x0d, 0x0a, 0x43, 0x53, 0x65, 0x71, 0x3a, 0x33, 0x20, 0x52,
	0x45, 0x47, 0x49, 0x53, 0x54, 0x45, 0x52, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74,
	0x3a, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a, 0x62, 0x6f, 0x62, 0x40, 0x31, 0x37, 0x32, 0x2e, 0x31,
	0x36, 0x2e, 0x32, 0x35, 0x34, 0x2e, 0x36, 0x36, 0x3a, 0x35, 0x30, 0x36, 0x30, 0x3e, 0x3b, 0x65,
	0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x3d, 0x31, 0x38, 0x30, 0x30, 0x0d, 0x0a, 0x50, 0x2d, 0x41,
	0x73, 0x73, 0x6f, 0x63, 0x69, 0x61, 0x74, 0x65, 0x64, 0x2d, 0x55, 0x52, 0x49, 0x3a, 0x20, 0x3c,
	0x73, 0x69, 0x70, 0x3a, 0x62, 0x6f, 0x62, 0x40, 0x73, 0x69, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x3e, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65,
	0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x30, 0x0d, 0x0a, 0x0d, 0x0a,
}

// Third packet is an INVITE which uses short header forms.
//
// INVITE sip:sip.provider.com SIP/2.0
// v:SIP/2.0/UDP 172.16.254.66:5060;branch=z9hG4bK3e5380d454981e88702eb2269669462;rport
// f:"Bob" <sip:bob@sip.provider.com>
// t:"Alice" <sip:alice@sip.provider.com>
// i:306366781@172_16_254_66
// CSeq:1 INVITE
// Allow:INVITE,ACK,CANCEL,BYE,OPTIONS,INFO,SUBSCRIBE,NOTIFY,REFER,UPDATE
// m: <sip:bob@172.16.254.66:5060>
// l:0

var testPacketSIPCompactInvite = []byte{
	0xb4, 0xfb, 0xe4, 0x1d, 0x65, 0x18, 0x94, 0xc6, 0x91, 0xa3, 0xb8, 0xc6, 0x08, 0x00, 0x45, 0x00,
	0x01, 0x7d, 0xd4, 0x08, 0x40, 0x00, 0x40, 0x11, 0x50, 0x8f, 0x0a, 0x25, 0x00, 0x89, 0x0a, 0x2a,
	0x00, 0x01, 0xcf, 0x80, 0x13, 0xc4, 0x01, 0x69, 0x16, 0x53, 0x49, 0x4e, 0x56, 0x49, 0x54, 0x45,
	0x20, 0x73, 0x69, 0x70, 0x3a, 0x73, 0x69, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65,
	0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x76,
	0x3a, 0x53, 0x49, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x2f, 0x55, 0x44, 0x50, 0x20, 0x31, 0x37, 0x32,
	0x2e, 0x31, 0x36, 0x2e, 0x32, 0x35, 0x34, 0x2e, 0x36, 0x36, 0x3a, 0x35, 0x30, 0x36, 0x30, 0x3b,
	0x62, 0x72, 0x61, 0x6e, 0x63, 0x68, 0x3d, 0x7a, 0x39, 0x68, 0x47, 0x34, 0x62, 0x4b, 0x33, 0x65,
	0x35, 0x33, 0x38, 0x30, 0x64, 0x34, 0x35, 0x34, 0x39, 0x38, 0x31, 0x65, 0x38, 0x38, 0x37, 0x30,
	0x32, 0x65, 0x62, 0x32, 0x32, 0x36, 0x39, 0x36, 0x36, 0x39, 0x34, 0x36, 0x32, 0x3b, 0x72, 0x70,
	0x6f, 0x72, 0x74, 0x0d, 0x0a, 0x66, 0x3a, 0x22, 0x42, 0x6f, 0x62, 0x22, 0x20, 0x3c, 0x73, 0x69,
	0x70, 0x3a, 0x62, 0x6f, 0x62, 0x40, 0x73, 0x69, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64,
	0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x3e, 0x0d, 0x0a, 0x74, 0x3a, 0x22, 0x41, 0x6c, 0x69, 0x63,
	0x65, 0x22, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a, 0x61, 0x6c, 0x69, 0x63, 0x65, 0x40, 0x73, 0x69,
	0x70, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6d, 0x3e, 0x0d,
	0x0a, 0x69, 0x3a, 0x33, 0x30, 0x36, 0x33, 0x36, 0x36, 0x37, 0x38, 0x31, 0x40, 0x31, 0x37, 0x32,
	0x5f, 0x31, 0x36, 0x5f, 0x32, 0x35, 0x34, 0x5f, 0x36, 0x36, 0x0d, 0x0a, 0x43, 0x53, 0x65, 0x71,
	0x3a, 0x31, 0x20, 0x49, 0x4e, 0x56, 0x49, 0x54, 0x45, 0x0d, 0x0a, 0x41, 0x6c, 0x6c, 0x6f, 0x77,
	0x3a, 0x49, 0x4e, 0x56, 0x49, 0x54, 0x45, 0x2c, 0x41, 0x43, 0x4b, 0x2c, 0x43, 0x41, 0x4e, 0x43,
	0x45, 0x4c, 0x2c, 0x42, 0x59, 0x45, 0x2c, 0x4f, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x53, 0x2c, 0x49,
	0x4e, 0x46, 0x4f, 0x2c, 0x53, 0x55, 0x42, 0x53, 0x43, 0x52, 0x49, 0x42, 0x45, 0x2c, 0x4e, 0x4f,
	0x54, 0x49, 0x46, 0x59, 0x2c, 0x52, 0x45, 0x46, 0x45, 0x52, 0x2c, 0x55, 0x50, 0x44, 0x41, 0x54,
	0x45, 0x0d, 0x0a, 0x6d, 0x3a, 0x20, 0x3c, 0x73, 0x69, 0x70, 0x3a, 0x62, 0x6f, 0x62, 0x40, 0x31,
	0x37, 0x32, 0x2e, 0x31, 0x36, 0x2e, 0x32, 0x35, 0x34, 0x2e, 0x36, 0x36, 0x3a, 0x35, 0x30, 0x36,
	0x30, 0x3e, 0x0d, 0x0a, 0x6c, 0x3a, 0x30, 0x0d, 0x0a, 0x0d, 0x0a,
}

// Fourth packet is an INVITE with a payload
// This only contains the SIP Content and Payload, for more readability of the SIP layer
var testPacketSIPOnlyInviteWithPayload = []byte(
	"INVITE sip:sip.provider.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 172.16.254.66:5060;branch=z9hG4bK.xIOVvIsyy;rport\r\n" +
		"From: \"Bob\" <sip:bob@sip.provider.com>\r\n" +
		"To: \"Alice\" <sip:alice@sip.provider.com>\r\n" +
		"Call-Id: 306366781@172_16_254_66\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Allow: INVITE,ACK,CANCEL,BYE,OPTIONS,INFO,SUBSCRIBE,NOTIFY,REFER,UPDATE\r\n" +
		"Contact: <sip:bob@172.16.254.66:5060>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 100\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=bob 4096 1976 IN IP4 172.16.254.66\r\n" +
		"s=Talk\r\n" +
		"c=IN 172.16.254.66\r\n" +
		"t=0 0\r\n" +
		"m=audio 6000 RTP/AVP 0",
)

// Fifth packet is an INVITE with an over-sized payload
// This packet is generated by appending an extra attribute to the payload of the previous packet
var testOverSizedPacketSIPOnlyInviteWithPayload = append(testPacketSIPOnlyInviteWithPayload, []byte("\r\na=This_is_beyond_the_content_length")...)

// Sixth packet is an INVITE identical to the fifth packet, except the 'Content-Length' is absent.
var testOverSizedPacketSIPOnlyInviteWithPayloadNoLength = bytes.Replace(testOverSizedPacketSIPOnlyInviteWithPayload, []byte("Content-Length: 100\r\n"), []byte{}, 1)

// Seventh packet is an INVITE with a payload but no Content-Length header
// This only contains the SIP Content and Payload, for more readability of the SIP layer
var testPacketSIPOnlyInviteWithPayloadNoContentLength = []byte(
	"INVITE sip:sip.provider.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 172.16.254.66:5060;branch=z9hG4bK.xIOVvIsyy;rport\r\n" +
		"From: \"Bob\" <sip:bob@sip.provider.com>\r\n" +
		"To: \"Alice\" <sip:alice@sip.provider.com>\r\n" +
		"Call-Id: 306366781@172_16_254_66\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Allow: INVITE,ACK,CANCEL,BYE,OPTIONS,INFO,SUBSCRIBE,NOTIFY,REFER,UPDATE\r\n" +
		"Contact: <sip:bob@172.16.254.66:5060>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=bob 4096 1976 IN IP4 172.16.254.66\r\n" +
		"s=Talk\r\n" +
		"c=IN 172.16.254.66\r\n" +
		"t=0 0\r\n" +
		"m=audio 6000 RTP/AVP 0",
)

// Eighth packet is an INVITE with no payload and no Content-Length header
// This only contains the SIP Content and Payload, for more readability of the SIP layer
var testPacketSIPOnlyInviteNoContentLength = []byte(
	"INVITE sip:sip.provider.com SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP 172.16.254.66:5060;branch=z9hG4bK.xIOVvIsyy;rport\r\n" +
		"From: \"Bob\" <sip:bob@sip.provider.com>\r\n" +
		"To: \"Alice\" <sip:alice@sip.provider.com>\r\n" +
		"Call-Id: 306366781@172_16_254_66\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Allow: INVITE,ACK,CANCEL,BYE,OPTIONS,INFO,SUBSCRIBE,NOTIFY,REFER,UPDATE\r\n" +
		"Contact: <sip:bob@172.16.254.66:5060>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"\r\n",
)

// This packet is generated by chopping of 10 bytes of a valid packet
// !This should end up with a truncated indication
var testUnderSizedPacketSIPOnlyInviteWithPayload = testPacketSIPOnlyInviteWithPayload[:len(testPacketSIPOnlyInviteWithPayload)-10]

// Incomplete packet that should be reported as truncated
// !This should end up with a truncated indication
var testPacketIncompleteHeaderSection = []byte(
	"INVITE sip:sip.provider.com SIP/2.0\r\n" +
		"From: \"Bob\" <sip:bob@sip.provider.com>\r\n" +
		"To: \"Alice\" <sip:alice@sip.provider.com>\r\n" +
		"Call-Id: 306366781@172_16_254_66\r\n",
)

// TestPacket that contains and abnormally large CSEQ value
// !This will trigger a parse-error
var testPacketInvalidCSEQMaxedout = []byte(
	"INVITE sip:sip.provider.com SIP/2.0\r\n" +
		"From: \"Bob\" <sip:bob@sip.provider.com>\r\n" +
		"To: \"Alice\" <sip:alice@sip.provider.com>\r\n" +
		"Call-Id: 306366781@172_16_254_66\r\n" +
		"CSeq: 4294967296 INVITE\r\n" +
		"\r\n",
)

// TestPacket that contains and negative CSEQ value
// !This will trigger a parse-error
var testPacketInvalidCSEQSubZero = []byte(
	"INVITE sip:sip.provider.com SIP/2.0\r\n" +
		"From: \"Bob\" <sip:bob@sip.provider.com>\r\n" +
		"To: \"Alice\" <sip:alice@sip.provider.com>\r\n" +
		"Call-Id: 306366781@172_16_254_66\r\n" +
		"CSeq: -1 INVITE\r\n" +
		"\r\n",
)

// TestPacket that contains and negative Content-Length value
// !This will trigger a parse-error
var testPacketInvalidContentLengthSubZero = []byte(
	"INVITE sip:sip.provider.com SIP/2.0\r\n" +
		"From: \"Bob\" <sip:bob@sip.provider.com>\r\n" +
		"To: \"Alice\" <sip:alice@sip.provider.com>\r\n" +
		"Call-Id: 306366781@172_16_254_66\r\n" +
		"CSeq: 101 INVITE\r\n" +
		"Content-Length: -129\r\n" +
		"\r\n",
)

// TestPacket that contains and abnormally large Content-Length value
// !This will trigger a parse-error
var testPacketInvalidContentLengthMaxedout = []byte(
	"INVITE sip:sip.provider.com SIP/2.0\r\n" +
		"From: \"Bob\" <sip:bob@sip.provider.com>\r\n" +
		"To: \"Alice\" <sip:alice@sip.provider.com>\r\n" +
		"Call-Id: 306366781@172_16_254_66\r\n" +
		"CSeq: 101 INVITE\r\n" +
		"Content-Length: 94294967296\r\n" +
		"\r\n",
)

func TestSIPDecode(t *testing.T) {
	type args struct {
		firstLayerDecoder gopacket.Decoder
		packetData        []byte
	}
	tests := []struct {
		name              string
		args              args
		wantError         string
		wantTruncated     bool
		wantIsResponse    bool
		wantMethod        SIPMethod
		wantCseq          int64
		wantContentLength int64
		wantHeaders       map[string][]string
		wantRequestURI    string
		wantPayload       []byte
	}{
		{"invalid CSEQ sub-zero", args{LayerTypeSIP, testPacketInvalidCSEQSubZero},
			`invalid CSEQ value: strconv.ParseUint: parsing "-1": invalid syntax`,
			false, false, SIPMethodInfo, 1, 0, map[string][]string{}, "", []byte{},
		},
		{"invalid CSEQ", args{LayerTypeSIP, testPacketInvalidCSEQMaxedout},
			`invalid CSEQ value: strconv.ParseUint: parsing "4294967296": value out of range`,
			false, false, SIPMethodInfo, 1, 0, map[string][]string{}, "", []byte{},
		},
		{"invalid Content-Length sub-zero", args{LayerTypeSIP, testPacketInvalidContentLengthSubZero},
			"invalid Content-Length: -129 out of range",
			false, false, SIPMethodInfo, 1, 0, map[string][]string{}, "", []byte{},
		},
		{"invalid Content-Length maxedout", args{LayerTypeSIP, testPacketInvalidContentLengthMaxedout},
			`invalid Content-Length: strconv.ParseInt: parsing "94294967296": value out of range`,
			false, false, SIPMethodInfo, 1, 0, map[string][]string{}, "", []byte{},
		},
		{"single empty line", args{LayerTypeSIP, []byte("\r\n")},
			`invalid first SIP line, empty`,
			false, false, SIPMethodInfo, 1, 0, map[string][]string{}, "", []byte{},
		},
		{"empty", args{LayerTypeSIP, []byte("")},
			``,
			true, false, 0, 0, 0, map[string][]string{},
			"", []byte{},
		},
		{"incomplete header section", args{LayerTypeSIP, testPacketIncompleteHeaderSection},
			``,
			true, false, SIPMethodInvite, 0, 0, map[string][]string{},
			"sip:sip.provider.com", []byte{},
		},
		{"inviteNoContentLength", args{LayerTypeSIP, testPacketSIPOnlyInviteNoContentLength},
			"", false, false, SIPMethodInvite, 1, 0,
			map[string][]string{
				"call-id":      {`306366781@172_16_254_66`},
				"contact":      {`<sip:bob@172.16.254.66:5060>`},
				"from":         {`"Bob" <sip:bob@sip.provider.com>`},
				"to":           {`"Alice" <sip:alice@sip.provider.com>`},
				"content-type": {`application/sdp`},
			}, "sip:sip.provider.com", []byte{},
		},
		{"inviteWithPayloadNoContentLength", args{LayerTypeSIP, testPacketSIPOnlyInviteWithPayloadNoContentLength},
			"", false, false, SIPMethodInvite, 1, 0,
			map[string][]string{
				"call-id":      {`306366781@172_16_254_66`},
				"contact":      {`<sip:bob@172.16.254.66:5060>`},
				"from":         {`"Bob" <sip:bob@sip.provider.com>`},
				"to":           {`"Alice" <sip:alice@sip.provider.com>`},
				"content-type": {`application/sdp`},
			},
			"sip:sip.provider.com",
			[]byte("v=0\r\no=bob 4096 1976 IN IP4 172.16.254.66\r\ns=Talk\r\nc=IN 172.16.254.66\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0"),
		},
		{"overSizedInviteWithPayloadNoLength", args{LayerTypeSIP, testOverSizedPacketSIPOnlyInviteWithPayloadNoLength},
			"", false, false, SIPMethodInvite, 1, 0,
			map[string][]string{
				"call-id":      {`306366781@172_16_254_66`},
				"contact":      {`<sip:bob@172.16.254.66:5060>`},
				"from":         {`"Bob" <sip:bob@sip.provider.com>`},
				"to":           {`"Alice" <sip:alice@sip.provider.com>`},
				"content-type": {`application/sdp`},
			},
			"sip:sip.provider.com",
			[]byte("v=0\r\no=bob 4096 1976 IN IP4 172.16.254.66\r\ns=Talk\r\nc=IN 172.16.254.66\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\na=This_is_beyond_the_content_length"),
		},
		{"overSizedInviteWithPayload", args{LayerTypeSIP, testOverSizedPacketSIPOnlyInviteWithPayload},
			"", false, false, SIPMethodInvite, 1, 100,
			map[string][]string{
				"call-id":        {`306366781@172_16_254_66`},
				"contact":        {`<sip:bob@172.16.254.66:5060>`},
				"from":           {`"Bob" <sip:bob@sip.provider.com>`},
				"to":             {`"Alice" <sip:alice@sip.provider.com>`},
				"content-type":   {`application/sdp`},
				"content-length": {`100`},
			},
			"sip:sip.provider.com",
			[]byte("v=0\r\no=bob 4096 1976 IN IP4 172.16.254.66\r\ns=Talk\r\nc=IN 172.16.254.66\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0"),
		},
		{"underSizedInviteWithPayload", args{LayerTypeSIP, testUnderSizedPacketSIPOnlyInviteWithPayload},
			"", true, false, SIPMethodInvite, 1, 100,
			map[string][]string{
				"call-id":        {`306366781@172_16_254_66`},
				"contact":        {`<sip:bob@172.16.254.66:5060>`},
				"from":           {`"Bob" <sip:bob@sip.provider.com>`},
				"to":             {`"Alice" <sip:alice@sip.provider.com>`},
				"content-type":   {`application/sdp`},
				"content-length": {`100`},
			},
			"sip:sip.provider.com",
			[]byte("v=0\r\no=bob 4096 1976 IN IP4 172.16.254.66\r\ns=Talk\r\nc=IN 172.16.254.66\r\nt=0 0\r\nm=audio 6000"),
		},
		{"inviteWithPayload", args{LayerTypeSIP, testPacketSIPOnlyInviteWithPayload},
			"", false, false, SIPMethodInvite, 1, 100,
			map[string][]string{
				"call-id":        {`306366781@172_16_254_66`},
				"contact":        {`<sip:bob@172.16.254.66:5060>`},
				"from":           {`"Bob" <sip:bob@sip.provider.com>`},
				"to":             {`"Alice" <sip:alice@sip.provider.com>`},
				"content-type":   {`application/sdp`},
				"content-length": {`100`},
			},
			"sip:sip.provider.com",
			[]byte("v=0\r\no=bob 4096 1976 IN IP4 172.16.254.66\r\ns=Talk\r\nc=IN 172.16.254.66\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0"),
		},
		{"sipRequest", args{LinkTypeEthernet, testPacketSIPRequest},
			"", false, false, SIPMethodRegister, 3, 0,
			map[string][]string{
				"call-id": {`306366781@172_16_254_66`},
				"contact": {`<sip:bob@172.16.254.66:5060>`},
			},
			"sip:sip.provider.com",
			[]byte{},
		},
		{"sipResponse", args{LinkTypeEthernet, testPacketSIPResponse},
			"", false, true, SIPMethodRegister, 3, 0,
			map[string][]string{
				"call-id": {`306366781@172_16_254_66`},
				"contact": {`<sip:bob@172.16.254.66:5060>;expires=1800`},
			},
			"",
			[]byte{},
		},
		{"compactInvite", args{LinkTypeEthernet, testPacketSIPCompactInvite},
			"", false, false, SIPMethodInvite, 1, 0,
			map[string][]string{
				"i": {`306366781@172_16_254_66`},
				"m": {`<sip:bob@172.16.254.66:5060>`},
				"f": {`"Bob" <sip:bob@sip.provider.com>`},
			},
			"sip:sip.provider.com",
			[]byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := gopacket.NewPacket(tt.args.packetData, tt.args.firstLayerDecoder, gopacket.Default)
			if p.ErrorLayer() != nil {
				assertNotEmpty(t, tt.wantError, "error not expected, actual: %v", p.ErrorLayer().Error())
				assertErrorContains(t, p.ErrorLayer().Error(), tt.wantError)
			} else {
				assertEqual(t, tt.wantTruncated, p.Metadata().Truncated, "truncated")
				assertEmpty(t, tt.wantError, "error expected")

				got, ok := p.Layer(LayerTypeSIP).(*SIP)
				assertTrue(t, ok, "SIP layer not present")

				assertEqual(t, tt.wantIsResponse, got.IsResponse, "Response")
				assertEqual(t, tt.wantMethod, got.Method, "METHOD")
				assertEqual(t, tt.wantCseq, got.GetCSeq(), "CSEQ")
				assertEqual(t, tt.wantContentLength, got.GetContentLength(), "Content-Length")

				assertMultiMapContains(t, tt.wantHeaders, got.Headers)
				assertEqual(t, tt.wantRequestURI, got.RequestURI, "URI")

				assertEqual(t, tt.wantPayload, got.Payload(), "Payload")
			}
			t.Log(p)
		})
	}

}

func TestSIPGetFirstHeader(t *testing.T) {
	type args struct {
		headers map[string][]string
	}
	tests := []struct {
		name         string
		args         args
		wantedHeader string
		wantedValue  string
	}{
		{"from", args{multiMapOf("from", "alice")}, "From", "alice"},
		{"from compact", args{multiMapOf("f", "jane")}, "From", "jane"},
		{"contact", args{multiMapOf("contact", "joe")}, "Contact", "joe"},
		{"contact compact", args{multiMapOf("m", "frank")}, "Contact", "frank"},
		{"call-id", args{multiMapOf("call-id", "123")}, "Call-ID", "123"},
		{"call-id compact", args{multiMapOf("i", "345")}, "Call-ID", "345"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &SIP{Headers: tt.args.headers}
			got := p.GetFirstHeader(tt.wantedHeader)
			assertEqual(t, tt.wantedValue, got)
		})
	}
}

// assertMultiMapContains asserts one multimap is contained within another or fails test.
func assertMultiMapContains(t *testing.T, expected map[string][]string, actual map[string][]string) {
	t.Helper()
	for k := range expected {
		subset(t, actual[k], expected[k], "header %s does not match, actual: %v", k, actual)
	}
}

// assertEqual asserts equality or fails test
func assertEqual(t *testing.T, expected, actual any, msgAndArgs ...any) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		fail(t, fmt.Sprintf("expected: '%v', actual: '%v'", expected, actual), msgAndArgs...)
	}
}

// assertTrue asserts true bool value or fails test
func assertTrue(t *testing.T, b bool, msgAndArgs ...any) {
	t.Helper()
	if !b {
		fail(t, fmt.Sprintf("expected: 'true', actual: '%v'", b), msgAndArgs...)
	}
}

// assertEmpty asserts empty string or fails test
func assertEmpty(t *testing.T, s string, msgAndArgs ...any) {
	t.Helper()
	if s != "" {
		fail(t, fmt.Sprintf("expected: <empty>, actual: '%v'", s), msgAndArgs...)
	}
}

// assertNotEmpty asserts Nonempty string or fails test
func assertNotEmpty(t *testing.T, s string, msgAndArgs ...any) {
	t.Helper()
	if s == "" {
		fail(t, fmt.Sprintf("expected: <NOT-empty>, actual: '%v'", s), msgAndArgs...)
	}
}

// assertErrorContains asserts error containing substring or fails test
func assertErrorContains(t *testing.T, e error, s string, msgAndArgs ...any) {
	t.Helper()
	if !strings.Contains(e.Error(), s) {
		fail(t, fmt.Sprintf("expected: error containing '%v', actual: '%v'", s, e.Error()), msgAndArgs...)
	}
}

// multiMapOf helper function that creates single value map[][] from the values passed
func multiMapOf[K comparable, V any](key K, value V) map[K][]V {
	return map[K][]V{key: {value}}
}

// containsElement try loop over the list check if the list includes the element.
// return (false, false) if impossible.
// return (true, false) if element was not found.
// return (true, true) if element was found.
func containsElement(list interface{}, element interface{}) (ok, found bool) {

	listValue := reflect.ValueOf(list)
	listType := reflect.TypeOf(list)
	if listType == nil {
		return false, false
	}
	listKind := listType.Kind()
	defer func() {
		if e := recover(); e != nil {
			ok = false
			found = false
		}
	}()

	if listKind == reflect.String {
		elementValue := reflect.ValueOf(element)
		return true, strings.Contains(listValue.String(), elementValue.String())
	}

	if listKind == reflect.Map {
		mapKeys := listValue.MapKeys()
		for i := 0; i < len(mapKeys); i++ {
			if reflect.DeepEqual(mapKeys[i].Interface(), element) {
				return true, true
			}
		}
		return true, false
	}

	for i := 0; i < listValue.Len(); i++ {
		if reflect.DeepEqual(listValue.Index(i).Interface(), element) {
			return true, true
		}
	}
	return true, false

}

// subset asserts that the specified list(array, slice...) or map contains all
// elements given in the specified subset list(array, slice...) or map.
//
//	subset(t, [1, 2, 3], [1, 2])
//	subset(t, {"x": 1, "y": 2}, {"x": 1})
func subset(t *testing.T, list, subset interface{}, msgAndArgs ...interface{}) (ok bool) {
	t.Helper()
	if subset == nil {
		return true // we consider nil to be equal to the nil set
	}

	listKind := reflect.TypeOf(list).Kind()
	if listKind != reflect.Array && listKind != reflect.Slice && listKind != reflect.Map {
		return fail(t, fmt.Sprintf("%q has an unsupported type %s", list, listKind), msgAndArgs...)
		//return false
	}

	subsetKind := reflect.TypeOf(subset).Kind()
	if subsetKind != reflect.Array && subsetKind != reflect.Slice && listKind != reflect.Map {
		return fail(t, fmt.Sprintf("%q has an unsupported type %s", subset, subsetKind), msgAndArgs...)
		//return false
	}

	if subsetKind == reflect.Map && listKind == reflect.Map {
		subsetMap := reflect.ValueOf(subset)
		actualMap := reflect.ValueOf(list)

		for _, k := range subsetMap.MapKeys() {
			ev := subsetMap.MapIndex(k)
			av := actualMap.MapIndex(k)

			if !av.IsValid() {
				return fail(t, fmt.Sprintf("%#v does not contain %#v", list, subset), msgAndArgs...)
				//return false
			}
			if !reflect.DeepEqual(ev.Interface(), av.Interface()) {
				return fail(t, fmt.Sprintf("%#v does not contain %#v", list, subset), msgAndArgs...)
				//return false
			}
		}

		return true
	}

	subsetList := reflect.ValueOf(subset)
	for i := 0; i < subsetList.Len(); i++ {
		element := subsetList.Index(i).Interface()
		ok, found := containsElement(list, element)
		if !ok {
			return fail(t, fmt.Sprintf("%#v could not be applied builtin len()", list), msgAndArgs...)
			//return false
		}
		if !found {
			return fail(t, fmt.Sprintf("%#v does not contain %#v", list, element), msgAndArgs...)
			//return false
		}
	}

	return true
}

// fail generates textual messages and reports error on test
func fail(t *testing.T, failureMessage string, msgAndArgs ...interface{}) bool {
	t.Helper()
	msg := ""
	if len(msgAndArgs) == 1 {
		if str, ok := msgAndArgs[0].(string); ok {
			msg = str
		} else {
			msg = fmt.Sprintf("%+v", msgAndArgs[0])
		}
	} else if len(msgAndArgs) > 1 {
		msg = fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...)
	}
	t.Errorf("%s %s", failureMessage, msg)
	return false
}
