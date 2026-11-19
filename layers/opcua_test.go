// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// opcuaFrame is the expected summary of one frame: its messages in order,
// each as type[:service id].
type opcuaFrame struct {
	num  int
	want string
}

// Expected summaries, taken from tshark 4.7 (TCP reassembly off) on the
// same files. The captures come from
// https://github.com/cisagov/icsnpp-opcua-binary (BSD-3-Clause), trimmed.
var opcuaPcapFrames = map[string][]opcuaFrame{
	"opcua-minimal.pcap": {
		{7, "HEL"}, {9, "ACK"}, {11, "OPN:446"}, {13, "OPN:449"}, {15, "MSG:461"}, {17, "MSG:464"},
		{19, "MSG:467"}, {21, "MSG:470"}, {23, "MSG:527"}, {25, "MSG:530"}, {27, "MSG:554"},
		{29, "MSG:557"}, {31, "MSG:554"}, {33, "MSG:557"}, {35, "MSG:473"}, {37, "MSG:476"},
		{39, "CLO:452"},
	},
	"opcua-getendpoints.pcap": {
		{5, "HEL"}, {7, "ACK"}, {9, "OPN:446"}, {11, "OPN:449"}, {13, "MSG:428"}, {15, "MSG:431"},
		{17, "CLO:452"},
	},
	"opcua-mainloop.pcap": {
		{6, "HEL"}, {8, "ACK"}, {10, "OPN:446"}, {12, "OPN:449"}, {14, "MSG:428"}, {16, "MSG:431"},
		{18, "CLO:452"}, {26, "HEL"}, {28, "ACK"}, {32, "OPN:446"}, {34, "OPN:449"}, {36, "MSG:428"},
		{38, "MSG:431"}, {40, "MSG:461"}, {42, "MSG:464"}, {44, "MSG:467"}, {46, "MSG:470"},
		{48, "MSG:527"}, {50, "MSG:530"}, {52, "MSG:527"}, {54, "MSG:530"}, {56, "MSG:787"},
		{58, "MSG:790"}, {60, "MSG:751"}, {62, "MSG:754"}, {64, "MSG:826"}, {66, "MSG:826"},
		{68, "MSG:826"}, {70, "MSG:826"}, {72, "MSG:826"}, {74, "MSG:826"},
		{76, "MSG:826 MSG:826 MSG:826"}, {78, "MSG:826"}, {80, "MSG:829"}, {82, "MSG:826"},
		{84, "MSG:631"}, {86, "MSG:634"}, {88, "MSG:673"}, {90, "MSG:676"}, {92, "MSG:673"},
		{94, "MSG:676"}, {96, "MSG:847"}, {98, "MSG:829"}, {99, "MSG:829"}, {100, "MSG:829"},
	},
	// Security mode Sign: the OPN bodies are encrypted, the MSG bodies
	// are signed plaintext.
	"opcua-signed.pcap": {
		{1, "HEL"}, {3, "ACK"}, {5, "OPN"}, {7, "OPN"}, {9, "MSG:461"}, {11, "MSG:464"},
		{13, "MSG:467"}, {15, "MSG:470"}, {17, "MSG:527"}, {19, "MSG:530"},
	},
	// A policy None discovery, then SignAndEncrypt: nothing decodes.
	"opcua-encrypted.pcap": {
		{5, "HEL"}, {7, "ACK"}, {9, "OPN:446"}, {11, "OPN:449"}, {13, "MSG:428"}, {15, "MSG:431"},
		{17, "CLO:452"}, {27, "HEL"}, {29, "ACK"}, {31, "OPN"}, {33, "OPN"}, {35, "MSG"},
		{37, "MSG"}, {39, "MSG"},
	},
	"opcua-read.pcap": {
		{5, "HEL"}, {7, "ACK"}, {9, "OPN:446"}, {11, "OPN:449"}, {13, "MSG:428"}, {15, "MSG:431"},
		{17, "MSG:461"}, {19, "MSG:464"}, {21, "MSG:467"}, {23, "MSG:470"}, {25, "MSG:631"},
		{27, "MSG:634"}, {29, "MSG:631"}, {31, "MSG:634"}, {33, "MSG:631"}, {35, "MSG:634"},
		{37, "MSG:631"}, {39, "MSG:634"},
	},
}

// readOPCUAPcap decodes a capture with the OPC UA port registered.
func readOPCUAPcap(t testing.TB, name string) []gopacket.Packet {
	t.Helper()
	registerOPCUADecoders()
	return readDecodedPcap(t, name)
}

// opcuaLayers returns the OPC UA messages of a packet, in order.
func opcuaLayers(p gopacket.Packet) []*OPCUA {
	var out []*OPCUA
	for _, l := range p.Layers() {
		if ua, ok := l.(*OPCUA); ok {
			out = append(out, ua)
		}
	}
	return out
}

func opcuaSummary(p gopacket.Packet) string {
	var parts []string
	for _, ua := range opcuaLayers(p) {
		s := ua.MessageType.String()
		if ua.Service != nil {
			s += fmt.Sprintf(":%d", ua.Service.ID)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func TestOPCUAPcaps(t *testing.T) {
	for name, frames := range opcuaPcapFrames {
		pkts := readOPCUAPcap(t, name)

		// Every packet decodes without error, and those listed match.
		for i, p := range pkts {
			if el := p.ErrorLayer(); el != nil {
				t.Errorf("%s #%d: %v", name, i+1, el.Error())
			}
		}
		listed := map[int]bool{}
		for _, f := range frames {
			listed[f.num] = true
			if got := opcuaSummary(pkts[f.num-1]); got != f.want {
				t.Errorf("%s #%d: got %q, want %q", name, f.num, got, f.want)
			}
		}

		// No other frame carries OPC UA.
		for i, p := range pkts {
			if !listed[i+1] && len(opcuaLayers(p)) != 0 {
				t.Errorf("%s #%d: unexpected %q", name, i+1, opcuaSummary(p))
			}
		}
	}
}

// opcuaPacketMsg returns the first OPC UA message of frame num.
func opcuaPacketMsg(t *testing.T, name string, num int) *OPCUA {
	t.Helper()
	ua := opcuaLayers(readOPCUAPcap(t, name)[num-1])
	if len(ua) == 0 {
		t.Fatalf("%s #%d: no OPC UA", name, num)
	}
	return ua[0]
}

func TestOPCUAHandshake(t *testing.T) {
	limits := OPCUAConnectionLimits{ReceiveBufferSize: 65536, SendBufferSize: 65536}
	hel := opcuaPacketMsg(t, "opcua-minimal.pcap", 7)
	if hel.ChunkType != OPCUAChunkFinal || hel.Hello.OPCUAConnectionLimits != limits ||
		hel.Hello.EndpointURL != "opc.tcp://localhost:4840/freeopcua/server/" {
		t.Errorf("HEL: %+v", hel.Hello)
	}
	if ack := opcuaPacketMsg(t, "opcua-minimal.pcap", 9); ack.Acknowledge != limits {
		t.Errorf("ACK: %+v", ack.Acknowledge)
	}

	// OpenSecureChannel request, policy None.
	opn := opcuaPacketMsg(t, "opcua-minimal.pcap", 11)
	if opn.SecurityHeader.SecurityPolicyURI != OPCUASecurityPolicyNone || opn.SecurityHeader.SenderCertificate != nil ||
		opn.SequenceNumber != 1 || opn.RequestID != 1 {
		t.Errorf("OPN header: %+v", opn)
	}
	req := opn.Service.OpenSecureChannelRequest
	if req == nil || req.RequestType != OPCUASecurityTokenIssue || req.SecurityMode != OPCUASecurityModeNone ||
		req.RequestedLifetime != 3600000 {
		t.Fatalf("OPN request: %+v", req)
	}
	wantTS := time.Date(2019, 9, 25, 21, 39, 7, 627018000, time.UTC)
	if h := opn.Service.RequestHeader; h == nil || h.RequestHandle != 1 || !h.Timestamp.Equal(wantTS) {
		t.Errorf("request header: %+v", h)
	}

	// The response hands out channel 9, token 14.
	resp := opcuaPacketMsg(t, "opcua-minimal.pcap", 13).Service
	tok := resp.OpenSecureChannelResponse.SecurityToken
	if tok.ChannelID != 9 || tok.TokenID != 14 || tok.RevisedLifetime != 3600000 || !resp.ResponseHeader.ServiceResult.IsGood() {
		t.Errorf("OPN response: %+v", resp.OpenSecureChannelResponse)
	}

	// Later messages carry the channel and token.
	msg := opcuaPacketMsg(t, "opcua-minimal.pcap", 15)
	if msg.SecureChannelID != 9 || msg.TokenID != 14 || msg.Service.ID != OPCUAServiceCreateSessionRequest {
		t.Errorf("MSG: %+v", msg)
	}
	if msg.Service.ID.String() != "CreateSessionRequest" || !msg.Service.ID.IsRequest() {
		t.Errorf("service name %q", msg.Service.ID)
	}
}

func TestOPCUAServices(t *testing.T) {
	ge := opcuaPacketMsg(t, "opcua-getendpoints.pcap", 13).Service
	if ge.GetEndpointsRequest == nil || ge.GetEndpointsRequest.EndpointURL != "opc.tcp://localhost:4840" ||
		ge.RequestHeader.TimeoutHint != 10000 {
		t.Errorf("GetEndpoints: %+v %+v", ge.GetEndpointsRequest, ge.RequestHeader)
	}

	// Read of ns=1;s=Boolean.Variable, Value attribute; the session's
	// authentication token is a GUID NodeId.
	rd := opcuaPacketMsg(t, "opcua-read.pcap", 25).Service
	want := []OPCUAReadValueID{{
		NodeID:      OPCUANodeID{Encoding: OPCUANodeIDString, Namespace: 1, StringID: "Boolean.Variable"},
		AttributeID: OPCUAAttributeValue,
	}}
	if rd.ReadRequest == nil || !reflect.DeepEqual(rd.ReadRequest.NodesToRead, want) {
		t.Fatalf("Read: %+v", rd.ReadRequest)
	}
	if got := rd.ReadRequest.NodesToRead[0].NodeID.String(); got != "ns=1;s=Boolean.Variable" {
		t.Errorf("NodeId string %q", got)
	}
	if rd.RequestHeader.AuthenticationToken.Encoding != OPCUANodeIDGUID {
		t.Errorf("auth token %v", rd.RequestHeader.AuthenticationToken)
	}

	// Three Publish requests in one segment.
	pkt := readOPCUAPcap(t, "opcua-mainloop.pcap")[75]
	if msgs := opcuaLayers(pkt); len(msgs) != 3 || msgs[2].SequenceNumber != msgs[0].SequenceNumber+2 {
		t.Errorf("pipelined: %d messages", len(msgs))
	}
}

func TestOPCUAEncrypted(t *testing.T) {
	opn := opcuaPacketMsg(t, "opcua-encrypted.pcap", 31)
	if opn.SecurityHeader.SecurityPolicyURI != "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15" ||
		len(opn.SecurityHeader.SenderCertificate) == 0 || opn.Service != nil || len(opn.Body) == 0 {
		t.Errorf("encrypted OPN: %+v", opn.SecurityHeader)
	}

	// Ciphertext does not pass for a service.
	msg := opcuaPacketMsg(t, "opcua-encrypted.pcap", 35)
	if msg.Service != nil {
		t.Errorf("encrypted MSG decoded as %v", msg.Service.ID)
	}
}

// le32 appends v little endian.
func le32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }

// uaString appends an OPC UA String.
func uaString(b []byte, s string) []byte { return append(le32(b, uint32(len(s))), s...) }

// uaMessage frames body as a transport message.
func uaMessage(typ string, chunk OPCUAChunkType, body []byte) []byte {
	b := append([]byte(typ), byte(chunk))
	b = le32(b, uint32(opcuaHeaderLen+len(body)))
	return append(b, body...)
}

// uaSecure builds a MSG body: channel, token, sequence header, service.
func uaSecure(service []byte) []byte {
	b := le32(le32(le32(le32(nil, 9), 14), 2), 2)
	return append(b, service...)
}

// uaRequestHeader is a minimal RequestHeader: null token, no timestamp,
// handle 7, no audit id, no additional header.
func uaRequestHeader() []byte {
	b := []byte{0x00, 0x00}
	b = append(b, make([]byte, 8)...)
	b = le32(b, 7)
	b = le32(b, 0)
	b = le32(b, 0xFFFFFFFF)
	b = le32(b, 0)
	return append(b, 0x00, 0x00, 0x00)
}

// uaServiceFault is a ServiceFault whose DiagnosticInfo nests depth
// inner DiagnosticInfos.
func uaServiceFault(depth int) []byte {
	b := []byte{0x01, 0x00, 0x8D, 0x01} // FourByte NodeId i=397
	b = append(b, make([]byte, 8)...)   // timestamp
	b = le32(le32(b, 7), 0x80000000)    // handle, Bad
	b = append(b, bytes.Repeat([]byte{opcuaDiagInnerDiag}, depth)...)
	b = append(b, 0x00)       // innermost DiagnosticInfo, empty
	b = le32(b, 0xFFFFFFFF)   // null string table
	return append(b, 0, 0, 0) // no additional header
}

func decodeUA(data []byte) gopacket.Packet {
	return gopacket.NewPacket(data, LayerTypeOPCUA, gopacket.Default)
}

func TestOPCUAConnectionMessages(t *testing.T) {
	errMsg := uaMessage("ERR", OPCUAChunkFinal, uaString(le32(nil, 0x80830000), "bad url"))
	ua := decodeUA(errMsg).Layer(LayerTypeOPCUA).(*OPCUA)
	if ua.Error.Error.String() != "BadTcpEndpointUrlInvalid" || ua.Error.Reason != "bad url" || !ua.Error.Error.IsBad() {
		t.Errorf("ERR: %+v", ua.Error)
	}

	rhe := uaMessage("RHE", OPCUAChunkFinal, uaString(uaString(nil, "urn:server"), "opc.tcp://h:4840"))
	ua = decodeUA(rhe).Layer(LayerTypeOPCUA).(*OPCUA)
	if ua.ReverseHello != (OPCUAReverseHello{ServerURI: "urn:server", EndpointURL: "opc.tcp://h:4840"}) {
		t.Errorf("RHE: %+v", ua.ReverseHello)
	}

	// An abort chunk carries an error instead of the service.
	abort := uaMessage("MSG", OPCUAChunkAbort, uaSecure(uaString(le32(nil, 0x80800000), "too large")))
	ua = decodeUA(abort).Layer(LayerTypeOPCUA).(*OPCUA)
	if ua.Error.Reason != "too large" || ua.Error.Error.String() != "BadTcpMessageTooLarge" || ua.Service != nil {
		t.Errorf("abort: %+v", ua)
	}
	if ua.ChunkType.String() != "A" || ua.MessageType.String() != "MSG" {
		t.Errorf("names %v %v", ua.ChunkType, ua.MessageType)
	}
}

func TestOPCUAChunked(t *testing.T) {
	// The first chunk of a long Read: header decoded, parameters cut.
	body := append([]byte{0x01, 0x00, 0x77, 0x02}, uaRequestHeader()...)
	body = append(body, make([]byte, 8)...)         // MaxAge
	body = le32(body, 0)                            // TimestampsToReturn
	body = le32(body, 1000)                         // 1000 nodes, few present
	body = append(body, 0x01, 0x02, 0x55, 0x08, 13) // a FourByte NodeId, cut
	ua := decodeUA(uaMessage("MSG", OPCUAChunkIntermediate, uaSecure(body))).Layer(LayerTypeOPCUA).(*OPCUA)
	s := ua.Service
	if s == nil || s.ID != OPCUAServiceReadRequest || s.RequestHeader.RequestHandle != 7 || s.ReadRequest != nil {
		t.Fatalf("chunk: %+v", s)
	}
	if len(s.Params) != 8+4+4+5 {
		t.Errorf("params %d", len(s.Params))
	}
	if n, err := ua.ServiceNodeID(); err != nil || n.String() != "i=631" || n.Encoding != OPCUANodeIDFourByte {
		t.Errorf("ServiceNodeID %v %v", n, err)
	}
}

func TestOPCUANodeIDs(t *testing.T) {
	guid := []byte{0x91, 0x2b, 0x96, 0x72, 0x75, 0xfa, 0xe6, 0x4a, 0x8d, 0x28, 0xb4, 0x04, 0xdc, 0x7d, 0xaf, 0x63}
	cases := []struct {
		wire []byte
		want string
	}{
		{[]byte{0x00, 0x48}, "i=72"},
		{[]byte{0x01, 0x05, 0x01, 0x04}, "ns=5;i=1025"},
		{[]byte{0x02, 0x02, 0x00, 0x15, 0xcd, 0x5b, 0x07}, "ns=2;i=123456789"},
		{uaString([]byte{0x03, 0x01, 0x00}, "Hot水"), "ns=1;s=Hot水"},
		{append([]byte{0x04, 0x04, 0x00}, guid...), "ns=4;g=72962b91-fa75-4ae6-8d28-b404dc7daf63"},
		{append(le32([]byte{0x05, 0x01, 0x00}, 3), 0xde, 0xad, 0xbe), "ns=1;b=3q2+"},
		{le32(uaString([]byte{0xC1, 0x01, 0x02, 0x00}, "urn:x"), 3), "svr=3;nsu=urn:x;i=2"},
	}
	for _, c := range cases {
		r := &opcuaReader{b: c.wire}
		n := r.expandedNodeID()
		if r.err != nil || n.String() != c.want || r.remaining() != 0 {
			t.Errorf("% x: got %q (%v), want %q", c.wire, n, r.err, c.want)
		}
	}

	// A plain NodeId refuses the ExpandedNodeId flags.
	r := &opcuaReader{b: []byte{0x80, 0x00}}
	if r.nodeID(); r.err == nil {
		t.Error("NodeId accepted a namespace URI flag")
	}
}

func TestOPCUAMalformed(t *testing.T) {
	hello := func(url []byte) []byte {
		b := make([]byte, 5*opcuaUint32Len)
		return uaMessage("HEL", OPCUAChunkFinal, append(b, url...))
	}
	cases := map[string]struct {
		data []byte
		want error
	}{
		"short header":    {[]byte("MSGF\x10\x00"), ErrOPCUATruncated},
		"size too big":    {[]byte("HELF\xff\x00\x00\x00\x00"), ErrOPCUATruncated},
		"size too small":  {[]byte("HELF\x04\x00\x00\x00"), ErrOPCUAMalformed},
		"unknown type":    {uaMessage("XYZ", OPCUAChunkFinal, nil), ErrOPCUAMalformed},
		"string lie":      {hello(le32(nil, 0x7FFFFFFF)), ErrOPCUAMalformed},
		"negative string": {hello(le32(nil, 0xFFFFFFF0)), ErrOPCUAMalformed},
		"short body":      {uaMessage("ACK", OPCUAChunkFinal, []byte{1, 2, 3}), ErrOPCUAMalformed},
		"short sequence":  {uaMessage("MSG", OPCUAChunkFinal, []byte{9, 0, 0, 0, 14, 0, 0, 0}), ErrOPCUAMalformed},
	}
	for name, c := range cases {
		el := decodeUA(c.data).ErrorLayer()
		if el == nil || !errors.Is(el.Error(), c.want) {
			t.Errorf("%s: got %v, want %v", name, el, c.want)
		}
	}

	// DiagnosticInfo nests up to the limit; past it the body is kept
	// raw, not an error.
	for depth, decoded := range map[int]bool{opcuaMaxDiagDepth: true, opcuaMaxDiagDepth + 1: false} {
		p := decodeUA(uaMessage("MSG", OPCUAChunkFinal, uaSecure(uaServiceFault(depth))))
		ua, ok := p.Layer(LayerTypeOPCUA).(*OPCUA)
		if !ok || p.ErrorLayer() != nil || (ua.Service != nil) != decoded {
			t.Errorf("DiagnosticInfo depth %d: %+v", depth, ua)
		}
	}

	// An array length beyond the data is refused before any allocation.
	r := &opcuaReader{b: le32(nil, 0x7FFFFFFF)}
	if r.strings(); !errors.Is(r.err, ErrOPCUAMalformed) {
		t.Errorf("array lie: %v", r.err)
	}
}

func TestOPCUASegment(t *testing.T) {
	ack := uaMessage("ACK", OPCUAChunkFinal, make([]byte, 5*opcuaUint32Len))
	data := append(append(append([]byte{}, ack...), ack...), ack[:10]...)

	// Two whole messages become layers; the cut one stays payload.
	p := decodeUA(data)
	msgs := opcuaLayers(p)
	if len(msgs) != 2 || p.ErrorLayer() != nil || !bytes.Equal(msgs[1].Payload, ack[:10]) {
		t.Errorf("got %d messages, error %v", len(msgs), p.ErrorLayer())
	}

	// A DecodingLayerParser sees the first message and its payload.
	var ua OPCUA
	parser := gopacket.NewDecodingLayerParser(LayerTypeOPCUA, &ua)
	var decoded []gopacket.LayerType
	if err := parser.DecodeLayers(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || ua.MessageType != OPCUAMessageAcknowledge || len(ua.Payload) != len(ack)+10 {
		t.Errorf("parser: %v %+v", decoded, ua)
	}
}

// TestOPCUATruncation cuts every message of every capture at every offset.
func TestOPCUATruncation(t *testing.T) {
	for _, msg := range opcuaSeeds(t) {
		for i := 0; i < len(msg); i++ {
			decodeOPCUAAll(msg[:i:i])
		}
	}
}

// opcuaSeeds returns the OPC UA messages of the captures, one per entry.
func opcuaSeeds(t testing.TB) [][]byte {
	var out [][]byte
	for name := range opcuaPcapFrames {
		for _, p := range readOPCUAPcap(t, name) {
			for _, ua := range opcuaLayers(p) {
				out = append(out, ua.Contents)
			}
		}
	}
	return out
}

// decodeOPCUAAll decodes data and touches what a caller could.
func decodeOPCUAAll(data []byte) {
	p := decodeUA(data)
	for _, ua := range opcuaLayers(p) {
		_ = fmt.Sprint(ua, ua.MessageType, ua.ChunkType, ua.Error.Error)
		_, _ = ua.ServiceNodeID()
		if s := ua.Service; s != nil {
			_ = fmt.Sprint(s.ID, s.TypeID, s.ID.IsRequest())
		}
	}
	var ua OPCUA
	var decoded []gopacket.LayerType
	_ = gopacket.NewDecodingLayerParser(LayerTypeOPCUA, &ua).DecodeLayers(data, &decoded)
}

func FuzzOPCUA(f *testing.F) {
	for _, msg := range opcuaSeeds(f) {
		f.Add(msg)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		decodeOPCUAAll(data)
	})
}
