// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"github.com/gopacket/gopacket"
)

// otSplitCase is one splitter, the layer its tokens decode as and two
// valid PDUs of different shapes.
type otSplitCase struct {
	name  string
	split bufio.SplitFunc
	layer gopacket.LayerType
	pdus  [][]byte
}

// otReadMode selects how a test feeds a stream to bufio.Scanner.
type otReadMode int

const (
	otReadWhole otReadMode = iota
	otReadByByte
)

// otStreamBuf is large enough for any test token, OPC UA included.
const otStreamBuf = opcuaStreamMax + opcuaHeaderLen

var (
	// TPKT carrying an empty COTP DT and a COTP CR with TSAPs and size.
	testTPKTEmpty = []byte{0x03, 0x00, 0x00, 0x07, 0x02, 0xf0, 0x80}
	testTPKTData  = []byte{
		0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,
		0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02, 0xc0, 0x01, 0x0a,
	}

	// IEC 104 STARTDT act and an I frame carrying C_IC_NA_1.
	testIEC104U = []byte{0x68, 0x04, 0x07, 0x00, 0x00, 0x00}
	testIEC104I = []byte{0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14}

	// Modbus read holding registers request and its response.
	testModbusReq  = []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01}
	testModbusResp = []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x03, 0x02, 0x12, 0x34}
)

// testOPCUAHello is a HEL message with a null endpoint URL.
func testOPCUAHello() []byte {
	b := []byte("HELF")
	b = binary.LittleEndian.AppendUint32(b, 32)
	for range 5 {
		b = binary.LittleEndian.AppendUint32(b, 0)
	}
	return binary.LittleEndian.AppendUint32(b, 0xffffffff)
}

// testOPCUAMsg is a MSG chunk with an opaque body of n octets.
func testOPCUAMsg(n int) []byte {
	b := []byte("MSGC")
	b = binary.LittleEndian.AppendUint32(b, uint32(opcuaHeaderLen+n))
	return append(b, make([]byte, n)...)
}

func otSplitCases() []otSplitCase {
	return []otSplitCase{
		{"TPKT", ScanTPKT, LayerTypeTPKT, [][]byte{testTPKTEmpty, testTPKTData}},
		{"DNP3", ScanDNP3, LayerTypeDNP3, [][]byte{
			dnp3Frame(0xc9, 4, 3, nil),
			dnp3Master(0xc0, 0xc0, 0x01, 0x3c, 0x02, 0x06, 0x3c, 0x03, 0x06, 0x3c, 0x04, 0x06, 0x3c, 0x01, 0x06),
		}},
		{"IEC104", ScanIEC104, LayerTypeIEC104, [][]byte{testIEC104U, testIEC104I}},
		{"OPCUA", ScanOPCUA, LayerTypeOPCUA, [][]byte{testOPCUAHello(), testOPCUAMsg(20)}},
		{"Modbus", ScanModbusTCP, LayerTypeModbus, [][]byte{testModbusReq, testModbusResp}},
	}
}

// otScan splits stream with split through a bufio.Scanner.
func otScan(split bufio.SplitFunc, stream []byte, mode otReadMode) ([][]byte, error) {
	var r io.Reader = bytes.NewReader(stream)
	if mode == otReadByByte {
		r = iotest.OneByteReader(r)
	}
	return otScanReader(split, r)
}

func otScanReader(split bufio.SplitFunc, r io.Reader) ([][]byte, error) {
	s := bufio.NewScanner(r)
	s.Buffer(nil, otStreamBuf)
	s.Split(split)

	var out [][]byte
	for s.Scan() {
		out = append(out, bytes.Clone(s.Bytes()))
	}
	return out, s.Err()
}

// otWantTokens fails unless got holds exactly want.
func otWantTokens(t *testing.T, got, want [][]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d tokens, want %d: %x", len(got), len(want), got)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("token %d = %x, want %x", i, got[i], want[i])
		}
	}
}

func TestOTStreamWhole(t *testing.T) {
	for _, tc := range otSplitCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, pdu := range tc.pdus {
				adv, tok, err := tc.split(pdu, false)
				if err != nil || adv != len(pdu) || !bytes.Equal(tok, pdu) {
					t.Fatalf("split(%x) = %d, %x, %v", pdu, adv, tok, err)
				}

				// The token decodes as the paired layer type.
				p := gopacket.NewPacket(tok, tc.layer, gopacket.Default)
				if p.ErrorLayer() != nil {
					t.Fatalf("decode %x: %v", tok, p.ErrorLayer().Error())
				}
				if p.Layer(tc.layer) == nil {
					t.Fatalf("decode %x: no %v layer", tok, tc.layer)
				}
			}
		})
	}
}

func TestOTStreamPrefix(t *testing.T) {
	for _, tc := range otSplitCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, pdu := range tc.pdus {
				for i := 1; i < len(pdu); i++ {
					// Mid-stream, a prefix asks for more data.
					adv, tok, err := tc.split(pdu[:i], false)
					if adv != 0 || tok != nil || err != nil {
						t.Fatalf("split(%x, false) = %d, %x, %v", pdu[:i], adv, tok, err)
					}

					// At EOF, it is a PDU cut short.
					_, tok, err = tc.split(pdu[:i], true)
					if tok != nil || !errors.Is(err, ErrOTStreamTruncated) {
						t.Fatalf("split(%x, true) = %x, %v", pdu[:i], tok, err)
					}
				}

				// An empty stream at EOF is a clean end.
				adv, tok, err := tc.split(nil, true)
				if adv != 0 || tok != nil || err != nil {
					t.Fatalf("split(nil, true) = %d, %x, %v", adv, tok, err)
				}
			}
		})
	}
}

func TestOTStreamBackToBack(t *testing.T) {
	for _, tc := range otSplitCases() {
		t.Run(tc.name, func(t *testing.T) {
			want := [][]byte{tc.pdus[0], tc.pdus[1], tc.pdus[0]}
			stream := bytes.Join(want, nil)
			for _, mode := range []otReadMode{otReadWhole, otReadByByte} {
				got, err := otScan(tc.split, stream, mode)
				if err != nil {
					t.Fatalf("mode %d: %v", mode, err)
				}
				otWantTokens(t, got, want)
			}
		})
	}
}

func TestOTStreamEveryOffset(t *testing.T) {
	for _, tc := range otSplitCases() {
		t.Run(tc.name, func(t *testing.T) {
			want := [][]byte{tc.pdus[1], tc.pdus[0]}
			stream := bytes.Join(want, nil)

			// Deliver the stream as two reads cut at offset i.
			for i := 1; i < len(stream); i++ {
				r := io.MultiReader(bytes.NewReader(stream[:i]), bytes.NewReader(stream[i:]))
				got, err := otScanReader(tc.split, r)
				if err != nil {
					t.Fatalf("cut at %d: %v", i, err)
				}
				otWantTokens(t, got, want)
			}
		})
	}
}

func TestOTStreamTrailingPartial(t *testing.T) {
	for _, tc := range otSplitCases() {
		t.Run(tc.name, func(t *testing.T) {
			pdu := tc.pdus[1]
			stream := append(bytes.Clone(tc.pdus[0]), pdu[:len(pdu)-1]...)
			got, err := otScan(tc.split, stream, otReadByByte)
			if !errors.Is(err, ErrOTStreamTruncated) {
				t.Fatalf("err = %v, want ErrOTStreamTruncated", err)
			}
			otWantTokens(t, got, tc.pdus[:1])
		})
	}
}

func TestOTStreamBadHeader(t *testing.T) {
	tests := []struct {
		name  string
		split bufio.SplitFunc
		data  []byte
		err   error
	}{
		{"TPKT version", ScanTPKT, []byte{0x02, 0x00, 0x00, 0x07, 0x02, 0xf0, 0x80}, ErrOTStreamBadHeader},
		{"TPKT short length", ScanTPKT, []byte{0x03, 0x00, 0x00, 0x06, 0x02, 0xf0}, ErrOTStreamBadHeader},
		{"OPCUA type", ScanOPCUA, []byte("XYZF\x20\x00\x00\x00"), ErrOTStreamBadHeader},
		{"OPCUA chunk", ScanOPCUA, []byte("MSGZ\x20\x00\x00\x00"), ErrOTStreamBadHeader},
		{"OPCUA short size", ScanOPCUA, []byte("MSGF\x07\x00\x00\x00"), ErrOTStreamBadHeader},
		{"OPCUA huge size", ScanOPCUA, []byte("MSGF\x01\x00\x00\x01"), ErrOTStreamTooLong},
		{"OPCUA max uint32", ScanOPCUA, []byte("MSGF\xff\xff\xff\xff"), ErrOTStreamTooLong},
		{"Modbus protocol", ScanModbusTCP, []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x06}, ErrOTStreamBadHeader},
		{"Modbus short length", ScanModbusTCP, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01}, ErrOTStreamBadHeader},
		{"Modbus long length", ScanModbusTCP, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xff}, ErrOTStreamTooLong},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adv, tok, err := tc.split(tc.data, false)
			if adv != 0 || tok != nil || !errors.Is(err, tc.err) {
				t.Fatalf("split = %d, %x, %v, want %v", adv, tok, err, tc.err)
			}
		})
	}
}

func TestOTStreamLimits(t *testing.T) {
	// The largest length each protocol allows waits for its data.
	maxClaims := []struct {
		name  string
		split bufio.SplitFunc
		data  []byte
	}{
		{"TPKT", ScanTPKT, []byte{0x03, 0x00, 0xff, 0xff}},
		{"OPCUA", ScanOPCUA, binary.LittleEndian.AppendUint32([]byte("MSGF"), opcuaStreamMax)},
		{"Modbus", ScanModbusTCP, []byte{0x00, 0x01, 0x00, 0x00, 0x00, modbusMaxLength}},
		{"IEC104", ScanIEC104, []byte{0x68, iec104MaxLength, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, tc := range maxClaims {
		t.Run(tc.name, func(t *testing.T) {
			adv, tok, err := tc.split(tc.data, false)
			if adv != 0 || tok != nil || err != nil {
				t.Fatalf("split = %d, %x, %v", adv, tok, err)
			}

			// Waiting on a large claim must not allocate for it.
			allocs := testing.AllocsPerRun(10, func() {
				tc.split(tc.data, false)
			})
			if allocs != 0 {
				t.Fatalf("%v allocations", allocs)
			}
		})
	}
}

func TestOTStreamResyncDNP3(t *testing.T) {
	a := dnp3Frame(0xc9, 4, 3, nil)
	b := dnp3Master(0xc0, 0xc0, 0x01, 0x3c, 0x02, 0x06)

	// A header with a bad CRC, and one with a length below 5 and a good
	// CRC, are false starts.
	badCRC := bytes.Clone(a)
	badCRC[dnp3HeaderCRCOff] ^= 0xff
	shortHdr := []byte{dnp3Start0, dnp3Start1, dnp3MinLength - 1, 0xc9, 4, 0, 3, 0}
	shortHdr = binary.LittleEndian.AppendUint16(shortHdr, DNP3CRC(shortHdr))

	garbage := [][]byte{{0x00, 0x05, 0x11, 0x05}, badCRC, {0x05}, shortHdr, {0x64, 0x05}}
	stream := bytes.Join([][]byte{garbage[0], a, garbage[1], garbage[2], b, garbage[3], garbage[4], a}, nil)
	for _, mode := range []otReadMode{otReadWhole, otReadByByte} {
		got, err := otScan(ScanDNP3, stream, mode)
		if err != nil {
			t.Fatalf("mode %d: %v", mode, err)
		}
		otWantTokens(t, got, [][]byte{a, b, a})
	}

	// Pure garbage yields nothing and ends cleanly.
	got, err := otScan(ScanDNP3, []byte{0x01, 0x02, 0x64, 0x05, 0x00}, otReadByByte)
	if err != nil || len(got) != 0 {
		t.Fatalf("garbage: %x, %v", got, err)
	}
}

func TestOTStreamResyncIEC104(t *testing.T) {
	// An I frame with a 4 octet length, a U frame with a longer one and
	// a length above 253 are false starts.
	garbage := [][]byte{
		{0x00, 0x11},
		{0x68, 0x04, 0x00, 0x00, 0x00, 0x00},
		{0x68, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00},
		{0x68, 0xfe, 0x00, 0x00, 0x00, 0x00},
	}
	stream := bytes.Join([][]byte{garbage[0], testIEC104U, garbage[1], testIEC104I, garbage[2], garbage[3], testIEC104U}, nil)
	for _, mode := range []otReadMode{otReadWhole, otReadByByte} {
		got, err := otScan(ScanIEC104, stream, mode)
		if err != nil {
			t.Fatalf("mode %d: %v", mode, err)
		}
		otWantTokens(t, got, [][]byte{testIEC104U, testIEC104I, testIEC104U})
	}

	// Pure garbage yields nothing and ends cleanly.
	got, err := otScan(ScanIEC104, []byte{0x01, 0x02, 0x03}, otReadByByte)
	if err != nil || len(got) != 0 {
		t.Fatalf("garbage: %x, %v", got, err)
	}
}

func TestOTStreamNoResync(t *testing.T) {
	// Splitters without start octets stop at garbage after a good PDU.
	for _, tc := range otSplitCases() {
		if tc.name == "DNP3" || tc.name == "IEC104" {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			stream := append(bytes.Clone(tc.pdus[0]), 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee)
			got, err := otScan(tc.split, stream, otReadByByte)
			if !errors.Is(err, ErrOTStreamBadHeader) {
				t.Fatalf("err = %v, want ErrOTStreamBadHeader", err)
			}
			otWantTokens(t, got, tc.pdus[:1])
		})
	}
}

func TestOTStreamDecoder(t *testing.T) {
	tests := []struct {
		port  uint16
		layer gopacket.LayerType
	}{
		{TCPPortTPKT, LayerTypeTPKT},
		{ModbusPort, LayerTypeModbus},
		{TCPPortIEC104, LayerTypeIEC104},
		{TCPPortOPCUA, LayerTypeOPCUA},
		{DNP3Port, LayerTypeDNP3},
	}

	for _, tc := range tests {
		split, layer, ok := OTStreamDecoder(TCPPort(tc.port))
		if !ok || split == nil || layer != tc.layer {
			t.Errorf("port %d: %v, %v, want %v", tc.port, layer, ok, tc.layer)
		}
	}

	if split, layer, ok := OTStreamDecoder(TCPPort(80)); ok || split != nil || layer != gopacket.LayerTypeZero {
		t.Errorf("port 80: %v, %v", layer, ok)
	}
}

func FuzzOTStreamSplit(f *testing.F) {
	for _, tc := range otSplitCases() {
		f.Add(bytes.Join(tc.pdus, nil))
	}
	f.Add([]byte{0x00, 0x05, 0x64, 0x05, 0x68, 0x04, 0x03, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, tc := range otSplitCases() {
			whole, errWhole := otScan(tc.split, data, otReadWhole)
			byByte, errByte := otScan(tc.split, data, otReadByByte)

			// Splitting must not depend on how the stream arrives.
			otWantTokens(t, byByte, whole)
			if (errWhole == nil) != (errByte == nil) || (errWhole != nil && errWhole.Error() != errByte.Error()) {
				t.Fatalf("%s: errors differ: %v, %v", tc.name, errWhole, errByte)
			}

			// Tokens are non-empty, in order and within the input.
			total := 0
			for _, tok := range whole {
				if len(tok) == 0 {
					t.Fatalf("%s: empty token", tc.name)
				}
				total += len(tok)
				gopacket.NewPacket(tok, tc.layer, gopacket.Default)
			}
			if total > len(data) {
				t.Fatalf("%s: %d token octets from %d input", tc.name, total, len(data))
			}
		}
	})
}
