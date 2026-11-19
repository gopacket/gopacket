// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// AMS over TCP, port 48898 (Beckhoff ADS specification). Every AMS
// packet travels behind a 6-byte header; fields are little endian.
//
//	+---------+--------+--------------------------+
//	| Command | Length | AMS header | ADS data    |
//	| 2       | 4      | 32         | Length - 32 |
//	+---------+--------+--------------------------+
//
// Command 0 carries an AMS packet. The others talk to the AMS router
// and have their own small bodies, kept raw.
//
// One TCP segment may hold several packets and a packet may span
// segments. The layer decodes the packets a segment holds in full and
// flags a cut one; ScanEtherCATAMSTCP splits a reassembled stream.
//
// The port mapping is opt-in (RegisterOTDecoders) and, as for every TCP
// payload, only applies with DecodeOptions.DecodeStreamsAsDatagrams.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

// TCPPortEtherCATAMS is the TCP port of AMS over TCP.
const TCPPortEtherCATAMS TCPPort = 48898

// LayerTypeEtherCATAMSTCP is the AMS over TCP layer.
var LayerTypeEtherCATAMSTCP = gopacket.RegisterLayerType(192, gopacket.LayerTypeMetadata{Name: "EtherCATAMSTCP", Decoder: gopacket.DecodeFunc(decodeEtherCATAMSTCP)})

const (
	ethercatAMSTCPHeaderLen = 6

	// ethercatAMSTCPMax caps the length a stream packet may claim. ADS
	// has no limit of its own; 16 MiB is far above what routers pass
	// and keeps a forged length from holding memory unbounded.
	ethercatAMSTCPMax = 16 << 20
)

// EtherCATAMSTCPCommand is the command word of the AMS/TCP header.
type EtherCATAMSTCPCommand uint16

// AMS/TCP commands.
const (
	EtherCATAMSTCPPacket       EtherCATAMSTCPCommand = 0x0000
	EtherCATAMSTCPPortClose    EtherCATAMSTCPCommand = 0x0001
	EtherCATAMSTCPPortConnect  EtherCATAMSTCPCommand = 0x1000
	EtherCATAMSTCPRouterNote   EtherCATAMSTCPCommand = 0x1001
	EtherCATAMSTCPGetLocalAddr EtherCATAMSTCPCommand = 0x1002
)

// String returns the command name.
func (c EtherCATAMSTCPCommand) String() string {
	switch c {
	case EtherCATAMSTCPPacket:
		return "AMS command"
	case EtherCATAMSTCPPortClose:
		return "Port close"
	case EtherCATAMSTCPPortConnect:
		return "Port connect"
	case EtherCATAMSTCPRouterNote:
		return "Router notification"
	case EtherCATAMSTCPGetLocalAddr:
		return "Get local net ID"
	}
	return fmt.Sprintf("Unknown(0x%04x)", uint16(c))
}

// EtherCATAMSTCPPDU is one AMS/TCP packet.
//
// Data holds the bytes after the 6-byte header. AMS is set for command 0
// when the AMS header is there. Truncated marks the last packet of a
// segment when the segment ends before Length bytes; Data then holds
// what is there and ADS bodies decode as far as they reach.
type EtherCATAMSTCPPDU struct {
	Command   EtherCATAMSTCPCommand
	Length    uint32
	Data      []byte
	AMS       *EtherCATAMS
	Truncated bool
}

// EtherCATAMSTCP is the AMS over TCP content of one TCP segment, or one
// token of ScanEtherCATAMSTCP. There is no payload.
//
// SignAndEncrypt transports (Secure ADS, TLS on port 8016) are not
// handled.
type EtherCATAMSTCP struct {
	BaseLayer
	PDUs []EtherCATAMSTCPPDU
}

// LayerType returns LayerTypeEtherCATAMSTCP.
func (a *EtherCATAMSTCP) LayerType() gopacket.LayerType { return LayerTypeEtherCATAMSTCP }

// CanDecode returns LayerTypeEtherCATAMSTCP.
func (a *EtherCATAMSTCP) CanDecode() gopacket.LayerClass { return LayerTypeEtherCATAMSTCP }

// NextLayerType returns LayerTypeZero: the layer has no payload.
func (a *EtherCATAMSTCP) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// ErrEtherCATAMSTCP is returned when a segment is too short for an
// AMS/TCP header.
var ErrEtherCATAMSTCP = errors.New("AMS/TCP header truncated")

// ethercatAMSTCPSize returns the size of the packet at the start of b,
// header included, cut to what b holds, and whether it was cut.
func ethercatAMSTCPSize(b []byte) (size int, cut bool) {
	length := binary.LittleEndian.Uint32(b[2:])
	room := len(b) - ethercatAMSTCPHeaderLen
	if uint64(length) > uint64(room) {
		return len(b), true
	}
	return ethercatAMSTCPHeaderLen + int(length), false
}

// DecodeFromBytes decodes the AMS/TCP packets of a TCP segment. A first
// pass counts them, each at least 6 bytes, then the list is allocated
// once. Bytes after the last packet that are too few for a header are
// left out of the layer contents.
func (a *EtherCATAMSTCP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	a.PDUs = a.PDUs[:0]
	if len(data) < ethercatAMSTCPHeaderLen {
		df.SetTruncated()
		return ErrEtherCATAMSTCP
	}

	count := 0
	for rest := data; len(rest) >= ethercatAMSTCPHeaderLen; count++ {
		size, _ := ethercatAMSTCPSize(rest)
		rest = rest[size:]
	}

	if cap(a.PDUs) < count {
		a.PDUs = make([]EtherCATAMSTCPPDU, 0, count)
	}

	used := 0
	for i := 0; i < count; i++ {
		rest := data[used:]
		size, cut := ethercatAMSTCPSize(rest)
		pdu := EtherCATAMSTCPPDU{
			Command:   EtherCATAMSTCPCommand(binary.LittleEndian.Uint16(rest)),
			Length:    binary.LittleEndian.Uint32(rest[2:]),
			Data:      rest[ethercatAMSTCPHeaderLen:size],
			Truncated: cut,
		}

		if pdu.Command == EtherCATAMSTCPPacket {
			pdu.AMS = decodeEtherCATAMS(pdu.Data)
		}
		if cut {
			df.SetTruncated()
		}

		a.PDUs = append(a.PDUs, pdu)
		used += size
	}

	a.BaseLayer = BaseLayer{Contents: data[:used]}
	return nil
}

func decodeEtherCATAMSTCP(data []byte, p gopacket.PacketBuilder) error {
	a := &EtherCATAMSTCP{}
	if err := a.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(a)
	return nil
}

// ScanEtherCATAMSTCP is a bufio.SplitFunc returning one AMS/TCP packet
// per token, decodable as LayerTypeEtherCATAMSTCP. AMS/TCP has no start
// marker to resynchronise on: a length above 16 MiB returns
// ErrOTStreamTooLong, and a stream that ends inside a packet
// ErrOTStreamTruncated. Tokens alias the input.
func ScanEtherCATAMSTCP(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < ethercatAMSTCPHeaderLen {
		return otNeedMore(data, 0, atEOF)
	}

	length := binary.LittleEndian.Uint32(data[2:])
	if length > ethercatAMSTCPMax {
		return 0, nil, fmt.Errorf("%w: AMS/TCP length %d", ErrOTStreamTooLong, length)
	}
	return otCut(data, ethercatAMSTCPHeaderLen+int(length), atEOF)
}
