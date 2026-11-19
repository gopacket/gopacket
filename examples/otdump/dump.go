// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

// Streams idle for streamIdle are flushed, checked every flushEvery of
// capture time, so out-of-order data does not wait forever on a live
// capture.
const (
	streamIdle = 2 * time.Minute
	flushEvery = time.Minute
)

// eofMode tells a drain whether the direction has ended.
type eofMode int

const (
	moreData eofMode = iota
	atEOF
)

// dumper prints one line per OT PDU and counts the layers it decoded.
type dumper struct {
	out       io.Writer
	assembler *reassembly.Assembler
	lastFlush time.Time

	// counts holds every layer decoded from OT traffic, by type.
	counts map[gopacket.LayerType]int
}

func newDumper(out io.Writer) *dumper {
	d := &dumper{out: out, counts: map[gopacket.LayerType]int{}}
	d.assembler = reassembly.NewAssembler(reassembly.NewStreamPool(&streamFactory{d: d}))
	return d
}

// packet feeds TCP on an OT port to reassembly and decodes the rest in
// place.
func (d *dumper) packet(p gopacket.Packet) {
	ci := p.Metadata().CaptureInfo
	d.flushIdle(ci.Timestamp)

	tcp, _ := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcp != nil && p.NetworkLayer() != nil && otPort(tcp) {
		d.assembler.AssembleWithContext(p.NetworkLayer().NetworkFlow(), tcp, &captureCtx{ci})
		return
	}

	if !hasOTLayer(p) {
		return
	}
	d.print(packetFlow(p), p)
}

// flushIdle closes streams idle for streamIdle, at most every flushEvery.
func (d *dumper) flushIdle(now time.Time) {
	if now.Sub(d.lastFlush) < flushEvery {
		return
	}

	if !d.lastFlush.IsZero() {
		d.assembler.FlushCloseOlderThan(now.Add(-streamIdle))
	}
	d.lastFlush = now
}

// flush completes every open stream.
func (d *dumper) flush() {
	d.assembler.FlushAll()
}

// pdu decodes one PDU cut from a stream and prints it.
func (d *dumper) pdu(flow string, layer gopacket.LayerType, pdu []byte) {
	d.print(flow, gopacket.NewPacket(pdu, layer, gopacket.Default))
}

// print counts the layers of p and prints its summary line.
func (d *dumper) print(flow string, p gopacket.Packet) {
	for _, l := range p.Layers() {
		d.counts[l.LayerType()]++
	}

	line := summary(p)
	if e := p.ErrorLayer(); e != nil {
		line += fmt.Sprintf(" error=%q", e.Error())
	}
	fmt.Fprintf(d.out, "%s %s\n", flow, line)
}

// otPort reports whether either port of tcp carries an OT stream.
func otPort(tcp *layers.TCP) bool {
	_, _, ok := streamDecoder(tcp)
	return ok
}

// streamDecoder returns the splitter and layer type for the OT port of
// tcp, the server port first.
func streamDecoder(tcp *layers.TCP) (bufio.SplitFunc, gopacket.LayerType, bool) {
	if split, layer, ok := layers.OTStreamDecoder(tcp.DstPort); ok {
		return split, layer, true
	}
	return layers.OTStreamDecoder(tcp.SrcPort)
}

// packetFlow names the endpoints of a packet decoded in place.
func packetFlow(p gopacket.Packet) string {
	if n := p.NetworkLayer(); n != nil {
		if t := p.TransportLayer(); t != nil {
			return endpoints(n.NetworkFlow(), t.TransportFlow())
		}
		return n.NetworkFlow().String()
	}
	if l := p.LinkLayer(); l != nil {
		return l.LinkFlow().String()
	}
	return "?"
}

// endpoints formats a flow as "src:port->dst:port".
func endpoints(net, transport gopacket.Flow) string {
	return fmt.Sprintf("%v:%v->%v:%v", net.Src(), transport.Src(), net.Dst(), transport.Dst())
}

// captureCtx hands reassembly the capture info of a packet.
type captureCtx struct {
	ci gopacket.CaptureInfo
}

func (c *captureCtx) GetCaptureInfo() gopacket.CaptureInfo {
	return c.ci
}

// streamFactory creates one otStream per TCP connection.
type streamFactory struct {
	d *dumper
}

func (f *streamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	split, layer, _ := streamDecoder(tcp)
	return &otStream{
		d:     f.d,
		split: split,
		layer: layer,
		flows: [2]string{endpoints(net, transport), endpoints(net.Reverse(), transport.Reverse())},
	}
}

// otStream splits each direction of a connection into PDUs.
//
//	segments -> half.buf -> split -> PDU -> dumper.pdu
type otStream struct {
	d     *dumper
	split bufio.SplitFunc
	layer gopacket.LayerType

	// flows and halves are indexed by direction, client to server first.
	flows  [2]string
	halves [2]half
}

// half is one direction of a stream: the octets not yet split, the
// COTP segments of an unfinished TSDU, and whether framing was lost for
// good.
type half struct {
	buf  bytes.Buffer
	cotp layers.COTPAssembler
	lost bool
}

// dirIndex maps a direction to its flows and halves index.
func dirIndex(dir reassembly.TCPFlowDirection) int {
	if dir == reassembly.TCPDirClientToServer {
		return 0
	}
	return 1
}

// Accept takes every segment, including those of a connection whose
// handshake the capture missed.
func (s *otStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	*start = true
	return true
}

// ReassembledSG appends in-order data to its direction and splits off
// the PDUs it completes.
func (s *otStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, skip := sg.Info()
	i := dirIndex(dir)
	h := &s.halves[i]

	// After missing octets the buffered PDU and TSDU can never complete.
	// Restart framing at the new data; unless the gap ended on a PDU
	// boundary, splitters without start octets fail on it and stop the
	// direction.
	if skip > 0 {
		fmt.Fprintf(s.d.out, "%s %v gap of %d octets\n", s.flows[i], s.layer, skip)
		h.buf.Reset()
		h.cotp.Reset()
	}

	n, _ := sg.Lengths()
	if h.lost || n == 0 {
		return
	}
	h.buf.Write(sg.Fetch(n))
	s.drain(i, moreData)
}

// ReassemblyComplete splits what is left of both directions.
func (s *otStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	s.drain(0, atEOF)
	s.drain(1, atEOF)
	return true
}

// drain hands each whole PDU buffered for direction i to the dumper. A
// splitter error stops the direction: its framing is lost. Each pass
// consumes octets or returns, so the loop is bounded by the buffer.
func (s *otStream) drain(i int, eof eofMode) {
	h := &s.halves[i]
	for !h.lost {
		adv, tok, err := s.split(h.buf.Bytes(), eof == atEOF)
		if err != nil {
			fmt.Fprintf(s.d.out, "%s %v stream: %v\n", s.flows[i], s.layer, err)
			h.lost = true
			h.buf.Reset()
			return
		}
		if adv == 0 {
			return
		}

		// The token aliases the buffer, so decode it before moving on.
		if tok != nil {
			s.token(i, tok)
		}
		h.buf.Next(adv)
	}
}

// token decodes one PDU of direction i. TPKT frames go through COTP
// segment reassembly first.
func (s *otStream) token(i int, tok []byte) {
	if s.layer != layers.LayerTypeTPKT {
		s.d.pdu(s.flows[i], s.layer, tok)
		return
	}
	s.tpkt(i, tok)
}

// tpkt decodes one TPKT. DT TPDUs go through the COTP assembler, which
// joins the segments of a TSDU too large for one TPDU (as MMS sends
// large responses); the last segment decodes the whole TSDU.
//
//	TPKT|DT      |seg 1   TPKT|DT      |seg 2   TPKT|DT EOT|seg 3
//	                   -> |seg 1 seg 2 seg 3| -> ISO session
func (s *otStream) tpkt(i int, tok []byte) {
	h := &s.halves[i]
	var t layers.TPKT
	var c layers.COTP
	if t.DecodeFromBytes(tok, gopacket.NilDecodeFeedback) != nil ||
		c.DecodeFromBytes(t.Payload, gopacket.NilDecodeFeedback) != nil {
		s.d.pdu(s.flows[i], s.layer, tok)
		return
	}

	tsdu, next, err := h.cotp.Feed(&c)
	if c.Type != layers.COTPTypeDT {
		s.d.pdu(s.flows[i], s.layer, tok)
		return
	}

	// The TSDU is decoded on its own, so count its carriers here.
	s.d.counts[layers.LayerTypeTPKT]++
	s.d.counts[layers.LayerTypeCOTP]++
	switch {
	case err != nil:
		fmt.Fprintf(s.d.out, "%s %v, dropped\n", s.flows[i], err)
	case next != gopacket.LayerTypeZero:
		s.d.pdu(s.flows[i], next, tsdu)
	case c.EOT:
		fmt.Fprintf(s.d.out, "%s COTP DT, no user data\n", s.flows[i])
	default:
		fmt.Fprintf(s.d.out, "%s COTP DT segment, %d octets held\n", s.flows[i], h.cotp.Pending())
	}
}
