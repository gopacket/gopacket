// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package main

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// hasOTLayer reports whether p holds a layer summary knows.
func hasOTLayer(p gopacket.Packet) bool {
	for _, l := range p.Layers() {
		if _, ok := layerSummary(l); ok {
			return true
		}
	}
	return false
}

// summary describes the innermost OT layer of p, e.g. MMS rather than
// the TPKT carrying it.
func summary(p gopacket.Packet) string {
	ls := p.Layers()
	for i := len(ls) - 1; i >= 0; i-- {
		if s, ok := layerSummary(ls[i]); ok {
			return s
		}
	}
	return "undecoded"
}

// layerSummary returns the protocol name and key fields of an OT layer.
func layerSummary(l gopacket.Layer) (string, bool) {
	switch v := l.(type) {
	case *layers.MMS:
		return mmsSummary(v), true
	case *layers.S7Comm:
		return fmt.Sprintf("S7comm %v %v ref=%d", v.ROSCTR, v.Function, v.PDURef), true
	case *layers.S7CommPlus:
		return fmt.Sprintf("S7comm-plus %v %v seq=%d", v.Opcode, v.Function, v.Sequence), true
	case *layers.ISOSession:
		return sessionSummary(v), true
	case *layers.COTP:
		return fmt.Sprintf("COTP %v", v.Type), true
	case *layers.DNP3:
		return dnp3Summary(v), true
	case *layers.IEC104:
		return iec104Summary(v), true
	case *layers.OPCUA:
		return opcuaSummary(v), true
	case *layers.OPCUAPubSub:
		return fmt.Sprintf("OPC UA PubSub %v messages=%d", v.Type, len(v.Messages)), true
	case *layers.Modbus:
		return fmt.Sprintf("Modbus tx=%d unit=%d %v", v.TransactionID, v.UnitID, v.GetFunction()), true
	case *layers.GOOSE:
		return fmt.Sprintf("GOOSE %s st=%d sq=%d", v.GocbRef, v.StNum, v.SqNum), true
	case *layers.SV:
		return fmt.Sprintf("SV asdus=%d", len(v.ASDUs)), true
	case *layers.PTP:
		return fmt.Sprintf("PTP %v seq=%d", v.MessageType, v.SequenceID), true
	case *layers.Profinet:
		return fmt.Sprintf("PROFINET frame=0x%04x", uint16(v.FrameID)), true
	case *layers.EtherCAT:
		return fmt.Sprintf("EtherCAT %v datagrams=%d", v.Type, len(v.Datagrams)), true
	case *layers.BACnetAPDU, *layers.BACnetNPDU, *layers.BVLC, *layers.BVLC6:
		return l.LayerType().String(), true
	}
	return "", false
}

// sessionSummary names the main SPDU and what was tolerated to decode
// the TSDU, e.g. "ISO session AC flaws=length-overrun".
func sessionSummary(s *layers.ISOSession) string {
	if s.Flaws == 0 {
		return fmt.Sprintf("ISO session %v", s.Type())
	}
	return fmt.Sprintf("ISO session %v flaws=%v", s.Type(), s.Flaws)
}

func mmsSummary(m *layers.MMS) string {
	switch m.Type {
	case layers.MMSConfirmedRequest, layers.MMSConfirmedResponse:
		// Service is the zero value (status) when the PDU carries none.
		if m.NoService {
			return fmt.Sprintf("MMS %v invoke=%d no service", m.Type, m.InvokeID)
		}

		return fmt.Sprintf("MMS %v invoke=%d %v", m.Type, m.InvokeID, m.Service)
	case layers.MMSUnconfirmed:
		return fmt.Sprintf("MMS %v %v", m.Type, m.Unconfirmed)
	}
	return fmt.Sprintf("MMS %v", m.Type)
}

func dnp3Summary(d *layers.DNP3) string {
	s := fmt.Sprintf("DNP3 %d->%d %v", d.Link.Source, d.Link.Destination, d.Link.Function)
	if d.Application != nil {
		s += fmt.Sprintf(" app=%v", d.Application.Function)
	}
	return s
}

func iec104Summary(i *layers.IEC104) string {
	switch i.Format {
	case layers.IEC104FormatI:
		return fmt.Sprintf("IEC104 I %v cot=%v ca=%d", i.ASDU.TypeID, i.ASDU.Cause, i.ASDU.CommonAddr)
	case layers.IEC104FormatS:
		return fmt.Sprintf("IEC104 S recv=%d", i.RecvSeq)
	}
	return fmt.Sprintf("IEC104 U %v", i.UFunction)
}

func opcuaSummary(o *layers.OPCUA) string {
	s := fmt.Sprintf("OPCUA %v%v size=%d", o.MessageType, o.ChunkType, o.MessageSize)
	if o.Service != nil {
		s += fmt.Sprintf(" %v", o.Service.ID)
	}
	return s
}
