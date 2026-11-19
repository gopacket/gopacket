// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

// RegisterOTDecoders maps the well-known ports and EtherTypes of the
// industrial protocols in this package to their decoders:
//
//	TCP 102          TPKT -> COTP -> S7comm / S7comm-plus / ISO session (MMS)
//	TCP/UDP 20000    DNP3
//	TCP 2404         IEC 60870-5-104
//	TCP 4840         OPC UA
//	UDP 47808        BACnet/IP
//	UDP 319, 320     PTP
//	UDP 34980        EtherCAT
//	EtherType 0x8892 PROFINET
//	EtherType 0x88A4 EtherCAT
//	EtherType 0x88B8 IEC 61850 GOOSE
//	EtherType 0x88BA IEC 61850 Sampled Values
//	EtherType 0x88F7 PTP
//
// It is opt-in: without it these frames decode as before (Payload, or a
// decode failure for the EtherTypes), so existing callers, including
// DecodingLayerParser users, see no change. Call it once at start-up,
// before decoding. Calling it again is harmless.
//
// The TCP-based decoders work per packet, so a PDU split across
// segments only decodes after stream reassembly (see the reassembly
// package); pass the reassembled bytes to gopacket.NewPacket with the
// protocol's layer type.
func RegisterOTDecoders() {
	registerS7Decoders()
	registerDNP3Decoders()
	registerIEC104Decoders()
	registerOPCUADecoders()
	registerBACnetDecoders()
	registerPTPDecoders()
	registerEtherCATDecoders()
	registerProfinetDecoders()
	registerIEC61850Decoders()
}
