// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import "github.com/gopacket/gopacket"

// LayerTypeISOSession is the ISO 8327 session layer carried in COTP data.
var LayerTypeISOSession = gopacket.RegisterLayerType(195, gopacket.LayerTypeMetadata{Name: "ISOSession", Decoder: gopacket.DecodeFunc(decodeISOSession)})

// decodeISOSession is a placeholder until the session decoder lands.
func decodeISOSession(data []byte, p gopacket.PacketBuilder) error {
	return p.NextDecoder(gopacket.LayerTypePayload)
}
