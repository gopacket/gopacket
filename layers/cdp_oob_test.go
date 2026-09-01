// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"

	"github.com/gopacket/gopacket"
)

// decodeCiscoDiscovery read the 4-byte version/ttl/checksum header without a
// length check, so a CDP payload shorter than 4 bytes panicked with a slice
// bounds out of range (found by fuzzing, e.g. []byte{0x00}). It must instead
// return a truncated error. SkipDecodeRecovery drives the decoder on the raw
// (non-recovering) path, mirroring how DecodingLayerParser invokes decoders.
func TestCiscoDiscoveryTruncated(t *testing.T) {
	for _, data := range [][]byte{{}, {0x01}, {0x01, 0x00}, {0x01, 0x00, 0x00}} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decodeCiscoDiscovery panicked on %d-byte input: %v", len(data), r)
				}
			}()
			p := gopacket.NewPacket(data, LayerTypeCiscoDiscovery, gopacket.DecodeOptions{SkipDecodeRecovery: true})
			if p.ErrorLayer() == nil {
				t.Errorf("expected an error layer for %d-byte CDP input", len(data))
			}
		}()
	}
}
