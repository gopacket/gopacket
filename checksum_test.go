// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Test the checksum computation helpers using IPv4 packets
func TestChecksum(t *testing.T) {
	testData := []struct {
		name   string
		header string
		want   string
	}{{
		name:   "sum has two carries",
		header: "4540005800000000ff11ffff0aeb1d070aed8877",
		want:   "fffe",
	}, {
		name:   "wikipedia case",
		header: "45000073000040004011b861c0a80001c0a800c7",
		want:   "b861",
	}}

	for _, test := range testData {
		bytes, err := hex.DecodeString(test.header)
		if err != nil {
			t.Fatalf("Failed to Decode header: %v", err)
		}
		wantBytes, err := hex.DecodeString(test.want)
		if err != nil {
			t.Fatalf("Failed to decode want checksum: %v", err)
		}

		// Clear checksum bytes
		bytes[10] = 0
		bytes[11] = 0

		csum := ComputeChecksum(bytes, 0)
		if got, want := FoldChecksum(csum), binary.BigEndian.Uint16(wantBytes); got != want {
			t.Errorf("In test %q, got incorrect checksum: got(%x), want(%x)", test.name, got, want)
		}
	}
}

// TestChecksumLargeData sums more than 128 KiB, where the 16-bit words add
// up to more than 32 bits and the carry out of bit 31 must be kept.
func TestChecksumLargeData(t *testing.T) {
	data := make([]byte, 131200)
	for i := range data {
		data[i] = 0xff
	}
	// 65600 words of 0xffff are zero in one's complement arithmetic.
	if got := FoldChecksum(ComputeChecksum(data, 0)); got != 0 {
		t.Errorf("checksum of all-ones data is %#x, want 0", got)
	}

	// Summing in two calls must give the same answer as one.
	split := ComputeChecksum(data[70000:], ComputeChecksum(data[:70000], 0))
	if got, want := FoldChecksum(split), FoldChecksum(ComputeChecksum(data, 0)); got != want {
		t.Errorf("split sum folds to %#x, whole sum to %#x", got, want)
	}

	// The layers subtract the checksum found in the data from the sum
	// before folding; the sum must not drop below it.
	data[0], data[1] = 0x12, 0x34
	sum := ComputeChecksum(data, 0)
	if sum < 0x1234 {
		t.Errorf("sum %#x is smaller than a word it contains", sum)
	}
	if got, want := FoldChecksum(sum-0x1234), FoldChecksum(ComputeChecksum(data[2:], 0)); got != want {
		t.Errorf("subtracting a word gives %#x, want %#x", got, want)
	}
}

// badChecksumLayer is a layer whose checksum never verifies.
type badChecksumLayer []byte

func (l badChecksumLayer) LayerType() LayerType  { return LayerTypeZero }
func (l badChecksumLayer) LayerContents() []byte { return l }
func (l badChecksumLayer) LayerPayload() []byte  { return nil }
func (l badChecksumLayer) VerifyChecksum() (error, ChecksumVerificationResult) {
	return nil, ChecksumVerificationResult{Valid: false, Correct: 1, Actual: 2}
}

// TestVerifyChecksumsLazy expects a lazily decoded packet to verify every
// layer, not only the ones an earlier accessor happened to decode.
func TestVerifyChecksumsLazy(t *testing.T) {
	dec := DecodeFunc(func(data []byte, p PacketBuilder) error {
		p.AddLayer(badChecksumLayer(data))
		return nil
	})
	for _, opts := range []DecodeOptions{Default, Lazy} {
		p := NewPacket([]byte{1, 2, 3}, dec, opts)
		err, mismatches := p.VerifyChecksums()
		if err != nil || len(mismatches) != 1 {
			t.Errorf("lazy=%v: err %v, %d mismatches, want 1", opts.Lazy, err, len(mismatches))
		}
	}
}
