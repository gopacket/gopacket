// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import (
	"errors"
	"io"
	"reflect"
	"runtime/debug"
	"testing"
)

type embedded struct {
	A, B int
}

type embedding struct {
	embedded
	C, D int
}

type embeddedPointer struct {
	A, B   *int
	AA, BB *string
}

type embeddingPointer struct {
	embeddedPointer
	C, D int
}

func TestDumpEmbedded(t *testing.T) {
	e := embedding{embedded: embedded{A: 1, B: 2}, C: 3, D: 4}
	if got, want := layerString(reflect.ValueOf(e), false, false), "{A=1 B=2 C=3 D=4}"; got != want {
		t.Errorf("embedded dump mismatch:\n   got: %v\n  want: %v", got, want)
	}
}

func TestDumpEmbeddedPointer(t *testing.T) {
	one := 1
	two := 2
	testString1 := "teststring1"
	testString2 := "teststring2"
	e := embeddingPointer{embeddedPointer: embeddedPointer{A: &one, B: &two, AA: &testString1, BB: &testString2}, C: 3, D: 4}
	if got, want := layerString(reflect.ValueOf(e), false, false), "{A=1 B=2 AA=teststring1 BB=teststring2 C=3 D=4}"; got != want {
		t.Errorf("embedded pointer dump mismatch:\n   got: %v\n  want: %v", got, want)
	}
}

type singlePacketSource [1][]byte

func (s *singlePacketSource) ReadPacketData() ([]byte, CaptureInfo, error) {
	if (*s)[0] == nil {
		return nil, CaptureInfo{}, io.EOF
	}
	out := (*s)[0]
	(*s)[0] = nil
	return out, CaptureInfo{}, nil
}

func TestConcatPacketSources(t *testing.T) {
	sourceA := &singlePacketSource{[]byte{1}}
	sourceB := &singlePacketSource{[]byte{2}}
	sourceC := &singlePacketSource{[]byte{3}}
	concat := ConcatFinitePacketDataSources(sourceA, sourceB, sourceC)
	a, _, err := concat.ReadPacketData()
	if err != nil || len(a) != 1 || a[0] != 1 {
		t.Errorf("expected [1], got %v/%v", a, err)
	}
	b, _, err := concat.ReadPacketData()
	if err != nil || len(b) != 1 || b[0] != 2 {
		t.Errorf("expected [2], got %v/%v", b, err)
	}
	c, _, err := concat.ReadPacketData()
	if err != nil || len(c) != 1 || c[0] != 3 {
		t.Errorf("expected [3], got %v/%v", c, err)
	}
	if _, _, err := concat.ReadPacketData(); err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

// oneByteLayer has one byte of contents, the rest of the data is its payload.
type oneByteLayer []byte

func (l oneByteLayer) LayerType() LayerType  { return LayerTypeZero }
func (l oneByteLayer) LayerContents() []byte { return l[:1] }
func (l oneByteLayer) LayerPayload() []byte  { return l[1:] }

// TestEagerDecodeDepth checks that eager decoding nests at most
// maxEagerDecodeDepth layers, that this many fits in a small stack, and that
// a decoder error below the limit surfaces as before.
func TestEagerDecodeDepth(t *testing.T) {
	errStop := errors.New("stop")
	var dec DecodeFunc
	dec = func(data []byte, p PacketBuilder) error {
		if data[0] != 0 {
			return errStop
		}
		p.AddLayer(oneByteLayer(data))
		return p.NextDecoder(dec)
	}
	check := func(p Packet, layers int) {
		t.Helper()
		if got := len(p.Layers()); got != layers {
			t.Errorf("expected %d layers, got %d", layers, got)
		}
	}

	// The first decoder isn't called through NextDecoder, so one more layer
	// than the depth fits. Cap the stack well under the default to show the
	// limit keeps it small.
	old := debug.SetMaxStack(64 << 20)
	defer debug.SetMaxStack(old)
	p := NewPacket(make([]byte, maxEagerDecodeDepth+1), dec, Default)
	if p.ErrorLayer() != nil {
		t.Errorf("unexpected error layer: %v", p.ErrorLayer().Error())
	}
	check(p, maxEagerDecodeDepth+1)

	p = NewPacket(make([]byte, maxEagerDecodeDepth+2), dec, Default)
	if p.ErrorLayer() == nil || p.ErrorLayer().Error() != errDecodeTooDeep {
		t.Fatalf("expected error layer with %v, got %v", errDecodeTooDeep, p.ErrorLayer())
	}
	if got := len(p.ErrorLayer().LayerContents()); got != 1 {
		t.Errorf("expected 1 byte in the error layer, got %d", got)
	}

	data := make([]byte, 1000)
	data[500] = 1
	p = NewPacket(data, dec, Default)
	if p.ErrorLayer() == nil || p.ErrorLayer().Error() != errStop {
		t.Fatalf("expected error layer with %v, got %v", errStop, p.ErrorLayer())
	}
	if got := len(p.ErrorLayer().LayerContents()); got != 500 {
		t.Errorf("expected 500 bytes in the error layer, got %d", got)
	}
	check(p, 501)
}

// TestNewPacketPoolCapsData checks that a pooled packet hands its decoders a
// slice capped at the packet length. A two-index reslice used to leave the
// capacity at the pool buffer size, so a decoder that resliced past the end
// read what the previous packet left behind instead of panicking.
func TestNewPacketPoolCapsData(t *testing.T) {
	const size = 100
	gotCap := -1
	record := DecodeFunc(func(data []byte, p PacketBuilder) error {
		gotCap = cap(data)
		return nil
	})

	p := NewPacket(make([]byte, size), record, DecodeOptions{Pool: true})
	if pooled, ok := p.(PooledPacket); ok {
		defer pooled.Dispose()
	}
	if gotCap != size {
		t.Fatalf("decoder input has capacity %d, want %d", gotCap, size)
	}
}

// countingChecksumLayer has one byte of contents, the rest is payload, and
// its checksum covers both; summed counts the bytes it was asked to sum.
type countingChecksumLayer struct {
	data   []byte
	summed *int
}

func (l countingChecksumLayer) LayerType() LayerType  { return LayerTypeZero }
func (l countingChecksumLayer) LayerContents() []byte { return l.data[:1] }
func (l countingChecksumLayer) LayerPayload() []byte  { return l.data[1:] }
func (l countingChecksumLayer) VerifyChecksum() (error, ChecksumVerificationResult) {
	*l.summed += len(l.data)
	return nil, ChecksumVerificationResult{Valid: true}
}

// TestVerifyChecksumsNested checks that the bytes VerifyChecksums sums stay
// linear in the packet size when every layer's checksum covers its payload,
// and that a reasonable nesting depth still verifies.
func TestVerifyChecksumsNested(t *testing.T) {
	summed := 0
	var dec DecodeFunc
	dec = func(data []byte, p PacketBuilder) error {
		if data[0] != 0 {
			return p.NextDecoder(LayerTypePayload)
		}
		p.AddLayer(countingChecksumLayer{data, &summed})
		return p.NextDecoder(dec)
	}
	packet := func(layers, size int) Packet {
		data := make([]byte, size)
		data[layers] = 1
		p := NewPacket(data, dec, Default)
		if p.ErrorLayer() != nil {
			t.Fatal(p.ErrorLayer().Error())
		}
		return p
	}

	const size = 10000
	if err, mismatches := packet(maxChecksumPasses, size).VerifyChecksums(); err != nil || len(mismatches) != 0 {
		t.Errorf("%d nested layers: err %v, mismatches %v", maxChecksumPasses, err, mismatches)
	}

	// one layer per byte, as many as eager decoding allows
	const deep = maxEagerDecodeDepth - 1
	summed = 0
	if err, _ := packet(deep-1, deep).VerifyChecksums(); err == nil {
		t.Error("quadratic packet verified without error")
	}
	if summed > (maxChecksumPasses+1)*deep {
		t.Errorf("summed %d bytes for a %d-byte packet", summed, deep)
	}
}
