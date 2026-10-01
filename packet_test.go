// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import (
	"context"
	"io"
	"reflect"
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

// zeroCopySource is a ZeroCopyPacketDataSource that, like a real zero copy
// source, hands out the same buffer on every call.
type zeroCopySource struct {
	buf   []byte
	calls int
}

func (s *zeroCopySource) ZeroCopyReadPacketData() ([]byte, CaptureInfo, error) {
	s.calls++
	s.buf[0] = byte(s.calls)
	return s.buf, CaptureInfo{CaptureLength: len(s.buf), Length: len(s.buf)}, nil
}

func TestZeroCopyPacketSourceNextPacket(t *testing.T) {
	src := &zeroCopySource{buf: make([]byte, 4)}
	ps := NewZeroCopyPacketSource(src, DecodePayload, WithNoCopy(true))

	p, err := ps.NextPacket()
	if err != nil {
		t.Fatalf("NextPacket: %v", err)
	}
	if src.calls != 1 {
		t.Fatalf("ZeroCopyReadPacketData called %d times, want 1", src.calls)
	}
	if &p.Data()[0] != &src.buf[0] {
		t.Error("packet data does not alias the zero copy source buffer")
	}
}

func TestZeroCopyPacketSourcePacketsNoCopy(t *testing.T) {
	tests := []struct {
		name      string
		newSource func() *PacketSource
		wantPanic bool
	}{
		{
			name: "zero copy source with NoCopy option",
			newSource: func() *PacketSource {
				return NewZeroCopyPacketSource(&zeroCopySource{buf: make([]byte, 4)}, DecodePayload, WithNoCopy(true))
			},
			wantPanic: true,
		},
		{
			name: "zero copy source with NoCopy set after construction",
			newSource: func() *PacketSource {
				ps := NewZeroCopyPacketSource(&zeroCopySource{buf: make([]byte, 4)}, DecodePayload)
				ps.DecodeOptions.NoCopy = true
				return ps
			},
			wantPanic: true,
		},
		{
			name: "zero copy source without NoCopy",
			newSource: func() *PacketSource {
				return NewZeroCopyPacketSource(&zeroCopySource{buf: make([]byte, 4)}, DecodePayload)
			},
		},
		{
			name: "copying source with NoCopy",
			newSource: func() *PacketSource {
				return NewPacketSource(&singlePacketSource{[]byte{1}}, DecodePayload, WithNoCopy(true))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := tt.newSource()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			panicked := func() (panicked bool) {
				defer func() { panicked = recover() != nil }()
				ps.PacketsCtx(ctx)
				return false
			}()
			if panicked != tt.wantPanic {
				t.Errorf("PacketsCtx panicked = %v, want %v", panicked, tt.wantPanic)
			}
		})
	}
}
