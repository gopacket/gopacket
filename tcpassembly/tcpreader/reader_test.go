// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package tcpreader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/tcpassembly"
)

var netFlow gopacket.Flow

func init() {
	netFlow, _ = gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.IP{1, 2, 3, 4}),
		layers.NewIPEndpoint(net.IP{5, 6, 7, 8}))
}

type readReturn struct {
	data []byte
	err  error
}
type readSequence struct {
	in   []layers.TCP
	want []readReturn
}
type testReaderFactory struct {
	lossErrors bool
	readSize   int
	ReaderStream
	output chan []byte
}

func (t *testReaderFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	return &t.ReaderStream
}

func testReadSequence(t *testing.T, lossErrors bool, readSize int, seq readSequence) {
	f := &testReaderFactory{ReaderStream: NewReaderStream()}
	f.ReaderStream.LossErrors = lossErrors
	p := tcpassembly.NewStreamPool(f)
	a := tcpassembly.NewAssembler(p)
	buf := make([]byte, readSize)
	go func() {
		for i, test := range seq.in {
			fmt.Println("Assembling", i)
			a.Assemble(netFlow, &test)
			fmt.Println("Assembly done")
		}
	}()
	for i, test := range seq.want {
		fmt.Println("Waiting for read", i)
		n, err := f.Read(buf[:])
		fmt.Println("Got read")
		if n != len(test.data) {
			t.Errorf("test %d want %d bytes, got %d bytes", i, len(test.data), n)
		} else if err != test.err {
			t.Errorf("test %d want err %v, got err %v", i, test.err, err)
		} else if !bytes.Equal(buf[:n], test.data) {
			t.Errorf("test %d\nwant: %v\n got: %v\n", i, test.data, buf[:n])
		}
	}
	fmt.Println("All done reads")
}

func TestRead(t *testing.T) {
	testReadSequence(t, false, 10, readSequence{
		in: []layers.TCP{
			{
				SYN:       true,
				SrcPort:   1,
				DstPort:   2,
				Seq:       1000,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			{
				FIN:     true,
				SrcPort: 1,
				DstPort: 2,
				Seq:     1004,
			},
		},
		want: []readReturn{
			{data: []byte{1, 2, 3}},
			{err: io.EOF},
		},
	})
}

func TestReadSmallChunks(t *testing.T) {
	testReadSequence(t, false, 2, readSequence{
		in: []layers.TCP{
			{
				SYN:       true,
				SrcPort:   1,
				DstPort:   2,
				Seq:       1000,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			{
				FIN:     true,
				SrcPort: 1,
				DstPort: 2,
				Seq:     1004,
			},
		},
		want: []readReturn{
			{data: []byte{1, 2}},
			{data: []byte{3}},
			{err: io.EOF},
		},
	})
}

func ExampleDiscardBytesToEOF() {
	b := bytes.NewBuffer([]byte{1, 2, 3, 4, 5})
	fmt.Println(DiscardBytesToEOF(b))
	// Output:
	// 5
}

// A Reassembly with no bytes still reports its Skip when LossErrors is on.
func TestReadLossOnEmptyReassembly(t *testing.T) {
	f := &testReaderFactory{ReaderStream: NewReaderStream()}
	f.ReaderStream.LossErrors = true
	a := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(f))
	go func() {
		syn := layers.TCP{SYN: true, SrcPort: 1, DstPort: 2, Seq: 1000, BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}}}
		fin := layers.TCP{FIN: true, SrcPort: 1, DstPort: 2, Seq: 1010}
		a.Assemble(netFlow, &syn)
		a.Assemble(netFlow, &fin)
		a.FlushAll()
	}()

	buf := make([]byte, 10)
	for i, want := range []readReturn{
		{data: []byte{1, 2, 3}},
		{err: DataLost},
		{err: io.EOF},
	} {
		n, err := f.Read(buf)
		if err != want.err || !bytes.Equal(buf[:n], want.data) {
			t.Fatalf("read %d: got (%v, %v), want (%v, %v)", i, buf[:n], err, want.data, want.err)
		}
	}
}

// Close in the middle of a stream must not block the assembler or itself.
func TestCloseAfterRead(t *testing.T) {
	f := &testReaderFactory{ReaderStream: NewReaderStream()}
	a := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(f))
	assembled := make(chan struct{})
	go func() {
		defer close(assembled)
		for _, tcp := range []layers.TCP{
			{SYN: true, SrcPort: 1, DstPort: 2, Seq: 1000, BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}}},
			{SrcPort: 1, DstPort: 2, Seq: 1004, BaseLayer: layers.BaseLayer{Payload: []byte{4, 5, 6}}},
			{FIN: true, SrcPort: 1, DstPort: 2, Seq: 1007},
		} {
			a.Assemble(netFlow, &tcp)
		}
	}()

	buf := make([]byte, 10)
	if n, err := f.Read(buf); err != nil || n != 3 {
		t.Fatalf("first read: got (%d, %v)", n, err)
	}
	closed := make(chan error, 1)
	go func() { closed <- f.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked")
	}
	select {
	case <-assembled:
	case <-time.After(2 * time.Second):
		t.Fatal("assembler blocked after Close")
	}
	if n, err := f.Read(buf); err != io.EOF || n != 0 {
		t.Fatalf("read after Close: got (%d, %v), want (0, EOF)", n, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// stuckReader fails every Read with the same non-EOF error.
type stuckReader struct{}

func (stuckReader) Read([]byte) (int, error) { return 0, errors.New("stuck") }

// DiscardBytesToEOF must give up on a reader that never reaches EOF.
func TestDiscardBytesToEOFPersistentError(t *testing.T) {
	done := make(chan int, 1)
	go func() { done <- DiscardBytesToEOF(stuckReader{}) }()
	select {
	case n := <-done:
		if n != 0 {
			t.Fatalf("discarded %d bytes, want 0", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DiscardBytesToEOF loops forever")
	}
}

// A loss error is not EOF: DiscardBytesToEOF keeps going past it.
func TestDiscardBytesToEOFSkipsDataLost(t *testing.T) {
	f := &testReaderFactory{ReaderStream: NewReaderStream()}
	f.ReaderStream.LossErrors = true
	a := tcpassembly.NewAssembler(tcpassembly.NewStreamPool(f))
	go func() {
		syn := layers.TCP{SYN: true, SrcPort: 1, DstPort: 2, Seq: 1000, BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}}}
		late := layers.TCP{FIN: true, SrcPort: 1, DstPort: 2, Seq: 1010, BaseLayer: layers.BaseLayer{Payload: []byte{4, 5}}}
		a.Assemble(netFlow, &syn)
		a.Assemble(netFlow, &late)
		a.FlushAll()
	}()
	if n := DiscardBytesToEOF(&f.ReaderStream); n != 5 {
		t.Fatalf("discarded %d bytes, want 5", n)
	}
}

// blockingReader hands out the buffer it was given and waits to be released.
type blockingReader struct {
	buf     chan *byte
	release chan struct{}
}

func (r blockingReader) Read(p []byte) (int, error) {
	r.buf <- &p[0]
	<-r.release
	return 0, io.EOF
}

// Concurrent discards must not read into one shared buffer.
func TestDiscardConcurrentBuffers(t *testing.T) {
	bufs := make(chan *byte, 2)
	release := make(chan struct{})
	for i := 0; i < 2; i++ {
		go DiscardBytesToFirstError(blockingReader{buf: bufs, release: release})
	}
	first, second := <-bufs, <-bufs
	close(release)
	if first == second {
		t.Fatal("two concurrent discards share one buffer")
	}
}

// TestDiscardBytesToEOFTwoDataLost drains a stream that reports loss twice
// in a row without any bytes in between: a run of DataLost errors is
// finite, so the discard loop must not give up on it.
func TestDiscardBytesToEOFTwoDataLost(t *testing.T) {
	f := &testReaderFactory{ReaderStream: NewReaderStream()}
	f.ReaderStream.LossErrors = true
	go func() {
		f.ReaderStream.Reassembled([]tcpassembly.Reassembly{{Skip: 1}})
		f.ReaderStream.Reassembled([]tcpassembly.Reassembly{{Skip: 1}})
		f.ReaderStream.Reassembled([]tcpassembly.Reassembly{{Bytes: []byte{1, 2, 3}}})
		f.ReaderStream.ReassemblyComplete()
	}()
	done := make(chan int)
	go func() { done <- DiscardBytesToEOF(&f.ReaderStream) }()
	select {
	case n := <-done:
		if n != 3 {
			t.Fatalf("discarded %d bytes, want 3", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DiscardBytesToEOF gave up and left the stream blocked")
	}
}
