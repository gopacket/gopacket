// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package tcpassembly

import (
	"net"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var netFlow gopacket.Flow

func init() {
	netFlow, _ = gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.IP{1, 2, 3, 4}),
		layers.NewIPEndpoint(net.IP{5, 6, 7, 8}))
}

func TestSequenceOverflow(t *testing.T) {
	if want, got := 20, Sequence((1<<32)-10).Difference(Sequence(10)); want != got {
		t.Errorf("overflow diff failure: got %d want %d", got, want)
	}
}

type testSequence struct {
	in   layers.TCP
	want []Reassembly
}

type testFactory struct {
	reassembly []Reassembly
}

func (t *testFactory) New(a, b gopacket.Flow) Stream {
	return t
}
func (t *testFactory) Reassembled(r []Reassembly) {
	t.reassembly = r
	for i := 0; i < len(r); i++ {
		t.reassembly[i].Seen = time.Time{}
	}
}
func (t *testFactory) ReassemblyComplete() {
}

func test(t *testing.T, s []testSequence) {
	fact := &testFactory{}
	p := NewStreamPool(fact)
	a := NewAssembler(p)
	a.MaxBufferedPagesPerConnection = 4
	for i, test := range s {
		fact.reassembly = []Reassembly{}
		a.Assemble(netFlow, &test.in)
		if !reflect.DeepEqual(fact.reassembly, test.want) {
			t.Fatalf("test %v:\nwant: %v\n got: %v\n", i, test.want, fact.reassembly)
		}
	}
}

func TestReorder(t *testing.T) {
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1001,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1004,
				BaseLayer: layers.BaseLayer{Payload: []byte{2, 2, 3}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1010,
				BaseLayer: layers.BaseLayer{Payload: []byte{4, 2, 3}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1007,
				BaseLayer: layers.BaseLayer{Payload: []byte{3, 2, 3}},
			},
			want: []Reassembly{
				Reassembly{
					Skip:  -1,
					Bytes: []byte{1, 2, 3},
				},
				Reassembly{
					Bytes: []byte{2, 2, 3},
				},
				Reassembly{
					Bytes: []byte{3, 2, 3},
				},
				Reassembly{
					Bytes: []byte{4, 2, 3},
				},
			},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1016,
				BaseLayer: layers.BaseLayer{Payload: []byte{2, 2, 3}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1019,
				BaseLayer: layers.BaseLayer{Payload: []byte{3, 2, 3}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1013,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			want: []Reassembly{
				Reassembly{
					Bytes: []byte{1, 2, 3},
				},
				Reassembly{
					Bytes: []byte{2, 2, 3},
				},
				Reassembly{
					Bytes: []byte{3, 2, 3},
				},
			},
		},
	})
}

func TestMaxPerSkip(t *testing.T) {
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1000,
				SYN:       true,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Bytes: []byte{1, 2, 3},
				},
			},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1007,
				BaseLayer: layers.BaseLayer{Payload: []byte{3, 2, 3}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1010,
				BaseLayer: layers.BaseLayer{Payload: []byte{4, 2, 3}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1013,
				BaseLayer: layers.BaseLayer{Payload: []byte{5, 2, 3}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1016,
				BaseLayer: layers.BaseLayer{Payload: []byte{6, 2, 3}},
			},
			want: []Reassembly{
				Reassembly{
					Skip:  3,
					Bytes: []byte{3, 2, 3},
				},
				Reassembly{
					Bytes: []byte{4, 2, 3},
				},
				Reassembly{
					Bytes: []byte{5, 2, 3},
				},
				Reassembly{
					Bytes: []byte{6, 2, 3},
				},
			},
		},
	})
}

func TestReorderFast(t *testing.T) {
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				SYN:       true,
				Seq:       1000,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Bytes: []byte{1, 2, 3},
				},
			},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1007,
				BaseLayer: layers.BaseLayer{Payload: []byte{3, 2, 3}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1004,
				BaseLayer: layers.BaseLayer{Payload: []byte{2, 2, 3}},
			},
			want: []Reassembly{
				Reassembly{
					Bytes: []byte{2, 2, 3},
				},
				Reassembly{
					Bytes: []byte{3, 2, 3},
				},
			},
		},
	})
}

func TestOverlap(t *testing.T) {
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				SYN:       true,
				Seq:       1000,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
				},
			},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1007,
				BaseLayer: layers.BaseLayer{Payload: []byte{7, 8, 9, 0, 1, 2, 3, 4, 5}},
			},
			want: []Reassembly{
				Reassembly{
					Bytes: []byte{1, 2, 3, 4, 5},
				},
			},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1010,
				BaseLayer: layers.BaseLayer{Payload: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
			},
			want: []Reassembly{
				Reassembly{
					Bytes: []byte{6, 7},
				},
			},
		},
	})
}

// A SYN on a connection that already saw its SYN is dropped by the receiver
// (RFC 5961): its payload must not be assembled as data.
func TestSynOnEstablished(t *testing.T) {
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				SYN:       true,
				Seq:       1000,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Bytes: []byte{1, 2, 3},
				},
			},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				SYN:       true,
				Seq:       1004,
				BaseLayer: layers.BaseLayer{Payload: []byte{9, 9, 9}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1004,
				BaseLayer: layers.BaseLayer{Payload: []byte{4, 5}},
			},
			want: []Reassembly{
				Reassembly{
					Bytes: []byte{4, 5},
				},
			},
		},
	})
}

// A RST or FIN whose position lies before nextSeq is dropped by the receiver
// as out of window: it must not end the stream.
func TestEndBeforeNextSeq(t *testing.T) {
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				SYN:       true,
				Seq:       1000,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Bytes: []byte{1, 2, 3},
				},
			},
		},
		{
			// a RST before nextSeq
			in: layers.TCP{
				SrcPort: 1,
				DstPort: 2,
				RST:     true,
				Seq:     0,
			},
			want: []Reassembly{},
		},
		{
			// a retransmitted FIN that ends before nextSeq
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				FIN:       true,
				Seq:       1001,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1004,
				BaseLayer: layers.BaseLayer{Payload: []byte{4, 5}},
			},
			want: []Reassembly{
				Reassembly{
					Bytes: []byte{4, 5},
				},
			},
		},
		{
			// a FIN that reaches nextSeq still ends the stream
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				FIN:       true,
				Seq:       1004,
				BaseLayer: layers.BaseLayer{Payload: []byte{4, 5, 6}},
			},
			want: []Reassembly{
				Reassembly{
					End:   true,
					Bytes: []byte{6},
				},
			},
		},
	})
}

// A RST ahead of the expected sequence number is dropped by the receiver:
// it must not be queued and end the stream at the next flush.
func TestOutOfOrderRST(t *testing.T) {
	fact := &testFactory{}
	p := NewStreamPool(fact)
	a := NewAssembler(p)
	for i, test := range []testSequence{
		{
			in:   layers.TCP{SrcPort: 1, DstPort: 2, SYN: true, Seq: 1000, BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}}},
			want: []Reassembly{{Start: true, Bytes: []byte{1, 2, 3}}},
		},
		{
			in:   layers.TCP{SrcPort: 1, DstPort: 2, RST: true, Seq: 1010},
			want: []Reassembly{},
		},
		{
			in:   layers.TCP{SrcPort: 1, DstPort: 2, Seq: 1004, BaseLayer: layers.BaseLayer{Payload: []byte{4, 5}}},
			want: []Reassembly{{Bytes: []byte{4, 5}}},
		},
	} {
		fact.reassembly = []Reassembly{}
		a.Assemble(netFlow, &test.in)
		if !reflect.DeepEqual(fact.reassembly, test.want) {
			t.Fatalf("test %v:\nwant: %v\n got: %v\n", i, test.want, fact.reassembly)
		}
	}
	fact.reassembly = []Reassembly{}
	a.FlushAll()
	if len(fact.reassembly) != 0 {
		t.Fatalf("flush delivered the queued RST: %v", fact.reassembly)
	}
}

func TestBufferedOverlap(t *testing.T) {
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1007,
				BaseLayer: layers.BaseLayer{Payload: []byte{7, 8, 9, 0, 1, 2, 3, 4, 5}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1010,
				BaseLayer: layers.BaseLayer{Payload: []byte{0, 1, 2, 3, 4, 5, 6, 7}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				SYN:       true,
				Seq:       1000,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
				},
				Reassembly{
					Bytes: []byte{1, 2, 3, 4, 5},
				},
				Reassembly{
					Bytes: []byte{6, 7},
				},
			},
		},
	})
}

func TestOverrun1(t *testing.T) {
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				SYN:       true,
				Seq:       0xFFFFFFFF,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
				},
			},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       10,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4}},
			},
			want: []Reassembly{
				Reassembly{
					Bytes: []byte{1, 2, 3, 4},
				},
			},
		},
	})
}

func TestOverrun2(t *testing.T) {
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       10,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				SYN:       true,
				Seq:       0xFFFFFFFF,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
				},
				Reassembly{
					Bytes: []byte{1, 2, 3, 4},
				},
			},
		},
	})
}

func TestCacheLargePacket(t *testing.T) {
	data := make([]byte, pageBytes*3)
	test(t, []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1001,
				BaseLayer: layers.BaseLayer{Payload: data},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1000,
				SYN:       true,
				BaseLayer: layers.BaseLayer{Payload: []byte{}},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Bytes: []byte{},
				},
				Reassembly{
					Bytes: data[:pageBytes],
				},
				Reassembly{
					Bytes: data[pageBytes : pageBytes*2],
				},
				Reassembly{
					Bytes: data[pageBytes*2 : pageBytes*3],
				},
			},
		},
	})
}

func BenchmarkSingleStream(b *testing.B) {
	t := layers.TCP{
		SrcPort:   1,
		DstPort:   2,
		SYN:       true,
		Seq:       1000,
		BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}},
	}
	a := NewAssembler(NewStreamPool(&testFactory{}))
	for i := 0; i < b.N; i++ {
		a.Assemble(netFlow, &t)
		if t.SYN {
			t.SYN = false
			t.Seq++
		}
		t.Seq += 10
	}
}

func BenchmarkSingleStreamSkips(b *testing.B) {
	t := layers.TCP{
		SrcPort:   1,
		DstPort:   2,
		SYN:       true,
		Seq:       1000,
		BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}},
	}
	a := NewAssembler(NewStreamPool(&testFactory{}))
	skipped := false
	for i := 0; i < b.N; i++ {
		if i%10 == 9 {
			t.Seq += 10
			skipped = true
		} else if skipped {
			t.Seq -= 20
		}
		a.Assemble(netFlow, &t)
		if t.SYN {
			t.SYN = false
			t.Seq++
		}
		t.Seq += 10
		if skipped {
			t.Seq += 10
			skipped = false
		}
	}
}

func BenchmarkSingleStreamLoss(b *testing.B) {
	t := layers.TCP{
		SrcPort:   1,
		DstPort:   2,
		SYN:       true,
		Seq:       1000,
		BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}},
	}
	a := NewAssembler(NewStreamPool(&testFactory{}))
	for i := 0; i < b.N; i++ {
		a.Assemble(netFlow, &t)
		t.SYN = false
		t.Seq += 11
	}
}

func BenchmarkMultiStreamGrow(b *testing.B) {
	t := layers.TCP{
		SrcPort:   1,
		DstPort:   2,
		Seq:       0,
		BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}},
	}
	a := NewAssembler(NewStreamPool(&testFactory{}))
	for i := 0; i < b.N; i++ {
		t.SrcPort = layers.TCPPort(i)
		a.Assemble(netFlow, &t)
		t.Seq += 10
	}
}

func BenchmarkMultiStreamConn(b *testing.B) {
	t := layers.TCP{
		SrcPort:   1,
		DstPort:   2,
		Seq:       0,
		SYN:       true,
		BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}},
	}
	a := NewAssembler(NewStreamPool(&testFactory{}))
	for i := 0; i < b.N; i++ {
		t.SrcPort = layers.TCPPort(i)
		a.Assemble(netFlow, &t)
		if i%65536 == 65535 {
			if t.SYN {
				t.SYN = false
				t.Seq++
			}
			t.Seq += 10
		}
	}
}

// testRaceFactory runs race from its first call to New, which is where another
// Assembler sharing the StreamPool can get to add the same connection first.
type testRaceFactory struct {
	testFactory
	race func()
}

func (t *testRaceFactory) New(a, b gopacket.Flow) Stream {
	if race := t.race; race != nil {
		t.race = nil
		race()
	}
	return t
}

// Losing the race to add a connection must not cost a pooled connection.
func TestConnectionAddedWhileCreatingStream(t *testing.T) {
	tcp := layers.TCP{SrcPort: 1, DstPort: 2, SYN: true}
	tf := &testRaceFactory{}
	pool := NewStreamPool(tf)
	tf.race = func() { NewAssembler(pool).Assemble(netFlow, &tcp) }
	NewAssembler(pool).Assemble(netFlow, &tcp)
	if n := len(pool.conns); n != 1 {
		t.Errorf("%d connections in the pool, want 1", n)
	}
	if n := len(pool.free); n != initialAllocSize-1 {
		t.Errorf("%d free connections left, want %d", n, initialAllocSize-1)
	}
}

// Pages buffered by one Assembler and flushed by another one sharing its
// StreamPool must no longer count against the first one's limit.
func TestSharedPoolFlush(t *testing.T) {
	fact := &testFactory{}
	p := NewStreamPool(fact)
	a := NewAssembler(p)
	a.MaxBufferedPagesTotal = 4
	flusher := NewAssembler(p)
	for i := 0; i < 3; i++ {
		a.Assemble(netFlow, &layers.TCP{
			SrcPort:   1,
			DstPort:   2,
			Seq:       uint32(1000 + 10*i),
			BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
		})
	}
	flusher.FlushAll()
	if got := a.pc.used.Load(); got != 0 {
		t.Errorf("assembler has %d pages in use after flush, want 0", got)
	}
	if got := flusher.pc.used.Load(); got != 0 {
		t.Errorf("flusher has %d pages in use after flush, want 0", got)
	}
	for i, test := range []testSequence{
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1000,
				SYN:       true,
				BaseLayer: layers.BaseLayer{Payload: []byte{}},
			},
			want: []Reassembly{
				Reassembly{
					Start: true,
					Bytes: []byte{},
				},
			},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1004,
				BaseLayer: layers.BaseLayer{Payload: []byte{2, 2, 3}},
			},
			want: []Reassembly{},
		},
		{
			in: layers.TCP{
				SrcPort:   1,
				DstPort:   2,
				Seq:       1001,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			want: []Reassembly{
				Reassembly{
					Bytes: []byte{1, 2, 3},
				},
				Reassembly{
					Bytes: []byte{2, 2, 3},
				},
			},
		},
	} {
		fact.reassembly = []Reassembly{}
		a.Assemble(netFlow, &test.in)
		if !reflect.DeepEqual(fact.reassembly, test.want) {
			t.Fatalf("test %v:\nwant: %v\n got: %v\n", i, test.want, fact.reassembly)
		}
	}
}

// testReuseFactory records every stream it creates and runs onComplete from
// ReassemblyComplete, while the Assembler still holds the connection lock.
type testReuseStream struct {
	fact  *testReuseFactory
	flow  gopacket.Flow
	bytes []byte
}

func (s *testReuseStream) Reassembled(rs []Reassembly) {
	for _, r := range rs {
		s.bytes = append(s.bytes, r.Bytes...)
	}
}
func (s *testReuseStream) ReassemblyComplete() {
	if s.fact.onComplete != nil {
		s.fact.onComplete()
	}
}

type testReuseFactory struct {
	streams    []*testReuseStream
	onComplete func()
}

func (f *testReuseFactory) New(a, b gopacket.Flow) Stream {
	s := &testReuseStream{fact: f, flow: b}
	f.streams = append(f.streams, s)
	return s
}

func (f *testReuseFactory) bytesFor(flow gopacket.Flow) [][]byte {
	var got [][]byte
	for _, s := range f.streams {
		if s.flow == flow {
			got = append(got, s.bytes)
		}
	}
	return got
}

// An Assembler that looked a connection up and then waited for its lock must
// not use it once another Assembler has removed it and the pool has handed
// it out again for a different flow.
func TestConnectionReusedWhileWaitingForLock(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	fact := &testReuseFactory{}
	pool := NewStreamPool(fact)
	closer, waiter, third := NewAssembler(pool), NewAssembler(pool), NewAssembler(pool)
	first := layers.TCP{SrcPort: 1, DstPort: 2, SYN: true, Seq: 1000, BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}}}
	again := layers.TCP{SrcPort: 1, DstPort: 2, SYN: true, Seq: 5000, BaseLayer: layers.BaseLayer{Payload: []byte{4, 5, 6}}}
	other := layers.TCP{SrcPort: 3, DstPort: 4, SYN: true, Seq: 7000, BaseLayer: layers.BaseLayer{Payload: []byte{7, 8, 9}}}
	for _, tcp := range []*layers.TCP{&first, &again, &other} {
		tcp.SetInternalPortsForTesting()
	}
	closer.Assemble(netFlow, &first)

	var wg sync.WaitGroup
	fact.onComplete = func() {
		fact.onComplete = nil
		wg.Add(1)
		go func() {
			defer wg.Done()
			waiter.Assemble(netFlow, &again)
		}()
		// Let waiter look the connection up and block on its lock before
		// closer removes it.
		time.Sleep(20 * time.Millisecond)
	}
	closer.FlushAll()
	// Recycle the freed connection object for another flow before waiter
	// gets the lock.
	third.Assemble(netFlow, &other)
	wg.Wait()

	want := [][]byte{{1, 2, 3}, {4, 5, 6}}
	if got := fact.bytesFor(first.TransportFlow()); !reflect.DeepEqual(got, want) {
		t.Errorf("first flow: got %v, want %v", got, want)
	}
	want = [][]byte{{7, 8, 9}}
	if got := fact.bytesFor(other.TransportFlow()); !reflect.DeepEqual(got, want) {
		t.Errorf("other flow: got %v, want %v", got, want)
	}
}

// A connection parked on the free list must not keep its Stream alive.
func TestRemoveDropsStream(t *testing.T) {
	fact := &testFactory{}
	p := NewStreamPool(fact)
	a := NewAssembler(p)
	a.Assemble(netFlow, &layers.TCP{SrcPort: 1, DstPort: 2, SYN: true, Seq: 1000, BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}}})
	var conn *connection
	for _, c := range p.conns {
		conn = c
	}
	a.Assemble(netFlow, &layers.TCP{SrcPort: 1, DstPort: 2, FIN: true, Seq: 1004})

	if n := len(p.conns); n != 0 {
		t.Fatalf("%d connections still in the pool, want 0", n)
	}
	if conn.stream != nil {
		t.Errorf("removed connection still references its Stream")
	}
}
