// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package tcpreader provides an implementation for tcpassembly.Stream which presents
// the caller with an io.Reader for easy processing.
//
// The assembly package handles packet data reordering, but its output is
// library-specific, thus not usable by the majority of external Go libraries.
// The io.Reader interface, on the other hand, is used throughout much of Go
// code as an easy mechanism for reading in data streams and decoding them.  For
// example, the net/http package provides the ReadRequest function, which can
// parse an HTTP request from a live data stream, just what we'd want when
// sniffing HTTP traffic.  Using ReaderStream, this is relatively easy to set
// up:
//
//	// Create our StreamFactory
//	type httpStreamFactory struct {}
//	func (f *httpStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
//		r := tcpreader.NewReaderStream()
//		go printRequests(&r, a, b)
//		return &r
//	}
//	func printRequests(r io.Reader, a, b gopacket.Flow) {
//		// Convert to bufio, since that's what ReadRequest wants.
//		buf := bufio.NewReader(r)
//		for {
//			if req, err := http.ReadRequest(buf); err == io.EOF {
//				return
//			} else if err != nil {
//				log.Println("Error parsing HTTP requests:", err)
//			} else {
//				fmt.Println(a, b)
//				fmt.Println("HTTP REQUEST:", req)
//				fmt.Println("Body contains", tcpreader.DiscardBytesToEOF(req.Body), "bytes")
//			}
//		}
//	}
//
// Using just this code, we're able to reference a powerful, built-in library
// for HTTP request parsing to do all the dirty-work of parsing requests from
// the wire in real-time.  Pass this stream factory to an tcpassembly.StreamPool,
// start up an tcpassembly.Assembler, and you're good to go!
package tcpreader

import (
	"errors"
	"io"
	"sync"

	"github.com/gopacket/gopacket/tcpassembly"
)

const discardBufferSize = 4096

// Concurrent discards each get their own buffer.
var discardBuffers = sync.Pool{
	New: func() interface{} {
		b := make([]byte, discardBufferSize)
		return &b
	},
}

// DiscardBytesToFirstError will read in all bytes up to the first error
// reported by the given reader, then return the number of bytes discarded
// and the error encountered.
func DiscardBytesToFirstError(r io.Reader) (discarded int, err error) {
	buf := discardBuffers.Get().(*[]byte)
	defer discardBuffers.Put(buf)
	for {
		n, e := r.Read(*buf)
		discarded += n
		if e != nil {
			return discarded, e
		}
	}
}

// DiscardBytesToEOF will read in all bytes from a Reader until it
// encounters an io.EOF, then return the number of bytes.  A Reader that
// returns a non-io.EOF error twice in a row without delivering any bytes
// is considered stuck and is given up on.  DataLost does not count: each
// Read reports it once, so a run of them ends on its own.
func DiscardBytesToEOF(r io.Reader) (discarded int) {
	stuck := false
	for {
		n, e := DiscardBytesToFirstError(r)
		discarded += n
		if e == io.EOF || (stuck && n == 0) {
			return
		}
		stuck = n == 0 && e != DataLost
	}
}

// ReaderStream implements both tcpassembly.Stream and io.Reader.  You can use it
// as a building block to make simple, easy stream handlers.
//
// IMPORTANT:  If you use a ReaderStream, you MUST read ALL BYTES from it,
// quickly.  Not reading available bytes will block TCP stream reassembly.  It's
// a common pattern to do this by starting a goroutine in the factory's New
// method:
//
//	type myStreamHandler struct {
//		r ReaderStream
//	}
//	func (m *myStreamHandler) run() {
//		// Do something here that reads all of the ReaderStream, or your assembly
//		// will block.
//		fmt.Println(tcpreader.DiscardBytesToEOF(&m.r))
//	}
//	func (f *myStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
//		s := &myStreamHandler{}
//		go s.run()
//		// Return the ReaderStream as the stream that assembly should populate.
//		return &s.r
//	}
type ReaderStream struct {
	ReaderStreamOptions
	reassembled  chan []tcpassembly.Reassembly
	done         chan bool
	current      []tcpassembly.Reassembly
	closed       bool
	lossReported bool
	first        bool
	initiated    bool
}

// ReaderStreamOptions provides user-resettable options for a ReaderStream.
type ReaderStreamOptions struct {
	// LossErrors determines whether this stream will return
	// ReaderStreamDataLoss errors from its Read function whenever it
	// determines data has been lost.
	LossErrors bool
}

// NewReaderStream returns a new ReaderStream object.
func NewReaderStream() ReaderStream {
	r := ReaderStream{
		reassembled: make(chan []tcpassembly.Reassembly),
		done:        make(chan bool),
		first:       true,
		initiated:   true,
	}
	return r
}

// Reassembled implements tcpassembly.Stream's Reassembled function.
func (r *ReaderStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	if !r.initiated {
		panic("ReaderStream not created via NewReaderStream")
	}
	r.reassembled <- reassembly
	<-r.done
}

// ReassemblyComplete implements tcpassembly.Stream's ReassemblyComplete function.
func (r *ReaderStream) ReassemblyComplete() {
	close(r.reassembled)
	close(r.done)
}

// stripEmpty strips empty reassembly slices off the front of its current set of
// slices.
func (r *ReaderStream) stripEmpty() {
	for len(r.current) > 0 && len(r.current[0].Bytes) == 0 {
		// An empty Reassembly may still carry a Skip the caller wants to hear
		// about: leave it for Read to report.
		if r.LossErrors && !r.lossReported && r.current[0].Skip != 0 {
			return
		}
		r.current = r.current[1:]
		r.lossReported = false
	}
}

// DataLost is returned by the ReaderStream's Read function when it encounters
// a Reassembly with Skip != 0.
var DataLost = errors.New("lost data")

// Read implements io.Reader's Read function.
// Given a byte slice, it will either copy a non-zero number of bytes into
// that slice and return the number of bytes and a nil error, or it will
// leave slice p as is and return 0, io.EOF.
func (r *ReaderStream) Read(p []byte) (int, error) {
	if !r.initiated {
		panic("ReaderStream not created via NewReaderStream")
	}
	var ok bool
	r.stripEmpty()
	for !r.closed && len(r.current) == 0 {
		if r.first {
			r.first = false
		} else {
			r.done <- true
		}
		if r.current, ok = <-r.reassembled; ok {
			r.stripEmpty()
		} else {
			r.closed = true
		}
	}
	if len(r.current) > 0 {
		current := &r.current[0]
		if r.LossErrors && !r.lossReported && current.Skip != 0 {
			r.lossReported = true
			return 0, DataLost
		}
		length := copy(p, current.Bytes)
		current.Bytes = current.Bytes[length:]
		return length, nil
	}
	return 0, io.EOF
}

// Close implements io.Closer's Close function, making ReaderStream a
// io.ReadCloser.  It discards all remaining bytes in the reassembly in a
// manner that's safe for the assembler (IE: it doesn't block).
func (r *ReaderStream) Close() error {
	r.current = nil
	if r.closed {
		return nil
	}
	r.closed = true

	// After a Read the assembler waits on done for the slice it handed over:
	// release it, or the drain below waits on it forever.
	if !r.first {
		r.done <- true
	}
	for {
		if _, ok := <-r.reassembled; !ok {
			return nil
		}
		r.done <- true
	}
}
