// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapgo

import (
	"bytes"
	"errors"
	"io"
)

var errLengthOverflow = errors.New("length from file does not fit in int")

// eofAfterError ends a stream after its first error. A gzip.Reader that
// failed returns the same error on every later Read, where a damaged plain
// file returns it once and then io.EOF. The read loops in the gopacket
// documentation stop on io.EOF only, so a gzip stream must end the same way.
type eofAfterError struct {
	r   io.Reader
	err error // the error to return next, io.EOF once the stream failed
}

func (e *eofAfterError) Read(p []byte) (int, error) {
	if e.err != nil {
		err := e.err
		e.err = io.EOF
		return 0, err
	}

	// Bytes and an error are never returned together: io.ReadFull drops an
	// error that arrives with the last bytes it needed, and a bad checksum
	// comes with the last bytes of the stream.
	n, err := e.r.Read(p)
	if err != nil && n > 0 {
		e.err = err
		return n, nil
	}
	if err != nil {
		e.err = io.EOF
	}
	return n, err
}

// eagerReadMax is the largest buffer allocated before its bytes are read.
// It is libpcap's MAXIMUM_SNAPLEN, so real packets keep the fast path.
const eagerReadMax = 262144

// eagerRead reports whether n bytes from the file may be allocated up front.
// Readers keep their usual fast path for such lengths and use readFull for
// the rest. A uint32 length above 2^31 is negative in a 32 bit int.
func eagerRead(n int) bool {
	return n >= 0 && n <= eagerReadMax
}

// readFull reads n bytes from r into a new slice, with io.ReadFull's errors.
// Lengths come from the file, so above eagerReadMax the slice grows with the
// bytes actually read: a 40 byte file cannot make the reader allocate 4 GiB.
func readFull(r io.Reader, n int) ([]byte, error) {
	if n < 0 {
		return nil, errLengthOverflow
	}
	if n <= eagerReadMax {
		data := make([]byte, n)
		_, err := io.ReadFull(r, data)
		return data, err
	}

	var buf bytes.Buffer
	buf.Grow(eagerReadMax)
	m, err := io.CopyN(&buf, r, int64(n))
	if err == io.EOF && m > 0 {
		err = io.ErrUnexpectedEOF
	}
	return buf.Bytes(), err
}

// bufferSize is the zero copy buffer size for a packet of n bytes under
// snaplen. snaplen comes from the file, so it only sizes up to eagerReadMax.
func bufferSize(snaplen, n int) int {
	if snaplen > eagerReadMax {
		snaplen = eagerReadMax
	}
	if snaplen < n {
		return n
	}
	return snaplen
}
