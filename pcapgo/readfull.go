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
