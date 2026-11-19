// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// PI service parameter blocks, by service name:
//
//	_INSE, _INS2, _DELE:      count, unknown, {type(2), number(5), fs}...
//	P_PROGRAM, _MODU, _GARB:  one ASCII argument, the whole block
//	_N_* (Sinumerik NC):      {length, string[, fill if length even]}...

const (
	s7commPIBlocksHead = 2
	s7commPIBlockLen   = s7commBlockTypeLen + s7commBlockNumDigits + 1
	s7commPINCPrefix   = "_N_"
)

// S7CommPIBlock is one block a PI service activates or deletes.
type S7CommPIBlock struct {
	Type       S7CommBlockType
	Number     string // ASCII digits
	Filesystem uint8  // e.g. 'P' passive, 'A' active
}

// decodeParams reads the parameter block of the services it knows.
func (pi *S7CommPIService) decodeParams() error {
	p := pi.ParamBlock
	switch pi.ServiceName {
	case "_INSE", "_INS2", "_DELE":
		blocks, err := s7commPIBlocks(p)
		if err != nil {
			return err
		}
		pi.Blocks = blocks
	case "P_PROGRAM", "_MODU", "_GARB":
		if len(p) > 0 {
			pi.Args = []string{string(p)}
		}
	default:
		if !strings.HasPrefix(pi.ServiceName, s7commPINCPrefix) {
			return nil
		}
		args, err := s7commPIArgs(p)
		if err != nil {
			return err
		}
		pi.Args = args
	}
	return nil
}

// s7commPIBlocks reads a block list.
func s7commPIBlocks(p []byte) ([]S7CommPIBlock, error) {
	if len(p) < s7commPIBlocksHead {
		return nil, fmt.Errorf("%w: PI block list %d octets", ErrS7CommMalformed, len(p))
	}
	n := int(p[0])
	p = p[s7commPIBlocksHead:]
	if n*s7commPIBlockLen > len(p) {
		return nil, fmt.Errorf("%w: %d PI blocks in %d octets", ErrS7CommMalformed, n, len(p))
	}

	blocks := make([]S7CommPIBlock, n)
	for i := range blocks {
		b := p[i*s7commPIBlockLen:]
		blocks[i] = S7CommPIBlock{
			Type:       S7CommBlockType(binary.BigEndian.Uint16(b[0:2])),
			Number:     string(b[s7commBlockTypeLen : s7commBlockTypeLen+s7commBlockNumDigits]),
			Filesystem: b[s7commPIBlockLen-1],
		}
	}
	return blocks, nil
}

// s7commPIArgs reads NC service arguments: length-prefixed strings,
// each padded so that length and string fill an even size.
func s7commPIArgs(p []byte) ([]string, error) {
	// Counting pass so the slice is allocated once.
	n := 0
	for rest := p; len(rest) > 0; n++ {
		size := 1 + int(rest[0])
		if size > len(rest) {
			return nil, fmt.Errorf("%w: PI argument %d length %d", ErrS7CommMalformed, n, rest[0])
		}
		rest = rest[s7commPIArgEnd(size, len(rest)):]
	}

	args := make([]string, 0, n)
	for len(p) > 0 {
		size := 1 + int(p[0])
		args = append(args, string(p[1:size]))
		p = p[s7commPIArgEnd(size, len(p)):]
	}
	return args, nil
}

// s7commPIArgEnd returns the end of an argument of size octets with its
// fill octet, capped at the available octets.
func s7commPIArgEnd(size, avail int) int {
	if size%2 == 1 {
		size++
	}
	if size > avail {
		return avail
	}
	return size
}
