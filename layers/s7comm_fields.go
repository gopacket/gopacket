// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/hex"
	"strconv"
)

// Named fields. Services with many record layouts (SZL records, the
// programmer command stacks) are split into a list of named fields
// instead of one struct per layout.

// S7CommFieldKind says which value of an S7CommField is set.
type S7CommFieldKind uint8

// Field kinds.
const (
	S7CommFieldUint  S7CommFieldKind = iota // Value
	S7CommFieldText                         // Text
	S7CommFieldBytes                        // Raw only
)

// S7CommField is one named field of a record. Raw holds the octets of
// the field, aliasing the packet data.
type S7CommField struct {
	Name  string
	Kind  S7CommFieldKind
	Value uint32 // S7CommFieldUint
	Text  string // S7CommFieldText, up to the first NUL
	Raw   []byte
}

// String returns the field as "name=value".
func (f S7CommField) String() string {
	switch f.Kind {
	case S7CommFieldUint:
		return f.Name + "=" + strconv.FormatUint(uint64(f.Value), 10)
	case S7CommFieldText:
		return f.Name + "=" + strconv.Quote(f.Text)
	}
	return f.Name + "=" + hex.EncodeToString(f.Raw)
}

// s7commFieldEnc is how a field definition reads its octets.
type s7commFieldEnc uint8

const (
	s7commEncBE  s7commFieldEnc = iota // big-endian unsigned
	s7commEncLE                        // little-endian unsigned
	s7commEncStr                       // ASCII
	s7commEncOct                       // octets
)

// s7commFieldDef defines one field of a fixed record layout.
type s7commFieldDef struct {
	name string
	size uint16
	enc  s7commFieldEnc
}

// s7commFixedFields reads a record by a fixed layout.
func s7commFixedFields(defs []s7commFieldDef, r []byte) []S7CommField {
	need := 0
	for _, d := range defs {
		need += int(d.size)
	}
	if len(r) < need {
		return nil
	}

	fields := make([]S7CommField, len(defs))
	for k, d := range defs {
		fields[k] = d.read(r[:d.size])
		r = r[d.size:]
	}
	return fields
}

// read decodes the octets of one field.
func (d s7commFieldDef) read(b []byte) S7CommField {
	f := S7CommField{Name: d.name, Raw: b}
	switch d.enc {
	case s7commEncStr:
		f.Kind = S7CommFieldText
		f.Text = s7commCString(b)
	case s7commEncOct:
		f.Kind = S7CommFieldBytes
	case s7commEncLE:
		for k := len(b) - 1; k >= 0; k-- {
			f.Value = f.Value<<s7commBitsPerByte | uint32(b[k])
		}
	default:
		for _, c := range b {
			f.Value = f.Value<<s7commBitsPerByte | uint32(c)
		}
	}
	return f
}

// s7commFieldCursor reads fields off a record whose layout depends on
// its content. Reading past the end sets short and yields nothing.
type s7commFieldCursor struct {
	rest   []byte
	fields []S7CommField
	short  bool
}

// take reads one field of a definition.
func (c *s7commFieldCursor) take(name string, size int, enc s7commFieldEnc) uint32 {
	if c.short || len(c.rest) < size {
		c.short = true
		return 0
	}

	f := s7commFieldDef{name, uint16(size), enc}.read(c.rest[:size])
	c.fields = append(c.fields, f)
	c.rest = c.rest[size:]
	return f.Value
}

// be reads a big-endian unsigned field.
func (c *s7commFieldCursor) be(name string, size int) uint32 {
	return c.take(name, size, s7commEncBE)
}

// oct reads a field of octets.
func (c *s7commFieldCursor) oct(name string, size int) {
	c.take(name, size, s7commEncOct)
}

// defs reads the fields of a fixed layout.
func (c *s7commFieldCursor) defs(defs []s7commFieldDef) {
	for _, d := range defs {
		c.take(d.name, int(d.size), d.enc)
	}
}

// word reads a little-endian 16 bit field.
func (c *s7commFieldCursor) word(name string) uint32 {
	return c.take(name, s7commSZLWordLen, s7commEncLE)
}

// list reads a count and that many 16 bit fields. The count is checked
// against the octets left before anything is appended.
func (c *s7commFieldCursor) list(countName, itemName string) {
	n := int(c.word(countName))
	if c.short || n*s7commSZLWordLen > len(c.rest) {
		c.short = true
		return
	}

	for k := 0; k < n; k++ {
		c.word(itemName)
	}
}

// done returns the fields, or nil if the record was too short.
func (c *s7commFieldCursor) done() []S7CommField {
	if c.short {
		return nil
	}
	return c.fields
}
