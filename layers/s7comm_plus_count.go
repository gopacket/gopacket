// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

// Most S7comm-plus lists end at a terminator, so their length is not
// known before they are read, and a list of three-octet items grown by
// appending costs several times its final size in discarded arrays.
// The reader therefore reads such a list twice:
//
//	dry run:  walk the list, keep nothing, note its length and the
//	          length of every list nested in it (hints, stream order)
//	real run: allocate each list once from its hint
//
// The outermost list starts the dry run; the lists inside it find
// their hint and start none, so a body is walked twice however deep it
// nests. Both runs are the same code: a dry run only skips what
// allocates. A hint is advice. A list that finds none, or a wrong one,
// still decodes right by appending.

// The reader counts its dry runs in dryRuns, for the tests to check
// that nesting does not multiply them.

// s7plusHint is what a dry run found for the list that starts with
// left octets unread: n entries (objects, for an element list) and m
// attributes.
type s7plusHint struct {
	left int
	n    int
	m    int
}

// s7plusNoSlot is the hint slot of a list that has noted nothing yet.
const s7plusNoSlot = -1

// note returns slot, or when the list has none yet, a new hint slot
// for the list that started with left octets unread. Empty lists never
// call it: a hint costs more than the terminator it would describe.
func (r *s7plusReader) note(slot, left int) int {
	if slot != s7plusNoSlot {
		return slot
	}
	r.hints = append(r.hints, s7plusHint{left: left})
	return len(r.hints) - 1
}

// hint returns the hint of the list that starts here, if a dry run
// left one.
func (r *s7plusReader) hint() (s7plusHint, bool) {
	// Hints are in stream order: those with more octets left belong to
	// lists already passed.
	for r.next < len(r.hints) && r.hints[r.next].left > len(r.b) {
		r.next++
	}
	if r.next == len(r.hints) {
		r.hints, r.next = r.hints[:0], 0
		return s7plusHint{}, false
	}

	h := r.hints[r.next]
	if h.left != len(r.b) {
		return s7plusHint{}, false
	}
	r.next++
	return h, true
}

// ahead returns the hint of the list that starts here. Without one it
// dry-runs scan, which must read that list, and puts the reader back.
func (r *s7plusReader) ahead(scan func()) s7plusHint {
	if r.err != nil {
		return s7plusHint{}
	}
	if h, ok := r.hint(); ok {
		return h
	}

	b, depth := r.b, r.depth
	r.dryRuns++
	r.dry = true
	scan()
	r.dry = false
	r.b, r.err, r.depth = b, nil, depth

	h, _ := r.hint()
	return h
}
