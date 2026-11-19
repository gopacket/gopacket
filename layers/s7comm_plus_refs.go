// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import "fmt"

// Attribute 1048 (SubscriptionReferenceList) of a subscription object
// is an address array of UDInt that is really a record:
//
//	header | unsubscribe count | subscribe count
//	| reference number...                          (unsubscribe count)
//	| head, reference number, unknown, access area,
//	  symbol CRC, sub-area, LID...                 (subscribe count)
//
// The low word of a subscription's head counts its sub-area and LIDs,
// as LIDCount does in a variable address.

// S7CommPlusIDSubscriptionRefs is the attribute ID of a subscription
// reference list.
const S7CommPlusIDSubscriptionRefs = 1048

const (
	// Header bits of a subscription reference list.
	s7plusRefsNewBit      = 1 << 31
	s7plusRefsChangeShift = 16

	// s7plusRefHeadDepth masks the LID count in a subscription's head.
	s7plusRefHeadDepth = 0xFFFF

	// A list has a header and two counts; a subscription has head,
	// reference number, unknown, area, CRC and sub-area at least.
	s7plusRefsHeadWords = 3
	s7plusRefMinWords   = 6
)

// S7CommPlusSubscriptionRef is one variable a subscription asks for.
// Notifications name it by RefNumber.
type S7CommPlusSubscriptionRef struct {
	Head      uint32
	RefNumber uint32
	Unknown   uint32
	Address   S7CommPlusAddress
}

// S7CommPlusSubscriptionRefs is a decoded subscription reference list:
// the reference numbers to drop and the variables to add.
type S7CommPlusSubscriptionRefs struct {
	Header       uint32
	Unsubscribed []uint32
	Subscribed   []S7CommPlusSubscriptionRef

	// Rest holds array elements after the last subscription.
	Rest []uint32
}

// New reports whether the list creates the subscription.
func (l *S7CommPlusSubscriptionRefs) New() bool { return l.Header&s7plusRefsNewBit != 0 }

// ChangeCounter returns the subscription change counter.
func (l *S7CommPlusSubscriptionRefs) ChangeCounter() uint8 {
	return uint8(l.Header >> s7plusRefsChangeShift)
}

// s7plusWords walks the elements of a UDInt array. short is set once a
// word is asked for that the array does not have.
type s7plusWords struct {
	e     []S7CommPlusElement
	short bool
}

func (w *s7plusWords) next() uint32 {
	if len(w.e) == 0 {
		w.short = true
		return 0
	}

	v := uint32(w.e[0].Bits)
	w.e = w.e[1:]
	return v
}

// take returns the next n words. The caller has checked n against
// what is left.
func (w *s7plusWords) take(n int) []uint32 {
	if n == 0 {
		return nil
	}

	out := make([]uint32, n)
	for i := range out {
		out[i] = w.next()
	}
	return out
}

// SubscriptionRefs decodes the value of attribute
// S7CommPlusIDSubscriptionRefs. Any other value, and a list whose
// counts exceed its array, returns ErrS7CommPlusMalformed.
func (v *S7CommPlusValue) SubscriptionRefs() (*S7CommPlusSubscriptionRefs, error) {
	if v.Flags != S7CommPlusFlagAddressArray || v.Type != S7CommPlusTypeUDInt || len(v.Elements) < s7plusRefsHeadWords {
		return nil, fmt.Errorf("%w: not a subscription reference list", ErrS7CommPlusMalformed)
	}

	w := &s7plusWords{e: v.Elements}
	l := &S7CommPlusSubscriptionRefs{Header: w.next()}
	drop, add := w.next(), w.next()
	if uint64(drop)+uint64(add)*s7plusRefMinWords > uint64(len(w.e)) {
		return l, fmt.Errorf("%w: %d and %d subscription references in %d words", ErrS7CommPlusMalformed, drop, add, len(w.e))
	}

	l.Unsubscribed = w.take(int(drop))
	if add > 0 {
		l.Subscribed = make([]S7CommPlusSubscriptionRef, 0, add)
	}
	for i := uint32(0); i < add && !w.short; i++ {
		ref, ok := w.ref()
		if !ok {
			return l, fmt.Errorf("%w: subscription reference %d overruns its list", ErrS7CommPlusMalformed, i+1)
		}
		l.Subscribed = append(l.Subscribed, ref)
	}

	l.Rest = w.take(len(w.e))
	return l, nil
}

// ref reads one subscription. As in a variable address, classic blob
// access has three LIDs at least.
func (w *s7plusWords) ref() (S7CommPlusSubscriptionRef, bool) {
	ref := S7CommPlusSubscriptionRef{Head: w.next(), RefNumber: w.next(), Unknown: w.next()}
	a := &ref.Address
	a.AccessArea = w.next()
	a.SymbolCRC = w.next()
	a.AccessSubArea = w.next()
	a.LIDCount = ref.Head & s7plusRefHeadDepth
	if w.short {
		return ref, false
	}
	if a.LIDCount <= 1 {
		return ref, true
	}

	n := int(a.LIDCount - 1)
	if a.classic() && n < s7plusClassicLIDs && len(w.e) > 0 && uint32(w.e[0].Bits) == s7plusLIDClassicBlob {
		n = s7plusClassicLIDs
	}
	if n > len(w.e) {
		return ref, false
	}

	a.LIDs = w.take(n)
	return ref, true
}
