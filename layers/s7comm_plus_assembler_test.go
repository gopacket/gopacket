// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// s7PlusPDUs feeds the S7comm-plus frames of a capture to one
// assembler per direction and returns the PDUs in capture order. Any
// Feed error fails the test.
func s7PlusPDUs(t *testing.T, name string) []*S7CommPlusPDU {
	t.Helper()
	asm := map[gopacket.Flow]*S7CommPlusAssembler{}
	var out []*S7CommPlusPDU
	for i, p := range s7Packets(t, name) {
		s, ok := p.Layer(LayerTypeS7CommPlus).(*S7CommPlus)
		if !ok {
			continue
		}

		dir := p.TransportLayer().TransportFlow()
		if asm[dir] == nil {
			asm[dir] = &S7CommPlusAssembler{}
		}
		pdu, err := asm[dir].Feed(s)
		if err != nil {
			t.Fatalf("%s frame %d: %v", name, i+1, err)
		}
		if pdu != nil {
			out = append(out, pdu)
		}
	}

	for dir, a := range asm {
		if a.Pending() != 0 {
			t.Errorf("%s %v: %d octets left pending", name, dir, a.Pending())
		}
	}
	return out
}

// TestS7CommPlusAssemblerPcap joins the one fragmented PDU of the
// captures, a CreateObject request in three frames, and checks every
// PDU structurally: it decodes to its last octet, and each response
// answers a request with as many results as that asked for.
func TestS7CommPlusAssemblerPcap(t *testing.T) {
	for name, wantJoined := range map[string]int{"s7commplus-1200-upload.pcap": 1, "s7commplus-1511-opc.pcap": 0} {
		joined := 0
		reqs := map[uint16]*S7CommPlusBody{}
		fns := map[uint16]S7CommPlusFunction{}
		for _, pdu := range s7PlusPDUs(t, name) {
			b, err := pdu.DecodeBody()
			if err != nil {
				t.Errorf("%s %v %v seq %d: %v", name, pdu.Opcode, pdu.Function, pdu.Sequence, err)
				continue
			}
			if len(b.Rest) > 10 || strings.Trim(string(b.Rest), "\x00") != "" {
				t.Errorf("%s %v %v seq %d: rest %x", name, pdu.Opcode, pdu.Function, pdu.Sequence, b.Rest)
			}

			if pdu.Frames > 1 {
				joined++
				if pdu.Frames != 3 || pdu.Opcode != S7CommPlusOpRequest || pdu.Function != S7CommPlusFuncCreateObject ||
					len(pdu.Data) != 2219 || b.Elements == nil || len(b.Elements.Objects) != 1 {
					t.Errorf("%s: joined PDU of %d frames, %v %v, %d octets", name, pdu.Frames, pdu.Opcode, pdu.Function, len(pdu.Data))
				}
			}

			switch pdu.Opcode {
			case S7CommPlusOpRequest:
				reqs[pdu.Sequence], fns[pdu.Sequence] = b, pdu.Function
			case S7CommPlusOpResponse, S7CommPlusOpResponse2:
				req := reqs[pdu.Sequence]
				if req == nil || fns[pdu.Sequence] != pdu.Function {
					t.Errorf("%s: response %v seq %d has no request", name, pdu.Function, pdu.Sequence)
					continue
				}
				s7PlusCheckAnswer(t, name, pdu, req, b)
			}
		}
		if joined != wantJoined {
			t.Errorf("%s: %d joined PDUs, want %d", name, joined, wantJoined)
		}
	}
}

// s7PlusCheckAnswer checks that a response has no more results than
// its request has items, and for a read exactly as many.
func s7PlusCheckAnswer(t *testing.T, name string, pdu *S7CommPlusPDU, req, resp *S7CommPlusBody) {
	t.Helper()
	switch pdu.Function {
	case S7CommPlusFuncGetMultiVariables:
		if got := len(resp.Values) + len(resp.Errors); got != int(req.ItemCount) {
			t.Errorf("%s seq %d: %d values and errors for %d items", name, pdu.Sequence, got, req.ItemCount)
		}
		for _, v := range resp.Values {
			if v.ID == 0 || v.ID > req.ItemCount {
				t.Errorf("%s seq %d: value for item %d of %d", name, pdu.Sequence, v.ID, req.ItemCount)
			}
		}
	case S7CommPlusFuncSetMultiVariables:
		if len(resp.Errors) > int(req.ItemCount) || len(req.Values) != int(req.ItemCount) {
			t.Errorf("%s seq %d: %d errors, %d values for %d items", name, pdu.Sequence, len(resp.Errors), len(req.Values), req.ItemCount)
		}
	}
}

// s7PlusSplit cuts the frame body of a whole PDU into pieces of size
// octets and returns one frame per piece, the last with the trailer.
// A V3 frame keeps its integrity part in the first piece and the
// others get one of their own.
func s7PlusSplit(s *S7CommPlus, size int) [][]byte {
	body := s.rawBody()
	var integrity []byte
	if s.Version == S7CommPlusV3 {
		integrity = append([]byte{byte(len(s.Integrity))}, s.Integrity...)
	}

	// The data header is never cut: a first frame is far larger.
	head := len(s.rawBody()) - len(s.Data)

	var frames [][]byte
	for len(body) > 0 {
		n := size
		if len(frames) == 0 && n < head {
			n = head
		}
		if n > len(body) {
			n = len(body)
		}
		piece := append(append([]byte{}, integrity...), body[:n]...)
		body = body[n:]
		frames = append(frames, s7PlusRawFrame(s.Version, piece, len(body) == 0))
	}
	return frames
}

// TestS7CommPlusAssemblerSplit cuts every whole PDU of the captures
// into frames of several sizes and joins them again: same header, same
// Data, same body. With one-octet pieces most continuation frames
// start like a data header, which the frame decoder then reads; the
// assembler must still take their octets as data.
func TestS7CommPlusAssemblerSplit(t *testing.T) {
	v3 := s7PlusFrame(t, s7Hex("72030030"+"20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"+
		"31000004f200000005000003863401"+"72030000"))
	var frames []*S7CommPlus
	for _, name := range []string{"s7commplus-1511-opc.pcap", "s7commplus-1200-upload.pcap"} {
		for _, s := range s7PlusLayers(s7Packets(t, name)) {
			if s.HasDataHeader && s.HasTrailer {
				frames = append(frames, s)
			}
		}
	}

	for _, s := range append(frames, v3) {
		want, wantErr := s.DecodeBody()
		for _, size := range []int{1, 2, 7, 64, len(s.rawBody())} {
			a := &S7CommPlusAssembler{}
			var pdu *S7CommPlusPDU
			parts := s7PlusSplit(s, size)
			for i, raw := range parts {
				got, err := a.Feed(s7PlusFrame(t, raw))
				if err != nil || (got != nil) != (i == len(parts)-1) {
					t.Fatalf("%v %v in pieces of %d, frame %d: %v, %v", s.Opcode, s.Function, size, i, got, err)
				}
				if a.Pending() > len(s.rawBody()) {
					t.Fatalf("pending %d of %d octets", a.Pending(), len(s.rawBody()))
				}
				pdu = got
			}

			if pdu.Frames != len(parts) || !bytes.Equal(pdu.Data, s.Data) || !pdu.HasTrailer ||
				pdu.Opcode != s.Opcode || pdu.Function != s.Function || pdu.Sequence != s.Sequence || pdu.SessionID != s.SessionID {
				t.Fatalf("%v %v in pieces of %d: %d frames, data %x, want %x", s.Opcode, s.Function, size, pdu.Frames, pdu.Data, s.Data)
			}
			got, err := pdu.DecodeBody()
			if !reflect.DeepEqual(got, want) || (err == nil) != (wantErr == nil) {
				t.Fatalf("%v %v in pieces of %d: body differs", s.Opcode, s.Function, size)
			}
		}
	}
}

func TestS7CommPlusAssemblerOrder(t *testing.T) {
	whole := s7PlusFrame(t, s7Hex("7202001132000005420000000234000000000000007202 0000"))
	first := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, s7Hex("3200000542000000023400"), false))
	inner := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, s7Hex("aabb"), false))
	last := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, s7Hex("ccdd"), true))
	event := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusKeepAlive, s7Hex(s7PlusEventHead), false))

	a := &S7CommPlusAssembler{}
	if pdu, err := a.Feed(nil); pdu != nil || err != nil {
		t.Errorf("nil frame: %v, %v", pdu, err)
	}

	// A continuation with no first frame: reported once, then skipped up
	// to the trailer.
	if pdu, err := a.Feed(inner); pdu != nil || !errors.Is(err, ErrS7CommPlusNoStart) {
		t.Errorf("orphan frame: %v, %v", pdu, err)
	}
	for _, s := range []*S7CommPlus{inner, first, last} {
		if pdu, err := a.Feed(s); pdu != nil || err != nil || a.Pending() != 0 {
			t.Errorf("skipped frame: %v, %v, pending %d", pdu, err, a.Pending())
		}
	}

	// A last frame alone is an orphan too and leaves nothing behind.
	if pdu, err := a.Feed(last); pdu != nil || !errors.Is(err, ErrS7CommPlusNoStart) {
		t.Errorf("orphan last frame: %v, %v", pdu, err)
	}

	// A whole PDU aliases its frame.
	pdu, err := a.Feed(whole)
	if err != nil || pdu == nil || pdu.Frames != 1 || &pdu.Data[0] != &whole.Data[0] {
		t.Fatalf("whole frame: %+v, %v", pdu, err)
	}

	// A system event between the frames of a PDU passes through.
	for _, s := range []*S7CommPlus{first, inner} {
		if pdu, err := a.Feed(s); pdu != nil || err != nil {
			t.Fatalf("fragment: %v, %v", pdu, err)
		}
	}
	if pdu, err := a.Feed(event); err != nil || pdu == nil || pdu.Version != S7CommPlusKeepAlive || a.Pending() != 3 {
		t.Fatalf("system event: %+v, %v, pending %d", pdu, err, a.Pending())
	}
	pdu, err = a.Feed(last)
	if err != nil || pdu == nil || pdu.Frames != 3 || !bytes.Equal(pdu.Data, s7Hex("00aabbccdd")) || a.Pending() != 0 {
		t.Fatalf("joined: %+v, %v", pdu, err)
	}
	if pdu.Function != S7CommPlusFuncSetMultiVariables || pdu.Sequence != 2 || pdu.Contents != nil {
		t.Errorf("joined header: %+v", pdu)
	}

	// The joined PDU does not alias its frames.
	first.Data[0], inner.Data[0] = 0xff, 0xff
	if !bytes.Equal(pdu.Data, s7Hex("00aabbccdd")) {
		t.Errorf("joined data follows its frames: %x", pdu.Data)
	}

	// Reset drops an unfinished PDU; its last frame is then an orphan.
	a.Feed(first)
	a.Reset()
	if pdu, err := a.Feed(last); pdu != nil || !errors.Is(err, ErrS7CommPlusNoStart) || a.Pending() != 0 {
		t.Errorf("after Reset: %v, %v", pdu, err)
	}
}

func TestS7CommPlusAssemblerCap(t *testing.T) {
	first := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, s7Hex("3200000542000000023400"), false))
	inner := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, bytes.Repeat([]byte{0xaa}, 6), false))
	last := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, s7Hex("ccdd"), true))
	whole := s7PlusFrame(t, s7Hex("7202001132000005420000000234000000000000007202 0000"))

	// 1 + 6 + 6 octets pass 12: reported once, then skipped to the trailer.
	a := &S7CommPlusAssembler{MaxSize: 12}
	for i, want := range []error{nil, nil, ErrS7CommPlusPDUTooLong, nil, nil} {
		s := inner
		if i == 0 {
			s = first
		}
		pdu, err := a.Feed(s)
		if pdu != nil || !errors.Is(err, want) || (want == nil) != (err == nil) {
			t.Errorf("frame %d: %v, %v", i, pdu, err)
		}
		if a.Pending() > a.MaxSize {
			t.Errorf("frame %d: pending %d over the cap", i, a.Pending())
		}
	}
	if pdu, err := a.Feed(last); pdu != nil || err != nil {
		t.Errorf("end of the long PDU: %v, %v", pdu, err)
	}
	if pdu, err := a.Feed(whole); pdu == nil || err != nil {
		t.Errorf("frame after the long PDU: %v, %v", pdu, err)
	}

	// A PDU of exactly the cap passes.
	a = &S7CommPlusAssembler{MaxSize: 9}
	a.Feed(first)
	a.Feed(inner)
	if pdu, err := a.Feed(last); err != nil || pdu == nil || len(pdu.Data) != 9 {
		t.Errorf("PDU at the cap: %+v, %v", pdu, err)
	}

	// A first frame over the cap is never held; one that also ends the
	// PDU is not the assembler's to refuse.
	a = &S7CommPlusAssembler{MaxSize: 2}
	big := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, s7Hex("3200000542000000023400aabbcc"), false))
	if pdu, err := a.Feed(big); pdu != nil || !errors.Is(err, ErrS7CommPlusPDUTooLong) || a.Pending() != 0 {
		t.Errorf("long first frame: %v, %v, pending %d", pdu, err, a.Pending())
	}
	a.Feed(last)
	if pdu, err := a.Feed(whole); pdu == nil || err != nil {
		t.Errorf("whole frame over the cap: %v, %v", pdu, err)
	}

	// The default cap.
	if got := (&S7CommPlusAssembler{}).limit(); got != S7CommPlusDefaultMaxPDU {
		t.Errorf("default cap %d", got)
	}
}

// A SetVarSubStreamed request sends its stream in pieces after a
// first frame that holds the whole body.
func TestS7CommPlusAssemblerStream(t *testing.T) {
	head := "31000005" + "7c" + "0000" + "0007" + "00000386" + "34"
	body := "00000001" + "0015026869" + s7PlusQualifier + "0000" + "000405"
	first := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, s7Hex(head+body), false))
	piece1 := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, s7Hex("03"+"aabbcc"), false))
	piece2 := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, s7Hex("02"+"ddee"+"00000000"), true))
	if first.Function != S7CommPlusFuncSetVarSubStreamed || first.Opcode != S7CommPlusOpRequest {
		t.Fatalf("first frame: %v %v", first.Opcode, first.Function)
	}

	a := &S7CommPlusAssembler{}
	for _, s := range []*S7CommPlus{first, piece1} {
		if pdu, err := a.Feed(s); pdu != nil || err != nil {
			t.Fatalf("stream frame: %v, %v", pdu, err)
		}
	}
	if a.Pending() != len(first.Data)+3 {
		t.Errorf("pending %d", a.Pending())
	}

	pdu, err := a.Feed(piece2)
	if err != nil || pdu == nil || pdu.Frames != 3 || !bytes.Equal(pdu.Data, s7Hex(body)) ||
		!bytes.Equal(pdu.Stream, s7Hex("aabbccddee")) || !bytes.Equal(pdu.StreamTail, s7Hex("00000000")) {
		t.Fatalf("stream PDU: %+v, %v", pdu, err)
	}
	b, err := pdu.DecodeBody()
	if err != nil || b.Stream == nil || b.Stream.Elements[0].Uint() != 5 || b.Qualifier == nil {
		t.Errorf("stream body: %+v, %v", b, err)
	}

	// A piece longer than its frame, and one over the cap.
	a.Feed(first)
	lie := s7PlusFrame(t, s7PlusRawFrame(S7CommPlusV2, s7Hex("05"+"aabb"), false))
	if pdu, err := a.Feed(lie); pdu != nil || !errors.Is(err, ErrS7CommPlusMalformed) || a.Pending() != 0 {
		t.Errorf("piece length lie: %v, %v", pdu, err)
	}
	a.Feed(piece2)

	a.MaxSize = len(first.Data) + 2
	a.Feed(first)
	if pdu, err := a.Feed(piece1); pdu != nil || !errors.Is(err, ErrS7CommPlusPDUTooLong) || a.Pending() != 0 {
		t.Errorf("stream over the cap: %v, %v", pdu, err)
	}
}

// FuzzS7CommPlusAssembler reads its input as frames back to back and
// feeds them to one assembler with a small cap. The first octet picks
// the cap.
func FuzzS7CommPlusAssembler(f *testing.F) {
	cat := func(frames ...[]byte) []byte { return append([]byte{40}, bytes.Join(frames, nil)...) }
	f.Add(cat(s7Hex("7202001132000005420000000234000000000000007202 0000")))
	f.Add(cat(s7PlusRawFrame(S7CommPlusV2, s7Hex("3200000542000000023400"), false),
		s7PlusRawFrame(S7CommPlusV2, s7Hex("aabb"), false), s7PlusRawFrame(S7CommPlusV2, s7Hex("ccdd"), true)))
	f.Add(cat(s7PlusRawFrame(S7CommPlusV2, s7Hex("310000057c0000000700000386340000000100150268690000000405"), false),
		s7PlusRawFrame(S7CommPlusV2, s7Hex("03aabbcc"), false), s7PlusRawFrame(S7CommPlusV2, s7Hex("02ddee00000000"), true)))
	f.Add(cat(s7PlusRawFrame(S7CommPlusKeepAlive, s7Hex(s7PlusEventHead+s7PlusEventStruct), false)))
	f.Add(cat(s7PlusRawFrame(S7CommPlusV2, s7Hex("aabb"), false), s7Hex(s7PlusSubscribeFrame), s7Hex(s7PlusNotifyFrame)))
	f.Add(cat(s7Hex("72030030" + "20000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" + "31000004f200000005000003863401")))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		a := &S7CommPlusAssembler{MaxSize: int(data[0])}
		limit := a.limit()
		data = data[1:]
		for len(data) > 0 {
			s := &S7CommPlus{}
			if s.DecodeFromBytes(data, gopacket.NilDecodeFeedback) != nil {
				return
			}
			data = s.Payload

			pdu, _ := a.Feed(s)
			if a.Pending() > limit {
				t.Fatalf("pending %d over the cap %d", a.Pending(), limit)
			}
			if pdu == nil {
				continue
			}
			if pdu.Frames > 1 && len(pdu.Data)+len(pdu.Stream) > limit {
				t.Fatalf("joined PDU of %d octets over the cap %d", len(pdu.Data)+len(pdu.Stream), limit)
			}
			s7PlusFuzzPDU(t, pdu)
		}
	})
}

// s7PlusFuzzPDU decodes whatever a PDU holds and calls every accessor
// on the result.
func s7PlusFuzzPDU(t *testing.T, pdu *S7CommPlusPDU) {
	if e, err := pdu.DecodeSysEvent(); err == nil && e.Value != nil && e.Message != "" {
		t.Fatalf("system event with text and value: %+v", e)
	}

	b, _ := pdu.DecodeBody()
	if b != nil && len(b.Rest) > len(pdu.Data) {
		t.Fatalf("rest %d of %d octets", len(b.Rest), len(pdu.Data))
	}
	s7PlusFuzzBody(b)
}

// s7PlusFuzzBody calls the lazy decoders on every value and type list
// entry of a body.
func s7PlusFuzzBody(b *S7CommPlusBody) {
	s7PlusWalk(b, func(iv *S7CommPlusIDValue) {
		_, _ = iv.Value.SubscriptionRefs()
	}, func(v *S7CommPlusVarType) {
		_, _ = v.Offsets()
	})
}
