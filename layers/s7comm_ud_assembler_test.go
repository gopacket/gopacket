// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/gopacket/gopacket"
)

// Type and group octets of the Userdata parameter.
const (
	s7TGCPURes   = 0x84 // response, CPU functions
	s7TGCPUReq   = 0x44 // request, CPU functions
	s7TGBlockRes = 0x83 // response, block functions
	s7TGNCPush   = 0x3f // push, NC programming
	s7TGPBCReq   = 0x46 // request, PBC BSEND
)

// s7UDUnit is one data unit of a test transfer.
type s7UDUnit struct {
	typeGroup, sub, seq, ref, last byte
	value                          []byte
}

// pdu builds the Userdata PDU of a data unit.
func (u s7UDUnit) pdu() []byte {
	pdu := s7UDPDU(u.typeGroup, u.sub, u.value)
	pdu[17], pdu[18], pdu[19] = u.seq, u.ref, u.last

	// Without a value the data header reads 0x0A, length 0, as in
	// requests for the next data unit.
	if len(u.value) == 0 {
		pdu[s7commHeaderLen+s7commUDExtLen] = byte(S7CommRetObjectMissing)
	}
	return pdu
}

// s7UDSplit cuts a value into data units at the given offsets; all but
// the last announce more.
func s7UDSplit(typeGroup, sub, seq, ref byte, value []byte, cuts ...int) []s7UDUnit {
	var units []s7UDUnit
	start := 0
	for i, end := range append(cuts, len(value)) {
		last := byte(1)
		if i == len(cuts) {
			last = 0
		}
		units = append(units, s7UDUnit{typeGroup, sub, seq, ref, last, value[start:end]})
		start = end
	}
	return units
}

// s7UDFeed feeds data units; every one but the last must be held.
func s7UDFeed(t *testing.T, a *S7CommUDAssembler, units []s7UDUnit) *S7CommUserdata {
	t.Helper()
	for i, unit := range units {
		u, err := a.Feed(s7Decode(t, unit.pdu()))
		if err != nil {
			t.Fatalf("unit %d: %v", i, err)
		}
		if i == len(units)-1 {
			return u
		}
		if u != nil {
			t.Fatalf("unit %d of %d returned a view", i, len(units))
		}
	}
	return nil
}

// s7TestSZLValue is an SZL 0x0111 response value: one module
// identification record.
var s7TestSZLValue = s7Hex("01110001001c0001" + "0001" + "3645533720333135" + "2d32454831342d30" + "41423020" + "00c000040001")

func TestS7CommUDAsmEveryOffset(t *testing.T) {
	val := s7TestSZLValue
	whole := s7Decode(t, s7UDPDU(s7TGCPURes, byte(S7CommCPUReadSZL), val)).Userdata
	if whole.SZL == nil || len(whole.SZL.ModuleIDs) != 1 {
		t.Fatalf("unfragmented SZL = %+v", whole.SZL)
	}

	// Units of at least two octets, the shortest that count as data.
	for cut := 2; cut <= len(val)-2; cut++ {
		var a S7CommUDAssembler
		u := s7UDFeed(t, &a, s7UDSplit(s7TGCPURes, byte(S7CommCPUReadSZL), 1, 3, val, cut))
		if u == nil || u.Fragments != 2 || !bytes.Equal(u.Data, val) || u.Fragmented() {
			t.Fatalf("cut %d: %+v", cut, u)
		}
		if u.DecodeErr != nil || u.SZL == nil || len(u.SZL.ModuleIDs) != 1 ||
			u.SZL.ModuleIDs[0] != whole.SZL.ModuleIDs[0] {
			t.Fatalf("cut %d: SZL %+v, err %v", cut, u.SZL, u.DecodeErr)
		}
		if a.Pending() != 0 {
			t.Fatalf("cut %d: %d octets held after the last unit", cut, a.Pending())
		}
	}

	// Two octets per unit.
	var cuts []int
	for i := 2; i < len(val)-1; i += 2 {
		cuts = append(cuts, i)
	}
	var a S7CommUDAssembler
	u := s7UDFeed(t, &a, s7UDSplit(s7TGCPURes, byte(S7CommCPUReadSZL), 1, 3, val, cuts...))
	if u == nil || u.Fragments != len(cuts)+1 || u.SZL == nil || len(u.SZL.ModuleIDs) != 1 {
		t.Errorf("two-octet units: %+v", u)
	}
}

// TestS7CommUDAsmPassThrough checks PDUs that are no part of a
// transfer come back as their own view, and non-Userdata as nil.
func TestS7CommUDAsmPassThrough(t *testing.T) {
	var a S7CommUDAssembler
	for _, pdu := range s7UDVectors {
		s := s7Decode(t, pdu)
		u, err := a.Feed(s)
		if err != nil {
			t.Fatal(err)
		}
		if s.Userdata == nil && u != nil {
			t.Errorf("% x: view for a PDU without Userdata", pdu)
		}
		if s.Userdata != nil && !s.Userdata.Fragmented() && u != s.Userdata {
			t.Errorf("% x: unfragmented view replaced", pdu)
		}
	}

	if u, err := a.Feed(nil); u != nil || err != nil {
		t.Errorf("nil layer: %v, %v", u, err)
	}
	if u, err := a.Feed(s7Decode(t, s7TestReadJob[7:])); u != nil || err != nil {
		t.Errorf("job: %v, %v", u, err)
	}
	if a.Pending() != 0 {
		t.Errorf("%d octets held", a.Pending())
	}
}

func TestS7CommUDAssemblerCap(t *testing.T) {
	sub := byte(S7CommCPUReadSZL)
	val := s7TestSZLValue
	a := S7CommUDAssembler{MaxSize: 20}
	feed := func(u s7UDUnit) (*S7CommUserdata, error) {
		return a.Feed(s7Decode(t, u.pdu()))
	}
	units := s7UDSplit(s7TGCPURes, sub, 1, 3, val, 12, 24)

	// 12 octets fit, 12 more do not: reported once, held data released
	// and the last unit dropped with the transfer.
	if u, err := feed(units[0]); u != nil || err != nil {
		t.Fatalf("first unit: %v, %v", u, err)
	}
	if u, err := feed(units[1]); u != nil || !errors.Is(err, ErrS7CommUDTooLong) {
		t.Fatalf("over cap: %v, %v", u, err)
	}
	if a.Pending() != 0 {
		t.Errorf("%d octets held after overflow", a.Pending())
	}
	if u, err := feed(units[2]); u != nil || err != nil {
		t.Errorf("last unit of dropped transfer: %v, %v", u, err)
	}

	// The cap covers all transfers together.
	if _, err := feed(s7UDUnit{s7TGCPURes, sub, 1, 3, 1, val[:12]}); err != nil {
		t.Fatal(err)
	}
	if _, err := feed(s7UDUnit{s7TGCPURes, sub, 2, 4, 1, val[:12]}); !errors.Is(err, ErrS7CommUDTooLong) {
		t.Errorf("second transfer over the shared cap: %v", err)
	}
	if a.Pending() != 12 {
		t.Errorf("%d octets held, want the first transfer's 12", a.Pending())
	}

	// The first transfer still completes, at exactly the cap.
	u, err := feed(s7UDUnit{s7TGCPURes, sub, 1, 3, 0, val[12:20]})
	if err != nil || u == nil || len(u.Data) != 20 || a.Pending() != 0 {
		t.Errorf("transfer at the cap: %+v, %v, %d held", u, err, a.Pending())
	}

	// Default cap.
	a = S7CommUDAssembler{}
	big := make([]byte, 60000)
	err = nil
	fed := 0
	for err == nil && fed < 4*S7CommUDDefaultMaxSize {
		_, err = feed(s7UDUnit{s7TGCPURes, sub, 1, 3, 1, big})
		fed += len(big)
		if a.Pending() > S7CommUDDefaultMaxSize {
			t.Fatalf("%d octets held, above the default cap", a.Pending())
		}
	}
	if !errors.Is(err, ErrS7CommUDTooLong) {
		t.Errorf("default cap: %v after %d octets", err, fed)
	}
}

// TestS7CommUDAssemblerOrder covers input that does not follow one
// transfer from first to last unit.
func TestS7CommUDAssemblerOrder(t *testing.T) {
	sub := byte(S7CommCPUReadSZL)
	val := s7TestSZLValue
	feed := func(a *S7CommUDAssembler, u s7UDUnit) *S7CommUserdata {
		t.Helper()
		v, err := a.Feed(s7Decode(t, u.pdu()))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Two transfers interleaved, told apart by sequence number, with
	// the requests for more in between.
	var a S7CommUDAssembler
	x := s7UDSplit(s7TGCPURes, sub, 1, 3, val, 10)
	y := s7UDSplit(s7TGBlockRes, byte(S7CommBlockListOfType), 2, 4, s7Hex("0001420100024201"), 4)
	more := s7UDUnit{s7TGCPUReq, sub, 1, 0, 0, nil}
	if feed(&a, x[0]) != nil || feed(&a, y[0]) != nil {
		t.Fatal("first units returned a view")
	}
	if v := feed(&a, more); v == nil || v.Fragments != 0 {
		t.Errorf("request for more: %+v", v)
	}
	if v := feed(&a, y[1]); v == nil || len(v.BlockEntries) != 2 || v.BlockEntries[1].Number != 2 {
		t.Errorf("block list: %+v", v)
	}
	if v := feed(&a, x[1]); v == nil || v.SZL == nil || len(v.SZL.ModuleIDs) != 1 {
		t.Errorf("SZL: %+v", v)
	}

	// A request and a response sharing a sequence number are separate.
	a = S7CommUDAssembler{}
	req := s7UDSplit(s7TGCPUReq, sub, 1, 3, []byte("abcdefgh"), 4)
	if feed(&a, x[0]) != nil || feed(&a, req[0]) != nil {
		t.Fatal("first units returned a view")
	}
	if v := feed(&a, req[1]); v == nil || string(v.Data) != "abcdefgh" {
		t.Errorf("request: %+v", v)
	}
	if v := feed(&a, x[1]); v == nil || !bytes.Equal(v.Data, val) {
		t.Errorf("response: %+v", v)
	}

	// The tail of a transfer whose start was not seen comes back alone;
	// it cannot be told from a whole value.
	a = S7CommUDAssembler{}
	if v := feed(&a, x[1]); v == nil || v.Fragments != 1 || !bytes.Equal(v.Data, val[10:]) {
		t.Errorf("lone tail: %+v", v)
	}

	// Another data unit reference, or another service, under the same
	// sequence number abandons the transfer.
	for _, other := range []s7UDUnit{
		{s7TGCPURes, sub, 1, 9, 0, val},
		{s7TGCPURes, byte(S7CommCPUDiagMessage), 1, 3, 0, val},
	} {
		a = S7CommUDAssembler{}
		feed(&a, x[0])
		if v := feed(&a, other); v == nil || v.Fragments != 1 || !bytes.Equal(v.Data, val) || a.Pending() != 0 {
			t.Errorf("after stale transfer: %+v, %d held", v, a.Pending())
		}
	}

	// So does an error response without data, and Reset.
	a = S7CommUDAssembler{}
	feed(&a, x[0])
	failed := s7Decode(t, s7UDUnit{s7TGCPURes, sub, 1, 3, 0, nil}.pdu())
	failed.Userdata.ErrorCode = 0xd401
	if v, err := a.Feed(failed); v != failed.Userdata || err != nil || a.Pending() != 0 {
		t.Errorf("error response: %+v, %v, %d held", v, err, a.Pending())
	}
	feed(&a, x[0])
	a.Reset()
	if a.Pending() != 0 {
		t.Errorf("%d octets held after Reset", a.Pending())
	}
}

// TestS7CommUDAsmUnitHeader checks the octets before each data
// unit of NC programming and PBC transfers stay out of the value, and
// that NC units join although their data unit reference counts up.
func TestS7CommUDAsmUnitHeader(t *testing.T) {
	var a S7CommUDAssembler
	nc := []s7UDUnit{
		{s7TGNCPush, byte(S7CommNCUpload), 5, 1, 1, []byte("\x00\x01first ")},
		{s7TGNCPush, byte(S7CommNCUpload), 5, 2, 1, []byte("\x00\x02second ")},
		{s7TGNCPush, byte(S7CommNCUpload), 5, 3, 0, []byte("\x00\x03third")},
	}
	u := s7UDFeed(t, &a, nc)
	if u == nil || string(u.Data) != "first second third" || u.Fragments != 3 || !bytes.Equal(u.UnitHeader, []byte{0, 3}) {
		t.Errorf("NC upload: %+v", u)
	}

	rid := []byte{0x12, 0x06, 0x13, 0x00, 0xde, 0xad, 0xbe, 0xef}
	pbc := []s7UDUnit{
		{s7TGPBCReq, 1, 1, 1, 1, append(bytes.Clone(rid), "ab"...)},
		{s7TGPBCReq, 1, 1, 1, 0, append(bytes.Clone(rid), "cd"...)},
	}
	u = s7UDFeed(t, &a, pbc)
	if u == nil || string(u.Data) != "abcd" || !bytes.Equal(u.UnitHeader, rid) {
		t.Errorf("BSEND: %+v", u)
	}
}

// TestS7CommUDAssemblerLies joins values whose own counts lie: the view
// stays nil with DecodeErr set, or holds what the data backs.
func TestS7CommUDAssemblerLies(t *testing.T) {
	sub := byte(S7CommCPUReadSZL)

	// Some CPUs send a record count of 0xFFFF in fragmented lists; the
	// records present are decoded, as Wireshark does.
	val := bytes.Clone(s7TestSZLValue)
	binary.BigEndian.PutUint16(val[6:8], 0xffff)
	var a S7CommUDAssembler
	u := s7UDFeed(t, &a, s7UDSplit(s7TGCPURes, sub, 1, 3, val, 9))
	if u == nil || u.DecodeErr != nil || u.SZL == nil || u.SZL.RecordCount != 0xffff || len(u.SZL.Records) != 1 {
		t.Errorf("0xFFFF records: %+v", u)
	}

	// Truncated at every offset the joined value never panics.
	for n := 2; n < len(s7TestSZLValue); n++ {
		u := s7UDFeed(t, &a, s7UDSplit(s7TGCPURes, sub, 1, 3, s7TestSZLValue[:n]))
		if u == nil || u.Fragments != 1 {
			t.Fatalf("%d octets: %+v", n, u)
		}
		if n < s7commSZLRespLen && u.DecodeErr == nil {
			t.Errorf("%d octets: no DecodeErr", n)
		}
	}
}

// s7TCPKey names a TCP connection by its client port.
func s7TCPKey(p gopacket.Packet) TCPPort {
	tcp, _ := p.Layer(LayerTypeTCP).(*TCP)
	if tcp == nil {
		return 0
	}
	if uint16(tcp.DstPort) == TCPPortTPKT {
		return tcp.SrcPort
	}
	return tcp.DstPort
}

// TestS7CommUDAssemblerPcap joins the two fragmented responses of the
// block list capture. tshark 4.7 reassembles frames 14+17 into an SZL
// 0x0000 list of 112 IDs and frames 96+99 into 71 SFC entries.
func TestS7CommUDAssemblerPcap(t *testing.T) {
	asm := map[TCPPort]*S7CommUDAssembler{}
	views := map[int]*S7CommUserdata{}
	held := 0
	for i, p := range s7Packets(t, "s7comm-blocklist.pcap") {
		s, _ := p.Layer(LayerTypeS7Comm).(*S7Comm)
		if s == nil || s.Userdata == nil {
			continue
		}

		key := s7TCPKey(p)
		if asm[key] == nil {
			asm[key] = &S7CommUDAssembler{}
		}
		u, err := asm[key].Feed(s)
		if err != nil {
			t.Fatalf("frame %d: %v", i+1, err)
		}
		if u == nil {
			held++
			continue
		}
		if u.DecodeErr != nil {
			t.Errorf("frame %d: %v", i+1, u.DecodeErr)
		}
		views[i+1] = u
	}

	if held != 2 || views[14] != nil || views[96] != nil {
		t.Errorf("%d PDUs held, frames 14 and 96: %v %v", held, views[14], views[96])
	}
	for _, a := range asm {
		if a.Pending() != 0 {
			t.Errorf("%d octets left pending", a.Pending())
		}
	}

	szl := views[17]
	if szl == nil || szl.Fragments != 2 || szl.SZL == nil || len(szl.SZL.Records) != 112 {
		t.Fatalf("frame 17: %+v", szl)
	}
	ids := szl.SZL.Records
	for i, want := range []uint16{0x0000, 0x0f00, 0x0002} {
		if got := binary.BigEndian.Uint16(ids[i]); got != want {
			t.Errorf("SZL ID %d = %#04x, want %#04x", i, got, want)
		}
	}
	if got := binary.BigEndian.Uint16(ids[111]); got != 0x04b6 {
		t.Errorf("last SZL ID = %#04x, want 0x04b6", got)
	}

	list := views[99]
	if list == nil || list.Fragments != 2 || len(list.BlockEntries) != 71 {
		t.Fatalf("frame 99: %+v", list)
	}
	first, last := list.BlockEntries[0], list.BlockEntries[70]
	if first != (S7CommBlockEntry{0, 0x42, S7CommLangAWL}) || last != (S7CommBlockEntry{127, 0x42, S7CommLangAWL}) {
		t.Errorf("block entries %+v ... %+v", first, last)
	}
}

// FuzzS7CommUDAssembler feeds length-prefixed S7comm PDUs cut from the
// input to an assembler with a small cap.
func FuzzS7CommUDAssembler(f *testing.F) {
	join := func(units ...s7UDUnit) []byte {
		var b []byte
		for _, u := range units {
			pdu := u.pdu()
			b = append(append(b, byte(len(pdu))), pdu...)
		}
		return b
	}
	sub := byte(S7CommCPUReadSZL)
	f.Add(join(s7UDSplit(s7TGCPURes, sub, 1, 3, s7TestSZLValue, 9, 20)...))
	f.Add(join(s7UDSplit(s7TGBlockRes, byte(S7CommBlockListOfType), 2, 4, s7Hex("0001420100024201"), 4)...))
	f.Add(join(s7UDUnit{s7TGNCPush, byte(S7CommNCUpload), 5, 1, 1, []byte("\x00\x01first")},
		s7UDUnit{s7TGCPURes, sub, 5, 1, 0, s7TestSZLValue}))
	f.Add(join(s7UDUnit{s7TGCPURes, sub, 1, 3, 1, bytes.Repeat([]byte{7}, 90)}, s7UDUnit{s7TGCPURes, sub, 1, 3, 0, nil}))

	f.Fuzz(func(t *testing.T, data []byte) {
		const maxSize = 128
		a := S7CommUDAssembler{MaxSize: maxSize}
		for len(data) > 0 {
			n := int(data[0])
			data = data[1:]
			if n > len(data) {
				n = len(data)
			}
			pdu := data[:n]
			data = data[n:]

			var s S7Comm
			if s.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback) != nil {
				continue
			}
			u, err := a.Feed(&s)
			if a.Pending() < 0 || a.Pending() > maxSize {
				t.Fatalf("%d octets held, cap %d", a.Pending(), maxSize)
			}
			if err != nil && u != nil {
				t.Fatalf("error %v with a view", err)
			}
			if u != nil && len(u.Data) > maxSize && u.Fragments > 1 {
				t.Fatalf("joined %d octets, cap %d", len(u.Data), maxSize)
			}
			if u != nil {
				_ = gopacket.LayerString(&S7Comm{Userdata: u})
			}
		}

		a.Reset()
		if a.Pending() != 0 {
			t.Fatal("octets held after Reset")
		}
	})
}
