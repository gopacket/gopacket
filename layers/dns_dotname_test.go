// Copyright 2024 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
)

// dottestWireName builds a wire-format DNS name from the given literal labels,
// root-terminated. A label may itself contain a literal dot (e.g. "foo.bar"),
// which is exactly the DNS-SD/mDNS case the boundary-preservation fix protects.
func dottestWireName(labels ...string) []byte {
	var out []byte
	for _, l := range labels {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0x00)
}

// dottestHeader builds a 12-byte DNS header with QR=1, AA=1 and the given counts.
func dottestHeader(qd, an uint16) []byte {
	return []byte{
		0x12, 0x34, // ID
		0x84, 0x00, // QR=1, AA=1
		byte(qd >> 8), byte(qd),
		byte(an >> 8), byte(an),
		0x00, 0x00, // NSCount
		0x00, 0x00, // ARCount
	}
}

// dottestAnswer builds a DNS response carrying a single answer record with the
// given owner name, type, and raw RDATA. RDLENGTH is derived from rdata.
func dottestAnswer(owner []byte, rtype DNSType, rdata []byte) []byte {
	pkt := dottestHeader(0, 1)
	pkt = append(pkt, owner...)
	pkt = append(pkt, byte(rtype>>8), byte(rtype)) // TYPE
	pkt = append(pkt, 0x00, 0x01)                  // CLASS IN
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x3c)      // TTL 60
	pkt = append(pkt, byte(len(rdata)>>8), byte(len(rdata)))
	return append(pkt, rdata...)
}

// TestDNSDottedLabelRoundTrip checks that a name whose single wire label
// contains a literal dot (e.g. the DNS-SD instance label "foo.bar") survives a
// decode -> serialize round trip byte-for-byte, for every DNS name field the
// layer decodes: the question name, the record owner name, and each name-bearing
// RDATA field including the fork-only NAPTR/SVCB/HTTPS/RRSIG names.
func TestDNSDottedLabelRoundTrip(t *testing.T) {
	dotted := dottestWireName("foo.bar") // a single label that contains a dot
	owner := dottestWireName("x")        // an ordinary single-dotless-label owner

	mkQuestion := func() []byte {
		p := dottestHeader(1, 0)
		p = append(p, dotted...)
		return append(p, byte(DNSTypeA>>8), byte(DNSTypeA), 0x00, 0x01)
	}

	soa := func() []byte {
		rdata := append([]byte{}, dottestWireName("m.x")...) // MName
		rdata = append(rdata, dottestWireName("r.y")...)     // RName
		return append(rdata, make([]byte, 20)...)            // serial..minimum
	}

	rrsig := func() []byte {
		rdata := make([]byte, 18) // fixed RRSIG fields
		rdata = append(rdata, dottestWireName("a.b")...)
		return append(rdata, 0xde, 0xad, 0xbe, 0xef) // signature
	}

	tests := []struct {
		name string
		pkt  []byte
	}{
		{"question name", mkQuestion()},
		{"owner name", dottestAnswer(dotted, DNSTypeA, []byte{192, 0, 2, 1})},
		{"NS rdata", dottestAnswer(owner, DNSTypeNS, dotted)},
		{"CNAME rdata", dottestAnswer(owner, DNSTypeCNAME, dotted)},
		{"PTR rdata", dottestAnswer(owner, DNSTypePTR, dotted)},
		{"MX rdata", dottestAnswer(owner, DNSTypeMX, append([]byte{0x00, 0x0a}, dotted...))},
		{"SRV rdata", dottestAnswer(owner, DNSTypeSRV, append([]byte{0x00, 0x0a, 0x00, 0x14, 0x1f, 0x90}, dotted...))},
		{"SOA rdata", dottestAnswer(owner, DNSTypeSOA, soa())},
		{"NAPTR replacement", dottestAnswer(owner, DNSTypeNAPTR, append([]byte{0x00, 0x0a, 0x00, 0x14, 0x00, 0x00, 0x00}, dotted...))},
		{"SVCB target", dottestAnswer(owner, DNSTypeSVCB, append([]byte{0x00, 0x01}, dotted...))},
		{"HTTPS target", dottestAnswer(owner, DNSTypeHTTPS, append([]byte{0x00, 0x01}, dotted...))},
		{"RRSIG signer name", dottestAnswer(owner, DNSTypeRRSIG, rrsig())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dns DNS
			if err := dns.DecodeFromBytes(tt.pkt, gopacket.NilDecodeFeedback); err != nil {
				t.Fatalf("decode: %v", err)
			}
			buf := gopacket.NewSerializeBuffer()
			if err := dns.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
				t.Fatalf("serialize: %v", err)
			}
			if !bytes.Equal(buf.Bytes(), tt.pkt) {
				t.Errorf("round-trip corrupted the name:\n got  %x\n want %x", buf.Bytes(), tt.pkt)
			}
		})
	}
}

// TestDNSEncodePresentationName checks that a newly-constructed (not decoded)
// name is parsed as presentation form: '.' separates labels, and \., \\, \DDD
// escape a literal byte into a single label.
func TestDNSEncodePresentationName(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  []byte // expected wire-format name
	}{
		{"plain dot separates labels", []byte("foo.bar"), dottestWireName("foo", "bar")},
		{"escaped dot is label data", []byte(`foo\.bar`), dottestWireName("foo.bar")},
		{"escaped backslash", []byte(`a\\b`), dottestWireName(`a\b`)},
		{"decimal escape", []byte(`a\046b`), dottestWireName("a.b")}, // \046 == '.'
		{"root", []byte("."), []byte{0x00}},
		{"empty", []byte(""), []byte{0x00}},
		{"trailing dot is root terminator", []byte("foo."), dottestWireName("foo")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := &DNS{Questions: []DNSQuestion{{Name: tt.input, Type: DNSTypeA, Class: DNSClassIN}}}
			buf := gopacket.NewSerializeBuffer()
			if err := dns.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
				t.Fatalf("serialize: %v", err)
			}
			got := buf.Bytes()[12:] // strip header
			want := append(append([]byte{}, tt.want...), 0x00, 0x01, 0x00, 0x01)
			if !bytes.Equal(got, want) {
				t.Errorf("name encode:\n got  %x\n want %x", got, want)
			}
		})
	}
}

// TestDNSEncodeNameErrors checks that an invalid presentation name makes
// SerializeTo return an error rather than emit a malformed packet or panic.
func TestDNSEncodeNameErrors(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"label longer than 63", bytes.Repeat([]byte("a"), 64)},
		{"trailing backslash", []byte(`foo\`)},
		{"truncated decimal escape", []byte(`foo\05`)},
		{"decimal escape over 255", []byte(`foo\256`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns := &DNS{Questions: []DNSQuestion{{Name: tt.input, Type: DNSTypeA, Class: DNSClassIN}}}
			buf := gopacket.NewSerializeBuffer()
			if err := dns.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err == nil {
				t.Errorf("expected error for name %q, got nil", tt.input)
			}
		})
	}
}

// TestDNSDecodeMutateEncode checks that once a caller changes a decoded name,
// the preserved boundaries are dropped and the new value is encoded as
// presentation form (so a literal dot in the new value splits labels).
func TestDNSDecodeMutateEncode(t *testing.T) {
	pkt := dottestAnswer(dottestWireName("x"), DNSTypeCNAME, dottestWireName("foo.bar"))

	var dns DNS
	if err := dns.DecodeFromBytes(pkt, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := string(dns.Answers[0].CNAME); got != "foo.bar" {
		t.Fatalf("decoded CNAME = %q, want foo.bar", got)
	}

	// Change the name. The decoded label boundaries must no longer be used.
	dns.Answers[0].CNAME = []byte("baz.qux")
	buf := gopacket.NewSerializeBuffer()
	if err := dns.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatalf("serialize: %v", err)
	}

	if !bytes.Contains(buf.Bytes(), dottestWireName("baz", "qux")) {
		t.Errorf("mutated name not re-encoded as two labels:\n %x", buf.Bytes())
	}
	if bytes.Contains(buf.Bytes(), []byte{0x07, 'b', 'a', 'z', '.', 'q', 'u', 'x'}) {
		t.Errorf("mutated name wrongly kept as a single preserved label:\n %x", buf.Bytes())
	}
}

// FuzzDecodeSerializeDNS fuzzes the decode -> serialize round trip: any input
// that decodes without error must re-serialize without panicking. This guards
// the name encoder's buffer sizing, which sizes the output with one routine and
// writes it with another, against ever disagreeing.
func FuzzDecodeSerializeDNS(f *testing.F) {
	f.Add(testPacketDNSNilRdata)
	f.Fuzz(func(t *testing.T, data []byte) {
		var dns DNS
		if err := dns.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			return
		}
		buf := gopacket.NewSerializeBuffer()
		_ = dns.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true})
	})
}
