// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/gopacket/gopacket"
)

// cdpPacket wraps one TLV value in a CDP header (version 2, TTL 180).
func cdpPacket(typ CDPTLVType, value []byte) []byte {
	b := []byte{0x02, 0xb4, 0x00, 0x00, 0x00, byte(typ), 0x00, byte(4 + len(value))}
	return append(b, value...)
}

// decodeCDP decodes without panic recovery so a decoder panic fails the test.
func decodeCDP(t *testing.T, data []byte) gopacket.Packet {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decoder panicked on crafted input: %v", r)
		}
	}()
	return gopacket.NewPacket(data, LayerTypeCiscoDiscovery, gopacket.DecodeOptions{SkipDecodeRecovery: true})
}

// TestCDPPowerTLVOddLength: Power Requested / Power Available values are read
// in 4-byte steps. A value whose length is not a multiple of 4 used to slice
// past its end; the partial tail is now ignored and the whole entries kept.
func TestCDPPowerTLVOddLength(t *testing.T) {
	for _, typ := range []CDPTLVType{CDPTLVPowerRequested, CDPTLVPowerAvailable} {
		// id 1, mgmt id 2, one 15400 mW value, one stray byte
		p := decodeCDP(t, cdpPacket(typ, []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x3c, 0x28, 0x00}))
		if p.ErrorLayer() != nil {
			t.Fatalf("%v: unexpected error: %v", typ, p.ErrorLayer().Error())
		}
		info := p.Layer(LayerTypeCiscoDiscoveryInfo).(*CiscoDiscoveryInfo)
		vals := info.PowerRequest.Values
		if typ == CDPTLVPowerAvailable {
			vals = info.PowerAvailable.Values
		}
		if len(vals) != 1 || vals[0] != 15400 {
			t.Errorf("%v: got values %v, want [15400]", typ, vals)
		}
	}
}

// TestCDPIPPrefixLengthOver32: a prefix length net.ParseCIDR refuses used to
// leave a nil *net.IPNet that was dereferenced.
func TestCDPIPPrefixLengthOver32(t *testing.T) {
	p := decodeCDP(t, cdpPacket(CDPTLVIPPrefix, []byte{10, 1, 2, 0, 24}))
	info := p.Layer(LayerTypeCiscoDiscoveryInfo).(*CiscoDiscoveryInfo)
	if p.ErrorLayer() != nil || len(info.IPPrefixes) != 1 || info.IPPrefixes[0].String() != "10.1.2.0/24" {
		t.Fatalf("valid prefix not decoded: %+v", info.IPPrefixes)
	}

	p = decodeCDP(t, cdpPacket(CDPTLVIPPrefix, []byte{10, 1, 2, 0, 33}))
	if p.ErrorLayer() == nil {
		t.Fatal("prefix length 33 decoded without error")
	}
}

// TestCDPAddressEntryLengths: the per-entry protocol and address lengths of an
// Addresses TLV were used as slice bounds without being compared with the
// bytes left in the TLV, and the entry count times 8 could wrap a 32-bit int.
func TestCDPAddressEntryLengths(t *testing.T) {
	cases := []struct {
		name  string
		value []byte
	}{
		{"address-length-overrun", []byte{0, 0, 0, 1, 0x01, 0x01, 0xcc, 0x00, 0x40, 192, 168, 0, 253}},
		{"address-length-fffe", []byte{0, 0, 0, 1, 0x01, 0x01, 0xcc, 0xff, 0xfe, 192, 168, 0, 253}},
		{"address-length-ffff", []byte{0, 0, 0, 1, 0x01, 0x01, 0xcc, 0xff, 0xff, 192, 168, 0, 253}},
		{"protocol-length-overrun", []byte{0, 0, 0, 1, 0x02, 0x08, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00}},
		{"address-length-missing", []byte{0, 0, 0, 1, 0x02, 0x08, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00}},
		{"count-overflow", []byte{0x20, 0, 0, 0}},
	}
	// A TLV behind the addresses gives the slice capacity to run into.
	next := append([]byte{0x00, 0x01, 0x00, 0x50}, make([]byte, 0x4c)...)

	for _, typ := range []CDPTLVType{CDPTLVAddress, CDPTLVMgmtAddresses} {
		for _, c := range cases {
			t.Run(typ.String()+"/"+c.name, func(t *testing.T) {
				last := cdpPacket(typ, c.value)
				for _, data := range [][]byte{last[:len(last):len(last)], append(last, next...)} {
					if p := decodeCDP(t, data); p.ErrorLayer() == nil {
						t.Fatal("crafted input decoded without an error")
					}
				}
			})
		}
	}

	// The well-formed entry still decodes.
	p := decodeCDP(t, cdpPacket(CDPTLVAddress, []byte{0, 0, 0, 1, 0x01, 0x01, 0xcc, 0x00, 0x04, 192, 168, 0, 253}))
	info := p.Layer(LayerTypeCiscoDiscoveryInfo).(*CiscoDiscoveryInfo)
	if p.ErrorLayer() != nil || len(info.Addresses) != 1 || info.Addresses[0].String() != "192.168.0.253" {
		t.Fatalf("valid address not decoded: %v", info.Addresses)
	}
}

// cdpEnergyWise builds a CDP payload holding one EnergyWise TLV: 72 fixed
// bytes, then num sub-TLVs.
func cdpEnergyWise(num int, subTLVs []byte) []byte {
	value := make([]byte, 72, 72+len(subTLVs))
	binary.BigEndian.PutUint16(value[68:], uint16(len(subTLVs)))
	binary.BigEndian.PutUint16(value[70:], uint16(num))
	value = append(value, subTLVs...)

	b := []byte{0x02, 0xb4, 0x00, 0x00, 0x00, byte(CDPTLVEnergyWise), 0x00, 0x00}
	binary.BigEndian.PutUint16(b[6:], uint16(4+len(value)))
	return append(b, value...)
}

// cdpEnergyWiseSubTLV is one sub-TLV: 32-bit type, 32-bit length, value.
func cdpEnergyWiseSubTLV(typ CDPEnergyWiseSubtype, value string) []byte {
	b := make([]byte, 8, 8+len(value))
	binary.BigEndian.PutUint32(b[0:], uint32(typ))
	binary.BigEndian.PutUint32(b[4:], uint32(len(value)))
	return append(b, value...)
}

// TestCDPEnergyWiseSubTLVLength: the Role, Domain and Name sub-TLVs copied
// everything up to the end of the EnergyWise TLV instead of their own value,
// so they swallowed the sub-TLVs behind them and a TLV packed with empty
// sub-TLVs allocated the square of the input.
func TestCDPEnergyWiseSubTLVLength(t *testing.T) {
	var sub []byte
	sub = append(sub, cdpEnergyWiseSubTLV(CDPEnergyWiseRole, "admin")...)
	sub = append(sub, cdpEnergyWiseSubTLV(CDPEnergyWiseDomain, "lab")...)
	sub = append(sub, cdpEnergyWiseSubTLV(CDPEnergyWiseName, "sw1")...)
	p := decodeCDP(t, cdpEnergyWise(3, sub))
	if p.ErrorLayer() != nil {
		t.Fatalf("decode failed: %v", p.ErrorLayer().Error())
	}
	ew := p.Layer(LayerTypeCiscoDiscoveryInfo).(*CiscoDiscoveryInfo).EnergyWise
	if ew.Role != "admin" || ew.Domain != "lab" || ew.Name != "sw1" {
		t.Errorf("got Role %q Domain %q Name %q, want admin, lab, sw1", ew.Role, ew.Domain, ew.Name)
	}

	const num = 8182 // fills the largest CDP TLV
	msg := cdpEnergyWise(num, bytes.Repeat(cdpEnergyWiseSubTLV(CDPEnergyWiseRole, ""), num))

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	p = decodeCDP(t, msg)
	runtime.ReadMemStats(&after)
	if p.ErrorLayer() != nil {
		t.Fatalf("decode failed: %v", p.ErrorLayer().Error())
	}

	grew := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(len(msg)) * 64; grew > limit {
		t.Fatalf("decoding %d bytes allocated %d bytes, limit %d", len(msg), grew, limit)
	}
}
