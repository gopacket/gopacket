// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
)

// A Siemens ConfirmedPrivateTransfer and its ACK, frames 3145 and 2628 of
// "Tower333 lighting 5min IP.pcap" (kargs.net): the vendor block between
// the [2] brackets is not tag encoded.
const (
	bacnetSiemensBlock = "00000056000000360008282d0043494d45545249435320444e45543500373130320043494d45545249435320444e4554350037303100" +
		"026301000441444d4e233fffffff00000100024a310100000000010000010000"
	bacnetSiemensRequest  = "02055812" + "0907" + "1a01ff" + "2e" + bacnetSiemensBlock + "2f"
	bacnetSiemensAckBlock = "00000030000000300005417e01544f57455233333320424c4e003730303100544f57455233333320424c4e0037303100"
	bacnetSiemensAck      = "308612" + "0907" + "1a01ff" + "2e" + bacnetSiemensAckBlock + "2f"
)

// TestBACnetChannelValueTags checks the context tags of the constructed
// alternatives of BACnetChannelValue: xy-color is [1], color-command [2].
func TestBACnetChannelValueTags(t *testing.T) {
	for want, value := range map[string]string{
		"lighting-command": "0e 09 01 0f",
		"xy-color":         "1e 44 3e99999a 44 3f000000 1f",
		"color-command":    "2e 09 01 2f",
	} {
		a := bacnetAPDUOfHex(t, "00 05 01 0f 0c 0d400001 19 55 3e "+value+" 3f")
		pv := bacnetFindField(a.Values(), "property-value")
		if pv == nil || len(pv.Fields) != 1 || len(pv.Fields[0].Fields) != 1 || pv.Fields[0].Fields[0].Name != want {
			t.Errorf("%s: %v", want, pv)
		}
	}
}

// TestBACnetStringEnd checks that a character string keeps the NUL or
// line feed a device ends it with: BACnet strings have no terminator.
func TestBACnetStringEnd(t *testing.T) {
	// Object names of bip-readprop.cap and "TAO2 TES.39A.cap".
	for want, tag := range map[string]string{
		"Critical Room Controller\\x00": "751a 00 437269746963616c20526f6f6d20436f6e74726f6c6c6572 00",
		"TIME DELAY 1\\n":               "750e 00 54494d452044454c41592031 0a",
	} {
		a := bacnetAPDUOfHex(t, "30 01 0c 0c 02000001 19 4d 3e "+tag+" 3f")
		if got := bacnetValuesText(a); got != "object-identifier=device,1 property-identifier=object-name property-value{\""+want+"\"}" {
			t.Errorf("%s", got)
		}
	}
}

// TestBACnetPrivateTransferRaw checks that a private transfer whose
// parameters are not tag encoded still decodes: the vendor and service
// number typed, the block raw.
func TestBACnetPrivateTransferRaw(t *testing.T) {
	block := "0001ff0e"
	tests := []struct {
		name, apdu, want, raw string
	}{
		{"confirmed request, capture", bacnetSiemensRequest,
			"vendor-id=7 service-number=511 service-parameters=" + bacnetSiemensBlock, bacnetSiemensBlock},
		{"complex ack, capture", bacnetSiemensAck,
			"vendor-id=7 service-number=511 result-block=" + bacnetSiemensAckBlock, bacnetSiemensAckBlock},
		{"unconfirmed request", "1004" + "0907" + "1903" + "2e" + block + "2f",
			"vendor-id=7 service-number=3 service-parameters=" + block, block},
		{"error", "500112" + "0e" + "9105" + "9100" + "0f" + "1907" + "2903" + "3e" + block + "3f",
			"error-type{error-class=services error-code=other} vendor-id=7 service-number=3 error-parameters=" + block, block},
		{"empty block of one stray octet", "1004" + "0907" + "1903" + "2e" + "ff" + "2f",
			"vendor-id=7 service-number=3 service-parameters=ff", "ff"},
	}
	for _, tt := range tests {
		a := &BACnetAPDU{}
		if err := a.DecodeFromBytes(mustHex(t, tt.apdu), gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if got := bacnetValuesText(a); got != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", tt.name, got, tt.want)
		}

		p, ok := a.ServiceData.(*BACnetParameters)
		if !ok {
			t.Errorf("%s: ServiceData is %T", tt.name, a.ServiceData)
			continue
		}
		last := p.Fields[len(p.Fields)-1]
		raw, _ := last.Value.([]byte)
		if !bytes.Equal(raw, mustHex(t, tt.raw)) || last.Type != BACnetDataTypeAny || last.Fields != nil {
			t.Errorf("%s: block %x type %v fields %v", tt.name, raw, last.Type, last.Fields)
		}
		bacnetTouchValues(a.Values())
	}

	// A well tagged block is still read as tags.
	a := bacnetAPDUOfHex(t, "1004"+"0907"+"1903"+"2e"+"2105"+"2f")
	if got, want := bacnetValuesText(a), "vendor-id=7 service-number=3 service-parameters{5}"; got != want {
		t.Errorf("tagged block: got %s want %s", got, want)
	}

	// What is not a private transfer, or has no block to fall back on, is
	// still malformed.
	bad := []string{
		"1008" + "0907" + "1903" + "2e" + block + "2f",                                   // Who-Is
		"1004" + "0907" + "1903" + "2e" + block,                                          // no closing tag
		"1004" + "0907" + "1903" + block + "2f",                                          // no opening tag
		"1004" + "2e" + "1f" + block + "2f",                                              // prefix itself malformed
		"500112" + "0e" + "9105" + "9100" + "0f" + "1907" + "2903" + "2e" + block + "2f", // wrong bracket for an Error
		"3086" + "0c" + "0907" + "1903" + "2e" + block + "2f",                            // ReadProperty-ACK
	}
	for _, s := range bad {
		a := &BACnetAPDU{}
		if err := a.DecodeFromBytes(mustHex(t, s), gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("%s decoded: %s", s, bacnetValuesText(a))
		}
	}
}
