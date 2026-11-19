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

// bacnetEventHead opens an UnconfirmedEventNotification of the object
// and event type given as hex; the event values follow it.
func bacnetEventHead(object, event string) string {
	return "10 03 09 00 1c 02000001 2c " + object + " 3e 19 07 3f 49 01 59 08 69 " + event + " 89 00 99 01 a9 00 b9 02 "
}

// bacnetTypedVectors are APDUs whose values Clause 21 leaves as ANY, or
// that Addendum 135-2020cp adds. All are built by hand; tshark 4.7
// dissects each one to the same fields and values without a complaint.
var bacnetTypedVectors = []struct {
	name string
	apdu string
	want string
}{
	// The values of a command failure are those of the event object:
	// BACnetBinaryPV for a Binary Output. From bo_command_failure.pcap.
	{"command-failure",
		"10 03 09 00 1c 02000001 2c 01000001 3e 2e a46b080a05 b4141f350c 2f 3f 49 01 59 00 69 03 89 00 99 00 a9 00 b9 02" +
			" ce 3e 0e 91 00 0f 1a 04 80 2e 91 01 2f 3f cf",
		"process-identifier=0 initiating-device-identifier=device,1 event-object-identifier=binary-output,1" +
			" timestamp{date-time{date=2007-08-10 time=20:31:53.12}} notification-class=1 priority=0 event-type=command-failure" +
			" notify-type=alarm ack-required=false from-state=normal to-state=offnormal" +
			" event-values{command-failure{command-value{inactive} status-flags=(in-alarm) feedback-value{active}}}"},
	{"change-of-status-flags, enumerated",
		bacnetEventHead("01000001", "12") + "ce fe 12 0e 91 01 0f 1a 04 80 ff 12 cf",
		"process-identifier=0 initiating-device-identifier=device,1 event-object-identifier=binary-output,1" +
			" timestamp{sequence-number=7} notification-class=1 priority=8 event-type=change-of-status-flags" +
			" notify-type=alarm ack-required=true from-state=normal to-state=offnormal" +
			" event-values{change-of-status-flags{present-value{active} referenced-flags=(in-alarm)}}"},
	{"change-of-status-flags, real",
		bacnetEventHead("00000001", "12") + "ce fe 12 0e 44 41a00000 0f 1a 04 80 ff 12 cf",
		"process-identifier=0 initiating-device-identifier=device,1 event-object-identifier=analog-input,1" +
			" timestamp{sequence-number=7} notification-class=1 priority=8 event-type=change-of-status-flags" +
			" notify-type=alarm ack-required=true from-state=normal to-state=offnormal" +
			" event-values{change-of-status-flags{present-value{20} referenced-flags=(in-alarm)}}"},
	{"access-event with authentication-factor",
		bacnetEventHead("07800001", "0d") + "ce de 09 01 1a 04 00 29 07 3e 19 02 3f 4e 1c 08000001 4f 5e 09 08 19 00 2b 010203 5f df cf",
		"process-identifier=0 initiating-device-identifier=device,1 event-object-identifier=access-door,1" +
			" timestamp{sequence-number=7} notification-class=1 priority=8 event-type=access-event" +
			" notify-type=alarm ack-required=true from-state=normal to-state=offnormal" +
			" event-values{access-event{access-event=granted status-flags=() access-event-tag=7 access-event-time{sequence-number=2}" +
			" access-credential{object-identifier=access-credential,1}" +
			" authentication-factor{format-type=wiegand26 format-class=0 value=010203}}}"},

	{"fault-out-of-range, real",
		"30 01 0c 0c 02400001 1a 0166 3e 6e 0e 44 00000000 0f 1e 44 42c80000 1f 6f 3f",
		"object-identifier=event-enrollment,1 property-identifier=fault-parameters" +
			" property-value{{fault-out-of-range{min-normal-value{real=0} max-normal-value{real=100}}}}"},
	{"fault-out-of-range, unsigned and integer",
		"30 01 0c 0c 02400001 1a 0166 3e 6e 0e 21 05 0f 1e 31 fb 1f 6f 3f",
		"object-identifier=event-enrollment,1 property-identifier=fault-parameters" +
			" property-value{{fault-out-of-range{min-normal-value{unsigned=5} max-normal-value{integer=-5}}}}"},

	{"channel value, lighting-command",
		"00 05 01 0f 0c 0d400001 19 55 3e 0e 09 01 1c 42c80000 4a 03e8 59 08 0f 3f",
		"object-identifier=channel,1 property-identifier=present-value" +
			" property-value{{lighting-command{operation=fade-to target-level=100 fade-time=1000 priority=8}}}"},
	{"channel value, xy-color",
		"00 05 01 0f 0c 0d400001 19 55 3e 1e 44 3e99999a 44 3f000000 1f 3f",
		"object-identifier=channel,1 property-identifier=present-value" +
			" property-value{{xy-color{x-coordinate=0.3 y-coordinate=0.5}}}"},
	{"channel value, color-command to a colour",
		"00 05 01 0f 0c 0d400001 19 55 3e 2e 09 01 1e 44 3e99999a 44 3f000000 1f 3a 03e8 2f 3f",
		"object-identifier=channel,1 property-identifier=present-value" +
			" property-value{{color-command{operation=fade-to-color target-color{x-coordinate=0.3 y-coordinate=0.5} fade-time=1000}}}"},
	{"channel value, color-command ramp",
		"00 05 01 0f 0c 0d400001 19 55 3e 2e 09 03 2a 0a8c 4a 0064 2f 3f",
		"object-identifier=channel,1 property-identifier=present-value" +
			" property-value{{color-command{operation=ramp-to-cct target-color-temperature=2700 ramp-rate=100}}}"},
	{"channel value, color-command step",
		"00 05 01 0f 0c 0d400001 19 55 3e 2e 09 04 5a 0032 2f 3f",
		"object-identifier=channel,1 property-identifier=present-value" +
			" property-value{{color-command{operation=step-up-cct step-increment=50}}}"},

	// The values of an audit notification are those of its target
	// property.
	{"audit notification",
		"10 0c 0e 49 04 bc 01000005 ce 09 55 cf d9 08 ee 91 01 ef fe 0f 91 00 ff 0f 0f",
		"notifications[{operation=life-safety target-object=binary-output,5 target-property{property-identifier=present-value}" +
			" target-priority=8 target-value{active} current-value{inactive}}]"},

	{"AuthRequest",
		"00 05 01 22 0e 09 0a 1e 31 05 31 ff 1f 2e 83 07 e0 80 0e 75 05 00 61 62 63 64 0f 2f 0f",
		`token-request{client=10 audience[5 -1] scope{standard=(view,adjust,control,infrastructure) extended["abcd"]}}`},
	{"AuthRequest without scope",
		"00 05 01 22 0e 09 0a 1e 31 05 1f 0f",
		"token-request{client=10 audience[5]}"},
	{"AuthRequest-ACK",
		"30 01 22 0e 09 63 1e a4 7e0b1405 b4 0c000000 1f 2e 31 05 2f 59 0a 6e 91 01 91 02 6f 7e 82 07 80 7f 89 01 9b aabbcc 0f",
		"token-response{issuer=99 issued{date=2026-11-20 time=12:00:00.00} audience[5] client=10" +
			" constraint{origin=same-network authentication=any-method} scope{standard=(view)} key-id=1 signature=aabbcc}"},
	{"AuthRequest-Error",
		"50 01 22 0e 91 02 91 1a 0f 1c 00 6e 6f 70",
		`error{error-class=property error-code=password-failure} error-details="nop"`},
}

func TestBACnetTypedValues(t *testing.T) {
	lies := []byte{0x00, 0x0E, 0x0F, 0x1E, 0x2F, 0x05, 0xF5, 0xFE, 0xFF}

	for _, tt := range bacnetTypedVectors {
		a := bacnetAPDUOfHex(t, tt.apdu)
		if got := bacnetValuesText(a); got != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", tt.name, got, tt.want)
		}

		// Cut anywhere, or lying in any octet, nothing panics.
		data := mustHex(t, tt.apdu)
		buf := make([]byte, len(data))
		for i := range data {
			bacnetDecodeValues(data[:i:i])
			for _, lie := range lies {
				copy(buf, data)
				buf[i] = lie
				bacnetDecodeValues(buf)
			}
		}
	}

	// A value that does not fit the datatype of the property is still
	// there, untyped: a Real where a BACnetBinaryPV belongs.
	a := bacnetAPDUOfHex(t, bacnetEventHead("01000001", "12")+"ce fe 12 0e 44 41a00000 0f 1a 04 80 ff 12 cf")
	pv := bacnetFindField(a.Values(), "event-values").Field("change-of-status-flags").Field("present-value")
	if pv == nil || pv.Type != BACnetDataTypeAny || len(pv.Fields) != 1 || pv.Fields[0].Value != float32(20) {
		t.Errorf("misfit present-value %v", pv)
	}

	// An alternative of AuthRequest that no revision defines has no
	// typed values; its tags stay.
	a = bacnetAPDUOfHex(t, "00 05 01 22 1e 09 0a 1f")
	if vals := a.Values(); vals != nil || len(a.Tags) != 3 {
		t.Errorf("unknown AuthRequest: %v, %d tags", vals, len(a.Tags))
	}
}

// TestBACnetTypedAllocBound checks that the lists of the new datatypes
// cost no more than the octets that announce them.
func TestBACnetTypedAllocBound(t *testing.T) {
	const (
		maxAllocsPerOctet = 2
		slackAllocs       = 64
		repeats           = 1024
	)
	inputs := [][]byte{
		// An AuthRequest for a great many audiences.
		append(append(mustHex(t, "00 05 01 22 0e 09 0a 1e"), bytes.Repeat([]byte{0x31, 0x05}, repeats)...), 0x1F, 0x0F),
		// A scope with a great many empty extended scopes.
		append(append(mustHex(t, "00 05 01 22 0e 09 0a 1e 1f 2e 82 07 80 0e"), bytes.Repeat([]byte{0x71, 0x00}, repeats)...), 0x0F, 0x2F, 0x0F),
		// A great many audit notifications, each with a value.
		append(append(mustHex(t, "10 0c 0e"), bytes.Repeat(mustHex(t, "bc 01000005 ce 09 55 cf ee 91 01 ef"), repeats)...), 0x0F),
	}

	for i, data := range inputs {
		var a BACnetAPDU
		allocs := testing.AllocsPerRun(4, func() {
			if err := a.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
				_ = a.Values()
			}
		})
		if limit := float64(maxAllocsPerOctet*len(data) + slackAllocs); allocs > limit {
			t.Errorf("input %d: %.0f allocations for %d octets", i, allocs, len(data))
		}
	}
}
