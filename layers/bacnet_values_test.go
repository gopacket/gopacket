// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// bacnetValuesText renders the parameters of an APDU on one line.
func bacnetValuesText(a *BACnetAPDU) string {
	vals := a.Values()
	parts := make([]string, len(vals))
	for i := range vals {
		parts[i] = vals[i].String()
	}
	return strings.Join(parts, " ")
}

// bacnetAPDUOfHex decodes an APDU given as hex.
func bacnetAPDUOfHex(t testing.TB, s string) *BACnetAPDU {
	t.Helper()
	a := &BACnetAPDU{}
	if err := a.DecodeFromBytes(mustHex(t, s), gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return a
}

// bacnetVectorAPDUs returns the APDU octets of the hand-built vectors.
func bacnetVectorAPDUs(t testing.TB) [][]byte {
	t.Helper()
	var out [][]byte
	for _, frame := range bacnetFrames(t, "bacnet-values.pcap") {
		p := gopacket.NewPacket(frame, LayerTypeBVLC, gopacket.Default)
		a, ok := p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU)
		if !ok {
			t.Fatalf("frame %d has no APDU: %v", len(out)+1, p.ErrorLayer())
		}
		out = append(out, append(append([]byte(nil), a.Contents...), a.Parameters...))
	}
	return out
}

// TestBACnetValueVectors decodes every hand-built frame and compares the
// typed parameters with the rendering recorded for it.
func TestBACnetValueVectors(t *testing.T) {
	apdus := bacnetVectorAPDUs(t)
	if len(apdus) != len(bacnetValueVectors) {
		t.Fatalf("%d frames, %d vectors", len(apdus), len(bacnetValueVectors))
	}

	for i, data := range apdus {
		vec := bacnetValueVectors[i]
		var a BACnetAPDU
		if err := a.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", vec.name, err)
			continue
		}
		if a.ServiceData == nil {
			t.Errorf("%s: no ServiceData", vec.name)
		}
		if got := bacnetValuesText(&a); got != vec.want {
			t.Errorf("%s:\n got %s\nwant %s", vec.name, got, vec.want)
		}
	}
}

// TestBACnetValuesInline holds the vectors tshark cannot check: it
// dissects RequestKey, a You-Are without its optional parameters, the
// expected invoke ID of Authenticate and the expiration time of a
// change-of-timer notification wrongly or not at all. They follow the
// productions of ASHRAE 135-1995 (the first two services left the
// standard in 2010) and 135-2020.
func TestBACnetValuesInline(t *testing.T) {
	tests := []struct{ name, apdu, want string }{
		{"RequestKey",
			"00 05 01 19 c4 02 00 00 01 21 01 61 11 c4 02 00 00 02 21 02 61 22",
			"requesting-device-identifier=device,1 requesting-device-address{network-number=1 mac-address=11} " +
				"remote-device-identifier=device,2 remote-device-address{network-number=2 mac-address=22}"},
		{"You-Are without address",
			"10 0e 22 01 04 75 08 00 4d 6f 64 65 6c 20 58 75 08 00 53 4e 2d 30 30 30 31",
			`vendor-id=260 model-name="Model X" serial-number="SN-0001"`},
		{"Authenticate with expected invoke ID",
			"00 05 01 18 0c 12 34 56 78 19 02",
			"pseudo-random-number=305419896 expected-invoke-id=2"},
		{"change-of-timer with expiration time",
			"10 03 09 01 1c 02 00 00 09 2c 07 c0 00 01 3e 19 13 3f 49 05 59 01 69 16 89 01 b9 00 ce fe 16 09 01 1a 04 00 " +
				"2e a4 7c 01 1f 03 b4 0a 00 00 00 2f 5e a4 7c 01 1f 03 b4 0c 00 00 00 5f ff 16 cf",
			"process-identifier=1 initiating-device-identifier=device,9 event-object-identifier=timer,1 " +
				"timestamp{sequence-number=19} notification-class=5 priority=1 event-type=change-of-timer notify-type=event " +
				"to-state=normal event-values{change-of-timer{new-state=running status-flags=() " +
				"update-time{date=2024-01-31 time=10:00:00.00} expiration-time{date=2024-01-31 time=12:00:00.00}}}"},
		{"fault-parameters fault-state",
			"30 01 0c 0c 02 40 00 01 1a 01 66 3e 4e 0e 19 01 79 04 0f 4f 3f",
			"object-identifier=event-enrollment,1 property-identifier=fault-parameters " +
				"property-value{{fault-state{list-of-fault-values[{binary-value=active} {reliability=open-loop}]}}}"},
		// A value that does not fit the datatype of its property is kept
		// as the tags say.
		{"weekly-schedule that is none",
			"30 01 0c 0c 04 40 00 01 19 7b 3e 21 01 74 00 6f 64 64 3f",
			`object-identifier=schedule,1 property-identifier=weekly-schedule property-value{1 "odd"}`},
		{"Who-Is",
			"10 08 09 0a 19 14",
			"device-instance-range-low-limit=10 device-instance-range-high-limit=20"},
		{"I-Am",
			"10 00 c4 02 00 00 7b 22 05 c4 91 03 21 2a",
			"i-am-device-identifier=device,123 max-apdu-length-accepted=1476 segmentation-supported=no-segmentation vendor-id=42"},
	}

	for _, test := range tests {
		a := bacnetAPDUOfHex(t, test.apdu)
		if got := bacnetValuesText(a); got != test.want {
			t.Errorf("%s:\n got %s\nwant %s", test.name, got, test.want)
		}
	}
}

// TestBACnetValueAPI walks a decoded tree the way a caller does.
func TestBACnetValueAPI(t *testing.T) {
	// ConfirmedEventNotification, out-of-range: the second vector frame
	// of the confirmed requests.
	var a *BACnetAPDU
	for i, vec := range bacnetValueVectors {
		if vec.name == "ConfirmedEventNotification out-of-range" {
			a = &BACnetAPDU{}
			if err := a.DecodeFromBytes(bacnetVectorAPDUs(t)[i], gopacket.NilDecodeFeedback); err != nil {
				t.Fatal(err)
			}
		}
	}
	if a == nil {
		t.Fatal("vector missing")
	}

	p, ok := a.ServiceData.(*BACnetParameters)
	if !ok {
		t.Fatalf("ServiceData %T", a.ServiceData)
	}
	if got := p.Field("event-type").Value; got != (BACnetEnumerated{Type: BACnetDataTypeEventType, Value: 5}) {
		t.Errorf("event-type %#v", got)
	}
	if got := p.Field("message-text").Value; got != "High" {
		t.Errorf("message-text %#v", got)
	}
	if p.Field("no-such-field") != nil {
		t.Error("found a field that is not there")
	}

	limit := p.Field("event-values").Field("out-of-range").Field("exceeded-limit")
	if limit == nil || limit.Value != float32(90) || limit.Type != BACnetDataTypeReal {
		t.Errorf("exceeded-limit %+v", limit)
	}
	flags := p.Field("event-values").Field("out-of-range").Field("status-flags")
	if b, ok := flags.Value.(BACnetBitString); !ok || !b.Bit(0) || b.Bit(1) || flags.Type != BACnetDataTypeStatusFlags {
		t.Errorf("status-flags %+v", flags)
	}
	if len(limit.Tags) != 1 || !limit.Tags[0].IsContext(3) {
		t.Errorf("exceeded-limit tags %+v", limit.Tags)
	}

	// The property value of a legacy ServiceData, typed on request.
	ack := bacnetAPDUOfHex(t, "30 01 0c 0c 04 40 00 01 19 20 3e a4 7c 01 01 01 a4 7c 0c 1f 02 3f").ServiceData.(*BACnetReadPropertyAck)
	vals := DecodeBACnetProperty(ack.Object.Type, ack.Property, ack.ArrayIndex, ack.Value)
	if len(vals) != 1 || vals[0].Type != BACnetDataTypeDateRange {
		t.Fatalf("effective-period %+v", vals)
	}
	if got := vals[0].Field("end-date").Value; got != (BACnetDate{Year: 2024, Month: 12, Day: 31, Weekday: 2}) {
		t.Errorf("end-date %#v", got)
	}

	// An unknown property comes back as its tags say.
	vals = DecodeBACnetProperty(BACnetObjectTypeDevice, 9999, BACnetNoArrayIndex, ack.Value)
	if len(vals) != 2 || vals[0].Type != BACnetDataTypeDate || vals[0].Name != "" {
		t.Errorf("untyped %+v", vals)
	}
	if vals := DecodeBACnetProperty(BACnetObjectTypeDevice, BACnetPropertyUnits, BACnetNoArrayIndex, nil); len(vals) != 0 {
		t.Errorf("no tags gave %+v", vals)
	}

	names := []struct{ got, want string }{
		{BACnetEnumerated{Type: BACnetDataTypeEngineeringUnits, Value: 62}.String(), "degrees-celsius"},
		{BACnetEnumerated{Type: BACnetDataTypeEnumerated, Value: 7}.String(), "7"},
		{BACnetDataTypeEngineeringUnits.EnumName(95), "no-units"},
		{BACnetDataTypeEventState.EnumName(1), "fault"},
		{BACnetDataTypeReliability.EnumName(1), "no-sensor"},
		{BACnetDataTypeDeviceStatus.EnumName(0), "operational"},
		{BACnetDataTypeSegmentation.EnumName(0), "segmented-both"},
		{BACnetDataTypePolarity.EnumName(0), "normal"},
		{BACnetDataTypeBinaryPV.EnumName(0), "inactive"},
		{BACnetDataTypeNotifyType.EnumName(2), "ack-notification"},
		{BACnetDataTypeObjectType.EnumName(8), "device"},
		{BACnetDataTypePropertyIdentifier.EnumName(85), "present-value"},
		{BACnetDataTypeErrorClass.EnumName(2), "property"},
		{BACnetDataTypeErrorCode.EnumName(32), "unknown-property"},
		{BACnetDataTypeEventState.EnumName(4000), "Unknown(4000)"},
		{BACnetDataTypeStatusFlags.BitName(0), "in-alarm"},
		{BACnetDataTypeStatusFlags.BitName(3), "out-of-service"},
		{BACnetDataTypeStatusFlags.BitName(9), "bit9"},
		{BACnetDataTypeStatusFlags.BitName(-1), "bit-1"},
		{BACnetDataTypeEventTransitionBits.BitName(2), "to-normal"},
		{BACnetDataTypeLimitEnable.BitName(1), "high-limit-enable"},
		{BACnetDataTypeServicesSupported.BitName(12), "read-property"},
		{BACnetDataTypeObjectTypesSupported.BitName(8), "device"},
		{BACnetDataTypeReal.BitName(0), "bit0"},
		{BACnetDataTypeDateTime.String(), "BACnetDateTime"},
		{BACnetDataTypeEngineeringUnits.String(), "BACnetEngineeringUnits"},
		{BACnetDataTypeAny.String(), "ANY"},
		{BACnetDataType(60000).String(), "ANY"},
		{BACnetBitString{Unused: 5, Bytes: []byte{0xA0}}.String(), "101"},
		{BACnetWeekNDay{Month: 255, WeekOfMonth: 6, DayOfWeek: 1}.String(), "*/06/01"},
	}
	for _, n := range names {
		if n.got != n.want {
			t.Errorf("name %q, want %q", n.got, n.want)
		}
	}
}

// bacnetTouchValues reads everything a caller could from a value tree.
func bacnetTouchValues(vals []BACnetValue) {
	for i := range vals {
		v := &vals[i]
		_ = v.String()
		_ = v.Type.String()
		_ = v.Field("value")
		_ = fmt.Sprint(v.Value)
		_ = v.Type.EnumName(uint32(len(v.Tags)))
		_ = v.Type.BitName(len(v.Fields))
		bacnetTouchValues(v.Fields)
	}
}

// bacnetDecodeValues decodes an APDU and reads its whole value tree.
func bacnetDecodeValues(data []byte) {
	var a BACnetAPDU
	if err := a.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return
	}
	bacnetTouchValues(a.Values())
	if p, ok := a.ServiceData.(*BACnetParameters); ok {
		_ = p.Field("object-identifier")
	}
}

// TestBACnetValuesTruncation cuts every vector at every offset, and lies
// in every octet about tags and lengths. Nothing may panic.
func TestBACnetValuesTruncation(t *testing.T) {
	// Octets that turn into the tags and lengths that hurt most: opening
	// and closing brackets, extended lengths, extended tag numbers.
	lies := []byte{0x00, 0x0E, 0x0F, 0x1E, 0x1F, 0x05, 0x0D, 0xF5, 0xFD, 0xFE, 0xFF}

	for _, data := range bacnetVectorAPDUs(t) {
		for i := 0; i < len(data); i++ {
			bacnetDecodeValues(data[:i:i])
		}

		buf := make([]byte, len(data))
		for i := range data {
			for _, lie := range lies {
				copy(buf, data)
				buf[i] = lie
				bacnetDecodeValues(buf)
			}
		}
	}
}

// bacnetNested returns a ReadProperty-ACK of a proprietary property whose
// value is depth brackets around one Null.
func bacnetNested(depth int) []byte {
	data := []byte{0x30, 0x01, 0x0C, 0x0C, 0x02, 0x00, 0x00, 0x01, 0x1A, 0x02, 0x58, 0x3E}
	data = append(data, bytes.Repeat([]byte{0x0E}, depth)...)
	data = append(data, 0x00)
	data = append(data, bytes.Repeat([]byte{0x0F}, depth)...)
	return append(data, 0x3F)
}

// TestBACnetValuesNesting checks the nesting cap: the deepest value the
// tag decoder lets through is decoded, one level more is an error.
func TestBACnetValuesNesting(t *testing.T) {
	// The property-value bracket is one level itself.
	deepest := bacnetNested(bacnetMaxTagDepth - 1)
	var a BACnetAPDU
	if err := a.DecodeFromBytes(deepest, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	vals := a.Values()
	if vals == nil {
		t.Fatal("deepest value not decoded")
	}

	depth := 0
	for v := &vals[len(vals)-1]; len(v.Fields) > 0; v = &v.Fields[0] {
		depth++
	}
	if depth != bacnetMaxTagDepth {
		t.Errorf("depth %d", depth)
	}
	bacnetTouchValues(vals)

	if err := a.DecodeFromBytes(bacnetNested(bacnetMaxTagDepth), gopacket.NilDecodeFeedback); err == nil {
		t.Error("nesting past the cap decoded")
	}

	// A typed value cannot be driven past the cap either: exception
	// schedules of calendar entries of date ranges, as deep as tags go.
	typed := []byte{0x30, 0x01, 0x0C, 0x0C, 0x04, 0x40, 0x00, 0x01, 0x19, 0x26, 0x3E}
	typed = append(typed, bytes.Repeat([]byte{0x0E, 0x1E}, bacnetMaxTagDepth)...)
	bacnetDecodeValues(typed)
}

// TestBACnetValuesAllocBound checks that decoding costs memory in
// proportion to the input: no input makes the decoder allocate more than
// a fixed number of objects and octets per octet it was given.
func TestBACnetValuesAllocBound(t *testing.T) {
	const (
		// A one-octet tag costs its BACnetTag, and up to a few
		// BACnetValue when CHOICE and SEQUENCE wrap it.
		maxAllocsPerOctet = 2
		maxBytesPerOctet  = 1024
		// Fixed cost of an APDU: its ServiceData and top-level lists.
		slackAllocs = 64
		slackBytes  = 8192
		repeats     = 512
	)
	header := []byte{0x30, 0x01, 0x0C, 0x0C, 0x04, 0x40, 0x00, 0x01, 0x19, 0x26, 0x3E}
	wrap := func(body []byte) []byte {
		return append(append(append([]byte(nil), header...), body...), 0x3F)
	}

	inputs := bacnetVectorAPDUs(t)
	inputs = append(inputs,
		// Nulls: the most values per octet.
		wrap(bytes.Repeat([]byte{0x00}, 4*repeats)),
		// Empty brackets: the most constructed values per octet.
		wrap(bytes.Repeat([]byte{0x0E, 0x0F}, 2*repeats)),
		// Special events with empty time value lists.
		wrap(bytes.Repeat([]byte{0x0E, 0x0C, 0x7C, 0x01, 0x01, 0x01, 0x0F, 0x2E, 0x2F, 0x39, 0x01}, repeats)),
		// Brackets as deep as they go, over and over.
		wrap(bytes.Repeat(bacnetNested(bacnetMaxTagDepth - 2)[11:], repeats/8)),
		// A typed value that fails at its last tag and is read again untyped.
		wrap(append(bytes.Repeat([]byte{0x0E, 0x0C, 0x7C, 0x01, 0x01, 0x01, 0x0F, 0x2E, 0x2F, 0x39, 0x01}, repeats), 0x00)),
	)

	for i, data := range inputs {
		decode := func() {
			var a BACnetAPDU
			if err := a.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil {
				_ = a.Values()
			}
		}

		allocs := testing.AllocsPerRun(4, decode)
		if limit := float64(maxAllocsPerOctet*len(data) + slackAllocs); allocs > limit {
			t.Errorf("input %d: %.0f allocations for %d octets", i, allocs, len(data))
		}

		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		decode()
		runtime.ReadMemStats(&after)
		if used := after.TotalAlloc - before.TotalAlloc; used > uint64(maxBytesPerOctet*len(data)+slackBytes) {
			t.Errorf("input %d: %d octets allocated for %d octets", i, used, len(data))
		}
	}
}

// FuzzBACnetValues fuzzes the typed decoding of property values, with the
// object type, property and array index that pick the datatype, and of
// whole APDUs.
func FuzzBACnetValues(f *testing.F) {
	for _, data := range bacnetVectorAPDUs(f) {
		f.Add(uint16(BACnetObjectTypeSchedule), uint32(BACnetPropertyExceptionSchedule), BACnetNoArrayIndex, data)

		// The property value alone, under the property that types it.
		var a BACnetAPDU
		if err := a.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			continue
		}
		ack, ok := a.ServiceData.(*BACnetReadPropertyAck)
		if !ok {
			continue
		}
		// The value sits between the opening tag 3, past the object
		// identifier, and the closing tag that ends the APDU.
		open := bytes.IndexByte(data[bacnetSeedValueFrom:], 0x3E)
		if open < 0 {
			continue
		}
		f.Add(uint16(ack.Object.Type), uint32(ack.Property), ack.ArrayIndex, data[bacnetSeedValueFrom+open+1:len(data)-1])
	}

	f.Fuzz(func(t *testing.T, object uint16, property uint32, index uint32, data []byte) {
		bacnetDecodeValues(data)

		tags, err := decodeBACnetTags(data)
		if err != nil {
			return
		}
		vals := DecodeBACnetProperty(BACnetObjectType(object), BACnetPropertyIdentifier(property), index, tags)
		bacnetTouchValues(vals)

		// Every tag is accounted for exactly once at the top level.
		n := 0
		for i := range vals {
			n += len(vals[i].Tags)
		}
		if n != len(tags) {
			t.Fatalf("%d tags in, %d tags in values", len(tags), n)
		}
	})
}

// bacnetSeedValueFrom is where the property identifier of a
// ReadProperty-ACK starts: after the APDU header and object identifier.
const bacnetSeedValueFrom = 8

// bacnetSegment cuts an unsegmented ComplexACK or Confirmed-Request into
// segments of at most size data octets.
func bacnetSegment(whole []byte, size int) [][]byte {
	// The service choice is the last header octet of both PDU types.
	hdr := 3
	if BACnetPDUType(whole[0]>>bacnetPDUTypeShift) == BACnetPDUConfirmedRequest {
		hdr = 4
	}
	data := whole[hdr:]

	var out [][]byte
	for seq := 0; len(data) > 0; seq++ {
		n := size
		if n > len(data) {
			n = len(data)
		}
		first := whole[0] | bacnetPDUFlagSEG
		if n < len(data) {
			first |= bacnetPDUFlagMOR
		}

		seg := []byte{first}
		seg = append(seg, whole[1:hdr-1]...)
		seg = append(seg, byte(seq), 4, whole[hdr-1])
		out = append(out, append(seg, data[:n]...))
		data = data[n:]
	}
	return out
}

// bacnetLongACK returns a ReadProperty-ACK of n address bindings.
func bacnetLongACK(invokeID uint8, n int) []byte {
	data := []byte{0x30, invokeID, 0x0C, 0x0C, 0x02, 0x00, 0x00, 0x01, 0x19, 0x1E, 0x3E}
	for i := 0; i < n; i++ {
		data = append(data, 0xC4, 0x02, 0x00, byte(i>>8), byte(i), 0x21, byte(i), 0x65, 0x06, 10, 0, byte(i>>8), byte(i), 0xBA, 0xC0)
	}
	return append(data, 0x3F)
}

// bacnetAddSegments feeds segments to the assembler in the given order
// and returns the APDU the last one completed.
func bacnetAddSegments(t *testing.T, asm *BACnetSegmentAssembler, source string, segs [][]byte, order []int) *BACnetAPDU {
	t.Helper()
	var whole *BACnetAPDU

	for n, i := range order {
		var a BACnetAPDU
		if err := a.DecodeFromBytes(segs[i], gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		if !a.Segmented || a.Tags != nil {
			t.Fatalf("segment %d not kept raw: %+v", i, a)
		}

		got, err := asm.Add([]byte(source), &a)
		if err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
		if got != nil && n != len(order)-1 {
			t.Fatalf("message complete after %d of %d segments", n+1, len(order))
		}
		whole = got
	}
	return whole
}

func TestBACnetSegmentAssembler(t *testing.T) {
	const segmentSize = 50

	ack := bacnetLongACK(7, 40)
	var plain BACnetAPDU
	if err := plain.DecodeFromBytes(ack, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	want := bacnetValuesText(&plain)
	segs := bacnetSegment(ack, segmentSize)
	if len(segs) < 10 {
		t.Fatalf("only %d segments", len(segs))
	}

	inOrder := make([]int, len(segs))
	swapped := make([]int, len(segs))
	var doubled []int
	for i := range segs {
		inOrder[i] = i
		swapped[i] = i
		doubled = append(doubled, i, i)
	}
	// Each window arrives backwards, except that segment 0 opens the
	// message; then the first segment is sent once more.
	for i := 1; i+2 < len(swapped); i += 3 {
		swapped[i], swapped[i+2] = swapped[i+2], swapped[i]
	}
	// The last segment completes the message, so it comes once.
	doubled = doubled[:len(doubled)-1]
	resent := append([]int{0, 1, 2, 0, 1, 2}, inOrder[3:]...)

	orders := map[string][]int{"in order": inOrder, "out of order": swapped, "duplicates": doubled, "resent window": resent}
	for name, order := range orders {
		asm := NewBACnetSegmentAssembler()
		whole := bacnetAddSegments(t, asm, "10.0.0.1", segs, order)
		if whole == nil {
			t.Errorf("%s: message not completed", name)
			continue
		}
		if whole.Segmented || whole.MoreFollows || whole.InvokeID != 7 || whole.PDUType != BACnetPDUComplexACK {
			t.Errorf("%s: header %+v", name, whole)
		}
		if !bytes.Equal(whole.Parameters, plain.Parameters) {
			t.Errorf("%s: parameters differ", name)
		}
		if _, ok := whole.ServiceData.(*BACnetReadPropertyAck); !ok {
			t.Errorf("%s: ServiceData %T", name, whole.ServiceData)
		}
		if got := bacnetValuesText(whole); got != want {
			t.Errorf("%s: values differ:\n got %s\nwant %s", name, got, want)
		}
		if asm.Pending() != 0 {
			t.Errorf("%s: %d messages left", name, asm.Pending())
		}
	}

	// A segmented request, whose header has one octet more.
	request := append([]byte{0x02, 0x55, 0x09, 0x10}, ack[3:]...)
	requestSegs := bacnetSegment(request, segmentSize)
	asm := NewBACnetSegmentAssembler()
	whole := bacnetAddSegments(t, asm, "10.0.0.2", requestSegs, inOrder[:len(requestSegs)])
	if whole == nil || whole.PDUType != BACnetPDUConfirmedRequest || whole.InvokeID != 9 ||
		!whole.SegmentedResponseAccepted || whole.MaxSegments != BACnetMaxSegments32 || whole.MaxAPDU != BACnetMaxAPDU1476 ||
		whole.ConfirmedService != BACnetConfirmedServiceWritePropertyMultiple || !bytes.Equal(whole.Parameters, plain.Parameters) {
		t.Errorf("request %+v", whole)
	}
}

// TestBACnetSegmentKeys interleaves messages that differ in one part of
// the key each: source, invoke ID, direction.
func TestBACnetSegmentKeys(t *testing.T) {
	type stream struct {
		source string
		whole  []byte
		segs   [][]byte
	}
	ack := bacnetLongACK(1, 12)
	streams := []*stream{
		{source: "a", whole: ack},
		{source: "b", whole: bacnetLongACK(1, 14)},
		{source: "a", whole: bacnetLongACK(2, 16)},
		{source: "a", whole: append([]byte{0x00, 0x05, 0x01, 0x10}, bacnetLongACK(1, 18)[3:]...)},
	}
	for _, s := range streams {
		s.segs = bacnetSegment(s.whole, 20)
	}

	asm := NewBACnetSegmentAssembler()
	done := 0
	for i := 0; done < len(streams); i++ {
		for _, s := range streams {
			if i >= len(s.segs) {
				continue
			}
			var a BACnetAPDU
			if err := a.DecodeFromBytes(s.segs[i], gopacket.NilDecodeFeedback); err != nil {
				t.Fatal(err)
			}
			whole, err := asm.Add([]byte(s.source), &a)
			if err != nil {
				t.Fatal(err)
			}
			if whole == nil {
				continue
			}

			done++
			if got := append(append([]byte(nil), whole.Contents...), whole.Parameters...); !bytes.Equal(got, s.whole) {
				t.Errorf("stream %q mixed up", s.source)
			}
		}
	}
	if asm.Pending() != 0 {
		t.Errorf("%d messages left", asm.Pending())
	}
}

func TestBACnetSegmentLimits(t *testing.T) {
	segs := bacnetSegment(bacnetLongACK(3, 40), 100)
	segment := func(i int) *BACnetAPDU {
		a := &BACnetAPDU{}
		if err := a.DecodeFromBytes(segs[i], gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		return a
	}

	// The size cap drops the message that passes it.
	asm := &BACnetSegmentAssembler{MaxSize: 250}
	for i := 0; i < 2; i++ {
		if whole, err := asm.Add(nil, segment(i)); whole != nil || err != nil {
			t.Fatalf("segment %d: %v %v", i, whole, err)
		}
	}
	if _, err := asm.Add(nil, segment(2)); err != ErrBACnetSegmentsTooLarge {
		t.Errorf("over the cap: %v", err)
	}
	if asm.Pending() != 0 {
		t.Errorf("%d messages left after the cap", asm.Pending())
	}
	// The rest of the dropped message is ignored.
	if whole, err := asm.Add(nil, segment(3)); whole != nil || err != nil || asm.Pending() != 0 {
		t.Errorf("segment of a dropped message: %v %v", whole, err)
	}

	// Segments held out of order count towards the cap too.
	asm = &BACnetSegmentAssembler{MaxSize: 250}
	_, _ = asm.Add(nil, segment(0))
	_, _ = asm.Add(nil, segment(2))
	if _, err := asm.Add(nil, segment(3)); err != ErrBACnetSegmentsTooLarge {
		t.Errorf("held segments over the cap: %v", err)
	}

	// One message more than MaxPending drops the one silent the longest.
	asm = &BACnetSegmentAssembler{MaxPending: 2}
	_, _ = asm.Add([]byte("old"), segment(0))
	_, _ = asm.Add([]byte("mid"), segment(0))
	_, _ = asm.Add([]byte("old"), segment(1))
	_, _ = asm.Add([]byte("new"), segment(0))
	if asm.Pending() != 2 {
		t.Fatalf("%d messages pending", asm.Pending())
	}
	if whole, _ := asm.Add([]byte("mid"), segment(1)); whole != nil || asm.Pending() != 2 {
		t.Error("evicted message still fed")
	}
	for i := 2; i < len(segs); i++ {
		whole, err := asm.Add([]byte("old"), segment(i))
		if err != nil || (whole != nil) != (i == len(segs)-1) {
			t.Fatalf("kept message, segment %d: %v %v", i, whole, err)
		}
	}

	// A message whose first segment was not seen is ignored; unsegmented
	// APDUs and nil pass through.
	asm = NewBACnetSegmentAssembler()
	if whole, err := asm.Add(nil, segment(1)); whole != nil || err != nil || asm.Pending() != 0 {
		t.Errorf("message without a start: %v %v", whole, err)
	}
	plain := bacnetAPDUOfHex(t, "10 08")
	if whole, err := asm.Add(nil, plain); whole != plain || err != nil {
		t.Errorf("unsegmented APDU: %v %v", whole, err)
	}
	if whole, err := asm.Add(nil, nil); whole != nil || err != nil {
		t.Errorf("nil APDU: %v %v", whole, err)
	}

	// Segment 0 with other data restarts the message: the invoke ID was
	// reused.
	other := bacnetSegment(bacnetLongACK(3, 2), 100)
	_, _ = asm.Add(nil, segment(0))
	_, _ = asm.Add(nil, segment(1))
	var a BACnetAPDU
	if err := a.DecodeFromBytes(other[0], gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	whole, err := asm.Add(nil, &a)
	if err != nil || whole == nil || len(whole.Parameters) != len(other[0])-5 {
		t.Errorf("restarted message: %v %v", whole, err)
	}

	// Joined data that is no tag stream is an error, not a panic.
	bad := [][]byte{{0x3C, 0x01, 0x00, 0x04, 0x0C, 0x3E}, {0x38, 0x01, 0x01, 0x04, 0x0C, 0x4F}}
	var got error
	for _, seg := range bad {
		var a BACnetAPDU
		if err := a.DecodeFromBytes(seg, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		_, got = asm.Add(nil, &a)
	}
	if got == nil {
		t.Error("broken joined message decoded")
	}

	// An APDU built by hand, without Contents, cannot be joined.
	if whole, err := asm.Add(nil, &BACnetAPDU{Segmented: true, PDUType: BACnetPDUComplexACK}); whole != nil || err == nil {
		t.Errorf("header-less segment: %v %v", whole, err)
	}
}

// bacnetWrapper is a security wrapper that is not encrypted and carries
// authentication data: 3 octets of service data from device 10 to 20.
const bacnetWrapper = "90 02 01 05 00 00 0a 00 00 00 2a 65 b8 f0 00" + // control .. timestamp
	" 00 00 14 00 01 01 07 00 02 06 0a 00 00 05 ba c0" + // destination device, DNET/DADR, SNET/SADR
	" 01 00 64 02 00 07 be ef" + // mechanism 1, user 100, role 2, 7 octets in all
	" 01 02 03" + // service data
	" 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a" // signature

func TestBACnetSecurityWrapper(t *testing.T) {
	want := &BACnetSecurityWrapper{
		Control:                 0x90,
		KeyRevision:             2,
		KeyIdentifier:           0x0105,
		SourceDevice:            10,
		MessageID:               42,
		Timestamp:               0x65B8F000,
		DestinationDevice:       20,
		DNET:                    1,
		DADR:                    []byte{7},
		SNET:                    2,
		SADR:                    []byte{10, 0, 0, 5, 0xBA, 0xC0},
		AuthenticationMechanism: 1,
		UserID:                  100,
		UserRole:                2,
		AuthenticationData:      []byte{0xBE, 0xEF},
		ServiceData:             []byte{1, 2, 3},
		Signature:               bytes.Repeat([]byte{0x5A}, 16),
	}
	wrapper := mustHex(t, bacnetWrapper)

	got, err := decodeBACnetSecurity(wrapper, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wrapper\n got %+v\nwant %+v", got, want)
	}
	c := got.Control
	if !c.NetworkMessage() || c.Encrypted() || !c.AuthenticationPresent() || c.DoNotUnwrap() || c.DoNotDecrypt() ||
		c.NonTrustedSource() || c.SecuredByRouter() {
		t.Errorf("control %#x", uint8(c))
	}

	// Cut anywhere the wrapper is an error, and the layers that carry it
	// keep it raw.
	for i := 0; i < len(wrapper); i++ {
		w, err := decodeBACnetSecurity(wrapper[:i:i], gopacket.NilDecodeFeedback)
		// Shorter service data still parses once the header is whole.
		if err == nil && i < len(wrapper)-3 {
			t.Errorf("cut at %d decoded: %+v", i, w)
		}
	}

	// Mechanism 0 has no authentication data; an encrypted wrapper hides
	// everything after the timestamp.
	plain := mustHex(t, "1f 00 00 00 00 00 01 00 00 00 01 00 00 00 02 00 00 02 ff ff 00 00 00 00 00 00 03 04 09"+strings.Repeat(" a5", 16))
	got, err = decodeBACnetSecurity(plain, gopacket.NilDecodeFeedback)
	if err != nil || got.UserID != 3 || got.UserRole != 4 || got.AuthenticationData != nil || !bytes.Equal(got.ServiceData, []byte{9}) ||
		got.DNET != 0xFFFF || len(got.DADR) != 0 || !got.Control.SecuredByRouter() || !got.Control.DoNotUnwrap() {
		t.Errorf("mechanism 0: %+v %v", got, err)
	}
	encrypted := mustHex(t, "40 01 00 01 00 00 01 00 00 00 01 00 00 00 02 de ad be ef 99"+strings.Repeat(" a5", 16))
	got, err = decodeBACnetSecurity(encrypted, gopacket.NilDecodeFeedback)
	if err != nil || !got.Control.Encrypted() || got.DestinationDevice != 0 || !bytes.Equal(got.ServiceData, []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x99}) ||
		len(got.Signature) != 16 {
		t.Errorf("encrypted: %+v %v", got, err)
	}

	// The three carriers: Secure-BVLL of BACnet/IP and BACnet/IPv6, and a
	// network security message.
	size := len(wrapper) + bvlcHeaderLen
	var bvlc BVLC
	frame := append([]byte{0x81, 0x0C, byte(size >> 8), byte(size)}, wrapper...)
	if err := bvlc.DecodeFromBytes(frame, gopacket.NilDecodeFeedback); err != nil || !reflect.DeepEqual(bvlc.Security, want) ||
		!bytes.Equal(bvlc.Secured, wrapper) {
		t.Errorf("BVLC: %+v %v", bvlc.Security, err)
	}

	var bvlc6 BVLC6
	frame = append([]byte{0x82, 0x0B, byte(size >> 8), byte(size)}, wrapper...)
	if err := bvlc6.DecodeFromBytes(frame, gopacket.NilDecodeFeedback); err != nil || !reflect.DeepEqual(bvlc6.Security, want) ||
		!bytes.Equal(bvlc6.Secured, wrapper) {
		t.Errorf("BVLC6: %+v %v", bvlc6.Security, err)
	}

	for msg := BACnetNetworkMessageChallengeRequest; msg <= BACnetNetworkMessageSetMasterKey; msg++ {
		var npdu BACnetNPDU
		frame = append([]byte{0x01, 0x80, byte(msg)}, wrapper...)
		err := npdu.DecodeFromBytes(frame, gopacket.NilDecodeFeedback)
		if err != nil || npdu.Security == nil || !bytes.Equal(npdu.Body, wrapper) {
			t.Errorf("NPDU %v: %+v %v", msg, npdu.Security, err)
			continue
		}
		// The message in the wrapper has a test of its own.
		npdu.Security.Message = nil
		if !reflect.DeepEqual(npdu.Security, want) {
			t.Errorf("NPDU %v: %+v", msg, npdu.Security)
		}

		// Too short for a wrapper: Body alone, as before.
		if err := npdu.DecodeFromBytes(frame[:10], gopacket.NilDecodeFeedback); err != nil || npdu.Security != nil || len(npdu.Body) != 7 {
			t.Errorf("short NPDU %v: %+v %v", msg, npdu, err)
		}
	}
}

func TestBACnetSC(t *testing.T) {
	const (
		origin = "01 02 03 04 05 06"
		dest   = "0a 0b 0c 0d 0e 0f"
		uuid   = "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
	)
	originVMAC := BACnetSCVMAC{1, 2, 3, 4, 5, 6}
	destVMAC := BACnetSCVMAC{10, 11, 12, 13, 14, 15}
	deviceUUID := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

	tests := []struct {
		name string
		data string
		want BACnetSC
	}{
		{"Encapsulated-NPDU with options",
			"01 0f 12 34 " + origin + " " + dest + " 41 bf 00 03 aa bb cc 01 01 00 10 08",
			BACnetSC{Function: BACnetSCFunctionEncapsulatedNPDU, Control: 0x0F, MessageID: 0x1234,
				OriginVMAC: originVMAC, DestinationVMAC: destVMAC,
				DestinationOptions: []BACnetSCOption{{Type: BACnetSCOptionSecurePath, MustUnderstand: true}},
				DataOptions: []BACnetSCOption{
					{Type: BACnetSCOptionProprietary, Data: []byte{0xAA, 0xBB, 0xCC},
						VendorID: 0xAABB, ProprietaryType: 0xCC, ProprietaryData: []byte{}},
					{Type: BACnetSCOptionSecurePath},
				}}},
		{"BVLC-Result ACK",
			"00 00 00 01 0a 00",
			BACnetSC{Function: BACnetSCFunctionResult, MessageID: 1, ResultFunction: BACnetSCFunctionHeartbeatRequest}},
		{"BVLC-Result NAK",
			"00 08 00 02 " + origin + " 06 01 41 00 07 00 0b 62 61 64",
			BACnetSC{Function: BACnetSCFunctionResult, Control: 0x08, MessageID: 2, OriginVMAC: originVMAC,
				ResultFunction: BACnetSCFunctionConnectRequest, ResultCode: BACnetSCResultNAK, ErrorMarker: 0x41,
				Error: BACnetError{Class: BACnetErrorClassCommunication, Code: 11}, ErrorDetails: "bad"}},
		{"Address-Resolution",
			"02 0c 00 03 " + origin + " " + dest,
			BACnetSC{Function: BACnetSCFunctionAddressResolution, Control: 0x0C, MessageID: 3,
				OriginVMAC: originVMAC, DestinationVMAC: destVMAC}},
		{"Address-Resolution-ACK",
			"03 04 00 04 " + dest + " 77 73 73 3a 2f 2f 61 20 77 73 73 3a 2f 2f 62",
			BACnetSC{Function: BACnetSCFunctionAddressResolutionAck, Control: 0x04, MessageID: 4,
				DestinationVMAC: destVMAC, URIs: "wss://a wss://b"}},
		{"Advertisement",
			"04 00 00 05 01 01 05 dc 05 96",
			BACnetSC{Function: BACnetSCFunctionAdvertisement, MessageID: 5, HubConnection: 1, AcceptsConnections: true,
				MaxBVLCLength: 1500, MaxNPDULength: 1430}},
		{"Advertisement-Solicitation",
			"05 00 00 06",
			BACnetSC{Function: BACnetSCFunctionAdvertisementSolicitation, MessageID: 6}},
		{"Connect-Request",
			"06 00 00 07 " + origin + " " + uuid + " 05 dc 05 96",
			BACnetSC{Function: BACnetSCFunctionConnectRequest, MessageID: 7, ConnectVMAC: originVMAC, DeviceUUID: deviceUUID,
				MaxBVLCLength: 1500, MaxNPDULength: 1430}},
		{"Connect-Accept",
			"07 00 00 07 " + dest + " " + uuid + " 10 00 0f 00",
			BACnetSC{Function: BACnetSCFunctionConnectAccept, MessageID: 7, ConnectVMAC: destVMAC, DeviceUUID: deviceUUID,
				MaxBVLCLength: 4096, MaxNPDULength: 3840}},
		{"Disconnect-Request", "08 00 00 08", BACnetSC{Function: BACnetSCFunctionDisconnectRequest, MessageID: 8}},
		{"Disconnect-ACK", "09 00 00 08", BACnetSC{Function: BACnetSCFunctionDisconnectAck, MessageID: 8}},
		{"Heartbeat-Request", "0a 00 00 09", BACnetSC{Function: BACnetSCFunctionHeartbeatRequest, MessageID: 9}},
		{"Heartbeat-ACK", "0b 00 00 09", BACnetSC{Function: BACnetSCFunctionHeartbeatAck, MessageID: 9}},
		{"Proprietary-Message",
			"0c 00 00 0a 01 04 07 de ad",
			BACnetSC{Function: BACnetSCFunctionProprietaryMessage, MessageID: 10, VendorID: 260, ProprietaryFunction: 7,
				ProprietaryData: []byte{0xDE, 0xAD}}},
	}

	for _, test := range tests {
		data := mustHex(t, test.data)
		var got BACnetSC
		if err := got.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", test.name, err)
			continue
		}
		if got.Function.String() != test.name[:len(got.Function.String())] {
			t.Errorf("%s: named %v", test.name, got.Function)
		}

		contents, payload := got.Contents, got.Payload
		got.BaseLayer = BaseLayer{}
		if test.want.ProprietaryData == nil && got.ProprietaryData != nil && len(got.ProprietaryData) == 0 {
			got.ProprietaryData = nil
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", test.name, got, test.want)
		}
		if len(contents)+len(payload) != len(data) {
			t.Errorf("%s: %d + %d octets of %d", test.name, len(contents), len(payload), len(data))
		}

		// Cut short, a message decodes or fails, and never panics.
		for i := 0; i < len(data); i++ {
			var cut BACnetSC
			_ = cut.DecodeFromBytes(data[:i:i], gopacket.NilDecodeFeedback)
		}
	}

	var sc BACnetSC

	// The NPDU of an Encapsulated-NPDU is decoded on.
	p := gopacket.NewPacket(mustHex(t, tests[0].data), LayerTypeBACnetSC, gopacket.Default)
	if a, ok := p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU); !ok || a.UnconfirmedService != BACnetUnconfirmedServiceWhoIs {
		t.Errorf("layers %v, error %v", p.Layers(), p.ErrorLayer())
	}
	if got := fmt.Sprint(BACnetSCResultNAK, BACnetSCOptionSecurePath, BACnetSCFunction(99)); got != "NAK Secure Path Unknown(99)" {
		t.Errorf("names %q", got)
	}
	c := BACnetSCControl(0x0F)
	if !c.HasOrigin() || !c.HasDestination() || !c.HasDestinationOptions() || !c.HasDataOptions() {
		t.Errorf("control %#x", uint8(c))
	}

	// The typed views of an advertisement, a list of URIs and the
	// Secure Path option.
	if err := sc.DecodeFromBytes(mustHex(t, "04 00 00 0a 02 01 05c4 05c4"), gopacket.NilDecodeFeedback); err != nil ||
		sc.HubConnection != BACnetSCHubFailover || sc.HubConnection.String() != "Connected to failover hub" {
		t.Errorf("advertisement %v %v", sc.HubConnection, err)
	}
	uris := "wss://a:4443 wss://b"
	if err := sc.DecodeFromBytes(append(mustHex(t, "03 00 00 09"), uris...), gopacket.NilDecodeFeedback); err != nil ||
		!reflect.DeepEqual(sc.URIList(), []string{"wss://a:4443", "wss://b"}) || sc.SecurePath() {
		t.Errorf("URIs %q %v", sc.URIList(), err)
	}
	if err := sc.DecodeFromBytes(mustHex(t, "01 01 00 01 41 01 00 10 08"), gopacket.NilDecodeFeedback); err != nil ||
		!sc.SecurePath() || sc.URIList() != nil {
		t.Errorf("secure path %+v %v", sc.DataOptions, err)
	}

	// A list of more options than are kept still ends where it ends.
	many := append([]byte{0x0A, 0x02, 0x00, 0x01}, bytes.Repeat([]byte{0x81}, 3*bacnetSCMaxOptions)...)
	many = append(many, 0x01)
	if err := sc.DecodeFromBytes(many, gopacket.NilDecodeFeedback); err != nil || len(sc.DestinationOptions) != bacnetSCMaxOptions {
		t.Errorf("%d options kept: %v", len(sc.DestinationOptions), err)
	}

	// Truncated fixed payloads and option lists are errors.
	for _, cut := range []string{"01", "06 00 00 07 01 02", "04 00 00 05 01", "00 00 00 01 0a", "00 00 00 01 0a 01 00",
		"01 08 00 01 01 02", "01 02 00 01 a1 00 05 01", "01 02 00 01 81", "0c 00 00 0a 01"} {
		if err := sc.DecodeFromBytes(mustHex(t, cut), gopacket.NilDecodeFeedback); err != ErrBACnetTruncated {
			t.Errorf("%s: %v", cut, err)
		}
	}
}

// TestBVLCAny runs a DecodingLayerParser over both BACnet/IP flavours
// with one set of layers.
func TestBVLCAny(t *testing.T) {
	var (
		any  BVLCAny
		npdu BACnetNPDU
		apdu BACnetAPDU
	)
	parser := gopacket.NewDecodingLayerParser(LayerTypeBVLC, &any, &npdu, &apdu)
	var decoded []gopacket.LayerType
	want := []gopacket.LayerType{LayerTypeBVLC, LayerTypeBACnetNPDU, LayerTypeBACnetAPDU}

	// Original-Unicast-NPDU, from VMAC aabbcc to ddeeff: Who-Is.
	if err := parser.DecodeLayers(mustHex(t, "82 01 00 0e aa bb cc dd ee ff 01 00 10 08"), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, want) || !any.IPv6 || any.BVLC6.SourceVMAC != (BACnetVMAC{0xAA, 0xBB, 0xCC}) ||
		apdu.UnconfirmedService != BACnetUnconfirmedServiceWhoIs {
		t.Errorf("BACnet/IPv6: %v %+v", decoded, any.BVLC6)
	}

	if err := parser.DecodeLayers(mustHex(t, "81 0b 00 0c 01 00 10 00 c4 02 00 00 7b 22"), &decoded); err == nil {
		t.Error("truncated I-Am decoded")
	}
	if err := parser.DecodeLayers(mustHex(t, "81 0a 00 08 01 00 10 08"), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, want) || any.IPv6 || any.BVLC.Function != BVLCFunctionOriginalUnicastNPDU {
		t.Errorf("BACnet/IP: %v %+v", decoded, any.BVLC)
	}

	// Functions without an NPDU end the stack.
	if err := parser.DecodeLayers(mustHex(t, "82 09 00 09 aa bb cc 00 3c"), &decoded); err != nil || len(decoded) != 1 || any.BVLC6.TTL != 60 {
		t.Errorf("Register-Foreign-Device: %v %v", decoded, err)
	}

	// Every frame of the BACnet/IPv6 vectors goes through.
	for i, frame := range bacnetFrames(t, "bacnet-vectors-ipv6.pcap") {
		var direct BVLC6
		wantErr := direct.DecodeFromBytes(frame, gopacket.NilDecodeFeedback)
		if err := any.DecodeFromBytes(frame, gopacket.NilDecodeFeedback); err != wantErr || !any.IPv6 ||
			!reflect.DeepEqual(any.BVLC6, direct) || !bytes.Equal(any.LayerPayload(), direct.Payload) ||
			any.NextLayerType() != direct.NextLayerType() {
			t.Errorf("frame %d: %v, want %v", i+1, err, wantErr)
		}
	}
	for _, cut := range []string{"", "82", "81 0a 00"} {
		if err := any.DecodeFromBytes(mustHex(t, cut), gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("%q decoded", cut)
		}
	}
}

// TestBACnetSegmentCapture reassembles a ReadRange-ACK that a trend log
// sent in two segments (TrendLogMultipleReadRange.pcap of the kargs.net
// BACnet captures); tshark shows the same 32 records once reassembled.
func TestBACnetSegmentCapture(t *testing.T) {
	const records = 32

	asm := NewBACnetSegmentAssembler()
	var whole *BACnetAPDU
	for _, p := range readDecodedPcap(t, "bacnet-segmented.pcap") {
		a, ok := p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU)
		if !ok {
			t.Fatalf("no APDU: %v", p.ErrorLayer())
		}

		got, err := asm.Add(p.NetworkLayer().NetworkFlow().Src().Raw(), a)
		if err != nil {
			t.Fatal(err)
		}
		if a.Segmented && got != nil {
			whole = got
		}
	}
	if whole == nil || asm.Pending() != 0 {
		t.Fatalf("not reassembled, %d pending", asm.Pending())
	}

	p, ok := whole.ServiceData.(*BACnetParameters)
	if !ok || whole.ConfirmedService != BACnetConfirmedServiceReadRange || whole.InvokeID != 1 {
		t.Fatalf("reassembled %+v", whole)
	}
	if got := p.Field("item-count").Value; got != uint64(records) {
		t.Errorf("item-count %#v", got)
	}
	data := p.Field("item-data")
	if data == nil || len(data.Fields) != records {
		t.Fatalf("item-data %+v", data)
	}
	want := "{timestamp{date=2011-09-27 time=14:40:03.09}"
	if got := data.Fields[0].String(); !strings.HasPrefix(got, want) {
		t.Errorf("first record %s", got)
	}
}
