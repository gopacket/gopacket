// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// bacnetFrame is the expected summary of one frame of a capture.
type bacnetFrame struct {
	num  int
	want string
}

// Expected summaries, taken from tshark 4.7 on the same files. The
// bacnet-* captures come from https://github.com/automayt/ICS-pcap; the
// vectors were built by hand from ASHRAE 135 and checked with tshark.
var bacnetPcapFrames = map[string][]bacnetFrame{
	"bacnet-bbmd.pcap": {
		{1, "bvlc=5"},
		{2, "bvlc=9 npdu=32 apdu=1 svc=8"},
		{3, "bvlc=0"},
		{4, "bvlc=4 npdu=32 apdu=1 svc=8"},
		{5, "bvlc=11 npdu=32 apdu=1 svc=0"},
		{6, "bvlc=4 npdu=32 apdu=1 svc=0"},
		{7, "bvlc=11 npdu=32 apdu=1 svc=0"},
		{8, "bvlc=4 npdu=32 apdu=1 svc=0"},
		{9, "bvlc=11 npdu=0 apdu=1 svc=0"},
		{10, "bvlc=4 npdu=0 apdu=1 svc=0"},
		{11, "bvlc=11 npdu=40 apdu=1 svc=0"},
		{12, "bvlc=4 npdu=40 apdu=1 svc=0"},
		{13, "bvlc=11 npdu=40 apdu=1 svc=0"},
		{14, "bvlc=4 npdu=40 apdu=1 svc=0"},
	},
	"bacnet-array-elements.pcap": {
		{1, "bvlc=5"},
		{2, "bvlc=9 npdu=32 apdu=1 svc=8"},
		{3, "bvlc=0"},
		{4, "bvlc=11 npdu=32 apdu=1 svc=8"},
		{5, "bvlc=4 npdu=32 apdu=1 svc=8"},
		{6, "bvlc=4 npdu=32 apdu=1 svc=8"},
		{7, "bvlc=11 npdu=32 apdu=1 svc=0"},
		{8, "bvlc=4 npdu=32 apdu=1 svc=0"},
		{9, "bvlc=10 npdu=4 apdu=0 svc=12"},
		{10, "bvlc=10 npdu=0 apdu=3 svc=12"},
		{20, "bvlc=10 npdu=0 apdu=3 svc=12"},
		{30, "bvlc=10 npdu=0 apdu=3 svc=12"},
		{39, "bvlc=10 npdu=4 apdu=0 svc=12"},
		{40, "bvlc=10 npdu=0 apdu=5 svc=12"},
	},
	"bacnet-devobjref.pcap": {
		{1, "bvlc=10 npdu=4 apdu=0 svc=12"},
		{2, "bvlc=10 npdu=0 apdu=3 svc=12"},
		{4, "bvlc=10 npdu=4 apdu=0 svc=12"},
		{5, "bvlc=10 npdu=0 apdu=3 svc=12"},
	},
	"bacnet-vectors.pcap": {
		{1, "bvlc=10 npdu=4 apdu=0 svc=15"},
		{2, "bvlc=10 npdu=0 apdu=2 svc=15"},
		{3, "bvlc=10 npdu=4 apdu=0 svc=14"},
		{4, "bvlc=10 npdu=0 apdu=3 svc=14"},
		{5, "bvlc=10 npdu=4 apdu=0 svc=5"},
		{6, "bvlc=11 npdu=0 apdu=1 svc=2"},
		{7, "bvlc=11 npdu=0 apdu=1 svc=6"},
		{8, "bvlc=11 npdu=0 apdu=1 svc=7"},
		{9, "bvlc=11 npdu=0 apdu=1 svc=1"},
		{10, "bvlc=11 npdu=0 apdu=1 svc=8"},
		{11, "bvlc=10 npdu=0 apdu=6"},
		{12, "bvlc=10 npdu=0 apdu=7"},
		{13, "bvlc=10 npdu=0 apdu=4"},
		{14, "bvlc=10 npdu=0 apdu=3 svc=12"},
		{15, "bvlc=10 npdu=0 apdu=5 svc=12"},
		{16, "bvlc=11 npdu=8 apdu=1 svc=0"},
		{17, "bvlc=11 npdu=32 apdu=1 svc=8"},
		{18, "bvlc=11 npdu=128 msg=0"},
		{19, "bvlc=11 npdu=128 msg=0"},
		{20, "bvlc=11 npdu=128 msg=1"},
		{21, "bvlc=10 npdu=128 msg=6"},
		{22, "bvlc=10 npdu=128 msg=3"},
		{23, "bvlc=10 npdu=128 msg=128"},
		{24, "bvlc=11 npdu=128 msg=19"},
		{25, "bvlc=3"},
		{26, "bvlc=7"},
		{27, "bvlc=8"},
		{28, "bvlc=1"},
		{29, "bvlc=2"},
		{30, "bvlc=0"},
		{31, "bvlc=12"},
	},
	"bacnet-vectors-ipv6.pcap": {
		{1, "bvlc=1 npdu=4 apdu=0 svc=12"},
		{2, "bvlc=2 npdu=0 apdu=1 svc=8"},
		{3, "bvlc=9"},
		{4, "bvlc=0"},
		{5, "bvlc=8 npdu=0 apdu=1 svc=8"},
		{6, "bvlc=3"},
	},
}

// readDecodedPcap decodes every packet of a capture in testdata, with the
// BACnet port registered.
func readDecodedPcap(t testing.TB, name string) []gopacket.Packet {
	t.Helper()
	registerBACnetDecoders()

	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := newSimplePcapReader(f)
	if err != nil {
		t.Fatal(err)
	}

	var pkts []gopacket.Packet
	for {
		data, err := r.readPacketData()
		if err == io.EOF {
			return pkts
		}
		if err != nil {
			t.Fatal(err)
		}
		pkts = append(pkts, gopacket.NewPacket(data, r.linkType, gopacket.DecodeOptions{DecodeStreamsAsDatagrams: true}))
	}
}

// bacnetSummary renders a packet the way the expectation tables do.
func bacnetSummary(p gopacket.Packet) string {
	var parts []string
	if b, ok := p.Layer(LayerTypeBVLC).(*BVLC); ok {
		parts = append(parts, fmt.Sprintf("bvlc=%d", b.Function))
	}
	if b, ok := p.Layer(LayerTypeBVLC6).(*BVLC6); ok {
		parts = append(parts, fmt.Sprintf("bvlc=%d", b.Function))
	}
	if n, ok := p.Layer(LayerTypeBACnetNPDU).(*BACnetNPDU); ok {
		parts = append(parts, fmt.Sprintf("npdu=%d", n.Control))
		if n.Control.NetworkMessage() {
			parts = append(parts, fmt.Sprintf("msg=%d", n.MessageType))
		}
	}
	if a, ok := p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU); ok {
		parts = append(parts, fmt.Sprintf("apdu=%d", a.PDUType))
		switch a.PDUType {
		case BACnetPDUUnconfirmedRequest:
			parts = append(parts, fmt.Sprintf("svc=%d", a.UnconfirmedService))
		case BACnetPDUConfirmedRequest, BACnetPDUSimpleACK, BACnetPDUComplexACK, BACnetPDUError:
			parts = append(parts, fmt.Sprintf("svc=%d", a.ConfirmedService))
		}
	}
	return strings.Join(parts, " ")
}

func TestBACnetPcaps(t *testing.T) {
	for name, frames := range bacnetPcapFrames {
		pkts := readDecodedPcap(t, name)

		// Every packet decodes without error, BACnet or not.
		for i, p := range pkts {
			if el := p.ErrorLayer(); el != nil {
				t.Errorf("%s #%d: %v", name, i+1, el.Error())
			}
		}
		for _, f := range frames {
			if got := bacnetSummary(pkts[f.num-1]); got != f.want {
				t.Errorf("%s #%d: got %q, want %q", name, f.num, got, f.want)
			}
		}
	}
}

// bacnetPacket returns frame num (1-based) of a capture.
func bacnetPacket(t *testing.T, name string, num int) gopacket.Packet {
	t.Helper()
	pkts := readDecodedPcap(t, name)
	if num > len(pkts) {
		t.Fatalf("%s has %d packets", name, len(pkts))
	}
	return pkts[num-1]
}

func bacnetAPDUOf(t *testing.T, p gopacket.Packet) *BACnetAPDU {
	t.Helper()
	a, ok := p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU)
	if !ok {
		t.Fatalf("no APDU in %v", p)
	}
	return a
}

func TestBACnetBBMDCapture(t *testing.T) {
	// Register-Foreign-Device with a TTL of 60000 s.
	b := bacnetPacket(t, "bacnet-bbmd.pcap", 1).Layer(LayerTypeBVLC).(*BVLC)
	if b.Function != BVLCFunctionRegisterForeignDevice || b.TTL != 60000 {
		t.Errorf("register: %v ttl %d", b.Function, b.TTL)
	}

	// Forwarded-NPDU from 192.168.0.105:47808 holding an I-Am of device
	// 123, vendor 260, routed with DNET 65535 and hop count 14.
	p := bacnetPacket(t, "bacnet-bbmd.pcap", 6)
	b = p.Layer(LayerTypeBVLC).(*BVLC)
	if b.Function != BVLCFunctionForwardedNPDU || !b.Address.IP.Equal(net.IPv4(192, 168, 0, 105)) || b.Address.Port != 47808 {
		t.Errorf("forwarded: %v from %v", b.Function, b.Address)
	}
	n := p.Layer(LayerTypeBACnetNPDU).(*BACnetNPDU)
	if !n.Control.HasDestination() || n.DNET != 65535 || len(n.DADR) != 0 || n.HopCount != 14 {
		t.Errorf("npdu: %+v", n)
	}
	iam, ok := bacnetAPDUOf(t, p).ServiceData.(*BACnetIAm)
	if !ok {
		t.Fatalf("I-Am not decoded")
	}
	want := &BACnetIAm{
		Device:        BACnetObjectIdentifier{Type: BACnetObjectTypeDevice, Instance: 123},
		MaxAPDULength: 1476,
		Segmentation:  BACnetSegmentedBoth,
		VendorID:      260,
	}
	if iam.Device != want.Device || iam.VendorID != want.VendorID {
		t.Errorf("I-Am: got %+v, want %+v", iam, want)
	}
	if iam.Device.String() != "device,123" {
		t.Errorf("object id string %q", iam.Device)
	}

	// A routed I-Am: both DNET and SNET/SADR present.
	n = bacnetPacket(t, "bacnet-bbmd.pcap", 11).Layer(LayerTypeBACnetNPDU).(*BACnetNPDU)
	if n.DNET != 65535 || n.HopCount != 254 || n.SNET != 26001 || !bytes.Equal(n.SADR, []byte{114}) {
		t.Errorf("routed npdu: %+v", n)
	}
}

func TestBACnetReadPropertyCapture(t *testing.T) {
	// ReadProperty device,12345 object-list, max APDU 480 octets.
	a := bacnetAPDUOf(t, bacnetPacket(t, "bacnet-array-elements.pcap", 9))
	rp, ok := a.ServiceData.(*BACnetReadProperty)
	if !ok {
		t.Fatalf("ReadProperty not decoded: %+v", a)
	}
	if a.InvokeID != 1 || a.MaxAPDU != BACnetMaxAPDU480 || a.MaxAPDU.Octets() != 480 {
		t.Errorf("header: %+v", a)
	}
	wantRP := BACnetReadProperty{
		Object:     BACnetObjectIdentifier{Type: BACnetObjectTypeDevice, Instance: 12345},
		Property:   BACnetPropertyObjectList,
		ArrayIndex: BACnetNoArrayIndex,
	}
	if *rp != wantRP {
		t.Errorf("got %+v, want %+v", rp, wantRP)
	}

	// The ACK lists 47 objects, the first being the device itself.
	ack, ok := bacnetAPDUOf(t, bacnetPacket(t, "bacnet-array-elements.pcap", 10)).ServiceData.(*BACnetReadPropertyAck)
	if !ok {
		t.Fatal("ReadProperty ACK not decoded")
	}
	if len(ack.Value) != 47 {
		t.Fatalf("got %d values", len(ack.Value))
	}
	first, err := ack.Value[0].ObjectIdentifier()
	if err != nil || first != wantRP.Object {
		t.Errorf("first value %v %v", first, err)
	}
	last, _ := ack.Value[46].ObjectIdentifier()
	if last != (BACnetObjectIdentifier{Type: BACnetObjectTypeFile, Instance: 2}) {
		t.Errorf("last value %v", last)
	}

	// Error: property / invalid-array-index.
	a = bacnetAPDUOf(t, bacnetPacket(t, "bacnet-array-elements.pcap", 40))
	if a.Error != (BACnetError{Class: BACnetErrorClassProperty, Code: BACnetErrorCodeInvalidArrayIndex}) {
		t.Errorf("error %+v", a.Error)
	}
	if a.Error.Code.String() != "invalid-array-index" {
		t.Errorf("error code name %q", a.Error.Code)
	}
}

func TestBACnetDeviceObjectReference(t *testing.T) {
	// The value is a BACnetDeviceObjectReference, context tagged: it stays
	// as raw tags, which the caller reads with the typed accessors.
	ack := bacnetAPDUOf(t, bacnetPacket(t, "bacnet-devobjref.pcap", 5)).ServiceData.(*BACnetReadPropertyAck)
	if ack.Property != BACnetPropertyMemberOf || len(ack.Value) != 1 || !ack.Value[0].IsContext(1) {
		t.Fatalf("got %+v", ack)
	}
	o, err := ack.Value[0].ObjectIdentifier()
	if err != nil || o != (BACnetObjectIdentifier{Type: BACnetObjectTypeLifeSafetyZone, Instance: 1}) {
		t.Errorf("got %v %v", o, err)
	}
}

func TestBACnetVectorServices(t *testing.T) {
	pkts := readDecodedPcap(t, "bacnet-vectors.pcap")
	svc := func(num int) BACnetServiceData {
		t.Helper()
		return bacnetAPDUOf(t, pkts[num-1]).ServiceData
	}

	// WriteProperty analog-value,1 present-value = 100.0 at priority 8.
	wp, ok := svc(1).(*BACnetWriteProperty)
	if !ok || wp.Priority != 8 || wp.Property != BACnetPropertyPresentValue || len(wp.Value) != 1 {
		t.Fatalf("WriteProperty: %+v", wp)
	}
	if v, err := wp.Value[0].Real(); err != nil || v != 100 {
		t.Errorf("value %v %v", v, err)
	}

	// ReadPropertyMultiple of two objects.
	rpm, ok := svc(3).(*BACnetReadPropertyMultiple)
	wantRPM := &BACnetReadPropertyMultiple{Specs: []BACnetReadAccessSpec{
		{Object: BACnetObjectIdentifier{Type: BACnetObjectTypeAnalogInput}, Properties: []BACnetPropertyReference{
			{Property: BACnetPropertyPresentValue, ArrayIndex: BACnetNoArrayIndex},
			{Property: BACnetPropertyObjectName, ArrayIndex: BACnetNoArrayIndex},
		}},
		{Object: BACnetObjectIdentifier{Type: BACnetObjectTypeDevice, Instance: 123}, Properties: []BACnetPropertyReference{
			{Property: BACnetPropertyObjectList, ArrayIndex: 0},
		}},
	}}
	if !ok || !reflect.DeepEqual(rpm, wantRPM) {
		t.Errorf("RPM: got %+v", rpm)
	}

	// The ACK: one value, one property-access error.
	ack, ok := svc(4).(*BACnetReadPropertyMultipleAck)
	if !ok || len(ack.Results) != 1 || len(ack.Results[0].Results) != 2 {
		t.Fatalf("RPM ACK: %+v", ack)
	}
	res := ack.Results[0].Results
	if v, _ := res[0].Value[0].Real(); v != 20 || res[0].Error != nil {
		t.Errorf("first result %+v", res[0])
	}
	if res[1].Error == nil || *res[1].Error != (BACnetError{Class: BACnetErrorClassProperty, Code: BACnetErrorCodeUnknownProperty}) {
		t.Errorf("second result %+v", res[1])
	}

	sub, ok := svc(5).(*BACnetSubscribeCOV)
	wantSub := &BACnetSubscribeCOV{ProcessID: 18, Object: BACnetObjectIdentifier{Type: BACnetObjectTypeAnalogInput, Instance: 3},
		IssueConfirmed: true, Lifetime: 120}
	if !ok || *sub != *wantSub {
		t.Errorf("SubscribeCOV: %+v", sub)
	}

	cov, ok := svc(6).(*BACnetCOVNotification)
	if !ok || cov.ProcessID != 18 || cov.Device.Instance != 123 || len(cov.Values) != 2 {
		t.Fatalf("COV: %+v", cov)
	}
	flags, err := cov.Values[1].Value[0].BitString()
	if err != nil || cov.Values[1].Property != BACnetPropertyStatusFlags || flags.Len() != 4 || flags.Bit(0) {
		t.Errorf("status flags %+v %v", flags, err)
	}

	ts, ok := svc(7).(*BACnetTimeSynchronization)
	if !ok || ts.Date.String() != "2022-11-19" || ts.Time.String() != "14:30:00.00" || ts.Date.Weekday != 6 {
		t.Errorf("TimeSynchronization: %+v", ts)
	}

	wh, ok := svc(8).(*BACnetWhoHas)
	if !ok || !wh.ByName || wh.ObjectName != "Room1" || wh.Limited {
		t.Errorf("Who-Has: %+v", wh)
	}

	ih, ok := svc(9).(*BACnetIHave)
	if !ok || ih.Device.Instance != 123 || ih.Object.Type != BACnetObjectTypeAnalogInput || ih.ObjectName != "Room1" {
		t.Errorf("I-Have: %+v", ih)
	}

	wi, ok := svc(10).(*BACnetWhoIs)
	if !ok || *wi != (BACnetWhoIs{Limited: true, LowLimit: 0, HighLimit: 4095}) {
		t.Errorf("Who-Is: %+v", wi)
	}
}

func TestBACnetVectorHeaders(t *testing.T) {
	pkts := readDecodedPcap(t, "bacnet-vectors.pcap")
	apdu := func(num int) *BACnetAPDU { return bacnetAPDUOf(t, pkts[num-1]) }

	if a := apdu(11); a.RejectReason != BACnetRejectUnrecognizedService || a.InvokeID != 5 {
		t.Errorf("Reject: %+v", a)
	}
	if a := apdu(12); a.AbortReason != BACnetAbortSegmentationNotSupported || !a.Server || a.InvokeID != 7 {
		t.Errorf("Abort: %+v", a)
	}
	if a := apdu(13); !a.NegativeACK || a.Server || a.SequenceNumber != 3 || a.WindowSize != 4 {
		t.Errorf("SegmentACK: %+v", a)
	}

	// A segment carries part of a tag stream: no tags, raw parameters.
	a := apdu(14)
	if !a.Segmented || !a.MoreFollows || a.SequenceNumber != 0 || a.WindowSize != 4 ||
		a.ConfirmedService != BACnetConfirmedServiceReadProperty || a.Tags != nil || len(a.Parameters) != 13 {
		t.Errorf("segmented ComplexACK: %+v", a)
	}
	if a := apdu(15); a.Error != (BACnetError{Class: BACnetErrorClassObject, Code: BACnetErrorCodeUnknownObject}) {
		t.Errorf("Error: %+v", a.Error)
	}

	n := pkts[15].Layer(LayerTypeBACnetNPDU).(*BACnetNPDU)
	if !n.Control.HasSource() || n.SNET != 5 || !bytes.Equal(n.SADR, []byte{0x0a}) || n.Control.HasDestination() {
		t.Errorf("routed I-Am NPDU: %+v", n)
	}
	n = pkts[16].Layer(LayerTypeBACnetNPDU).(*BACnetNPDU)
	if n.DNET != 0xFFFF || len(n.DADR) != 0 || n.HopCount != 255 {
		t.Errorf("global broadcast NPDU: %+v", n)
	}
}

func TestBACnetVectorNetworkMessages(t *testing.T) {
	pkts := readDecodedPcap(t, "bacnet-vectors.pcap")
	npdu := func(num int) *BACnetNPDU { return pkts[num-1].Layer(LayerTypeBACnetNPDU).(*BACnetNPDU) }

	if n := npdu(18); n.MessageType != BACnetNetworkMessageWhoIsRouterToNetwork || n.Networks != nil {
		t.Errorf("Who-Is-Router: %+v", n)
	}
	if n := npdu(19); !reflect.DeepEqual(n.Networks, []uint16{5}) {
		t.Errorf("Who-Is-Router DNET: %+v", n)
	}
	if n := npdu(20); !reflect.DeepEqual(n.Networks, []uint16{5, 6}) {
		t.Errorf("I-Am-Router: %+v", n)
	}
	wantRT := []BACnetRoutingEntry{
		{DNET: 5, PortID: 1, PortInfo: []byte{}},
		{DNET: 6, PortID: 2, PortInfo: []byte{0xaa, 0xbb}},
	}
	if n := npdu(21); !reflect.DeepEqual(n.RoutingTable, wantRT) {
		t.Errorf("Initialize-Routing-Table: %+v", n.RoutingTable)
	}
	if n := npdu(22); n.RejectReason != BACnetNetworkRejectUnknownNetwork || n.Networks[0] != 7 {
		t.Errorf("Reject-Message: %+v", n)
	}
	if n := npdu(23); n.VendorID != 260 || !bytes.Equal(n.Body, []byte{0xde, 0xad}) || n.MessageType.String() != "Proprietary" {
		t.Errorf("proprietary: %+v", n)
	}
	if n := npdu(24); n.Networks[0] != 7 || n.NetworkNumberStatus != BACnetNetworkNumberConfigured {
		t.Errorf("Network-Number-Is: %+v", n)
	}
}

func TestBACnetVectorBVLC(t *testing.T) {
	pkts := readDecodedPcap(t, "bacnet-vectors.pcap")
	bvlc := func(num int) *BVLC { return pkts[num-1].Layer(LayerTypeBVLC).(*BVLC) }

	bdt := bvlc(25).BDT
	if len(bdt) != 2 || bdt[1].Address.String() != "192.168.1.1:47808" || bdt[1].Mask.String() != "ffffff00" {
		t.Errorf("Read-BDT-Ack: %+v", bdt)
	}
	fdt := bvlc(26).FDT
	if len(fdt) != 1 || fdt[0].TTL != 60 || fdt[0].Remaining != 45 || !fdt[0].Address.IP.Equal(net.IPv4(10, 0, 0, 5)) {
		t.Errorf("Read-FDT-Ack: %+v", fdt)
	}
	if b := bvlc(27); b.Address.String() != "10.0.0.5:47808" {
		t.Errorf("Delete-FDT-Entry: %+v", b)
	}
	if b := bvlc(30); b.ResultCode != BVLCResultRegisterForeignDeviceNAK || b.ResultCode.String() != "Register-Foreign-Device NAK" {
		t.Errorf("BVLC-Result: %+v", b)
	}
	if b := bvlc(31); !bytes.Equal(b.Secured, []byte{1, 2, 3, 4}) || b.NextLayerType() != gopacket.LayerTypeZero {
		t.Errorf("Secure-BVLL: %+v", b)
	}

	pkts = readDecodedPcap(t, "bacnet-vectors-ipv6.pcap")
	bvlc6 := func(num int) *BVLC6 { return pkts[num-1].Layer(LayerTypeBVLC6).(*BVLC6) }
	if b := bvlc6(1); b.SourceVMAC != (BACnetVMAC{0, 0, 1}) || b.DestinationVMAC != (BACnetVMAC{0, 0, 2}) {
		t.Errorf("Original-Unicast: %+v", b)
	}
	if b := bvlc6(3); b.TTL != 60 {
		t.Errorf("Register-Foreign-Device: %+v", b)
	}
	if b := bvlc6(4); b.ResultCode != BVLC6ResultRegisterForeignDeviceNAK {
		t.Errorf("BVLC-Result: %+v", b)
	}
	if b := bvlc6(5); b.Address.String() != "[fe80::1]:47808" {
		t.Errorf("Forwarded-NPDU: %+v", b)
	}
	if b := bvlc6(6); b.DestinationVMAC != (BACnetVMAC{0, 0, 2}) || b.NextLayerType() != gopacket.LayerTypeZero {
		t.Errorf("Address-Resolution: %+v", b)
	}
}

func TestBACnetTagValues(t *testing.T) {
	// One tag of each application type, then context and extended forms.
	data := mustHex(t, "00"+ // Null
		"11"+ // Boolean true
		"22 01 00"+ // Unsigned 256
		"31 ff"+ // Signed -1
		"32 80 00"+ // Signed -32768
		"44 3f c0 00 00"+ // Real 1.5
		"55 08 40 09 21 fb 54 44 2d 18"+ // Double pi
		"62 de ad"+ // OctetString
		"75 07 05 63 61 66 e9 21 21"+ // CharacterString ISO 8859-1 "café!!"
		"75 07 04 00 68 00 c4 00 b1"+ // CharacterString UCS-2 "h\u00c4\u00b1"
		"82 05 a0"+ // BitString 101
		"91 03"+ // Enumerated 3
		"a4 ff 01 ff ff"+ // Date *-01-*
		"b4 17 3b 3b 63"+ // Time 23:59:59.99
		"c4 00 c0 00 07"+ // ObjectIdentifier binary-input,7
		"f9 c8 01"+ // context tag 200, Unsigned 1
		"65 fe 00 01 aa"+ // OctetString, 16-bit length 1
		"65 ff 00 00 00 01 bb") // OctetString, 32-bit length 1
	tags, err := decodeBACnetTags(data)
	if err != nil {
		t.Fatal(err)
	}

	want := []interface{}{
		nil, true, uint64(256), int64(-1), int64(-32768), float32(1.5), math.Pi,
		[]byte{0xde, 0xad}, "café!!", "h\u00c4\u00b1", BACnetBitString{Unused: 5, Bytes: []byte{0xa0}}, uint64(3),
		BACnetDate{Year: 0xFF, Month: 1, Day: 0xFF, Weekday: 0xFF},
		BACnetTime{Hour: 23, Minute: 59, Second: 59, Hundredths: 99},
		BACnetObjectIdentifier{Type: BACnetObjectTypeBinaryInput, Instance: 7},
		[]byte{1}, []byte{0xaa}, []byte{0xbb},
	}
	if len(tags) != len(want) {
		t.Fatalf("got %d tags, want %d", len(tags), len(want))
	}
	want[9] = "hÄ±"
	for i := range tags {
		got, err := tags[i].Value()
		if err != nil || !reflect.DeepEqual(got, want[i]) {
			t.Errorf("tag %d: got %#v (%v), want %#v", i, got, err, want[i])
		}
	}
	if !tags[15].IsContext(200) {
		t.Errorf("extended tag number: %+v", tags[15])
	}
	if b, _ := tags[10].BitString(); b.Len() != 3 || !b.Bit(0) || b.Bit(1) || !b.Bit(2) || b.Bit(3) {
		t.Errorf("bit string %+v", b)
	}
	if d, _ := tags[12].Date(); d.String() != "*-01-*" {
		t.Errorf("date string %q", d)
	}

	// Accessors refuse the wrong type.
	if _, err := tags[2].Real(); err == nil {
		t.Error("Real of an Unsigned")
	}
}

func TestBACnetTagNesting(t *testing.T) {
	open := func(n int) string { return strings.Repeat("0e ", n) }
	closing := func(n int) string { return strings.Repeat("0f ", n) }

	// Nesting up to the limit decodes; one more opening tag is refused.
	tags, err := decodeBACnetTags(mustHex(t, open(bacnetMaxTagDepth)+"21 01 "+closing(bacnetMaxTagDepth)))
	if err != nil || tags[bacnetMaxTagDepth].Depth != bacnetMaxTagDepth {
		t.Errorf("max depth: %v", err)
	}
	cases := map[string]string{
		"too deep":       open(bacnetMaxTagDepth+1) + closing(bacnetMaxTagDepth+1),
		"unclosed":       "0e 21 01",
		"stray closing":  "21 01 0f",
		"mismatched":     "0e 1f",
		"app opening":    "06",
		"length lie":     "65 ff ff ff ff ff 00",
		"short extended": "f9",
	}
	for name, h := range cases {
		if _, err := decodeBACnetTags(mustHex(t, h)); !errors.Is(err, ErrBACnetTag) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestBACnetMalformed(t *testing.T) {
	registerBACnetDecoders()
	cases := map[string]struct {
		hex  string
		want error
	}{
		"short header":     {"81 0a 00", ErrBACnetTruncated},
		"length too long":  {"81 0a 00 20 01 00", ErrBACnetTruncated},
		"length too short": {"81 0a 00 03", ErrBACnetMalformed},
		"bad type":         {"80 0a 00 04", ErrBVLCType},
		"bad BDT length":   {"81 03 00 07 01 02 03", ErrBACnetMalformed},
		"npdu version":     {"81 0a 00 08 02 00 10 08", ErrBACnetNPDUVersion},
		"npdu DLEN lie":    {"81 0a 00 0a 01 20 00 05 09 00", ErrBACnetTruncated},
		"npdu SLEN zero":   {"81 0a 00 0b 01 08 00 05 00 10 08", ErrBACnetMalformed},
		"routes lie":       {"81 0a 00 0a 01 80 06 ff 00 05", ErrBACnetTruncated},
		"apdu type 8":      {"81 0a 00 07 01 00 80", ErrBACnetMalformed},
		"apdu short":       {"81 0a 00 08 01 00 00 05", ErrBACnetTruncated},
		"apdu bad tags":    {"81 0a 00 0b 01 00 10 08 0e 21 01", ErrBACnetTag},
	}
	for name, c := range cases {
		p := gopacket.NewPacket(mustHex(t, c.hex), LayerTypeBVLC, gopacket.Default)
		el := p.ErrorLayer()
		if el == nil || !errors.Is(el.Error(), c.want) {
			t.Errorf("%s: got %v, want %v", name, el, c.want)
		}
	}

	// Well-tagged parameters of the wrong shape keep their tags only.
	a := bacnetAPDUOf(t, gopacket.NewPacket(mustHex(t, "81 0a 00 0a 01 00 10 00 21 01"), LayerTypeBVLC, gopacket.Default))
	if a.ServiceData != nil || len(a.Tags) != 1 {
		t.Errorf("wrong shape I-Am: %+v", a)
	}
}

// TestBACnetTruncation cuts every frame of every capture at every offset.
// Nothing may panic, and a cut frame never decodes past its data.
func TestBACnetTruncation(t *testing.T) {
	for name := range bacnetPcapFrames {
		for _, frame := range bacnetFrames(t, name) {
			for i := 0; i < len(frame); i++ {
				decodeBACnetAll(frame[:i:i])
			}
		}
	}
}

// bacnetFrames returns the UDP payloads of the BACnet packets of a capture.
func bacnetFrames(t testing.TB, name string) [][]byte {
	var out [][]byte
	for _, p := range readDecodedPcap(t, name) {
		udp, ok := p.Layer(LayerTypeUDP).(*UDP)
		if !ok || udp.DstPort != UDPPort(UDPPortBACnet) {
			continue
		}
		out = append(out, udp.Payload)
	}
	return out
}

// decodeBACnetAll decodes data from BVLC down and touches every field
// and accessor a caller could, as the fuzzer does.
func decodeBACnetAll(data []byte) {
	p := gopacket.NewPacket(data, LayerTypeBVLC, gopacket.Default)
	for _, l := range p.Layers() {
		_ = fmt.Sprint(l)
	}
	a, ok := p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU)
	if !ok {
		return
	}
	_ = fmt.Sprintf("%v %v %v %v %v %v %v", a.PDUType, a.ConfirmedService, a.UnconfirmedService,
		a.RejectReason, a.AbortReason, a.Error.Class, a.Error.Code)
	for i := range a.Tags {
		tag := &a.Tags[i]
		_, _ = tag.Value()
		_, _ = tag.Boolean()
		_, _ = tag.Unsigned()
		_, _ = tag.Signed()
		_, _, _ = tag.CharacterString()
		if b, err := tag.BitString(); err == nil {
			for j := -1; j <= b.Len(); j++ {
				_ = b.Bit(j)
			}
		}
	}
}

func TestBACnetDecodingLayerParser(t *testing.T) {
	var (
		bvlc BVLC
		npdu BACnetNPDU
		apdu BACnetAPDU
	)
	parser := gopacket.NewDecodingLayerParser(LayerTypeBVLC, &bvlc, &npdu, &apdu)
	var decoded []gopacket.LayerType

	data := mustHex(t, "81 0a 00 1a 01 04 00 05 01 0f 0c 00 80 00 01 19 55 3e 44 42 c8 00 00 3f 49 08")
	if err := parser.DecodeLayers(data, &decoded); err != nil {
		t.Fatal(err)
	}
	want := []gopacket.LayerType{LayerTypeBVLC, LayerTypeBACnetNPDU, LayerTypeBACnetAPDU}
	if !reflect.DeepEqual(decoded, want) {
		t.Errorf("decoded %v", decoded)
	}
	if _, ok := apdu.ServiceData.(*BACnetWriteProperty); !ok {
		t.Errorf("service %T", apdu.ServiceData)
	}

	// Reuse with a shorter message leaves nothing behind.
	if err := parser.DecodeLayers(mustHex(t, "81 0b 00 08 01 00 10 08"), &decoded); err != nil {
		t.Fatal(err)
	}
	if wi, ok := apdu.ServiceData.(*BACnetWhoIs); !ok || wi.Limited || apdu.Tags != nil || apdu.InvokeID != 0 {
		t.Errorf("stale APDU: %+v", apdu)
	}
}

func TestBACnetEnumStrings(t *testing.T) {
	cases := map[fmt.Stringer]string{
		BVLCFunctionOriginalUnicastNPDU:                "Original-Unicast-NPDU",
		BVLC6FunctionAddressResolutionAck:              "Address-Resolution-ACK",
		BACnetPDUComplexACK:                            "ComplexACK",
		BACnetConfirmedServiceReadPropertyMultiple:     "readPropertyMultiple",
		BACnetUnconfirmedServiceWhoIs:                  "who-Is",
		BACnetObjectTypeAnalogInput:                    "analog-input",
		BACnetObjectType(300):                          "proprietary(300)",
		BACnetPropertyPresentValue:                     "present-value",
		BACnetPropertyIdentifier(600):                  "proprietary(600)",
		BACnetErrorCodeUnknownObject:                   "unknown-object",
		BACnetMaxSegments8:                             "8 segments",
		BACnetMaxAPDU480:                               "Up to 480 octets",
		BACnetPriorityLifeSafety:                       "Life Safety",
		BACnetNetworkMessageInitializeRoutingTableAck:  "Initialize-Routing-Table-Ack",
		BACnetAbortReason(99):                          "Unknown(99)",
		BACnetSegmentation(3):                          "no-segmentation",
		BACnetAppTagObjectIdentifier:                   "ObjectIdentifier",
		BACnetConfirmedServiceConfirmedCOVNotification: "confirmedCOVNotification",
	}
	for v, want := range cases {
		if got := v.String(); got != want {
			t.Errorf("%T(%v): got %q, want %q", v, v, got, want)
		}
	}
}

func FuzzBACnet(f *testing.F) {
	registerBACnetDecoders()
	for name := range bacnetPcapFrames {
		for _, frame := range bacnetFrames(f, name) {
			f.Add(frame)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decodeBACnetAll(data)

		// The DecodingLayerParser path shares DecodeFromBytes but not the
		// packet decoders.
		var (
			bvlc BVLC
			npdu BACnetNPDU
			apdu BACnetAPDU
		)
		var decoded []gopacket.LayerType
		parser := gopacket.NewDecodingLayerParser(LayerTypeBVLC, &bvlc, &npdu, &apdu)
		_ = parser.DecodeLayers(data, &decoded)
	})
}

// mustHex decodes space-separated hex.
func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
