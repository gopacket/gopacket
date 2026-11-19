// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// The parts of a plain text security wrapper around the service data of
// the vectors below: device 1 to device 2, no authentication data. The
// vectors are built by hand from Clause 24 of ASHRAE 135-2016; no public
// capture holds a secured BACnet message, and tshark 4.7 does not follow
// the wrapper past its addresses, so nothing here was cross-checked.
const (
	bacnetSecHeader  = "01 0001 000001 00000005 5f000000 000002 0001 01 0a 0002 01 0b"
	bacnetSecTrailer = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
)

// bacnetSecuredNPDU returns an NPDU carrying network security message t
// with the service data given as hex.
func bacnetSecuredNPDU(t testing.TB, msg BACnetNetworkMessageType, control uint8, service string) []byte {
	t.Helper()
	return mustHex(t, fmt.Sprintf("01 80 %02x %02x %s %s %s", uint8(msg), control, bacnetSecHeader, service, bacnetSecTrailer))
}

var bacnetSecurityVectors = []struct {
	name    string
	msg     BACnetNetworkMessageType
	control uint8
	service string
	want    BACnetSecurityMessage
}{
	{"Challenge-Request", BACnetNetworkMessageChallengeRequest, 0x80,
		"01 00000004 5e000000",
		&BACnetChallengeRequest{Challenge: 1, OriginalMessageID: 4, OriginalTimestamp: 0x5E000000}},

	{"Security-Payload, APDU", BACnetNetworkMessageSecurityPayload, 0x00,
		"0002 1008",
		&BACnetSecurityPayload{Payload: []byte{0x10, 0x08}}},
	{"Security-Payload, network message", BACnetNetworkMessageSecurityPayload, 0x80,
		"0005 01 0001 0002",
		&BACnetSecurityPayload{Payload: []byte{0x01, 0x00, 0x01, 0x00, 0x02},
			NetworkMessage: &BACnetNPDU{Version: 1, Control: 0x80, MessageType: BACnetNetworkMessageIAmRouterToNetwork,
				Body: []byte{0x00, 0x01, 0x00, 0x02}, Networks: []uint16{1, 2}}}},
	// A security message is not unwrapped a second time.
	{"Security-Payload, nested", BACnetNetworkMessageSecurityPayload, 0x80,
		"0002 0b 00",
		&BACnetSecurityPayload{Payload: []byte{0x0B, 0x00}}},

	{"Security-Response success", BACnetNetworkMessageSecurityResponse, 0x80,
		"00 00000004 5e000000",
		&BACnetSecurityResponse{Code: BACnetSecurityResponseSuccess, OriginalMessageID: 4, OriginalTimestamp: 0x5E000000, Details: []byte{}}},
	{"Security-Response badTimestamp", BACnetNetworkMessageSecurityResponse, 0x80,
		"06 00000004 5e000000 5e000010",
		&BACnetSecurityResponse{Code: BACnetSecurityResponseBadTimestamp, OriginalMessageID: 4, OriginalTimestamp: 0x5E000000,
			Details: []byte{0x5E, 0x00, 0x00, 0x10}, ExpectedTimestamp: 0x5E000010}},
	{"Security-Response cannotUseKey", BACnetNetworkMessageSecurityResponse, 0x80,
		"07 00000004 5e000000 0105",
		&BACnetSecurityResponse{Code: BACnetSecurityResponseCannotUseKey, OriginalMessageID: 4, OriginalTimestamp: 0x5E000000,
			Details: []byte{0x01, 0x05}, Keys: []uint16{0x0105}}},
	{"Security-Response incorrectKey", BACnetNetworkMessageSecurityResponse, 0x80,
		"0e 00000004 5e000000 02 0101 0102",
		&BACnetSecurityResponse{Code: BACnetSecurityResponseIncorrectKey, OriginalMessageID: 4, OriginalTimestamp: 0x5E000000,
			Details: []byte{0x02, 0x01, 0x01, 0x01, 0x02}, Keys: []uint16{0x0101, 0x0102}}},
	{"Security-Response tooManyKeys", BACnetNetworkMessageSecurityResponse, 0x80,
		"15 00000004 5e000000 08",
		&BACnetSecurityResponse{Code: BACnetSecurityResponseTooManyKeys, OriginalMessageID: 4, OriginalTimestamp: 0x5E000000,
			Details: []byte{0x08}, MaxKeys: 8}},
	{"Security-Response unknownAuthenticationType", BACnetNetworkMessageSecurityResponse, 0x80,
		"16 00000004 5e000000 c8 0104",
		&BACnetSecurityResponse{Code: BACnetSecurityResponseUnknownAuthenticationType, OriginalMessageID: 4, OriginalTimestamp: 0x5E000000,
			Details: []byte{0xC8, 0x01, 0x04}, AuthenticationMechanism: 200, VendorID: 260}},
	{"Security-Response unknownKey", BACnetNetworkMessageSecurityResponse, 0x80,
		"17 00000004 5e000000 0107",
		&BACnetSecurityResponse{Code: BACnetSecurityResponseUnknownKey, OriginalMessageID: 4, OriginalTimestamp: 0x5E000000,
			Details: []byte{0x01, 0x07}, Keys: []uint16{0x0107}}},
	{"Security-Response unknownKeyRevision", BACnetNetworkMessageSecurityResponse, 0x80,
		"18 00000004 5e000000 03",
		&BACnetSecurityResponse{Code: BACnetSecurityResponseUnknownKeyRevision, OriginalMessageID: 4, OriginalTimestamp: 0x5E000000,
			Details: []byte{0x03}, KeyRevision: 3}},

	{"Request-Key-Update", BACnetNetworkMessageRequestKeyUpdate, 0x80,
		"02 5e000000 5f000000 03 5f000000 60000000 01",
		&BACnetRequestKeyUpdate{
			Set1:                    BACnetKeySetTiming{Revision: 2, ActivationTime: 0x5E000000, ExpirationTime: 0x5F000000},
			Set2:                    BACnetKeySetTiming{Revision: 3, ActivationTime: 0x5F000000, ExpirationTime: 0x60000000},
			DistributionKeyRevision: 1}},

	{"Update-Key-Set, both sets", BACnetNetworkMessageUpdateKeySet, 0x80,
		"da" + // set 1 timing and keys, set 2 timing and keys, more follow
			" 02 5e000000 5f000000 02 0104 02 aabb 0105 01 cc" +
			" 03 5f000000 60000000 00",
		&BACnetUpdateKeySet{Flags: 0xDA,
			Set1: BACnetKeySetUpdate{HasTiming: true, HasKeys: true,
				Timing: BACnetKeySetTiming{Revision: 2, ActivationTime: 0x5E000000, ExpirationTime: 0x5F000000},
				Keys:   []BACnetSecurityKey{{Identifier: 0x0104, Value: []byte{0xAA, 0xBB}}, {Identifier: 0x0105, Value: []byte{0xCC}}}},
			Set2: BACnetKeySetUpdate{HasTiming: true, HasKeys: true,
				Timing: BACnetKeySetTiming{Revision: 3, ActivationTime: 0x5F000000, ExpirationTime: 0x60000000},
				Keys:   []BACnetSecurityKey{}}}},
	{"Update-Key-Set, clear and remove", BACnetNetworkMessageUpdateKeySet, 0x80,
		"25",
		&BACnetUpdateKeySet{Flags: 0x25}},
	{"Update-Key-Set, set 2 keys only", BACnetNetworkMessageUpdateKeySet, 0x80,
		"08 01 0104 00",
		&BACnetUpdateKeySet{Flags: 0x08,
			Set2: BACnetKeySetUpdate{HasKeys: true, Keys: []BACnetSecurityKey{{Identifier: 0x0104, Value: []byte{}}}}}},

	{"Update-Distribution-Key", BACnetNetworkMessageUpdateDistributionKey, 0x80,
		"04 0001 03 010203",
		&BACnetUpdateDistributionKey{KeyRevision: 4, Key: BACnetSecurityKey{Identifier: 1, Value: []byte{1, 2, 3}}}},
	{"Request-Master-Key", BACnetNetworkMessageRequestMasterKey, 0x80,
		"02 00 01",
		&BACnetRequestMasterKey{Algorithms: []uint8{0, 1}}},
	{"Set-Master-Key", BACnetNetworkMessageSetMasterKey, 0x80,
		"0002 04 deadbeef",
		&BACnetSetMasterKey{Key: BACnetSecurityKey{Identifier: 2, Value: []byte{0xDE, 0xAD, 0xBE, 0xEF}}}},
}

func TestBACnetSecurityMessages(t *testing.T) {
	for _, tt := range bacnetSecurityVectors {
		var n BACnetNPDU
		data := bacnetSecuredNPDU(t, tt.msg, tt.control, tt.service)
		if err := n.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if !strings.HasPrefix(tt.name, n.MessageType.String()) {
			t.Errorf("%s: named %v", tt.name, n.MessageType)
		}

		w := n.Security
		if w == nil || w.SourceDevice != 1 || w.DestinationDevice != 2 || w.MessageID != 5 || len(w.Signature) != 16 {
			t.Errorf("%s: wrapper %+v", tt.name, w)
			continue
		}
		if !reflect.DeepEqual(w.Message, tt.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tt.name, w.Message, tt.want)
		}
		if !bytes.Equal(w.ServiceData, mustHex(t, tt.service)) {
			t.Errorf("%s: service data %x", tt.name, w.ServiceData)
		}

		// Encrypted, the same octets are not looked at.
		data[3] |= 0x40
		if err := n.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil || n.Security == nil ||
			n.Security.Message != nil || !n.Security.Control.Encrypted() || n.NextLayerType() != gopacket.LayerTypeZero {
			t.Errorf("%s encrypted: %+v %v", tt.name, n.Security, err)
		}
		data[3] &^= 0x40

		// Cut anywhere, the NPDU still decodes and never reads past
		// the cut; service data cut short has no message.
		for i := bacnetNPDUMinLen + 1; i < len(data); i++ {
			if err := n.DecodeFromBytes(data[:i:i], gopacket.NilDecodeFeedback); err != nil {
				t.Errorf("%s cut at %d: %v", tt.name, i, err)
			}
		}
		// The signature is the last 16 octets, so a wrapper one octet
		// short loses the last octet of its service data.
		short := append(append([]byte(nil), data[:len(data)-17]...), data[len(data)-16:]...)
		if err := n.DecodeFromBytes(short, gopacket.NilDecodeFeedback); err != nil || n.Security == nil {
			t.Errorf("%s short: %v", tt.name, err)
		} else if n.Security.Message != nil && len(mustHex(t, tt.service)) > 1 && tt.msg != BACnetNetworkMessageSecurityResponse {
			t.Errorf("%s short: message %+v", tt.name, n.Security.Message)
		}
	}

	if got := fmt.Sprint(BACnetSecurityResponseBadTimestamp, BACnetSecurityResponseUnknownSourceMessage, BACnetSecurityResponseCode(0x40)); got != "badTimestamp unknownSourceMessage Unknown(64)" {
		t.Errorf("names %q", got)
	}
	f := BACnetKeySetFlags(0x27)
	if !f.ClearSet1() || !f.ClearSet2() || !f.MoreFollows() || !f.RemoveAllKeys() || BACnetKeySetFlags(0xD8).ClearSet1() {
		t.Errorf("flags %#x", uint8(f))
	}
}

// TestBACnetSecuredAPDU checks that an APDU secured in plain text is
// decoded as the next layer, and an encrypted one is not.
func TestBACnetSecuredAPDU(t *testing.T) {
	// A Who-Is for devices 1 to 2.
	data := bacnetSecuredNPDU(t, BACnetNetworkMessageSecurityPayload, 0x00, "0006 1008 0901 1902")

	p := gopacket.NewPacket(data, LayerTypeBACnetNPDU, gopacket.Default)
	if e := p.ErrorLayer(); e != nil {
		t.Fatal(e.Error())
	}
	n := p.Layer(LayerTypeBACnetNPDU).(*BACnetNPDU)
	a, ok := p.Layer(LayerTypeBACnetAPDU).(*BACnetAPDU)
	if !ok {
		t.Fatalf("no APDU: %v", p)
	}
	who, ok := a.ServiceData.(*BACnetWhoIs)
	if !ok || who.LowLimit != 1 || who.HighLimit != 2 {
		t.Errorf("service data %+v", a.ServiceData)
	}
	if len(n.Contents)+len(n.Payload)+len(n.Security.Signature) != len(data) || !bytes.Equal(n.Payload, mustHex(t, "1008 0901 1902")) {
		t.Errorf("contents %d payload %x", len(n.Contents), n.Payload)
	}

	// A payload length that lies leaves the wrapper without a message.
	lie := bacnetSecuredNPDU(t, BACnetNetworkMessageSecurityPayload, 0x00, "0007 1008 0901 1902")
	if err := n.DecodeFromBytes(lie, gopacket.NilDecodeFeedback); err != nil || n.Security == nil || n.Security.Message != nil || n.Payload != nil {
		t.Errorf("length lie: %+v %v", n.Security, err)
	}

	// An Update-Key-Set that announces more keys than it can hold costs
	// no list.
	keys := bacnetSecuredNPDU(t, BACnetNetworkMessageUpdateKeySet, 0x80, "40 ff 0104 00")
	allocs := testing.AllocsPerRun(4, func() {
		_ = n.DecodeFromBytes(keys, gopacket.NilDecodeFeedback)
	})
	if n.Security == nil || n.Security.Message != nil || allocs > 4 {
		t.Errorf("key count lie: %+v, %v allocations", n.Security, allocs)
	}
}

// TestBACnetSecurityAuthentication checks the authentication data of a
// vendor's mechanism, whose length counts the whole field.
func TestBACnetSecurityAuthentication(t *testing.T) {
	// mechanism 200, user 7, role 3, length 9: vendor 260, data aa bb.
	wrapper := mustHex(t, "10 "+bacnetSecHeader+" c8 0007 03 0009 0104 aabb"+" 01 02 "+bacnetSecTrailer)
	w, err := decodeBACnetSecurity(wrapper, gopacket.NilDecodeFeedback)
	if err != nil {
		t.Fatal(err)
	}
	if w.AuthenticationMechanism != 200 || w.UserID != 7 || w.UserRole != 3 || w.AuthenticationVendorID != 260 ||
		!bytes.Equal(w.AuthenticationData, []byte{0xAA, 0xBB}) || !bytes.Equal(w.ServiceData, []byte{1, 2}) {
		t.Errorf("wrapper %+v", w)
	}

	// A length shorter than the fields it counts, and one past the data.
	for _, bad := range []string{"c8 0007 03 0006 0104", "01 0007 03 0004", "01 0007 03 0030 aabb"} {
		if _, err := decodeBACnetSecurity(mustHex(t, "10 "+bacnetSecHeader+bad+bacnetSecTrailer), gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("%s decoded", bad)
		}
	}
}
