package layers

import (
	"encoding/hex"
	"testing"

	"github.com/gopacket/gopacket"
)

// Test basic Diameter message decoding
func TestDiameterDecoding(t *testing.T) {
	// Sample Diameter Capabilities-Exchange-Request (CER)
	// Version: 1, Length: 92, Flags: Request (0x80), Command: 257 (CER)
	// Application-ID: 0, Hop-by-Hop: 0x00000001, End-to-End: 0x00000001
	data := []byte{
		0x01, 0x00, 0x00, 0x5c, // Version, Length (92)
		0x80, 0x00, 0x01, 0x01, // Flags, Command Code (257)
		0x00, 0x00, 0x00, 0x00, // Application ID (0)
		0x00, 0x00, 0x00, 0x01, // Hop-by-Hop ID
		0x00, 0x00, 0x00, 0x01, // End-to-End ID
		// AVP: Origin-Host (264)
		0x00, 0x00, 0x01, 0x08, // AVP Code: 264
		0x40, 0x00, 0x00, 0x18, // Flags: Mandatory, Length: 24
		0x74, 0x65, 0x73, 0x74, // Data: "test.example.com"
		0x2e, 0x65, 0x78, 0x61,
		0x6d, 0x70, 0x6c, 0x65,
		0x2e, 0x63, 0x6f, 0x6d,
		// AVP: Origin-Realm (296)
		0x00, 0x00, 0x01, 0x28, // AVP Code: 296
		0x40, 0x00, 0x00, 0x13, // Flags: Mandatory, Length: 19
		0x65, 0x78, 0x61, 0x6d, // Data: "example.com"
		0x70, 0x6c, 0x65, 0x2e,
		0x63, 0x6f, 0x6d, 0x00,
		// AVP: Host-IP-Address (257)
		0x00, 0x00, 0x01, 0x01, // AVP Code: 257
		0x40, 0x00, 0x00, 0x0e, // Flags: Mandatory, Length: 14
		0x00, 0x01, 0x0a, 0x00, // Address Family: IPv4, Data: 10.0.0.1
		0x00, 0x01, 0x00, 0x00,
		// AVP: Vendor-Id (266)
		0x00, 0x00, 0x01, 0x0a, // AVP Code: 266
		0x40, 0x00, 0x00, 0x0c, // Flags: Mandatory, Length: 12
		0x00, 0x00, 0x00, 0x00, // Vendor ID: 0
		// AVP: Auth-Application-Id (258)
		0x00, 0x00, 0x01, 0x02, // AVP Code: 258
		0x40, 0x00, 0x00, 0x0c, // Flags: Mandatory, Length: 12
		0x00, 0x00, 0x00, 0x00, // Application ID: 0 (Diameter Common Messages)
	}

	p := gopacket.NewPacket(data, LayerTypeDiameter, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal("Failed to decode Diameter:", p.ErrorLayer().Error())
	}

	diameterLayer := p.Layer(LayerTypeDiameter)
	if diameterLayer == nil {
		t.Fatal("No Diameter layer found")
	}

	diameter := diameterLayer.(*Diameter)

	// Check header fields
	if diameter.Version != 1 {
		t.Errorf("Version: expected 1, got %d", diameter.Version)
	}

	if diameter.MessageLength != 92 {
		t.Errorf("MessageLength: expected 92, got %d", diameter.MessageLength)
	}

	if !diameter.CommandFlags.Request {
		t.Error("Expected Request flag to be set")
	}

	if diameter.CommandCode != 257 {
		t.Errorf("CommandCode: expected 257 (CER), got %d", diameter.CommandCode)
	}

	if diameter.ApplicationID != 0 {
		t.Errorf("ApplicationID: expected 0, got %d", diameter.ApplicationID)
	}

	if diameter.HopByHopID != 1 {
		t.Errorf("HopByHopID: expected 1, got %d", diameter.HopByHopID)
	}

	if diameter.EndToEndID != 1 {
		t.Errorf("EndToEndID: expected 1, got %d", diameter.EndToEndID)
	}

	// Check AVPs
	if len(diameter.AVPs) < 4 {
		t.Errorf("Expected at least 4 AVPs, got %d", len(diameter.AVPs))
	}

	// Check Origin-Host AVP
	if len(diameter.AVPs) > 0 {
		avp := diameter.AVPs[0]
		if avp.Code != 264 {
			t.Errorf("First AVP Code: expected 264 (Origin-Host), got %d", avp.Code)
		}
		if !avp.Flags.Mandatory {
			t.Error("Origin-Host AVP should be mandatory")
		}
		originHost := avp.GetString()
		if originHost != "test.example.com" {
			t.Errorf("Origin-Host: expected 'test.example.com', got '%s'", originHost)
		}
	}
}

// Test Diameter AVP with Vendor flag
func TestDiameterVendorAVP(t *testing.T) {
	// Diameter message with vendor-specific AVP
	data := []byte{
		0x01, 0x00, 0x00, 0x24, // Version, Length (36)
		0x80, 0x00, 0x01, 0x01, // Flags: Request, Command Code (257)
		0x00, 0x00, 0x00, 0x00, // Application ID (0)
		0x00, 0x00, 0x00, 0x01, // Hop-by-Hop ID
		0x00, 0x00, 0x00, 0x01, // End-to-End ID
		// Vendor-specific AVP
		0x00, 0x00, 0x00, 0x01, // AVP Code: 1
		0xc0, 0x00, 0x00, 0x10, // Flags: Vendor+Mandatory, Length: 16
		0x00, 0x00, 0x28, 0xaf, // Vendor ID: 10415 (3GPP)
		0x00, 0x00, 0x00, 0x0a, // Data: 10
	}

	p := gopacket.NewPacket(data, LayerTypeDiameter, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal("Failed to decode Diameter with vendor AVP:", p.ErrorLayer().Error())
	}

	diameterLayer := p.Layer(LayerTypeDiameter)
	if diameterLayer == nil {
		t.Fatal("No Diameter layer found")
	}

	diameter := diameterLayer.(*Diameter)

	if len(diameter.AVPs) != 1 {
		t.Fatalf("Expected 1 AVP, got %d", len(diameter.AVPs))
	}

	avp := diameter.AVPs[0]
	if !avp.Flags.Vendor {
		t.Error("Expected Vendor flag to be set")
	}

	if !avp.Flags.Mandatory {
		t.Error("Expected Mandatory flag to be set")
	}

	if avp.VendorID != 10415 {
		t.Errorf("VendorID: expected 10415 (3GPP), got %d", avp.VendorID)
	}

	val, err := avp.GetUnsigned32()
	if err != nil {
		t.Fatal("Failed to get Unsigned32:", err)
	}
	if val != 10 {
		t.Errorf("AVP value: expected 10, got %d", val)
	}
}

// Test Diameter message serialization
func TestDiameterSerialization(t *testing.T) {
	// Create a Diameter message
	diameter := &Diameter{
		Version:       1,
		MessageLength: 0, // Will be calculated
		CommandFlags: DiameterCommandFlags{
			Request:   true,
			Proxiable: false,
			Error:     false,
		},
		CommandCode:   257, // CER
		ApplicationID: 0,
		HopByHopID:    1,
		EndToEndID:    1,
		AVPs: []DiameterAVP{
			{
				Code: 264, // Origin-Host
				Flags: DiameterAVPFlags{
					Mandatory: true,
				},
				Data: []byte("test.example.com"),
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
	}

	err := diameter.SerializeTo(buf, opts)
	if err != nil {
		t.Fatal("Failed to serialize Diameter:", err)
	}

	bytes := buf.Bytes()

	// Decode it back
	p := gopacket.NewPacket(bytes, LayerTypeDiameter, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal("Failed to decode serialized Diameter:", p.ErrorLayer().Error())
	}

	diameterLayer := p.Layer(LayerTypeDiameter)
	if diameterLayer == nil {
		t.Fatal("No Diameter layer found in serialized packet")
	}

	decoded := diameterLayer.(*Diameter)

	if decoded.Version != diameter.Version {
		t.Errorf("Version mismatch: expected %d, got %d", diameter.Version, decoded.Version)
	}

	if decoded.CommandCode != diameter.CommandCode {
		t.Errorf("CommandCode mismatch: expected %d, got %d", diameter.CommandCode, decoded.CommandCode)
	}

	if decoded.CommandFlags.Request != diameter.CommandFlags.Request {
		t.Error("Request flag mismatch")
	}

	if len(decoded.AVPs) != len(diameter.AVPs) {
		t.Errorf("AVP count mismatch: expected %d, got %d", len(diameter.AVPs), len(decoded.AVPs))
	}

	if len(decoded.AVPs) > 0 {
		if string(decoded.AVPs[0].Data) != string(diameter.AVPs[0].Data) {
			t.Error("AVP data mismatch")
		}
	}
}

// Test grouped AVP decoding
func TestDiameterGroupedAVP(t *testing.T) {
	// Create a message with a grouped AVP (Vendor-Specific-Application-Id)
	data, _ := hex.DecodeString(
		"01000034" + // Version 1, Length 52
			"80000101" + // Flags: Request, Command: 257
			"00000000" + // Application ID: 0
			"00000001" + // Hop-by-Hop: 1
			"00000001" + // End-to-End: 1
			// Grouped AVP: Vendor-Specific-Application-Id (260)
			"00000104" + // AVP Code: 260
			"40000020" + // Flags: Mandatory, Length: 32
			// Sub-AVP: Vendor-Id (266)
			"0000010a" + // AVP Code: 266
			"4000000c" + // Flags: Mandatory, Length: 12
			"0000028a" + // Vendor ID: 650 (example)
			// Sub-AVP: Auth-Application-Id (258)
			"00000102" + // AVP Code: 258
			"4000000c" + // Flags: Mandatory, Length: 12
			"01000023") // Auth-App-ID: 16777251

	if len(data) == 0 {
		t.Fatal("Failed to decode hex string")
	}

	p := gopacket.NewPacket(data, LayerTypeDiameter, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal("Failed to decode Diameter with grouped AVP:", p.ErrorLayer().Error())
	}

	diameterLayer := p.Layer(LayerTypeDiameter)
	if diameterLayer == nil {
		t.Fatal("No Diameter layer found")
	}

	diameter := diameterLayer.(*Diameter)

	if len(diameter.AVPs) < 1 {
		t.Fatal("Expected at least 1 AVP")
	}

	// Check the grouped AVP
	groupedAVP := diameter.AVPs[0]
	if groupedAVP.Code != 260 {
		t.Errorf("Expected AVP code 260 (Vendor-Specific-Application-Id), got %d", groupedAVP.Code)
	}

	if len(groupedAVP.GroupedAVPs) != 2 {
		t.Errorf("Expected 2 sub-AVPs, got %d", len(groupedAVP.GroupedAVPs))
	}
}

// Test helper functions
func TestDiameterHelperFunctions(t *testing.T) {
	d := &Diameter{
		CommandFlags: DiameterCommandFlags{
			Request:       true,
			Proxiable:     true,
			Error:         false,
			Retransmitted: false,
		},
	}

	if !d.IsRequest() {
		t.Error("IsRequest() should return true")
	}

	if !d.IsProxiable() {
		t.Error("IsProxiable() should return true")
	}

	if d.IsError() {
		t.Error("IsError() should return false")
	}

	if d.IsRetransmitted() {
		t.Error("IsRetransmitted() should return false")
	}

	avp := &DiameterAVP{
		Flags: DiameterAVPFlags{
			Vendor:    true,
			Mandatory: false,
			Protected: true,
		},
	}

	if !avp.IsVendorSpecific() {
		t.Error("IsVendorSpecific() should return true")
	}

	if avp.IsMandatory() {
		t.Error("IsMandatory() should return false")
	}

	if !avp.IsProtected() {
		t.Error("IsProtected() should return true")
	}
}

// Test vendor-specific AVP type detection
func TestDiameterVendorAVPTypes(t *testing.T) {
	// Test 3GPP vendor AVP
	avpType, ok := GetDiameterAVPType(8, 10415) // MSISDN from 3GPP
	if !ok {
		t.Error("3GPP MSISDN AVP should be recognized")
	}
	if avpType != DiameterAVPTypeUnsigned32 {
		t.Errorf("3GPP MSISDN should be Unsigned32, got %v", avpType)
	}

	// Test ETSI vendor AVP
	avpType, ok = GetDiameterAVPType(311, 13019) // SIP-Auth-Data-Item from ETSI
	if !ok {
		t.Error("ETSI SIP-Auth-Data-Item AVP should be recognized")
	}
	if avpType != DiameterAVPTypeOctetString {
		t.Errorf("ETSI SIP-Auth-Data-Item should be OctetString, got %v", avpType)
	}

	// Test grouped AVP from 3GPP
	avpType, ok = GetDiameterAVPType(443, 10415) // Subscription-Id
	if !ok {
		t.Error("3GPP Subscription-Id should be recognized")
	}
	if avpType != DiameterAVPTypeGrouped {
		t.Errorf("3GPP Subscription-Id should be Grouped, got %v", avpType)
	}

	// Test vendor name lookup
	vendorName := GetVendorName(10415)
	if vendorName != "3GPP" {
		t.Errorf("Vendor 10415 should be 3GPP, got %s", vendorName)
	}

	vendorName = GetVendorName(13019)
	if vendorName != "ETSI" {
		t.Errorf("Vendor 13019 should be ETSI, got %s", vendorName)
	}

	// Test unknown vendor
	vendorName = GetVendorName(99999)
	if vendorName == "3GPP" || vendorName == "ETSI" {
		t.Errorf("Unknown vendor should not match known vendors, got %s", vendorName)
	}
}

// Test AVP String method
func TestDiameterAVPString(t *testing.T) {
	avp := &DiameterAVP{
		Code: 264,
		Flags: DiameterAVPFlags{
			Mandatory: true,
		},
		Length: 24,
		Data:   []byte("test.example.com"),
	}

	str := avp.String()
	if str == "" {
		t.Error("AVP String() should not be empty")
	}
	t.Logf("AVP String representation: %s", str)

	// Test vendor-specific AVP
	vendorAVP := &DiameterAVP{
		Code: 8,
		Flags: DiameterAVPFlags{
			Vendor:    true,
			Mandatory: true,
		},
		VendorID: 10415,
		Length:   16,
		Data:     []byte{0x00, 0x00, 0x00, 0x0a},
	}

	str = vendorAVP.String()
	if str == "" {
		t.Error("Vendor AVP String() should not be empty")
	}
	t.Logf("Vendor AVP String representation: %s", str)

	vendorName := vendorAVP.GetVendorIDString()
	if vendorName != "3GPP" {
		t.Errorf("Expected vendor name '3GPP', got '%s'", vendorName)
	}
}

// Test 3GPP vendor-specific AVP in message
func TestDiameter3GPPVendorAVP(t *testing.T) {
	// Diameter message with 3GPP vendor-specific AVP (MSISDN = 8, Vendor = 10415)
	data := []byte{
		0x01, 0x00, 0x00, 0x24, // Version, Length (36)
		0x80, 0x00, 0x01, 0x01, // Flags: Request, Command Code (257)
		0x00, 0x00, 0x00, 0x00, // Application ID (0)
		0x00, 0x00, 0x00, 0x01, // Hop-by-Hop ID
		0x00, 0x00, 0x00, 0x01, // End-to-End ID
		// 3GPP Vendor-specific AVP (MSISDN)
		0x00, 0x00, 0x00, 0x08, // AVP Code: 8 (MSISDN)
		0xc0, 0x00, 0x00, 0x10, // Flags: Vendor+Mandatory, Length: 16
		0x00, 0x00, 0x28, 0xaf, // Vendor ID: 10415 (3GPP)
		0x12, 0x34, 0x56, 0x78, // MSISDN data
	}

	p := gopacket.NewPacket(data, LayerTypeDiameter, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Fatal("Failed to decode Diameter with 3GPP vendor AVP:", p.ErrorLayer().Error())
	}

	diameterLayer := p.Layer(LayerTypeDiameter)
	if diameterLayer == nil {
		t.Fatal("No Diameter layer found")
	}

	diameter := diameterLayer.(*Diameter)

	if len(diameter.AVPs) != 1 {
		t.Fatalf("Expected 1 AVP, got %d", len(diameter.AVPs))
	}

	avp := diameter.AVPs[0]
	if avp.Code != 8 {
		t.Errorf("Expected AVP code 8 (MSISDN), got %d", avp.Code)
	}

	if !avp.IsVendorSpecific() {
		t.Error("Expected vendor-specific AVP")
	}

	if avp.VendorID != 10415 {
		t.Errorf("Expected vendor ID 10415 (3GPP), got %d", avp.VendorID)
	}

	vendorName := avp.GetVendorIDString()
	if vendorName != "3GPP" {
		t.Errorf("Expected vendor '3GPP', got '%s'", vendorName)
	}

	// Check AVP type detection
	avpType, ok := GetDiameterAVPType(avp.Code, avp.VendorID)
	if !ok {
		t.Error("3GPP MSISDN AVP type should be recognized")
	}
	if avpType != DiameterAVPTypeUnsigned32 {
		t.Errorf("Expected Unsigned32 type for MSISDN, got %v", avpType)
	}
}

// Benchmark Diameter decoding
func BenchmarkDiameterDecoding(b *testing.B) {
	data := []byte{
		0x01, 0x00, 0x00, 0x40,
		0x80, 0x00, 0x01, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x08,
		0x40, 0x00, 0x00, 0x18,
		0x74, 0x65, 0x73, 0x74,
		0x2e, 0x65, 0x78, 0x61,
		0x6d, 0x70, 0x6c, 0x65,
		0x2e, 0x63, 0x6f, 0x6d,
		0x00, 0x00, 0x01, 0x02,
		0x40, 0x00, 0x00, 0x0c,
		0x00, 0x00, 0x00, 0x00,
	}

	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(data, LayerTypeDiameter, gopacket.NoCopy)
	}
}
