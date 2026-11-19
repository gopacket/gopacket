// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"
)

// Captures of decoded service bodies, trimmed from
// https://github.com/cisagov/icsnpp-opcua-binary (BSD-3-Clause):
// opcua-services.pcap holds a Call, a BrowseNext, a FindServers and a
// ServiceFault (frames 1-7) from four open62541 captures, then the Read
// of every built-in type of open62541_read_service_test_data.pcap;
// opcua-publish.pcap holds a CreateMonitoredItems response of 24 items
// and a Publish response with a DataChangeNotification, from
// opcua_with-gap.pcap. Expected values are from tshark 4.7.
var opcuaServicePcaps = []string{"opcua-services.pcap", "opcua-publish.pcap"}

// opcuaTyped reports whether a typed parameter field of s is set.
func opcuaTyped(s *OPCUAService) bool {
	v := reflect.ValueOf(s).Elem()
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if name == "RequestHeader" || name == "ResponseHeader" {
			continue
		}
		if f := v.Field(i); f.Kind() == reflect.Ptr && !f.IsNil() {
			return true
		}
	}
	return false
}

// opcuaPcapService returns the service of the first message of frame num.
func opcuaPcapService(t *testing.T, name string, num int) *OPCUAService {
	t.Helper()
	s := opcuaPacketMsg(t, name, num).Service
	if s == nil {
		t.Fatalf("%s #%d: no service", name, num)
	}
	return s
}

func nsString(ns uint16, s string) OPCUANodeID {
	return OPCUANodeID{Encoding: OPCUANodeIDString, Namespace: ns, StringID: s}
}

func nsNumeric(enc OPCUANodeIDEncoding, ns uint16, id uint32) OPCUANodeID {
	return OPCUANodeID{Encoding: enc, Namespace: ns, Numeric: id}
}

func TestOPCUAServicePcaps(t *testing.T) {
	// Every packet decodes; every whole service body gets typed fields.
	for _, name := range opcuaServicePcaps {
		for i, p := range readOPCUAPcap(t, name) {
			if el := p.ErrorLayer(); el != nil {
				t.Errorf("%s #%d: %v", name, i+1, el.Error())
			}
			for _, ua := range opcuaLayers(p) {
				if ua.Service == nil || !opcuaTyped(ua.Service) && ua.Service.ID != OPCUAServiceServiceFault {
					t.Errorf("%s #%d: %v not decoded", name, i+1, ua.Service)
				}
			}
		}
	}

	const svc = "opcua-services.pcap"
	call := opcuaPcapService(t, svc, 1).CallRequest
	wantCall := []OPCUACallMethodRequest{{
		ObjectID:       nsNumeric(OPCUANodeIDTwoByte, 0, 85),
		MethodID:       nsNumeric(OPCUANodeIDFourByte, 1, 62541),
		InputArguments: []OPCUAVariant{{Type: OPCUATypeString, Value: "Hello Server"}},
	}}
	if call == nil || !reflect.DeepEqual(call.MethodsToCall, wantCall) {
		t.Errorf("Call: %+v", call)
	}
	if res := opcuaPcapService(t, svc, 2).CallResponse; res == nil || len(res.Results) != 1 ||
		res.Results[0].StatusCode.String() != "BadNodeIdUnknown" {
		t.Errorf("Call response: %+v", res)
	}

	cp := []byte{0x23, 0x68, 0x38, 0xba, 0x29, 0xb5, 0x16, 0x7f, 0xfd, 0xdf, 0x7d, 0x07, 0x2f, 0xa2, 0x4a, 0x64}
	if bn := opcuaPcapService(t, svc, 3).BrowseNextRequest; bn == nil || bn.ReleaseContinuationPoints ||
		!reflect.DeepEqual(bn.ContinuationPoints, [][]byte{cp}) {
		t.Errorf("BrowseNext: %+v", bn)
	}
	bnr := opcuaPcapService(t, svc, 4).BrowseNextResponse
	wantRef := OPCUAReferenceDescription{
		ReferenceTypeID: nsNumeric(OPCUANodeIDTwoByte, 0, 45),
		IsForward:       true,
		NodeID:          nsNumeric(OPCUANodeIDFourByte, 0, 852),
		BrowseName:      OPCUAQualifiedName{Name: "ServerState"},
		DisplayName:     OPCUALocalizedText{Mask: 3, Text: "ServerState"},
		NodeClass:       OPCUANodeClassDataType,
	}
	if bnr == nil || !bytes.Equal(bnr.Results[0].ContinuationPoint, cp) ||
		!reflect.DeepEqual(bnr.Results[0].References, []OPCUAReferenceDescription{wantRef}) {
		t.Errorf("BrowseNext response: %+v", bnr)
	}

	if fs := opcuaPcapService(t, svc, 5).FindServersRequest; fs == nil || fs.EndpointURL != "" {
		t.Errorf("FindServers: %+v", fs)
	}
	servers := opcuaPcapService(t, svc, 6).FindServersResponse.Servers
	if len(servers) != 2 || servers[0].ApplicationURI != "urn:open62541.example.local_discovery_server" ||
		servers[0].ApplicationType != OPCUAApplicationDiscoveryServer || servers[0].ApplicationName.Locale != "en" ||
		!reflect.DeepEqual(servers[1].DiscoveryURLs, []string{"opc.tcp://Maui-16714:51944/", "opc.tcp://Maui-16714:51944/"}) {
		t.Errorf("FindServers response: %+v", servers)
	}

	fault := opcuaPcapService(t, svc, 7)
	if fault.ResponseHeader.ServiceResult.String() != "BadNoSubscription" || len(fault.Params) != 0 {
		t.Errorf("ServiceFault: %+v", fault)
	}
}

// TestOPCUAReadVariants checks the Read responses of every built-in
// type against tshark.
func TestOPCUAReadVariants(t *testing.T) {
	guid := func(s string) OPCUAGUID {
		var g OPCUAGUID
		var d1 uint32
		var d2, d3 uint16
		var d4 [8]byte
		fmt.Sscanf(s, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", &d1, &d2, &d3,
			&d4[0], &d4[1], &d4[2], &d4[3], &d4[4], &d4[5], &d4[6], &d4[7])
		binary.LittleEndian.PutUint32(g[0:], d1)
		binary.LittleEndian.PutUint16(g[4:], d2)
		binary.LittleEndian.PutUint16(g[6:], d3)
		copy(g[8:], d4[:])
		return g
	}
	dims := []int32{2, 2}
	dataValue := func(n int32, st OPCUAStatusCode, picos uint16) OPCUADataValue {
		return OPCUADataValue{
			Mask:              0x3F,
			Value:             OPCUAVariant{Type: OPCUATypeInt32, Value: n},
			Status:            st,
			SourcePicoseconds: picos,
			ServerPicoseconds: picos,
		}
	}
	cases := map[int]OPCUAVariant{
		10:  {Type: OPCUATypeBoolean, Value: false},
		18:  {Type: OPCUATypeBoolean, IsArray: true, Dimensions: dims, Value: []bool{false, true, false}},
		26:  {Type: OPCUATypeSByte, IsArray: true, Value: []int8{0, 127}},
		78:  {Type: OPCUATypeInt32, IsArray: true, Dimensions: dims, Value: []int32{0, 1073741823, 2147483647}},
		118: {Type: OPCUATypeString, Value: "This is a string variable"},
		130: {Type: OPCUATypeDateTime, Value: time.Date(2022, 10, 6, 16, 39, 39, 221441000, time.UTC)},
		142: {Type: OPCUATypeGUID, Value: guid("19982326-39d1-e659-fddf-3d13f79f2982")},
		154: {Type: OPCUATypeByteString, Value: []byte("This is a bytestring variable")},
		166: {Type: OPCUATypeNodeID, Value: OPCUANodeID{Encoding: OPCUANodeIDGUID, Namespace: 100,
			GUID: guid("7eea9d0e-6249-b7ae-eb1e-b1fb2ca27ac7")}},
		202: {Type: OPCUATypeExpandedNodeID, Value: nsString(1, "This is a ExpandedNodeId String variable")},
		250: {Type: OPCUATypeStatusCode, Value: OPCUAStatusCode(0)},
		262: {Type: OPCUATypeQualifiedName, Value: OPCUAQualifiedName{Namespace: 100, Name: "A Qualified Name Variable"}},
		274: {Type: OPCUATypeLocalizedText, Value: OPCUALocalizedText{Mask: 3, Locale: "en-US", Text: "A Localized Text Variable"}},
		310: {Type: OPCUATypeDataValue, IsArray: true, Dimensions: dims, Value: []OPCUADataValue{
			dataValue(1, 0x80070000, 1), dataValue(2, 0x81150000, 2), dataValue(3, 0x00A90000, 3)}},
		338: {Type: OPCUATypeFloat, IsArray: true, Dimensions: dims, Value: []float32{0, 3.14, 6.28, 12.56}},
		350: {Type: OPCUATypeDouble, IsArray: true, Dimensions: dims, Value: []float64{0, 0, 0, 0}},
	}
	for num, want := range cases {
		s := opcuaPcapService(t, "opcua-services.pcap", num)
		if s.ReadResponse == nil || len(s.ReadResponse.Results) != 1 {
			t.Errorf("#%d: %+v", num, s.ReadResponse)
			continue
		}
		got := s.ReadResponse.Results[0].Value
		if want.Type == OPCUATypeDataValue {
			// Timestamps are not compared.
			vals, ok := got.Value.([]OPCUADataValue)
			for i := range vals {
				vals[i].SourceTimestamp, vals[i].ServerTimestamp = time.Time{}, time.Time{}
			}
			if !ok {
				t.Errorf("#%d: %T", num, got.Value)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("#%d: got %#v, want %#v", num, got, want)
		}
	}

	// An ExtensionObject in a Variant keeps its body: here a
	// UserNameIdentityToken.
	ext := opcuaPcapService(t, "opcua-services.pcap", 286).ReadResponse.Results[0].Value.Value.(OPCUAExtensionObject)
	if ext.TypeID.Numeric != opcuaUserNameTokenID || ext.Encoding != 1 || !bytes.Contains(ext.Body, []byte("MyUserName")) {
		t.Errorf("ExtensionObject: %+v", ext)
	}

	diag := opcuaPcapService(t, "opcua-services.pcap", 314).ReadResponse.Results[0].Value.Value.(OPCUADiagnosticInfo)
	if diag.AdditionalInfo != "A DiagnosticInfo variable with additional information." {
		t.Errorf("DiagnosticInfo: %+v", diag)
	}
}

func TestOPCUASessionServices(t *testing.T) {
	const minimal = "opcua-minimal.pcap"
	cs := opcuaPcapService(t, minimal, 15).CreateSessionRequest
	if cs == nil || cs.SessionName != "Pure Python Client Session1" || cs.EndpointURL != "opc.tcp://localhost:4840/freeopcua/server/" ||
		cs.ClientDescription.ApplicationType != OPCUAApplicationClient || cs.RequestedSessionTimeout != 3600000 ||
		len(cs.ClientNonce) != 32 || cs.ClientCertificate != nil {
		t.Errorf("CreateSession: %+v", cs)
	}

	csr := opcuaPcapService(t, minimal, 17).CreateSessionResponse
	if csr == nil || csr.SessionID.String() != "i=14" || csr.AuthenticationToken.String() != "i=1004" ||
		csr.RevisedSessionTimeout != 3600000 || len(csr.ServerEndpoints) != 1 {
		t.Fatalf("CreateSession response: %+v", csr)
	}
	ep := csr.ServerEndpoints[0]
	if ep.EndpointURL != "opc.tcp://127.0.0.1:4840/freeopcua/server/" || ep.SecurityMode != OPCUASecurityModeNone ||
		ep.Server.ApplicationType != OPCUAApplicationClientAndServer || len(ep.UserIdentityTokens) != 3 ||
		ep.UserIdentityTokens[1] != (OPCUAUserTokenPolicy{PolicyID: "certificate_basic256sha256", TokenType: OPCUAUserTokenCertificate}) {
		t.Errorf("endpoint: %+v", ep)
	}

	act := opcuaPcapService(t, minimal, 19).ActivateSessionRequest
	if act == nil || !reflect.DeepEqual(act.LocaleIDs, []string{"en"}) ||
		act.ClientSignature.Algorithm != "http://www.w3.org/2000/09/xmldsig#rsa-sha1" ||
		!reflect.DeepEqual(act.IdentityToken, &OPCUAUserIdentityToken{TokenType: OPCUAUserTokenAnonymous, PolicyID: "anonymous"}) {
		t.Errorf("ActivateSession: %+v", act)
	}
	if ar := opcuaPcapService(t, minimal, 21).ActivateSessionResponse; ar == nil || len(ar.ServerNonce) != 32 || ar.Results != nil {
		t.Errorf("ActivateSession response: %+v", ar)
	}

	// UserName: the policy and the name, never the password.
	user := opcuaPcapService(t, "opcua-mainloop.pcap", 44).ActivateSessionRequest
	if tok := user.IdentityToken; tok == nil ||
		!reflect.DeepEqual(*tok, OPCUAUserIdentityToken{TokenType: OPCUAUserTokenUserName, PolicyID: "open62541-username-policy", UserName: "user1"}) {
		t.Errorf("UserName token: %+v", user.IdentityToken)
	}
	if !bytes.Contains(user.UserIdentityToken.Body, []byte("password")) {
		t.Error("raw token body lost")
	}

	if cl := opcuaPcapService(t, minimal, 35).CloseSessionRequest; cl == nil || !cl.DeleteSubscriptions {
		t.Errorf("CloseSession: %+v", cl)
	}

	ge := opcuaPcapService(t, "opcua-mainloop.pcap", 38).GetEndpointsResponse
	if ge == nil || len(ge.Endpoints) != 1 || ge.Endpoints[0].EndpointURL != "opc.tcp://localhost:4840" ||
		ge.Endpoints[0].SecurityPolicyURI != OPCUASecurityPolicyNone || ge.Endpoints[0].UserIdentityTokens[1].TokenType != OPCUAUserTokenUserName {
		t.Errorf("GetEndpoints response: %+v", ge)
	}
	if ge := opcuaPcapService(t, "opcua-getendpoints.pcap", 15).GetEndpointsResponse; ge == nil || ge.Endpoints != nil {
		t.Errorf("empty GetEndpoints response: %+v", ge)
	}
}

func TestOPCUANodeServices(t *testing.T) {
	const minimal = "opcua-minimal.pcap"
	br := opcuaPcapService(t, minimal, 23).BrowseRequest
	wantDesc := OPCUABrowseDescription{
		NodeID:          nsNumeric(OPCUANodeIDTwoByte, 0, 84),
		ReferenceTypeID: nsNumeric(OPCUANodeIDTwoByte, 0, 33),
		IncludeSubtypes: true,
		ResultMask:      0x3F,
	}
	if br == nil || !reflect.DeepEqual(br.NodesToBrowse, []OPCUABrowseDescription{wantDesc}) {
		t.Errorf("Browse: %+v", br)
	}

	refs := opcuaPcapService(t, minimal, 25).BrowseResponse.Results[0].References
	var names []string
	for _, r := range refs {
		names = append(names, fmt.Sprintf("%s %s %s %v", r.NodeID, r.BrowseName.Name, r.TypeDefinition, r.NodeClass))
	}
	want := []string{"i=85 Objects i=61 Object", "i=86 Types i=61 Object", "i=87 Views i=61 Object"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("Browse response: %q", names)
	}

	tr := opcuaPcapService(t, minimal, 27).TranslateBrowsePathsToNodeIDsRequest
	if tr == nil || len(tr.BrowsePaths) != 1 || len(tr.BrowsePaths[0].RelativePath) != 3 ||
		tr.BrowsePaths[0].RelativePath[2].TargetName != (OPCUAQualifiedName{Namespace: 2, Name: "MyVariable"}) {
		t.Errorf("Translate: %+v", tr)
	}
	trr := opcuaPcapService(t, minimal, 29).TranslateBrowsePathsToNodeIDsResponse
	wantTarget := []OPCUABrowsePathTarget{{TargetID: nsNumeric(OPCUANodeIDNumeric, 2, 2), RemainingPathIndex: math.MaxUint32}}
	if trr == nil || !reflect.DeepEqual(trr.Results[0].Targets, wantTarget) {
		t.Errorf("Translate response: %+v", trr)
	}

	const mainloop = "opcua-mainloop.pcap"
	if rd := opcuaPcapService(t, mainloop, 86).ReadResponse; rd == nil ||
		!reflect.DeepEqual(rd.Results, []OPCUADataValue{{Mask: opcuaDataValueStatus, Status: 0x80340000}}) {
		t.Errorf("Read response: %+v", rd)
	}

	wr := opcuaPcapService(t, mainloop, 88).WriteRequest
	wantWrite := []OPCUAWriteValue{{
		NodeID:      nsString(1, "the.answer"),
		AttributeID: OPCUAAttributeValue,
		Value:       OPCUADataValue{Mask: opcuaDataValueValue, Value: OPCUAVariant{Type: OPCUATypeInt32, Value: int32(1)}},
	}}
	if wr == nil || !reflect.DeepEqual(wr.NodesToWrite, wantWrite) {
		t.Errorf("Write: %+v", wr)
	}
	if res := opcuaPcapService(t, mainloop, 90).WriteResponse; res == nil ||
		!reflect.DeepEqual(res.Results, []OPCUAStatusCode{0x80340000}) {
		t.Errorf("Write response: %+v", res)
	}
}

func TestOPCUASubscriptionServices(t *testing.T) {
	const mainloop = "opcua-mainloop.pcap"
	cs := opcuaPcapService(t, mainloop, 56).CreateSubscriptionRequest
	wantCS := &OPCUACreateSubRequest{
		OPCUASubscriptionParams: OPCUASubscriptionParams{RequestedPublishingInterval: 500, RequestedLifetimeCount: 10000, RequestedMaxKeepAliveCount: 10},
		PublishingEnabled:       true,
	}
	if !reflect.DeepEqual(cs, wantCS) {
		t.Errorf("CreateSubscription: %+v", cs)
	}
	csr := opcuaPcapService(t, mainloop, 58).CreateSubscriptionResponse
	if csr == nil || csr.SubscriptionID != 1 || csr.RevisedPublishingInterval != 500 || csr.RevisedMaxKeepAliveCount != 10 {
		t.Errorf("CreateSubscription response: %+v", csr)
	}

	mi := opcuaPcapService(t, mainloop, 60).CreateMonitoredItemsRequest
	wantItem := OPCUAMonitoredItemCreate{
		ItemToMonitor:       OPCUAReadValueID{NodeID: nsString(1, "the.answer"), AttributeID: OPCUAAttributeValue},
		MonitoringMode:      OPCUAMonitoringReporting,
		RequestedParameters: OPCUAMonitoringParameters{ClientHandle: 1, SamplingInterval: 250, QueueSize: 1, DiscardOldest: true},
	}
	if mi == nil || mi.SubscriptionID != 1 || mi.TimestampsToReturn != OPCUATimestampsBoth ||
		!reflect.DeepEqual(mi.ItemsToCreate, []OPCUAMonitoredItemCreate{wantItem}) {
		t.Errorf("CreateMonitoredItems: %+v", mi)
	}

	if pr := opcuaPcapService(t, mainloop, 64).PublishRequest; pr == nil || pr.SubscriptionAcknowledgements != nil {
		t.Errorf("Publish: %+v", pr)
	}
	if pr := opcuaPcapService(t, mainloop, 80).PublishResponse; pr == nil || pr.SubscriptionID != 1 ||
		pr.NotificationMessage.SequenceNumber != 1 || pr.NotificationMessage.PublishTime.IsZero() {
		t.Errorf("Publish response: %+v", pr)
	}
	if ds := opcuaPcapService(t, mainloop, 96).DeleteSubscriptionsRequest; ds == nil || !reflect.DeepEqual(ds.SubscriptionIDs, []uint32{1}) {
		t.Errorf("DeleteSubscriptions: %+v", ds)
	}

	// 24 items; the ninth is refused.
	mir := opcuaPcapService(t, "opcua-publish.pcap", 1).CreateMonitoredItemsResponse
	if mir == nil || len(mir.Results) != 24 || mir.Results[0].MonitoredItemID != 831635093 ||
		mir.Results[8].StatusCode.String() != "BadNodeIdUnknown" || mir.Results[8].MonitoredItemID != 0 ||
		mir.Results[23].MonitoredItemID != 831635116 || mir.Results[0].RevisedSamplingInterval != 5 {
		t.Errorf("CreateMonitoredItems response: %+v", mir)
	}

	// The DataChangeNotification of 23 items, in tshark order.
	pub := opcuaPcapService(t, "opcua-publish.pcap", 2).PublishResponse
	if pub == nil || pub.SubscriptionID != 458500267 || !reflect.DeepEqual(pub.AvailableSequenceNumbers, []uint32{1}) ||
		len(pub.NotificationMessage.NotificationData) != 1 {
		t.Fatalf("Publish response: %+v", pub)
	}
	dc := pub.NotificationMessage.NotificationData[0].DataChange
	wantHandles := []uint32{6, 5, 4, 15, 14, 13, 24, 3, 2, 1, 23, 22, 21, 20, 19, 18, 17, 16, 8, 7, 12, 11, 10}
	var handles []uint32
	for _, it := range dc.MonitoredItems {
		handles = append(handles, it.ClientHandle)
	}
	if !reflect.DeepEqual(handles, wantHandles) {
		t.Errorf("handles %v", handles)
	}
	first, second := dc.MonitoredItems[0].Value, dc.MonitoredItems[1].Value
	if first.Value.Type != OPCUATypeBoolean || first.Value.Value != false || first.ServerTimestamp.IsZero() ||
		!reflect.DeepEqual(second.Value, OPCUAVariant{Type: OPCUATypeInt16, Value: int16(1)}) {
		t.Errorf("values %+v %+v", first, second)
	}
}

// uaBuilder appends OPC UA Binary values, for hand-built vectors.
type uaBuilder []byte

func (b uaBuilder) u8(v ...uint8) uaBuilder { return append(b, v...) }

func (b uaBuilder) u16(v uint16) uaBuilder { return binary.LittleEndian.AppendUint16(b, v) }

func (b uaBuilder) u32(v ...uint32) uaBuilder {
	for _, x := range v {
		b = binary.LittleEndian.AppendUint32(b, x)
	}
	return b
}

func (b uaBuilder) f64(v float64) uaBuilder {
	return binary.LittleEndian.AppendUint64(b, math.Float64bits(v))
}

func (b uaBuilder) str(s string) uaBuilder { return append(b.u32(uint32(len(s))), s...) }

// null appends a null String, ByteString or array.
func (b uaBuilder) null() uaBuilder { return b.u32(math.MaxUint32) }

// node appends a FourByte NodeId.
func (b uaBuilder) node(ns uint8, id uint16) uaBuilder { return b.u8(0x01, ns).u16(id) }

// ext appends an ExtensionObject with a binary body.
func (b uaBuilder) ext(id uint16, body []byte) uaBuilder {
	return b.node(0, id).u8(0x01).str(string(body))
}

// uaResponseHeader is a minimal ResponseHeader: handle 7, Good.
func uaResponseHeader() []byte {
	return uaBuilder(make([]byte, 8)).u32(7, 0).u8(0x00).null().u8(0x00, 0x00, 0x00)
}

// uaServiceMsg frames the parameters of service id behind its header.
func uaServiceMsg(id OPCUAServiceID, params []byte) []byte {
	b := uaBuilder{}.node(0, uint16(id))
	if id.IsRequest() {
		b = append(b, uaRequestHeader()...)
	} else {
		b = append(b, uaResponseHeader()...)
	}
	return uaMessage("MSG", OPCUAChunkFinal, uaSecure(append(b, params...)))
}

// decodeUAService decodes a message built by uaServiceMsg.
func decodeUAService(t *testing.T, msg []byte) *OPCUAService {
	t.Helper()
	p := decodeUA(msg)
	if el := p.ErrorLayer(); el != nil {
		t.Fatalf("error layer %v", el.Error())
	}
	ua, ok := p.Layer(LayerTypeOPCUA).(*OPCUA)
	if !ok || ua.Service == nil {
		t.Fatal("no service")
	}
	return ua.Service
}

// uaVector is a hand-built service body and the field it decodes to.
type uaVector struct {
	name   string
	id     OPCUAServiceID
	params []byte
	got    func(*OPCUAService) interface{}
	want   interface{}
}

// Services absent from the captures, built by hand after OPC 10000-4.
func uaVectors() []uaVector {
	b := uaBuilder{}
	params := OPCUAMonitoringParameters{ClientHandle: 1, SamplingInterval: 100, QueueSize: 10, DiscardOldest: true}
	paramsWire := b.u32(1).f64(100).u8(0, 0, 0).u32(10).u8(1)
	statusChange := b.u32(0x80760000).u8(0x00)
	events := b.u32(1, 4, 2).u8(0x0C).str("Boiler").u8(0x05).u16(500)
	return []uaVector{
		{"ModifySubscription", OPCUAServiceModifySubscriptionRequest, b.u32(5).f64(250).u32(100, 10, 0).u8(3),
			func(s *OPCUAService) interface{} { return s.ModifySubscriptionRequest },
			&OPCUAModifySubRequest{SubscriptionID: 5, OPCUASubscriptionParams: OPCUASubscriptionParams{250, 100, 10, 0}, Priority: 3}},
		{"ModifySubscription resp", OPCUAServiceModifySubscriptionResponse, b.f64(500).u32(300, 20),
			func(s *OPCUAService) interface{} { return s.ModifySubscriptionResponse },
			&OPCUASubscriptionRevision{RevisedPublishingInterval: 500, RevisedLifetimeCount: 300, RevisedMaxKeepAliveCount: 20}},
		{"SetPublishingMode", OPCUAServiceSetPublishingModeRequest, b.u8(1).u32(2, 5, 6),
			func(s *OPCUAService) interface{} { return s.SetPublishingModeRequest },
			&OPCUASetPublishingRequest{PublishingEnabled: true, SubscriptionIDs: []uint32{5, 6}}},
		{"SetPublishingMode resp", OPCUAServiceSetPublishingModeResponse, b.u32(2, 0, 0x80790000).null(),
			func(s *OPCUAService) interface{} { return s.SetPublishingModeResponse },
			&OPCUAResults{Results: []OPCUAStatusCode{0, 0x80790000}}},
		{"DeleteSubscriptions resp", OPCUAServiceDeleteSubscriptionsResponse, b.u32(1, 0, 1).u8(0x01).u32(2),
			func(s *OPCUAService) interface{} { return s.DeleteSubscriptionsResponse },
			&OPCUAResults{Results: []OPCUAStatusCode{0}, DiagnosticInfos: []OPCUADiagnosticInfo{
				{Mask: 1, SymbolicID: 2, NamespaceURI: -1, Locale: -1, LocalizedText: -1}}}},
		{"Republish", OPCUAServiceRepublishRequest, b.u32(5, 9),
			func(s *OPCUAService) interface{} { return s.RepublishRequest },
			&OPCUARepublishRequest{SubscriptionID: 5, RetransmitSequenceNumber: 9}},
		{"Republish resp", OPCUAServiceRepublishResponse, b.u32(9).u8(make([]byte, 8)...).u32(1).ext(opcuaStatusChangeNotifID, statusChange),
			func(s *OPCUAService) interface{} {
				return s.RepublishResponse.NotificationMessage.NotificationData[0].StatusChange
			},
			&OPCUAStatusChangeNotification{Status: 0x80760000, DiagnosticInfo: OPCUADiagnosticInfo{SymbolicID: -1, NamespaceURI: -1, Locale: -1, LocalizedText: -1}}},
		{"Publish events", OPCUAServicePublishResponse,
			b.u32(1, 1, 3).u8(0).u32(3).u8(make([]byte, 8)...).u32(1).ext(opcuaEventNotifListID, events).u32(1, 0).null(),
			func(s *OPCUAService) interface{} {
				return s.PublishResponse.NotificationMessage.NotificationData[0].Events
			},
			&OPCUAEventNotificationList{Events: []OPCUAEventFieldList{{ClientHandle: 4, EventFields: []OPCUAVariant{
				{Type: OPCUATypeString, Value: "Boiler"}, {Type: OPCUATypeUInt16, Value: uint16(500)}}}}}},
		{"ModifyMonitoredItems", OPCUAServiceModifyMonitoredItemsRequest, append(b.u32(5, 2, 1, 7), paramsWire...),
			func(s *OPCUAService) interface{} { return s.ModifyMonitoredItemsRequest },
			&OPCUAModifyItemsRequest{SubscriptionID: 5, TimestampsToReturn: OPCUATimestampsBoth,
				ItemsToModify: []OPCUAMonitoredItemModify{{MonitoredItemID: 7, RequestedParameters: params}}}},
		{"ModifyMonitoredItems resp", OPCUAServiceModifyMonitoredItemsResponse, b.u32(1, 0).f64(100).u32(10).u8(0, 0, 0).null(),
			func(s *OPCUAService) interface{} { return s.ModifyMonitoredItemsResponse },
			&OPCUAModifyItemsResponse{Results: []OPCUAMonitoredItemModifyResult{
				{OPCUAMonitoredItemRevision: OPCUAMonitoredItemRevision{RevisedSamplingInterval: 100, RevisedQueueSize: 10}}}}},
		{"SetMonitoringMode", OPCUAServiceSetMonitoringModeRequest, b.u32(5, 1, 2, 7, 8),
			func(s *OPCUAService) interface{} { return s.SetMonitoringModeRequest },
			&OPCUASetMonitoringRequest{SubscriptionID: 5, MonitoringMode: OPCUAMonitoringSampling, MonitoredItemIDs: []uint32{7, 8}}},
		{"SetMonitoringMode resp", OPCUAServiceSetMonitoringModeResponse, b.u32(2, 0, 0).null(),
			func(s *OPCUAService) interface{} { return s.SetMonitoringModeResponse },
			&OPCUAResults{Results: []OPCUAStatusCode{0, 0}}},
		{"DeleteMonitoredItems", OPCUAServiceDeleteMonitoredItemsRequest, b.u32(5, 1, 7),
			func(s *OPCUAService) interface{} { return s.DeleteMonitoredItemsRequest },
			&OPCUADeleteItemsRequest{SubscriptionID: 5, MonitoredItemIDs: []uint32{7}}},
		{"DeleteMonitoredItems resp", OPCUAServiceDeleteMonitoredItemsResponse, b.u32(1, 0x80420000).null(),
			func(s *OPCUAService) interface{} { return s.DeleteMonitoredItemsResponse },
			&OPCUAResults{Results: []OPCUAStatusCode{0x80420000}}},
		{"RegisterNodes", OPCUAServiceRegisterNodesRequest, b.u32(2).u8(0x03).u16(2).str("Pump").u8(0x01, 0x00).u16(2258),
			func(s *OPCUAService) interface{} { return s.RegisterNodesRequest },
			&OPCUANodeIDList{NodeIDs: []OPCUANodeID{nsString(2, "Pump"), nsNumeric(OPCUANodeIDFourByte, 0, 2258)}}},
		{"RegisterNodes resp", OPCUAServiceRegisterNodesResponse, b.u32(1).node(2, 1),
			func(s *OPCUAService) interface{} { return s.RegisterNodesResponse },
			&OPCUANodeIDList{NodeIDs: []OPCUANodeID{nsNumeric(OPCUANodeIDFourByte, 2, 1)}}},
		{"UnregisterNodes", OPCUAServiceUnregisterNodesRequest, b.u32(1).node(2, 1),
			func(s *OPCUAService) interface{} { return s.UnregisterNodesRequest },
			&OPCUANodeIDList{NodeIDs: []OPCUANodeID{nsNumeric(OPCUANodeIDFourByte, 2, 1)}}},
		{"HistoryRead", OPCUAServiceHistoryReadRequest,
			b.ext(649, []byte{1, 2, 3}).u32(0).u8(0).u32(1).u8(0x03).u16(2).str("Temp").null().u16(0).null().null(),
			func(s *OPCUAService) interface{} { return s.HistoryReadRequest },
			&OPCUAHistoryReadRequest{
				HistoryReadDetails: OPCUAExtensionObject{TypeID: nsNumeric(OPCUANodeIDFourByte, 0, 649), Encoding: 1, Body: []byte{1, 2, 3}},
				NodesToRead:        []OPCUAHistoryReadValueID{{NodeID: nsString(2, "Temp")}},
			}},
		{"HistoryRead resp", OPCUAServiceHistoryReadResponse, b.u32(1, 0).str("cp").ext(658, []byte{9}).null(),
			func(s *OPCUAService) interface{} { return s.HistoryReadResponse },
			&OPCUAHistoryReadResponse{Results: []OPCUAHistoryReadResult{{
				ContinuationPoint: []byte("cp"),
				HistoryData:       OPCUAExtensionObject{TypeID: nsNumeric(OPCUANodeIDFourByte, 0, 658), Encoding: 1, Body: []byte{9}},
			}}}},
		{"X509 token", OPCUAServiceActivateSessionRequest,
			b.null().null().null().null().ext(opcuaX509TokenID, b.str("x509").str("DER")).null().null(),
			func(s *OPCUAService) interface{} { return s.ActivateSessionRequest.IdentityToken },
			&OPCUAUserIdentityToken{TokenType: OPCUAUserTokenCertificate, PolicyID: "x509", CertificateData: []byte("DER")}},
		{"issued token", OPCUAServiceActivateSessionRequest,
			b.null().null().null().null().ext(opcuaIssuedTokenID, b.str("jwt").str("secret").str("rsa-oaep")).null().null(),
			func(s *OPCUAService) interface{} { return s.ActivateSessionRequest.IdentityToken },
			&OPCUAUserIdentityToken{TokenType: OPCUAUserTokenIssued, PolicyID: "jwt", EncryptionAlgorithm: "rsa-oaep"}},
		{"Call arguments", OPCUAServiceCallRequest,
			b.u32(1).node(0, 85).node(1, 2).u32(4).u8(0x10).str("<a/>").u8(0x80).u32(3).
				u8(0x18, 0x06).u32(7).u8(0x92).u32(1).u8(0xC1, 0x00, 0x05, 0x00).str("urn:x").u32(2),
			func(s *OPCUAService) interface{} { return s.CallRequest.MethodsToCall[0].InputArguments },
			[]OPCUAVariant{
				{Type: OPCUATypeXMLElement, Value: "<a/>"},
				{Type: OPCUATypeNull, IsArray: true},
				{Type: OPCUATypeVariant, Value: OPCUAVariant{Type: OPCUATypeInt32, Value: int32(7)}},
				{Type: OPCUATypeExpandedNodeID, IsArray: true, Value: []OPCUANodeID{
					{Encoding: OPCUANodeIDFourByte, Numeric: 5, NamespaceURI: "urn:x", ServerIndex: 2}}},
			}},
		{"unknown token", OPCUAServiceActivateSessionRequest,
			b.null().null().null().null().ext(999, b.str("x")).null().null(),
			func(s *OPCUAService) interface{} { return s.ActivateSessionRequest.IdentityToken },
			(*OPCUAUserIdentityToken)(nil)},
	}
}

func TestOPCUAHandBuilt(t *testing.T) {
	for _, v := range uaVectors() {
		s := decodeUAService(t, uaServiceMsg(v.id, v.params))
		if s.ID != v.id || len(s.Params) != 0 {
			t.Errorf("%s: id %v, %d bytes left", v.name, s.ID, len(s.Params))
			continue
		}
		if got := v.got(s); !reflect.DeepEqual(got, v.want) {
			t.Errorf("%s: got %+v, want %+v", v.name, got, v.want)
		}
	}

	// Without parameters there is no typed field.
	for _, id := range []OPCUAServiceID{OPCUAServiceUnregisterNodesResponse, OPCUAServiceCloseSessionResponse} {
		if s := decodeUAService(t, uaServiceMsg(id, nil)); opcuaTyped(s) || len(s.Params) != 0 {
			t.Errorf("%v: %+v", id, s)
		}
	}
}

// TestOPCUAParamsCut checks that parameters cut at every offset leave the
// header decoded and the rest raw, without an error.
func TestOPCUAParamsCut(t *testing.T) {
	for _, v := range uaVectors() {
		for i := 0; i < len(v.params); i++ {
			s := decodeUAService(t, uaServiceMsg(v.id, v.params[:i]))
			if opcuaTyped(s) || !bytes.Equal(s.Params, v.params[:i]) || s.RequestHeader == nil && s.ResponseHeader == nil {
				t.Errorf("%s cut at %d: %+v", v.name, i, s)
				break
			}
		}
	}
}

// uaNestedVariant is a Write of one Variant nested levels deep: arrays of
// one Variant around an Int32.
func uaNestedVariant(levels int) []byte {
	b := uaBuilder{}.u32(1).node(1, 1).u32(13).null().u8(opcuaDataValueValue)
	for i := 1; i < levels; i++ {
		b = b.u8(opcuaVariantArray | uint8(OPCUATypeVariant)).u32(1)
	}
	return b.u8(uint8(OPCUATypeInt32)).u32(42)
}

func TestOPCUAMalformedParams(t *testing.T) {
	b := uaBuilder{}
	cases := []struct {
		name   string
		id     OPCUAServiceID
		params []byte
	}{
		{"DataValue count lie", OPCUAServiceReadResponse, b.u32(0x7FFFFFFF).u8(0)},
		{"negative count", OPCUAServiceReadResponse, b.u32(0xFFFFFFFE)},
		{"nested reference lie", OPCUAServiceBrowseResponse, b.u32(1, 0).null().u32(0x10000000)},
		{"string lie", OPCUAServiceCallRequest, b.u32(1).node(0, 85).node(1, 2).u32(1).u8(0x0C).u32(0x7FFFFFF0)},
		{"nested claims", OPCUAServiceReadResponse, b.u32(2).u8(0x01, 0x80|uint8(OPCUATypeVariant)).u32(3).u8(0, 0)},
		{"too deep", OPCUAServiceWriteRequest, uaNestedVariant(opcuaMaxValueDepth)},
		{"dims count lie", OPCUAServiceReadResponse, b.u32(1).u8(0x01, 0xC6).u32(1, 1, 0x7FFFFFFF)},
		{"dims without array", OPCUAServiceReadResponse, b.u32(1).u8(0x01, 0x46).u32(1)},
		{"type 26", OPCUAServiceReadResponse, b.u32(1).u8(0x01, 26).u32(0)},
		{"reserved encoding", OPCUAServiceWriteRequest, b.u32(1).u8(0x06)},
	}
	for _, c := range cases {
		msg := uaServiceMsg(c.id, c.params)
		s := decodeUAService(t, msg)
		if opcuaTyped(s) || !bytes.Equal(s.Params, c.params) {
			t.Errorf("%s: %+v", c.name, s)
		}
	}

	// One level shallower decodes.
	s := decodeUAService(t, uaServiceMsg(OPCUAServiceWriteRequest, uaNestedVariant(opcuaMaxValueDepth-1)))
	if s.WriteRequest == nil {
		t.Fatal("nesting at the limit refused")
	}
	v := s.WriteRequest.NodesToWrite[0].Value.Value
	for i := 1; i < opcuaMaxValueDepth-1; i++ {
		v = v.Value.([]OPCUAVariant)[0]
	}
	if v.Value != int32(42) {
		t.Errorf("innermost %+v", v)
	}

	// Huge dimensions are kept as numbers, never allocated from.
	huge := b.u32(1).u8(0x01, 0xC6).u32(1, 1, 2, 0x7FFFFFFF, 0x7FFFFFFF).null()
	s = decodeUAService(t, uaServiceMsg(OPCUAServiceReadResponse, huge))
	if got := s.ReadResponse.Results[0].Value; !reflect.DeepEqual(got.Dimensions, []int32{0x7FFFFFFF, 0x7FFFFFFF}) {
		t.Errorf("dims %+v", got)
	}
}

// TestOPCUAMinSizes checks that each array element minimum is reachable:
// a run of elements of exactly that size decodes.
func TestOPCUAMinSizes(t *testing.T) {
	b := uaBuilder{}
	qname := b.u16(0).null()
	appDesc := b.null().null().u8(0).u32(0).null().null().null()
	cases := []struct {
		name    string
		minSize int
		elem    []byte
		read    func(r *opcuaReader) int
	}{
		{"ApplicationDescription", opcuaMinAppDescLen, appDesc,
			func(r *opcuaReader) int { return len(opcuaArray(r, opcuaMinAppDescLen, r.applicationDescription)) }},
		{"EndpointDescription", opcuaMinEndpointLen, append(append(b.null(), appDesc...), b.null().u32(0).null().null().null().u8(0)...),
			func(r *opcuaReader) int { return len(r.endpoints()) }},
		{"UserTokenPolicy", opcuaMinTokenPolLen, b.null().u32(0).null().null().null(),
			func(r *opcuaReader) int { return len(opcuaArray(r, opcuaMinTokenPolLen, r.userTokenPolicy)) }},
		{"SignedSoftwareCertificate", opcuaMinSoftCertLen, b.null().null(),
			func(r *opcuaReader) int { return len(r.softwareCerts()) }},
		{"WriteValue", opcuaMinWriteValueLen, b.u8(0, 0).u32(0).null().u8(0),
			func(r *opcuaReader) int { return len(r.writeRequest().NodesToWrite) }},
		{"BrowseDescription", opcuaMinBrowseDescLen, b.u8(0, 0).u32(0).u8(0, 0, 0).u32(0, 0),
			func(r *opcuaReader) int { return len(opcuaArray(r, opcuaMinBrowseDescLen, r.browseDescription)) }},
		{"BrowseResult", opcuaMinBrowseResLen, b.u32(0).null().null(),
			func(r *opcuaReader) int { return len(opcuaArray(r, opcuaMinBrowseResLen, r.browseResult)) }},
		{"ReferenceDescription", opcuaMinRefDescLen, append(append(b.u8(0, 0, 0, 0, 0), qname...), b.u8(0).u32(0).u8(0, 0)...),
			func(r *opcuaReader) int { return len(opcuaArray(r, opcuaMinRefDescLen, r.referenceDescription)) }},
		{"RelativePathElement", opcuaMinPathElemLen, append(b.u8(0, 0, 0, 0), qname...),
			func(r *opcuaReader) int { return len(opcuaArray(r, opcuaMinPathElemLen, r.pathElement)) }},
		{"BrowsePathResult", opcuaMinPathResultLen, b.u32(0).null(),
			func(r *opcuaReader) int { return len(opcuaArray(r, opcuaMinPathResultLen, r.pathResult)) }},
		{"CallMethodResult", opcuaMinCallResultLen, b.u32(0).null().null().null(),
			func(r *opcuaReader) int { return len(opcuaArray(r, opcuaMinCallResultLen, r.callResult)) }},
		{"HistoryReadValueId", opcuaMinHistReadIDLen, append(b.u8(0, 0).null(), append(qname, b.null()...)...),
			func(r *opcuaReader) int { return len(opcuaArray(r, opcuaMinHistReadIDLen, r.historyReadValueID)) }},
		{"MonitoredItemCreateResult", opcuaMinCreateResLen, b.u32(0, 0).f64(0).u32(0).u8(0, 0, 0),
			func(r *opcuaReader) int { return len(r.createItemsResponse().Results) }},
		{"MonitoredItemCreateRequest", opcuaMinItemCreateLen,
			append(append(b.u8(0, 0).u32(0).null(), qname...), b.u32(0).u32(0).f64(0).u8(0, 0, 0).u32(0).u8(0)...),
			func(r *opcuaReader) int { return len(opcuaArray(r, opcuaMinItemCreateLen, r.itemCreate)) }},
		{"Variant", opcuaMinMaskedLen, []byte{0}, func(r *opcuaReader) int { return len(r.variants(0)) }},
		{"DataValue", opcuaMinMaskedLen, []byte{0}, func(r *opcuaReader) int { return len(r.dataValues(0)) }},
		{"LocalizedText", opcuaMinMaskedLen, []byte{0}, func(r *opcuaReader) int {
			return len(opcuaArray(r, opcuaMinMaskedLen, r.localizedText))
		}},
	}
	const count = 3
	for _, c := range cases {
		if len(c.elem) != c.minSize {
			t.Errorf("%s: minimal element is %d bytes, constant %d", c.name, len(c.elem), c.minSize)
			continue
		}
		data := uaBuilder{}.u32(count)
		for i := 0; i < count; i++ {
			data = append(data, c.elem...)
		}
		// Trailing DiagnosticInfo arrays of the responses.
		data = data.null()
		r := &opcuaReader{b: data}
		if n := c.read(r); n != count || r.err != nil {
			t.Errorf("%s: %d elements, %v", c.name, n, r.err)
		}
	}
}

// A Read response of empty DataValues costs its structs, allocated once,
// and arrays nested in arrays cannot claim the same bytes twice.
func TestOPCUAAllocBound(t *testing.T) {
	const values = 60000
	const maxPerByte = 160

	data := uaBuilder{}.u32(values).u8(make([]byte, values)...).null()
	got := allocPerByte(len(data), func() {
		r := &opcuaReader{b: data}
		_ = r.readResponse()
	})
	t.Logf("OPC UA DataValues: %.0f bytes per input byte", got)
	if got > maxPerByte {
		t.Errorf("DataValues allocate %.0f bytes per input byte, want <= %d", got, maxPerByte)
	}

	// Each level claims all the bytes after it; only the first fits.
	nested := uaBuilder{}
	for i := 0; i < opcuaMaxValueDepth-1; i++ {
		nested = nested.u8(opcuaVariantArray | uint8(OPCUATypeVariant)).u32(values)
	}
	nested = append(nested, make([]byte, values)...)
	got = allocPerByte(len(nested), func() {
		r := &opcuaReader{b: nested}
		_ = r.variant(0)
	})
	t.Logf("OPC UA nested Variants: %.0f bytes per input byte", got)
	if got > maxPerByte {
		t.Errorf("nested Variants allocate %.0f bytes per input byte, want <= %d", got, maxPerByte)
	}
}

// TestOPCUAServiceTruncation cuts every message of the service captures
// and every hand-built vector at every offset.
func TestOPCUAServiceTruncation(t *testing.T) {
	var msgs [][]byte
	for _, name := range opcuaServicePcaps {
		for _, p := range readOPCUAPcap(t, name) {
			for _, ua := range opcuaLayers(p) {
				msgs = append(msgs, ua.Contents)
			}
		}
	}
	for _, v := range uaVectors() {
		msgs = append(msgs, uaServiceMsg(v.id, v.params))
	}

	for _, msg := range msgs {
		for i := 0; i < len(msg); i++ {
			decodeOPCUAAll(msg[:i:i])
		}
	}
}

// uaVectorSeeds returns the hand-built vectors as service bodies.
func uaVectorSeeds() [][]byte {
	var out [][]byte
	for _, v := range uaVectors() {
		out = append(out, uaServiceMsg(v.id, v.params)[opcuaHeaderLen+16:])
	}
	return append(out, uaServiceMsg(OPCUAServiceWriteRequest, uaNestedVariant(opcuaMaxValueDepth-1))[opcuaHeaderLen+16:])
}

func FuzzOPCUAServices(f *testing.F) {
	for _, body := range uaVectorSeeds() {
		f.Add(body)
	}
	for _, name := range opcuaServicePcaps {
		for _, p := range readOPCUAPcap(f, name) {
			for _, ua := range opcuaLayers(p) {
				f.Add(ua.Body)
			}
		}
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		decodeOPCUAAll(uaMessage("MSG", OPCUAChunkFinal, uaSecure(body)))

		s := decodeOPCUAService(body)
		if s == nil {
			return
		}
		if !bytes.HasSuffix(body, s.Params) {
			t.Fatalf("Params is not the tail of the body")
		}
		_ = fmt.Sprintf("%+v", s)
	})
}
