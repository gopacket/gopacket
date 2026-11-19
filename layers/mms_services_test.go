// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// Vectors for the MMS services typed after read/write. Sources:
//
//	iti       ITI/ICS-Security-Tools pcaps/IEC61850/MMS - Specific Commands
//	          (MMS straight after COTP; PDUs copied as hex, decoded by tshark 4.7)
//	captures  getVariableAccessAttributes responses of iec61850_mms_siemens.pcap
//	hand      built from ISO 9506-2; no public capture holds them. Each was
//	          wrapped in TPKT/COTP/session/presentation and decoded by tshark
//	          4.7 to check the encoding, except for the TypeSpecification
//	          alternatives tshark does not know (floating-point, mMSString,
//	          utc-time).

// mmsCtx encodes a context class TLV; tags of 31 and up use the high tag
// number form, e.g. [72] constructed = bf 48 len.
func mmsCtx(tag int, form osiBERForm, parts ...[]byte) []byte {
	id := byte(0x80)
	if form == osiBERConstructed {
		id |= osiBERFormBit
	}
	if tag < osiBERHighTag {
		return iecTLV(id|byte(tag), parts...)
	}

	t := iecTLV(id|osiBERHighTag, parts...)
	return append([]byte{t[0], byte(tag)}, t[1:]...)
}

// Shorthands for the vectors: constructed and primitive context TLVs,
// VisibleString, GraphicString, confirmed request and response.
func mc(tag int, parts ...[]byte) []byte { return mmsCtx(tag, osiBERConstructed, parts...) }
func mp(tag int, parts ...[]byte) []byte { return mmsCtx(tag, osiBERPrimitive, parts...) }
func mvs(s string) []byte                { return iecTLV(0x1a, []byte(s)) }
func mgs(s string) []byte                { return iecTLV(0x19, []byte(s)) }
func mreq(svc []byte) []byte             { return iecTLV(0xa0, iecTLV(0x02, []byte{1}), svc) }
func mresp(svc []byte) []byte            { return iecTLV(0xa1, iecTLV(0x02, []byte{1}), svc) }
func mdom(d, i string) []byte            { return mc(1, mvs(d), mvs(i)) }
func mvmd(s string) []byte               { return mp(0, []byte(s)) }

func mhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type mmsVector struct {
	name  string
	pdu   []byte
	check func(m *MMS) bool
}

// mmsTypeVector is a structure type with every TypeSpecification
// alternative, used by a getVariableAccessAttributes response.
func mmsTypeVector() []byte {
	comp := func(name string, typ []byte) []byte {
		if name == "" {
			return iecTLV(0x30, mc(1, typ))
		}
		return iecTLV(0x30, mp(0, []byte(name)), mc(1, typ))
	}
	return mc(2, mp(0, []byte{0xff}), mc(1,
		comp("arr", mc(1, mp(1, []byte{10}), mc(2, mp(5, []byte{16})))),
		comp("f", mc(7, iecTLV(0x02, []byte{32}), iecTLV(0x02, []byte{8}))),
		comp("tn", mc(0, mdom("LD0", "T1"))),
		comp("bt", mp(12, []byte{0xff})),
		comp("ms", mp(16, []byte{64})),
		comp("os", mp(9, []byte{0xff, 0x00})),
		comp("", mp(3)),
		comp("u", mp(6, []byte{32})),
		comp("b", mp(13, []byte{4})),
		comp("o", mp(15)),
		comp("g", mp(11)),
		comp("utc", mp(17)),
	))
}

// mmsAltVector is an AlternateAccess body with every form:
// selectAlternateAccess, named, allElements and component.
func mmsAltVector() []byte {
	return bytes.Join([][]byte{
		mc(0, mp(0, []byte("mag")), iecTLV(0x30, mp(2, []byte{3}))),
		mc(5, mp(0, []byte("nm")), mc(3, mp(0, []byte{2}), mp(1, []byte{4}))),
		mp(4),
		mp(1, []byte("q")),
	}, nil)
}

func mmsWantAlt() []MMSAlternateAccess {
	return []MMSAlternateAccess{
		{Selection: MMSAltComponent, Component: "mag", SelectAlternate: true,
			Nested: []MMSAlternateAccess{{Selection: MMSAltIndex, Index: 3}}},
		{Named: true, Name: "nm", Selection: MMSAltIndexRange, Index: 2, Count: 4},
		{Selection: MMSAltAllElements},
		{Selection: MMSAltComponent, Component: "q"},
	}
}

var mmsTOD = mhex("000003e8") // 1 s after midnight, no date

func mmsBaseVectors() []mmsVector {
	ld0 := MMSObjectName{MMSScopeDomain, "LD0", "DS1"}
	vmd := func(s string) MMSObjectName { return MMSObjectName{Scope: MMSScopeVMD, ItemID: s} }
	piName := "R395024397Application_1"
	tod := mmsTimeOfDayEpoch.Add(time.Second)

	return []mmsVector{
		// iti captures.
		{"iti deleteProgramInvocation", mhex("a01e0201019f27184d7553656375726974795f4170706c69636174696f6e5f31"), func(m *MMS) bool {
			return m.Service == MMSDeleteProgramInvocation && m.ProgramReq.Name == "MuSecurity_Application_1"
		}},
		{"iti getAlarmSummary", mhex("a00c020101bf3f06800100810100"), func(m *MMS) bool {
			return *m.AlarmSummaryReq == MMSAlarmSummaryRequest{}
		}},
		{"iti getDomainAttributes", mhex("a0160201019f251044544c6f6746696c6573446f6d61696e"), func(m *MMS) bool {
			return m.DomainReq.DomainName == "DTLogFilesDomain"
		}},
		{"iti initiateDownloadSequence", mhex("a029020101ba24801044544c6f6746696c6573446f6d61696ea10d1a0b4d7553656341433830304d820100"), func(m *MMS) bool {
			return reflect.DeepEqual(*m.DomainReq, MMSDomainRequest{DomainName: "DTLogFilesDomain", Capabilities: []string{"MuSecAC800M"}})
		}},
		{"iti initiateUploadSequence", mhex("a0150201019d1044544c6f6746696c6573446f6d61696e"), func(m *MMS) bool {
			return m.DomainReq.DomainName == "DTLogFilesDomain"
		}},
		{"iti terminateUploadSequence", mhex("a0080201019f1f020000"), func(m *MMS) bool {
			return m.Service == MMSTerminateUploadSequence && m.DomainReq.ULSMID == 0
		}},
		{"iti kill", mhex("a01f020101bf2c198017523339353032343339374170706c69636174696f6e5f31"), func(m *MMS) bool {
			return m.ProgramReq.Name == piName
		}},
		{"iti reset", mhex("a01f020101bf2b198017523339353032343339374170706c69636174696f6e5f31"), func(m *MMS) bool {
			return m.Service == MMSReset && m.ProgramReq.Name == piName
		}},
		{"iti resume", mhex("a01f020101bf2a198017523339353032343339374170706c69636174696f6e5f31"), func(m *MMS) bool {
			return m.Service == MMSResume && m.ProgramReq.Name == piName
		}},
		{"iti stop", mhex("a01f020101bf29198017523339353032343339374170706c69636174696f6e5f31"), func(m *MMS) bool {
			return m.Service == MMSStop && m.ProgramReq.Name == piName
		}},
		{"iti start", mhex("a021020101bf281b8017523339353032343339374170706c69636174696f6e5f318100"), func(m *MMS) bool {
			return reflect.DeepEqual(*m.ProgramReq, MMSProgramRequest{Name: piName, Reusable: true})
		}},
		{"iti takeControl untyped", mhex("a017020101b312a00a80087265736572766564830101860101"), func(m *MMS) bool {
			return m.Service == MMSTakeControl && m.ServiceDecodeErr == nil && len(m.ServiceData) == 18
		}},

		// Variable access.
		{"getVariableAccessAttributes address", mreq(mc(6, mc(1, mp(0, []byte{0x10})))), func(m *MMS) bool {
			return m.ObjectName == nil && m.VariableAddress.Kind == MMSAddressNumeric && m.VariableAddress.Numeric == 16
		}},
		{"getVariableAccessAttributes symbolic", mreq(mc(6, mc(1, mp(1, []byte("MW100"))))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.VariableAddress, MMSAddress{Kind: MMSAddressSymbolic, Symbolic: "MW100"})
		}},
		{"getVariableAccessAttributes response", mresp(mc(6, mp(0, []byte{0xff}), mc(1, mp(1, []byte("%M"))), mc(2, mmsTypeVector()))), func(m *MMS) bool {
			va := m.VariableAttributes
			return va.Deletable && va.HasAddress && va.Address.Symbolic == "%M" && mmsCheckTypes(&va.Type)
		}},
		{"read alternate access", mreq(mc(4, mc(1, mc(0, iecTLV(0x30, mc(0, mvmd("V")), mc(5, mmsAltVector())))))), func(m *MMS) bool {
			v := m.ReadReq.Access.Variables[0]
			return v.Name == vmd("V") && reflect.DeepEqual(v.Alternate, mmsWantAlt()) && len(v.AlternateAccess) == len(mmsAltVector())
		}},
		{"read variable forms", mreq(mc(4, mc(1, mc(0,
			iecTLV(0x30, mc(1, mp(0, []byte{0x10}))),
			iecTLV(0x30, mc(1, mp(1, []byte("MW100")))),
			iecTLV(0x30, mc(1, mp(2, []byte{1, 2, 3}))),
			iecTLV(0x30, mc(2, mp(0, []byte{5}), mp(5, []byte{8}))),
			iecTLV(0x30, mc(3, iecTLV(0x30, mp(0, []byte("c")), mc(1, mc(0, mvmd("x")))))),
			iecTLV(0x30, mp(4)),
		)))), func(m *MMS) bool {
			v := m.ReadReq.Access.Variables
			return len(v) == 6 && v[0].Address.Numeric == 16 && v[1].Address.Symbolic == "MW100" &&
				bytes.Equal(v[2].Address.Unconstrained, []byte{1, 2, 3}) && v[3].Kind == MMSVariableDescription &&
				v[3].Address.Numeric == 5 && v[3].Type.Kind == MMSTypeInteger && v[3].Type.Size == 8 &&
				v[4].Kind == MMSVariableScattered && len(v[4].Spec) == 12 && v[5].Kind == MMSVariableInvalidated
		}},
		{"deleteNamedVariableList", mreq(mc(13, mp(0, []byte{0}), mc(1, mdom("LD0", "DS1"), mvmd("DS2")), mp(2, []byte("LD0")))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.DeleteReq, MMSDeleteRequest{MMSDeleteScopeSpecific, []MMSObjectName{ld0, vmd("DS2")}, "LD0"})
		}},
		{"deleteNamedVariableList response", mresp(mc(13, mp(0, []byte{2}), mp(1, []byte{1}))), func(m *MMS) bool {
			return *m.DeleteResp == MMSDeleteResponse{2, 1}
		}},
		{"deleteVariableAccess domain", mreq(mc(10, mp(0, []byte{2}), mp(2, []byte("LD0")))), func(m *MMS) bool {
			return m.DeleteReq.Scope == MMSDeleteScopeDomain && m.DeleteReq.DomainID == "LD0"
		}},

		// VMD.
		{"status", mreq(mp(0, []byte{0xff})), func(m *MMS) bool { return m.StatusReq.ExtendedDerivation }},
		{"status response", mresp(mc(0, mp(0, []byte{0}), mp(1, []byte{1}), mp(2, []byte{6, 0xc0}))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.Status, MMSVMDStatus{MMSStateChangesAllowed, MMSPartiallyOperational, []byte{0xc0}, 6})
		}},
		{"unsolicitedStatus", iecTLV(0xa3, mc(1, mp(0, []byte{2}), mp(1, []byte{3}))), func(m *MMS) bool {
			return m.Unconfirmed == MMSUnconfirmedStatus && m.Status.Logical == MMSLimitedServices && m.Status.Physical == MMSNeedsCommissioning
		}},
		{"rename", mreq(mc(3, mc(0, mp(0, []byte{9})), mc(1, mvmd("OLD")), mp(2, []byte("NEW")))), func(m *MMS) bool {
			return *m.RenameReq == MMSRenameRequest{MMSClassDomain, vmd("OLD"), "NEW"}
		}},
		{"getCapabilityList", mreq(mc(71, mvs("cap1"))), func(m *MMS) bool { return m.CapabilityList.ContinueAfter == "cap1" }},
		{"getCapabilityList response", mresp(mc(71, mc(0, mvs("c1"), mvs("c2")), mp(1, []byte{0}))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.CapabilityList, MMSCapabilityList{Capabilities: []string{"c1", "c2"}})
		}},

		// Domains.
		{"getDomainAttributes response", mresp(mc(37, mc(0, mvs("cap")), mp(1, []byte{2}), mp(2, []byte{0xff}), mp(3, []byte{0}), mc(4, mvs("P1")), mp(5, []byte{0}))), func(m *MMS) bool {
			d := m.DomainResp
			return d.State == MMSDomainReady && d.Deletable && !d.Sharable && reflect.DeepEqual(d.Capabilities, []string{"cap"}) && reflect.DeepEqual(d.ProgramInvocations, []string{"P1"})
		}},
		{"initiateUploadSequence response", mresp(mc(29, mp(0, []byte{7}), mc(1, mvs("cap")))), func(m *MMS) bool {
			return m.DomainResp.ULSMID == 7 && m.DomainResp.Capabilities[0] == "cap"
		}},
		{"uploadSegment response", mresp(mc(30, mp(0, []byte{1, 2, 3}), mp(1, []byte{0}))), func(m *MMS) bool {
			return bytes.Equal(m.DomainResp.LoadData, []byte{1, 2, 3}) && !m.DomainResp.MoreFollows && !m.DomainResp.Coded
		}},
		{"downloadSegment", mreq(mp(27, []byte("LD0"))), func(m *MMS) bool { return m.DomainReq.DomainName == "LD0" }},
		{"downloadSegment coded", mresp(mc(27, iecTLV(0x28, iecTLV(0x02, []byte{3}), mp(1, []byte{0xaa})))), func(m *MMS) bool {
			return m.DomainResp.Coded && m.DomainResp.MoreFollows && len(m.DomainResp.LoadData) == 6
		}},
		{"terminateDownloadSequence discard", mreq(mc(28, mp(0, []byte("LD0")), mc(1, mc(0, mp(3, []byte{1}))))), func(m *MMS) bool {
			return m.DomainReq.DomainName == "LD0" && *m.DomainReq.Discard == MMSServiceError{Class: MMSErrorResource, Code: 1}
		}},
		{"deleteDomain", mreq(mp(36, []byte("LD0"))), func(m *MMS) bool { return m.DomainReq.DomainName == "LD0" }},

		// Program invocations.
		{"createProgramInvocation", mreq(mc(38, mp(0, []byte("PI")), mc(1, mvs("D1"), mvs("D2")), mp(2, []byte{0}), mp(3, []byte{0xff}))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.ProgramReq, MMSProgramRequest{Name: "PI", Domains: []string{"D1", "D2"}, Monitor: true, HasMonitor: true})
		}},
		{"start argument", mreq(mc(40, mp(0, []byte("PI")), mp(1, []byte("arg")))), func(m *MMS) bool {
			return m.ProgramReq.ExecutionArgument == "arg"
		}},
		{"getProgramInvocationAttributes response", mresp(mc(45, mp(0, []byte{3}), mc(1, mvs("D1")), mp(2, []byte{0xff}), mp(3, []byte{0}), mp(4, []byte{0xff}), mp(5, []byte("go")), mp(1, []byte("x")))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.ProgramAttributes, MMSProgramAttributes{State: MMSProgramRunning, Domains: []string{"D1"}, Deletable: true, Monitor: true, StartArgument: "go", ExecutionArgument: "x"})
		}},

		// Files.
		{"fileOpen", mreq(mc(72, mc(0, mgs("/COMTRADE/"), mgs("a.cfg")), mp(1, []byte{0}))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.FileReq, MMSFileRequest{FileName: []string{"/COMTRADE/", "a.cfg"}})
		}},
		{"fileOpen response", mresp(mc(72, mp(0, []byte{5}), mc(1, mp(0, []byte{4, 0}), mp(1, []byte("20231005120000Z"))))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.FileResp, MMSFileResponse{FRSMID: 5, Attributes: MMSFileAttributes{1024, "20231005120000Z"}})
		}},
		{"fileRead", mreq(mp(73, []byte{5})), func(m *MMS) bool { return m.FileReq.FRSMID == 5 }},
		{"fileRead response", mresp(mc(73, mp(0, []byte{0xde, 0xad}), mp(1, []byte{0}))), func(m *MMS) bool {
			return bytes.Equal(m.FileResp.Data, []byte{0xde, 0xad}) && !m.FileResp.MoreFollows
		}},
		{"fileRead response more", mresp(mc(73, mp(0, []byte{1}))), func(m *MMS) bool { return m.FileResp.MoreFollows }},
		{"fileClose", mreq(mp(74, []byte{0xff})), func(m *MMS) bool { return m.FileReq.FRSMID == -1 }},
		{"fileRename", mreq(mc(75, mc(0, mgs("a")), mc(1, mgs("b")))), func(m *MMS) bool {
			return m.FileReq.FileName[0] == "a" && m.FileReq.NewFileName[0] == "b"
		}},
		{"fileDelete", mreq(mc(76, mgs("a.cfg"))), func(m *MMS) bool { return m.FileReq.FileName[0] == "a.cfg" }},
		{"fileDirectory", mreq(mc(77, mc(0, mgs("/COMTRADE/*")), mc(1, mgs("a.cfg")))), func(m *MMS) bool {
			return m.FileReq.FileName[0] == "/COMTRADE/*" && m.FileReq.ContinueAfter[0] == "a.cfg"
		}},
		{"fileDirectory response", mresp(mc(77, mc(0, iecTLV(0x30,
			iecTLV(0x30, mc(0, mgs("a.cfg")), mc(1, mp(0, []byte{4, 0}), mp(1, []byte("20231005120000Z")))),
			iecTLV(0x30, mc(0, mgs("b.dat")), mc(1, mp(0, []byte{1, 0, 0}))),
		)), mp(1, []byte{0xff}))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.FileResp, MMSFileResponse{MoreFollows: true, Entries: []MMSDirectoryEntry{
				{[]string{"a.cfg"}, MMSFileAttributes{1024, "20231005120000Z"}},
				{[]string{"b.dat"}, MMSFileAttributes{65536, ""}},
			}})
		}},
		{"obtainFile", mreq(mc(46, mc(1, mgs("src")), mc(2, mgs("dst")))), func(m *MMS) bool {
			return m.FileReq.FileName[0] == "src" && m.FileReq.NewFileName[0] == "dst"
		}},

		// Journals.
		{"readJournal", mreq(mc(65, mc(0, mdom("LD0", "LOG")), mc(1, mp(0, mmsTOD)))), func(m *MMS) bool {
			return m.JournalReq.Name == MMSObjectName{MMSScopeDomain, "LD0", "LOG"}
		}},
		{"readJournal response", mresp(mc(65, mc(0, mjentry(1), mjentry(2)), mp(1, []byte{0xff}))), func(m *MMS) bool {
			r := m.JournalResp
			return r.Entries == 2 && r.MoreFollows && len(r.List) == 2 && bytes.Equal(r.List[1].ID, []byte{2}) &&
				r.List[0].Content.OccurrenceTime.Equal(mmsTODTime)
		}},
		{"writeJournal", mreq(mc(66, mc(0, mvmd("J")), mc(1, iecTLV(0x30, mp(0, mmsTOD)), iecTLV(0x30, mp(0, mmsTOD)), iecTLV(0x30, mp(0, mmsTOD))))), func(m *MMS) bool {
			return m.JournalReq.Name == vmd("J") && m.JournalReq.Entries == 3 && len(m.JournalReq.Content) == 3
		}},
		{"reportJournalStatus", mreq(mc(68, mvmd("J"))), func(m *MMS) bool { return *m.ObjectName == vmd("J") }},
		{"reportJournalStatus response", mresp(mc(68, mp(0, []byte{5}), mp(1, []byte{0xff}))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.JournalResp, MMSJournalResponse{CurrentEntries: 5, Deletable: true})
		}},

		// Events.
		{"defineEventCondition", mreq(mc(47, mc(0, mvmd("EC1")), mp(1, []byte{1}), mp(2, []byte{10}), mp(3, []byte{20}), mp(4, []byte{0xff}), mc(6, mc(0, mvmd("VAR"))), mp(7, []byte{100}))), func(m *MMS) bool {
			c := m.EventCondition
			return c.Name == vmd("EC1") && c.Class == MMSEventMonitored && c.Priority == 10 && c.Severity == 20 &&
				c.AlarmSummaryReports && c.Monitored.Name == vmd("VAR") && c.HasEvaluationInterval && c.EvaluationInterval == 100
		}},
		{"getEventConditionAttributes", mreq(mc(49, mvmd("EC1"))), func(m *MMS) bool { return *m.ObjectName == vmd("EC1") }},
		{"getEventConditionAttributes response", mresp(mc(49, mp(0, []byte{0xff}), mp(1, []byte{1}), mp(3, []byte{5}), mc(6, mc(0, mc(0, mvmd("VAR")))))), func(m *MMS) bool {
			c := m.EventCondition
			return c.Deletable && c.Priority == mmsDefaultPriority && c.Severity == 5 && c.Monitored.Name == vmd("VAR")
		}},
		{"getEventConditionAttributes undefined", mresp(mc(49, mp(1, []byte{0}), mc(6, mp(1)))), func(m *MMS) bool {
			return m.EventCondition.MonitoredUndefined && m.EventCondition.Monitored == nil
		}},
		{"reportEventConditionStatus", mreq(mc(50, mvmd("EC1"))), func(m *MMS) bool { return *m.ObjectName == vmd("EC1") }},
		{"reportEventConditionStatus response", mresp(mc(50, mp(0, []byte{2}), mp(1, []byte{3}), mp(2, []byte{0xff}), mc(3, mp(0, mmsTOD)), mc(4, mp(1, []byte{7})))), func(m *MMS) bool {
			s := m.EventConditionStatus
			return s.State == MMSEventActive && s.Enrollments == 3 && s.HasEnabled && s.Enabled &&
				s.ToActive.Time.Equal(tod) && s.HasToIdle && s.ToIdle == MMSEventTime{Kind: MMSEventTimeSequence, Sequence: 7}
		}},
		{"eventNotification", iecTLV(0xa3, mc(2, mc(0, mvmd("EE1")), mc(1, mc(0, mvmd("EC1"))), mp(2, []byte{50}), mp(3, []byte{2}),
			mc(4, mp(0, mmsTOD)), mp(6, []byte{0}), mp(7, []byte{1}), mc(8, mvmd("EA1"), mc(0, mp(2))))), func(m *MMS) bool {
			e := m.EventNotification
			return e.EnrollmentName == vmd("EE1") && e.ConditionName == vmd("EC1") && e.Severity == 50 && e.HasState &&
				e.State == MMSEventActive && e.TransitionTime.Time.Equal(tod) && e.HasAckRule && e.AckRule == MMSAckSimple &&
				e.HasAction && e.ActionName == vmd("EA1") && bytes.Equal(e.ActionResponse, []byte{0x82, 0x00})
		}},
		{"eventNotification failure", iecTLV(0xa3, mc(2, mc(0, mvmd("EE1")), mc(1, mp(1)), mp(2, []byte{1}), mc(4, mp(2)), mc(8, mvmd("EA1"), mc(1, mc(0, mp(7, []byte{2})))))), func(m *MMS) bool {
			e := m.EventNotification
			return e.ConditionUndefined && e.TransitionTime.Kind == MMSEventTimeUndef && e.ActionError.Class == MMSErrorAccess
		}},
		{"acknowledgeEventNotification", mreq(mc(62, mc(0, mvmd("EE1")), mp(2, []byte{1}), mc(3, mp(1, []byte{9})))), func(m *MMS) bool {
			return *m.EventAck == MMSEventAck{vmd("EE1"), MMSEventIdle, MMSEventTime{Kind: MMSEventTimeSequence, Sequence: 9}}
		}},
		{"getAlarmSummary filter", mreq(mc(63, mp(2, []byte{2}), mc(3, mp(0, []byte{1}), mp(1, []byte{100})), mc(5, mvmd("EC9")))), func(m *MMS) bool {
			return *m.AlarmSummaryReq == MMSAlarmSummaryRequest{true, true, 2, true, 1, 100, true, vmd("EC9")}
		}},
		{"getAlarmSummary response", mresp(mc(63, mc(0, iecTLV(0x30, mc(0, mvmd("EC1"))), iecTLV(0x30, mc(0, mvmd("EC2")))), mp(1, []byte{0xff}))), func(m *MMS) bool {
			a := m.AlarmSummary
			return a.Summaries == 2 && a.MoreFollows && len(a.List) == 2 && a.List[1].ConditionName == vmd("EC2")
		}},

		// Errors.
		{"confirmed-Error fileRename detail", iecTLV(0xa2, mp(0, []byte{9}), mc(2, mc(0, mp(11, []byte{7})), mp(1, []byte{2}), mp(2, []byte("gone")), mc(3, mp(9, []byte{1})))), func(m *MMS) bool {
			return m.InvokeID == 9 && *m.Error == MMSServiceError{MMSErrorFile, 7, 2, "gone"} &&
				m.ErrorDetail.Kind == MMSErrDetailFileRename && m.ErrorDetail.Value == 1
		}},
		{"cancel-Error enrollment detail", iecTLV(0xa7, mp(0, []byte{5}), mc(1, mc(0, mp(10, []byte{1})), mc(3, mc(8, mvmd("EE"))))), func(m *MMS) bool {
			return m.Error.Class == MMSErrorCancel && m.ErrorDetail.Kind == MMSErrDetailDefineEnrollment && m.ErrorDetail.Name == vmd("EE")
		}},
		{"conclude-Error no detail", iecTLV(0xad, mc(0, mp(9, []byte{1}))), func(m *MMS) bool {
			return m.Error.Class == MMSErrorConclude && m.ErrorDetail == nil && m.ServiceDecodeErr == nil
		}},
	}
}

// mmsCheckTypes checks the decoded mmsTypeVector.
func mmsCheckTypes(s *MMSTypeSpec) bool {
	if s.Kind != MMSTypeStructure || !s.Packed || len(s.Components) != 12 {
		return false
	}

	c := s.Components
	arr := c[0].Type
	return c[0].Name == "arr" && arr.Kind == MMSTypeArray && arr.Elements == 10 && arr.Element.Kind == MMSTypeInteger && arr.Element.Size == 16 &&
		c[1].Type.Kind == MMSTypeFloatingPoint && c[1].Type.FormatWidth == 32 && c[1].Type.ExponentWidth == 8 &&
		c[2].Type.Name == MMSObjectName{MMSScopeDomain, "LD0", "T1"} &&
		c[3].Type.Kind == MMSTypeBinaryTime && c[3].Type.WithDate &&
		c[4].Type.Kind == MMSTypeMMSString && c[4].Type.Size == 64 &&
		c[5].Type.Kind == MMSTypeOctetString && c[5].Type.Size == -256 &&
		c[6].Name == "" && c[6].Type.Kind == MMSTypeBoolean &&
		c[7].Type.Kind == MMSTypeUnsigned && c[7].Type.Size == 32 &&
		c[8].Type.Kind == MMSTypeBCD && c[8].Type.Size == 4 &&
		c[9].Type.Kind == MMSTypeObjID && c[10].Type.Kind == MMSTypeGeneralizedTime && c[11].Type.Kind == MMSTypeUTCTime
}

func TestMMSServiceVectors(t *testing.T) {
	for _, v := range mmsVectors() {
		p := iecSession(iecDT(v.pdu))
		m, ok := p.Layer(LayerTypeMMS).(*MMS)
		if !ok {
			t.Errorf("%s: %v", v.name, p.ErrorLayer())
			continue
		}
		if m.ServiceDecodeErr != nil {
			t.Errorf("%s: %v", v.name, m.ServiceDecodeErr)
			continue
		}
		if !mmsSafeCheck(v.check, m) {
			t.Errorf("%s: %+v", v.name, m)
		}
	}
}

// mmsSafeCheck runs a vector check, turning a nil typed field into a
// failure rather than a panic.
func mmsSafeCheck(check func(*MMS) bool, m *MMS) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return check(m)
}

// TestMMSGVAACaptures checks the getVariableAccessAttributes responses of
// the Siemens capture against tshark 4.7: 38 responses, 1787 named
// components; tshark shows no type for utc-time.
func TestMMSGVAACaptures(t *testing.T) {
	tsdus := iecTSDUsByFrame(t, "iec61850_mms_siemens.pcap")

	responses, components := 0, 0
	for _, list := range tsdus {
		for _, data := range list {
			m, ok := iecSession(data).Layer(LayerTypeMMS).(*MMS)
			if !ok {
				continue
			}
			if m.ServiceDecodeErr != nil {
				t.Errorf("invoke %d: %v", m.InvokeID, m.ServiceDecodeErr)
			}
			if m.VariableAttributes == nil {
				continue
			}
			responses++
			components += mmsCountComponents(&m.VariableAttributes.Type)
		}
	}
	if responses != 38 || components != 1787 {
		t.Errorf("%d responses, %d components", responses, components)
	}

	// Frame 28: LLN0 = {ST {Mod, Beh, Health}, CF, DC, EX}.
	_, m := iecMMSOf(t, tsdus, 28)
	ty := m.VariableAttributes.Type
	st := ty.Components[0].Type
	mod := st.Components[0].Type.Components
	want := []MMSTypeComponent{
		{"stVal", MMSTypeSpec{Kind: MMSTypeInteger, Size: 8}},
		{"q", MMSTypeSpec{Kind: MMSTypeBitString, Size: 13}},
		{"t", MMSTypeSpec{Kind: MMSTypeUTCTime}},
	}
	if m.InvokeID != 9 || m.VariableAttributes.Deletable || len(ty.Components) != 4 || ty.Components[0].Name != "ST" ||
		st.Components[0].Name != "Mod" || !reflect.DeepEqual(mod, want) {
		t.Errorf("frame 28: %+v", ty)
	}

	vendor := ty.Components[2].Type.Components[0].Type.Components[0]
	if vendor.Name != "vendor" || vendor.Type.Kind != MMSTypeVisibleString || vendor.Type.Size != -255 {
		t.Errorf("vendor %+v", vendor)
	}
}

func mmsCountComponents(s *MMSTypeSpec) int {
	n := len(s.Components)
	for i := range s.Components {
		n += mmsCountComponents(&s.Components[i].Type)
	}
	if s.Element != nil {
		n += mmsCountComponents(s.Element)
	}
	return n
}

// TestMMSServiceSoftErrors checks that a malformed element of a newly
// typed service keeps the PDU decodable with its raw ServiceData.
func TestMMSServiceSoftErrors(t *testing.T) {
	tests := map[string][]byte{
		"fileOpen garbage":     iecTLV(0xa0, iecTLV(0x02, []byte{1}), iecTLV(0x30), []byte{0xbf, 0x48, 0x01, 0xaa}),
		"fileRead constructed": mreq(mc(73, mp(0))),
		"status constructed":   mreq(mc(0)),
		"fileDirectory short":  mresp(mc(77, []byte{0xa0, 0x05, 0x30})),
		"bad type tag":         mresp(mc(6, mp(0, []byte{0}), mc(2, mp(8)))),
		"no type":              mresp(mc(6, mp(0, []byte{0}))),
		"array no element":     mresp(mc(6, mc(2, mc(1, mp(1, []byte{1}))))),
		"unsigned8 overflow":   mresp(mc(6, mc(2, mp(5, []byte{1, 0})))),
		"event time tag":       iecTLV(0xa3, mc(2, mc(4, mp(5)))),
		"error detail tag":     iecTLV(0xa2, mp(0, []byte{9}), mc(2, mc(0, mp(1, []byte{0})), mc(3, mp(12, []byte{0})))),
		"journal without name": mreq(mc(66, mc(1))),
		"program without name": mreq(mc(44)),
		"address primitive":    mreq(mc(6, mp(1, []byte{0}))),
		"long ULSM":            mreq(mp(30, []byte{1, 0, 0, 0, 0})),
	}
	for name, pdu := range tests {
		m := &MMS{}
		if err := m.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if m.ServiceDecodeErr == nil {
			t.Errorf("%s: no soft error", name)
		}
		if m.FileReq != nil || m.FileResp != nil || m.StatusReq != nil || m.VariableAttributes != nil ||
			m.EventNotification != nil || m.ErrorDetail != nil || m.JournalReq != nil || m.ProgramReq != nil ||
			m.VariableAddress != nil || m.DomainReq != nil {
			t.Errorf("%s: partial typed field %+v", name, m)
		}
	}

	// A malformed alternate access or address keeps the raw octets only.
	m := &MMS{}
	pdu := mreq(mc(4, mc(1, mc(0, iecTLV(0x30, mc(1, mp(0)), mc(5, mp(0)))))))
	if err := m.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	v := m.ReadReq.Access.Variables[0]
	if v.Alternate != nil || len(v.AlternateAccess) != 2 || v.Kind != MMSVariableAddress || len(v.Spec) != 2 {
		t.Errorf("variable %+v", v)
	}
}

// TestMMSBigInteger decodes integers past 64 bits, which used to fail
// the whole PDU.
func TestMMSBigInteger(t *testing.T) {
	neg := append([]byte{0xff}, make([]byte, 8)...)
	pos := append([]byte{0x01}, make([]byte, 9)...)
	pdu := mresp(mc(4, mc(1, mp(5, neg), mp(6, pos), mp(5, []byte{0x80}), mp(6, append([]byte{0}, bytes.Repeat([]byte{0xff}, 8)...)))))

	m := &MMS{}
	if err := m.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	r := m.ReadResp.Results
	minus264 := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 64))
	plus272 := new(big.Int).Lsh(big.NewInt(1), 72)
	if !r[0].Data.IntOverflow || r[0].Data.Int != 0 || r[0].Data.BigInt().Cmp(minus264) != 0 {
		t.Errorf("integer %+v", r[0].Data)
	}
	if !r[1].Data.IntOverflow || r[1].Data.BigInt().Cmp(plus272) != 0 {
		t.Errorf("unsigned %+v", r[1].Data)
	}
	if r[2].Data.IntOverflow || r[2].Data.Int != -128 || r[2].Data.BigInt().Int64() != -128 {
		t.Errorf("small integer %+v", r[2].Data)
	}
	if r[3].Data.IntOverflow || r[3].Data.Uint != 1<<64-1 {
		t.Errorf("9 octet unsigned %+v", r[3].Data)
	}
	if (&MMSData{Type: MMSDataBoolean}).BigInt() != nil {
		t.Error("BigInt of a boolean")
	}

	// Negative unsigned and empty integers still fail.
	for _, v := range [][]byte{mp(6, []byte{0x80}), mp(5), mp(6, append([]byte{0x80}, make([]byte, 9)...))} {
		if err := (&MMS{}).DecodeFromBytes(mresp(mc(4, mc(1, v))), gopacket.NilDecodeFeedback); err == nil {
			t.Errorf("%x decoded", v)
		}
	}
}

// TestISOPresentationPDVs decodes every PDV of a PPDU carrying an ACSE
// release, an MMS read and opaque octets.
func TestISOPresentationPDVs(t *testing.T) {
	rlrq := iecTLV(0x62, iecTLV(0x80, []byte{0}))
	read := mreq(mc(4, mc(1, mc(0, iecTLV(0x30, mc(0, mvmd("V")))))))
	ud := iecTLV(0x61,
		iecTLV(0x30, iecTLV(0x02, []byte{1}), iecTLV(0xa0, rlrq)),
		iecTLV(0x30, iecTLV(0x02, []byte{3}), iecTLV(0xa0, read)),
		iecTLV(0x30, iecTLV(0x02, []byte{3}), iecTLV(0x81, []byte{1, 2})))
	p := iecSession(append([]byte{0x01, 0x00, 0x01, 0x00}, ud...))

	// The packet routes the first PDV only.
	pr := p.Layer(LayerTypeISOPresentation).(*ISOPresentation)
	if len(pr.PDVs) != 3 || p.Layer(LayerTypeACSE) == nil || p.Layer(LayerTypeMMS) != nil {
		t.Fatalf("layers %v", p.Layers())
	}

	if l, err := pr.PDVLayer(0); err != nil || l.(*ACSE).Type != ACSERLRQ {
		t.Errorf("PDV 0: %v %v", l, err)
	}
	if l, err := pr.PDVLayer(1); err != nil || l.(*MMS).ReadReq.Access.Variables[0].Name.ItemID != "V" {
		t.Errorf("PDV 1: %v %v", l, err)
	}
	if l, err := pr.PDVLayer(2); l != nil || err != nil {
		t.Errorf("PDV 2: %v %v", l, err)
	}
	if _, err := pr.PDVLayer(3); err != errISOPresNoPDV {
		t.Errorf("PDV 3: %v", err)
	}

	// A malformed later PDV reports its error.
	bad := iecTLV(0x61, iecTLV(0x30, iecTLV(0x02, []byte{3}), iecTLV(0xa0, read)), iecTLV(0x30, iecTLV(0x02, []byte{3}), iecTLV(0xa0, []byte{0xa0, 0x00})))
	pr = iecSession(append([]byte{0x01, 0x00, 0x01, 0x00}, bad...)).Layer(LayerTypeISOPresentation).(*ISOPresentation)
	if _, err := pr.PDVLayer(1); err == nil {
		t.Error("malformed PDV 1 decoded")
	}
}

// TestACSEInfo decodes AP-title and AE-qualifier form 1, invocation
// identifiers and a second user-information EXTERNAL.
func TestACSEInfo(t *testing.T) {
	atv := func(oid []byte, v string) []byte {
		return iecTLV(0x30, iecTLV(0x06, oid), iecTLV(0x13, []byte(v)))
	}
	cn, org := []byte{0x55, 0x04, 0x03}, []byte{0x55, 0x04, 0x0a}
	ext := func(ctx byte, apdu []byte) []byte {
		return iecTLV(0x28, iecTLV(0x02, []byte{ctx}), iecTLV(0xa0, apdu))
	}
	initiate := iecTLV(0xa8, mp(1, []byte{1}))
	conclude := []byte{0x8b, 0x00}

	aarq := iecTLV(0x60,
		mc(1, iecTLV(0x06, []byte{0x28, 0xca, 0x22, 0x02, 0x03})),
		mc(2, iecTLV(0x30, iecTLV(0x31, atv(cn, "IED1"), atv(org, "Grid")), iecTLV(0x31, atv(org, "Sub")))),
		mc(4, iecTLV(0x02, []byte{5})),
		mc(6, iecTLV(0x06, []byte{0x29, 0x01})),
		mc(7, iecTLV(0x31, atv(cn, "AE1"))),
		mc(9, iecTLV(0x02, []byte{0x01, 0x00})),
		mc(5, iecTLV(0x04, []byte{1})),
		mc(30, ext(3, initiate), ext(3, conclude)))

	a := &ACSE{}
	if err := a.DecodeFromBytes(aarq, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	wantName := []ACSEAttribute{{0, "2.5.4.3", []byte("IED1")}, {0, "2.5.4.10", []byte("Grid")}, {1, "2.5.4.10", []byte("Sub")}}
	if !reflect.DeepEqual(a.CalledInfo.APTitleName, wantName) || !a.CalledInfo.HasAPInvocationID || a.CalledInfo.APInvocationID != 5 ||
		a.CalledInfo.HasAEInvocationID || a.Called.APTitle != "" || len(a.Called.APTitleRaw) == 0 {
		t.Errorf("called %+v %+v", a.Called, a.CalledInfo)
	}
	if a.Calling.APTitle != "1.1.1" || !reflect.DeepEqual(a.CallingInfo.AEQualifierName, []ACSEAttribute{{0, "2.5.4.3", []byte("AE1")}}) ||
		a.CallingInfo.AEInvocationID != 256 || !a.CallingInfo.HasAEInvocationID {
		t.Errorf("calling %+v %+v", a.Calling, a.CallingInfo)
	}

	if l, err := a.UserLayer(1); err != nil || l.(*MMS).Type != MMSConcludeRequest {
		t.Errorf("user-information 1: %v %v", l, err)
	}
	if _, err := a.UserLayer(2); err != errACSENoUserInfo {
		t.Errorf("user-information 2: %v", err)
	}

	// AARE responding invocation identifiers.
	aare := iecTLV(0x61, mc(1, iecTLV(0x06, []byte{0x28, 0xca, 0x22, 0x02, 0x03})), mc(2, iecTLV(0x02, []byte{0})), mc(6, iecTLV(0x02, []byte{2})), mc(7, iecTLV(0x02, []byte{3})))
	if err := a.DecodeFromBytes(aare, gopacket.NilDecodeFeedback); err != nil {
		t.Fatal(err)
	}
	if r := a.RespondingInfo; r.APInvocationID != 2 || r.AEInvocationID != 3 || !r.HasAPInvocationID || !r.HasAEInvocationID {
		t.Errorf("responding %+v", r)
	}

	// Malformed form 1 names and identifiers are dropped, not fatal.
	odd := iecTLV(0x60, mc(2, iecTLV(0x30, iecTLV(0x31, iecTLV(0x30, iecTLV(0x05))))), mc(4, iecTLV(0x04, []byte{1})), mc(8, iecTLV(0x02, nil)))
	if err := a.DecodeFromBytes(odd, gopacket.NilDecodeFeedback); err != nil || a.CalledInfo.APTitleName != nil ||
		a.CalledInfo.HasAPInvocationID || a.CallingInfo.HasAPInvocationID {
		t.Errorf("malformed info %+v: %v", a.CalledInfo, err)
	}
}

// TestMMSServiceTruncation cuts every vector at every offset, directly
// and through the session stack.
func TestMMSServiceTruncation(t *testing.T) {
	for _, v := range mmsVectors() {
		for i := range v.pdu {
			cut := v.pdu[:i]
			if err := (&MMS{}).DecodeFromBytes(cut, gopacket.NilDecodeFeedback); err == nil && i < 2 {
				t.Errorf("%s: %d octets decoded", v.name, i)
			}
			iecSession(iecDT(cut))
		}
	}
}

// mmsWrap is one TLV of a nesting level: its identifier and the octets
// that precede the nested value inside it.
type mmsWrap struct {
	id    byte
	extra []byte
}

// mmsNest wraps core depth times in the TLVs of level (outermost first),
// built from the inside out in one buffer so deep values stay cheap.
func mmsNest(depth int, core []byte, level []mmsWrap) []byte {
	const maxHdr = 6
	per := 0
	for _, w := range level {
		per += maxHdr + len(w.extra)
	}
	buf := make([]byte, depth*per+len(core))
	start := len(buf) - len(core)
	copy(buf[start:], core)

	for range depth {
		for i := len(level) - 1; i >= 0; i-- {
			start -= len(level[i].extra)
			copy(buf[start:], level[i].extra)

			hdr := mmsHdr(level[i].id, len(buf)-start)
			start -= len(hdr)
			copy(buf[start:], hdr)
		}
	}
	return buf[start:]
}

// mmsHdr encodes a TLV identifier and length.
func mmsHdr(id byte, n int) []byte {
	switch {
	case n < 0x80:
		return []byte{id, byte(n)}
	case n <= 0xff:
		return []byte{id, 0x81, byte(n)}
	case n <= 0xffff:
		return []byte{id, 0x82, byte(n >> 8), byte(n)}
	default:
		return []byte{id, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// TestMMSServiceDeepNesting sends 10k nested types and alternate
// accesses.
func TestMMSServiceDeepNesting(t *testing.T) {
	const depth = 10000

	// Arrays of arrays: a1 (81 01 01, a2 (a1 ...)).
	ty := mmsNest(depth, mp(3), []mmsWrap{{0xa1, mp(1, []byte{1})}, {0xa2, nil}})
	m := &MMS{}
	if err := m.DecodeFromBytes(mresp(mc(6, mc(2, ty))), gopacket.NilDecodeFeedback); err != nil || m.ServiceDecodeErr != errOSIBERDepth {
		t.Errorf("type nesting: %v, %v", err, m.ServiceDecodeErr)
	}

	// Structures of structures: a2 (a1 (30 (a1 ...))).
	ty = mmsNest(depth, mp(3), []mmsWrap{{0xa2, nil}, {0xa1, nil}, {0x30, nil}, {0xa1, nil}})
	if _, err := decodeMMSTypeIn(ty, 0); err != errOSIBERDepth {
		t.Errorf("structure nesting: %v", err)
	}

	// selectAlternateAccess within selectAlternateAccess: a0 (83 00, 30 (...)).
	alt := mmsNest(depth, mp(4), []mmsWrap{{0xa0, mp(3)}, {0x30, nil}})
	if _, err := decodeMMSAltAccess(alt, 0); err != errOSIBERDepth {
		t.Errorf("alternate access nesting: %v", err)
	}
	pdu := mreq(mc(4, mc(1, mc(0, iecTLV(0x30, mc(0, mvmd("V")), mc(5, alt))))))
	if err := m.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil || m.ReadReq.Access.Variables[0].Alternate != nil {
		t.Errorf("read with deep alternate access: %v", err)
	}

	// The same nesting, shallow enough, decodes.
	alt = mmsNest(osiBERMaxDepth, mp(4), []mmsWrap{{0xa0, mp(3)}, {0x30, nil}})
	if _, err := decodeMMSAltAccess(alt, 0); err != nil {
		t.Errorf("alternate access at the depth cap: %v", err)
	}
}

// TestMMSServiceLengthLies claims lengths past the data.
func TestMMSServiceLengthLies(t *testing.T) {
	tests := map[string][]byte{
		"fileRead data":    mresp([]byte{0xbf, 0x49, 0x06, 0x80, 0x84, 0x7f, 0xff, 0xff, 0xff}),
		"components":       mresp(mc(6, mc(2, []byte{0xa2, 0x04, 0xa1, 0x83, 0xff, 0xff}))),
		"directory":        mresp(mc(77, []byte{0xa0, 0x04, 0x30, 0x82, 0xff, 0xff})),
		"service length":   []byte{0xa1, 0x84, 0xff, 0xff, 0xff, 0xff, 0x02, 0x01, 0x01},
		"alternate access": mreq(mc(4, mc(1, mc(0, iecTLV(0x30, mc(0, mvmd("V")), []byte{0xa5, 0x03, 0xa0, 0x82, 0x10}))))),
	}
	for name, pdu := range tests {
		m := &MMS{}
		err := m.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback)
		if err == nil && m.ServiceDecodeErr == nil && (m.ReadReq == nil || m.ReadReq.Access.Variables[0].Alternate != nil) {
			t.Errorf("%s: decoded", name)
		}
	}
}

// Lists of minimal items are allocated once, from their real count.
func TestMMSServiceAllocBound(t *testing.T) {
	const items = 10000
	const maxPerByte = 60

	tests := map[string]func() []byte{
		"type components": func() []byte {
			return mresp(mc(6, mc(2, mc(2, mc(1, bytes.Repeat(iecTLV(0x30, mc(1, mp(3))), items))))))
		},
		"directory entries": func() []byte {
			return mresp(mc(77, mc(0, iecTLV(0x30, bytes.Repeat(iecTLV(0x30, mc(0), mc(1)), items)))))
		},
		"alternate access": func() []byte {
			return mreq(mc(4, mc(1, mc(0, iecTLV(0x30, mc(0, mvmd("V")), mc(5, bytes.Repeat(mp(4), items)))))))
		},
	}
	for name, build := range tests {
		pdu := build()
		m := &MMS{}
		got := allocPerByte(len(pdu), func() {
			_ = m.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback)
		})
		if m.ServiceDecodeErr != nil {
			t.Fatalf("%s: %v", name, m.ServiceDecodeErr)
		}
		t.Logf("%s: %.0f bytes per input byte", name, got)
		if got > maxPerByte {
			t.Errorf("%s: %.0f bytes per input byte, want <= %d", name, got, maxPerByte)
		}
	}
}

func FuzzMMSServices(f *testing.F) {
	for _, v := range mmsVectors() {
		f.Add(v.pdu)
	}
	for _, v := range mmsRealVectors() {
		f.Add(mresp(mc(4, mc(1, mp(8, v.raw), mp(11, []byte("20260102030405.5Z"))))))
	}
	for _, ts := range iecExtractTSDUs(iecReadPcap(f, "testdata/iec61850_mms_siemens.pcap")) {
		if m, ok := iecSession(ts.data).Layer(LayerTypeMMS).(*MMS); ok && m.VariableAttributes != nil {
			f.Add([]byte(m.Contents))
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		m := &MMS{}
		if err := m.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err == nil && len(m.Contents) > len(data) {
			t.Fatal("contents longer than input")
		}
		if m.EventAction != nil {
			_, _ = m.EventAction.Request()
		}
		if m.EventNotification != nil {
			_, _ = m.EventNotification.Response()
		}
		if m.ReadResp != nil {
			for i := range m.ReadResp.Results {
				mmsDataWalk(t, &m.ReadResp.Results[i].Data)
			}
		}

		// Through the stack, with the PDU as a second PDV.
		ud := iecTLV(0x61, iecTLV(0x30, iecTLV(0x02, []byte{3}), iecTLV(0xa0, []byte{0x8b, 0x00})), iecTLV(0x30, iecTLV(0x02, []byte{3}), iecTLV(0xa0, data)))
		p := iecSession(append([]byte{0x01, 0x00, 0x01, 0x00}, ud...))
		if pr, ok := p.Layer(LayerTypeISOPresentation).(*ISOPresentation); ok && len(pr.PDVs) == 2 {
			_, _ = pr.PDVLayer(1)
		}
	})
}
