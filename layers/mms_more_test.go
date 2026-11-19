// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// Vectors for the semaphore, operator station, variable and type
// definition, event action, event enrollment and journal services, and
// for what ISO 9506-2:2003 adds. No public capture holds any of them, so
// all are hand built from the ASN.1:
//
//	1990  wrapped in TPKT/COTP/session/presentation and decoded by tshark
//	      4.7, which shows every field with the same value and no expert
//	      error. Its ASN.1 leaves out the request of an event action, so
//	      defineEventAction and the getEventActionAttributes response
//	      are only checked up to there.
//	2003  additionalService, service-ext, services 80 to 86, the 2003
//	      event action failure and initiate detail: tshark dissects the
//	      1990 edition and cannot check them. They follow a third party
//	      transcription of the 2003 ASN.1.

var mmsTODTime = mmsTimeOfDayEpoch.Add(time.Second)

// mmsAppRef is an ApplicationReference body: AP title 1.1.1.999, AP
// invocation 5, AE qualifier 12, AE invocation 6.
func mmsAppRef() []byte {
	return bytes.Join([][]byte{
		mc(0, iecTLV(0x06, []byte{0x29, 0x01, 0x87, 0x67})),
		mc(1, iecTLV(0x02, []byte{5})),
		mc(2, iecTLV(0x02, []byte{12})),
		mc(3, iecTLV(0x02, []byte{6})),
	}, nil)
}

// mmsWantAppRef checks the decoded mmsAppRef.
func mmsWantAppRef(r *MMSApplicationReference) bool {
	return r != nil && r.Title.APTitle == "1.1.1.999" && r.Title.HasAEQualifier && r.Title.AEQualifier == 12 &&
		r.Info.HasAPInvocationID && r.Info.APInvocationID == 5 && r.Info.HasAEInvocationID && r.Info.AEInvocationID == 6
}

// mjentry is a JournalEntry with identifier id and an annotation.
func mjentry(id byte) []byte {
	return iecTLV(0x30, mp(0, []byte{id}), mc(1, iecTLV(0x30, mmsAppRef())), mc(2, mp(0, mmsTOD), mp(3, []byte("note"))))
}

// mmsExt appends a service-ext detail to a confirmed PDU with identifier
// id.
func mmsExt(id byte, svc, detail []byte) []byte {
	return iecTLV(id, iecTLV(0x02, []byte{1}), svc, mc(79, detail))
}

func mmsVectors() []mmsVector {
	out := mmsBaseVectors()
	out = append(out, mmsVariableVectors()...)
	out = append(out, mmsSemaphoreVectors()...)
	out = append(out, mmsEventVectors()...)
	out = append(out, mmsJournalVectors()...)
	return append(out, mmsAdditionVectors()...)
}

func mmsVariableVectors() []mmsVector {
	vmd := func(s string) MMSObjectName { return MMSObjectName{Scope: MMSScopeVMD, ItemID: s} }
	scattered := mc(1,
		iecTLV(0x30, mp(0, []byte("c1")), mc(1, mc(0, mvmd("V1")))),
		iecTLV(0x30, mc(1, mc(0, mvmd("V2"))), mc(2, mp(4))))
	wantScattered := func(c []MMSScatteredComponent) bool {
		return len(c) == 2 && c[0].Name == "c1" && c[0].Variable.Name == vmd("V1") && c[0].Alternate == nil &&
			c[1].Name == "" && c[1].Variable.Name == vmd("V2") && len(c[1].Alternate) == 1
	}
	ext := iecTLV(0x28, iecTLV(0x02, []byte{9}), mp(1, []byte{1, 2}))

	return []mmsVector{
		{"defineNamedVariable", mreq(mc(7, mc(0, mvmd("V1")), mc(1, mp(0, []byte{5})), mc(2, mp(3)))), func(m *MMS) bool {
			v := m.NamedVariable
			return v.Name == vmd("V1") && v.Address.Kind == MMSAddressNumeric && v.Address.Numeric == 5 && v.Type.Kind == MMSTypeBoolean
		}},
		{"defineNamedVariable response", mresp(mp(7)), func(m *MMS) bool { return m.Service == MMSDefineNamedVariable }},
		{"defineScatteredAccess", mreq(mc(8, mc(0, mvmd("SA")), scattered)), func(m *MMS) bool {
			return m.ScatteredAccess.Name == vmd("SA") && wantScattered(m.ScatteredAccess.Components)
		}},
		{"getScatteredAccessAttributes", mreq(mc(9, mvmd("SA"))), func(m *MMS) bool { return *m.ObjectName == vmd("SA") }},
		{"getScatteredAccessAttributes response", mresp(mc(9, mp(0, []byte{0xff}), scattered)), func(m *MMS) bool {
			return m.ScatteredAccess.Deletable && wantScattered(m.ScatteredAccess.Components)
		}},
		{"read scattered", mreq(mc(4, mc(1, mc(0, iecTLV(0x30, mc(3, scattered[2:])))))), func(m *MMS) bool {
			v := m.ReadReq.Access.Variables[0]
			return v.Kind == MMSVariableScattered && wantScattered(v.Scattered)
		}},
		{"defineNamedType", mreq(mc(14, mvmd("T1"), mp(3))), func(m *MMS) bool {
			return m.NamedType.Name == vmd("T1") && m.NamedType.Type.Kind == MMSTypeBoolean
		}},
		{"getNamedTypeAttributes", mreq(mc(15, mvmd("T1"))), func(m *MMS) bool { return *m.ObjectName == vmd("T1") }},
		{"getNamedTypeAttributes response", mresp(mc(15, mp(0, []byte{0xff}), mc(1, mp(1, []byte{4}), mc(2, mp(3))))), func(m *MMS) bool {
			n := m.NamedType
			return n.Deletable && n.Type.Kind == MMSTypeArray && n.Type.Elements == 4 && n.Type.Element.Kind == MMSTypeBoolean
		}},
		{"deleteNamedType", mreq(mc(16, mp(0, []byte{0}), mc(1, mvmd("T1")))), func(m *MMS) bool {
			return m.DeleteReq.Scope == MMSDeleteScopeSpecific && m.DeleteReq.Names[0] == vmd("T1")
		}},
		{"deleteNamedType response", mresp(mc(16, mp(0, []byte{1}), mp(1, []byte{1}))), func(m *MMS) bool {
			return m.DeleteResp != nil
		}},

		// Operator station.
		{"input", mreq(mc(17, mp(0, []byte("OP1")), mp(1, []byte{0}), mc(2, mvs("Name?")), mp(3, []byte{30}))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.OperatorReq, MMSOperatorRequest{Station: "OP1", Prompts: []string{"Name?"}, InputTimeOut: 30, HasInputTimeOut: true})
		}},
		{"input response", mresp(mp(17, []byte("bob"))), func(m *MMS) bool { return m.OperatorResp.Input == "bob" }},
		{"output", mreq(mc(18, mp(0, []byte("OP1")), mc(1, mvs("hi"), mvs("there")))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.OperatorReq, MMSOperatorRequest{Station: "OP1", Echo: true, Output: []string{"hi", "there"}})
		}},
		{"output response", mresp(mp(18)), func(m *MMS) bool { return m.Service == MMSOutput }},

		// Domains moved to and from files, coded load data.
		{"requestDomainDownload", mreq(mc(32, mp(0, []byte("DOM")), mc(1, mvs("cap")), mp(2, []byte{0xff}), mc(4, mgs("f.bin")))), func(m *MMS) bool {
			r := m.DomainReq
			return r.DomainName == "DOM" && r.Sharable && reflect.DeepEqual(r.Capabilities, []string{"cap"}) &&
				reflect.DeepEqual(r.FileName, []string{"f.bin"}) && r.ThirdParty == nil
		}},
		{"requestDomainUpload", mreq(mc(33, mp(0, []byte("DOM")), mc(1, mgs("f.bin")))), func(m *MMS) bool {
			return m.DomainReq.DomainName == "DOM" && reflect.DeepEqual(m.DomainReq.FileName, []string{"f.bin"}) && m.DomainReq.Capabilities == nil
		}},
		{"loadDomainContent", mreq(mc(34, mp(0, []byte("DOM")), mc(1), mp(2, []byte{0}), mc(4, mgs("a"), mgs("b")), mc(5, mmsAppRef()))), func(m *MMS) bool {
			return reflect.DeepEqual(m.DomainReq.FileName, []string{"a", "b"}) && !m.DomainReq.Sharable && mmsWantAppRef(m.DomainReq.ThirdParty)
		}},
		{"storeDomainContent", mreq(mc(35, mp(0, []byte("DOM")), mc(1, mgs("f")), mc(2, mmsAppRef()))), func(m *MMS) bool {
			return reflect.DeepEqual(m.DomainReq.FileName, []string{"f"}) && mmsWantAppRef(m.DomainReq.ThirdParty)
		}},
		{"storeDomainContent response", mresp(mp(35)), func(m *MMS) bool { return m.Service == MMSStoreDomainContent }},
		{"downloadSegment external", mresp(mc(27, ext, mp(1, []byte{0}))), func(m *MMS) bool {
			r := m.DomainResp
			return r.Coded && r.LoadKind == MMSLoadCoded && !r.MoreFollows && r.External.ContextID == 9 &&
				r.External.Encoding == ISOPresentationOctetAligned && bytes.Equal(r.External.Data, []byte{1, 2})
		}},
		{"uploadSegment embedded", mresp(mc(30, iecTLV(0x2b, mc(0, mc(0)), mp(1, []byte{7})))), func(m *MMS) bool {
			return m.DomainResp.LoadKind == MMSLoadEmbedded && !m.DomainResp.Coded && m.DomainResp.MoreFollows
		}},
		{"start external argument", mreq(mc(40, mp(0, []byte("PI")), ext)), func(m *MMS) bool {
			return m.ProgramReq.Name == "PI" && m.ProgramReq.ExecutionExternal.ContextID == 9
		}},
	}
}

func mmsSemaphoreVectors() []mmsVector {
	vmd := func(s string) MMSObjectName { return MMSObjectName{Scope: MMSScopeVMD, ItemID: s} }
	sem := mc(0, mvmd("SEM"))
	take := bytes.Join([][]byte{sem, mp(1, []byte("tok")), mp(2, []byte{10}), mp(3, []byte{5}), mp(4, []byte{6}), mp(5, []byte{0xff}), mp(6, []byte{0})}, nil)
	wantTake := func(r *MMSSemaphoreRequest) bool {
		return r.Name == vmd("SEM") && r.NamedToken == "tok" && r.Priority == 10 && r.HasAcceptableDelay && r.AcceptableDelay == 5 &&
			r.HasControlTimeOut && r.ControlTimeOut == 6 && r.HasAbortOnTimeOut && r.AbortOnTimeOut && !r.RelinquishIfLost
	}
	entry := iecTLV(0x30, mp(0, []byte{1}), mp(1, []byte{1}), mc(2, iecTLV(0x30, mmsAppRef())), mp(3, []byte("tok")),
		mp(4, []byte{7}), mp(5, []byte{8}), mp(6, []byte{0xff}), mp(7, []byte{0}))
	modifiers := iecTLV(0x30,
		mc(0, mc(0, mvmd("EE")), mc(1, mvmd("EC")), mp(2, []byte{1, 0x0c}), mp(3, []byte{4})),
		mc(1, take))

	return []mmsVector{
		{"takeControl", mreq(mc(19, take, mc(7, mmsAppRef()))), func(m *MMS) bool {
			return wantTake(m.SemaphoreReq) && mmsWantAppRef(m.SemaphoreReq.Preempt)
		}},
		{"takeControl defaults", mreq(mc(19, sem)), func(m *MMS) bool {
			return reflect.DeepEqual(*m.SemaphoreReq, MMSSemaphoreRequest{Name: vmd("SEM"), Priority: mmsDefaultPriority, RelinquishIfLost: true})
		}},
		{"takeControl response token", mresp(mc(19, mp(1, []byte("tok")))), func(m *MMS) bool {
			return m.SemaphoreResp.HasNamedToken && m.SemaphoreResp.NamedToken == "tok"
		}},
		{"takeControl response", mresp(mc(19, mp(0))), func(m *MMS) bool { return !m.SemaphoreResp.HasNamedToken }},
		{"relinquishControl", mreq(mc(20, sem, mp(1, []byte("tok")))), func(m *MMS) bool {
			return m.SemaphoreReq.Name == vmd("SEM") && m.SemaphoreReq.NamedToken == "tok"
		}},
		{"relinquishControl response", mresp(mp(20)), func(m *MMS) bool { return m.Service == MMSRelinquishControl }},
		{"defineSemaphore", mreq(mc(21, sem, mp(1, []byte{3}))), func(m *MMS) bool {
			return m.SemaphoreReq.Name == vmd("SEM") && m.SemaphoreReq.Tokens == 3
		}},
		{"deleteSemaphore", mreq(mc(22, mvmd("SEM"))), func(m *MMS) bool { return *m.ObjectName == vmd("SEM") }},
		{"reportSemaphoreStatus", mreq(mc(23, mvmd("SEM"))), func(m *MMS) bool { return *m.ObjectName == vmd("SEM") }},
		{"reportSemaphoreStatus response", mresp(mc(23, mp(0, []byte{0xff}), mp(1, []byte{1}), mp(2, []byte{3}), mp(3, []byte{1}), mp(4, []byte{0}))), func(m *MMS) bool {
			return reflect.DeepEqual(*m.SemaphoreResp, MMSSemaphoreResponse{Deletable: true, Class: MMSSemaphorePool, Tokens: 3, OwnedTokens: 1})
		}},
		{"reportPoolSemaphoreStatus", mreq(mc(24, sem, mp(1, []byte("t0")))), func(m *MMS) bool {
			return m.SemaphoreReq.StartAfter == "t0"
		}},
		{"reportPoolSemaphoreStatus response", mresp(mc(24, mc(0, mp(0, []byte("t1")), mp(1, []byte("t2")), mp(2, []byte("t3"))), mp(1, []byte{0}))), func(m *MMS) bool {
			want := []MMSNamedToken{{MMSTokenFree, "t1"}, {MMSTokenOwned, "t2"}, {MMSTokenHung, "t3"}}
			return reflect.DeepEqual(m.SemaphoreResp.NamedTokens, want) && !m.SemaphoreResp.MoreFollows
		}},
		{"reportSemaphoreEntryStatus", mreq(mc(25, sem, mp(1, []byte{1}), mp(2, []byte{9}))), func(m *MMS) bool {
			return m.SemaphoreReq.State == MMSSemaphoreOwner && bytes.Equal(m.SemaphoreReq.EntryStartAfter, []byte{9})
		}},
		{"reportSemaphoreEntryStatus response", mresp(mc(25, mc(0, entry))), func(m *MMS) bool {
			e := m.SemaphoreResp.Entries[0]
			return m.SemaphoreResp.MoreFollows && bytes.Equal(e.EntryID, []byte{1}) && e.Class == MMSEntryModifier && mmsWantAppRef(e.Application) &&
				e.NamedToken == "tok" && e.Priority == 7 && e.HasRemainingTimeOut && e.RemainingTimeOut == 8 && e.AbortOnTimeOut && !e.RelinquishIfLost
		}},
		{"modifiers + status", iecTLV(0xa0, iecTLV(0x02, []byte{1}), modifiers, mp(0, []byte{0})), func(m *MMS) bool {
			if len(m.Modifiers) != 2 || m.Service != MMSStatus || m.StatusReq == nil {
				return false
			}
			ev := m.Modifiers[0]
			return ev.Kind == MMSModifierEvent && ev.Event.EnrollmentName == vmd("EE") && ev.Event.ConditionName == vmd("EC") &&
				ev.Event.Transitions == MMSDisabledToActive|MMSIdleToActive && ev.Event.AcceptableDelay == 4 &&
				m.Modifiers[1].Kind == MMSModifierSemaphore && wantTake(m.Modifiers[1].Semaphore)
		}},
	}
}

func mmsEventVectors() []mmsVector {
	vmd := func(s string) MMSObjectName { return MMSObjectName{Scope: MMSScopeVMD, ItemID: s} }
	enrollment := iecTLV(0x30, mc(0, mvmd("EE1")), mc(1, mc(0, mvmd("EC1"))), mc(2, mp(1)), mc(3, iecTLV(0x30, mmsAppRef())),
		mp(4, []byte{0xff}), mp(5, []byte{1}), mp(6, []byte{1}), mp(7, []byte{9}), mp(8, []byte{3}))
	alarm := iecTLV(0x30, mc(0, mvmd("EC1")), mp(1, []byte{5}), mp(2, []byte{2}), mp(3, []byte{1}), mc(5, mp(0, mmsTOD)), mc(6, mp(1, []byte{7})))
	alarmEnroll := iecTLV(0x30, mc(0, mvmd("EE1")), mc(2, iecTLV(0x30, mmsAppRef())), mp(3, []byte{5}), mp(4, []byte{2}), mp(6, []byte{0xff}),
		mp(7, []byte{1}), mp(8, []byte{3}), mc(9, mp(0, mmsTOD)), mc(10, mp(1, []byte{4})), mc(11, mp(1, []byte{5})), mc(12, mp(1, []byte{6})))
	seq := func(n uint32) MMSEventTime { return MMSEventTime{Kind: MMSEventTimeSequence, Sequence: n} }

	return []mmsVector{
		{"deleteEventCondition specific", mreq(mc(48, mc(0, mvmd("EC1"), mvmd("EC2")))), func(m *MMS) bool {
			r := m.EventDeleteReq
			return r.Scope == MMSEventDeleteSpecific && reflect.DeepEqual(r.Names, []MMSObjectName{vmd("EC1"), vmd("EC2")})
		}},
		{"deleteEventCondition domain", mreq(mc(48, mp(2, []byte("LD0")))), func(m *MMS) bool {
			return m.EventDeleteReq.Scope == MMSEventDeleteDomain && m.EventDeleteReq.DomainID == "LD0"
		}},
		{"deleteEventCondition aa", mreq(mc(48, mp(1))), func(m *MMS) bool { return m.EventDeleteReq.Scope == MMSEventDeleteAA }},
		{"deleteEventCondition response", mresp(mp(48, []byte{2})), func(m *MMS) bool { return m.EventDeleteResp.NotDeleted == 2 }},
		{"deleteEventAction vmd", mreq(mc(54, mp(4))), func(m *MMS) bool { return m.EventDeleteReq.Scope == MMSEventDeleteVMD }},
		{"deleteEventAction domain", mreq(mc(54, mp(3, []byte("LD0")))), func(m *MMS) bool {
			return m.EventDeleteReq.Scope == MMSEventDeleteDomain && m.EventDeleteReq.DomainID == "LD0"
		}},
		{"deleteEventAction response", mresp(mp(54, []byte{0})), func(m *MMS) bool { return m.EventDeleteResp.NotDeleted == 0 }},
		{"deleteEventEnrollment ec", mreq(mc(58, mc(1, mvmd("EC1")))), func(m *MMS) bool {
			return m.EventDeleteReq.Scope == MMSEventDeleteCondition && m.EventDeleteReq.Name == vmd("EC1")
		}},
		{"deleteEventEnrollment ea", mreq(mc(58, mc(2, mvmd("EA1")))), func(m *MMS) bool {
			return m.EventDeleteReq.Scope == MMSEventDeleteAction && m.EventDeleteReq.Name == vmd("EA1")
		}},
		{"deleteEventEnrollment response", mresp(mp(58, []byte{1})), func(m *MMS) bool { return m.EventDeleteResp.NotDeleted == 1 }},
		{"alterEventConditionMonitoring", mreq(mc(51, mc(0, mvmd("EC1")), mp(1, []byte{0xff}), mp(2, []byte{9}), mp(3, []byte{0}), mp(4, []byte{100}))), func(m *MMS) bool {
			return *m.EventAlter == MMSEventAlter{vmd("EC1"), true, true, 9, true, false, true, 100, true}
		}},
		{"alterEventConditionMonitoring response", mresp(mp(51)), func(m *MMS) bool { return m.Service == MMSAlterEventConditionMonitoring }},
		{"triggerEvent", mreq(mc(52, mc(0, mvmd("EC1")), mp(1, []byte{3}))), func(m *MMS) bool {
			return *m.EventAlter == MMSEventAlter{Name: vmd("EC1"), Priority: 3, HasPriority: true}
		}},
		{"defineEventAction", mreq(mc(53, mc(0, mvmd("EA1")), mc(1, mc(1, mc(0, mvmd("SEM")))), mc(2, mp(0, []byte{0xff})))), func(m *MMS) bool {
			a := m.EventAction
			req, err := a.Request()
			return err == nil && a.Name == vmd("EA1") && len(a.Modifiers) == 1 && a.Modifiers[0].Semaphore.Name == vmd("SEM") &&
				a.Service == MMSStatus && req.StatusReq.ExtendedDerivation
		}},
		{"getEventActionAttributes", mreq(mc(55, mvmd("EA1"))), func(m *MMS) bool { return *m.ObjectName == vmd("EA1") }},
		{"getEventActionAttributes response", mresp(mc(55, mp(0, []byte{0xff}), mc(1), mc(2, mc(4, mc(1, mc(0, iecTLV(0x30, mc(0, mvmd("V1"))))))))), func(m *MMS) bool {
			a := m.EventAction
			req, err := a.Request()
			return err == nil && a.Deletable && len(a.Modifiers) == 0 && a.Service == MMSRead && req.ReadReq.Access.Variables[0].Name == vmd("V1")
		}},
		{"reportEventActionStatus", mreq(mc(56, mvmd("EA1"))), func(m *MMS) bool { return *m.ObjectName == vmd("EA1") }},
		{"reportEventActionStatus response", mresp(mp(56, []byte{4})), func(m *MMS) bool { return m.EventActionStatus.Enrollments == 4 }},
		{"defineEventEnrollment", mreq(mc(57, mc(0, mvmd("EE1")), mc(1, mvmd("EC1")), mp(2, []byte{1, 0x0c}), mp(3, []byte{1}), mc(4, mvmd("EA1")), mc(5, iecTLV(0x30, mmsAppRef())))), func(m *MMS) bool {
			e := m.EventEnrollment
			return e.Name == vmd("EE1") && e.ConditionName == vmd("EC1") && e.Transitions == MMSDisabledToActive|MMSIdleToActive &&
				e.AckRule == 1 && e.HasAction && e.ActionName == vmd("EA1") && mmsWantAppRef(e.Client)
		}},
		{"defineEventEnrollment response", mresp(mp(57)), func(m *MMS) bool { return m.Service == MMSDefineEventEnrollment }},
		{"alterEventEnrollment", mreq(mc(59, mc(0, mvmd("EE1")), mp(1, []byte{1, 0x10}), mp(2, []byte{2}))), func(m *MMS) bool {
			e := m.EventEnrollment
			return e.Name == vmd("EE1") && e.HasTransitions && e.Transitions == MMSActiveToIdle && e.HasAckRule && e.AckRule == 2
		}},
		{"alterEventEnrollment response", mresp(mc(59, mc(0, mp(0, []byte{2})), mc(1, mp(0, mmsTOD)))), func(m *MMS) bool {
			s := m.EnrollmentStatus
			return s.State == MMSEnrollmentActive && !s.StateUndefined && s.TransitionTime.Kind == MMSEventTimeOfDay && s.TransitionTime.Time.Equal(mmsTODTime)
		}},
		{"alterEventEnrollment response undefined", mresp(mc(59, mc(0, mp(1)), mc(1, mp(1, []byte{3})))), func(m *MMS) bool {
			return m.EnrollmentStatus.StateUndefined && m.EnrollmentStatus.TransitionTime == seq(3)
		}},
		{"reportEventEnrollmentStatus", mreq(mc(60, mvmd("EE1"))), func(m *MMS) bool { return *m.ObjectName == vmd("EE1") }},
		{"reportEventEnrollmentStatus response", mresp(mc(60, mp(0, []byte{1, 0x0c}), mp(1, []byte{0}), mp(2, []byte{1}), mp(3, []byte{1}), mp(4, []byte{7}))), func(m *MMS) bool {
			return *m.EnrollmentStatus == MMSEnrollmentStatus{Transitions: MMSDisabledToActive | MMSIdleToActive, Duration: MMSEnrollmentPermanent,
				AckRule: 1, HasAckRule: true, State: MMSEnrollmentActiveAcked}
		}},
		{"getEventEnrollmentAttributes", mreq(mc(61, mp(0, []byte{0}), mc(1, mvmd("EE1")), mc(2, iecTLV(0x30, mmsAppRef())), mc(3, mvmd("EC1")), mc(4, mvmd("EA1")), mc(5, mvmd("EE0")))), func(m *MMS) bool {
			q := m.EnrollmentQuery
			return q.Scope == MMSEnrollmentScopeSpecific && q.Names[0] == vmd("EE1") && mmsWantAppRef(q.Client) && q.HasCondition &&
				q.ConditionName == vmd("EC1") && q.HasAction && q.ActionName == vmd("EA1") && q.HasContinueAfter && q.ContinueAfter == vmd("EE0")
		}},
		{"getEventEnrollmentAttributes defaults", mreq(mc(61)), func(m *MMS) bool {
			return reflect.DeepEqual(*m.EnrollmentQuery, MMSEnrollmentQuery{Scope: MMSEnrollmentScopeClient})
		}},
		{"getEventEnrollmentAttributes response", mresp(mc(61, mc(0, enrollment), mp(1, []byte{0xff}))), func(m *MMS) bool {
			e := m.EnrollmentList.Enrollments[0]
			return m.EnrollmentList.MoreFollows && e.Name == vmd("EE1") && e.ConditionName == vmd("EC1") && !e.ConditionUndefined &&
				e.ActionUndefined && !e.HasAction && mmsWantAppRef(e.Client) && e.Deletable && e.Class == MMSEnrollmentNotification &&
				e.Duration == MMSEnrollmentPermanent && e.HasInvokeID && e.InvokeID == 9 && e.HasRemainingDelay && e.RemainingDelay == 3
		}},
		{"getAlarmSummary entries", mresp(mc(63, mc(0, alarm))), func(m *MMS) bool {
			a := m.AlarmSummary.List[0]
			return a.ConditionName == vmd("EC1") && a.Severity == 5 && a.State == MMSEventActive && a.Unacknowledged == MMSUnackedActive &&
				a.HasToActive && a.ToActive.Time.Equal(mmsTODTime) && a.HasToIdle && a.ToIdle == seq(7)
		}},
		{"getAlarmEnrollmentSummary", mreq(mc(64, mp(0, []byte{0}), mp(2, []byte{2}))), func(m *MMS) bool {
			return !m.AlarmSummaryReq.EnrollmentsOnly && m.AlarmSummaryReq.ActiveAlarmsOnly && m.AlarmSummaryReq.AckFilter == 2
		}},
		{"getAlarmEnrollmentSummary response", mresp(mc(64, mc(0, alarmEnroll), mp(1, []byte{0xff}))), func(m *MMS) bool {
			a := m.AlarmSummary.Enrollments[0]
			return m.AlarmSummary.Summaries == 1 && m.AlarmSummary.MoreFollows && a.EnrollmentName == vmd("EE1") && mmsWantAppRef(a.Client) &&
				a.Severity == 5 && a.State == MMSEventActive && a.NotificationLost && a.HasAckRule && a.AckRule == 1 &&
				a.HasEnrollmentState && a.EnrollmentState == MMSEnrollmentActiveNoAckA && a.HasToActive && a.ToActive.Time.Equal(mmsTODTime) &&
				a.HasActiveAcked && a.ActiveAcked == seq(4) && a.HasToIdle && a.ToIdle == seq(5) && a.HasIdleAcked && a.IdleAcked == seq(6)
		}},
		{"eventNotification action response", iecTLV(0xa3, mc(2, mc(0, mvmd("EE1")), mc(1, mp(1)), mp(2, []byte{1}), mc(4, mp(2)),
			mc(8, mvmd("EA1"), mc(0, mc(0, mp(0, []byte{0}), mp(1, []byte{1})))))), func(m *MMS) bool {
			r, err := m.EventNotification.Response()
			return err == nil && r.Service == MMSStatus && r.Status.Physical == 1
		}},
		{"eventNotification 2003 failure", iecTLV(0xa3, mc(2, mc(0, mvmd("EE1")), mc(1, mp(1)), mp(2, []byte{1}), mc(4, mp(2)),
			mc(8, mvmd("EA1"), mc(1, mp(0, []byte{2}), mc(1, mc(0, mp(7, []byte{2}))))))), func(m *MMS) bool {
			e := m.EventNotification
			return e.HasAction && e.HasModifierPosition && e.ModifierPosition == 2 && e.ActionError.Class == MMSErrorAccess && e.ActionError.Code == 2
		}},
	}
}

func mmsJournalVectors() []mmsVector {
	vmd := func(s string) MMSObjectName { return MMSObjectName{Scope: MMSScopeVMD, ItemID: s} }
	data := mc(2, mp(0, mmsTOD), mc(2, mc(0, mc(0, mvmd("EC1")), mp(1, []byte{2})), mc(1, iecTLV(0x30, mp(0, []byte("tag")), mc(1, mp(3, []byte{0xff}))))))
	wantData := func(c MMSJournalContent) bool {
		return c.Form == MMSJournalData && c.OccurrenceTime.Equal(mmsTODTime) && c.HasEvent && c.EventCondition == vmd("EC1") &&
			c.EventState == MMSEventActive && len(c.Variables) == 1 && c.Variables[0].Tag == "tag" && c.Variables[0].Value.Bool
	}

	return []mmsVector{
		{"readJournal range", mreq(mc(65, mc(0, mvmd("J")), mc(1, mp(1, []byte{8})), mc(2, mp(1, []byte{5})), mc(4, mvs("v1"), mvs("v2")), mc(5, mp(0, mmsTOD), mp(1, []byte{9})))), func(m *MMS) bool {
			r := m.JournalReq
			return r.Name == vmd("J") && !r.Start.HasTime && bytes.Equal(r.Start.Entry, []byte{8}) && r.Stop == nil && r.HasEntryCount &&
				r.EntryCount == 5 && reflect.DeepEqual(r.Variables, []string{"v1", "v2"}) && r.After.HasTime && r.After.Time.Equal(mmsTODTime) &&
				bytes.Equal(r.After.Entry, []byte{9})
		}},
		{"readJournal times", mreq(mc(65, mc(0, mvmd("J")), mc(1, mp(0, mmsTOD)), mc(2, mp(0, mmsTOD)))), func(m *MMS) bool {
			r := m.JournalReq
			return r.Start.HasTime && r.Start.Time.Equal(mmsTODTime) && r.Stop.HasTime && r.Stop.Time.Equal(mmsTODTime) && !r.HasEntryCount
		}},
		{"readJournal response data", mresp(mc(65, mc(0, iecTLV(0x30, mp(0, []byte{1}), mc(1, iecTLV(0x30, mmsAppRef())), data)))), func(m *MMS) bool {
			e := m.JournalResp.List[0]
			return bytes.Equal(e.ID, []byte{1}) && mmsWantAppRef(e.Application) && wantData(e.Content) && !m.JournalResp.MoreFollows
		}},
		{"writeJournal content", mreq(mc(66, mc(0, mvmd("J")), mc(1, iecTLV(0x30, data[2:]), iecTLV(0x30, mp(0, mmsTOD), mp(3, []byte("note")))))), func(m *MMS) bool {
			c := m.JournalReq.Content
			return m.JournalReq.Entries == 2 && wantData(c[0]) && c[1].Form == MMSJournalAnnotation && c[1].Annotation == "note"
		}},
		{"writeJournal 2003 annotation", mreq(mc(66, mc(0, mvmd("J")), mc(1, iecTLV(0x30, mp(0, mmsTOD), mc(3, mvs("note")))))), func(m *MMS) bool {
			return m.JournalReq.Content[0].Annotation == "note"
		}},
		{"writeJournal response", mresp(mp(66)), func(m *MMS) bool { return m.Service == MMSWriteJournal }},
		{"initializeJournal", mreq(mc(67, mc(0, mvmd("J")), mc(1, mp(0, mmsTOD), mp(1, []byte{4})))), func(m *MMS) bool {
			l := m.JournalReq.Limit
			return m.JournalReq.Name == vmd("J") && l.HasTime && l.Time.Equal(mmsTODTime) && bytes.Equal(l.Entry, []byte{4})
		}},
		{"initializeJournal response", mresp(mp(67, []byte{12})), func(m *MMS) bool { return m.JournalResp.Deleted == 12 }},
		{"createJournal", mreq(mc(69, mc(0, mvmd("J")))), func(m *MMS) bool { return m.JournalReq.Name == vmd("J") }},
		{"createJournal response", mresp(mp(69)), func(m *MMS) bool { return m.Service == MMSCreateJournal }},
		{"deleteJournal", mreq(mc(70, mc(0, mvmd("J")))), func(m *MMS) bool { return m.JournalReq.Name == vmd("J") }},
		{"deleteJournal response", mresp(mp(70)), func(m *MMS) bool { return m.Service == MMSDeleteJournal }},
	}
}

// mmsAdditionVectors holds what ISO 9506-2:2003 adds.
func mmsAdditionVectors() []mmsVector {
	vmd := func(s string) MMSObjectName { return MMSObjectName{Scope: MMSScopeVMD, ItemID: s} }
	add := func(tag int, parts ...[]byte) []byte { return mc(78, mc(tag, parts...)) }
	elements := mc(0,
		mc(0, iecTLV(0x30, mp(1, []byte("D")), mc(2, mvs("c")), mp(3, []byte{0xff}), mc(4, mp(0, []byte{1, 2})))),
		mc(1, iecTLV(0x30, mp(1, []byte("D")), mc(3, mp(0, []byte{3})))),
		mp(2, []byte("D")),
		mc(3, mp(0, []byte("P")), mc(1, mvs("D")), mp(2, []byte{0}), mp(3, []byte{0xff}), mp(4, []byte{2})))
	wantElements := func(e []MMSControlElement) bool {
		return len(e) == 4 && e[0].Kind == MMSElementBeginDomain && e[0].Name == "D" && e[0].Sharable && e[0].Capabilities[0] == "c" &&
			e[0].Load.Kind == MMSLoadNonCoded && bytes.Equal(e[0].Load.Data, []byte{1, 2}) &&
			e[1].Kind == MMSElementContinueDomain && bytes.Equal(e[1].Load.Data, []byte{3}) &&
			e[2].Kind == MMSElementEndDomain && e[2].Name == "D" &&
			e[3].Kind == MMSElementProgram && e[3].Name == "P" && e[3].Domains[0] == "D" && !e[3].Reusable && e[3].Monitor && e[3].State == MMSProgramIdle
	}
	acl := mc(1, mc(0, mp(0)), mc(2, mc(4, mc(1, mvs("SEM")), mc(2, iecTLV(0x30, mmsAppRef())), mc(3, mp(0, []byte("pw"))), mc(5, mp(0), mc(2, iecTLV(0x05))))))
	wantACL := func(e []MMSAccessElement) bool {
		if len(e) != 2 || e[0].Operation != MMSAccessRead || e[0].Condition.Kind != MMSAccessNever || e[1].Operation != MMSAccessWrite {
			return false
		}
		j := e[1].Condition
		return j.Kind == MMSAccessJoint && len(j.Conditions) == 4 && j.Conditions[0].Semaphore == "SEM" && mmsWantAppRef(j.Conditions[1].User) &&
			bytes.Equal(j.Conditions[2].Password, mp(0, []byte("pw"))) && j.Conditions[3].Kind == MMSAccessAlternate &&
			len(j.Conditions[3].Conditions) == 2 && j.Conditions[3].Conditions[1].Kind == MMSAccessUser && j.Conditions[3].Conditions[1].User == nil
	}
	class := mc(0, mp(0, []byte{0}))

	return []mmsVector{
		{"initiate-Request 2003", iecTLV(0xa8, mp(1, []byte{5}), mp(2, []byte{5}), mc(4, mp(0, []byte{1}), mp(1, []byte{5, 0xf1, 0x00}),
			mp(2, []byte{3, 0xee, 0x08}), mp(3, []byte{1, 0xf0, 0x02}), mp(4, []byte{5, 0xe0}), mp(5, []byte("M_Std")))), func(m *MMS) bool {
			in := m.Initiate
			return in.Version == 1 && bytes.Equal(in.AdditionalSupported, []byte{0xf0, 0x02}) && bytes.Equal(in.AdditionalCBB, []byte{0xe0}) &&
				in.PrivilegeClass == "M_Std"
		}},
		{"initiate-Request bad additions", iecTLV(0xa8, mc(4, mp(0, []byte{1}), mp(3, nil), mp(4, []byte{9}))), func(m *MMS) bool {
			return m.Initiate.Version == 1 && m.Initiate.AdditionalSupported == nil && m.Initiate.AdditionalCBB == nil
		}},
		{"getNameList csObjectClass", mreq(mc(1, mc(0, mp(1, []byte{1})), mc(1, mp(0)))), func(m *MMS) bool {
			g := m.GetNameListReq
			return g.HasCSObjectClass && g.CSObjectClass == MMSClassUnitControl && g.Scope == MMSScopeVMD
		}},

		// service-ext.
		{"createProgramInvocation ext", mmsExt(0xa0, mc(38, mp(0, []byte("PI")), mc(1, mvs("D"))), mp(38, []byte{1})), func(m *MMS) bool {
			return m.ProgramReq.Name == "PI" && m.ServiceExt.Service == MMSCreateProgramInvocation && m.ServiceExt.ControlState == MMSControlControlling
		}},
		{"start ext", mmsExt(0xa0, mc(40, mp(0, []byte("PI"))), mc(40, iecTLV(0x30, mp(0, []byte("loc")), mc(1, mp(2, []byte{5}))))), func(m *MMS) bool {
			x := m.ServiceExt
			return x.Controlling && x.StartLocation == "loc" && x.StartCount == MMSStartCount{MMSStartStepCount, 5}
		}},
		{"start ext normal", mmsExt(0xa0, mc(40, mp(0, []byte("PI"))), mc(40, iecTLV(0x05))), func(m *MMS) bool {
			return !m.ServiceExt.Controlling && m.ServiceExt.Service == MMSStart
		}},
		{"resume ext", mmsExt(0xa0, mc(42, mp(0, []byte("PI"))), mc(42, iecTLV(0x30, mp(0)))), func(m *MMS) bool {
			return m.ServiceExt.Controlling && m.ServiceExt.ContinueMode
		}},
		{"defineEventCondition ext", mmsExt(0xa0, mc(47, mc(0, mvmd("EC1")), mp(1, []byte{0})), mc(47, mp(0, []byte("text")))), func(m *MMS) bool {
			return m.EventCondition != nil && m.ServiceExt.Enhancement == MMSEnhancement{Kind: MMSEnhancementString, String: "text"}
		}},
		{"alterEventEnrollment ext", mmsExt(0xa0, mc(59, mc(0, mvmd("EE1"))), mc(59, mp(1, []byte{4}))), func(m *MMS) bool {
			return m.ServiceExt.Enhancement == MMSEnhancement{Kind: MMSEnhancementIndex, Index: 4}
		}},
		{"other ext", mmsExt(0xa0, mp(0, []byte{0}), iecTLV(0x05)), func(m *MMS) bool {
			return m.StatusReq != nil && m.ServiceExt.Other
		}},
		{"status response ext", mmsExt(0xa1, mc(0, mp(0, []byte{0}), mp(1, []byte{0})), mc(0, iecTLV(0x30, mp(0, []byte{3}), mp(1, []byte{4, 0xa0}), mp(3, []byte("prog"))))), func(m *MMS) bool {
			s := m.ServiceExt.Status
			return m.Status != nil && s.OperationState == 3 && s.ExtendedStatus == 0xa && s.ExtendedStatusMask == 0xf && s.SelectedProgram == "prog"
		}},
		{"getProgramInvocationAttributes ext", mmsExt(0xa1, mc(45, mp(0, []byte{3}), mc(1), mp(2, []byte{0}), mp(3, []byte{0}), mp(4, []byte{0}), mp(5, nil)),
			mc(45, mp(0, []byte{7}), mc(1, mc(0, mc(0, mvs("P1")), mp(1, []byte("loc")), mc(2, mp(0)))))), func(m *MMS) bool {
			p := m.ServiceExt.Program
			return p.ErrorCode == 7 && p.Control == MMSControlControlling && p.Controlled[0] == "P1" && p.ProgramLocation == "loc" && p.RunningMode.Kind == MMSStartNoLimit
		}},
		{"getEventConditionAttributes ext", mmsExt(0xa1, mc(49, mp(1, []byte{0})), mc(49, mc(0, mp(0, []byte{9})), mc(1, mvmd("L1")), mc(2, mp(1, []byte{2})))), func(m *MMS) bool {
			c := m.ServiceExt.Condition
			return c.HasPriorityOverride && c.PriorityOverride == 9 && c.Lists[0] == vmd("L1") && m.ServiceExt.Enhancement.Index == 2
		}},
		{"eventNotification ext", iecTLV(0xa3, mc(2, mc(0, mvmd("EE1")), mc(1, mp(1)), mp(2, []byte{1}), mc(4, mp(2))), mc(79, mc(2, mp(0, []byte("text"))))), func(m *MMS) bool {
			return m.EventNotification != nil && m.ServiceExt.Enhancement.String == "text"
		}},

		// additionalService.
		{"vMDStop", mreq(mc(78, mp(0))), func(m *MMS) bool { return m.Additional.Kind == MMSAddVMDStop }},
		{"vMDReset", mreq(mc(78, mp(1, []byte{0xff}))), func(m *MMS) bool {
			return m.Additional.Kind == MMSAddVMDReset && m.Additional.ExtendedDerivation
		}},
		{"vMDReset response", mresp(add(1, mp(0, []byte{0}), mp(1, []byte{1}))), func(m *MMS) bool {
			return m.Additional.Status.Physical == 1
		}},
		{"select", mreq(add(2, mp(0, []byte("PI0")), mc(1, mvs("PI1")))), func(m *MMS) bool {
			return m.Additional.Name == "PI0" && m.Additional.Programs[0] == "PI1"
		}},
		{"alterPI", mreq(add(3, mp(0, []byte("PI0")), mc(1, mp(1, []byte{4})))), func(m *MMS) bool {
			return m.Additional.Name == "PI0" && m.Additional.StartCount == MMSStartCount{MMSStartCycleCount, 4}
		}},
		{"uCLoad", mreq(mc(78, mp(5, []byte("UC")))), func(m *MMS) bool { return m.Additional.Kind == MMSAddUCLoad && m.Additional.Name == "UC" }},
		{"uCLoad response", mresp(add(5, elements, mp(1, []byte{0}))), func(m *MMS) bool {
			return wantElements(m.Additional.Elements) && !m.Additional.MoreFollows
		}},
		{"uCUpload", mreq(add(6, mp(0, []byte("UC")), mp(2, []byte{7}))), func(m *MMS) bool {
			return m.Additional.Name == "UC" && *m.Additional.Position == MMSUnitPosition{Kind: MMSUnitULSM, ULSMID: 7}
		}},
		{"uCUpload response", mresp(add(6, elements, mp(3, []byte("P2")))), func(m *MMS) bool {
			return wantElements(m.Additional.Elements) && *m.Additional.Position == MMSUnitPosition{Kind: MMSUnitProgram, Name: "P2"}
		}},
		{"startUC", mreq(add(7, mp(0, []byte("UC")), mp(1, []byte("arg")))), func(m *MMS) bool {
			return m.Additional.Name == "UC" && m.Additional.ExecutionArgument == "arg"
		}},
		{"createUC", mreq(add(9, mp(0, []byte("UC")), mc(1, mvs("D")), mc(2, mvs("P")))), func(m *MMS) bool {
			return m.Additional.Domains[0] == "D" && m.Additional.Programs[0] == "P"
		}},
		{"createUC response", mresp(mc(78, mp(9))), func(m *MMS) bool { return m.Additional.Kind == MMSAddCreateUC }},
		{"getUCAttributes response", mresp(add(12, mc(0, mvs("D")), mc(1, mvs("P")))), func(m *MMS) bool {
			return m.Additional.Domains[0] == "D" && m.Additional.Programs[0] == "P"
		}},
		{"loadUCFromFile", mreq(add(13, mp(0, []byte("UC")), mc(1, mgs("f")), mc(2, mmsAppRef()))), func(m *MMS) bool {
			return m.Additional.FileName[0] == "f" && mmsWantAppRef(m.Additional.ThirdParty)
		}},
		{"defineECL", mreq(add(16, mc(0, mvmd("L")), mc(1, mvmd("EC1")), mc(2, mvmd("L2")))), func(m *MMS) bool {
			a := m.Additional
			return a.ListName == vmd("L") && a.Conditions[0] == vmd("EC1") && a.Lists[0] == vmd("L2")
		}},
		{"deleteECL", mreq(add(17, mvmd("L"))), func(m *MMS) bool { return m.Additional.ListName == vmd("L") }},
		{"getECLAttributes response", mresp(add(20, mc(1, mvmd("EC1")), mc(2, mvmd("L2")))), func(m *MMS) bool {
			return m.Additional.Conditions[0] == vmd("EC1") && m.Additional.Lists[0] == vmd("L2")
		}},
		{"reportECLStatus", mreq(add(21, mc(0, mvmd("L")), mp(1, []byte("EC0")))), func(m *MMS) bool {
			return m.Additional.ListName == vmd("L") && m.Additional.ContinueAfter == "EC0"
		}},
		{"reportECLStatus response", mresp(add(21, mc(1, iecTLV(0x30, mc(0, mvmd("EC1")), mp(1, []byte{2}), mp(2, []byte{1}), mp(3, []byte{0xff}), mc(4, mp(1, []byte{7})))), mp(2, []byte{0}))), func(m *MMS) bool {
			c := m.Additional.ConditionStatus[0]
			return !m.Additional.MoreFollows && c.Name == vmd("EC1") && c.Status.State == MMSEventActive && c.Status.Enrollments == 1 &&
				c.Status.Enabled && c.Status.HasToActive && c.Status.ToActive.Sequence == 7
		}},
		{"alterECLMonitoring", mreq(add(22, mc(0, mvmd("L")), mp(1, []byte{0xff}), mc(2, mp(0, []byte{5})))), func(m *MMS) bool {
			return m.Additional.Enabled && m.Additional.HasPriority && m.Additional.Priority == 5
		}},

		// Data exchange and access control lists.
		{"getDataExchangeAttributes", mreq(mc(80, mvmd("DX"))), func(m *MMS) bool { return *m.ObjectName == vmd("DX") }},
		{"getDataExchangeAttributes response", mresp(mc(80, mp(0, []byte{0xff}), mc(1, mp(3)), mc(2, mp(3), mp(3)), mp(3, []byte("PI")), mp(4, []byte("acl")))), func(m *MMS) bool {
			x := m.DataExchange
			return x.InUse && len(x.RequestTypes) == 1 && len(x.ResponseTypes) == 2 && x.ProgramInvocation == "PI" && x.AccessControlList == "acl"
		}},
		{"exchangeData", mreq(mc(81, mc(0, mvmd("DX")), mc(1, mp(3, []byte{0xff})))), func(m *MMS) bool {
			return m.DataExchange.Name == vmd("DX") && m.DataExchange.Data[0].Bool
		}},
		{"exchangeData response", mresp(mc(81, mc(0, mp(5, []byte{7})))), func(m *MMS) bool { return m.DataExchange.Data[0].Int == 7 }},
		{"defineAccessControlList", mreq(mc(82, mp(0, []byte("ACL")), acl)), func(m *MMS) bool {
			return m.AccessControl.Name == "ACL" && wantACL(m.AccessControl.Elements)
		}},
		{"defineAccessControlList response", mresp(mp(82)), func(m *MMS) bool { return m.AccessControl == nil }},
		{"getAccessControlListAttributes object", mreq(mc(83, mc(2, mc(0, class), mc(1, mvmd("V1"))))), func(m *MMS) bool {
			a := m.AccessControl
			return a.HasObject && a.ObjectClass == MMSClassNamedVariable && a.ObjectName == vmd("V1")
		}},
		{"getAccessControlListAttributes vmd", mreq(mc(83, mp(1))), func(m *MMS) bool { return m.AccessControl.VMD }},
		{"getAccessControlListAttributes response", mresp(mc(83, mc(0, mvs("ACL")), acl, mp(2, []byte{0xff}), mc(3, iecTLV(0x30, mc(0, class), mp(1, []byte{4}))), mp(4, []byte("M_Std")))), func(m *MMS) bool {
			a := m.AccessControl
			return a.Name == "ACL" && wantACL(a.Elements) && a.VMDUse && a.References[0] == MMSAccessReference{MMSClassNamedVariable, 4} && a.AccessControlList == "M_Std"
		}},
		{"reportAccessControlledObjects", mreq(mc(84, mp(0, []byte("ACL")), mc(1, class), mc(2, mvmd("V0")))), func(m *MMS) bool {
			a := m.AccessControl
			return a.Name == "ACL" && a.ObjectClass == MMSClassNamedVariable && a.HasContinueAfter && a.ContinueAfter == vmd("V0")
		}},
		{"reportAccessControlledObjects response", mresp(mc(84, mc(0, mvmd("V1")), mp(1, []byte{0xff}))), func(m *MMS) bool {
			return m.AccessControl.Names[0] == vmd("V1") && m.AccessControl.MoreFollows
		}},
		{"deleteAccessControlList", mreq(mp(85, []byte("ACL"))), func(m *MMS) bool { return m.AccessControl.Name == "ACL" }},
		{"changeAccessControl", mreq(mc(86, mc(1, mc(0, class), mc(1, mp(2, []byte("LD0")))), mp(2, []byte("ACL")))), func(m *MMS) bool {
			a := m.AccessControl
			return a.HasObject && a.Scope == MMSDeleteScopeDomain && a.DomainID == "LD0" && a.Name == "ACL"
		}},
		{"changeAccessControl response", mresp(mc(86, mp(0, []byte{3}), mp(1, []byte{2}))), func(m *MMS) bool {
			return m.AccessControl.Matched == 3 && m.AccessControl.Changed == 2
		}},
	}
}

// TestMMSNoService decodes confirmed-ResponsePDUs without a service, as
// libiec61850 sent them: frame 18 of iec61850_mms_libiec61850.pcap, and
// frame 14 of the ITI iec61850_write.pcap with an empty SEQUENCE in
// place of the service. tshark 4.7 shows both with their invokeID.
func TestMMSNoService(t *testing.T) {
	for _, pdu := range []string{"a103020100", "a1050201003000"} {
		m := &MMS{}
		if err := m.DecodeFromBytes(mhex(pdu), gopacket.NilDecodeFeedback); err != nil {
			t.Errorf("%s: %v", pdu, err)
			continue
		}
		if m.Type != MMSConfirmedResponse || m.InvokeID != 0 || !m.NoService || m.ServiceDecodeErr != errMMSNoService {
			t.Errorf("%s: %+v", pdu, m)
		}
	}

	// A request needs its service.
	if err := (&MMS{}).DecodeFromBytes(mhex("a00702010030000400"), gopacket.NilDecodeFeedback); err == nil {
		t.Error("request with an OCTET STRING service decoded")
	}
}

// mmsBig wraps a body of any length in a constructed context element
// with a low tag.
func mmsBig(tag byte, body []byte) []byte {
	return append(mmsHdr(0xa0|tag, len(body)), body...)
}

// mmsBigPDU builds the confirmed request (0xa0) or response (0xa1) PDU
// around a service element of any length.
func mmsBigPDU(id byte, svc []byte) []byte {
	body := append(iecTLV(0x02, []byte{1}), svc...)
	return append(mmsHdr(id, len(body)), body...)
}

// mmsHigh encodes a constructed context element with a tag past 30, e.g.
// [61] = bf 3d.
func mmsHigh(tag byte, body []byte) []byte {
	return append(append([]byte{0xbf}, mmsHdr(tag, len(body))...), body...)
}

// Lists of minimal items of the services added here are allocated once,
// from their real count.
func TestMMSMoreAllocBound(t *testing.T) {
	const items = 10000
	const maxPerByte = 60

	name := mc(0, mvmd(""))
	journalVars := bytes.Repeat(iecTLV(0x30, mp(0), mc(1, mp(3, []byte{0}))), items)
	journalEntry := append(mp(0, mmsTOD), mmsBig(2, mmsBig(1, journalVars))...)
	modifiers := append(mmsHdr(0x30, items*len(mc(1, name))), bytes.Repeat(mc(1, name), items)...)

	tests := map[string]struct {
		pdu   []byte
		count func(m *MMS) int
	}{
		"named tokens": {mmsBigPDU(0xa1, mmsBig(24, mmsBig(0, bytes.Repeat(mp(0), items)))),
			func(m *MMS) int { return len(m.SemaphoreResp.NamedTokens) }},
		"semaphore entries": {mmsBigPDU(0xa1, mmsBig(25, mmsBig(0, bytes.Repeat(iecTLV(0x30), items)))),
			func(m *MMS) int { return len(m.SemaphoreResp.Entries) }},
		"modifiers": {mmsBigPDU(0xa0, append(modifiers, mp(0, []byte{0})...)),
			func(m *MMS) int { return len(m.Modifiers) }},
		"scattered components": {mmsBigPDU(0xa0, mmsBig(8, append(name, mmsBig(1, bytes.Repeat(iecTLV(0x30, mc(1, mp(4))), items))...))),
			func(m *MMS) int { return len(m.ScatteredAccess.Components) }},
		"enrollments": {mmsBigPDU(0xa1, mmsHigh(61, mmsBig(0, bytes.Repeat(iecTLV(0x30, name), items)))),
			func(m *MMS) int { return len(m.EnrollmentList.Enrollments) }},
		"alarm summaries": {mmsBigPDU(0xa1, mmsHigh(63, mmsBig(0, bytes.Repeat(iecTLV(0x30, name), items)))),
			func(m *MMS) int { return len(m.AlarmSummary.List) }},
		"alarm enrollments": {mmsBigPDU(0xa1, mmsHigh(64, mmsBig(0, bytes.Repeat(iecTLV(0x30, name), items)))),
			func(m *MMS) int { return len(m.AlarmSummary.Enrollments) }},
		"journal entries": {mmsBigPDU(0xa1, mmsHigh(65, mmsBig(0, bytes.Repeat(iecTLV(0x30, mc(2, mp(0, mmsTOD))), items)))),
			func(m *MMS) int { return len(m.JournalResp.List) }},
		"journal contents": {mmsBigPDU(0xa0, mmsHigh(66, append(name, mmsBig(1, bytes.Repeat(iecTLV(0x30, mp(0, mmsTOD)), items))...))),
			func(m *MMS) int { return len(m.JournalReq.Content) }},
		"journal variables": {mmsBigPDU(0xa0, mmsHigh(66, append(name, mmsBig(1, append(mmsHdr(0x30, len(journalEntry)), journalEntry...))...))),
			func(m *MMS) int { return len(m.JournalReq.Content[0].Variables) }},
		"control elements": {mmsBigPDU(0xa1, mmsHigh(78, mmsBig(5, mmsBig(0, bytes.Repeat(mp(2), items))))),
			func(m *MMS) int { return len(m.Additional.Elements) }},
		"listed conditions": {mmsBigPDU(0xa1, mmsHigh(78, mmsBig(21, mmsBig(1, bytes.Repeat(iecTLV(0x30, name), items))))),
			func(m *MMS) int { return len(m.Additional.ConditionStatus) }},
		"access conditions": {mmsBigPDU(0xa0, mmsHigh(82, mmsBig(1, mmsBig(0, mmsBig(5, bytes.Repeat(mp(0), items)))))),
			func(m *MMS) int { return len(m.AccessControl.Elements[0].Condition.Conditions) }},
		"access references": {mmsBigPDU(0xa1, mmsHigh(83, mmsBig(3, bytes.Repeat(iecTLV(0x30), items)))),
			func(m *MMS) int { return len(m.AccessControl.References) }},
		"exchange types": {mmsBigPDU(0xa1, mmsHigh(80, mmsBig(1, bytes.Repeat(mp(3), items)))),
			func(m *MMS) int { return len(m.DataExchange.RequestTypes) }},
		"exchange data": {mmsBigPDU(0xa1, mmsHigh(81, mmsBig(0, bytes.Repeat(mp(3, []byte{0}), items)))),
			func(m *MMS) int { return len(m.DataExchange.Data) }},
	}
	for name, tc := range tests {
		m := &MMS{}
		got := allocPerByte(len(tc.pdu), func() {
			_ = m.DecodeFromBytes(tc.pdu, gopacket.NilDecodeFeedback)
		})
		if m.ServiceDecodeErr != nil {
			t.Errorf("%s: %v", name, m.ServiceDecodeErr)
			continue
		}
		if n := tc.count(m); n != items {
			t.Errorf("%s: %d items, want %d", name, n, items)
		}
		t.Logf("%s: %.0f bytes per input byte", name, got)
		if got > maxPerByte {
			t.Errorf("%s: %.0f bytes per input byte, want <= %d", name, got, maxPerByte)
		}
	}
}

// TestMMSMoreDeepNesting sends 10k nested scattered accesses, access
// conditions and event actions.
func TestMMSMoreDeepNesting(t *testing.T) {
	const depth = 10000
	leaf := mc(0, mvmd("V"))

	// A scattered access whose component is a scattered access: a3 (30
	// (a1 (a3 ...))).
	spec, err := osiBERSingle(mmsNest(depth, leaf, []mmsWrap{{0xa3, nil}, {0x30, nil}, {0xa1, nil}}))
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeMMSVarSpec(spec)
	if err != nil {
		t.Fatal(err)
	}

	// The levels past the cap only keep their raw Spec.
	levels := 0
	for len(v.Scattered) == 1 {
		v = v.Scattered[0].Variable
		levels++
	}
	if levels != osiBERMaxDepth+1 || v.Kind != MMSVariableScattered || v.Scattered != nil || len(v.Spec) == 0 {
		t.Errorf("scattered nesting: %d levels, last %v with %d raw octets", levels, v.Kind, len(v.Spec))
	}
	if _, err := decodeMMSScattered(nil, osiBERMaxDepth+1); err != errOSIBERDepth {
		t.Errorf("scattered depth: %v", err)
	}

	m := &MMS{}
	list := mmsNest(depth, leaf, []mmsWrap{{0x30, nil}, {0xa1, nil}, {0xa3, nil}})
	pdu := mmsBigPDU(0xa0, mmsBig(8, append(mc(0, mvmd("SA")), mmsBig(1, list)...)))
	if err := m.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil || m.ServiceDecodeErr != nil || len(m.ScatteredAccess.Components) != 1 {
		t.Errorf("defineScatteredAccess nesting: %v, %v", err, m.ServiceDecodeErr)
	}

	// The same nesting, shallow enough, decodes.
	if spec, err = osiBERSingle(mmsNest(osiBERMaxDepth/2, leaf, []mmsWrap{{0xa3, nil}, {0x30, nil}, {0xa1, nil}})); err != nil {
		t.Fatal(err)
	}
	if v, _ := decodeMMSVarSpec(spec); len(v.Scattered) != 1 {
		t.Errorf("shallow scattered nesting: %+v", v)
	}

	// joint within joint: a4 (a4 (...)).
	cond := mmsNest(depth, mp(0), []mmsWrap{{0xa4, nil}})
	pdu = mmsBigPDU(0xa0, mmsHigh(82, mmsBig(1, mmsBig(0, cond))))
	if err := m.DecodeFromBytes(pdu, gopacket.NilDecodeFeedback); err != nil || m.ServiceDecodeErr != errOSIBERDepth || m.AccessControl != nil {
		t.Errorf("access condition nesting: %v, %v", err, m.ServiceDecodeErr)
	}

	// An event action holding an event action is decoded one level at a
	// time, by the caller. Building this one costs the square of its depth.
	const actions = 1000
	inner := mp(0, []byte{0})
	for range actions {
		inner = mmsHigh(53, append(mc(0, mvmd("EA")), mmsBig(2, inner)...))
	}
	if err := m.DecodeFromBytes(mmsBigPDU(0xa0, inner), gopacket.NilDecodeFeedback); err != nil || m.ServiceDecodeErr != nil {
		t.Fatalf("event action nesting: %v, %v", err, m.ServiceDecodeErr)
	}
	levels = 0
	for a := m.EventAction; a != nil && a.Service == MMSDefineEventAction; levels++ {
		req, err := a.Request()
		if err != nil {
			t.Fatalf("level %d: %v", levels, err)
		}
		a = req.EventAction
	}
	if levels != actions-1 {
		t.Errorf("event action levels %d, want %d", levels, actions-1)
	}
}

// TestMMSMoreSoftErrors claims lengths past the data and feeds malformed
// fields: the PDU decodes, the typed field stays nil and
// ServiceDecodeErr tells why.
func TestMMSMoreSoftErrors(t *testing.T) {
	name := mc(0, mvmd("N"))
	tests := map[string][]byte{
		"named tokens":         mresp(mc(24, []byte{0xa0, 0x04, 0x80, 0x82, 0xff, 0xff})),
		"semaphore entries":    mresp(mc(25, []byte{0xa0, 0x04, 0x30, 0x84, 0x7f, 0xff})),
		"modifiers":            iecTLV(0xa0, iecTLV(0x02, []byte{1}), []byte{0x30, 0x04, 0xa0, 0x82, 0xff, 0xff}, mp(0, []byte{0})),
		"modifier no names":    iecTLV(0xa0, iecTLV(0x02, []byte{1}), iecTLV(0x30, mc(0)), mp(0, []byte{0})),
		"modifier tag":         iecTLV(0xa0, iecTLV(0x02, []byte{1}), iecTLV(0x30, mc(2)), mp(0, []byte{0})),
		"takeControl no name":  mreq(mc(19, mp(1, []byte("t")))),
		"takeControl response": mresp(mc(19, mp(2))),
		"defineSemaphore":      mreq(mc(21, name, mp(1, []byte{1, 0, 0}))),
		"scattered":            mreq(mc(8, name, []byte{0xa1, 0x04, 0x30, 0x82, 0xff, 0xff})),
		"scattered no list":    mreq(mc(8, name)),
		"scattered no var":     mreq(mc(8, name, mc(1, iecTLV(0x30)))),
		"named variable":       mreq(mc(7, mc(1, mp(0, []byte{1})))),
		"named type":           mreq(mc(14, mvmd("T"))),
		"named type response":  mresp(mc(15, mp(3))),
		"input response":       mresp(mc(17)),
		"output response":      mresp(mp(18, []byte{0})),
		"delete condition":     mreq(mc(48, mp(7))),
		"delete action tag 2":  mreq(mc(54, mp(2, []byte("D")))),
		"delete response":      mresp(mp(48, []byte{1, 0, 0, 0, 0})),
		"alter no name":        mreq(mc(51, mp(1, []byte{0}))),
		"event action":         mreq(mc(53, name)),
		"event action ext":     mreq(mc(53, name, mc(2, mc(79)))),
		"enrollment no name":   mreq(mc(57, mc(1, mvmd("EC")))),
		"enrollments":          mresp(mc(61, mc(0, iecTLV(0x30)))),
		"enrollment state":     mresp(mc(59, mc(0, mp(2)))),
		"alarm summaries":      mresp(mc(63, mc(0, iecTLV(0x30)))),
		"alarm enrollments":    mresp(mc(64, []byte{0xa0, 0x04, 0x30, 0x82, 0xff, 0xff})),
		"journal entry":        mresp(mc(65, mc(0, iecTLV(0x30, mp(0, []byte{1}))))),
		"journal content":      mreq(mc(66, name, mc(1, iecTLV(0x30, mp(3, []byte("x")))))),
		"journal variable":     mreq(mc(66, name, mc(1, iecTLV(0x30, mp(0, mmsTOD), mc(2, mc(1, iecTLV(0x30, mp(0)))))))),
		"journal time":         mreq(mc(65, name, mc(1, mp(0, []byte{1})))),
		"journal position tag": mreq(mc(67, name, mc(1, mp(2)))),
		"initialize response":  mresp(mc(67)),
		"additional tag":       mreq(mc(78, mp(23))),
		"additional empty":     mreq(mc(78)),
		"vMDStop content":      mreq(mc(78, mp(0, []byte{1}))),
		"control element":      mresp(mc(78, mc(5, mc(0, mp(4))))),
		"unit position":        mreq(mc(78, mc(6, mp(0, []byte("UC")), mc(2)))),
		"access condition":     mreq(mc(82, mc(1, mc(0, mp(6))))),
		"access element":       mreq(mc(82, mc(1, mp(0)))),
		"access target":        mreq(mc(83, mp(3))),
		"exchange data":        mreq(mc(81, mc(1, []byte{0x83, 0x05}))),
		"service-ext":          mmsExt(0xa0, mp(0, []byte{0}), mc(40, mp(0))),
		"service-ext empty":    iecTLV(0xa0, iecTLV(0x02, []byte{1}), mp(0, []byte{0}), mc(79)),
		"service-ext status":   mmsExt(0xa1, mc(0, mp(0, []byte{0}), mp(1, []byte{0})), mc(0, mp(0))),
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
		if m.SemaphoreReq != nil || m.SemaphoreResp != nil || m.Modifiers != nil || m.ScatteredAccess != nil || m.NamedVariable != nil ||
			m.NamedType != nil || m.OperatorResp != nil || m.EventDeleteReq != nil || m.EventDeleteResp != nil || m.EventAlter != nil ||
			m.EventAction != nil || m.EventEnrollment != nil || m.EnrollmentList != nil || m.EnrollmentStatus != nil || m.AlarmSummary != nil ||
			m.JournalReq != nil || m.JournalResp != nil || m.AccessControl != nil || m.DataExchange != nil {
			t.Errorf("%s: partial typed field %+v", name, m)
		}
	}

	// An additional service or service-ext detail that does not decode
	// keeps its kind and raw value.
	m := &MMS{}
	if err := m.DecodeFromBytes(tests["vMDStop content"], gopacket.NilDecodeFeedback); err != nil || m.Additional.Kind != MMSAddVMDStop || !bytes.Equal(m.Additional.Data, []byte{1}) {
		t.Errorf("additional marker: %v, %+v", err, m.Additional)
	}
	if err := m.DecodeFromBytes(tests["service-ext"], gopacket.NilDecodeFeedback); err != nil || m.ServiceExt.Service != MMSStart || !bytes.Equal(m.ServiceExt.Raw, mp(0)) {
		t.Errorf("service-ext marker: %v, %+v", err, m.ServiceExt)
	}
}
