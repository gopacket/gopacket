// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gopacket/gopacket"
)

// iec104DumpOrder is the field order of a dump line.
var iec104DumpOrder = strings.Fields(`
apdulen type utype tx rx typeid sq numix causetx nega test oa addr ioa
cp16time cp24time.ms cp24time.min cp24time.iv cp56time.ms cp56time.min
cp56time.gen cp56time.iv cp56time.hour cp56time.su cp56time.day
cp56time.dow cp56time.month cp56time.year siq.spi siq.bl siq.sb siq.nt
siq.iv diq.dpi diq.bl diq.sb diq.nt diq.iv qds.ov qds.bl qds.sb qds.nt
qds.iv vti.v vti.t qos.ql qos.se sco.on sco.qu sco.se dco.on dco.qu
dco.se rco.up rco.qu rco.se qpm.kpa qpm.lpc qpm.pop nof lof
frq.confirm frq.qualifier nos srq.ready srq.qualifier scq.select
scq.qualifier lsq chs afq.ack afq.qualifier los segmentdata sof.status
sof.lfd sof.for sof.fa sep.es sep.ei sep.bl sep.sb sep.nt sep.iv
spe.gs spe.sl1 spe.sl2 spe.sl3 spe.sie spe.srd qdp.ei qdp.bl qdp.sb
qdp.nt qdp.iv oci.gc oci.cl1 oci.cl2 oci.cl3 qpa fbp scd.st scd.cd asn
asn.fin asn.fir usr mal rsc csq ksq kwa kst hln hal cln wkl
challenge_data hmac wkd aid err etm.ms etm.min etm.iv etm.hour etm.su
etm.day etm.dow etm.month etm.year eln error_text coi.r coi.i qoi
qcc.rqt qcc.frz qrp bcr.count bcr.sq bcr.cy bcr.ca bcr.iv bitstring
float normval scalval tsc rawdata`)

// iec104Dump collects the fields of a frame under the names tshark gives
// them, less the "iec60870_asdu." and "iec60870_104." prefixes, each with
// its values in frame order. It renders them as tshark -T fields does, so
// that a line of tshark output is the wanted value of a test.
type iec104Dump struct {
	vals map[string][]string
	// noOA is set for a 1-octet cause of transmission: no originator.
	noOA bool
}

func (x *iec104Dump) add(name string, v interface{}) {
	if x.vals == nil {
		x.vals = map[string][]string{}
	}
	var s string
	switch t := v.(type) {
	case bool:
		s = "False"
		if t {
			s = "True"
		}
	case []byte:
		s = hex.EncodeToString(t)
	case string:
		s = t
	default:
		s = fmt.Sprint(v)
	}
	x.vals[name] = append(x.vals[name], s)
}

func iec104Hex(v uint8) string { return fmt.Sprintf("0x%02x", v) }

func (x *iec104Dump) time(prefix string, t IEC104Time) {
	x.add(prefix+".ms", t.Milliseconds)
	x.add(prefix+".min", t.Minute)
	if prefix != "etm" {
		if t.Format == IEC104TimeCP56 {
			x.add(prefix+".gen", t.Substituted)
		}
	}
	x.add(prefix+".iv", t.Invalid)
	if t.Format != IEC104TimeCP56 {
		return
	}
	x.add(prefix+".hour", t.Hour)
	x.add(prefix+".su", t.Summer)
	x.add(prefix+".day", t.Day)
	x.add(prefix+".dow", t.Weekday)
	x.add(prefix+".month", t.Month)
	x.add(prefix+".year", t.Year)
}

func (x *iec104Dump) quality(prefix string, q IEC104Quality, ov, ei bool) {
	if ov {
		x.add(prefix+".ov", q&IEC104QualityOverflow != 0)
	}
	if ei {
		x.add(prefix+".ei", q&IEC104QualityElapsedInvalid != 0)
	}
	x.add(prefix+".bl", q&IEC104QualityBlocked != 0)
	x.add(prefix+".sb", q&IEC104QualitySubstituted != 0)
	x.add(prefix+".nt", q&IEC104QualityNotTopical != 0)
	x.add(prefix+".iv", q&IEC104QualityInvalid != 0)
}

func (x *iec104Dump) part(part iec104Part, o *IEC104Object, t IEC104TypeID) {
	switch part {
	case partSIQ:
		x.add("siq.spi", o.SinglePoint)
		x.quality("siq", o.Quality, false, false)
	case partDIQ:
		x.add("diq.dpi", uint8(o.DoublePoint))
		x.quality("diq", o.Quality, false, false)
	case partVTI:
		x.add("vti.v", o.Step)
		x.add("vti.t", o.Transient)
	case partQDS:
		x.quality("qds", o.Quality, true, false)
	case partQDP:
		x.quality("qdp", o.Quality, false, true)
	case partBSI:
		x.add("bitstring", fmt.Sprintf("0x%08x", o.Bitstring))
	case partSCD:
		x.add("scd.st", fmt.Sprintf("0x%04x", o.Status))
		x.add("scd.cd", fmt.Sprintf("0x%04x", o.Changed))
	case partNVA:
		x.add("normval", fmt.Sprintf("%.5g", o.NormalizedValue()))
	case partSVA:
		x.add("scalval", o.Scaled)
	case partFloat:
		x.add("float", fmt.Sprintf("%.5g", o.Float))
	case partBCR:
		x.add("bcr.count", o.Counter.Value)
		x.add("bcr.sq", o.Counter.Sequence)
		x.add("bcr.cy", o.Counter.Carry)
		x.add("bcr.ca", o.Counter.Adjusted)
		x.add("bcr.iv", o.Counter.Invalid)
	case partSEP:
		x.add("sep.es", uint8(o.DoublePoint))
		x.quality("sep", o.Quality, false, true)
	case partSPE:
		x.add("spe.gs", o.Event&IEC104EventGeneral != 0)
		x.add("spe.sl1", o.Event&IEC104EventPhaseL1 != 0)
		x.add("spe.sl2", o.Event&IEC104EventPhaseL2 != 0)
		x.add("spe.sl3", o.Event&IEC104EventPhaseL3 != 0)
		x.add("spe.sie", o.Event&IEC104EventEarth != 0)
		x.add("spe.srd", o.Event&IEC104EventReverse != 0)
	case partOCI:
		x.add("oci.gc", o.Event&IEC104EventGeneral != 0)
		x.add("oci.cl1", o.Event&IEC104EventPhaseL1 != 0)
		x.add("oci.cl2", o.Event&IEC104EventPhaseL2 != 0)
		x.add("oci.cl3", o.Event&IEC104EventPhaseL3 != 0)
	case partCP16:
		x.add("cp16time", o.Elapsed)
	case partCP24:
		x.time("cp24time", o.Time)
	case partCP56:
		x.time("cp56time", o.Time)
	case partCP56Stop:
		x.time("cp56time", o.File.Stop)
	case partSCO:
		x.add("sco.on", o.Command.State != 0)
		x.add("sco.qu", uint8(o.Command.QU()))
		x.add("sco.se", o.Command.Select)
	case partDCO:
		x.add("dco.on", o.Command.State)
		x.add("dco.qu", uint8(o.Command.QU()))
		x.add("dco.se", o.Command.Select)
	case partRCO:
		x.add("rco.up", o.Command.State)
		x.add("rco.qu", uint8(o.Command.QU()))
		x.add("rco.se", o.Command.Select)
	case partQOS:
		x.add("qos.ql", o.Command.Qualifier)
		x.add("qos.se", o.Command.Select)
	case partQualifier:
		x.qualifier(o, t)
	case partTest:
		if t == IEC104TypeTest {
			x.add("fbp", fmt.Sprintf("0x%04x", o.Test))
		} else {
			x.add("tsc", o.Test)
		}
	case partNOF:
		x.add("nof", o.File.Name)
	case partLOF:
		x.add("lof", o.File.Length)
	case partNOS:
		x.add("nos", o.File.Section)
	case partFileQual:
		x.fileQual(o, t)
	case partCHS:
		x.add("chs", iec104Hex(o.File.Checksum))
	case partSegment:
		x.add("los", o.File.Length)
		if len(o.File.Segment) > 0 {
			x.add("segmentdata", o.File.Segment)
		}
	case partAID:
		x.add("aid", o.AssociationID)
	}
}

func iec104Bit(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func (x *iec104Dump) qualifier(o *IEC104Object, t IEC104TypeID) {
	switch t {
	case IEC104TypeEndOfInit:
		x.add("coi.r", uint8(o.COI().Cause()))
		x.add("coi.i", o.COI().LocalChange())
	case IEC104TypeInterrogation:
		x.add("qoi", uint8(o.QOI()))
	case IEC104TypeCounterInterrogation:
		x.add("qcc.rqt", uint8(o.QCC().Request()))
		x.add("qcc.frz", uint8(o.QCC().Freeze()))
	case IEC104TypeResetProcess:
		x.add("qrp", uint8(o.QRP()))
	case IEC104TypeParamActivation:
		x.add("qpa", uint8(o.QPA()))
	default:
		x.add("qpm.kpa", uint8(o.QPM().Kind()))
		x.add("qpm.lpc", iec104Bit(o.QPM().LocalChange()))
		x.add("qpm.pop", iec104Bit(o.QPM().NotInOperation()))
	}
}

func (x *iec104Dump) fileQual(o *IEC104Object, t IEC104TypeID) {
	f := &o.File
	switch t {
	case IEC104TypeFileReady:
		x.add("frq.confirm", f.FRQ().Negative())
		x.add("frq.qualifier", f.FRQ().Qualifier())
	case IEC104TypeSectionReady:
		x.add("srq.ready", f.SRQ().NotReady())
		x.add("srq.qualifier", f.SRQ().Qualifier())
	case IEC104TypeCallFile:
		x.add("scq.select", uint8(f.SCQ().Action()))
		x.add("scq.qualifier", uint8(f.SCQ().Error()))
	case IEC104TypeLastSection:
		x.add("lsq", uint8(f.LSQ()))
	case IEC104TypeAckFile:
		x.add("afq.ack", uint8(f.AFQ().Ack()))
		x.add("afq.qualifier", uint8(f.AFQ().Error()))
	case IEC104TypeDirectory:
		x.add("sof.status", f.SOF().Status())
		x.add("sof.lfd", f.SOF().LastFile())
		x.add("sof.for", f.SOF().Directory())
		x.add("sof.fa", f.SOF().Active())
	}
}

func (x *iec104Dump) security(t IEC104TypeID, s *IEC104Security) {
	if t != IEC104TypeKeyStatusRequest {
		x.add("asn.fin", s.Final)
		x.add("asn.fir", s.First)
		x.add("asn", s.SegmentNumber)
	}
	if !s.Decoded {
		return
	}
	switch t {
	case IEC104TypeAuthChallenge:
		x.add("csq", s.Sequence)
		x.add("usr", s.User)
		x.add("mal", uint8(s.MACAlgorithm))
		x.add("rsc", s.Reason)
		x.add("cln", len(s.Challenge))
		x.add("challenge_data", s.Challenge)
	case IEC104TypeAuthReply:
		x.add("csq", s.Sequence)
		x.add("usr", s.User)
		x.add("hln", len(s.MAC))
		x.add("hmac", s.MAC)
	case IEC104TypeAuthAggressive:
		if s.Encapsulated != nil {
			x.asdu(s.Encapsulated)
		}
		x.add("csq", s.Sequence)
		x.add("usr", s.User)
		x.add("hmac", s.MAC)
	case IEC104TypeKeyStatusRequest:
		x.add("usr", s.User)
	case IEC104TypeKeyStatus:
		x.add("ksq", s.Sequence)
		x.add("usr", s.User)
		x.add("kwa", uint8(s.KeyWrap))
		x.add("kst", uint8(s.KeyStatus))
		x.add("hal", uint8(s.MACAlgorithm))
		x.add("cln", len(s.Challenge))
		x.add("challenge_data", s.Challenge)
		if len(s.MAC) > 0 {
			x.add("hmac", s.MAC)
		}
	case IEC104TypeKeyChange:
		x.add("ksq", s.Sequence)
		x.add("usr", s.User)
		x.add("wkl", len(s.WrappedKey))
		x.add("wkd", s.WrappedKey)
	case IEC104TypeAuthError:
		x.add("csq", s.Sequence)
		x.add("usr", s.User)
		x.add("aid", s.AssociationID)
		x.add("err", uint8(s.ErrorCode))
		x.time("etm", s.ErrorTime)
		x.add("eln", len(s.ErrorText))
		if len(s.ErrorText) > 0 {
			x.add("error_text", string(s.ErrorText))
		}
	}
}

func (x *iec104Dump) asdu(a *IEC104ASDU) {
	x.add("typeid", uint8(a.TypeID))
	x.add("sq", a.Sequence)
	x.add("numix", a.NumObjects)
	x.add("causetx", uint8(a.Cause))
	x.add("nega", a.Negative)
	x.add("test", a.Test)
	if !x.noOA {
		x.add("oa", a.Originator)
	}
	x.add("addr", a.CommonAddr)

	if a.TypeID.hasSecurityBody() {
		x.security(a.TypeID, &a.Security)
		return
	}

	info, known := iec104Types[a.TypeID]
	if !known || a.TypeID == IEC104TypeRead {
		raw := a.Raw
		if a.TypeID == IEC104TypeRead && len(a.Objects) > 0 {
			x.add("ioa", a.Objects[0].IOA)
			return
		}
		if len(raw) >= 3 {
			x.add("ioa", iec104UintLE(raw[:3]))
			if len(raw) > 3 {
				x.add("rawdata", raw[3:])
			}
		}
		return
	}

	for k := range a.Objects {
		o := &a.Objects[k]
		x.add("ioa", o.IOA)
		for _, part := range info.parts {
			x.part(part, o, a.TypeID)
		}
	}
}

// apdus dumps the IEC 104 layers of a packet.
func (x *iec104Dump) apdus(p gopacket.Packet) {
	for _, l := range p.Layers() {
		apdu, ok := l.(*IEC104)
		if !ok {
			continue
		}

		x.add("apdulen", apdu.Length)
		switch apdu.Format {
		case IEC104FormatI:
			x.add("type", "0x00000000")
			x.add("tx", apdu.SendSeq)
			x.add("rx", apdu.RecvSeq)
			x.asdu(&apdu.ASDU)
		case IEC104FormatS:
			x.add("type", "0x00000001")
			x.add("rx", apdu.RecvSeq)
		case IEC104FormatU:
			x.add("type", "0x00000003")
			x.add("utype", fmt.Sprintf("0x%08x", uint8(apdu.UFunction)>>2))
		}
	}
}

// String lists the fields that have values as "name=v1,v2", in the order
// of iec104DumpOrder.
func (x *iec104Dump) String() string {
	var out []string
	for _, name := range iec104DumpOrder {
		// tshark prints nothing for an empty byte string.
		if v := strings.Join(x.vals[name], ","); v != "" {
			out = append(out, name+"="+v)
		}
	}
	return strings.Join(out, " ")
}
