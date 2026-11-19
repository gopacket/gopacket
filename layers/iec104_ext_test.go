// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

// iec104HandmadeGolden is tshark 4.7 ground truth for
// testdata/iec104_handmade.pcap, one line per frame in the form of
// iec104Dump. The capture was built with text2pcap from hand-written
// APDUs for what the public captures lack: qualifiers, file transfer and
// secure authentication. tshark dissects every frame without a malformed
// or expert item.
var iec104HandmadeGolden = []string{
	// M_EI_NA_1 COI remote reset, local change
	"apdulen=14 type=0x00000000 tx=0 rx=1 typeid=70 sq=False numix=1 causetx=4 nega=False test=False oa=3 addr=10 ioa=0 coi.r=2 coi.i=True",
	// C_IC_NA_1 QOI station
	"apdulen=14 type=0x00000000 tx=1 rx=1 typeid=100 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=0 qoi=20",
	// C_IC_NA_1 QOI group 5 negative
	"apdulen=14 type=0x00000000 tx=2 rx=1 typeid=100 sq=False numix=1 causetx=7 nega=True test=False oa=3 addr=10 ioa=0 qoi=25",
	// C_CI_NA_1 QCC general, freeze with reset
	"apdulen=14 type=0x00000000 tx=3 rx=1 typeid=101 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=0 qcc.rqt=5 qcc.frz=2",
	// C_CI_NA_1 QCC group 3, reset
	"apdulen=14 type=0x00000000 tx=4 rx=1 typeid=101 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=0 qcc.rqt=3 qcc.frz=3",
	// C_RP_NA_1 QRP event buffer
	"apdulen=14 type=0x00000000 tx=5 rx=1 typeid=105 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=0 qrp=2",
	// P_ME_NA_1 QPM threshold, POP, LPC
	"apdulen=16 type=0x00000000 tx=6 rx=1 typeid=110 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=33 qpm.kpa=1 qpm.lpc=1 qpm.pop=1 normval=0.5",
	// P_ME_NB_1 QPM smoothing, LPC
	"apdulen=16 type=0x00000000 tx=7 rx=1 typeid=111 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=34 qpm.kpa=2 qpm.lpc=1 qpm.pop=0 scalval=-5",
	// P_ME_NC_1 QPM low limit
	"apdulen=18 type=0x00000000 tx=8 rx=1 typeid=112 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=35 qpm.kpa=3 qpm.lpc=0 qpm.pop=0 float=1.5",
	// P_AC_NA_1 QPA cyclic
	"apdulen=14 type=0x00000000 tx=9 rx=1 typeid=113 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=36 qpa=3",
	// C_SC_NA_1 on, short pulse, select
	"apdulen=14 type=0x00000000 tx=10 rx=1 typeid=45 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=49 sco.on=True sco.qu=1 sco.se=True",
	// C_DC_NA_1 on, long pulse
	"apdulen=14 type=0x00000000 tx=11 rx=1 typeid=46 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=50 dco.on=2 dco.qu=2 dco.se=False",
	// C_RC_NA_1 lower, persistent, select
	"apdulen=14 type=0x00000000 tx=12 rx=1 typeid=47 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=51 rco.up=1 rco.qu=3 rco.se=True",
	// C_SE_NA_1 QOS QL 5 select
	"apdulen=16 type=0x00000000 tx=13 rx=1 typeid=48 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=52 qos.ql=5 qos.se=True normval=-0.5",
	// C_SE_NB_1 QOS QL 127
	"apdulen=16 type=0x00000000 tx=14 rx=1 typeid=49 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=53 qos.ql=127 qos.se=False scalval=12345",
	// C_SE_NC_1 QOS execute
	"apdulen=18 type=0x00000000 tx=15 rx=1 typeid=50 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=54 qos.ql=0 qos.se=False float=-10",
	// C_SE_TC_1 QOS with time
	"apdulen=25 type=0x00000000 tx=16 rx=1 typeid=63 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=55 cp56time.ms=1000 cp56time.min=30 cp56time.gen=False cp56time.iv=False cp56time.hour=10 cp56time.su=True cp56time.day=15 cp56time.dow=3 cp56time.month=11 cp56time.year=25 qos.ql=1 qos.se=True float=10",
	// F_FR_NA_1 negative
	"apdulen=19 type=0x00000000 tx=17 rx=1 typeid=120 sq=False numix=1 causetx=13 nega=False test=False oa=3 addr=10 ioa=65 nof=2 lof=74565 frq.confirm=True frq.qualifier=1",
	// F_SR_NA_1 not ready
	"apdulen=20 type=0x00000000 tx=18 rx=1 typeid=121 sq=False numix=1 causetx=13 nega=False test=False oa=3 addr=10 ioa=65 nof=2 lof=1024 nos=3 srq.ready=True srq.qualifier=0",
	// F_SC_NA_1 request section, checksum failed
	"apdulen=17 type=0x00000000 tx=19 rx=1 typeid=122 sq=False numix=1 causetx=13 nega=False test=False oa=3 addr=10 ioa=65 nof=2 nos=3 scq.select=6 scq.qualifier=2",
	// F_LS_NA_1 section without deactivation
	"apdulen=18 type=0x00000000 tx=20 rx=1 typeid=123 sq=False numix=1 causetx=13 nega=False test=False oa=3 addr=10 ioa=65 nof=2 nos=3 lsq=3 chs=0x5a",
	// F_AF_NA_1 negative file ack, unexpected name
	"apdulen=17 type=0x00000000 tx=21 rx=1 typeid=124 sq=False numix=1 causetx=13 nega=False test=False oa=3 addr=10 ioa=65 nof=2 nos=3 afq.ack=2 afq.qualifier=4",
	// F_SG_NA_1 five octets
	"apdulen=22 type=0x00000000 tx=22 rx=1 typeid=125 sq=False numix=1 causetx=13 nega=False test=False oa=3 addr=10 ioa=65 nof=2 nos=3 los=5 segmentdata=deadbeef01",
	// F_SG_NA_1 empty
	"apdulen=17 type=0x00000000 tx=23 rx=1 typeid=125 sq=False numix=1 causetx=13 nega=False test=False oa=3 addr=10 ioa=65 nof=2 nos=3 los=0",
	// F_DR_TA_1 two entries SQ
	"apdulen=39 type=0x00000000 tx=24 rx=1 typeid=126 sq=True numix=2 causetx=5 nega=False test=False oa=3 addr=10 ioa=80,81 cp56time.ms=1000,60159 cp56time.min=30,59 cp56time.gen=False,False cp56time.iv=False,True cp56time.hour=10,23 cp56time.su=True,False cp56time.day=15,31 cp56time.dow=3,4 cp56time.month=11,12 cp56time.year=25,99 nof=1,2 lof=4096,16777215 sof.status=5,0 sof.lfd=True,True sof.for=True,False sof.fa=True,False",
	// F_DR_TA_1 two entries
	"apdulen=42 type=0x00000000 tx=25 rx=1 typeid=126 sq=False numix=2 causetx=5 nega=False test=False oa=3 addr=10 ioa=80,96 cp56time.ms=1000,60159 cp56time.min=30,59 cp56time.gen=False,False cp56time.iv=False,True cp56time.hour=10,23 cp56time.su=True,False cp56time.day=15,31 cp56time.dow=3,4 cp56time.month=11,12 cp56time.year=25,99 nof=1,2 lof=4096,16777215 sof.status=5,0 sof.lfd=False,True sof.for=True,False sof.fa=False,True",
	// F_SC_NB_1 range
	"apdulen=29 type=0x00000000 tx=26 rx=1 typeid=127 sq=False numix=1 causetx=5 nega=False test=False oa=3 addr=10 ioa=65 cp56time.ms=1000,60159 cp56time.min=30,59 cp56time.gen=False,False cp56time.iv=False,True cp56time.hour=10,23 cp56time.su=True,False cp56time.day=15,31 cp56time.dow=3,4 cp56time.month=11,12 cp56time.year=25,99 nof=3",
	// S_IT_TC_1 statistics
	"apdulen=27 type=0x00000000 tx=27 rx=1 typeid=41 sq=False numix=1 causetx=3 nega=False test=False oa=3 addr=10 ioa=112 cp56time.ms=1000 cp56time.min=30 cp56time.gen=False cp56time.iv=False cp56time.hour=10 cp56time.su=True cp56time.day=15 cp56time.dow=3 cp56time.month=11 cp56time.year=25 aid=4660 bcr.count=305419896 bcr.sq=5 bcr.cy=True bcr.ca=False bcr.iv=True",
	// C_TS_NA_1 pattern
	"apdulen=15 type=0x00000000 tx=28 rx=1 typeid=104 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=0 fbp=0x55aa",
	// C_TS_TA_1 counter
	"apdulen=22 type=0x00000000 tx=29 rx=1 typeid=107 sq=False numix=1 causetx=6 nega=False test=False oa=3 addr=10 ioa=0 cp56time.ms=1000 cp56time.min=30 cp56time.gen=False cp56time.iv=False cp56time.hour=10 cp56time.su=True cp56time.day=15 cp56time.dow=3 cp56time.month=11 cp56time.year=25 tsc=4660",
	// S_CH_NA_1
	"apdulen=25 type=0x00000000 tx=30 rx=1 typeid=81 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 asn=1 asn.fin=True asn.fir=True usr=2 mal=4 rsc=1 csq=305419896 cln=4 challenge_data=deadbeef",
	// S_RP_NA_1
	"apdulen=27 type=0x00000000 tx=31 rx=1 typeid=82 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 asn=2 asn.fin=True asn.fir=True usr=2 csq=305419896 hln=8 hmac=0102030405060708",
	// S_AR_NA_1 wrapping C_SC_NA_1
	"apdulen=35 type=0x00000000 tx=32 rx=1 typeid=83,45 sq=False,False numix=1,1 causetx=14,6 nega=False,False test=False,False oa=3,3 addr=10,10 ioa=49 sco.on=True sco.qu=0 sco.se=True asn=0 asn.fin=True asn.fir=True usr=2 csq=305419897 hmac=aabbccddeeff1122",
	// S_KR_NA_1
	"apdulen=12 type=0x00000000 tx=33 rx=1 typeid=84 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 usr=2",
	// S_KS_NA_1 HMAC-SHA-256/16
	"apdulen=42 type=0x00000000 tx=34 rx=1 typeid=85 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 asn=0 asn.fin=True asn.fir=True usr=2 ksq=1 kwa=1 kst=1 hal=4 cln=4 challenge_data=a1a2a3a4 hmac=000102030405060708090a0b0c0d0e0f",
	// S_KS_NA_1 no MAC
	"apdulen=24 type=0x00000000 tx=35 rx=1 typeid=85 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 asn=0 asn.fin=True asn.fir=True usr=2 ksq=2 kwa=2 kst=2 hal=0 cln=2 challenge_data=b1b2",
	// S_KS_NA_1 AES-GMAC
	"apdulen=34 type=0x00000000 tx=36 rx=1 typeid=85 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 asn=0 asn.fin=True asn.fir=True usr=1 ksq=3 kwa=1 kst=1 hal=6 cln=0 hmac=000102030405060708090a0b",
	// S_KC_NA_1
	"apdulen=25 type=0x00000000 tx=37 rx=1 typeid=86 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 asn=0 asn.fin=True asn.fir=True usr=2 ksq=4 wkl=6 wkd=112233445566",
	// S_ER_NA_1 with text
	"apdulen=35 type=0x00000000 tx=38 rx=1 typeid=87 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 asn=0 asn.fin=True asn.fir=True usr=2 csq=305419896 aid=7 err=5 etm.ms=1000 etm.min=30 etm.iv=False etm.hour=10 etm.su=True etm.day=15 etm.dow=3 etm.month=11 etm.year=25 eln=6 error_text=denied",
	// S_ER_NA_1 without text
	"apdulen=29 type=0x00000000 tx=39 rx=1 typeid=87 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 asn=0 asn.fin=True asn.fir=True usr=1 csq=1 aid=0 err=1 etm.ms=60159 etm.min=59 etm.iv=True etm.hour=23 etm.su=False etm.day=31 etm.dow=4 etm.month=12 etm.year=99 eln=0",
	// S_UK_NA_1 raw
	"apdulen=16 type=0x00000000 tx=40 rx=1 typeid=93 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 ioa=131520 rawdata=030405",
	// unknown type 200 raw
	"apdulen=15 type=0x00000000 tx=41 rx=1 typeid=200 sq=False numix=1 causetx=3 nega=False test=False oa=3 addr=10 ioa=197121 rawdata=aabb",
	// S_CH_NA_1 first of several segments
	"apdulen=17 type=0x00000000 tx=42 rx=1 typeid=81 sq=False numix=1 causetx=14 nega=False test=False oa=3 addr=10 asn=1 asn.fin=False asn.fir=True",
}

// iec104TCPPayload is where the APDU starts in the handmade capture:
// after Ethernet, IPv4 and TCP headers without options.
const iec104TCPPayload = 54

// iec104Handmade returns the APDUs of the handmade capture.
func iec104Handmade(t testing.TB) [][]byte {
	t.Helper()
	packets, err := iec104ReadPcap("testdata/iec104_handmade.pcap")
	if err != nil {
		t.Fatal(err)
	}

	for k := range packets {
		packets[k] = packets[k][iec104TCPPayload:]
	}
	return packets
}

// Every field of every handmade frame decodes as tshark decodes it.
func TestIEC104Handmade(t *testing.T) {
	packets := iec104Handmade(t)
	if len(packets) != len(iec104HandmadeGolden) {
		t.Fatalf("%d frames, want %d", len(packets), len(iec104HandmadeGolden))
	}

	for k, data := range packets {
		p := gopacket.NewPacket(data, LayerTypeIEC104, gopacket.Default)
		if e := p.ErrorLayer(); e != nil {
			t.Errorf("frame %d: %v", k+1, e.Error())
		}

		var x iec104Dump
		x.apdus(p)
		if got := x.String(); got != iec104HandmadeGolden[k] {
			t.Errorf("frame %d:\n got %s\nwant %s", k+1, got, iec104HandmadeGolden[k])
		}
	}
}

// iec104First decodes the first handmade frame of a type identification.
func iec104First(t *testing.T, id IEC104TypeID) *IEC104ASDU {
	t.Helper()
	for _, data := range iec104Handmade(t) {
		var apdu IEC104
		if err := apdu.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		if apdu.ASDU.TypeID == id {
			return &apdu.ASDU
		}
	}

	t.Fatalf("no frame of type %v", id)
	return nil
}

// The typed qualifier accessors split the octets as the golden lines say.
func TestIEC104Qualifiers(t *testing.T) {
	obj := func(id IEC104TypeID) *IEC104Object {
		return &iec104First(t, id).Objects[0]
	}

	coi := obj(IEC104TypeEndOfInit).COI()
	if coi.Cause() != IEC104COIRemoteReset || !coi.LocalChange() {
		t.Errorf("COI %#x", uint8(coi))
	}
	if q := obj(IEC104TypeInterrogation).QOI(); q != IEC104QOIStation || q.Group() != 0 {
		t.Errorf("QOI %d", q)
	}
	if q := obj(IEC104TypeCounterInterrogation).QCC(); q.Request() != IEC104QCCGeneral ||
		q.Freeze() != IEC104QCCFreezeReset {
		t.Errorf("QCC %#x", uint8(q))
	}
	if q := obj(IEC104TypeResetProcess).QRP(); q != IEC104QRPEventBuffer {
		t.Errorf("QRP %d", q)
	}
	if q := obj(IEC104TypeParamNormalized).QPM(); q.Kind() != IEC104QPMThreshold ||
		!q.LocalChange() || !q.NotInOperation() {
		t.Errorf("QPM %#x", uint8(q))
	}
	if q := obj(IEC104TypeParamActivation).QPA(); q != IEC104QPACyclicTx {
		t.Errorf("QPA %d", q)
	}

	// QOC: SCO on, short pulse, select. QOS: QL 5, select.
	if c := obj(IEC104TypeSingleCommand).Command; c.State != 1 || c.QU() != IEC104QUShortPulse || !c.Select {
		t.Errorf("SCO %+v", c)
	}
	if c := obj(IEC104TypeSetpointNormalized).Command; c.Qualifier != 5 || !c.Select {
		t.Errorf("QOS %+v", c)
	}
}

// The file transfer types decode into typed names, lengths and qualifiers.
func TestIEC104FileTransfer(t *testing.T) {
	file := func(id IEC104TypeID) *IEC104File {
		return &iec104First(t, id).Objects[0].File
	}

	f := file(IEC104TypeFileReady)
	if f.Name != 2 || f.Length != 0x012345 || !f.FRQ().Negative() || f.FRQ().Qualifier() != 1 {
		t.Errorf("F_FR_NA_1 %+v", f)
	}
	f = file(IEC104TypeSectionReady)
	if f.Name != 2 || f.Section != 3 || f.Length != 0x000400 || !f.SRQ().NotReady() || f.SRQ().Qualifier() != 0 {
		t.Errorf("F_SR_NA_1 %+v", f)
	}
	f = file(IEC104TypeCallFile)
	if f.SCQ().Action() != IEC104SCQRequestSection || f.SCQ().Error() != IEC104FileErrChecksum {
		t.Errorf("F_SC_NA_1 %+v", f)
	}
	f = file(IEC104TypeLastSection)
	if f.LSQ() != IEC104LSQSection || f.Checksum != 0x5a {
		t.Errorf("F_LS_NA_1 %+v", f)
	}
	f = file(IEC104TypeAckFile)
	if f.AFQ().Ack() != IEC104AFQFileNegative || f.AFQ().Error() != IEC104FileErrName {
		t.Errorf("F_AF_NA_1 %+v", f)
	}
	f = file(IEC104TypeSegment)
	if f.Length != 5 || !bytes.Equal(f.Segment, []byte{0xde, 0xad, 0xbe, 0xef, 0x01}) {
		t.Errorf("F_SG_NA_1 %+v", f)
	}

	// F_DR_TA_1 with SQ: the second entry follows without an address.
	dir := iec104First(t, IEC104TypeDirectory)
	if len(dir.Objects) != 2 || dir.Objects[1].IOA != dir.Objects[0].IOA+1 {
		t.Fatalf("F_DR_TA_1 objects %+v", dir.Objects)
	}
	sof := dir.Objects[0].File.SOF()
	if sof.Status() != 5 || !sof.LastFile() || !sof.Directory() || !sof.Active() {
		t.Errorf("SOF %#x", uint8(sof))
	}
	if f := dir.Objects[1].File; f.Name != 2 || f.Length != 0xffffff || f.SOF().Directory() {
		t.Errorf("F_DR_TA_1 second entry %+v", f)
	}

	q := iec104First(t, IEC104TypeQueryLog).Objects[0]
	if q.File.Name != 3 || q.Time.Hour != 10 || q.File.Stop.Hour != 23 || !q.File.Stop.Invalid {
		t.Errorf("F_SC_NB_1 %+v", q)
	}
}

// The secure authentication bodies decode into typed fields.
func TestIEC104Security(t *testing.T) {
	s := &iec104First(t, IEC104TypeAuthChallenge).Security
	if !s.Decoded || !s.First || !s.Final || s.SegmentNumber != 1 || s.Sequence != 0x12345678 ||
		s.User != 2 || s.MACAlgorithm != IEC104MACSHA256x16 || s.Reason != 1 ||
		!bytes.Equal(s.Challenge, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("S_CH_NA_1 %+v", s)
	}

	s = &iec104First(t, IEC104TypeAuthReply).Security
	if !s.Decoded || s.SegmentNumber != 2 || len(s.MAC) != 8 || s.MAC[7] != 8 {
		t.Errorf("S_RP_NA_1 %+v", s)
	}

	s = &iec104First(t, IEC104TypeAuthAggressive).Security
	if !s.Decoded || s.Encapsulated == nil || s.Encapsulated.TypeID != IEC104TypeSingleCommand ||
		len(s.Encapsulated.Objects) != 1 || s.Encapsulated.Objects[0].IOA != 0x31 ||
		s.Sequence != 0x12345679 || len(s.MAC) != 8 || len(s.EncapsulatedRaw) != 10 {
		t.Errorf("S_AR_NA_1 %+v", s)
	}

	s = &iec104First(t, IEC104TypeKeyStatusRequest).Security
	if !s.Decoded || s.User != 2 || s.First || s.Final {
		t.Errorf("S_KR_NA_1 %+v", s)
	}

	s = &iec104First(t, IEC104TypeKeyStatus).Security
	if !s.Decoded || s.Sequence != 1 || s.KeyWrap != IEC104KeyWrapAES128 || s.KeyStatus != IEC104KeyStatusOK ||
		s.MACAlgorithm != IEC104MACSHA256x16 || len(s.Challenge) != 4 || len(s.MAC) != 16 {
		t.Errorf("S_KS_NA_1 %+v", s)
	}

	s = &iec104First(t, IEC104TypeKeyChange).Security
	if !s.Decoded || s.Sequence != 4 || !bytes.Equal(s.WrappedKey, []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}) {
		t.Errorf("S_KC_NA_1 %+v", s)
	}

	s = &iec104First(t, IEC104TypeAuthError).Security
	if !s.Decoded || s.AssociationID != 7 || s.ErrorCode != 5 || string(s.ErrorText) != "denied" ||
		s.ErrorTime.Format != IEC104TimeCP56 || s.ErrorTime.Month != 11 || s.ErrorTime.Year != 25 {
		t.Errorf("S_ER_NA_1 %+v", s)
	}

	// S_IT_TC_1 is an ordinary object type with an association ID.
	o := iec104First(t, IEC104TypeSecurityStatistics).Objects[0]
	if o.AssociationID != 0x1234 || o.Counter.Value != 0x12345678 || o.Counter.Sequence != 5 ||
		!o.Counter.Carry || !o.Counter.Invalid || o.Time.Day != 15 {
		t.Errorf("S_IT_TC_1 %+v", o)
	}

	// S_UK_NA_1 is named and kept raw, as in Wireshark.
	a := iec104First(t, IEC104TypeUpdateKeySym)
	if a.TypeID.String() != "S_UK_NA_1" || len(a.Raw) != 6 || a.Security.Decoded {
		t.Errorf("S_UK_NA_1 %+v", a)
	}
}

// A body cut into segments is left raw in each ASDU and decodes once the
// assembler has joined it.
func TestIEC104SecurityAssembler(t *testing.T) {
	body := []byte{0x78, 0x56, 0x34, 0x12, 0x02, 0x00, 0x04, 0x01, 0x04, 0x00, 0xde, 0xad, 0xbe, 0xef}
	segment := func(asn uint8, part []byte) []byte {
		asdu := append([]byte{0x51, 0x01, 0x0e, 0x00, 0x0a, 0x00, asn}, part...)
		return append([]byte{0x68, uint8(4 + len(asdu)), 0, 0, 0, 0}, asdu...)
	}
	decode := func(data []byte) *IEC104Security {
		var apdu IEC104
		if err := apdu.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
			t.Fatal(err)
		}
		return &apdu.ASDU.Security
	}

	var m IEC104SecurityAssembler
	parts := [][]byte{segment(0x40, body[:5]), segment(0x01, body[5:9]), segment(0x82, body[9:])}
	var whole []byte
	for k, part := range parts {
		s := decode(part)
		if s.Decoded {
			t.Errorf("segment %d decoded on its own", k)
		}

		got, err := m.Add(s)
		if err != nil || (got != nil) != (k == len(parts)-1) {
			t.Fatalf("segment %d: %v, %v", k, got, err)
		}
		whole = got
	}

	var s IEC104Security
	rest, err := s.DecodeBody(IEC104TypeAuthChallenge, whole, IEC104ASDUOptions{})
	if err != nil || len(rest) != 0 || s.Sequence != 0x12345678 || !bytes.Equal(s.Challenge, body[10:]) {
		t.Errorf("assembled body: %+v, rest %x, %v", s, rest, err)
	}

	// A segment out of sequence, or one without a first, is refused.
	m.Add(decode(parts[0]))
	if _, err := m.Add(decode(parts[2])); !errors.Is(err, ErrIEC104SecuritySequence) {
		t.Errorf("gap: %v", err)
	}
	if _, err := m.Add(decode(parts[1])); !errors.Is(err, ErrIEC104SecuritySequence) {
		t.Errorf("no first segment: %v", err)
	}

	// The cap bounds the body however many segments arrive.
	small := IEC104SecurityAssembler{MaxSize: 8}
	small.Add(decode(parts[0]))
	if _, err := small.Add(decode(parts[1])); !errors.Is(err, ErrIEC104SecurityTooLong) {
		t.Errorf("cap: %v", err)
	}

	// The sequence number wraps from 63 to 0.
	var wrap IEC104SecurityAssembler
	wrap.Add(decode(segment(0x40|63, body[:5])))
	if got, err := wrap.Add(decode(segment(0x80, body[5:]))); err != nil || !bytes.Equal(got, body) {
		t.Errorf("wrap: %x, %v", got, err)
	}
}

// iec104Resize rewrites a decoded IEC 104 ASDU with the field sizes of
// opts: it drops the originator and the high address octets. It reports
// false for ASDUs whose values do not fit or that carry no objects.
func iec104Resize(a *IEC104ASDU, raw []byte, f iec104Fields) ([]byte, bool) {
	if _, known := iec104Types[a.TypeID]; !known || len(a.Objects) == 0 ||
		a.CommonAddr>>(8*uint(f.ca)) != 0 {
		return nil, false
	}

	out := append([]byte{}, raw[:iec104TypeVSQLen+f.cot]...)
	out = append(out, raw[iec104TypeVSQLen+iec104COTLen:][:f.ca]...)
	for k, o := range a.Objects {
		if o.IOA>>(8*uint(f.ioa)) != 0 {
			return nil, false
		}
		if k == 0 || !a.Sequence {
			out = append(out, byte(o.IOA), byte(o.IOA>>8), byte(o.IOA>>16))
			out = out[:len(out)-iec104IOALen+f.ioa]
		}
		out = append(out, o.Raw...)
	}
	return out, true
}

// With IEC 101 field sizes an ASDU decodes to the same values as its
// IEC 104 form, on every object-carrying frame of the captures.
func TestIEC104Options(t *testing.T) {
	var asdus [][]byte
	for _, data := range iec104Handmade(t) {
		asdus = append(asdus, data[iec104APCILen:])
	}
	for _, path := range []string{"testdata/iec104.pcap", "testdata/iec104_sq.pcap"} {
		for _, data := range iec104Packets(t, path) {
			p := gopacket.NewPacket(data, LayerTypeIEC104, gopacket.Default)
			for _, l := range p.Layers() {
				if apdu, ok := l.(*IEC104); ok && apdu.Format == IEC104FormatI {
					asdus = append(asdus, apdu.Contents[iec104APCILen:])
				}
			}
		}
	}

	sizes := []IEC104ASDUOptions{
		{COTSize: 1, CommonAddrSize: 1, IOASize: 2}, // Wireshark's IEC 101 defaults
		{COTSize: 1, CommonAddrSize: 1, IOASize: 1},
		{COTSize: 2, CommonAddrSize: 1, IOASize: 3},
		{COTSize: 1, CommonAddrSize: 2, IOASize: 2},
		{},
		{COTSize: 2, CommonAddrSize: 2, IOASize: 3},
	}
	checked := 0
	for _, raw := range asdus {
		var ref IEC104ASDU
		if err := ref.DecodeWithOptions(raw, IEC104ASDUOptions{}); err != nil {
			t.Fatal(err)
		}
		want := iec104Dump{}
		want.asdu(&ref)

		for _, opts := range sizes {
			f, err := opts.fields()
			if err != nil {
				t.Fatal(err)
			}
			small, ok := iec104Resize(&ref, raw, f)
			if !ok {
				continue
			}

			got, err := DecodeIEC104ASDU(small, opts)
			if err != nil {
				t.Errorf("%+v %x: %v", opts, small, err)
				continue
			}
			dump := iec104Dump{noOA: f.cot == 1}
			dump.asdu(got)
			delete(want.vals, "oa")
			if f.cot == iec104COTLen {
				want.vals["oa"] = []string{fmt.Sprint(ref.Originator)}
			}
			if dump.String() != want.String() {
				t.Errorf("%+v %x:\n got %s\nwant %s", opts, small, dump.String(), want.String())
			}
			checked++
		}
	}
	if checked < len(asdus) {
		t.Errorf("only %d ASDUs checked", checked)
	}

	// SQ addresses wrap at the address size.
	a, err := DecodeIEC104ASDU([]byte{0x01, 0x82, 0x03, 0x01, 0xff, 0x01, 0x00}, sizes[1])
	if err != nil || len(a.Objects) != 2 || a.Objects[0].IOA != 0xff || a.Objects[1].IOA != 0 {
		t.Errorf("1-octet SQ wrap: %+v, %v", a, err)
	}

	for _, opts := range []IEC104ASDUOptions{{COTSize: 3}, {COTSize: -1}, {CommonAddrSize: 3}, {IOASize: 4}, {IOASize: -2}} {
		if _, err := DecodeIEC104ASDU(asdus[0], opts); !errors.Is(err, ErrIEC104BadOptions) {
			t.Errorf("%+v: %v", opts, err)
		}
		var s IEC104Security
		if _, err := s.DecodeBody(IEC104TypeAuthReply, nil, opts); !errors.Is(err, ErrIEC104BadOptions) {
			t.Errorf("DecodeBody %+v: %v", opts, err)
		}
	}
}

// iec104Vectors101 are FT 1.2 user data ASDUs with a 1-octet cause, a
// 1-octet common address and a 2-octet object address, as tshark 4.7
// dissects them with those iec60870_101 preferences.
var iec104Vectors101 = []struct {
	asdu, want string
}{
	// P_ME_NC_1, QPM low limit.
	{"7001060a23000000c03f03",
		"typeid=112 sq=False numix=1 causetx=6 nega=False test=False addr=10 ioa=35 qpm.kpa=3 qpm.lpc=0 qpm.pop=0 float=1.5"},
	// F_DR_TA_1, two entries from one address.
	{"7e82050a500001000010 00e5e8031e8a6f0b19 0200ffffff20ffeabb179f0c63",
		"typeid=126 sq=True numix=2 causetx=5 nega=False test=False addr=10 ioa=80,81 cp56time.ms=1000,60159 " +
			"cp56time.min=30,59 cp56time.gen=False,False cp56time.iv=False,True cp56time.hour=10,23 " +
			"cp56time.su=True,False cp56time.day=15,31 cp56time.dow=3,4 cp56time.month=11,12 cp56time.year=25,99 " +
			"nof=1,2 lof=4096,16777215 sof.status=5,0 sof.lfd=True,True sof.for=True,False sof.fa=True,False"},
	// S_AR_NA_1 wrapping a C_SC_NA_1 of the same field sizes.
	{"53010e0a c0 2d01060a310081 79563412 0200 aabbccddeeff1122",
		"typeid=83,45 sq=False,False numix=1,1 causetx=14,6 nega=False,False test=False,False addr=10,10 ioa=49 " +
			"sco.on=True sco.qu=0 sco.se=True asn=0 asn.fin=True asn.fir=True usr=2 csq=305419897 hmac=aabbccddeeff1122"},
}

func TestIEC104Vectors101(t *testing.T) {
	opts := IEC104ASDUOptions{COTSize: 1, CommonAddrSize: 1, IOASize: 2}
	for _, tt := range iec104Vectors101 {
		raw, err := hex.DecodeString(strings.ReplaceAll(tt.asdu, " ", ""))
		if err != nil {
			t.Fatal(err)
		}

		a, err := DecodeIEC104ASDU(raw, opts)
		if err != nil {
			t.Errorf("%s: %v", tt.asdu, err)
			continue
		}
		x := iec104Dump{noOA: true}
		x.asdu(a)
		if got := x.String(); got != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", tt.asdu, got, tt.want)
		}
	}
}

// Every prefix of every handmade ASDU decodes without panic, under each
// set of field sizes, and never yields more than the octets allow.
func TestIEC104HandmadeTruncated(t *testing.T) {
	sizes := []IEC104ASDUOptions{{}, {COTSize: 1, CommonAddrSize: 1, IOASize: 2}, {COTSize: 1, CommonAddrSize: 1, IOASize: 1}}
	for _, data := range iec104Handmade(t) {
		for n := 0; n <= len(data); n++ {
			cut := data[:n]
			var apdu IEC104
			if err := apdu.DecodeFromBytes(cut, gopacket.NilDecodeFeedback); err == nil && n < len(data) {
				t.Errorf("%x cut to %d decoded", data[:8], n)
			}
			gopacket.NewPacket(cut, LayerTypeIEC104, gopacket.Default)

			// Shorten the APDU to fit the cut, so that the ASDU is what
			// ends early rather than the frame.
			if n < iec104APCILen {
				continue
			}
			lie := append([]byte{}, cut...)
			lie[1] = uint8(n - iec104HeaderLen)
			gopacket.NewPacket(lie, LayerTypeIEC104, gopacket.Default)

			for _, opts := range sizes {
				var a IEC104ASDU
				if err := a.DecodeWithOptions(cut[iec104APCILen:], opts); err != nil {
					continue
				}
				iec104Bounded(t, &a, cut[iec104APCILen:])
			}
		}
	}
}

// iec104Bounded checks that what an ASDU holds fits the octets it came
// from.
func iec104Bounded(t *testing.T, a *IEC104ASDU, data []byte) {
	t.Helper()
	total := len(a.Raw)
	for _, o := range a.Objects {
		total += len(o.Raw)
	}
	s := &a.Security
	for _, b := range [][]byte{s.Challenge, s.MAC, s.WrappedKey, s.ErrorText, s.EncapsulatedRaw} {
		total += len(b)
	}

	if total > len(data) || len(a.Objects) > int(a.NumObjects) || len(s.Segment) > len(data) {
		t.Errorf("%x: holds %d octets, %d objects", data, total, len(a.Objects))
	}
}

// Length fields that promise more than the body holds are errors, not
// reads past it.
func TestIEC104LengthLies(t *testing.T) {
	dui := func(id IEC104TypeID, body string) []byte {
		b, err := hex.DecodeString(strings.ReplaceAll(body, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte{uint8(id), 0x01, 0x0e, 0x00, 0x0a, 0x00}, b...)
	}
	tests := []struct {
		name string
		asdu []byte
		want error
	}{
		{"S_CH_NA_1 CLN 0xffff", dui(81, "c0 01000000 0200 04 01 ffff dead"), ErrIEC104SecurityTooShort},
		{"S_CH_NA_1 CLN one over", dui(81, "c0 01000000 0200 04 01 0300 dead"), ErrIEC104SecurityTooShort},
		{"S_CH_NA_1 no ASN", dui(81, ""), ErrIEC104SecurityTooShort},
		{"S_CH_NA_1 ASN only", dui(81, "c0"), ErrIEC104SecurityTooShort},
		{"S_RP_NA_1 HLN 0xffff", dui(82, "c0 01000000 0200 ffff 0102"), ErrIEC104SecurityTooShort},
		{"S_AR_NA_1 empty", dui(83, "c0"), ErrIEC104SecurityTooShort},
		{"S_AR_NA_1 short inner", dui(83, "c0 2d01060a0031"), ErrIEC104SecurityTooShort},
		{"S_AR_NA_1 no CSQ", dui(83, "c0 2d01060a0031000081 0102"), ErrIEC104SecurityTooShort},
		{"S_AR_NA_1 inner claims 127 objects", dui(83, "c0 2d7f060a0031000081 01000000 0200"), ErrIEC104ObjectsTooLong},
		{"S_KR_NA_1 one octet", dui(84, "02"), ErrIEC104SecurityTooShort},
		{"S_KS_NA_1 CLN 0xffff", dui(85, "c0 01000000 0200 01 01 04 ffff a1"), ErrIEC104SecurityTooShort},
		{"S_KS_NA_1 MAC short", dui(85, "c0 01000000 0200 01 01 04 0100 a1 0102"), ErrIEC104SecurityTooShort},
		{"S_KC_NA_1 WKL 0xffff", dui(86, "c0 01000000 0200 ffff 11"), ErrIEC104SecurityTooShort},
		{"S_ER_NA_1 ELN 0xffff", dui(87, "c0 01000000 0200 0700 05 e8031e8a6f0b19 ffff 41"), ErrIEC104SecurityTooShort},
		{"S_ER_NA_1 ETM short", dui(87, "c0 01000000 0200 0700 05 e8031e"), ErrIEC104SecurityTooShort},
		{"S_IT_TC_1 short", append([]byte{41, 0x01, 0x03, 0x00, 0x0a, 0x00}, 0x70, 0, 0, 0x34, 0x12), ErrIEC104ObjectsTooLong},
		{"F_SG_NA_1 LOS over", append([]byte{125, 0x01, 0x0d, 0x00, 0x0a, 0x00}, 0x41, 0, 0, 2, 0, 3, 9, 1, 2), ErrIEC104ObjectsTooLong},
	}
	for _, tt := range tests {
		if _, err := DecodeIEC104ASDU(tt.asdu, IEC104ASDUOptions{}); !errors.Is(err, tt.want) {
			t.Errorf("%s: got %v, want %v", tt.name, err, tt.want)
		}

		// In a packet the APCI stays a layer and the error follows it.
		apdu := append([]byte{0x68, uint8(iec104ControlLen + len(tt.asdu)), 0, 0, 0, 0}, tt.asdu...)
		p := gopacket.NewPacket(apdu, LayerTypeIEC104, gopacket.Default)
		if p.Layer(LayerTypeIEC104) == nil || p.ErrorLayer() == nil {
			t.Errorf("%s: layers %v", tt.name, p.Layers())
		}
	}

	// A nested secure authentication ASDU is kept raw, not decoded: an
	// S_AR_NA_1 cannot make the decoder recurse.
	a, err := DecodeIEC104ASDU(dui(83, "c0 53010e000a00 010203 01000000 0200 aabb"), IEC104ASDUOptions{})
	if err != nil || a.Security.Encapsulated != nil || len(a.Security.EncapsulatedRaw) != 9 ||
		!bytes.Equal(a.Security.MAC, []byte{0xaa, 0xbb}) {
		t.Errorf("nested S_AR_NA_1: %+v, %v", a, err)
	}

	// S_KS_NA_1 with a vendor's MAC algorithm: the MAC is what is left.
	a, err = DecodeIEC104ASDU(dui(85, "c0 01000000 0200 01 01 80 0100 a1 010203"), IEC104ASDUOptions{})
	if err != nil || len(a.Security.MAC) != 3 || len(a.Raw) != 0 {
		t.Errorf("vendor HAL: %+v, %v", a, err)
	}

	// Octets past the body are kept in Raw.
	a, err = DecodeIEC104ASDU(dui(82, "c0 01000000 0200 0100 aa bbcc"), IEC104ASDUOptions{})
	if err != nil || !bytes.Equal(a.Raw, []byte{0xbb, 0xcc}) {
		t.Errorf("trailing octets: %+v, %v", a, err)
	}
}

// Decoding allocates for the object list only, sized by the object count
// after it is checked against the data, and never by a length field.
func TestIEC104Allocs(t *testing.T) {
	// 60 single points from one address.
	sq := []byte{0x68, 0x46, 0, 0, 0, 0, 0x01, 0xbc, 0x03, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00}
	sq = append(sq, make([]byte, 60)...)
	sq[1] = uint8(len(sq) - iec104HeaderLen)

	var apdu IEC104
	if err := apdu.DecodeFromBytes(sq, gopacket.NilDecodeFeedback); err != nil || len(apdu.ASDU.Objects) != 60 {
		t.Fatalf("%d objects, %v", len(apdu.ASDU.Objects), err)
	}
	if n := testing.AllocsPerRun(100, func() {
		_ = apdu.DecodeFromBytes(sq, gopacket.NilDecodeFeedback)
	}); n != 0 {
		t.Errorf("reused layer: %v allocations", n)
	}

	// 127 objects claimed by 16 octets: refused before the list is made.
	lie := []byte{0x68, 0x10, 0, 0, 0, 0, 0x01, 0xff, 0x03, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01}
	if n := testing.AllocsPerRun(100, func() {
		var fresh IEC104
		_ = fresh.DecodeFromBytes(lie, gopacket.NilDecodeFeedback)
	}); n != 0 {
		t.Errorf("lying object count: %v allocations", n)
	}

	// Security bodies alias the packet: a 0xffff length allocates nothing.
	huge := []byte{0x68, 0x12, 0, 0, 0, 0, 0x51, 0x01, 0x0e, 0x00, 0x0a, 0x00,
		0xc0, 1, 0, 0, 0, 2, 0, 4, 1, 0xff, 0xff}
	huge[1] = uint8(len(huge) - iec104HeaderLen)
	if n := testing.AllocsPerRun(100, func() {
		var fresh IEC104
		_ = fresh.DecodeFromBytes(huge, gopacket.NilDecodeFeedback)
	}); n != 0 {
		t.Errorf("lying challenge length: %v allocations", n)
	}

	// The assembler never holds more than its cap.
	m := IEC104SecurityAssembler{MaxSize: 100}
	seg := IEC104Security{First: true, Segment: make([]byte, 60)}
	m.Add(&seg)
	seg = IEC104Security{SegmentNumber: 1, Segment: make([]byte, 60)}
	if _, err := m.Add(&seg); !errors.Is(err, ErrIEC104SecurityTooLong) || cap(m.body) > 100 {
		t.Errorf("assembler holds %d octets: %v", cap(m.body), err)
	}
}

// The names of the new enumerations follow Wireshark.
func TestIEC104QualifierStrings(t *testing.T) {
	tests := []struct {
		got  fmt.Stringer
		want string
	}{
		{IEC104COIRemoteReset, "Remote reset"},
		{IEC104COICause(9), "Unknown(9)"},
		{IEC104QOIStation, "Station interrogation (global)"},
		{IEC104QOI(25), "Group 5 interrogation"},
		{IEC104QOI(0), "Not specified"},
		{IEC104QOI(37), "Unknown(37)"},
		{IEC104QCCGeneral, "General counter interrogation"},
		{IEC104QCCRequest(3), "Group 3 counter interrogation"},
		{IEC104QCCRequest(6), "Unknown(6)"},
		{IEC104QCCFreezeReset, "Counter freeze with reset"},
		{IEC104QPMSmoothing, "Smoothing factor (filter time constant)"},
		{IEC104QPMKind(9), "Unknown(9)"},
		{IEC104QPAObject, "Act/deact of the parameter of the addressed object"},
		{IEC104QRPGeneral, "General reset of process"},
		{IEC104QULongPulse, "Long Pulse"},
		{IEC104QU(9), "Unknown(9)"},
		{IEC104FileErrChecksum, "Checksum failed"},
		{IEC104SCQDeleteFile, "Delete file"},
		{IEC104LSQSectionDeact, "Section transfer with deactivation"},
		{IEC104AFQSectionPositive, "Positive acknowledge of section transfer"},
		{IEC104MACSHA256x8, "HMAC-SHA-256 truncated to 8 octets (serial)"},
		{IEC104MACAlgorithm(200), "(vendor-specific choice)"},
		{IEC104KeyWrapAES256, "AES-256 Key Wrap Algorithm"},
		{IEC104KeyStatusAuthFail, "AUTH FAIL"},
		{IEC104AuthErrorCode(11), "Unknown User"},
		{IEC104AuthErrorCode(12), "Unknown(12)"},
		{IEC104AuthErrorCode(130), "(vendor-specific choice)"},
		{IEC104TypeAuthAggressive, "S_AR_NA_1"},
		{IEC104TypeUpdateKeyConfirm, "S_UC_NA_1"},
	}
	for _, tt := range tests {
		if s := tt.got.String(); s != tt.want {
			t.Errorf("got %q, want %q", s, tt.want)
		}
	}
}
