// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
)

// DNP3 (IEEE 1815) over TCP or UDP port 20000. One DNP3 layer is one data
// link frame, with its transport header and, when the frame starts an
// application fragment, the application header and object headers:
//
//	link header (10 bytes)                  user data, 16 byte blocks
//	+------+-----+-----+-----+-----+-----+  +----------+-----+----------+-----+
//	| 0564 | LEN | CTL | DST | SRC | CRC |  | block 1  | CRC | block 2  | CRC |
//	+------+-----+-----+-----+-----+-----+  +----------+-----+----------+-----+
//	                                          |
//	         CRCs stripped -> UserData: | TH | AC | FC | IIN | objects ... |
//
// Bad CRCs are flagged (HeaderCRCOK, BadBlocks), not fatal: the frame is
// still decoded, as Wireshark does. So are link headers a receiver would
// reject (LinkIssues). Each layer shows what its frame holds; a
// DNP3Assembler joins the frames of a fragment and decodes it whole.

// DNP3Port is the IANA port for DNP3 over TCP and UDP.
const DNP3Port uint16 = 20000

// Link and transport layer sizes and masks.
const (
	dnp3Start0       = 0x05
	dnp3Start1       = 0x64
	dnp3HeaderLen    = 10 // start, length, control, destination, source, CRC
	dnp3HeaderCRCOff = 8
	dnp3CRCLen       = 2
	dnp3BlockLen     = 16
	dnp3MinLength    = 5      // LEN counts control, destination and source
	dnp3CRCPoly      = 0xA6BC // 0x3D65 bit reversed
	dnp3CtlDir       = 0x80
	dnp3CtlPrm       = 0x40
	dnp3CtlFCB       = 0x20
	dnp3CtlFCV       = 0x10 // DFC in a secondary frame
	dnp3CtlFunc      = 0x0F
	dnp3TrFIN        = 0x80
	dnp3TrFIR        = 0x40
	dnp3TrSeq        = 0x3F
)

// Application layer sizes and masks.
const (
	dnp3AppHeaderLen  = 2 // application control + function code
	dnp3IINLen        = 2
	dnp3ObjHeaderLen  = 3 // group, variation, qualifier
	dnp3AcFIR         = 0x80
	dnp3AcFIN         = 0x40
	dnp3AcCON         = 0x20
	dnp3AcUNS         = 0x10
	dnp3AcSeq         = 0x0F
	dnp3QualReserved  = 0x80
	dnp3QualPrefix    = 0x70
	dnp3QualPrefixPos = 4
	dnp3QualRange     = 0x0F
	dnp3BitsPerByte   = 8
)

// Errors returned by DNP3 decoding.
var (
	ErrDNP3TooShort     = errors.New("DNP3 frame shorter than its link header")
	ErrDNP3BadStart     = errors.New("DNP3 frame does not start with 0x0564")
	ErrDNP3BadLength    = errors.New("DNP3 link length below minimum")
	ErrDNP3Truncated    = errors.New("DNP3 frame shorter than its link length")
	ErrDNP3AppTooShort  = errors.New("DNP3 application header cut short")
	ErrDNP3ObjTruncated = errors.New("DNP3 object header or data cut short")
	ErrDNP3BadRange     = errors.New("DNP3 object range stop below start")
)

// LayerTypeDNP3 is the layer type of a DNP3 link frame.
var LayerTypeDNP3 = gopacket.RegisterLayerType(155, gopacket.LayerTypeMetadata{Name: "DNP3", Decoder: gopacket.DecodeFunc(decodeDNP3)})

// registerDNP3Decoders maps TCP and UDP port 20000 to DNP3. It is not
// called from init: doing so would change what existing callers decode on
// that port. Calling it more than once is harmless.
func registerDNP3Decoders() {
	RegisterTCPPortLayerType(TCPPort(DNP3Port), LayerTypeDNP3)
	RegisterUDPPortLayerType(UDPPort(DNP3Port), LayerTypeDNP3)
}

// dnp3CRCTable is the lookup table of CRC-16/DNP.
var dnp3CRCTable = dnp3MakeCRCTable()

// dnp3MakeCRCTable builds the table for the reflected polynomial.
func dnp3MakeCRCTable() [256]uint16 {
	var t [256]uint16
	for i := range t {
		crc := uint16(i)
		for b := 0; b < dnp3BitsPerByte; b++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ dnp3CRCPoly
				continue
			}
			crc >>= 1
		}
		t[i] = crc
	}
	return t
}

// DNP3CRC returns the CRC-16/DNP of b as it is carried on the wire (sent
// little endian). For example DNP3CRC([]byte("123456789")) is 0xEA82.
func DNP3CRC(b []byte) uint16 {
	var crc uint16
	for _, c := range b {
		crc = crc>>8 ^ dnp3CRCTable[byte(crc)^c]
	}
	return ^crc
}

// DNP3LinkFunc is a data link function code. Primary (PRM=1) and
// secondary (PRM=0) frames share the 4 bit code space, so the value keeps
// the PRM bit (0x40) to tell them apart; Code returns the bare 4 bits.
type DNP3LinkFunc uint8

// DNP3LinkFunc values. Primary codes have the PRM bit set.
const (
	DNP3LinkResetLinkStates  DNP3LinkFunc = dnp3CtlPrm | 0x00
	DNP3LinkResetUserProcess DNP3LinkFunc = dnp3CtlPrm | 0x01 // obsolete
	DNP3LinkTestLinkStates   DNP3LinkFunc = dnp3CtlPrm | 0x02
	DNP3LinkConfirmedData    DNP3LinkFunc = dnp3CtlPrm | 0x03
	DNP3LinkUnconfirmedData  DNP3LinkFunc = dnp3CtlPrm | 0x04
	DNP3LinkRequestStatus    DNP3LinkFunc = dnp3CtlPrm | 0x09
	DNP3LinkAck              DNP3LinkFunc = 0x00
	DNP3LinkNack             DNP3LinkFunc = 0x01
	DNP3LinkStatus           DNP3LinkFunc = 0x0B
	DNP3LinkNotFunctioning   DNP3LinkFunc = 0x0E // obsolete
	DNP3LinkNotSupported     DNP3LinkFunc = 0x0F
)

// Code returns the 4 bit function code without the PRM bit.
func (f DNP3LinkFunc) Code() uint8 {
	return uint8(f) & dnp3CtlFunc
}

// Primary reports whether f is a primary (PRM=1) function.
func (f DNP3LinkFunc) Primary() bool {
	return uint8(f)&dnp3CtlPrm != 0
}

// String returns the function name.
func (f DNP3LinkFunc) String() string {
	switch f {
	case DNP3LinkResetLinkStates:
		return "Reset of Remote Link"
	case DNP3LinkResetUserProcess:
		return "Reset of User Process"
	case DNP3LinkTestLinkStates:
		return "Test Function for Link"
	case DNP3LinkConfirmedData:
		return "User Data"
	case DNP3LinkUnconfirmedData:
		return "Unconfirmed User Data"
	case DNP3LinkRequestStatus:
		return "Request Link Status"
	case DNP3LinkAck:
		return "ACK"
	case DNP3LinkNack:
		return "NACK"
	case DNP3LinkStatus:
		return "Status of Link"
	case DNP3LinkNotFunctioning:
		return "Link Service Not Functioning"
	case DNP3LinkNotSupported:
		return "Link Service Not Used or Implemented"
	}

	if f.Primary() {
		return fmt.Sprintf("Unknown Primary(%d)", f.Code())
	}
	return fmt.Sprintf("Unknown Secondary(%d)", f.Code())
}

// DNP3Link is the data link header. FCB and FCV are only set in primary
// frames and DFC only in secondary frames, where the spec defines them.
type DNP3Link struct {
	Length      uint8 // octets from Control to the end of user data, CRCs excluded
	Control     uint8
	Dir         bool // set when sent by a master
	Primary     bool // PRM
	FCB         bool
	FCV         bool
	DFC         bool
	Function    DNP3LinkFunc
	Destination uint16
	Source      uint16
	CRC         uint16
}

// DNP3Transport is the one byte transport header.
type DNP3Transport struct {
	FIN bool
	FIR bool
	Seq uint8
}

// DNP3 is one DNP3 data link frame. UserData is the user data with the
// block CRCs removed: the transport header then an application fragment
// or a piece of one. Application is set when the frame begins a fragment
// (transport FIR). Payload of the embedded BaseLayer holds the bytes after
// this frame, which may be more frames. LinkIssues flags what a receiver
// would reject the frame for; it is never a decoding error.
type DNP3 struct {
	BaseLayer
	Link        DNP3Link
	LinkIssues  DNP3LinkIssue
	HeaderCRCOK bool
	BadBlocks   int // user data blocks whose CRC does not match
	UserData    []byte
	Transport   DNP3Transport // valid when UserData is not empty
	Application *DNP3Application
}

// CRCValid reports whether the header and every user data block CRC match.
func (d *DNP3) CRCValid() bool {
	return d.HeaderCRCOK && d.BadBlocks == 0
}

// LayerType returns LayerTypeDNP3.
func (d *DNP3) LayerType() gopacket.LayerType {
	return LayerTypeDNP3
}

// CanDecode returns LayerTypeDNP3.
func (d *DNP3) CanDecode() gopacket.LayerClass {
	return LayerTypeDNP3
}

// NextLayerType returns LayerTypeZero: later frames of a segment are
// decoded by decodeDNP3 itself, as Modbus does.
func (d *DNP3) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// Payload returns the application bytes of this frame: UserData without
// its transport header.
func (d *DNP3) Payload() []byte {
	if len(d.UserData) == 0 {
		return nil
	}
	return d.UserData[1:]
}

// dnp3FrameLen returns the wire size of a frame carrying n user data
// bytes: the header plus every 16 byte block and its CRC.
func dnp3FrameLen(n int) int {
	blocks := (n + dnp3BlockLen - 1) / dnp3BlockLen
	return dnp3HeaderLen + n + blocks*dnp3CRCLen
}

// DecodeFromBytes decodes one link frame from the start of data. When
// only the application data is malformed, the error is returned with Link,
// Transport and the part of Application that decoded filled in, much as
// Wireshark shows a malformed frame.
func (d *DNP3) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if err := d.decodeFrame(data, df); err != nil {
		return err
	}
	return d.decodeApp()
}

// decodeFrame delimits the link frame, checks its CRCs and reads the link
// and transport headers.
func (d *DNP3) decodeFrame(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < dnp3HeaderLen {
		df.SetTruncated()
		return ErrDNP3TooShort
	}

	if data[0] != dnp3Start0 || data[1] != dnp3Start1 {
		return ErrDNP3BadStart
	}

	length := data[2]
	if length < dnp3MinLength {
		return fmt.Errorf("%w: %d", ErrDNP3BadLength, length)
	}

	userLen := int(length) - dnp3MinLength
	frameLen := dnp3FrameLen(userLen)
	if len(data) < frameLen {
		df.SetTruncated()
		return fmt.Errorf("%w: need %d bytes, have %d", ErrDNP3Truncated, frameLen, len(data))
	}

	d.decodeLink(data)
	d.LinkIssues = d.Link.issues()
	d.HeaderCRCOK = DNP3CRC(data[:dnp3HeaderCRCOff]) == d.Link.CRC
	d.stripCRCs(data[dnp3HeaderLen:frameLen], userLen)
	d.Contents = data[:frameLen]
	d.BaseLayer.Payload = data[frameLen:]
	d.Transport = DNP3Transport{}
	d.Application = nil

	if len(d.UserData) == 0 {
		return nil
	}

	th := d.UserData[0]
	d.Transport = DNP3Transport{FIN: th&dnp3TrFIN != 0, FIR: th&dnp3TrFIR != 0, Seq: th & dnp3TrSeq}
	return nil
}

// decodeApp decodes the application header and objects when the frame
// begins a fragment. Later pieces of a fragment are left in UserData.
func (d *DNP3) decodeApp() error {
	if len(d.UserData) == 0 || !d.Transport.FIR {
		return nil
	}

	end := dnp3MoreSegments
	if d.Transport.FIN {
		end = dnp3LastSegment
	}

	d.Application = &DNP3Application{}
	err := d.Application.decode(d.UserData[1:], end)

	// Masters send requests with DIR set, outstations responses with it
	// clear. A fragment too short to hold its function says nothing.
	if len(d.UserData) > dnp3AppHeaderLen && d.Application.Function.IsResponse() == d.Link.Dir {
		d.LinkIssues |= DNP3LinkBadDirection
	}
	return err
}

// decodeLink reads the fixed link header fields. The caller has checked
// data holds the header.
func (d *DNP3) decodeLink(data []byte) {
	ctl := data[3]
	l := &d.Link
	l.Length = data[2]
	l.Control = ctl
	l.Dir = ctl&dnp3CtlDir != 0
	l.Primary = ctl&dnp3CtlPrm != 0
	l.FCB = l.Primary && ctl&dnp3CtlFCB != 0
	l.FCV = l.Primary && ctl&dnp3CtlFCV != 0
	l.DFC = !l.Primary && ctl&dnp3CtlFCV != 0
	l.Function = DNP3LinkFunc(ctl & (dnp3CtlPrm | dnp3CtlFunc))
	l.Destination = binary.LittleEndian.Uint16(data[4:6])
	l.Source = binary.LittleEndian.Uint16(data[6:8])
	l.CRC = binary.LittleEndian.Uint16(data[dnp3HeaderCRCOff:dnp3HeaderLen])
}

// stripCRCs copies the n user data bytes out of their CRC protected
// blocks into UserData and counts blocks whose CRC does not match. The
// caller has checked blocks holds dnp3FrameLen(n)-dnp3HeaderLen bytes.
func (d *DNP3) stripCRCs(blocks []byte, n int) {
	if cap(d.UserData) < n {
		d.UserData = make([]byte, 0, n)
	}
	d.UserData = d.UserData[:0]
	d.BadBlocks = 0
	for n > 0 {
		size := min(n, dnp3BlockLen)
		block := blocks[:size]
		crc := binary.LittleEndian.Uint16(blocks[size : size+dnp3CRCLen])
		if DNP3CRC(block) != crc {
			d.BadBlocks++
		}

		d.UserData = append(d.UserData, block...)
		blocks = blocks[size+dnp3CRCLen:]
		n -= size
	}
}

// decodeDNP3 decodes every link frame of a segment, each as its own layer.
// It loops rather than chaining through NextDecoder so that many frames
// in one buffer do not each cost a stack frame. A trailing frame that does
// not delimit, e.g. one cut by segmentation, stays the previous layer's
// payload, as with Modbus. A frame with malformed application data is
// added, then its error ends the decode.
func decodeDNP3(data []byte, p gopacket.PacketBuilder) error {
	d := &DNP3{}
	if err := d.decodeFrame(data, p); err != nil {
		return err
	}
	p.AddLayer(d)
	p.SetApplicationLayer(d)
	if err := d.decodeApp(); err != nil {
		return err
	}

	for len(d.BaseLayer.Payload) > 0 {
		next := &DNP3{}
		if err := next.decodeFrame(d.BaseLayer.Payload, gopacket.NilDecodeFeedback); err != nil {
			break
		}
		p.AddLayer(next)
		if err := next.decodeApp(); err != nil {
			return err
		}
		d = next
	}
	return nil
}

// dnp3SegmentEnd says whether the transport segment ends its fragment, so
// objects cut at the end of the frame are expected rather than malformed.
type dnp3SegmentEnd uint8

const (
	dnp3MoreSegments dnp3SegmentEnd = iota
	dnp3LastSegment
)

// dnp3ObjMode says whether object headers are followed by object values.
type dnp3ObjMode uint8

const (
	dnp3WithValues  dnp3ObjMode = iota
	dnp3HeadersOnly             // e.g. a READ request: indexes at most
)

// DNP3AppFunc is an application layer function code.
type DNP3AppFunc uint8

// DNP3AppFunc values from IEEE 1815-2012 table 4-1.
const (
	DNP3FuncConfirm            DNP3AppFunc = 0
	DNP3FuncRead               DNP3AppFunc = 1
	DNP3FuncWrite              DNP3AppFunc = 2
	DNP3FuncSelect             DNP3AppFunc = 3
	DNP3FuncOperate            DNP3AppFunc = 4
	DNP3FuncDirectOperate      DNP3AppFunc = 5
	DNP3FuncDirectOperateNR    DNP3AppFunc = 6
	DNP3FuncImmedFreeze        DNP3AppFunc = 7
	DNP3FuncImmedFreezeNR      DNP3AppFunc = 8
	DNP3FuncFreezeClear        DNP3AppFunc = 9
	DNP3FuncFreezeClearNR      DNP3AppFunc = 10
	DNP3FuncFreezeAtTime       DNP3AppFunc = 11
	DNP3FuncFreezeAtTimeNR     DNP3AppFunc = 12
	DNP3FuncColdRestart        DNP3AppFunc = 13
	DNP3FuncWarmRestart        DNP3AppFunc = 14
	DNP3FuncInitializeData     DNP3AppFunc = 15
	DNP3FuncInitializeAppl     DNP3AppFunc = 16
	DNP3FuncStartAppl          DNP3AppFunc = 17
	DNP3FuncStopAppl           DNP3AppFunc = 18
	DNP3FuncSaveConfig         DNP3AppFunc = 19
	DNP3FuncEnableUnsolicited  DNP3AppFunc = 20
	DNP3FuncDisableUnsolicited DNP3AppFunc = 21
	DNP3FuncAssignClass        DNP3AppFunc = 22
	DNP3FuncDelayMeasure       DNP3AppFunc = 23
	DNP3FuncRecordCurrentTime  DNP3AppFunc = 24
	DNP3FuncOpenFile           DNP3AppFunc = 25
	DNP3FuncCloseFile          DNP3AppFunc = 26
	DNP3FuncDeleteFile         DNP3AppFunc = 27
	DNP3FuncGetFileInfo        DNP3AppFunc = 28
	DNP3FuncAuthenticateFile   DNP3AppFunc = 29
	DNP3FuncAbortFile          DNP3AppFunc = 30
	DNP3FuncActivateConfig     DNP3AppFunc = 31
	DNP3FuncAuthRequest        DNP3AppFunc = 32
	DNP3FuncAuthRequestNoAck   DNP3AppFunc = 33
	DNP3FuncResponse           DNP3AppFunc = 129
	DNP3FuncUnsolicited        DNP3AppFunc = 130
	DNP3FuncAuthResponse       DNP3AppFunc = 131
)

// dnp3AppFuncNames maps function codes to their names.
var dnp3AppFuncNames = map[DNP3AppFunc]string{
	DNP3FuncConfirm:            "Confirm",
	DNP3FuncRead:               "Read",
	DNP3FuncWrite:              "Write",
	DNP3FuncSelect:             "Select",
	DNP3FuncOperate:            "Operate",
	DNP3FuncDirectOperate:      "Direct Operate",
	DNP3FuncDirectOperateNR:    "Direct Operate No Ack",
	DNP3FuncImmedFreeze:        "Immediate Freeze",
	DNP3FuncImmedFreezeNR:      "Immediate Freeze No Ack",
	DNP3FuncFreezeClear:        "Freeze and Clear",
	DNP3FuncFreezeClearNR:      "Freeze and Clear No Ack",
	DNP3FuncFreezeAtTime:       "Freeze at Time",
	DNP3FuncFreezeAtTimeNR:     "Freeze at Time No Ack",
	DNP3FuncColdRestart:        "Cold Restart",
	DNP3FuncWarmRestart:        "Warm Restart",
	DNP3FuncInitializeData:     "Initialize Data",
	DNP3FuncInitializeAppl:     "Initialize Application",
	DNP3FuncStartAppl:          "Start Application",
	DNP3FuncStopAppl:           "Stop Application",
	DNP3FuncSaveConfig:         "Save Configuration",
	DNP3FuncEnableUnsolicited:  "Enable Unsolicited",
	DNP3FuncDisableUnsolicited: "Disable Unsolicited",
	DNP3FuncAssignClass:        "Assign Class",
	DNP3FuncDelayMeasure:       "Delay Measurement",
	DNP3FuncRecordCurrentTime:  "Record Current Time",
	DNP3FuncOpenFile:           "Open File",
	DNP3FuncCloseFile:          "Close File",
	DNP3FuncDeleteFile:         "Delete File",
	DNP3FuncGetFileInfo:        "Get File Info",
	DNP3FuncAuthenticateFile:   "Authenticate File",
	DNP3FuncAbortFile:          "Abort File",
	DNP3FuncActivateConfig:     "Activate Config",
	DNP3FuncAuthRequest:        "Authentication Request",
	DNP3FuncAuthRequestNoAck:   "Authentication Request No Ack",
	DNP3FuncResponse:           "Response",
	DNP3FuncUnsolicited:        "Unsolicited Response",
	DNP3FuncAuthResponse:       "Authentication Response",
}

// String returns the function name.
func (f DNP3AppFunc) String() string {
	if name, ok := dnp3AppFuncNames[f]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", uint8(f))
}

// IsResponse reports whether f is sent by an outstation, and so is
// followed by internal indications.
func (f DNP3AppFunc) IsResponse() bool {
	return f == DNP3FuncResponse || f == DNP3FuncUnsolicited || f == DNP3FuncAuthResponse
}

// headerOnly reports whether a request with function f lists object
// headers without object values, e.g. a READ of class 1 data.
func (f DNP3AppFunc) headerOnly() bool {
	switch f {
	case DNP3FuncRead, DNP3FuncImmedFreeze, DNP3FuncImmedFreezeNR,
		DNP3FuncFreezeClear, DNP3FuncFreezeClearNR,
		DNP3FuncEnableUnsolicited, DNP3FuncDisableUnsolicited,
		DNP3FuncAssignClass:
		return true
	}
	return false
}

// DNP3IIN holds the internal indications of a response: IIN1 in the high
// byte, IIN2 in the low byte, as they appear on the wire.
type DNP3IIN uint16

// DNP3IIN bits.
const (
	DNP3IINBroadcast        DNP3IIN = 0x0100
	DNP3IINClass1Events     DNP3IIN = 0x0200
	DNP3IINClass2Events     DNP3IIN = 0x0400
	DNP3IINClass3Events     DNP3IIN = 0x0800
	DNP3IINNeedTime         DNP3IIN = 0x1000
	DNP3IINLocalControl     DNP3IIN = 0x2000
	DNP3IINDeviceTrouble    DNP3IIN = 0x4000
	DNP3IINDeviceRestart    DNP3IIN = 0x8000
	DNP3IINNoFuncSupport    DNP3IIN = 0x0001
	DNP3IINObjectUnknown    DNP3IIN = 0x0002
	DNP3IINParameterError   DNP3IIN = 0x0004
	DNP3IINEventOverflow    DNP3IIN = 0x0008
	DNP3IINAlreadyExecuting DNP3IIN = 0x0010
	DNP3IINConfigCorrupt    DNP3IIN = 0x0020
	DNP3IINReserved2        DNP3IIN = 0x0040
	DNP3IINReserved1        DNP3IIN = 0x0080
)

// dnp3IINNames lists the IIN bits in wire order for String.
var dnp3IINNames = []struct {
	bit  DNP3IIN
	name string
}{
	{DNP3IINBroadcast, "Broadcast"},
	{DNP3IINClass1Events, "Class1Events"},
	{DNP3IINClass2Events, "Class2Events"},
	{DNP3IINClass3Events, "Class3Events"},
	{DNP3IINNeedTime, "NeedTime"},
	{DNP3IINLocalControl, "LocalControl"},
	{DNP3IINDeviceTrouble, "DeviceTrouble"},
	{DNP3IINDeviceRestart, "DeviceRestart"},
	{DNP3IINNoFuncSupport, "NoFuncSupport"},
	{DNP3IINObjectUnknown, "ObjectUnknown"},
	{DNP3IINParameterError, "ParameterError"},
	{DNP3IINEventOverflow, "EventOverflow"},
	{DNP3IINAlreadyExecuting, "AlreadyExecuting"},
	{DNP3IINConfigCorrupt, "ConfigCorrupt"},
	{DNP3IINReserved2, "Reserved2"},
	{DNP3IINReserved1, "Reserved1"},
}

// Has reports whether every bit of flag is set.
func (i DNP3IIN) Has(flag DNP3IIN) bool {
	return i&flag == flag
}

// String lists the set bits, e.g. "DeviceRestart|NeedTime".
func (i DNP3IIN) String() string {
	var names []string
	for _, n := range dnp3IINNames {
		if i.Has(n.bit) {
			names = append(names, n.name)
		}
	}
	return strings.Join(names, "|")
}

// DNP3AppControl is the application control octet.
type DNP3AppControl struct {
	FIR bool
	FIN bool
	CON bool
	UNS bool
	Seq uint8
}

// DNP3Application is the application layer of a frame that begins a
// fragment. Objects lists the object headers in order. When the parse
// stops early, the last one is the header that stopped it, its State
// saying why: an object whose size this decoder does not know, a reserved
// qualifier code, a bad range, or objects continuing in the next frame of
// the fragment. Unparsed holds the bytes from that header on.
type DNP3Application struct {
	Control  DNP3AppControl
	Function DNP3AppFunc
	IIN      DNP3IIN // responses only
	Objects  []DNP3ObjectHeader
	Unparsed []byte
}

// DNP3Group is an object group number.
type DNP3Group uint8

// DNP3Group values for the groups this decoder sizes, plus a few others.
const (
	DNP3GroupDeviceAttributes   DNP3Group = 0
	DNP3GroupBinaryInput        DNP3Group = 1
	DNP3GroupBinaryInputEvent   DNP3Group = 2
	DNP3GroupDoubleBitInput     DNP3Group = 3
	DNP3GroupDoubleBitEvent     DNP3Group = 4
	DNP3GroupBinaryOutput       DNP3Group = 10
	DNP3GroupBinaryOutputEvent  DNP3Group = 11
	DNP3GroupBinaryCommand      DNP3Group = 12
	DNP3GroupBinaryCommandEvent DNP3Group = 13
	DNP3GroupCounter            DNP3Group = 20
	DNP3GroupFrozenCounter      DNP3Group = 21
	DNP3GroupCounterEvent       DNP3Group = 22
	DNP3GroupFrozenCounterEvent DNP3Group = 23
	DNP3GroupAnalogInput        DNP3Group = 30
	DNP3GroupFrozenAnalogInput  DNP3Group = 31
	DNP3GroupAnalogInputEvent   DNP3Group = 32
	DNP3GroupFrozenAnalogEvent  DNP3Group = 33
	DNP3GroupAnalogDeadband     DNP3Group = 34
	DNP3GroupAnalogOutputStatus DNP3Group = 40
	DNP3GroupAnalogOutput       DNP3Group = 41
	DNP3GroupAnalogOutputEvent  DNP3Group = 42
	DNP3GroupAnalogCommandEvent DNP3Group = 43
	DNP3GroupTime               DNP3Group = 50
	DNP3GroupCTO                DNP3Group = 51
	DNP3GroupTimeDelay          DNP3Group = 52
	DNP3GroupClassData          DNP3Group = 60
	DNP3GroupFile               DNP3Group = 70
	DNP3GroupIIN                DNP3Group = 80
	DNP3GroupDeviceStorage      DNP3Group = 81
	DNP3GroupDeviceProfile      DNP3Group = 82
	DNP3GroupPrivateObject      DNP3Group = 83
	DNP3GroupDataSetPrototype   DNP3Group = 85
	DNP3GroupDataSetDescriptor  DNP3Group = 86
	DNP3GroupDataSet            DNP3Group = 87
	DNP3GroupDataSetEvent       DNP3Group = 88
	DNP3GroupApplication        DNP3Group = 90
	DNP3GroupOperationStatus    DNP3Group = 91
	DNP3GroupBCD                DNP3Group = 101
	DNP3GroupUint8              DNP3Group = 102
	DNP3GroupOctetString        DNP3Group = 110
	DNP3GroupOctetStringEvent   DNP3Group = 111
	DNP3GroupVTOutput           DNP3Group = 112
	DNP3GroupVTEvent            DNP3Group = 113
	DNP3GroupAuthentication     DNP3Group = 120
	DNP3GroupSecurityStat       DNP3Group = 121
	DNP3GroupSecurityStatEvent  DNP3Group = 122
)

// dnp3GroupNames maps groups to their names.
var dnp3GroupNames = map[DNP3Group]string{
	DNP3GroupDeviceAttributes:   "Device Attributes",
	DNP3GroupBinaryInput:        "Binary Input",
	DNP3GroupBinaryInputEvent:   "Binary Input Event",
	DNP3GroupDoubleBitInput:     "Double-bit Binary Input",
	DNP3GroupDoubleBitEvent:     "Double-bit Binary Input Event",
	DNP3GroupBinaryOutput:       "Binary Output",
	DNP3GroupBinaryOutputEvent:  "Binary Output Event",
	DNP3GroupBinaryCommand:      "Binary Output Command",
	DNP3GroupBinaryCommandEvent: "Binary Output Command Event",
	DNP3GroupCounter:            "Counter",
	DNP3GroupFrozenCounter:      "Frozen Counter",
	DNP3GroupCounterEvent:       "Counter Event",
	DNP3GroupFrozenCounterEvent: "Frozen Counter Event",
	DNP3GroupAnalogInput:        "Analog Input",
	DNP3GroupFrozenAnalogInput:  "Frozen Analog Input",
	DNP3GroupAnalogInputEvent:   "Analog Input Event",
	DNP3GroupFrozenAnalogEvent:  "Frozen Analog Input Event",
	DNP3GroupAnalogDeadband:     "Analog Input Deadband",
	DNP3GroupAnalogOutputStatus: "Analog Output Status",
	DNP3GroupAnalogOutput:       "Analog Output",
	DNP3GroupAnalogOutputEvent:  "Analog Output Event",
	DNP3GroupAnalogCommandEvent: "Analog Output Command Event",
	DNP3GroupTime:               "Time and Date",
	DNP3GroupCTO:                "Common Time of Occurrence",
	DNP3GroupTimeDelay:          "Time Delay",
	DNP3GroupClassData:          "Class Data",
	DNP3GroupFile:               "File Control",
	DNP3GroupIIN:                "Internal Indications",
	DNP3GroupDeviceStorage:      "Device Storage",
	DNP3GroupDeviceProfile:      "Device Profile",
	DNP3GroupPrivateObject:      "Private Registration Object",
	DNP3GroupDataSetPrototype:   "Data Set Prototype",
	DNP3GroupDataSetDescriptor:  "Data Set Descriptor",
	DNP3GroupDataSet:            "Data Set",
	DNP3GroupDataSetEvent:       "Data Set Event",
	DNP3GroupApplication:        "Application",
	DNP3GroupOperationStatus:    "Status of Requested Operation",
	DNP3GroupBCD:                "Binary-Coded Decimal Integer",
	DNP3GroupUint8:              "Unsigned Integer",
	DNP3GroupOctetString:        "Octet String",
	DNP3GroupOctetStringEvent:   "Octet String Event",
	DNP3GroupVTOutput:           "Virtual Terminal Output",
	DNP3GroupVTEvent:            "Virtual Terminal Event",
	DNP3GroupAuthentication:     "Authentication",
	DNP3GroupSecurityStat:       "Security Statistic",
	DNP3GroupSecurityStatEvent:  "Security Statistic Event",
}

// String returns the group name.
func (g DNP3Group) String() string {
	if name, ok := dnp3GroupNames[g]; ok {
		return name
	}
	return fmt.Sprintf("Group(%d)", uint8(g))
}

// DNP3PrefixCode is the object prefix code of a qualifier: what, if
// anything, precedes each object.
type DNP3PrefixCode uint8

// DNP3PrefixCode values.
const (
	DNP3PrefixNone   DNP3PrefixCode = 0
	DNP3PrefixIndex1 DNP3PrefixCode = 1 // 1 octet index
	DNP3PrefixIndex2 DNP3PrefixCode = 2
	DNP3PrefixIndex4 DNP3PrefixCode = 3
	DNP3PrefixSize1  DNP3PrefixCode = 4 // 1 octet object size
	DNP3PrefixSize2  DNP3PrefixCode = 5
	DNP3PrefixSize4  DNP3PrefixCode = 6
)

// Len returns the prefix width in bytes, or -1 for the reserved code 7.
func (c DNP3PrefixCode) Len() int {
	switch c {
	case DNP3PrefixNone:
		return 0
	case DNP3PrefixIndex1, DNP3PrefixSize1:
		return 1
	case DNP3PrefixIndex2, DNP3PrefixSize2:
		return 2
	case DNP3PrefixIndex4, DNP3PrefixSize4:
		return 4
	}
	return -1
}

// IsSize reports whether the prefix gives the object size, not its index.
func (c DNP3PrefixCode) IsSize() bool {
	return c >= DNP3PrefixSize1 && c <= DNP3PrefixSize4
}

// String returns the prefix code name.
func (c DNP3PrefixCode) String() string {
	switch c {
	case DNP3PrefixNone:
		return "None"
	case DNP3PrefixIndex1, DNP3PrefixIndex2, DNP3PrefixIndex4:
		return fmt.Sprintf("%d-Octet Index", c.Len())
	case DNP3PrefixSize1, DNP3PrefixSize2, DNP3PrefixSize4:
		return fmt.Sprintf("%d-Octet Object Size", c.Len())
	}
	return fmt.Sprintf("Reserved(%d)", uint8(c))
}

// DNP3RangeCode is the range specifier code of a qualifier.
type DNP3RangeCode uint8

// DNP3RangeCode values. Codes 3 to 5 hold a start and a stop like codes
// 0 to 2 (IEEE 1815-2012 table 4-6, and the parsing rules of DNP3
// application note AN2013-004b), one object per address. Wireshark
// follows the older reading of a single absolute address instead, so it
// shows other objects for these three codes.
const (
	DNP3RangeStartStop1  DNP3RangeCode = 0x0 // 1 octet start and stop index
	DNP3RangeStartStop2  DNP3RangeCode = 0x1
	DNP3RangeStartStop4  DNP3RangeCode = 0x2
	DNP3RangeVirtual1    DNP3RangeCode = 0x3 // 1 octet start and stop virtual address
	DNP3RangeVirtual2    DNP3RangeCode = 0x4
	DNP3RangeVirtual4    DNP3RangeCode = 0x5
	DNP3RangeAll         DNP3RangeCode = 0x6 // no range field
	DNP3RangeCount1      DNP3RangeCode = 0x7 // 1 octet object count
	DNP3RangeCount2      DNP3RangeCode = 0x8
	DNP3RangeCount4      DNP3RangeCode = 0x9
	DNP3RangeFreeFormat1 DNP3RangeCode = 0xB // 1 octet count of variable format objects
)

// width returns the bytes of one range field value, 0 for no range, or -1
// for a reserved code.
func (c DNP3RangeCode) width() int {
	switch c {
	case DNP3RangeStartStop1, DNP3RangeVirtual1, DNP3RangeCount1, DNP3RangeFreeFormat1:
		return 1
	case DNP3RangeStartStop2, DNP3RangeVirtual2, DNP3RangeCount2:
		return 2
	case DNP3RangeStartStop4, DNP3RangeVirtual4, DNP3RangeCount4:
		return 4
	case DNP3RangeAll:
		return 0
	}
	return -1
}

// IsStartStop reports whether the range field holds start and stop values.
func (c DNP3RangeCode) IsStartStop() bool {
	return c <= DNP3RangeVirtual4
}

// IsVirtual reports whether the start and stop values are virtual
// addresses (codes 3 to 5) rather than point indexes.
func (c DNP3RangeCode) IsVirtual() bool {
	return c >= DNP3RangeVirtual1 && c <= DNP3RangeVirtual4
}

// String returns the range code name.
func (c DNP3RangeCode) String() string {
	switch {
	case c <= DNP3RangeStartStop4:
		return fmt.Sprintf("%d-Octet Start/Stop Indexes", c.width())
	case c <= DNP3RangeVirtual4:
		return fmt.Sprintf("%d-Octet Start/Stop Virtual Addresses", c.width())
	case c == DNP3RangeAll:
		return "No Range Field"
	case c <= DNP3RangeCount4:
		return fmt.Sprintf("%d-Octet Count of Objects", c.width())
	case c == DNP3RangeFreeFormat1:
		return "1-Octet Count of Variable Format Objects"
	}
	return fmt.Sprintf("Reserved(%d)", uint8(c))
}

// DNP3HeaderState says how far an object header decoded.
type DNP3HeaderState uint8

// DNP3HeaderState values.
const (
	// DNP3HeaderDecoded: the header and every object it covers decoded.
	DNP3HeaderDecoded DNP3HeaderState = iota
	// DNP3HeaderReserved: the qualifier holds a reserved prefix or range
	// code, so the range field and the objects cannot be delimited.
	DNP3HeaderReserved
	// DNP3HeaderUnsized: the range decoded, the objects are of a size
	// this decoder cannot tell.
	DNP3HeaderUnsized
	// DNP3HeaderTruncated: the range field or the objects run past the
	// end of the fragment, or of the segment when more segments follow.
	DNP3HeaderTruncated
	// DNP3HeaderBadRange: the stop of the range is below its start.
	DNP3HeaderBadRange
)

// String returns the state name.
func (s DNP3HeaderState) String() string {
	switch s {
	case DNP3HeaderDecoded:
		return "Decoded"
	case DNP3HeaderReserved:
		return "Reserved Qualifier"
	case DNP3HeaderUnsized:
		return "Unsized Objects"
	case DNP3HeaderTruncated:
		return "Truncated"
	case DNP3HeaderBadRange:
		return "Bad Range"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(s))
}

// DNP3ObjectHeader is one object header and the objects it covers.
//
// Count is the number of objects (stop-start+1 for a start/stop range),
// or 0 for DNP3RangeAll. Data is every byte the objects take, prefixes
// included. Headers that carry no values, such as those of a READ request
// or class data, leave it empty, except that index-prefixed qualifiers
// (0x17, 0x28) keep their index prefixes in it. Objects slices Data per object for byte
// aligned objects. Packed objects (one bit per binary input, two per
// double-bit input) are not sliced: BitsPerObject is set and PackedValue
// reads them out of Data.
//
// State is DNP3HeaderDecoded for every header but the last of a fragment
// whose parse stopped there: that one names the object that stopped it
// and has neither Data nor Objects. Wireshark lists such a header too.
type DNP3ObjectHeader struct {
	Group         DNP3Group
	Variation     uint8
	Qualifier     uint8
	Prefix        DNP3PrefixCode
	Range         DNP3RangeCode
	Start         uint32
	Stop          uint32
	Count         uint64
	Data          []byte
	Objects       []DNP3Object
	BitsPerObject uint8
	State         DNP3HeaderState
}

// ReservedBit reports whether bit 7 of the qualifier, reserved and sent
// as 0, is set. The prefix and range codes are read all the same.
func (h *DNP3ObjectHeader) ReservedBit() bool {
	return h.Qualifier&dnp3QualReserved != 0
}

// DNP3Object is one object of a header. Index is the point index from the
// object prefix, or start+n for a range, or n otherwise. Data holds the
// object value with its prefix removed; it is empty in a request that
// lists indexes only.
type DNP3Object struct {
	Index uint32
	Data  []byte
}

// PackedValue returns object i of a packed header (BitsPerObject 1 or 2),
// first object in the low bits of the first byte. It returns 0 past the
// end of Data or for a header that is not packed.
func (h *DNP3ObjectHeader) PackedValue(i uint64) uint8 {
	bits := uint64(h.BitsPerObject)
	if bits == 0 || i >= h.Count {
		return 0
	}

	bit := i * bits
	if bit/dnp3BitsPerByte >= uint64(len(h.Data)) {
		return 0
	}

	mask := byte(1)<<bits - 1
	return h.Data[bit/dnp3BitsPerByte] >> (bit % dnp3BitsPerByte) & mask
}

// dnp3ObjSize describes how one group/variation is laid out: a fixed
// size in bytes, or packed bits per object.
type dnp3ObjSize struct {
	bytes int
	bits  int
}

// dnp3GV packs a group and variation into one table key.
func dnp3GV(g DNP3Group, v uint8) uint16 {
	return uint16(g)<<dnp3BitsPerByte | uint16(v)
}

// dnp3ObjSizes lists the fixed object sizes from IEEE 1815-2012 annex A.
// Groups 110 to 113 are sized by their variation and handled apart.
var dnp3ObjSizes = map[uint16]dnp3ObjSize{
	dnp3GV(1, 1): {bits: 1}, dnp3GV(1, 2): {bytes: 1},
	dnp3GV(2, 1): {bytes: 1}, dnp3GV(2, 2): {bytes: 7}, dnp3GV(2, 3): {bytes: 3},
	dnp3GV(3, 1): {bits: 2}, dnp3GV(3, 2): {bytes: 1},
	dnp3GV(4, 1): {bytes: 1}, dnp3GV(4, 2): {bytes: 7}, dnp3GV(4, 3): {bytes: 3},
	dnp3GV(10, 1): {bits: 1}, dnp3GV(10, 2): {bytes: 1},
	dnp3GV(11, 1): {bytes: 1}, dnp3GV(11, 2): {bytes: 7},
	dnp3GV(12, 1): {bytes: 11}, dnp3GV(12, 2): {bytes: 11}, dnp3GV(12, 3): {bits: 1},
	dnp3GV(13, 1): {bytes: 1}, dnp3GV(13, 2): {bytes: 7},
	dnp3GV(20, 1): {bytes: 5}, dnp3GV(20, 2): {bytes: 3}, dnp3GV(20, 3): {bytes: 5}, dnp3GV(20, 4): {bytes: 3},
	dnp3GV(20, 5): {bytes: 4}, dnp3GV(20, 6): {bytes: 2}, dnp3GV(20, 7): {bytes: 4}, dnp3GV(20, 8): {bytes: 2},
	dnp3GV(21, 1): {bytes: 5}, dnp3GV(21, 2): {bytes: 3}, dnp3GV(21, 3): {bytes: 5}, dnp3GV(21, 4): {bytes: 3},
	dnp3GV(21, 5): {bytes: 11}, dnp3GV(21, 6): {bytes: 9}, dnp3GV(21, 7): {bytes: 11}, dnp3GV(21, 8): {bytes: 9},
	dnp3GV(21, 9): {bytes: 4}, dnp3GV(21, 10): {bytes: 2}, dnp3GV(21, 11): {bytes: 4}, dnp3GV(21, 12): {bytes: 2},
	dnp3GV(22, 1): {bytes: 5}, dnp3GV(22, 2): {bytes: 3}, dnp3GV(22, 3): {bytes: 5}, dnp3GV(22, 4): {bytes: 3},
	dnp3GV(22, 5): {bytes: 11}, dnp3GV(22, 6): {bytes: 9}, dnp3GV(22, 7): {bytes: 11}, dnp3GV(22, 8): {bytes: 9},
	dnp3GV(23, 1): {bytes: 5}, dnp3GV(23, 2): {bytes: 3}, dnp3GV(23, 3): {bytes: 5}, dnp3GV(23, 4): {bytes: 3},
	dnp3GV(23, 5): {bytes: 11}, dnp3GV(23, 6): {bytes: 9}, dnp3GV(23, 7): {bytes: 11}, dnp3GV(23, 8): {bytes: 9},
	dnp3GV(30, 1): {bytes: 5}, dnp3GV(30, 2): {bytes: 3}, dnp3GV(30, 3): {bytes: 4}, dnp3GV(30, 4): {bytes: 2},
	dnp3GV(30, 5): {bytes: 5}, dnp3GV(30, 6): {bytes: 9},
	dnp3GV(31, 1): {bytes: 5}, dnp3GV(31, 2): {bytes: 3}, dnp3GV(31, 3): {bytes: 11}, dnp3GV(31, 4): {bytes: 9},
	dnp3GV(31, 5): {bytes: 4}, dnp3GV(31, 6): {bytes: 2}, dnp3GV(31, 7): {bytes: 5}, dnp3GV(31, 8): {bytes: 9},
	dnp3GV(32, 1): {bytes: 5}, dnp3GV(32, 2): {bytes: 3}, dnp3GV(32, 3): {bytes: 11}, dnp3GV(32, 4): {bytes: 9},
	dnp3GV(32, 5): {bytes: 5}, dnp3GV(32, 6): {bytes: 9}, dnp3GV(32, 7): {bytes: 11}, dnp3GV(32, 8): {bytes: 15},
	dnp3GV(33, 1): {bytes: 5}, dnp3GV(33, 2): {bytes: 3}, dnp3GV(33, 3): {bytes: 11}, dnp3GV(33, 4): {bytes: 9},
	dnp3GV(33, 5): {bytes: 5}, dnp3GV(33, 6): {bytes: 9}, dnp3GV(33, 7): {bytes: 11}, dnp3GV(33, 8): {bytes: 15},
	dnp3GV(34, 1): {bytes: 2}, dnp3GV(34, 2): {bytes: 4}, dnp3GV(34, 3): {bytes: 4},
	dnp3GV(40, 1): {bytes: 5}, dnp3GV(40, 2): {bytes: 3}, dnp3GV(40, 3): {bytes: 5}, dnp3GV(40, 4): {bytes: 9},
	dnp3GV(41, 1): {bytes: 5}, dnp3GV(41, 2): {bytes: 3}, dnp3GV(41, 3): {bytes: 5}, dnp3GV(41, 4): {bytes: 9},
	dnp3GV(42, 1): {bytes: 5}, dnp3GV(42, 2): {bytes: 3}, dnp3GV(42, 3): {bytes: 11}, dnp3GV(42, 4): {bytes: 9},
	dnp3GV(42, 5): {bytes: 5}, dnp3GV(42, 6): {bytes: 9}, dnp3GV(42, 7): {bytes: 11}, dnp3GV(42, 8): {bytes: 15},
	dnp3GV(43, 1): {bytes: 5}, dnp3GV(43, 2): {bytes: 3}, dnp3GV(43, 3): {bytes: 11}, dnp3GV(43, 4): {bytes: 9},
	dnp3GV(43, 5): {bytes: 5}, dnp3GV(43, 6): {bytes: 9}, dnp3GV(43, 7): {bytes: 11}, dnp3GV(43, 8): {bytes: 15},
	dnp3GV(50, 1): {bytes: 6}, dnp3GV(50, 2): {bytes: 10}, dnp3GV(50, 3): {bytes: 6}, dnp3GV(50, 4): {bytes: 11},
	dnp3GV(51, 1): {bytes: 6}, dnp3GV(51, 2): {bytes: 6},
	dnp3GV(52, 1): {bytes: 2}, dnp3GV(52, 2): {bytes: 2},
	dnp3GV(80, 1):  {bits: 1},
	dnp3GV(81, 1):  {bytes: 3},
	dnp3GV(86, 2):  {bytes: 1},
	dnp3GV(101, 1): {bytes: 2}, dnp3GV(101, 2): {bytes: 4}, dnp3GV(101, 3): {bytes: 8},
	dnp3GV(102, 1): {bytes: 1},
	dnp3GV(121, 1): {bytes: 7},
	dnp3GV(122, 1): {bytes: 7}, dnp3GV(122, 2): {bytes: 13},
}

// dnp3SizeOf returns the layout of group g variation v. Class data has no
// values; octet strings and virtual terminal objects are as many bytes as
// their variation number.
func dnp3SizeOf(g DNP3Group, v uint8) (dnp3ObjSize, bool) {
	switch g {
	case DNP3GroupClassData:
		return dnp3ObjSize{}, true
	case DNP3GroupOctetString, DNP3GroupOctetStringEvent, DNP3GroupVTOutput, DNP3GroupVTEvent:
		return dnp3ObjSize{bytes: int(v)}, v > 0
	}

	size, ok := dnp3ObjSizes[dnp3GV(g, v)]
	return size, ok
}

// dnp3TimeLen is the size of a DNP3 absolute time: milliseconds since
// 1970-01-01 UTC in 48 bits, little endian.
const dnp3TimeLen = 6

// DNP3Time converts the absolute time at the start of b, as carried by
// g50v1, g51 or g2v2 after its flags octet, to a time.Time. It returns the
// zero Time when b is shorter than 6 bytes.
func DNP3Time(b []byte) time.Time {
	if len(b) < dnp3TimeLen {
		return time.Time{}
	}

	var ms uint64
	for i := dnp3TimeLen - 1; i >= 0; i-- {
		ms = ms<<dnp3BitsPerByte | uint64(b[i])
	}
	return time.UnixMilli(int64(ms)).UTC()
}

// dnp3Uint reads a little endian value of 1, 2 or 4 bytes.
func dnp3Uint(b []byte, width int) uint32 {
	switch width {
	case 1:
		return uint32(b[0])
	case 2:
		return uint32(binary.LittleEndian.Uint16(b))
	case 4:
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

// errDNP3Stop ends object parsing without failing the decode: the rest of
// the fragment is kept in Unparsed.
var errDNP3Stop = errors.New("dnp3: stop object parsing")

// decode reads the application header, the IIN of a response, then every
// object header it can size.
func (a *DNP3Application) decode(frag []byte, end dnp3SegmentEnd) error {
	if len(frag) < dnp3AppHeaderLen {
		return ErrDNP3AppTooShort
	}

	ac := frag[0]
	a.Control = DNP3AppControl{
		FIR: ac&dnp3AcFIR != 0,
		FIN: ac&dnp3AcFIN != 0,
		CON: ac&dnp3AcCON != 0,
		UNS: ac&dnp3AcUNS != 0,
		Seq: ac & dnp3AcSeq,
	}
	a.Function = DNP3AppFunc(frag[1])
	rest := frag[dnp3AppHeaderLen:]

	if a.Function.IsResponse() {
		if len(rest) < dnp3IINLen {
			return ErrDNP3AppTooShort
		}
		a.IIN = DNP3IIN(binary.BigEndian.Uint16(rest))
		rest = rest[dnp3IINLen:]
	}

	mode := dnp3WithValues
	if !a.Function.IsResponse() && a.Function.headerOnly() {
		mode = dnp3HeadersOnly
	}

	lenient := false
	for len(rest) > 0 {
		var h DNP3ObjectHeader
		n, err := h.decode(rest, mode)
		if errors.Is(err, ErrDNP3ObjTruncated) && end == dnp3MoreSegments {
			err = errDNP3Stop
		}

		// Bytes past a late sized object were never parsed before, so
		// their errors stop parsing rather than fail the frame.
		if err != nil && lenient {
			err = errDNP3Stop
		}

		// Name the object that stopped the parse. Fewer than three
		// bytes are no header: it has no state and is left out.
		if err != nil && h.State != DNP3HeaderDecoded {
			a.Objects = append(a.Objects, h)
		}

		if errors.Is(err, errDNP3Stop) {
			a.Unparsed = rest
			return nil
		}

		if err != nil {
			a.Unparsed = rest
			return err
		}
		a.Objects = append(a.Objects, h)
		rest = rest[n:]
		lenient = lenient || h.lateSliced(mode)
	}
	return nil
}

// decode reads one object header and the objects it covers from b and
// returns how many bytes they take. It returns errDNP3Stop for objects it
// cannot size and ErrDNP3ObjTruncated when b ends early. Once the three
// header bytes are read, any failure is recorded in State.
func (h *DNP3ObjectHeader) decode(b []byte, mode dnp3ObjMode) (int, error) {
	if len(b) < dnp3ObjHeaderLen {
		return 0, ErrDNP3ObjTruncated
	}

	h.Group = DNP3Group(b[0])
	h.Variation = b[1]
	h.Qualifier = b[2]
	h.Prefix = DNP3PrefixCode(b[2] & dnp3QualPrefix >> dnp3QualPrefixPos)
	h.Range = DNP3RangeCode(b[2] & dnp3QualRange)

	n, err := h.decodeRange(b[dnp3ObjHeaderLen:])
	if err != nil {
		return 0, h.stopped(err)
	}
	n += dnp3ObjHeaderLen

	size, err := h.decodeObjects(b[n:], mode)
	if err != nil {
		return 0, h.stopped(err)
	}
	return n + size, nil
}

// stopped records in State why the header did not decode, unless a more
// precise state is set, and drops any object sliced before the fault.
func (h *DNP3ObjectHeader) stopped(err error) error {
	switch {
	case h.State != DNP3HeaderDecoded:
	case errors.Is(err, ErrDNP3BadRange):
		h.State = DNP3HeaderBadRange
	default:
		h.State = DNP3HeaderTruncated
	}

	h.Data, h.Objects, h.BitsPerObject = nil, nil, 0
	return err
}

// decodeRange reads the range field and sets Start, Stop and Count. It
// returns the field width.
func (h *DNP3ObjectHeader) decodeRange(b []byte) (int, error) {
	// Reserved codes leave the layout of what follows undefined. The
	// reserved bit 7 does not: the codes read the same with it set.
	w := h.Range.width()
	if w < 0 || h.Prefix.Len() < 0 {
		h.State = DNP3HeaderReserved
		return 0, errDNP3Stop
	}

	if h.Range == DNP3RangeAll {
		return 0, nil
	}

	if !h.Range.IsStartStop() {
		if len(b) < w {
			return 0, ErrDNP3ObjTruncated
		}
		h.Count = uint64(dnp3Uint(b, w))
		return w, nil
	}

	if len(b) < 2*w {
		return 0, ErrDNP3ObjTruncated
	}
	h.Start = dnp3Uint(b, w)
	h.Stop = dnp3Uint(b[w:], w)
	if h.Stop < h.Start {
		return 0, fmt.Errorf("%w: start %d, stop %d", ErrDNP3BadRange, h.Start, h.Stop)
	}
	h.Count = uint64(h.Stop-h.Start) + 1
	return 2 * w, nil
}

// decodeObjects slices the objects of the header out of b and returns the
// bytes they take. Every object takes at least one byte before anything
// is allocated for it, so a large claimed count costs nothing until the
// bytes are there.
func (h *DNP3ObjectHeader) decodeObjects(b []byte, mode dnp3ObjMode) (int, error) {
	prefix := h.Prefix.Len()
	if h.Group == DNP3GroupClassData || mode == dnp3HeadersOnly && !h.valuedRequest() {
		return h.decodeFixed(b, prefix, 0)
	}

	// "All objects" (qualifier 0x06) lists no objects, so no values follow.
	if h.Range == DNP3RangeAll || h.Count == 0 {
		return 0, nil
	}

	if h.Prefix.IsSize() {
		return h.decodeSized(b, prefix)
	}

	if dnp3LateSized(h.Group, h.Variation) {
		return h.decodeLate(b, prefix)
	}

	size, ok := dnp3SizeOf(h.Group, h.Variation)
	if !ok {
		return 0, h.unsized()
	}

	// Free format objects are variable sized: each needs a size prefix.
	if h.Range == DNP3RangeFreeFormat1 {
		return 0, h.unsized()
	}

	if size.bits == 0 {
		return h.decodeFixed(b, prefix, size.bytes)
	}

	// Packed objects are only defined without a prefix.
	if prefix != 0 {
		return 0, h.unsized()
	}

	total := (h.Count*uint64(size.bits) + dnp3BitsPerByte - 1) / dnp3BitsPerByte
	if total > uint64(len(b)) {
		return 0, ErrDNP3ObjTruncated
	}
	h.Data = b[:total]
	h.BitsPerObject = uint8(size.bits)
	return int(total), nil
}

// valuedRequest reports whether the header carries object values even in
// a request that otherwise lists headers only: objects sized by their
// prefix, e.g. the g70v5 naming the file block to READ, and the g120v3
// aggressive mode request that may lead any request. Wireshark makes the
// same two exceptions.
func (h *DNP3ObjectHeader) valuedRequest() bool {
	return h.Prefix.IsSize() || h.Group == DNP3GroupAuthentication && h.Variation == dnp3AuthAggrVar
}

// unsized marks the header as one whose objects cannot be delimited and
// stops the parse.
func (h *DNP3ObjectHeader) unsized() error {
	h.State = DNP3HeaderUnsized
	return errDNP3Stop
}

// decodeFixed slices Count objects of prefix+size bytes each. With neither
// a prefix nor a size there is nothing to slice.
func (h *DNP3ObjectHeader) decodeFixed(b []byte, prefix, size int) (int, error) {
	per := uint64(prefix + size)
	if per == 0 {
		return 0, nil
	}

	total := h.Count * per
	if total > uint64(len(b)) {
		return 0, ErrDNP3ObjTruncated
	}
	h.Data = b[:total]

	h.Objects = make([]DNP3Object, h.Count)
	for i := range h.Objects {
		obj := b[uint64(i)*per : uint64(i+1)*per]
		h.Objects[i] = DNP3Object{Index: h.index(i, obj[:prefix]), Data: obj[prefix:]}
	}
	return int(total), nil
}

// decodeSized slices Count objects that each start with their own size.
func (h *DNP3ObjectHeader) decodeSized(b []byte, prefix int) (int, error) {
	h.Objects = make([]DNP3Object, 0, min(h.Count, uint64(len(b)/prefix)))
	off := 0
	for i := uint64(0); i < h.Count; i++ {
		if len(b)-off < prefix {
			return 0, ErrDNP3ObjTruncated
		}

		size := uint64(dnp3Uint(b[off:], prefix))
		if size > uint64(len(b)-off-prefix) {
			return 0, ErrDNP3ObjTruncated
		}

		start := off + prefix
		off = start + int(size)
		h.Objects = append(h.Objects, DNP3Object{Index: h.Start + uint32(i), Data: b[start:off]})
	}
	h.Data = b[:off]
	return off, nil
}

// dnp3LateSizes are fixed object sizes added after the first release.
var dnp3LateSizes = map[uint16]int{
	dnp3GV(120, 3): 6, // aggressive mode request: CSQ, user
	dnp3GV(120, 4): 2, // session key status request: user
}

// dnp3LateSized reports whether objects of group g variation v were left
// unsized, so in Unparsed, by the first release: device attributes,
// whose size each carries, and dnp3LateSizes. g0v254 asks for all
// attributes and carries none.
func dnp3LateSized(g DNP3Group, v uint8) bool {
	if g == DNP3GroupDeviceAttributes {
		return v != 0 && v != dnp3AttrAll
	}

	_, ok := dnp3LateSizes[dnp3GV(g, v)]
	return ok
}

// lateSliced reports whether decodeObjects sliced the header through
// decodeLate.
func (h *DNP3ObjectHeader) lateSliced(mode dnp3ObjMode) bool {
	return mode == dnp3WithValues && len(h.Objects) > 0 && !h.Prefix.IsSize() && dnp3LateSized(h.Group, h.Variation)
}

// decodeLate slices objects dnp3LateSized names. Any shortfall stops
// parsing, as their unknown size did, so no frame that decoded before
// fails now.
func (h *DNP3ObjectHeader) decodeLate(b []byte, prefix int) (int, error) {
	if h.Range == DNP3RangeFreeFormat1 {
		return 0, h.unsized()
	}

	var n int
	var err error
	if h.Group == DNP3GroupDeviceAttributes {
		n, err = h.decodeAttrs(b, prefix)
	} else {
		n, err = h.decodeFixed(b, prefix, dnp3LateSizes[dnp3GV(h.Group, h.Variation)])
	}

	if err != nil {
		return 0, h.unsized()
	}
	return n, nil
}

// decodeAttrs slices Count device attributes, each its prefix, a data
// type code, a length and that many value bytes: 01 02 41 42 is a VSTR
// "AB".
func (h *DNP3ObjectHeader) decodeAttrs(b []byte, prefix int) (int, error) {
	per := prefix + dnp3AttrHeaderLen
	h.Objects = make([]DNP3Object, 0, min(h.Count, uint64(len(b)/per)))
	off := 0
	for i := 0; uint64(i) < h.Count; i++ {
		if len(b)-off < per {
			return 0, ErrDNP3ObjTruncated
		}

		start := off + prefix
		end := start + dnp3AttrHeaderLen + int(b[start+1])
		if end > len(b) {
			return 0, ErrDNP3ObjTruncated
		}

		h.Objects = append(h.Objects, DNP3Object{Index: h.index(i, b[off:start]), Data: b[start:end]})
		off = end
	}
	h.Data = b[:off]
	return off, nil
}

// index returns the point index of object i: its index prefix when it has
// one, else its place in the range.
func (h *DNP3ObjectHeader) index(i int, prefix []byte) uint32 {
	if len(prefix) > 0 && !h.Prefix.IsSize() {
		return dnp3Uint(prefix, len(prefix))
	}
	return h.Start + uint32(i)
}
