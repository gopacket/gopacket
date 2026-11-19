// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The qualifier octets of IEC 60870-5-101, 7.2.6.21 to 7.2.6.39, split
// into their subfields. The decoder stores each qualifier raw; the types
// here give the octet its meaning:
//
//	IEC104Object.Qualifier  COI QOI QCC QPM QPA QRP   by type identification
//	IEC104Object.Command    QOC (QU, S/E), QOS (QL, S/E)
//	IEC104File.Qualifier    FRQ SRQ SCQ LSQ AFQ SOF   by type identification
//
// Names follow Wireshark's packet-iec104.c.

package layers

import "fmt"

// Qualifier bit fields.
const (
	iec104COICauseMask = 0x7F
	iec104COIChangeBit = 0x80

	iec104QCCRequestMask = 0x3F
	iec104QCCFreezeShift = 6

	iec104QPMKindMask   = 0x3F
	iec104QPMChangeBit  = 0x40
	iec104QPMNotOperBit = 0x80

	iec104FileQualMask = 0x7F // FRQ, SRQ: qualifier below the flag bit
	iec104FileFlagBit  = 0x80 // FRQ: negative; SRQ: not ready
	iec104FileLowMask  = 0x0F // SCQ, AFQ: action
	iec104FileErrShift = 4    // SCQ, AFQ: error

	iec104SOFStatusMask = 0x1F
	iec104SOFLastBit    = 0x20 // LFD
	iec104SOFDirBit     = 0x40 // FOR
	iec104SOFActiveBit  = 0x80 // FA
)

// Value ranges of the file transfer elements (IEC 60870-5-101, 7.2.6.28
// to 7.2.6.38): 0 is the default, then a range kept for the standard and
// one for private use.
const (
	iec104FileQualPrivate  = 64  // FRQ, SRQ: 64 to 127
	iec104SOFStatusPrivate = 16  // SOF status: 16 to 31
	iec104NOFPrivate       = 128 // NOF: 128 to 255
	iec104NOFNamedEnd      = 256 // NOF: plain file names from here
)

// iec104RangeName names a value by its range: "Default" for 0, reserved
// for the standard below private, reserved for private use from there.
func iec104RangeName(v, private uint8) string {
	switch {
	case v == 0:
		return "Default"
	case v < private:
		return fmt.Sprintf("Reserved, standard(%d)", v)
	}
	return fmt.Sprintf("Reserved, private(%d)", v)
}

// IEC104COI is the cause of initialisation of M_EI_NA_1.
type IEC104COI uint8

// IEC104COICause is the cause in the low seven bits of COI.
type IEC104COICause uint8

// Causes of initialisation.
const (
	IEC104COIPowerOn     IEC104COICause = 0
	IEC104COIManualReset IEC104COICause = 1
	IEC104COIRemoteReset IEC104COICause = 2
)

// String returns the cause as Wireshark names it.
func (c IEC104COICause) String() string {
	switch c {
	case IEC104COIPowerOn:
		return "Local power switch on"
	case IEC104COIManualReset:
		return "Local manual reset"
	case IEC104COIRemoteReset:
		return "Remote reset"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(c))
}

// Cause returns the cause of initialisation.
func (c IEC104COI) Cause() IEC104COICause {
	return IEC104COICause(c & iec104COICauseMask)
}

// LocalChange reports whether the station initialised after a change of
// its local parameters.
func (c IEC104COI) LocalChange() bool {
	return c&iec104COIChangeBit != 0
}

// IEC104QOI is the qualifier of interrogation of C_IC_NA_1.
type IEC104QOI uint8

// Qualifiers of interrogation. Groups 2 to 15 lie between the group
// bounds.
const (
	IEC104QOIStation IEC104QOI = 20
	IEC104QOIGroup1  IEC104QOI = 21
	IEC104QOIGroup16 IEC104QOI = 36
)

// Group returns the interrogated group, 1 to 16, or 0 when the qualifier
// names none.
func (q IEC104QOI) Group() int {
	if q < IEC104QOIGroup1 || q > IEC104QOIGroup16 {
		return 0
	}
	return int(q-IEC104QOIGroup1) + 1
}

// String returns the qualifier as Wireshark names it.
func (q IEC104QOI) String() string {
	switch {
	case q == 0:
		return "Not specified"
	case q == IEC104QOIStation:
		return "Station interrogation (global)"
	case q.Group() != 0:
		return fmt.Sprintf("Group %d interrogation", q.Group())
	}
	return fmt.Sprintf("Unknown(%d)", uint8(q))
}

// IEC104QCC is the qualifier of counter interrogation of C_CI_NA_1.
type IEC104QCC uint8

// IEC104QCCRequest is RQT, the counters a C_CI_NA_1 asks for.
type IEC104QCCRequest uint8

// Counter requests. Groups 2 and 3 lie between the group bounds.
const (
	IEC104QCCGroup1  IEC104QCCRequest = 1
	IEC104QCCGroup4  IEC104QCCRequest = 4
	IEC104QCCGeneral IEC104QCCRequest = 5
)

// String returns the request as Wireshark names it.
func (r IEC104QCCRequest) String() string {
	switch {
	case r == 0:
		return "Not specified"
	case r == IEC104QCCGeneral:
		return "General counter interrogation"
	case r >= IEC104QCCGroup1 && r <= IEC104QCCGroup4:
		return fmt.Sprintf("Group %d counter interrogation", uint8(r))
	}
	return fmt.Sprintf("Unknown(%d)", uint8(r))
}

// IEC104QCCFreeze is FRZ, what a C_CI_NA_1 does to the counters.
type IEC104QCCFreeze uint8

// Freeze actions.
const (
	IEC104QCCRead        IEC104QCCFreeze = 0
	IEC104QCCFreezeOnly  IEC104QCCFreeze = 1
	IEC104QCCFreezeReset IEC104QCCFreeze = 2
	IEC104QCCReset       IEC104QCCFreeze = 3
)

// String returns the action name.
func (f IEC104QCCFreeze) String() string {
	switch f {
	case IEC104QCCRead:
		return "Read only"
	case IEC104QCCFreezeOnly:
		return "Counter freeze without reset"
	case IEC104QCCFreezeReset:
		return "Counter freeze with reset"
	case IEC104QCCReset:
		return "Counter reset"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(f))
}

// Request returns RQT.
func (q IEC104QCC) Request() IEC104QCCRequest {
	return IEC104QCCRequest(q & iec104QCCRequestMask)
}

// Freeze returns FRZ.
func (q IEC104QCC) Freeze() IEC104QCCFreeze {
	return IEC104QCCFreeze(q >> iec104QCCFreezeShift)
}

// IEC104QPM is the qualifier of parameter of measured values of P_ME_*.
type IEC104QPM uint8

// IEC104QPMKind is KPA, the kind of parameter.
type IEC104QPMKind uint8

// Kinds of parameter.
const (
	IEC104QPMThreshold IEC104QPMKind = 1
	IEC104QPMSmoothing IEC104QPMKind = 2
	IEC104QPMLowLimit  IEC104QPMKind = 3
	IEC104QPMHighLimit IEC104QPMKind = 4
)

// String returns the kind name.
func (k IEC104QPMKind) String() string {
	switch k {
	case 0:
		return "Not used"
	case IEC104QPMThreshold:
		return "Threshold value"
	case IEC104QPMSmoothing:
		return "Smoothing factor (filter time constant)"
	case IEC104QPMLowLimit:
		return "Low limit for transmission of measured values"
	case IEC104QPMHighLimit:
		return "High limit for transmission of measured values"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(k))
}

// Kind returns KPA.
func (q IEC104QPM) Kind() IEC104QPMKind {
	return IEC104QPMKind(q & iec104QPMKindMask)
}

// LocalChange returns LPC: the parameter was changed locally.
func (q IEC104QPM) LocalChange() bool {
	return q&iec104QPMChangeBit != 0
}

// NotInOperation returns POP: the parameter is not in operation.
func (q IEC104QPM) NotInOperation() bool {
	return q&iec104QPMNotOperBit != 0
}

// IEC104QPA is the qualifier of parameter activation of P_AC_NA_1.
type IEC104QPA uint8

// Qualifiers of parameter activation.
const (
	IEC104QPALoaded   IEC104QPA = 1 // previously loaded parameters
	IEC104QPAObject   IEC104QPA = 2 // parameter of the addressed object
	IEC104QPACyclicTx IEC104QPA = 3 // cyclic transmission of the object
)

// String returns the qualifier as Wireshark names it.
func (q IEC104QPA) String() string {
	switch q {
	case 0:
		return "Not used"
	case IEC104QPALoaded:
		return "Act/deact of the previously loaded parameters (object address = 0)"
	case IEC104QPAObject:
		return "Act/deact of the parameter of the addressed object"
	case IEC104QPACyclicTx:
		return "Act/deact of persistent cyclic or periodic transmission of the addressed object"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(q))
}

// IEC104QRP is the qualifier of reset process command of C_RP_NA_1.
type IEC104QRP uint8

// Qualifiers of reset process command.
const (
	IEC104QRPGeneral     IEC104QRP = 1
	IEC104QRPEventBuffer IEC104QRP = 2
)

// String returns the qualifier as Wireshark names it.
func (q IEC104QRP) String() string {
	switch q {
	case 0:
		return "Not used"
	case IEC104QRPGeneral:
		return "General reset of process"
	case IEC104QRPEventBuffer:
		return "Reset of pending information with time tag of the event buffer"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(q))
}

// COI returns the qualifier of an M_EI_NA_1 object.
func (o *IEC104Object) COI() IEC104COI { return IEC104COI(o.Qualifier) }

// QOI returns the qualifier of a C_IC_NA_1 object.
func (o *IEC104Object) QOI() IEC104QOI { return IEC104QOI(o.Qualifier) }

// QCC returns the qualifier of a C_CI_NA_1 object.
func (o *IEC104Object) QCC() IEC104QCC { return IEC104QCC(o.Qualifier) }

// QPM returns the qualifier of a P_ME_NA_1, P_ME_NB_1 or P_ME_NC_1 object.
func (o *IEC104Object) QPM() IEC104QPM { return IEC104QPM(o.Qualifier) }

// QPA returns the qualifier of a P_AC_NA_1 object.
func (o *IEC104Object) QPA() IEC104QPA { return IEC104QPA(o.Qualifier) }

// QRP returns the qualifier of a C_RP_NA_1 object.
func (o *IEC104Object) QRP() IEC104QRP { return IEC104QRP(o.Qualifier) }

// IEC104QU is the QU field of the command qualifier QOC, which SCO, DCO
// and RCO carry in IEC104Command.Qualifier.
type IEC104QU uint8

// Command qualifiers.
const (
	IEC104QUNone       IEC104QU = 0
	IEC104QUShortPulse IEC104QU = 1
	IEC104QULongPulse  IEC104QU = 2
	IEC104QUPersistent IEC104QU = 3
)

// String returns the qualifier as Wireshark names it.
func (q IEC104QU) String() string {
	switch q {
	case IEC104QUNone:
		return "No pulse defined"
	case IEC104QUShortPulse:
		return "Short Pulse"
	case IEC104QULongPulse:
		return "Long Pulse"
	case IEC104QUPersistent:
		return "Persistent Output"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(q))
}

// QU returns the command qualifier of SCO, DCO or RCO as its type. For a
// set-point Qualifier is QL, a plain number, and QU does not apply.
func (c IEC104Command) QU() IEC104QU { return IEC104QU(c.Qualifier) }

// IEC104FRQ is the file ready qualifier of F_FR_NA_1.
type IEC104FRQ uint8

// Negative reports a negative confirm of select, request, deactivate or
// delete.
func (q IEC104FRQ) Negative() bool { return q&iec104FileFlagBit != 0 }

// Qualifier returns the low seven bits; 0 is the default.
func (q IEC104FRQ) Qualifier() uint8 { return uint8(q) & iec104FileQualMask }

// String returns the confirm and the qualifier, e.g. "Negative, Default".
func (q IEC104FRQ) String() string {
	confirm := "Positive"
	if q.Negative() {
		confirm = "Negative"
	}
	return confirm + ", " + iec104RangeName(q.Qualifier(), iec104FileQualPrivate)
}

// IEC104SRQ is the section ready qualifier of F_SR_NA_1.
type IEC104SRQ uint8

// NotReady reports that the section is not ready to load.
func (q IEC104SRQ) NotReady() bool { return q&iec104FileFlagBit != 0 }

// Qualifier returns the low seven bits; 0 is the default.
func (q IEC104SRQ) Qualifier() uint8 { return uint8(q) & iec104FileQualMask }

// String returns the readiness and the qualifier, e.g. "Ready, Default".
func (q IEC104SRQ) String() string {
	ready := "Ready"
	if q.NotReady() {
		ready = "Not ready"
	}
	return ready + ", " + iec104RangeName(q.Qualifier(), iec104FileQualPrivate)
}

// IEC104FileError is the error nibble of SCQ and AFQ.
type IEC104FileError uint8

// File transfer errors.
const (
	IEC104FileErrNone     IEC104FileError = 0
	IEC104FileErrNoMemory IEC104FileError = 1
	IEC104FileErrChecksum IEC104FileError = 2
	IEC104FileErrService  IEC104FileError = 3
	IEC104FileErrName     IEC104FileError = 4
	IEC104FileErrSection  IEC104FileError = 5
)

// String returns the error as Wireshark names it.
func (e IEC104FileError) String() string {
	switch e {
	case IEC104FileErrNone:
		return "Default"
	case IEC104FileErrNoMemory:
		return "Requested memory space not available"
	case IEC104FileErrChecksum:
		return "Checksum failed"
	case IEC104FileErrService:
		return "Unexpected communication service"
	case IEC104FileErrName:
		return "Unexpected name of file"
	case IEC104FileErrSection:
		return "Unexpected name of section"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(e))
}

// IEC104SCQ is the select and call qualifier of F_SC_NA_1.
type IEC104SCQ uint8

// IEC104SCQAction is the action nibble of SCQ.
type IEC104SCQAction uint8

// Select and call actions.
const (
	IEC104SCQSelectFile     IEC104SCQAction = 1
	IEC104SCQRequestFile    IEC104SCQAction = 2
	IEC104SCQDeactFile      IEC104SCQAction = 3
	IEC104SCQDeleteFile     IEC104SCQAction = 4
	IEC104SCQSelectSection  IEC104SCQAction = 5
	IEC104SCQRequestSection IEC104SCQAction = 6
	IEC104SCQDeactSection   IEC104SCQAction = 7
)

// String returns the action name.
func (a IEC104SCQAction) String() string {
	switch a {
	case 0:
		return "Default"
	case IEC104SCQSelectFile:
		return "Select file"
	case IEC104SCQRequestFile:
		return "Request file"
	case IEC104SCQDeactFile:
		return "Deactivate file"
	case IEC104SCQDeleteFile:
		return "Delete file"
	case IEC104SCQSelectSection:
		return "Select section"
	case IEC104SCQRequestSection:
		return "Request section"
	case IEC104SCQDeactSection:
		return "Deactivate section"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(a))
}

// Action returns the low nibble.
func (q IEC104SCQ) Action() IEC104SCQAction {
	return IEC104SCQAction(q & iec104FileLowMask)
}

// Error returns the high nibble.
func (q IEC104SCQ) Error() IEC104FileError {
	return IEC104FileError(q >> iec104FileErrShift)
}

// IEC104LSQ is the last section or segment qualifier of F_LS_NA_1.
type IEC104LSQ uint8

// Last section or segment qualifiers.
const (
	IEC104LSQFile         IEC104LSQ = 1 // file transfer without deactivation
	IEC104LSQFileDeact    IEC104LSQ = 2
	IEC104LSQSection      IEC104LSQ = 3 // section transfer without deactivation
	IEC104LSQSectionDeact IEC104LSQ = 4
)

// String returns the qualifier as Wireshark names it.
func (q IEC104LSQ) String() string {
	switch q {
	case 0:
		return "Not used"
	case IEC104LSQFile:
		return "File transfer without deactivation"
	case IEC104LSQFileDeact:
		return "File transfer with deactivation"
	case IEC104LSQSection:
		return "Section transfer without deactivation"
	case IEC104LSQSectionDeact:
		return "Section transfer with deactivation"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(q))
}

// IEC104AFQ is the acknowledge file or section qualifier of F_AF_NA_1.
type IEC104AFQ uint8

// IEC104AFQAck is the acknowledge nibble of AFQ.
type IEC104AFQAck uint8

// Acknowledgements.
const (
	IEC104AFQFilePositive    IEC104AFQAck = 1
	IEC104AFQFileNegative    IEC104AFQAck = 2
	IEC104AFQSectionPositive IEC104AFQAck = 3
	IEC104AFQSectionNegative IEC104AFQAck = 4
)

// String returns the acknowledgement as Wireshark names it.
func (a IEC104AFQAck) String() string {
	switch a {
	case 0:
		return "Not used"
	case IEC104AFQFilePositive:
		return "Positive acknowledge of file transfer"
	case IEC104AFQFileNegative:
		return "Negative acknowledge of file transfer"
	case IEC104AFQSectionPositive:
		return "Positive acknowledge of section transfer"
	case IEC104AFQSectionNegative:
		return "Negative acknowledge of section transfer"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(a))
}

// Ack returns the low nibble.
func (q IEC104AFQ) Ack() IEC104AFQAck {
	return IEC104AFQAck(q & iec104FileLowMask)
}

// Error returns the high nibble.
func (q IEC104AFQ) Error() IEC104FileError {
	return IEC104FileError(q >> iec104FileErrShift)
}

// IEC104SOF is the status of file of F_DR_TA_1.
type IEC104SOF uint8

// Status returns the low five bits; 0 is the default.
func (s IEC104SOF) Status() uint8 { return uint8(s) & iec104SOFStatusMask }

// LastFile returns LFD: this is the last file of the directory.
func (s IEC104SOF) LastFile() bool { return s&iec104SOFLastBit != 0 }

// Directory returns FOR: the name is a subdirectory, not a file.
func (s IEC104SOF) Directory() bool { return s&iec104SOFDirBit != 0 }

// Active returns FA: the file transfer is active.
func (s IEC104SOF) Active() bool { return s&iec104SOFActiveBit != 0 }

// String returns the status and the three flags as Wireshark words
// them, e.g. "Default, Last file, File, Waits for transfer".
func (s IEC104SOF) String() string {
	last, kind, active := "Additional file follows", "File", "Waits for transfer"
	if s.LastFile() {
		last = "Last file"
	}
	if s.Directory() {
		kind = "Subdirectory"
	}
	if s.Active() {
		active = "Transfer active"
	}
	return iec104RangeName(s.Status(), iec104SOFStatusPrivate) + ", " + last + ", " + kind + ", " + active
}

// IEC104NOF is the name of file (IEC 60870-5-101, 7.2.6.33).
type IEC104NOF uint16

// File names the standard defines.
const (
	IEC104NOFDefault     IEC104NOF = 0
	IEC104NOFTransparent IEC104NOF = 1
	IEC104NOFDisturbance IEC104NOF = 2
	IEC104NOFEvents      IEC104NOF = 3
	IEC104NOFAnalogue    IEC104NOF = 4
)

// String returns what the name stands for, e.g. "Sequences of events".
func (n IEC104NOF) String() string {
	switch {
	case n == IEC104NOFDefault:
		return "Default"
	case n == IEC104NOFTransparent:
		return "Transparent file"
	case n == IEC104NOFDisturbance:
		return "Disturbance data of protection equipment"
	case n == IEC104NOFEvents:
		return "Sequences of events"
	case n == IEC104NOFAnalogue:
		return "Sequences of recorded analogue values"
	case n < iec104NOFPrivate:
		return fmt.Sprintf("Reserved, standard(%d)", uint16(n))
	case n < iec104NOFNamedEnd:
		return fmt.Sprintf("Reserved, private(%d)", uint16(n))
	}
	return fmt.Sprintf("File(%d)", uint16(n))
}

// IEC104NOS is the name of section (IEC 60870-5-101, 7.2.6.34).
type IEC104NOS uint8

// String returns "Default" for 0, else the section, e.g. "Section(3)".
func (n IEC104NOS) String() string {
	if n == 0 {
		return "Default"
	}
	return fmt.Sprintf("Section(%d)", uint8(n))
}

// NOF returns the name of file of a file transfer object.
func (f *IEC104File) NOF() IEC104NOF { return IEC104NOF(f.Name) }

// NOS returns the name of section of a file transfer object.
func (f *IEC104File) NOS() IEC104NOS { return IEC104NOS(f.Section) }

// FRQ returns the qualifier of an F_FR_NA_1 object.
func (f *IEC104File) FRQ() IEC104FRQ { return IEC104FRQ(f.Qualifier) }

// SRQ returns the qualifier of an F_SR_NA_1 object.
func (f *IEC104File) SRQ() IEC104SRQ { return IEC104SRQ(f.Qualifier) }

// SCQ returns the qualifier of an F_SC_NA_1 object.
func (f *IEC104File) SCQ() IEC104SCQ { return IEC104SCQ(f.Qualifier) }

// LSQ returns the qualifier of an F_LS_NA_1 object.
func (f *IEC104File) LSQ() IEC104LSQ { return IEC104LSQ(f.Qualifier) }

// AFQ returns the qualifier of an F_AF_NA_1 object.
func (f *IEC104File) AFQ() IEC104AFQ { return IEC104AFQ(f.Qualifier) }

// SOF returns the status of an F_DR_TA_1 object.
func (f *IEC104File) SOF() IEC104SOF { return IEC104SOF(f.Qualifier) }
