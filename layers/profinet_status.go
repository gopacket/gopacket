// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Names for ErrorCode1 and ErrorCode2 of a PNIO status (IEC 61158-6-10,
// "Coding of the field PNIOStatus"). ErrorDecode selects the table:
//
//	PNIORW  ErrorCode1 = ErrorClass (high nibble) + ErrorCode (low nibble),
//	        ErrorCode2 user specific
//	PNIO    ErrorCode1 = the block or the state machine that failed,
//	        ErrorCode2 = the field of the block or the reason

package layers

import "fmt"

// ErrorCode1 values of ErrorDecode PNIO that the ErrorCode2 tables key on.
const (
	profinetErr1BlockFirst  = 1  // faulty connect, control and release blocks
	profinetErr1BlockLast   = 57 // ARSXPBlockRes
	profinetErr1CMRPC       = 64
	profinetErr1RTAProtocol = 253

	profinetErrClassShift = 4
)

// profinetErr1PNIORW names ErrorCode1 of ErrorDecode PNIORW.
var profinetErr1PNIORW = map[uint8]string{
	0xA0: "Application: read error",
	0xA1: "Application: write error",
	0xA2: "Application: module failure",
	0xA7: "Application: busy",
	0xA8: "Application: version conflict",
	0xA9: "Application: feature not supported",
	0xB0: "Access: invalid index",
	0xB1: "Access: write length error",
	0xB2: "Access: invalid slot or subslot",
	0xB3: "Access: type conflict",
	0xB4: "Access: invalid area or API",
	0xB5: "Access: state conflict",
	0xB6: "Access: access denied",
	0xB7: "Access: invalid range",
	0xB8: "Access: invalid parameter",
	0xB9: "Access: invalid type",
	0xBA: "Access: backup",
	0xBF: "Access: unauthorized access denied",
	0xC0: "Resource: read constrain conflict",
	0xC1: "Resource: write constrain conflict",
	0xC2: "Resource: resource busy",
	0xC3: "Resource: resource unavailable",
}

// profinetErrClass is an error class of PNIORW: its name and the first
// low nibble of ErrorCode1 that is left to the user. The codes between the
// named ones and that nibble are not specified.
type profinetErrClass struct {
	name      string
	userFirst uint8
}

var profinetErrClasses = map[uint8]profinetErrClass{
	0xA: {"Application", 0xA},
	0xB: {"Access", 0xB},
	0xC: {"Resource", 0x8},
}

// profinetErr1PNIO names ErrorCode1 of ErrorDecode PNIO.
var profinetErr1PNIO = map[uint8]string{
	1:   "Connect: faulty ARBlockReq",
	2:   "Connect: faulty IOCRBlockReq",
	3:   "Connect: faulty ExpectedSubmoduleBlockReq",
	4:   "Connect: faulty AlarmCRBlockReq",
	5:   "Connect: faulty PrmServerBlockReq",
	6:   "Connect: faulty MCRBlockReq",
	7:   "Connect: faulty ARRPCBlockReq",
	8:   "Read or write: faulty record",
	9:   "Connect: faulty IRInfoBlock",
	10:  "Connect: faulty SRInfoBlock",
	11:  "Connect: faulty ARFSUBlock",
	12:  "Connect: faulty ARVendorBlockReq",
	13:  "Connect: faulty RSInfoBlock",
	14:  "Connect: faulty ARSXPBlockReq",
	20:  "Control: faulty block of PrmEnd after connect",
	21:  "Control: faulty block of PrmEnd after plug",
	22:  "Control: faulty block of ApplicationReady after connect",
	23:  "Control: faulty block of ApplicationReady after plug",
	24:  "Control: faulty block of PrmBegin",
	25:  "Control: faulty SubmoduleListBlock",
	40:  "Release: faulty block",
	50:  "Connect: faulty ARBlockRes",
	51:  "Connect: faulty IOCRBlockRes",
	52:  "Connect: faulty AlarmCRBlockRes",
	53:  "Connect: faulty ModuleDiffBlock",
	54:  "Connect: faulty ARRPCBlockRes",
	55:  "Connect: faulty ARServerBlockRes",
	56:  "Connect: faulty ARVendorBlockRes",
	57:  "Connect: faulty ARSXPBlockRes",
	60:  "AlarmAck error",
	61:  "CMDEV",
	62:  "CMCTL",
	63:  "CTLDINA",
	64:  "CMRPC",
	65:  "ALPMI",
	66:  "ALPMR",
	67:  "LMPM",
	68:  "MAC",
	69:  "RPC",
	70:  "APMR",
	71:  "APMS",
	72:  "CPM",
	73:  "PPM",
	74:  "DCPUCS",
	75:  "DCPUCR",
	76:  "DCPMCS",
	77:  "DCPMCR",
	78:  "FSPM",
	100: "CTLSM",
	101: "CTLRDI",
	102: "CTLRDR",
	103: "CTLWRI",
	104: "CTLWRR",
	105: "CTLIO",
	106: "CTLSU",
	107: "CTLRPC",
	108: "CTLPBE",
	109: "CTLSRL",
	200: "CMSM",
	202: "CMRDR",
	204: "CMWRR",
	205: "CMIO",
	206: "CMSU",
	208: "CMINA",
	209: "CMPBE",
	210: "CMSRL",
	211: "CMDMC",
	224: "SXP protocol error",
	225: "RTAv3 protocol error",
	253: "RTA protocol error",
	255: "User specific",
}

// profinetErr2Block names ErrorCode2 for a faulty block: the header field
// at fault. Higher values count the fields of the block body.
var profinetErr2Block = [...]string{"BlockType", "BlockLength", "BlockVersionHigh", "BlockVersionLow"}

// profinetErr2CMRPC names ErrorCode2 of ErrorCode1 CMRPC.
var profinetErr2CMRPC = [...]string{
	0:  "ArgsLength invalid",
	1:  "Unknown blocks",
	2:  "IOCR missing",
	3:  "Wrong AlarmCRBlock count",
	4:  "Out of AR resources",
	5:  "AR UUID unknown",
	6:  "State conflict",
	7:  "Out of provider, consumer or alarm resources",
	8:  "Out of memory",
	9:  "PDev already owned",
	10: "ARset state conflict during connection establishment",
	11: "ARset parameter conflict during connection establishment",
	12: "PDev, port(s) without interface",
	13: "Discrepancy between PDev and ARType",
	14: "PDev, discrepancy between PDev ownership and ARProperties",
}

// profinetErr2RTA names ErrorCode2 of ErrorCode1 RTA protocol error: why
// an AR was aborted.
var profinetErr2RTA = [...]string{
	1:  "Sequence number error",
	2:  "Instance closed",
	3:  "AR out of memory",
	4:  "AR add provider or consumer failed",
	5:  "AR consumer DHT or WDT expired",
	6:  "AR CMI timeout",
	7:  "AR alarm open failed",
	8:  "AR alarm send confirmation negative",
	9:  "AR alarm ack send confirmation negative",
	10: "AR alarm data too long",
	11: "AR alarm indication error",
	12: "AR RPC client call confirmation negative",
	13: "AR abort request",
	14: "AR re-run aborts existing AR",
	15: "AR release indication received",
	16: "AR device deactivated",
	17: "AR removed",
	18: "AR protocol violation",
	19: "AR name resolution error",
	20: "AR RPC bind error",
	21: "AR RPC connect error",
	22: "AR RPC read error",
	23: "AR RPC write error",
	24: "AR RPC control error",
	25: "AR forbidden pull or plug after check response and before in-data indication",
	26: "AR AP removed",
	27: "AR link down",
	28: "AR could not register multicast MAC address",
	29: "Not synchronized (cannot start companion AR)",
	30: "Wrong topology (cannot start companion AR)",
	31: "AR DCP station name changed",
	32: "AR DCP reset to factory",
	33: "Cannot start companion AR because of a 0x8ipp submodule in the first AR",
	34: "AR no IRData record yet",
	35: "AR PDev",
	36: "AR PDev, no port offers required speed or duplex",
	37: "AR IP suite changed",
	38: "IOCARSR RDHT expired",
	39: "IOCARSR PDev parameterization impossible",
	40: "Remote application ready timeout expired",
	41: "IOCARSR redundant interface lost or access to the peripherals impossible",
	42: "IOCARSR MTOT expired",
	43: "IOCARSR AR protocol violation",
	44: "PDev, plug port without CombinedObjectContainer",
	45: "NME, no or wrong configuration",
}

// Code1Name names ErrorCode1 for the ErrorDecode of the status. It returns
// "" for a status that is OK and for codes the standard leaves open.
func (s ProfinetPNIOStatus) Code1Name() string {
	switch s.ErrorDecode {
	case ProfinetErrorDecodePNIORW:
		if name, ok := profinetErr1PNIORW[s.ErrorCode1]; ok {
			return name
		}
		class, ok := profinetErrClasses[s.ErrorCode1>>profinetErrClassShift]
		if ok && s.ErrorCode1&profinetNibbleMask >= class.userFirst {
			return class.name + ": user specific"
		}
	case ProfinetErrorDecodePNIO:
		return profinetErr1PNIO[s.ErrorCode1]
	}
	return ""
}

// Code2Name names ErrorCode2 where the standard gives it a meaning: the
// faulty field of a block, the CMRPC reason and the reason an AR was
// aborted. It returns "" otherwise.
func (s ProfinetPNIOStatus) Code2Name() string {
	if s.ErrorDecode != ProfinetErrorDecodePNIO {
		return ""
	}

	code := int(s.ErrorCode2)
	switch {
	case s.ErrorCode1 == profinetErr1CMRPC:
		if code < len(profinetErr2CMRPC) {
			return profinetErr2CMRPC[code]
		}
	case s.ErrorCode1 == profinetErr1RTAProtocol:
		if code < len(profinetErr2RTA) {
			return profinetErr2RTA[code]
		}
	case s.ErrorCode1 >= profinetErr1BlockFirst && s.ErrorCode1 <= profinetErr1BlockLast:
		if _, ok := profinetErr1PNIO[s.ErrorCode1]; !ok {
			return ""
		}
		if code < len(profinetErr2Block) {
			return profinetErr2Block[code]
		}
		return fmt.Sprintf("Field %d of the block", code-len(profinetErr2Block)+1)
	}
	return ""
}
