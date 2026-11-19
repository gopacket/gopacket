// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// ADS names and sum-up commands (Beckhoff ADS specification and ADS
// return code list).
//
// A sum-up command is a read write request whose index group selects the
// kind and whose index offset counts the accesses N:
//
//	group   request data                      response data
//	0xF080  N x (Group, Offset, Length)       N x Result | data
//	0xF081  N x (Group, Offset, Length)       N x Result
//	        | write data
//	0xF082  N x (Group, Offset, ReadLength,   N x (Result, Length) | data
//	        WriteLength) | write data
//	0xF083  N x (Group, Offset, Length)       N x (Result, Length) | data
//	0xF084  N x (Group, Offset, Length)       N x (Result, Length) | data
//
// The data of 0xF080 and 0xF083 is laid out by the requested lengths,
// that of 0xF082 and 0xF084 by the returned ones. A response names
// neither N nor its group, so it only decodes next to its request:
// see EtherCATADS.SumUpResults.

package layers

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	ethercatADSSumReadLen = 12 // group, offset, length
	ethercatADSSumRWLen   = 16 // group, offset, read length, write length
	ethercatADSSumResLen  = 4  // result
	ethercatADSSumExLen   = 8  // result, length
	ethercatADSTimeUnit   = 100 * time.Nanosecond
)

// EtherCATADSGroup is an ADS index group.
type EtherCATADSGroup uint32

// Index groups of the ADS system services and the PLC.
const (
	EtherCATADSGroupPLCMemory     EtherCATADSGroup = 0x4020
	EtherCATADSGroupPLCMemoryBit  EtherCATADSGroup = 0x4021
	EtherCATADSGroupPLCData       EtherCATADSGroup = 0x4040
	EtherCATADSGroupSymbolTable   EtherCATADSGroup = 0xF000
	EtherCATADSGroupSymbolName    EtherCATADSGroup = 0xF001
	EtherCATADSGroupSymbolValue   EtherCATADSGroup = 0xF002
	EtherCATADSGroupHandleByName  EtherCATADSGroup = 0xF003
	EtherCATADSGroupValueByName   EtherCATADSGroup = 0xF004
	EtherCATADSGroupValueByHandle EtherCATADSGroup = 0xF005
	EtherCATADSGroupReleaseHandle EtherCATADSGroup = 0xF006
	EtherCATADSGroupInfoByName    EtherCATADSGroup = 0xF007
	EtherCATADSGroupSymbolVersion EtherCATADSGroup = 0xF008
	EtherCATADSGroupInfoByNameEx  EtherCATADSGroup = 0xF009
	EtherCATADSGroupSymbolUpload  EtherCATADSGroup = 0xF00B
	EtherCATADSGroupUploadInfo    EtherCATADSGroup = 0xF00C
	EtherCATADSGroupInputBytes    EtherCATADSGroup = 0xF020
	EtherCATADSGroupInputBits     EtherCATADSGroup = 0xF021
	EtherCATADSGroupOutputBytes   EtherCATADSGroup = 0xF030
	EtherCATADSGroupOutputBits    EtherCATADSGroup = 0xF031
	EtherCATADSGroupSumUpRead     EtherCATADSGroup = 0xF080
	EtherCATADSGroupSumUpWrite    EtherCATADSGroup = 0xF081
	EtherCATADSGroupSumUpRW       EtherCATADSGroup = 0xF082
	EtherCATADSGroupSumUpReadEx   EtherCATADSGroup = 0xF083
	EtherCATADSGroupSumUpReadEx2  EtherCATADSGroup = 0xF084
	EtherCATADSGroupSumUpAddNote  EtherCATADSGroup = 0xF085
	EtherCATADSGroupSumUpDelNote  EtherCATADSGroup = 0xF086
	EtherCATADSGroupDeviceData    EtherCATADSGroup = 0xF100
)

// String returns the index group name.
func (g EtherCATADSGroup) String() string {
	switch g {
	case EtherCATADSGroupPLCMemory:
		return "PLC memory"
	case EtherCATADSGroupPLCMemoryBit:
		return "PLC memory bit"
	case EtherCATADSGroupPLCData:
		return "PLC data"
	case EtherCATADSGroupSymbolTable:
		return "Symbol table"
	case EtherCATADSGroupSymbolName:
		return "Symbol name"
	case EtherCATADSGroupSymbolValue:
		return "Symbol value"
	case EtherCATADSGroupHandleByName:
		return "Handle by name"
	case EtherCATADSGroupValueByName:
		return "Value by name"
	case EtherCATADSGroupValueByHandle:
		return "Value by handle"
	case EtherCATADSGroupReleaseHandle:
		return "Release handle"
	case EtherCATADSGroupInfoByName:
		return "Info by name"
	case EtherCATADSGroupSymbolVersion:
		return "Symbol version"
	case EtherCATADSGroupInfoByNameEx:
		return "Info by name ex"
	case EtherCATADSGroupSymbolUpload:
		return "Symbol upload"
	case EtherCATADSGroupUploadInfo:
		return "Symbol upload info"
	case EtherCATADSGroupInputBytes:
		return "Input image bytes"
	case EtherCATADSGroupInputBits:
		return "Input image bits"
	case EtherCATADSGroupOutputBytes:
		return "Output image bytes"
	case EtherCATADSGroupOutputBits:
		return "Output image bits"
	case EtherCATADSGroupSumUpRead:
		return "Sum-up read"
	case EtherCATADSGroupSumUpWrite:
		return "Sum-up write"
	case EtherCATADSGroupSumUpRW:
		return "Sum-up read write"
	case EtherCATADSGroupSumUpReadEx:
		return "Sum-up read ex"
	case EtherCATADSGroupSumUpReadEx2:
		return "Sum-up read ex 2"
	case EtherCATADSGroupSumUpAddNote:
		return "Sum-up add notification"
	case EtherCATADSGroupSumUpDelNote:
		return "Sum-up delete notification"
	case EtherCATADSGroupDeviceData:
		return "Device data"
	}
	return fmt.Sprintf("0x%x", uint32(g))
}

// IsSumUp reports whether a read write on the group is a sum-up command
// this package decodes (0xF080 to 0xF084).
func (g EtherCATADSGroup) IsSumUp() bool {
	return g >= EtherCATADSGroupSumUpRead && g <= EtherCATADSGroupSumUpReadEx2
}

// EtherCATADSSumItem is one access of a sum-up request. Length is the
// read length, WriteLength and Data the write side; a kind that only
// reads or only writes leaves the other at zero. Data is nil when the
// request is cut before it.
type EtherCATADSSumItem struct {
	IndexGroup  EtherCATADSGroup
	IndexOffset uint32
	Length      uint32
	WriteLength uint32
	Data        []byte
}

// EtherCATADSSumResult is the answer to one access of a sum-up request.
// Length is the returned length, 0 where the response has none. Data is
// nil when the response is cut before it.
type EtherCATADSSumResult struct {
	Result EtherCATADSError
	Length uint32
	Data   []byte
}

// ethercatADSTake cuts the first n bytes off b. It returns nil and what
// is left when b is shorter; n is not trusted.
func ethercatADSTake(b []byte, n uint32) (head, rest []byte) {
	if uint64(n) > uint64(len(b)) {
		return nil, nil
	}
	return b[:n:n], b[n:]
}

// decodeEtherCATADSSumUp reads the access list of a sum-up request. The
// announced count is not trusted: the list is sized by the entries the
// data holds.
func decodeEtherCATADSSumUp(group EtherCATADSGroup, announced uint32, data []byte) []EtherCATADSSumItem {
	if !group.IsSumUp() {
		return nil
	}

	entry := ethercatADSSumReadLen
	if group == EtherCATADSGroupSumUpRW {
		entry = ethercatADSSumRWLen
	}

	n := len(data) / entry
	if uint64(n) > uint64(announced) {
		n = int(announced)
	}
	if n == 0 {
		return nil
	}

	items := make([]EtherCATADSSumItem, n)
	tail := data[n*entry:]

	for i := range items {
		e := data[i*entry:]
		it := &items[i]
		it.IndexGroup = EtherCATADSGroup(binary.LittleEndian.Uint32(e))
		it.IndexOffset = binary.LittleEndian.Uint32(e[4:])
		length := binary.LittleEndian.Uint32(e[8:])

		switch group {
		case EtherCATADSGroupSumUpWrite:
			it.WriteLength = length
		case EtherCATADSGroupSumUpRW:
			it.Length = length
			it.WriteLength = binary.LittleEndian.Uint32(e[12:])
		default:
			it.Length = length
			continue
		}

		// Write data follows the list, in list order.
		it.Data, tail = ethercatADSTake(tail, it.WriteLength)
	}
	return items
}

// SumUpResults decodes the data of a read write response as the answer
// to the sum-up request req, one result per access of the request. It
// returns nil when req is no sum-up request or the response is shorter
// than its result list. Pair the two by the AMS invoke ID.
func (a *EtherCATADS) SumUpResults(req *EtherCATADS) []EtherCATADSSumResult {
	if a == nil || req == nil || len(req.SumUp) == 0 {
		return nil
	}

	group := req.IndexGroup
	entry := ethercatADSSumExLen
	if group == EtherCATADSGroupSumUpRead || group == EtherCATADSGroupSumUpWrite {
		entry = ethercatADSSumResLen
	}

	// The request list was sized by its own packet; the response must
	// hold a result for each access too.
	n := len(req.SumUp)
	if len(a.Data)/entry < n {
		return nil
	}

	out := make([]EtherCATADSSumResult, n)
	tail := a.Data[n*entry:]

	for i := range out {
		e := a.Data[i*entry:]
		r := &out[i]
		r.Result = EtherCATADSError(binary.LittleEndian.Uint32(e))
		if entry == ethercatADSSumExLen {
			r.Length = binary.LittleEndian.Uint32(e[4:])
		}

		// Data is laid out by the requested or the returned length.
		size := r.Length
		switch group {
		case EtherCATADSGroupSumUpWrite:
			continue
		case EtherCATADSGroupSumUpRead, EtherCATADSGroupSumUpReadEx:
			size = req.SumUp[i].Length
		}
		r.Data, tail = ethercatADSTake(tail, size)
	}
	return out
}

// EtherCATADSTransMode is the transmission mode of a notification.
type EtherCATADSTransMode uint32

// ADS transmission modes.
const (
	EtherCATADSTransNone            EtherCATADSTransMode = 0
	EtherCATADSTransClientCycle     EtherCATADSTransMode = 1
	EtherCATADSTransClientOnChange  EtherCATADSTransMode = 2
	EtherCATADSTransServerCycle     EtherCATADSTransMode = 3
	EtherCATADSTransServerOnChange  EtherCATADSTransMode = 4
	EtherCATADSTransServerCycle2    EtherCATADSTransMode = 5
	EtherCATADSTransServerOnChange2 EtherCATADSTransMode = 6
	EtherCATADSTransClientFirstReq  EtherCATADSTransMode = 10
)

// String returns the transmission mode name.
func (m EtherCATADSTransMode) String() string {
	switch m {
	case EtherCATADSTransNone:
		return "No transmission"
	case EtherCATADSTransClientCycle:
		return "Client cycle"
	case EtherCATADSTransClientOnChange:
		return "Client on change"
	case EtherCATADSTransServerCycle:
		return "Server cycle"
	case EtherCATADSTransServerOnChange:
		return "Server on change"
	case EtherCATADSTransServerCycle2:
		return "Server cycle 2"
	case EtherCATADSTransServerOnChange2:
		return "Server on change 2"
	case EtherCATADSTransClientFirstReq:
		return "Client first request"
	}
	return fmt.Sprintf("Unknown(%d)", uint32(m))
}

// MaxDelayTime returns the longest time an add notification request
// lets the server hold a notification back.
func (a *EtherCATADS) MaxDelayTime() time.Duration {
	return time.Duration(a.MaxDelay) * ethercatADSTimeUnit
}

// CycleDuration returns the interval at which an add notification
// request has the server check the variable.
func (a *EtherCATADS) CycleDuration() time.Duration {
	return time.Duration(a.CycleTime) * ethercatADSTimeUnit
}

// EtherCATADSState is the ADS state of a device.
type EtherCATADSState uint16

// ADS states.
const (
	EtherCATADSStateInvalid      EtherCATADSState = 0
	EtherCATADSStateIdle         EtherCATADSState = 1
	EtherCATADSStateReset        EtherCATADSState = 2
	EtherCATADSStateInit         EtherCATADSState = 3
	EtherCATADSStateStart        EtherCATADSState = 4
	EtherCATADSStateRun          EtherCATADSState = 5
	EtherCATADSStateStop         EtherCATADSState = 6
	EtherCATADSStateSaveConfig   EtherCATADSState = 7
	EtherCATADSStateLoadConfig   EtherCATADSState = 8
	EtherCATADSStatePowerFailure EtherCATADSState = 9
	EtherCATADSStatePowerGood    EtherCATADSState = 10
	EtherCATADSStateError        EtherCATADSState = 11
	EtherCATADSStateShutdown     EtherCATADSState = 12
	EtherCATADSStateSuspend      EtherCATADSState = 13
	EtherCATADSStateResume       EtherCATADSState = 14
	EtherCATADSStateConfig       EtherCATADSState = 15
	EtherCATADSStateReconfig     EtherCATADSState = 16
)

// ethercatADSStateNames is indexed by state.
var ethercatADSStateNames = [...]string{
	"Invalid", "Idle", "Reset", "Init", "Start", "Run", "Stop",
	"Save config", "Load config", "Power failure", "Power good", "Error",
	"Shutdown", "Suspend", "Resume", "Config", "Reconfig",
}

// String returns the state name.
func (s EtherCATADSState) String() string {
	if int(s) < len(ethercatADSStateNames) {
		return ethercatADSStateNames[s]
	}
	return fmt.Sprintf("Unknown(%d)", uint16(s))
}

// EtherCATAMSPort is an AMS port: the service addressed on a device.
type EtherCATAMSPort uint16

// Well-known AMS ports.
const (
	EtherCATAMSPortRouter      EtherCATAMSPort = 1
	EtherCATAMSPortDebugger    EtherCATAMSPort = 2
	EtherCATAMSPortLogger      EtherCATAMSPort = 100
	EtherCATAMSPortEventLogger EtherCATAMSPort = 110
	EtherCATAMSPortRealtime    EtherCATAMSPort = 200
	EtherCATAMSPortTrace       EtherCATAMSPort = 290
	EtherCATAMSPortIO          EtherCATAMSPort = 300
	EtherCATAMSPortNC          EtherCATAMSPort = 500
	EtherCATAMSPortNCSAF       EtherCATAMSPort = 501
	EtherCATAMSPortNCSVB       EtherCATAMSPort = 511
	EtherCATAMSPortISG         EtherCATAMSPort = 600
	EtherCATAMSPortCNC         EtherCATAMSPort = 700
	EtherCATAMSPortPLC         EtherCATAMSPort = 800
	EtherCATAMSPortPLCRuntime1 EtherCATAMSPort = 801
	EtherCATAMSPortPLCRuntime2 EtherCATAMSPort = 811
	EtherCATAMSPortPLCRuntime3 EtherCATAMSPort = 821
	EtherCATAMSPortPLCRuntime4 EtherCATAMSPort = 831
	EtherCATAMSPortTC3PLC1     EtherCATAMSPort = 851
	EtherCATAMSPortTC3PLC2     EtherCATAMSPort = 852
	EtherCATAMSPortTC3PLC3     EtherCATAMSPort = 853
	EtherCATAMSPortTC3PLC4     EtherCATAMSPort = 854
	EtherCATAMSPortCamshaft    EtherCATAMSPort = 900
	EtherCATAMSPortSystem      EtherCATAMSPort = 10000
	EtherCATAMSPortScope       EtherCATAMSPort = 14000
)

// String returns "number(name)" for a well-known port, else the number.
func (p EtherCATAMSPort) String() string {
	name := ""
	switch p {
	case EtherCATAMSPortRouter:
		name = "Router"
	case EtherCATAMSPortDebugger:
		name = "Debugger"
	case EtherCATAMSPortLogger:
		name = "Logger"
	case EtherCATAMSPortEventLogger:
		name = "Event logger"
	case EtherCATAMSPortRealtime:
		name = "Realtime"
	case EtherCATAMSPortTrace:
		name = "Trace"
	case EtherCATAMSPortIO:
		name = "I/O"
	case EtherCATAMSPortNC:
		name = "NC"
	case EtherCATAMSPortNCSAF:
		name = "NC SAF"
	case EtherCATAMSPortNCSVB:
		name = "NC SVB"
	case EtherCATAMSPortISG:
		name = "ISG"
	case EtherCATAMSPortCNC:
		name = "CNC"
	case EtherCATAMSPortPLC:
		name = "PLC"
	case EtherCATAMSPortPLCRuntime1:
		name = "PLC runtime 1"
	case EtherCATAMSPortPLCRuntime2:
		name = "PLC runtime 2"
	case EtherCATAMSPortPLCRuntime3:
		name = "PLC runtime 3"
	case EtherCATAMSPortPLCRuntime4:
		name = "PLC runtime 4"
	case EtherCATAMSPortTC3PLC1:
		name = "TwinCAT 3 PLC 1"
	case EtherCATAMSPortTC3PLC2:
		name = "TwinCAT 3 PLC 2"
	case EtherCATAMSPortTC3PLC3:
		name = "TwinCAT 3 PLC 3"
	case EtherCATAMSPortTC3PLC4:
		name = "TwinCAT 3 PLC 4"
	case EtherCATAMSPortCamshaft:
		name = "Camshaft controller"
	case EtherCATAMSPortSystem:
		name = "System service"
	case EtherCATAMSPortScope:
		name = "Scope"
	default:
		return fmt.Sprintf("%d", uint16(p))
	}
	return fmt.Sprintf("%d(%s)", uint16(p), name)
}

// EtherCATADSError is an ADS return code: the error code of the AMS
// header and the result of an ADS response.
type EtherCATADSError uint32

// The first code of each ADS return code range.
const (
	EtherCATADSNoError   EtherCATADSError = 0x000
	EtherCATADSErrRouter EtherCATADSError = 0x500
	EtherCATADSErrDevice EtherCATADSError = 0x700
	EtherCATADSErrClient EtherCATADSError = 0x740
)

// ethercatADSGlobalErrs names the global codes, 0x00 and up.
var ethercatADSGlobalErrs = [...]string{
	"No error",
	"Internal error",
	"No real time",
	"Allocation locked, memory error",
	"Mailbox full",
	"Wrong HMSG",
	"Target port not found",
	"Target machine not found",
	"Unknown command ID",
	"Invalid task ID",
	"No IO",
	"Unknown AMS command",
	"Win32 error",
	"Port not connected",
	"Invalid AMS length",
	"Invalid AMS net ID",
	"Installation level too low",
	"No debugging available",
	"Port disabled",
	"Port already connected",
	"AMS sync Win32 error",
	"AMS sync timeout",
	"AMS sync error",
	"No index map for AMS sync",
	"Invalid AMS port",
	"No memory",
	"TCP send error",
	"Host unreachable",
	"Invalid AMS fragment",
	"TLS send error",
	"Access denied",
}

// ethercatADSRouterErrs names the router codes, 0x500 and up.
var ethercatADSRouterErrs = [...]string{
	"Locked memory cannot be allocated",
	"Router memory size could not be changed",
	"Mailbox full",
	"Debug mailbox full",
	"Unknown port type",
	"Router not initialized",
	"Port number already assigned",
	"Port not registered",
	"Maximum number of ports reached",
	"Invalid port",
	"Router not active",
	"Mailbox full for fragmented messages",
	"Fragment timeout",
	"Port removed",
}

// ethercatADSDeviceErrs names the device codes, 0x700 and up.
var ethercatADSDeviceErrs = [...]string{
	"General device error",
	"Service not supported",
	"Invalid index group",
	"Invalid index offset",
	"Reading or writing not permitted",
	"Parameter size not correct",
	"Invalid data values",
	"Device not ready",
	"Device busy",
	"Invalid operating system context",
	"Insufficient memory",
	"Invalid parameter values",
	"Not found",
	"Syntax error",
	"Objects do not match",
	"Object already exists",
	"Symbol not found",
	"Invalid symbol version",
	"Device in invalid state",
	"Transmission mode not supported",
	"Invalid notification handle",
	"Notification client not registered",
	"No further handle available",
	"Notification size too large",
	"Device not initialized",
	"Device timeout",
	"Interface query failed",
	"Wrong interface requested",
	"Invalid class ID",
	"Invalid object ID",
	"Request pending",
	"Request aborted",
	"Signal warning",
	"Invalid array index",
	"Symbol not active",
	"Access denied",
	"Missing license",
	"License expired",
	"License exceeded",
	"Invalid license",
	"Invalid system ID in license",
	"License not limited in time",
	"License issue time in the future",
	"License period too long",
	"Exception at system start",
	"License file read twice",
	"Invalid signature",
	"Invalid certificate",
	"Public key not known from OEM",
	"License not valid for this system ID",
	"Demo license prohibited",
	"Invalid function ID",
	"Outside the valid range",
	"Invalid alignment",
	"Invalid platform level",
	"Context: forward to passive level",
	"Context: forward to dispatch level",
	"Context: forward to real time",
}

// ethercatADSClientErrs names the client codes, 0x740 and up; the gap
// before 0x750 has no codes.
var ethercatADSClientErrs = [...]string{
	"Client error",
	"Invalid service parameter",
	"Polling list is empty",
	"Var connection already in use",
	"Invoke ID already in use",
	"Timeout",
	"Error in Win32 subsystem",
	"Invalid client timeout value",
	"Port not opened",
	"No AMS address",
	"", "", "", "", "", "",
	"Internal error in ADS sync",
	"Hash table overflow",
	"Key not found in the table",
	"No symbols in the cache",
	"Invalid response received",
	"Sync port is locked",
}

// String returns the return code name.
func (e EtherCATADSError) String() string {
	ranges := [...]struct {
		base  EtherCATADSError
		names []string
	}{
		{EtherCATADSErrClient, ethercatADSClientErrs[:]},
		{EtherCATADSErrDevice, ethercatADSDeviceErrs[:]},
		{EtherCATADSErrRouter, ethercatADSRouterErrs[:]},
		{EtherCATADSNoError, ethercatADSGlobalErrs[:]},
	}

	// The ranges are tried from the highest base down, so a code lands
	// in the range it belongs to.
	for _, r := range ranges {
		if e < r.base {
			continue
		}

		if off := uint32(e - r.base); off < uint32(len(r.names)) && r.names[off] != "" {
			return r.names[off]
		}
		break
	}
	return fmt.Sprintf("Unknown(0x%x)", uint32(e))
}
