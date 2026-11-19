// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Beckhoff AMS/ADS as carried by EtherCAT: in AoE mailboxes and in type 2
// EtherCAT frames (Beckhoff ADS specification, Wireshark packet-ams.c).
// Fields are little endian.
//
//	AMS header (32 bytes):
//	+-----------+------+-----------+------+-----+-------+-----+-------+--------+
//	| TargetNet | Port | SourceNet | Port | Cmd | Flags | Len | Error | Invoke |
//	| 6         | 2    | 6         | 2    | 2   | 2     | 4   | 4     | 4      |
//	+-----------+------+-----------+------+-----+-------+-----+-------+--------+
//
// When the ADS flag is set the body is an ADS request or response, chosen
// by the command and the response flag:
//
//	command        request                              response
//	device info    -                                    Result, version, name
//	read           Group, Offset, Length                Result, Length, data
//	write          Group, Offset, Length, data          Result
//	read state     -                                    Result, ADS and device state
//	write control  ADS state, device state, Length,     Result
//	               data
//	add notif.     Group, Offset, Length, mode,         Result, handle
//	               max delay, cycle time
//	del notif.     handle                               Result
//	notification   Length, stamp count, stamps          -
//	read write     Group, Offset, read Length,          Result, Length, data
//	               write Length, data
//
// A read write request on index groups 0xF080 to 0xF084 is a sum-up
// command: several accesses in one, see ethercat_ads.go.
//
// AMS over TCP (port 48898) wraps the same packet in a 6-byte header,
// see ethercat_ams_tcp.go. AMS over UDP (port 48899, route discovery)
// is a different protocol and is not handled.

package layers

import (
	"encoding/binary"
	"fmt"
)

const (
	ethercatAMSHeaderLen  = 32
	ethercatAMSNetIDLen   = 6
	ethercatADSResultLen  = 4
	ethercatADSReadLen    = 12 // group, offset, length
	ethercatADSRWLen      = 16 // group, offset, read length, write length
	ethercatADSReadResLen = 8  // result, length
	ethercatADSStateLen   = 8  // result, ADS state, device state
	ethercatADSCtrlLen    = 8  // ADS state, device state, length
	ethercatADSInfoLen    = 8  // result, version, revision, build
	ethercatADSAddLen     = 24 // group, offset, length, mode, max delay, cycle time
	ethercatADSHandleLen  = 4
	ethercatADSAddResLen  = 8  // result, handle
	ethercatADSNoteLen    = 8  // length, stamp count
	ethercatADSStampLen   = 12 // timestamp, sample count
	ethercatADSSampleLen  = 8  // handle, size
)

// EtherCATAMSNetID is a 6-byte AMS network identifier.
type EtherCATAMSNetID [ethercatAMSNetIDLen]byte

// String returns the dotted form, e.g. "192.168.1.10.1.1".
func (n EtherCATAMSNetID) String() string {
	return fmt.Sprintf("%d.%d.%d.%d.%d.%d", n[0], n[1], n[2], n[3], n[4], n[5])
}

// EtherCATADSCommand is the AMS command identifier.
type EtherCATADSCommand uint16

// ADS commands.
const (
	EtherCATADSInvalid            EtherCATADSCommand = 0
	EtherCATADSReadDeviceInfo     EtherCATADSCommand = 1
	EtherCATADSRead               EtherCATADSCommand = 2
	EtherCATADSWrite              EtherCATADSCommand = 3
	EtherCATADSReadState          EtherCATADSCommand = 4
	EtherCATADSWriteControl       EtherCATADSCommand = 5
	EtherCATADSAddNotification    EtherCATADSCommand = 6
	EtherCATADSDeleteNotification EtherCATADSCommand = 7
	EtherCATADSNotification       EtherCATADSCommand = 8
	EtherCATADSReadWrite          EtherCATADSCommand = 9
)

// String returns the command name.
func (c EtherCATADSCommand) String() string {
	switch c {
	case EtherCATADSInvalid:
		return "Invalid"
	case EtherCATADSReadDeviceInfo:
		return "ADS Read Device Info"
	case EtherCATADSRead:
		return "ADS Read"
	case EtherCATADSWrite:
		return "ADS Write"
	case EtherCATADSReadState:
		return "ADS Read State"
	case EtherCATADSWriteControl:
		return "ADS Write Control"
	case EtherCATADSAddNotification:
		return "ADS Add Device Notification"
	case EtherCATADSDeleteNotification:
		return "ADS Delete Device Notification"
	case EtherCATADSNotification:
		return "ADS Device Notification"
	case EtherCATADSReadWrite:
		return "ADS Read Write"
	}
	return fmt.Sprintf("Unknown(%d)", uint16(c))
}

// EtherCATAMSFlags is the AMS state flag word.
type EtherCATAMSFlags uint16

// AMS state flags.
const (
	EtherCATAMSResponse       EtherCATAMSFlags = 0x0001
	EtherCATAMSNoReturn       EtherCATAMSFlags = 0x0002
	EtherCATAMSADSCommand     EtherCATAMSFlags = 0x0004
	EtherCATAMSSystemCommand  EtherCATAMSFlags = 0x0008
	EtherCATAMSHighPriority   EtherCATAMSFlags = 0x0010
	EtherCATAMSTimestampAdded EtherCATAMSFlags = 0x0020
	EtherCATAMSUDP            EtherCATAMSFlags = 0x0040
	EtherCATAMSInitCommand    EtherCATAMSFlags = 0x0080
	EtherCATAMSBroadcast      EtherCATAMSFlags = 0x8000
)

// Has reports whether the flag is set.
func (f EtherCATAMSFlags) Has(flag EtherCATAMSFlags) bool { return f&flag != 0 }

// EtherCATADSSample is one value of a device notification.
type EtherCATADSSample struct {
	Handle uint32
	Data   []byte
}

// EtherCATADSStamp is one timestamped group of notification samples.
// Timestamp is a Windows FILETIME: 100 ns steps since 1601-01-01 UTC.
type EtherCATADSStamp struct {
	Timestamp uint64
	Samples   []EtherCATADSSample
}

// EtherCATADS is the body of an ADS request or response. The fields set
// depend on the command and direction, as listed in the file comment.
type EtherCATADS struct {
	Result      EtherCATADSError // responses
	IndexGroup  EtherCATADSGroup
	IndexOffset uint32
	// Length is the read or write length of the request, or the data
	// length of a read response.
	Length      uint32
	WriteLength uint32 // read write request
	ADSState    EtherCATADSState
	DeviceState uint16

	// Read device info response.
	MajorVersion uint8
	MinorVersion uint8
	Build        uint16
	DeviceName   []byte // without NUL padding

	// Notifications. MaxDelay and CycleTime count 100 ns steps; see
	// MaxDelayTime and CycleDuration.
	Handle           uint32
	TransmissionMode EtherCATADSTransMode
	MaxDelay         uint32
	CycleTime        uint32
	StampCount       uint32 // as announced; Stamps holds those present
	Stamps           []EtherCATADSStamp

	Data []byte // read, write and control data

	// SumUp lists the accesses of a sum-up request: a read write on
	// index groups 0xF080 to 0xF084. IndexOffset announces their number;
	// SumUp holds those present.
	SumUp []EtherCATADSSumItem
}

// EtherCATAMS is an AMS packet with its ADS body.
//
// Data holds the bytes after the header. ADS is set when the ADS flag is
// and the body is long enough for the command; system commands and bodies
// of unknown commands stay raw in Data.
type EtherCATAMS struct {
	TargetNetID EtherCATAMSNetID
	TargetPort  EtherCATAMSPort
	SourceNetID EtherCATAMSNetID
	SourcePort  EtherCATAMSPort
	Command     EtherCATADSCommand
	Flags       EtherCATAMSFlags
	Length      uint32
	ErrorCode   EtherCATADSError
	InvokeID    uint32
	Data        []byte
	ADS         *EtherCATADS
}

// IsResponse reports whether the packet answers a request.
func (a *EtherCATAMS) IsResponse() bool { return a.Flags.Has(EtherCATAMSResponse) }

// decodeEtherCATAMS decodes an AMS packet, nil when the header is cut.
func decodeEtherCATAMS(data []byte) *EtherCATAMS {
	if len(data) < ethercatAMSHeaderLen {
		return nil
	}

	a := &EtherCATAMS{
		TargetPort: EtherCATAMSPort(binary.LittleEndian.Uint16(data[6:8])),
		SourcePort: EtherCATAMSPort(binary.LittleEndian.Uint16(data[14:16])),
		Command:    EtherCATADSCommand(binary.LittleEndian.Uint16(data[16:18])),
		Flags:      EtherCATAMSFlags(binary.LittleEndian.Uint16(data[18:20])),
		Length:     binary.LittleEndian.Uint32(data[20:24]),
		ErrorCode:  EtherCATADSError(binary.LittleEndian.Uint32(data[24:28])),
		InvokeID:   binary.LittleEndian.Uint32(data[28:32]),
		Data:       data[ethercatAMSHeaderLen:],
	}
	copy(a.TargetNetID[:], data[0:6])
	copy(a.SourceNetID[:], data[8:14])

	if !a.Flags.Has(EtherCATAMSADSCommand) {
		return a
	}

	if a.IsResponse() {
		a.ADS = decodeEtherCATADSRes(a.Command, a.Data)
	} else {
		a.ADS = decodeEtherCATADSReq(a.Command, a.Data)
	}
	return a
}

// ethercatADSReqLen returns the fixed length of an ADS request body, 0
// for commands without request fields.
func ethercatADSReqLen(cmd EtherCATADSCommand) int {
	switch cmd {
	case EtherCATADSRead, EtherCATADSWrite:
		return ethercatADSReadLen
	case EtherCATADSReadWrite:
		return ethercatADSRWLen
	case EtherCATADSWriteControl:
		return ethercatADSCtrlLen
	case EtherCATADSAddNotification:
		return ethercatADSAddLen
	case EtherCATADSDeleteNotification:
		return ethercatADSHandleLen
	case EtherCATADSNotification:
		return ethercatADSNoteLen
	}
	return 0
}

// ethercatADSResLen returns the fixed length of an ADS response body, 0
// for commands without a response.
func ethercatADSResLen(cmd EtherCATADSCommand) int {
	switch cmd {
	case EtherCATADSReadDeviceInfo:
		return ethercatADSInfoLen
	case EtherCATADSRead, EtherCATADSReadWrite:
		return ethercatADSReadResLen
	case EtherCATADSReadState:
		return ethercatADSStateLen
	case EtherCATADSAddNotification:
		return ethercatADSAddResLen
	case EtherCATADSWrite, EtherCATADSWriteControl, EtherCATADSDeleteNotification:
		return ethercatADSResultLen
	}
	return 0
}

// decodeEtherCATADSReq decodes an ADS request body. It returns nil for a
// command without request fields or a body too short for them.
func decodeEtherCATADSReq(cmd EtherCATADSCommand, b []byte) *EtherCATADS {
	need := ethercatADSReqLen(cmd)
	if need == 0 || len(b) < need {
		return nil
	}

	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
	a := &EtherCATADS{}

	switch cmd {
	case EtherCATADSRead, EtherCATADSWrite, EtherCATADSAddNotification:
		a.IndexGroup, a.IndexOffset, a.Length = EtherCATADSGroup(u32(0)), u32(4), u32(8)
	case EtherCATADSReadWrite:
		a.IndexGroup, a.IndexOffset, a.Length, a.WriteLength = EtherCATADSGroup(u32(0)), u32(4), u32(8), u32(12)
	}

	switch cmd {
	case EtherCATADSWrite, EtherCATADSReadWrite, EtherCATADSWriteControl:
		a.Data = b[need:]
	}

	switch cmd {
	case EtherCATADSWriteControl:
		a.ADSState = EtherCATADSState(binary.LittleEndian.Uint16(b[0:2]))
		a.DeviceState = binary.LittleEndian.Uint16(b[2:4])
		a.Length = u32(4)
	case EtherCATADSReadWrite:
		a.SumUp = decodeEtherCATADSSumUp(a.IndexGroup, a.IndexOffset, a.Data)
	case EtherCATADSAddNotification:
		a.TransmissionMode, a.MaxDelay, a.CycleTime = EtherCATADSTransMode(u32(12)), u32(16), u32(20)
	case EtherCATADSDeleteNotification:
		a.Handle = u32(0)
	case EtherCATADSNotification:
		a.Length, a.StampCount = u32(0), u32(4)
		a.Stamps = decodeEtherCATADSStamps(b[need:], a.StampCount)
	}
	return a
}

// decodeEtherCATADSRes decodes an ADS response body. It returns nil for
// a command without a response or a body too short for its fields.
func decodeEtherCATADSRes(cmd EtherCATADSCommand, b []byte) *EtherCATADS {
	need := ethercatADSResLen(cmd)
	if need == 0 || len(b) < need {
		return nil
	}

	a := &EtherCATADS{Result: EtherCATADSError(binary.LittleEndian.Uint32(b))}
	rest := b[ethercatADSResultLen:]

	switch cmd {
	case EtherCATADSReadDeviceInfo:
		a.MajorVersion = rest[0]
		a.MinorVersion = rest[1]
		a.Build = binary.LittleEndian.Uint16(rest[2:4])
		a.DeviceName = trimEtherCATNUL(b[need:])
	case EtherCATADSRead, EtherCATADSReadWrite:
		a.Length = binary.LittleEndian.Uint32(rest)
		a.Data = b[need:]
	case EtherCATADSReadState:
		a.ADSState = EtherCATADSState(binary.LittleEndian.Uint16(rest[0:2]))
		a.DeviceState = binary.LittleEndian.Uint16(rest[2:4])
	case EtherCATADSAddNotification:
		a.Handle = binary.LittleEndian.Uint32(rest)
	}
	return a
}

// decodeEtherCATADSStamps reads the stamps of a device notification:
//
//	stamp:  Timestamp (8) | SampleCount (4) | samples
//	sample: Handle (4) | Size (4) | data
//
// The announced counts are not trusted: a first pass counts the stamps
// and samples the data really holds, then the lists are allocated once.
// Decoding stops at the first entry that does not fit.
func decodeEtherCATADSStamps(b []byte, announced uint32) []EtherCATADSStamp {
	stamps, samples := countEtherCATADSStamps(b, announced)
	if stamps == 0 {
		return nil
	}

	out := make([]EtherCATADSStamp, stamps)
	pool := make([]EtherCATADSSample, samples)

	for i := range out {
		out[i].Timestamp = binary.LittleEndian.Uint64(b)
		want := binary.LittleEndian.Uint32(b[8:])
		b = b[ethercatADSStampLen:]

		used := 0
		for ; uint32(used) < want && used < len(pool); used++ {
			size, ok := ethercatADSSampleSize(b)
			if !ok {
				break
			}

			pool[used] = EtherCATADSSample{
				Handle: binary.LittleEndian.Uint32(b),
				Data:   b[ethercatADSSampleLen : ethercatADSSampleLen+size],
			}
			b = b[ethercatADSSampleLen+size:]
		}

		out[i].Samples = pool[:used:used]
		pool = pool[used:]
	}
	return out
}

// ethercatADSSampleSize returns the data size of the sample at the start
// of b, and whether the whole sample fits.
func ethercatADSSampleSize(b []byte) (int, bool) {
	if len(b) < ethercatADSSampleLen {
		return 0, false
	}

	size := binary.LittleEndian.Uint32(b[4:])
	if uint64(size) > uint64(len(b)-ethercatADSSampleLen) {
		return 0, false
	}
	return int(size), true
}

// countEtherCATADSStamps walks the stamps like the decoder does and
// returns how many stamps and samples fit. A stamp whose samples are cut
// short still counts, with the samples that fit; nothing follows it.
func countEtherCATADSStamps(b []byte, announced uint32) (stamps, samples int) {
	for uint32(stamps) < announced && len(b) >= ethercatADSStampLen {
		want := binary.LittleEndian.Uint32(b[8:])
		b = b[ethercatADSStampLen:]
		stamps++

		for n := uint32(0); n < want; n++ {
			size, ok := ethercatADSSampleSize(b)
			if !ok {
				return stamps, samples
			}

			b = b[ethercatADSSampleLen+size:]
			samples++
		}
	}
	return stamps, samples
}
