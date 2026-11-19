// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"time"
)

// CPU function group alarm and diagnostic services.
//
// Alarm message (indications, ack, lock, query request):
//
//	[scan: unknown(2), time(8), unknown(2) | indications: time(8)]
//	function, object count, objects
//
// A request or indication object is a variable specification, length
// and syntax ID followed by, for the ALARM syntaxes, the associated
// value count, event ID, states and associated values (read data). A
// response object is a return code.
//
// Alarm query response:
//
//	function, object count, return code, transport size,
//	complete length(2), {dataset length, unknown(2), alarm type,
//	event ID(4), unknown, event state, ack going, ack coming
//	[, ALARM_S: coming time, value, going time, value]}...
//
// Diagnostic message, also the record of SZL xyA0:
//
//	event ID(2), priority class, OB number, DatID(2), info 1(2),
//	info 2(4), time(8)

// More CPU subfunctions. Wireshark names 0x11 (S7CommCPUAlarmSInd)
// ALARM_SQ and 0x12 ALARM_S.
const (
	S7CommCPUScanInd         S7CommSubfunction = 0x09
	S7CommCPUAlarm8LockInd   S7CommSubfunction = 0x0D
	S7CommCPUAlarm8UnlockInd S7CommSubfunction = 0x0E
	S7CommCPUARSendInd       S7CommSubfunction = 0x10
	S7CommCPUAlarmSQInd      S7CommSubfunction = 0x11
	S7CommCPUAlarmS12Ind     S7CommSubfunction = 0x12
	S7CommCPUNotify8Ind      S7CommSubfunction = 0x16
)

const (
	s7commAlarmHead       = 2 // function, object count
	s7commAlarmScanExtra  = 2 // unknown octets around the scan time
	s7commAlarmObjHead    = 3 // varspec, length, syntax ID
	s7commAlarmEventLen   = 5 // value count, event ID
	s7commAlarmQueryLen   = 7 // unknown, query type, unknown, 4-octet key
	s7commAlarmQueryHead  = 6 // function, count, ret, tsize, length(2)
	s7commAlarmDatasetLen = 12
	s7commAlarmContinued  = 0xFFFF // complete length of an open-ended list
	s7commDiagMsgLen      = 20
	s7commMsgReqLen       = 10 // events, reserved, user name(8)
	s7commMsgResLen       = 2  // result, reserved
	s7commMsgUserLen      = 8
	s7commMsgEventAlarm   = 0x80 // subscribe to ALARM messages
)

// S7CommAlarmQueryType selects what an alarm query asks for.
type S7CommAlarmQueryType uint8

// Alarm query types.
const (
	S7CommQueryByAlarmType S7CommAlarmQueryType = 1
	S7CommQueryByEventID   S7CommAlarmQueryType = 3
)

// S7CommAlarmType is the alarm type of an alarm query.
type S7CommAlarmType uint8

// Alarm types.
const (
	S7CommAlarmTypeScan   S7CommAlarmType = 1
	S7CommAlarmTypeAlarm8 S7CommAlarmType = 2
	S7CommAlarmTypeAlarmS S7CommAlarmType = 4
)

// S7CommAlarm is an alarm message. Time is set for the indications
// that carry one and is zero if it is not a valid date.
type S7CommAlarm struct {
	Time        time.Time
	Function    uint8
	ObjectCount uint8
	Objects     []S7CommAlarmObject
}

// S7CommAlarmObject is one alarm message object. Signal state octets
// carry one bit per signal (bit 0 = signal 1).
type S7CommAlarmObject struct {
	VarSpec    uint8
	Length     uint8
	SyntaxID   S7CommSyntaxID
	ValueCount uint8
	EventID    uint32 // ALARM syntaxes, or query by event ID
	EventState uint8  // ALARM_IND, NOTIFY_IND
	State      uint8  // ALARM_IND, NOTIFY_IND
	AckGoing   uint8  // ALARM_IND, ALARM_ACK, NOTIFY_IND
	AckComing  uint8  // ALARM_IND, ALARM_ACK, NOTIFY_IND
	// NOTIFY_IND only.
	EventGoing       uint8
	EventComing      uint8
	EventLastChanged uint8
	Values           []S7CommDataItem // associated values
	// ALARM_QUERYREQ only.
	QueryType S7CommAlarmQueryType
	AlarmType S7CommAlarmType // query by alarm type
	// Response objects carry only this.
	ReturnCode S7CommReturnCode
}

// S7CommAlarmQuery is an alarm query response.
type S7CommAlarmQuery struct {
	Function       uint8
	ObjectCount    uint8
	ReturnCode     S7CommReturnCode
	TransportSize  S7CommDataTransportSize
	CompleteLength uint16
	Alarms         []S7CommAlarmEntry
}

// S7CommAlarmEntry is one pending alarm of a query response. The
// ALARM_S fields are set for that alarm type only; times are zero if
// not a valid date.
type S7CommAlarmEntry struct {
	Length      uint8
	AlarmType   S7CommAlarmType
	EventID     uint32
	EventState  uint8
	AckGoing    uint8
	AckComing   uint8
	Coming      time.Time
	ComingValue *S7CommDataItem
	Going       time.Time
	GoingValue  *S7CommDataItem
}

// S7CommDiagMessage is a CPU diagnostic buffer entry. Time is zero if
// it is not a valid date.
type S7CommDiagMessage struct {
	EventID       uint16
	PriorityClass uint8
	OBNumber      uint8
	DatID         uint16
	Info1         uint16
	Info2         uint32
	Time          time.Time
}

// S7CommMsgService is a message service subscription request or its
// response. AlarmType is set when the request subscribes to ALARM
// messages or the response carries it.
type S7CommMsgService struct {
	Events    uint8 // request: 0x01 mode, 0x02 system, 0x04 user, 0x80 alarm
	Username  string
	Result    uint8 // response
	AlarmType uint8
}

// decodeCPU reads the CPU services other than SZL read.
func (u *S7CommUserdata) decodeCPU() error {
	switch u.Subfunction {
	case S7CommCPUDiagMessage:
		m, err := s7commDiagMessage(u.Data)
		if err != nil {
			return err
		}
		u.Diag = &m
		return nil
	case S7CommCPUMessageService:
		return u.decodeMsgService()
	case S7CommCPUARSendInd:
		return u.decodeSend(binary.LittleEndian)
	case S7CommCPUAlarmQuery:
		if u.Type == S7CommUDTypeResponse {
			return u.decodeAlarmQuery()
		}
		return u.decodeAlarm()
	case S7CommCPUNotifyInd, S7CommCPUNotify8Ind, S7CommCPUAlarmSQInd, S7CommCPUAlarmS12Ind,
		S7CommCPUScanInd, S7CommCPUAlarmAck, S7CommCPUAlarmAckInd, S7CommCPUAlarm8Ind,
		S7CommCPUAlarm8Lock, S7CommCPUAlarm8LockInd, S7CommCPUAlarm8Unlock, S7CommCPUAlarm8UnlockInd:
		return u.decodeAlarm()
	}
	return nil
}

// s7commDiagMessage reads a 20-octet diagnostic message.
func s7commDiagMessage(d []byte) (S7CommDiagMessage, error) {
	if len(d) < s7commDiagMsgLen {
		return S7CommDiagMessage{}, fmt.Errorf("%w: diagnostic message %d octets", ErrS7CommMalformed, len(d))
	}

	be := binary.BigEndian
	m := S7CommDiagMessage{
		EventID:       be.Uint16(d[0:2]),
		PriorityClass: d[2],
		OBNumber:      d[3],
		DatID:         be.Uint16(d[4:6]),
		Info1:         be.Uint16(d[6:8]),
		Info2:         be.Uint32(d[8:12]),
	}
	m.Time, _ = s7commBCDTime(d[12:s7commDiagMsgLen], s7commBCDShort)
	return m, nil
}

// decodeMsgService reads a message service request or response.
func (u *S7CommUserdata) decodeMsgService() error {
	d := u.Data
	m := &S7CommMsgService{}
	switch u.Type {
	case S7CommUDTypeRequest:
		if len(d) < s7commMsgReqLen {
			return fmt.Errorf("%w: message service request %d octets", ErrS7CommMalformed, len(d))
		}
		m.Events = d[0]
		m.Username = s7commCString(d[2 : 2+s7commMsgUserLen])
		if m.Events&s7commMsgEventAlarm != 0 && len(d) > s7commMsgReqLen {
			m.AlarmType = d[s7commMsgReqLen]
		}
	case S7CommUDTypeResponse:
		if len(d) < s7commMsgResLen {
			return fmt.Errorf("%w: message service response %d octets", ErrS7CommMalformed, len(d))
		}
		m.Result = d[0]
		if len(d) > s7commMsgResLen {
			m.AlarmType = d[s7commMsgResLen]
		}
	default:
		return nil
	}
	u.MsgService = m
	return nil
}

// decodeAlarm reads an alarm message.
func (u *S7CommUserdata) decodeAlarm() error {
	d := u.Data
	a := &S7CommAlarm{}

	var err error
	switch u.Subfunction {
	case S7CommCPUScanInd:
		if len(d) < s7commAlarmScanExtra+s7commBCDShortLen+s7commAlarmScanExtra {
			return fmt.Errorf("%w: scan indication %d octets", ErrS7CommMalformed, len(d))
		}
		a.Time, _ = s7commBCDTime(d[s7commAlarmScanExtra:], s7commBCDShort)
		d = d[s7commAlarmScanExtra+s7commBCDShortLen+s7commAlarmScanExtra:]
	case S7CommCPUAlarm8Ind, S7CommCPUAlarmAckInd, S7CommCPUAlarmSQInd, S7CommCPUAlarmS12Ind,
		S7CommCPUNotifyInd, S7CommCPUNotify8Ind:
		if len(d) < s7commBCDShortLen {
			return fmt.Errorf("%w: alarm indication %d octets", ErrS7CommMalformed, len(d))
		}
		a.Time, _ = s7commBCDTime(d, s7commBCDShort)
		d = d[s7commBCDShortLen:]
	}
	if len(d) < s7commAlarmHead {
		return fmt.Errorf("%w: alarm message %d octets", ErrS7CommMalformed, len(d))
	}
	a.Function = d[0]
	a.ObjectCount = d[1]
	d = d[s7commAlarmHead:]

	if u.Type == S7CommUDTypeResponse {
		a.Objects, err = s7commAlarmResults(d, int(a.ObjectCount))
	} else {
		a.Objects, err = s7commAlarmObjects(d, int(a.ObjectCount))
	}
	if err != nil {
		return err
	}
	u.Alarm = a
	return nil
}

// s7commAlarmResults reads the return code of each response object.
func s7commAlarmResults(d []byte, n int) ([]S7CommAlarmObject, error) {
	if n > len(d) {
		return nil, fmt.Errorf("%w: %d alarm results in %d octets", ErrS7CommMalformed, n, len(d))
	}

	objs := make([]S7CommAlarmObject, n)
	for i := range objs {
		objs[i].ReturnCode = S7CommReturnCode(d[i])
	}
	return objs, nil
}

// s7commAlarmObjects reads n request or indication objects.
func s7commAlarmObjects(d []byte, n int) ([]S7CommAlarmObject, error) {
	if n*s7commAlarmObjHead > len(d) {
		return nil, fmt.Errorf("%w: %d alarm objects in %d octets", ErrS7CommMalformed, n, len(d))
	}

	objs := make([]S7CommAlarmObject, 0, n)
	for i := 0; i < n; i++ {
		o, rest, err := s7commAlarmObj(d)
		if err != nil {
			return nil, fmt.Errorf("alarm object %d: %w", i, err)
		}
		objs = append(objs, o)
		d = rest
	}
	return objs, nil
}

// s7commAlarmObj reads one request or indication object.
func s7commAlarmObj(d []byte) (S7CommAlarmObject, []byte, error) {
	var o S7CommAlarmObject
	if len(d) < s7commAlarmObjHead {
		return o, nil, fmt.Errorf("%w: alarm object %d octets", ErrS7CommMalformed, len(d))
	}
	o.VarSpec, o.Length, o.SyntaxID = d[0], d[1], S7CommSyntaxID(d[2])
	d = d[s7commAlarmObjHead:]

	switch o.SyntaxID {
	case S7CommSyntaxAlarmLock, S7CommSyntaxAlarmInd, S7CommSyntaxNotifyInd, S7CommSyntaxAlarmAck:
		return s7commAlarmEvent(o, d)
	case S7CommSyntaxAlarmQuery:
		if len(d) < s7commAlarmQueryLen {
			return o, nil, fmt.Errorf("%w: alarm query %d octets", ErrS7CommMalformed, len(d))
		}
		o.QueryType = S7CommAlarmQueryType(d[1])
		key := binary.BigEndian.Uint32(d[3:7])
		switch o.QueryType {
		case S7CommQueryByAlarmType:
			o.AlarmType = S7CommAlarmType(key)
		case S7CommQueryByEventID:
			o.EventID = key
		}
		return o, d[s7commAlarmQueryLen:], nil
	}

	// Unknown syntax: skip the rest of the specification.
	n := int(o.Length) - 1
	if n < 0 || n > len(d) {
		return o, nil, fmt.Errorf("%w: alarm object length %d", ErrS7CommMalformed, o.Length)
	}
	return o, d[n:], nil
}

// s7commAlarmEvent reads the event part of an ALARM syntax object.
func s7commAlarmEvent(o S7CommAlarmObject, d []byte) (S7CommAlarmObject, []byte, error) {
	ind := o.SyntaxID == S7CommSyntaxAlarmInd || o.SyntaxID == S7CommSyntaxNotifyInd
	notify := o.SyntaxID == S7CommSyntaxNotifyInd
	ack := ind || o.SyntaxID == S7CommSyntaxAlarmAck

	// Fixed part: value count, event ID, then 2 state octets for the
	// indications, 2 ack octets with ack, 4 event octets for NOTIFY.
	need := s7commAlarmEventLen
	if ind {
		need += 2
	}
	if ack {
		need += 2
	}
	if notify {
		need += 4
	}
	if len(d) < need {
		return o, nil, fmt.Errorf("%w: alarm event %d octets", ErrS7CommMalformed, len(d))
	}

	o.ValueCount = d[0]
	o.EventID = binary.BigEndian.Uint32(d[1:5])
	d = d[s7commAlarmEventLen:]
	if ind {
		o.EventState, o.State = d[0], d[1]
		d = d[2:]
	}
	if ack {
		o.AckGoing, o.AckComing = d[0], d[1]
		d = d[2:]
	}
	if notify {
		o.EventGoing, o.EventComing, o.EventLastChanged = d[0], d[1], d[2]
		d = d[4:]
	}
	if !ind || o.ValueCount == 0 {
		return o, d, nil
	}

	vals, rest, err := s7commReadData(d, int(o.ValueCount))
	if err != nil {
		return o, nil, err
	}
	o.Values = vals
	return o, rest, nil
}

// decodeAlarmQuery reads an alarm query response.
func (u *S7CommUserdata) decodeAlarmQuery() error {
	d := u.Data
	if len(d) < s7commAlarmQueryHead {
		return fmt.Errorf("%w: alarm query response %d octets", ErrS7CommMalformed, len(d))
	}

	q := &S7CommAlarmQuery{
		Function:       d[0],
		ObjectCount:    d[1],
		ReturnCode:     S7CommReturnCode(d[2]),
		TransportSize:  S7CommDataTransportSize(d[3]),
		CompleteLength: binary.BigEndian.Uint16(d[4:6]),
	}
	d = d[s7commAlarmQueryHead:]
	if q.ReturnCode == S7CommRetSuccess {
		alarms, err := s7commAlarmEntries(d, q.CompleteLength)
		if err != nil {
			return err
		}
		q.Alarms = alarms
	}
	u.AlarmQuery = q
	return nil
}

// s7commAlarmEntries reads datasets until the complete length is used
// up or, for an open-ended list (0xFFFF), until a zero octet.
func s7commAlarmEntries(d []byte, total uint16) ([]S7CommAlarmEntry, error) {
	alarms := make([]S7CommAlarmEntry, 0, len(d)/s7commAlarmDatasetLen)
	remaining := int(total)
	for {
		e, n, err := s7commAlarmEntry(d)
		if err != nil {
			return nil, fmt.Errorf("alarm %d: %w", len(alarms), err)
		}
		alarms = append(alarms, e)
		d = d[n:]
		remaining -= n

		if total == s7commAlarmContinued {
			if len(d) == 0 || d[0] == 0 {
				return alarms, nil
			}
			continue
		}
		if remaining <= 0 || len(d) == 0 {
			return alarms, nil
		}
	}
}

// s7commAlarmEntry reads one dataset and returns its size.
func s7commAlarmEntry(d []byte) (S7CommAlarmEntry, int, error) {
	var e S7CommAlarmEntry
	if len(d) < s7commAlarmDatasetLen {
		return e, 0, fmt.Errorf("%w: alarm dataset %d octets", ErrS7CommMalformed, len(d))
	}
	e.Length = d[0]
	e.AlarmType = S7CommAlarmType(d[3])
	e.EventID = binary.BigEndian.Uint32(d[4:8])
	e.EventState, e.AckGoing, e.AckComing = d[9], d[10], d[11]
	if e.AlarmType != S7CommAlarmTypeAlarmS {
		return e, s7commAlarmDatasetLen, nil
	}

	// ALARM_S: coming time and value, going time and value.
	rest := d[s7commAlarmDatasetLen:]
	var err error
	if e.Coming, e.ComingValue, rest, err = s7commAlarmStamp(rest); err != nil {
		return e, 0, err
	}
	if e.Going, e.GoingValue, rest, err = s7commAlarmStamp(rest); err != nil {
		return e, 0, err
	}
	return e, len(d) - len(rest), nil
}

// s7commAlarmStamp reads a timestamp and one associated value.
func s7commAlarmStamp(d []byte) (time.Time, *S7CommDataItem, []byte, error) {
	if len(d) < s7commBCDShortLen {
		return time.Time{}, nil, nil, fmt.Errorf("%w: alarm time %d octets", ErrS7CommMalformed, len(d))
	}

	t, _ := s7commBCDTime(d, s7commBCDShort)
	vals, rest, err := s7commReadData(d[s7commBCDShortLen:], 1)
	if err != nil {
		return time.Time{}, nil, nil, err
	}
	return t, &vals[0], rest, nil
}
