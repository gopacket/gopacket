// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import "time"

// MMS journal services (ISO 9506-2 clause 18). Best effort, like
// mms_services.go.

// MMSJournalPosition is a point in a journal: a time, an entry
// identifier, or both. Entry is nil when absent.
type MMSJournalPosition struct {
	HasTime bool
	Time    time.Time
	Entry   []byte
}

// MMSJournalForm is the entryForm CHOICE of a journal entry.
type MMSJournalForm uint8

// Journal entry forms.
const (
	MMSJournalData MMSJournalForm = iota
	MMSJournalAnnotation
)

// String returns the ASN.1 name of the form.
func (f MMSJournalForm) String() string {
	return mmsEnumName([]string{"data", "annotation"}, int64(f))
}

// MMSJournalVariable is one logged variable: its tag and value.
type MMSJournalVariable struct {
	Tag   string
	Value MMSData
}

// MMSJournalContent is an EntryContent. A data entry holds an event
// transition (HasEvent), variable values or both; an annotation entry
// holds a text.
type MMSJournalContent struct {
	OccurrenceTime time.Time
	Form           MMSJournalForm
	HasEvent       bool
	EventCondition MMSObjectName
	EventState     MMSEventState
	Variables      []MMSJournalVariable
	Annotation     string
	// AdditionalDetail is the raw companion standard detail.
	AdditionalDetail []byte
}

// MMSJournalEntry is one JournalEntry of a ReadJournal-Response.
// Application is nil when malformed.
type MMSJournalEntry struct {
	ID          []byte
	Application *MMSApplicationReference
	Content     MMSJournalContent
}

// MMSJournalRequest holds the arguments of the journal requests. Name is
// always set:
//
//	Start, Stop, EntryCount, Variables, After   readJournal
//	Entries, Content                            writeJournal
//	Limit                                       initializeJournal
//
// Start is the rangeStartSpecification (a time or an entry), Stop the
// endingTime and EntryCount the numberOfEntries of the
// rangeStopSpecification, After the entryToStartAfter and Limit the
// limitSpecification. Entries counts Content.
type MMSJournalRequest struct {
	Name    MMSObjectName
	Entries int

	Start         *MMSJournalPosition
	Stop          *MMSJournalPosition
	EntryCount    int32
	HasEntryCount bool
	Variables     []string
	After         *MMSJournalPosition

	Content []MMSJournalContent

	Limit *MMSJournalPosition
}

// MMSJournalResponse is a ReadJournal-Response (Entries, List,
// MoreFollows), a ReportJournalStatus-Response (CurrentEntries,
// Deletable, AccessControlList) or an InitializeJournal-Response
// (Deleted). Entries counts List.
type MMSJournalResponse struct {
	Entries           int
	List              []MMSJournalEntry
	MoreFollows       bool
	CurrentEntries    uint32
	Deletable         bool
	AccessControlList string
	Deleted           uint32
}

// Journal tags.
const (
	mmsTagJouName      uint32 = 0
	mmsTagJouEntries   uint32 = 1
	mmsTagJouStart     uint32 = 1
	mmsTagJouStop      uint32 = 2
	mmsTagJouVariables uint32 = 4
	mmsTagJouAfter     uint32 = 5
	mmsTagJouLimit     uint32 = 1
	mmsTagJouTime      uint32 = 0
	mmsTagJouEntry     uint32 = 1
	mmsTagJouList      uint32 = 0
	mmsTagJouMore      uint32 = 1
	mmsTagJouCurrent   uint32 = 0
	mmsTagJouDeletable uint32 = 1
	mmsTagJouACL       uint32 = 2

	mmsTagJEID         uint32 = 0
	mmsTagJEApp        uint32 = 1
	mmsTagJEContent    uint32 = 2
	mmsTagEntTime      uint32 = 0
	mmsTagEntDetail    uint32 = 1
	mmsTagEntData      uint32 = 2
	mmsTagEntNote      uint32 = 3
	mmsTagEntEvent     uint32 = 0
	mmsTagEntVars      uint32 = 1
	mmsTagEntEventName uint32 = 0
	mmsTagEntEventSt   uint32 = 1
	mmsTagJVTag        uint32 = 0
	mmsTagJVValue      uint32 = 1
)

// decodeMMSJournalReq reads a journal request: [0] journalName and the
// fields of service s.
func decodeMMSJournalReq(t osiBERTLV, s MMSConfirmedService) (*MMSJournalRequest, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSJournalRequest{}
	found := false
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagJouName):
			r.Name, err = decodeMMSObjectNameIn(f.Value)
			found = true
		case s == MMSWriteJournal && f.is(osiBERContext, osiBERConstructed, mmsTagJouEntries):
			r.Content, err = decodeMMSContents(f.Value)
			r.Entries = len(r.Content)
		case s == MMSInitializeJournal && f.is(osiBERContext, osiBERConstructed, mmsTagJouLimit):
			r.Limit, err = decodeMMSJournalPos(f.Value)
		case s == MMSReadJournal:
			err = r.decodeRange(f)
		}
		return err
	})
	if err == nil && !found {
		err = errMMSField
	}
	return mmsResult(r, err)
}

// decodeRange stores one ReadJournal-Request field: [1] start CHOICE,
// [2] stop CHOICE, [4] listOfVariables, [5] entryToStartAfter.
func (r *MMSJournalRequest) decodeRange(f osiBERTLV) error {
	if f.Class != osiBERContext || f.Form != osiBERConstructed {
		return nil
	}

	var err error
	switch f.Tag {
	case mmsTagJouStart:
		// startingTime [0] or startingEntry [1]: one position field.
		r.Start, err = decodeMMSJournalPos(f.Value)
	case mmsTagJouStop:
		err = r.decodeStop(f.Value)
	case mmsTagJouVariables:
		r.Variables, err = decodeMMSStrings(f.Value, osiBERTagVisible)
	case mmsTagJouAfter:
		r.After, err = decodeMMSJournalPos(f.Value)
	}
	return err
}

// decodeStop reads rangeStopSpecification: endingTime [0] TimeOfDay or
// numberOfEntries [1] Integer32.
func (r *MMSJournalRequest) decodeStop(b []byte) error {
	t, err := osiBERSingle(b)
	if err != nil {
		return err
	}
	if !t.is(osiBERContext, osiBERPrimitive, mmsTagJouEntry) {
		r.Stop, err = decodeMMSJournalPos(b)
		return err
	}

	n, err := mmsInt32(t.Value)
	r.EntryCount, r.HasEntryCount = int32(n), true
	return err
}

// decodeMMSJournalPos reads [0] TimeOfDay and/or [1] OCTET STRING entry
// identifier.
func decodeMMSJournalPos(b []byte) (*MMSJournalPosition, error) {
	p := &MMSJournalPosition{}
	err := mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagJouTime):
			p.Time, err = decodeMMSTimeOfDay(f.Value)
			p.HasTime = true
		case f.is(osiBERContext, osiBERPrimitive, mmsTagJouEntry):
			p.Entry = f.Value
		default:
			err = errMMSField
		}
		return err
	})
	return mmsResult(p, err)
}

// decodeMMSJournalResp reads ReadJournal-Response ([0] entries, [1]
// moreFollows DEFAULT FALSE) or ReportJournalStatus-Response ([0]
// currentEntries, [1] mmsDeletable, [2] accessControlList).
func decodeMMSJournalResp(t osiBERTLV, s MMSConfirmedService) (*MMSJournalResponse, error) {
	b, err := mmsBody(t, osiBERConstructed)
	if err != nil {
		return nil, err
	}

	r := &MMSJournalResponse{}
	err = mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case s == MMSReadJournal && f.is(osiBERContext, osiBERConstructed, mmsTagJouList):
			r.List, err = decodeMMSJournalList(f.Value)
			r.Entries = len(r.List)
		case s == MMSReadJournal && f.is(osiBERContext, osiBERPrimitive, mmsTagJouMore):
			r.MoreFollows, err = osiBERBool(f.Value)
		case s == MMSReportJournalStatus && f.is(osiBERContext, osiBERPrimitive, mmsTagJouCurrent):
			r.CurrentEntries, err = osiBERUint32(f.Value)
		case s == MMSReportJournalStatus && f.is(osiBERContext, osiBERPrimitive, mmsTagJouDeletable):
			r.Deletable, err = osiBERBool(f.Value)
		case s == MMSReportJournalStatus && f.is(osiBERContext, osiBERPrimitive, mmsTagJouACL):
			r.AccessControlList = string(f.Value)
		}
		return err
	})
	return mmsResult(r, err)
}

// decodeMMSJournalInit reads InitializeJournal-Response: entries deleted.
func decodeMMSJournalInit(t osiBERTLV) (*MMSJournalResponse, error) {
	n, err := mmsCount(t)
	return mmsResult(&MMSJournalResponse{Deleted: n}, err)
}

// decodeMMSJournalList decodes SEQUENCE OF JournalEntry { [0]
// entryIdentifier, [1] originatingApplication, [2] entryContent }.
func decodeMMSJournalList(b []byte) ([]MMSJournalEntry, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSJournalEntry, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		var e MMSJournalEntry
		found := false
		err = mmsFields(item, func(f osiBERTLV) error {
			var err error
			switch {
			case f.is(osiBERContext, osiBERPrimitive, mmsTagJEID):
				e.ID = f.Value
			case f.is(osiBERContext, osiBERConstructed, mmsTagJEApp):
				e.Application, _ = decodeMMSAppRefIn(f.Value)
			case f.is(osiBERContext, osiBERConstructed, mmsTagJEContent):
				e.Content, err = decodeMMSContent(f.Value)
				found = true
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errMMSField
		}
		out = append(out, e)
	}
	return out, nil
}

// decodeMMSContents decodes a SEQUENCE OF EntryContent body.
func decodeMMSContents(b []byte) ([]MMSJournalContent, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSJournalContent, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		c, err := decodeMMSContent(item)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// decodeMMSContent reads an EntryContent body: [0] occurrenceTime, [1]
// additionalDetail OPTIONAL, then data [2] or annotation [3].
func decodeMMSContent(b []byte) (MMSJournalContent, error) {
	var c MMSJournalContent
	timed := false
	err := mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERPrimitive, mmsTagEntTime):
			c.OccurrenceTime, err = decodeMMSTimeOfDay(f.Value)
			timed = true
		case f.Class == osiBERContext && f.Tag == mmsTagEntDetail:
			c.AdditionalDetail = f.Value
		case f.is(osiBERContext, osiBERConstructed, mmsTagEntData):
			c.Form = MMSJournalData
			err = c.decodeData(f.Value)
		case f.Class == osiBERContext && f.Tag == mmsTagEntNote:
			c.Form = MMSJournalAnnotation
			c.Annotation, err = mmsAnnotation(f)
		}
		return err
	})

	// The time is mandatory.
	if err == nil && !timed {
		err = errMMSField
	}
	return c, err
}

// mmsAnnotation reads the annotation: an IMPLICIT VisibleString in ISO
// 9506-2:1990, an EXPLICIT MMSString since 2003.
func mmsAnnotation(f osiBERTLV) (string, error) {
	if f.Form == osiBERPrimitive {
		return string(f.Value), nil
	}

	t, err := osiBERSingle(f.Value)
	if err != nil {
		return "", err
	}
	if t.Class != osiBERUniversal || t.Form != osiBERPrimitive {
		return "", errMMSField
	}
	return string(t.Value), nil
}

// decodeData reads the data form: [0] event { [0] eventConditionName, [1]
// currentState } OPTIONAL, [1] listOfVariables OPTIONAL.
func (c *MMSJournalContent) decodeData(b []byte) error {
	return mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagEntEvent):
			c.HasEvent = true
			err = c.decodeEvent(f.Value)
		case f.is(osiBERContext, osiBERConstructed, mmsTagEntVars):
			c.Variables, err = decodeMMSJournalVars(f.Value)
		}
		return err
	})
}

// decodeEvent reads the event of a data entry.
func (c *MMSJournalContent) decodeEvent(b []byte) error {
	return mmsFields(b, func(f osiBERTLV) error {
		var err error
		switch {
		case f.is(osiBERContext, osiBERConstructed, mmsTagEntEventName):
			c.EventCondition, err = decodeMMSObjectNameIn(f.Value)
		case f.is(osiBERContext, osiBERPrimitive, mmsTagEntEventSt):
			var n int64
			n, err = osiBERInt(f.Value)
			c.EventState = MMSEventState(n)
		}
		return err
	})
}

// decodeMMSJournalVars decodes SEQUENCE OF SEQUENCE { [0] variableTag,
// [1] EXPLICIT Data }.
func decodeMMSJournalVars(b []byte) ([]MMSJournalVariable, error) {
	count, err := osiBERCount(b)
	if err != nil {
		return nil, err
	}

	out := make([]MMSJournalVariable, 0, count)
	for len(b) > 0 {
		item, rest, err := osiBERExpect(b, osiBERUniversal, osiBERConstructed, osiBERTagSequence)
		if err != nil {
			return nil, err
		}
		b = rest

		tag, item, err := osiBERExpect(item, osiBERContext, osiBERPrimitive, mmsTagJVTag)
		if err != nil {
			return nil, err
		}
		val, _, err := osiBERExpect(item, osiBERContext, osiBERConstructed, mmsTagJVValue)
		if err != nil {
			return nil, err
		}
		data, err := osiBERSingle(val)
		if err != nil {
			return nil, err
		}

		v := MMSJournalVariable{Tag: string(tag)}
		if v.Value, err = decodeMMSData(data, 0); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
