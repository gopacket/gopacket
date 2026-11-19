// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"strings"
	"time"
)

// Values of the less common DNP3 objects: the obsolete file identifier
// (g70v1), device storage and profile (g81, g82), private registration
// objects (g83), data sets (g85 to g88), application identifiers (g90),
// the status of a requested operation (g91), BCD integers (g101), the
// update key objects of secure authentication (g120v8, v10 to v15) and
// security statistics (g121, g122).
//
// Wireshark dissects g120v11, v12, v13, v15, g121 and g122 only; the
// layouts of the others follow the Zeek and Suricata parsers and, for
// the elements of data sets, IEEE 1815-2012 annex A alone.

// Sizes and masks of these objects.
const (
	dnp3FillMask       = 0x7F // g81v1: buffer fill percentage
	dnp3OverflowBit    = 0x80 // g81v1: buffer overflowed
	dnp3ProfileHdrLen  = 4    // g82v1: group, variation, qualifier, range
	dnp3PrivSpecLen    = 4    // g83v2: quantity, group, variation
	dnp3VendorLen      = 4    // g83: vendor code
	dnp3DescElemMin    = 3    // descriptor code, data type, maximum length
	dnp3StatusElemMin  = 1    // g91v1: status code
	dnp3BCDNibble      = 4
	dnp3BCDMaxDigit    = 9
	dnp3BCDDecimalBase = 10
)

// DNP3FileID is the obsolete file identifier (g70v1).
type DNP3FileID struct {
	FileType    uint8
	Attributes  uint8
	StartRecord uint16
	EndRecord   uint16
	Size        uint32
	Created     time.Time
	Permissions uint16
	FileID      uint32
	OwnerID     uint32
	GroupID     uint32
	Function    uint8
	Status      uint8
	Name        string
	Data        []byte // the records that follow the name, size field included
}

// DNP3BufferFill is the fill status of an event buffer (g81v1) for the
// objects of Group and Variation.
type DNP3BufferFill struct {
	Overflow  bool
	Percent   uint8
	Group     DNP3Group
	Variation uint8
}

// DNP3ProfileHeader is one object header a device profile lists.
type DNP3ProfileHeader struct {
	Group     DNP3Group
	Variation uint8
	Qualifier uint8
	Range     uint8
}

// DNP3DeviceProfile is a device profile (g82v1). Bit n of Functions is
// set when the device supports function code n.
type DNP3DeviceProfile struct {
	Functions uint64
	Headers   []DNP3ProfileHeader
}

// DNP3PrivateObject is a private registration object (g83v1). Data holds
// the objects the vendor defines for ObjectID.
type DNP3PrivateObject struct {
	Vendor   string
	ObjectID uint16
	Data     []byte
}

// DNP3PrivateSpec is one entry of a private registration object
// descriptor: Quantity objects of Group and Variation.
type DNP3PrivateSpec struct {
	Quantity  uint16
	Group     DNP3Group
	Variation uint8
}

// DNP3PrivateDescriptor is a private registration object descriptor
// (g83v2).
type DNP3PrivateDescriptor struct {
	Vendor   string
	ObjectID uint16
	Specs    []DNP3PrivateSpec
}

// DNP3DescriptorCode says what an element of a data set prototype or
// descriptor describes.
type DNP3DescriptorCode uint8

// DNP3DescriptorCode values.
const (
	DNP3DescriptorID            DNP3DescriptorCode = 1
	DNP3DescriptorUUID          DNP3DescriptorCode = 2
	DNP3DescriptorNamespace     DNP3DescriptorCode = 3
	DNP3DescriptorName          DNP3DescriptorCode = 4
	DNP3DescriptorDataElement   DNP3DescriptorCode = 5
	DNP3DescriptorPrototype     DNP3DescriptorCode = 6
	DNP3DescriptorControlValue  DNP3DescriptorCode = 7
	DNP3DescriptorControlStatus DNP3DescriptorCode = 8
)

// dnp3DescriptorNames maps descriptor codes to their spec names.
var dnp3DescriptorNames = map[DNP3DescriptorCode]string{
	DNP3DescriptorID:            "ID",
	DNP3DescriptorUUID:          "UUID",
	DNP3DescriptorNamespace:     "NSPC",
	DNP3DescriptorName:          "NAME",
	DNP3DescriptorDataElement:   "DAEL",
	DNP3DescriptorPrototype:     "PTYP",
	DNP3DescriptorControlValue:  "CTLV",
	DNP3DescriptorControlStatus: "CTLS",
}

// String returns the descriptor code name.
func (c DNP3DescriptorCode) String() string {
	if name, ok := dnp3DescriptorNames[c]; ok {
		return name
	}
	return fmt.Sprintf("Reserved(%d)", uint8(c))
}

// DNP3DescriptorElement is one element of a data set prototype or
// descriptor. Ancillary is the name or identifier the element carries.
type DNP3DescriptorElement struct {
	Code      DNP3DescriptorCode
	Type      DNP3AttrType
	MaxLength uint8
	Ancillary []byte
}

// DNP3DataSetDescriptor is a data set prototype (g85v1) or the contents
// of a data set descriptor (g86v1): the elements that describe the
// values of a data set, in order. Each is a length octet counting what
// follows it, a descriptor code, a data type code, the maximum length of
// the value and an ancillary value: 06 04 01 00 41 42 43 is the NAME
// "ABC".
type DNP3DataSetDescriptor struct {
	Elements []DNP3DescriptorElement
}

// DNP3DataSetTraits is the characteristics octet of a data set
// descriptor (g86v2).
type DNP3DataSetTraits uint8

// DNP3DataSetTraits bits.
const (
	DNP3DataSetReadable  DNP3DataSetTraits = 0x01 // RD
	DNP3DataSetWritable  DNP3DataSetTraits = 0x02 // WR
	DNP3DataSetStatic    DNP3DataSetTraits = 0x04 // ST: has static data
	DNP3DataSetEvents    DNP3DataSetTraits = 0x08 // EV: generates events
	DNP3DataSetDynamic   DNP3DataSetTraits = 0x10 // DF: defined by the master
	dnp3DataSetTraitMask                   = 0x1F
)

// dnp3TraitNames names the characteristics bits in wire order.
var dnp3TraitNames = []struct {
	bit  DNP3DataSetTraits
	name string
}{
	{DNP3DataSetReadable, "RD"},
	{DNP3DataSetWritable, "WR"},
	{DNP3DataSetStatic, "ST"},
	{DNP3DataSetEvents, "EV"},
	{DNP3DataSetDynamic, "DF"},
}

// Has reports whether every bit of t2 is set.
func (t DNP3DataSetTraits) Has(t2 DNP3DataSetTraits) bool {
	return t&t2 == t2
}

// String lists the set bits, e.g. "RD|ST", and reserved bits as
// Reserved(0x20).
func (t DNP3DataSetTraits) String() string {
	var names []string
	for _, n := range dnp3TraitNames {
		if t&n.bit != 0 {
			names = append(names, n.name)
		}
	}

	if rest := t &^ dnp3DataSetTraitMask; rest != 0 {
		names = append(names, fmt.Sprintf("Reserved(%#02x)", uint8(rest)))
	}
	return strings.Join(names, "|")
}

// DNP3DataSet is the present value of a data set (g87v1) or a snapshot
// of one (g88v1): its values in the order its descriptor lists them,
// each sent as a length octet and that many octets. The first value is
// the data set identifier; a snapshot follows it with its time. The
// descriptor, sent apart, says how to read each value.
type DNP3DataSet struct {
	Elements [][]byte
}

// DNP3AppID names an application (g90v1).
type DNP3AppID struct {
	Name string
}

// DNP3OperationStatus is the status of one object of an activate
// configuration request.
type DNP3OperationStatus struct {
	Status    uint8
	Ancillary []byte
}

// DNP3ActivateStatus is the status of a requested operation (g91v1):
// how long the device stays busy, and one status per requested object.
type DNP3ActivateStatus struct {
	Delay    time.Duration
	Statuses []DNP3OperationStatus
}

// DNP3BCD is a binary-coded decimal integer (g101) of 4, 8 or 16
// digits. Raw holds the digits as sent, four bits each, the lowest digit
// in the lowest bits: 0x1234 is 1234.
type DNP3BCD struct {
	Raw    uint64
	Digits uint8
}

// Uint returns the decimal value. It errors when a digit is above 9.
func (b DNP3BCD) Uint() (uint64, error) {
	var v uint64
	for i := int(b.Digits) - 1; i >= 0; i-- {
		digit := b.Raw >> (uint(i) * dnp3BCDNibble) & (1<<dnp3BCDNibble - 1)
		if digit > dnp3BCDMaxDigit {
			return 0, ErrDNP3BadBCD
		}
		v = v*dnp3BCDDecimalBase + digit
	}
	return v, nil
}

// DNP3SecurityStat is a security statistic or security statistic event
// (g121, g122). Its flags are those of a counter.
type DNP3SecurityStat struct {
	Flags       DNP3Flags
	Association uint16
	Value       uint32
	Time        DNP3Timestamp
}

// DNP3AuthUserCert is a user certificate (g120v8).
type DNP3AuthUserCert struct {
	Method      uint8 // key change method
	CertType    uint8
	Certificate []byte
}

// DNP3AuthUserStatus is a user status change (g120v10).
type DNP3AuthUserStatus struct {
	Method     uint8 // key change method
	Operation  uint8
	Seq        uint32 // SCS
	Role       uint16
	RoleExpiry uint16 // days
	UserName   string
	PublicKey  []byte
	CertData   []byte
}

// DNP3AuthUpdateKeyReq is an update key change request (g120v11).
type DNP3AuthUpdateKeyReq struct {
	Method    uint8 // key change method
	UserName  string
	Challenge []byte
}

// DNP3AuthUpdateKeyReply is an update key change reply (g120v12).
type DNP3AuthUpdateKeyReply struct {
	Seq       uint32 // KSQ
	User      uint16
	Challenge []byte
}

// DNP3AuthUpdateKey is an update key change (g120v13).
type DNP3AuthUpdateKey struct {
	Seq     uint32 // KSQ
	User    uint16
	KeyData []byte
}

// DNP3AuthSignature is an update key change signature (g120v14).
type DNP3AuthSignature struct {
	Signature []byte
}

func (DNP3FileID) dnp3Value()             {}
func (DNP3BufferFill) dnp3Value()         {}
func (DNP3DeviceProfile) dnp3Value()      {}
func (DNP3PrivateObject) dnp3Value()      {}
func (DNP3PrivateDescriptor) dnp3Value()  {}
func (DNP3DataSetDescriptor) dnp3Value()  {}
func (DNP3DataSetTraits) dnp3Value()      {}
func (DNP3DataSet) dnp3Value()            {}
func (DNP3AppID) dnp3Value()              {}
func (DNP3ActivateStatus) dnp3Value()     {}
func (DNP3BCD) dnp3Value()                {}
func (DNP3SecurityStat) dnp3Value()       {}
func (DNP3AuthUserCert) dnp3Value()       {}
func (DNP3AuthUserStatus) dnp3Value()     {}
func (DNP3AuthUpdateKeyReq) dnp3Value()   {}
func (DNP3AuthUpdateKeyReply) dnp3Value() {}
func (DNP3AuthUpdateKey) dnp3Value()      {}
func (DNP3AuthSignature) dnp3Value()      {}

// list returns how many entries of at least size bytes a claimed count
// can hold in what is left, so nothing is allocated for entries that
// are not there. It marks the read short when the count does not fit.
func (r *dnp3Reader) list(count, size int) int {
	if count <= len(r.b)/size {
		return count
	}
	r.short = true
	r.b = nil
	return 0
}

// dnp3FileID reads a g70v1 file identifier.
func dnp3FileID(r *dnp3Reader) DNP3Value {
	n := r.u16()
	f := DNP3FileID{FileType: r.u8(), Attributes: r.u8(), StartRecord: r.u16(), EndRecord: r.u16(), Size: r.u32()}
	f.Created, f.Permissions = r.time(), r.u16()
	f.FileID, f.OwnerID, f.GroupID = r.u32(), r.u32(), r.u32()
	f.Function, f.Status = r.u8(), r.u8()
	f.Name = string(r.bytes(int(n)))
	f.Data = r.rest()
	return f
}

// dnp3Storage reads g81v1 and g82v1.
func dnp3Storage(r *dnp3Reader, g DNP3Group, v uint8) DNP3Value {
	if v != 1 {
		return nil
	}

	if g == DNP3GroupDeviceStorage {
		fill := r.u8()
		return DNP3BufferFill{Overflow: fill&dnp3OverflowBit != 0, Percent: fill & dnp3FillMask, Group: DNP3Group(r.u8()), Variation: r.u8()}
	}

	p := DNP3DeviceProfile{Functions: r.u64()}
	n := r.list(int(r.u16()), dnp3ProfileHdrLen)
	p.Headers = make([]DNP3ProfileHeader, n)
	for i := range p.Headers {
		p.Headers[i] = DNP3ProfileHeader{Group: DNP3Group(r.u8()), Variation: r.u8(), Qualifier: r.u8(), Range: r.u8()}
	}
	return p
}

// dnp3Private reads g83v1 and v2.
func dnp3Private(r *dnp3Reader, v uint8) DNP3Value {
	switch v {
	case 1:
		o := DNP3PrivateObject{Vendor: string(r.bytes(dnp3VendorLen)), ObjectID: r.u16()}
		o.Data = r.bytes(int(r.u16()))
		return o
	case 2:
		d := DNP3PrivateDescriptor{Vendor: string(r.bytes(dnp3VendorLen)), ObjectID: r.u16()}
		n := r.list(int(r.u16()), dnp3PrivSpecLen)
		d.Specs = make([]DNP3PrivateSpec, n)
		for i := range d.Specs {
			d.Specs[i] = DNP3PrivateSpec{Quantity: r.u16(), Group: DNP3Group(r.u8()), Variation: r.u8()}
		}
		return d
	}
	return nil
}

// Data set variations.
const (
	dnp3SetContentsVar = 1 // g85v1, g86v1, g87v1, g88v1
	dnp3SetTraitsVar   = 2 // g86v2
)

// dnp3DataSet reads the data set objects g85 to g88. g86v3, the point
// index attributes, has no decoder.
func dnp3DataSet(r *dnp3Reader, g DNP3Group, v uint8) DNP3Value {
	switch {
	case g == DNP3GroupDataSetDescriptor && v == dnp3SetTraitsVar:
		return DNP3DataSetTraits(r.u8())
	case v != dnp3SetContentsVar:
		return nil
	case g == DNP3GroupDataSetPrototype || g == DNP3GroupDataSetDescriptor:
		return dnp3Descriptor(r)
	}

	// Every element takes its length octet, so the bytes left bound them.
	var s DNP3DataSet
	for len(r.b) > 0 {
		s.Elements = append(s.Elements, r.bytes(int(r.u8())))
	}
	return s
}

// dnp3Descriptor reads the descriptor elements that fill an object.
func dnp3Descriptor(r *dnp3Reader) DNP3Value {
	var d DNP3DataSetDescriptor
	for len(r.b) > 0 {
		n := int(r.u8())
		if n < dnp3DescElemMin {
			r.short = true
			break
		}

		e := DNP3DescriptorElement{Code: DNP3DescriptorCode(r.u8()), Type: DNP3AttrType(r.u8()), MaxLength: r.u8()}
		e.Ancillary = r.bytes(n - dnp3DescElemMin)
		d.Elements = append(d.Elements, e)
	}
	return d
}

// dnp3AppID reads a g90v1 application identifier: its name fills the
// object.
func dnp3AppID(r *dnp3Reader, v uint8) DNP3Value {
	if v != 1 {
		return nil
	}
	return DNP3AppID{Name: string(r.rest())}
}

// dnp3Activate reads a g91v1 status of requested operation.
func dnp3Activate(r *dnp3Reader, v uint8) DNP3Value {
	if v != 1 {
		return nil
	}

	s := DNP3ActivateStatus{Delay: time.Duration(r.u32()) * time.Millisecond}
	n := r.list(int(r.u8()), dnp3StatusElemMin+1)
	s.Statuses = make([]DNP3OperationStatus, 0, n)
	for i := 0; i < n; i++ {
		size := int(r.u8())
		if size < dnp3StatusElemMin {
			r.short = true
			break
		}
		s.Statuses = append(s.Statuses, DNP3OperationStatus{Status: r.u8(), Ancillary: r.bytes(size - dnp3StatusElemMin)})
	}
	return s
}

// dnp3BCD reads g101v1 to v3: 2, 4 or 8 octets.
func dnp3BCD(r *dnp3Reader, v uint8) DNP3Value {
	switch v {
	case 1:
		return DNP3BCD{Raw: uint64(r.u16()), Digits: 4}
	case 2:
		return DNP3BCD{Raw: uint64(r.u32()), Digits: 8}
	case 3:
		return DNP3BCD{Raw: r.u64(), Digits: 16}
	}
	return nil
}

// Security statistic variations.
const (
	dnp3StatVar     = 1
	dnp3StatTimeVar = 2 // g122 only
)

// dnp3SecStat reads g121v1, g122v1 and g122v2.
func dnp3SecStat(r *dnp3Reader, g DNP3Group, v uint8) DNP3Value {
	timed := g == DNP3GroupSecurityStatEvent && v == dnp3StatTimeVar
	if v != dnp3StatVar && !timed {
		return nil
	}

	s := DNP3SecurityStat{Flags: DNP3Flags{Family: DNP3FlagsCounter, Raw: r.u8()}, Association: r.u16(), Value: r.u32()}
	if timed {
		s.Time = r.stamp(DNP3TimeAbsolute)
	}
	return s
}

// Update key variations of secure authentication (g120).
const (
	dnp3AuthUserCertVar   = 8
	dnp3AuthUserStatVar   = 10
	dnp3AuthUpdKeyReqVar  = 11
	dnp3AuthUpdKeyRepVar  = 12
	dnp3AuthUpdKeyVar     = 13
	dnp3AuthUpdKeySigVar  = 14
	dnp3AuthUpdKeyConfVar = 15
)

// dnp3AuthUpdate reads the user and update key objects g120v8 and v10
// to v15. Lengths lead the data they size, as in g120v5.
func dnp3AuthUpdate(r *dnp3Reader, v uint8) DNP3Value {
	switch v {
	case dnp3AuthUserCertVar:
		return DNP3AuthUserCert{Method: r.u8(), CertType: r.u8(), Certificate: r.rest()}
	case dnp3AuthUserStatVar:
		s := DNP3AuthUserStatus{Method: r.u8(), Operation: r.u8(), Seq: r.u32(), Role: r.u16(), RoleExpiry: r.u16()}
		name, key, cert := r.u16(), r.u16(), r.u16()
		s.UserName = string(r.bytes(int(name)))
		s.PublicKey = r.bytes(int(key))
		s.CertData = r.bytes(int(cert))
		return s
	case dnp3AuthUpdKeyReqVar:
		q := DNP3AuthUpdateKeyReq{Method: r.u8()}
		name, chal := r.u16(), r.u16()
		q.UserName = string(r.bytes(int(name)))
		q.Challenge = r.bytes(int(chal))
		return q
	case dnp3AuthUpdKeyRepVar:
		p := DNP3AuthUpdateKeyReply{Seq: r.u32(), User: r.u16()}
		p.Challenge = r.bytes(int(r.u16()))
		return p
	case dnp3AuthUpdKeyVar:
		k := DNP3AuthUpdateKey{Seq: r.u32(), User: r.u16()}
		k.KeyData = r.bytes(int(r.u16()))
		return k
	case dnp3AuthUpdKeySigVar:
		return DNP3AuthSignature{Signature: r.rest()}
	case dnp3AuthUpdKeyConfVar:
		return DNP3AuthMAC{MAC: r.rest()}
	}
	return nil
}
