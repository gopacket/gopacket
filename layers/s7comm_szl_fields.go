// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import "encoding/binary"

// SZL records as named fields. S7CommSZL.Fields splits a record of any
// SZL ID and index Wireshark 4.7 decodes; the typed views in
// s7comm_szl.go cover the common ones.
//
//	ID                    index           content
//	0000                  any             SZL IDs the module knows
//	0011, 0111            any             module identification
//	0012, 0112            any             CPU characteristic
//	0013, 0113            0               user memory areas
//	0014, 0114            any             system areas
//	0015, 0115            any             block types
//	001C, 011C-031C       any             component identification
//	0222                  any             interrupt status
//	0124, 0424            0               mode transition
//	0131                  1-9, 0x10       communication capabilities
//	0132                  1,2,4,5,6,8,B,C communication status
//	0019, 0119, 0074, 0174 any            LED status
//	0076, 0077, 0078      any             DNN nodes of R/H CPUs
//	xy91 (0-5,9,A,C,D,E; 4C)  any         module status
//	xy92 (0-6; 40,42,46)  any             rack and station status
//	xy94 (0,1,2,6,7)      any             station status
//	0696, 0C96            any             PROFINET module status
//	xyA0 (0,1,4-E)        any             diagnostic buffer
//
// Field names are the ones of the Siemens SZL description (index, anz,
// mlfb, ...). A field is never smaller than the octets it is read
// from: octets holding flags are single fields with their bits not
// split, and the words of 0131 index 8 keep their time value (bits
// 0-11) and time base (bits 12-15) together.

const (
	s7commSZLStationLen   = 256 // station status bitmap of xy94
	s7commSZLStatusOctets = 16  // station status octets of xy92
	s7commSZLDNNVersion   = 5   // only version of xy78 with a known layout
	s7commSZLCDiagLen     = 28  // component diagnostic entry of xy78
	s7commSZLWordLen      = 2
)

// Fields returns record i split into named fields, or nil when i is
// out of range, the SZL ID and index have no known layout, or the
// record is shorter than its layout. It allocates on each call and
// decodes nothing ahead of it.
func (z *S7CommSZL) Fields(i int) []S7CommField {
	if i < 0 || i >= len(z.Records) {
		return nil
	}
	r := z.Records[i]

	if defs := z.fieldDefs(r); defs != nil {
		return s7commFixedFields(defs, r)
	}
	return z.varFields(r)
}

// fieldDefs returns the fixed layout of the SZL ID and index, or nil.
// r is the record: component identification picks its layout by the
// record's own index.
func (z *S7CommSZL) fieldDefs(r []byte) []s7commFieldDef {
	switch z.ID {
	case 0x0000:
		return s7commSZLxy00
	case 0x0011, 0x0111:
		return s7commSZLxy11
	case 0x0012, 0x0112:
		return s7commSZLxy12
	case 0x0013, 0x0113:
		return s7commSZLIfIndex0(z.Index, s7commSZL0013)
	case 0x0014, 0x0114:
		return s7commSZLxy14
	case 0x0015, 0x0115:
		return s7commSZLxy15
	case 0x001C, 0x011C, 0x021C, 0x031C:
		return s7commSZLCompDefs(r)
	case 0x0222:
		return s7commSZLxy22
	case 0x0124, 0x0424:
		return s7commSZLIfIndex0(z.Index, s7commSZLxy24)
	case s7commSZLCommCaps:
		return s7commSZL0131Defs(z.Index)
	case s7commSZLCommStatus:
		return s7commSZL0132Defs(z.Index)
	case 0x0019, 0x0119, 0x0074, 0x0174:
		return s7commSZLxy74
	case 0x0076:
		return s7commSZLxy76
	case 0x0091, 0x0191, 0x0291, 0x0391, 0x0491, 0x0591, 0x0991, 0x0A91, 0x0C91, 0x4C91, 0x0D91, 0x0E91:
		return s7commSZLxy91
	case 0x0092, 0x0192, 0x0292, 0x0392, 0x0492, 0x0592, 0x0692, 0x4092, 0x4292, 0x4692:
		return s7commSZLxy92
	case 0x0094, 0x0194, 0x0294, 0x0694, 0x0794:
		return s7commSZLxy94
	case 0x0696, 0x0C96:
		return s7commSZLxy96
	case 0x00A0, 0x01A0, 0x04A0, 0x05A0, 0x06A0, 0x07A0, 0x08A0, 0x09A0, 0x0AA0, 0x0BA0, 0x0CA0, 0x0DA0, 0x0EA0:
		return s7commSZLxyA0
	}
	return nil
}

// s7commSZLIfIndex0 returns defs for index 0 only.
func s7commSZLIfIndex0(index uint16, defs []s7commFieldDef) []s7commFieldDef {
	if index != 0 {
		return nil
	}
	return defs
}

// s7commSZL0131Defs returns the 0x0131 layout of an index.
func s7commSZL0131Defs(index uint16) []s7commFieldDef {
	switch index {
	case 0x0001:
		return s7commSZL0131x1
	case 0x0002:
		return s7commSZL0131x2
	case 0x0003:
		return s7commSZL0131x3
	case 0x0004:
		return s7commSZL0131x4
	case 0x0005:
		return s7commSZL0131x5
	case 0x0006:
		return s7commSZL0131x6
	case 0x0007:
		return s7commSZL0131x7
	case 0x0008:
		return s7commSZL0131x8
	case 0x0009:
		return s7commSZL0131x9
	case 0x0010:
		return s7commSZL0131x10
	}
	return nil
}

// s7commSZL0132Defs returns the 0x0132 layout of an index.
func s7commSZL0132Defs(index uint16) []s7commFieldDef {
	switch index {
	case 0x0001:
		return s7commSZL0132x1
	case 0x0002:
		return s7commSZL0132x2
	case 0x0004:
		return s7commSZL0132x4
	case 0x0005:
		return s7commSZL0132x5
	case 0x0006:
		return s7commSZL0132x6
	case 0x0008:
		return s7commSZL0132x8
	case 0x000B:
		return s7commSZL0132xB
	case 0x000C:
		return s7commSZL0132xC
	}
	return nil
}

// s7commSZLCompDefs returns the component identification layout for
// the index a record starts with. H-CPUs set upper index bits to name
// the CPU, so only the low nibble selects.
func s7commSZLCompDefs(r []byte) []s7commFieldDef {
	if len(r) < s7commSZLHeadLen {
		return nil
	}

	switch binary.BigEndian.Uint16(r) & s7commSZLCompIdxMask {
	case 0x1, 0x2:
		return s7commSZLxy1CName
	case 0x3:
		return s7commSZLxy1CTag
	case 0x4:
		return s7commSZLxy1CCopyright
	case 0x5:
		return s7commSZLxy1CSerial
	case 0x7:
		return s7commSZLxy1CCPUType
	case 0x8:
		return s7commSZLxy1CCard
	case s7commSZLCompProfile:
		return s7commSZLxy1CProfile
	case s7commSZLCompOEM:
		return s7commSZLxy1COEM
	case 0xB:
		return s7commSZLxy1CLocation
	}
	return s7commSZLxy1COther
}

// varFields splits the records whose size follows from their content:
// the DNN relations (0x0077) and DNN diagnostics (0x0078) of R/H CPUs.
func (z *S7CommSZL) varFields(r []byte) []S7CommField {
	switch z.ID {
	case 0x0077:
		return s7commSZLRelations(r)
	case 0x0078:
		return s7commSZLDNNDiag(r)
	}
	return nil
}

// s7commSZLRelations splits a 0x0077 record: version, then the parent,
// child, redundancy and IO device agent node lists.
func s7commSZLRelations(r []byte) []S7CommField {
	c := &s7commFieldCursor{rest: r}
	c.word("version")
	c.list("num_parent", "obj_parent")
	c.list("num_child", "obj_child")
	c.list("num_redundancy_links", "obj_redundancy")
	c.list("num_iodevice_agent_links", "obj_iodevice_agent")
	return c.done()
}

// s7commSZLDNNDiag splits a 0x0078 record of version 5:
//
//	version, geo address (5 words), name(32), short name(32), mode,
//	diagnostic count, entries (28 each), states, vendor, order ID(20),
//	I&M1 function(32) and location(22), asset ID(32), [TLV count, TLVs]
//
// Another version yields the version and the rest as one field.
func s7commSZLDNNDiag(r []byte) []S7CommField {
	c := &s7commFieldCursor{rest: r}
	if c.word("version") != s7commSZLDNNVersion {
		c.take("unknown_version_data", len(c.rest), s7commEncOct)
		return c.done()
	}

	for _, name := range []string{"subsys", "station", "rack", "slot", "subslot"} {
		c.word(name)
	}
	c.take("name", 32, s7commEncStr)
	c.take("short_name", 32, s7commEncStr)
	c.word("dnn_mode")

	n := int(c.word("num_cdiag"))
	if c.short || n*s7commSZLCDiagLen > len(c.rest) {
		return nil
	}
	for k := 0; k < n; k++ {
		c.cdiag()
	}

	c.take("comp_state_detail", 4, s7commEncLE)
	for _, name := range []string{"io_state", "res"} {
		c.word(name)
	}
	c.take("maint_state", 4, s7commEncLE)
	for _, name := range []string{"operating_state", "own_state", "sub_ord_io_state", "sub_ord_state",
		"disp_own_state", "disp_sub_ord_state", "disp_mode"} {
		c.word(name)
	}
	c.take("vendor", 2, s7commEncBE)
	c.take("order_id", 20, s7commEncStr)
	c.take("iam1_function", 32, s7commEncStr)
	c.take("iam1_location", 22, s7commEncStr)
	c.take("asset_id", 32, s7commEncStr)
	if c.short || len(c.rest) == 0 {
		return c.done()
	}

	// Optional TLVs: the count is the low octet of a 16 bit field.
	tlvs := int(c.word("tlv_num") & 0xFF)
	for k := 0; k < tlvs && !c.short; k++ {
		c.take("tlv_type", 1, s7commEncLE)
		if size := int(c.take("tlv_len", 1, s7commEncLE)); size > 0 {
			c.take("tlv_data", size, s7commEncOct)
		}
	}
	return c.done()
}

// cdiag reads one component diagnostic entry of a 0x0078 record.
func (c *s7commFieldCursor) cdiag() {
	for _, name := range []string{"ch_nr", "ch_prop", "alcat", "cdiag_res"} {
		c.word(name)
	}
	c.take("qualifier", 4, s7commEncLE)
	for _, name := range []string{"chet", "text_list_chet", "echet", "text_list_echet",
		"add_val_0", "add_val_1", "add_val_2", "add_val_3"} {
		c.word(name)
	}
}

// Layouts not generated from one flat field list.
var (
	// 0000: one SZL ID per record.
	s7commSZLxy00 = []s7commFieldDef{{"szl_id", 2, s7commEncBE}}

	// xy12: one CPU characteristic per record.
	s7commSZLxy12 = []s7commFieldDef{{"charac", 2, s7commEncBE}}

	// xy1C: component identification, by index.
	s7commSZLxy1CName = []s7commFieldDef{
		{"index", 2, s7commEncBE}, {"name", 24, s7commEncStr}, {"res", 8, s7commEncOct},
	}
	s7commSZLxy1CTag = []s7commFieldDef{{"index", 2, s7commEncBE}, {"tag", 32, s7commEncStr}}

	s7commSZLxy1CCopyright = []s7commFieldDef{
		{"index", 2, s7commEncBE}, {"copyright", 26, s7commEncStr}, {"res", 6, s7commEncOct},
	}
	s7commSZLxy1CSerial = []s7commFieldDef{
		{"index", 2, s7commEncBE}, {"serialn", 24, s7commEncStr}, {"res", 8, s7commEncOct},
	}
	s7commSZLxy1CCPUType = []s7commFieldDef{{"index", 2, s7commEncBE}, {"cputypname", 32, s7commEncStr}}
	s7commSZLxy1CCard    = []s7commFieldDef{{"index", 2, s7commEncBE}, {"snmcmmc", 32, s7commEncStr}}

	s7commSZLxy1CProfile = []s7commFieldDef{
		{"index", 2, s7commEncBE}, {"manufacturer_id", 2, s7commEncBE}, {"profile_id", 2, s7commEncBE},
		{"profile_spec_typ", 2, s7commEncBE}, {"res", 26, s7commEncOct},
	}
	s7commSZLxy1COEM = []s7commFieldDef{
		{"index", 2, s7commEncBE}, {"oem_copyright_string", 26, s7commEncStr},
		{"oem_id", 2, s7commEncBE}, {"oem_add_id", 4, s7commEncBE},
	}
	s7commSZLxy1CLocation = []s7commFieldDef{{"index", 2, s7commEncBE}, {"loc_id", 32, s7commEncStr}}
	s7commSZLxy1COther    = []s7commFieldDef{{"index", 2, s7commEncBE}, {"res", 32, s7commEncOct}}

	// xy91: module status.
	s7commSZLxy91 = []s7commFieldDef{
		{"adr1", 2, s7commEncBE}, {"adr2", 2, s7commEncBE}, {"logadr", 2, s7commEncBE},
		{"solltyp", 2, s7commEncBE}, {"isttyp", 2, s7commEncBE}, {"res1", 2, s7commEncBE},
		{"eastat", 2, s7commEncBE}, {"berbgbr", 2, s7commEncBE},
	}

	// xy92: one bit per rack or station, 16 octets.
	s7commSZLxy92 = []s7commFieldDef{{"status", s7commSZLStatusOctets, s7commEncOct}}

	// xy94: index, then one bit per station, bit 0 a group flag.
	s7commSZLxy94 = []s7commFieldDef{{"index", 2, s7commEncBE}, {"status", s7commSZLStationLen, s7commEncOct}}

	// xyA0: diagnostic buffer entry.
	s7commSZLxyA0 = []s7commFieldDef{
		{"eventid", 2, s7commEncBE}, {"prioclass", 1, s7commEncBE}, {"obnumber", 1, s7commEncBE},
		{"datid", 2, s7commEncBE}, {"info1", 2, s7commEncBE}, {"info2", 4, s7commEncBE},
		{"time", s7commBCDShortLen, s7commEncOct},
	}
)

// Layouts taken field by field from the Wireshark 4.7 S7comm dissector.
// xy13: user memory areas.
var s7commSZL0013 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"code", 2, s7commEncBE},
	{"size", 4, s7commEncBE},
	{"mode", 2, s7commEncBE},
	{"granu", 2, s7commEncBE},
	{"ber1", 4, s7commEncBE},
	{"belegt1", 4, s7commEncBE},
	{"block1", 4, s7commEncBE},
	{"ber2", 4, s7commEncBE},
	{"belegt2", 4, s7commEncBE},
	{"block2", 4, s7commEncBE},
}

// xy14: system areas.
var s7commSZLxy14 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"code", 2, s7commEncBE},
	{"quantity", 2, s7commEncBE},
	{"reman", 2, s7commEncBE},
}

// xy15: block types.
var s7commSZLxy15 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"maxanz", 2, s7commEncBE},
	{"maxlng", 2, s7commEncBE},
	{"maxabl", 4, s7commEncBE},
}

// xy11: module identification.
var s7commSZLxy11 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"mlfb", 20, s7commEncStr},
	{"bgtyp", 2, s7commEncBE},
	{"ausbg", 2, s7commEncBE},
	{"ausbe", 2, s7commEncBE},
}

// xy22: interrupt status.
var s7commSZLxy22 = []s7commFieldDef{
	{"info", 20, s7commEncOct},
	{"al1", 2, s7commEncBE},
	{"al2", 2, s7commEncBE},
	{"al3", 4, s7commEncBE},
}

// 0131 index 1: communication capability.
var s7commSZL0131x1 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"pdu", 2, s7commEncBE},
	{"anz", 2, s7commEncBE},
	{"mpi_bps", 4, s7commEncBE},
	{"kbus_bps", 4, s7commEncBE},
	{"res", 26, s7commEncOct},
}

// 0131 index 2: test and installation.
var s7commSZL0131x2 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"funkt_0", 1, s7commEncBE},
	{"funkt_1", 1, s7commEncBE},
	{"funkt_2", 1, s7commEncBE},
	{"funkt_3", 1, s7commEncBE},
	{"funkt_4", 1, s7commEncBE},
	{"funkt_5", 1, s7commEncBE},
	{"aseg", 6, s7commEncOct},
	{"eseg", 6, s7commEncOct},
	{"trgereig_0", 1, s7commEncBE},
	{"trgereig_1", 1, s7commEncBE},
	{"trgereig_2", 1, s7commEncBE},
	{"trgbed", 1, s7commEncBE},
	{"pfad", 1, s7commEncBE},
	{"tiefe", 1, s7commEncBE},
	{"systrig", 1, s7commEncBE},
	{"erg_par", 1, s7commEncBE},
	{"erg_pat_1", 2, s7commEncBE},
	{"erg_pat_2", 2, s7commEncBE},
	{"force", 2, s7commEncBE},
	{"time", 2, s7commEncBE},
	{"res", 4, s7commEncBE},
}

// 0131 index 3: operator interface.
var s7commSZL0131x3 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"funkt_0", 1, s7commEncBE},
	{"funkt_1", 1, s7commEncBE},
	{"funkt_2", 1, s7commEncBE},
	{"funkt_3", 1, s7commEncBE},
	{"data", 2, s7commEncBE},
	{"anz", 2, s7commEncBE},
	{"per_min", 2, s7commEncBE},
	{"per_max", 2, s7commEncBE},
	{"res", 26, s7commEncOct},
}

// 0131 index 4: object management.
var s7commSZL0131x4 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"funkt_0", 1, s7commEncBE},
	{"funkt_1", 1, s7commEncBE},
	{"funkt_2", 1, s7commEncBE},
	{"funkt_3", 1, s7commEncBE},
	{"funkt_4", 1, s7commEncBE},
	{"funkt_5", 1, s7commEncBE},
	{"funkt_6", 1, s7commEncBE},
	{"funkt_7", 1, s7commEncBE},
	{"kop", 1, s7commEncBE},
	{"del", 1, s7commEncBE},
	{"kett", 1, s7commEncBE},
	{"hoch", 1, s7commEncBE},
	{"ver", 1, s7commEncBE},
	{"res", 25, s7commEncOct},
}

// 0131 index 5: diagnostics.
var s7commSZL0131x5 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"funkt_0", 1, s7commEncBE},
	{"funkt_1", 1, s7commEncBE},
	{"funkt_2", 1, s7commEncBE},
	{"funkt_3", 1, s7commEncBE},
	{"funkt_4", 1, s7commEncBE},
	{"funkt_5", 1, s7commEncBE},
	{"funkt_6", 1, s7commEncBE},
	{"funkt_7", 1, s7commEncBE},
	{"anz_sen", 2, s7commEncBE},
	{"anz_ein", 2, s7commEncBE},
	{"anz_mel", 2, s7commEncBE},
	{"res", 24, s7commEncOct},
}

// 0131 index 6: data exchange.
var s7commSZL0131x6 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"funkt_0", 1, s7commEncBE},
	{"funkt_1", 1, s7commEncBE},
	{"funkt_2", 1, s7commEncBE},
	{"funkt_3", 1, s7commEncBE},
	{"funkt_4", 1, s7commEncBE},
	{"funkt_5", 1, s7commEncBE},
	{"funkt_6", 1, s7commEncBE},
	{"funkt_7", 1, s7commEncBE},
	{"schnell", 1, s7commEncBE},
	{"zugtyp_0", 1, s7commEncBE},
	{"zugtyp_1", 1, s7commEncBE},
	{"zugtyp_2", 1, s7commEncBE},
	{"zugtyp_3", 1, s7commEncBE},
	{"zugtyp_4", 1, s7commEncBE},
	{"zugtyp_5", 1, s7commEncBE},
	{"zugtyp_6", 1, s7commEncBE},
	{"zugtyp_7", 1, s7commEncBE},
	{"res1", 1, s7commEncOct},
	{"max_sd_empf", 2, s7commEncBE},
	{"max_sd_al8p", 2, s7commEncBE},
	{"max_inst", 2, s7commEncBE},
	{"res2", 2, s7commEncOct},
	{"verb_proj", 1, s7commEncBE},
	{"verb_prog", 1, s7commEncBE},
	{"res3", 10, s7commEncOct},
}

// 0131 index 7: global data.
var s7commSZL0131x7 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"funkt_0", 1, s7commEncBE},
	{"funkt_1", 1, s7commEncBE},
	{"obj_0", 1, s7commEncBE},
	{"obj_1", 1, s7commEncBE},
	{"kons", 1, s7commEncBE},
	{"sen", 1, s7commEncBE},
	{"rec", 1, s7commEncBE},
	{"time", 1, s7commEncBE},
	{"proj", 1, s7commEncBE},
	{"alarm", 1, s7commEncBE},
	{"mode", 1, s7commEncBE},
	{"kreis", 1, s7commEncBE},
	{"sk_1", 1, s7commEncBE},
	{"sk_2", 1, s7commEncBE},
	{"ek_1", 1, s7commEncBE},
	{"ek_2", 1, s7commEncBE},
	{"len_1", 1, s7commEncBE},
	{"len_2", 1, s7commEncBE},
	{"len_3", 1, s7commEncBE},
	{"res", 19, s7commEncOct},
}

// 0131 index 8: test and installation time base.
var s7commSZL0131x8 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"last_1", 2, s7commEncBE},
	{"last_2", 2, s7commEncBE},
	{"last_3", 2, s7commEncBE},
	{"merker", 2, s7commEncBE},
	{"ea", 2, s7commEncBE},
	{"tz", 2, s7commEncBE},
	{"db", 2, s7commEncBE},
	{"ld", 2, s7commEncBE},
	{"reg", 2, s7commEncBE},
	{"ba_stali1", 2, s7commEncBE},
	{"ba_stali2", 2, s7commEncBE},
	{"ba_stali3", 2, s7commEncBE},
	{"akku", 2, s7commEncBE},
	{"address", 2, s7commEncBE},
	{"dbreg", 2, s7commEncBE},
	{"res", 8, s7commEncOct},
}

// 0131 index 9: time of day.
var s7commSZL0131x9 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"sync_k", 1, s7commEncBE},
	{"sync_mpi", 1, s7commEncBE},
	{"sync_mfi", 1, s7commEncBE},
	{"res1", 1, s7commEncBE},
	{"abw_puf", 2, s7commEncBE},
	{"abw_5v", 2, s7commEncBE},
	{"anz_bsz", 2, s7commEncBE},
	{"res2", 28, s7commEncOct},
}

// 0131 index 0x10: message parameters.
var s7commSZL0131x10 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"funk_1", 1, s7commEncBE},
	{"funk_2", 1, s7commEncBE},
	{"ber_meld_1", 1, s7commEncBE},
	{"ber_meld_2", 1, s7commEncBE},
	{"ber_zus_1", 1, s7commEncBE},
	{"ber_zus_2", 1, s7commEncBE},
	{"typ_zus_1", 1, s7commEncBE},
	{"typ_zus_2", 1, s7commEncBE},
	{"maxanz_arch", 2, s7commEncBE},
	{"res", 28, s7commEncOct},
}

// 0132 index 1: communication status.
var s7commSZL0132x1 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"res_pg", 2, s7commEncBE},
	{"res_os", 2, s7commEncBE},
	{"u_pg", 2, s7commEncBE},
	{"u_os", 2, s7commEncBE},
	{"proj", 2, s7commEncBE},
	{"auf", 2, s7commEncBE},
	{"free", 2, s7commEncBE},
	{"used", 2, s7commEncBE},
	{"last", 2, s7commEncBE},
	{"res", 20, s7commEncOct},
}

// 0132 index 2: test and installation status.
var s7commSZL0132x2 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"anz", 2, s7commEncBE},
	{"res", 36, s7commEncOct},
}

// 0132 index 4: protection.
var s7commSZL0132x4 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"key", 2, s7commEncBE},
	{"param", 2, s7commEncBE},
	{"real", 2, s7commEncBE},
	{"bart_sch", 2, s7commEncBE},
	{"crst_wrst", 2, s7commEncBE},
	{"ken_f", 2, s7commEncBE},
	{"ken_rel", 2, s7commEncBE},
	{"ken_ver1_hw", 2, s7commEncLE},
	{"ken_ver2_hw", 2, s7commEncLE},
	{"ken_ver1_awp", 2, s7commEncLE},
	{"ken_ver2_awp", 2, s7commEncLE},
	{"res", 16, s7commEncOct},
}

// 0132 index 5: diagnostics status.
var s7commSZL0132x5 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"erw", 2, s7commEncBE},
	{"send", 2, s7commEncBE},
	{"moeg", 2, s7commEncBE},
	{"ltmerz", 2, s7commEncBE},
	{"res", 30, s7commEncOct},
}

// 0132 index 6: data exchange status.
var s7commSZL0132x6 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"used_0", 1, s7commEncOct},
	{"used_1", 1, s7commEncOct},
	{"used_2", 1, s7commEncOct},
	{"used_3", 1, s7commEncOct},
	{"used_4", 1, s7commEncOct},
	{"used_5", 1, s7commEncOct},
	{"used_6", 1, s7commEncOct},
	{"used_7", 1, s7commEncOct},
	{"anz_schnell", 1, s7commEncBE},
	{"anz_inst", 2, s7commEncBE},
	{"anz_multicast", 2, s7commEncBE},
	{"res", 25, s7commEncOct},
}

// 0132 index 8: time system.
var s7commSZL0132x8 = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"zykl", 2, s7commEncBE},
	{"korr", 2, s7commEncBE},
	{"clock0", 2, s7commEncBE},
	{"clock1", 2, s7commEncBE},
	{"clock2", 2, s7commEncBE},
	{"clock3", 2, s7commEncBE},
	{"clock4", 2, s7commEncBE},
	{"clock5", 2, s7commEncBE},
	{"clock6", 2, s7commEncBE},
	{"clock7", 2, s7commEncBE},
	{"time", 8, s7commEncOct},
	{"res", 10, s7commEncOct},
}

// 0132 index 0xB: run-time meters 0-7.
var s7commSZL0132xB = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"bszl_0", 1, s7commEncBE},
	{"bszl_1", 1, s7commEncBE},
	{"bszu_0", 1, s7commEncBE},
	{"bszu_1", 1, s7commEncBE},
	{"clock0", 4, s7commEncBE},
	{"clock1", 4, s7commEncBE},
	{"clock2", 4, s7commEncBE},
	{"clock3", 4, s7commEncBE},
	{"clock4", 4, s7commEncBE},
	{"clock5", 4, s7commEncBE},
	{"clock6", 4, s7commEncBE},
	{"clock7", 4, s7commEncBE},
	{"res", 2, s7commEncOct},
}

// 0132 index 0xC: run-time meters 8-15.
var s7commSZL0132xC = []s7commFieldDef{
	{"index", 2, s7commEncBE},
	{"bszl_0", 1, s7commEncBE},
	{"bszl_1", 1, s7commEncBE},
	{"bszu_0", 1, s7commEncBE},
	{"bszu_1", 1, s7commEncBE},
	{"clock8", 4, s7commEncBE},
	{"clock9", 4, s7commEncBE},
	{"clock10", 4, s7commEncBE},
	{"clock11", 4, s7commEncBE},
	{"clock12", 4, s7commEncBE},
	{"clock13", 4, s7commEncBE},
	{"clock14", 4, s7commEncBE},
	{"clock15", 4, s7commEncBE},
	{"res", 2, s7commEncOct},
}

// xy74 and xy19: LED status.
var s7commSZLxy74 = []s7commFieldDef{
	{"cpu_led_id", 2, s7commEncBE},
	{"led_on", 1, s7commEncBE},
	{"led_blink", 1, s7commEncBE},
}

// xy76: DNN top node (R/H CPUs).
var s7commSZLxy76 = []s7commFieldDef{
	{"version", 2, s7commEncLE},
	{"top_dnn_id", 2, s7commEncLE},
}

// xy96: PROFINET module status.
var s7commSZLxy96 = []s7commFieldDef{
	{"logadr", 2, s7commEncBE},
	{"system", 2, s7commEncBE},
	{"api", 4, s7commEncBE},
	{"station", 2, s7commEncBE},
	{"slot", 2, s7commEncBE},
	{"subslot", 2, s7commEncBE},
	{"offset", 2, s7commEncBE},
	{"solltyp1", 2, s7commEncBE},
	{"solltyp2", 2, s7commEncBE},
	{"solltyp3", 2, s7commEncBE},
	{"solltyp4_5", 4, s7commEncBE},
	{"solltyp6_7", 4, s7commEncBE},
	{"expactid", 2, s7commEncBE},
	{"reserve1", 2, s7commEncBE},
	{"eastat", 2, s7commEncBE},
	{"berbgbr", 2, s7commEncBE},
	{"reserve2", 10, s7commEncOct},
}

// xy24: mode transition.
var s7commSZLxy24 = []s7commFieldDef{
	{"ereig", 2, s7commEncBE},
	{"ae", 1, s7commEncBE},
	{"bzu_id", 1, s7commEncBE},
	{"res", 4, s7commEncOct},
	{"anlinfo1", 1, s7commEncBE},
	{"anlinfo2", 1, s7commEncBE},
	{"anlinfo3", 1, s7commEncBE},
	{"anlinfo4", 1, s7commEncBE},
	{"time", 8, s7commEncOct},
}
