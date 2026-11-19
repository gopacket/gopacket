// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

// Programmer command parameters and the data of the services without
// a typed view, as named fields (S7CommTIS.ParamFields, DataFields):
//
//	0x01, 0x13  block status           request lines, indication
//	0x03        output ISTACK          registers, OB start info
//	0x04        output BSTACK          one 16-octet entry per block
//	0x05        output LSTACK          local data of one block
//	0x0A        breakpoint             registers at the breakpoint
//	0x0B        exit HOLD
//	0x0D-0x12   disable, enable, delete, list, read, replace job
//
// Layouts follow the Wireshark 4.7 S7comm dissector. Octets holding
// flags are single fields. Timestamps are 8 BCD octets named "time".

// More subfunctions of the programmer commands group.
const (
	S7CommTISBlockStat   S7CommSubfunction = 0x01
	S7CommTISIStack      S7CommSubfunction = 0x03
	S7CommTISBStack      S7CommSubfunction = 0x04
	S7CommTISLStack      S7CommSubfunction = 0x05
	S7CommTISBreakpoint  S7CommSubfunction = 0x0A
	S7CommTISExitHold    S7CommSubfunction = 0x0B
	S7CommTISDisableJob  S7CommSubfunction = 0x0D
	S7CommTISEnableJob   S7CommSubfunction = 0x0E
	S7CommTISDeleteJob   S7CommSubfunction = 0x0F
	S7CommTISReadJobList S7CommSubfunction = 0x10
	S7CommTISReadJob     S7CommSubfunction = 0x11
	S7CommTISReplaceJob  S7CommSubfunction = 0x12
	S7CommTISBlockStat2  S7CommSubfunction = 0x13
)

const (
	// Request parameter sizes from which further fields are present.
	s7commTISParamBase    = 4
	s7commTISParamTrigger = 20
	s7commTISParamBlock   = 26
	s7commTISParamSAZ     = 28
	s7commTISParamCall    = 36
	s7commTISParamCallAdr = 38

	// Call environment selecting the DB register condition.
	s7commTISCallEnvDB = 2

	// A replace job holds another job; Wireshark stops at 8 levels.
	s7commTISMaxNest = 8

	s7commTISBStackLen  = 16 // BSTACK entry
	s7commTISJobListLen = 4  // job list entry
	s7commTISOBInfoLen  = 12 // OB start info of the ISTACK
	s7commTISOBNumAt    = 3  // OB number within the start info
)

// ParamFields returns the parameter part split into named fields, or
// nil when it is empty or shorter than its layout.
func (t *S7CommTIS) ParamFields() []S7CommField {
	if len(t.Param) == 0 {
		return nil
	}

	c := &s7commFieldCursor{rest: t.Param}
	c.tisParam(t.typ)
	return c.done()
}

// DataFields returns the data part split into named fields for the
// services listed in s7comm_ud_tis_fields.go. It is nil for other
// services, including variable status, modify and force (see
// Addresses, Values and Results), and when the data is shorter than
// its layout.
func (t *S7CommTIS) DataFields() []S7CommField {
	if len(t.Body) == 0 {
		return nil
	}

	c := &s7commFieldCursor{rest: t.Body}
	if !c.tisData(t.typ, t.sub, 0) {
		return nil
	}
	return c.done()
}

// tisParam reads the parameter part. A request grows with the job it
// sets up; anything else holds two words.
func (c *s7commFieldCursor) tisParam(typ S7CommUserdataType) {
	if typ != S7CommUDTypeRequest {
		c.be("res_param1", 2)
		c.be("res_param2", 2)
		return
	}

	size := len(c.rest)
	if size >= s7commTISParamBase {
		c.defs(s7commTISParamHead)
	}
	if size >= s7commTISParamTrigger {
		c.defs(s7commTISParamTrig)
	}
	if size >= s7commTISParamBlock {
		c.defs(s7commTISParamBlk)
	}
	if size >= s7commTISParamSAZ {
		c.be("saz", 2)
	}
	if size < s7commTISParamCall {
		return
	}

	env := c.be("callenv", 2)
	c.be("callcond", 2)
	if env == s7commTISCallEnvDB {
		c.be("db1_nr", 2)
		c.be("db2_nr", 2)
		return
	}
	c.be("callcond_blocktype", 2)
	c.be("callcond_blocknr", 2)
	if size >= s7commTISParamCallAdr {
		c.be("callcond_address", 2)
	}
}

// tisData reads the data part of a service; false if it has no field
// layout. nest counts the replace jobs around it.
func (c *s7commFieldCursor) tisData(typ S7CommUserdataType, sub S7CommSubfunction, nest int) bool {
	req := typ == S7CommUDTypeRequest

	switch sub {
	case S7CommTISBlockStat, S7CommTISBlockStat2:
		c.tisBlockStat(typ, sub)
	case S7CommTISIStack:
		if req {
			c.oct("res", 2)
			break
		}
		c.tisIStack()
	case S7CommTISBStack:
		if req {
			c.oct("res", 2)
			break
		}
		c.tisBStack()
	case S7CommTISLStack:
		c.tisLStack(typ)
	case S7CommTISBreakpoint:
		if req {
			c.oct("res", 2)
			break
		}
		c.defs(s7commTISBreakpointDefs)
	case S7CommTISExitHold:
		if req {
			c.be("exithold_until", 1)
			c.be("exithold_res1", 1)
		}
	case S7CommTISDisableJob, S7CommTISEnableJob, S7CommTISDeleteJob,
		S7CommTISReadJobList, S7CommTISReadJob, S7CommTISReplaceJob:
		c.tisJob(typ, sub, nest)
	default:
		return false
	}
	return true
}

// tisBlockStat reads a block status request (one entry per statement
// line, with the registers to report) or indication.
func (c *s7commFieldCursor) tisBlockStat(typ S7CommUserdataType, sub S7CommSubfunction) {
	size := len(c.rest)
	switch typ {
	case S7CommUDTypeRequest:
	case S7CommUDTypePush:
		c.be("startaddr_awl", 2)
		c.oct("data", len(c.rest))
		return
	default:
		c.oct("res", size)
		return
	}

	// Version 1 has one 2-octet entry per line to the end; version 2
	// counts its 4-octet entries.
	lines := 0
	if sub == S7CommTISBlockStat2 {
		c.be("flagsunknown", 1)
		lines = int(c.be("number_of_lines", 1))
		c.oct("res", 1)
	} else {
		c.oct("res", 1)
		if size >= 2 {
			lines = (size - 2) / 2
		}
	}
	c.be("registerflag", 1)

	for i := 0; i < lines && !c.short; i++ {
		if sub == S7CommTISBlockStat2 {
			c.be("line_address", 2)
		}
		c.oct("res", 1)
		c.be("registerflag", 1)
	}
}

// tisIStack reads an interrupt stack: the registers, then the start
// info of the interrupted OB, laid out by its number, and its time.
func (c *s7commFieldCursor) tisIStack() {
	c.defs(s7commTISIStackDefs)
	if c.short || len(c.rest) < s7commTISOBInfoLen {
		c.short = true
		return
	}

	c.defs(s7commOBInfoDefs(c.rest[s7commTISOBNumAt]))
	c.oct("time", s7commBCDShortLen)
}

// tisBStack reads block stack entries. An OB entry is followed by its
// priority class and start time.
func (c *s7commFieldCursor) tisBStack() {
	for len(c.rest) >= s7commTISBStackLen && !c.short {
		typ := c.be("interrupted_blocktype", 2)
		c.defs(s7commTISBStackDefs)
		if S7CommSubblockType(typ) != S7CommSubblockOB {
			continue
		}

		// Some CPUs cut the last OB entry short.
		if len(c.rest) < 4 {
			return
		}
		c.be("interrupted_prioclass", 1)
		c.oct("res", 1)
		c.oct("res", 2)
		if len(c.rest) < s7commBCDShortLen {
			c.oct("res", len(c.rest))
			return
		}
		c.oct("time", s7commBCDShortLen)
	}
}

// tisLStack reads a local data stack request or reply.
func (c *s7commFieldCursor) tisLStack(typ S7CommUserdataType) {
	if typ == S7CommUDTypeRequest {
		c.be("interrupted_prioclass", 1)
		c.be("nest_depth", 1)
		return
	}

	c.be("interrupted_blocktype", 2)
	c.be("interrupted_blocknr", 2)
	c.be("interrupted_address", 2)
	size := int(c.be("lstack_size", 2))
	c.oct("lstack_data", size)
	c.be("interrupted_prioclass", 1)
	c.oct("res", 1)
	c.oct("res", 2)
	c.oct("time", s7commBCDShortLen)
}

// tisJob reads the job management services.
func (c *s7commFieldCursor) tisJob(typ S7CommUserdataType, sub S7CommSubfunction, nest int) {
	if typ != S7CommUDTypeRequest {
		c.tisJobReply(sub)
		return
	}

	switch sub {
	case S7CommTISDeleteJob:
		c.oct("res", 2)
	case S7CommTISEnableJob, S7CommTISDisableJob, S7CommTISReadJob:
		c.be("job_function", 1)
		c.be("job_seqnr", 1)
	case S7CommTISReadJobList:
		c.oct("res", 2)
		c.oct("res", 2)
	case S7CommTISReplaceJob:
		c.tisReplaceJob(nest)
	}
}

// tisReplaceJob reads a replace job request: the job to replace, then
// the parameter and data of its replacement, itself a job.
func (c *s7commFieldCursor) tisReplaceJob(nest int) {
	c.oct("res", 2)
	sub := S7CommSubfunction(c.be("job_function", 1))
	c.be("job_seqnr", 1)
	pSize := int(c.be("parametersize", 2))
	dSize := int(c.be("datasize", 2))
	if c.short || pSize+dSize > len(c.rest) {
		c.short = true
		return
	}

	// Each part is read by a cursor of its own so that a short part
	// cannot run into the next.
	rest := c.rest
	if pSize > 0 {
		c.rest = rest[:pSize]
		c.tisParam(S7CommUDTypeRequest)
	}
	if dSize > 0 && !c.short {
		c.rest = rest[pSize : pSize+dSize]
		if nest >= s7commTISMaxNest || !c.tisData(S7CommUDTypeRequest, sub, nest+1) {
			c.oct("job_data", len(c.rest))
		}
	}
	c.rest = rest[pSize+dSize:]
}

// tisJobReply reads a job list or a read job reply; the other job
// services answer without data.
func (c *s7commFieldCursor) tisJobReply(sub S7CommSubfunction) {
	switch sub {
	case S7CommTISReadJobList:
		for len(c.rest) >= s7commTISJobListLen {
			c.be("job_function", 1)
			c.be("job_seqnr", 1)
			c.oct("res", 2)
		}
	case S7CommTISReadJob:
		pSize := int(c.be("parametersize", 2))
		dSize := int(c.be("datasize", 2))
		if c.short || pSize+dSize > len(c.rest) {
			c.short = true
			return
		}

		rest := c.rest
		if pSize > 0 {
			c.rest = rest[:pSize]
			c.tisParam(S7CommUDTypeRequest)
		}
		c.rest = rest[pSize:]
		if dSize > 0 && !c.short {
			c.oct("job_data", dSize)
		}
	}
}

// Fixed parts of the programmer command layouts.
var (
	s7commTISParamHead = []s7commFieldDef{{"param1", 2, s7commEncBE}, {"param2", 2, s7commEncBE}}

	s7commTISParamTrig = []s7commFieldDef{
		{"param3", 2, s7commEncBE}, {"answersize", 2, s7commEncBE}, {"param5", 2, s7commEncBE},
		{"param6", 2, s7commEncBE}, {"param7", 2, s7commEncBE}, {"param8", 2, s7commEncBE},
		{"param9", 2, s7commEncBE}, {"trgevent", 2, s7commEncBE},
	}

	s7commTISParamBlk = []s7commFieldDef{
		{"block_type", 2, s7commEncBE}, {"block_num", 2, s7commEncBE}, {"startaddr_awl", 2, s7commEncBE},
	}

	s7commTISIStackDefs = []s7commFieldDef{
		{"continued_blocktype", 2, s7commEncBE}, {"continued_blocknr", 2, s7commEncBE},
		{"continued_address", 2, s7commEncBE},
		{"db1_type", 1, s7commEncBE}, {"db2_type", 1, s7commEncBE},
		{"db1_nr", 2, s7commEncBE}, {"db2_nr", 2, s7commEncBE}, {"res", 4, s7commEncOct},
		{"accu1", 4, s7commEncBE}, {"accu2", 4, s7commEncBE}, {"accu3", 4, s7commEncBE},
		{"accu4", 4, s7commEncBE}, {"ar1", 4, s7commEncBE}, {"ar2", 4, s7commEncBE},
		{"res", 2, s7commEncOct}, {"stw", 2, s7commEncBE},
		{"interrupted_blocktype", 2, s7commEncBE}, {"interrupted_blocknr", 2, s7commEncBE},
		{"interrupted_address", 2, s7commEncBE}, {"res", 2, s7commEncOct}, {"res", 4, s7commEncOct},
	}

	// BSTACK entry after its block type.
	s7commTISBStackDefs = []s7commFieldDef{
		{"interrupted_blocknr", 2, s7commEncBE}, {"interrupted_address", 2, s7commEncBE},
		{"db1_type", 1, s7commEncBE}, {"db2_type", 1, s7commEncBE},
		{"db1_nr", 2, s7commEncBE}, {"db2_nr", 2, s7commEncBE}, {"res", 4, s7commEncOct},
	}

	s7commTISBreakpointDefs = []s7commFieldDef{
		{"interrupted_blocktype", 2, s7commEncBE}, {"interrupted_blocknr", 2, s7commEncBE},
		{"interrupted_address", 2, s7commEncBE},
		{"breakpoint_blocktype", 2, s7commEncBE}, {"breakpoint_blocknr", 2, s7commEncBE},
		{"breakpoint_address", 2, s7commEncBE}, {"res", 2, s7commEncOct}, {"stw", 2, s7commEncBE},
		{"accu1", 4, s7commEncBE}, {"accu2", 4, s7commEncBE}, {"ar1", 4, s7commEncBE}, {"ar2", 4, s7commEncBE},
		{"db1_type", 1, s7commEncBE}, {"db2_type", 1, s7commEncBE},
		{"db1_nr", 2, s7commEncBE}, {"db2_nr", 2, s7commEncBE},
	}
)

// s7commOBInfoDefs returns the start info layout of an OB number.
func s7commOBInfoDefs(ob uint8) []s7commFieldDef {
	switch ob {
	case 1:
		return s7commOBInfo1
	case 10, 11, 12, 13, 14, 15, 16, 17:
		return s7commOBInfo10
	case 20, 21, 22, 23:
		return s7commOBInfo20
	case 30, 31, 32, 33, 34, 35, 36, 37, 38:
		return s7commOBInfo30
	case 40, 41, 42, 43, 44, 45, 46, 47, 48:
		return s7commOBInfo40
	case 55, 56, 57:
		return s7commOBInfo55
	case 80:
		return s7commOBInfo80
	case 81:
		return s7commOBInfo81
	case 82:
		return s7commOBInfo82
	case 83:
		return s7commOBInfo83
	case 84:
		return s7commOBInfo84
	case 85, 87:
		return s7commOBInfo85
	case 86:
		return s7commOBInfo86
	case 90:
		return s7commOBInfo90
	case 100, 101, 102:
		return s7commOBInfo100
	case 121:
		return s7commOBInfo121
	case 122:
		return s7commOBInfo122
	}
	return s7commOBInfoDefault
}

// OB start info layouts, 12 octets each, named as the OB's local
// variables without the OBn_ prefix.
var (
	s7commOBInfo1 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"scan_1", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"prev_cycle", 2, s7commEncBE},
		{"min_cycle", 2, s7commEncBE},
		{"max_cycle", 2, s7commEncBE},
	}
	s7commOBInfo10 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"strt_inf", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"period_exe", 2, s7commEncBE},
		{"reserved_3", 2, s7commEncBE},
		{"reserved_4", 2, s7commEncBE},
	}
	s7commOBInfo20 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"strt_inf", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"sign", 2, s7commEncBE},
		{"dtime", 4, s7commEncBE},
	}
	s7commOBInfo30 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"strt_inf", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"phase_offset", 2, s7commEncBE},
		{"reserved_3", 2, s7commEncBE},
		{"exec_freq", 2, s7commEncBE},
	}
	s7commOBInfo40 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"strt_inf", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"io_flag", 1, s7commEncBE},
		{"mdl_addr", 2, s7commEncBE},
		{"point_addr", 4, s7commEncBE},
	}
	s7commOBInfo55 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"strt_inf", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"io_flag", 1, s7commEncBE},
		{"mdl_addr", 2, s7commEncBE},
		{"inf_len", 1, s7commEncBE},
		{"alarm_type", 1, s7commEncBE},
		{"alarm_slot", 1, s7commEncBE},
		{"alarm_spec", 1, s7commEncBE},
	}
	s7commOBInfo80 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"flt_id", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"error_info", 2, s7commEncBE},
		{"err_ev_class", 1, s7commEncBE},
		{"err_ev_num", 1, s7commEncBE},
		{"err_ob_priority", 1, s7commEncBE},
		{"err_ob_num", 1, s7commEncBE},
	}
	s7commOBInfo81 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"flt_id", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"rack_cpu", 2, s7commEncBE},
		{"reserved_3", 2, s7commEncBE},
		{"reserved_4", 2, s7commEncBE},
	}
	s7commOBInfo82 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"flt_id", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"io_flag", 1, s7commEncBE},
		{"mdl_addr", 2, s7commEncBE},
		{"8x_fault_flags", 1, s7commEncBE},
		{"mdl_type_b", 1, s7commEncBE},
		{"8x_fault_flags", 1, s7commEncBE},
		{"8x_fault_flags", 1, s7commEncBE},
	}
	s7commOBInfo83 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"flt_id", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"io_flag", 1, s7commEncBE},
		{"mdl_addr", 2, s7commEncBE},
		{"rack_num", 2, s7commEncBE},
		{"mdl_type_w", 2, s7commEncBE},
	}
	s7commOBInfo84 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"flt_id", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"reserved_3", 2, s7commEncBE},
		{"reserved_4_dw", 4, s7commEncBE},
	}
	s7commOBInfo85 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"flt_id", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"reserved_3", 2, s7commEncBE},
		{"err_ev_class", 1, s7commEncBE},
		{"err_ev_num", 1, s7commEncBE},
		{"err_ob_priority", 1, s7commEncBE},
		{"err_ob_num", 1, s7commEncBE},
	}
	s7commOBInfo86 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"flt_id", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"mdl_addr", 2, s7commEncBE},
		{"racks_flt", 4, s7commEncBE},
	}
	s7commOBInfo90 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"strt_inf", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"reserved_3", 2, s7commEncBE},
		{"reserved_4_dw", 4, s7commEncBE},
	}
	s7commOBInfo100 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"strtup", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"reserved_2", 1, s7commEncBE},
		{"stop", 2, s7commEncBE},
		{"strt_info", 4, s7commEncBE},
	}
	s7commOBInfo121 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"sw_flt", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"blk_type", 1, s7commEncBE},
		{"reserved_1", 1, s7commEncBE},
		{"flt_reg", 2, s7commEncBE},
		{"flt_blk_num", 2, s7commEncBE},
		{"prg_addr", 2, s7commEncBE},
	}
	s7commOBInfo122 = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"sw_flt", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"blk_type", 1, s7commEncBE},
		{"mem_area", 1, s7commEncBE},
		{"mem_addr", 2, s7commEncBE},
		{"flt_blk_num", 2, s7commEncBE},
		{"prg_addr", 2, s7commEncBE},
	}
	s7commOBInfoDefault = []s7commFieldDef{
		{"ev_class", 1, s7commEncBE},
		{"res", 1, s7commEncBE},
		{"priority", 1, s7commEncBE},
		{"number", 1, s7commEncBE},
		{"res", 2, s7commEncBE},
		{"res", 2, s7commEncBE},
		{"res", 2, s7commEncBE},
		{"res", 2, s7commEncBE},
	}
)
