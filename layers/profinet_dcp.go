// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// PROFINET DCP (Discovery and basic Configuration Protocol) support.
//
// A DCP PDU follows Frame IDs 0xFEFC-0xFEFF (IEC 61158-6-10 4.3, Wireshark
// packet-pn-dcp.c):
//
//	+-----------+-------------+-----+---------------------+------------+--------+
//	| ServiceID | ServiceType | Xid | ResponseDelay/Rsvd  | DataLength | Blocks |
//	| 1         | 1           | 4   | 2                   | 2          | n      |
//	+-----------+-------------+-----+---------------------+------------+--------+
//
// Each block is Option(1) Suboption(1) DCPBlockLength(2), then a 2-byte
// BlockInfo (identify/get responses, hello requests) or BlockQualifier (set
// requests), then the value, padded to an even length. Get requests carry
// bare Option/Suboption selectors instead of blocks.
//
// Values by option (Wireshark dissect_PNDCP_Suboption_*):
//
//	IP       MAC | IP, mask, gateway | the same plus four DNS servers
//	Device   names as text | vendor and device ID | role | option list |
//	         instance | RSI and protocol property bits
//	DHCP     OptionCode (1), ParameterLength (1), ParameterData
//	Control  BlockQualifier, then a signal value; or Option, Suboption,
//	         BlockError for a response
//	NME/CIM  domain UUID and name | manager priority | parameter UUID |
//	         agent UUID | vendor, device and instance ID
//
// Manufacturer specific options (0x80-0xFE) have no known layout: their
// value stays raw.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
)

const (
	profinetDCPHeaderLen      = 10
	profinetDCPBlockHeaderLen = 4
	profinetDCPSelectorLen    = 2
	profinetDCPPrefixLen      = 2
	profinetDCPDNSServers     = 4
	profinetDCPDHCPHeadLen    = 2 // option code, parameter length
	profinetDCPCIMLen         = 6 // vendor ID, device ID, instance
	profinetDCPResetModeShift = 1
)

var (
	// ErrProfinetDCPTooShort is returned when a DCP header is truncated.
	ErrProfinetDCPTooShort = errors.New("PROFINET DCP header too short")
	// ErrProfinetDCPBlock is returned when a DCP block runs past the DCP data.
	ErrProfinetDCPBlock = errors.New("PROFINET DCP block exceeds DCP data length")
)

// ProfinetDCPServiceID is the DCP service.
type ProfinetDCPServiceID uint8

// DCP service IDs.
const (
	ProfinetDCPServiceGet      ProfinetDCPServiceID = 0x03
	ProfinetDCPServiceSet      ProfinetDCPServiceID = 0x04
	ProfinetDCPServiceIdentify ProfinetDCPServiceID = 0x05
	ProfinetDCPServiceHello    ProfinetDCPServiceID = 0x06
)

// String returns the service name.
func (s ProfinetDCPServiceID) String() string {
	switch s {
	case ProfinetDCPServiceGet:
		return "Get"
	case ProfinetDCPServiceSet:
		return "Set"
	case ProfinetDCPServiceIdentify:
		return "Identify"
	case ProfinetDCPServiceHello:
		return "Hello"
	}
	return fmt.Sprintf("Unknown(0x%02x)", uint8(s))
}

// ProfinetDCPServiceType says whether a PDU is a request or a response.
type ProfinetDCPServiceType uint8

// DCP service types. Bit 0 selects response, bit 2 flags an unsupported
// service in the response.
const (
	ProfinetDCPRequest             ProfinetDCPServiceType = 0x00
	ProfinetDCPResponseSuccess     ProfinetDCPServiceType = 0x01
	ProfinetDCPResponseUnsupported ProfinetDCPServiceType = 0x05
)

// String returns the service type name.
func (t ProfinetDCPServiceType) String() string {
	switch t {
	case ProfinetDCPRequest:
		return "Request"
	case ProfinetDCPResponseSuccess:
		return "Response Success"
	case ProfinetDCPResponseUnsupported:
		return "Response Unsupported"
	}
	return fmt.Sprintf("Unknown(0x%02x)", uint8(t))
}

// IsResponse reports whether the response bit is set.
func (t ProfinetDCPServiceType) IsResponse() bool { return t&ProfinetDCPResponseSuccess != 0 }

// ProfinetDCPOption is the option byte of a DCP block.
type ProfinetDCPOption uint8

// DCP options.
const (
	ProfinetDCPOptionIP               ProfinetDCPOption = 0x01
	ProfinetDCPOptionDevice           ProfinetDCPOption = 0x02
	ProfinetDCPOptionDHCP             ProfinetDCPOption = 0x03
	ProfinetDCPOptionControl          ProfinetDCPOption = 0x05
	ProfinetDCPOptionDeviceInitiative ProfinetDCPOption = 0x06
	ProfinetDCPOptionNME              ProfinetDCPOption = 0x07
	ProfinetDCPOptionManufFirst       ProfinetDCPOption = 0x80
	ProfinetDCPOptionManufLast        ProfinetDCPOption = 0xFE
	ProfinetDCPOptionAll              ProfinetDCPOption = 0xFF
)

// IsManufacturer reports whether the option is manufacturer specific.
func (o ProfinetDCPOption) IsManufacturer() bool {
	return o >= ProfinetDCPOptionManufFirst && o <= ProfinetDCPOptionManufLast
}

// String returns the option name.
func (o ProfinetDCPOption) String() string {
	switch {
	case o == ProfinetDCPOptionIP:
		return "IP"
	case o == ProfinetDCPOptionDevice:
		return "Device properties"
	case o == ProfinetDCPOptionDHCP:
		return "DHCP"
	case o == ProfinetDCPOptionControl:
		return "Control"
	case o == ProfinetDCPOptionDeviceInitiative:
		return "Device Initiative"
	case o == ProfinetDCPOptionNME:
		return "NME"
	case o == ProfinetDCPOptionAll:
		return "All Selector"
	case o.IsManufacturer():
		return "Manufacturer specific"
	}
	return fmt.Sprintf("Reserved(0x%02x)", uint8(o))
}

// ProfinetDCPBlockType is an option and suboption pair, Option<<8|Suboption.
type ProfinetDCPBlockType uint16

// DCP block types with a decoded value.
const (
	ProfinetDCPBlockIPMAC            ProfinetDCPBlockType = 0x0101
	ProfinetDCPBlockIPParameter      ProfinetDCPBlockType = 0x0102
	ProfinetDCPBlockIPSuite          ProfinetDCPBlockType = 0x0103
	ProfinetDCPBlockTypeOfStation    ProfinetDCPBlockType = 0x0201
	ProfinetDCPBlockNameOfStation    ProfinetDCPBlockType = 0x0202
	ProfinetDCPBlockDeviceID         ProfinetDCPBlockType = 0x0203
	ProfinetDCPBlockDeviceRole       ProfinetDCPBlockType = 0x0204
	ProfinetDCPBlockDeviceOptions    ProfinetDCPBlockType = 0x0205
	ProfinetDCPBlockAliasName        ProfinetDCPBlockType = 0x0206
	ProfinetDCPBlockDeviceInstance   ProfinetDCPBlockType = 0x0207
	ProfinetDCPBlockOEMDeviceID      ProfinetDCPBlockType = 0x0208
	ProfinetDCPBlockRSIProperties    ProfinetDCPBlockType = 0x020A
	ProfinetDCPBlockProtocolProps    ProfinetDCPBlockType = 0x020B
	ProfinetDCPBlockDHCPHostName     ProfinetDCPBlockType = 0x030C
	ProfinetDCPBlockDHCPVendor       ProfinetDCPBlockType = 0x032B
	ProfinetDCPBlockDHCPServerID     ProfinetDCPBlockType = 0x0336
	ProfinetDCPBlockDHCPParamRequest ProfinetDCPBlockType = 0x0337
	ProfinetDCPBlockDHCPClassID      ProfinetDCPBlockType = 0x033C
	ProfinetDCPBlockDHCPClientID     ProfinetDCPBlockType = 0x033D
	ProfinetDCPBlockDHCPFQDN         ProfinetDCPBlockType = 0x0351
	ProfinetDCPBlockDHCPUUID         ProfinetDCPBlockType = 0x0361
	ProfinetDCPBlockDHCPControl      ProfinetDCPBlockType = 0x03FF
	ProfinetDCPBlockStartTransaction ProfinetDCPBlockType = 0x0501
	ProfinetDCPBlockEndTransaction   ProfinetDCPBlockType = 0x0502
	ProfinetDCPBlockSignal           ProfinetDCPBlockType = 0x0503
	ProfinetDCPBlockResponse         ProfinetDCPBlockType = 0x0504
	ProfinetDCPBlockFactoryReset     ProfinetDCPBlockType = 0x0505
	ProfinetDCPBlockResetToFactory   ProfinetDCPBlockType = 0x0506
	ProfinetDCPBlockDeviceInitiative ProfinetDCPBlockType = 0x0601
	ProfinetDCPBlockNMEDomain        ProfinetDCPBlockType = 0x0701
	ProfinetDCPBlockNMEManager       ProfinetDCPBlockType = 0x0702
	ProfinetDCPBlockNMEParameterUUID ProfinetDCPBlockType = 0x0703
	ProfinetDCPBlockNMEAgent         ProfinetDCPBlockType = 0x0704
	ProfinetDCPBlockCIMInterface     ProfinetDCPBlockType = 0x0705
	ProfinetDCPBlockAllSelector      ProfinetDCPBlockType = 0xFFFF
)

// profinetDCPOptionShift places the option in the high byte of a block type.
const profinetDCPOptionShift = 8

// Option returns the option half of the block type.
func (t ProfinetDCPBlockType) Option() ProfinetDCPOption {
	return ProfinetDCPOption(t >> profinetDCPOptionShift)
}

// String returns the block type name.
func (t ProfinetDCPBlockType) String() string {
	switch t {
	case ProfinetDCPBlockIPMAC:
		return "IP/MAC address"
	case ProfinetDCPBlockIPParameter:
		return "IP/IP parameter"
	case ProfinetDCPBlockIPSuite:
		return "IP/Full IP suite"
	case ProfinetDCPBlockTypeOfStation:
		return "Device/Type of station"
	case ProfinetDCPBlockNameOfStation:
		return "Device/Name of station"
	case ProfinetDCPBlockDeviceID:
		return "Device/Device ID"
	case ProfinetDCPBlockDeviceRole:
		return "Device/Device role"
	case ProfinetDCPBlockDeviceOptions:
		return "Device/Device options"
	case ProfinetDCPBlockAliasName:
		return "Device/Alias name"
	case ProfinetDCPBlockDeviceInstance:
		return "Device/Device instance"
	case ProfinetDCPBlockOEMDeviceID:
		return "Device/OEM device ID"
	case ProfinetDCPBlockRSIProperties:
		return "Device/RSI properties"
	case ProfinetDCPBlockProtocolProps:
		return "Device/Protocol properties"
	case ProfinetDCPBlockDHCPHostName:
		return "DHCP/Host name"
	case ProfinetDCPBlockDHCPVendor:
		return "DHCP/Vendor specific"
	case ProfinetDCPBlockDHCPServerID:
		return "DHCP/Server identifier"
	case ProfinetDCPBlockDHCPParamRequest:
		return "DHCP/Parameter request list"
	case ProfinetDCPBlockDHCPClassID:
		return "DHCP/Class identifier"
	case ProfinetDCPBlockDHCPFQDN:
		return "DHCP/FQDN"
	case ProfinetDCPBlockDHCPUUID:
		return "DHCP/UUID client identifier"
	case ProfinetDCPBlockNMEDomain:
		return "NME/Configuration domain"
	case ProfinetDCPBlockNMEManager:
		return "NME/Manager"
	case ProfinetDCPBlockNMEParameterUUID:
		return "NME/Parameter UUID"
	case ProfinetDCPBlockNMEAgent:
		return "NME/Agent"
	case ProfinetDCPBlockCIMInterface:
		return "NME/CIM interface"
	case ProfinetDCPBlockDHCPClientID:
		return "DHCP/Client identifier"
	case ProfinetDCPBlockDHCPControl:
		return "DHCP/Control"
	case ProfinetDCPBlockStartTransaction:
		return "Control/Start transaction"
	case ProfinetDCPBlockEndTransaction:
		return "Control/End transaction"
	case ProfinetDCPBlockSignal:
		return "Control/Signal"
	case ProfinetDCPBlockResponse:
		return "Control/Response"
	case ProfinetDCPBlockFactoryReset:
		return "Control/Factory reset"
	case ProfinetDCPBlockResetToFactory:
		return "Control/Reset to factory"
	case ProfinetDCPBlockDeviceInitiative:
		return "Device initiative"
	case ProfinetDCPBlockAllSelector:
		return "All selector"
	}
	return fmt.Sprintf("%v/0x%02x", t.Option(), uint8(t))
}

// ProfinetDCPPrefix says which 2-byte field opens a block value.
type ProfinetDCPPrefix uint8

// DCP block prefixes.
const (
	ProfinetDCPPrefixNone ProfinetDCPPrefix = iota
	ProfinetDCPPrefixBlockInfo
	ProfinetDCPPrefixBlockQualifier
)

// String returns the prefix name.
func (p ProfinetDCPPrefix) String() string {
	switch p {
	case ProfinetDCPPrefixNone:
		return "None"
	case ProfinetDCPPrefixBlockInfo:
		return "BlockInfo"
	case ProfinetDCPPrefixBlockQualifier:
		return "BlockQualifier"
	}
	return fmt.Sprintf("Unknown(%d)", uint8(p))
}

// ProfinetDCPDeviceRole is the device role bit field.
type ProfinetDCPDeviceRole uint8

// Device role bits.
const (
	ProfinetDCPRoleIODevice     ProfinetDCPDeviceRole = 0x01
	ProfinetDCPRoleIOController ProfinetDCPDeviceRole = 0x02
	ProfinetDCPRoleIOMultidev   ProfinetDCPDeviceRole = 0x04
	ProfinetDCPRoleSupervisor   ProfinetDCPDeviceRole = 0x08
)

// ProfinetDCPResetMode is the mode of a Control/Reset to factory block,
// carried in bits 1-15 of its BlockQualifier.
type ProfinetDCPResetMode uint16

// Reset to factory modes.
const (
	ProfinetDCPResetApplication   ProfinetDCPResetMode = 1
	ProfinetDCPResetCommunication ProfinetDCPResetMode = 2
	ProfinetDCPResetEngineering   ProfinetDCPResetMode = 3
	ProfinetDCPResetAllStored     ProfinetDCPResetMode = 4
	ProfinetDCPResetDevice        ProfinetDCPResetMode = 8
	ProfinetDCPResetAndRestore    ProfinetDCPResetMode = 9
)

// String returns the reset mode name.
func (m ProfinetDCPResetMode) String() string {
	switch m {
	case ProfinetDCPResetApplication:
		return "Reset application data"
	case ProfinetDCPResetCommunication:
		return "Reset communication parameter"
	case ProfinetDCPResetEngineering:
		return "Reset engineering parameter"
	case ProfinetDCPResetAllStored:
		return "Reset all stored data except the security configuration"
	case ProfinetDCPResetDevice:
		return "Reset all stored data to factory values"
	case ProfinetDCPResetAndRestore:
		return "Reset and restore data"
	}
	return fmt.Sprintf("reserved(%d)", uint16(m))
}

// ProfinetDCPBlockError is the error code of a Control/Response block.
type ProfinetDCPBlockError uint8

// DCP block errors.
const (
	ProfinetDCPErrorOK                  ProfinetDCPBlockError = 0x00
	ProfinetDCPErrorOptionUnsupported   ProfinetDCPBlockError = 0x01
	ProfinetDCPErrorSuboptionUnsupp     ProfinetDCPBlockError = 0x02
	ProfinetDCPErrorSuboptionNotSet     ProfinetDCPBlockError = 0x03
	ProfinetDCPErrorResource            ProfinetDCPBlockError = 0x04
	ProfinetDCPErrorSetNotPossible      ProfinetDCPBlockError = 0x05
	ProfinetDCPErrorInOperation         ProfinetDCPBlockError = 0x06
	ProfinetDCPErrorSecurityRestriction ProfinetDCPBlockError = 0x07
)

// String returns the block error name.
func (e ProfinetDCPBlockError) String() string {
	switch e {
	case ProfinetDCPErrorOK:
		return "Ok"
	case ProfinetDCPErrorOptionUnsupported:
		return "Option unsupported"
	case ProfinetDCPErrorSuboptionUnsupp:
		return "Suboption unsupported or no data set available"
	case ProfinetDCPErrorSuboptionNotSet:
		return "Suboption not set"
	case ProfinetDCPErrorResource:
		return "Resource error"
	case ProfinetDCPErrorSetNotPossible:
		return "Set not possible by local reasons"
	case ProfinetDCPErrorInOperation:
		return "In operation, set not possible"
	case ProfinetDCPErrorSecurityRestriction:
		return "Set or get not possible by security reasons"
	}
	return fmt.Sprintf("Reserved(0x%02x)", uint8(e))
}

// ProfinetDCPSelector is an Option/Suboption pair, as listed by Get
// requests and Device/Device options blocks.
type ProfinetDCPSelector struct {
	Option    ProfinetDCPOption
	Suboption uint8
}

// Type returns the selector as a block type.
func (s ProfinetDCPSelector) Type() ProfinetDCPBlockType {
	return ProfinetDCPBlockType(s.Option)<<profinetDCPOptionShift | ProfinetDCPBlockType(s.Suboption)
}

// ProfinetDCPBlock is one DCP block.
//
// Value holds the bytes after the prefix, without padding. The typed fields
// below it are filled for the block types they belong to, when Value is
// long enough; they alias the packet data.
//
// Name ends at the first NUL, as tshark prints it: devices pad names with
// NULs. Value keeps every byte.
type ProfinetDCPBlock struct {
	Option    ProfinetDCPOption
	Suboption uint8
	Length    uint16 // DCPBlockLength as sent, prefix included
	Prefix    ProfinetDCPPrefix
	BlockInfo uint16 // BlockInfo or BlockQualifier, per Prefix
	Value     []byte

	MAC              net.HardwareAddr      // IP/MAC address
	IP               net.IP                // IP parameter, full IP suite
	Subnet           net.IP                // IP parameter, full IP suite
	Gateway          net.IP                // IP parameter, full IP suite
	DNS              []net.IP              // full IP suite
	Name             string                // type of station, name of station, alias name, NME domain name, arbitrary DHCP client identifier
	VendorID         uint16                // device ID, OEM device ID
	DeviceID         uint16                // device ID, OEM device ID
	Role             ProfinetDCPDeviceRole // device role
	Options          []ProfinetDCPSelector // device options
	Instance         uint16                // device instance, high<<8 | low
	Signal           uint16                // control signal value
	Response         ProfinetDCPSelector   // control response: option answered
	BlockError       ProfinetDCPBlockError // control response
	DeviceInitiative uint16                // device initiative value
	Properties       uint16                // RSI properties, protocol properties
	DHCPOptionCode   DHCPOpt               // DHCP blocks
	NMEPriority      uint16                // NME manager
}

// ResetMode returns the mode of a Control/Reset to factory block.
func (b *ProfinetDCPBlock) ResetMode() ProfinetDCPResetMode {
	return ProfinetDCPResetMode(b.BlockInfo >> profinetDCPResetModeShift)
}

// Type returns the block's option and suboption as one value.
func (b *ProfinetDCPBlock) Type() ProfinetDCPBlockType {
	return ProfinetDCPSelector{b.Option, b.Suboption}.Type()
}

// ProfinetDCP is a PROFINET DCP PDU.
//
// Blocks are parsed only for the known services and service types, as
// Wireshark does. A Get request's selectors appear as blocks with no
// length, prefix or value. Ethernet padding after DataLength is ignored.
type ProfinetDCP struct {
	BaseLayer

	ServiceID     ProfinetDCPServiceID
	ServiceType   ProfinetDCPServiceType
	Xid           uint32
	ResponseDelay uint16 // identify requests; reserved otherwise
	DataLength    uint16
	Blocks        []ProfinetDCPBlock
}

// LayerType returns LayerTypeProfinetDCP.
func (d *ProfinetDCP) LayerType() gopacket.LayerType { return LayerTypeProfinetDCP }

// CanDecode returns LayerTypeProfinetDCP.
func (d *ProfinetDCP) CanDecode() gopacket.LayerClass { return LayerTypeProfinetDCP }

// NextLayerType returns LayerTypeZero: DCP carries no further layer.
func (d *ProfinetDCP) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// Payload returns the raw block area, also decoded into Blocks.
func (d *ProfinetDCP) Payload() []byte { return d.BaseLayer.Payload }

// DecodeFromBytes decodes a DCP PDU, starting at the ServiceID.
func (d *ProfinetDCP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < profinetDCPHeaderLen {
		df.SetTruncated()
		return ErrProfinetDCPTooShort
	}

	d.ServiceID = ProfinetDCPServiceID(data[0])
	d.ServiceType = ProfinetDCPServiceType(data[1])
	d.Xid = binary.BigEndian.Uint32(data[2:6])
	d.ResponseDelay = binary.BigEndian.Uint16(data[6:8])
	d.DataLength = binary.BigEndian.Uint16(data[8:10])
	d.Blocks = d.Blocks[:0]

	// Clip the block area to the captured bytes; padding past it is dropped.
	end := profinetDCPHeaderLen + int(d.DataLength)
	if end > len(data) {
		df.SetTruncated()
		end = len(data)
	}
	d.BaseLayer = BaseLayer{Contents: data[:profinetDCPHeaderLen], Payload: data[profinetDCPHeaderLen:end]}

	if !d.knownService() {
		return nil
	}
	return d.decodeBlocks(data[profinetDCPHeaderLen:end], df)
}

// knownService reports whether the service and type are ones whose blocks
// can be parsed.
func (d *ProfinetDCP) knownService() bool {
	switch d.ServiceID {
	case ProfinetDCPServiceGet, ProfinetDCPServiceSet, ProfinetDCPServiceIdentify, ProfinetDCPServiceHello:
	default:
		return false
	}

	switch d.ServiceType {
	case ProfinetDCPRequest, ProfinetDCPResponseSuccess, ProfinetDCPResponseUnsupported:
		return true
	}
	return false
}

// prefix returns the field that opens block values for this PDU: BlockInfo
// in identify/get responses and hello requests, BlockQualifier in set
// requests.
func (d *ProfinetDCP) prefix() ProfinetDCPPrefix {
	resp := d.ServiceType.IsResponse()
	switch {
	case d.ServiceID == ProfinetDCPServiceIdentify && resp,
		d.ServiceID == ProfinetDCPServiceGet && resp,
		d.ServiceID == ProfinetDCPServiceHello && !resp:
		return ProfinetDCPPrefixBlockInfo
	case d.ServiceID == ProfinetDCPServiceSet && !resp:
		return ProfinetDCPPrefixBlockQualifier
	}
	return ProfinetDCPPrefixNone
}

// decodeBlocks walks the block area. Each block consumes at least two
// bytes, so the loop is bounded by len(data).
func (d *ProfinetDCP) decodeBlocks(data []byte, df gopacket.DecodeFeedback) error {
	// Get requests list selectors, not blocks.
	if d.ServiceID == ProfinetDCPServiceGet && d.ServiceType == ProfinetDCPRequest {
		// The count is known: allocate once instead of growing by append,
		// keeping a reused layer's array when it is big enough.
		if n := len(data) / profinetDCPSelectorLen; cap(d.Blocks) < n {
			d.Blocks = make([]ProfinetDCPBlock, 0, n)
		}
		for ; len(data) >= profinetDCPSelectorLen; data = data[profinetDCPSelectorLen:] {
			d.Blocks = append(d.Blocks, ProfinetDCPBlock{Option: ProfinetDCPOption(data[0]), Suboption: data[1]})
		}
		return nil
	}

	prefix := d.prefix()
	for len(data) > 0 {
		if len(data) < profinetDCPBlockHeaderLen {
			return d.blockOverrun(df)
		}

		length := int(binary.BigEndian.Uint16(data[2:4]))
		if profinetDCPBlockHeaderLen+length > len(data) {
			return d.blockOverrun(df)
		}

		b := ProfinetDCPBlock{
			Option:    ProfinetDCPOption(data[0]),
			Suboption: data[1],
			Length:    uint16(length),
		}
		b.decodeValue(data[profinetDCPBlockHeaderLen:profinetDCPBlockHeaderLen+length], prefix)
		d.Blocks = append(d.Blocks, b)

		// Blocks are padded to an even length.
		next := profinetDCPBlockHeaderLen + length
		if next%2 == 1 && next < len(data) {
			next++
		}
		data = data[next:]
	}
	return nil
}

// blockOverrun reports a block that does not fit: truncation when the
// capture cut the DCP data short, an error when DataLength itself lies.
func (d *ProfinetDCP) blockOverrun(df gopacket.DecodeFeedback) error {
	if int(d.DataLength) > len(d.BaseLayer.Payload) {
		df.SetTruncated()
		return nil
	}
	return ErrProfinetDCPBlock
}

// blockPrefix returns the prefix a block carries, given the one the PDU
// implies. It follows Wireshark's dissectors:
//   - Control transaction, signal and reset blocks always open with a
//     BlockQualifier; other Control blocks never do.
//   - IP blocks carry the PDU prefix only for known suboptions.
//   - Manufacturer, All selector and reserved options carry none.
func (b *ProfinetDCPBlock) blockPrefix(pdu ProfinetDCPPrefix) ProfinetDCPPrefix {
	switch b.Option {
	case ProfinetDCPOptionControl:
		switch b.Type() {
		case ProfinetDCPBlockStartTransaction, ProfinetDCPBlockEndTransaction, ProfinetDCPBlockSignal,
			ProfinetDCPBlockFactoryReset, ProfinetDCPBlockResetToFactory:
			return ProfinetDCPPrefixBlockQualifier
		}
		return ProfinetDCPPrefixNone
	case ProfinetDCPOptionIP:
		switch b.Type() {
		case ProfinetDCPBlockIPMAC, ProfinetDCPBlockIPParameter, ProfinetDCPBlockIPSuite:
			return pdu
		}
		return ProfinetDCPPrefixNone
	case ProfinetDCPOptionDevice, ProfinetDCPOptionDHCP, ProfinetDCPOptionDeviceInitiative, ProfinetDCPOptionNME:
		return pdu
	}
	return ProfinetDCPPrefixNone
}

// decodeValue splits off the prefix and fills the typed fields.
func (b *ProfinetDCPBlock) decodeValue(v []byte, pdu ProfinetDCPPrefix) {
	if prefix := b.blockPrefix(pdu); prefix != ProfinetDCPPrefixNone && len(v) >= profinetDCPPrefixLen {
		b.Prefix = prefix
		b.BlockInfo = binary.BigEndian.Uint16(v)
		v = v[profinetDCPPrefixLen:]
	}
	b.Value = v

	switch b.Type() {
	case ProfinetDCPBlockIPMAC:
		if len(v) >= 6 {
			b.MAC = net.HardwareAddr(v[:6])
		}
	case ProfinetDCPBlockIPParameter:
		b.decodeIPParameter(v)
	case ProfinetDCPBlockIPSuite:
		b.decodeIPParameter(v)
		b.decodeDNS(v)
	case ProfinetDCPBlockTypeOfStation, ProfinetDCPBlockNameOfStation, ProfinetDCPBlockAliasName:
		b.Name = dcpName(v)
	case ProfinetDCPBlockDeviceID, ProfinetDCPBlockOEMDeviceID:
		if len(v) >= 4 {
			b.VendorID = binary.BigEndian.Uint16(v)
			b.DeviceID = binary.BigEndian.Uint16(v[2:])
		}
	case ProfinetDCPBlockDeviceRole:
		if len(v) >= 1 {
			b.Role = ProfinetDCPDeviceRole(v[0])
		}
	case ProfinetDCPBlockDeviceOptions:
		for ; len(v) >= profinetDCPSelectorLen; v = v[profinetDCPSelectorLen:] {
			b.Options = append(b.Options, ProfinetDCPSelector{ProfinetDCPOption(v[0]), v[1]})
		}
	case ProfinetDCPBlockDeviceInstance:
		if len(v) >= 2 {
			b.Instance = binary.BigEndian.Uint16(v)
		}
	case ProfinetDCPBlockSignal:
		if len(v) >= 2 {
			b.Signal = binary.BigEndian.Uint16(v)
		}
	case ProfinetDCPBlockResponse:
		if len(v) >= 3 {
			b.Response = ProfinetDCPSelector{ProfinetDCPOption(v[0]), v[1]}
			b.BlockError = ProfinetDCPBlockError(v[2])
		}
	case ProfinetDCPBlockDeviceInitiative:
		if len(v) >= 2 {
			b.DeviceInitiative = binary.BigEndian.Uint16(v)
		}
	case ProfinetDCPBlockRSIProperties, ProfinetDCPBlockProtocolProps:
		if len(v) >= 2 {
			b.Properties = binary.BigEndian.Uint16(v)
		}
	}

	switch b.Option {
	case ProfinetDCPOptionDHCP:
		b.decodeDHCP(v)
	case ProfinetDCPOptionNME:
		b.decodeNME(v)
	}
}

// dcpName returns a station name: the text up to the first NUL.
func dcpName(v []byte) string {
	for i, c := range v {
		if c == 0 {
			return string(v[:i])
		}
	}
	return string(v)
}

// DHCPParameter returns the parameter data of a DHCP block, clipped to the
// block when its length byte lies. It is a method rather than a field to
// keep the block small: a Get request allocates one block per two bytes.
func (b *ProfinetDCPBlock) DHCPParameter() []byte {
	v := b.Value
	if b.Option != ProfinetDCPOptionDHCP || len(v) < profinetDCPDHCPHeadLen {
		return nil
	}

	n := int(v[1])
	v = v[profinetDCPDHCPHeadLen:]
	if n > len(v) {
		n = len(v)
	}
	return v[:n]
}

// decodeDHCP reads a DHCP block: the option code again, a length and the
// parameter data. A client identifier parameter is a type byte followed,
// for an arbitrary identifier, by the identifier text.
func (b *ProfinetDCPBlock) decodeDHCP(v []byte) {
	if len(v) < profinetDCPDHCPHeadLen {
		return
	}
	b.DHCPOptionCode = DHCPOpt(v[0])

	if param := b.DHCPParameter(); b.Type() == ProfinetDCPBlockDHCPClientID && len(param) > 1 {
		b.Name = string(param[1:])
	}
}

// UUID returns the UUID that opens an NME domain, parameter UUID or agent
// block, and whether the block carries one. Like DHCPParameter it is a
// method to keep the block small.
func (b *ProfinetDCPBlock) UUID() (u ProfinetUUID, ok bool) {
	if len(b.Value) < profinetUUIDLen {
		return u, false
	}

	switch b.Type() {
	case ProfinetDCPBlockNMEDomain, ProfinetDCPBlockNMEParameterUUID:
	case ProfinetDCPBlockNMEAgent:
		// Wireshark reads the agent only behind a BlockInfo.
		if b.Prefix != ProfinetDCPPrefixBlockInfo {
			return u, false
		}
	default:
		return u, false
	}

	copy(u[:], b.Value)
	return u, true
}

// decodeNME reads an NME (CIM) block. Like Wireshark, the manager and CIM
// interface values are read only behind a BlockInfo.
func (b *ProfinetDCPBlock) decodeNME(v []byte) {
	info := b.Prefix == ProfinetDCPPrefixBlockInfo

	switch b.Type() {
	case ProfinetDCPBlockNMEDomain:
		if len(v) >= profinetUUIDLen {
			b.Name = dcpName(v[profinetUUIDLen:])
		}
	case ProfinetDCPBlockNMEManager:
		if info && len(v) >= 2 {
			b.NMEPriority = binary.BigEndian.Uint16(v)
		}
	case ProfinetDCPBlockCIMInterface:
		if info && len(v) >= profinetDCPCIMLen {
			b.VendorID = binary.BigEndian.Uint16(v)
			b.DeviceID = binary.BigEndian.Uint16(v[2:])
			b.Instance = binary.BigEndian.Uint16(v[4:])
		}
	}
}

// decodeIPParameter reads IP address, subnet mask and gateway (3 x 4 bytes).
func (b *ProfinetDCPBlock) decodeIPParameter(v []byte) {
	if len(v) < 3*net.IPv4len {
		return
	}
	b.IP = net.IP(v[0:4])
	b.Subnet = net.IP(v[4:8])
	b.Gateway = net.IP(v[8:12])
}

// decodeDNS reads the four DNS servers that follow the IP parameter in a
// full IP suite block.
func (b *ProfinetDCPBlock) decodeDNS(v []byte) {
	start := 3 * net.IPv4len
	if len(v) < start+profinetDCPDNSServers*net.IPv4len {
		return
	}

	b.DNS = make([]net.IP, profinetDCPDNSServers)
	for i := range b.DNS {
		off := start + i*net.IPv4len
		b.DNS[i] = net.IP(v[off : off+net.IPv4len])
	}
}

func decodeProfinetDCP(data []byte, p gopacket.PacketBuilder) error {
	d := &ProfinetDCP{}
	if err := d.DecodeFromBytes(data, p); err != nil {
		return err
	}

	p.AddLayer(d)
	p.SetApplicationLayer(d)
	return nil
}
