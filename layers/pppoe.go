// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/gopacket/gopacket"
)

// PPPoE is the layer for PPPoE encapsulation headers.
type PPPoE struct {
	BaseLayer
	Version   uint8
	Type      uint8
	Code      PPPoECode
	SessionId uint16
	Length    uint16
	Tags      PPPoETags
}

type PPPoETags []PPPoETag

// String returns a string version of the tags list.
func (pt PPPoETags) String() string {
	buf := &bytes.Buffer{}
	buf.WriteByte('[')
	for i, tag := range pt {
		buf.WriteString(tag.String())
		if i+1 != len(pt) {
			buf.WriteString(", ")
		}
	}
	buf.WriteByte(']')
	return buf.String()
}

// PPPoETag Represents a payload TAG
type PPPoETag struct {
	Type   PPPoETagType
	Length uint16
	Value  []byte
}

// String returns a string version of a payload TAG
func (pt PPPoETag) String() string {
	switch pt.Type {
	case PPPoETagEOL:
		return fmt.Sprintf("Tag(%s)", pt.Type)
	case PPPoETagServiceName, PPPoETagACName:
		return fmt.Sprintf("Tag(%s, '%s')", pt.Type, string(pt.Value))
	case PPPoETagHostUniq, PPPoETagACCookie, PPPoETagRelaySessionID:
		return fmt.Sprintf("Tag(%s, '%s')", pt.Type, hex.EncodeToString(pt.Value))
	case PPPoETagServiceNameError, PPPoETagACSystemError:
		if pt.Value[0] != 0 {
			return fmt.Sprintf("Tag(%s, '%s')", pt.Type, string(pt.Value))
		} else {
			return fmt.Sprintf("Tag(%s, '%s')", pt.Type, hex.EncodeToString(pt.Value))
		}
	case PPPoETagGenericError:
		if pt.Length > 0 {
			return fmt.Sprintf("Tag(%s, '%s')", pt.Type, string(pt.Value))
		} else {
			return fmt.Sprintf("Tag(%s)", pt.Type)
		}
	default:
		return fmt.Sprintf("Tag(%s:%v)", pt.Type, pt.Value)
	}
}

func (pt *PPPoETag) decode(data []byte) error {
	if len(data) < 4 {
		// Tags must be at least 4 bytes long (TYPE + LENGTH).
		return DecOptionNotEnoughData
	}
	pt.Type = PPPoETagType(binary.BigEndian.Uint16(data[0:2]))
	switch pt.Type {
	case PPPoETagEOL:
		pt.Length = 0
		pt.Value = nil
	default:
		pt.Length = binary.BigEndian.Uint16(data[2:4])
		if int(pt.Length) > len(data[4:]) {
			return DecOptionMalformed
		}
		pt.Value = data[4 : 4+int(pt.Length)]
	}
	return nil
}

func (pt *PPPoETag) encode(data []byte) error {
	switch pt.Type {
	case PPPoETagEOL:
		binary.BigEndian.PutUint16(data[0:2], uint16(pt.Type))
	default:
		binary.BigEndian.PutUint16(data[0:2], uint16(pt.Type))
		binary.BigEndian.PutUint16(data[2:4], pt.Length)
		copy(data[4:], pt.Value)
	}
	return nil
}

// String returns a string version of a PPPoETagType.
func (pt PPPoETagType) String() string {
	switch pt {
	case PPPoETagEOL:
		return "End-Of-List"
	case PPPoETagServiceName:
		return "Service-Name"
	case PPPoETagACName:
		return "AC-Name"
	case PPPoETagHostUniq:
		return "Host-Uniq"
	case PPPoETagACCookie:
		return "AC-Cookie"
	case PPPoETagVendorSpecific:
		return "Vendor-Specific"
	case PPPoETagRelaySessionID:
		return "Relay-Session-ID"
	case PPPoETagServiceNameError:
		return "Service-Name-Error"
	case PPPoETagACSystemError:
		return "AC-System-Error"
	case PPPoETagGenericError:
		return "Generic-Error"
	default:
		return "Unknown"
	}
}

// LayerType returns gopacket.LayerTypePPPoE.
func (p *PPPoE) LayerType() gopacket.LayerType {
	return LayerTypePPPoE
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (p *PPPoE) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	plen := int(p.Len())

	data, err := b.PrependBytes(plen)
	if err != nil {
		return err
	}
	data[0] = (p.Version << 4) | p.Type
	data[1] = byte(p.Code)
	binary.BigEndian.PutUint16(data[2:], p.SessionId)

	offset := 6
	if len(p.Tags) > 0 {
		for _, tag := range p.Tags {
			if err := tag.encode(data[offset:]); err != nil {
				return err
			}
			// A pad option is only a single byte
			offset += 4 + len(tag.Value)
		}
	}

	if opts.FixLengths {
		// Subtract 6 Bytes, as the Length field doesn't include the PPPoE header
		p.Length = uint16(plen - 6)
	}
	binary.BigEndian.PutUint16(data[4:], p.Length)

	return nil
}

func (p *PPPoE) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	p.Version = data[0] >> 4
	p.Type = data[0] & 0x0f
	p.Code = PPPoECode(data[1])
	p.SessionId = binary.BigEndian.Uint16(data[2:4])
	p.Length = binary.BigEndian.Uint16(data[4:6])

	tags := data[6:]

	stop := len(tags)
	start := 0

	for start < stop {
		tag := PPPoETag{}
		if err := tag.decode(tags[start:]); err != nil {
			return err
		}
		p.Tags = append(p.Tags, tag)
		// There are 4 bytes from Type + Length and the length of the value.
		start += 4 + int(tag.Length)
	}

	p.BaseLayer = BaseLayer{Contents: data[:6], Payload: data[6 : 6+p.Length]}

	return nil
}

func (p *PPPoE) Len() uint16 {
	n := uint16(6)
	for _, tag := range p.Tags {
		n += 4 + uint16(tag.Length)
	}
	return n
}

func (p *PPPoE) CanDecode() gopacket.LayerClass { return LayerTypePPPoE }

func (p *PPPoE) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

// decodePPPoE decodes the PPPoE header (see http://tools.ietf.org/html/rfc2516).
func decodePPPoE(data []byte, p gopacket.PacketBuilder) error {
	pppoe := &PPPoE{}
	err := pppoe.DecodeFromBytes(data, p)
	p.AddLayer(pppoe)
	if err != nil {
		return err
	}
	return p.NextDecoder(pppoe.Code)
}

// NewPPPoETag constructs a new PPPoeTag with a given type and data.
func NewPPPoETag(t PPPoETagType, data []byte) PPPoETag {
	tag := PPPoETag{Type: t}
	if data != nil {
		tag.Value = data
		tag.Length = uint16(len(data))
	}
	return tag
}
