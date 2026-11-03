// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
// author: Raphael Coeffic <raphael.coeffic@frafos.com>

package pcapgo

import (
	"bytes"
	"fmt"
	"net/netip"
)

type nameRecordHeader struct {
	recordType   uint16
	recordLength uint16
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func paddingBytes32b(length int) int {
	padding := length % 4
	if padding > 0 {
		padding = 4 - padding
	}
	return padding
}

func newIPAddress(data []byte) *NgIPAddress {
	addr := &NgIPAddress{}
	addr.Addr, _ = netip.AddrFromSlice(data)
	return addr
}

func newHWAddress(data []byte) *NgEUIAddress {
	addr := &NgEUIAddress{}
	addr.Addr = bytes.Clone(data)
	return addr
}

func (r *NgReader) readIPAddr(nr *NgNameRecord, length int) error {
	if _, err := r.readBytes(r.buf[:length]); err != nil {
		return fmt.Errorf("could not read IP address: %v", err)
	}
	nr.Addr = newIPAddress(r.buf[:length])
	return nil
}

func (r *NgReader) readHWAddr(nr *NgNameRecord, length int) error {
	if _, err := r.readBytes(r.buf[:length]); err != nil {
		return fmt.Errorf("could not read EUI address: %v", err)
	}
	nr.Addr = newHWAddress(r.buf[:length])
	return nil
}

func (r *NgReader) readNameResolutionBlock() error {

	for r.currentBlock.length > 0 {
		// Read name record header
		if _, err := r.readBytes(r.buf[:4]); err != nil {
			return fmt.Errorf("could not read NameRecord Header block length: %v", err)
		}
		r.currentBlock.length -= 4

		var nrh = &nameRecordHeader{}
		nrh.recordType = r.getUint16(r.buf[0:2])
		nrh.recordLength = r.getUint16(r.buf[2:4])

		var nameRecord = NgNameRecord{}
		length := min(int(nrh.recordLength), int(r.currentBlock.length))
		padding := paddingBytes32b(length)
		addressLength := 0
		switch nrh.recordType {
		case ngNameRecordIPv4:
			addressLength = 4
		case ngNameRecordIPv6:
			addressLength = 16
		case ngNameRecordEUI48:
			addressLength = 6
		case ngNameRecordEUI64:
			addressLength = 8
		}
		if length < addressLength {
			return fmt.Errorf("name record of type %d is too short for its address", nrh.recordType)
		}

		switch nrh.recordType {
		case ngNameRecordIPv4:
			if err := r.readIPAddr(&nameRecord, 4); err != nil {
				return fmt.Errorf("could not read IPv4 address: %v", err)
			}
		case ngNameRecordIPv6:
			if err := r.readIPAddr(&nameRecord, 16); err != nil {
				return fmt.Errorf("could not read IPv6 address: %v", err)
			}
		case ngNameRecordEUI48:
			if err := r.readHWAddr(&nameRecord, 6); err != nil {
				return fmt.Errorf("could not read EUI-48 address: %v", err)
			}
		case ngNameRecordEUI64:
			if err := r.readHWAddr(&nameRecord, 8); err != nil {
				return fmt.Errorf("could not read EUI-64 address: %v", err)
			}
		case ngNameRecordEnd:
			goto DONE
		default:
			// discard record length
			if err := r.discard(length + padding); err != nil {
				return fmt.Errorf("could not discard unknown name record: %v", err)
			}
			continue
		}
		r.currentBlock.length -= uint32(length)
		length -= nameRecord.Addr.Len()

		// Read only the bytes declared by this record.
		names := make([]byte, length)
		if _, err := r.readBytes(names); err != nil {
			return fmt.Errorf("could not read name: %v", err)
		}
		for len(names) > 0 {
			var name []byte
			name, names, _ = bytes.Cut(names, []byte{0})
			nameRecord.Names = append(nameRecord.Names, string(name))
		}
		r.nameRecords = append(r.nameRecords, nameRecord)

		//consume padding
		if err := r.discard(padding); err != nil {
			return err
		}
	}

DONE:
	// discard everything after 'nrb_record_end' (including options)
	return r.discard(int(r.currentBlock.length))
}
