// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Services whose value is a transfer of user or file data, usually
// over several PDUs: NC programming (Sinumerik file transfer), PBC
// BSEND/BRECV and AR_SEND. Their layouts follow the Wireshark 4.7
// S7comm dissector.
//
// NC programming, after the octets in S7CommUserdata.UnitHeader:
//
//	request download request:           file name
//	start upload request:               unacknowledged count, unknown,
//	                                    file name
//	request download response, continue
//	download or upload push:            unacknowledged count, unknown
//	download block, upload and start
//	upload, response or push:           file length(8 ASCII),
//	                                    file time(16 ASCII),
//	                                    [path to LF, file data]
//	anything else:                      not known, kept in Rest
//
// BSEND: length(2), data. AR_SEND: length(2, little-endian), data.
// The R_ID or AR_ID is the last four octets of the unit header.

const (
	s7commNCHeadLen     = 2  // unacknowledged count and unknown octet
	s7commNCFileLenLen  = 8  // ASCII digits or spaces
	s7commNCFileTimeLen = 16 // ASCII
	s7commNCFileHeadLen = s7commNCFileLenLen + s7commNCFileTimeLen
	s7commNCPathEnd     = '\n'

	s7commSendLenLen = 2 // length before BSEND and AR_SEND data
	s7commSendIDAt   = 4 // R_ID or AR_ID within the unit header
)

// S7CommNCFile is an NC programming value. Only the fields of the
// layout the subfunction and direction select are set.
type S7CommNCFile struct {
	UnackCount uint8
	Unknown    uint8
	Filename   string
	FileLength string // 8 ASCII characters; spaces for a directory
	FileTime   string // 16 ASCII characters
	FilePath   string // without its closing line feed
	FileData   []byte
	Rest       []byte // value, or its tail, without a known layout
}

// S7CommSendData is the value of a PBC BSEND or an AR_SEND. ID is the
// R_ID or AR_ID each data unit names, 0 when the unit header is
// missing. Length is the size the sender states; Data is what follows.
type S7CommSendData struct {
	ID     uint32
	Length uint16
	Data   []byte
}

// decodeNC reads an NC programming value.
func (u *S7CommUserdata) decodeNC() error {
	d := u.Data
	if len(d) < s7commNCHeadLen {
		return nil
	}
	req := u.Type == S7CommUDTypeRequest
	f := &S7CommNCFile{}

	switch {
	case req && u.Subfunction == S7CommNCRequestDownload:
		f.Filename = string(d)
	case req && u.Subfunction == S7CommNCStartUpload:
		f.UnackCount, f.Unknown = d[0], d[1]
		f.Filename = string(d[s7commNCHeadLen:])
	case u.Type == S7CommUDTypeResponse && u.Subfunction == S7CommNCRequestDownload,
		u.Type == S7CommUDTypePush && (u.Subfunction == S7CommNCContUpload || u.Subfunction == S7CommNCContDownload):
		f.UnackCount, f.Unknown = d[0], d[1]
	case !req && u.Subfunction.ncHasUnitHeader():
		if err := f.decodeFile(d); err != nil {
			return err
		}
	default:
		f.Rest = d
	}
	u.NC = f
	return nil
}

// decodeFile reads the file header and, when present, path and data.
func (f *S7CommNCFile) decodeFile(d []byte) error {
	if len(d) < s7commNCFileHeadLen {
		return fmt.Errorf("%w: NC file header %d octets", ErrS7CommMalformed, len(d))
	}
	f.FileLength = string(d[:s7commNCFileLenLen])
	f.FileTime = string(d[s7commNCFileLenLen:s7commNCFileHeadLen])
	d = d[s7commNCFileHeadLen:]

	// Path and data are left out of some units; without a line feed
	// the rest has no known layout.
	end := bytes.IndexByte(d, s7commNCPathEnd)
	if end < 0 {
		f.Rest = d
		return nil
	}
	f.FilePath = string(d[:end])
	f.FileData = d[end+1:]
	return nil
}

// decodeSend reads a BSEND or AR_SEND value with the given byte order
// of its length.
func (u *S7CommUserdata) decodeSend(order binary.ByteOrder) error {
	d := u.Data
	if len(d) < s7commSendLenLen {
		return fmt.Errorf("%w: send data %d octets", ErrS7CommMalformed, len(d))
	}

	s := &S7CommSendData{Length: order.Uint16(d), Data: d[s7commSendLenLen:]}
	if len(u.UnitHeader) == s7commPBCUnitHead {
		s.ID = binary.BigEndian.Uint32(u.UnitHeader[s7commSendIDAt:])
	}
	u.Send = s
	return nil
}
