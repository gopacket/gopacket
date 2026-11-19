// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/gopacket/gopacket"
)

// iecSnapHandBuilt names the hand built frames of iecSnapVectors.
const iecSnapHandBuilt = "hand built"

// GOOSE and SV share the MMS Data decoder. Their decode output was
// snapshotted before MMS Data learnt new alternatives: a frame that
// decoded then must still dump the same, field for field.
//
// Each digest is the SHA-256 of iecSnapDump over the capture, taken at
// commit 38fdb73.
var iecSnapGolden = map[string]string{
	"iec61850_goose_abb.pcap":         "5d790a519dee853109a397ed891ade22b3a6a9878d03d44d85f6b8e862ea2cd1",
	"iec61850_goose_ge_f650.pcap":     "c67819fd1f1d4f0eac0078c4f12d6b59e4926831329fe39139c85bc3aab3eb9d",
	"iec61850_goose_gooseind.pcap":    "aa1eda2335c98f50ee9c0307f9f2ec7011e280576f5bc80d3a61da260a6cbb99",
	"iec61850_goose_iedscout.pcap":    "5a2b9fa4f9346a45931dd7600671be074e503112301bf59819329fb0744ea6f2",
	"iec61850_goose_vlan.pcap":        "0705a888f35137a05f9130b69584b2744145e55c68ae5bb630799db83ea028cb",
	"iec61850_mms_reports_goose.pcap": "81359558592e75158a1acda51734520d07d587f0539e6a4141dd23eda23afe82",
	"iec61850_sv_92le.pcap":           "ed6d1d4154827b1b6cfc5dbdbf9e10b3e5d490002e7195809890815829a3473e",
	"iec61850_sv_bad_length.pcap":     "6ea667c8c524ca897e8585be657757d3106f93ecf8db0d9220ac5464b06ee27e",
	"iec61850_sv_multi_asdu.pcap":     "80004930ecb0c5a89b14e66aac8bc18b7246e743f802d2e6bcc8c02955c55760",
	iecSnapHandBuilt:                  "12f2f72e452946594d9a2ffefa10b2921355e52f4d67fa42d872f5d02034f063",
}

// iecSnapVectors returns goosePdus holding every Data alternative that
// decoded at the snapshot, nested ones included: the captures lack most.
func iecSnapVectors() [][]byte {
	data := bytes.Join([][]byte{
		iecTLV(0x83, []byte{0xff}),
		iecTLV(0x84, []byte{0x06, 0x40}),
		iecTLV(0x85, []byte{0xfe, 0x0c}),
		iecTLV(0x85, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}),
		iecTLV(0x86, []byte{0x00, 0xff, 0xff, 0xff, 0xff}),
		iecTLV(0x87, []byte{0x08, 0x3f, 0xc0, 0x00, 0x00}),
		iecTLV(0x87, []byte{0x0b, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18}),
		iecTLV(0x89, []byte{0xde, 0xad}),
		iecTLV(0x8a, []byte("abc")),
		iecTLV(0x8b, []byte("20260102030405.5Z")),
		iecTLV(0x8c, []byte{0x00, 0x00, 0x03, 0xe8, 0x00, 0x01}),
		iecTLV(0x8c, []byte{0x00, 0x00, 0x03, 0xe8}),
		iecTLV(0x8d, []byte{0x12}),
		iecTLV(0x8e, []byte{0x05, 0xa0}),
		iecTLV(0x8f, []byte{0x28, 0xca, 0x22, 0x02, 0x01}),
		iecTLV(0x90, []byte("é")),
		iecTLV(0x91, []byte{0, 0, 0, 1, 0x80, 0, 0, 0x0a}),
		iecTLV(0xa2, iecTLV(0xa1, iecTLV(0x85, []byte{7}), iecTLV(0x87, []byte{0x08, 0, 0, 0, 0}))),
	}, nil)

	head := [][]byte{
		iecTLV(0x80, []byte("gcb")), iecTLV(0x81, []byte{0x07, 0xd0}), iecTLV(0x82, []byte("ds")),
		iecTLV(0x84, make([]byte, 8)), iecTLV(0x85, []byte{1}), iecTLV(0x86, []byte{2}),
		iecTLV(0x87, []byte{0}), iecTLV(0x88, []byte{3}), iecTLV(0x89, []byte{0}),
		iecTLV(0x8a, []byte{18}),
	}
	pdu := func(allData []byte) []byte {
		fields := append(append([][]byte{}, head...), iecTLV(0xab, allData))
		return iecFrame(EthernetTypeGOOSE, 1, iecTLV(0x61, fields...))
	}

	return [][]byte{pdu(data), pdu(nil), pdu(iecTLV(0xa1))}
}

// iecSnapDump renders the GOOSE and SV layers of every frame. A frame
// that fails to decode only contributes a marker: its error may change.
func iecSnapDump(frames [][]byte) (dump []byte, decoded int) {
	var out bytes.Buffer
	for i, f := range frames {
		p := iecDecode(f)
		if p.ErrorLayer() != nil {
			fmt.Fprintf(&out, "%d: error\n", i)
			continue
		}

		for _, lt := range []gopacket.LayerType{LayerTypeGOOSE, LayerTypeSV} {
			if l := p.Layer(lt); l != nil {
				decoded++
				fmt.Fprintf(&out, "%d: %s\n", i, gopacket.LayerDump(l))
			}
		}
	}
	return out.Bytes(), decoded
}

func TestIEC61850Snapshot(t *testing.T) {
	for name, want := range iecSnapGolden {
		frames := iecSnapVectors()
		if name != iecSnapHandBuilt {
			frames = iecReadPcap(t, "testdata/"+name)
		}

		dump, decoded := iecSnapDump(frames)
		sum := sha256.Sum256(dump)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%q: %d frames, %d layers, %d octets of dump, digest %s", name, len(frames), decoded, len(dump), got)
		}
	}
}
