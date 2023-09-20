// Copyright 2012, Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

func FuzzNewPacket(f *testing.F) {
	// Seed the corpus with test data from CDP
	for _, td := range cdpTestData {
		f.Add(td.data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		stime := time.Now()
		_ = gopacket.NewPacket(data, LinkTypeEthernet, testDecodeOptions)

		if e := time.Since(stime); e > (time.Second * 1) {
			t.Errorf("corpus entry took too long: %s", e)
		}
	})
}
