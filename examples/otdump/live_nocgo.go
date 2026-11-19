// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build !cgo

package main

import "errors"

// openLive needs libpcap, which a build without cgo cannot link; reading
// files with -r still works.
func openLive(string, int) (captureSource, func(), error) {
	return nil, nil, errors.New("live capture needs a cgo build with libpcap")
}
