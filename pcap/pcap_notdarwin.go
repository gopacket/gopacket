// Copyright 2024 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build !darwin
// +build !darwin

package pcap

// SetWantPktap is a no-op on non-Darwin platforms.
// pktap metadata headers are a macOS kernel feature only.
func (p *InactiveHandle) SetWantPktap(_ bool) error {
	return nil
}
