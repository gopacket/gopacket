// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build !(linux || windows)
// +build !linux,!windows

// Package routing is currently only supported in Linux and Windows, but the build system requires a valid go file for all architectures.

package routing

func (r *router) setupRouteTable() error {
	panic("router only implemented in linux and windows")
}
