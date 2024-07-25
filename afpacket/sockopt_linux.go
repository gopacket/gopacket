// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

//go:build linux
// +build linux

package afpacket

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// setsockopt provides access to the setsockopt syscall.
func setsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		vallen,
		0,
	)
	if errno != 0 {
		return error(errno)
	}

	return nil
}

// getsockopt provides access to the getsockopt syscall.
func getsockopt(fd, level, name int, val unsafe.Pointer, vallen uintptr) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		vallen,
		0,
	)
	if errno != 0 {
		return error(errno)
	}

	return nil
}
