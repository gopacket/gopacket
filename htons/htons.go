package htons

import "unsafe"

// Htons converts x from host to network byte order.
func Htons(x uint16) uint16 {
	o := 1
	if *(*byte)(unsafe.Pointer(&o)) == 0 {
		return x
	}
	return x<<8 | x>>8
}
