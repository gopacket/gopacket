package endian

import (
	"encoding/binary"
	"math/bits"
)

func hostUsesNetByteorder() bool {
	// Compiler eliminates string comparison since it knows both values
	// at compile time, https://godbolt.org/z/YKKrEdGEx
	return binary.NativeEndian.String() == binary.BigEndian.String()
}

// Htons converts x from host to network byte order.
func Htons(v uint16) uint16 {
	if hostUsesNetByteorder() {
		return v
	}
	return bits.ReverseBytes16(v)
}
