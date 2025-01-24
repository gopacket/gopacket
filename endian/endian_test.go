package endian

import (
	"encoding/binary"
	"testing"
)

func TestHostUsesNetByteorder(t *testing.T) {
	buf := [2]byte{0, 42}
	hostIsNet := 42 == binary.NativeEndian.Uint16(buf[:])
	if hostIsNet != hostUsesNetByteorder() {
		t.Errorf("hostUsesNetByteorder: want %v, got %v", hostIsNet, hostUsesNetByteorder())
	}
}

func TestHtons(t *testing.T) {
	for _, v := range []uint16{0, 1, 0xcafe, 0xbabe, 0xffff} {
		var buf [2]byte
		binary.BigEndian.PutUint16(buf[:], v)
		expected := binary.NativeEndian.Uint16(buf[:])
		if Htons(v) != expected {
			t.Errorf("Htons(%x): got %x, want %x", v, Htons(v), expected)
		}
	}
}
