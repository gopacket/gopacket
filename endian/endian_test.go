package endian

import (
	"encoding/binary"
	"testing"
)

func TestIsLittleEndian(t *testing.T) {
	if !isLittleEndian(binary.LittleEndian) {
		t.Error("binary.LittleEndian was not detected as little endian")
	}
	if isLittleEndian(binary.BigEndian) {
		t.Error("binary.BigEndian was detected as little endian")
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
