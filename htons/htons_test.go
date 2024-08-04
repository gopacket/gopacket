package htons

import (
	"testing"
	"unsafe"
)

func TestHtons(t *testing.T) {
	tt := []struct {
		host, net uint16
	}{
		{0x0001, 0x0100},
		{0xcafe, 0xfeca},
		{0xbabe, 0xbeba},
		{0x0000, 0x0000},
		{0xffff, 0xffff},
	}
	x := 1
	isBigEndian := *(*byte)(unsafe.Pointer(&x)) == 0
	for _, v := range tt {
		var want uint16
		if isBigEndian {
			want = v.host
		} else {
			want = v.net
		}
		x := Htons(v.host)
		if x != want {
			t.Errorf("isBig: %t htons(%04x) = <%04x> want <%04x>", isBigEndian, v.host, x, want)
		}
	}
}
