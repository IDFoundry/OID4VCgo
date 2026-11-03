package statuslist

import (
	"encoding/base64"
	"testing"
)

// lst is decoded as strictly as every other base64url value: no line
// breaks, and no stray bits past the last byte.
func TestStatusList_LstIsStrictBase64URL(t *testing.T) {
	sl, err := New(Bits1, []uint8{0, 1, 0}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(sl.Lst)%4 == 0 {
		t.Fatalf("lst %q has no partial final group: the test proves nothing", sl.Lst)
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := sl.Lst[len(sl.Lst)-1]
	stray := sl.Lst[:len(sl.Lst)-1] + string(alphabet[(indexOf(alphabet, last)|1)])
	if stray == sl.Lst {
		stray = sl.Lst[:len(sl.Lst)-1] + string(alphabet[(indexOf(alphabet, last)|2)])
	}
	if _, err := base64.RawURLEncoding.DecodeString(stray); err != nil {
		t.Fatalf("lenient decoding refuses %q too: the test proves nothing", stray)
	}
	for name, lst := range map[string]string{
		"stray trailing bits": stray,
		"a line break":        sl.Lst[:2] + "\n" + sl.Lst[2:],
	} {
		bad := StatusList{Bits: sl.Bits, Lst: lst}
		if _, err := bad.Decode(); err == nil {
			t.Errorf("%s: Decode accepted %q", name, lst)
		}
		if _, err := bad.Status(0); err == nil {
			t.Errorf("%s: Status accepted %q", name, lst)
		}
	}
}

func indexOf(s string, c byte) int {
	for i := range len(s) {
		if s[i] == c {
			return i
		}
	}
	return -1
}
