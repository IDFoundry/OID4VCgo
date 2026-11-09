// Package testbounds checks that a parser of untrusted bytes stays in
// bounds: it parses a valid input cut short at every length and with
// every byte changed, each in a slice with no spare capacity.
//
// The spare capacity matters. b[i:j] past len(b) but within cap(b)
// doesn't panic, so a parser missing a bounds check passes a test whose
// input is a prefix of a larger buffer, or one a fuzzer handed it, but
// panics on a message read off the radio into a buffer of its own size.
package testbounds

import (
	"fmt"
	"testing"
)

// Exact is a copy of b with no spare capacity.
func Exact(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c[:len(c):len(c)]
}

// NoPanic runs parse on Exact(b), failing t, under what, if it panics.
func NoPanic(t testing.TB, what string, b []byte, parse func([]byte) error) (err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: %x: panic: %v", what, b, r)
			err = fmt.Errorf("panicked: %v", r)
		}
	}()
	return parse(Exact(b))
}

// Check parses valid, which must succeed, then every proper prefix of
// it and every copy with one byte changed, none of which may panic.
// With refuseTruncated, every prefix must also be refused, as a whole
// message cut short is.
func Check(t testing.TB, name string, valid []byte, refuseTruncated bool, parse func([]byte) error) {
	t.Helper()
	if err := NoPanic(t, name, valid, parse); err != nil {
		t.Fatalf("%s: the valid input: %v", name, err)
	}
	for n := range len(valid) {
		if err := NoPanic(t, fmt.Sprintf("%s cut to %d bytes", name, n), valid[:n], parse); err == nil && refuseTruncated {
			t.Errorf("%s cut to %d bytes: accepted", name, n)
		}
	}
	for i := range valid {
		for _, v := range []byte{0x00, 0xff, valid[i] + 1, valid[i] - 1} {
			changed := Exact(valid)
			changed[i] = v
			_ = NoPanic(t, fmt.Sprintf("%s with byte %d set to %#x", name, i, v), changed, parse)
		}
	}
}
