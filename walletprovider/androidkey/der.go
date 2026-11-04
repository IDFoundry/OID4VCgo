package androidkey

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// The DER readers below are deliberately small and lenient in the two
// places Keymaster implementations are known to stray from DER: a
// BOOLEAN true other than 0xFF, and an INTEGER with a redundant leading
// byte. Neither changes what the value means. Everything else — tags,
// lengths, nesting — must be exact, and every read is bounded.

// maxElements bounds how many elements one SEQUENCE or SET may hold.
// The largest, an AuthorizationList, has fewer than 60 defined fields.
const maxElements = 128

// maxIntegerBytes bounds an INTEGER's encoding: every integer in the
// schema fits in 64 bits, with one byte to spare for a sign.
const maxIntegerBytes = 9

// element reads one complete TLV from der and returns it with the
// bytes after it.
func element(der []byte) (asn1.RawValue, []byte, error) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil {
		return asn1.RawValue{}, nil, err
	}
	return v, rest, nil
}

// single reads der as exactly one TLV.
func single(der []byte) (asn1.RawValue, error) {
	v, rest, err := element(der)
	if err != nil {
		return asn1.RawValue{}, err
	}
	if len(rest) != 0 {
		return asn1.RawValue{}, errors.New("trailing data")
	}
	return v, nil
}

// universal reports whether v is the universal type tag, constructed
// or primitive as compound says.
func universal(v asn1.RawValue, tag int, compound bool) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == tag && v.IsCompound == compound
}

// children splits a constructed value's contents into its elements.
func children(v asn1.RawValue) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for rest := v.Bytes; len(rest) > 0; {
		if len(out) == maxElements {
			return nil, fmt.Errorf("more than %d elements", maxElements)
		}
		e, next, err := element(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		rest = next
	}
	return out, nil
}

// constructed checks v is a SEQUENCE (or SET, by tag) and returns its
// elements.
func constructed(v asn1.RawValue, tag int, what string) ([]asn1.RawValue, error) {
	if !universal(v, tag, true) {
		return nil, fmt.Errorf("%s: not a %s", what, tagName(tag))
	}
	elems, err := children(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return elems, nil
}

func tagName(tag int) string {
	if tag == asn1.TagSet {
		return "SET"
	}
	return "SEQUENCE"
}

// integer reads an INTEGER (or, with tag TagEnum, an ENUMERATED) that
// fits in an int64.
func integer(v asn1.RawValue, tag int) (int64, error) {
	if !universal(v, tag, false) {
		return 0, fmt.Errorf("tag %d, want %d", v.Tag, tag)
	}
	b := v.Bytes
	if len(b) == 0 || len(b) > maxIntegerBytes {
		return 0, fmt.Errorf("a %d-byte integer", len(b))
	}
	n := new(big.Int).SetBytes(b)
	if b[0]&0x80 != 0 {
		n.Sub(n, new(big.Int).Lsh(big.NewInt(1), uint(8*len(b))))
	}
	if !n.IsInt64() {
		return 0, errors.New("integer out of range")
	}
	return n.Int64(), nil
}

// octets reads a primitive OCTET STRING.
func octets(v asn1.RawValue) ([]byte, error) {
	if !universal(v, asn1.TagOctetString, false) {
		return nil, fmt.Errorf("tag %d, want an OCTET STRING", v.Tag)
	}
	return v.Bytes, nil
}

// boolean reads a BOOLEAN: zero is false, any other byte true.
func boolean(v asn1.RawValue) (bool, error) {
	if !universal(v, asn1.TagBoolean, false) || len(v.Bytes) != 1 {
		return false, errors.New("not a one-byte BOOLEAN")
	}
	return v.Bytes[0] != 0, nil
}

// null checks v is a NULL.
func null(v asn1.RawValue) error {
	if !universal(v, asn1.TagNull, false) || len(v.Bytes) != 0 {
		return errors.New("not a NULL")
	}
	return nil
}

// integerSet reads a SET OF INTEGER.
func integerSet(v asn1.RawValue) ([]int64, error) {
	elems, err := constructed(v, asn1.TagSet, "set")
	if err != nil {
		return nil, err
	}
	out := make([]int64, 0, len(elems))
	for _, e := range elems {
		n, err := integer(e, asn1.TagInteger)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
