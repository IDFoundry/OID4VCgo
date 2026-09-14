package sdjwtvc

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
)

// Disclosure is a single SD-JWT Disclosure (RFC 9901 §4.2): either an
// object-property disclosure (Name set, §4.2.1) or an array-element
// disclosure (Name empty, §4.2.2).
type Disclosure struct {
	Salt  string
	Name  string
	Value any

	// encoded caches Encode's result at construction/parse time, so a
	// Disclosure always re-serializes to the exact bytes its digest was
	// computed over (RFC 9901 §4.2.3) or that it was parsed from —
	// never a re-marshaled equivalent that could legally differ in
	// whitespace or key encoding without being wrong, but would break
	// digest matching against the original.
	encoded string
}

// IsArrayElement reports whether d is an array-element disclosure
// (RFC 9901 §4.2.2) rather than an object-property one (§4.2.1).
func (d Disclosure) IsArrayElement() bool { return d.Name == "" }

func newSalt() (string, error) {
	b := make([]byte, 16) // 128 bits — RFC 9901 §4.2.1's recommended entropy
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sdjwtvc: generate salt: %w", err)
	}
	return b64.EncodeToString(b), nil
}

// NewObjectDisclosure creates a Disclosure for an object property named
// name with value (RFC 9901 §4.2.1). name must not be "_sd" or "...".
func NewObjectDisclosure(name string, value any) (Disclosure, error) {
	if name == "_sd" || name == "..." {
		return Disclosure{}, fmt.Errorf("sdjwtvc: claim name %q is reserved", name)
	}
	salt, err := newSalt()
	if err != nil {
		return Disclosure{}, err
	}
	return encodeDisclosure(Disclosure{Salt: salt, Name: name, Value: value})
}

// NewArrayElementDisclosure creates a Disclosure for an array element
// (RFC 9901 §4.2.2).
func NewArrayElementDisclosure(value any) (Disclosure, error) {
	salt, err := newSalt()
	if err != nil {
		return Disclosure{}, err
	}
	return encodeDisclosure(Disclosure{Salt: salt, Value: value})
}

func encodeDisclosure(d Disclosure) (Disclosure, error) {
	encoded, err := d.encode()
	if err != nil {
		return Disclosure{}, err
	}
	d.encoded = encoded
	return d, nil
}

func (d Disclosure) encode() (string, error) {
	var arr []any
	if d.IsArrayElement() {
		arr = []any{d.Salt, d.Value}
	} else {
		arr = []any{d.Salt, d.Name, d.Value}
	}
	raw, err := json.Marshal(arr)
	if err != nil {
		return "", fmt.Errorf("sdjwtvc: encode disclosure: %w", err)
	}
	return b64.EncodeToString(raw), nil
}

// Encode returns the base64url-encoded Disclosure string (RFC 9901
// §4.2.1/§4.2.2) — the exact bytes a digest is computed over and that
// appear in the SD-JWT's compact serialization.
func (d Disclosure) Encode() (string, error) {
	if d.encoded != "" {
		return d.encoded, nil
	}
	return d.encode()
}

// ParseDisclosure parses a base64url-encoded Disclosure string.
func ParseDisclosure(s string) (Disclosure, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return Disclosure{}, fmt.Errorf("sdjwtvc: decode disclosure: %w", err)
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return Disclosure{}, fmt.Errorf("sdjwtvc: unmarshal disclosure: %w", err)
	}

	d := Disclosure{encoded: s}
	switch len(arr) {
	case 2:
		if err := json.Unmarshal(arr[0], &d.Salt); err != nil {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure salt: %w", err)
		}
		var v any
		if err := json.Unmarshal(arr[1], &v); err != nil {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure value: %w", err)
		}
		d.Value = v
	case 3:
		if err := json.Unmarshal(arr[0], &d.Salt); err != nil {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure salt: %w", err)
		}
		if err := json.Unmarshal(arr[1], &d.Name); err != nil {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure name: %w", err)
		}
		if d.Name == "_sd" || d.Name == "..." {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure claim name %q is reserved", d.Name)
		}
		var v any
		if err := json.Unmarshal(arr[2], &v); err != nil {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure value: %w", err)
		}
		d.Value = v
	default:
		return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure array has %d elements, want 2 or 3", len(arr))
	}
	return d, nil
}

// Digest returns the base64url-encoded digest of d's encoded form under
// alg (RFC 9901 §4.2.3).
func (d Disclosure) Digest(alg HashAlg) (string, error) {
	encoded, err := d.Encode()
	if err != nil {
		return "", err
	}
	return hashString(alg, encoded)
}
