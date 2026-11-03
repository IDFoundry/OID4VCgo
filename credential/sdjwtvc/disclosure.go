package sdjwtvc

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// Disclosure is a single SD-JWT Disclosure (RFC 9901 §4.2): either an
// object-property disclosure (§4.2.1) or an array-element disclosure
// (§4.2.2). One built as a literal is an array element when its Name is
// empty; one from NewObjectDisclosure or ParseDisclosure keeps the form
// it was made in, so a property named "" (a valid JSON name) stays a
// property.
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

	// named is set for an object-property disclosure whatever its Name,
	// "" included: the arity it was made or parsed with, not its Name.
	named bool
}

// IsArrayElement reports whether d is an array-element disclosure
// (RFC 9901 §4.2.2) rather than an object-property one (§4.2.1).
func (d Disclosure) IsArrayElement() bool { return !d.named && d.Name == "" }

func newSalt() (string, error) {
	b := make([]byte, 16) // 128 bits — RFC 9901 §4.2.1's recommended entropy
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("sdjwtvc: generate salt: %w", err)
	}
	return b64.EncodeToString(b), nil
}

// NewObjectDisclosure creates a Disclosure for an object property named
// name with value (RFC 9901 §4.2.1). name must not be "_sd", "_sd_alg"
// or "...".
func NewObjectDisclosure(name string, value any) (Disclosure, error) {
	if name == "_sd" || name == "_sd_alg" || name == "..." {
		return Disclosure{}, fmt.Errorf("sdjwtvc: claim name %q is reserved", name)
	}
	salt, err := newSalt()
	if err != nil {
		return Disclosure{}, err
	}
	return encodeDisclosure(Disclosure{Salt: salt, Name: name, Value: value, named: true})
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
	// strictjson: a disclosed object with a member twice is refused,
	// not read last-wins as encoding/json would.
	var arr []json.RawMessage
	if err := strictjson.Unmarshal(raw, &arr); err != nil {
		return Disclosure{}, fmt.Errorf("sdjwtvc: unmarshal disclosure: %w", err)
	}

	d := Disclosure{encoded: s}
	switch len(arr) {
	case 2:
		if err := jsonString(arr[0], &d.Salt); err != nil {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure salt: %w", err)
		}
		var v any
		if err := strictjson.Unmarshal(arr[1], &v); err != nil {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure value: %w", err)
		}
		d.Value = v
	case 3:
		if err := jsonString(arr[0], &d.Salt); err != nil {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure salt: %w", err)
		}
		if err := jsonString(arr[1], &d.Name); err != nil {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure name: %w", err)
		}
		d.named = true
		// _sd_alg belongs at the payload's top level alone (RFC 9901
		// §4.1.1), never in a disclosure.
		if d.Name == "_sd" || d.Name == "_sd_alg" || d.Name == "..." {
			return Disclosure{}, fmt.Errorf("sdjwtvc: disclosure claim name %q is reserved", d.Name)
		}
		var v any
		if err := strictjson.Unmarshal(arr[2], &v); err != nil {
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

// jsonString decodes raw, which must be a JSON string (RFC 9901 §4.2.1
// and §4.2.2 make a Disclosure's salt and claim name strings), into s.
// encoding/json would leave s empty for null.
func jsonString(raw json.RawMessage, s *string) error {
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte(`"`)) {
		return fmt.Errorf("not a string")
	}
	return strictjson.Unmarshal(raw, s)
}
