package sdjwtvc

import (
	"fmt"
	"strings"
)

// minNestedDigestChars is the fewest encoded Disclosure characters a
// digest inside a Disclosure takes: the shortest digest, SHA-256's, is
// 43 base64url characters in the Disclosure's JSON, which encoding the
// Disclosure grows by a third.
const minNestedDigestChars = 57

// parseReferencedDisclosures decodes encoded, a presentation's encoded
// Disclosures joined by '~' (present false for none), given payload,
// its verified Issuer-signed JWT's payload: each part is hashed, and
// only a part whose digest payload or a part already decoded
// references (RFC 9901 §4.2.4, §4.2.6) is decoded, in turn. A part no
// digest references, or one repeating another, is refused, as
// ResolveDisclosures would refuse it after decoding (§7.1 step 3.5),
// but here before any is decoded: the decoding work is then bounded by
// the digests the issuer signed. So is the hashing: more parts than
// payload's digests, and the digests encoded's length leaves room for,
// could reference are refused before any is split off or hashed. The
// Disclosures keep their presented order.
func parseReferencedDisclosures(payload map[string]any, alg HashAlg, encoded string, present bool) ([]Disclosure, error) {
	if !present {
		return nil, nil
	}
	pending := collectDigests(payload, nil, 0)
	n := strings.Count(encoded, "~") + 1
	if limit := len(pending) + len(encoded)/minNestedDigestChars; n > limit {
		return nil, fmt.Errorf("sdjwtvc: %d disclosures presented, more than the payload's digests could reference (%d)", n, limit)
	}
	parts := strings.Split(encoded, "~")
	index := make(map[string]int, len(parts))
	for i, part := range parts {
		digest, err := hashString(alg, part)
		if err != nil {
			return nil, err
		}
		if _, dup := index[digest]; dup {
			return nil, fmt.Errorf("sdjwtvc: two presented disclosures hash to the same digest %s", digest)
		}
		index[digest] = i
	}
	out := make([]Disclosure, len(parts))
	decoded := 0
	for len(pending) > 0 {
		digest := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		i, ok := index[digest]
		if !ok {
			continue
		}
		delete(index, digest)
		d, err := ParseDisclosure(parts[i])
		if err != nil {
			return nil, fmt.Errorf("sdjwtvc: disclosure %d: %w", i, err)
		}
		out[i] = d
		decoded++
		pending = collectDigests(d.Value, pending, 0)
	}
	if decoded != len(parts) {
		return nil, fmt.Errorf("sdjwtvc: %d disclosure(s) were not referenced by any digest in the payload", len(parts)-decoded)
	}
	return out, nil
}

// collectDigests appends to out every digest v references at any
// depth: an object's _sd entries and an array's {"...": digest}
// elements, the places ResolveDisclosures looks. Nesting past
// MaxResolveDepth is left for ResolveDisclosures to refuse.
func collectDigests(v any, out []string, depth int) []string {
	if depth > MaxResolveDepth {
		return out
	}
	switch t := v.(type) {
	case map[string]any:
		out = append(out, sdDigests(t)...)
		for k, child := range t {
			if k != "_sd" {
				out = collectDigests(child, out, depth+1)
			}
		}
	case []any:
		for _, el := range t {
			if digest, isRef := disclosureRefDigest(el); isRef {
				out = append(out, digest)
			} else {
				out = collectDigests(el, out, depth+1)
			}
		}
	}
	return out
}
