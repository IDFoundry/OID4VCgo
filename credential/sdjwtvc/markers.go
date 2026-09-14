package sdjwtvc

import (
	"fmt"
	"sort"
)

// SD marks value as a selectively disclosable object property
// (RFC 9901 §4.2.1) when used as a value in a map[string]any passed to
// Issue via Claims.Additional. It has no effect used anywhere else in
// the claim tree.
func SD(value any) any { return sdValue{value} }

// SDElement marks value as a selectively disclosable array element
// (RFC 9901 §4.2.2) when used as an element of a []any passed to Issue.
// It has no effect used anywhere else in the claim tree.
func SDElement(value any) any { return sdElement{value} }

type sdValue struct{ v any }
type sdElement struct{ v any }

// seal walks a claims tree, replacing every SD/SDElement marker with
// its digest — embedded per RFC 9901 §4.2.4 — and collecting the
// corresponding Disclosures, recursively. A disclosed value that itself
// contains further markers therefore produces §4.2.6 "recursive
// Disclosures" with no special-casing: sealing an outer SD() value
// first seals its contents, so the outer Disclosure's own value already
// has any inner digests embedded in it.
func seal(v any, alg HashAlg) (any, []Disclosure, error) {
	switch t := v.(type) {
	case map[string]any:
		return sealMap(t, alg)
	case []any:
		return sealArray(t, alg)
	case sdValue:
		return nil, nil, fmt.Errorf("sdjwtvc: SD() used outside an object property value")
	case sdElement:
		return nil, nil, fmt.Errorf("sdjwtvc: SDElement() used outside an array element")
	default:
		return v, nil, nil
	}
}

func sealMap(m map[string]any, alg HashAlg) (map[string]any, []Disclosure, error) {
	out := make(map[string]any, len(m))
	var digests []string
	var disclosures []Disclosure

	for k, v := range m {
		if k == "_sd" || k == "_sd_alg" || k == "..." {
			return nil, nil, fmt.Errorf("sdjwtvc: claim name %q is reserved", k)
		}
		if sv, ok := v.(sdValue); ok {
			sealedInner, innerDs, err := seal(sv.v, alg)
			if err != nil {
				return nil, nil, err
			}
			d, err := NewObjectDisclosure(k, sealedInner)
			if err != nil {
				return nil, nil, err
			}
			digest, err := d.Digest(alg)
			if err != nil {
				return nil, nil, err
			}
			digests = append(digests, digest)
			disclosures = append(disclosures, d)
			disclosures = append(disclosures, innerDs...)
			continue
		}
		sealed, ds, err := seal(v, alg)
		if err != nil {
			return nil, nil, err
		}
		out[k] = sealed
		disclosures = append(disclosures, ds...)
	}

	if len(digests) > 0 {
		// RFC 9901 §4.2.4.1: the Issuer MUST hide the original claim
		// order. Sorting is a simple, deterministic way to do that —
		// the spec only requires the method not depend on the
		// original order, not that it be random.
		sort.Strings(digests)
		sd := make([]any, len(digests))
		for i, dg := range digests {
			sd[i] = dg
		}
		out["_sd"] = sd
	}
	return out, disclosures, nil
}

func sealArray(arr []any, alg HashAlg) ([]any, []Disclosure, error) {
	out := make([]any, 0, len(arr))
	var disclosures []Disclosure

	for _, el := range arr {
		if se, ok := el.(sdElement); ok {
			sealedInner, innerDs, err := seal(se.v, alg)
			if err != nil {
				return nil, nil, err
			}
			d, err := NewArrayElementDisclosure(sealedInner)
			if err != nil {
				return nil, nil, err
			}
			digest, err := d.Digest(alg)
			if err != nil {
				return nil, nil, err
			}
			out = append(out, map[string]any{"...": digest})
			disclosures = append(disclosures, d)
			disclosures = append(disclosures, innerDs...)
			continue
		}
		sealed, ds, err := seal(el, alg)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, sealed)
		disclosures = append(disclosures, ds...)
	}
	return out, disclosures, nil
}

// addDecoys adds n decoy digests (RFC 9901 §4.2.5) to payload's
// top-level _sd array, creating it if necessary. Decoys at nested
// levels aren't supported yet — add them the same way sealMap adds its
// own _sd array once a real caller needs per-level decoys, rather than
// speculatively now.
func addDecoys(payload map[string]any, alg HashAlg, n int) error {
	existing, _ := payload["_sd"].([]any)
	digests := make([]string, 0, len(existing)+n)
	for _, d := range existing {
		if s, ok := d.(string); ok {
			digests = append(digests, s)
		}
	}
	for i := 0; i < n; i++ {
		salt, err := newSalt()
		if err != nil {
			return err
		}
		// Hash arbitrary random data — RFC 9901 §4.2.5: a decoy has no
		// real Disclosure behind it.
		digest, err := hashString(alg, salt)
		if err != nil {
			return err
		}
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	sd := make([]any, len(digests))
	for i, d := range digests {
		sd[i] = d
	}
	payload["_sd"] = sd
	return nil
}
