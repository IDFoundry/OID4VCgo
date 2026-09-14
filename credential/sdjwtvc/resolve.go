package sdjwtvc

import "fmt"

// ResolveDisclosures implements RFC 9901 §7.1 steps 3-5: it matches
// each Disclosure to a digest embedded — directly or recursively —
// in payload, replaces each matched digest with the disclosed claim or
// array element, strips _sd/_sd_alg, and rejects the input if a digest
// repeats anywhere in payload (step 4) or a Disclosure goes unused
// (step 5). A digest with no matching Disclosure is left absent from
// the result (an object property is simply not added; an array element
// is dropped) rather than treated as an error — §7.1 step 3.c.i: "If no
// such Disclosure can be found, the digest MUST be ignored" — since
// this is the normal shape of a decoy digest or a Disclosure a Holder
// chose not to present.
func ResolveDisclosures(payload map[string]any, alg HashAlg, disclosures []Disclosure) (map[string]any, error) {
	byDigest := make(map[string]Disclosure, len(disclosures))
	for _, d := range disclosures {
		digest, err := d.Digest(alg)
		if err != nil {
			return nil, err
		}
		if _, dup := byDigest[digest]; dup {
			return nil, fmt.Errorf("sdjwtvc: two presented disclosures hash to the same digest %s", digest)
		}
		byDigest[digest] = d
	}

	usedDigests := make(map[string]bool, len(disclosures))
	seenDigests := make(map[string]bool)

	resolved, err := resolveValue(payload, byDigest, usedDigests, seenDigests)
	if err != nil {
		return nil, err
	}
	resolvedMap, ok := resolved.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("sdjwtvc: resolved SD-JWT payload is not a JSON object")
	}
	if len(usedDigests) != len(disclosures) {
		return nil, fmt.Errorf("sdjwtvc: %d disclosure(s) were not referenced by any digest in the payload", len(disclosures)-len(usedDigests))
	}
	return resolvedMap, nil
}

func resolveValue(v any, byDigest map[string]Disclosure, usedDigests, seenDigests map[string]bool) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		return resolveMap(t, byDigest, usedDigests, seenDigests)
	case []any:
		return resolveArray(t, byDigest, usedDigests, seenDigests)
	default:
		return v, nil
	}
}

func resolveMap(m map[string]any, byDigest map[string]Disclosure, usedDigests, seenDigests map[string]bool) (map[string]any, error) {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k == "_sd" || k == "_sd_alg" {
			continue
		}
		resolved, err := resolveValue(v, byDigest, usedDigests, seenDigests)
		if err != nil {
			return nil, err
		}
		out[k] = resolved
	}

	sdRaw, hasSD := m["_sd"]
	if !hasSD {
		return out, nil
	}
	sdList, ok := sdRaw.([]any)
	if !ok {
		return nil, fmt.Errorf("sdjwtvc: _sd is not an array")
	}
	for _, item := range sdList {
		digest, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("sdjwtvc: _sd entry is not a string")
		}
		if seenDigests[digest] {
			return nil, fmt.Errorf("sdjwtvc: digest %s appears more than once in the SD-JWT", digest)
		}
		seenDigests[digest] = true

		d, found := byDigest[digest]
		if !found {
			continue
		}
		if d.IsArrayElement() {
			return nil, fmt.Errorf("sdjwtvc: disclosure for digest %s is an array-element disclosure but was embedded in an object's _sd", digest)
		}
		if _, exists := out[d.Name]; exists {
			return nil, fmt.Errorf("sdjwtvc: claim %q already exists at this level", d.Name)
		}
		usedDigests[digest] = true
		resolvedValue, err := resolveValue(d.Value, byDigest, usedDigests, seenDigests)
		if err != nil {
			return nil, err
		}
		out[d.Name] = resolvedValue
	}
	return out, nil
}

func resolveArray(arr []any, byDigest map[string]Disclosure, usedDigests, seenDigests map[string]bool) ([]any, error) {
	out := make([]any, 0, len(arr))
	for _, el := range arr {
		if obj, ok := el.(map[string]any); ok && len(obj) == 1 {
			if digestRaw, has := obj["..."]; has {
				digest, ok := digestRaw.(string)
				if !ok {
					return nil, fmt.Errorf(`sdjwtvc: array element "..." value is not a string`)
				}
				if seenDigests[digest] {
					return nil, fmt.Errorf("sdjwtvc: digest %s appears more than once in the SD-JWT", digest)
				}
				seenDigests[digest] = true

				d, found := byDigest[digest]
				if !found {
					continue
				}
				if !d.IsArrayElement() {
					return nil, fmt.Errorf("sdjwtvc: disclosure for digest %s is an object-property disclosure but was embedded as an array element", digest)
				}
				usedDigests[digest] = true
				resolvedValue, err := resolveValue(d.Value, byDigest, usedDigests, seenDigests)
				if err != nil {
					return nil, err
				}
				out = append(out, resolvedValue)
				continue
			}
		}
		resolved, err := resolveValue(el, byDigest, usedDigests, seenDigests)
		if err != nil {
			return nil, err
		}
		out = append(out, resolved)
	}
	return out, nil
}
