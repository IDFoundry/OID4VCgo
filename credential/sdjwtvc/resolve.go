package sdjwtvc

import "fmt"

// MaxResolveDepth bounds how deeply ResolveDisclosures will recurse
// into payload's own object/array nesting, or into a disclosed
// value's own further _sd/"..." digests (RFC 9901 §7.1's own
// disclosure-chaining), before rejecting the input — to avoid
// unbounded CPU/allocation work walking a maliciously deep structure
// before anything is rejected. encoding/json.Unmarshal's own
// ~10000-level built-in nesting cap is the only other backstop here,
// which bounds a crash but not the cost of walking up to it; matches
// this repo's own established "every untrusted-parsing path gets an
// explicit, repo-chosen ceiling" discipline (internal/jose/internal/jwe/
// internal/cose's own MaxCompactBytes/MaxBytes) — found missing here in
// a repo-wide security review. A caller whose accepted input can
// legitimately nest deeper should call ResolveDisclosuresMax with its
// own configured ceiling instead.
const MaxResolveDepth = 32

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
// chose not to present. It rejects payload/disclosure nesting deeper
// than MaxResolveDepth; use ResolveDisclosuresMax for a caller that
// needs a different ceiling.
func ResolveDisclosures(payload map[string]any, alg HashAlg, disclosures []Disclosure) (map[string]any, error) {
	return ResolveDisclosuresMax(payload, alg, disclosures, MaxResolveDepth)
}

// ResolveDisclosuresMax is ResolveDisclosures with an explicit nesting
// depth ceiling instead of MaxResolveDepth.
func ResolveDisclosuresMax(payload map[string]any, alg HashAlg, disclosures []Disclosure, maxDepth int) (map[string]any, error) {
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

	resolved, err := resolveValue(payload, byDigest, usedDigests, seenDigests, 0, maxDepth)
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

func resolveValue(v any, byDigest map[string]Disclosure, usedDigests, seenDigests map[string]bool, depth, maxDepth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("sdjwtvc: payload/disclosure nesting exceeds the %d level limit", maxDepth)
	}
	switch t := v.(type) {
	case map[string]any:
		return resolveMap(t, byDigest, usedDigests, seenDigests, depth, maxDepth)
	case []any:
		return resolveArray(t, byDigest, usedDigests, seenDigests, depth, maxDepth)
	default:
		return v, nil
	}
}

func resolveMap(m map[string]any, byDigest map[string]Disclosure, usedDigests, seenDigests map[string]bool, depth, maxDepth int) (map[string]any, error) {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k == "_sd" || k == "_sd_alg" {
			continue
		}
		resolved, err := resolveValue(v, byDigest, usedDigests, seenDigests, depth+1, maxDepth)
		if err != nil {
			return nil, err
		}
		out[k] = resolved
	}
	if err := resolveSDDigests(m, out, byDigest, usedDigests, seenDigests, depth, maxDepth); err != nil {
		return nil, err
	}
	return out, nil
}

// resolveSDDigests resolves m's own top-level "_sd" array (RFC 9901
// §4.1.1) into out, in place — split out of resolveMap purely to keep
// it under the linter's own cognitive complexity ceiling.
func resolveSDDigests(m, out map[string]any, byDigest map[string]Disclosure, usedDigests, seenDigests map[string]bool, depth, maxDepth int) error {
	sdRaw, hasSD := m["_sd"]
	if !hasSD {
		return nil
	}
	sdList, ok := sdRaw.([]any)
	if !ok {
		return fmt.Errorf("sdjwtvc: _sd is not an array")
	}
	for _, item := range sdList {
		digest, ok := item.(string)
		if !ok {
			return fmt.Errorf("sdjwtvc: _sd entry is not a string")
		}
		if seenDigests[digest] {
			return fmt.Errorf("sdjwtvc: digest %s appears more than once in the SD-JWT", digest)
		}
		seenDigests[digest] = true

		d, found := byDigest[digest]
		if !found {
			continue
		}
		if d.IsArrayElement() {
			return fmt.Errorf("sdjwtvc: disclosure for digest %s is an array-element disclosure but was embedded in an object's _sd", digest)
		}
		if _, exists := out[d.Name]; exists {
			return fmt.Errorf("sdjwtvc: claim %q already exists at this level", d.Name)
		}
		usedDigests[digest] = true
		resolvedValue, err := resolveValue(d.Value, byDigest, usedDigests, seenDigests, depth+1, maxDepth)
		if err != nil {
			return err
		}
		out[d.Name] = resolvedValue
	}
	return nil
}

func resolveArray(arr []any, byDigest map[string]Disclosure, usedDigests, seenDigests map[string]bool, depth, maxDepth int) ([]any, error) {
	out := make([]any, 0, len(arr))
	for _, el := range arr {
		newOut, handled, err := appendResolvedDisclosureRef(out, el, byDigest, usedDigests, seenDigests, depth, maxDepth)
		if err != nil {
			return nil, err
		}
		if handled {
			out = newOut
			continue
		}
		resolved, err := resolveValue(el, byDigest, usedDigests, seenDigests, depth+1, maxDepth)
		if err != nil {
			return nil, err
		}
		out = append(out, resolved)
	}
	return out, nil
}

// appendResolvedDisclosureRef is resolveArray's own handling of one
// array element that might be an RFC 9901 §4.2.6 recursive-disclosure
// reference ({"...": "<digest>"}) — split out purely to keep
// resolveArray under the linter's own cognitive complexity ceiling.
// handled=false means el isn't such a reference at all, and the caller
// should fall back to resolving it as an ordinary value; handled=true
// covers all three reference outcomes: appended (out gains the
// disclosed value), silently dropped (no matching Disclosure, per §7.1
// step 3.c.i — out is returned unchanged), or a malformed/duplicate
// reference (err is set).
func appendResolvedDisclosureRef(out []any, el any, byDigest map[string]Disclosure, usedDigests, seenDigests map[string]bool, depth, maxDepth int) (result []any, handled bool, err error) {
	obj, ok := el.(map[string]any)
	if !ok || len(obj) != 1 {
		return out, false, nil
	}
	digestRaw, has := obj["..."]
	if !has {
		return out, false, nil
	}
	digest, ok := digestRaw.(string)
	if !ok {
		return nil, true, fmt.Errorf(`sdjwtvc: array element "..." value is not a string`)
	}
	if seenDigests[digest] {
		return nil, true, fmt.Errorf("sdjwtvc: digest %s appears more than once in the SD-JWT", digest)
	}
	seenDigests[digest] = true

	d, found := byDigest[digest]
	if !found {
		return out, true, nil
	}
	if !d.IsArrayElement() {
		return nil, true, fmt.Errorf("sdjwtvc: disclosure for digest %s is an object-property disclosure but was embedded as an array element", digest)
	}
	usedDigests[digest] = true
	resolvedValue, err := resolveValue(d.Value, byDigest, usedDigests, seenDigests, depth+1, maxDepth)
	if err != nil {
		return nil, true, err
	}
	return append(out, resolvedValue), true, nil
}
