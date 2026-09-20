package sdjwtvc

import "fmt"

// SelectDisclosures returns the subset of all needed to disclose
// exactly the claims named by paths — RFC 9901 §7.2's own "the Holder
// MAY choose to not disclose ... some or all of the Disclosures".
// Each path is a sequence of top-level-then-nested object property
// names (e.g. []string{"address", "street_address"}) walked against
// payload — the Issuer JWT's own not-yet-resolved claims (still
// carrying "_sd"/"_sd_alg"), exactly what jose.DecodeUnverified's own
// payload return value is before ResolveDisclosures runs.
//
// Walking a path descends only through object properties — a
// mandatory (already-plaintext) one is followed directly; a
// selectively-disclosable one is resolved by finding its own
// Disclosure among the current object's "_sd" array, which is then
// included in the result. Once a path is fully walked, every
// Disclosure the target value itself transitively references
// (recursively, through further nested "_sd"/"..." entries — RFC 9901
// §4.2.6's own "recursive Disclosures", including array elements) is
// included too, so the disclosed value comes through intact rather
// than missing its own internal selectively-disclosed pieces. A path
// component absent from payload (a claim the credential doesn't
// actually carry) is silently skipped — asking to disclose a claim
// that isn't there discloses nothing for it, the same "ignore, don't
// error" stance ResolveDisclosures itself takes for an unmatched
// digest (§7.1 step 3.c.i).
//
// This function only understands object-property traversal — it has
// no notion of selecting one array element or one specific index (the
// §7.1 wildcard/integer path components a JSON-based Claims Path
// Pointer can carry into an *array*, as opposed to indexing into an
// object). A caller whose own paths need that is expected to fall back
// to disclosing more broadly itself; see wallet's own doc comment for
// where this repo currently draws that line.
func SelectDisclosures(payload map[string]any, alg HashAlg, all []Disclosure, paths [][]string) ([]Disclosure, error) {
	byDigest := make(map[string]Disclosure, len(all))
	for _, d := range all {
		digest, err := d.Digest(alg)
		if err != nil {
			return nil, err
		}
		byDigest[digest] = d
	}

	selected := make(map[string]Disclosure)
	for _, path := range paths {
		if err := selectPath(payload, byDigest, path, selected); err != nil {
			return nil, err
		}
	}

	out := make([]Disclosure, 0, len(selected))
	for _, d := range selected {
		out = append(out, d)
	}
	return out, nil
}

// selectPath walks node — a raw, not-yet-resolved SD-JWT subtree —
// following path's own sequence of object-property names, marking
// every Disclosure traversed along the way into selected (keyed by
// digest, so revisiting the same one via a different path is a no-op).
func selectPath(node any, byDigest map[string]Disclosure, path []string, selected map[string]Disclosure) error {
	if len(path) == 0 {
		return includeAllDisclosures(node, byDigest, selected)
	}
	obj, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("sdjwtvc: select disclosures: path element %q: not an object", path[0])
	}
	key := path[0]
	if child, present := obj[key]; present {
		return selectPath(child, byDigest, path[1:], selected)
	}

	for _, digest := range sdDigests(obj) {
		d, found := byDigest[digest]
		if !found || d.IsArrayElement() || d.Name != key {
			continue
		}
		selected[digest] = d
		return selectPath(d.Value, byDigest, path[1:], selected)
	}
	return nil
}

// sdDigests returns obj's own "_sd" array entries that are actually
// strings — the digest list every level of a not-yet-resolved SD-JWT
// payload carries, per RFC 9901 §4.1.1. A non-string entry is silently
// skipped rather than treated as an error, the same "malformed input
// degrades gracefully" stance byDigest lookups elsewhere in this file
// already take for a digest with no matching Disclosure.
func sdDigests(obj map[string]any) []string {
	raw, _ := obj["_sd"].([]any)
	digests := make([]string, 0, len(raw))
	for _, item := range raw {
		if digest, ok := item.(string); ok {
			digests = append(digests, digest)
		}
	}
	return digests
}

// includeAllDisclosures marks every Disclosure node transitively
// references — recursively, through nested "_sd" object entries and
// "..." array entries — as selected. Called once a path has been
// fully walked, so the disclosed target value comes through with its
// own internal selective disclosures intact rather than left as
// unresolved digest stubs.
func includeAllDisclosures(node any, byDigest map[string]Disclosure, selected map[string]Disclosure) error {
	switch t := node.(type) {
	case map[string]any:
		return includeAllDisclosuresInObject(t, byDigest, selected)
	case []any:
		return includeAllDisclosuresInArray(t, byDigest, selected)
	}
	return nil
}

// includeAllDisclosuresInObject and includeAllDisclosuresInArray are
// includeAllDisclosures's own two case bodies (map[string]any/[]any),
// split into top-level helpers purely to keep it under the linter's
// own cognitive complexity ceiling.
func includeAllDisclosuresInObject(obj map[string]any, byDigest map[string]Disclosure, selected map[string]Disclosure) error {
	for k, v := range obj {
		if k == "_sd" || k == "_sd_alg" {
			continue
		}
		if err := includeAllDisclosures(v, byDigest, selected); err != nil {
			return err
		}
	}
	for _, digest := range sdDigests(obj) {
		if err := includeDisclosure(digest, byDigest, selected); err != nil {
			return err
		}
	}
	return nil
}

func includeAllDisclosuresInArray(arr []any, byDigest map[string]Disclosure, selected map[string]Disclosure) error {
	for _, el := range arr {
		if digest, isRef := disclosureRefDigest(el); isRef {
			if err := includeDisclosure(digest, byDigest, selected); err != nil {
				return err
			}
			continue
		}
		if err := includeAllDisclosures(el, byDigest, selected); err != nil {
			return err
		}
	}
	return nil
}

// disclosureRefDigest reports whether el is an RFC 9901 §4.2.6
// recursive-disclosure array-element reference (a single-key object
// {"...": "<digest>"}), returning its own digest if so.
func disclosureRefDigest(el any) (digest string, isRef bool) {
	obj, ok := el.(map[string]any)
	if !ok || len(obj) != 1 {
		return "", false
	}
	digestRaw, has := obj["..."]
	if !has {
		return "", false
	}
	digest, ok = digestRaw.(string)
	return digest, ok
}

// includeDisclosure marks digest's own Disclosure as selected (a
// digest with no matching Disclosure is silently ignored, same as
// elsewhere) and recurses into its own value.
func includeDisclosure(digest string, byDigest map[string]Disclosure, selected map[string]Disclosure) error {
	if _, already := selected[digest]; already {
		return nil
	}
	d, found := byDigest[digest]
	if !found {
		return nil
	}
	selected[digest] = d
	return includeAllDisclosures(d.Value, byDigest, selected)
}
