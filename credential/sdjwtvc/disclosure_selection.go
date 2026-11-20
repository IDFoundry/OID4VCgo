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
// SelectDisclosures walks object members only; SelectDisclosuresAt
// also walks into arrays, by index or every element.
func SelectDisclosures(payload map[string]any, alg HashAlg, all []Disclosure, paths [][]string) ([]Disclosure, error) {
	general := make([][]any, len(paths))
	for i, path := range paths {
		general[i] = make([]any, len(path))
		for j, key := range path {
			general[i][j] = key
		}
	}
	return SelectDisclosuresAt(payload, alg, all, general)
}

// SelectDisclosuresAt is SelectDisclosures for claims path pointers
// that also walk into arrays (OpenID4VP §7.1): each path component is a
// string (an object member), a non-negative int (one array element) or
// nil (every element of an array). An array element is either a plain
// value or, when selectively disclosable, a {"...": digest} placeholder
// whose Disclosure is then included (RFC 9901 §4.2.4.2). An index
// counts the elements the holder's credential has, so placeholders with
// no matching Disclosure (decoys) aren't counted. As for an absent
// member, an index past the array's end selects nothing. The paths'
// order doesn't matter: a path selecting a value whole includes every
// Disclosure within it, even one another path only walked through.
func SelectDisclosuresAt(payload map[string]any, alg HashAlg, all []Disclosure, paths [][]any) ([]Disclosure, error) {
	s := disclosureSelection{
		byDigest: make(map[string]Disclosure, len(all)),
		selected: make(map[string]Disclosure),
		whole:    make(map[string]bool),
	}
	for _, d := range all {
		digest, err := d.Digest(alg)
		if err != nil {
			return nil, err
		}
		s.byDigest[digest] = d
	}

	for _, path := range paths {
		if err := s.selectPath(payload, path); err != nil {
			return nil, err
		}
	}

	out := make([]Disclosure, 0, len(s.selected))
	for _, d := range s.selected {
		out = append(out, d)
	}
	return out, nil
}

// disclosureSelection is SelectDisclosuresAt's work: all the Disclosures
// by digest, those selected so far, and of those, the ones included
// whole, with every Disclosure their values reference. A path that only
// walks through a Disclosure selects it without its nested ones, so a
// later path that selects its whole value must still include them:
// which paths come first doesn't change what is selected.
type disclosureSelection struct {
	byDigest map[string]Disclosure
	selected map[string]Disclosure
	whole    map[string]bool
}

// selectPath walks node — a raw, not-yet-resolved SD-JWT subtree —
// following path, marking every Disclosure traversed along the way
// into s.selected (keyed by digest, so revisiting the same one via a
// different path is a no-op).
func (s disclosureSelection) selectPath(node any, path []any) error {
	if len(path) == 0 {
		return s.includeAllDisclosures(node)
	}
	switch c := path[0].(type) {
	case string:
		return s.selectMember(node, c, path[1:])
	case int:
		if c < 0 {
			return fmt.Errorf("sdjwtvc: select disclosures: negative array index %d", c)
		}
		return s.selectElements(node, c, path[1:])
	case nil:
		return s.selectElements(node, -1, path[1:])
	default:
		return fmt.Errorf("sdjwtvc: select disclosures: path component %v is neither a string, an int nor nil", c)
	}
}

// selectMember is selectPath for an object member key: a plaintext one
// is followed directly, a selectively disclosable one through its
// Disclosure among the object's "_sd" digests.
func (s disclosureSelection) selectMember(node any, key string, rest []any) error {
	obj, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("sdjwtvc: select disclosures: path element %q: not an object", key)
	}
	if child, present := obj[key]; present {
		return s.selectPath(child, rest)
	}
	for _, digest := range sdDigests(obj) {
		d, found := s.byDigest[digest]
		if !found || d.IsArrayElement() || d.Name != key {
			continue
		}
		s.selected[digest] = d
		return s.selectPath(d.Value, rest)
	}
	return nil
}

// selectElements is selectPath for an array: element index, or every
// element when index is -1. Under a wildcard, an element the rest of
// the path can't walk (another type than it expects) is skipped, as
// OpenID4VP §7.1 drops it from the selection.
func (s disclosureSelection) selectElements(node any, index int, rest []any) error {
	arr, ok := node.([]any)
	if !ok {
		return fmt.Errorf("sdjwtvc: select disclosures: path element %v: not an array", indexComponent(index))
	}
	elements := resolveElements(arr, s.byDigest)
	if index != -1 {
		if index >= len(elements) {
			return nil
		}
		return s.selectElement(elements[index], rest)
	}
	for _, el := range elements {
		if !walkable(el.value, rest) {
			continue
		}
		if err := s.selectElement(el, rest); err != nil {
			return err
		}
	}
	return nil
}

// arrayElement is an array element as the holder's credential has it:
// its value, and the digest of the Disclosure it came from, if any.
type arrayElement struct {
	value  any
	digest string
}

// resolveElements is arr with each disclosure reference resolved, and
// a decoy, which the holder's credential has no Disclosure for, left
// out: indices count the elements the credential has.
func resolveElements(arr []any, byDigest map[string]Disclosure) []arrayElement {
	out := make([]arrayElement, 0, len(arr))
	for _, el := range arr {
		ref, isRef := disclosureRefDigest(el)
		if !isRef {
			out = append(out, arrayElement{value: el})
			continue
		}
		if d, found := byDigest[ref]; found {
			out = append(out, arrayElement{value: d.Value, digest: ref})
		}
	}
	return out
}

// selectElement selects el, its Disclosure when it came from one, and
// what rest selects inside it.
func (s disclosureSelection) selectElement(el arrayElement, rest []any) error {
	if el.digest != "" {
		s.selected[el.digest] = s.byDigest[el.digest]
	}
	return s.selectPath(el.value, rest)
}

// walkable reports whether value has the type rest's first component
// walks: an object for a member, an array for an index or wildcard.
func walkable(value any, rest []any) bool {
	if len(rest) == 0 {
		return true
	}
	if _, member := rest[0].(string); member {
		_, ok := value.(map[string]any)
		return ok
	}
	_, ok := value.([]any)
	return ok
}

// indexComponent is index as a path component, for an error.
func indexComponent(index int) any {
	if index == -1 {
		return nil
	}
	return index
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
func (s disclosureSelection) includeAllDisclosures(node any) error {
	switch t := node.(type) {
	case map[string]any:
		return s.includeAllDisclosuresInObject(t)
	case []any:
		return s.includeAllDisclosuresInArray(t)
	}
	return nil
}

// includeAllDisclosuresInObject and includeAllDisclosuresInArray are
// includeAllDisclosures's own two case bodies (map[string]any/[]any),
// split into separate methods purely to keep it under the linter's
// own cognitive complexity ceiling.
func (s disclosureSelection) includeAllDisclosuresInObject(obj map[string]any) error {
	for k, v := range obj {
		if k == "_sd" || k == "_sd_alg" {
			continue
		}
		if err := s.includeAllDisclosures(v); err != nil {
			return err
		}
	}
	for _, digest := range sdDigests(obj) {
		if err := s.includeDisclosure(digest); err != nil {
			return err
		}
	}
	return nil
}

func (s disclosureSelection) includeAllDisclosuresInArray(arr []any) error {
	for _, el := range arr {
		if digest, isRef := disclosureRefDigest(el); isRef {
			if err := s.includeDisclosure(digest); err != nil {
				return err
			}
			continue
		}
		if err := s.includeAllDisclosures(el); err != nil {
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
// elsewhere) and recurses into its own value, unless it has already
// been included whole: one a path only walked through is selected, but
// not yet with what its value references.
func (s disclosureSelection) includeDisclosure(digest string) error {
	if s.whole[digest] {
		return nil
	}
	d, found := s.byDigest[digest]
	if !found {
		return nil
	}
	s.whole[digest] = true
	s.selected[digest] = d
	return s.includeAllDisclosures(d.Value)
}
