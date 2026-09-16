package mdoc

import "github.com/fxamacker/cbor/v2"

// SelectNameSpaces returns a copy of s trimmed to only the
// namespace/element pairs paths names — ISO/IEC 18013-5's own
// namespace/data-element selective disclosure mechanism (§10.3.3): a
// Holder may present a subset of the elements an Issuer originally
// signed, and every remaining IssuerSignedItem still verifies against
// the MSO's own valueDigests exactly as before (Verify), since
// trimming never touches an item's own bytes or salt, only which items
// are included at all.
//
// Each entry in paths is a [namespace, element] pair — the mdoc-form
// Claims Path Pointer dcql.Path.MdocNamespaceAndElement already
// extracts. A pair naming an element s doesn't actually carry is
// silently skipped, the same "asking for what isn't there discloses
// nothing for it" stance credential/sdjwtvc.SelectDisclosures takes. A
// namespace left with no selected elements is omitted entirely from
// the result — an empty items slice is invalid (Marshal's own
// "namespace has no data elements" check).
//
// This lives here, rather than as caller-side filtering of the
// exported NameSpaces field alone, precisely because of the cached
// IssuerSignedItemBytes rawItems holds (see IssuerSigned's own doc
// comment on why Marshal/Verify must never re-derive an item's bytes
// from its decoded ElementValue): the result's own rawItems is kept
// index-aligned with the trimmed NameSpaces, something only this
// package can do since rawItems is private.
func (s IssuerSigned) SelectNameSpaces(paths [][2]string) IssuerSigned {
	wanted := make(map[string]map[string]bool, len(paths))
	for _, p := range paths {
		namespace, element := p[0], p[1]
		if wanted[namespace] == nil {
			wanted[namespace] = make(map[string]bool)
		}
		wanted[namespace][element] = true
	}

	nameSpaces := make(map[string][]IssuerSignedItem, len(s.NameSpaces))
	rawItems := make(map[string][]cbor.RawMessage, len(s.rawItems))
	for namespace, items := range s.NameSpaces {
		elements := wanted[namespace]
		if len(elements) == 0 {
			continue
		}
		cached := s.rawItems[namespace]
		keptItems := make([]IssuerSignedItem, 0, len(items))
		keptRaw := make([]cbor.RawMessage, 0, len(items))
		for i, item := range items {
			if !elements[item.ElementIdentifier] {
				continue
			}
			keptItems = append(keptItems, item)
			if i < len(cached) {
				keptRaw = append(keptRaw, cached[i])
			}
		}
		if len(keptItems) == 0 {
			continue
		}
		nameSpaces[namespace] = keptItems
		// Only carry the cache forward if it covered every kept item —
		// otherwise Marshal/Verify's own per-item fallback (re-deriving
		// bytes from ElementValue) already handles the gap correctly
		// for whichever items lack a cached entry.
		if len(keptRaw) == len(keptItems) {
			rawItems[namespace] = keptRaw
		}
	}
	return IssuerSigned{NameSpaces: nameSpaces, IssuerAuth: s.IssuerAuth, rawItems: rawItems}
}
