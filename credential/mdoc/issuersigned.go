package mdoc

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/fxamacker/cbor/v2"
)

// randomMinLength is §12.3.5's minimum length for IssuerSignedItem.Random.
const randomMinLength = 16

// IssuerSignedItem is one disclosed data element, plus the DigestID and
// salt an mdoc reader needs to check it against the MSO's valueDigests
// (§10.3.3, §12.3.5). Field order matches §10.3.3's own CDDL — this
// package's CBOR encoder preserves Go struct field order (it isn't
// configured for canonical/sorted map keys), so changing this order
// changes IssuerSignedItemBytes' encoding and therefore its digest.
//
// If ElementValue is (or contains) a native Go map, encoding it twice
// can produce different bytes each time — Go deliberately randomizes
// map iteration order, and this package isn't configured to sort map
// keys (doing so would also reorder struct fields like this one's,
// breaking byte-for-byte compatibility with real issuers — see
// IssuerSigned's own doc comment for how this package avoids that
// trap for the two paths that matter, Issue/Marshal and
// UnmarshalIssuerSigned/Verify). Prefer a typed struct with cbor tags
// (as this package's own tests do for array-of-object element values)
// over a raw map for any ElementValue you construct by hand outside of
// Issue.
type IssuerSignedItem struct {
	DigestID          uint64      `cbor:"digestID"`
	Random            []byte      `cbor:"random"`
	ElementIdentifier string      `cbor:"elementIdentifier"`
	ElementValue      interface{} `cbor:"elementValue"`
}

// IssuerSigned is §10.3.3's IssuerSigned: the MSO plus the disclosed
// data elements it authenticates, organized by namespace.
//
// Issue and UnmarshalIssuerSigned are IssuerSigned's real constructors
// — both cache each item's exact IssuerSignedItemBytes internally
// (rawItems) at the moment those bytes are first known (computed fresh
// in Issue; taken verbatim from the wire in UnmarshalIssuerSigned), and
// Marshal/Verify always reuse that cache rather than re-deriving bytes
// from NameSpaces. This is what makes both paths safe even when an
// ElementValue is a native Go map: the bytes a digest was computed
// over are the exact bytes transmitted, never a second, independently
// (and possibly differently) encoded copy. An IssuerSigned built
// directly as a struct literal has no cache, so Marshal/Verify fall
// back to re-deriving bytes from NameSpaces for it — safe only if
// every ElementValue encodes deterministically (see
// IssuerSignedItem's own doc comment).
type IssuerSigned struct {
	NameSpaces map[string][]IssuerSignedItem
	IssuerAuth []byte // an encoded COSE_Sign1 (untagged) — see Issue/Verify

	rawItems map[string][]cbor.RawMessage // see the doc comment above; index-aligned with NameSpaces[namespace]
}

// wireIssuerSigned is §10.3.3's own IssuerSigned CDDL:
//
//	IssuerSigned = {
//	    "issuerAuth" : IssuerAuth,
//	    ? "nameSpaces" : IssuerNameSpaces,
//	}
//
// IssuerAuth is embedded as a raw CBOR array (Issue.IssuerAuth's bytes
// already are one, via internal/cose), not re-wrapped.
type wireIssuerSigned struct {
	IssuerAuth cbor.RawMessage              `cbor:"issuerAuth"`
	NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces,omitempty"`
}

// Marshal encodes s as §10.3.3's IssuerSigned CBOR map — the form
// transmitted to a Holder and, eventually, embedded in a Document.
func (s IssuerSigned) Marshal() ([]byte, error) {
	nameSpaces, err := s.issuerNameSpacesWire()
	if err != nil {
		return nil, err
	}
	wire := wireIssuerSigned{
		IssuerAuth: cbor.RawMessage(s.IssuerAuth),
		NameSpaces: nameSpaces,
	}
	b, err := encMode.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("mdoc: marshal IssuerSigned: %w", err)
	}
	return b, nil
}

// issuerNameSpacesWire returns each item's IssuerSignedItemBytes, from
// s.rawItems when available (see IssuerSigned's doc comment) and
// re-derived from the logical NameSpaces otherwise.
func (s IssuerSigned) issuerNameSpacesWire() (map[string][]cbor.RawMessage, error) {
	out := make(map[string][]cbor.RawMessage, len(s.NameSpaces))
	for namespace, items := range s.NameSpaces {
		if len(items) == 0 {
			return nil, fmt.Errorf("mdoc: namespace %q has no data elements", namespace)
		}
		cached := s.rawItems[namespace]
		encoded := make([]cbor.RawMessage, len(items))
		for i, item := range items {
			if i < len(cached) {
				encoded[i] = cached[i]
				continue
			}
			b, err := issuerSignedItemBytes(item)
			if err != nil {
				return nil, err
			}
			encoded[i] = b
		}
		out[namespace] = encoded
	}
	return out, nil
}

// UnmarshalIssuerSigned decodes data as §10.3.3's IssuerSigned CBOR
// map — Marshal's inverse. It performs no signature or digest
// verification; use Verify for that.
func UnmarshalIssuerSigned(data []byte) (IssuerSigned, error) {
	var wire wireIssuerSigned
	if err := decMode.Unmarshal(data, &wire); err != nil {
		return IssuerSigned{}, fmt.Errorf("mdoc: unmarshal IssuerSigned: %w", err)
	}
	nameSpaces, err := decodeIssuerNameSpaces(wire.NameSpaces)
	if err != nil {
		return IssuerSigned{}, err
	}
	return IssuerSigned{NameSpaces: nameSpaces, IssuerAuth: []byte(wire.IssuerAuth), rawItems: wire.NameSpaces}, nil
}

// issuerSignedItemBytes returns item's IssuerSignedItemBytes (§10.3.3:
// #6.24(bstr .cbor IssuerSignedItem)) — both the wire representation of
// item inside IssuerNameSpaces and the input to its digest (§12.3.5).
// Only called where no cached copy already exists — see IssuerSigned's
// doc comment.
func issuerSignedItemBytes(item IssuerSignedItem) ([]byte, error) {
	b, err := wrapTag24(item)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode IssuerSignedItemBytes: %w", err)
	}
	return b, nil
}

func newDigester(alg DigestAlg) (hash.Hash, error) {
	switch alg {
	case SHA256:
		return sha256.New(), nil
	case SHA384:
		return sha512.New384(), nil
	case SHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("mdoc: unsupported digest algorithm %q", alg)
	}
}

// digest returns the §12.3.5 digest of an IssuerSignedItem's
// IssuerSignedItemBytes under alg.
func digest(alg DigestAlg, itemBytes []byte) ([]byte, error) {
	h, err := newDigester(alg)
	if err != nil {
		return nil, err
	}
	h.Write(itemBytes)
	return h.Sum(nil), nil
}

// decodeIssuerNameSpaces decodes wire (§10.3.3's IssuerNameSpaces:
// namespace => [+ IssuerSignedItemBytes]) into its logical form.
func decodeIssuerNameSpaces(wire map[string][]cbor.RawMessage) (map[string][]IssuerSignedItem, error) {
	out := make(map[string][]IssuerSignedItem, len(wire))
	for namespace, itemBytesList := range wire {
		items := make([]IssuerSignedItem, len(itemBytesList))
		for i, itemBytes := range itemBytesList {
			var item IssuerSignedItem
			if err := unwrapTag24(itemBytes, &item); err != nil {
				return nil, fmt.Errorf("mdoc: decode namespace %q item %d: %w", namespace, i, err)
			}
			items[i] = item
		}
		out[namespace] = items
	}
	return out, nil
}
