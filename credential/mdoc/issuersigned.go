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
type IssuerSignedItem struct {
	DigestID          uint64      `cbor:"digestID"`
	Random            []byte      `cbor:"random"`
	ElementIdentifier string      `cbor:"elementIdentifier"`
	ElementValue      interface{} `cbor:"elementValue"`
}

// IssuerSigned is §10.3.3's IssuerSigned: the MSO plus the disclosed
// data elements it authenticates, organized by namespace.
type IssuerSigned struct {
	NameSpaces map[string][]IssuerSignedItem
	IssuerAuth []byte // an encoded COSE_Sign1 (untagged) — see Issue/Verify
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
	nameSpaces, err := encodeIssuerNameSpaces(s.NameSpaces)
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
	return IssuerSigned{NameSpaces: nameSpaces, IssuerAuth: []byte(wire.IssuerAuth)}, nil
}

// issuerSignedItemBytes returns item's IssuerSignedItemBytes (§10.3.3:
// #6.24(bstr .cbor IssuerSignedItem)) — both the wire representation of
// item inside IssuerNameSpaces and the input to its digest (§12.3.5).
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

// encodeIssuerNameSpaces encodes ns as §10.3.3's IssuerNameSpaces map
// (namespace => [+ IssuerSignedItemBytes]).
func encodeIssuerNameSpaces(ns map[string][]IssuerSignedItem) (map[string][]cbor.RawMessage, error) {
	out := make(map[string][]cbor.RawMessage, len(ns))
	for namespace, items := range ns {
		if len(items) == 0 {
			return nil, fmt.Errorf("mdoc: namespace %q has no data elements", namespace)
		}
		encoded := make([]cbor.RawMessage, len(items))
		for i, item := range items {
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

// decodeIssuerNameSpaces is encodeIssuerNameSpaces' inverse.
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
