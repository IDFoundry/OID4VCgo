package dcql

import (
	"encoding/json"
	"fmt"
)

// pathElementKind is PathElement's own closed set of forms (§7): a
// string object-member selector, a wildcard array selector (wire form
// JSON null), or a non-negative integer array-index selector.
type pathElementKind int

const (
	pathKey pathElementKind = iota
	pathWildcard
	pathIndex
)

// PathElement is one component of a Claims Path Pointer (§7) — exactly
// one of a string (select an object member), a wildcard (select every
// element of an array), or a non-negative integer (select one array
// index) is ever set. Build one with PathKey, PathIndex, or the
// package-level Wildcard value.
type PathElement struct {
	kind  pathElementKind
	key   string
	index int
}

// Wildcard selects every element of an array — the wire form's JSON
// null (§7.1).
var Wildcard = PathElement{kind: pathWildcard}

// PathKey builds a PathElement selecting object member key.
func PathKey(key string) PathElement { return PathElement{kind: pathKey, key: key} }

// PathIndex builds a PathElement selecting array index i — i must be
// non-negative (§7.1).
func PathIndex(i int) PathElement { return PathElement{kind: pathIndex, index: i} }

// IsKey reports whether p selects an object member — Key returns which
// one.
func (p PathElement) IsKey() bool { return p.kind == pathKey }

// IsWildcard reports whether p selects every element of an array.
func (p PathElement) IsWildcard() bool { return p.kind == pathWildcard }

// IsIndex reports whether p selects one array index — Index returns
// which one.
func (p PathElement) IsIndex() bool { return p.kind == pathIndex }

// Key is p's own object-member name. Only meaningful when IsKey.
func (p PathElement) Key() string { return p.key }

// Index is p's own array index. Only meaningful when IsIndex.
func (p PathElement) Index() int { return p.index }

// MarshalJSON encodes p as §7's own wire form: a JSON string, null, or
// non-negative integer.
func (p PathElement) MarshalJSON() ([]byte, error) {
	switch p.kind {
	case pathKey:
		return json.Marshal(p.key)
	case pathWildcard:
		return []byte("null"), nil
	case pathIndex:
		return json.Marshal(p.index)
	default:
		return nil, fmt.Errorf("dcql: path element: invalid kind %d", p.kind)
	}
}

// UnmarshalJSON decodes §7's own wire form: a JSON string, null, or
// non-negative integer.
func (p *PathElement) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*p = Wildcard
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*p = PathKey(s)
		return nil
	}
	var i int
	if err := json.Unmarshal(data, &i); err == nil {
		if i < 0 {
			return fmt.Errorf("dcql: path element: index must be non-negative, got %d", i)
		}
		*p = PathIndex(i)
		return nil
	}
	return fmt.Errorf("dcql: path element: must be a string, non-negative integer, or null")
}

// Path is a Claims Path Pointer (§7): a non-empty sequence of
// PathElement addressing a specific claim within a Credential.
// Evaluating a Path against an actual credential (§7.1's JSON
// semantics for "dc+sd-jwt", §7.2's two-component form for
// "mso_mdoc") is the wallet-presentation role's own job, not this
// package's — see the package doc comment.
type Path []PathElement

// Validate checks p's own structural MUST: non-empty (§6.3's own
// "REQUIRED" on the parent Claims Query's "path").
func (p Path) Validate() error {
	if len(p) == 0 {
		return fmt.Errorf("dcql: path must be non-empty")
	}
	return nil
}

// MdocNamespaceAndElement reports p's own two mdoc-specific
// components — the ISO 18013-5 namespace and data element identifier —
// when p is a valid mdoc-format Claims Path Pointer (§7.2: exactly two
// string components; mdoc has no wildcard/integer/nested-object
// addressing). ok is false otherwise.
func (p Path) MdocNamespaceAndElement() (namespace, element string, ok bool) {
	if len(p) != 2 || !p[0].IsKey() || !p[1].IsKey() {
		return "", "", false
	}
	return p[0].Key(), p[1].Key(), true
}
