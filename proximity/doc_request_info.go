package proximity

import (
	"bytes"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/identifier"
)

// Limits on one document request's DocRequestInfo (DocRequest's
// RequestInfo). Like the request-level ones, they are this library's
// resource policy, not limits ISO/IEC 18013-5 sets. Information over
// any of them isn't read (DocRequest.RequestInfoError), never
// truncated; the totals apply on top of the per-item limits.
const (
	// MaxAlternativeDataElements is the most alternativeDataElements
	// sets one document request may carry.
	MaxAlternativeDataElements = 32
	// MaxAlternativeElementSets is the most alternatives one set may
	// give for its requested element.
	MaxAlternativeElementSets = 8
	// MaxElementsPerAlternative is the most element references one
	// alternative may list.
	MaxElementsPerAlternative = 8
	// MaxAlternativeElements is the most element references one
	// document request's alternativeDataElements may list in all, its
	// requested elements included, repeats counted.
	MaxAlternativeElements = 256
	// MaxIssuerIdentifiers is the most issuerIdentifiers one document
	// request may carry.
	MaxIssuerIdentifiers = 16
	// MaxIssuerIdentifierBytes bounds each issuer identifier, an
	// authority key identifier's KeyIdentifier.
	MaxIssuerIdentifierBytes = 64
)

// DocRequestInfo is a document request's DocRequestInfo — its
// ItemsRequest's requestInfo (ISO/IEC 18013-5 second edition draft,
// §10.2.4) — as far as this package reads it: its
// alternativeDataElements and issuerIdentifiers. Its other members
// (uniqueDocSetRequired, maximumResponseSize, zkRequest,
// docResponseEncryption) and any extension are accepted, and signed as
// received, but not read or shown here.
//
// Nothing in it is enforced: which element, alternative or document to
// answer with is the application's decision, as for use cases. A
// response still discloses only elements the document request's
// nameSpaces asked for (BuildDeviceResponse refuses any other), so an
// alternative can't be answered with in place of the element it
// stands for.
type DocRequestInfo struct {
	// AlternativeDataElements are the document request's alternatives,
	// in the request's order, each for one of its requested elements;
	// empty, not nil, when the information has none.
	AlternativeDataElements []AlternativeDataElements

	// IssuerIdentifiers are the issuers the reader accepts for this
	// document, each the KeyIdentifier of an AuthorityKeyIdentifier as
	// the reader sent it; empty, not nil, when the information has
	// none, which leaves the issuer unrestricted. They aren't matched
	// against any held mdoc's chain here.
	IssuerIdentifiers [][]byte
}

// AlternativeDataElements is one of a document request's
// alternativeDataElements sets: the elements the reader also accepts
// in place of one it requested.
type AlternativeDataElements struct {
	// RequestedElement is the [namespace, element] the alternatives
	// stand for: always one of the document request's Elements.
	RequestedElement [2]string

	// AlternativeElementSets are the alternatives, most preferred
	// first, as the reader sent them: each is [namespace, element]
	// pairs, all of which stand in for RequestedElement together. They
	// need not be among the document request's Elements.
	AlternativeElementSets [][][2]string
}

// clone is a deep copy of info; nil for nil.
func (info *DocRequestInfo) clone() *DocRequestInfo {
	if info == nil {
		return nil
	}
	out := &DocRequestInfo{
		AlternativeDataElements: make([]AlternativeDataElements, len(info.AlternativeDataElements)),
		IssuerIdentifiers:       make([][]byte, len(info.IssuerIdentifiers)),
	}
	for i, set := range info.AlternativeDataElements {
		c := AlternativeDataElements{RequestedElement: set.RequestedElement, AlternativeElementSets: make([][][2]string, len(set.AlternativeElementSets))}
		for j, alt := range set.AlternativeElementSets {
			c.AlternativeElementSets[j] = append(make([][2]string, 0, len(alt)), alt...)
		}
		out.AlternativeDataElements[i] = c
	}
	for i, id := range info.IssuerIdentifiers {
		out.IssuerIdentifiers[i] = bytes.Clone(id)
	}
	return out
}

// parseDocRequestInfo decodes raw, an ItemsRequest's requestInfo as
// received, for a document request asking for requested. err is for
// one that isn't a map, null included, which refuses the request.
// unread is for a map whose known members don't have DocRequestInfo's
// shape (§10.2.4) — each list non-empty, element references
// [namespace, element] identifiers, every requestedElement one of
// requested, issuer identifiers non-empty byte strings — or exceed this
// package's limits: the information is then not shown (info is nil),
// but the request stands, as for deviceRequestInfo. raw has already
// been walked by decMode, with the ItemsRequest it is in.
func parseDocRequestInfo(raw []byte, requested [][2]string) (info *DocRequestInfo, unread, err error) {
	if _, _, _, err := cborHeader(raw, 5); err != nil {
		return nil, nil, fmt.Errorf("requestInfo isn't a map: %w", ErrCBORValidation)
	}
	info = &DocRequestInfo{AlternativeDataElements: []AlternativeDataElements{}, IssuerIdentifiers: [][]byte{}}
	references := 0
	unread = mapEntries(raw, -1, "DocRequestInfo", func(key string, known bool, value []byte) error {
		if !known {
			return nil
		}
		var err error
		switch key {
		case "alternativeDataElements":
			info.AlternativeDataElements, err = parseAlternativeDataElements(value, requested, &references)
		case "issuerIdentifiers":
			info.IssuerIdentifiers, err = parseIssuerIdentifiers(value)
		}
		return err
	})
	if unread != nil {
		return nil, unread, nil
	}
	return info, nil, nil
}

// nonEmptyArrayItems is arrayItems for a CDDL [+ item]: an empty array
// is refused.
func nonEmptyArrayItems(raw []byte, limit int, what string, fn func(i int, item []byte) error) error {
	n := 0
	if err := arrayItems(raw, limit, what, func(i int, item []byte) error {
		n++
		return fn(i, item)
	}); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%s is empty: %w", what, ErrCBORValidation)
	}
	return nil
}

// parseAlternativeDataElements is a DocRequestInfo's
// alternativeDataElements, its element references counted in
// references.
func parseAlternativeDataElements(raw []byte, requested [][2]string, references *int) ([]AlternativeDataElements, error) {
	sets := []AlternativeDataElements{}
	err := nonEmptyArrayItems(raw, MaxAlternativeDataElements, "alternativeDataElements", func(i int, item []byte) error {
		set, err := parseAlternativeDataElementsSet(item, requested, references)
		if err != nil {
			return fmt.Errorf("alternativeDataElements[%d]: %w", i, err)
		}
		sets = append(sets, set)
		return nil
	})
	return sets, err
}

func parseAlternativeDataElementsSet(raw []byte, requested [][2]string, references *int) (AlternativeDataElements, error) {
	var set AlternativeDataElements
	var haveRequested, haveAlternatives bool
	err := mapEntries(raw, -1, "AlternativeDataElementsSet", func(key string, known bool, value []byte) error {
		if !known {
			return nil
		}
		var err error
		switch key {
		case "requestedElement":
			haveRequested = true
			set.RequestedElement, err = parseElementReference(value, references)
		case "alternativeElementSets":
			haveAlternatives = true
			set.AlternativeElementSets, err = parseAlternativeElementSets(value, references)
		}
		return err
	})
	if err != nil {
		return AlternativeDataElements{}, err
	}
	if !haveRequested {
		return AlternativeDataElements{}, fmt.Errorf("no requestedElement: %w", ErrCBORValidation)
	}
	if !haveAlternatives {
		return AlternativeDataElements{}, fmt.Errorf("no alternativeElementSets: %w", ErrCBORValidation)
	}
	isRequested := false
	for _, e := range requested {
		isRequested = isRequested || e == set.RequestedElement
	}
	if !isRequested {
		return AlternativeDataElements{}, fmt.Errorf("requestedElement %s/%s isn't in nameSpaces: %w", set.RequestedElement[0], set.RequestedElement[1], ErrCBORValidation)
	}
	return set, nil
}

func parseAlternativeElementSets(raw []byte, references *int) ([][][2]string, error) {
	sets := [][][2]string{}
	err := nonEmptyArrayItems(raw, MaxAlternativeElementSets, "alternativeElementSets", func(i int, item []byte) error {
		alt := [][2]string{}
		err := nonEmptyArrayItems(item, MaxElementsPerAlternative, "AlternativeElementSet", func(_ int, ref []byte) error {
			e, err := parseElementReference(ref, references)
			alt = append(alt, e)
			return err
		})
		if err != nil {
			return fmt.Errorf("alternativeElementSets[%d]: %w", i, err)
		}
		sets = append(sets, alt)
		return nil
	})
	return sets, err
}

// parseElementReference is raw, an ElementReference — [NameSpace,
// DataElementIdentifier] — counted in references.
func parseElementReference(raw []byte, references *int) ([2]string, error) {
	if *references++; *references > MaxAlternativeElements {
		return [2]string{}, fmt.Errorf("alternativeDataElements lists over %d element references: %w", MaxAlternativeElements, ErrCBORValidation)
	}
	var ref [2]string
	n := 0
	err := arrayItems(raw, 2, "element reference", func(i int, item []byte) error {
		n++
		if len(item) == 0 || item[0]>>5 != 3 || decMode.Unmarshal(item, &ref[i]) != nil {
			return fmt.Errorf("an element reference holds a non-text item: %w", ErrCBORValidation)
		}
		if err := identifier.Check(ref[i]); err != nil {
			return fmt.Errorf("element reference: %w: %w", err, ErrCBORValidation)
		}
		return nil
	})
	if err != nil {
		return [2]string{}, err
	}
	if n != 2 {
		return [2]string{}, fmt.Errorf("an element reference has %d items, want 2: %w", n, ErrCBORValidation)
	}
	return ref, nil
}

// parseIssuerIdentifiers is a DocRequestInfo's issuerIdentifiers.
func parseIssuerIdentifiers(raw []byte) ([][]byte, error) {
	ids := [][]byte{}
	err := nonEmptyArrayItems(raw, MaxIssuerIdentifiers, "issuerIdentifiers", func(i int, item []byte) error {
		var id []byte
		if len(item) == 0 || item[0]>>5 != 2 || decMode.Unmarshal(item, &id) != nil {
			return fmt.Errorf("issuerIdentifiers[%d] isn't a byte string: %w", i, ErrCBORValidation)
		}
		if len(id) == 0 {
			return fmt.Errorf("issuerIdentifiers[%d] is empty: %w", i, ErrCBORValidation)
		}
		if len(id) > MaxIssuerIdentifierBytes {
			return fmt.Errorf("issuerIdentifiers[%d] is %d bytes, over %d: %w", i, len(id), MaxIssuerIdentifierBytes, ErrCBORValidation)
		}
		ids = append(ids, id)
		return nil
	})
	return ids, err
}
