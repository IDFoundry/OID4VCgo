package proximity

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// decodeDocInfo decodes, with both parsers, a request for one mDL
// asking for age_over_18, with info as its ItemsRequest's requestInfo
// (none for nil). It fails the test when the parsers disagree.
func decodeDocInfo(t *testing.T, info any) (DocRequest, error) {
	t.Helper()
	b := testRequest{docs: []testDoc{{docType: mDL, requestInfo: info}}}.build(t, testTranscriptBytes(t, "doc-info"))
	parsed, perr := ParseDeviceRequest(b)
	decoded, derr := DecodeDeviceRequest(b)
	if (perr == nil) != (derr == nil) {
		t.Fatalf("ParseDeviceRequest %v, DecodeDeviceRequest %v", perr, derr)
	}
	if derr != nil {
		return DocRequest{}, derr
	}
	doc := decoded.DocRequests()[0]
	if !reflect.DeepEqual(parsed[0].RequestInfo, doc.RequestInfo) || (parsed[0].RequestInfoError == nil) != (doc.RequestInfoError == nil) {
		t.Fatalf("ParseDeviceRequest %+v, DecodeDeviceRequest %+v", parsed[0].RequestInfo, doc.RequestInfo)
	}
	return doc, nil
}

// ref is the ElementReference [mDLNS, element].
func ref(element string) []string { return []string{mDLNS, element} }

// altSet is an AlternativeDataElementsSet for requested, with
// alternatives, plus extra entries.
func altSet(requested, alternatives any, extra ...any) map[string]any {
	set := map[string]any{"requestedElement": requested, "alternativeElementSets": alternatives}
	for i := 0; i+1 < len(extra); i += 2 {
		set[extra[i].(string)] = extra[i+1]
	}
	return set
}

// alternatives is n alternatives of per references each.
func alternatives(n, per int) [][][]string {
	out := make([][][]string, n)
	for i := range out {
		for j := 0; j < per; j++ {
			out[i] = append(out[i], ref("age_in_years"))
		}
	}
	return out
}

// sets is n sets for age_over_18, each with alternatives(1, per).
func sets(n, per int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = altSet(ref("age_over_18"), alternatives(1, per))
	}
	return out
}

// identifiers is n issuer identifiers of size bytes each.
func identifiers(n, size int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = bytes.Repeat([]byte{byte(i + 1)}, size)
	}
	return out
}

// The decoded information keeps what the reader sent, in its order:
// alternatives in their order of preference, an alternative from
// another namespace, a repeated requested element, and issuer
// identifiers byte for byte. The members this package doesn't read,
// extensions and integer keys are accepted and not shown.
func TestDocRequestInfo_Decoded(t *testing.T) {
	aki := bytes.Repeat([]byte{0xab}, 20)
	info := map[any]any{
		"alternativeDataElements": []any{
			altSet(ref("age_over_18"), [][][]string{{ref("age_in_years")}, {ref("birth_date"), {"org.example.other", "x"}}}, "futureField", 1),
			altSet(ref("age_over_18"), [][][]string{{ref("portrait")}}),
		},
		"issuerIdentifiers":    [][]byte{aki, {1}},
		"uniqueDocSetRequired": true,
		"maximumResponseSize":  1000,
		"zkRequest":            map[string]any{"x": 1},
		"org.example.ext":      []int{1},
		7:                      "integer key",
	}
	doc, err := decodeDocInfo(t, info)
	if err != nil {
		t.Fatal(err)
	}
	want := &DocRequestInfo{
		AlternativeDataElements: []AlternativeDataElements{
			{RequestedElement: [2]string{mDLNS, "age_over_18"}, AlternativeElementSets: [][][2]string{{{mDLNS, "age_in_years"}}, {{mDLNS, "birth_date"}, {"org.example.other", "x"}}}},
			{RequestedElement: [2]string{mDLNS, "age_over_18"}, AlternativeElementSets: [][][2]string{{{mDLNS, "portrait"}}}},
		},
		IssuerIdentifiers: [][]byte{aki, {1}},
	}
	if doc.RequestInfoError != nil || !reflect.DeepEqual(doc.RequestInfo, want) {
		t.Fatalf("RequestInfo %+v (%v), want %+v", doc.RequestInfo, doc.RequestInfoError, want)
	}

	// DocRequests returns copies.
	b := testRequest{docs: []testDoc{{docType: mDL, requestInfo: info}}}.build(t, testTranscriptBytes(t, "doc-info"))
	req, err := DecodeDeviceRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	first := req.DocRequests()[0].RequestInfo
	first.AlternativeDataElements[0].AlternativeElementSets[0][0][1] = "changed"
	first.IssuerIdentifiers[0][0] = 0
	if again := req.DocRequests()[0].RequestInfo; !reflect.DeepEqual(again, want) {
		t.Errorf("a changed copy changed the request: %+v", again)
	}
}

// Absent information is nil; present information without members this
// package reads is empty, its lists not nil.
func TestDocRequestInfo_AbsentAndEmpty(t *testing.T) {
	absent, err := decodeDocInfo(t, nil)
	if err != nil || absent.RequestInfo != nil || absent.RequestInfoError != nil {
		t.Fatalf("absent: %+v, %v, %v", absent.RequestInfo, absent.RequestInfoError, err)
	}
	for name, info := range map[string]any{
		"empty map":         map[string]any{},
		"only an extension": map[string]any{"org.example.ext": 1},
		"indefinite empty":  cbor.RawMessage{0xbf, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := decodeDocInfo(t, info)
			if err != nil {
				t.Fatal(err)
			}
			got := doc.RequestInfo
			if got == nil || got.AlternativeDataElements == nil || got.IssuerIdentifiers == nil || len(got.AlternativeDataElements)+len(got.IssuerIdentifiers) != 0 {
				t.Errorf("RequestInfo %+v (%v), want present and empty", got, doc.RequestInfoError)
			}
		})
	}
}

// requestInfo that isn't a map refuses the request.
func TestDocRequestInfo_RefusesNonMap(t *testing.T) {
	for name, info := range map[string]any{
		"null":    cbor.RawMessage{0xf6},
		"array":   []int{},
		"text":    "info",
		"integer": 1,
		"tagged":  tagged(t, []byte{0xa0}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeDocInfo(t, info); !errors.Is(err, ErrCBORValidation) {
				t.Errorf("decode = %v, want a validation error", err)
			}
		})
	}
}

// requireDocInfoUnread checks that doc carries information it couldn't
// read: none shown, and why, the request standing.
func requireDocInfoUnread(t *testing.T, doc DocRequest, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("decode = %v, want the request without its information", err)
	}
	if doc.RequestInfo != nil || !errors.Is(doc.RequestInfoError, ErrCBORValidation) {
		t.Errorf("RequestInfo %+v, RequestInfoError %v; want nil and a validation error", doc.RequestInfo, doc.RequestInfoError)
	}
}

// Known members of another shape than DocRequestInfo's aren't read, and
// the request stands without them.
func TestDocRequestInfo_Unreadable(t *testing.T) {
	ok := [][][]string{{ref("age_in_years")}}
	alt := func(set any) map[string]any { return map[string]any{"alternativeDataElements": []any{set}} }
	for name, info := range map[string]any{
		"null alternativeDataElements":  map[string]any{"alternativeDataElements": nil},
		"empty alternativeDataElements": map[string]any{"alternativeDataElements": []any{}},
		"alternativeDataElements a map": map[string]any{"alternativeDataElements": map[string]any{}},
		"set not a map":                 alt(1),
		"no requestedElement":           alt(map[string]any{"alternativeElementSets": ok}),
		"no alternativeElementSets":     alt(map[string]any{"requestedElement": ref("age_over_18")}),
		"requested element not asked":   alt(altSet(ref("age_in_years"), ok)),
		"requested element elsewhere":   alt(altSet([]string{"org.example.other", "age_over_18"}, ok)),
		"requested element too short":   alt(altSet([]string{mDLNS}, ok)),
		"requested element too long":    alt(altSet([]string{mDLNS, "age_over_18", "x"}, ok)),
		"requested element integers":    alt(altSet([]int{1, 2}, ok)),
		"requested element a map":       alt(altSet(map[string]string{mDLNS: "age_over_18"}, ok)),
		"requested element empty name":  alt(altSet([]string{mDLNS, ""}, ok)),
		"null alternativeElementSets":   alt(altSet(ref("age_over_18"), nil)),
		"empty alternativeElementSets":  alt(altSet(ref("age_over_18"), []any{})),
		"empty alternative":             alt(altSet(ref("age_over_18"), [][]any{{}})),
		"alternative not an array":      alt(altSet(ref("age_over_18"), []any{ref("age_in_years")})),
		"alternative with bytes":        alt(altSet(ref("age_over_18"), [][]any{{[][]byte{{1}, {2}}}})),
		"alternative control character": alt(altSet(ref("age_over_18"), [][][]string{{{mDLNS, "age\x1b[2J"}}})),
		"null issuerIdentifiers":        map[string]any{"issuerIdentifiers": nil},
		"empty issuerIdentifiers":       map[string]any{"issuerIdentifiers": [][]byte{}},
		"issuerIdentifiers a byte str":  map[string]any{"issuerIdentifiers": []byte{1}},
		"text issuer identifier":        map[string]any{"issuerIdentifiers": []string{"ab"}},
		"empty issuer identifier":       map[string]any{"issuerIdentifiers": [][]byte{{}}},
		"tagged issuer identifier":      map[string]any{"issuerIdentifiers": []any{cbor.Tag{Number: 24, Content: []byte{1}}}},
		"unreadable beside readable":    map[string]any{"issuerIdentifiers": [][]byte{{1}}, "alternativeDataElements": nil},
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := decodeDocInfo(t, info)
			requireDocInfoUnread(t, doc, err)
		})
	}
}

// Every limit: its exact value is read, and one more isn't, the request
// standing without the information.
func TestDocRequestInfo_Limits(t *testing.T) {
	alt := func(sets ...any) map[string]any { return map[string]any{"alternativeDataElements": sets} }
	ids := func(n, size int) map[string]any { return map[string]any{"issuerIdentifiers": identifiers(n, size)} }
	// Each set of one alternative of 7 references, its requested
	// element counted, is 8: 32 of them are 256.
	for name, tc := range map[string]struct {
		at, over any
	}{
		"sets": {alt(sets(MaxAlternativeDataElements, 1)...), alt(sets(MaxAlternativeDataElements+1, 1)...)},
		"alternatives per set": {
			alt(altSet(ref("age_over_18"), alternatives(MaxAlternativeElementSets, 1))),
			alt(altSet(ref("age_over_18"), alternatives(MaxAlternativeElementSets+1, 1))),
		},
		"elements per alternative": {
			alt(altSet(ref("age_over_18"), alternatives(1, MaxElementsPerAlternative))),
			alt(altSet(ref("age_over_18"), alternatives(1, MaxElementsPerAlternative+1))),
		},
		"element references in all": {
			alt(sets(MaxAlternativeElements/8, 7)...),
			alt(append(sets(MaxAlternativeElements/8-1, 7), altSet(ref("age_over_18"), alternatives(2, 4)))...),
		},
		"issuer identifiers":      {ids(MaxIssuerIdentifiers, 20), ids(MaxIssuerIdentifiers+1, 20)},
		"issuer identifier bytes": {ids(1, MaxIssuerIdentifierBytes), ids(1, MaxIssuerIdentifierBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := decodeDocInfo(t, tc.at)
			if err != nil || doc.RequestInfo == nil {
				t.Errorf("at the limit: %v, %v", err, doc.RequestInfoError)
			}
			doc, err = decodeDocInfo(t, tc.over)
			requireDocInfoUnread(t, doc, err)
			if !strings.Contains(doc.RequestInfoError.Error(), "over") {
				t.Errorf("RequestInfoError %v doesn't name the limit", doc.RequestInfoError)
			}
		})
	}
}
