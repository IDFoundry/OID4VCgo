package oid4vci

import (
	"math"
	"reflect"
	"slices"
	"testing"
)

// deepEqualSubset is the comparison claimsWithin and stringsWithin
// replace: every element of sub reflect.DeepEqual to one of super's, by
// scanning super for each.
func deepEqualSubset[T any](sub, super []T) bool {
	for _, s := range sub {
		if !slices.ContainsFunc(super, func(x T) bool { return reflect.DeepEqual(s, x) }) {
			return false
		}
	}
	return true
}

// equivalenceClaims are claims descriptions that differ from each other
// in one way reflect.DeepEqual tells apart, or doesn't: a nil or empty
// path or display, a path element's dynamic type, -0 and 0, NaN, an
// unset, false or true mandatory, and strings that would run together
// unless delimited.
func equivalenceClaims() []ClaimsDescription {
	yes, no, alsoYes := true, false, true
	return []ClaimsDescription{
		{},
		{Path: []any{}},
		{Path: []any{"a"}},
		{Path: []any{"a"}, Mandatory: &yes},
		{Path: []any{"a"}, Mandatory: &alsoYes},
		{Path: []any{"a"}, Mandatory: &no},
		{Path: []any{"a"}, Display: []ClaimDisplay{}},
		{Path: []any{"a"}, Display: []ClaimDisplay{{Name: "n", Locale: "en"}}},
		{Path: []any{"a"}, Display: []ClaimDisplay{{Name: "ne", Locale: "n"}}},
		{Path: []any{"a"}, Display: []ClaimDisplay{{Name: "n"}, {Locale: "en"}}},
		{Path: []any{"ab"}},
		{Path: []any{"a", "b"}},
		{Path: []any{"a:b"}},
		{Path: []any{"1:a"}},
		{Path: []any{"a", nil}},
		{Path: []any{"a", 0}},
		{Path: []any{"a", 0.0}},
		{Path: []any{"a", math.Copysign(0, -1)}},
		{Path: []any{"a", 1}},
		{Path: []any{"a", 1.0}},
		{Path: []any{"a", int64(1)}},
		{Path: []any{"a", math.NaN()}},
		{Path: []any{"a", true}},
		{Path: []any{nil}},
		{Path: []any{""}},
	}
}

// claimsWithin decides exactly as the reflect.DeepEqual scan it
// replaces, for each pair of descriptions that differ in one of the
// ways DeepEqual tells apart or doesn't.
func TestClaimsWithin_MatchesDeepEqual(t *testing.T) {
	claims := equivalenceClaims()
	for i, a := range claims {
		for j, b := range claims {
			// Where i == j, a and b share their slices, which DeepEqual
			// takes as equal, NaN included.
			for _, super := range [][]ClaimsDescription{{b}, {claims[(j+1)%len(claims)], b}} {
				if got, want := claimsWithin([]ClaimsDescription{a}, super), deepEqualSubset([]ClaimsDescription{a}, super); got != want {
					t.Errorf("claimsWithin([%d] %+v, [%d] %+v) = %v, reflect.DeepEqual says %v", i, a, j, b, got, want)
				}
			}
		}
		if !claimsWithin([]ClaimsDescription{a}, []ClaimsDescription{a}) {
			t.Errorf("claimsWithin([%d] %+v, itself) = false", i, a)
		}
	}
}

// FuzzClaimsWithin checks claimsWithin and stringsWithin against the
// reflect.DeepEqual scans they replace, on lists built from the input:
// sub's descriptions are fresh or copies of super's, sharing their
// slices, and path elements of every type DeepEqual tells apart.
func FuzzClaimsWithin(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{3, 1, 2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	f.Add([]byte{2, 2, 9, 9, 9, 1, 0, 0, 7, 7, 7, 2, 1, 3, 1, 0, 5})
	f.Fuzz(func(t *testing.T, data []byte) {
		next := func() int {
			if len(data) == 0 {
				return 0
			}
			b := data[0]
			data = data[1:]
			return int(b)
		}
		elements := []func() any{
			func() any { return "a" }, func() any { return "b" }, func() any { return "" }, func() any { return "a:b" },
			func() any { return nil }, func() any { return 0 }, func() any { return 1 }, func() any { return 0.0 },
			func() any { return math.Copysign(0, -1) }, func() any { return 1.0 }, func() any { return math.NaN() },
			func() any { return int64(1) }, func() any { return true }, func() any { return math.Inf(1) },
		}
		claim := func() ClaimsDescription {
			var c ClaimsDescription
			if n := next() % 5; n > 0 {
				c.Path = make([]any, n-1)
				for i := range c.Path {
					c.Path[i] = elements[next()%len(elements)]()
				}
			}
			switch next() % 3 {
			case 1:
				v := false
				c.Mandatory = &v
			case 2:
				v := true
				c.Mandatory = &v
			}
			if n := next() % 4; n > 0 {
				c.Display = make([]ClaimDisplay, n-1)
				for i := range c.Display {
					c.Display[i] = ClaimDisplay{Name: []string{"", "n", "en"}[next()%3], Locale: []string{"", "n", "en"}[next()%3]}
				}
			}
			return c
		}
		super := make([]ClaimsDescription, next()%6)
		for i := range super {
			super[i] = claim()
		}
		sub := make([]ClaimsDescription, next()%6)
		for i := range sub {
			if len(super) > 0 && next()%2 == 0 {
				sub[i] = super[next()%len(super)] // shares super's slices
			} else {
				sub[i] = claim()
			}
		}
		if got, want := claimsWithin(sub, super), deepEqualSubset(sub, super); got != want {
			t.Fatalf("claimsWithin(%+v, %+v) = %v, reflect.DeepEqual says %v", sub, super, got, want)
		}
		strs := []string{"", "a", "b", "ab"}
		superStrings := make([]string, next()%4)
		for i := range superStrings {
			superStrings[i] = strs[next()%len(strs)]
		}
		subStrings := make([]string, next()%4)
		for i := range subStrings {
			subStrings[i] = strs[next()%len(strs)]
		}
		if got, want := stringsWithin(subStrings, superStrings), deepEqualSubset(subStrings, superStrings); got != want {
			t.Fatalf("stringsWithin(%q, %q) = %v, want %v", subStrings, superStrings, got, want)
		}
	})
}
