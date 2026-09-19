package sdjwtvc

import "testing"

// nestedPayload builds a plain map[string]any nested depth levels deep
// via a "nested" property at each level — no selective disclosure
// involved at all, since resolveMap recurses into every value
// unconditionally (SD() marker or not), which is exactly what lets
// this test exercise MaxResolveDepth without needing a real
// disclosure-chaining tree that deep.
func nestedPayload(depth int) map[string]any {
	m := map[string]any{"leaf": true}
	for i := 0; i < depth; i++ {
		m = map[string]any{"nested": m}
	}
	return m
}

func TestResolveDisclosures_RejectsExcessiveNestingDepth(t *testing.T) {
	deep := nestedPayload(MaxResolveDepth + 10)

	if _, err := ResolveDisclosures(deep, SHA256, nil); err == nil {
		t.Error("ResolveDisclosures = nil error, want error (nesting exceeds MaxResolveDepth)")
	}

	// ResolveDisclosuresMax with a raised ceiling accepts the same
	// input ResolveDisclosures rejects.
	if _, err := ResolveDisclosuresMax(deep, SHA256, nil, MaxResolveDepth+20); err != nil {
		t.Errorf("ResolveDisclosuresMax with a raised ceiling: %v", err)
	}
}

func TestResolveDisclosures_AcceptsNestingWithinDepth(t *testing.T) {
	shallow := nestedPayload(MaxResolveDepth - 5)
	if _, err := ResolveDisclosures(shallow, SHA256, nil); err != nil {
		t.Errorf("ResolveDisclosures rejected nesting within MaxResolveDepth: %v", err)
	}
}
