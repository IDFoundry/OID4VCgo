package sdjwtvc

import (
	"encoding/json"
	"testing"
)

// mustEncodeJSONArray base64url-encodes arr as sdjwtvc's own Disclosure
// encoding would, for constructing malformed-on-purpose test fixtures
// (e.g. a disclosure array using a reserved claim name) that this
// package's own constructors correctly refuse to build.
func mustEncodeJSONArray(t *testing.T, arr []any) string {
	t.Helper()
	raw, err := json.Marshal(arr)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b64.EncodeToString(raw)
}
