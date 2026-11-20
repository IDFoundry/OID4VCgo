package statuslist

import "testing"

// An idx of 2^53 may be 2^53 + 1, rounded on decoding: it's refused
// with the larger ones.
func TestParseStatusClaimRefusesRoundedIndex(t *testing.T) {
	for _, idx := range []float64{1 << 53, 1<<53 + 2} {
		if _, err := ParseStatusClaim(map[string]any{"status_list": map[string]any{"idx": idx, "uri": "https://status.example/1"}}); err == nil {
			t.Errorf("ParseStatusClaim with idx %.0f = nil error, want it refused", idx)
		}
	}
	if _, err := ParseStatusClaim(map[string]any{"status_list": map[string]any{"idx": float64(1<<53 - 1), "uri": "https://status.example/1"}}); err != nil {
		t.Errorf("ParseStatusClaim with idx 2^53 − 1: %v", err)
	}
}
