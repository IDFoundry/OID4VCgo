package statuslist

import "fmt"

// StatusListRef is the content of a Referenced Token's
// status.status_list claim (draft-12 §6.2): a pointer to the index
// within, and URI of, a Status List Token that carries this token's
// status.
type StatusListRef struct {
	Idx int    // REQUIRED
	URI string // REQUIRED
}

// Claim builds the "status" claim a Referenced Token embeds to point
// back at ref (draft-12 §6.2) — the same map[string]any shape
// credential/sdjwtvc's Claims.Status expects.
func (ref StatusListRef) Claim() map[string]any {
	return map[string]any{
		"status_list": map[string]any{
			"idx": ref.Idx,
			"uri": ref.URI,
		},
	}
}

// ParseStatusClaim extracts a StatusListRef from an already-resolved
// Referenced Token's "status" claim (draft-12 §6.2, §8.3 step 1) — for
// example, credential/sdjwtvc.Verify's returned payload["status"].
func ParseStatusClaim(status map[string]any) (StatusListRef, error) {
	raw, ok := status["status_list"]
	if !ok {
		return StatusListRef{}, fmt.Errorf("statuslist: status claim has no status_list member")
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return StatusListRef{}, fmt.Errorf("statuslist: status_list is not an object")
	}

	idxRaw, ok := m["idx"]
	if !ok {
		return StatusListRef{}, fmt.Errorf("statuslist: status_list is missing the required idx claim")
	}
	idxFloat, ok := idxRaw.(float64)
	if !ok || idxFloat < 0 || idxFloat != float64(int(idxFloat)) {
		return StatusListRef{}, fmt.Errorf("statuslist: status_list.idx is not a non-negative integer")
	}

	uri, ok := m["uri"].(string)
	if !ok || uri == "" {
		return StatusListRef{}, fmt.Errorf("statuslist: status_list is missing the required uri claim")
	}

	return StatusListRef{Idx: int(idxFloat), URI: uri}, nil
}
