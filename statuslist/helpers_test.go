package statuslist

import "encoding/json"

// marshalUnmarshal round-trips v through JSON into a map[string]any,
// the same shape ParseStatusClaim receives real Referenced Token
// claims in (e.g. from encoding/json's default number decoding).
func marshalUnmarshal(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
