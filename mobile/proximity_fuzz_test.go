package mobile

import (
	"encoding/json"
	"slices"
	"testing"
)

// FuzzProximityHolder starts a proximity presentation on a development
// wallet holding no credentials and hands it an arbitrary message from
// the reader, then the app's calls with arbitrary choices: Request,
// Respond and Terminate. Nothing panics, every result is JSON, the
// event is one HandleMessage documents, and a failing Respond returns
// a coded error. The session's own decryption rejects nearly every
// message (the root proximity package fuzzes past it); this covers the
// mobile and walletflow layers' handling of what comes back.
func FuzzProximityHolder(f *testing.F) {
	w, err := NewWallet(`{"development":true}`, newGoKeyStore(), memStore{records: map[string][]byte{}}, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{0xa0}, `[["org.iso.18013.5.1","age_over_18"]]`, 0)
	f.Add([]byte{0xa1, 0x66, 's', 't', 'a', 't', 'u', 's', 0x14}, `[]`, -1)
	f.Add([]byte{0xa1, 0x6a, 'e', 'R', 'e', 'a', 'd', 'e', 'r', 'K', 'e', 'y', 0x40}, `x`, 1)
	f.Fuzz(func(t *testing.T, msg []byte, elements string, doc int) {
		p, err := w.StartProximityPresentationWithModes(`["peripheral_server","central_client"]`)
		if err != nil {
			t.Fatal(err)
		}
		var ev struct {
			Event string `json:"event"`
		}
		if out := p.HandleMessage(nil, msg); json.Unmarshal([]byte(out), &ev) != nil {
			t.Fatalf("HandleMessage = %q, not JSON", out)
		}
		if !slices.Contains([]string{"request", "ended", "none"}, ev.Event) {
			t.Fatalf("HandleMessage event %q", ev.Event)
		}
		if out := p.Request(); !json.Valid([]byte(out)) {
			t.Fatalf("Request = %q, not JSON", out)
		}
		if out, err := p.Respond(nil, doc, "x", elements); err != nil && code(err) == "" {
			t.Fatalf("Respond: an error without a code: %v", err)
		} else if err == nil && !json.Valid([]byte(out)) {
			t.Fatalf("Respond = %q, not JSON", out)
		}
		if out := p.Terminate(); !json.Valid([]byte(out)) {
			t.Fatalf("Terminate = %q, not JSON", out)
		}
	})
}
