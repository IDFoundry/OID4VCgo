package walletprovider

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// A key is written as it was when bodies carried it as raw JSON:
// jwk.JWK's members, and none of wireJWK's others.
func TestWireJWKKeepsTheWireFormat(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, pub := range []any{&ec.PublicKey, ed} {
		k, err := marshalKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(keyAttestationRequestBody{InstanceKey: wireJWK{JWK: k.jwk}, Keys: []wireJWK{{JWK: k.jwk}}, Challenge: "c"})
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(struct {
			InstanceKey json.RawMessage   `json:"instance_key"`
			Challenge   string            `json:"challenge"`
			Keys        []json.RawMessage `json:"keys"`
			Evidence    []evidenceBody    `json:"evidence"`
		}{k.json, "c", []json.RawMessage{k.json}, nil})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%T: written as %s, was %s", pub, got, want)
		}
	}
}
