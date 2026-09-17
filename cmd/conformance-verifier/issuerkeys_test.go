package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

const testJWK = `{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`

func TestNewStaticIssuerKeyResolver_DefaultsAlgToES256(t *testing.T) {
	r, err := newStaticIssuerKeyResolver(json.RawMessage(testJWK))
	if err != nil {
		t.Fatalf("newStaticIssuerKeyResolver: %v", err)
	}
	pub, alg, err := r.ResolveIssuerKey(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("ResolveIssuerKey: %v", err)
	}
	if pub == nil {
		t.Fatalf("ResolveIssuerKey returned a nil public key")
	}
	if alg != jose.ES256 {
		t.Fatalf("alg = %q, want %q", alg, jose.ES256)
	}
}

func TestNewStaticIssuerKeyResolver_HonorsExplicitAlg(t *testing.T) {
	withAlg := `{"kty":"EC","crv":"P-256","alg":"ES256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`
	r, err := newStaticIssuerKeyResolver(json.RawMessage(withAlg))
	if err != nil {
		t.Fatalf("newStaticIssuerKeyResolver: %v", err)
	}
	_, alg, err := r.ResolveIssuerKey(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("ResolveIssuerKey: %v", err)
	}
	if alg != jose.ES256 {
		t.Fatalf("alg = %q, want %q", alg, jose.ES256)
	}
}

func TestNewStaticIssuerKeyResolver_RejectsMalformedJWK(t *testing.T) {
	if _, err := newStaticIssuerKeyResolver(json.RawMessage(`{"kty":"nonsense"}`)); err == nil {
		t.Fatalf("newStaticIssuerKeyResolver = nil error, want error")
	}
}

// ResolveIssuerKey ignores header/payload entirely — it always trusts
// the one statically-configured key — so passing garbage for both
// must not error.
func TestStaticIssuerKeyResolver_IgnoresHeaderAndPayload(t *testing.T) {
	r, err := newStaticIssuerKeyResolver(json.RawMessage(testJWK))
	if err != nil {
		t.Fatalf("newStaticIssuerKeyResolver: %v", err)
	}
	if _, _, err := r.ResolveIssuerKey(context.Background(), map[string]any{"unexpected": true}, map[string]any{"vct": "anything"}); err != nil {
		t.Fatalf("ResolveIssuerKey: %v", err)
	}
}
