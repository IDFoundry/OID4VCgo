package sdjwtvc

import (
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// paddedPresentation returns a compact SD-JWT whose single Disclosure
// carries padBytes of value, with a placeholder issuer JWT — enough for
// Parse's size check, which runs before anything is verified.
func paddedPresentation(t *testing.T, padBytes int) string {
	t.Helper()
	padding, err := NewObjectDisclosure("padding", strings.Repeat("a", padBytes))
	if err != nil {
		t.Fatalf("NewObjectDisclosure: %v", err)
	}
	compact, err := Presentation{IssuerJWT: "issuer-jwt", Disclosures: []Disclosure{padding}}.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	return compact
}

func TestParseRejectsOversizedPresentation(t *testing.T) {
	compact := paddedPresentation(t, MaxBytes)
	if len(compact) <= MaxBytes {
		t.Fatalf("compact is %d bytes, want > MaxBytes (%d)", len(compact), MaxBytes)
	}

	if _, err := Parse(compact); err == nil {
		t.Error("Parse = nil error, want error (oversized presentation)")
	}

	// ParseMax with a raised ceiling accepts the same input Parse
	// rejects.
	if _, err := ParseMax(compact, len(compact)); err != nil {
		t.Errorf("ParseMax with a raised ceiling: %v", err)
	}
}

// TestParseAcceptsPresentationOverJOSECeiling checks the whole
// presentation is bounded by MaxBytes, not jose.MaxCompactBytes: a
// Disclosure carrying more than 64 KiB (a portrait, raw eMRTD data
// groups) is legitimate.
func TestParseAcceptsPresentationOverJOSECeiling(t *testing.T) {
	compact := paddedPresentation(t, jose.MaxCompactBytes)
	if len(compact) <= jose.MaxCompactBytes {
		t.Fatalf("compact is %d bytes, want > jose.MaxCompactBytes (%d)", len(compact), jose.MaxCompactBytes)
	}
	if _, err := Parse(compact); err != nil {
		t.Errorf("Parse(%d bytes): %v", len(compact), err)
	}
}

// TestIssueVerify_LargeDisclosure round-trips a credential whose one
// selectively disclosable claim is well over jose.MaxCompactBytes
// through Issue, Parse, a Key Binding JWT and Verify: the issuer JWT
// and Key Binding JWT stay small (they hold only digests and claims)
// and remain bounded by jose.Verify, while the presentation as a whole
// is bounded by MaxBytes.
func TestIssueVerify_LargeDisclosure(t *testing.T) {
	issuerKey := testKey(t)
	holderKey := testKey(t)
	large := strings.Repeat("A", 200<<10) // ~200 KiB, e.g. a base64url portrait

	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{
		VCT:        "https://credentials.example.com/identity_credential",
		CNF:        map[string]any{"jwk": jwkFromECDSA(t, &holderKey.PublicKey)},
		Additional: map[string]any{"portrait": SD(large)},
	}, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pres, err := Parse(sdjwt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pres.IssuerJWT) > jose.MaxCompactBytes {
		t.Fatalf("issuer JWT is %d bytes, want it to stay within jose.MaxCompactBytes", len(pres.IssuerJWT))
	}
	pres.KeyBindingJWT, err = NewKeyBindingJWT(holderKey, jose.ES256, pres, SHA256, KeyBindingClaims{
		Audience: "https://example.com/verifier", Nonce: "n",
	})
	if err != nil {
		t.Fatalf("NewKeyBindingJWT: %v", err)
	}
	presentation, err := pres.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if len(presentation) <= jose.MaxCompactBytes {
		t.Fatalf("presentation is %d bytes, want > jose.MaxCompactBytes", len(presentation))
	}

	payload, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
		RequireKeyBinding: KeyBindingRequired, HolderPublicKey: &holderKey.PublicKey,
		KeyBindingAlg: jose.ES256, ExpectedAudience: "https://example.com/verifier",
		ExpectedNonce: "n", MaxKeyBindingAge: time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if payload["portrait"] != large {
		t.Errorf("portrait round-tripped as %d bytes, want %d", len(payload["portrait"].(string)), len(large))
	}
}
