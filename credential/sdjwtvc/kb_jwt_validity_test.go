package sdjwtvc

import (
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A Key Binding JWT's exp and nbf are optional, but when present each
// must be a NumericDate that holds (RFC 7519 §4.1.4, §4.1.5).
func TestVerifyKeyBindingJWT_ExpAndNbf(t *testing.T) {
	issuerKey, holderKey := testKey(t), testKey(t)
	now := time.Now()
	for name, tc := range map[string]struct {
		extra map[string]any
		skew  time.Duration
		want  string // "" accepted
	}{
		"no exp or nbf":              {nil, 0, ""},
		"exp in the future":          {map[string]any{"exp": now.Add(time.Minute).Unix()}, 0, ""},
		"nbf in the past":            {map[string]any{"nbf": now.Add(-time.Minute).Unix()}, 0, ""},
		"exp a string":               {map[string]any{"exp": "1767225600"}, 0, "exp claim is not a number"},
		"nbf a string":               {map[string]any{"nbf": "1767225600"}, 0, "nbf claim is not a number"},
		"expired":                    {map[string]any{"exp": now.Add(-time.Minute).Unix()}, 0, "key binding JWT has expired"},
		"expired, within skew":       {map[string]any{"exp": now.Add(-time.Minute).Unix()}, 2 * time.Minute, ""},
		"not yet valid":              {map[string]any{"nbf": now.Add(time.Minute).Unix()}, 0, "key binding JWT is not yet valid"},
		"not yet valid, within skew": {map[string]any{"nbf": now.Add(time.Minute).Unix()}, 2 * time.Minute, ""},
	} {
		t.Run(name, func(t *testing.T) {
			sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{VCT: "vc-type", CNF: map[string]any{"jwk": jwkFromECDSA(t, &holderKey.PublicKey)}}, IssueOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pres, err := Parse(sdjwt)
			if err != nil {
				t.Fatal(err)
			}
			if pres.KeyBindingJWT, err = NewKeyBindingJWT(holderKey, jose.ES256, pres, SHA256, KeyBindingClaims{Audience: "aud", Nonce: "n", Extra: tc.extra}); err != nil {
				t.Fatal(err)
			}
			presentation, err := pres.Compact()
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
				RequireKeyBinding: KeyBindingRequired, HolderPublicKey: &holderKey.PublicKey, KeyBindingAlg: jose.ES256,
				ExpectedAudience: "aud", ExpectedNonce: "n", MaxKeyBindingAge: time.Hour, MaxClockSkew: tc.skew,
			})
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("Verify = %v, want accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("Verify = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyKeyBindingJWT_NegativeSkew(t *testing.T) {
	_, err := VerifyKeyBindingJWT("x", nil, jose.ES256, KeyBindingCheck{ExpectedAudience: "a", ExpectedNonce: "n", MaxAge: time.Minute, MaxClockSkew: -time.Second})
	if err == nil || !strings.Contains(err.Error(), "MaxClockSkew") {
		t.Errorf("VerifyKeyBindingJWT = %v, want a MaxClockSkew error", err)
	}
}

// An empty ExpectedSDHash is refused, as an empty audience or nonce is:
// it would accept a Key Binding JWT without sd_hash, bound to no
// presentation (RFC 9901 §4.3), before its signature is even checked.
func TestVerifyKeyBindingJWT_RequiresExpectedSDHash(t *testing.T) {
	_, err := VerifyKeyBindingJWT("x", nil, jose.ES256, KeyBindingCheck{ExpectedAudience: "a", ExpectedNonce: "n", MaxAge: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "ExpectedSDHash is required") {
		t.Errorf("VerifyKeyBindingJWT = %v, want ExpectedSDHash required", err)
	}
}
