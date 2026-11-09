package sdjwtvc

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// kbTestPresentation issues an SD-JWT VC bound to holderKey with two
// selectively disclosable claims, and returns it parsed, with both
// Disclosures.
func kbTestPresentation(t *testing.T, issuerKey, holderKey *ecdsa.PrivateKey) Presentation {
	t.Helper()
	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{
		VCT:        "vc-type",
		CNF:        map[string]any{"jwk": jwkFromECDSA(t, &holderKey.PublicKey)},
		Additional: map[string]any{"family_name": SD("Möbius"), "email": SD("alice@example.com")},
	}, IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pres, err := Parse(sdjwt)
	if err != nil {
		t.Fatal(err)
	}
	if len(pres.Disclosures) != 2 {
		t.Fatalf("%d Disclosures, want 2", len(pres.Disclosures))
	}
	return pres
}

// verifyKB verifies pres as an SD-JWT+KB bound to holderKey.
func verifyKB(t *testing.T, pres Presentation, issuerKey, holderKey *ecdsa.PrivateKey) error {
	t.Helper()
	presentation, err := pres.Compact()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
		RequireKeyBinding: KeyBindingRequired, HolderPublicKey: &holderKey.PublicKey, KeyBindingAlg: jose.ES256,
		ExpectedAudience: "aud", ExpectedNonce: "n", MaxKeyBindingAge: time.Hour,
	})
	return err
}

// A Key Binding JWT signed by a key other than the one the credential
// is bound to is refused: otherwise anyone holding a copy of the
// SD-JWT could present it.
func TestVerify_RefusesKeyBindingJWTFromAnotherKey(t *testing.T) {
	issuerKey, holderKey, thiefKey := testKey(t), testKey(t), testKey(t)
	pres := kbTestPresentation(t, issuerKey, holderKey)
	var err error
	if pres.KeyBindingJWT, err = NewKeyBindingJWT(holderKey, jose.ES256, pres, SHA256, KeyBindingClaims{Audience: "aud", Nonce: "n"}); err != nil {
		t.Fatal(err)
	}
	if err := verifyKB(t, pres, issuerKey, holderKey); err != nil {
		t.Fatalf("signed by the holder's key: %v", err)
	}

	if pres.KeyBindingJWT, err = NewKeyBindingJWT(thiefKey, jose.ES256, pres, SHA256, KeyBindingClaims{Audience: "aud", Nonce: "n"}); err != nil {
		t.Fatal(err)
	}
	err = verifyKB(t, pres, issuerKey, holderKey)
	if !errors.Is(err, ErrKeyBinding) || !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("signed by another key: Verify = %v, want a key binding signature failure", err)
	}
}

// The Key Binding JWT's sd_hash covers the Disclosures presented: one
// made over another selection of them is refused (RFC 9901 §7.3 step
// 5.f).
func TestVerify_RefusesKeyBindingJWTOverOtherDisclosures(t *testing.T) {
	issuerKey, holderKey := testKey(t), testKey(t)
	pres := kbTestPresentation(t, issuerKey, holderKey)
	var err error
	if pres.KeyBindingJWT, err = NewKeyBindingJWT(holderKey, jose.ES256, pres, SHA256, KeyBindingClaims{Audience: "aud", Nonce: "n"}); err != nil {
		t.Fatal(err)
	}
	pres.Disclosures = pres.Disclosures[:1]
	err = verifyKB(t, pres, issuerKey, holderKey)
	if !errors.Is(err, ErrKeyBinding) || !strings.Contains(err.Error(), "sd_hash does not match") {
		t.Errorf("Verify = %v, want an sd_hash refusal", err)
	}
}

// Each of VerifyKeyBindingJWT's checks refuses a Key Binding JWT that
// is otherwise valid and correctly signed.
func TestVerifyKeyBindingJWT_RefusesEachBadClaim(t *testing.T) {
	holderKey := testKey(t)
	now := time.Now()
	valid := func() map[string]any {
		return map[string]any{"iat": now.Unix(), "aud": "aud", "nonce": "n", "sd_hash": "hash"}
	}
	check := KeyBindingCheck{ExpectedAudience: "aud", ExpectedNonce: "n", ExpectedSDHash: "hash", MaxAge: time.Minute, Now: func() time.Time { return now }}

	for name, tc := range map[string]struct {
		header map[string]any
		edit   func(map[string]any)
		want   string // "" accepted
	}{
		"valid":                {map[string]any{"typ": KeyBindingTyp}, func(map[string]any) {}, ""},
		"no typ":               {nil, func(map[string]any) {}, "typ is"},
		"typ of an SD-JWT VC":  {map[string]any{"typ": "dc+sd-jwt"}, func(map[string]any) {}, "typ is"},
		"typ application/jwt":  {map[string]any{"typ": "jwt"}, func(map[string]any) {}, "typ is"},
		"another sd_hash":      {map[string]any{"typ": KeyBindingTyp}, func(c map[string]any) { c["sd_hash"] = "other" }, "sd_hash does not match"},
		"no sd_hash":           {map[string]any{"typ": KeyBindingTyp}, func(c map[string]any) { delete(c, "sd_hash") }, "sd_hash does not match"},
		"sd_hash not a string": {map[string]any{"typ": KeyBindingTyp}, func(c map[string]any) { c["sd_hash"] = 1 }, "sd_hash does not match"},
		"another aud":          {map[string]any{"typ": KeyBindingTyp}, func(c map[string]any) { c["aud"] = "other" }, "aud does not match"},
		"another nonce":        {map[string]any{"typ": KeyBindingTyp}, func(c map[string]any) { c["nonce"] = "other" }, "nonce does not match"},
		"no iat":               {map[string]any{"typ": KeyBindingTyp}, func(c map[string]any) { delete(c, "iat") }, "iat claim is missing"},
		"iat a string":         {map[string]any{"typ": KeyBindingTyp}, func(c map[string]any) { c["iat"] = "1767225600" }, "iat claim is missing"},
		"iat too old":          {map[string]any{"typ": KeyBindingTyp}, func(c map[string]any) { c["iat"] = now.Add(-2 * time.Minute).Unix() }, "too old"},
		"iat in the future":    {map[string]any{"typ": KeyBindingTyp}, func(c map[string]any) { c["iat"] = now.Add(2 * time.Minute).Unix() }, "too far in the future"},
	} {
		t.Run(name, func(t *testing.T) {
			claims := valid()
			tc.edit(claims)
			raw, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			kbJWT, err := jose.Sign(jose.ES256, holderKey, tc.header, raw)
			if err != nil {
				t.Fatal(err)
			}
			_, err = VerifyKeyBindingJWT(kbJWT, &holderKey.PublicKey, jose.ES256, check)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("VerifyKeyBindingJWT = %v, want accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("VerifyKeyBindingJWT = %v, want %q", err, tc.want)
			}
		})
	}
}
