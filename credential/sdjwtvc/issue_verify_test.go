package sdjwtvc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func jwkFromECDSA(t *testing.T, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	// SEC1 uncompressed point: 0x04 || X || Y, each coordinate
	// curve-size bytes — avoids the deprecated PublicKey.X/Y field
	// access (see crypto/ecdsa's own doc comment as of Go 1.26).
	raw, err := pub.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}
	size := (len(raw) - 1) / 2
	x := raw[1 : 1+size]
	y := raw[1+size:]
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64.EncodeToString(x),
		"y":   b64.EncodeToString(y),
	}
}

func TestIssueVerify_FullDisclosure(t *testing.T) {
	issuerKey := testKey(t)
	holderKey := testKey(t)

	claims := Claims{
		VCT: "https://credentials.example.com/identity_credential",
		Iss: "https://example.com/issuer",
		CNF: map[string]any{"jwk": jwkFromECDSA(t, &holderKey.PublicKey)},
		Additional: map[string]any{
			"given_name":  "Alice",
			"family_name": SD("Möbius"),
			"nationalities": []any{
				"DE", SDElement("FR"), "US",
			},
		},
	}

	sdjwt, disclosures, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(disclosures) != 2 {
		t.Fatalf("got %d disclosures, want 2", len(disclosures))
	}

	// Issue always includes every Disclosure, so parsing the Issuer's
	// own output already yields a "present everything" Presentation.
	pres, err := Parse(sdjwt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	kbJWT, err := NewKeyBindingJWT(holderKey, jose.ES256, pres, SHA256, KeyBindingClaims{
		Audience: "https://example.com/verifier",
		Nonce:    "n-0S6_WzA2Mj",
	})
	if err != nil {
		t.Fatalf("NewKeyBindingJWT: %v", err)
	}

	pres.KeyBindingJWT = kbJWT
	presentation, err := pres.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}

	payload, header, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
		RequireKeyBinding: KeyBindingRequired,
		HolderPublicKey:   &holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  "https://example.com/verifier",
		ExpectedNonce:     "n-0S6_WzA2Mj",
		MaxKeyBindingAge:  time.Hour,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if header["typ"] != TypHeader {
		t.Errorf("typ = %v, want %v", header["typ"], TypHeader)
	}
	if payload["given_name"] != "Alice" || payload["family_name"] != "Möbius" {
		t.Errorf("payload = %+v", payload)
	}
	nats, _ := payload["nationalities"].([]any)
	if len(nats) != 3 {
		t.Errorf("nationalities = %v, want 3 elements", nats)
	}
	if payload["vct"] != claims.VCT {
		t.Errorf("vct = %v", payload["vct"])
	}
}

func TestIssueVerify_PartialDisclosure_NoKeyBinding(t *testing.T) {
	issuerKey := testKey(t)

	claims := Claims{
		VCT: "https://credentials.example.com/identity_credential",
		Additional: map[string]any{
			"given_name":  "Alice",
			"family_name": SD("Möbius"),
			"email":       SD("alice@example.com"),
		},
	}
	sdjwt, disclosures, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	pres, err := Parse(sdjwt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Present only the family_name disclosure, not email.
	var toPresent []Disclosure
	for _, d := range disclosures {
		if d.Name == "family_name" {
			toPresent = append(toPresent, d)
		}
	}
	pres.Disclosures = toPresent
	presentation, err := pres.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}

	payload, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if payload["family_name"] != "Möbius" {
		t.Errorf("family_name = %v", payload["family_name"])
	}
	if _, hasEmail := payload["email"]; hasEmail {
		t.Errorf("email should not be disclosed, got %v", payload["email"])
	}
	if payload["given_name"] != "Alice" {
		t.Errorf("given_name = %v", payload["given_name"])
	}
}

func TestVerify_RejectsMissingRequiredKeyBinding(t *testing.T) {
	issuerKey := testKey(t)
	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{VCT: "vc-type"}, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, _, err = Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingRequired})
	if err == nil {
		t.Errorf("Verify accepted a bare SD-JWT when RequireKeyBinding was set")
	}
}

func TestVerify_RejectsTamperedDisclosureValue(t *testing.T) {
	issuerKey := testKey(t)
	claims := Claims{
		VCT:        "vc-type",
		Additional: map[string]any{"age": SD(30)},
	}
	sdjwt, disclosures, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Tamper: rebuild the age disclosure with a different value but
	// the original salt, then present that instead. Its digest will no
	// longer match anything embedded in the issuer JWT.
	tampered := Disclosure{Salt: disclosures[0].Salt, Name: "age", Value: 99}
	encTampered, err := tampered.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	pres, err := Parse(sdjwt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	presentation := pres.IssuerJWT + "~" + encTampered + "~"

	if _, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}); err == nil {
		t.Errorf("Verify accepted a tampered disclosure")
	}
}

func TestVerify_RejectsWrongIssuerKey(t *testing.T) {
	issuerKey := testKey(t)
	otherKey := testKey(t)
	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{VCT: "vc-type"}, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := Verify(sdjwt, &otherKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}); err == nil {
		t.Errorf("Verify accepted a signature under the wrong issuer key")
	}
}

// newKeyBoundSDJWTVCPresentation issues a fresh SD-JWT VC bound to
// holderKey and presents it with a Key Binding JWT naming aud/nonce —
// the shared setup TestVerify_RejectsWrongKeyBindingNonce/
// TestVerify_KeyBindingMaxAge/TestVerify_RequiresMaxKeyBindingAge all
// need, varying only what they check about the resulting Verify call.
func newKeyBoundSDJWTVCPresentation(t *testing.T, issuerKey, holderKey *ecdsa.PrivateKey, aud, nonce string) string {
	t.Helper()
	claims := Claims{VCT: "vc-type", CNF: map[string]any{"jwk": jwkFromECDSA(t, &holderKey.PublicKey)}}
	sdjwt, _, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pres, err := Parse(sdjwt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	kbJWT, err := NewKeyBindingJWT(holderKey, jose.ES256, pres, SHA256, KeyBindingClaims{
		Audience: aud, Nonce: nonce,
	})
	if err != nil {
		t.Fatalf("NewKeyBindingJWT: %v", err)
	}
	pres.KeyBindingJWT = kbJWT
	presentation, err := pres.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	return presentation
}

func TestVerify_RejectsWrongKeyBindingNonce(t *testing.T) {
	issuerKey := testKey(t)
	holderKey := testKey(t)
	presentation := newKeyBoundSDJWTVCPresentation(t, issuerKey, holderKey, "aud", "correct-nonce")

	_, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
		RequireKeyBinding: KeyBindingRequired,
		HolderPublicKey:   &holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  "aud",
		ExpectedNonce:     "wrong-nonce",
		MaxKeyBindingAge:  time.Hour,
	})
	if err == nil {
		t.Errorf("Verify accepted a key binding JWT with the wrong nonce")
	}
}

func TestVerify_KeyBindingMaxAge(t *testing.T) {
	issuerKey := testKey(t)
	holderKey := testKey(t)
	presentation := newKeyBoundSDJWTVCPresentation(t, issuerKey, holderKey, "aud", "n")

	future := func() time.Time { return time.Now().Add(2 * time.Hour) }
	_, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
		RequireKeyBinding: KeyBindingRequired,
		HolderPublicKey:   &holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  "aud",
		ExpectedNonce:     "n",
		MaxKeyBindingAge:  time.Hour,
		Now:               future,
	})
	if err == nil {
		t.Errorf("Verify accepted an expired key binding JWT")
	}
}

// TestVerify_KeyBindingIatInFuture proves MaxKeyBindingAge's freshness
// check rejects a Key Binding JWT whose iat is too far in the future,
// not just too far in the past — found live against the OIDF
// conformance suite's own kb-jwt-iat-in-future negative test, which a
// purely past-looking "age > MaxAge" check silently accepted (a
// negative age is never greater than a positive MaxAge). Mirrors
// TestVerify_KeyBindingMaxAge's own technique in reverse: the KB-JWT
// is genuinely signed at the real time.Now(), and Now is set back
// instead, making that real signing instant look MaxKeyBindingAge in
// the future relative to "verification time."
func TestVerify_KeyBindingIatInFuture(t *testing.T) {
	issuerKey := testKey(t)
	holderKey := testKey(t)
	presentation := newKeyBoundSDJWTVCPresentation(t, issuerKey, holderKey, "aud", "n")

	past := func() time.Time { return time.Now().Add(-2 * time.Hour) }
	_, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
		RequireKeyBinding: KeyBindingRequired,
		HolderPublicKey:   &holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  "aud",
		ExpectedNonce:     "n",
		MaxKeyBindingAge:  time.Hour,
		Now:               past,
	})
	if err == nil {
		t.Errorf("Verify accepted a key binding JWT whose iat is in the future relative to verification time")
	}
}

// TestVerify_RequiresMaxKeyBindingAge proves MaxKeyBindingAge's zero
// value is rejected outright rather than silently disabling the Key
// Binding JWT freshness check (see KeyBindingCheck.MaxAge's own doc
// comment) — a caller can no longer leave this unset while requiring
// key binding.
func TestVerify_RequiresMaxKeyBindingAge(t *testing.T) {
	issuerKey := testKey(t)
	holderKey := testKey(t)
	presentation := newKeyBoundSDJWTVCPresentation(t, issuerKey, holderKey, "aud", "n")

	_, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
		RequireKeyBinding: KeyBindingRequired,
		HolderPublicKey:   &holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  "aud",
		ExpectedNonce:     "n",
		// MaxKeyBindingAge deliberately left unset.
	})
	if err == nil {
		t.Fatal("Verify = nil error, want error (MaxKeyBindingAge unset while RequireKeyBinding is true)")
	}
}

// TestVerify_RequiresRequireKeyBinding proves RequireKeyBinding's Go
// zero value is rejected outright rather than silently meaning
// KeyBindingNotRequired (see KeyBindingRequirement's own doc comment)
// — a caller must state the policy decision RFC 9901 §7.3 step 1
// requires explicitly.
func TestVerify_RequiresRequireKeyBinding(t *testing.T) {
	issuerKey := testKey(t)
	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{VCT: "vc-type"}, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, _, err = Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, VerifyOptions{})
	if err == nil {
		t.Fatal("Verify = nil error, want error (RequireKeyBinding unset)")
	}
}

func TestVerifyKeyBindingJWT_RequiresMaxAge(t *testing.T) {
	holderKey := testKey(t)
	kbJWT, err := jose.Sign(jose.ES256, holderKey, map[string]any{"typ": KeyBindingTyp}, []byte(`{"aud":"aud","nonce":"n","sd_hash":"h"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_, err = VerifyKeyBindingJWT(kbJWT, &holderKey.PublicKey, jose.ES256, KeyBindingCheck{
		ExpectedAudience: "aud", ExpectedNonce: "n", ExpectedSDHash: "h",
		// MaxAge deliberately left unset.
	})
	if err == nil {
		t.Fatal("VerifyKeyBindingJWT = nil error, want error (MaxAge unset)")
	}
}

// issueBareCompact builds a bare (no Key Binding) presentation of a
// freshly issued credential carrying claims, returning it alongside
// the issuer key it was signed with — the shared setup every exp/nbf
// test below needs, since none of them exercise key binding.
func issueBareCompact(t *testing.T, claims Claims) (*ecdsa.PrivateKey, string) {
	t.Helper()
	issuerKey := testKey(t)
	sdjwt, _, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pres, err := Parse(sdjwt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	presentation, err := pres.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	return issuerKey, presentation
}

// TestVerify_RejectsExpiredCredential, TestVerify_RejectsNotYetValidCredential
// and TestVerify_AcceptsCredentialWithinValidityWindow are the
// regression tests for a real bug found in a repo-wide security
// review: Verify used to never check exp/nbf at all — it looks and
// behaves like a complete verification (returns a plain payload, no
// separate "is it still valid" step), so a caller had no obvious
// signal that time-validity was still their own job. This repo's own
// sibling Verify functions (credential/mdoc.Verify,
// statuslist.VerifyToken/VerifyTokenCWT) already checked their own
// equivalent validity window unconditionally — sdjwtvc.Verify was the
// odd one out.
func TestVerify_RejectsExpiredCredential(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	issuerKey, presentation := issueBareCompact(t, Claims{VCT: "vc-type", Exp: &past})

	if _, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}); err == nil {
		t.Error("Verify accepted a credential whose own exp claim is in the past")
	}
}

func TestVerify_RejectsNotYetValidCredential(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	issuerKey, presentation := issueBareCompact(t, Claims{VCT: "vc-type", Nbf: &future})

	if _, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}); err == nil {
		t.Error("Verify accepted a credential whose own nbf claim is in the future")
	}
}

// TestVerify_AcceptsCredentialWithinValidityWindow proves the fix
// above doesn't reject a legitimately-current credential — exp in the
// future, nbf in the past both pass.
func TestVerify_AcceptsCredentialWithinValidityWindow(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	future := time.Now().Add(time.Hour).Unix()
	issuerKey, presentation := issueBareCompact(t, Claims{VCT: "vc-type", Nbf: &past, Exp: &future})

	if _, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}); err != nil {
		t.Errorf("Verify rejected a credential within its own valid exp/nbf window: %v", err)
	}
}

func TestIssue_NoSelectivelyDisclosableClaims(t *testing.T) {
	// draft-11 §3.2.2.4: no _sd claim and no Disclosures when nothing
	// is selectively disclosable.
	issuerKey := testKey(t)
	sdjwt, disclosures, err := Issue(issuerKey, jose.ES256, Claims{
		VCT:        "vc-type",
		Additional: map[string]any{"given_name": "Alice"},
	}, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(disclosures) != 0 {
		t.Fatalf("got %d disclosures, want 0", len(disclosures))
	}
	payload, _, err := Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if payload["given_name"] != "Alice" {
		t.Errorf("given_name = %v", payload["given_name"])
	}
	if _, hasSD := payload["_sd"]; hasSD {
		t.Errorf("payload has _sd with zero disclosures")
	}
}

func TestIssue_RejectsReservedClaimInAdditional(t *testing.T) {
	issuerKey := testKey(t)
	_, _, err := Issue(issuerKey, jose.ES256, Claims{
		VCT:        "vc-type",
		Additional: map[string]any{"vct": "override-attempt"},
	}, IssueOptions{})
	if err == nil {
		t.Errorf("Issue accepted \"vct\" inside Additional")
	}
}

func TestIssue_RequiresVCT(t *testing.T) {
	issuerKey := testKey(t)
	if _, _, err := Issue(issuerKey, jose.ES256, Claims{}, IssueOptions{}); err == nil {
		t.Errorf("Issue accepted Claims with no VCT")
	}
}

func TestIssue_Decoys(t *testing.T) {
	issuerKey := testKey(t)
	claims := Claims{
		VCT:        "vc-type",
		Additional: map[string]any{"a": SD("1")},
	}
	sdjwt, disclosures, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{Decoys: 3})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(disclosures) != 1 {
		t.Fatalf("got %d disclosures, want 1", len(disclosures))
	}
	// Verify still succeeds with decoys present alongside the real digest.
	payload, _, err := Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	_ = payload
}

func TestIssue_IssuerCertificate_SetsX5CHeader(t *testing.T) {
	issuerKey := testKey(t)
	cert := testcert.SelfSigned(t, "test-issuer", &issuerKey.PublicKey, issuerKey)
	claims := Claims{VCT: "vc-type"}

	sdjwt, _, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{IssuerCertificate: cert})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	x5c := testcert.AssertSingleX5CHeader(t, sdjwt)
	got, ok := x5c[0].(string)
	if !ok {
		t.Fatalf("x5c[0] = %#v, want a string", x5c[0])
	}
	want := base64.StdEncoding.EncodeToString(cert.Raw)
	if got != want {
		t.Errorf("x5c[0] = %q, want %q", got, want)
	}
}

func TestIssue_IssuerCertificate_RejectsPublicKeyMismatch(t *testing.T) {
	issuerKey := testKey(t)
	otherKey := testKey(t)
	cert := testcert.SelfSigned(t, "test-issuer", &otherKey.PublicKey, otherKey)
	claims := Claims{VCT: "vc-type"}

	if _, _, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{IssuerCertificate: cert}); err == nil {
		t.Error("Issue accepted an IssuerCertificate whose public key doesn't match signer")
	}
}

type nonComparablePublicKey struct{}

// nonComparableSigner is a crypto.Signer returning
// nonComparablePublicKey — Sign is never called in this test, so it's
// left unimplemented (a nil-safe panic-on-call stand-in is unnecessary
// here since Issue never signs anything before the check this exists
// to exercise).
type nonComparableSigner struct{}

func (nonComparableSigner) Public() crypto.PublicKey { return nonComparablePublicKey{} }
func (nonComparableSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("not called by this test")
}

// TestIssue_IssuerCertificate_RejectsSignerWithoutEqualMethod is the
// regression test for a real bug found in a repo-wide
// spec-comprehensiveness review (as a side effect of adding the
// analogous check to credential/mdoc.Issue): Issue used to do a direct
// (unchecked) type assertion to compare signer's own public key
// against opts.IssuerCertificate's — every stdlib key type implements
// the required Equal method, so this never panicked with an ordinary
// ecdsa/rsa/ed25519 signer, but a custom crypto.Signer (an HSM/KMS-backed
// one) whose own public key type doesn't implement it caused Issue to
// panic instead of returning the documented config-mismatch error —
// the same bug class verifier.New's own equivalent check already
// guards against.
func TestIssue_IssuerCertificate_RejectsSignerWithoutEqualMethod(t *testing.T) {
	issuerKey := testKey(t)
	cert := testcert.SelfSigned(t, "test-issuer", &issuerKey.PublicKey, issuerKey)
	claims := Claims{VCT: "vc-type"}

	if _, _, err := Issue(nonComparableSigner{}, jose.ES256, claims, IssueOptions{IssuerCertificate: cert}); err == nil {
		t.Error("Issue = nil error, want error (not a panic)")
	}
}

func TestRoundedExp_SameDayIssuanceYieldsSameExp(t *testing.T) {
	// Two "issuances" separated by a real, non-trivial gap, both
	// within the same UTC day — the exact scenario
	// happy-flow-multiple-clients caught live: two credentials issued
	// moments apart must not carry two different exp values, or a
	// party holding both can correlate them by the gap alone.
	first := time.Date(2026, time.September, 16, 10, 0, 0, 0, time.UTC)
	second := first.Add(3 * time.Second)

	lifetime := 365 * 24 * time.Hour
	got1 := RoundedExp(first, lifetime)
	got2 := RoundedExp(second, lifetime)
	if got1 != got2 {
		t.Errorf("RoundedExp(first) = %d, RoundedExp(second) = %d, want equal for same-day issuance", got1, got2)
	}
}

func TestRoundedExp_CrossesDayBoundary(t *testing.T) {
	before := time.Date(2026, time.September, 16, 23, 59, 59, 0, time.UTC)
	after := time.Date(2026, time.September, 17, 0, 0, 1, 0, time.UTC)

	lifetime := 24 * time.Hour
	got1 := RoundedExp(before, lifetime)
	got2 := RoundedExp(after, lifetime)
	if got1 == got2 {
		t.Errorf("RoundedExp on either side of a day boundary produced the same value %d, want different", got1)
	}
	wantBefore := time.Date(2026, time.September, 17, 0, 0, 0, 0, time.UTC).Unix()
	if got1 != wantBefore {
		t.Errorf("RoundedExp(before) = %d, want %d (start of before's own day + lifetime)", got1, wantBefore)
	}
}

func TestIssue_RejectsOutOfRangeDecoys(t *testing.T) {
	issuerKey := testKey(t)
	claims := Claims{VCT: "vc-type"}
	for _, n := range []int{-1, MaxDecoys + 1, int(^uint(0) >> 1)} {
		if _, _, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{Decoys: n}); err == nil {
			t.Errorf("Issue(Decoys=%d) = nil error, want error", n)
		}
	}
	if _, _, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{Decoys: MaxDecoys}); err != nil {
		t.Errorf("Issue(Decoys=MaxDecoys): %v", err)
	}
}
