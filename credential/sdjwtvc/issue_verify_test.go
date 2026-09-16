package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/testcert"
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
		RequireKeyBinding: true,
		HolderPublicKey:   &holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  "https://example.com/verifier",
		ExpectedNonce:     "n-0S6_WzA2Mj",
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

	payload, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{})
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
	_, _, err = Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: true})
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

	if _, _, err := Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{}); err == nil {
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
	if _, _, err := Verify(sdjwt, &otherKey.PublicKey, jose.ES256, VerifyOptions{}); err == nil {
		t.Errorf("Verify accepted a signature under the wrong issuer key")
	}
}

func TestVerify_RejectsWrongKeyBindingNonce(t *testing.T) {
	issuerKey := testKey(t)
	holderKey := testKey(t)
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
		Audience: "aud", Nonce: "correct-nonce",
	})
	if err != nil {
		t.Fatalf("NewKeyBindingJWT: %v", err)
	}
	pres.KeyBindingJWT = kbJWT
	presentation, err := pres.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}

	_, _, err = Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
		RequireKeyBinding: true,
		HolderPublicKey:   &holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  "aud",
		ExpectedNonce:     "wrong-nonce",
	})
	if err == nil {
		t.Errorf("Verify accepted a key binding JWT with the wrong nonce")
	}
}

func TestVerify_KeyBindingMaxAge(t *testing.T) {
	issuerKey := testKey(t)
	holderKey := testKey(t)
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
		Audience: "aud", Nonce: "n",
	})
	if err != nil {
		t.Fatalf("NewKeyBindingJWT: %v", err)
	}
	pres.KeyBindingJWT = kbJWT
	presentation, err := pres.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}

	future := func() time.Time { return time.Now().Add(2 * time.Hour) }
	_, _, err = Verify(presentation, &issuerKey.PublicKey, jose.ES256, VerifyOptions{
		RequireKeyBinding: true,
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
	payload, _, err := Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, VerifyOptions{})
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
	payload, _, err := Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, VerifyOptions{})
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

	issuerJWT := strings.SplitN(sdjwt, "~", 2)[0]
	header, _, err := jose.DecodeUnverified(issuerJWT)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}

	x5c, ok := header["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf("header[\"x5c\"] = %#v, want a single-entry array", header["x5c"])
	}
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
