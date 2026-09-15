package wallet_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/wallet"
)

const testPresentationVCT = "https://credentials.example.com/identity_credential"

func presentationJWKFromECDSA(pub *ecdsa.PublicKey) (map[string]any, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	size := (len(raw) - 1) / 2
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": enc(raw[1 : 1+size]), "y": enc(raw[1+size:]),
	}, nil
}

// heldSDJWTVCFixture is a real, freshly issued "dc+sd-jwt" credential
// bound to a fresh holder key, wrapped as a wallet.HeldCredential —
// the setup every MatchDCQLQuery/PresentSDJWTVC/PresentCredentials
// test needs.
type heldSDJWTVCFixture struct {
	issuerKey *ecdsa.PrivateKey
	holderKey *ecdsa.PrivateKey
	held      wallet.HeldCredential
}

func newHeldSDJWTVC(t *testing.T) heldSDJWTVCFixture {
	t.Helper()
	issuerKey := testP256Key(t)
	holderKey := testP256Key(t)
	holderJWK, err := presentationJWKFromECDSA(&holderKey.PublicKey)
	if err != nil {
		t.Fatalf("presentationJWKFromECDSA: %v", err)
	}
	sdjwt, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT: testPresentationVCT,
		CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{
			"given_name": "Alice",
		},
	}, sdjwtvc.IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return heldSDJWTVCFixture{
		issuerKey: issuerKey, holderKey: holderKey,
		held: wallet.HeldCredential{
			Format: sdjwtvc.CredentialFormat, Credential: sdjwt,
			HolderKey: holderKey, HolderKeyAlg: jose.ES256,
		},
	}
}

func testPresentationQuery(t *testing.T) dcql.Query {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{testPresentationVCT}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	return dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}}},
	}}}
}

func TestMatchDCQLQuery(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	matches, err := wallet.MatchDCQLQuery(testPresentationQuery(t), []wallet.HeldCredential{fixture.held})
	if err != nil {
		t.Fatalf("MatchDCQLQuery: %v", err)
	}
	if len(matches) != 1 || matches["identity_credential"].Credential != fixture.held.Credential {
		t.Errorf("matches = %+v", matches)
	}
}

func TestMatchDCQLQueryRejectsNoCandidate(t *testing.T) {
	if _, err := wallet.MatchDCQLQuery(testPresentationQuery(t), nil); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

func TestMatchDCQLQueryRejectsWrongVCT(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"https://credentials.example.com/some_other_credential"}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "x", Format: sdjwtvc.CredentialFormat, Meta: meta}}}
	if _, err := wallet.MatchDCQLQuery(query, []wallet.HeldCredential{fixture.held}); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

func TestMatchDCQLQueryRejectsClaimSets(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{testPresentationVCT}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims:    []dcql.ClaimsQuery{{ID: "given_name", Path: dcql.Path{dcql.PathKey("given_name")}}},
		ClaimSets: [][]string{{"given_name"}},
	}}}
	if _, err := wallet.MatchDCQLQuery(query, []wallet.HeldCredential{fixture.held}); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

func TestMatchDCQLQueryRejectsInvalidQuery(t *testing.T) {
	if _, err := wallet.MatchDCQLQuery(dcql.Query{}, nil); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

func TestPresentSDJWTVC(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	compact, err := wallet.PresentSDJWTVC(fixture.held, "x509_hash:verifier", "nonce-1")
	if err != nil {
		t.Fatalf("PresentSDJWTVC: %v", err)
	}
	claims, _, err := sdjwtvc.Verify(compact, &fixture.issuerKey.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: true,
		HolderPublicKey:   &fixture.holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  "x509_hash:verifier",
		ExpectedNonce:     "nonce-1",
	})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	if claims["given_name"] != "Alice" {
		t.Errorf("given_name = %v, want Alice", claims["given_name"])
	}
}

func TestPresentSDJWTVCRejectsWrongFormat(t *testing.T) {
	held := wallet.HeldCredential{Format: "mso_mdoc", Credential: "irrelevant"}
	if _, err := wallet.PresentSDJWTVC(held, "aud", "nonce"); err == nil {
		t.Fatalf("PresentSDJWTVC = nil error, want error")
	}
}

func TestPresentCredentials(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	vpToken, err := wallet.PresentCredentials(wallet.PresentationRequest{
		Query:       testPresentationQuery(t),
		Credentials: []wallet.HeldCredential{fixture.held},
		Audience:    "x509_hash:verifier",
		Nonce:       "nonce-1",
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	if len(vpToken["identity_credential"]) != 1 {
		t.Fatalf("vp_token = %v", vpToken)
	}
	claims, _, err := sdjwtvc.Verify(vpToken["identity_credential"][0], &fixture.issuerKey.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: true,
		HolderPublicKey:   &fixture.holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  "x509_hash:verifier",
		ExpectedNonce:     "nonce-1",
	})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	if claims["given_name"] != "Alice" {
		t.Errorf("given_name = %v, want Alice", claims["given_name"])
	}
}

func TestPresentCredentialsRejectsMissingAudienceOrNonce(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	cases := map[string]wallet.PresentationRequest{
		"missing audience": {Query: testPresentationQuery(t), Credentials: []wallet.HeldCredential{fixture.held}, Nonce: "nonce-1"},
		"missing nonce":    {Query: testPresentationQuery(t), Credentials: []wallet.HeldCredential{fixture.held}, Audience: "x509_hash:verifier"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := wallet.PresentCredentials(req); err == nil {
				t.Fatalf("PresentCredentials(%s) = nil error, want error", name)
			}
		})
	}
}
