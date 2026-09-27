package verifier_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// TestResponseKeyID_RoutesAWalletResponseToItsRequest checks the kid a
// real Wallet's encrypted response carries is its request's
// ResponseEncryptionKeyID, and not another request's — what lets a
// Verifier with several requests open find the right decryption key.
func TestResponseKeyID_RoutesAWalletResponseToItsRequest(t *testing.T) {
	v := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t), State: "s1"})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	other, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t), State: "s2"})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	if built.ResponseEncryptionKeyID == "" || built.ResponseEncryptionKeyID == other.ResponseEncryptionKeyID {
		t.Fatalf("ResponseEncryptionKeyID = %q (other request %q), want a distinct, non-empty kid per request", built.ResponseEncryptionKeyID, other.ResponseEncryptionKeyID)
	}

	authReq, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: built.ClientID, VerifierTrust: wallet.NoVerifierTrust{},
	})
	if err != nil {
		t.Fatalf("ParseAuthorizationRequest: %v", err)
	}
	responseJWE, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: map[string][]string{"cred1": {"presentation"}}, State: authReq.State,
		EncryptionKey: authReq.ResponseEncryptionKey, EncryptionKeyID: authReq.ResponseEncryptionKeyID,
		EncryptionEnc: authReq.ResponseEncryptionEnc,
	})
	if err != nil {
		t.Fatalf("BuildDirectPostResponse: %v", err)
	}
	kid, err := verifier.ResponseKeyID(responseJWE)
	if err != nil || kid != built.ResponseEncryptionKeyID {
		t.Fatalf("ResponseKeyID = %q, %v; want %q", kid, err, built.ResponseEncryptionKeyID)
	}
	parsed, err := v.ParseDirectPostJWTResponse(responseJWE, built.ResponseDecryptionKey)
	if err != nil || parsed.State != "s1" {
		t.Fatalf("decrypt with the routed key: state %q, %v", parsed.State, err)
	}
}

func TestResponseKeyID_Rejects(t *testing.T) {
	noKid := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ECDH-ES","enc":"A128GCM"}`)) + ".." + strings.Repeat("A", 4) + ".AAAA.AAAA"
	for name, jwe := range map[string]string{
		"not a JWE":       "not-a-jwe",
		"JWS, not JWE":    "e30.e30.e30",
		"header, no kid":  noKid,
		"header not JSON": "bm90LWpzb24..AAAA.AAAA.AAAA",
	} {
		if kid, err := verifier.ResponseKeyID(jwe); err == nil {
			t.Errorf("%s: ResponseKeyID = %q, want an error", name, kid)
		}
	}
}
