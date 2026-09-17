package attestation

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// TestParseWalletAttestationClaims_OID4VCIAppendixEExample reproduces
// Appendix E's own worked example claims (again re-signed locally,
// since the spec's own decoded example carries no independently
// verifiable signature — see keyattestation_test.go's equivalent note).
func TestParseWalletAttestationClaims_OID4VCIAppendixEExample(t *testing.T) {
	const examplePayload = `{
		"iss": "https://wallet-provider.example.com",
		"sub": "https://wallet.example.org",
		"wallet_name": "Wallet Solution X by Wonderland State Department",
		"wallet_link": "https://example.com/wallet/detail_info.html",
		"nbf": 1300815780,
		"exp": 1300819380,
		"cnf": {
			"jwk": {
				"kty": "EC",
				"use": "sig",
				"crv": "P-256",
				"x": "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
				"y": "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
			}
		}
	}`
	key := testKey(t)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": WalletAttestationTypHeader, "kid": "11"}, []byte(examplePayload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	claims, err := ParseWalletAttestationClaims(compact)
	if err != nil {
		t.Fatalf("ParseWalletAttestationClaims: %v", err)
	}
	if claims.WalletName != "Wallet Solution X by Wonderland State Department" {
		t.Errorf("WalletName = %q", claims.WalletName)
	}
	if claims.WalletLink != "https://example.com/wallet/detail_info.html" {
		t.Errorf("WalletLink = %q", claims.WalletLink)
	}
}

func TestParseWalletAttestationClaims_Status(t *testing.T) {
	key := testKey(t)
	payload := `{"status":{"status_list":{"idx":3,"uri":"https://example.com/statuslists/1"}}}`
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": WalletAttestationTypHeader}, []byte(payload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := ParseWalletAttestationClaims(compact)
	if err != nil {
		t.Fatalf("ParseWalletAttestationClaims: %v", err)
	}
	if claims.Status == nil {
		t.Fatalf("Status is nil")
	}
}

func TestParseWalletAttestationClaims_NoExtraClaims(t *testing.T) {
	key := testKey(t)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": WalletAttestationTypHeader}, []byte(`{"iss":"a","sub":"b"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := ParseWalletAttestationClaims(compact)
	if err != nil {
		t.Fatalf("ParseWalletAttestationClaims: %v", err)
	}
	if claims.WalletName != "" || claims.WalletLink != "" || claims.Status != nil {
		t.Errorf("claims = %+v, want all zero", claims)
	}
}

func TestParseWalletAttestationClaims_RejectsMalformedCompact(t *testing.T) {
	if _, err := ParseWalletAttestationClaims("not-a-jwt"); err == nil {
		t.Errorf("ParseWalletAttestationClaims accepted a malformed compact JWS")
	}
}

func TestParseWalletAttestationClaims_RejectsNonJSONPayload(t *testing.T) {
	key := testKey(t)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": WalletAttestationTypHeader}, []byte("not json"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := ParseWalletAttestationClaims(compact); err == nil {
		t.Errorf("ParseWalletAttestationClaims accepted a non-JSON payload")
	}
}

func TestParseWalletAttestationClaims_RejectsWrongTyp(t *testing.T) {
	key := testKey(t)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "not-the-right-typ"}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := ParseWalletAttestationClaims(compact); err == nil {
		t.Errorf("ParseWalletAttestationClaims accepted the wrong typ header")
	}
}
