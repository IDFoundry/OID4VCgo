package wallet

import (
	"encoding/json"
	"net/http"
	"testing"
)

// FuzzDecodeCredentialOffer exercises decodeCredentialOffer against
// arbitrary bytes — a Credential Offer fetched via credential_offer_uri
// is hosted wherever the offer names, not necessarily the Credential
// Issuer itself, so it's attacker-influenceable wire data parsed
// before any of its own claims (let alone the Issuer Metadata it
// points at) are trusted.
func FuzzDecodeCredentialOffer(f *testing.F) {
	valid, err := json.Marshal(map[string]any{
		"credential_issuer":            "https://issuer.example.com",
		"credential_configuration_ids": []string{"IdentityCredential"},
	})
	if err != nil {
		f.Fatalf("marshal valid offer: %v", err)
	}

	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"credential_issuer":"","credential_configuration_ids":[]}`))
	f.Add([]byte(`{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["a","a"]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeCredentialOffer(data)
	})
}

// FuzzDecodeTokenResponse exercises decodeTokenResponse against
// arbitrary bytes — the Token Endpoint's own response body,
// Authorization-Server-supplied but parsed before any of its claims
// (an access_token this Wallet is about to start presenting) are used.
func FuzzDecodeTokenResponse(f *testing.F) {
	expiresIn := int64(3600)
	valid, err := json.Marshal(map[string]any{
		"access_token": "fuzz-access-token", "token_type": "DPoP", "expires_in": expiresIn,
	})
	if err != nil {
		f.Fatalf("marshal valid token response: %v", err)
	}
	noExpiresIn, err := json.Marshal(map[string]any{
		"access_token": "fuzz-access-token", "token_type": "Bearer",
	})
	if err != nil {
		f.Fatalf("marshal token response without expires_in: %v", err)
	}

	f.Add(valid)
	f.Add(noExpiresIn)
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeTokenResponse(data)
	})
}

// FuzzParseCredentialResult exercises parseCredentialResult against
// arbitrary bytes, under both HTTP statuses it treats specially — the
// Credential/Deferred Credential Endpoint's own response body, parsed
// (or, for any other status, handed to parseError) before an issued
// credential is trusted.
func FuzzParseCredentialResult(f *testing.F) {
	completed, err := json.Marshal(map[string]any{
		"credentials": []map[string]any{{"credential": "fuzz-issued-credential"}},
	})
	if err != nil {
		f.Fatalf("marshal completed response: %v", err)
	}
	pending, err := json.Marshal(map[string]any{
		"transaction_id": "fuzz-txn", "interval": 5,
	})
	if err != nil {
		f.Fatalf("marshal pending response: %v", err)
	}
	errResp, err := json.Marshal(map[string]any{
		"error": "invalid_proof", "error_description": "fuzz error",
	})
	if err != nil {
		f.Fatalf("marshal error response: %v", err)
	}

	f.Add(http.StatusOK, completed)
	f.Add(http.StatusAccepted, pending)
	f.Add(http.StatusBadRequest, errResp)
	f.Add(http.StatusOK, []byte(`not json`))
	f.Add(http.StatusInternalServerError, []byte(`not json either`))

	f.Fuzz(func(t *testing.T, statusCode int, body []byte) {
		_, _ = parseCredentialResult(statusCode, body)
	})
}

// FuzzParseError exercises parseError against arbitrary bytes —
// tolerant by design (a non-JSON body just leaves Code/Description
// empty), but still worth a panic/hang check since it's called on
// every non-2xx Credential/Token Endpoint response.
func FuzzParseError(f *testing.F) {
	valid, err := json.Marshal(map[string]any{"error": "invalid_request", "error_description": "fuzz"})
	if err != nil {
		f.Fatalf("marshal error body: %v", err)
	}

	f.Add(http.StatusBadRequest, valid)
	f.Add(http.StatusInternalServerError, []byte(`not json`))
	f.Add(http.StatusBadRequest, []byte(``))

	f.Fuzz(func(t *testing.T, statusCode int, body []byte) {
		_ = parseError(statusCode, body)
	})
}
