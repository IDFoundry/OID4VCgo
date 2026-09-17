package wallet_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/wallet"
)

func testEncryptionRecipientJWK(t *testing.T, kid string, pub *ecdsa.PublicKey) json.RawMessage {
	t.Helper()
	k, err := jwk.Marshal(pub)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	raw, err := json.Marshal(struct {
		jwk.JWK
		Kid string `json:"kid"`
	}{JWK: k, Kid: kid})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return raw
}

func jweResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/jwt"}},
	}
}

// simulateIssuerEncryptedExchange returns a fakeProtectedResourceClient
// callback that plays the issuer's role for a §10-encrypted exchange:
// decrypt the incoming request with reqPriv, extract the Wallet's own
// credential_response_encryption object from it, and encrypt
// responseBody back to that ephemeral key — the same round trip a real
// issuer.Issuer (DecryptRequestBody/EncryptResponseBody) performs.
// resource is the very fakeProtectedResourceClient this callback will
// be installed on: its own Do already drains req.Body into lastBody
// before invoking this callback, so this reads that rather than
// req.Body a second time (which would already be empty).
func simulateIssuerEncryptedExchange(t *testing.T, resource *fakeProtectedResourceClient, reqPriv *ecdsa.PrivateKey, responseBody []byte) func(context.Context, *http.Request) (*http.Response, error) {
	t.Helper()
	return func(_ context.Context, req *http.Request) (*http.Response, error) {
		if req.Header.Get("Content-Type") != "application/jwt" {
			t.Fatalf("Content-Type = %q, want application/jwt", req.Header.Get("Content-Type"))
		}
		plaintext, err := jwe.Decrypt(reqPriv, string(resource.lastBody))
		if err != nil {
			t.Fatalf("jwe.Decrypt request: %v", err)
		}
		var parsed struct {
			ResponseEncryption *struct {
				JWK json.RawMessage `json:"jwk"`
				Enc string          `json:"enc"`
			} `json:"credential_response_encryption"`
		}
		if err := json.Unmarshal(plaintext, &parsed); err != nil {
			t.Fatalf("unmarshal decrypted request: %v", err)
		}
		if parsed.ResponseEncryption == nil {
			t.Fatalf("decrypted request has no credential_response_encryption")
		}
		respPub, err := jwk.ParsePublicKey(parsed.ResponseEncryption.JWK)
		if err != nil {
			t.Fatalf("parse response encryption jwk: %v", err)
		}
		ecRespPub, ok := respPub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("response encryption jwk is not EC")
		}
		compact, err := jwe.Encrypt(ecRespPub, jwe.Enc(parsed.ResponseEncryption.Enc), responseBody, jwe.EncryptOptions{})
		if err != nil {
			t.Fatalf("jwe.Encrypt response: %v", err)
		}
		return jweResponse(compact), nil
	}
}

// credentialCaller abstracts over RequestCredential/RequestDeferredCredential
// for tests exercising behavior §10 encryption applies identically to
// both endpoints — avoids duplicating each such test once per
// endpoint.
type credentialCaller func(t *testing.T, w *wallet.Wallet, resource wallet.ProtectedResourceClient, reqEnc *wallet.RequestEncryption, respEnc *wallet.ResponseEncryption) (wallet.CredentialResult, error)

func callRequestCredential(t *testing.T, w *wallet.Wallet, resource wallet.ProtectedResourceClient, reqEnc *wallet.RequestEncryption, respEnc *wallet.ResponseEncryption) (wallet.CredentialResult, error) {
	t.Helper()
	return w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          "https://issuer.example.com",
		RequestEncryption:         reqEnc,
		ResponseEncryption:        respEnc,
	})
}

func callRequestDeferredCredential(t *testing.T, w *wallet.Wallet, resource wallet.ProtectedResourceClient, reqEnc *wallet.RequestEncryption, respEnc *wallet.ResponseEncryption) (wallet.CredentialResult, error) {
	t.Helper()
	return w.RequestDeferredCredential(context.Background(), resource, testDeferredCredentialEndpoint(t), wallet.DeferredCredentialRequest{
		TransactionID:      "txn-1",
		RequestEncryption:  reqEnc,
		ResponseEncryption: respEnc,
	})
}

func credentialCallers() map[string]credentialCaller {
	return map[string]credentialCaller{"credential": callRequestCredential, "deferred_credential": callRequestDeferredCredential}
}

func TestRejectsResponseEncryptionWithoutRequestEncryption(t *testing.T) {
	for name, call := range credentialCallers() {
		t.Run(name, func(t *testing.T) {
			w, err := wallet.New(validConfig(), validDependencies())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			resource := &fakeProtectedResourceClient{do: func(context.Context, *http.Request) (*http.Response, error) {
				t.Fatalf("unexpected HTTP call")
				return nil, nil
			}}
			if _, err := call(t, w, resource, nil, &wallet.ResponseEncryption{Enc: jwe.A128GCM}); err == nil {
				t.Fatalf("call = nil error, want error")
			}
		})
	}
}

func TestResponseEncryptionRoundTrip(t *testing.T) {
	for name, call := range credentialCallers() {
		t.Run(name, func(t *testing.T) {
			w, err := wallet.New(validConfig(), validDependencies())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			reqRecipientKey := testP256Key(t)
			resource := &fakeProtectedResourceClient{}
			resource.do = simulateIssuerEncryptedExchange(t, resource, reqRecipientKey, []byte(`{"credentials":[{"credential":"c1"}]}`))

			result, err := call(t, w, resource, &wallet.RequestEncryption{
				RecipientJWK: testEncryptionRecipientJWK(t, "req-1", &reqRecipientKey.PublicKey),
				Enc:          jwe.A128GCM,
			}, &wallet.ResponseEncryption{Enc: jwe.A128GCM})
			if err != nil {
				t.Fatalf("call: %v", err)
			}
			if len(result.Credentials) != 1 || result.Credentials[0].Credential != "c1" {
				t.Errorf("Credentials = %v", result.Credentials)
			}
		})
	}
}

// TestResponseEncryptionJWKDeclaresAlg confirms the ephemeral public
// key prepareResponseEncryption sends as "credential_response_encryption.jwk"
// declares its own "alg" — required by §8.2's own "jwk" member
// ("MUST identify the encryption algorithm expected to be used") and
// enforced live by the OIDF conformance suite's own
// invalid_encryption_parameters check ("credential_response_encryption
// must identify the encryption algorithm via 'jwk.alg'"), confirmed
// against a real oid4vci-1_0-wallet-test-credential-issuance module.
// This package only ever performs ECDH-ES Direct Key Agreement
// (internal/jwe's sole supported Alg), so "ECDH-ES" is the only value
// that could ever be correct here.
func TestResponseEncryptionJWKDeclaresAlg(t *testing.T) {
	for name, call := range credentialCallers() {
		t.Run(name, func(t *testing.T) {
			w, err := wallet.New(validConfig(), validDependencies())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			reqRecipientKey := testP256Key(t)
			resource := &fakeProtectedResourceClient{}
			resource.do = simulateIssuerEncryptedExchange(t, resource, reqRecipientKey, []byte(`{"credentials":[{"credential":"c1"}]}`))

			if _, err := call(t, w, resource, &wallet.RequestEncryption{
				RecipientJWK: testEncryptionRecipientJWK(t, "req-1", &reqRecipientKey.PublicKey),
				Enc:          jwe.A128GCM,
			}, &wallet.ResponseEncryption{Enc: jwe.A128GCM}); err != nil {
				t.Fatalf("call: %v", err)
			}

			plaintext, err := jwe.Decrypt(reqRecipientKey, string(resource.lastBody))
			if err != nil {
				t.Fatalf("jwe.Decrypt request: %v", err)
			}
			var parsed struct {
				ResponseEncryption struct {
					JWK struct {
						Alg string `json:"alg"`
					} `json:"jwk"`
				} `json:"credential_response_encryption"`
			}
			if err := json.Unmarshal(plaintext, &parsed); err != nil {
				t.Fatalf("unmarshal decrypted request: %v", err)
			}
			if parsed.ResponseEncryption.JWK.Alg != string(jwe.ECDHES) {
				t.Errorf("credential_response_encryption.jwk.alg = %q, want %q", parsed.ResponseEncryption.JWK.Alg, jwe.ECDHES)
			}
		})
	}
}

// --- CredentialRequest ---

func TestRequestCredential_EncryptsRequestWhenConfigured(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	recipientKey := testP256Key(t)
	resource := &fakeProtectedResourceClient{
		do: func(ctx context.Context, req *http.Request) (*http.Response, error) {
			if req.Header.Get("Content-Type") != "application/jwt" {
				t.Errorf("Content-Type = %q, want application/jwt", req.Header.Get("Content-Type"))
			}
			return jsonResponse([]byte(`{"credentials":[{"credential":"c1"}]}`)), nil
		},
	}

	_, err = w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          "https://issuer.example.com",
		RequestEncryption: &wallet.RequestEncryption{
			RecipientJWK: testEncryptionRecipientJWK(t, "req-1", &recipientKey.PublicKey),
			Enc:          jwe.A128GCM,
		},
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}

	header, err := jwe.DecodeHeader(string(resource.lastBody))
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if header["kid"] != "req-1" {
		t.Errorf("kid = %v, want req-1", header["kid"])
	}
	plaintext, err := jwe.Decrypt(recipientKey, string(resource.lastBody))
	if err != nil {
		t.Fatalf("jwe.Decrypt: %v", err)
	}
	var sentBody struct {
		CredentialConfigurationID string `json:"credential_configuration_id"`
	}
	if err := json.Unmarshal(plaintext, &sentBody); err != nil {
		t.Fatalf("unmarshal decrypted body: %v", err)
	}
	if sentBody.CredentialConfigurationID != "IdentityCredential" {
		t.Errorf("credential_configuration_id = %q", sentBody.CredentialConfigurationID)
	}
}

func TestRequestCredential_RejectsEncryptedResponseWhenNotRequested(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	recipientKey := testP256Key(t)
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			compact, err := jwe.Encrypt(&recipientKey.PublicKey, jwe.A128GCM, []byte(`{"credentials":[]}`), jwe.EncryptOptions{})
			if err != nil {
				t.Fatalf("jwe.Encrypt: %v", err)
			}
			return jweResponse(compact), nil
		},
	}
	_, err = w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          "https://issuer.example.com",
	})
	if err == nil {
		t.Fatalf("RequestCredential = nil error, want error (unexpectedly encrypted response)")
	}
}

func TestRequestCredential_RejectsPlainResponseWhenEncryptionRequested(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	recipientKey := testP256Key(t)
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			return jsonResponse([]byte(`{"credentials":[]}`)), nil
		},
	}
	_, err = w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          "https://issuer.example.com",
		RequestEncryption: &wallet.RequestEncryption{
			RecipientJWK: testEncryptionRecipientJWK(t, "req-1", &recipientKey.PublicKey),
			Enc:          jwe.A128GCM,
		},
		ResponseEncryption: &wallet.ResponseEncryption{Enc: jwe.A128GCM},
	})
	if err == nil {
		t.Fatalf("RequestCredential = nil error, want error (issuer didn't honor requested response encryption)")
	}
}

func TestRequestCredential_RejectsInvalidRecipientJWK(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{do: func(context.Context, *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	}}
	_, err = w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          "https://issuer.example.com",
		RequestEncryption: &wallet.RequestEncryption{
			RecipientJWK: json.RawMessage(`not-json`),
			Enc:          jwe.A128GCM,
		},
	})
	if err == nil {
		t.Fatalf("RequestCredential = nil error, want error")
	}
}

// --- DeferredCredentialRequest ---

func TestRequestDeferredCredential_EncryptsRequestWhenConfigured(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	recipientKey := testP256Key(t)
	resource := &fakeProtectedResourceClient{
		do: func(ctx context.Context, req *http.Request) (*http.Response, error) {
			return jsonResponse([]byte(`{"credentials":[{"credential":"c1"}]}`)), nil
		},
	}

	_, err = w.RequestDeferredCredential(context.Background(), resource, testDeferredCredentialEndpoint(t), wallet.DeferredCredentialRequest{
		TransactionID: "txn-1",
		RequestEncryption: &wallet.RequestEncryption{
			RecipientJWK: testEncryptionRecipientJWK(t, "req-1", &recipientKey.PublicKey),
			Enc:          jwe.A128GCM,
		},
	})
	if err != nil {
		t.Fatalf("RequestDeferredCredential: %v", err)
	}

	plaintext, err := jwe.Decrypt(recipientKey, string(resource.lastBody))
	if err != nil {
		t.Fatalf("jwe.Decrypt: %v", err)
	}
	var sentBody struct {
		TransactionID string `json:"transaction_id"`
	}
	if err := json.Unmarshal(plaintext, &sentBody); err != nil {
		t.Fatalf("unmarshal decrypted body: %v", err)
	}
	if sentBody.TransactionID != "txn-1" {
		t.Errorf("transaction_id = %q, want txn-1", sentBody.TransactionID)
	}
}
