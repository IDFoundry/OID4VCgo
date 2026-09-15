package wallet_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/issuer"
	"github.com/idfoundry/oid4vcigo/storage"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// issuerNonceFake plays the role of the network for wallet's own Nonce
// Endpoint call, routing it to a real issuer.Issuer's own RequestNonce
// — no HTTP server, but genuinely the production code on both sides.
type issuerNonceFake struct{ iss *issuer.Issuer }

func (f issuerNonceFake) Do(req *http.Request) (*http.Response, error) {
	result, err := f.iss.RequestNonce(req.Context())
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		CNonce string `json:"c_nonce"`
	}{CNonce: result.CNonce})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     http.Header{"Content-Type": {"application/json"}},
	}, nil
}

// issuerCredentialFake plays the role of a sender-constrained
// Credential Endpoint call, routing it to a real issuer.Issuer's own
// RequestCredential. Sender-constraining itself (DPoP/mTLS) is
// fapigo/client's own job — this fake stands in for it, since proving
// that belongs to fapigo/client's own test suite, not this one; what
// this test proves is that wallet's outbound wire format is exactly
// what issuer's inbound parsing expects, and vice versa for the
// response.
type issuerCredentialFake struct {
	iss    *issuer.Issuer
	auth   issuer.AuthorizedRequest
	claims *sdjwtvc.Claims
}

func (f issuerCredentialFake) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	var wire struct {
		CredentialConfigurationID string              `json:"credential_configuration_id"`
		Proofs                    map[string][]string `json:"proofs"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, err
	}

	result, reqErr := f.iss.RequestCredential(ctx, f.auth, issuer.CredentialRequest{
		CredentialConfigurationID: wire.CredentialConfigurationID,
		Proofs:                    wire.Proofs,
		SDJWTClaims:               f.claims,
	})
	if reqErr != nil {
		var ierr *issuer.Error
		if errors.As(reqErr, &ierr) {
			body, err := json.Marshal(struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}{Error: string(ierr.Code()), ErrorDescription: ierr.PublicDescription()})
			if err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: ierr.HTTPStatus(),
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     http.Header{"Content-Type": {"application/json"}},
			}, nil
		}
		return nil, reqErr
	}

	body, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     http.Header{"Content-Type": {"application/json"}},
	}, nil
}

// TestWalletIssuerRoundTrip drives a full immediate-issuance flow
// end-to-end — wallet requests a nonce, generates a real jwt-type key
// proof, POSTs a real Credential Request, and parses a real Credential
// Response, all verified by a real issuer.Issuer — to keep wallet's
// own wire format from silently drifting out of sync with what issuer
// actually accepts, and vice versa.
func TestWalletIssuerRoundTrip(t *testing.T) {
	issuerURL, err := fapi.ParseIssuerURL("http://localhost", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	credentialEndpoint, err := fapi.ParseEndpointURL("http://localhost/credential", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	nonceEndpoint, err := fapi.ParseEndpointURL("http://localhost/nonce", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}

	issuerSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	const vct = "https://credentials.example.com/identity_credential"

	iss, err := issuer.New(issuer.Config{
		Issuer: issuerURL,
		Endpoints: issuer.Endpoints{
			Credential: credentialEndpoint,
			Nonce:      nonceEndpoint,
		},
		Limits: issuer.Limits{NonceLifetime: time.Minute},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {
				Format:                               sdjwtvc.CredentialFormat,
				Scope:                                "identity_credential",
				VCT:                                  vct,
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
	}, issuer.Dependencies{
		Nonces:      storage.NewNonceStore(),
		Clock:       issuer.ClockFunc(time.Now),
		Random:      rand.Reader,
		SDJWTSigner: &issuer.SDJWTSigner{Signer: issuerSigner, Alg: jose.ES256},
	})
	if err != nil {
		t.Fatalf("issuer.New: %v", err)
	}

	w, err := wallet.New(wallet.Config{
		ProofSigningAlg: jose.ES256,
		Fetch: fapihttp.Config{
			MaxResponseBytes: 1 << 20, RequestTimeout: 5 * time.Second, AllowLoopbackHTTP: true,
		},
	}, wallet.Dependencies{
		HTTP:  issuerNonceFake{iss: iss},
		Clock: wallet.ClockFunc(time.Now),
	})
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}

	nonceResult, err := w.RequestNonce(context.Background(), nonceEndpoint)
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	if nonceResult.CNonce == "" {
		t.Fatalf("CNonce is empty")
	}

	walletKey := testP256Key(t)
	resource := issuerCredentialFake{
		iss:    iss,
		auth:   issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}},
		claims: &sdjwtvc.Claims{VCT: vct},
	}

	result, err := w.RequestCredential(context.Background(), resource, credentialEndpoint, wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{walletKey},
		CredentialIssuer:          issuerURL.String(),
		Nonce:                     nonceResult.CNonce,
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(result.Credentials))
	}

	payload, _, err := sdjwtvc.Verify(result.Credentials[0].Credential, &issuerSigner.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	if payload["vct"] != vct {
		t.Errorf("vct = %v, want %q", payload["vct"], vct)
	}
}
