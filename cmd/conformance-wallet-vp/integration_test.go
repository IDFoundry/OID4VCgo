package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/internal/testcert"
	"github.com/idfoundry/oid4vcigo/verifier"
)

// fixedIssuerKeyResolver always resolves to the one issuer key this
// test signed the fixture credential with — standing in for whatever
// real trust mechanism a deployment would use, the same fake shape
// verifier's own tests use (see verifier/verify_response_test.go's
// fixedSDJWTVCIssuerKeyResolver).
type fixedIssuerKeyResolver struct{ pub crypto.PublicKey }

func (r fixedIssuerKeyResolver) ResolveIssuerKey(context.Context, map[string]any, map[string]any) (crypto.PublicKey, jose.Alg, error) {
	return r.pub, jose.ES256, nil
}

// TestHandleAuthorize_FullRoundTripAgainstARealVerifier is the same
// scenario this binary was manually smoke-tested against
// cmd/conformance-verifier with (see conformance/wallet-vp/README.md):
// a real verifier.Verifier builds and signs an Authorization Request,
// this binary's own handleAuthorize fetches/verifies it, presents its
// fixture credential, and the Verifier cryptographically verifies the
// resulting direct_post.jwt response end to end — not a mock on
// either side.
func TestHandleAuthorize_FullRoundTripAgainstARealVerifier(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate credential issuer key: %v", err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	cfg := Config{
		VCT:    "urn:eudi:pid:1",
		Claims: map[string]string{"given_name": "Jean", "family_name": "Dupont"},
	}
	cred, err := issueFixtureCredential(cfg, issuerKey, holderKey)
	if err != nil {
		t.Fatalf("issueFixtureCredential: %v", err)
	}
	wallet := &server{cred: cred}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate verifier client key: %v", err)
	}
	clientCert := testcert.SelfSigned(t, "conformance-verifier-test", &clientKey.PublicKey, clientKey)

	mux := http.NewServeMux()
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)

	responseURI, err := fapi.ParseEndpointURL(ts.URL + "/response")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	v, err := verifier.New(verifier.Config{
		ClientCertificate:  clientCert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
	}, verifier.Dependencies{Signer: clientKey, Random: rand.Reader})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}

	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{cfg.VCT}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "cred1", Format: "dc+sd-jwt", Meta: meta,
		Claims: []dcql.ClaimsQuery{
			{Path: dcql.Path{dcql.PathKey("given_name")}},
			{Path: dcql.Path{dcql.PathKey("family_name")}},
		},
	}}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	issuerJWK, err := jwk.Marshal(&issuerKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal issuer jwk: %v", err)
	}
	issuerJWKRaw, err := json.Marshal(issuerJWK)
	if err != nil {
		t.Fatalf("marshal issuer jwk: %v", err)
	}
	issuerPub, err := jwk.ParsePublicKey(issuerJWKRaw)
	if err != nil {
		t.Fatalf("parse issuer jwk: %v", err)
	}

	type verifyOutcome struct {
		claims map[string]any
		err    error
	}
	var got verifyOutcome

	mux.HandleFunc("GET /request/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(built.RequestObject))
	})
	mux.HandleFunc("POST /response", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		parsed, err := v.ParseDirectPostJWTResponse(r.FormValue("response"), built.ResponseDecryptionKey)
		if err != nil {
			var respErr *verifier.ResponseError
			if errors.As(err, &respErr) {
				got.err = respErr
			} else {
				got.err = err
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query: query, Response: parsed, ExpectedNonce: built.Nonce,
			IssuerKeys: fixedIssuerKeyResolver{pub: issuerPub},
		})
		if err != nil {
			got.err = err
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(result.Credentials) != 1 {
			got.err = errors.New("verifier returned an unexpected number of credentials")
			http.Error(w, "wrong credential count", http.StatusInternalServerError)
			return
		}
		got.claims = result.Credentials[0].Claims
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"redirect_uri": ts.URL + "/callback"})
	})
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	previousHTTPClient := httpClient
	httpClient = ts.Client() // trust the httptest server's own cert for this binary's outbound calls
	t.Cleanup(func() { httpClient = previousHTTPClient })

	requestURL := ts.URL + "/authorize?" + url.Values{
		"client_id":   {built.ClientID},
		"request_uri": {ts.URL + "/request/1"},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, requestURL, nil)
	rec := httptest.NewRecorder()
	wallet.handleAuthorize(rec, req)

	if rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("handleAuthorize: status %d: %s", rec.Code, body)
	}
	if got.err != nil {
		t.Fatalf("verifier's own VerifyResponse: %v", got.err)
	}
	if got.claims["given_name"] != "Jean" || got.claims["family_name"] != "Dupont" {
		t.Fatalf("disclosed claims = %+v, want given_name=Jean family_name=Dupont", got.claims)
	}
}
