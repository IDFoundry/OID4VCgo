package walletflowtest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// An Anonymous issuer's token endpoint takes no client authentication:
// a pre-authorized code redemption that authenticates a client anyway
// is refused with invalid_request before the code is spent, so the
// wallet's own anonymous redemption then succeeds.
func TestAnonymousRefusesClientAuthentication(t *testing.T) {
	env, err := walletflowtest.New(walletflowtest.Options{Anonymous: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	ctx := context.Background()
	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: oid4vci.ES256,
		Fetch: fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 10 * time.Second, AllowLoopbackHTTP: true},
	}, wallet.Dependencies{HTTP: env.HTTP, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	uri, err := env.PreAuthorizedOffer("", walletflowtest.MdocConfigurationID)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := w.ResolveCredentialOffer(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := w.FetchCredentialIssuerMetadata(ctx, offer.CredentialIssuer)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := wallet.PlanPreAuthorizedCode(offer, metadata)
	if err != nil {
		t.Fatal(err)
	}
	asMeta, err := w.FetchAuthorizationServerMetadata(ctx, plan.AuthorizationServer)
	if err != nil {
		t.Fatal(err)
	}

	dpopKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, tc := range map[string]struct{ form, header map[string]string }{
		"client assertion": {form: map[string]string{
			"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": "a.b.c",
		}},
		"client attestation": {header: map[string]string{"OAuth-Client-Attestation": "a.b.c", "OAuth-Client-Attestation-PoP": "d.e.f"}},
	} {
		proof, err := w.GenerateDPoPProof(dpopKey, http.MethodPost, asMeta.TokenEndpoint, "", "")
		if err != nil {
			t.Fatal(err)
		}
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {plan.PreAuthorizedCode}}
		for k, v := range tc.form {
			form.Set(k, v)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, asMeta.TokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", proof)
		for k, v := range tc.header {
			req.Header.Set(k, v)
		}
		resp, err := env.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || body.Error != "invalid_request" {
			t.Errorf("%s: %d %q, want 400 invalid_request", name, resp.StatusCode, body.Error)
		}
	}

	tokenEndpoint, err := fapi.ParseEndpointURL(asMeta.TokenEndpoint, fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.RequestPreAuthorizedCodeToken(ctx, tokenEndpoint, wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: plan.PreAuthorizedCode, DPoPKey: dpopKey,
	}); err != nil {
		t.Fatalf("the refused requests spent the code: %v", err)
	}
}
