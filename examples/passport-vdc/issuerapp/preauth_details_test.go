package issuerapp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// withAuthorizationDetails is a wallet transport whose pre-authorized
// code Token Requests also carry details, as OpenID4VCI §6.1.1 lets a
// wallet send them, and which keeps the last successful Token Response.
type withAuthorizationDetails struct {
	base    http.RoundTripper
	details string

	mu       sync.Mutex
	response []byte
}

func (w *withAuthorizationDetails) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/token") {
		return w.base.RoundTrip(r)
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	if form.Get("grant_type") == "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
		form.Set("authorization_details", w.details)
		body = []byte(form.Encode())
	}
	r = r.Clone(r.Context())
	r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	resp, err := w.base.RoundTrip(r)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	respBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	w.response = respBody
	w.mu.Unlock()
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	return resp, nil
}

// detailsWallet is env's wallet configuration, its pre-authorized code
// Token Requests asking for configIDs in authorization_details.
func detailsWallet(t *testing.T, env *demotest.Env, configIDs ...string) (walletapp.Config, *withAuthorizationDetails) {
	t.Helper()
	details := make([]oid4vci.AuthorizationDetail, len(configIDs))
	for i, id := range configIDs {
		details[i] = oid4vci.AuthorizationDetail{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: id}
	}
	return detailsWalletAsking(t, env, details)
}

// detailsWalletAsking is env's wallet configuration, its pre-authorized
// code Token Requests carrying details.
func detailsWalletAsking(t *testing.T, env *demotest.Env, details []oid4vci.AuthorizationDetail) (walletapp.Config, *withAuthorizationDetails) {
	t.Helper()
	raw, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	transport := &withAuthorizationDetails{base: env.HTTP.Transport, details: string(raw)}
	cfg := env.WalletConfig()
	httpClient := *env.HTTP
	httpClient.Transport = transport
	cfg.HTTP = &httpClient
	return cfg, transport
}

// TestPreAuthorized_AcceptsAuthorizationDetails: a pre-authorized code
// Token Request naming configurations in authorization_details gets an
// access token, and a Token Response with a credential_identifier for
// each of them (§6.2), rather than spending the code on an error; the
// wallet then requests, and gets, each credential by its
// credential_identifier, as §8.2 requires once the token has them (the
// issuer refuses a credential_configuration_id then).
func TestPreAuthorized_AcceptsAuthorizationDetails(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreatePreAuthorizedTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if md := get(t, env, "/.well-known/oauth-authorization-server"); !strings.Contains(md, `"authorization_details_types_supported":["openid_credential"]`) {
		t.Error("the Authorization Server's metadata doesn't list openid_credential authorization_details")
	}
	cfg, transport := detailsWallet(t, env, issuerapp.MdocConfigurationID, issuerapp.SDJWTConfigurationID)
	received, err := walletapp.Receive(ctx, cfg, offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil || len(received) != 2 {
		t.Errorf("Receive = %d credentials, %v; want both", len(received), err)
	}
	if got := statusFormats(env.Issuer.IssuedStatuses()); !got[mdoc.CredentialFormat] || !got[sdjwtvc.CredentialFormat] {
		t.Errorf("status entries for %v, want one for each format", got)
	}

	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.response == nil {
		t.Fatal("the Token Request with authorization_details got no token")
	}
	var token struct {
		AuthorizationDetails []oid4vci.AuthorizationDetail `json:"authorization_details"`
	}
	if err := json.Unmarshal(transport.response, &token); err != nil {
		t.Fatal(err)
	}
	identified := map[string]bool{}
	for _, d := range token.AuthorizationDetails {
		identified[d.CredentialConfigurationID] = len(d.CredentialIdentifiers) > 0
	}
	if !identified[issuerapp.MdocConfigurationID] || !identified[issuerapp.SDJWTConfigurationID] {
		t.Errorf("Token Response authorization_details = %+v, want a credential_identifier for each configuration", token.AuthorizationDetails)
	}
}

// TestPreAuthorized_AcceptsAuthorizationDetailsWithClaims: a
// pre-authorized code Token Request whose authorization_details name
// claims (§5.1.1), with a display, gets a token: the Authorization
// Server's registry is deep enough for what RedeemPreAuthorizedCode
// accepts and mints, so it doesn't refuse them once the code is spent.
func TestPreAuthorized_AcceptsAuthorizationDetailsWithClaims(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreatePreAuthorizedTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	cfg, transport := detailsWalletAsking(t, env, []oid4vci.AuthorizationDetail{{
		Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: issuerapp.SDJWTConfigurationID,
		Claims: []oid4vci.ClaimsDescription{{Path: []any{"given_name"}, Display: []oid4vci.ClaimDisplay{{Name: "Given name", Locale: "en"}}}},
	}})
	if _, err := walletapp.Receive(ctx, cfg, offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}); err != nil {
		t.Errorf("Receive: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	var token struct {
		AuthorizationDetails []oid4vci.AuthorizationDetail `json:"authorization_details"`
	}
	if transport.response == nil {
		t.Fatal("the Token Request with claims got no token")
	}
	if err := json.Unmarshal(transport.response, &token); err != nil {
		t.Fatal(err)
	}
	if len(token.AuthorizationDetails) != 1 || len(token.AuthorizationDetails[0].Claims) != 1 {
		t.Errorf("Token Response authorization_details = %+v, want the one asked for, with its claim", token.AuthorizationDetails)
	}
}

// statusFormats is the formats statuses were allocated for.
func statusFormats(statuses []issuerapp.IssuedStatus) map[string]bool {
	out := map[string]bool{}
	for _, s := range statuses {
		out[s.Format] = true
	}
	return out
}

// TestPreAuthorized_ReviewByCredentialIdentifier: a passport uploaded
// for review, its credentials requested by credential_identifier, is
// deferred into a review of each requested configuration.
func TestPreAuthorized_ReviewByCredentialIdentifier(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateOffer(ctx, demotest.SyntheticEvidence(), issuerapp.OfferOptions{PreAuthorized: true, Review: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := detailsWallet(t, env, issuerapp.MdocConfigurationID, issuerapp.SDJWTConfigurationID)
	received, pending, err := walletapp.ReceiveDeferrable(ctx, cfg, offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil || len(received) != 0 || len(pending) != 2 {
		t.Fatalf("ReceiveDeferrable = %d received, %d pending, %v; want both deferred", len(received), len(pending), err)
	}
	formats := map[string]bool{}
	for _, rv := range env.Issuer.Reviews() {
		formats[rv.Format] = true
	}
	if !formats[mdoc.CredentialFormat] || !formats[sdjwtvc.CredentialFormat] {
		t.Errorf("reviews for %v, want one for each format", formats)
	}
}
