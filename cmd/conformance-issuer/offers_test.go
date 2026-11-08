package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// offersTestEnv is a running issuer with Config.Offers set: its public
// endpoints and its offer-minting handler, each on its own listener.
type offersTestEnv struct {
	client                 *http.Client
	cfg                    Config
	attesterKey, clientKey *ecdsa.PrivateKey
	offersURL              string
}

// startOffersTestServer is startTestIssuerServer for a cfg with Offers
// set, also serving the offers handler newServers returns.
func startOffersTestServer(t *testing.T, change func(*Config)) offersTestEnv {
	t.Helper()
	cfg := baseTestConfig(t)
	cfg.Offers = &OffersConfig{ListenAddr: "127.0.0.1:0"}
	if change != nil {
		change(&cfg)
	}
	attesterKey, clientKey := newKeyPair(t)
	cfg.Client.AttesterJWKS = mustJWKSet(t, &attesterKey.PublicKey)
	cfg.DefaultSubject = "offers-test-subject"

	ts := httptest.NewUnstartedServer(nil)
	cfg.Issuer = "https://" + ts.Listener.Addr().String()
	built, err := newServers(cfg)
	if err != nil {
		t.Fatalf("newServers: %v", err)
	}
	if built.offers == nil {
		t.Fatal("newServers returned no offers handler with Config.Offers set")
	}
	ts.Config.Handler = built.public
	tlsCert, err := cfg.tlsCertificate()
	if err != nil {
		t.Fatal(err)
	}
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	offers := httptest.NewServer(built.offers)
	t.Cleanup(offers.Close)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test-only, talks to this test's own throwaway TLS listener
	return offersTestEnv{client: client, cfg: cfg, attesterKey: attesterKey, clientKey: clientKey, offersURL: offers.URL + "/offers"}
}

func newKeyPair(t *testing.T) (a, b *ecdsa.PrivateKey) {
	t.Helper()
	var err error
	if a, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if b, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func mustJWKSet(t *testing.T, pub *ecdsa.PublicKey) json.RawMessage {
	t.Helper()
	raw, err := conformancecert.JWKSet(pub, "attester-1")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func keyAttestationConfig(t *testing.T, pub *ecdsa.PublicKey, jwtProofRequiresIt bool) *conformanceconfig.KeyAttestationConfig {
	t.Helper()
	trusted, err := jwk.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(trusted)
	if err != nil {
		t.Fatal(err)
	}
	return &conformanceconfig.KeyAttestationConfig{TrustedJWK: raw, JWTProofRequiresKeyAttestation: jwtProofRequiresIt}
}

// mint POSTs req to the offers endpoint and returns the status and body.
func (e offersTestEnv) mint(t *testing.T, req string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(e.offersURL, "application/json", strings.NewReader(req)) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// offer mints an offer and returns the Credential Offer it carries,
// resolving a by-reference one at the Credential Offer Endpoint.
func (e offersTestEnv) offer(t *testing.T, req string) (oid4vci.CredentialOffer, offerResponse) {
	t.Helper()
	status, body := e.mint(t, req)
	if status != http.StatusOK {
		t.Fatalf("POST /offers: %d %s", status, body)
	}
	var resp offerResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(resp.URI)
	if err != nil || u.Scheme != "openid-credential-offer" {
		t.Fatalf("offer URI %q isn't an openid-credential-offer:// link", resp.URI)
	}
	raw := u.Query().Get("credential_offer")
	if ref := u.Query().Get("credential_offer_uri"); ref != "" {
		if !strings.HasPrefix(ref, e.cfg.Issuer+credentialOfferPath+"/") {
			t.Fatalf("credential_offer_uri %q isn't at the Credential Offer Endpoint", ref)
		}
		r, err := e.client.Get(ref) //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if r.StatusCode != http.StatusOK || r.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("GET %s: %d (Cache-Control %q) %s", ref, r.StatusCode, r.Header.Get("Cache-Control"), b)
		}
		raw = string(b)
	}
	var offer oid4vci.CredentialOffer
	if err := json.Unmarshal([]byte(raw), &offer); err != nil {
		t.Fatalf("offer %q: %v", raw, err)
	}
	return offer, resp
}

// preAuthorizedTokenRequest is a pre-authorized code Token Request,
// attested and DPoP-bound, with extra form parameters.
func (e offersTestEnv) preAuthorizedTokenRequest(t *testing.T, code string, extra url.Values, attested bool) *http.Request {
	t.Helper()
	now := time.Now()
	tokenURL := e.cfg.Issuer + "/token"
	form := url.Values{"grant_type": {preAuthorizedCodeGrantType}, "pre-authorized_code": {code}, "client_id": {e.cfg.Client.ID}}
	for k, v := range extra {
		form[k] = v
	}
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode())) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dpop, err := buildDPoPProof(e.clientKey, http.MethodPost, tokenURL, randomHex(t, 16), "", now)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("DPoP", dpop)
	if attested {
		for k, v := range clientAttestationHeaders(t, e.attesterKey, "attester-1", e.cfg.Client, e.clientKey, e.cfg.Issuer, now) {
			req.Header[k] = v
		}
	}
	return req
}

// do sends req and returns the status and decoded JSON body.
func (e offersTestEnv) do(t *testing.T, req *http.Request) (int, map[string]any) {
	t.Helper()
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	return resp.StatusCode, body
}

// TestPreAuthorizedCodeFlow drives an offer minted with a tx_code, by
// reference, through the attested, DPoP-bound pre-authorized code
// Token Request to a Credential, with the refusals around it: a wrong
// tx_code (which leaves the code redeemable), an unattested request,
// and the code redeemed twice.
func TestPreAuthorizedCodeFlow(t *testing.T) {
	e := startOffersTestServer(t, nil)
	offer, _ := e.offer(t, `{"grant":"pre-authorized_code","credential_configuration_ids":["`+e.cfg.CredentialConfigurationID+`"],"tx_code":"493817","by_reference":true}`)
	grant := offer.Grants.PreAuthorizedCode
	if grant == nil || grant.TxCode == nil || grant.TxCode.Length != 6 || grant.TxCode.InputMode != "numeric" {
		t.Fatalf("offer grants = %+v, want a pre-authorized code with a 6-digit numeric tx_code", offer.Grants)
	}

	if status, body := e.do(t, e.preAuthorizedTokenRequest(t, grant.PreAuthorizedCode, url.Values{"tx_code": {"000000"}}, true)); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("wrong tx_code: %d %v, want 400 invalid_grant", status, body)
	}
	if status, body := e.do(t, e.preAuthorizedTokenRequest(t, grant.PreAuthorizedCode, url.Values{"tx_code": {"493817"}}, false)); status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("no Wallet Attestation: %d %v, want 401 invalid_client", status, body)
	}
	status, token := e.do(t, e.preAuthorizedTokenRequest(t, grant.PreAuthorizedCode, url.Values{"tx_code": {"493817"}}, true))
	if status != http.StatusOK || token["token_type"] != "DPoP" {
		t.Fatalf("token: %d %v, want 200 with a DPoP token", status, token)
	}
	if status, body := e.do(t, e.preAuthorizedTokenRequest(t, grant.PreAuthorizedCode, url.Values{"tx_code": {"493817"}}, true)); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("code redeemed twice: %d %v, want 400 invalid_grant", status, body)
	}

	accessToken, _ := token["access_token"].(string)
	now := time.Now()
	nonceResp := doJSON(t, e.client, mustRequest(t, http.MethodPost, e.cfg.Issuer+"/nonce"))
	holderKey, _ := newKeyPair(t)
	proof, err := buildCredentialProofJWT(holderKey, e.cfg.Client.ID, e.cfg.Issuer, nonceResp["c_nonce"].(string), now)
	if err != nil {
		t.Fatal(err)
	}
	cred := postCredentialRequest(t, e.client, e.cfg, e.clientKey, accessToken, now, map[string]any{
		"credential_configuration_id": e.cfg.CredentialConfigurationID, "proofs": map[string][]string{"jwt": {proof}},
	})
	if creds, _ := cred["credentials"].([]any); len(creds) != 1 {
		t.Fatalf("credential response = %v, want one credential", cred)
	}
}

func mustRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, http.NoBody) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// TestPreAuthorizedCode_AuthorizationDetails covers both ways a
// pre-authorized code's token carries credential_identifiers (§6.2): an
// offer minted with them, and a Token Request naming the configuration
// in authorization_details (§6.1.1).
func TestPreAuthorizedCode_AuthorizationDetails(t *testing.T) {
	e := startOffersTestServer(t, nil)
	id := e.cfg.CredentialConfigurationID
	for name, tc := range map[string]struct {
		offer string
		extra url.Values
	}{
		"minted with the offer": {offer: `{"grant":"pre-authorized_code","credential_configuration_ids":["` + id + `"],"credential_identifiers":true}`},
		"requested at the Token Endpoint": {
			offer: `{"grant":"pre-authorized_code","credential_configuration_ids":["` + id + `"]}`,
			extra: url.Values{"authorization_details": {`[{"type":"openid_credential","credential_configuration_id":"` + id + `"}]`}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			offer, _ := e.offer(t, tc.offer)
			if offer.Grants.PreAuthorizedCode.TxCode != nil {
				t.Errorf("an offer minted without a tx_code asks for one: %+v", offer.Grants.PreAuthorizedCode.TxCode)
			}
			status, token := e.do(t, e.preAuthorizedTokenRequest(t, offer.Grants.PreAuthorizedCode.PreAuthorizedCode, tc.extra, true))
			details, _ := token["authorization_details"].([]any)
			if status != http.StatusOK || len(details) != 1 {
				t.Fatalf("token: %d %v, want 200 with one authorization_details entry", status, token)
			}
			d, _ := details[0].(map[string]any)
			if ids, _ := d["credential_identifiers"].([]any); d["credential_configuration_id"] != id || len(ids) != 1 {
				t.Fatalf("authorization_details[0] = %v, want %s with one credential_identifier", d, id)
			}
		})
	}
	// Malformed authorization_details are refused, and leave the code
	// redeemable.
	offer, _ := e.offer(t, `{"grant":"pre-authorized_code","credential_configuration_ids":["`+id+`"]}`)
	code := offer.Grants.PreAuthorizedCode.PreAuthorizedCode
	if status, body := e.do(t, e.preAuthorizedTokenRequest(t, code, url.Values{"authorization_details": {"%5B%5D"}}, true)); status != http.StatusBadRequest || body["error"] != "invalid_authorization_details" {
		t.Fatalf("malformed authorization_details: %d %v, want 400 invalid_authorization_details", status, body)
	}
	if status, body := e.do(t, e.preAuthorizedTokenRequest(t, code, nil, true)); status != http.StatusOK {
		t.Fatalf("the code after a refused request: %d %v, want 200", status, body)
	}
}

// TestOffers_AuthorizationCodeOffer covers an authorization code offer:
// by value, carrying the issuer_state it returns.
func TestOffers_AuthorizationCodeOffer(t *testing.T) {
	e := startOffersTestServer(t, nil)
	offer, resp := e.offer(t, `{"grant":"authorization_code","credential_configuration_ids":["`+e.cfg.CredentialConfigurationID+`"]}`)
	if offer.Grants.AuthorizationCode == nil || resp.IssuerState == "" || offer.Grants.AuthorizationCode.IssuerState != resp.IssuerState {
		t.Fatalf("offer = %+v, response = %+v: want an authorization code grant with the returned issuer_state", offer, resp)
	}
	if offer.CredentialIssuer != e.cfg.Issuer || offer.Grants.PreAuthorizedCode != nil {
		t.Fatalf("offer = %+v", offer)
	}
}

// TestOffers_RefusesMalformedRequests covers POST /offers' refusals.
func TestOffers_RefusesMalformedRequests(t *testing.T) {
	e := startOffersTestServer(t, nil)
	id := e.cfg.CredentialConfigurationID
	for name, req := range map[string]string{
		"not JSON":                         `{`,
		"unknown member":                   `{"grant":"pre-authorized_code","credential_configuration_ids":["` + id + `"],"other":1}`,
		"no configurations":                `{"grant":"pre-authorized_code"}`,
		"unknown configuration":            `{"grant":"pre-authorized_code","credential_configuration_ids":["nope"]}`,
		"unknown grant":                    `{"grant":"client_credentials","credential_configuration_ids":["` + id + `"]}`,
		"tx_code on an authorization code": `{"grant":"authorization_code","credential_configuration_ids":["` + id + `"],"tx_code":"1234"}`,
		"oversized":                        `{"grant":"pre-authorized_code","credential_configuration_ids":["` + strings.Repeat("x", maxOfferRequestBytes) + `"]}`,
	} {
		if status, body := e.mint(t, req); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", name, status, body)
		}
	}
	resp, err := http.Get(e.offersURL) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /offers: %d, want 405", resp.StatusCode)
	}
	r, err := e.client.Get(e.cfg.Issuer + credentialOfferPath + "/unknown") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown offer reference: %d, want 404", r.StatusCode)
	}
}

// TestTokenEndpoint_PreAuthorizedCodeNeedsOffers covers the grant
// being refused, and unadvertised, without Config.Offers.
func TestTokenEndpoint_PreAuthorizedCodeNeedsOffers(t *testing.T) {
	client, cfg, attesterKey, clientKey := setupFullFlowTest(t, "no-offers-client", "no-offers-subject")
	e := offersTestEnv{client: client, cfg: cfg, attesterKey: attesterKey, clientKey: clientKey}
	if status, body := e.do(t, e.preAuthorizedTokenRequest(t, "code", nil, true)); status != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
		t.Fatalf("pre-authorized code without offers: %d %v, want 400 unsupported_grant_type", status, body)
	}
	md := getJSON(t, client, cfg.Issuer+"/.well-known/oauth-authorization-server")
	grants, _ := md["grant_types_supported"].([]any)
	if containsAny(grants, preAuthorizedCodeGrantType) {
		t.Errorf("grant_types_supported = %v lists the pre-authorized code grant without offers", grants)
	}
	if r, err := client.Get(cfg.Issuer + credentialOfferPath + "/x"); err == nil { //nolint:noctx // test
		_ = r.Body.Close()
		if r.StatusCode != http.StatusNotFound && r.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Credential Offer Endpoint without offers: %d", r.StatusCode)
		}
	}
}

// TestOffersServer covers the offers listener's server: the handler,
// on the configured address, with a header timeout.
func TestOffersServer(t *testing.T) {
	h := http.NewServeMux()
	srv := offersServer("127.0.0.1:18447", h)
	if srv.Addr != "127.0.0.1:18447" || srv.Handler != h || srv.ReadHeaderTimeout <= 0 || srv.TLSConfig != nil {
		t.Errorf("offersServer = %+v", srv)
	}
}

// TestValidateOffers covers the offers listener's loopback-only rule.
func TestValidateOffers(t *testing.T) {
	if err := validateOffers(nil); err != nil {
		t.Errorf("nil: %v", err)
	}
	for _, ok := range []string{"127.0.0.1:18447", "[::1]:0"} {
		if err := validateOffers(&OffersConfig{ListenAddr: ok}); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:18447", ":18447", "localhost:18447", "192.0.2.1:1", "127.0.0.1"} {
		if err := validateOffers(&OffersConfig{ListenAddr: bad}); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	cfg := baseTestConfig(t)
	cfg.Offers = &OffersConfig{ListenAddr: "0.0.0.0:1"}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/config.json"
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Errorf("loadConfig with a non-loopback offers listener: %v", err)
	}
}

// TestAuthorizationDetailsAtPAR covers Config.AuthorizationDetails: an
// authorization code requested by openid_credential
// authorization_details rather than scope, whose token grants a
// credential_identifier the consent minted, and the Credential Request
// naming it.
func TestAuthorizationDetailsAtPAR(t *testing.T) {
	e := startOffersTestServer(t, func(c *Config) { c.AuthorizationDetails = true })
	now := time.Now()
	verifier, challenge := pkceChallenge(t)
	parURL := e.cfg.Issuer + "/par"
	form := url.Values{
		"response_type": {"code"}, "client_id": {e.cfg.Client.ID}, "redirect_uri": {e.cfg.Client.RedirectURIs[0]},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"authorization_details": {`[{"type":"openid_credential","credential_configuration_id":"` + e.cfg.CredentialConfigurationID + `"}]`},
	}
	par := e.formRequest(t, parURL, form, now)
	parResp := doJSON(t, e.client, par)
	requestURI, _ := parResp["request_uri"].(string)

	authorizeURL := e.cfg.Issuer + "/authorize?" + url.Values{"client_id": {e.cfg.Client.ID}, "request_uri": {requestURI}}.Encode()
	callback := driveConsentToCallback(t, e.client, e.cfg.Issuer, authorizeURL, e.cfg.DefaultSubject, "")
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatalf("no code: %s", callback)
	}
	token := doJSON(t, e.client, e.formRequest(t, e.cfg.Issuer+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {e.cfg.Client.RedirectURIs[0]},
		"code_verifier": {verifier}, "client_id": {e.cfg.Client.ID},
	}, now))
	details, _ := token["authorization_details"].([]any)
	if len(details) != 1 {
		t.Fatalf("token response = %v, want one authorization_details entry", token)
	}
	d, _ := details[0].(map[string]any)
	ids, _ := d["credential_identifiers"].([]any)
	if len(ids) != 1 {
		t.Fatalf("authorization_details[0] = %v, want one credential_identifier", d)
	}
	nonceResp := doJSON(t, e.client, mustRequest(t, http.MethodPost, e.cfg.Issuer+"/nonce"))
	holderKey, _ := newKeyPair(t)
	proof, err := buildCredentialProofJWT(holderKey, e.cfg.Client.ID, e.cfg.Issuer, nonceResp["c_nonce"].(string), now)
	if err != nil {
		t.Fatal(err)
	}
	accessToken, _ := token["access_token"].(string)
	cred := postCredentialRequest(t, e.client, e.cfg, e.clientKey, accessToken, now, map[string]any{
		"credential_identifier": ids[0], "proofs": map[string][]string{"jwt": {proof}},
	})
	if creds, _ := cred["credentials"].([]any); len(creds) != 1 {
		t.Fatalf("credential response = %v, want one credential", cred)
	}
}

// formRequest is an attested, DPoP-bound form POST to endpoint.
func (e offersTestEnv) formRequest(t *testing.T, endpoint string, form url.Values, now time.Time) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode())) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dpop, err := buildDPoPProof(e.clientKey, http.MethodPost, endpoint, randomHex(t, 16), "", now)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("DPoP", dpop)
	for k, v := range clientAttestationHeaders(t, e.attesterKey, "attester-1", e.cfg.Client, e.clientKey, e.cfg.Issuer, now) {
		req.Header[k] = v
	}
	return req
}

// TestDPoPNonces covers Config.DPoPNonces: PAR and the Credential
// Endpoint each challenge a DPoP proof without their nonce.
func TestDPoPNonces(t *testing.T) {
	e := startOffersTestServer(t, func(c *Config) { c.DPoPNonces = true })
	now := time.Now()
	_, challenge := pkceChallenge(t)
	par := e.formRequest(t, e.cfg.Issuer+"/par", url.Values{
		"response_type": {"code"}, "client_id": {e.cfg.Client.ID}, "redirect_uri": {e.cfg.Client.RedirectURIs[0]},
		"scope": {e.cfg.Scope}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}, now)
	resp, err := e.client.Do(par)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !bytes.Contains(body, []byte("use_dpop_nonce")) || resp.Header.Get("DPoP-Nonce") == "" {
		t.Fatalf("PAR without a nonce: %d %s (DPoP-Nonce %q), want a use_dpop_nonce challenge", resp.StatusCode, body, resp.Header.Get("DPoP-Nonce"))
	}

	// The pre-authorized code's Token Request: challenged, then
	// answered once it carries the nonce.
	offer, _ := e.offer(t, `{"grant":"pre-authorized_code","credential_configuration_ids":["`+e.cfg.CredentialConfigurationID+`"]}`)
	code := offer.Grants.PreAuthorizedCode.PreAuthorizedCode
	tokenReq := e.preAuthorizedTokenRequest(t, code, nil, true)
	tokenResp, err := e.client.Do(tokenReq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(tokenResp.Body)
	_ = tokenResp.Body.Close()
	nonce := tokenResp.Header.Get("DPoP-Nonce")
	if tokenResp.StatusCode != http.StatusBadRequest || !bytes.Contains(body, []byte("use_dpop_nonce")) || nonce == "" {
		t.Fatalf("token request without a nonce: %d %s, want a use_dpop_nonce challenge", tokenResp.StatusCode, body)
	}
	tokenReq = e.preAuthorizedTokenRequest(t, code, nil, true)
	proof, err := buildDPoPProofWithNonce(e.clientKey, e.cfg.Issuer+"/token", nonce, now)
	if err != nil {
		t.Fatal(err)
	}
	tokenReq.Header.Set("DPoP", proof)
	status, token := e.do(t, tokenReq)
	if status != http.StatusOK {
		t.Fatalf("token request with the nonce: %d %v", status, token)
	}

	accessToken, _ := token["access_token"].(string)
	cred, err := e.client.Do(buildCredentialRequest(t, e.cfg, e.clientKey, accessToken, "application/json", []byte(`{}`), now))
	if err != nil {
		t.Fatal(err)
	}
	_ = cred.Body.Close()
	if cred.StatusCode != http.StatusUnauthorized || !strings.Contains(cred.Header.Get("WWW-Authenticate"), "use_dpop_nonce") || cred.Header.Get("DPoP-Nonce") == "" {
		t.Fatalf("Credential Request without a nonce: %d (WWW-Authenticate %q), want a use_dpop_nonce challenge", cred.StatusCode, cred.Header.Get("WWW-Authenticate"))
	}
}

// buildDPoPProofWithNonce is buildDPoPProof for a POST to htu carrying
// the server's DPoP nonce (RFC 9449 §8).
func buildDPoPProofWithNonce(key *ecdsa.PrivateKey, htu, nonce string, now time.Time) (string, error) {
	pub, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{"jti": rand.Text(), "htm": http.MethodPost, "htu": htu, "iat": now.Unix(), "nonce": nonce})
	if err != nil {
		return "", err
	}
	return jose.Sign(jose.ES256, key, map[string]any{"typ": dpopProofTypHeader, "jwk": pub}, payload)
}

// TestKeyAttestation_JWTProofRequiresIt covers
// KeyAttestationConfig.JWTProofRequiresKeyAttestation: the jwt proof
// type advertises key_attestations_required.
func TestKeyAttestation_JWTProofRequiresIt(t *testing.T) {
	trusted, _ := newKeyPair(t)
	for _, required := range []bool{false, true} {
		e := startOffersTestServer(t, func(c *Config) {
			c.KeyAttestation = keyAttestationConfig(t, &trusted.PublicKey, required)
		})
		md := getJSON(t, e.client, e.cfg.Issuer+"/.well-known/openid-credential-issuer")
		configs, _ := md["credential_configurations_supported"].(map[string]any)
		c, _ := configs[e.cfg.CredentialConfigurationID].(map[string]any)
		proofTypes, _ := c["proof_types_supported"].(map[string]any)
		jwtProof, _ := proofTypes["jwt"].(map[string]any)
		if _, has := jwtProof["key_attestations_required"]; has != required {
			t.Errorf("required=%v: jwt proof type = %v", required, jwtProof)
		}
		if _, has := proofTypes["attestation"]; !has {
			t.Errorf("required=%v: no attestation proof type: %v", required, proofTypes)
		}
	}
}
