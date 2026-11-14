//go:build conformance_production

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// productionTestConfig is baseTestConfig under Config.Production, its
// key attestations trusted by kaCAPEM.
func productionTestConfig(t *testing.T, kaCAPEM string) Config {
	t.Helper()
	cfg := baseTestConfig(t)
	signingKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	sealingKey := make([]byte, 32)
	if _, err := rand.Read(sealingKey); err != nil {
		t.Fatal(err)
	}
	cfg.Production = &ProductionConfig{
		DatabasePath:             filepath.Join(t.TempDir(), "issuer.sqlite"),
		SealingKey:               base64.StdEncoding.EncodeToString(sealingKey),
		AccessTokenSigningKeyPEM: signingKeyPEM,
	}
	cfg.KeyAttestation = &conformanceconfig.KeyAttestationConfig{TrustAnchorPEM: kaCAPEM}
	return cfg
}

// buildKeyAttestationJWT builds a Key Attestation JWT (OpenID4VCI 1.0
// Appendix D.1) attesting holderKey, signed by kaKey with its
// certificate kaLeafPEM in x5c, as the OIDF suite's emulated Wallet
// does: no iss and no status claim.
func buildKeyAttestationJWT(t *testing.T, kaKey *ecdsa.PrivateKey, kaLeafPEM string, holderKey *ecdsa.PrivateKey, nonce string, now time.Time) string {
	t.Helper()
	leaf, err := conformancecert.ParseCertificatePEM(kaLeafPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.Marshal(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"attested_keys": []any{pub}, "nonce": nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.Sign(jose.ES256, kaKey, map[string]any{
		"typ": "key-attestation+jwt", "x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)},
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// buildAttestedProofJWT is buildCredentialProofJWT with keyAttestation
// in its key_attestation header.
func buildAttestedProofJWT(t *testing.T, holderKey *ecdsa.PrivateKey, clientID, audience, nonce, keyAttestation string, now time.Time) string {
	t.Helper()
	pub, err := jwk.Marshal(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"iss": clientID, "aud": audience, "iat": now.Unix(), "nonce": nonce})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.Sign(jose.ES256, holderKey, map[string]any{
		"typ": credentialProofTypHeader, "jwk": pub, "key_attestation": keyAttestation,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// The production setup builds — server.New and issuer.New accept it
// under production assurance — offers only jwt proofs requiring a key
// attestation, and issues a Credential for a proof carrying one, from
// a Wallet Provider its trust anchor certifies, but not for a proof
// without one.
func TestProductionSetup_IssuesForKeyAttestedJWTProof(t *testing.T) {
	kaKey, _, kaLeafPEM, kaCAPEM, err := conformancecert.GenerateSignerAndCert("production-test-key-attestation", "production-test-key-attestation-ca")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	client, cfg, attesterKey, clientKey := setupFullFlowTestWithConfig(t, productionTestConfig(t, kaCAPEM), "production-client", "production-subject")

	md := getJSON(t, client, cfg.Issuer+"/.well-known/openid-credential-issuer")
	configs, _ := md["credential_configurations_supported"].(map[string]any)
	sdjwt, _ := configs[cfg.CredentialConfigurationID].(map[string]any)
	proofTypes, _ := sdjwt["proof_types_supported"].(map[string]any)
	if _, ok := proofTypes["attestation"]; ok || len(proofTypes) != 1 {
		t.Fatalf("proof_types_supported = %v, want jwt alone", proofTypes)
	}
	if jwtProof, _ := proofTypes["jwt"].(map[string]any); jwtProof["key_attestations_required"] == nil {
		t.Fatalf("jwt proof type = %v, want key_attestations_required", jwtProof)
	}

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	accessToken, cNonce := performAuthFlowThroughNonce(t, client, cfg, attesterKey, clientKey, now)

	// Without a key attestation: refused.
	bare, err := buildCredentialProofJWT(holderKey, cfg.Client.ID, cfg.Issuer, cNonce, now)
	if err != nil {
		t.Fatal(err)
	}
	status, body := postCredential(t, client, cfg, clientKey, accessToken, now, bare)
	if status != http.StatusBadRequest || !strings.Contains(body, "invalid_proof") {
		t.Fatalf("proof without key_attestation: status %d, body %s; want 400 invalid_proof", status, body)
	}

	// With one, under a fresh c_nonce: the refused proof spent the last.
	nonceReq, err := http.NewRequest(http.MethodPost, cfg.Issuer+"/nonce", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	cNonce, _ = doJSON(t, client, nonceReq)["c_nonce"].(string)
	keyAttestation := buildKeyAttestationJWT(t, kaKey, kaLeafPEM, holderKey, cNonce, now)
	attested := buildAttestedProofJWT(t, holderKey, cfg.Client.ID, cfg.Issuer, cNonce, keyAttestation, now)
	status, body = postCredential(t, client, cfg, clientKey, accessToken, now, attested)
	if status != http.StatusOK || !strings.Contains(body, `"credentials"`) {
		t.Fatalf("proof with key_attestation: status %d, body %s; want 200 with credentials", status, body)
	}
}

// Under production an authorization error before the user has
// authenticated is shown on the Authorization Server's own page, not
// redirected to the client's redirect URI, even a registered one
// (SPECIFICATIONS.md's "Known strictness"): what turns the OIDF suite's
// unknown-request_uri modules from PASSED to REVIEW.
func TestProductionSetup_ShowsAuthorizationErrorsLocally(t *testing.T) {
	_, _, _, kaCAPEM, err := conformancecert.GenerateSignerAndCert("production-test-key-attestation", "production-test-key-attestation-ca")
	if err != nil {
		t.Fatal(err)
	}
	client, cfg, _, _ := setupFullFlowTestWithConfig(t, productionTestConfig(t, kaCAPEM), "production-client", "production-subject")
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	authorizeURL := cfg.Issuer + "/authorize?" + url.Values{
		"client_id": {cfg.Client.ID}, "request_uri": {"urn:ietf:params:oauth:request_uri:unknown"},
		"redirect_uri": {cfg.Client.RedirectURIs[0]}, "state": {"s"},
	}.Encode()
	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "" || resp.StatusCode < 400 {
		t.Fatalf("GET /authorize with an unknown request_uri: status %d, Location %q; want an error page", resp.StatusCode, loc)
	}
}

// postCredential sends one Credential Request with proofJWT, returning
// the status and body.
func postCredential(t *testing.T, client *http.Client, cfg Config, clientKey *ecdsa.PrivateKey, accessToken string, now time.Time, proofJWT string) (int, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"credential_configuration_id": cfg.CredentialConfigurationID,
		"proofs":                      map[string][]string{"jwt": {proofJWT}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(buildCredentialRequest(t, cfg, clientKey, accessToken, "application/json", body, now))
	if err != nil {
		t.Fatalf("POST /credential: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(raw)
}

// Under ProductionConfig.AttestationStatusAllowLoopback the production
// setup checks a key attestation's status from a list on loopback, over
// TLS chained to AttestationStatusTLSTrustAnchorsPEM, as an interop
// run's Wallet Provider serves it: issued for an entry VALID, refused
// for one INVALID. issuer.New would refuse that fetcher's checker under
// production; the wrapper keeps the check.
func TestProductionSetup_ChecksKeyAttestationStatusOnLoopback(t *testing.T) {
	kaKey, _, kaLeafPEM, kaCAPEM, err := conformancecert.GenerateSignerAndCert("production-test-key-attestation", "production-test-key-attestation-ca")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := conformancecert.ParseCertificatePEM(kaLeafPEM)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	list, err := statuslist.New(statuslist.Bits1, []uint8{uint8(statuslist.StatusValid), uint8(statuslist.StatusInvalid)}, "")
	if err != nil {
		t.Fatal(err)
	}
	var listURI string
	lists := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		exp := now.Add(time.Hour).Unix()
		token, err := statuslist.IssueTokenX5C(kaKey, oid4vci.ES256,
			statuslist.TokenClaims{Sub: listURI, Iat: now.Unix(), Exp: &exp, StatusList: list}, []*x509.Certificate{leaf})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", statuslist.TokenMediaType)
		_, _ = io.WriteString(w, token)
	}))
	defer lists.Close()
	listURI = lists.URL + "/statuslists/1"

	cfg := productionTestConfig(t, kaCAPEM)
	cfg.Production.AttestationStatusAllowLoopback = true
	cfg.Production.AttestationStatusTLSTrustAnchorsPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: lists.Certificate().Raw}))
	client, cfg, attesterKey, clientKey := setupFullFlowTestWithConfig(t, cfg, "production-client", "production-subject")
	accessToken, cNonce := performAuthFlowThroughNonce(t, client, cfg, attesterKey, clientKey, now)
	nonceReq := func() string {
		req, err := http.NewRequest(http.MethodPost, cfg.Issuer+"/nonce", http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := doJSON(t, client, req)["c_nonce"].(string)
		return n
	}
	for _, c := range []struct {
		idx    int
		status int
		want   string
	}{
		{1, http.StatusBadRequest, "invalid_proof"},
		{0, http.StatusOK, `"credentials"`},
	} {
		holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keyAttestation := keyAttestationWithStatus(t, kaKey, leaf, holderKey, cNonce, now, listURI, c.idx)
		proof := buildAttestedProofJWT(t, holderKey, cfg.Client.ID, cfg.Issuer, cNonce, keyAttestation, now)
		status, body := postCredential(t, client, cfg, clientKey, accessToken, now, proof)
		if status != c.status || !strings.Contains(body, c.want) {
			t.Fatalf("key attestation status entry %d: status %d, body %s; want %d with %s", c.idx, status, body, c.status, c.want)
		}
		cNonce = nonceReq()
	}
}

func TestAttestationStatusFetcher(t *testing.T) {
	f, err := attestationStatusFetcher(ProductionConfig{})
	if err != nil || f.AllowLoopback || f.HTTP != nil || !f.HardenedForProduction() {
		t.Fatalf("default: %+v, %v; want a hardened fetcher on the system roots", f, err)
	}
	if _, err := attestationStatusFetcher(ProductionConfig{AttestationStatusTLSTrustAnchorsPEM: "not PEM"}); err == nil {
		t.Fatal("trust anchors holding no PEM certificate were taken")
	}
}

// keyAttestationWithStatus is buildKeyAttestationJWT with a status
// claim naming entry idx of the list at uri.
func keyAttestationWithStatus(t *testing.T, kaKey *ecdsa.PrivateKey, leaf *x509.Certificate, holderKey *ecdsa.PrivateKey, nonce string, now time.Time, uri string, idx int) string {
	t.Helper()
	pub, err := jwk.Marshal(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"attested_keys": []any{pub}, "nonce": nonce,
		"status": map[string]any{"status_list": map[string]any{"idx": idx, "uri": uri}},
	})
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.Sign(jose.ES256, kaKey, map[string]any{
		"typ": "key-attestation+jwt", "x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)},
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
