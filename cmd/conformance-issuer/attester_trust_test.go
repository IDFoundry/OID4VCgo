package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// postPARWithAttestation sends a PAR request authenticated by
// attestationJWT (plus a fresh PoP by clientKey) and returns its status.
func postPARWithAttestation(t *testing.T, client *http.Client, cfg Config, cc ConfigClient, clientKey *ecdsa.PrivateKey, attestationJWT string, now time.Time) int {
	t.Helper()
	_, challenge := pkceChallenge(t)
	parURL := cfg.Issuer + "/par"
	dpop, err := buildDPoPProof(clientKey, http.MethodPost, parURL, randomHex(t, 16), "", now)
	if err != nil {
		t.Fatalf("buildDPoPProof: %v", err)
	}
	pop, err := buildClientAttestationPoPJWT(clientKey, cc.ID, cfg.Issuer, randomHex(t, 16), now)
	if err != nil {
		t.Fatalf("buildClientAttestationPoPJWT: %v", err)
	}
	form := url.Values{
		"response_type": {"code"}, "client_id": {cc.ID}, "redirect_uri": {cc.RedirectURIs[0]},
		"scope": {cfg.Scope}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	req, err := http.NewRequest(http.MethodPost, parURL, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new par request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpop)
	req.Header.Set("OAuth-Client-Attestation", attestationJWT)
	req.Header.Set("OAuth-Client-Attestation-PoP", pop)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /par: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// x5cAttestation mints a Client Attestation JWT for cc signed by key,
// carrying certPEM as its x5c chain.
func x5cAttestation(t *testing.T, key *ecdsa.PrivateKey, certPEM string, cc ConfigClient, instanceKey *ecdsa.PublicKey, now time.Time) string {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("certPEM holds no PEM block")
	}
	jwt, err := attestation.IssueWalletAttestation(key, oid4vci.ES256,
		attestation.Header{X5C: []string{base64.StdEncoding.EncodeToString(block.Bytes)}},
		attestation.WalletAttestationClaims{
			Issuer: cc.ExpectedAttesterIssuer, Subject: cc.ID, InstanceKey: instanceKey,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		})
	if err != nil {
		t.Fatalf("IssueWalletAttestation: %v", err)
	}
	return jwt
}

// TestPAR_AttesterTrustAnchors checks a client configured with
// attester_trust_anchors_pem authenticates by the Client Attestation's
// x5c chain (fapigo/server's X5CAttesterChain, HAIP 1.0 §4.4.1): a leaf
// its CA issued is accepted, even with no kid and no registered keys;
// a leaf from another CA, and an attestation without x5c, are refused.
func TestPAR_AttesterTrustAnchors(t *testing.T) {
	now := time.Now()
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test-only, talks to this test's own throwaway TLS listener
	attesterKey, _, attesterCertPEM, caPEM, err := conformancecert.GenerateSignerAndCert("attester-leaf", "attester-ca")
	if err != nil {
		t.Fatalf("GenerateSignerAndCert: %v", err)
	}
	otherKey, _, otherCertPEM, _, err := conformancecert.GenerateSignerAndCert("other-leaf", "other-ca")
	if err != nil {
		t.Fatalf("GenerateSignerAndCert: %v", err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cfg := baseTestConfig(t)
	cfg.Client.AttesterJWKS = nil
	cfg.Client.AttesterTrustAnchorsPEM = caPEM
	startTestIssuerServer(t, &cfg)
	cc := cfg.Client

	if got := postPARWithAttestation(t, httpClient, cfg, cc, clientKey, x5cAttestation(t, attesterKey, attesterCertPEM, cc, &clientKey.PublicKey, now), now); got != http.StatusCreated {
		t.Fatalf("attestation chaining to the trusted CA: status %d, want 201", got)
	}
	if got := postPARWithAttestation(t, httpClient, cfg, cc, clientKey, x5cAttestation(t, otherKey, otherCertPEM, cc, &clientKey.PublicKey, now), now); got != http.StatusUnauthorized {
		t.Errorf("attestation from another CA: status %d, want 401", got)
	}
	noX5C, err := buildClientAttestationJWT(attesterKey, "attester-1", cc.ExpectedAttesterIssuer, cc.ID, &clientKey.PublicKey, now)
	if err != nil {
		t.Fatalf("buildClientAttestationJWT: %v", err)
	}
	if got := postPARWithAttestation(t, httpClient, cfg, cc, clientKey, noX5C, now); got != http.StatusUnauthorized {
		t.Errorf("attestation without x5c: status %d, want 401", got)
	}
}

func TestLoadConfig_AttesterTrustChoice(t *testing.T) {
	_, _, _, caPEM, err := conformancecert.GenerateSignerAndCert("attester-leaf", "attester-ca")
	if err != nil {
		t.Fatalf("GenerateSignerAndCert: %v", err)
	}
	both := baseTestConfig(t)
	both.Client.AttesterTrustAnchorsPEM = caPEM
	neither := baseTestConfig(t)
	neither.Client.AttesterJWKS = nil
	mixed := baseTestConfig(t)
	mixed.Client.AttesterJWKS, mixed.Client.AttesterTrustAnchorsPEM = nil, caPEM
	client2 := baseTestConfig(t).Client
	client2.ID = "client-2"
	mixed.Client2 = &client2 // client2 keeps attester_jwks

	for name, cfg := range map[string]Config{"both": both, "neither": neither, "mixed across clients": mixed} {
		if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
			t.Errorf("%s: loadConfig accepted it", name)
		}
	}
}
