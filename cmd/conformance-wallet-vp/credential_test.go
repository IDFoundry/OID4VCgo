package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
	"github.com/idfoundry/oid4vcigo/internal/jose"
)

func TestIssueFixtureCredential_SetsExp(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	ca, caKey, _, _, err := conformancecert.GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	issuerCertPEM, err := conformancecert.IssueLeafCertPEM("test-issuer", issuerKey, ca, caKey)
	if err != nil {
		t.Fatalf("IssueLeafCertPEM: %v", err)
	}
	cfg := Config{
		VCT:                            "urn:eudi:pid:1",
		Claims:                         map[string]string{"given_name": "Jean"},
		CredentialIssuerCertificatePEM: issuerCertPEM,
	}

	before := time.Now()
	cred, err := issueFixtureCredential(cfg, issuerKey, holderKey)
	if err != nil {
		t.Fatalf("issueFixtureCredential: %v", err)
	}

	issuerJWT, _, _ := strings.Cut(cred.Credential, "~")
	_, payload, err := jose.Verify(jose.ES256, &issuerKey.PublicKey, issuerJWT)
	if err != nil {
		t.Fatalf("jose.Verify: %v", err)
	}
	var wire struct {
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if wire.Exp == nil {
		t.Fatal("issued credential has no exp claim")
	}
	wantMin := before.Add(fixtureCredentialLifetime - time.Minute).Unix()
	wantMax := before.Add(fixtureCredentialLifetime + time.Minute).Unix()
	if *wire.Exp < wantMin || *wire.Exp > wantMax {
		t.Errorf("exp = %d, want between %d and %d", *wire.Exp, wantMin, wantMax)
	}
}
