package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// TestBuildServerConfig_TrustsAttesterByCA checks cmd/conformance-issuer
// is told to trust the suite's Client Attestations by the CA that issued
// the attester's x5c leaf (fapigo/server's X5CAttesterChain), and that
// the leaf the suite signs with verifies against it without being
// self-signed and names the attester as a URI SAN — what
// X5CAttesterChain with AttesterIssuerInCertificate requires.
func TestBuildServerConfig_TrustsAttesterByCA(t *testing.T) {
	r, err := generateRun("test", "https://localhost.emobix.co.uk:8443/test/a/test")
	if err != nil {
		t.Fatalf("generateRun: %v", err)
	}
	raw, err := buildServerConfig(r)
	if err != nil {
		t.Fatalf("buildServerConfig: %v", err)
	}
	var cfg struct {
		Client, Client2 map[string]json.RawMessage
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	leaf := parsePEMCert(t, r.attesterLeafPEM)
	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		t.Fatal("the attester leaf is self-signed")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != r.attesterIssuer {
		t.Errorf("attester leaf URI SANs = %v, want exactly %q", leaf.URIs, r.attesterIssuer)
	}
	for name, client := range map[string]map[string]json.RawMessage{"client": cfg.Client, "client2": cfg.Client2} {
		if _, ok := client["attester_jwks"]; ok {
			t.Errorf("%s still registers attester_jwks", name)
		}
		var anchorsPEM string
		if err := json.Unmarshal(client["attester_trust_anchors_pem"], &anchorsPEM); err != nil || anchorsPEM == "" {
			t.Fatalf("%s.attester_trust_anchors_pem missing: %v", name, err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(anchorsPEM)) {
			t.Fatalf("%s.attester_trust_anchors_pem holds no certificate", name)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Errorf("%s: the attester leaf doesn't verify against its trust anchors: %v", name, err)
		}
	}
}

func parsePEMCert(t *testing.T, s string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
