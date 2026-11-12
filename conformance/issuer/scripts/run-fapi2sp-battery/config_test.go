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

// TestBuildServerConfig_ServesMdocCRL checks the mdoc Document
// Signer's CRL distribution point is where cmd/conformance-issuer is
// told to serve its IACA's CRL, on the issuer's suite-network host,
// and that the CRL is the IACA's, signed by it.
func TestBuildServerConfig_ServesMdocCRL(t *testing.T) {
	r, err := generateRun("test", "https://conformance-issuer:8443")
	if err != nil {
		t.Fatalf("generateRun: %v", err)
	}
	raw, err := buildServerConfig(r)
	if err != nil {
		t.Fatalf("buildServerConfig: %v", err)
	}
	var cfg struct {
		Mdoc struct {
			CertificatePEM            string `json:"certificate_pem"`
			TrustAnchorCertificatePEM string `json:"trust_anchor_certificate_pem"`
			CRLPEM                    string `json:"crl_pem"`
			CRLListenAddr             string `json:"crl_listen_addr"`
		}
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ds := parsePEMCert(t, cfg.Mdoc.CertificatePEM)
	iaca := parsePEMCert(t, cfg.Mdoc.TrustAnchorCertificatePEM)
	const want = "http://conformance-issuer:8080/mdoc-iaca.crl"
	if len(ds.CRLDistributionPoints) != 1 || ds.CRLDistributionPoints[0] != want {
		t.Errorf("CRLDistributionPoints = %v, want [%s]", ds.CRLDistributionPoints, want)
	}
	if cfg.Mdoc.CRLListenAddr != ":8080" {
		t.Errorf("crl_listen_addr = %q, want :8080", cfg.Mdoc.CRLListenAddr)
	}
	block, _ := pem.Decode([]byte(cfg.Mdoc.CRLPEM))
	if block == nil || block.Type != "X509 CRL" {
		t.Fatal("crl_pem holds no X509 CRL block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}
	if !bytes.Equal(crl.RawIssuer, ds.RawIssuer) {
		t.Error("CRL issuer is not the Document Signer certificate's issuer")
	}
	if err := crl.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("CRL signature: %v", err)
	}
}

// TestBuildServerConfig_Production checks -production's server config:
// the production setup's own keys, and key attestations trusted by the
// CA that issued the leaf the suite signs them with, not by a key.
func TestBuildServerConfig_Production(t *testing.T) {
	r, err := generateRun("test", "https://conformance-issuer:8443")
	if err != nil {
		t.Fatalf("generateRun: %v", err)
	}
	r.production = true
	raw, err := buildServerConfig(r)
	if err != nil {
		t.Fatalf("buildServerConfig: %v", err)
	}
	var cfg struct {
		KeyAttestation map[string]json.RawMessage `json:"key_attestation"`
		Production     *serverProductionConfig    `json:"production"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p := cfg.Production; p == nil || p.DatabasePath == "" || p.SealingKey == "" || p.AccessTokenSigningKeyPEM == "" {
		t.Fatalf("production = %+v, want every field set", cfg.Production)
	}
	if _, ok := cfg.KeyAttestation["trusted_jwk"]; ok {
		t.Error("key_attestation still trusts a key")
	}
	var anchorPEM string
	if err := json.Unmarshal(cfg.KeyAttestation["trust_anchor_pem"], &anchorPEM); err != nil {
		t.Fatalf("key_attestation.trust_anchor_pem: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(anchorPEM)) {
		t.Fatal("key_attestation.trust_anchor_pem holds no certificate")
	}
	if _, err := parsePEMCert(t, r.keyAttestationLeafPEM).Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("the key attestation leaf doesn't verify against the trust anchor: %v", err)
	}
}
