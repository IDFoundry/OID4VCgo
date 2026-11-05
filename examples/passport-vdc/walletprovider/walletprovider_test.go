package walletprovider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

const testIssuer = "https://provider.example"

func TestPEM_RoundTrips(t *testing.T) {
	p, err := New(testIssuer)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data, err := p.PEM()
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	loaded, err := Load(testIssuer, data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.Key.Equal(p.Key) || !loaded.Certificate.Equal(p.Certificate) || !loaded.CACertificate.Equal(p.CACertificate) {
		t.Error("Load didn't restore the key and both certificates")
	}
}

// TestCertificate_NamesIssuer checks the provider's certificate carries
// its identifier as its URI SAN, which the issuer binds the Wallet
// Attestation to (AttesterIssuerInCertificate), and that Load refuses a
// file naming another provider.
func TestCertificate_NamesIssuer(t *testing.T) {
	p, err := New(testIssuer)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(p.Certificate.URIs) != 1 || p.Certificate.URIs[0].String() != testIssuer {
		t.Errorf("certificate URI SANs = %v, want exactly %q", p.Certificate.URIs, testIssuer)
	}
	data, err := p.PEM()
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	if _, err := Load("https://other-provider.example", data); err == nil || !strings.Contains(err.Error(), "rerun cmd/wallet-provider") {
		t.Errorf("Load for another provider: error = %v, want a hint to regenerate", err)
	}
	if _, err := New("not-a-uri"); err == nil {
		t.Error("New accepted an issuer that isn't an absolute URI")
	}
}

func TestLoad_RejectsKeyOnlyFile(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Load("", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err == nil || !strings.Contains(err.Error(), "rerun cmd/wallet-provider") {
		t.Fatalf("Load(key only) error = %v, want a hint to regenerate", err)
	}
}

func TestLoad_RejectsCertificateForAnotherKey(t *testing.T) {
	p, err := New(testIssuer)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	other, err := New(testIssuer)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.Certificate = other.Certificate
	data, err := p.PEM()
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	if _, err := Load(testIssuer, data); err == nil {
		t.Fatal("Load accepted a certificate for another key")
	}
}
