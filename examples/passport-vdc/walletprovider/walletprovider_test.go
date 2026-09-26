package walletprovider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
)

func TestPEM_RoundTrips(t *testing.T) {
	p, err := New("https://provider.example")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data, err := p.PEM()
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	loaded, err := Load("https://provider.example", data)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.Key.Equal(p.Key) || !loaded.Certificate.Equal(p.Certificate) || !loaded.CACertificate.Equal(p.CACertificate) {
		t.Error("Load didn't restore the key and both certificates")
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
	p, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	other, err := New("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.Certificate = other.Certificate
	data, err := p.PEM()
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	if _, err := Load("", data); err == nil {
		t.Fatal("Load accepted a certificate for another key")
	}
}

// TestKeyAttestation_VerifiesAgainstCertificate checks a Key Attestation
// built from KeyAttestationHeader and KeyAttestationClaims carries the
// provider's certificate (not the CA) as x5c, verifies with its key and
// attests the given key.
func TestKeyAttestation_VerifiesAgainstCertificate(t *testing.T) {
	p, err := New("https://provider.example")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims, err := p.KeyAttestationClaims([]*ecdsa.PublicKey{&holder.PublicKey}, now, time.Minute)
	if err != nil {
		t.Fatalf("KeyAttestationClaims: %v", err)
	}
	claims.IssuedAt = now.Unix()
	compact, err := attestation.Issue(p.Key, oid4vci.ES256, p.KeyAttestationHeader(), claims)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, err := attestation.Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if x5c := parsed.X5C(); len(x5c) != 1 {
		t.Fatalf("x5c has %d certificates, want just the provider's", len(x5c))
	}
	verified, err := parsed.Verify(p.Certificate.PublicKey, oid4vci.ES256, attestation.VerifyOptions{Now: now, RequireExpiry: true})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok, err := verified.KeyAttested(&holder.PublicKey); err != nil || !ok {
		t.Errorf("KeyAttested(holder) = %v, %v; want true", ok, err)
	}
	if verified.KeyStorage != nil || verified.UserAuthentication != nil {
		t.Error("the demo asserts an attack-potential level for software keys")
	}
}
