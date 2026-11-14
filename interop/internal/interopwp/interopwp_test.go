package interopwp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/interop/internal/interopwp"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

const (
	identifier = "https://provider.example"
	clientID   = "wallet-client"
)

// newProvider serves a walletprovider.Provider over TLS, accepting
// FakeVerifier evidence, and returns its URL and an HTTP client
// trusting it.
func newProvider(t *testing.T) (*walletprovider.Provider, string, *http.Client) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := url.Parse(identifier)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Wallet Provider"}, URIs: []*url.URL{id},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	p, err := walletprovider.New(walletprovider.Config{
		Identifier: identifier, ClientIDs: []string{clientID}, StatusListBaseURI: identifier + "/status", StatusListSize: 1024,
		Policy: walletprovider.Policy{
			Platforms: map[walletprovider.Platform]walletprovider.PlatformPolicy{
				walletprovidertest.FakePlatform: {SecurityLevels: []walletprovider.SecurityLevel{walletprovider.SecurityLevelTEE}},
			},
			KeyStorage: []walletprovider.KeyStorageRule{{
				Platform: walletprovidertest.FakePlatform, SecurityLevel: walletprovider.SecurityLevelTEE,
				KeyStorage: []attestation.AttackPotentialResistance{attestation.ISO18045Moderate},
			}},
		},
	}, walletprovider.Dependencies{
		Signer: key, Chain: []*x509.Certificate{leaf},
		Instances: &walletprovider.MemoryInstanceStore{}, InstanceKeys: &walletprovider.MemoryInstanceKeyStore{},
		Challenges: &walletprovider.MemoryChallengeStore{}, StatusIndices: &statuslist.MemoryIndexStore{},
		Evidence: []walletprovider.EvidenceVerifier{walletprovidertest.FakeVerifier{SecurityLevel: walletprovider.SecurityLevelTEE}},
		Random:   rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(p.Handler())
	t.Cleanup(srv.Close)
	return p, srv.URL, srv.Client()
}

func TestProviderAttests(t *testing.T) {
	ctx := context.Background()
	_, base, hc := newProvider(t)
	p, err := interopwp.Register(ctx, base, hc)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if p.InstanceID() == "" {
		t.Fatal("no instance ID")
	}
	instanceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Twice: the second time, the key is already recorded.
	for i := range 2 {
		wa, err := p.WalletAttestation(ctx, clientID, instanceKey.Public())
		if err != nil {
			t.Fatalf("WalletAttestation %d: %v", i, err)
		}
		if strings.Count(wa, ".") != 2 {
			t.Fatalf("WalletAttestation %d: not a compact JWT: %q", i, wa)
		}
	}
	holder1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ka, err := p.KeyAttestation(ctx, instanceKey.Public(), []*ecdsa.PublicKey{&holder1.PublicKey, &holder2.PublicKey}, "nonce-1")
	if err != nil {
		t.Fatalf("KeyAttestation: %v", err)
	}
	if strings.Count(ka, ".") != 2 {
		t.Fatalf("KeyAttestation: not a compact JWT: %q", ka)
	}
}

func TestProviderRefusals(t *testing.T) {
	ctx := context.Background()
	_, base, hc := newProvider(t)
	p, err := interopwp.Register(ctx, base, hc)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := p.KeyAttestation(ctx, nil, nil, "n"); err == nil {
		t.Error("a Key Attestation of no keys was asked for")
	}
	// A Key Attestation for an instance key no Wallet Attestation
	// recorded is the provider's to refuse.
	unknown, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holder, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := p.KeyAttestation(ctx, unknown.Public(), []*ecdsa.PublicKey{&holder.PublicKey}, "n"); err == nil {
		t.Error("a Key Attestation for an unrecorded instance key was issued")
	}
	if _, err := p.WalletAttestation(ctx, "another-client", unknown.Public()); err == nil {
		t.Error("a Wallet Attestation for a client the provider doesn't attest was issued")
	}
	if _, err := interopwp.Register(ctx, "http://insecure.example", hc); err == nil {
		t.Error("an http provider URL was taken")
	}
}
