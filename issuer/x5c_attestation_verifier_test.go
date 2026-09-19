package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func x5cKeyAttestation(t *testing.T, signer *ecdsa.PrivateKey, certs ...*x509.Certificate) attestation.KeyAttestation {
	t.Helper()
	x5c := make([]string, len(certs))
	for i, c := range certs {
		x5c[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	attestedKey, err := json.Marshal(map[string]any{"kty": "EC"})
	if err != nil {
		t.Fatalf("marshal attested key: %v", err)
	}
	compact, err := attestation.Issue(signer, jose.ES256,
		attestation.Header{X5C: x5c},
		attestation.Claims{IssuedAt: 1, AttestedKeys: []json.RawMessage{attestedKey}},
	)
	if err != nil {
		t.Fatalf("attestation.Issue: %v", err)
	}
	parsed, err := attestation.Parse(compact)
	if err != nil {
		t.Fatalf("attestation.Parse: %v", err)
	}
	return parsed
}

func TestX5CAttestationVerifier_AcceptsCASignedLeaf(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, leafKey := testcert.Leaf(t, "test-leaf", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	verifier := issuer.X5CAttestationVerifier{Roots: roots}

	pub, alg, err := verifier.ResolveAttestationKey(context.Background(), x5cKeyAttestation(t, leafKey, leaf))
	if err != nil {
		t.Fatalf("ResolveAttestationKey: %v", err)
	}
	if alg != jose.ES256 {
		t.Errorf("alg = %q, want ES256", alg)
	}
	gotPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || !gotPub.Equal(&leafKey.PublicKey) {
		t.Errorf("resolved public key does not match the leaf's own key")
	}
}

func TestX5CAttestationVerifier_RejectsMissingX5C(t *testing.T) {
	verifier := issuer.X5CAttestationVerifier{Roots: x509.NewCertPool()}
	_, leafKey := testcert.SelfSignedLeaf(t, "irrelevant")
	if _, _, err := verifier.ResolveAttestationKey(context.Background(), x5cKeyAttestation(t, leafKey)); err == nil {
		t.Error("ResolveAttestationKey accepted a header with no x5c")
	}
}

func TestX5CAttestationVerifier_RejectsSelfSignedLeafEvenIfTrusted(t *testing.T) {
	leaf, leafKey := testcert.SelfSignedLeaf(t, "self-signed-leaf")
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	verifier := issuer.X5CAttestationVerifier{Roots: roots}

	if _, _, err := verifier.ResolveAttestationKey(context.Background(), x5cKeyAttestation(t, leafKey, leaf)); err == nil {
		t.Error("ResolveAttestationKey accepted a self-signed leaf")
	}
}

func TestX5CAttestationVerifier_RejectsUntrustedChain(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, leafKey := testcert.Leaf(t, "test-leaf", ca, caKey)
	verifier := issuer.X5CAttestationVerifier{Roots: x509.NewCertPool()}

	if _, _, err := verifier.ResolveAttestationKey(context.Background(), x5cKeyAttestation(t, leafKey, leaf)); err == nil {
		t.Error("ResolveAttestationKey accepted a chain that doesn't lead to a trusted root")
	}
}
