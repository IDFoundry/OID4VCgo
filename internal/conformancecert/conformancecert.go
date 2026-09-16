// Package conformancecert builds throwaway self-signed key material
// for the conformance/*/scripts/generate-config generators — never
// for production use, and deliberately not internal/testcert (that
// one builds a *x509.Certificate for tests to hold in memory; these
// generators need PEM text to write into a JSON config file).
package conformancecert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/jwk"
)

// SelfSignedPEM generates a fresh EC P-256 key and a self-signed
// leaf certificate for it (commonName, dnsNames, valid from an hour
// ago to 10 years out), returning both PEM-encoded.
func SelfSignedPEM(commonName string, dnsNames []string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyPEM, err = ECKeyPEM(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyPEM, nil
}

// GenerateECKeyPEM generates a fresh EC P-256 key and returns its
// PEM encoding.
func GenerateECKeyPEM() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	return ECKeyPEM(key)
}

// ECKeyPEM PEM-encodes an already-generated EC private key.
func ECKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

// jwkWithKid embeds jwk.Marshal's own public-only shape plus the "kid"
// member a JWK Set entry conventionally carries — the same "embed
// jwk.JWK + extra fields locally" pattern
// verifier/authorization_request.go's own responseEncryptionJWK
// already establishes.
type jwkWithKid struct {
	jwk.JWK
	Kid string `json:"kid"`
}

// JWKSet builds a single-key JWK Set ({"keys":[...]}) for pub, tagged
// with kid — the shape a Client Attestation-verifying party's own
// Dependencies.ClientKeys (fapigo/keys/ephemeral.ClientKeySpec.JWKS)
// expects, and what a Credential Issuer's own conformance config
// embeds for its one registered attester's public key.
func JWKSet(pub crypto.PublicKey, kid string) (json.RawMessage, error) {
	j, err := jwk.Marshal(pub)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"keys": []jwkWithKid{{JWK: j, Kid: kid}}})
}

// WriteJSONConfig JSON-marshals cfg and writes it to a fresh file
// under t.TempDir(), returning the path — the "write this binary's
// own Config out so loadConfig can read it back" step every
// cmd/conformance-*'s own config_test.go needs identically.
func WriteJSONConfig(t *testing.T, cfg any) string {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
