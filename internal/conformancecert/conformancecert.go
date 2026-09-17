// Package conformancecert builds throwaway self-signed key material
// for the conformance/*/scripts/generate-config generators — never
// for production use, and deliberately not internal/testcert (that
// one builds a *x509.Certificate for tests to hold in memory; these
// generators need PEM text to write into a JSON config file). It also
// holds ParseCertificatePEM, the runtime counterpart every
// cmd/conformance-* binary's own Config parsing needs identically to
// read that PEM text back.
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
	"fmt"
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
	der, err := selfSignedDER(commonName, dnsNames, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyPEM, err = ECKeyPEM(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyPEM, nil
}

// SelfSignedCertPEMForKey builds a self-signed leaf certificate for an
// already-generated key (commonName, valid from an hour ago to 10
// years out), returning it PEM-encoded — for wrapping a key that must
// stay the same across calls (e.g. a credential-issuer signing key
// whose public half a relying party already trusts), unlike
// SelfSignedPEM's own fresh-key-every-time shape.
func SelfSignedCertPEMForKey(commonName string, key *ecdsa.PrivateKey) (string, error) {
	der, err := selfSignedDER(commonName, nil, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// GenerateCA generates a fresh EC P-256 self-signed CA certificate and
// key (commonName, valid from an hour ago to 10 years out) — the
// trust anchor a generate-config script hands to a relying party (e.g.
// the OIDF suite's own "*_trust_anchor_pem" test configuration). Issue
// leaf certificates under it with IssueLeafCertPEM rather than
// presenting a self-signed leaf directly: some relying parties reject
// a self-signed x5c leaf outright, confirmed live against the OIDF
// suite's own SD-JWT VC check ("Leaf certificate in x5c chain must not
// be self-signed").
func GenerateCA(commonName string) (cert *x509.Certificate, key *ecdsa.PrivateKey, certPEM, keyPEM string, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", "", err
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", "", err
	}
	keyPEM, err = ECKeyPEM(key)
	if err != nil {
		return nil, nil, "", "", err
	}
	return cert, key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyPEM, nil
}

// GenerateSignerAndCert generates a fresh EC P-256 key plus a leaf
// certificate wrapping it, issued under a fresh throwaway CA — the
// "generate a credential-issuer signing key, then wrap it in a
// CA-issued (not self-signed) leaf" sequence every generate-config
// script producing x5c-bearing test credentials needs identically
// (see GenerateCA's own doc comment for why a bare self-signed leaf
// doesn't work). leafCommonName/caCommonName name the leaf/CA
// certificates respectively; caCertPEM is what to paste into a relying
// party's own trust-anchor test configuration.
func GenerateSignerAndCert(leafCommonName, caCommonName string) (key *ecdsa.PrivateKey, keyPEM, certPEM, caCertPEM string, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", "", "", err
	}
	keyPEM, err = ECKeyPEM(key)
	if err != nil {
		return nil, "", "", "", err
	}
	ca, caKey, caCertPEM, _, err := GenerateCA(caCommonName)
	if err != nil {
		return nil, "", "", "", err
	}
	certPEM, err = IssueLeafCertPEM(leafCommonName, key, ca, caKey)
	if err != nil {
		return nil, "", "", "", err
	}
	return key, keyPEM, certPEM, caCertPEM, nil
}

// IssueLeafCertPEM issues a leaf certificate for leafKey's own public
// key, signed by caCert/caKey (see GenerateCA), returning it
// PEM-encoded — for a leaf whose own private key also signs something
// else (a credential, a request object) where a self-signed leaf would
// be rejected (see GenerateCA's own doc comment).
func IssueLeafCertPEM(commonName string, leafKey *ecdsa.PrivateKey, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (string, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

func selfSignedDER(commonName string, dnsNames []string, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:     dnsNames,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
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

// ParseCertificatePEM decodes a single PEM CERTIFICATE block and
// parses it as an *x509.Certificate — the runtime counterpart to this
// package's own generation helpers, for a cmd/conformance-*'s own
// Config parsing (e.g. CredentialIssuerCertificatePEM), used
// identically by more than one binary.
func ParseCertificatePEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParseECPrivateKeyPEM decodes a single PEM EC PRIVATE KEY block and
// parses it as an *ecdsa.PrivateKey — ParseCertificatePEM's own
// counterpart for a cmd/conformance-*'s own Config parsing (e.g.
// CredentialIssuerSigningKeyPEM, CredentialRequestDecryptionKeyPEM),
// used identically by more than one binary.
func ParseECPrivateKeyPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseECPrivateKey(block.Bytes)
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

// AssertMatchingPublicKey fails t unless certKey (a certificate's own
// PublicKey field) is the same key as signingKey's own public half —
// the "did the generated certificate actually wrap this signing key"
// check every cmd/conformance-*'s own config_test.go needs
// identically.
func AssertMatchingPublicKey(t *testing.T, signingKey *ecdsa.PrivateKey, certKey crypto.PublicKey) {
	t.Helper()
	if !signingKey.PublicKey.Equal(certKey) {
		t.Error("certificate's public key does not match the signing key's")
	}
}

// TestKeyAndSelfSignedCertPEM generates a fresh EC P-256 key plus a
// self-signed certificate wrapping it (commonName), both PEM-encoded
// — for a test's own CredentialIssuerCertificatePEM-shaped config
// field where the suite's own self-signed-leaf rejection isn't being
// exercised (that's GenerateSignerAndCert's own CA-issued leaf, used
// by the real generate-config scripts, not this test-only shortcut).
func TestKeyAndSelfSignedCertPEM(t *testing.T, commonName string) (keyPEM, certPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM, err = ECKeyPEM(key)
	if err != nil {
		t.Fatalf("ECKeyPEM: %v", err)
	}
	certPEM, err = SelfSignedCertPEMForKey(commonName, key)
	if err != nil {
		t.Fatalf("SelfSignedCertPEMForKey: %v", err)
	}
	return keyPEM, certPEM
}

// RequireNonEmpty returns a "config: <jsonFieldName> is required"
// error unless value is non-empty — the loadConfig required-field
// check every cmd/conformance-*'s own Config needs identically for
// each string field, jsonFieldName matching that field's own JSON tag.
func RequireNonEmpty(jsonFieldName, value string) error {
	if value == "" {
		return fmt.Errorf("config: %s is required", jsonFieldName)
	}
	return nil
}

// CredentialExp computes an "exp" claim for a credential issued at
// now, rounded down to the start of now's own UTC day before adding
// lifetime — never the raw issuance instant. Two credentials issued
// moments apart (e.g. one per client in a multi-client flow) would
// otherwise carry two exp values differing by exactly that real
// inter-issuance gap, letting a party holding both correlate them —
// confirmed live against the OIDF conformance suite's own
// oid4vci-1_0-issuer-happy-flow-multiple-clients module, which flagged
// exactly this ("Credential time information [exp] advanced by ~the
// real inter-issuance gap... indicating the issuer embeds the precise
// issuance time... iat/exp/nbf... MUST be randomized or rounded to
// prevent linkability", RFC 9901 §10.1). Day-granularity rounding
// means every credential issued on the same calendar day carries an
// identical exp, closing that channel while still bounding validity.
func CredentialExp(now time.Time, lifetime time.Duration) int64 {
	dayStart := now.UTC().Truncate(24 * time.Hour)
	return dayStart.Add(lifetime).Unix()
}
