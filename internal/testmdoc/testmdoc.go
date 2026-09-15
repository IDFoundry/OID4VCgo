// Package testmdoc provides shared "mso_mdoc" test fixtures for OID4VP
// presentation tests across packages (verifier, wallet) — never for
// production use. A regular (not _test.go) package specifically so
// more than one package's own tests can share it; Go doesn't let a
// _test.go file's own symbols be imported from another package's
// tests — the same reason internal/testcert exists.
package testmdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/internal/testcert"
)

// DocType is the ISO/IEC 18013-5 docType every Fixture this package
// issues carries.
const DocType = "org.iso.18013.5.1.mDL"

// Fixture is a real, freshly issued "mso_mdoc" credential (an mDL
// carrying given_name/family_name in its own org.iso.18013.5.1
// namespace) plus the keys behind it.
type Fixture struct {
	IssuerKey    *ecdsa.PrivateKey
	DeviceKey    *ecdsa.PrivateKey
	IssuerSigned mdoc.IssuerSigned
}

// Issue builds a Fixture.
func Issue(t *testing.T) Fixture {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testmdoc: generate issuer key: %v", err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testmdoc: generate device key: %v", err)
	}
	cert := testcert.SelfSigned(t, "testmdoc fixture issuer", &issuerKey.PublicKey, issuerKey)

	signed := time.Now()
	issuerSigned, err := mdoc.Issue(issuerKey, cose.ES256, mdoc.Claims{
		DocType: DocType,
		NameSpaces: map[string]map[string]interface{}{
			"org.iso.18013.5.1": {"given_name": "Alice", "family_name": "Doe"},
		},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     signed,
		ValidFrom:  signed,
		ValidUntil: signed.Add(24 * time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{cert.Raw}})
	if err != nil {
		t.Fatalf("testmdoc: mdoc.Issue: %v", err)
	}
	return Fixture{IssuerKey: issuerKey, DeviceKey: deviceKey, IssuerSigned: issuerSigned}
}

// Query builds the standard DCQL query every Fixture this package
// issues satisfies: DocType, requesting its own given_name element.
func Query(t *testing.T) dcql.Query {
	t.Helper()
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: DocType})
	if err != nil {
		t.Fatalf("testmdoc: NewMdocMeta: %v", err)
	}
	return dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "mdl", Format: mdoc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("given_name")}}},
	}}}
}

// ResponseEncryptionThumbprint computes the RFC 7638 SHA-256 JWK
// thumbprint of key's own public key as raw bytes —
// oid4vpmdoc.HandoverParams.ResponseEncryptionJWKThumbprint's own
// shape, and exactly what a real Verifier/Wallet each independently
// derive from the same key to reconstruct identical
// SessionTranscriptBytes.
func ResponseEncryptionThumbprint(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	j, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("testmdoc: jwk.Marshal: %v", err)
	}
	thumbprint, err := j.Thumbprint()
	if err != nil {
		t.Fatalf("testmdoc: Thumbprint: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		t.Fatalf("testmdoc: decode thumbprint: %v", err)
	}
	return raw
}
