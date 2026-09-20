package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// fixtureCredentialLifetime bounds the fixture credential's own "exp"
// claim — HAIP/SD-JWT VC §11.2.3's own RECOMMENDED (not required) way
// to limit a credential's validity, confirmed live as something the
// OIDF conformance suite's own log flags as a WARNING when absent.
// A year is generous headroom for this binary's own "issue once at
// startup, reuse for the process's whole lifetime" shape (see
// issueFixtureCredential's own doc comment) — this binary is never
// expected to run anywhere near that long. See
// conformancecert.CredentialExp's own doc comment for why the actual
// exp value is day-rounded, not this value added to the raw issuance
// instant — this binary only ever issues one credential, so the
// linkability risk that rounding closes doesn't apply here, but
// rounding anyway costs nothing and keeps both conformance binaries'
// own exp computation identical.
const fixtureCredentialLifetime = 365 * 24 * time.Hour

// issueFixtureCredential builds this binary's own held SD-JWT VC —
// issued by issuerKey for cfg.VCT/cfg.Claims (every claim selectively
// disclosable), bound to holderKey's own public key via "cnf" (RFC
// 7800) — everything wallet.HeldCredential needs to actually present
// it later. Issued once at startup; this binary presents the exact
// same fixture credential for every session, matching cmd/conformance-
// verifier's own "one static config, no per-session fixture state"
// shape.
func issueFixtureCredential(cfg Config, issuerKey, holderKey *ecdsa.PrivateKey) (wallet.HeldCredential, error) {
	holderJWK, err := jwk.Marshal(&holderKey.PublicKey)
	if err != nil {
		return wallet.HeldCredential{}, fmt.Errorf("marshal holder public key: %w", err)
	}
	issuerCert, err := cfg.credentialIssuerCertificate()
	if err != nil {
		return wallet.HeldCredential{}, err
	}

	additional := make(map[string]any, len(cfg.Claims))
	for name, value := range cfg.Claims {
		additional[name] = sdjwtvc.SD(value)
	}
	exp := conformancecert.CredentialExp(time.Now(), fixtureCredentialLifetime)

	sdjwt, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT:        cfg.VCT,
		CNF:        map[string]any{"jwk": holderJWK},
		Exp:        &exp,
		Additional: additional,
	}, sdjwtvc.IssueOptions{IssuerCertificate: issuerCert})
	if err != nil {
		return wallet.HeldCredential{}, fmt.Errorf("issue fixture sd-jwt vc: %w", err)
	}

	return wallet.HeldCredential{
		Format:       sdjwtvc.CredentialFormat,
		Credential:   sdjwt,
		HolderKey:    holderKey,
		HolderKeyAlg: jose.ES256,
	}, nil
}

// issueFixtureMdocCredential is issueFixtureCredential's own "mso_mdoc"
// counterpart: builds this binary's own held mdoc (an mDL, cfg.MdocDocType/
// cfg.MdocNamespace/cfg.MdocClaims), issued by cfg's own Document Signer
// identity (cfg.mdocIssuerKey/mdocIssuerCertificate — ISO/IEC 18013-5's
// own IACA/Document Signer hierarchy, internal/conformancecert.
// GenerateMdocIACA/GenerateMdocDocumentSigner; the suite's own
// "credential.trust_anchor_pem" doubles as the mdoc IACA trust anchor
// when no VICAL is configured, confirmed against the suite's own
// AbstractVP1FinalWalletTest.java doc comment), bound to deviceKey's own
// public key via DeviceKeyInfo.DeviceKey (mdoc's own "cnf" analog) —
// mirrors internal/testmdoc's own test-only fixture, but production-safe
// (no *testing.T) and X5Chain-backed by a real, non-self-signed
// certificate rather than testmdoc's own bare self-signed one, matching
// this file's own SD-JWT VC fixture's identical non-self-signed-leaf
// requirement (see conformance/wallet-vp/README.md's own "x5c" findings).
func issueFixtureMdocCredential(cfg Config, deviceKey *ecdsa.PrivateKey) (wallet.HeldCredential, error) {
	issuerKey, err := cfg.mdocIssuerKey()
	if err != nil {
		return wallet.HeldCredential{}, err
	}
	issuerCert, err := cfg.mdocIssuerCertificate()
	if err != nil {
		return wallet.HeldCredential{}, err
	}

	nameSpaceClaims := make(map[string]interface{}, len(cfg.MdocClaims))
	for name, value := range cfg.MdocClaims {
		nameSpaceClaims[name] = value
	}
	now := time.Now()

	issuerSigned, err := mdoc.Issue(issuerKey, cose.ES256, mdoc.Claims{
		DocType:    cfg.MdocDocType,
		NameSpaces: map[string]map[string]interface{}{cfg.MdocNamespace: nameSpaceClaims},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     now,
		ValidFrom:  now,
		ValidUntil: now.Add(fixtureCredentialLifetime),
	}, mdoc.IssueOptions{X5Chain: [][]byte{issuerCert.Raw}})
	if err != nil {
		return wallet.HeldCredential{}, fmt.Errorf("issue fixture mdoc: %w", err)
	}
	wire, err := issuerSigned.Marshal()
	if err != nil {
		return wallet.HeldCredential{}, fmt.Errorf("marshal fixture mdoc: %w", err)
	}

	return wallet.HeldCredential{
		Format:      mdoc.CredentialFormat,
		Credential:  base64.RawURLEncoding.EncodeToString(wire),
		HolderKey:   deviceKey,
		MdocDocType: cfg.MdocDocType,
	}, nil
}
