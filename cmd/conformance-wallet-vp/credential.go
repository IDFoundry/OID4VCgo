package main

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// fixtureCredentialLifetime bounds the fixture credential's own "exp"
// claim — HAIP/SD-JWT VC §11.2.3's own RECOMMENDED (not required) way
// to limit a credential's validity, confirmed live as something the
// OIDF conformance suite's own log flags as a WARNING when absent.
// A year is generous headroom for this binary's own "issue once at
// startup, reuse for the process's whole lifetime" shape (see
// issueFixtureCredential's own doc comment) — this binary is never
// expected to run anywhere near that long.
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
	exp := time.Now().Add(fixtureCredentialLifetime).Unix()

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
