package main

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/wallet"
)

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

	additional := make(map[string]any, len(cfg.Claims))
	for name, value := range cfg.Claims {
		additional[name] = sdjwtvc.SD(value)
	}

	sdjwt, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT:        cfg.VCT,
		CNF:        map[string]any{"jwk": holderJWK},
		Additional: additional,
	}, sdjwtvc.IssueOptions{})
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
