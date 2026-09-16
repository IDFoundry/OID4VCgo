package main

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
)

// staticIssuerKeyResolver implements verifier.SDJWTVCIssuerKeyResolver
// by trusting exactly one statically-configured JWK, regardless of
// header/payload — this binary has no dynamic trust anchor/x5c chain
// validation, DID resolution, or VCT metadata lookup to do: it's
// pointed at the OIDF suite's own emulated Credential Issuer, whose
// signing key is a fixed test-configuration value (see Config's own
// doc comment), not something to resolve per credential.
type staticIssuerKeyResolver struct {
	pub crypto.PublicKey
	alg jose.Alg
}

func newStaticIssuerKeyResolver(rawJWK json.RawMessage) (staticIssuerKeyResolver, error) {
	pub, err := jwk.ParsePublicKey(rawJWK)
	if err != nil {
		return staticIssuerKeyResolver{}, fmt.Errorf("parse credential_issuer_jwk: %w", err)
	}
	var withAlg struct {
		Alg jose.Alg `json:"alg"`
	}
	if err := json.Unmarshal(rawJWK, &withAlg); err != nil {
		return staticIssuerKeyResolver{}, fmt.Errorf("parse credential_issuer_jwk: %w", err)
	}
	alg := withAlg.Alg
	if alg == "" {
		// HAIP 1.0 §7's own minimum — the same default RecommendedJOSEAlgorithm
		// documents for a deployment that doesn't declare one explicitly.
		alg = jose.ES256
	}
	return staticIssuerKeyResolver{pub: pub, alg: alg}, nil
}

func (r staticIssuerKeyResolver) ResolveIssuerKey(_ context.Context, _, _ map[string]any) (crypto.PublicKey, jose.Alg, error) {
	return r.pub, r.alg, nil
}
