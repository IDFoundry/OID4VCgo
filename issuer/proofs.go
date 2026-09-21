package issuer

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// resolveJWTProofKeys verifies every jwt-type key proof in values
// (Appendix F.1): typ, alg (against ptc's own allow-list), the binding
// key conveyed via "jwk", "kid" or "x5c" (see resolveProofBindingKey),
// the JWS signature (self-consistency — a proof is signed by the very
// key it declares, proving possession), and the body's aud/iat/nonce
// claims. §8.2's own batch-issuance example shares one c_nonce across
// every proof in the request — this consumes it once, from the first
// proof, and requires every other proof to declare that same value,
// matching NonceStore's own doc comment ("Consume is still called once
// per request, not once per proof").
func (iss *Issuer) resolveJWTProofKeys(
	ctx context.Context, auth AuthorizedRequest, values []string, ptc oid4vci.ProofTypeConfiguration,
) ([]resolvedKey, error) {
	if ptc.KeyAttestationsRequired != nil {
		return nil, newError(ErrorInvalidCredentialRequest, 400,
			"this credential_configuration_id requires a key attestation on the jwt proof type, which is not supported", nil)
	}

	keys := make([]resolvedKey, 0, len(values))
	var expectedNonce string
	nonceRequired := !iss.cfg.Endpoints.Nonce.IsZero()

	for i, raw := range values {
		pub, jwkRaw, nonce, err := iss.verifyJWTProof(ctx, auth, raw, i, ptc)
		if err != nil {
			return nil, err
		}

		if nonceRequired {
			if nonce == "" {
				return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: nonce is required", i), nil)
			}
			if i == 0 {
				if err := iss.consumeNonce(ctx, nonce); err != nil {
					return nil, err
				}
				expectedNonce = nonce
			} else if nonce != expectedNonce {
				return nil, newError(ErrorInvalidNonce, 400, fmt.Sprintf("proof %d: nonce does not match the request's consumed nonce", i), nil)
			}
		}

		keys = append(keys, resolvedKey{Public: pub, JWKRaw: jwkRaw})
	}
	return keys, nil
}

// verifyJWTProof verifies one jwt-type key proof — typ, alg (against
// ptc's own allow-list), the binding key conveyed via "jwk", "kid" or
// "x5c" (see resolveProofBindingKey), the JWS signature
// (self-consistency — a proof is signed by the very key it declares,
// proving possession), and the body's aud/iat/iss claims — and returns
// its own binding key plus its own "nonce" body claim (unvalidated:
// resolveJWTProofKeys itself handles the required/consistency checks,
// which span across every proof in the request, not just this one).
// Split out purely to keep resolveJWTProofKeys under the linter's own
// cognitive complexity ceiling.
func (iss *Issuer) verifyJWTProof(ctx context.Context, auth AuthorizedRequest, raw string, i int, ptc oid4vci.ProofTypeConfiguration) (crypto.PublicKey, json.RawMessage, string, error) {
	header, _, err := jose.DecodeUnverified(raw)
	if err != nil {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d is malformed", i), err)
	}
	if typ, _ := header["typ"].(string); typ != jwtProofTyp {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d has typ %q, want %q", i, typ, jwtProofTyp), nil)
	}
	algStr, _ := header["alg"].(string)
	if !slices.Contains(ptc.ProofSigningAlgValuesSupported, algStr) {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d alg %q is not supported", i, algStr), nil)
	}
	pub, alg, jwkRaw, err := iss.resolveProofBindingKey(ctx, header)
	if err != nil {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: %v", i, err), nil)
	}

	// alg, not jose.Alg(algStr): for a kid/x5c-conveyed key, alg is
	// whatever Dependencies.ProofBindingKeys actually vetted that key
	// for, never the header's own unverified claim — see
	// ProofBindingKeyResolver's own doc comment for why. Verify still
	// rejects the request if algStr disagrees with the vetted alg (its
	// own header-vs-expected check), so a Wallet claiming a different
	// algorithm than the resolved key was actually trusted for is
	// still cleanly refused. For a jwk-conveyed key (self-asserted, no
	// external trust resolution — the same proof-of-possession model
	// wallet's own DPoP proofs use), alg is exactly algStr.
	_, payload, err := jose.Verify(alg, pub, raw)
	if err != nil {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: signature verification failed", i), err)
	}

	var body struct {
		Iss   string `json:"iss"`
		Aud   string `json:"aud"`
		Iat   int64  `json:"iat"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: unmarshal body", i), err)
	}
	if body.Aud != iss.cfg.Issuer.String() {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: aud does not match this issuer", i), nil)
	}
	if body.Iat == 0 {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: iat is required", i), nil)
	}
	// auth.ClientID == "" here only ever means an explicit
	// ClientIDIntentionallyUnset (RequestCredential's own
	// requireClientIDDecision already rejected any other empty
	// case before this ever runs) — this check is deliberately
	// skipped for that acknowledged deployment choice, not by
	// silent default.
	if body.Iss != "" && auth.ClientID != "" && body.Iss != auth.ClientID {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: iss does not match the authenticated client", i), nil)
	}
	return pub, jwkRaw, body.Nonce, nil
}

// resolveProofBindingKey resolves a jwt-type key proof's own binding
// key from header: "jwk" directly (see jwkHeaderKey), or "kid"/"x5c"
// via Dependencies.ProofBindingKeys when configured (Appendix F.1's
// own "MUST NOT be present if [another] is present" means exactly one
// of the three is ever expected). A resolved kid/x5c key is
// re-marshaled as a JWK for resolvedKey.JWKRaw — cnf.jwk (RFC 7800)
// needs a JWK either way, regardless of how the Wallet originally
// conveyed the key.
//
// The returned jose.Alg is header's own "alg" claim for a jwk-conveyed
// key (self-asserted — a jwk proof establishes possession of a
// freshly-presented key, not trust in a pre-vetted one, the same model
// wallet's own DPoP proofs use) but ProofBindingKeys' own resolved
// algorithm for a kid/x5c-conveyed key, never header's claim — see
// ProofBindingKeyResolver's own doc comment for why trusting the
// resolver's algorithm, not the header's, matters there.
func (iss *Issuer) resolveProofBindingKey(ctx context.Context, header map[string]any) (crypto.PublicKey, jose.Alg, json.RawMessage, error) {
	_, hasJWK := header["jwk"]
	_, hasKID := header["kid"]
	_, hasX5C := header["x5c"]
	present := 0
	for _, has := range [...]bool{hasJWK, hasKID, hasX5C} {
		if has {
			present++
		}
	}
	if present != 1 {
		return nil, "", nil, fmt.Errorf("exactly one of jwk, kid or x5c is required")
	}

	if hasJWK {
		jwkRaw, err := jwkHeaderKey(header)
		if err != nil {
			return nil, "", nil, err
		}
		pub, err := jwk.ParsePublicKey(jwkRaw)
		if err != nil {
			return nil, "", nil, fmt.Errorf("parse jwk: %w", err)
		}
		algStr, _ := header["alg"].(string)
		return pub, jose.Alg(algStr), jwkRaw, nil
	}

	if iss.deps.ProofBindingKeys == nil {
		return nil, "", nil, fmt.Errorf("kid/x5c-based key resolution is not supported; use jwk")
	}
	pub, alg, err := iss.deps.ProofBindingKeys.ResolveProofBindingKey(ctx, header)
	if err != nil {
		return nil, "", nil, fmt.Errorf("resolve proof binding key: %w", err)
	}
	marshaled, err := jwk.Marshal(pub)
	if err != nil {
		return nil, "", nil, fmt.Errorf("marshal resolved key as jwk: %w", err)
	}
	jwkRaw, err := json.Marshal(marshaled)
	if err != nil {
		return nil, "", nil, fmt.Errorf("marshal resolved key as jwk: %w", err)
	}
	return pub, alg, jwkRaw, nil
}

// resolveAttestationProofKeys verifies every Key Attestation JWT in
// values (Appendix F.3): its signature, against the trust key
// Dependencies.AttestationVerifier resolves, and — the same
// once-per-request rule resolveJWTProofKeys applies — its nonce claim.
// Each verified attestation contributes one resolvedKey per entry in
// its own attested_keys claim (Appendix F.3's "SHOULD issue a
// Credential for each cryptographic public key") — a fan-out
// checkBatchSize's own cap on len(values) doesn't bound, since a
// single attestation JWT (up to jose.MaxCompactBytes) can still pack
// in enough small JWKs to force many real signing operations from one
// HTTP request with batch_size 1 (found in a repo-wide security
// review — the exact amplification checkBatchSize exists to prevent,
// through a side door). The running total across every attestation in
// values is capped at maxBatchSize independently, for that reason.
func (iss *Issuer) resolveAttestationProofKeys(ctx context.Context, values []string) ([]resolvedKey, error) {
	if iss.deps.AttestationVerifier == nil {
		return nil, newError(ErrorInvalidProof, 400, "attestation proof type is not supported", nil)
	}

	now := iss.deps.Clock.Now()
	nonceRequired := !iss.cfg.Endpoints.Nonce.IsZero()
	maxKeys := iss.maxBatchSize()
	var expectedNonce string
	var keys []resolvedKey

	for i, raw := range values {
		verified, err := iss.verifyOneAttestation(ctx, raw, i, now)
		if err != nil {
			return nil, err
		}

		if nonceRequired {
			if verified.Nonce == "" {
				return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: nonce is required", i), nil)
			}
			if i == 0 {
				if err := iss.consumeNonce(ctx, verified.Nonce); err != nil {
					return nil, err
				}
				expectedNonce = verified.Nonce
			} else if verified.Nonce != expectedNonce {
				return nil, newError(ErrorInvalidNonce, 400, fmt.Sprintf("attestation %d: nonce does not match the request's consumed nonce", i), nil)
			}
		}

		keys, err = appendAttestedKeys(keys, verified, i, maxKeys)
		if err != nil {
			return nil, err
		}
	}
	if len(keys) == 0 {
		return nil, newError(ErrorInvalidProof, 400, "no attested keys were found", nil)
	}
	return keys, nil
}

// verifyOneAttestation parses and verifies one Key Attestation JWT
// (its signature, against the trust key Dependencies.AttestationVerifier
// resolves) — split out of resolveAttestationProofKeys purely to keep
// it under the linter's own cognitive complexity ceiling.
func (iss *Issuer) verifyOneAttestation(ctx context.Context, raw string, i int, now time.Time) (attestation.VerifiedClaims, error) {
	parsed, err := attestation.Parse(raw)
	if err != nil {
		return attestation.VerifiedClaims{}, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d is malformed", i), err)
	}
	pub, alg, err := iss.deps.AttestationVerifier.ResolveAttestationKey(ctx, parsed)
	if err != nil {
		return attestation.VerifiedClaims{}, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: resolve trust key", i), err)
	}
	verified, err := parsed.Verify(pub, alg, attestation.VerifyOptions{Now: now})
	if err != nil {
		return attestation.VerifiedClaims{}, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: verification failed", i), err)
	}
	return verified, nil
}

// appendAttestedKeys appends one resolvedKey per entry in verified's
// own attested_keys claim to keys, enforcing maxKeys as a running total
// across every attestation in the request — split out of
// resolveAttestationProofKeys purely to keep it under the linter's own
// cognitive complexity ceiling.
func appendAttestedKeys(keys []resolvedKey, verified attestation.VerifiedClaims, i, maxKeys int) ([]resolvedKey, error) {
	for j, attestedKeyRaw := range verified.AttestedKeys {
		if len(keys) >= maxKeys {
			return nil, newError(ErrorInvalidProof, 400,
				fmt.Sprintf("attestation %d: attested_keys would yield more resolved keys than this issuer's own batch_size (%d) across the request", i, maxKeys), nil)
		}
		attestedPub, err := jwk.ParsePublicKey(attestedKeyRaw)
		if err != nil {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: attested_keys[%d]: parse jwk", i, j), err)
		}
		keys = append(keys, resolvedKey{Public: attestedPub, JWKRaw: json.RawMessage(attestedKeyRaw)})
	}
	return keys, nil
}

// consumeNonce consumes nonce via NonceStore and checks it hasn't
// expired, translating both failure modes into the invalid_nonce error
// code §8.3.1.2 defines.
func (iss *Issuer) consumeNonce(ctx context.Context, nonce string) error {
	record, err := iss.deps.Nonces.Consume(ctx, NonceConsumption{Nonce: nonce})
	if err != nil {
		return newError(ErrorInvalidNonce, 400, "nonce is unknown or already used", err)
	}
	if iss.deps.Clock.Now().After(record.ExpiresAt) {
		return newError(ErrorInvalidNonce, 400, "nonce has expired", nil)
	}
	return nil
}
