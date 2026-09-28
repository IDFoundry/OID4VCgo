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
	for i, raw := range values {
		pub, jwkRaw, nonce, err := iss.verifyJWTProof(ctx, auth, raw, i, ptc)
		if err != nil {
			return nil, err
		}
		if err := iss.checkProofNonce(ctx, "proof", i, nonce, &expectedNonce); err != nil {
			return nil, err
		}
		keys = append(keys, resolvedKey{Public: pub, JWKRaw: jwkRaw})
	}
	return keys, nil
}

// checkProofNonce applies the c_nonce rule to proof (or attestation) i
// of a request, when this issuer has a Nonce Endpoint: every proof must
// carry a nonce; the first one's is consumed, and every later proof
// must carry that same value (*expected, set from the first) — once per
// request, not once per proof, as NonceStore's own doc comment
// requires. what names the proof kind in errors.
func (iss *Issuer) checkProofNonce(ctx context.Context, what string, i int, nonce string, expected *string) error {
	if iss.cfg.Endpoints.Nonce.IsZero() {
		return nil
	}
	if nonce == "" {
		return newError(ErrorInvalidProof, 400, fmt.Sprintf("%s %d: nonce is required", what, i), nil)
	}
	if i == 0 {
		if err := iss.consumeNonce(ctx, nonce); err != nil {
			return err
		}
		*expected = nonce
		return nil
	}
	if nonce != *expected {
		return newError(ErrorInvalidNonce, 400, fmt.Sprintf("%s %d: nonce does not match the request's consumed nonce", what, i), nil)
	}
	return nil
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
	if err := iss.checkProofAge(body.Iat, i); err != nil {
		return nil, nil, "", err
	}
	// auth.ClientID() == "" here only ever means an explicit
	// NoClientIdentity (RequestCredential's own
	// requireClientIdentityDecision already rejected any other empty
	// case before this ever runs) — this check is deliberately
	// skipped for that acknowledged deployment choice, not by
	// silent default.
	if clientID := auth.ClientID(); body.Iss != "" && clientID != "" && body.Iss != clientID {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: iss does not match the authenticated client", i), nil)
	}
	return pub, jwkRaw, body.Nonce, nil
}

// resolveProofBindingKey resolves a jwt-type key proof's own binding
// key from header: "jwk" directly (see jwkHeaderKey), or "kid"/"x5c"
// via Dependencies.ProofBindingKeys when configured (Appendix F.1's
// own "MUST NOT be present if [another] is present" means exactly one
// of the three is ever expected). The key is re-marshaled as a JWK for
// resolvedKey.JWKRaw however it was conveyed — cnf.jwk (RFC 7800) needs
// a JWK either way, and re-encoding a jwk header too keeps anything
// else in it out of the signed credential. A jwk header carrying a
// private key is refused (Appendix F.4).
//
// The returned jose.Alg is header's own "alg" claim for a jwk-conveyed
// key (self-asserted — a jwk proof establishes possession of a
// freshly-presented key, not trust in a pre-vetted one, the same model
// wallet's own DPoP proofs use) but ProofBindingKeys' own resolved
// algorithm for a kid/x5c-conveyed key, never header's claim — see
// ProofBindingKeyResolver's own doc comment for why trusting the
// resolver's algorithm, not the header's, matters there.
// checkProofAge bounds a jwt proof's iat to Limits.MaxProofAge either
// side of Now when there is no Nonce Endpoint — without one, nothing
// else dates the proof, and it could be replayed indefinitely (Appendix
// F.4). With one, checkProofNonce's consumed c_nonce does.
func (iss *Issuer) checkProofAge(iat int64, i int) error {
	if !iss.cfg.Endpoints.Nonce.IsZero() {
		return nil
	}
	age := iss.deps.Clock.Now().Sub(time.Unix(iat, 0))
	if age > iss.cfg.Limits.MaxProofAge || -age > iss.cfg.Limits.MaxProofAge {
		return newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: iat is outside the accepted window of %s", i, iss.cfg.Limits.MaxProofAge), nil)
	}
	return nil
}

func (iss *Issuer) resolveProofBindingKey(ctx context.Context, header map[string]any) (crypto.PublicKey, jose.Alg, json.RawMessage, error) {
	pub, alg, err := iss.resolveProofKey(ctx, header)
	if err != nil {
		return nil, "", nil, err
	}
	// cnf.jwk is re-encoded from the resolved key, however the Wallet
	// conveyed it, so nothing else it put in a jwk header ends up inside
	// the credential this issuer signs.
	jwkRaw, err := publicJWK(pub)
	if err != nil {
		return nil, "", nil, err
	}
	return pub, alg, jwkRaw, nil
}

// resolveProofKey finds the proof's key from exactly one of its jwk,
// kid or x5c header parameters.
func (iss *Issuer) resolveProofKey(ctx context.Context, header map[string]any) (crypto.PublicKey, jose.Alg, error) {
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
		return nil, "", fmt.Errorf("exactly one of jwk, kid or x5c is required")
	}

	if hasJWK {
		jwkRaw, err := jwkHeaderKey(header)
		if err != nil {
			return nil, "", err
		}
		pub, err := jwk.ParsePublicKey(jwkRaw)
		if err != nil {
			return nil, "", fmt.Errorf("parse jwk: %w", err)
		}
		algStr, _ := header["alg"].(string)
		return pub, jose.Alg(algStr), nil
	}

	if iss.deps.ProofBindingKeys == nil {
		return nil, "", fmt.Errorf("kid/x5c-based key resolution is not supported; use jwk")
	}
	pub, alg, err := iss.deps.ProofBindingKeys.ResolveProofBindingKey(ctx, header)
	if err != nil {
		return nil, "", fmt.Errorf("resolve proof binding key: %w", err)
	}
	return pub, alg, nil
}

// publicJWK encodes pub as the JWK a credential's holder binding
// carries (cnf.jwk, RFC 7800): its public members only.
func publicJWK(pub crypto.PublicKey) (json.RawMessage, error) {
	marshaled, err := jwk.Marshal(pub)
	if err != nil {
		return nil, fmt.Errorf("binding key: %w", err)
	}
	return json.Marshal(marshaled)
}

// bindingKeyFromJWK parses raw, a public JWK, into a resolvedKey whose
// JWKRaw is re-encoded from it (publicJWK).
func bindingKeyFromJWK(raw []byte) (resolvedKey, error) {
	pub, err := jwk.ParsePublicKey(raw)
	if err != nil {
		return resolvedKey{}, err
	}
	canonical, err := publicJWK(pub)
	return resolvedKey{Public: pub, JWKRaw: canonical}, err
}

// resolveAttestationProofKeys verifies every Key Attestation JWT in
// values (Appendix F.3): its signature, against the trust key
// Dependencies.AttestationVerifier resolves, with an algorithm ptc
// advertises, and — the same once-per-request rule resolveJWTProofKeys
// applies — its nonce claim.
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
func (iss *Issuer) resolveAttestationProofKeys(ctx context.Context, values []string, ptc oid4vci.ProofTypeConfiguration) ([]resolvedKey, error) {
	if iss.deps.AttestationVerifier == nil {
		return nil, newError(ErrorInvalidProof, 400, "attestation proof type is not supported", nil)
	}

	now := iss.deps.Clock.Now()
	maxKeys := iss.maxBatchSize()
	var expectedNonce string
	var keys []resolvedKey

	for i, raw := range values {
		verified, err := iss.verifyOneAttestation(ctx, raw, i, now, ptc.ProofSigningAlgValuesSupported)
		if err != nil {
			return nil, err
		}
		if err := meetsKeyAttestationRequirement(verified, ptc.KeyAttestationsRequired, i); err != nil {
			return nil, err
		}
		if iss.deps.AttestationStatus != nil {
			if err := iss.deps.AttestationStatus.CheckAttestationStatus(ctx, verified); err != nil {
				return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: status", i), err)
			}
		}
		if err := iss.checkProofNonce(ctx, "attestation", i, verified.Nonce, &expectedNonce); err != nil {
			return nil, err
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
//
// The resolved key's algorithm must be one of algs, the proof type's
// proof_signing_alg_values_supported: Appendix F.3's "the value of the
// alg JWT header of the key attestation MUST match one of the entries
// in the proof_signing_alg_values_supported metadata parameter".
// Checking the resolved algorithm covers the header too, since Verify
// then requires the header's alg to equal it.
func (iss *Issuer) verifyOneAttestation(ctx context.Context, raw string, i int, now time.Time, algs []string) (attestation.VerifiedClaims, error) {
	parsed, err := attestation.Parse(raw)
	if err != nil {
		return attestation.VerifiedClaims{}, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d is malformed", i), err)
	}
	pub, alg, err := iss.deps.AttestationVerifier.ResolveAttestationKey(ctx, parsed)
	if err != nil {
		return attestation.VerifiedClaims{}, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: resolve trust key", i), err)
	}
	if !slices.Contains(algs, string(alg)) {
		return attestation.VerifiedClaims{}, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: alg %q is not in proof_signing_alg_values_supported", i, alg), nil)
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
// meetsKeyAttestationRequirement checks a key attestation asserts at
// least one of the key_storage and user_authentication levels this
// issuer accepts (key_attestations_required, OID4VCI 1.0 §12.2.4 and
// Appendix D.2), for each the issuer constrains. An attestation that
// asserts no level for a constrained one doesn't meet it.
func meetsKeyAttestationRequirement(verified attestation.VerifiedClaims, req *oid4vci.KeyAttestationRequirement, i int) error {
	if req == nil {
		return nil
	}
	for _, c := range []struct {
		name     string
		accepted []string
		asserted []attestation.AttackPotentialResistance
	}{
		{"key_storage", req.KeyStorage, verified.KeyStorage},
		{"user_authentication", req.UserAuthentication, verified.UserAuthentication},
	} {
		if len(c.accepted) == 0 {
			continue
		}
		if !slices.ContainsFunc(c.asserted, func(level attestation.AttackPotentialResistance) bool {
			return slices.Contains(c.accepted, string(level))
		}) {
			return newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: %s %v meets none of the accepted levels %v", i, c.name, c.asserted, c.accepted), nil)
		}
	}
	return nil
}

func appendAttestedKeys(keys []resolvedKey, verified attestation.VerifiedClaims, i, maxKeys int) ([]resolvedKey, error) {
	for j, attestedKeyRaw := range verified.AttestedKeys {
		if len(keys) >= maxKeys {
			return nil, newError(ErrorInvalidProof, 400,
				fmt.Sprintf("attestation %d: attested_keys would yield more resolved keys than this issuer's own batch_size (%d) across the request", i, maxKeys), nil)
		}
		key, err := bindingKeyFromJWK(attestedKeyRaw)
		if err != nil {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: attested_keys[%d]: parse jwk", i, j), err)
		}
		keys = append(keys, key)
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
