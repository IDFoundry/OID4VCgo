package issuer

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
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
//
// A proof carrying a key_attestation header (Appendix D.1, F.1) is
// resolved to the keys that attestation attests: see
// resolveKeyAttestationHeader. ptc.KeyAttestationsRequired makes the
// header required.
func (iss *Issuer) resolveJWTProofKeys(
	ctx context.Context, auth AuthorizedRequest, values []string, ptc oid4vci.ProofTypeConfiguration,
) ([]resolvedKey, error) {
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
		header, err := proofHeader(raw, i)
		if err != nil {
			return nil, err
		}
		keyAttestation, err := keyAttestationHeader(header, i)
		if err != nil {
			return nil, err
		}
		switch {
		case keyAttestation != "":
			attested, err := iss.resolveKeyAttestationHeader(ctx, keyAttestation, pub, expectedNonce, i, ptc)
			if err != nil {
				return nil, err
			}
			keys = appendUniqueKeys(keys, attested)
		case ptc.KeyAttestationsRequired != nil:
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: this credential_configuration_id requires a key_attestation header", i), nil)
		default:
			keyHeader, err := proofKeyHeader(header)
			if err != nil {
				return nil, err
			}
			// Not de-duplicated: checkDistinctKeys refuses one key proved
			// twice.
			keys = append(keys, resolvedKey{Public: pub, JWKRaw: jwkRaw, ProofKeyHeader: keyHeader})
		}
		// The running total, after every proof whatever its kind:
		// checkBatchSize bounds the number of proofs, not the keys a
		// key attestation adds, so proofs with and without one together
		// could otherwise resolve more keys than batch_size.
		if limit := iss.maxBatchSize(); len(keys) > limit {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: the key attestations attest more keys than this issuer's batch_size (%d)", i, limit), nil)
		}
	}
	return keys, nil
}

// proofHeader is jwt proof i's JOSE header. raw's signature is already
// verified, so its header is the Wallet's.
func proofHeader(raw string, i int) (map[string]any, error) {
	header, _, err := jose.DecodeUnverified(raw)
	if err != nil {
		return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d is malformed", i), err)
	}
	return header, nil
}

// proofKeyHeader is header, in JSON, when its proof conveys its key by
// kid or x5c, which Dependencies.ProofBindingKeys resolves, so a
// deferred issuance can resolve it again (resolvedKey.ProofKeyHeader);
// nil for a jwk-conveyed key, which carries no trust to re-check.
func proofKeyHeader(header map[string]any) (json.RawMessage, error) {
	_, hasKID := header["kid"]
	_, hasX5C := header["x5c"]
	if !hasKID && !hasX5C {
		return nil, nil
	}
	raw, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("issuer: proof key header: %w", err)
	}
	return raw, nil
}

// keyAttestationHeader is the key_attestation member of jwt proof i's
// header, "" when it has none.
func keyAttestationHeader(header map[string]any, i int) (string, error) {
	value, present := header["key_attestation"]
	if !present {
		return "", nil
	}
	compact, ok := value.(string)
	if !ok || compact == "" {
		return "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: key_attestation isn't a JWT", i), nil)
	}
	return compact, nil
}

// resolveKeyAttestationHeader verifies the key attestation a jwt proof
// carries in its key_attestation header (Appendix D.1, F.1) and returns
// the keys it attests:
//   - its signature, by a key Dependencies.AttestationVerifier trusts,
//     with an alg in proof_signing_alg_values_supported (F.1);
//   - its exp, which D.1 requires "if the attestation is used with the
//     JWT proof type";
//   - its nonce, which must be the c_nonce the proof itself carried
//     (F.1: "the nonce claim in the key attestation MUST be set to a
//     server-provided c_nonce"), or, without a Nonce Endpoint, its iat
//     within Limits.MaxProofAge;
//   - that the proof is "signed by a key contained in the attestation"
//     (D.1);
//   - key_attestations_required, and its status, after its freshness.
func (iss *Issuer) resolveKeyAttestationHeader(
	ctx context.Context, compact string, proofKey crypto.PublicKey, nonce string, i int, ptc oid4vci.ProofTypeConfiguration,
) ([]resolvedKey, error) {
	if iss.deps.AttestationVerifier == nil {
		return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: key_attestation isn't supported by this issuer", i), nil)
	}
	signed, err := iss.verifyOneAttestation(ctx, compact, i, iss.deps.Clock.Now(), ptc.ProofSigningAlgValuesSupported)
	if err != nil {
		return nil, err
	}
	verified := signed.Claims
	if verified.ExpiresAt == nil {
		return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: its key_attestation has no exp, which the jwt proof type requires (Appendix D.1)", i), nil)
	}
	if !iss.cfg.Endpoints.Nonce.IsZero() && verified.Nonce != nonce {
		return nil, newError(ErrorInvalidNonce, 400, fmt.Sprintf("proof %d: its key_attestation's nonce isn't the proof's c_nonce", i), nil)
	}
	if err := iss.checkProofAge(verified.IssuedAt.Unix(), i); err != nil {
		return nil, err
	}
	attested, err := verified.KeyAttested(proofKey)
	if err != nil || !attested {
		return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d isn't signed by a key its key_attestation attests (Appendix D.1)", i), err)
	}
	if err := meetsKeyAttestationRequirement(verified, ptc.KeyAttestationsRequired, i); err != nil {
		return nil, err
	}
	if err := iss.requestAttestationStatus(ctx, signed, fmt.Sprintf("proof %d", i)); err != nil {
		return nil, err
	}
	return appendAttestedKeys(nil, verified, compact, i, iss.maxBatchSize())
}

// appendUniqueKeys appends each of add to keys unless keys already has
// it: a Wallet sending one jwt proof per attested key may repeat the
// key attestation in each.
func appendUniqueKeys(keys, add []resolvedKey) []resolvedKey {
	for _, k := range add {
		if !slices.ContainsFunc(keys, func(have resolvedKey) bool { return bytes.Equal(have.JWKRaw, k.JWKRaw) }) {
			keys = append(keys, k)
		}
	}
	return keys
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
	if err != nil && trustUndecided(err) {
		// As for a key attestation's signer (verifyOneAttestation): the
		// certificate's revocation couldn't be decided, a server error.
		return nil, nil, "", fmt.Errorf("issuer: proof %d: its key's trust can't be decided now: %w", i, err)
	}
	if err != nil {
		// The resolver's own error — certificate subjects, a DID
		// method's upstream message — stays the cause, not the Wallet's
		// error_description.
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: its key couldn't be resolved or isn't trusted", i), err)
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
		Iss   string   `json:"iss"`
		Aud   string   `json:"aud"`
		Iat   *float64 `json:"iat"` // a NumericDate, which may be fractional (RFC 7519 §2)
		Nonce string   `json:"nonce"`
	}
	// Exact member names (strictjson): of "aud" and "AUD", encoding/json
	// would read the last, where an exact-match parser reads "aud".
	if err := strictjson.Unmarshal(payload, &body); err != nil {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: unmarshal body", i), err)
	}
	if body.Aud != iss.cfg.Issuer.String() {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: aud does not match this issuer", i), nil)
	}
	if body.Iat == nil || *body.Iat == 0 {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: iat is required", i), nil)
	}
	issued, err := jwtdate.FromFloat(*body.Iat)
	if err != nil {
		return nil, nil, "", newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: iat", i), err)
	}
	if err := iss.checkProofAge(issued.Unix(), i); err != nil {
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
	// Times compared, not a negated age: that overflows for an iat far
	// in the future, which would then be replayable indefinitely.
	issued, err := jwtdate.FromUnix(iat)
	now, window := iss.deps.Clock.Now(), iss.cfg.Limits.MaxProofAge
	if err != nil || issued.After(now.Add(window)) || issued.Before(now.Add(-window)) {
		return newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: iat is outside the accepted window of %s", i, window), nil)
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
	pub, alg, err := iss.deps.ProofBindingKeys.ResolveProofBindingKey(certchain.WithTime(ctx, iss.deps.Clock.Now()), header)
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
	if len(values) != 1 {
		// Appendix F.3: the proofs object carries exactly one key
		// attestation, which attests every key.
		return nil, newError(ErrorInvalidProof, 400, "the attestation proof type takes exactly one key attestation", nil)
	}

	now := iss.deps.Clock.Now()
	maxKeys := iss.maxBatchSize()
	var expectedNonce string
	var keys []resolvedKey

	for i, raw := range values {
		signed, err := iss.verifyOneAttestation(ctx, raw, i, now, ptc.ProofSigningAlgValuesSupported)
		if err != nil {
			return nil, err
		}
		verified := signed.Claims
		// Freshness first: a replayed attestation is refused before its
		// status is fetched, which would otherwise cost a Status List
		// fetch for each replay of any attestation ever issued.
		if err := iss.checkProofNonce(ctx, "attestation", i, verified.Nonce, &expectedNonce); err != nil {
			return nil, err
		}
		// Without a Nonce Endpoint, the attestation's iat is its only
		// freshness (Appendix F.4), as a jwt proof's is.
		if err := iss.checkProofAge(verified.IssuedAt.Unix(), i); err != nil {
			return nil, err
		}
		if err := meetsKeyAttestationRequirement(verified, ptc.KeyAttestationsRequired, i); err != nil {
			return nil, err
		}
		if err := iss.requestAttestationStatus(ctx, signed, fmt.Sprintf("attestation %d", i)); err != nil {
			return nil, err
		}
		keys, err = appendAttestedKeys(keys, verified, raw, i, maxKeys)
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
func (iss *Issuer) verifyOneAttestation(ctx context.Context, raw string, i int, now time.Time, algs []string) (VerifiedKeyAttestation, error) {
	parsed, err := attestation.Parse(raw)
	if err != nil {
		return VerifiedKeyAttestation{}, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d is malformed", i), err)
	}
	pub, alg, err := iss.deps.AttestationVerifier.ResolveAttestationKey(certchain.WithTime(ctx, iss.deps.Clock.Now()), parsed)
	if err != nil {
		if trustUndecided(err) {
			// Not the Wallet's fault, nor a verdict on its keys: a
			// server error, which it retries, rather than invalid_proof.
			return VerifiedKeyAttestation{}, fmt.Errorf("issuer: attestation %d: its signer's trust can't be decided now: %w", i, err)
		}
		return VerifiedKeyAttestation{}, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: resolve trust key", i), err)
	}
	if !slices.Contains(algs, string(alg)) {
		return VerifiedKeyAttestation{}, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: alg %q is not in proof_signing_alg_values_supported", i, alg), nil)
	}
	verified, err := parsed.Verify(pub, alg, attestation.VerifyOptions{Now: now})
	if err != nil {
		return VerifiedKeyAttestation{}, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: verification failed", i), err)
	}
	return VerifiedKeyAttestation{Claims: verified, SignerKey: pub, SignerCertificates: signerCertificates(parsed, pub)}, nil
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

func appendAttestedKeys(keys []resolvedKey, verified attestation.VerifiedClaims, compact string, i, maxKeys int) ([]resolvedKey, error) {
	for j, attestedKeyRaw := range verified.AttestedKeys {
		if len(keys) >= maxKeys {
			return nil, newError(ErrorInvalidProof, 400,
				fmt.Sprintf("attestation %d: attested_keys would yield more resolved keys than this issuer's own batch_size (%d) across the request", i, maxKeys), nil)
		}
		key, err := bindingKeyFromJWK(attestedKeyRaw)
		if err != nil {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: attested_keys[%d]: parse jwk", i, j), err)
		}
		key.KeyAttestation = compact
		keys = append(keys, key)
	}
	return keys, nil
}

// checkAttestationStatus runs Dependencies.AttestationStatus, when set,
// on a verified key attestation.
func (iss *Issuer) checkAttestationStatus(ctx context.Context, verified VerifiedKeyAttestation) error {
	if iss.deps.AttestationStatus == nil {
		return nil
	}
	return iss.deps.AttestationStatus.CheckAttestationStatus(ctx, verified)
}

// requestAttestationStatus is checkAttestationStatus for a Credential
// Request's key attestation, what naming it in errors: invalid_proof
// for one the checker refuses (ErrKeyAttestationRevoked), and a server
// error for a status it couldn't determine, so the Wallet retries
// rather than giving up keys that may well be valid — the split
// fapigo/server makes for a Wallet Attestation's status.
func (iss *Issuer) requestAttestationStatus(ctx context.Context, verified VerifiedKeyAttestation, what string) error {
	err := iss.checkAttestationStatus(ctx, verified)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrKeyAttestationRevoked):
		return newError(ErrorInvalidProof, 400, what+": key_attestation status", err)
	default:
		return fmt.Errorf("issuer: %s: key attestation status can't be checked now: %w", what, err)
	}
}

// trustUndecided reports whether err, from Dependencies.AttestationVerifier,
// says a key attestation's signer couldn't be judged now, rather than
// that it isn't trusted: a revocation check that couldn't decide
// (certrevocation.ErrNoCurrentCRL, or any error but
// certrevocation.ErrRevoked from an X5CAttestationVerifier's
// Revocation) or a context that ended. A revoked certificate, an
// untrusted chain or anything else is a refusal.
func trustUndecided(err error) bool {
	if errors.Is(err, certrevocation.ErrRevoked) {
		return false
	}
	return errors.Is(err, certchain.ErrRevocationUndecided) || errors.Is(err, certrevocation.ErrNoCurrentCRL) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// consumeNonce consumes nonce via NonceStore and checks it hasn't
// expired, translating an unknown or used nonce (ErrNonceUnknown) and
// an expired one into the invalid_nonce error code §8.3.1.2 defines,
// as it does a nonce another Credential Issuer sharing the store issued
// (NonceConsumption.Owner).
// Any other store error is the store's, not the Wallet's: a plain
// error, a 500.
func (iss *Issuer) consumeNonce(ctx context.Context, nonce string) error {
	record, err := iss.deps.Nonces.Consume(ctx, NonceConsumption{Nonce: nonce, Owner: iss.storeOwner()})
	if errors.Is(err, ErrNonceUnknown) {
		return newError(ErrorInvalidNonce, 400, "nonce is unknown or already used", err)
	}
	if err != nil {
		return fmt.Errorf("issuer: consume c_nonce: %w", err)
	}
	if !iss.owns(record.Owner) {
		// A store that ignored consumption.Owner, or dropped Owner.
		return newError(ErrorInvalidNonce, 400, "nonce is unknown or already used", errors.New("the c_nonce isn't this Credential Issuer's"))
	}
	if iss.deps.Clock.Now().After(record.ExpiresAt) {
		return newError(ErrorInvalidNonce, 400, "nonce has expired", nil)
	}
	return nil
}
