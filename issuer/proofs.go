package issuer

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcigo/attestation"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
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
	ctx context.Context, auth AuthorizedRequest, values []string, ptc ProofTypeConfiguration,
) ([]resolvedKey, error) {
	if ptc.KeyAttestationsRequired != nil {
		return nil, newError(ErrorInvalidCredentialRequest, 400,
			"this credential_configuration_id requires a key attestation on the jwt proof type, which is not supported", nil)
	}

	keys := make([]resolvedKey, 0, len(values))
	var expectedNonce string
	nonceRequired := !iss.cfg.Endpoints.Nonce.IsZero()

	for i, raw := range values {
		header, _, err := jose.DecodeUnverified(raw)
		if err != nil {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d is malformed", i), err)
		}
		if typ, _ := header["typ"].(string); typ != jwtProofTyp {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d has typ %q, want %q", i, typ, jwtProofTyp), nil)
		}
		algStr, _ := header["alg"].(string)
		if !slices.Contains(ptc.ProofSigningAlgValuesSupported, algStr) {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d alg %q is not supported", i, algStr), nil)
		}
		pub, jwkRaw, err := iss.resolveProofBindingKey(ctx, header)
		if err != nil {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: %v", i, err), nil)
		}

		_, payload, err := jose.Verify(jose.Alg(algStr), pub, raw)
		if err != nil {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: signature verification failed", i), err)
		}

		var body struct {
			Iss   string `json:"iss"`
			Aud   string `json:"aud"`
			Iat   int64  `json:"iat"`
			Nonce string `json:"nonce"`
		}
		if err := json.Unmarshal(payload, &body); err != nil {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: unmarshal body", i), err)
		}
		if body.Aud != iss.cfg.Issuer.String() {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: aud does not match this issuer", i), nil)
		}
		if body.Iat == 0 {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: iat is required", i), nil)
		}
		if body.Iss != "" && auth.ClientID != "" && body.Iss != auth.ClientID {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: iss does not match the authenticated client", i), nil)
		}

		if nonceRequired {
			if body.Nonce == "" {
				return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("proof %d: nonce is required", i), nil)
			}
			if i == 0 {
				if err := iss.consumeNonce(ctx, body.Nonce); err != nil {
					return nil, err
				}
				expectedNonce = body.Nonce
			} else if body.Nonce != expectedNonce {
				return nil, newError(ErrorInvalidNonce, 400, fmt.Sprintf("proof %d: nonce does not match the request's consumed nonce", i), nil)
			}
		}

		keys = append(keys, resolvedKey{Public: pub, JWKRaw: jwkRaw})
	}
	return keys, nil
}

// resolveProofBindingKey resolves a jwt-type key proof's own binding
// key from header: "jwk" directly (see jwkHeaderKey), or "kid"/"x5c"
// via Dependencies.ProofBindingKeys when configured (Appendix F.1's
// own "MUST NOT be present if [another] is present" means exactly one
// of the three is ever expected). A resolved kid/x5c key is
// re-marshaled as a JWK for resolvedKey.JWKRaw — cnf.jwk (RFC 7800)
// needs a JWK either way, regardless of how the Wallet originally
// conveyed the key.
func (iss *Issuer) resolveProofBindingKey(ctx context.Context, header map[string]any) (crypto.PublicKey, json.RawMessage, error) {
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
		return nil, nil, fmt.Errorf("exactly one of jwk, kid or x5c is required")
	}

	if hasJWK {
		jwkRaw, err := jwkHeaderKey(header)
		if err != nil {
			return nil, nil, err
		}
		pub, err := jwk.ParsePublicKey(jwkRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse jwk: %w", err)
		}
		return pub, jwkRaw, nil
	}

	if iss.deps.ProofBindingKeys == nil {
		return nil, nil, fmt.Errorf("kid/x5c-based key resolution is not supported; use jwk")
	}
	pub, err := iss.deps.ProofBindingKeys.ResolveProofBindingKey(ctx, header)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve proof binding key: %w", err)
	}
	marshaled, err := jwk.Marshal(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal resolved key as jwk: %w", err)
	}
	jwkRaw, err := json.Marshal(marshaled)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal resolved key as jwk: %w", err)
	}
	return pub, jwkRaw, nil
}

// resolveAttestationProofKeys verifies every Key Attestation JWT in
// values (Appendix F.3): its signature, against the trust key
// Dependencies.AttestationVerifier resolves, and — the same
// once-per-request rule resolveJWTProofKeys applies — its nonce claim.
// Each verified attestation contributes one resolvedKey per entry in
// its own attested_keys claim (Appendix F.3's "SHOULD issue a
// Credential for each cryptographic public key").
func (iss *Issuer) resolveAttestationProofKeys(ctx context.Context, values []string) ([]resolvedKey, error) {
	if iss.deps.AttestationVerifier == nil {
		return nil, newError(ErrorInvalidProof, 400, "attestation proof type is not supported", nil)
	}

	now := iss.deps.Clock.Now()
	nonceRequired := !iss.cfg.Endpoints.Nonce.IsZero()
	var expectedNonce string
	var keys []resolvedKey

	for i, raw := range values {
		parsed, err := attestation.Parse(raw)
		if err != nil {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d is malformed", i), err)
		}
		pub, alg, err := iss.deps.AttestationVerifier.ResolveAttestationKey(ctx, parsed)
		if err != nil {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: resolve trust key", i), err)
		}
		verified, err := parsed.Verify(pub, alg, attestation.VerifyOptions{Now: now})
		if err != nil {
			return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: verification failed", i), err)
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

		for j, attestedKeyRaw := range verified.AttestedKeys {
			attestedPub, err := jwk.ParsePublicKey(attestedKeyRaw)
			if err != nil {
				return nil, newError(ErrorInvalidProof, 400, fmt.Sprintf("attestation %d: attested_keys[%d]: parse jwk", i, j), err)
			}
			keys = append(keys, resolvedKey{Public: attestedPub, JWKRaw: json.RawMessage(attestedKeyRaw)})
		}
	}
	if len(keys) == 0 {
		return nil, newError(ErrorInvalidProof, 400, "no attested keys were found", nil)
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
