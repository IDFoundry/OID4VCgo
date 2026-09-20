package sdjwtvc

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// KeyBindingClaims is the input to NewKeyBindingJWT (RFC 9901 §4.3).
type KeyBindingClaims struct {
	Audience string // REQUIRED
	Nonce    string // REQUIRED
	Extra    map[string]any
}

// NewKeyBindingJWT signs a Key Binding JWT over presentation using
// signer/alg. signer must correspond to the public key the Issuer
// published in the SD-JWT's cnf claim (RFC 9901 §4.1.2) — that's the
// key a Verifier checks against (§4.3.2).
func NewKeyBindingJWT(signer crypto.Signer, alg jose.Alg, presentation Presentation, hashAlg HashAlg, claims KeyBindingClaims) (string, error) {
	if claims.Audience == "" || claims.Nonce == "" {
		return "", fmt.Errorf("sdjwtvc: KeyBindingClaims.Audience and Nonce are required")
	}
	sdHash, err := presentation.SDHash(hashAlg)
	if err != nil {
		return "", err
	}

	payload := make(map[string]any, len(claims.Extra)+4)
	for k, v := range claims.Extra {
		payload[k] = v
	}
	payload["iat"] = time.Now().Unix()
	payload["aud"] = claims.Audience
	payload["nonce"] = claims.Nonce
	payload["sd_hash"] = sdHash

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("sdjwtvc: marshal key binding claims: %w", err)
	}
	kbJWT, err := jose.Sign(alg, signer, map[string]any{"typ": KeyBindingTyp}, raw)
	if err != nil {
		return "", fmt.Errorf("sdjwtvc: sign key binding JWT: %w", err)
	}
	return kbJWT, nil
}

// KeyBindingCheck configures VerifyKeyBindingJWT.
type KeyBindingCheck struct {
	ExpectedAudience string
	ExpectedNonce    string
	ExpectedSDHash   string

	// MaxAge rejects a Key Binding JWT whose iat is further than MaxAge
	// from now, in EITHER direction — too far in the past (RFC 9901
	// §7.3 step 5.e) or claiming to be issued in the future (a
	// forward-dated iat is just as clearly not "the current time" as a
	// stale one; confirmed live against the OIDF conformance suite's
	// own kb-jwt-iat-in-future negative test that a purely
	// past-looking check silently accepts it — a negative "age" is
	// never greater than a positive MaxAge). Now defaults to time.Now.
	// REQUIRED (must be positive): VerifyKeyBindingJWT rejects the Go
	// zero value rather than silently treating "unset" as "no
	// freshness check at all" — a caller that left this unset would
	// otherwise accept an old-but-otherwise-valid Key Binding JWT for
	// the same transaction indefinitely (aud/nonce/sd_hash still all
	// have to match exactly, so this was never a primary bypass, but
	// it was a real defense-in-depth gap for anyone who expected
	// "unset" to mean "sensible default" rather than "off" — found
	// comparing this package's own trust-boundary DX against FAPIgo's).
	MaxAge time.Duration
	Now    func() time.Time
}

// VerifyKeyBindingJWT validates a Key Binding JWT per RFC 9901 §7.3
// steps 5.b-5.h against the holder's public key and check's
// expectations, returning its claims.
func VerifyKeyBindingJWT(kbJWT string, holderPub crypto.PublicKey, alg jose.Alg, check KeyBindingCheck) (map[string]any, error) {
	if check.MaxAge <= 0 {
		return nil, fmt.Errorf("sdjwtvc: KeyBindingCheck.MaxAge is required (must be positive)")
	}
	header, raw, err := jose.Verify(alg, holderPub, kbJWT)
	if err != nil {
		return nil, fmt.Errorf("sdjwtvc: verify key binding JWT signature: %w", err)
	}
	if typ, _ := header["typ"].(string); typ != KeyBindingTyp {
		return nil, fmt.Errorf("sdjwtvc: key binding JWT typ is %q, want %q", typ, KeyBindingTyp)
	}

	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("sdjwtvc: unmarshal key binding claims: %w", err)
	}

	if aud, _ := claims["aud"].(string); aud != check.ExpectedAudience {
		return nil, fmt.Errorf("sdjwtvc: key binding JWT aud does not match the expected audience")
	}
	if nonce, _ := claims["nonce"].(string); nonce != check.ExpectedNonce {
		return nil, fmt.Errorf("sdjwtvc: key binding JWT nonce does not match the expected value")
	}
	if sdHash, _ := claims["sd_hash"].(string); sdHash != check.ExpectedSDHash {
		return nil, fmt.Errorf("sdjwtvc: key binding JWT sd_hash does not match the presented SD-JWT")
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		return nil, fmt.Errorf("sdjwtvc: key binding JWT iat claim is missing or not a number")
	}
	now := time.Now
	if check.Now != nil {
		now = check.Now
	}
	issued := time.Unix(int64(iat), 0)
	age := now().Sub(issued)
	if age < 0 {
		if -age > check.MaxAge {
			return nil, fmt.Errorf("sdjwtvc: key binding JWT iat is too far in the future (issued %s from now)", -age)
		}
		return claims, nil
	}
	if age > check.MaxAge {
		return nil, fmt.Errorf("sdjwtvc: key binding JWT is too old (issued %s ago)", age)
	}
	return claims, nil
}
