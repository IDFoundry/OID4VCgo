package wallet

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
)

// dpopProofTyp is DPoP's own required JOSE "typ" header (RFC 9449
// §4.2).
const dpopProofTyp = "dpop+jwt"

// dpopJTIEntropyBytes sets how much randomness backs a DPoP proof's
// own jti claim — RFC 9449 §4.2 requires it "created with enough
// entropy that the probability of an attacker guessing it is
// negligible." 128 bits.
const dpopJTIEntropyBytes = 16

// GenerateDPoPProof builds an RFC 9449 §4.2 DPoP proof for one HTTP
// request: header {typ: "dpop+jwt", jwk: signer's own public key},
// body {jti, htm, htu, iat[, nonce][, ath]}.
//
// RequestPreAuthorizedCodeToken calls this for its own Token Request,
// where ath is always "" (§4.3: ath is only meaningful "in conjunction
// with the presentation of an access token", which doesn't exist yet
// at the token endpoint). It's exported so a caller building its own
// sender-constrained requests for a pre-authorized_code-obtained
// access token — RequestCredential/RequestDeferredCredential/
// RequestNotification all just need *some* ProtectedResourceClient —
// can reuse this instead of reimplementing DPoP proof construction a
// second time; for that case, set ath to the base64url(SHA-256(access
// token)) digest RFC 9449 §4.3 defines. This package itself doesn't
// build that ProtectedResourceClient — see the package doc comment for
// why (the Authorization Code Flow's own resource requests go through
// fapigo/client's already-hardened (*client.Client).ProtectedResource
// instead, which this same reasoning doesn't apply to).
func (w *Wallet) GenerateDPoPProof(signer crypto.Signer, htm, htu, nonce, ath string) (string, error) {
	pub, err := jwk.Marshal(signer.Public())
	if err != nil {
		return "", fmt.Errorf("wallet: generate dpop proof: marshal jwk: %w", err)
	}
	header := map[string]any{"typ": dpopProofTyp, "jwk": pub}

	jti, err := w.randomToken(dpopJTIEntropyBytes)
	if err != nil {
		return "", fmt.Errorf("wallet: generate dpop proof: %w", err)
	}
	body := map[string]any{
		"jti": jti,
		"htm": htm,
		"htu": htu,
		"iat": w.deps.Clock.Now().Unix(),
	}
	if nonce != "" {
		body["nonce"] = nonce
	}
	if ath != "" {
		body["ath"] = ath
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("wallet: generate dpop proof: marshal payload: %w", err)
	}

	proof, err := jose.Sign(w.cfg.ProofSigningAlg, signer, header, payload)
	if err != nil {
		return "", fmt.Errorf("wallet: generate dpop proof: %w", err)
	}
	return proof, nil
}

// DPoPAccessTokenHash returns the "ath" claim value RFC 9449 §4.3
// defines for a DPoP proof accompanying accessToken: the base64url
// (no padding) encoding of the access token's own SHA-256 digest.
func DPoPAccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomToken returns n bytes of Dependencies.Random, base64url-encoded.
func (w *Wallet) randomToken(n int) (string, error) {
	if w.deps.Random == nil {
		return "", fmt.Errorf("random is not configured")
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(w.deps.Random, raw); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
