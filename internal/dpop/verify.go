package dpop

import (
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// proofTyp is DPoP's own required JOSE "typ" header (RFC 9449 §4.2) —
// the same constant wallet's own GenerateDPoPProof sets.
const proofTyp = "dpop+jwt"

// ReplayChecker records that a DPoP proof's own "jti" has been used,
// failing if it has already been seen — RFC 9449 §11.1's own MUST
// ("The server MUST reject any DPoP proof in which the jti has been
// seen before"). Implementations are expected to key storage by a
// namespaced digest of jti, not the raw value, but that adaptation is
// the caller's own responsibility so this package stays decoupled from
// any specific storage contract.
type ReplayChecker interface {
	UseOnce(ctx context.Context, jti string, expiresAt time.Time) error
}

// VerifyRequest describes one DPoP proof to verify.
type VerifyRequest struct {
	// Proof is the compact JWS presented in the DPoP header.
	Proof string

	// Method and URL are the HTTP method and target URI of the request
	// the proof was presented with — the proof's own "htm"/"htu"
	// claims must match them (RFC 9449 §4.3: htu is compared with its
	// own query/fragment ignored, so URL should already have neither,
	// matching wallet's own GenerateDPoPProof caller convention).
	Method string
	URL    string

	// Now is the time to validate the proof's own "iat" against.
	Now time.Time

	// MaxProofAge is how old (relative to Now) a proof's own "iat" may
	// be before it's rejected. Required — no implicit default.
	MaxProofAge time.Duration

	// MaxClockSkew bounds how far in the future (relative to Now) a
	// proof's own "iat" may be before it's rejected. Zero means no
	// tolerance for a future-dated proof.
	MaxClockSkew time.Duration

	// RequiredNonce, if non-empty, must equal the proof's own "nonce"
	// claim exactly (RFC 9449 §9's own nonce-challenge flow — the
	// server side of the retry wallet.RequestPreAuthorizedCodeToken
	// already implements client-side).
	RequiredNonce string

	// Replay detects proof replay by "jti" (RFC 9449 §11.1). Required:
	// there's no safe way for a server-side verifier to skip it.
	Replay ReplayChecker
}

// VerifiedProof is everything about a DPoP proof worth retaining once
// verified: the public key it was signed with (both as a
// crypto.PublicKey and its own RFC 7638 thumbprint, for binding an
// access token via its own "cnf" claim), when it was issued, and the
// proof's own "nonce" claim (empty if absent).
type VerifiedProof struct {
	PublicKey  crypto.PublicKey
	Thumbprint string
	IssuedAt   time.Time
	Nonce      string
}

// dpopClaims is the DPoP proof body's own wire shape (RFC 9449 §4.2).
type dpopClaims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	Nonce string `json:"nonce"`
}

// Verify checks a DPoP proof against req. On success, the returned
// VerifiedProof's Thumbprint identifies the key that produced it — the
// caller is responsible for deciding what to do with that (bind a
// freshly issued access token's own "cnf" to it; this package has no
// opinion on token issuance).
func Verify(ctx context.Context, req VerifyRequest) (VerifiedProof, error) {
	if err := validateVerifyRequest(req); err != nil {
		return VerifiedProof{}, err
	}

	header, _, err := jose.DecodeUnverified(req.Proof)
	if err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: %w", err)
	}
	pub, parsedJWK, err := resolveDPoPProofKey(header)
	if err != nil {
		return VerifiedProof{}, err
	}

	algStr, _ := header["alg"].(string)
	_, payload, err := jose.Verify(jose.Alg(algStr), pub, req.Proof)
	if err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: signature verification failed: %w", err)
	}

	var claims dpopClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: unmarshal claims: %w", err)
	}
	iat, err := validateDPoPClaims(claims, req)
	if err != nil {
		return VerifiedProof{}, err
	}

	if err := req.Replay.UseOnce(ctx, claims.JTI, iat.Add(req.MaxProofAge)); err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: replay check: %w", err)
	}

	thumbprint, err := parsedJWK.Thumbprint()
	if err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: %w", err)
	}
	return VerifiedProof{PublicKey: pub, Thumbprint: thumbprint, IssuedAt: iat, Nonce: claims.Nonce}, nil
}

// validateVerifyRequest checks req's own required fields — split out
// of Verify purely to keep it under the linter's own cognitive
// complexity ceiling.
func validateVerifyRequest(req VerifyRequest) error {
	if req.Method == "" {
		return fmt.Errorf("dpop: method is required")
	}
	if req.URL == "" {
		return fmt.Errorf("dpop: url is required")
	}
	if req.Now.IsZero() {
		return fmt.Errorf("dpop: now is required")
	}
	if req.MaxProofAge <= 0 {
		return fmt.Errorf("dpop: max_proof_age must be positive")
	}
	if req.Replay == nil {
		return fmt.Errorf("dpop: replay is required")
	}
	return nil
}

// resolveDPoPProofKey checks header's own "typ" and resolves its own
// "jwk" member into a usable public key — split out of Verify purely
// to keep it under the linter's own cognitive complexity ceiling.
func resolveDPoPProofKey(header map[string]any) (crypto.PublicKey, jwk.JWK, error) {
	if typ, _ := header["typ"].(string); typ != proofTyp {
		return nil, jwk.JWK{}, fmt.Errorf("dpop: typ is %q, want %q", header["typ"], proofTyp)
	}
	jwkVal, ok := header["jwk"]
	if !ok {
		return nil, jwk.JWK{}, fmt.Errorf("dpop: header is missing jwk")
	}
	jwkRaw, err := json.Marshal(jwkVal)
	if err != nil {
		return nil, jwk.JWK{}, fmt.Errorf("dpop: marshal jwk header: %w", err)
	}
	var parsedJWK jwk.JWK
	if err := json.Unmarshal(jwkRaw, &parsedJWK); err != nil {
		return nil, jwk.JWK{}, fmt.Errorf("dpop: unmarshal jwk header: %w", err)
	}
	pub, err := parsedJWK.PublicKey()
	if err != nil {
		return nil, jwk.JWK{}, fmt.Errorf("dpop: jwk header: %w", err)
	}
	return pub, parsedJWK, nil
}

// validateDPoPClaims checks claims against req (jti/htm/htu/iat/nonce)
// and returns the parsed iat — split out of Verify purely to keep it
// under the linter's own cognitive complexity ceiling.
func validateDPoPClaims(claims dpopClaims, req VerifyRequest) (time.Time, error) {
	if claims.JTI == "" {
		return time.Time{}, fmt.Errorf("dpop: jti is required")
	}
	if !strings.EqualFold(claims.HTM, req.Method) {
		return time.Time{}, fmt.Errorf("dpop: htm does not match")
	}
	htu, err := url.Parse(claims.HTU)
	if err != nil {
		return time.Time{}, fmt.Errorf("dpop: malformed htu")
	}
	want, err := url.Parse(req.URL)
	if err != nil {
		return time.Time{}, fmt.Errorf("dpop: malformed url")
	}
	if canonicalURI(htu) != canonicalURI(want) {
		return time.Time{}, fmt.Errorf("dpop: htu does not match")
	}
	if claims.IAT == 0 {
		return time.Time{}, fmt.Errorf("dpop: iat is required")
	}
	iat := time.Unix(claims.IAT, 0)
	if iat.After(req.Now.Add(req.MaxClockSkew)) {
		return time.Time{}, fmt.Errorf("dpop: iat is in the future")
	}
	if req.Now.Sub(iat) > req.MaxProofAge {
		return time.Time{}, fmt.Errorf("dpop: proof has expired")
	}
	if req.RequiredNonce != "" {
		if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(req.RequiredNonce)) != 1 {
			return time.Time{}, fmt.Errorf("dpop: nonce does not match")
		}
	}
	return iat, nil
}

// canonicalURI strips u's own query and fragment (RFC 9449 §4.3: "the
// query and fragment parts of the htu... are ignored").
func canonicalURI(u *url.URL) string {
	v := *u
	v.RawQuery, v.Fragment = "", ""
	return v.String()
}
