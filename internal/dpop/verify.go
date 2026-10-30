package dpop

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// proofTyp is DPoP's own required JOSE "typ" header (RFC 9449 §4.2) —
// the same constant wallet's own GenerateDPoPProof sets. It's compared
// as a media type (jose.TypeIs).
const proofTyp = "dpop+jwt"

// MaxJTILength bounds a proof's "jti" in bytes. RFC 9449 §4.2 asks only
// for enough entropy to make a collision unlikely (a 96-bit random
// value is suggested), so anything longer is refused rather than
// verified and remembered.
const MaxJTILength = 256

// ReplayChecker records that a DPoP proof's own "jti" has been used,
// failing if it has already been seen — RFC 9449 §11.1's own MUST
// ("The server MUST reject any DPoP proof in which the jti has been
// seen before"). Verify passes it JTIDigest(jti), not the raw value,
// so what a checker remembers per proof is small and fixed-size
// whatever the client sent.
type ReplayChecker interface {
	UseOnce(ctx context.Context, jti string, expiresAt time.Time) error
}

// VerifyRequest describes one DPoP proof to verify.
type VerifyRequest struct {
	// Proof is the compact JWS presented in the DPoP header.
	Proof string

	// Method and URL are the HTTP method and target URI of the request
	// the proof was presented with — the proof's own "htm"/"htu"
	// claims must match them. URL must be an absolute http or https
	// URL. The two URIs are compared normalized (RFC 9449 §4.3, RFC 3986
	// §6.2.2-§6.2.3; see canonicalURI): query and fragment ignored,
	// scheme and host compared case-insensitively, a default port
	// dropped and dot segments removed.
	Method string
	URL    string

	// Now is the time to validate the proof's own "iat" against.
	Now time.Time

	// MaxProofAge is how old (relative to Now) a proof's own "iat" may
	// be before it's rejected. Required — no implicit default.
	MaxProofAge time.Duration

	// MaxClockSkew bounds how far in the future (relative to Now) a
	// proof's own "iat" or "nbf" may be, and how long past its "exp" it
	// is still taken. Zero means no tolerance. Verify keeps a proof's
	// replay record until MaxProofAge plus twice MaxClockSkew after its
	// iat, so a server whose clock runs up to MaxClockSkew behind this
	// one's can't take it again either.
	MaxClockSkew time.Duration

	// RequiredNonce, if non-empty, must equal the proof's own "nonce"
	// claim exactly (RFC 9449 §9's own nonce-challenge flow — the
	// server side of the retry wallet.RequestPreAuthorizedCodeToken
	// already implements client-side).
	RequiredNonce string

	// CheckNonce, if set, is called with the proof's "nonce" claim
	// (empty if absent) once the proof is otherwise valid and before
	// its jti is recorded with Replay, so a proof failing a server's
	// nonce policy (RFC 9449 §8) leaves nothing in the replay record.
	// An error from it fails Verify, wrapped.
	CheckNonce func(ctx context.Context, nonce string) error

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
// Its NumericDates may be fractional (RFC 7519 §2), so they're read as
// numbers; nbf and exp are optional, and checked when present (RFC 7519
// §4.1.4-§4.1.5).
type dpopClaims struct {
	JTI   string   `json:"jti"`
	HTM   string   `json:"htm"`
	HTU   string   `json:"htu"`
	IAT   *float64 `json:"iat"`
	NBF   *float64 `json:"nbf"`
	EXP   *float64 `json:"exp"`
	Nonce string   `json:"nonce"`
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
	if err := strictjson.Unmarshal(payload, &claims); err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: unmarshal claims: %w", err)
	}
	iat, err := validateDPoPClaims(claims, req)
	if err != nil {
		return VerifiedProof{}, err
	}

	if req.CheckNonce != nil {
		if err := req.CheckNonce(ctx, claims.Nonce); err != nil {
			return VerifiedProof{}, fmt.Errorf("dpop: nonce: %w", err)
		}
	}

	// Another server accepts this proof until iat+MaxProofAge by its own
	// clock, which may run up to MaxClockSkew behind this one's; keeping
	// the record 2×MaxClockSkew longer covers that, so a store that drops
	// records at expiresAt can't let the proof be replayed there.
	expiresAt := iat.Add(saturatingAdd(req.MaxProofAge, req.MaxClockSkew, req.MaxClockSkew))
	if err := req.Replay.UseOnce(ctx, JTIDigest(claims.JTI), expiresAt); err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: replay check: %w", err)
	}

	thumbprint, err := parsedJWK.Thumbprint()
	if err != nil {
		return VerifiedProof{}, fmt.Errorf("dpop: %w", err)
	}
	return VerifiedProof{PublicKey: pub, Thumbprint: thumbprint, IssuedAt: iat, Nonce: claims.Nonce}, nil
}

// JTIDigest is the key Verify records a proof's jti under with
// ReplayChecker: its SHA-256 digest, base64url-encoded without padding.
func JTIDigest(jti string) string {
	sum := sha256.Sum256([]byte(jti))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// saturatingAdd is the sum of ds, all non-negative, or the longest
// Duration when it would overflow.
func saturatingAdd(ds ...time.Duration) time.Duration {
	var sum time.Duration
	for _, d := range ds {
		if d > math.MaxInt64-sum {
			return math.MaxInt64
		}
		sum += d
	}
	return sum
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
	if _, ok := parseHTTPURL(req.URL); !ok {
		return fmt.Errorf("dpop: url must be an absolute http or https URL with an ASCII host")
	}
	if req.Now.IsZero() {
		return fmt.Errorf("dpop: now is required")
	}
	if req.MaxProofAge <= 0 {
		return fmt.Errorf("dpop: max_proof_age must be positive")
	}
	if req.MaxClockSkew < 0 {
		return fmt.Errorf("dpop: max_clock_skew must not be negative")
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
	if typ, _ := header["typ"].(string); !jose.TypeIs(typ, proofTyp) {
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
	if err := strictjson.Unmarshal(jwkRaw, &parsedJWK); err != nil {
		return nil, jwk.JWK{}, fmt.Errorf("dpop: unmarshal jwk header: %w", err)
	}
	// RFC 9449 §4.3: "the jwk JOSE Header Parameter does not contain a
	// private key".
	if parsedJWK.D != "" {
		return nil, jwk.JWK{}, fmt.Errorf("dpop: jwk header carries a private key")
	}
	pub, err := parsedJWK.PublicKey()
	if err != nil {
		return nil, jwk.JWK{}, fmt.Errorf("dpop: jwk header: %w", err)
	}
	return pub, parsedJWK, nil
}

// validateDPoPClaims checks claims against req (jti/htm/htu/iat/nbf/
// exp/nonce) and returns the parsed iat — split out of Verify purely to
// keep it under the linter's own cognitive complexity ceiling.
func validateDPoPClaims(claims dpopClaims, req VerifyRequest) (time.Time, error) {
	if claims.JTI == "" {
		return time.Time{}, fmt.Errorf("dpop: jti is required")
	}
	if len(claims.JTI) > MaxJTILength {
		return time.Time{}, fmt.Errorf("dpop: jti is longer than %d bytes", MaxJTILength)
	}
	// HTTP methods are case-sensitive (RFC 9110 §9.1), and htm is "the
	// value of the HTTP method" (RFC 9449 §4.2): "post" isn't POST. As
	// FAPIgo's own DPoP verification compares it.
	if claims.HTM != req.Method {
		return time.Time{}, fmt.Errorf("dpop: htm does not match")
	}
	if !sameTarget(claims.HTU, req.URL) {
		return time.Time{}, fmt.Errorf("dpop: htu does not match")
	}
	iat, err := checkProofTimes(claims, req)
	if err != nil {
		return time.Time{}, err
	}
	if req.RequiredNonce != "" {
		if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(req.RequiredNonce)) != 1 {
			return time.Time{}, fmt.Errorf("dpop: nonce does not match")
		}
	}
	return iat, nil
}

// checkProofTimes holds the proof to its iat: no further in the future
// than MaxClockSkew and no older than MaxProofAge. An nbf or exp the
// proof carries counts too (RFC 7519 §4.1.4-§4.1.5), with MaxClockSkew
// the tolerance either way, as fapigo/server's DPoP verification has
// it. It returns the proof's iat.
func checkProofTimes(claims dpopClaims, req VerifyRequest) (time.Time, error) {
	if claims.IAT == nil || *claims.IAT == 0 {
		return time.Time{}, fmt.Errorf("dpop: iat is required")
	}
	iat, err := jwtdate.FromFloat(*claims.IAT)
	if err != nil {
		return time.Time{}, fmt.Errorf("dpop: iat: %w", err)
	}
	latest := req.Now.Add(req.MaxClockSkew)
	if iat.After(latest) {
		return time.Time{}, fmt.Errorf("dpop: iat is in the future")
	}
	if iat.Before(req.Now.Add(-req.MaxProofAge)) {
		return time.Time{}, fmt.Errorf("dpop: proof has expired")
	}
	if claims.NBF != nil {
		nbf, err := jwtdate.FromFloat(*claims.NBF)
		if err != nil {
			return time.Time{}, fmt.Errorf("dpop: nbf: %w", err)
		}
		if nbf.After(latest) {
			return time.Time{}, fmt.Errorf("dpop: nbf is in the future")
		}
	}
	if claims.EXP != nil {
		exp, err := jwtdate.FromFloat(*claims.EXP)
		if err != nil {
			return time.Time{}, fmt.Errorf("dpop: exp: %w", err)
		}
		if req.Now.After(exp.Add(req.MaxClockSkew)) {
			return time.Time{}, fmt.Errorf("dpop: proof has expired (exp)")
		}
	}
	return iat, nil
}
