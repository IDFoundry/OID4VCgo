package walletprovider

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// RequestTypHeader is the JOSE "typ" header of a signed request.
const RequestTypHeader = "wallet-provider-request+jwt"

// maxRequestClockSkew is how far in the future a signed request's iat
// may be.
const maxRequestClockSkew = time.Minute

// Request is a request to the provider after registration, as the HTTP
// layer receives it.
type Request struct {
	// JWT is the signed request: SignRequest's result.
	JWT string

	// Method, Path and Body are the HTTP request's method, its URL path
	// and its body, which the JWT must cover.
	Method string
	Path   string
	Body   []byte
}

// requestClaims is a signed request's claims.
type requestClaims struct {
	// Subject is the instance ID.
	Subject    string `json:"sub"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	BodySHA256 string `json:"body_sha256"`
	Challenge  string `json:"challenge"`
	IssuedAt   int64  `json:"iat"`
}

// SignRequest signs a request to the provider with the instance key,
// as a wallet does on every request after registration: a JWT whose
// sub is the instance ID, covering the method, path, the SHA-256 of the
// body (base64url, as body_sha256) and challenge, a challenge issued
// for PurposeRequest, signed ES256 (P-256) or EdDSA (Ed25519) with typ
// RequestTypHeader.
func SignRequest(instanceKey crypto.Signer, instanceID, challenge, method, path string, body []byte, now time.Time) (string, error) {
	alg, err := keyAlg(instanceKey.Public())
	if err != nil {
		return "", fmt.Errorf("walletprovider: the instance key: %w", err)
	}
	payload, err := json.Marshal(requestClaims{
		Subject: instanceID, Method: method, Path: path, BodySHA256: bodyHash(body),
		Challenge: challenge, IssuedAt: now.Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("walletprovider: marshal request claims: %w", err)
	}
	jwt, err := jose.Sign(alg, instanceKey, map[string]any{"typ": RequestTypHeader}, payload)
	if err != nil {
		return "", fmt.Errorf("walletprovider: sign request: %w", err)
	}
	return jwt, nil
}

// VerifyRequest checks a signed request and returns the active instance
// it comes from. The HTTP layer requires it of every request after
// registration, so the instance ID alone grants nothing: the JWT must
// verify with the instance's key, cover req's method, path and body,
// be recent, and carry a challenge issued for PurposeRequest, which it
// consumes, so a request is accepted once. It refuses a request from
// an instance that isn't active.
//
// The signature is checked before anything else about the instance is
// revealed or changed: a request that doesn't verify fails with
// ErrInstanceNotFound or ErrInvalidRequest, never ErrInstanceNotActive,
// and leaves the challenge it names unused, so a forged request can
// neither learn an instance's state nor burn a wallet's challenge.
func (p *Provider) VerifyRequest(ctx context.Context, req Request) (Instance, error) {
	header, payload, err := jose.DecodeUnverified(req.JWT)
	if err != nil {
		return Instance{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	if typ, _ := header["typ"].(string); !jose.TypeIs(typ, RequestTypHeader) {
		return Instance{}, fmt.Errorf("%w: typ is %q, want %q", ErrInvalidRequest, typ, RequestTypHeader)
	}
	var unverified requestClaims
	if err := strictjson.Unmarshal(payload, &unverified); err != nil {
		return Instance{}, fmt.Errorf("%w: claims: %w", ErrInvalidRequest, err)
	}
	in, err := p.getInstance(ctx, unverified.Subject)
	if err != nil {
		return Instance{}, err
	}
	key, err := jwk.ParsePublicKey(in.Key)
	if err != nil {
		return Instance{}, fmt.Errorf("walletprovider: the stored instance key: %w", err)
	}
	alg, err := keyAlg(key)
	if err != nil {
		return Instance{}, fmt.Errorf("walletprovider: the stored instance key: %w", err)
	}
	_, verified, err := jose.Verify(alg, key, req.JWT)
	if err != nil {
		return Instance{}, fmt.Errorf("%w: signature: %w", ErrInvalidRequest, err)
	}
	var c requestClaims
	if err := strictjson.Unmarshal(verified, &c); err != nil {
		return Instance{}, fmt.Errorf("%w: claims: %w", ErrInvalidRequest, err)
	}
	now := p.now()
	iat := time.Unix(c.IssuedAt, 0)
	switch {
	case c.Method != req.Method || c.Path != req.Path:
		return Instance{}, fmt.Errorf("%w: signed for %s %s, not %s %s", ErrInvalidRequest, c.Method, c.Path, req.Method, req.Path)
	case c.BodySHA256 != bodyHash(req.Body):
		return Instance{}, fmt.Errorf("%w: signed for another body", ErrInvalidRequest)
	case iat.After(now.Add(maxRequestClockSkew)) || iat.Before(now.Add(-p.cfg.ChallengeTTL)):
		return Instance{}, fmt.Errorf("%w: iat %v isn't recent", ErrInvalidRequest, iat)
	}
	// The instance's state is reported only to its own key's holder, and
	// the challenge used up only by a request that verified.
	if err := stateError(in.State); err != nil {
		return Instance{}, err
	}
	if _, err := p.consumeChallenge(ctx, c.Challenge, PurposeRequest); err != nil {
		return Instance{}, err
	}
	return in, nil
}

func bodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
