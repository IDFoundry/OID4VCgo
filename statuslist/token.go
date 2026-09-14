package statuslist

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/jose"
)

// TokenTyp is the required JOSE "typ" header of a Status List Token in
// JWT format (draft-12 §5.1).
const TokenTyp = "statuslist+jwt" //nolint:gosec // a JOSE "typ" header value, not a credential

// TokenMediaType is the media type a Status List Token in JWT format
// is served and requested as (draft-12 §8.1, §8.2).
const TokenMediaType = "application/statuslist+jwt"

// TokenClaims is a Status List Token's JWT Claims Set (draft-12 §5.1).
type TokenClaims struct {
	Sub        string // REQUIRED: the URI this Status List Token is served at
	Iat        int64  // REQUIRED
	Exp        *int64
	TTL        *int64 // seconds
	StatusList StatusList

	Additional map[string]any
}

// IssueToken signs claims into a Status List Token in JWT format
// (draft-12 §5.1). keyID sets the JOSE "kid" header, if non-empty.
func IssueToken(signer crypto.Signer, alg jose.Alg, claims TokenClaims, keyID string) (string, error) {
	if claims.Sub == "" {
		return "", fmt.Errorf("statuslist: TokenClaims.Sub is required")
	}
	if !claims.StatusList.Bits.valid() {
		return "", fmt.Errorf("statuslist: TokenClaims.StatusList.Bits is invalid")
	}

	payload := make(map[string]any, len(claims.Additional)+5)
	for k, v := range claims.Additional {
		payload[k] = v
	}
	payload["sub"] = claims.Sub
	payload["iat"] = claims.Iat
	if claims.Exp != nil {
		payload["exp"] = *claims.Exp
	}
	if claims.TTL != nil {
		payload["ttl"] = *claims.TTL
	}
	payload["status_list"] = claims.StatusList

	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("statuslist: marshal token claims: %w", err)
	}

	header := map[string]any{"typ": TokenTyp}
	if keyID != "" {
		header["kid"] = keyID
	}
	return jose.Sign(alg, signer, header, raw)
}

// VerifyOptions configures VerifyToken.
type VerifyOptions struct {
	Now func() time.Time // defaults to time.Now
}

// VerifyToken verifies a Status List Token's signature and typ header,
// and rejects an expired token (draft-12 §5.1 rule 2-3, §8.3 step 4.3).
// It does not check sub against a specific Referenced Token — that's
// Check's job, since it needs the StatusListRef to compare against.
func VerifyToken(token string, pub crypto.PublicKey, alg jose.Alg, opts VerifyOptions) (TokenClaims, error) {
	header, raw, err := jose.Verify(alg, pub, token)
	if err != nil {
		return TokenClaims{}, fmt.Errorf("statuslist: verify token signature: %w", err)
	}
	if typ, _ := header["typ"].(string); typ != TokenTyp {
		return TokenClaims{}, fmt.Errorf("statuslist: token typ is %q, want %q", typ, TokenTyp)
	}

	var decoded struct {
		Sub        string     `json:"sub"`
		Iat        int64      `json:"iat"`
		Exp        *int64     `json:"exp"`
		TTL        *int64     `json:"ttl"`
		StatusList StatusList `json:"status_list"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return TokenClaims{}, fmt.Errorf("statuslist: unmarshal token claims: %w", err)
	}
	if decoded.Sub == "" {
		return TokenClaims{}, fmt.Errorf("statuslist: token is missing the required sub claim")
	}
	if !decoded.StatusList.Bits.valid() {
		return TokenClaims{}, fmt.Errorf("statuslist: token's status_list.bits is invalid")
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	if decoded.Exp != nil && now().Unix() > *decoded.Exp {
		return TokenClaims{}, fmt.Errorf("statuslist: token is expired")
	}

	return TokenClaims{
		Sub:        decoded.Sub,
		Iat:        decoded.Iat,
		Exp:        decoded.Exp,
		TTL:        decoded.TTL,
		StatusList: decoded.StatusList,
	}, nil
}
