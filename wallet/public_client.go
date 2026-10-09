package wallet

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	fapi "github.com/idfoundry/fapigo"
)

// RefreshTokenRequest is the input to RequestRefreshToken.
type RefreshTokenRequest struct {
	// RefreshToken is REQUIRED: the one a Token Response gave.
	RefreshToken fapi.Secret

	// DPoPKey is the key the refresh token is bound to — the DPoP key
	// of the Token Request that obtained it (RFC 9449 §5: a public
	// client's refresh token is bound to it) — and the refreshed access
	// token is bound to it too. nil for a refresh token obtained with a
	// Bearer access token: the request then carries no DPoP proof.
	DPoPKey crypto.Signer
}

// RequestRefreshToken refreshes a token a public client obtained — an
// anonymous pre-authorized code redemption's, say (OpenID4VCI 1.0 §6.1,
// §14.5) — at the Authorization Server's token endpoint (RFC 6749 §6).
// It authenticates no client: a DPoP-bound refresh token is held to its
// DPoP key instead (RFC 9449 §5), so the request carries a proof from
// req.DPoPKey, retried once on a DPoP nonce challenge as
// RequestPreAuthorizedCodeToken is. A client that authenticates at the
// token endpoint (a Wallet Attestation) refreshes through fapigo/client
// instead. A refused refresh token is a *Error with Code
// "invalid_grant".
func (w *Wallet) RequestRefreshToken(ctx context.Context, endpoint fapi.URL, req RefreshTokenRequest) (PreAuthorizedCodeTokenResult, error) {
	if req.RefreshToken.Reveal() == "" {
		return PreAuthorizedCodeTokenResult{}, errors.New("wallet: request refresh token: refresh_token is required")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", req.RefreshToken.Reveal())
	body, err := w.postToken(ctx, endpoint, []byte(form.Encode()), req.DPoPKey, nil, "request refresh token")
	if err != nil {
		return PreAuthorizedCodeTokenResult{}, err
	}
	return decodeTokenResponse(body)
}

// RevokeToken revokes a token a public client obtained at the
// Authorization Server's revocation endpoint (RFC 7009 §2.1), with no
// client authentication: RFC 7009 §5 lets a server accept a public
// client's request with the token alone. tokenTypeHint is
// "refresh_token" or "access_token", or "" for none. A 200 response
// means the token is no longer valid, whether or not the server knew it
// (§2.2); any other is a *Error.
func (w *Wallet) RevokeToken(ctx context.Context, endpoint fapi.URL, token fapi.Secret, tokenTypeHint string) error {
	if token.Reveal() == "" {
		return errors.New("wallet: revoke token: token is required")
	}
	form := url.Values{}
	form.Set("token", token.Reveal())
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	if _, err := w.postToken(ctx, endpoint, []byte(form.Encode()), nil, nil, "revoke token"); err != nil {
		return err
	}
	return nil
}

// BearerResourceClient returns a ProtectedResourceClient presenting
// accessToken as a Bearer token (RFC 6750 §2.1), for a Token Response
// whose token_type is "Bearer": an Authorization Server may issue one
// even to a client that sent a DPoP proof (RFC 9449 §5), which
// OpenID4VCI 1.0 allows (§13.2 RECOMMENDS sender-constrained tokens; it
// doesn't require them). Anyone holding a Bearer token can use it: keep
// it only where §13.10 asks, "in a secure manner". Requests go through
// Dependencies.HTTP.
func (w *Wallet) BearerResourceClient(accessToken fapi.Secret) ProtectedResourceClient {
	return bearerResourceClient{w: w, token: accessToken.Reveal()}
}

type bearerResourceClient struct {
	w     *Wallet
	token string
}

func (c bearerResourceClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c.token == "" {
		return nil, errors.New("wallet: bearer resource client: an access token is required")
	}
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+c.token)
	res, err := c.w.deps.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wallet: bearer resource client: %w", err)
	}
	return res, nil
}

// Token types a Token Response's token_type names (RFC 6749 §7.1,
// RFC 9449 §5), compared case-insensitively.
const (
	TokenTypeDPoP   = "DPoP"
	TokenTypeBearer = "Bearer"
)

// CanonicalTokenType is tokenType ("dpop", "BEARER", ...) as
// TokenTypeDPoP or TokenTypeBearer: token_type is case-insensitive
// (RFC 6749 §7.1). Any other type is an error: a wallet can't present
// it.
func CanonicalTokenType(tokenType string) (string, error) {
	switch {
	case strings.EqualFold(tokenType, TokenTypeDPoP):
		return TokenTypeDPoP, nil
	case strings.EqualFold(tokenType, TokenTypeBearer):
		return TokenTypeBearer, nil
	default:
		return "", fmt.Errorf("wallet: unsupported token_type %q", tokenType)
	}
}
