package walletflowtest

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/dpop"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// publicTokens is an Anonymous issuer's own token service, under
// Options.BearerTokens or AnonymousRefresh: the tokens a public client
// gets from it are opaque, recorded here with what they grant, and
// refreshed and revoked with no client authentication (RFC 6749 §6,
// RFC 7009 §5). A DPoP-bound one is checked through dpop, the
// Authorization Server's own resource verifier, by its JWT access
// token; a Bearer one here.
type publicTokens struct {
	dpop   issuer.AccessTokenVerifier
	bearer bool
	replay issuer.DPoPReplayChecker

	mu     sync.Mutex
	grants map[string]publicGrant // by refresh token
	access map[string]issuer.Grant
}

// publicGrant is what a refresh token grants: the redeemed code's
// result, and the DPoP key it's bound to ("" for a Bearer grant).
type publicGrant struct {
	result     issuer.ExchangePreAuthorizedCodeResult
	thumbprint string
}

// issue answers an anonymous redemption with result: its access token,
// a Bearer one under Options.BearerTokens, and a refresh token.
func (p *publicTokens) issue(w http.ResponseWriter, r *http.Request, e *Env, result issuer.ExchangePreAuthorizedCodeResult) {
	// The refresh token is bound to the request's DPoP key whatever the
	// access token's type (RFC 9449 §5): a public client's refresh token
	// is.
	thumbprint, err := p.dpopKey(r, e)
	if err != nil {
		issuer.NewError(issuer.ErrorInvalidTokenRequest, err.Error()).WriteJSON(w)
		return
	}
	refresh := rand.Text()
	p.mu.Lock()
	p.grants[refresh] = publicGrant{result: result, thumbprint: thumbprint}
	p.mu.Unlock()
	p.write(w, result, refresh)
}

// refresh redeems a refresh token: one bound to a DPoP key needs a
// proof from it (RFC 9449 §5). Each refresh rotates the refresh token.
func (p *publicTokens) refresh(w http.ResponseWriter, r *http.Request, e *Env, refresh string) {
	p.mu.Lock()
	g, ok := p.grants[refresh]
	p.mu.Unlock()
	if !ok {
		issuer.NewError(issuer.ErrorInvalidGrant, "unknown refresh token").WriteJSON(w)
		return
	}
	if g.thumbprint != "" {
		thumbprint, err := p.dpopKey(r, e)
		if err != nil || thumbprint != g.thumbprint {
			issuer.NewError(issuer.ErrorInvalidGrant, "the refresh token is bound to another DPoP key").WriteJSON(w)
			return
		}
	}
	next := rand.Text()
	p.mu.Lock()
	delete(p.grants, refresh)
	p.grants[next] = g
	p.mu.Unlock()
	result := g.result
	if !p.bearer {
		// A fresh access token for the same grant, bound to the same key;
		// write mints a Bearer one itself.
		token, _, err := (accessTokenAdapter{inner: e.accessTokens}).IssueAccessToken(r.Context(), accessTokenParams(e, result, g.thumbprint))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		result.AccessToken = token
	}
	p.write(w, result, next)
}

// revoke revokes a refresh token, and reports whether it was one.
func (p *publicTokens) revoke(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	token := r.PostForm.Get("token")
	_, ok := p.grants[token]
	delete(p.grants, token)
	return ok
}

// write writes the Token Response: result's access token, as a Bearer
// one under Options.BearerTokens.
func (p *publicTokens) write(w http.ResponseWriter, result issuer.ExchangePreAuthorizedCodeResult, refresh string) {
	tokenType := wallet.TokenTypeDPoP
	if p.bearer {
		tokenType = wallet.TokenTypeBearer
		bearer := rand.Text()
		p.mu.Lock()
		if p.access == nil {
			p.access = map[string]issuer.Grant{}
		}
		p.access[bearer] = issuer.Grant{
			Subject: result.Subject,
			Authorized: issuer.AuthorizedRequest{
				ClientIdentity: issuer.NoClientIdentity{}, Subject: result.Subject, Scopes: result.Scope,
				AuthorizationDetails: result.AuthorizationDetails,
			},
		}
		p.mu.Unlock()
		result.AccessToken = bearer
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": result.AccessToken, "token_type": tokenType, "expires_in": int64(result.ExpiresIn.Seconds()),
		"refresh_token": refresh, "authorization_details": result.AuthorizationDetails,
	})
}

// Verify implements issuer.AccessTokenVerifier: a Bearer token this
// service issued, or a DPoP-bound one through the resource verifier.
func (p *publicTokens) Verify(r *http.Request, endpoint *url.URL) (issuer.Grant, error) {
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return p.dpop.Verify(r, endpoint)
	}
	p.mu.Lock()
	g, ok := p.access[token]
	p.mu.Unlock()
	if !ok {
		return issuer.Grant{}, errUnknownBearer
	}
	return g, nil
}

// WriteError implements issuer.AccessTokenVerifier.
func (p *publicTokens) WriteError(w http.ResponseWriter, err error) {
	if errors.Is(err, errUnknownBearer) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p.dpop.WriteError(w, err)
}

var errUnknownBearer = errors.New("walletflowtest: unknown Bearer access token")

// dpopKey is the thumbprint of the key r's DPoP proof was signed with,
// for the token endpoint.
func (p *publicTokens) dpopKey(r *http.Request, e *Env) (string, error) {
	return e.verifyTokenEndpointDPoP(r, p.replay)
}

// accessTokenParams are the parameters to mint result's access token
// again, bound to thumbprint.
func accessTokenParams(e *Env, result issuer.ExchangePreAuthorizedCodeResult, thumbprint string) issuer.AccessTokenParams {
	params := issuer.AccessTokenParams{
		Scope: result.Scope, Thumbprint: thumbprint, Subject: result.Subject,
		Issuer: e.issuerURL().String(), Audience: e.issuerURL().String(), Now: time.Now(), Lifetime: result.ExpiresIn, Random: rand.Reader,
	}
	if len(result.AuthorizationDetails) > 0 {
		raw, _ := json.Marshal(result.AuthorizationDetails)
		params.Claims = map[string]json.RawMessage{"authorization_details": raw}
	}
	return params
}

// verifyTokenEndpointDPoP verifies r's DPoP proof for the token endpoint,
// and returns its key's RFC 7638 thumbprint.
func (e *Env) verifyTokenEndpointDPoP(r *http.Request, replay issuer.DPoPReplayChecker) (string, error) {
	verified, err := dpop.Verify(r.Context(), dpop.VerifyRequest{
		Proof: r.Header.Get("DPoP"), Method: http.MethodPost, URL: e.endpoint("/token").String(),
		Now: time.Now(), MaxProofAge: time.Minute, MaxClockSkew: 30 * time.Second, Replay: replay,
	})
	if err != nil {
		return "", err
	}
	return verified.Thumbprint, nil
}

// revokeAll revokes every public client's refresh token.
func (p *publicTokens) revokeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.grants)
}
