package identifierlist

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// Publisher signs an identifier list from the current identifiers:
// Token signs one now, and ServeHTTP serves one over HTTP at its uri.
// The signing algorithm follows the signer's key: ES256, ES384 or
// ES512 for P-256, P-384 or P-521, EdDSA for Ed25519.
//
// An issuer that pre-signs the list and serves it as a static file
// calls Token (or IssueToken) on its own schedule and needs nothing
// else here; see IssueToken for the Content-Type the host must serve.
// ServeHTTP signs a token once and serves it for CacheFor, so requests
// — which anyone can make — don't each cost a signature; Invalidate
// drops it after a revocation. A Publisher must not be copied after
// first use; use it by pointer.
type Publisher struct {
	// URI is the list's uri: every token's sub, and the uri MSOs name.
	// REQUIRED.
	URI string

	// Signer signs the tokens, and Chain is its certificate chain, leaf
	// first, without the trust anchor. REQUIRED.
	Signer crypto.Signer
	Chain  []*x509.Certificate

	// Identifiers returns the identifiers of every revoked MSO the list
	// covers. REQUIRED. A revoked MSO's identifier must keep being
	// returned until that MSO's validUntil has passed: ISO/IEC 18013-5
	// §12.3.6.1 has a revocation be permanent, and "as long as the MSO
	// is still considered valid according to the validUntil element, no
	// MSO revocation list shall be issued that indicates a different
	// status than revoked".
	Identifiers func(ctx context.Context) ([][]byte, error)

	// Lifetime is how long a token is valid (its exp); zero means one
	// hour. It must be at least a second.
	Lifetime time.Duration

	// TTL, if positive, is how long a Relying Party may cache a token:
	// its ttl claim, in whole seconds, and the bound on ServeHTTP's
	// Cache-Control max-age. It must be at least a second, and no
	// longer than Lifetime.
	TTL time.Duration

	// CacheFor is how long ServeHTTP serves a token before signing a
	// new one. Zero means TTL when TTL is set, and 30 seconds
	// otherwise; negative means sign a new token for every request. It
	// is capped at half of Lifetime, so a served token is valid for at
	// least half its lifetime.
	CacheFor time.Duration

	// Typ is the tokens' COSE typ header, as IssueOptions.Typ.
	Typ string

	// OnError, if set, is called with the request and the error when
	// ServeHTTP can't sign a token: when it answers 500, and when it
	// answers with the cached token instead, still within its exp,
	// because signing a new one failed. The response doesn't carry the
	// error.
	OnError func(r *http.Request, err error)

	// Now defaults to time.Now.
	Now func() time.Time

	mu       sync.Mutex
	token    []byte
	signedAt time.Time
	exp      time.Time
}

// signTimeout bounds a signature ServeHTTP makes for its cache, which
// doesn't end with the request that started it.
const signTimeout = 30 * time.Second

// Token signs a new identifier list from the current identifiers. It
// never caches.
func (p *Publisher) Token(ctx context.Context) ([]byte, error) {
	token, _, err := p.sign(ctx, p.now())
	return token, err
}

// sign signs a token issued at now, and returns its exp.
func (p *Publisher) sign(ctx context.Context, now time.Time) ([]byte, time.Time, error) {
	alg, err := p.validate()
	if err != nil {
		return nil, time.Time{}, err
	}
	identifiers, err := p.Identifiers(ctx)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("identifierlist: load identifiers: %w", err)
	}
	exp := now.Add(p.lifetime()).Unix()
	claims := TokenClaims{Sub: p.URI, Iat: now.Unix(), Exp: &exp, Identifiers: identifiers}
	if p.TTL > 0 {
		ttl := int64(p.TTL / time.Second)
		claims.TTL = &ttl
	}
	token, err := IssueToken(p.Signer, alg, claims, p.Chain, IssueOptions{Typ: p.Typ})
	if err != nil {
		return nil, time.Time{}, err
	}
	return token, time.Unix(exp, 0), nil
}

// validate checks p's configuration, and returns the algorithm its
// signer's key signs with.
func (p *Publisher) validate() (cose.Alg, error) {
	switch {
	case p.URI == "" || p.Signer == nil || len(p.Chain) == 0 || p.Identifiers == nil:
		return 0, errors.New("identifierlist: Publisher.URI, Signer, Chain and Identifiers are required")
	case p.Lifetime > 0 && p.Lifetime < time.Second:
		return 0, fmt.Errorf("identifierlist: Publisher.Lifetime is %s, under the one second a token's exp can express", p.Lifetime)
	case p.TTL > 0 && p.TTL < time.Second:
		return 0, fmt.Errorf("identifierlist: Publisher.TTL is %s, under the one second a ttl claim can express", p.TTL)
	case p.TTL > p.lifetime():
		return 0, fmt.Errorf("identifierlist: Publisher.TTL (%s) is longer than its Lifetime (%s)", p.TTL, p.lifetime())
	}
	alg, err := cose.AlgForKey(p.Signer.Public())
	if err != nil {
		return 0, fmt.Errorf("identifierlist: Publisher.Signer: %w", err)
	}
	return alg, nil
}

// ServeHTTP implements http.Handler: a GET or HEAD is answered with a
// token as MediaType, cached as CacheFor says.
func (p *Publisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	served, signErr := p.cachedToken(r.Context())
	if signErr != nil && p.OnError != nil {
		p.OnError(r, signErr)
	}
	if served.token == nil {
		http.Error(w, "the identifier list is unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", MediaType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if p.TTL > 0 {
		// No longer than the ttl left, nor past the token's exp.
		maxAge := max(min(p.TTL-served.now.Sub(served.signedAt), served.exp.Sub(served.now)), 0)
		w.Header().Set("Cache-Control", "max-age="+strconv.FormatInt(int64(maxAge/time.Second), 10))
	}
	// #nosec G705 -- token is an identifier list this Publisher signed,
	// sent as its own media type with nosniff, never HTML.
	_, _ = w.Write(served.token)
}

// servedToken is a token ServeHTTP answers with, when it was signed
// and expires, and the time it's served at.
type servedToken struct {
	token              []byte
	signedAt, exp, now time.Time
}

// cachedToken returns the cached token, signing a new one once it's
// older than the cache window. Signing happens under the lock, so
// concurrent requests share one signature, with a context that doesn't
// end with the request that happens to start it. When signing fails
// and the cached token hasn't expired, it's returned with the error.
func (p *Publisher) cachedToken(ctx context.Context) (servedToken, error) {
	signCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), signTimeout)
	defer cancel()
	window := p.cacheWindow()
	if window <= 0 {
		// Nothing shared: a token per request, signed without the lock.
		now := p.now()
		token, exp, err := p.sign(signCtx, now)
		return servedToken{token: token, signedAt: now, exp: exp, now: now}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	cached := servedToken{token: p.token, signedAt: p.signedAt, exp: p.exp, now: now}
	if p.token != nil && now.Sub(p.signedAt) < window && !now.Before(p.signedAt) {
		return cached, nil
	}
	token, exp, err := p.sign(signCtx, now)
	if err != nil {
		if p.token != nil && !now.Before(p.signedAt) && now.Before(p.exp) {
			return cached, err
		}
		return servedToken{}, err
	}
	p.token, p.signedAt, p.exp = token, now, exp
	return servedToken{token: token, signedAt: now, exp: exp, now: now}, nil
}

// Invalidate drops the cached token, so the next request is signed
// from the current identifiers: call it after a revocation. Until one
// is, ServeHTTP has no token to fall back on.
func (p *Publisher) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.token = nil
}

func (p *Publisher) cacheWindow() time.Duration {
	window := p.CacheFor
	switch {
	case window < 0:
		return 0
	case window == 0 && p.TTL > 0:
		window = p.TTL
	case window == 0:
		window = 30 * time.Second
	}
	return min(window, p.lifetime()/2)
}

func (p *Publisher) lifetime() time.Duration {
	if p.Lifetime <= 0 {
		return time.Hour
	}
	return p.Lifetime
}

func (p *Publisher) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}
