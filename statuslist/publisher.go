package statuslist

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// Publisher serves a Status List Token at its uri (draft-14 §8.1): an
// http.Handler that serves a token signed from the current statuses,
// in the form the Accept header asks for — CWT for
// CWTTokenMediaType (an mdoc's reference), JWT otherwise (an SD-JWT
// VC's) — carrying the signer's certificate chain as x5c/x5chain, as
// HAIP 1.0 §6.1 requires. The signing algorithm follows the signer's
// key: ES256 for P-256, EdDSA for Ed25519.
//
// Each form's token is signed once and served for CacheFor, so
// requests — which anyone can make — don't each cost a signature. A
// status change reaches Relying Parties within CacheFor, unless the
// issuer calls Invalidate when it makes one, plus however long they
// cache the token themselves (TTL). A Publisher must not be copied
// after first use; use it by pointer.
//
// Checker (with Fetcher) is the Relying Party side of the same exchange.
type Publisher struct {
	// URI is the Status List's uri — every token's sub, and the uri
	// Referenced Tokens name. REQUIRED.
	URI string

	// Signer signs the tokens, and Chain is its certificate chain, leaf
	// first. REQUIRED.
	Signer crypto.Signer
	Chain  []*x509.Certificate

	// Statuses returns the current status of every index. REQUIRED.
	Statuses func(ctx context.Context) ([]uint8, error)

	// Bits is how many bits each status takes; zero means Bits1.
	Bits Bits

	// Lifetime is how long a served token is valid (its exp); zero
	// means one hour.
	Lifetime time.Duration

	// TTL, if positive, is how long a Relying Party may cache a token:
	// its ttl claim, and the response's Cache-Control max-age.
	TTL time.Duration

	// CacheFor is how long ServeHTTP serves a token before signing a
	// new one. Zero means TTL when TTL is set, and 30 seconds
	// otherwise; negative means sign a new token for every request. It
	// is capped at half of Lifetime, so a served token is always valid
	// for at least half its lifetime.
	CacheFor time.Duration

	// Now defaults to time.Now.
	Now func() time.Time

	mu     sync.Mutex
	cached [2]cachedToken // JWT, CWT
}

type cachedToken struct {
	token    []byte
	signedAt time.Time
}

// ServeHTTP implements http.Handler.
func (p *Publisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cwt := strings.Contains(r.Header.Get("Accept"), CWTTokenMediaType)
	token, err := p.cachedTokenFor(r.Context(), cwt)
	if err != nil {
		http.Error(w, "the status list is unavailable", http.StatusInternalServerError)
		return
	}
	mediaType := TokenMediaType
	if cwt {
		mediaType = CWTTokenMediaType
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if p.TTL > 0 {
		w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(int(p.TTL.Seconds())))
	}
	// #nosec G705 -- token is a Status List Token this Publisher signed,
	// sent as its own media type with nosniff, never HTML.
	_, _ = w.Write(token)
}

// cachedTokenFor returns the form's cached token, signing a new one
// once the cached one is older than the cache window. Signing happens
// under the lock, so concurrent requests share one signature.
func (p *Publisher) cachedTokenFor(ctx context.Context, cwt bool) ([]byte, error) {
	window := p.cacheWindow()
	if window <= 0 {
		return p.Token(ctx, cwt)
	}
	i := 0
	if cwt {
		i = 1
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.cached[i]; c.token != nil && now.Sub(c.signedAt) < window && !now.Before(c.signedAt) {
		return c.token, nil
	}
	token, err := p.Token(ctx, cwt)
	if err != nil {
		return nil, err
	}
	p.cached[i] = cachedToken{token: token, signedAt: now}
	return token, nil
}

// Invalidate drops the cached tokens, so the next request is signed
// from the current statuses — call it after a status changes, so the
// change is served at once instead of within CacheFor.
func (p *Publisher) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cached = [2]cachedToken{}
}

// cacheWindow is CacheFor's effective value.
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

// Token signs a new Status List Token for the current statuses: CWT
// when cwt is true, JWT otherwise. Unlike ServeHTTP, it never caches.
func (p *Publisher) Token(ctx context.Context, cwt bool) ([]byte, error) {
	if p.URI == "" || p.Signer == nil || len(p.Chain) == 0 || p.Statuses == nil {
		return nil, errors.New("statuslist: Publisher.URI, Signer, Chain and Statuses are required")
	}
	statuses, err := p.Statuses(ctx)
	if err != nil {
		return nil, err
	}
	bits := p.Bits
	if bits == 0 {
		bits = Bits1
	}
	sl, err := New(bits, statuses, "")
	if err != nil {
		return nil, err
	}
	now := p.now()
	exp := now.Add(p.lifetime()).Unix()
	claims := TokenClaims{Sub: p.URI, Iat: now.Unix(), Exp: &exp, StatusList: sl}
	if p.TTL > 0 {
		ttl := int64(p.TTL.Seconds())
		claims.TTL = &ttl
	}
	switch key := p.Signer.Public().(type) {
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() {
			return nil, errors.New("statuslist: Publisher.Signer's ECDSA key isn't P-256")
		}
		if cwt {
			return IssueTokenCWTX5Chain(p.Signer, cose.ES256, claims, p.Chain)
		}
		token, err := IssueTokenX5C(p.Signer, jose.ES256, claims, p.Chain)
		return []byte(token), err
	case ed25519.PublicKey:
		if cwt {
			return IssueTokenCWTX5Chain(p.Signer, cose.EdDSA, claims, p.Chain)
		}
		token, err := IssueTokenX5C(p.Signer, jose.EdDSA, claims, p.Chain)
		return []byte(token), err
	default:
		return nil, errors.New("statuslist: Publisher.Signer's key type isn't supported")
	}
}
