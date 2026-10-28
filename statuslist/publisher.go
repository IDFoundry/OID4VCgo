package statuslist

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
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
// CWTTokenMediaType (an mdoc's reference), JWT for TokenMediaType (an
// SD-JWT VC's), and DefaultForm when it names neither —
// carrying the signer's certificate chain as x5c/x5chain, as HAIP 1.0
// §6.1 requires. The signing algorithm follows the signer's key: ES256
// for P-256, EdDSA for Ed25519.
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

	// DefaultForm is the form served when the Accept header names
	// neither — draft-14 §8.1 lets a Relying Party send none when the
	// form is "known implicitly or out-of-band". Zero means FormJWT; set
	// FormCWT for a list only mdocs reference, since an mdoc reader may
	// send no Accept and expects a CWT. Any other value is refused: Token
	// fails, and ServeHTTP answers 500.
	DefaultForm Form

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
	gzipped  []byte // token, gzip-compressed once first asked for
	signedAt time.Time
}

// ServeHTTP implements http.Handler.
func (p *Publisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Has("time") {
		// Historical resolution (draft-ietf-oauth-status-list §8.4):
		// this Publisher keeps only the current list, and serving that
		// for a past time would answer a question it wasn't asked.
		http.Error(w, "historical resolution (the time parameter) is not supported", http.StatusNotImplemented)
		return
	}
	// Every Accept line: RFC 9110 §5.3 lets a client split the list
	// across several.
	cwt := p.servesCWT(strings.Join(r.Header.Values("Accept"), ", "))
	gz := acceptsGzip(r.Header.Values("Accept-Encoding"))
	token, err := p.cachedTokenFor(r.Context(), cwt, gz)
	if err != nil {
		http.Error(w, "the status list is unavailable", http.StatusInternalServerError)
		return
	}
	mediaType := TokenMediaType
	if cwt {
		mediaType = CWTTokenMediaType
	}
	w.Header().Set("Vary", "Accept, Accept-Encoding")
	if gz {
		// draft-14 §8.2: the response "SHOULD use gzip Content-Encoding".
		w.Header().Set("Content-Encoding", "gzip")
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

// Form is a Status List Token's form: a JWT (an SD-JWT VC's reference)
// or a CWT (an mdoc's).
type Form int

const (
	// FormJWT is a token served as TokenMediaType.
	FormJWT Form = iota
	// FormCWT is a token served as CWTTokenMediaType.
	FormCWT
)

// String returns "jwt" or "cwt", or Form(n) for any other value.
func (f Form) String() string {
	switch f {
	case FormJWT:
		return "jwt"
	case FormCWT:
		return "cwt"
	}
	return "Form(" + strconv.Itoa(int(f)) + ")"
}

// servesCWT reports whether accept asks for the CWT form: CWT when it
// names CWTTokenMediaType, JWT when it names only TokenMediaType, and
// DefaultForm when it names neither.
func (p *Publisher) servesCWT(accept string) bool {
	if strings.Contains(accept, CWTTokenMediaType) {
		return true
	}
	if strings.Contains(accept, TokenMediaType) {
		return false
	}
	return p.DefaultForm == FormCWT
}

// cachedTokenFor returns the form's cached token, signing a new one
// once the cached one is older than the cache window, gzip-compressed
// when gz is set. Signing and compressing happen under the lock, so
// concurrent requests share one signature and one compression.
func (p *Publisher) cachedTokenFor(ctx context.Context, cwt, gz bool) ([]byte, error) {
	window := p.cacheWindow()
	if window <= 0 {
		token, err := p.Token(ctx, cwt)
		if err != nil || !gz {
			return token, err
		}
		return gzipBytes(token)
	}
	i := 0
	if cwt {
		i = 1
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	c := &p.cached[i]
	if c.token == nil || now.Sub(c.signedAt) >= window || now.Before(c.signedAt) {
		token, err := p.Token(ctx, cwt)
		if err != nil {
			return nil, err
		}
		*c = cachedToken{token: token, signedAt: now}
	}
	if !gz {
		return c.token, nil
	}
	if c.gzipped == nil {
		gzipped, err := gzipBytes(c.token)
		if err != nil {
			return nil, err
		}
		c.gzipped = gzipped
	}
	return c.gzipped, nil
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// acceptsGzip reports whether an Accept-Encoding header accepts gzip
// with a q above zero (RFC 9110 §12.5.3).
func acceptsGzip(acceptEncoding []string) bool {
	for _, line := range acceptEncoding {
		for _, part := range strings.Split(line, ",") {
			coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
			if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
				continue
			}
			q := 1.0
			if name, value, ok := strings.Cut(strings.TrimSpace(params), "="); ok && strings.EqualFold(strings.TrimSpace(name), "q") {
				var err error
				if q, err = strconv.ParseFloat(strings.TrimSpace(value), 64); err != nil {
					continue
				}
			}
			return q > 0
		}
	}
	return false
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
	if p.DefaultForm != FormJWT && p.DefaultForm != FormCWT {
		return nil, fmt.Errorf("statuslist: Publisher.DefaultForm is %v, not FormJWT or FormCWT", p.DefaultForm)
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
