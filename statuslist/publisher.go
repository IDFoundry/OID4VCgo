package statuslist

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/listhttp"
)

// Publisher serves a Status List Token at its uri (draft-14 §8.1): an
// http.Handler that serves a token signed from the current statuses,
// in the form the Accept header asks for — CWT for
// CWTTokenMediaType (an mdoc's reference), JWT for TokenMediaType (an
// SD-JWT VC's), and DefaultForm when it names neither —
// carrying the signer's certificate chain as x5c/x5chain, as HAIP 1.0
// §6.1 requires. The signing algorithm follows the signer's key: ES256
// for P-256 and EdDSA for Ed25519 in either form, and ES384 for P-384
// and ES512 for P-521 in the CWT form only — an mdoc issuer's IACA
// material may be on those curves (ISO/IEC 18013-5 §9.1.2.4), but this
// module's JWTs are ES256 or EdDSA. A Publisher whose signer is on
// P-384 or P-521 sets DefaultForm to FormCWT, and answers a request
// for the JWT form alone 406 Not Acceptable.
//
// Each form's token is signed once and served for CacheFor, so
// requests — which anyone can make — don't each cost a signature, and
// concurrent requests for a form wait on one signature. A status
// change reaches Relying Parties within CacheFor, unless the issuer
// calls Invalidate when it makes one, plus however long they cache the
// token themselves (TTL); while signing a new token fails, the form's
// cached one is served until its exp, and OnError told. A response
// carries a strong ETag, and a request whose If-None-Match names it is
// answered 304 Not Modified. A Publisher must not be copied after
// first use; use it by pointer.
//
// Each replica serving a list signs its own tokens, unless Tokens
// shares them: then one replica at a time signs the list's token, and
// the others serve it.
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

	// Bits is how many bits each status takes; zero means Bits1. ISO/IEC
	// 18013-5 §12.3.6.5 requires Bits1 for a list mdocs reference. The
	// Publisher doesn't know which credentials reference it, so it
	// doesn't enforce that, and a Checker reads a list of any valid
	// Bits correctly.
	Bits Bits

	// Lifetime is how long a served token is valid (its exp); zero
	// means one hour.
	Lifetime time.Duration

	// TTL, if positive, is how long a Relying Party may cache a token:
	// its ttl claim, and the bound on the response's Cache-Control
	// max-age, which counts down the ttl left on the token served. It
	// must be at least a second, which is what a ttl claim counts in,
	// and no longer than Lifetime.
	TTL time.Duration

	// MaxTokenBytes is the largest token Token signs; zero means
	// DefaultMaxTokenBytes, the largest a Checker reads by default. A
	// list that grows past it fails to publish rather than being served
	// to Relying Parties that refuse it: raise it, with theirs, for a
	// very large list.
	MaxTokenBytes int

	// CacheFor is how long ServeHTTP serves a token before signing a
	// new one. Zero means TTL when TTL is set, and 30 seconds
	// otherwise; negative means sign a new token for every request. It
	// is capped at half of Lifetime, so a served token is always valid
	// for at least half its lifetime.
	CacheFor time.Duration

	// OnError, if set, is called with the request and the error when
	// ServeHTTP can't sign a token: when it answers 500, and when it
	// answers with the form's cached token instead, still within its
	// exp, because signing a new one failed. The response doesn't carry
	// the error.
	OnError func(r *http.Request, err error)

	// Tokens, if set, shares the tokens between the replicas serving
	// the list (TokenStore): each serves a stored token signed from the
	// list's current statuses within CacheFor, and the one that takes
	// the store's lease signs a new one when there's none, rather than
	// every replica reading the statuses and signing its own. While a
	// replica holds the lease, the others serve the stored token for a
	// bounded time: one signed before the list's last status change
	// within CacheFor of its signing, as a replica sharing nothing
	// would serve its own, and one signed after it for a lease longer,
	// 35 seconds — the 30 a signature may take, and 5 more. Then they
	// sign their own: a replica that holds the lease but can't sign
	// keeps nobody serving its stale token. Invalidate has this replica sign
	// the next token itself. A stored token is served only by a replica
	// with the same leaf certificate in Chain: after a key or
	// certificate changes, a replica signs its own rather than serve the
	// old signer's, and while replicas with different signers serve the
	// list, as during a rollout, the token stored changes hands about
	// once per TokensCheck. Ignored when CacheFor is negative.
	Tokens TokenStore

	// TokensCheck is how often a replica asks Tokens for a newer token:
	// a status change reaches the others within it, plus the time a
	// replica takes to sign. Zero means DefaultTokensCheck; it's at
	// most CacheFor's effective value.
	TokensCheck time.Duration

	// Now defaults to time.Now.
	Now func() time.Time

	cached [2]listhttp.Cache // JWT, CWT
	holder listhttp.Holder
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
	if !cwt && p.cwtOnly() {
		http.Error(w, "this status list is served as "+CWTTokenMediaType+" only", http.StatusNotAcceptable)
		return
	}
	form, mediaType := FormJWT, TokenMediaType
	if cwt {
		form, mediaType = FormCWT, CWTTokenMediaType
	}
	// A signature ServeHTTP makes for its cache doesn't end with the
	// request that happens to start it.
	sign := func(ctx context.Context, now time.Time) ([]byte, time.Time, error) {
		return p.token(ctx, cwt, now)
	}
	var served listhttp.Served
	var err error
	if p.Tokens != nil {
		served, err = p.cached[form].GetShared(r.Context(), p.shared(form), p.now, sign)
	} else {
		served, err = p.cached[form].Get(r.Context(), p.cacheWindow(), p.now, sign)
	}
	if err != nil && p.OnError != nil {
		p.OnError(r, err)
	}
	if served.Token == nil {
		http.Error(w, "the status list is unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Vary", "Accept, Accept-Encoding")
	// draft-14 §8.2: the response "SHOULD use gzip Content-Encoding".
	gz := acceptsGzip(r.Header.Values("Accept-Encoding"))
	if err := listhttp.Write(w, r, served, mediaType, p.TTL, gz); err != nil {
		http.Error(w, "the status list is unavailable", http.StatusInternalServerError)
	}
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

// servesCWT reports whether accept asks for the CWT form: the form
// whose media type it gives the higher q (CWT on a tie), ignoring one
// it gives q=0 (RFC 9110 §12.5.1), and DefaultForm when it names
// neither with a q above zero.
func (p *Publisher) servesCWT(accept string) bool {
	jwtQ, cwtQ := 0.0, 0.0
	for _, part := range strings.Split(accept, ",") {
		mediaType, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		for _, param := range strings.Split(params, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(param), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(name), "q") {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || v < 0 || v > 1 {
				v = 0
			}
			q = v
		}
		switch mediaType = strings.TrimSpace(mediaType); {
		case strings.EqualFold(mediaType, CWTTokenMediaType):
			cwtQ = max(cwtQ, q)
		case strings.EqualFold(mediaType, TokenMediaType):
			jwtQ = max(jwtQ, q)
		}
	}
	if cwtQ == 0 && jwtQ == 0 {
		return p.DefaultForm == FormCWT
	}
	return cwtQ >= jwtQ
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
// change is served at once instead of within CacheFor. Until one is,
// ServeHTTP has no token to fall back on if signing fails. With Tokens,
// this replica signs that token whatever the store holds, and stores it
// for the others, which serve it from their next check: a store that
// keeps list versions needs no Invalidate for that.
func (p *Publisher) Invalidate() {
	for i := range p.cached {
		p.cached[i].Invalidate()
	}
}

// shared is how ServeHTTP shares form's tokens through Tokens.
func (p *Publisher) shared(form Form) listhttp.Shared {
	check := p.TokensCheck
	if check <= 0 {
		check = DefaultTokensCheck
	}
	return listhttp.Shared{
		Store: listhttp.StoreOf[Form](p.Tokens, p.URI, form), Holder: p.holder.Name(),
		Fresh: p.cacheWindow(), Check: check, Signer: signerOf(p.Chain),
	}
}

// signerOf names the signer whose chain is chain to a TokenStore: its
// leaf certificate's SHA-256.
func signerOf(chain []*x509.Certificate) []byte {
	if len(chain) == 0 {
		return nil
	}
	return listhttp.SignerOf(chain[0].Raw)
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
	token, _, err := p.token(ctx, cwt, p.now())
	return token, err
}

// token is Token for a token issued at now, and returns its exp.
func (p *Publisher) token(ctx context.Context, cwt bool, now time.Time) ([]byte, time.Time, error) {
	if p.URI == "" || p.Signer == nil || len(p.Chain) == 0 || p.Statuses == nil {
		return nil, time.Time{}, errors.New("statuslist: Publisher.URI, Signer, Chain and Statuses are required")
	}
	if err := p.validate(); err != nil {
		return nil, time.Time{}, err
	}
	limit, err := VerifyOptions{MaxTokenBytes: p.MaxTokenBytes}.maxTokenBytes()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("statuslist: Publisher.MaxTokenBytes: %w", err)
	}
	exp := now.Add(p.lifetime()).Unix()
	token, err := p.sign(ctx, cwt, now, exp)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(token) > limit {
		return nil, time.Time{}, fmt.Errorf("statuslist: the token is %d bytes, over the %d a Relying Party reads (Publisher.MaxTokenBytes)", len(token), limit)
	}
	return token, time.Unix(exp, 0), nil
}

// validate checks p's settings.
func (p *Publisher) validate() error {
	switch {
	case p.DefaultForm != FormJWT && p.DefaultForm != FormCWT:
		return fmt.Errorf("statuslist: Publisher.DefaultForm is %v, not FormJWT or FormCWT", p.DefaultForm)
	case p.Lifetime > 0 && p.Lifetime < time.Second:
		return fmt.Errorf("statuslist: Publisher.Lifetime is %s, under the one second a token's exp can express", p.Lifetime)
	case p.TTL > 0 && p.TTL < time.Second:
		return fmt.Errorf("statuslist: Publisher.TTL is %s, under the one second a ttl claim can express", p.TTL)
	case p.TTL > p.lifetime():
		return fmt.Errorf("statuslist: Publisher.TTL (%s) is longer than its Lifetime (%s)", p.TTL, p.lifetime())
	case p.DefaultForm == FormJWT && p.cwtOnly():
		return errors.New("statuslist: Publisher.Signer's key signs CWT tokens only (ES384 or ES512): set DefaultForm to FormCWT")
	}
	return nil
}

// cwtOnly reports whether the signer's key signs CWT tokens but not
// JWTs: a P-384 or P-521 key.
func (p *Publisher) cwtOnly() bool {
	if p.Signer == nil {
		return false
	}
	alg, err := cose.AlgForKey(p.Signer.Public())
	return err == nil && alg != cose.ES256 && alg != cose.EdDSA
}

// sign is token, before its size check: a token issued at now that
// expires at exp.
func (p *Publisher) sign(ctx context.Context, cwt bool, now time.Time, exp int64) ([]byte, error) {
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
	claims := TokenClaims{Sub: p.URI, Iat: now.Unix(), Exp: &exp, StatusList: sl}
	if p.TTL > 0 {
		ttl := int64(p.TTL.Seconds())
		claims.TTL = &ttl
	}
	alg, err := cose.AlgForKey(p.Signer.Public())
	if err != nil {
		return nil, fmt.Errorf("statuslist: Publisher.Signer: %w", err)
	}
	if cwt {
		return IssueTokenCWTX5Chain(p.Signer, alg, claims, p.Chain)
	}
	var joseAlg jose.Alg
	switch alg {
	case cose.ES256:
		joseAlg = jose.ES256
	case cose.EdDSA:
		joseAlg = jose.EdDSA
	default:
		return nil, errors.New("statuslist: Publisher.Signer's key signs CWT tokens only (ES384 or ES512), not JWTs")
	}
	token, err := IssueTokenX5C(p.Signer, joseAlg, claims, p.Chain)
	return []byte(token), err
}
