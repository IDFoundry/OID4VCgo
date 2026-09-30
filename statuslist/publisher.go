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
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// Publisher serves a Status List Token at its uri (draft-14 §8.1): an
// http.Handler that signs a fresh token for each request from the
// current statuses, in the form the Accept header asks for — CWT for
// CWTTokenMediaType (an mdoc's reference), JWT otherwise (an SD-JWT
// VC's) — carrying the signer's certificate chain as x5c/x5chain, as
// HAIP 1.0 §6.1 requires. The signing algorithm follows the signer's
// key: ES256 for P-256, EdDSA for Ed25519.
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

	// Now defaults to time.Now.
	Now func() time.Time
}

// ServeHTTP implements http.Handler.
func (p Publisher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cwt := strings.Contains(r.Header.Get("Accept"), CWTTokenMediaType)
	token, err := p.Token(r.Context(), cwt)
	if err != nil {
		http.Error(w, "the status list is unavailable", http.StatusInternalServerError)
		return
	}
	mediaType := TokenMediaType
	if cwt {
		mediaType = CWTTokenMediaType
	}
	w.Header().Set("Content-Type", mediaType)
	if p.TTL > 0 {
		w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(int(p.TTL.Seconds())))
	}
	_, _ = w.Write(token)
}

// Token signs a Status List Token for the current statuses: CWT when
// cwt is true, JWT otherwise.
func (p Publisher) Token(ctx context.Context, cwt bool) ([]byte, error) {
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
	now := time.Now()
	if p.Now != nil {
		now = p.Now()
	}
	lifetime := p.Lifetime
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	exp := now.Add(lifetime).Unix()
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
