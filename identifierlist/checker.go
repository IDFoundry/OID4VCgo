package identifierlist

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/statuscache"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Checker checks an MSO's identifier list reference end to end: it
// fetches the list at ref.URI, then Checks it. Fetcher is
// statuslist.Fetcher, with its https-only, redirect, content type,
// size and public-address rules; a zero MaxBytes means this package's
// own 4 MiB. The list must be served as MediaType.
//
// A Checker holds nothing about any one credential, so one serves
// every credential: each Check is given the MSO's reference and its
// document signer path, and binds the list's signer to that mdoc's
// issuer (ISO/IEC 18013-5 §12.3.6.2) itself.
//
// Without a Cache, each Check fetches the list and verifies it again,
// and a list near the 4 MiB limit takes a noticeable fraction of a
// second to parse. With one, a list is kept as statuslist.Cache
// describes, for no longer than its ttl and exp allow, and each Check
// verifies the cached list again against its own MSO's binding, its
// signer's chain, its signature and its times, but doesn't parse it
// again.
type Checker struct {
	Fetcher statuslist.Fetcher

	// Roots are the trust anchors for list signers when the reference
	// names no Certificate: normally the IACA certificates the mdoc
	// issuers chain to. A signer must also be under the CA that signed
	// the mdoc's document signer, not just under any of them: Check
	// refuses a reference with no Certificate given no document signer
	// path, unless Options.UnboundSigner decides the signer.
	Roots *x509.CertPool

	Options VerifyOptions

	// Cache, if set, keeps the lists this Checker and others sharing it
	// fetched and verified; statuslist.Checkers may share it too. Nil
	// fetches every list afresh.
	Cache *statuslist.Cache
}

// Check validates ref, fetches the list it names and checks it, as
// Check does: documentSignerPath is the MSO's IssuerAuth x5chain as
// verified, and ref and it must come from a verified MSO. With an
// error, revoked is true. With a Cache, the identifiers returned share
// memory with it: treat them as read-only.
func (c Checker) Check(ctx context.Context, ref Ref, documentSignerPath []*x509.Certificate) (revoked bool, claims TokenClaims, err error) {
	if err := ref.validate(); err != nil {
		return true, TokenClaims{}, err
	}
	f := c.Fetcher
	if f.MaxBytes <= 0 {
		f.MaxBytes = maxTokenBytes
	}
	if engine := statuscache.Unwrap(c.Cache); engine != nil {
		claims, err = c.checkCached(ctx, engine, f, ref, documentSignerPath)
	} else {
		claims, err = c.checkFetched(ctx, f, ref, documentSignerPath)
	}
	if err != nil {
		return true, TokenClaims{}, err
	}
	return claims.Contains(ref.ID), claims, nil
}

// checkFetched is Check without a Cache.
func (c Checker) checkFetched(ctx context.Context, f statuslist.Fetcher, ref Ref, documentSignerPath []*x509.Certificate) (TokenClaims, error) {
	token, err := fetch(ctx, f, ref.URI)
	if err != nil {
		return TokenClaims{}, err
	}
	parsed, err := check(ctx, token, c.Roots, ref, documentSignerPath, c.Options, nil)
	return parsed.claims, err
}

func fetch(ctx context.Context, f statuslist.Fetcher, uri string) ([]byte, error) {
	token, err := f.Fetch(ctx, uri, MediaType)
	if err != nil {
		return nil, fmt.Errorf("identifierlist: %w", err)
	}
	return token, nil
}

// checkCached is Check through engine: each list it's handed, cached
// or fetched, is checked against this Checker's trust and ref's
// binding.
func (c Checker) checkCached(ctx context.Context, engine *statuscache.Cache, f statuslist.Fetcher, ref Ref, documentSignerPath []*x509.Certificate) (TokenClaims, error) {
	var claims TokenClaims
	err := engine.Check(ctx, ref.URI, MediaType, fetcherKey(f),
		func(ctx context.Context) ([]byte, error) { return fetch(ctx, f, ref.URI) },
		func(token []byte, memo any) (statuscache.Verified, error) {
			// A list another Checker's Fetcher fetched may be larger than
			// this one's would.
			if len(token) > f.MaxBytes {
				return statuscache.Verified{}, fmt.Errorf("identifierlist: statuslist: fetch %s: token exceeds %d bytes", ref.URI, f.MaxBytes)
			}
			m, _ := memo.(*tokenMemo)
			m = m.of(token)
			parsed, err := check(ctx, token, c.Roots, ref, documentSignerPath, c.Options, m.parsedClaims())
			if err != nil {
				return statuscache.Verified{}, err
			}
			claims = parsed.claims.clone()
			if m == nil {
				m = &tokenMemo{digest: sha256.Sum256(token), parsed: parsed}
			}
			return statuscache.Verified{
				Iat: parsed.claims.Iat, Exp: parsed.claims.Exp, TTL: parsed.claims.TTL,
				Memo: m, MemoBytes: m.size(),
			}, nil
		})
	return claims, err
}

// fetcherKey names f's configuration, so that only checks whose
// Fetchers would fetch alike share a fetch.
func fetcherKey(f statuslist.Fetcher) string {
	return fmt.Sprintf("%p/%d/%t/%t/%t/%t", f.HTTP, f.MaxBytes, f.AllowLoopback, f.AllowPrivate, f.AllowProxy, f.UncheckedTransport)
}

// tokenMemo is what a Cache keeps of a verified list's bytes beyond the
// bytes themselves: its parsed claims, which depend on those bytes
// alone, which digest names.
type tokenMemo struct {
	digest [sha256.Size]byte
	parsed parsedClaims
}

// of is m if it was made from token's bytes, nil otherwise.
func (m *tokenMemo) of(token []byte) *tokenMemo {
	if m == nil || m.digest != sha256.Sum256(token) {
		return nil
	}
	return m
}

// parsedClaims is m's parsed claims, nil for a nil m.
func (m *tokenMemo) parsedClaims() *parsedClaims {
	if m == nil {
		return nil
	}
	return &m.parsed
}

// size is roughly how many bytes m holds: the identifiers share the
// verified payload, a copy of the token's.
func (m *tokenMemo) size() int {
	n := len(m.parsed.claims.Sub)
	for _, id := range m.parsed.claims.Identifiers {
		n += len(id) + 24
	}
	return n
}

// clone is c with its own exp, ttl and identifier slice, so a caller
// changing them doesn't change a Cache's; the identifiers' bytes are
// still shared.
func (c TokenClaims) clone() TokenClaims {
	if c.Exp != nil {
		exp := *c.Exp
		c.Exp = &exp
	}
	if c.TTL != nil {
		ttl := *c.TTL
		c.TTL = &ttl
	}
	c.Identifiers = slices.Clone(c.Identifiers)
	return c
}

// ErrRevoked is RequireNotRevoked's error for an MSO on its list.
var ErrRevoked = errors.New("identifierlist: the MSO's identifier is on its identifier list: it is revoked")

// RequireNotRevoked checks ref as Check does, and returns nil only when
// the MSO isn't revoked: ErrRevoked when it is, and Check's error when
// the list can't be read.
func (c Checker) RequireNotRevoked(ctx context.Context, ref Ref, documentSignerPath []*x509.Certificate) error {
	revoked, _, err := c.Check(ctx, ref, documentSignerPath)
	if err != nil {
		return err
	}
	if revoked {
		return ErrRevoked
	}
	return nil
}
