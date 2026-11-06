package identifierlist

import (
	"context"
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
// size and public-address rules; a zero MaxBytes means
// Options.MaxTokenBytes, or when that's zero too, this package's own
// DefaultMaxTokenBytes. The list must be served as MediaType.
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
// checks the cached list again against its own MSO's binding, its
// signer's chain and revocation, and its times, but doesn't verify its
// signature or parse it again. Check copies the cached identifiers'
// slice for its caller; RequireNotRevoked doesn't need to.
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
	claims, cached, err := c.check(ctx, ref, documentSignerPath)
	if err != nil {
		return true, TokenClaims{}, err
	}
	if cached {
		claims = claims.clone()
	}
	return claims.listed(ref.ID), claims, nil
}

// check is Check before deciding revoked, with the claims as verified:
// a Cache's own when cached is set.
func (c Checker) check(ctx context.Context, ref Ref, documentSignerPath []*x509.Certificate) (claims TokenClaims, cached bool, err error) {
	if err := ref.validate(); err != nil {
		return TokenClaims{}, false, err
	}
	opts := c.Options
	if opts.MaxTokenBytes == 0 {
		opts.MaxTokenBytes = c.Fetcher.MaxBytes
	}
	limit, err := maxTokenBytes("VerifyOptions.MaxTokenBytes", opts.MaxTokenBytes)
	if err != nil {
		return TokenClaims{}, false, err
	}
	f := c.Fetcher
	if f.MaxBytes <= 0 {
		f.MaxBytes = limit
	}
	c.Options = opts
	if engine := statuscache.Unwrap(c.Cache); engine != nil {
		claims, err = c.checkCached(ctx, engine, f, ref, documentSignerPath)
		return claims, true, err
	}
	claims, err = c.checkFetched(ctx, f, ref, documentSignerPath)
	return claims, false, err
}

// checkFetched is Check without a Cache.
func (c Checker) checkFetched(ctx context.Context, f statuslist.Fetcher, ref Ref, documentSignerPath []*x509.Certificate) (TokenClaims, error) {
	token, err := fetch(ctx, f, ref.URI)
	if err != nil {
		return TokenClaims{}, err
	}
	parsed, _, err := check(ctx, token, c.Roots, ref, documentSignerPath, c.Options)
	return parsed.claims, err
}

func fetch(ctx context.Context, f statuslist.Fetcher, uri string) ([]byte, error) {
	token, err := f.Fetch(ctx, uri, MediaType)
	if err != nil {
		return nil, fmt.Errorf("identifierlist: %w", err)
	}
	return token, nil
}

// checkCached is Check through engine: a list it fetches is verified
// in full, and one a check verified before is checked again, from its
// memo, against this Checker's trust and ref's binding.
func (c Checker) checkCached(ctx context.Context, engine *statuscache.Cache, f statuslist.Fetcher, ref Ref, documentSignerPath []*x509.Certificate) (TokenClaims, error) {
	var used *tokenMemo
	err := engine.Check(ctx, ref.URI, MediaType, fetcherKey(f),
		func(ctx context.Context) ([]byte, error) { return fetch(ctx, f, ref.URI) },
		func(token []byte) (statuscache.Verified, error) {
			parsed, chain, err := check(ctx, token, c.Roots, ref, documentSignerPath, c.Options)
			if err != nil {
				return statuscache.Verified{}, err
			}
			m := &tokenMemo{size: len(token), parsed: parsed}
			// Copied, so that m doesn't keep the token's bytes alive.
			for _, der := range chain {
				m.chain = append(m.chain, slices.Clone(der))
			}
			used = m
			return statuscache.Verified{
				Iat: parsed.claims.Iat, Exp: parsed.claims.Exp, TTL: parsed.claims.TTL,
				Memo: m, MemoBytes: m.bytes(),
			}, nil
		},
		func(memo any) error {
			m, ok := memo.(*tokenMemo)
			if !ok {
				return errors.New("identifierlist: the cached entry isn't an identifier list's")
			}
			// A list another Checker's Fetcher fetched may be larger than
			// this one's would.
			if m.size > f.MaxBytes {
				return fmt.Errorf("identifierlist: statuslist: fetch %s: token exceeds %d bytes", ref.URI, f.MaxBytes)
			}
			if err := recheck(ctx, m.chain, m.parsed, c.Roots, ref, documentSignerPath, c.Options); err != nil {
				return err
			}
			used = m
			return nil
		})
	if err != nil {
		return TokenClaims{}, err
	}
	return used.parsed.claims, nil
}

// fetcherKey names f's configuration, so that only checks whose
// Fetchers would fetch alike share a fetch.
func fetcherKey(f statuslist.Fetcher) string {
	return fmt.Sprintf("%p/%d/%t/%t/%t/%t", f.HTTP, f.MaxBytes, f.AllowLoopback, f.AllowPrivate, f.AllowProxy, f.UncheckedTransport)
}

// tokenMemo is what a Cache keeps of a list a check verified in full:
// what that check found that depends on the list's bytes alone, without
// the bytes — their size, the signer's chain the list carries, whose
// leaf's key its signature verified under, and its claims as parsed.
type tokenMemo struct {
	size   int
	chain  [][]byte
	parsed parsedClaims
}

// bytes is roughly how many bytes m holds: the identifiers share the
// verified payload, a copy of the token's and no larger.
func (m *tokenMemo) bytes() int {
	n := m.size + len(m.parsed.claims.Sub) + 24*len(m.parsed.claims.Identifiers)
	for _, der := range m.chain {
		n += len(der)
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
	// The claims aren't returned, so a Cache's aren't copied.
	claims, _, err := c.check(ctx, ref, documentSignerPath)
	if err != nil {
		return err
	}
	if claims.listed(ref.ID) {
		return ErrRevoked
	}
	return nil
}
