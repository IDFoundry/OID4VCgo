package verifier

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"sync"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// chainMemo is the outcome of each distinct certificate chain the
// built-in resolvers verified during one VerifyResponse call: an answer
// repeating one chain across its presentations (up to
// MaxPresentationsPerQuery per query), or an mdoc's x5chain resolved
// once for its key and once for its paths, costs its verification once.
type chainMemo struct {
	mu      sync.Mutex
	results map[chainMemoKey]chainResult
}

// chainMemoKey is one chain under one root pool, for one kind of
// resolver: within a VerifyResponse call, each kind's resolver is the
// request's own, so its policy and revocation checker are fixed too.
type chainMemoKey struct {
	kind  string
	roots *x509.CertPool
	chain [sha256.Size]byte
}

type chainResult struct {
	leaf   *x509.Certificate
	chains [][]*x509.Certificate
	err    error
}

type chainMemoContextKey struct{}

// withChainMemo is ctx carrying a new chainMemo.
func withChainMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, chainMemoContextKey{}, &chainMemo{results: make(map[chainMemoKey]chainResult)})
}

// verifyTrustedChains is certchain.VerifyTrustedChainsAt at
// verificationTime(ctx), its outcome memoized in ctx's chainMemo when
// it has one.
func verifyTrustedChains(ctx context.Context, kind string, ders [][]byte, roots *x509.CertPool, policy func(*x509.Certificate, [][]*x509.Certificate) error, revocation certrevocation.Checker) (*x509.Certificate, [][]*x509.Certificate, error) {
	memo, _ := ctx.Value(chainMemoContextKey{}).(*chainMemo)
	if memo == nil {
		return certchain.VerifyTrustedChainsAt(ctx, ders, roots, policy, revocation, verificationTime(ctx))
	}
	key := chainMemoKey{kind: kind, roots: roots, chain: hashChain(ders)}
	memo.mu.Lock()
	r, ok := memo.results[key]
	memo.mu.Unlock()
	if ok {
		return r.leaf, r.chains, r.err
	}
	r.leaf, r.chains, r.err = certchain.VerifyTrustedChainsAt(ctx, ders, roots, policy, revocation, verificationTime(ctx))
	memo.mu.Lock()
	memo.results[key] = r
	memo.mu.Unlock()
	return r.leaf, r.chains, r.err
}

// hashChain identifies ders, each entry length-prefixed so that no two
// chains share an identity.
func hashChain(ders [][]byte) [sha256.Size]byte {
	h := sha256.New()
	var n [8]byte
	for _, der := range ders {
		binary.BigEndian.PutUint64(n[:], uint64(len(der)))
		h.Write(n[:])
		h.Write(der)
	}
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}
