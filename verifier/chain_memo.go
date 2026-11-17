package verifier

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// MaxFailedIssuerChainsPerResponse bounds how many distinct issuer
// certificate chains that fail to verify VerifyResponse tries for one
// response, through a VerifyResponseRequest.IssuerKeys that is an
// X5CIssuerKeyResolver or an MdocIssuerKeys that is an
// X5ChainIssuerKeyResolver. Once that many have failed, the response is
// refused before any further chain is verified. Chains that verify
// aren't counted, so an honest response presenting credentials from
// many issuers is never refused by it; a crafted one, whose chains no
// configured root anchors, is stopped after a few cheap failures. A
// chain repeated across presentations counts once.
const MaxFailedIssuerChainsPerResponse = 4

// chainMemo is the outcome of each distinct certificate chain the
// request's own built-in resolvers verified during one VerifyResponse
// call: an answer repeating one chain across its presentations (up to
// MaxPresentationsPerQuery per query), or an mdoc's x5chain resolved
// once for its key and once for its paths, costs its verification once.
//
// It is passed explicitly, and only to VerifyResponseRequest.IssuerKeys
// or MdocIssuerKeys when that is itself the built-in resolver: within
// the call, each kind's resolver is then one value, so its leaf policy,
// revocation checker and verification time are fixed. A resolver of
// the caller's own, dispatching to several built-in ones with different
// policies, never sees it.
type chainMemo struct {
	mu      sync.Mutex
	results map[chainMemoKey]chainResult
	failed  int // distinct chains in results that failed to verify
}

// chainMemoKey is one chain under one root pool, for one kind of
// resolver.
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

func newChainMemo() *chainMemo {
	return &chainMemo{results: make(map[chainMemoKey]chainResult)}
}

// errTooManyIssuerChains refuses a response once
// MaxFailedIssuerChainsPerResponse of its distinct chains have failed:
// VerifyResponse refuses the whole response, not just the presentation
// that went over.
var errTooManyIssuerChains = fmt.Errorf("%d distinct issuer certificate chains in one response failed to verify", MaxFailedIssuerChainsPerResponse)

// verifyTrustedChains is certchain.VerifyTrustedChainsAt at
// verificationTime(ctx), its outcome memoized in memo when it isn't
// nil. A memo whose failed chains have reached
// MaxFailedIssuerChainsPerResponse refuses another chain with
// errTooManyIssuerChains, unverified.
func verifyTrustedChains(ctx context.Context, memo *chainMemo, kind string, ders [][]byte, roots *x509.CertPool, policy func(*x509.Certificate, [][]*x509.Certificate) error, revocation certrevocation.Checker) (*x509.Certificate, [][]*x509.Certificate, error) {
	if memo == nil {
		return certchain.VerifyTrustedChainsAt(ctx, ders, roots, policy, revocation, verificationTime(ctx))
	}
	key := chainMemoKey{kind: kind, roots: roots, chain: hashChain(ders)}
	memo.mu.Lock()
	r, ok := memo.results[key]
	full := memo.failed >= MaxFailedIssuerChainsPerResponse
	memo.mu.Unlock()
	if ok {
		return r.leaf, r.chains, r.err
	}
	if full {
		return nil, nil, errTooManyIssuerChains
	}
	r.leaf, r.chains, r.err = certchain.VerifyTrustedChainsAt(ctx, ders, roots, policy, revocation, verificationTime(ctx))
	memo.mu.Lock()
	if _, seen := memo.results[key]; !seen && r.err != nil {
		memo.failed++
	}
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
