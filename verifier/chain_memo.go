package verifier

import (
	"context"
	"crypto"
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
// refused as a whole when the next distinct chain is reached, unverified.
//
// Only chains that don't verify count: those no configured root anchors,
// with a signature that doesn't verify, or with a certificate that
// doesn't parse or is outside its validity. A crafted response, whose
// chains no configured root anchors, is stopped after a few cheap
// failures. A chain that verifies isn't counted, even when its leaf
// policy (LeafPolicy) or revocation check then refuses it: its
// certificates come from a CA the Verifier trusts. So a response
// presenting credentials from many issuers, revoked ones among them,
// isn't refused by it, whatever their order; one with more than
// MaxFailedIssuerChainsPerResponse credentials from issuers no root
// anchors still is, even beside a valid one. A chain repeated across
// presentations counts once.
//
// VerifyResponse also counts each presentation whose chain fails toward
// MaxFailedPresentationsPerResponse, with every other failed check, so
// it refuses such a response at the same point or sooner.
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
	failed  int // distinct chains in results that didn't verify
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
// MaxFailedIssuerChainsPerResponse of its distinct chains haven't
// verified:
// VerifyResponse refuses the whole response, not just the presentation
// that went over.
var errTooManyIssuerChains = fmt.Errorf("%d distinct issuer certificate chains in one response failed to verify", MaxFailedIssuerChainsPerResponse)

// leafSignature checks a credential's signature with pub, the key of
// the leaf of the chain the credential presents, before that chain is
// verified (see verifyTrustedChains). It returns nil for a key it has
// no algorithm for, leaving that to the chain's own checks.
type leafSignature func(pub crypto.PublicKey) error

// issuerSignatureError is a credential whose signature doesn't verify
// with the key of the leaf certificate it presents: refused whatever
// the chain, which isn't verified.
type issuerSignatureError struct{ err error }

func (e *issuerSignatureError) Error() string {
	return "the credential's signature doesn't verify with its issuer certificate's key: " + e.err.Error()
}

func (e *issuerSignatureError) Unwrap() error { return e.err }

// checkLeafSignature runs signed, if set, with the key of ders' leaf,
// not yet trusted: a credential whose signature doesn't verify with it
// is refused before its chain costs a check. A leaf that doesn't parse,
// or whose key the chain check would refuse, is left to that check.
func checkLeafSignature(ders [][]byte, signed leafSignature) error {
	if signed == nil || len(ders) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil || certchain.CheckKeySize(leaf) != nil {
		return nil
	}
	if err := signed(leaf.PublicKey); err != nil {
		return &issuerSignatureError{err}
	}
	return nil
}

// verifyTrustedChains is certchain.VerifyTrustedChainsAt at
// verificationTime(ctx), its outcome memoized in memo when it isn't
// nil. A memo whose chains that didn't verify have reached
// MaxFailedIssuerChainsPerResponse refuses another chain with
// errTooManyIssuerChains, unverified. With signed set, the
// credential's signature is first checked with the leaf's key
// (checkLeafSignature): a genuine chain replayed under a signature its
// key didn't make costs no chain check, and isn't counted.
func verifyTrustedChains(ctx context.Context, memo *chainMemo, kind string, ders [][]byte, roots *x509.CertPool, policy func(*x509.Certificate, [][]*x509.Certificate) error, revocation certrevocation.Checker, signed leafSignature) (*x509.Certificate, [][]*x509.Certificate, error) {
	if err := checkLeafSignature(ders, signed); err != nil {
		return nil, nil, err
	}
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
	// certchain.VerifyTrustedChainsAt, step by step: a chain counts
	// toward MaxFailedIssuerChainsPerResponse only when it doesn't
	// verify, not when a chain that does is then refused by the leaf
	// policy or revocation.
	now := verificationTime(ctx)
	r.leaf, r.chains, r.err = certchain.VerifyChainsAt(ders, roots, now)
	unverified := r.err != nil
	if unverified {
		r.err = &unverifiedChainError{r.err}
	} else {
		if r.chains, r.err = certchain.ApprovedChains(r.leaf, r.chains, policy); r.err == nil {
			r.chains, r.err = certchain.NotRevokedChains(ctx, r.chains, revocation, now)
		}
		if r.err != nil {
			r.leaf, r.chains = nil, nil
		}
	}
	memo.mu.Lock()
	if _, seen := memo.results[key]; !seen && unverified {
		memo.failed++
	}
	memo.results[key] = r
	memo.mu.Unlock()
	return r.leaf, r.chains, r.err
}

// unverifiedChainError is a chain that didn't verify, as
// MaxFailedIssuerChainsPerResponse counts it, rather than one that
// verified and was then refused: VerifyResponse counts a presentation
// whose chain didn't verify toward MaxFailedPresentationsPerResponse.
type unverifiedChainError struct{ err error }

func (e *unverifiedChainError) Error() string { return e.err.Error() }
func (e *unverifiedChainError) Unwrap() error { return e.err }

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
