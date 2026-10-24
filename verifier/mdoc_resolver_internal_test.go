package verifier

import (
	"context"
	"crypto"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// loggingResolver wraps another resolver, as a logging or caching one
// would.
type loggingResolver struct{ inner MdocIssuerKeyResolver }

func (l loggingResolver) ResolveMdocIssuerKey(ctx context.Context, x5chain [][]byte, docType string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	return l.inner.ResolveMdocIssuerKey(ctx, x5chain, docType)
}

func (l loggingResolver) Unwrap() MdocIssuerKeyResolver { return l.inner }

// keyOnlyResolver authenticates a key but verifies no chain.
type keyOnlyResolver struct{}

func (keyOnlyResolver) ResolveMdocIssuerKey(context.Context, [][]byte, string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	return nil, 0, nil
}

// A wrapped chain resolver still gets the document signer checks,
// through Unwrap; one that verifies no chain doesn't, and production
// refuses it.
func TestMdocChainResolver(t *testing.T) {
	inner := X5ChainIssuerKeyResolver{}
	if got, ok := mdocChainResolver(loggingResolver{loggingResolver{inner}}); !ok || got == nil {
		t.Error("a twice-wrapped X5ChainIssuerKeyResolver wasn't found")
	}
	if _, ok := mdocChainResolver(keyOnlyResolver{}); ok {
		t.Error("a key-only resolver was taken for a chain resolver")
	}
	if _, ok := mdocChainResolver(loggingResolver{keyOnlyResolver{}}); ok {
		t.Error("a wrapped key-only resolver was taken for a chain resolver")
	}
}

// A wrapped resolver without Revocation is refused through Unwrap, as
// an unwrapped one is.
func TestCheckIssuerKeysValid_Wrapped(t *testing.T) {
	if err := checkIssuerKeysValid(VerifyResponseRequest{MdocIssuerKeys: loggingResolver{X5ChainIssuerKeyResolver{}}}); err == nil {
		t.Error("a wrapped X5ChainIssuerKeyResolver without Revocation was accepted")
	}
	ok := loggingResolver{X5ChainIssuerKeyResolver{Revocation: certrevocation.NoCheck{}}}
	if err := checkIssuerKeysValid(VerifyResponseRequest{MdocIssuerKeys: ok}); err != nil {
		t.Errorf("a wrapped resolver with NoCheck: %v", err)
	}
	if err := checkIssuerKeysValid(VerifyResponseRequest{MdocIssuerKeys: loggingResolver{keyOnlyResolver{}}}); err != nil {
		t.Errorf("a resolver with no Validate: %v", err)
	}
}
