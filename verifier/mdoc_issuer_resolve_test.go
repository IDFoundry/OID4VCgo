package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

const resolveDocType = "org.iso.18013.5.1.mDL"

// revokingChecker refuses every chain as revoked.
type revokingChecker struct{}

func (revokingChecker) CheckRevocation(context.Context, certrevocation.Check) error {
	return certrevocation.ErrRevoked
}

// wrapper wraps an X5ChainIssuerKeyResolver, as a logging or caching
// resolver would.
type wrapper struct {
	verifier.X5ChainIssuerKeyResolver
}

func (w wrapper) Unwrap() verifier.MdocIssuerKeyResolver { return w.X5ChainIssuerKeyResolver }

type resolveFixture struct {
	iaca  *x509.Certificate
	ds    *x509.Certificate
	dsKey *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newResolveFixture(t testing.TB) resolveFixture {
	t.Helper()
	iaca, iacaKey, _, _, err := conformancecert.GenerateMdocIACA("resolve test IACA", "US", "https://iaca.example")
	if err != nil {
		t.Fatal(err)
	}
	dsKey, _, dsPEM, err := conformancecert.GenerateMdocDocumentSigner("resolve test DS", "US", "https://iaca.example", "https://iaca.example/crl", iaca, iacaKey)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(dsPEM))
	ds, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	return resolveFixture{iaca: iaca, ds: ds, dsKey: dsKey, roots: roots}
}

func signedNow() mdoc.VerifiedMSO {
	return mdoc.VerifiedMSO{ValidityInfo: mdoc.ValidityInfo{Signed: time.Now()}}
}

// ResolveMdocIssuer and Check give what ResolveMdocIssuerKey and
// CheckMdocIssuer give, verifying an X5ChainIssuerKeyResolver's chain
// once instead of twice; a wrapping resolver is still asked twice.
func TestResolveMdocIssuer_VerifiesTheChainOnce(t *testing.T) {
	f := newResolveFixture(t)
	ctx := context.Background()
	x5chain := [][]byte{f.ds.Raw}

	for _, tc := range []struct {
		name      string
		resolver  func(countingRevocation) verifier.MdocIssuerKeyResolver
		wantCalls int32
	}{
		{"value", func(r countingRevocation) verifier.MdocIssuerKeyResolver {
			return verifier.X5ChainIssuerKeyResolver{Roots: f.roots, Revocation: r}
		}, 1},
		{"pointer", func(r countingRevocation) verifier.MdocIssuerKeyResolver {
			return &verifier.X5ChainIssuerKeyResolver{Roots: f.roots, Revocation: r}
		}, 1},
		{"wrapped", func(r countingRevocation) verifier.MdocIssuerKeyResolver {
			return wrapper{verifier.X5ChainIssuerKeyResolver{Roots: f.roots, Revocation: r}}
		}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := countingRevocation{new(atomic.Int32)}
			key, alg, err := tc.resolver(before).ResolveMdocIssuerKey(ctx, x5chain, resolveDocType)
			if err != nil {
				t.Fatal(err)
			}
			wantChain, err := verifier.CheckMdocIssuer(ctx, tc.resolver(before), x5chain, resolveDocType, key, signedNow())
			if err != nil {
				t.Fatal(err)
			}

			revocation := countingRevocation{new(atomic.Int32)}
			issuer, err := verifier.ResolveMdocIssuer(ctx, tc.resolver(revocation), x5chain, resolveDocType)
			if err != nil {
				t.Fatalf("ResolveMdocIssuer: %v", err)
			}
			if !f.dsKey.PublicKey.Equal(issuer.Key) || issuer.Alg != alg {
				t.Errorf("key %v, alg %v; want the document signer's, %v", issuer.Key, issuer.Alg, alg)
			}
			chain, err := issuer.Check(ctx, signedNow())
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if !slices.EqualFunc(chain, wantChain, slices.Equal) || len(chain) != 1 {
				t.Errorf("chain has %d certificates, want CheckMdocIssuer's %d", len(chain), len(wantChain))
			}
			if got := revocation.checks.Load(); got != tc.wantCalls {
				t.Errorf("revocation asked about %d paths, want %d (ResolveMdocIssuerKey then CheckMdocIssuer: %d)", got, tc.wantCalls, before.checks.Load())
			}
		})
	}
}

// Verifying the chain once refuses everything verifying it twice did:
// an untrusted, revoked or expired document signer when the key is
// resolved, and one failing the document signer checks at Check.
func TestResolveMdocIssuer_StillRefuses(t *testing.T) {
	f := newResolveFixture(t)
	other, _, _, _, err := conformancecert.GenerateMdocIACA("another IACA", "US", "https://other.example")
	if err != nil {
		t.Fatal(err)
	}
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(other)
	x5chain := [][]byte{f.ds.Raw}

	for _, tc := range []struct {
		name     string
		resolver verifier.X5ChainIssuerKeyResolver
		ctx      context.Context
	}{
		{"untrusted", verifier.X5ChainIssuerKeyResolver{Roots: otherRoots, Revocation: certrevocation.NoCheck{}}, context.Background()},
		{"revoked", verifier.X5ChainIssuerKeyResolver{Roots: f.roots, Revocation: revokingChecker{}}, context.Background()},
		{"expired", verifier.X5ChainIssuerKeyResolver{Roots: f.roots, Revocation: certrevocation.NoCheck{}}, verifier.WithVerificationTime(context.Background(), f.ds.NotAfter.Add(time.Hour))},
		{"no revocation", verifier.X5ChainIssuerKeyResolver{Roots: f.roots}, context.Background()},
		{"no roots for the type", verifier.X5ChainIssuerKeyResolver{RootsByDocType: map[string]*x509.CertPool{"org.example.other": f.roots}, Revocation: certrevocation.NoCheck{}}, context.Background()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifier.ResolveMdocIssuer(tc.ctx, tc.resolver, x5chain, resolveDocType); err == nil {
				t.Error("ResolveMdocIssuer accepted the chain")
			}
		})
	}

	resolver := verifier.X5ChainIssuerKeyResolver{Roots: f.roots, Revocation: certrevocation.NoCheck{}}
	issuer, err := verifier.ResolveMdocIssuer(context.Background(), resolver, x5chain, resolveDocType)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		verified mdoc.VerifiedMSO
	}{
		{"signed outside the signer's validity", mdoc.VerifiedMSO{ValidityInfo: mdoc.ValidityInfo{Signed: f.ds.NotAfter.Add(time.Hour)}}},
		{"another issuing country", mdoc.VerifiedMSO{
			ValidityInfo: mdoc.ValidityInfo{Signed: time.Now()},
			NameSpaces:   map[string]map[string]any{"org.iso.18013.5.1": {"issuing_country": "FR"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := issuer.Check(context.Background(), tc.verified); err == nil {
				t.Error("Check accepted the document signer")
			}
			if _, err := verifier.CheckMdocIssuer(context.Background(), resolver, x5chain, resolveDocType, issuer.Key, tc.verified); err == nil {
				t.Error("CheckMdocIssuer accepted the document signer")
			}
		})
	}
}

// BenchmarkMdocIssuer compares resolving and checking an mdoc issuer as
// two calls, each verifying the chain, with ResolveMdocIssuer and Check.
func BenchmarkMdocIssuer(b *testing.B) {
	f := newResolveFixture(b)
	ctx := context.Background()
	x5chain := [][]byte{f.ds.Raw}
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: f.roots, Revocation: certrevocation.NoCheck{}}
	verified := signedNow()
	b.Run("ResolveMdocIssuerKey+CheckMdocIssuer", func(b *testing.B) {
		for b.Loop() {
			key, _, err := resolver.ResolveMdocIssuerKey(ctx, x5chain, resolveDocType)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := verifier.CheckMdocIssuer(ctx, resolver, x5chain, resolveDocType, key, verified); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ResolveMdocIssuer+Check", func(b *testing.B) {
		for b.Loop() {
			issuer, err := verifier.ResolveMdocIssuer(ctx, resolver, x5chain, resolveDocType)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := issuer.Check(ctx, verified); err != nil {
				b.Fatal(err)
			}
		}
	})
}
