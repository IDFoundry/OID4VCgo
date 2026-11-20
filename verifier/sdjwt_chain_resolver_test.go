package verifier_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// sdJWTVCWrapper wraps another SDJWTVCIssuerKeyResolver, as a caching
// or logging layer would: it declares LiveFetchHardened and Unwraps to
// it.
type sdJWTVCWrapper struct {
	inner verifier.SDJWTVCIssuerKeyResolver
}

func (w sdJWTVCWrapper) ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	return w.inner.ResolveIssuerKey(ctx, header, payload)
}

func (sdJWTVCWrapper) Capabilities() verifier.KeySourceCapabilities {
	return verifier.KeySourceCapabilities{LiveFetchHardened: true}
}

func (w sdJWTVCWrapper) Unwrap() verifier.SDJWTVCIssuerKeyResolver { return w.inner }

// hardenedKeyOnlySDJWTResolver is a keyOnlySDJWTResolver, verifying no
// chain, that declares LiveFetchHardened: a resolver trusting issuers'
// keys from their metadata would look the same to the Verifier.
type hardenedKeyOnlySDJWTResolver struct{ keyOnlySDJWTResolver }

func (hardenedKeyOnlySDJWTResolver) Capabilities() verifier.KeySourceCapabilities {
	return verifier.KeySourceCapabilities{LiveFetchHardened: true}
}

// productionVerifier is a Verifier under AssuranceProduction.
func productionVerifier(t *testing.T) *verifier.Verifier {
	t.Helper()
	cfg, deps := validConfig(t)
	caIssuedClientCert(t, &cfg, &deps)
	cfg.Assurance = verifier.AssuranceProduction
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Under AssuranceProduction, an SD-JWT VC issuer key resolver must
// verify issuer chains (an SDJWTVCIssuerChainResolver, or a wrapper that
// Unwraps to one), unless AllowUnanchoredSDJWTVCIssuers says its issuers
// are trusted without certificates: otherwise IssuerAnchor is nil and
// no hook can tell which trusted CA vouched for an issuer. Development
// is unchanged.
func TestVerifyResponse_ProductionRequiresSDJWTVCChainResolver(t *testing.T) {
	ca, _ := testcert.CA(t, "issuer CA")
	x5c := verifier.X5CIssuerKeyResolver{Roots: certPool(ca), Revocation: certrevocation.NoCheck{}}
	keyOnly := hardenedKeyOnlySDJWTResolver{keyOnlySDJWTResolver{x5c}}
	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system root pool: %v", err)
	}
	const refusal = "issuer_keys must verify issuer chains"
	for _, tc := range []struct {
		name        string
		production  bool
		keys        verifier.SDJWTVCIssuerKeyResolver
		unanchored  bool
		wantRefusal string
	}{
		{name: "key only", production: true, keys: keyOnly, wantRefusal: refusal},
		{name: "key only, unanchored issuers allowed", production: true, keys: keyOnly, unanchored: true},
		{name: "X5CIssuerKeyResolver", production: true, keys: x5c},
		{name: "*X5CIssuerKeyResolver", production: true, keys: &x5c},
		{name: "a wrapped X5CIssuerKeyResolver", production: true, keys: sdJWTVCWrapper{x5c}},
		{name: "a twice-wrapped X5CIssuerKeyResolver", production: true, keys: sdJWTVCWrapper{sdJWTVCWrapper{x5c}}},
		{name: "a wrapped key-only resolver", production: true, keys: sdJWTVCWrapper{keyOnly}, wantRefusal: refusal},
		{name: "a wrapper of nothing", production: true, keys: sdJWTVCWrapper{}, wantRefusal: refusal},
		// The opt-out declares no chain is verified; it doesn't excuse
		// a chain resolver anchored by every public CA.
		{
			name: "a wrapped system-pool resolver, unanchored issuers allowed", production: true, unanchored: true,
			keys:        sdJWTVCWrapper{verifier.X5CIssuerKeyResolver{Roots: system, Revocation: certrevocation.NoCheck{}}},
			wantRefusal: "system root pool",
		},
		{name: "development, key only", keys: keyOnly},
		{name: "development, a wrapped key-only resolver", keys: sdJWTVCWrapper{keyOnly}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := newTestVerifier(t)
			if tc.production {
				v = productionVerifier(t)
			}
			// req carries no real response, so VerifyResponse always
			// fails; what matters is whether it fails on the assurance
			// check or gets past it.
			_, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
				Query: testIdentityQuery(t), ExpectedNonce: "nonce", MaxKeyBindingAge: time.Hour,
				IssuerKeys: tc.keys, AllowUnanchoredSDJWTVCIssuers: tc.unanchored,
				AnyIssuerForAnyType: true, NoStatusCheck: true,
			})
			if err == nil {
				t.Fatal("VerifyResponse with an empty response = nil error, want error")
			}
			switch {
			case tc.wantRefusal != "" && !strings.Contains(err.Error(), tc.wantRefusal):
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantRefusal)
			case tc.wantRefusal == "" && strings.Contains(err.Error(), "under AssuranceProduction"):
				t.Fatalf("error = %v, want the assurance check to pass", err)
			}
		})
	}
}

// NewTransactions applies the same requirement to its Verify, so
// Transactions refuses a resolver verifying no chain under production
// for every flow it serves, the Digital Credentials API's among them.
func TestNewTransactions_ProductionRequiresSDJWTVCChainResolver(t *testing.T) {
	prod := productionVerifier(t)
	assured := assuredTransactionStore{storage.NewVerifierTransactionStore()}
	ca, _ := testcert.CA(t, "issuer CA")
	x5c := verifier.X5CIssuerKeyResolver{Roots: certPool(ca), Revocation: certrevocation.NoCheck{}}
	keyOnly := hardenedKeyOnlySDJWTResolver{keyOnlySDJWTResolver{x5c}}
	for _, flow := range []struct {
		name string
		cfg  verifier.TransactionsConfig
	}{
		{"redirect", verifier.TransactionsConfig{RequestURIBase: "https://verifier.example.com/request-objects"}},
		{"DC API", verifier.TransactionsConfig{Origins: []string{"https://verifier.example.com"}, Scope: "dcapi"}},
	} {
		for _, tc := range []struct {
			name       string
			keys       verifier.SDJWTVCIssuerKeyResolver
			unanchored bool
			refused    bool
		}{
			{name: "key only", keys: keyOnly, refused: true},
			{name: "key only, unanchored issuers allowed", keys: keyOnly, unanchored: true},
			{name: "X5CIssuerKeyResolver", keys: x5c},
			{name: "a wrapped X5CIssuerKeyResolver", keys: sdJWTVCWrapper{x5c}},
		} {
			cfg := flow.cfg
			cfg.NoStatusCheck = true
			cfg.Verify = verifier.VerifyResponseRequest{IssuerKeys: tc.keys, AllowUnanchoredSDJWTVCIssuers: tc.unanchored, AnyIssuerForAnyType: true}
			_, err := verifier.NewTransactions(prod, assured, cfg)
			switch {
			case tc.refused && (err == nil || !strings.Contains(err.Error(), "issuer_keys must verify issuer chains")):
				t.Errorf("%s, %s: %v, want refused", flow.name, tc.name, err)
			case !tc.refused && err != nil:
				t.Errorf("%s, %s: %v", flow.name, tc.name, err)
			}
		}
	}
}

// verifyAnchorTestCredentialWith is verifyAnchorTestCredential with v,
// accepting any issuer for any type, and unanchored as
// AllowUnanchoredSDJWTVCIssuers.
func verifyAnchorTestCredentialWith(t *testing.T, v *verifier.Verifier, cred string, holderKey *ecdsa.PrivateKey, keys verifier.SDJWTVCIssuerKeyResolver, unanchored bool) (verifier.VerifyResponseResult, error) {
	t.Helper()
	ctx := context.Background()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{anchorTestPID}})
	if err != nil {
		t.Fatal(err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("family_name")}}},
	}}}
	const nonce = "nonce-0123456789abcdef"
	vpToken, err := wallet.PresentCredentials(ctx, wallet.PresentationRequest{
		Query: query, Audience: v.ClientID(), Nonce: nonce,
		Credentials: []wallet.HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256}},
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	return v.VerifyResponse(ctx, verifier.VerifyResponseRequest{
		Query: query, Response: verifier.ParsedResponse{VPToken: vpToken}, ExpectedNonce: nonce,
		IssuerKeys: keys, MaxKeyBindingAge: time.Hour, NoStatusCheck: true, AnyIssuerForAnyType: true,
		AllowUnanchoredSDJWTVCIssuers: unanchored,
	})
}

// A wrapper that Unwraps to an X5CIssuerKeyResolver passes production,
// and its credential's verified chain and anchor come from the resolver
// it wraps: RootsByVCT's per-type anchors too, which
// ResolveIssuerChains can't apply without the credential.
func TestSDJWTVCWrapper_ReachesTheVerifiedAnchor(t *testing.T) {
	pidCA, pidCAKey := testcert.CA(t, "PID Provider CA")
	loyaltyCA, _ := testcert.CA(t, "Loyalty Club CA")
	leaf, leafKey := testcert.Leaf(t, "pid.example", pidCA, pidCAKey)
	cred, holder := anchorTestCredential(t, anchorTestPID, "", nil, leaf, leafKey)
	prod := productionVerifier(t)
	for name, inner := range map[string]verifier.X5CIssuerKeyResolver{
		"Roots":      {Roots: certPool(loyaltyCA, pidCA), Revocation: certrevocation.NoCheck{}},
		"RootsByVCT": {RootsByVCT: map[string]*x509.CertPool{anchorTestPID: certPool(pidCA), anchorTestLoyalty: certPool(loyaltyCA)}, Revocation: certrevocation.NoCheck{}},
	} {
		result, err := verifyAnchorTestCredentialWith(t, prod, cred, holder, sdJWTVCWrapper{sdJWTVCWrapper{inner}}, false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := result.Credentials[0]
		if !bytes.Equal(got.IssuerAnchor, pidCA.Raw) || !verifier.AnchorIs(got.IssuerAnchor, pidCA) {
			t.Errorf("%s: IssuerAnchor isn't the PID CA's", name)
		}
		if len(got.IssuerChain) != 1 || !bytes.Equal(got.IssuerChain[0], leaf.Raw) {
			t.Errorf("%s: IssuerChain isn't the verified path without its anchor", name)
		}
	}

	// A resolver verifying no chain is refused under production, and
	// verifies with the opt-out, with no anchor.
	keyOnly := hardenedKeyOnlySDJWTResolver{keyOnlySDJWTResolver{verifier.X5CIssuerKeyResolver{Roots: certPool(pidCA), Revocation: certrevocation.NoCheck{}}}}
	if _, err := verifyAnchorTestCredentialWith(t, prod, cred, holder, keyOnly, false); err == nil || !strings.Contains(err.Error(), "issuer_keys must verify issuer chains") {
		t.Fatalf("a key-only resolver under production: %v, want refused", err)
	}
	result, err := verifyAnchorTestCredentialWith(t, prod, cred, holder, keyOnly, true)
	if err != nil {
		t.Fatalf("a key-only resolver with AllowUnanchoredSDJWTVCIssuers: %v", err)
	}
	if result.Credentials[0].IssuerAnchor != nil {
		t.Error("a resolver verifying no chain gave an anchor")
	}
}
