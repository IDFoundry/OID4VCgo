package verifier_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// byVCT is a caller's IssuerKeys dispatching each credential to the
// X5CIssuerKeyResolver for its vct, with the request's ctx.
type byVCT map[string]verifier.X5CIssuerKeyResolver

func (r byVCT) ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, jose.Alg, error) {
	vct, _ := payload["vct"].(string)
	inner, ok := r[vct]
	if !ok {
		return nil, "", fmt.Errorf("no resolver for vct %q", vct)
	}
	return inner.ResolveIssuerKey(ctx, header, payload)
}

// keyBoundPresentation is an SD-JWT VC of vct signed by issuerKey under
// opts, presented with a KB-JWT for aud and nonce.
func keyBoundPresentation(t *testing.T, vct string, opts sdjwtvc.IssueOptions, issuerKey crypto.Signer, aud, nonce string) string {
	t.Helper()
	holderKey := testP256Key(t)
	holderJWK, err := jwkFromECDSA(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sdjwt, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT: vct, CNF: map[string]any{"jwk": holderJWK}, Additional: map[string]any{"given_name": "Alice"},
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	pres, err := sdjwtvc.Parse(sdjwt)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := sdjwtvc.NewKeyBindingJWT(holderKey, jose.ES256, pres, sdjwtvc.SHA256, sdjwtvc.KeyBindingClaims{Audience: aud, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	pres.KeyBindingJWT = kb
	compact, err := pres.Compact()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// A caller's resolver dispatching to two X5CIssuerKeyResolvers that
// share a root pool, one lenient and one strict, has each check every
// chain under its own leaf policy and revocation checker: a chain the
// lenient one accepted earlier in the response isn't accepted for the
// strict one on that verification.
func TestVerifyResponse_ChainOutcomeNotSharedAcrossResolvers(t *testing.T) {
	const loyaltyVCT = "https://credentials.example.com/loyalty_card"
	ca, caKey := testcert.CA(t, "shared root")
	leaf, leafKey := testcert.Leaf(t, "loyalty issuer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	var strictCalls atomic.Int32
	strict := verifier.X5CIssuerKeyResolver{
		Roots: roots, Revocation: testcert.CRLs(t, ca, caKey, leaf),
		LeafPolicy: func(*x509.Certificate, [][]*x509.Certificate) error {
			strictCalls.Add(1)
			return errors.New("not a PID issuer")
		},
	}
	lenient := verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}, LeafPolicy: verifier.AnyIssuerLeaf}

	_, _, v := newTestVerifierWithConfig(t)
	query := dcql.Query{Credentials: []dcql.CredentialQuery{
		{ID: "loyalty", Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, loyaltyVCT)},
		{ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, testVCT)},
	}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	opts := sdjwtvc.IssueOptions{IssuerCertificate: leaf}
	res, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: query,
		Response: verifier.ParsedResponse{VPToken: map[string][]string{
			"loyalty": {keyBoundPresentation(t, loyaltyVCT, opts, leafKey, v.ClientID(), built.Nonce)},
			"pid":     {keyBoundPresentation(t, testVCT, opts, leafKey, v.ClientID(), built.Nonce)},
		}},
		ExpectedNonce: built.Nonce, MaxKeyBindingAge: time.Hour,
		IssuerKeys: byVCT{loyaltyVCT: lenient, testVCT: strict},
	})
	if err == nil {
		for _, c := range res.Credentials {
			if c.CredentialQueryID == "pid" {
				t.Fatal("the PID was accepted on the lenient resolver's verification of its chain")
			}
		}
	}
	if strictCalls.Load() == 0 {
		t.Error("the strict resolver's leaf policy was never called")
	}
}

// A response whose distinct issuer chains fail to verify is refused as
// a whole once MaxFailedIssuerChainsPerResponse of them have failed.
func TestVerifyResponse_RefusesAfterTooManyFailedIssuerChains(t *testing.T) {
	ca, _ := testcert.CA(t, "issuer root")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	other, otherKey := testcert.CA(t, "untrusted root")
	resolver := verifier.X5CIssuerKeyResolver{Roots: roots, LeafPolicy: verifier.AnyIssuerLeaf, Revocation: certrevocation.NoCheck{}}
	var presentations []string
	for i := range verifier.MaxFailedIssuerChainsPerResponse + 3 {
		leaf, leafKey := testcert.Leaf(t, fmt.Sprintf("issuer %d", i), other, otherKey)
		presentations = append(presentations, leafSignedPresentation(t, leafKey, leaf))
	}

	_, err := newTestVerifier(t).VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: multipleQuery(t), Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": presentations}},
		ExpectedNonce: "n", MaxKeyBindingAge: time.Hour, IssuerKeys: resolver,
	})
	var vErr *verifier.Error
	if !errors.As(err, &vErr) || vErr.Reason() != verifier.ReasonMalformed || !strings.Contains(err.Error(), "failed to verify") {
		t.Fatalf("err = %v, want a malformed response refused for its failed chains", err)
	}
}

// Distinct issuer chains that verify aren't counted: a response
// presenting more of them than the failure limits, each credential
// verifying, is verified in full.
func TestVerifyResponse_ValidIssuerChainsArentCapped(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer root")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	var checks atomic.Int32
	resolver := verifier.X5CIssuerKeyResolver{Roots: roots, LeafPolicy: verifier.AnyIssuerLeaf, Revocation: countingRevocation{&checks}}
	n := max(verifier.MaxFailedIssuerChainsPerResponse, verifier.MaxFailedPresentationsPerResponse) + 12
	var presentations []string
	for i := range n {
		leaf, leafKey := testcert.Leaf(t, fmt.Sprintf("issuer %d", i), ca, caKey)
		presentations = append(presentations, leafSignedPresentation(t, leafKey, leaf))
	}

	result, err := newTestVerifier(t).VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: unboundQuery(t), Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": presentations}},
		ExpectedNonce: "n", MaxKeyBindingAge: time.Hour, IssuerKeys: resolver,
	})
	if err != nil || len(result.Credentials) != n {
		t.Fatalf("VerifyResponse = %d credentials, %v; want all %d: chains that verify were capped", len(result.Credentials), err, n)
	}
	if got := checks.Load(); got != int32(n) {
		t.Errorf("%d chains verified, want %d", got, n)
	}
}
