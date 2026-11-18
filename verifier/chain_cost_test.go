package verifier_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// budgetResolver fails every key resolution as path building does at
// crypto/x509's signature-check cap, counting the calls.
type budgetResolver struct{ n *atomic.Int32 }

func (b budgetResolver) ResolveIssuerKey(context.Context, map[string]any, map[string]any) (crypto.PublicKey, jose.Alg, error) {
	b.n.Add(1)
	return nil, "", fmt.Errorf("certchain: certificate chain does not verify against a trusted root: %w", certchain.ErrChainBudget)
}

// unsignedPresentation is an SD-JWT presentation whose Issuer-signed
// JWT has header and a signature that verifies under no key.
func unsignedPresentation(t *testing.T, header map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"vct":"`+testVCT+`"}`)) + ".AAAA~"
}

// leafSignedPresentation is an SD-JWT presentation whose Issuer-signed
// JWT presents x5c and is signed by key, its leaf's: its signature
// verifies with the leaf's key, so the chain is what decides it.
func leafSignedPresentation(t *testing.T, key crypto.Signer, x5c ...*x509.Certificate) string {
	t.Helper()
	return leafSignedCredential(t, key, `{"vct":"`+testVCT+`"}`, x5c...)
}

// leafSignedCredential is leafSignedPresentation with payload, the
// Issuer-signed JWT's: a credential of its own for each payload.
func leafSignedCredential(t *testing.T, key crypto.Signer, payload string, x5c ...*x509.Certificate) string {
	t.Helper()
	chain := make([]any, len(x5c))
	for i, cert := range x5c {
		chain[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	jwt, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "dc+sd-jwt", "x5c": chain}, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return jwt + "~"
}

func multipleQuery(t *testing.T) dcql.Query {
	t.Helper()
	return dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, testVCT), Multiple: true}}}
}

// unboundQuery is multipleQuery without holder binding: a credential
// with no cnf, presented without a KB-JWT, verifies.
func unboundQuery(t *testing.T) dcql.Query {
	t.Helper()
	q := multipleQuery(t)
	unbound := false
	q.Credentials[0].RequireCryptographicHolderBinding = &unbound
	return q
}

// An answer repeating one issuer chain across its presentations, each a
// credential of its own, has the chain verified once: the revocation
// check, run once per verified path, runs once for the three.
func TestVerifyResponse_VerifiesEachDistinctChainOnce(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer root")
	leaf, leafKey := testcert.Leaf(t, "issuer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	var checks atomic.Int32
	resolver := verifier.X5CIssuerKeyResolver{Roots: roots, LeafPolicy: verifier.AnyIssuerLeaf, Revocation: countingRevocation{&checks}}
	var presentations []string
	for i := range 3 {
		presentations = append(presentations, leafSignedCredential(t, leafKey, fmt.Sprintf(`{"vct":%q,"jti":"%d"}`, testVCT, i), leaf))
	}

	result, err := newTestVerifier(t).VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: unboundQuery(t), Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": presentations}},
		ExpectedNonce: "n", MaxKeyBindingAge: time.Hour, IssuerKeys: resolver,
	})
	if err != nil || len(result.Credentials) != 3 {
		t.Fatalf("VerifyResponse = %+v, %v; want the three credentials", result, err)
	}
	if got := checks.Load(); got != 1 {
		t.Errorf("revocation checked %d times for one chain presented three times, want 1", got)
	}
}

// After a presentation whose issuer chain ran path building to its
// signature-check cap, the query's other presentations are discarded
// unverified.
func TestVerifyResponse_StopsAtAnExhaustedChainBudget(t *testing.T) {
	var calls atomic.Int32
	pres := unsignedPresentation(t, map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"})
	presentations := []string{pres, pres + "a", pres + "b", pres + "c"}
	_, err := newTestVerifier(t).VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: multipleQuery(t), Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": presentations}},
		ExpectedNonce: "n", MaxKeyBindingAge: time.Hour, IssuerKeys: budgetResolver{&calls},
	})
	if !errors.Is(err, certchain.ErrChainBudget) {
		t.Fatalf("err = %v, want the exhausted budget", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("%d presentations' issuers resolved, want only the first", got)
	}
}
