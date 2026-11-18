package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// These tests bound what one response costs by the signatures the
// verifier checks (jose.Checks, cose.Checks), not by time: certificate
// chains are checked by crypto/x509 and not counted. They don't run in
// parallel, so no other test's checks are counted with theirs.

func p521Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// issuerJWT is an Issuer-signed JWT presenting x5c, over payload,
// signed by key: ES512 for a P-521 key (which jose.Sign doesn't sign),
// ES256 otherwise.
func issuerJWT(t *testing.T, key *ecdsa.PrivateKey, payload []byte, x5c ...*x509.Certificate) string {
	t.Helper()
	chain := make([]any, len(x5c))
	for i, cert := range x5c {
		chain[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	header := map[string]any{"typ": "dc+sd-jwt", "x5c": chain}
	if key.Curve != elliptic.P521() {
		jwt, err := jose.Sign(jose.ES256, key, header, payload)
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}
	header["alg"] = string(jose.ES512)
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha512.Sum512([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 132)
	r.FillBytes(sig[:66])
	s.FillBytes(sig[66:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// boundCredential is a new SD-JWT VC of testVCT bound to a fresh holder
// key, its Issuer-signed JWT presenting x5c and signed by issuerKey.
func boundCredential(t *testing.T, issuerKey *ecdsa.PrivateKey, x5c ...*x509.Certificate) sdjwtvc.Presentation {
	t.Helper()
	holderJWK, err := jwkFromECDSA(&testP256Key(t).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	issued, _, err := sdjwtvc.Issue(testP256Key(t), jose.ES256, sdjwtvc.Claims{
		VCT: testVCT, CNF: map[string]any{"jwk": holderJWK}, Additional: map[string]any{"given_name": "Alice"},
	}, sdjwtvc.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pres, err := sdjwtvc.Parse(issued)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		t.Fatal(err)
	}
	pres.IssuerJWT = issuerJWT(t, issuerKey, payload, x5c...)
	return pres
}

// withKeyBinding is pres presented with a KB-JWT for aud and nonce
// signed by kbKey: not the holder's, so it doesn't verify.
func withKeyBinding(t *testing.T, pres sdjwtvc.Presentation, kbKey *ecdsa.PrivateKey, aud, nonce string) string {
	t.Helper()
	kb, err := sdjwtvc.NewKeyBindingJWT(kbKey, jose.ES256, pres, sdjwtvc.SHA256, sdjwtvc.KeyBindingClaims{Audience: aud, Nonce: nonce})
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

func repeated(presentation string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = presentation
	}
	return out
}

// wantRefused fails t unless err refuses the whole response as
// malformed, its message containing want.
func wantRefused(t *testing.T, name string, err error, want string) {
	t.Helper()
	var vErr *verifier.Error
	if !errors.As(err, &vErr) || vErr.Reason() != verifier.ReasonMalformed || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: err = %v, want the response refused as malformed: %q", name, err, want)
	}
}

// CRY-1: presentations whose issuer signature fails under a self-made
// P-521 leaf, whose key is the sender's choice, are counted: the
// response is refused after MaxFailedPresentationsPerResponse of them,
// at that many P-521 checks, not MaxPresentationsPerQuery. Copies of
// one are refused at the second, before its signature is checked.
func TestVerifyResponse_CountsBogusLeafSignatures(t *testing.T) {
	ca, _ := testcert.CA(t, "issuer root")
	attacker, attackerKey := testcert.CA(t, "attacker root")
	resolver := verifier.X5CIssuerKeyResolver{Roots: rootsOf(ca), LeafPolicy: verifier.AnyIssuerLeaf, Revocation: certrevocation.NoCheck{}}
	bogus := func(i int) string {
		leaf := testcert.LeafFor(t, fmt.Sprintf("attacker leaf %d", i), &p521Key(t).PublicKey, attacker, attackerKey)
		// Signed by another key: well formed, and fails only once checked.
		return issuerJWT(t, p521Key(t), []byte(`{"vct":"`+testVCT+`"}`), leaf) + "~"
	}
	distinct := make([]string, verifier.MaxPresentationsPerQuery)
	for i := range distinct {
		distinct[i] = bogus(i)
	}

	for _, c := range []struct {
		name          string
		presentations []string
		want          string
		maxChecks     int64
	}{
		{"distinct presentations", distinct, "presentations in one response failed to verify", verifier.MaxFailedPresentationsPerResponse},
		{"copies of one", repeated(distinct[0], verifier.MaxPresentationsPerQuery), "presented more than once", 1},
	} {
		before := jose.Checks()
		_, err := newTestVerifier(t).VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query: multipleQuery(t), Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": c.presentations}},
			ExpectedNonce: "n", MaxKeyBindingAge: time.Hour, IssuerKeys: resolver,
		})
		wantRefused(t, c.name, err, c.want)
		if checks := jose.Checks() - before; checks > c.maxChecks {
			t.Errorf("%s: %d signatures checked, want at most %d", c.name, checks, c.maxChecks)
		}
	}
}

// DOS-2: copies of one genuine credential from a P-521 issuer, each
// with a KB-JWT that doesn't verify, are refused at the second copy,
// before its issuer signature is checked again; distinct genuine
// credentials failing the same way are counted, and refused after
// MaxFailedPresentationsPerResponse. Each presentation's issuer
// signature is checked once: with the x5c leaf's key, and not again
// when the credential is verified.
func TestVerifyResponse_CopiesAndFailedHolderBindingAreBounded(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer root")
	issuerKey := p521Key(t)
	leaf := testcert.LeafFor(t, "P-521 issuer", &issuerKey.PublicKey, ca, caKey)
	resolver := verifier.X5CIssuerKeyResolver{Roots: rootsOf(ca), LeafPolicy: verifier.AnyIssuerLeaf, Revocation: certrevocation.NoCheck{}}
	v := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: multipleQuery(t)})
	if err != nil {
		t.Fatal(err)
	}
	stranger := testP256Key(t)
	badKB := func() string {
		return withKeyBinding(t, boundCredential(t, issuerKey, leaf), stranger, v.ClientID(), built.Nonce)
	}
	batch := make([]string, verifier.MaxPresentationsPerQuery)
	for i := range batch {
		batch[i] = badKB()
	}
	verify := func(presentations []string) (verifier.VerifyResponseResult, error) {
		return v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query: multipleQuery(t), Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": presentations}},
			ExpectedNonce: built.Nonce, MaxKeyBindingAge: time.Hour, IssuerKeys: resolver,
		})
	}

	// Per presentation verified: its issuer signature (ES512) once, and
	// its KB-JWT (ES256).
	for _, c := range []struct {
		name          string
		presentations []string
		want          string
		maxChecks     int64
	}{
		{"copies of one credential", repeated(batch[0], verifier.MaxPresentationsPerQuery), "presented more than once", 2},
		{"distinct credentials", batch, "presentations in one response failed to verify", 2 * verifier.MaxFailedPresentationsPerResponse},
	} {
		before := jose.Checks()
		_, err := verify(c.presentations)
		wantRefused(t, c.name, err, c.want)
		if checks := jose.Checks() - before; checks > c.maxChecks {
			t.Errorf("%s: %d signatures checked, want at most %d", c.name, checks, c.maxChecks)
		}
	}

	holderKey := testP256Key(t)
	honest := boundCredential(t, issuerKey, leaf)
	holderJWK, err := jwkFromECDSA(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, payload, err := jose.DecodeUnverified(honest.IssuerJWT)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["cnf"] = map[string]any{"jwk": holderJWK}
	if payload, err = json.Marshal(claims); err != nil {
		t.Fatal(err)
	}
	honest.IssuerJWT = issuerJWT(t, issuerKey, payload, leaf)
	before := jose.Checks()
	if result, err := verify([]string{withKeyBinding(t, honest, holderKey, v.ClientID(), built.Nonce)}); err != nil || len(result.Credentials) != 1 {
		t.Fatalf("the honest presentation: %+v, %v", result, err)
	}
	if checks := jose.Checks() - before; checks != 2 {
		t.Errorf("the honest presentation: %d signatures checked, want 2: its issuer signature once, and its KB-JWT", checks)
	}
}

// The mdoc path as the SD-JWT one: IssuerAuth under a self-made P-521
// leaf it doesn't verify with is counted, copies of one mdoc are
// refused at the second, and a genuine mdoc's IssuerAuth is checked
// once.
func TestVerifyResponse_MdocFailuresAreBounded(t *testing.T) {
	ca, caKey := testcert.CAWithSubject(t, pkix.Name{CommonName: "Utopia IACA", Country: []string{"UT"}})
	attacker, attackerKey := testcert.CA(t, "attacker root")
	mf := newMdocVerifyFixture(t)
	mf.query.Credentials[0].Multiple = true
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: rootsOf(ca), LeafPolicy: verifier.AnyIssuerLeaf, Revocation: certrevocation.NoCheck{}}
	// present is f's mdoc, its IssuerAuth presenting leaf and signed by
	// signer, with f's device signature for mf's request.
	present := func(f testmdoc.Fixture, leaf *x509.Certificate, alg cose.Alg, signer *ecdsa.PrivateKey) string {
		protected, unprotected, payload, err := cose.DecodeUnverified(f.IssuerSigned.IssuerAuth)
		if err != nil {
			t.Fatal(err)
		}
		protected.Alg = alg
		unprotected.X5Chain = [][]byte{leaf.Raw}
		issuerSigned := f.IssuerSigned
		if issuerSigned.IssuerAuth, err = cose.Sign(alg, signer, protected, unprotected, payload, []byte{}); err != nil {
			t.Fatal(err)
		}
		return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: issuerSigned, DeviceSigned: mf.deviceSigned(t, f, nil)})
	}
	bogus := make([]string, verifier.MaxPresentationsPerQuery)
	for i := range bogus {
		leaf := testcert.LeafFor(t, fmt.Sprintf("attacker document signer %d", i), &p521Key(t).PublicKey, attacker, attackerKey)
		bogus[i] = present(testmdoc.Issue(t), leaf, cose.ES512, p521Key(t))
	}
	verify := func(presentations []string) (verifier.VerifyResponseResult, error) {
		return mf.verifyWith(t, mf.nonce, func(r *verifier.VerifyResponseRequest) {
			r.Response.VPToken["mdl"] = presentations
			r.MdocIssuerKeys = resolver
		})
	}

	for _, c := range []struct {
		name          string
		presentations []string
		want          string
		maxChecks     int64
	}{
		{"distinct mdocs", bogus, "presentations in one response failed to verify", verifier.MaxFailedPresentationsPerResponse},
		{"copies of one", repeated(bogus[0], verifier.MaxPresentationsPerQuery), "presented more than once", 1},
	} {
		before := cose.Checks()
		_, err := verify(c.presentations)
		wantRefused(t, c.name, err, c.want)
		if checks := cose.Checks() - before; checks > c.maxChecks {
			t.Errorf("%s: %d signatures checked, want at most %d", c.name, checks, c.maxChecks)
		}
	}

	leaf, leafKey := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Utopia document signer", Country: []string{"UT"}}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, caKey)
	genuine := present(mf.f, leaf, cose.ES256, leafKey)
	before := cose.Checks()
	if result, err := verify([]string{genuine}); err != nil || len(result.Credentials) != 1 {
		t.Fatalf("the genuine mdoc: %+v, %v", result, err)
	}
	if checks := cose.Checks() - before; checks != 2 {
		t.Errorf("the genuine mdoc: %d signatures checked, want 2: IssuerAuth once, and the device signature", checks)
	}
}

// An honest response isn't refused for presentations discarded for what
// they say rather than for a failed check, however many, nor for fewer
// than MaxFailedPresentationsPerResponse failed checks; the failed ones
// are discarded and the rest verified. Past the limit, the response is
// refused even beside a valid credential, as
// MaxFailedIssuerChainsPerResponse refuses one, a chain that doesn't
// verify counting with the other failures.
func TestVerifyResponse_FailedPresentationLimitSparesHonestResponses(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer root")
	leaf, leafKey := testcert.Leaf(t, "issuer", ca, caKey)
	resolver := verifier.X5CIssuerKeyResolver{Roots: rootsOf(ca), LeafPolicy: verifier.AnyIssuerLeaf, Revocation: certrevocation.NoCheck{}}
	v := newTestVerifier(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: multipleQuery(t)})
	if err != nil {
		t.Fatal(err)
	}
	valid := keyBoundPresentation(t, testVCT, sdjwtvc.IssueOptions{IssuerCertificate: leaf}, leafKey, v.ClientID(), built.Nonce)
	notAnswering := func() string {
		// Verifies, but isn't of the type the query asks for.
		return keyBoundPresentation(t, "https://credentials.example.com/loyalty_card", sdjwtvc.IssueOptions{IssuerCertificate: leaf}, leafKey, v.ClientID(), built.Nonce)
	}
	failing := func() string {
		return withKeyBinding(t, boundCredential(t, leafKey, leaf), testP256Key(t), v.ClientID(), built.Nonce)
	}
	verify := func(presentations []string) (verifier.VerifyResponseResult, error) {
		return v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query: multipleQuery(t), Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": presentations}},
			ExpectedNonce: built.Nonce, MaxKeyBindingAge: time.Hour, IssuerKeys: resolver,
		})
	}
	n := 2 * verifier.MaxFailedPresentationsPerResponse

	var ordinary []string
	for range n {
		ordinary = append(ordinary, notAnswering())
	}
	result, err := verify(append(ordinary, valid))
	if err != nil || len(result.Credentials) != 1 || len(result.Discarded) != n {
		t.Errorf("%d presentations not answering the query, then a valid one: %d verified, %d discarded, %v; want 1 and %d", n, len(result.Credentials), len(result.Discarded), err, n)
	}
	for _, d := range result.Discarded {
		if d.Code != verifier.ReasonNotAnswered {
			t.Errorf("discarded as %s, want %s", d.Code, verifier.ReasonNotAnswered)
		}
	}

	var under []string
	for range verifier.MaxFailedPresentationsPerResponse - 1 {
		under = append(under, failing())
	}
	result, err = verify(append(under, valid))
	if err != nil || len(result.Credentials) != 1 || len(result.Discarded) != len(under) {
		t.Errorf("%d failed holder bindings, then a valid presentation: %+v, %v; want it verified, the others discarded", len(under), result, err)
	}

	// A chain no root anchors counts with the rest.
	other, otherKey := testcert.CA(t, "a root this verifier doesn't trust")
	foreign, foreignKey := testcert.Leaf(t, "foreign issuer", other, otherKey)
	untrusted := leafSignedPresentation(t, foreignKey, foreign)
	_, err = verify(append(append(under, untrusted), valid))
	wantRefused(t, "at the limit, then a valid presentation", err, "presentations in one response failed to verify")
}
