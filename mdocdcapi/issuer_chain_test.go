package mdocdcapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// countingRevocation counts the issuer chains it's asked about: one per
// chain verified.
type countingRevocation struct{ n *atomic.Int32 }

func (c countingRevocation) CheckRevocation(context.Context, certrevocation.Check) error {
	c.n.Add(1)
	return nil
}

// chainHarness is a request for given_name from n document types, as
// the wallet parsed it, and an mdoc of each type signed by one document
// signer whose x5chain, [signer, intermediate], is anchored at a root on
// caCurve.
type chainHarness struct {
	request  Request
	incoming Incoming
	fixtures []testmdoc.Fixture
	roots    *x509.CertPool
	x5chain  [][]byte
}

func chainCert(t testing.TB, serial int64, subject, issuer string, pub any, signer *ecdsa.PrivateKey, ca bool) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: subject, Country: []string{"UT"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: ca,
	}
	if ca {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	parent := &x509.Certificate{Subject: pkix.Name{CommonName: issuer, Country: []string{"UT"}}, PublicKey: signer.Public()}
	if subject == issuer {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func chainKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// signedUnder is f with its IssuerAuth signed again by key, presenting
// x5chain.
func signedUnder(t testing.TB, f testmdoc.Fixture, key *ecdsa.PrivateKey, x5chain [][]byte) testmdoc.Fixture {
	t.Helper()
	protected, unprotected, payload, err := cose.DecodeUnverified(f.IssuerSigned.IssuerAuth)
	if err != nil {
		t.Fatal(err)
	}
	unprotected.X5Chain = x5chain
	if f.IssuerSigned.IssuerAuth, err = cose.Sign(cose.ES256, key, protected, unprotected, payload, []byte{}); err != nil {
		t.Fatal(err)
	}
	return f
}

func newChainHarness(t testing.TB, n int, caCurve elliptic.Curve) chainHarness {
	t.Helper()
	rootKey, interKey, signerKey := chainKey(t, caCurve), chainKey(t, caCurve), chainKey(t, elliptic.P256())
	root := chainCert(t, 1, "mdocdcapi chain root", "mdocdcapi chain root", &rootKey.PublicKey, rootKey, true)
	inter := chainCert(t, 2, "mdocdcapi chain intermediate", root.Subject.CommonName, &interKey.PublicKey, rootKey, true)
	signer := chainCert(t, 3, "mdocdcapi document signer", inter.Subject.CommonName, &signerKey.PublicKey, interKey, false)
	h := chainHarness{roots: x509.NewCertPool(), x5chain: [][]byte{signer.Raw, inter.Raw}}
	h.roots.AddCert(root)

	var docs []DocumentRequest
	for i := range n {
		dt := fmt.Sprintf("org.example.chain.%d", i)
		f := testmdoc.IssueWith(t, func(c *mdoc.Claims) { c.DocType = dt })
		h.fixtures = append(h.fixtures, signedUnder(t, f, signerKey, h.x5chain))
		docs = append(docs, DocumentRequest{DocType: dt, Elements: map[string]map[string]bool{testmdoc.Namespace: {"given_name": false}}})
	}
	readerCert, readerKey := testcert.SelfSignedLeaf(t, "mdocdcapi test reader")
	var err error
	h.request, err = BuildRequest(RequestParams{Origin: testOrigin, Documents: docs, Readers: []ReaderKey{{Signer: readerKey, Chain: []*x509.Certificate{readerCert}}}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(h.request.Data)
	if err != nil {
		t.Fatal(err)
	}
	if h.incoming, err = ParseRequest(data, testOrigin); err != nil {
		t.Fatal(err)
	}
	return h
}

// respond is the wallet's response with fixtures, each answering the
// document request of its index.
func (h chainHarness) respond(t testing.TB, fixtures []testmdoc.Fixture) string {
	t.Helper()
	answers := make([]Answer, len(fixtures))
	for i, f := range fixtures {
		answers[i] = Answer{Document: i, IssuerSigned: f.IssuerSigned, Holder: f.DeviceKey, Elements: [][2]string{{testmdoc.Namespace, "given_name"}}}
	}
	encrypted, err := h.incoming.RespondDocuments(context.Background(), answers)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encrypted)
}

// verify is VerifyResponseDocuments of response under h's roots,
// counting the issuer chains verified.
func (h chainHarness) verify(response string, chains *atomic.Int32) ([]Verified, error) {
	return VerifyResponseDocuments(context.Background(), VerifyParams{
		Pending: h.request.Pending, Response: response,
		IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: h.roots, LeafPolicy: verifier.AnyIssuerLeaf, Revocation: countingRevocation{chains}},
		Assurance:  verifier.AssuranceDevelopment, NoStatusCheck: true,
	})
}

// The documents of one response that share an issuer chain have it
// verified once, as VerifyResponse's own documents do.
func TestVerifyResponseDocuments_VerifiesASharedIssuerChainOnce(t *testing.T) {
	h := newChainHarness(t, 3, elliptic.P256())
	var chains atomic.Int32
	vs, err := h.verify(h.respond(t, h.fixtures), &chains)
	if err != nil || len(vs) != 3 {
		t.Fatalf("verified %d documents, %v; want 3", len(vs), err)
	}
	if n := chains.Load(); n != 1 {
		t.Errorf("the shared issuer chain was verified %d times, want once", n)
	}
}

// A document whose IssuerAuth doesn't verify with the key of the
// x5chain leaf it presents is refused before its chain is verified,
// even when that chain is genuine.
func TestVerifyResponseDocuments_IssuerSignatureBeforeChain(t *testing.T) {
	h := newChainHarness(t, 1, elliptic.P256())
	replayed := signedUnder(t, h.fixtures[0], chainKey(t, elliptic.P256()), h.x5chain)
	var chains atomic.Int32
	if _, err := h.verify(h.respond(t, []testmdoc.Fixture{replayed}), &chains); err == nil {
		t.Fatal("a genuine chain under another key's signature was accepted")
	}
	if n := chains.Load(); n != 0 {
		t.Errorf("its chain was verified (%d revocation checks), want none", n)
	}
	single, err := VerifyResponse(context.Background(), VerifyParams{
		Pending: h.request.Pending, Response: h.respond(t, []testmdoc.Fixture{replayed}),
		IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: h.roots, LeafPolicy: verifier.AnyIssuerLeaf, Revocation: countingRevocation{&chains}},
		Assurance:  verifier.AssuranceDevelopment, NoStatusCheck: true,
	})
	if err == nil {
		t.Fatalf("VerifyResponse accepted it: %+v", single)
	}
	if n := chains.Load(); n != 0 {
		t.Errorf("VerifyResponse verified its chain (%d revocation checks), want none", n)
	}
}

// A response is decoded as strict base64url: one with a line break in
// it, which encoding/base64 skips, is refused before it's decrypted.
func TestVerifyResponseDocuments_StrictBase64URL(t *testing.T) {
	h := newChainHarness(t, 1, elliptic.P256())
	response := h.respond(t, h.fixtures)
	var chains atomic.Int32
	if _, err := h.verify(response, &chains); err != nil {
		t.Fatalf("the response as encoded: %v", err)
	}
	broken := response[:len(response)/2] + "\n" + response[len(response)/2:]
	if _, err := h.verify(broken, &chains); err == nil || !strings.Contains(err.Error(), "isn't base64url") {
		t.Errorf("a response with a line break: %v, want it refused as not base64url", err)
	}
}
