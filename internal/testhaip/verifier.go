package testhaip

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Verifier is a running OpenID4VP Verifier (verifier.Transactions),
// trusting credentials from its Env's issuer.
type Verifier struct {
	// Trust is what a wallet trusts the Verifier by.
	Trust wallet.VerifierTrust
	// Name is the common name of the Verifier's certificate.
	Name string

	txs *verifier.Transactions
}

// The browser binding every request is begun with.
const verifierBrowser = "testhaip-browser"

// StartVerifier starts a Verifier on a loopback TLS server, stopped when
// t ends. httptest serves every server with the same certificate, so
// e.HTTP reaches it too.
func (e *Env) StartVerifier(t testing.TB) *Verifier {
	t.Helper()
	v := &Verifier{Name: "testhaip verifier"}
	ts := httptest.NewUnstartedServer(nil)
	base := "https://" + ts.Listener.Addr().String()
	responseURI, err := fapi.ParseEndpointURL(base + "/response")
	must(t, err)
	ca, caKey := testcert.CA(t, "testhaip verifier CA")
	cert, key := testcert.Leaf(t, v.Name, ca, caKey)
	formats := verifier.SDJWTVCFormatSupport([]string{"ES256"}, []string{"ES256"})
	for k, val := range verifier.MdocFormatSupport() {
		formats[k] = val
	}
	vv, err := verifier.New(verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: cert, ResponseURI: responseURI,
		SigningAlg: jose.ES256, EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM}, VPFormatsSupported: formats,
	}, verifier.Dependencies{Signer: key, Random: rand.Reader})
	must(t, err)
	if v.txs, err = verifier.NewTransactions(vv, storage.NewVerifierTransactionStore(), verifier.TransactionsConfig{
		RequestURIBase: base + "/request-objects",
		Verify: verifier.VerifyResponseRequest{
			IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: e.IssuerRoots}, MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: e.IssuerRoots},
			MaxKeyBindingAge: time.Hour,
		},
	}); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	v.Trust = wallet.X5CVerifierRoots{Roots: roots}

	mux := http.NewServeMux()
	mux.Handle("GET /request-objects/{id}", v.txs.RequestObjectHandler())
	mux.Handle("POST /response", v.txs.ResponseHandler())
	ts.Config.Handler = mux
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return v
}

// SDJWTQuery asks for an SD-JWT VC of the Env's type, disclosing claims.
func (e *Env) SDJWTQuery(t testing.TB, id string, claims ...string) dcql.CredentialQuery {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{e.vct}})
	must(t, err)
	q := dcql.CredentialQuery{ID: id, Format: "dc+sd-jwt", Meta: meta}
	for _, c := range claims {
		q.Claims = append(q.Claims, dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey(c)}})
	}
	return q
}

// MdocQuery asks for an mdoc of DocType, disclosing elements of
// NameSpace.
func MdocQuery(t testing.TB, id string, elements ...string) dcql.CredentialQuery {
	t.Helper()
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: DocType})
	must(t, err)
	q := dcql.CredentialQuery{ID: id, Format: "mso_mdoc", Meta: meta}
	for _, el := range elements {
		q.Claims = append(q.Claims, dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey(NameSpace), dcql.PathKey(el)}})
	}
	return q
}

// Begin starts a cross-device request for query and returns its ID and
// the openid4vp:// link a wallet answers.
func (v *Verifier) Begin(t testing.TB, query dcql.Query) (id, link string) {
	t.Helper()
	begun, err := v.txs.Begin(context.Background(), query, verifierBrowser, false)
	must(t, err)
	return begun.ID, begun.Link
}

// Lookup returns the request's state.
func (v *Verifier) Lookup(t testing.TB, id string) verifier.TransactionView {
	t.Helper()
	view, err := v.txs.Lookup(context.Background(), id, verifierBrowser)
	must(t, err)
	return view
}
