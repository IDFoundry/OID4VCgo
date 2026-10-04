package walletflowtest

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Verifier is a running OpenID4VP Verifier (verifier.Transactions),
// trusting credentials from its Env's issuer.
type Verifier struct {
	// Trust is what a wallet trusts the Verifier by: CA, the trust
	// anchor of its request-signing certificate.
	Trust wallet.VerifierTrust
	CA    *x509.Certificate
	// Name is the common name of the Verifier's certificate, and
	// ClientID its client_id (x509_hash).
	Name     string
	ClientID string

	txs *verifier.Transactions
}

// The browser binding every request is begun with.
const verifierBrowser = "testhaip-browser"

// StartVerifier starts a Verifier on a loopback TLS server, stopped by
// e.Close. httptest serves every server with the same certificate, so
// e.HTTP reaches it too.
func (e *Env) StartVerifier() (started *Verifier, err error) {
	defer recoverInto(&err)
	v := &Verifier{Name: "walletflowtest verifier"}
	ts := httptest.NewUnstartedServer(nil)
	base := "https://" + ts.Listener.Addr().String()
	responseURI, err := fapi.ParseEndpointURL(base + "/response")
	must(err)
	ca, caKey := newCA("walletflowtest verifier CA")
	cert, key := newLeaf(v.Name, ca, caKey)
	formats := verifier.SDJWTVCFormatSupport([]string{"ES256"}, []string{"ES256"})
	for k, val := range verifier.MdocFormatSupport() {
		formats[k] = val
	}
	vv, err := verifier.New(verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: cert, ResponseURI: responseURI,
		SigningAlg: jose.ES256, EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM}, VPFormatsSupported: formats,
	}, verifier.Dependencies{Signer: key, Random: rand.Reader})
	must(err)
	v.ClientID = vv.ClientID()
	v.txs, err = verifier.NewTransactions(vv, storage.NewVerifierTransactionStore(), verifier.TransactionsConfig{
		RequestURIBase: base + "/request-objects",
		Verify: verifier.VerifyResponseRequest{
			IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: e.IssuerRoots}, MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: e.IssuerRoots},
			MaxKeyBindingAge: time.Hour,
		},
	})
	must(err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	v.Trust, v.CA = wallet.X5CVerifierRoots{Roots: roots}, ca

	mux := http.NewServeMux()
	mux.Handle("GET /request-objects/{id}", v.txs.RequestObjectHandler())
	mux.Handle("POST /response", v.txs.ResponseHandler())
	ts.Config.Handler = mux
	ts.StartTLS()
	e.mu.Lock()
	e.closers = append(e.closers, ts.Close)
	e.mu.Unlock()
	return v, nil
}

// SDJWTQuery asks for an SD-JWT VC of the Env's type, disclosing claims.
func (e *Env) SDJWTQuery(id string, claims ...string) (q dcql.CredentialQuery, err error) {
	defer recoverInto(&err)
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{e.vct}})
	must(err)
	q = dcql.CredentialQuery{ID: id, Format: "dc+sd-jwt", Meta: meta}
	for _, c := range claims {
		q.Claims = append(q.Claims, dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey(c)}})
	}
	return q, nil
}

// MdocQuery asks for an mdoc of DocType, disclosing elements of
// NameSpace.
func MdocQuery(id string, elements ...string) (q dcql.CredentialQuery, err error) {
	defer recoverInto(&err)
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: DocType})
	must(err)
	q = dcql.CredentialQuery{ID: id, Format: "mso_mdoc", Meta: meta}
	for _, el := range elements {
		q.Claims = append(q.Claims, dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey(NameSpace), dcql.PathKey(el)}})
	}
	return q, nil
}

// Begin starts a cross-device request for query and returns its ID and
// the openid4vp:// link a wallet answers.
func (v *Verifier) Begin(query dcql.Query) (id, link string, err error) {
	begun, err := v.txs.Begin(context.Background(), query, verifierBrowser, false)
	if err != nil {
		return "", "", fmt.Errorf("walletflowtest: %w", err)
	}
	return begun.ID, begun.Link, nil
}

// Lookup returns the request's state.
func (v *Verifier) Lookup(id string) (verifier.TransactionView, error) {
	view, err := v.txs.Lookup(context.Background(), id, verifierBrowser)
	if err != nil {
		return verifier.TransactionView{}, fmt.Errorf("walletflowtest: %w", err)
	}
	return view, nil
}
