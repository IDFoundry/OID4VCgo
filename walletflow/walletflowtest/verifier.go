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
	"github.com/idfoundry/oid4vcgo/registration"
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
	// v and verify answer DC API requests, which no transaction holds:
	// the response comes back through the platform.
	v      *verifier.Verifier
	verify verifier.VerifyResponseRequest
}

// The browser binding every request is begun with.
const verifierBrowser = "testhaip-browser"

// StartVerifier starts a Verifier on a loopback TLS server, stopped by
// e.Close. httptest serves every server with the same certificate, so
// e.HTTP reaches it too.
func (e *Env) StartVerifier() (*Verifier, error) { return e.startVerifier(nil) }

// StartRegisteredVerifier is StartVerifier for a Verifier e's registrar
// (RegistrarRoots) has registered to request claims: its requests carry
// the registration in verifier_info (the registration package).
func (e *Env) StartRegisteredVerifier(claims ...dcql.Path) (*Verifier, error) {
	if claims == nil {
		claims = []dcql.Path{}
	}
	return e.startVerifier(claims)
}

// startVerifier starts a Verifier, registered for registered unless
// it's nil.
func (e *Env) startVerifier(registered []dcql.Path) (started *Verifier, err error) {
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
	cfg := verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: cert, ResponseURI: responseURI,
		SigningAlg: jose.ES256, EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM}, VPFormatsSupported: formats,
	}
	vv, err := verifier.New(cfg, verifier.Dependencies{Signer: key, Random: rand.Reader})
	must(err)
	v.ClientID = vv.ClientID()
	if registered != nil {
		token, err := registration.Issue(registration.Registration{
			Registrar: "https://" + RegistrarHost, ClientID: v.ClientID, Name: "Registered " + v.Name,
			Purpose: "Testing", PrivacyPolicy: "https://verifier.walletflowtest.example/privacy",
			Claims: registered, Expires: time.Now().Add(24 * time.Hour),
		}, e.registrarKey, []*x509.Certificate{e.registrarCert})
		must(err)
		cfg.VerifierInfo = []verifier.VerifierInfo{{Format: registration.Format, Data: token}}
		vv, err = verifier.New(cfg, verifier.Dependencies{Signer: key, Random: rand.Reader})
		must(err)
	}
	v.v, v.verify = vv, verifier.VerifyResponseRequest{
		IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: e.IssuerRoots}, MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: e.IssuerRoots},
		MaxKeyBindingAge: time.Hour,
	}
	v.txs, err = verifier.NewTransactions(vv, storage.NewVerifierTransactionStore(), verifier.TransactionsConfig{
		RequestURIBase: base + "/request-objects", Verify: v.verify,
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
	q = dcql.SDJWTVCQuery(id, e.vct)
	for _, c := range claims {
		q.Claims = append(q.Claims, dcql.ClaimsQuery{Path: dcql.KeyPath(c)})
	}
	return q, nil
}

// MdocQuery asks for an mdoc of DocType, disclosing elements of
// NameSpace.
func MdocQuery(id string, elements ...string) (q dcql.CredentialQuery, err error) {
	defer recoverInto(&err)
	q = dcql.MdocQuery(id, DocType)
	for _, el := range elements {
		q.Claims = append(q.Claims, dcql.ClaimsQuery{Path: dcql.KeyPath(NameSpace, el)})
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
