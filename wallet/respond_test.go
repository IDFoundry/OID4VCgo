package wallet_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// TestRespond answers a real verifier.Transactions request in one call,
// and the verifier accepts it.
func TestRespond(t *testing.T) {
	ctx := context.Background()
	issuerCA, issuerCAKey := testcert.CA(t, "respond issuer CA")
	issuerCert, issuerKey := testcert.Leaf(t, "respond issuer", issuerCA, issuerCAKey)
	holderKey := testP256Key(t)
	holderJWK, err := jwk.Marshal(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cred, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:respond:1", CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{"given_name": sdjwtvc.SD("Jean")},
	}, sdjwtvc.IssueOptions{IssuerCertificate: issuerCert})
	if err != nil {
		t.Fatal(err)
	}
	held := wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256}

	var txs *verifier.Transactions
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { txs.ResponseHandler().ServeHTTP(w, r) }))
	defer srv.Close()
	responseURI, err := fapi.ParseEndpointURL(srv.URL + "/response")
	if err != nil {
		t.Fatal(err)
	}
	verifierCA, verifierCAKey := testcert.CA(t, "respond verifier CA")
	verifierCert, verifierKey := testcert.Leaf(t, "respond verifier", verifierCA, verifierCAKey)
	v, err := verifier.New(verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: verifierCert, ResponseURI: responseURI,
		SigningAlg: jose.ES256, EncValuesSupported: []jwe.Enc{jwe.A128GCM},
		VPFormatsSupported: verifier.SDJWTVCFormatSupport([]string{"ES256"}, []string{"ES256"}),
	}, verifier.Dependencies{Signer: verifierKey, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuerCA)
	if txs, err = verifier.NewTransactions(v, storage.NewVerifierTransactionStore(), verifier.TransactionsConfig{
		RequestURIBase: "https://verifier.example.com/request-objects",
		Verify:         verifier.VerifyResponseRequest{IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: roots}, MaxKeyBindingAge: time.Hour},
	}); err != nil {
		t.Fatal(err)
	}
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:respond:1"}})
	if err != nil {
		t.Fatal(err)
	}
	begun, err := txs.Begin(ctx, dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "cred", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}}},
	}}}, "holder-browser-session", false)
	if err != nil {
		t.Fatal(err)
	}
	object, err := txs.RequestObject(ctx, begun.ID)
	if err != nil {
		t.Fatal(err)
	}
	link, _ := url.Parse(begun.Link)
	verifierRoots := x509.NewCertPool()
	verifierRoots.AddCert(verifierCA)
	req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: object, ClientID: link.Query().Get("client_id"), VerifierTrust: wallet.X5CVerifierRoots{Roots: verifierRoots},
	})
	if err != nil {
		t.Fatalf("ParseAuthorizationRequest: %v", err)
	}

	responded, err := wallet.Respond(ctx, srv.Client(), req, []wallet.HeldCredential{held}, nil)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if len(responded.VPToken["cred"]) != 1 {
		t.Errorf("VPToken = %v, want one presentation for cred", responded.VPToken)
	}
	view, err := txs.Lookup(ctx, begun.ID, "holder-browser-session")
	if err != nil || view.Status != verifier.TransactionDone || view.Result.Credentials[0].Claims["given_name"] != "Jean" {
		t.Fatalf("verifier after Respond: %+v, %v", view, err)
	}

	if _, err := wallet.Respond(ctx, srv.Client(), req, nil, nil); err == nil {
		t.Error("Respond with no credentials succeeded")
	}
	if _, err := wallet.Respond(ctx, srv.Client(), req, []wallet.HeldCredential{held}, nil); err == nil {
		t.Error("a second answer to a completed request was accepted")
	}
}
