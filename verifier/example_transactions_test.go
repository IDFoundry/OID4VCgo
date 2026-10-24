package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// A Verifier deployment on Transactions: it builds each request, serves
// its Request Object and response_uri, verifies the answer, and binds
// the result to the browser that asked. Here a wallet answers in
// process; in a deployment it fetches the request_uri and posts to
// response_uri over HTTP, through the two handlers.
func ExampleNewTransactions() {
	issuerCA, issuerCAKey := exampleCA("example-issuer-ca")
	issuerCert, issuerKey := exampleLeaf("example-issuer", issuerCA, issuerCAKey)
	verifierCA, verifierCAKey := exampleCA("example-verifier-ca")
	verifierCert, verifierKey := exampleLeaf("example-verifier", verifierCA, verifierCAKey)
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		panic(err)
	}
	v, err := verifier.New(verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: verifierCert, ResponseURI: responseURI,
		SigningAlg: oid4vci.ES256, EncValuesSupported: []oid4vci.JWEEnc{oid4vci.A128GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
	}, verifier.Dependencies{Signer: verifierKey, Random: rand.Reader})
	if err != nil {
		panic(err)
	}

	// The issuers this deployment trusts, and what every answer gets
	// checked with. A production deployment also sets Accept to check
	// revocation (verifier.RequireValidStatus).
	issuerRoots := x509.NewCertPool()
	issuerRoots.AddCert(issuerCA)
	txs, err := verifier.NewTransactions(v, storage.NewVerifierTransactionStore(), verifier.TransactionsConfig{
		RequestURIBase: "https://verifier.example.com/request",
		Verify: verifier.VerifyResponseRequest{
			// NoCheck keeps the example short: a deployment passes
			// certrevocation.CRLs with its CAs' current lists.
			IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: issuerRoots, Revocation: certrevocation.NoCheck{}}, MaxKeyBindingAge: 5 * time.Minute,
			// Which issuers may issue which types: here issuerCA issues
			// PIDs and nothing else. Under AssuranceProduction this, or
			// AnyIssuerForAnyType, is required.
			IssuerAuthorized: func(_ context.Context, a verifier.IssuerAuthorization) error {
				if a.Type != "urn:eudi:pid:1" {
					return fmt.Errorf("issuerCA doesn't issue %q", a.Type)
				}
				return nil
			},
		},
	})
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /request/{id}", txs.RequestObjectHandler())
	mux.Handle("POST /response", txs.ResponseHandler())

	// A browser asks: the binding is a random token kept in its session,
	// which Lookup checks, so only it can read the result.
	ctx := context.Background()
	binding := rand.Text()
	begun, err := txs.Begin(ctx, dcql.Query{Credentials: []dcql.CredentialQuery{
		dcql.SDJWTVCQuery("pid", "urn:eudi:pid:1", dcql.KeyPath("given_name")),
	}}, binding, false)
	if err != nil {
		panic(err)
	}
	// begun.Link is the openid4vp:// link (or QR code) for the wallet.

	// The wallet's side, in process.
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	holderJWK, err := attestation.AttestedKey(&holderKey.PublicKey)
	if err != nil {
		panic(err)
	}
	credential, _, err := sdjwtvc.Issue(issuerKey, oid4vci.ES256, sdjwtvc.Claims{
		VCT: "urn:eudi:pid:1", CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{"given_name": sdjwtvc.SD("Jean")},
	}, sdjwtvc.IssueOptions{IssuerCertificate: issuerCert})
	if err != nil {
		panic(err)
	}
	requestObject, err := txs.RequestObject(ctx, begun.ID)
	if err != nil {
		panic(err)
	}
	verifierRoots := x509.NewCertPool()
	verifierRoots.AddCert(verifierCA)
	req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: requestObject, ClientID: v.ClientID(), VerifierTrust: wallet.X5CVerifierRoots{Roots: verifierRoots},
	})
	if err != nil {
		panic(err)
	}
	vpToken, err := wallet.PresentCredentials(ctx, wallet.PresentationRequest{
		Query: req.Query, Audience: req.ClientID, Nonce: req.Nonce,
		Credentials: []wallet.HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: credential, HolderKey: holderKey, HolderKeyAlg: oid4vci.ES256}},
	})
	if err != nil {
		panic(err)
	}
	answer, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, State: req.State, EncryptionKey: req.ResponseEncryptionKey,
		EncryptionKeyID: req.ResponseEncryptionKeyID, EncryptionEnc: req.ResponseEncryptionEnc,
	})
	if err != nil {
		panic(err)
	}
	// What ResponseHandler does with the posted response.
	if _, err := txs.HandleResponse(ctx, answer); err != nil {
		panic(err)
	}

	// The browser that asked reads the result.
	view, err := txs.Lookup(ctx, begun.ID, binding)
	if err != nil {
		panic(err)
	}
	fmt.Println(view.Status == verifier.TransactionDone, view.Result.Credentials[0].Claims["given_name"])
	// Output: true Jean
}
