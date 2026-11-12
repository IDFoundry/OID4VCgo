package wallet_test

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
	"net/http"
	"net/http/httptest"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// ExampleWallet_FetchAuthorizationRequest demonstrates OID4VP §5.10's
// own request_uri fetch — the one piece of the flow
// wallet.ParseAuthorizationRequest deliberately never does itself (see
// its own doc comment: transport is the caller's job, the same split
// verifier.BuildAuthorizationRequest draws on the building side).
// FetchAuthorizationRequest is the batteries-included default: a plain
// GET, using this Wallet's own hardened fetcher — exactly what a real
// Verifier's request_uri endpoint expects unless its link asks for
// §5.10's POST variant, which FetchAuthorizationRequestPost sends
// through the same fetcher.
//
// This example stands up a real *verifier.Verifier and a real HTTP
// server for it (httptest.Server, an actual TCP listener — not a fake
// transport) purely so FetchAuthorizationRequest has a genuine Request
// Object to fetch; a real integration only needs the Wallet-side calls
// this example makes.
func ExampleWallet_FetchAuthorizationRequest() {
	// --- Stand up a real Verifier, the same way any OID4VP Verifier
	// using this library would (see verifier.New's own doc comment for
	// every field here). A real deployment's ClientCertificate/Signer
	// come from its own key management and a real CA, not freshly
	// generated per request; this example generates a throwaway CA and
	// a leaf under it (HAIP 1.0 §5: the request-signing certificate
	// must not be self-signed).
	caKey, caCert, err := exampleCertificate(nil, nil, "ExampleWallet_FetchAuthorizationRequest CA")
	if err != nil {
		fmt.Println("CA:", err)
		return
	}
	clientKey, clientCert, err := exampleCertificate(caCert, caKey, "ExampleWallet_FetchAuthorizationRequest")
	if err != nil {
		fmt.Println("leaf:", err)
		return
	}
	responseURI, _ := fapi.ParseEndpointURL("https://verifier.example.com/response")
	v, err := verifier.New(verifier.Config{
		Assurance:          verifier.AssuranceDevelopment,
		ClientCertificate:  clientCert,
		ResponseURI:        responseURI,
		SigningAlg:         oid4vci.ES256,
		EncValuesSupported: []oid4vci.JWEEnc{oid4vci.A128GCM},
		VPFormatsSupported: verifier.SDJWTVCFormatSupport([]string{oid4vci.ES256}, []string{oid4vci.ES256}),
	}, verifier.Dependencies{Signer: clientKey, Random: rand.Reader})
	if err != nil {
		fmt.Println("verifier.New:", err)
		return
	}

	query := dcql.Query{Credentials: []dcql.CredentialQuery{dcql.SDJWTVCQuery("cred1", "urn:eudi:pid:1")}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		fmt.Println("BuildAuthorizationRequest:", err)
		return
	}

	// A real Verifier serves built.RequestObject at its own
	// request_uri — this httptest.Server stands in for that endpoint.
	// Asked with POST (request_uri_method=post, §5.10), it builds a
	// fresh Request Object carrying the Wallet's wallet_nonce instead.
	requestURIServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestObject := built.RequestObject
		if r.Method == http.MethodPost {
			fresh, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query, WalletNonce: r.PostFormValue("wallet_nonce")})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			requestObject = fresh.RequestObject
		}
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(requestObject))
	}))
	defer requestURIServer.Close()

	// --- The Wallet side: everything a real integration needs,
	// including which Verifiers to trust (OID4VP §5.9.3) — here, any
	// whose request-signing certificate chains to the example CA.
	verifierRoots := x509.NewCertPool()
	verifierRoots.AddCert(caCert)
	w, err := wallet.New(wallet.Config{
		Assurance:       wallet.AssuranceDevelopment,
		ProofSigningAlg: oid4vci.ES256,
		Fetch: fapihttp.Config{
			MaxResponseBytes: 1 << 20, RequestTimeout: 5 * time.Second,
			// httptest.Server listens on 127.0.0.1 — a real deployment
			// fetches a real Verifier's own https:// request_uri and
			// leaves this false (the default).
			AllowLoopbackHTTP: true,
		},
		VerifierTrust: wallet.X5CVerifierRoots{Roots: verifierRoots},
	}, wallet.Dependencies{HTTP: http.DefaultClient, Clock: wallet.ClockFunc(time.Now)})
	if err != nil {
		fmt.Println("wallet.New:", err)
		return
	}

	authReq, err := w.FetchAuthorizationRequest(context.Background(), requestURIServer.URL, v.ClientID())
	if err != nil {
		fmt.Println("FetchAuthorizationRequest:", err)
		return
	}
	fmt.Println("fetched and parsed a real Request Object over HTTP GET")
	fmt.Println("signed by trusted verifier:", authReq.VerifierCertificate.Subject.CommonName)
	fmt.Println("query asks for credential ID:", authReq.Query.Credentials[0].ID)

	// For a link with request_uri_method=post (§5.10), the Wallet
	// POSTs a fresh wallet_nonce, and optionally its own metadata, to
	// request_uri through the same hardened fetcher — request_uri comes
	// from the QR code or deep link, which anyone can make — and checks
	// the Request Object echoes that nonce (§5.10.1).
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		fmt.Println("wallet_nonce:", err)
		return
	}
	walletMetadata := json.RawMessage(`{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]}},` +
		`"response_types_supported":["vp_token"],"response_modes_supported":["direct_post.jwt"],` +
		`"issuer":"https://self-issued.me/v2"}`)
	if _, err := w.FetchAuthorizationRequestPost(context.Background(), requestURIServer.URL, v.ClientID(),
		base64.RawURLEncoding.EncodeToString(nonce), walletMetadata); err != nil {
		fmt.Println("FetchAuthorizationRequestPost:", err)
		return
	}
	fmt.Println("fetched a Request Object over HTTP POST, bound to its wallet_nonce")

	// Output:
	// fetched and parsed a real Request Object over HTTP GET
	// signed by trusted verifier: ExampleWallet_FetchAuthorizationRequest
	// query asks for credential ID: cred1
	// fetched a Request Object over HTTP POST, bound to its wallet_nonce
}

// exampleCertificate generates a P-256 key and a certificate for it
// named name: a self-signed CA when parent is nil, otherwise a leaf
// issued by parent.
func exampleCertificate(parent *x509.Certificate, parentKey *ecdsa.PrivateKey, name string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if parent == nil {
		tmpl.KeyUsage, tmpl.IsCA, tmpl.BasicConstraintsValid = x509.KeyUsageCertSign, true, true
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return key, cert, err
}
