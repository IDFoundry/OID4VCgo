package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
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
// Verifier's request_uri endpoint expects unless it also offers §5.10's
// OPTIONAL POST variant.
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
	// come from its own key management, not freshly generated per
	// request; this example generates a throwaway self-signed one since
	// there is no *testing.T here to hang a shared test helper off of.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("generate key:", err)
		return
	}
	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ExampleWallet_FetchAuthorizationRequest"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTmpl, certTmpl, &clientKey.PublicKey, clientKey)
	if err != nil {
		fmt.Println("CreateCertificate:", err)
		return
	}
	clientCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		fmt.Println("ParseCertificate:", err)
		return
	}
	responseURI, _ := fapi.ParseEndpointURL("https://verifier.example.com/response")
	v, err := verifier.New(verifier.Config{
		Assurance:          verifier.AssuranceDevelopment,
		ClientCertificate:  clientCert,
		ResponseURI:        responseURI,
		SigningAlg:         oid4vci.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
		VPFormatsSupported: verifier.SDJWTVCFormatSupport([]string{oid4vci.ES256}, []string{oid4vci.ES256}),
	}, verifier.Dependencies{Signer: clientKey, Random: rand.Reader})
	if err != nil {
		fmt.Println("verifier.New:", err)
		return
	}

	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		fmt.Println("NewSDJWTVCMeta:", err)
		return
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "cred1", Format: "dc+sd-jwt", Meta: meta}}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		fmt.Println("BuildAuthorizationRequest:", err)
		return
	}

	// A real Verifier serves built.RequestObject at its own
	// request_uri — this httptest.Server stands in for that endpoint.
	requestURIServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(built.RequestObject))
	}))
	defer requestURIServer.Close()

	// --- The Wallet side: everything a real integration needs.
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
	fmt.Println("query asks for credential ID:", authReq.Query.Credentials[0].ID)

	// The OPTIONAL POST variant (§5.10): a Wallet sends a fresh
	// "wallet_nonce" so the Verifier can embed it in the signed Request
	// Object (§5.10.1), which ParseAuthorizationRequest then checks was
	// echoed back. FetchAuthorizationRequest doesn't cover this: it
	// uses this Wallet's own hardened fetcher (fapihttp.Client), which
	// is GET-only by design — widening it to an arbitrary POST would
	// weaken the SSRF hardening every other caller of it relies on. A
	// Wallet that wants the POST variant performs that request itself
	// (a plain http.Client is reasonable here: by this point
	// request_uri is a value already resolved from an openid4vp://
	// deep link/QR code, not attacker-supplied input the way an
	// initial fetch target can be) and calls ParseAuthorizationRequest
	// directly:
	//
	//	walletNonce := freshOpaqueValue()
	//	form := url.Values{"wallet_nonce": {walletNonce}}
	//	resp, err := http.Post(requestURI, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	//	// ... read resp.Body into requestObject ...
	//	authReq, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
	//		RequestObject: requestObject, ClientID: clientID, WalletNonce: walletNonce,
	//	})

	// Output:
	// fetched and parsed a real Request Object over HTTP GET
	// query asks for credential ID: cred1
}
