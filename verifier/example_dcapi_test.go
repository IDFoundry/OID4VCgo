package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// The OpenID4VP flow over the Digital Credentials API, from the
// Verifier's side: build a signed request for the page to pass to
// navigator.credentials.get, then verify the response the page posts
// back. A wallet (package wallet) answers in between, standing in for
// the platform and whatever wallet the user picks.
func ExampleVerifier_BuildDCAPIAuthorizationRequest() {
	// The page's own origin, from this Verifier's configuration.
	const origin = "https://verifier.example.com"

	// A held "dc+sd-jwt" credential, from an issuer under issuerCA.
	issuerCA, issuerCAKey := exampleCA("example-issuer-ca")
	issuerCert, issuerKey := exampleLeaf("example-issuer", issuerCA, issuerCAKey)
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	holderJWK, err := attestation.AttestedKey(&holderKey.PublicKey)
	if err != nil {
		panic(err)
	}
	sdjwt, _, err := sdjwtvc.Issue(issuerKey, oid4vci.ES256, sdjwtvc.Claims{
		VCT: "urn:eudi:pid:1", CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{"given_name": sdjwtvc.SD("Jean")},
	}, sdjwtvc.IssueOptions{IssuerCertificate: issuerCert})
	if err != nil {
		panic(err)
	}
	held := wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: sdjwt, HolderKey: holderKey, HolderKeyAlg: oid4vci.ES256}

	// The Verifier, signing its requests with a certificate under
	// verifierCA.
	verifierCA, verifierCAKey := exampleCA("example-verifier-ca")
	verifierCert, verifierKey := exampleLeaf("example-verifier", verifierCA, verifierCAKey)
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		panic(err)
	}
	v, err := verifier.New(verifier.Config{
		Assurance:          verifier.AssuranceDevelopment,
		ClientCertificate:  verifierCert,
		ResponseURI:        responseURI,
		SigningAlg:         oid4vci.ES256,
		EncValuesSupported: []oid4vci.JWEEnc{oid4vci.A128GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
	}, verifier.Dependencies{Signer: verifierKey, Random: rand.Reader})
	if err != nil {
		panic(err)
	}

	// Build the request. Keep built (its Nonce, ResponseDecryptionKey and
	// ExpectedOrigins) for the response; the page passes
	// {"request": built.RequestObject} as the "openid4vp-v1-signed"
	// request's data.
	query := dcql.Query{Credentials: []dcql.CredentialQuery{
		dcql.SDJWTVCQuery("pid", "urn:eudi:pid:1", dcql.KeyPath("given_name")),
	}}
	built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: query, ExpectedOrigins: []string{origin},
	})
	if err != nil {
		panic(err)
	}

	// The wallet: check the request (the platform reports the origin),
	// present the credential bound to that origin, and encrypt the
	// vp_token to the Verifier's key.
	verifierRoots := x509.NewCertPool()
	verifierRoots.AddCert(verifierCA)
	authReq, err := wallet.ParseDCAPIRequest(wallet.ParseDCAPIRequestParams{
		Request: built.RequestObject, Origin: origin,
		VerifierTrust: wallet.X5CVerifierRoots{Roots: verifierRoots},
	})
	if err != nil {
		panic(err)
	}
	vpToken, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query: authReq.Query, Credentials: []wallet.HeldCredential{held},
		Origin: authReq.Origin, Nonce: authReq.Nonce,
	})
	if err != nil {
		panic(err)
	}
	response, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken:       vpToken,
		EncryptionKey: authReq.ResponseEncryptionKey, EncryptionKeyID: authReq.ResponseEncryptionKeyID,
		EncryptionEnc: authReq.ResponseEncryptionEnc,
	})
	if err != nil {
		panic(err)
	}

	// Verify the response the page posted back: the "response" member
	// of the DC API result.
	parsed, err := v.ParseDirectPostJWTResponse(response, built.ResponseDecryptionKey)
	if err != nil {
		panic(err)
	}
	issuerRoots := x509.NewCertPool()
	issuerRoots.AddCert(issuerCA)
	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: query, Response: parsed, ExpectedNonce: built.Nonce,
		IssuerKeys:       &verifier.X5CIssuerKeyResolver{Roots: issuerRoots},
		MaxKeyBindingAge: time.Hour,
		// Origin is this Verifier's own page origin, from its
		// configuration: never from the HTTP request carrying the
		// response (an Origin header, a parameter), or a site relaying
		// this Verifier's request as its own would be accepted.
		Origin:          origin,
		ExpectedOrigins: built.ExpectedOrigins,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("expected origins:", built.ExpectedOrigins)
	fmt.Println("given_name:", result.Credentials[0].Claims["given_name"])
	// Output:
	// expected origins: [https://verifier.example.com]
	// given_name: Jean
}
