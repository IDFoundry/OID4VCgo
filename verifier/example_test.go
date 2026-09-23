package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// exampleCA/exampleLeaf are Example_VerifyResponse's own throwaway
// x509 setup — Example functions take no *testing.T, so they can't use
// this package's own ContractCA/ContractLeaf (which need one to report
// setup failures); panic stands in for t.Fatalf here instead, the
// idiomatic choice for an Example's own unrecoverable setup errors.

func exampleCA(commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert, key
}

func exampleLeaf(commonName string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert, key
}

// ExampleVerifier_VerifyResponse is the complete round trip
// VerifyResponseRequest.IssuerKeys' own doc comment points to: a
// Verifier builds a signed Authorization Request, a Wallet (package
// wallet — standing in here for whatever real wallet a deployment
// actually talks to) resolves and answers it with a real presented
// credential, and the Verifier verifies the response — wired with
// X5CIssuerKeyResolver, the ready-made SDJWTVCIssuerKeyResolver this
// package ships for the common "I have a trust anchor CA pool" case.
// A deployment with a different trust policy (DID resolution, VCT
// metadata lookup) implements SDJWTVCIssuerKeyResolver itself instead
// (see TestX5CTrustContract for a contract test to run against it).
func ExampleVerifier_VerifyResponse() {
	// --- Issuer setup: a real (non-self-signed — HAIP §5.3's own MUST)
	// credential issuer certificate, chained to a CA this example will
	// configure as its own trust anchor below.
	issuerCA, issuerCAKey := exampleCA("example-issuer-ca")
	issuerCert, issuerKey := exampleLeaf("example-issuer", issuerCA, issuerCAKey)
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	holderJWK, err := jwk.Marshal(&holderKey.PublicKey)
	if err != nil {
		panic(err)
	}
	sdjwt, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:eudi:pid:1", CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{"given_name": sdjwtvc.SD("Jean")},
	}, sdjwtvc.IssueOptions{IssuerCertificate: issuerCert})
	if err != nil {
		panic(err)
	}
	held := wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: sdjwt, HolderKey: holderKey, HolderKeyAlg: jose.ES256}

	// --- Verifier setup: its own signing identity (for the Request
	// Object's own JAR signature) and query.
	verifierCA, verifierCAKey := exampleCA("example-verifier-ca")
	verifierCert, verifierKey := exampleLeaf("example-verifier", verifierCA, verifierCAKey)
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		panic(err)
	}
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		panic(err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "cred1", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}}},
	}}}

	v, err := verifier.New(verifier.Config{
		ClientCertificate:  verifierCert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
	}, verifier.Dependencies{Signer: verifierKey, Random: rand.Reader})
	if err != nil {
		panic(err)
	}

	// --- The actual OID4VP exchange: build the request, have a wallet
	// answer it, verify the answer.
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		panic(err)
	}

	authReq, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: built.RequestObject, ClientID: built.ClientID,
	})
	if err != nil {
		panic(err)
	}
	vpToken, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query: authReq.Query, Credentials: []wallet.HeldCredential{held},
		Audience: authReq.ClientID, Nonce: authReq.Nonce,
	})
	if err != nil {
		panic(err)
	}
	responseJWE, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, State: authReq.State,
		EncryptionKey: authReq.ResponseEncryptionKey, EncryptionKeyID: authReq.ResponseEncryptionKeyID,
		EncryptionEnc: authReq.ResponseEncryptionEnc,
	})
	if err != nil {
		panic(err)
	}

	parsed, err := v.ParseDirectPostJWTResponse(responseJWE, built.ResponseDecryptionKey)
	if err != nil {
		panic(err)
	}

	// This is the line this example exists to show: IssuerKeys is
	// REQUIRED (VerifyResponse errors without it) and this package
	// leaves deciding what to trust up to the caller — here,
	// X5CIssuerKeyResolver against a pool containing issuerCA, the one
	// CA this deployment has decided to trust.
	roots := x509.NewCertPool()
	roots.AddCert(issuerCA)
	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: query, Response: parsed, ExpectedNonce: built.Nonce,
		IssuerKeys:       &verifier.X5CIssuerKeyResolver{Roots: roots},
		MaxKeyBindingAge: time.Hour,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(result.Credentials[0].Claims["given_name"])
	// Output: Jean
}
