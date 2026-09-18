package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// FuzzParseAuthorizationRequest exercises ParseAuthorizationRequest
// against arbitrary strings — a Request Object is Verifier-supplied
// (or, in the request_uri flow, fetched from wherever the Verifier
// named), attacker-controlled wire data a Wallet must parse before it
// discloses anything. Notable: PR #110 found a real bug here
// (selectResponseEncryptionKey blindly trusting keys[0] instead of
// skipping unparseable decoy JWKs) — the exact class of defect fuzzing
// exists to catch, in this exact function. Builds one genuine,
// verifier.BuildAuthorizationRequest-produced Request Object as seed
// material so the fuzzer starts from something that actually parses.
func FuzzParseAuthorizationRequest(f *testing.F) {
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate signer key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz wallet authorization_request"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &signerKey.PublicKey, signerKey)
	if err != nil {
		f.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		f.Fatalf("ParseCertificate: %v", err)
	}
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		f.Fatalf("ParseEndpointURL: %v", err)
	}
	v, err := verifier.New(verifier.Config{
		ClientCertificate:  cert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{}},
	}, verifier.Dependencies{Signer: signerKey, Random: rand.Reader})
	if err != nil {
		f.Fatalf("verifier.New: %v", err)
	}
	clientID := v.ClientID()

	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		f.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "cred1", Format: "dc+sd-jwt", Meta: meta}}}

	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query, State: "fuzz-state"})
	if err != nil {
		f.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	f.Add(built.RequestObject)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, requestObject string) {
		_, _ = wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
			RequestObject: requestObject, ClientID: clientID,
		})
	})
}
