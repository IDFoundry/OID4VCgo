package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testverifier"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// FuzzParseDCAPIRequest exercises ParseDCAPIRequest past the signature
// check, as FuzzParseAuthorizationRequestSigned does for the redirect
// flow: the harness signs each fuzzed payload with its own self-signed
// certificate, whose x509_hash it sets as client_id in the seeds. A
// request it accepts must expect the origin it was given.
func FuzzParseDCAPIRequest(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz-verifier"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		f.Fatalf("CreateCertificate: %v", err)
	}
	hash := sha256.Sum256(der)
	clientID := "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
	header := map[string]any{"typ": "oauth-authz-req+jwt", "x5c": []string{base64.StdEncoding.EncodeToString(der)}}
	const origin = "https://verifier.example.com"

	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		f.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	built, err := testverifier.New(f).BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query:           dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "cred1", Format: "dc+sd-jwt", Meta: meta}}},
		ExpectedOrigins: []string{origin},
	})
	if err != nil {
		f.Fatalf("BuildDCAPIAuthorizationRequest: %v", err)
	}
	_, rawPayload, err := jose.DecodeUnverified(built.RequestObject)
	if err != nil {
		f.Fatalf("DecodeUnverified: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(rawPayload, &claims); err != nil {
		f.Fatalf("unmarshal payload: %v", err)
	}
	claims["client_id"] = clientID
	for _, mutate := range []func(){
		func() {},
		func() { claims["transaction_data"] = []string{"e30"} },
		func() { claims["expected_origins"] = []string{"https://other.example.com"} },
	} {
		mutate()
		seed, err := json.Marshal(claims)
		if err != nil {
			f.Fatalf("marshal payload: %v", err)
		}
		f.Add(seed)
	}
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, payload []byte) {
		requestObject, err := jose.Sign(jose.ES256, key, header, payload)
		if err != nil {
			t.Fatalf("sign request object: %v", err)
		}
		req, err := wallet.ParseDCAPIRequest(wallet.ParseDCAPIRequestParams{
			Request: requestObject, Origin: origin, VerifierTrust: wallet.NoVerifierTrust{},
		})
		if err != nil {
			return
		}
		var got struct {
			ExpectedOrigins []string `json:"expected_origins"`
		}
		if err := json.Unmarshal(payload, &got); err != nil || !slices.Contains(got.ExpectedOrigins, origin) {
			t.Fatalf("accepted a request whose expected_origins %v don't include %q", got.ExpectedOrigins, origin)
		}
		if req.Origin != origin || req.ResponseEncryptionKey == nil || req.ResponseURI != "" {
			t.Fatalf("accepted request = %+v", req)
		}
	})
}
