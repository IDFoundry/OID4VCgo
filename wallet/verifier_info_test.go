package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/registration"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// TestVerifierInfo_RoundTrip: a registration a Verifier carries in
// verifier_info reaches the Wallet in both flows, and verifies against
// the registrar's roots for that Verifier's client_id.
func TestVerifierInfo_RoundTrip(t *testing.T) {
	key, cert, trust := testVerifierSignerAndCert(t)
	clientID := newTestVerifierWith(t, key, cert).ClientID()
	roots, token := testRegistration(t, clientID)
	v := newTestVerifierWithInfo(t, key, cert, []verifier.VerifierInfo{{Format: registration.Format, Data: token, CredentialIDs: []string{"cred1"}}})
	query := testQuery(t)

	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	got, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{RequestObject: built.RequestObject, ClientID: clientID, VerifierTrust: trust})
	if err != nil {
		t.Fatal(err)
	}
	dcapi, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{Query: query, ExpectedOrigins: []string{"https://verifier.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	gotDC, err := wallet.ParseDCAPIRequest(wallet.ParseDCAPIRequestParams{Request: dcapi.RequestObject, Origin: "https://verifier.example.com", VerifierTrust: trust})
	if err != nil {
		t.Fatal(err)
	}
	for name, req := range map[string]wallet.AuthorizationRequest{"redirect": got, "dc api": gotDC} {
		if len(req.VerifierInfo) != 1 || req.VerifierInfo[0].Format != registration.Format || !req.VerifierInfo[0].AppliesTo("cred1") || req.VerifierInfo[0].AppliesTo("other") {
			t.Fatalf("%s: VerifierInfo = %+v", name, req.VerifierInfo)
		}
		data, ok := req.VerifierInfo[0].DataString()
		if !ok {
			t.Fatalf("%s: data isn't a string", name)
		}
		reg, err := registration.Verify(data, roots, req.ClientID, time.Now())
		if err != nil || reg.Name != "Test Shop" {
			t.Errorf("%s: registration.Verify = %+v, %v", name, reg, err)
		}
	}

	// A request without verifier_info has none.
	plain, err := newTestVerifierWith(t, key, cert).BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	if req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{RequestObject: plain.RequestObject, ClientID: clientID, VerifierTrust: trust}); err != nil || req.VerifierInfo != nil {
		t.Errorf("no verifier_info: %+v, %v", req.VerifierInfo, err)
	}
}

// TestVerifierInfo_VerifierRefuses: the Verifier refuses an entry
// without a format or data, and builds no request whose query lacks a
// credential query an entry names.
func TestVerifierInfo_VerifierRefuses(t *testing.T) {
	key, cert, _ := testVerifierSignerAndCert(t)
	for name, info := range map[string]verifier.VerifierInfo{
		"no format":   {Data: "x"},
		"no data":     {Format: "jwt"},
		"number data": {Format: "jwt", Data: 7},
		"empty ids":   {Format: "jwt", Data: "x", CredentialIDs: []string{}},
	} {
		if _, err := verifier.New(verifierConfig(t, cert, []verifier.VerifierInfo{info}), verifier.Dependencies{Signer: key, Random: rand.Reader}); err == nil {
			t.Errorf("%s: verifier.New accepted it", name)
		}
	}
	v := newTestVerifierWithInfo(t, key, cert, []verifier.VerifierInfo{{Format: "jwt", Data: "x", CredentialIDs: []string{"nope"}}})
	if _, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)}); err == nil {
		t.Error("a request with verifier_info naming no credential query of it was built")
	}
}

func verifierConfig(t *testing.T, cert *x509.Certificate, info []verifier.VerifierInfo) verifier.Config {
	t.Helper()
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		t.Fatal(err)
	}
	return verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: cert, ResponseURI: responseURI,
		SigningAlg: jose.ES256, EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
		VerifierInfo:       info,
	}
}

func newTestVerifierWithInfo(t *testing.T, key *ecdsa.PrivateKey, cert *x509.Certificate, info []verifier.VerifierInfo) *verifier.Verifier {
	t.Helper()
	v, err := verifier.New(verifierConfig(t, cert, info), verifier.Dependencies{Signer: key, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// testRegistration is a registrar's roots and a registration it issued
// for clientID.
func testRegistration(t *testing.T, clientID string) (*x509.CertPool, string) {
	t.Helper()
	caKey, caCert := testCA(t, "test registrar CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "test registrar"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		URIs: []*url.URL{{Scheme: "https", Host: "registrar.example"}},
	}, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	token, err := registration.Issue(registration.Registration{
		Registrar: "https://registrar.example", ClientID: clientID, Name: "Test Shop",
		Claims: []dcql.Path{{dcql.PathKey("age_over_18")}}, Expires: time.Now().Add(time.Hour),
	}, key, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return roots, token
}
