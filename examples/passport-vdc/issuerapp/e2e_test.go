package issuerapp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
	"github.com/idfoundry/oid4vcgo/haip"
)

const (
	walletClientID = "passport-vdc-wallet"
	redirectURI    = "http://127.0.0.1/callback"
	providerIssuer = "https://wallet-provider.demo.example"
)

func date(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return d
}

// syntheticEvidence stands in for a verified passport, so this test
// runs in CI without a real (personal-data) passport file.
func syntheticEvidence() passport.Evidence {
	return passport.Evidence{
		Identity: passport.Identity{
			FamilyName: "DOE", GivenNames: "JANE", NamesFromMRZ: true,
			BirthDate: passport.BirthDate{
				Resolution: passport.BirthDateInferred, Date: date("1980-01-01"), Youngest: date("1980-01-01"),
			},
			Sex: "F", Nationality: "SGP", IssuingCountry: "SGP", DocumentNumber: "K0000000A",
			ExpiryDate: time.Now().AddDate(5, 0, 0),
		},
		Raw: passport.RawDataGroups{
			SOD: []byte("synthetic-sod"), DG1: []byte("synthetic-dg1"), DG2: bytes.Repeat([]byte{0xAB}, 20<<10),
		},
		Checks: passport.Checks{PassiveAuthentication: true, ChipAuthenticity: "n/a"},
	}
}

// startIssuer runs an issuerapp.App on a loopback TLS listener, with
// an empty CSCA pool: tests using it inject already-verified Evidence.
func startIssuer(t *testing.T, provider *walletprovider.Provider) (*issuerapp.App, string) {
	t.Helper()
	return startIssuerWithPool(t, provider, &cms.GenericCertPool{})
}

// startIssuerWithMasterList is startIssuer trusting gmrtd's built-in
// ICAO CSCA master list, for tests that upload a real passport.
func startIssuerWithMasterList(t *testing.T, provider *walletprovider.Provider) (*issuerapp.App, string) {
	t.Helper()
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}
	return startIssuerWithPool(t, provider, pool)
}

func startIssuerWithPool(t *testing.T, provider *walletprovider.Provider, pool cms.CertPool) (*issuerapp.App, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	issuerURL := "https://" + srv.Listener.Addr().String()
	jwks, err := provider.PublicJWKS()
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	app, err := issuerapp.New(issuerapp.Config{
		IssuerURL: issuerURL,
		CSCAPool:  pool,
		Wallet: issuerapp.WalletClient{
			ClientID: walletClientID, RedirectURIs: []string{redirectURI},
			ProviderIssuer: providerIssuer, ProviderJWKS: jwks,
		},
	})
	if err != nil {
		t.Fatalf("issuerapp.New: %v", err)
	}
	srv.Config.Handler = app
	srv.StartTLS()
	t.Cleanup(srv.Close)
	tlsClients[issuerURL] = srv.Client()
	return app, issuerURL
}

// tlsClients maps each test issuer's URL to an *http.Client trusting its
// self-signed TLS certificate.
var tlsClients = map[string]*http.Client{}

// TestEndToEnd_IssuesBothFormats drives the full HAIP issuance flow
// against the demo issuer with the demo wallet (walletapp, built on a
// real fapigo/client and oid4vcgo/wallet): credential offer → PAR
// carrying issuer_state (Wallet Attestation + PoP, DPoP) → approval →
// token → nonce → credential, once per format.
func TestEndToEnd_IssuesBothFormats(t *testing.T) {
	ctx := context.Background()
	provider, err := walletprovider.New(providerIssuer)
	if err != nil {
		t.Fatalf("walletprovider.New: %v", err)
	}
	app, issuerURL := startIssuer(t, provider)

	offer, err := app.CreateTransaction(ctx, syntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	received, err := walletapp.Receive(ctx, walletConfig(provider, issuerURL), offer.URI, walletapp.HeadlessApprover{HTTP: tlsClients[issuerURL]})
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	byConfig := map[string]walletapp.Received{}
	for _, r := range received {
		byConfig[r.ConfigurationID] = r
	}
	if len(byConfig) != 2 {
		t.Fatalf("received %d credentials, want one per format", len(received))
	}
	issuerPub := app.IssuerCertificate().PublicKey

	// mso_mdoc
	mdocCred := byConfig[issuerapp.MdocConfigurationID]
	wire, err := base64.RawURLEncoding.DecodeString(mdocCred.Credential)
	if err != nil {
		t.Fatalf("decode mdoc credential: %v", err)
	}
	signed, err := mdoc.UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}
	verified, err := mdoc.Verify(signed, credential.DocType, issuerPub, haip.RecommendedCOSEAlgorithm, mdoc.VerifyOptions{})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	if verified.NameSpaces[credential.IdentityNamespace][credential.FamilyName] != "DOE" {
		t.Errorf("mdoc family_name = %v", verified.NameSpaces[credential.IdentityNamespace][credential.FamilyName])
	}
	if got, _ := verified.NameSpaces[credential.ICAONamespace][credential.ICAODG2].([]byte); len(got) != 20<<10 {
		t.Errorf("mdoc icao_dg2 is %d bytes, want %d", len(got), 20<<10)
	}
	if !mdocCred.HolderKey.PublicKey.Equal(verified.DeviceKey) {
		t.Error("mdoc DeviceKey isn't the holder key the wallet proved")
	}

	// dc+sd-jwt
	payload, _, err := sdjwtvc.Verify(byConfig[issuerapp.SDJWTConfigurationID].Credential, issuerPub, oid4vci.ES256,
		sdjwtvc.VerifyOptions{RequireKeyBinding: sdjwtvc.KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	if payload["vct"] != issuerURL+issuerapp.VCTPath || payload[credential.FamilyName] != "DOE" || payload[credential.ICAOSOD] == nil {
		t.Errorf("sd-jwt payload = %v", payload)
	}
}

// TestAuthorize_RejectsRequestWithoutOffer checks that an authorization
// request not started from this issuer's credential offer (no
// issuer_state) can't reach the approval page.
func TestAuthorize_RejectsRequestWithoutOffer(t *testing.T) {
	ctx := context.Background()
	provider, err := walletprovider.New(providerIssuer)
	if err != nil {
		t.Fatalf("walletprovider.New: %v", err)
	}
	_, issuerURL := startIssuer(t, provider)

	// A well-formed offer for this issuer, but with no grants — so no
	// issuer_state for the wallet to send.
	uri, err := oid4vci.CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{issuerapp.MdocConfigurationID},
	}.AppendToURL("openid-credential-offer://")
	if err != nil {
		t.Fatalf("AppendToURL: %v", err)
	}
	_, err = walletapp.Receive(ctx, walletConfig(provider, issuerURL), uri, walletapp.HeadlessApprover{HTTP: tlsClients[issuerURL]})
	if err == nil || !strings.Contains(err.Error(), "no interaction handle") {
		t.Fatalf("Receive without issuer_state: error = %v, want the approval page to be refused", err)
	}
}

func walletConfig(provider *walletprovider.Provider, issuerURL string) walletapp.Config {
	return walletapp.Config{ClientID: walletClientID, RedirectURI: redirectURI, Provider: provider, HTTP: tlsClients[issuerURL]}
}
