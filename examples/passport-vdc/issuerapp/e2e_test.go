package issuerapp_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/haip"
)

// TestEndToEnd_IssuesBothFormats drives the full HAIP issuance flow
// against the demo issuer with the demo wallet (walletapp, built on a
// real fapigo/client and oid4vcgo/wallet): credential offer → PAR
// carrying issuer_state (Wallet Attestation + PoP, DPoP) → approval →
// token → nonce → credential, once per format.
func TestEndToEnd_IssuesBothFormats(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)

	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP})
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
	issuerPub := env.Issuer.IssuerCertificate().PublicKey

	mdocCred := byConfig[issuerapp.MdocConfigurationID]
	if mdocCred.DocType != credential.DocType {
		t.Errorf("received mdoc DocType = %q", mdocCred.DocType)
	}
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

	payload, _, err := sdjwtvc.Verify(byConfig[issuerapp.SDJWTConfigurationID].Credential, issuerPub, oid4vci.ES256,
		sdjwtvc.VerifyOptions{RequireKeyBinding: sdjwtvc.KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	if payload["vct"] != env.IssuerURL+issuerapp.VCTPath || payload[credential.FamilyName] != "DOE" || payload[credential.ICAOSOD] == nil {
		t.Errorf("sd-jwt payload = %v", payload)
	}
}

// TestAuthorize_RejectsRequestWithoutOffer checks that an authorization
// request not started from this issuer's credential offer (no
// issuer_state) can't reach the approval page.
func TestAuthorize_RejectsRequestWithoutOffer(t *testing.T) {
	env := demotest.New(t, nil)
	uri, err := oid4vci.CredentialOffer{
		CredentialIssuer:           env.IssuerURL,
		CredentialConfigurationIDs: []string{issuerapp.MdocConfigurationID},
	}.AppendToURL("openid-credential-offer://")
	if err != nil {
		t.Fatalf("AppendToURL: %v", err)
	}
	_, err = walletapp.Receive(context.Background(), env.WalletConfig(), uri, walletapp.HeadlessApprover{HTTP: env.HTTP})
	if err == nil || !strings.Contains(err.Error(), "no interaction handle") {
		t.Fatalf("Receive without issuer_state: error = %v, want the approval page to be refused", err)
	}
}
