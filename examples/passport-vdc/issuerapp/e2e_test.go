package issuerapp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
	"github.com/idfoundry/oid4vcgo/haip"
)

// TestEndToEnd_IssuesBothFormats drives the full HAIP issuance flow
// against the demo issuer with the demo wallet (walletapp, built on a
// real fapigo/client and oid4vcgo/wallet): credential offer → PAR
// carrying issuer_state (Wallet Attestation + PoP, DPoP) → approval →
// token → nonce → credential with a Key Attestation proof, once per
// format.
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

// TestMetadata_RequiresKeyAttestation checks both configurations accept
// only the attestation proof type, with key attestation required.
func TestMetadata_RequiresKeyAttestation(t *testing.T) {
	env := demotest.New(t, nil)
	resp, err := env.HTTP.Get(env.IssuerURL + "/.well-known/openid-credential-issuer")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var meta oid4vci.Metadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	for _, id := range []string{issuerapp.MdocConfigurationID, issuerapp.SDJWTConfigurationID} {
		proofTypes := meta.CredentialConfigurationsSupported[id].ProofTypesSupported
		att, ok := proofTypes[oid4vci.ProofTypeAttestation]
		if len(proofTypes) != 1 || !ok || att.KeyAttestationsRequired == nil {
			t.Errorf("%s proof_types_supported = %+v, want only attestation, with key_attestations_required", id, proofTypes)
		}
	}
}

// TestCredential_RejectsKeyAttestationFromUntrustedCA has the wallet
// present a Key Attestation whose x5c certificate chains to another
// Wallet Provider CA: authorization succeeds (the Wallet Attestation is
// valid) but the credential request is refused.
func TestCredential_RejectsKeyAttestationFromUntrustedCA(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	other, err := walletprovider.New(demotest.ProviderIssuer)
	if err != nil {
		t.Fatalf("walletprovider.New: %v", err)
	}
	untrusted := *env.Provider
	untrusted.Certificate, untrusted.CACertificate = other.Certificate, other.CACertificate
	cfg := env.WalletConfig()
	cfg.Provider = &untrusted

	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	_, err = walletapp.Receive(ctx, cfg, offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP})
	// "resolve trust key": the x5c chain doesn't reach the trusted CA.
	if err == nil || !strings.Contains(err.Error(), "invalid_proof") || !strings.Contains(err.Error(), "resolve trust key") {
		t.Fatalf("Receive: error = %v, want the credential request refused for an untrusted x5c chain", err)
	}
}

// TestMetadata_SignedWithItsOwnKey checks the signed Credential Issuer
// Metadata isn't signed with the key that signs credentials, and that
// its certificate chains to the same demo CA.
func TestMetadata_SignedWithItsOwnKey(t *testing.T) {
	env := demotest.New(t, nil)
	req, err := http.NewRequest(http.MethodGet, env.IssuerURL+"/.well-known/openid-credential-issuer", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/jwt")
	resp, err := env.HTTP.Do(req)
	if err != nil {
		t.Fatalf("GET signed metadata: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.Header.Get("Content-Type") != "application/jwt" {
		t.Fatalf("signed metadata: Content-Type %q, %v", resp.Header.Get("Content-Type"), err)
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(strings.Split(string(body), ".")[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil || len(header.X5C) == 0 {
		t.Fatalf("header x5c: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(header.X5C[0])
	if err != nil {
		t.Fatalf("decode x5c: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse x5c: %v", err)
	}
	if cert.PublicKey.(*ecdsa.PublicKey).Equal(env.Issuer.IssuerCertificate().PublicKey) {
		t.Error("metadata is signed with the credential signing key")
	}
	if err := cert.CheckSignatureFrom(env.Issuer.IssuerCACertificate()); err != nil {
		t.Errorf("metadata signing certificate isn't issued by the demo CA: %v", err)
	}
}
