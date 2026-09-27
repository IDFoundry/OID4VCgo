package issuerapp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/idfoundry/fapigo/client"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
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
	received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
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

// TestPAR_RejectsWalletFromUntrustedProvider has a wallet attested by
// another Wallet Provider — its key and certificate under another CA —
// try to redeem an offer: its Wallet Attestation's x5c chain doesn't
// reach the trusted Wallet Provider CA, so PAR refuses it (HAIP 1.0
// §4.4.1, fapigo/server's X5CAttesterChain) and nothing is issued.
func TestPAR_RejectsWalletFromUntrustedProvider(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	other, err := walletprovider.New(demotest.ProviderIssuer)
	if err != nil {
		t.Fatalf("walletprovider.New: %v", err)
	}
	cfg := env.WalletConfig()
	cfg.Provider = other

	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	_, err = walletapp.Receive(ctx, cfg, offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err == nil || !strings.Contains(err.Error(), "pushed authorization request") || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("Receive: error = %v, want PAR to refuse the Wallet Attestation", err)
	}
	// The offer wasn't claimed: the trusted wallet can still redeem it.
	if _, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}); err != nil {
		t.Fatalf("Receive by the trusted wallet afterwards: %v", err)
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

// TestOffer_RedeemedOnce checks an offer works once: after one wallet
// has redeemed it, another attempt is refused at the approval step.
func TestOffer_RedeemedOnce(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	approver := walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}
	if _, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, approver); err != nil {
		t.Fatalf("first Receive: %v", err)
	}
	if _, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, approver); err == nil || !strings.Contains(err.Error(), "no interaction handle") {
		t.Fatalf("second Receive: error = %v, want the approval page refused", err)
	}
}

// TestApproval_RequiresConfirmationCode checks approving with a wrong
// confirmation code issues nothing and doesn't use up the offer: the
// right code still works afterwards.
func TestApproval_RequiresConfirmationCode(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	wrong := "x" + offer.ConfirmationCode[1:]
	_, err = walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: wrong})
	if err == nil || !strings.Contains(err.Error(), "no redirect") {
		t.Fatalf("Receive with a wrong code: error = %v, want approval refused", err)
	}
	received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil || len(received) != 2 {
		t.Fatalf("Receive with the right code after a wrong one: %d credentials, %v", len(received), err)
	}
}

// TestVCTMetadata_IsValidTypeMetadata checks the document served at the
// credentials' vct is valid SD-JWT VC Type Metadata for that vct.
func TestVCTMetadata_IsValidTypeMetadata(t *testing.T) {
	env := demotest.New(t, nil)
	resp, err := env.HTTP.Get(env.IssuerURL + issuerapp.VCTPath)
	if err != nil {
		t.Fatalf("GET vct: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc sdjwtvc.TypeMetadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := doc.Validate(); err != nil || doc.VCT != env.IssuerURL+issuerapp.VCTPath || len(doc.Claims) == 0 {
		t.Fatalf("type metadata = %+v, %v", doc, err)
	}
}

// recordingTransport records the Content-Type of every request to, and
// response from, a URL path.
type recordingTransport struct {
	base     http.RoundTripper
	path     string
	mu       sync.Mutex
	requests []string
	replies  []string
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(r)
	if r.URL.Path == rt.path && err == nil {
		rt.mu.Lock()
		rt.requests = append(rt.requests, r.Header.Get("Content-Type"))
		rt.replies = append(rt.replies, resp.Header.Get("Content-Type"))
		rt.mu.Unlock()
	}
	return resp, err
}

// TestCredential_EncryptedBothWays checks the issuer advertises request
// and response encryption as required, and that the wallet's credential
// requests and the issuer's responses really travel as JWEs.
func TestCredential_EncryptedBothWays(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)

	resp, err := env.HTTP.Get(env.IssuerURL + "/.well-known/openid-credential-issuer")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	var meta struct {
		Request  map[string]any `json:"credential_request_encryption"`
		Response map[string]any `json:"credential_response_encryption"`
	}
	err = json.NewDecoder(resp.Body).Decode(&meta)
	_ = resp.Body.Close()
	if err != nil || meta.Request["encryption_required"] != true || meta.Response["encryption_required"] != true {
		t.Fatalf("metadata encryption = %+v / %+v (%v), want both required", meta.Request, meta.Response, err)
	}

	recorder := &recordingTransport{base: env.HTTP.Transport, path: "/credential"}
	cfg := env.WalletConfig()
	recording := *env.HTTP
	recording.Transport = recorder
	cfg.HTTP = &recording
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	received, err := walletapp.Receive(ctx, cfg, offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil || len(received) != 2 {
		t.Fatalf("Receive: %d credentials, %v", len(received), err)
	}
	if len(recorder.requests) != 2 {
		t.Fatalf("saw %d credential requests, want 2", len(recorder.requests))
	}
	for i := range recorder.requests {
		if recorder.requests[i] != "application/jwt" || recorder.replies[i] != "application/jwt" {
			t.Errorf("credential exchange %d: request %q, response %q; want both application/jwt", i, recorder.requests[i], recorder.replies[i])
		}
	}
}

// TestASMetadata_AdvertisesDPoP checks the Authorization Server metadata
// advertises DPoP's signing algorithms (RFC 9449 §5.1), now served by
// fapigo's own server.Metadata.
func TestASMetadata_AdvertisesDPoP(t *testing.T) {
	env := demotest.New(t, nil)
	resp, err := env.HTTP.Get(env.IssuerURL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("GET metadata: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var meta struct {
		DPoP []string `json:"dpop_signing_alg_values_supported"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !slices.Contains(meta.DPoP, "ES256") {
		t.Fatalf("dpop_signing_alg_values_supported = %v, want ES256", meta.DPoP)
	}
}

// TestRevoke_Refuses checks the revocation page refuses a cross-origin
// form post (another site revoking through a visitor's browser) and an
// index no credential has.
func TestRevoke_Refuses(t *testing.T) {
	env := demotest.New(t, nil)
	post := func(origin, idx string) int {
		req, err := http.NewRequest(http.MethodPost, env.IssuerURL+"/status/revoke", strings.NewReader(url.Values{"idx": {idx}}.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := env.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := post("https://attacker.example", "0"); got != http.StatusForbidden {
		t.Errorf("cross-origin revoke: status %d, want 403", got)
	}
	if got := post(env.IssuerURL, "12345"); got != http.StatusBadRequest {
		t.Errorf("revoking an unused index: status %d, want 400", got)
	}
}

// foreignStateApprover approves like HeadlessApprover, then swaps the
// callback's state for one from a flow this wallet never began — a
// callback URL someone else delivered.
type foreignStateApprover struct{ walletapp.HeadlessApprover }

func (a foreignStateApprover) Approve(ctx context.Context, authorizationURL string, session client.SessionHandle) (walletapp.Callback, error) {
	cb, err := a.HeadlessApprover.Approve(ctx, authorizationURL, session)
	if err != nil {
		return cb, err
	}
	q, err := url.ParseQuery(cb.Query)
	if err != nil {
		return cb, err
	}
	q.Set("state", "a-flow-this-wallet-never-began")
	cb.Query = q.Encode()
	return cb, nil
}

// TestReceive_RefusesCallbackForAnotherFlow checks a wallet process
// refuses a callback for a flow it didn't begin even when it carries the
// process's own session handle: its session store holds only its own
// flow, which is what binds a loopback or headless flow to it.
func TestReceive_RefusesCallbackForAnotherFlow(t *testing.T) {
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransaction(context.Background(), demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	approver := foreignStateApprover{walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}}
	if received, err := walletapp.Receive(context.Background(), env.WalletConfig(), offer.URI, approver); err == nil {
		t.Fatalf("Receive completed with another flow's callback (%d credentials)", len(received))
	}
}
