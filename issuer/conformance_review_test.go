package issuer_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// One key proved twice in a batch is refused: each key binds at most
// one Credential (OpenID4VCI §8.3).
func TestRequestCredential_RefusesOneKeyTwice(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key, nonce := testP256Key(t), f.issueNonce(t)
	proof := buildJWTProof(t, key, testIssuer, nonce)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof, buildJWTProof(t, key, testIssuer, nonce)}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidProof)

	f = newCredentialEndpointFixture(t)
	attested := testP256Key(t)
	_, err = f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {buildAttestation(t, f.attestationSigner, f.issueNonce(t), &attested.PublicKey, &attested.PublicKey)}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

// A key attestation's x5c must not carry the trust anchor (HAIP 1.0
// §4.5.1), and its certificates are checked at the verification time.
func TestX5CAttestationVerifier_AnchorAndTime(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, leafKey := testcert.Leaf(t, "test-leaf", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	v := issuer.X5CAttestationVerifier{Roots: roots}
	if _, _, err := v.ResolveAttestationKey(context.Background(), x5cKeyAttestation(t, leafKey, leaf, ca)); err == nil {
		t.Error("accepted an x5c carrying its trust anchor")
	}
	later := certchain.WithTime(context.Background(), leaf.NotAfter.Add(time.Hour))
	if _, _, err := v.ResolveAttestationKey(later, x5cKeyAttestation(t, leafKey, leaf)); err == nil {
		t.Error("accepted a certificate expired at the verification time")
	}
}

// Under AssuranceProduction the SD-JWT VC signer must have a certificate
// (HAIP 1.0 §6.1.1); the issuer can't advertise a jwt proof algorithm it
// can't verify.
func TestNew_RefusesWhatTheIssuerCantDo(t *testing.T) {
	cfg, deps := productionAssuredConfigAndDeps(t)
	deps.SDJWTSigner.IssuerCertificate = nil
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "issuer_certificate") {
		t.Errorf("production without a signer certificate: %v", err)
	}
	cfg, deps = validConfig(t), validDependencies(t)
	cc := cfg.CredentialConfigurationsSupported["IdentityCredential"]
	cc.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256", "RS256"}}}
	cfg.CredentialConfigurationsSupported["IdentityCredential"] = cc
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "RS256") {
		t.Errorf("advertising RS256: %v", err)
	}
}

// A token that doesn't authorize the configuration is answered 403
// insufficient_scope, with a WWW-Authenticate challenge (OpenID4VCI
// §8.3.1.1, RFC 6750 §3.1).
func TestRequestCredential_InsufficientScopeResponse(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"other"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID, SDJWTClaims: testSDJWTClaims(),
	})
	rec := httptest.NewRecorder()
	issuer.WriteError(rec, err)
	if got := rec.Header().Values("WWW-Authenticate"); rec.Code != http.StatusForbidden || len(got) != 2 ||
		got[0] != `DPoP error="insufficient_scope"` || got[1] != `Bearer error="insufficient_scope"` {
		t.Errorf("status %d, WWW-Authenticate %v; want 403 with an insufficient_scope challenge", rec.Code, rec.Header().Values("WWW-Authenticate"))
	}
}

// A notification_id is issued only when the Notification Endpoint is
// published: without it the Wallet has nowhere to use one.
func TestRequestCredential_NotificationIDOnlyWithTheEndpoint(t *testing.T) {
	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.Notifications = newFakeNotificationStore()
	})
	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.NotificationID != "" {
		t.Errorf("notification_id %q issued without a Notification Endpoint", resp.NotificationID)
	}
}
