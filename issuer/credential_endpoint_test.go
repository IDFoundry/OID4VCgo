package issuer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

const (
	testSDJWTConfigID = "IdentityCredential"
	testMdocConfigID  = "MobileDrivingLicence"
)

func testP256Key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// fixedAttestationVerifier resolves every Key Attestation to the same
// fixed trust key, as a real deployment's AttestationVerifier would for
// a single known attestation provider.
type fixedAttestationVerifier struct {
	pub crypto.PublicKey
	alg jose.Alg
}

func (v fixedAttestationVerifier) ResolveAttestationKey(context.Context, attestation.KeyAttestation) (crypto.PublicKey, jose.Alg, error) {
	return v.pub, v.alg, nil
}

// fixedProofBindingKeyResolver resolves every jwt-type proof's kid/x5c
// header to one fixed key (or fails with err, when set), as a real
// deployment's ProofBindingKeyResolver would for a single trusted key
// identifier or certificate — it never inspects header itself, since
// what it returns is exactly what the test wants to happen next.
type fixedProofBindingKeyResolver struct {
	pub crypto.PublicKey
	err error
}

func (r fixedProofBindingKeyResolver) ResolveProofBindingKey(context.Context, map[string]any) (crypto.PublicKey, jose.Alg, error) {
	if r.err != nil {
		return nil, "", r.err
	}
	return r.pub, jose.ES256, nil
}

// credentialEndpointFixture is a fully configured Issuer supporting
// both credential formats over both proof types, plus everything
// needed to build valid requests against it.
type credentialEndpointFixture struct {
	iss *issuer.Issuer

	sdjwtSigner       *issuer.SDJWTSigner
	mdocSigner        *issuer.MdocSigner
	attestationSigner *ecdsa.PrivateKey // the attestation provider's own key

	nonces *fakeNonceStore
	now    time.Time
}

// newCredentialEndpointFixture builds a fully configured Issuer.
// mutate, if given, can adjust Config and/or Dependencies before New is
// called — e.g. to override the default BatchCredentialIssuance
// (BatchSize 2, high enough for every existing multi-proof test in this
// file) or to replace a Dependencies field.
func newCredentialEndpointFixture(t testing.TB, mutate ...func(cfg *issuer.Config, deps *issuer.Dependencies)) credentialEndpointFixture {
	t.Helper()
	f, err := tryCredentialEndpointFixture(t, mutate...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

// tryCredentialEndpointFixture is newCredentialEndpointFixture,
// returning New's error.
func tryCredentialEndpointFixture(t testing.TB, mutate ...func(cfg *issuer.Config, deps *issuer.Dependencies)) (credentialEndpointFixture, error) {
	t.Helper()
	sdjwtSigner := testSDJWTSigner(t)
	mdocSigner := testMdocSigner(t)
	attestationSigner := testP256Key(t)
	nonces := newFakeNonceStore()
	now := time.Now()

	cfg := issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		Issuer:    mustIssuerURL(t, testIssuer),
		Endpoints: issuer.Endpoints{
			Credential: mustEndpointURL(t, testCredentialEndpoint),
			Nonce:      mustEndpointURL(t, testNonceEndpoint),
		},
		Limits:                  issuer.Limits{NonceLifetime: time.Minute},
		BatchCredentialIssuance: &oid4vci.BatchCredentialIssuance{BatchSize: 2},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			testSDJWTConfigID: {
				Format:                               sdjwtvc.CredentialFormat,
				Scope:                                "identity_credential",
				VCT:                                  "https://credentials.example.com/identity_credential",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT:         {ProofSigningAlgValuesSupported: []string{"ES256"}},
					oid4vci.ProofTypeAttestation: {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
			testMdocConfigID: {
				Format:                                  mdoc.CredentialFormat,
				DocType:                                 "org.iso.18013.5.1.mDL",
				CryptographicBindingMethodsSupported:    []string{"cose_key"},
				CredentialSigningAlgValuesSupportedCOSE: []cose.Alg{cose.ES256},
				ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
		},
	}
	deps := issuer.Dependencies{
		Nonces:      nonces,
		Clock:       fixedClock{now: now},
		Random:      rand.Reader,
		SDJWTSigner: sdjwtSigner,
		MdocSigner:  mdocSigner,
		AttestationVerifier: fixedAttestationVerifier{
			pub: &attestationSigner.PublicKey, alg: jose.ES256,
		},
	}
	for _, m := range mutate {
		m(&cfg, &deps)
	}

	iss, err := issuer.New(cfg, deps)
	return credentialEndpointFixture{
		iss: iss, sdjwtSigner: sdjwtSigner, mdocSigner: mdocSigner,
		attestationSigner: attestationSigner, nonces: nonces, now: now,
	}, err
}

func (f credentialEndpointFixture) issueNonce(t *testing.T) string {
	t.Helper()
	if err := f.nonces.Issue(context.Background(), issuer.NonceIssuance{
		Owner: testIssuer, Nonce: "test-nonce", ExpiresAt: f.now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue nonce: %v", err)
	}
	return "test-nonce"
}

// jwkJSON returns pub's public JWK as JSON.
func jwkJSON(t testing.TB, pub crypto.PublicKey) json.RawMessage {
	t.Helper()
	k, err := jwk.Marshal(pub)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return raw
}

func buildJWTProof(t *testing.T, key *ecdsa.PrivateKey, aud, nonce string) string {
	t.Helper()
	var jwkObj map[string]any
	if err := json.Unmarshal(jwkJSON(t, &key.PublicKey), &jwkObj); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	header := map[string]any{"typ": "openid4vci-proof+jwt", "jwk": jwkObj}
	body := map[string]any{"aud": aud, "iat": time.Now().Unix()}
	if nonce != "" {
		body["nonce"] = nonce
	}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	compact, err := jose.Sign(jose.ES256, key, header, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

func buildAttestation(t *testing.T, signer *ecdsa.PrivateKey, nonce string, attestedKeys ...crypto.PublicKey) string {
	t.Helper()
	raws := make([]json.RawMessage, len(attestedKeys))
	for i, pub := range attestedKeys {
		raws[i] = jwkJSON(t, pub)
	}
	compact, err := attestation.Issue(signer, jose.ES256, attestation.Header{}, attestation.Claims{
		IssuedAt: time.Now().Unix(), AttestedKeys: raws, Nonce: nonce,
	})
	if err != nil {
		t.Fatalf("attestation.Issue: %v", err)
	}
	return compact
}

func testSDJWTClaims() *sdjwtvc.Claims {
	return &sdjwtvc.Claims{VCT: "https://credentials.example.com/identity_credential"}
}

func testMdocClaims(t *testing.T) *mdoc.Claims {
	t.Helper()
	signed := time.Now()
	return &mdoc.Claims{
		DocType:    "org.iso.18013.5.1.mDL",
		NameSpaces: map[string]map[string]interface{}{"org.iso.18013.5.1": {"family_name": "Doe"}},
		// Comfortably inside testMdocSigner's own X5Chain leaf
		// certificate NotAfter (now + 24h, from testcert.SelfSigned) —
		// mdoc.Issue now rejects a ValidUntil past the leaf
		// certificate's own NotAfter (§12.3.4).
		Signed: signed, ValidFrom: signed, ValidUntil: signed.Add(time.Hour),
	}
}

// requestOneSDJWTCredential drives one successful "dc+sd-jwt"
// credential request through f — a fresh wallet key, nonce, and
// jwt-type proof — asserting exactly one credential comes back, and
// returns it.
func requestOneSDJWTCredential(t *testing.T, f credentialEndpointFixture) string {
	t.Helper()
	walletKey := testP256Key(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, walletKey, testIssuer, nonce)

	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(resp.Credentials))
	}
	return resp.Credentials[0].Credential
}

func TestRequestCredential_SDJWT_JWTProof(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	credential := requestOneSDJWTCredential(t, f)

	_, _, err := sdjwtvc.Verify(credential, &f.sdjwtSigner.Signer.(*ecdsa.PrivateKey).PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: sdjwtvc.KeyBindingNotRequired,
	})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
}

func TestRequestCredential_SDJWT_IssuerCertificate(t *testing.T) {
	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		key := deps.SDJWTSigner.Signer.(*ecdsa.PrivateKey)
		deps.SDJWTSigner.IssuerCertificate = testcert.SelfSigned(t, "test-issuer", &key.PublicKey, key)
	})
	credential := requestOneSDJWTCredential(t, f)
	testcert.AssertSingleX5CHeader(t, credential)
}

func TestRequestCredential_SDJWT_Batch(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key1, key2 := testP256Key(t), testP256Key(t)
	nonce := f.issueNonce(t)
	proof1 := buildJWTProof(t, key1, testIssuer, nonce)
	proof2 := buildJWTProof(t, key2, testIssuer, nonce)

	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof1, proof2}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(resp.Credentials) != 2 {
		t.Fatalf("got %d credentials, want 2", len(resp.Credentials))
	}
	if resp.Credentials[0].Credential == resp.Credentials[1].Credential {
		t.Errorf("both batch credentials are identical")
	}
}

// TestRequestCredential_BatchSize table-drives checkBatchSize's own
// cap on the jwt proofs array's own size against every boundary that
// matters: unconfigured caps at exactly 1 (not 0, and not unlimited —
// §12.2.4's own "the presence of this parameter means the issuer
// supports more than one key proof" read as implying absence means it
// doesn't), and a configured BatchSize caps at exactly that.
func TestRequestCredential_BatchSize(t *testing.T) {
	cases := map[string]struct {
		batchSize int // 0 means Config.BatchCredentialIssuance stays nil
		numProofs int
		wantErr   bool
	}{
		"single proof, unconfigured":       {batchSize: 0, numProofs: 1, wantErr: false},
		"two proofs, unconfigured":         {batchSize: 0, numProofs: 2, wantErr: true},
		"two proofs, configured for two":   {batchSize: 2, numProofs: 2, wantErr: false},
		"three proofs, configured for two": {batchSize: 2, numProofs: 3, wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
				if tc.batchSize == 0 {
					cfg.BatchCredentialIssuance = nil
				} else {
					cfg.BatchCredentialIssuance = &oid4vci.BatchCredentialIssuance{BatchSize: tc.batchSize}
				}
			})
			nonce := f.issueNonce(t)
			proofs := make([]string, tc.numProofs)
			for i := range proofs {
				proofs[i] = buildJWTProof(t, testP256Key(t), testIssuer, nonce)
			}

			resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: proofs},
				SDJWTClaims:               testSDJWTClaims(),
			})
			if tc.wantErr {
				assertIssuerError(t, err, issuer.ErrorInvalidProof)
				return
			}
			if err != nil {
				t.Fatalf("RequestCredential: %v", err)
			}
			if len(resp.Credentials) != tc.numProofs {
				t.Fatalf("got %d credentials, want %d", len(resp.Credentials), tc.numProofs)
			}
		})
	}
}

// grantingConfiguration is an AuthorizedRequest whose access token grants
// configID through an "openid_credential" authorization detail — how a
// configuration without a scope is authorized.
func grantingConfiguration(configID string) issuer.AuthorizedRequest {
	return issuer.AuthorizedRequest{
		ClientIdentity: issuer.KnownClientID("test-client"),
		AuthorizationDetails: []oid4vci.AuthorizationDetail{{
			Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: configID,
		}},
	}
}

func TestRequestCredential_Mdoc_JWTProof(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	walletKey := testP256Key(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, walletKey, testIssuer, nonce)
	claims := testMdocClaims(t)

	resp, err := f.iss.RequestCredential(context.Background(), grantingConfiguration(testMdocConfigID), issuer.CredentialRequest{
		CredentialConfigurationID: testMdocConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		MdocClaims:                claims,
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(resp.Credentials))
	}

	wire, err := base64.RawURLEncoding.DecodeString(resp.Credentials[0].Credential)
	if err != nil {
		t.Fatalf("decode base64url: %v", err)
	}
	signed, err := mdoc.UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}
	// claims.ValidFrom, not f.now: both are real time.Now() captures a
	// few statements apart, and claims.ValidUntil is only claims.ValidFrom
	// + 1h (shrunk from 24h to fit inside testMdocSigner's own leaf
	// certificate NotAfter, per mdoc.Issue's new validity-vs-cert
	// check) — comparing against the independently-captured f.now left
	// only microseconds of margin, an intermittent race.
	verified, err := mdoc.Verify(signed, "org.iso.18013.5.1.mDL", &f.mdocSigner.Signer.(*ecdsa.PrivateKey).PublicKey, cose.ES256, mdoc.VerifyOptions{
		Now: func() time.Time { return claims.ValidFrom.Add(30 * time.Minute) },
	})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	devicePub, ok := verified.DeviceKey.(*ecdsa.PublicKey)
	if !ok || !devicePub.Equal(&walletKey.PublicKey) {
		t.Errorf("DeviceKey = %v, want %v", verified.DeviceKey, &walletKey.PublicKey)
	}
}

// TestRequestCredential_AttestationProof uses the fixture's own
// default BatchCredentialIssuance (BatchSize 2 — see
// newCredentialEndpointFixture's own doc comment), which is exactly
// large enough for this attestation's own two attested_keys: an
// attestation proof's own fan-out is a real batch issuance request
// (CredentialRequest.Proofs' own doc comment: "a multi-key attestation"
// is what "makes ... a batch issuance request"), so it's bound by the
// identical batch_size ceiling checkBatchSize enforces for a
// multi-entry proofs array — see
// TestRequestCredential_RejectsWhenAttestedKeysExceedBatchSize for the
// case where it doesn't fit.
func TestRequestCredential_AttestationProof(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key1, key2 := testP256Key(t), testP256Key(t)
	nonce := f.issueNonce(t)
	att := buildAttestation(t, f.attestationSigner, nonce, &key1.PublicKey, &key2.PublicKey)

	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(resp.Credentials) != 2 {
		t.Fatalf("got %d credentials, want 2 (one per attested key)", len(resp.Credentials))
	}
}

// TestRequestCredential_RejectsWhenAttestedKeysExceedBatchSize is the
// regression test for a real signing-operation amplification a
// repo-wide security review found: checkBatchSize's own cap on the
// proofs array's own size (one attestation JWT here) never bounded how
// many Credentials that one attestation's own attested_keys could fan
// out to — a single (comfortably under jose.MaxCompactBytes)
// attestation could pack in enough small JWKs to force far more real
// signing operations than batch_size ever allowed through the
// multi-proof path. resolveAttestationProofKeys now caps the running
// resolved-key total at the identical batch_size ceiling.
func TestRequestCredential_RejectsWhenAttestedKeysExceedBatchSize(t *testing.T) {
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
		// nil caps the effective batch_size at exactly 1 (see
		// TestRequestCredential_BatchSize) — the fixture's own default
		// BatchSize of 2 is exactly what TestRequestCredential_AttestationProof
		// needs to succeed, so this test overrides it down to 1 to put
		// this attestation's own two attested_keys over the limit.
		cfg.BatchCredentialIssuance = nil
	})
	key1, key2 := testP256Key(t), testP256Key(t)
	nonce := f.issueNonce(t)
	att := buildAttestation(t, f.attestationSigner, nonce, &key1.PublicKey, &key2.PublicKey)

	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsUnknownConfig(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client")}, issuer.CredentialRequest{
		CredentialConfigurationID: "NoSuchConfig",
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorUnknownCredentialConfig)
}

func TestRequestCredential_RejectsMissingConfigID(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client")}, issuer.CredentialRequest{})
	assertIssuerError(t, err, issuer.ErrorInvalidCredentialRequest)
}

// TestRequestCredential_CredentialIdentifier table-drives §8.2's own
// alternative credential_identifier path: resolved against
// AuthorizedRequest.AuthorizationDetails rather than
// CredentialConfigurationID/Scopes. The success case's own Scopes is
// deliberately left empty (would fail the credential_configuration_id
// path, per TestRequestCredential_RejectsMissingScope) to prove this
// path never consults it; setConfigID additionally covers §8.2's own
// mutual-exclusivity MUST.
func TestRequestCredential_CredentialIdentifier(t *testing.T) {
	const identifier = "CivilEngineeringDegree-2023"
	cases := map[string]struct {
		auth        issuer.AuthorizedRequest
		setConfigID bool
		wantErr     issuer.ErrorCode // "" means success
	}{
		"resolves and succeeds, ignoring scope": {
			auth: issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), AuthorizationDetails: []oid4vci.AuthorizationDetail{
				{Type: "openid_credential", CredentialConfigurationID: testSDJWTConfigID, CredentialIdentifiers: []string{identifier}},
			}},
		},
		"no authorization_details at all": {
			auth:    issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client")},
			wantErr: issuer.ErrorUnknownCredentialIdentifier,
		},
		"non-matching identifier": {
			auth: issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), AuthorizationDetails: []oid4vci.AuthorizationDetail{
				{Type: "openid_credential", CredentialConfigurationID: testSDJWTConfigID, CredentialIdentifiers: []string{"SomeOtherIdentifier"}},
			}},
			wantErr: issuer.ErrorUnknownCredentialIdentifier,
		},
		"matching identifier under the wrong type": {
			auth: issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), AuthorizationDetails: []oid4vci.AuthorizationDetail{
				{Type: "not_openid_credential", CredentialConfigurationID: testSDJWTConfigID, CredentialIdentifiers: []string{identifier}},
			}},
			wantErr: issuer.ErrorUnknownCredentialIdentifier,
		},
		"authorized config isn't supported by this issuer": {
			auth: issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), AuthorizationDetails: []oid4vci.AuthorizationDetail{
				{Type: "openid_credential", CredentialConfigurationID: "NoSuchConfig", CredentialIdentifiers: []string{identifier}},
			}},
			wantErr: issuer.ErrorUnknownCredentialConfig,
		},
		"locations include this issuer": {
			auth: issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), AuthorizationDetails: []oid4vci.AuthorizationDetail{
				{Type: "openid_credential", CredentialConfigurationID: testSDJWTConfigID, CredentialIdentifiers: []string{identifier}, Locations: []string{"https://elsewhere.example.com", testIssuer}},
			}},
		},
		// §5.1.1: a detail for another location grants nothing here.
		"locations name only another issuer": {
			auth: issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), AuthorizationDetails: []oid4vci.AuthorizationDetail{
				{Type: "openid_credential", CredentialConfigurationID: testSDJWTConfigID, CredentialIdentifiers: []string{identifier}, Locations: []string{"https://elsewhere.example.com"}},
			}},
			wantErr: issuer.ErrorUnknownCredentialIdentifier,
		},
		"credential_configuration_id also present": {
			auth: issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), AuthorizationDetails: []oid4vci.AuthorizationDetail{
				{Type: "openid_credential", CredentialConfigurationID: testSDJWTConfigID, CredentialIdentifiers: []string{identifier}},
			}},
			setConfigID: true,
			wantErr:     issuer.ErrorInvalidCredentialRequest,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t)
			nonce := f.issueNonce(t)
			proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)

			req := issuer.CredentialRequest{
				CredentialIdentifier: identifier,
				Proofs:               map[string][]string{oid4vci.ProofTypeJWT: {proof}},
				SDJWTClaims:          testSDJWTClaims(),
			}
			if tc.setConfigID {
				req.CredentialConfigurationID = testSDJWTConfigID
			}

			resp, err := f.iss.RequestCredential(context.Background(), tc.auth, req)
			if tc.wantErr != "" {
				assertIssuerError(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("RequestCredential: %v", err)
			}
			if len(resp.Credentials) != 1 {
				t.Fatalf("got %d credentials, want 1", len(resp.Credentials))
			}
		})
	}
}

func TestRequestCredential_RejectsMissingScope(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"other_scope"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInsufficientScope)
}

// TestRequestCredential_CredentialConfigurationIDAuthorization checks a
// credential_configuration_id is issued only when the access token grants
// it — by the configuration's scope or an authorization detail naming it
// — and never by default for a configuration without a scope
// (testMdocConfigID), which a token granted for another credential must
// not reach. A token whose authorization detail carries
// credential_identifiers must use one of those instead (§8.2).
func TestRequestCredential_CredentialConfigurationIDAuthorization(t *testing.T) {
	detail := func(configID string, identifiers ...string) oid4vci.AuthorizationDetail {
		return oid4vci.AuthorizationDetail{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: configID, CredentialIdentifiers: identifiers}
	}
	located := func(d oid4vci.AuthorizationDetail, locations ...string) oid4vci.AuthorizationDetail {
		d.Locations = locations
		return d
	}
	for name, tc := range map[string]struct {
		configID string
		auth     issuer.AuthorizedRequest
		wantErr  issuer.ErrorCode
	}{
		"scoped, scope granted":                      {testSDJWTConfigID, issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, ""},
		"scoped, other scope":                        {testSDJWTConfigID, issuer.AuthorizedRequest{Scopes: []string{"other_scope"}}, issuer.ErrorInsufficientScope},
		"scoped, granted by detail":                  {testSDJWTConfigID, issuer.AuthorizedRequest{AuthorizationDetails: []oid4vci.AuthorizationDetail{detail(testSDJWTConfigID)}}, ""},
		"scope-less, granted by detail":              {testMdocConfigID, issuer.AuthorizedRequest{AuthorizationDetails: []oid4vci.AuthorizationDetail{detail(testMdocConfigID)}}, ""},
		"scope-less, token for another scope":        {testMdocConfigID, issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.ErrorInsufficientScope},
		"scope-less, token for another detail":       {testMdocConfigID, issuer.AuthorizedRequest{AuthorizationDetails: []oid4vci.AuthorizationDetail{detail(testSDJWTConfigID)}}, issuer.ErrorInsufficientScope},
		"scope-less, no grant at all":                {testMdocConfigID, issuer.AuthorizedRequest{}, issuer.ErrorInsufficientScope},
		"granted through credential_identifiers":     {testMdocConfigID, issuer.AuthorizedRequest{AuthorizationDetails: []oid4vci.AuthorizationDetail{detail(testMdocConfigID, "mdl-1")}}, issuer.ErrorInvalidCredentialRequest},
		"scope granted, but identifiers were issued": {testSDJWTConfigID, issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}, AuthorizationDetails: []oid4vci.AuthorizationDetail{detail(testSDJWTConfigID, "pid-1")}}, issuer.ErrorInvalidCredentialRequest},
		"detail located at this issuer":              {testMdocConfigID, issuer.AuthorizedRequest{AuthorizationDetails: []oid4vci.AuthorizationDetail{located(detail(testMdocConfigID), testIssuer)}}, ""},
		"detail located elsewhere":                   {testMdocConfigID, issuer.AuthorizedRequest{AuthorizationDetails: []oid4vci.AuthorizationDetail{located(detail(testMdocConfigID), "https://elsewhere.example.com")}}, issuer.ErrorInsufficientScope},
		// Identifiers issued for another location don't bar this one's scope.
		"scope granted, identifiers for elsewhere": {testSDJWTConfigID, issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}, AuthorizationDetails: []oid4vci.AuthorizationDetail{located(detail(testSDJWTConfigID, "pid-1"), "https://elsewhere.example.com")}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t)
			proof := buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))
			tc.auth.ClientIdentity = issuer.KnownClientID("test-client")
			req := issuer.CredentialRequest{
				CredentialConfigurationID: tc.configID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
			}
			if tc.configID == testMdocConfigID {
				req.MdocClaims = testMdocClaims(t)
			} else {
				req.SDJWTClaims = testSDJWTClaims()
			}
			_, err := f.iss.RequestCredential(context.Background(), tc.auth, req)
			if tc.wantErr != "" {
				assertIssuerError(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("RequestCredential: %v", err)
			}
		})
	}
}

func TestRequestCredential_RejectsWrongNumberOfProofTypes(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)

	t.Run("zero proof types", func(t *testing.T) {
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			SDJWTClaims:               testSDJWTClaims(),
		})
		assertIssuerError(t, err, issuer.ErrorInvalidProof)
	})

	t.Run("two proof types", func(t *testing.T) {
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs: map[string][]string{
				oid4vci.ProofTypeJWT:         {proof},
				oid4vci.ProofTypeAttestation: {proof},
			},
			SDJWTClaims: testSDJWTClaims(),
		})
		assertIssuerError(t, err, issuer.ErrorInvalidCredentialRequest)
	})

	t.Run("empty proof array", func(t *testing.T) {
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {}},
			SDJWTClaims:               testSDJWTClaims(),
		})
		assertIssuerError(t, err, issuer.ErrorInvalidCredentialRequest)
	})
}

func TestRequestCredential_RejectsUnsupportedProofType(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := requestSDJWTWithProof(f, "di_vp", "whatever")
	assertIssuerError(t, err, issuer.ErrorInvalidCredentialRequest)
}

func TestRequestCredential_RejectsWrongAud(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), "https://wrong-issuer.example.com", nonce)
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsMissingNonce(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, "")
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsUnknownNonce(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, "never-issued")
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
}

func TestRequestCredential_RejectsReusedNonce(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof1 := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof1}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	if err != nil {
		t.Fatalf("first RequestCredential: %v", err)
	}

	proof2 := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	_, err = f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof2}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
}

func TestRequestCredential_RejectsMismatchedNonceAcrossBatch(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	if err := f.nonces.Issue(context.Background(), issuer.NonceIssuance{Owner: testIssuer, Nonce: "other-nonce", ExpiresAt: f.now.Add(time.Minute)}); err != nil {
		t.Fatalf("Issue nonce: %v", err)
	}
	proof1 := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	proof2 := buildJWTProof(t, testP256Key(t), testIssuer, "other-nonce")

	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof1, proof2}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
}

func TestRequestCredential_RejectsWrongTyp(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key := testP256Key(t)
	k, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	rawJWK, _ := json.Marshal(k)
	var jwkObj map[string]any
	_ = json.Unmarshal(rawJWK, &jwkObj)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "wrong+typ", "jwk": jwkObj}, []byte(`{"aud":"`+testIssuer+`","iat":1}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, compact)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsKidHeader(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key := testP256Key(t)
	nonce := f.issueNonce(t)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "openid4vci-proof+jwt", "kid": "some-kid"},
		[]byte(`{"aud":"`+testIssuer+`","iat":1,"nonce":"`+nonce+`"}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, compact)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_JWTProof_KidResolved(t *testing.T) {
	bindingKey := testP256Key(t)
	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, d *issuer.Dependencies) {
		d.ProofBindingKeys = fixedProofBindingKeyResolver{pub: &bindingKey.PublicKey}
	})
	nonce := f.issueNonce(t)
	proof, err := jose.Sign(jose.ES256, bindingKey, map[string]any{"typ": "openid4vci-proof+jwt", "kid": "did:example:wallet#key-1"},
		[]byte(`{"aud":"`+testIssuer+`","iat":1,"nonce":"`+nonce+`"}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	resp, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(resp.Credentials))
	}
}

// TestRequestCredential_ResolverErrorStaysInternal: a proof-key
// resolver's own error — certificate subjects, a DID method's upstream
// message — is the error's cause, never the Wallet-facing
// error_description.
func TestRequestCredential_ResolverErrorStaysInternal(t *testing.T) {
	bindingKey := testP256Key(t)
	secret := errors.New("CN=internal-ca.corp.example, upstream http://10.0.0.7/did failed")
	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, d *issuer.Dependencies) {
		d.ProofBindingKeys = fixedProofBindingKeyResolver{err: secret}
	})
	nonce := f.issueNonce(t)
	proof, err := jose.Sign(jose.ES256, bindingKey, map[string]any{"typ": "openid4vci-proof+jwt", "kid": "did:example:wallet#key-1"},
		[]byte(`{"aud":"`+testIssuer+`","iat":1,"nonce":"`+nonce+`"}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
	var ierr *issuer.Error
	if errors.As(err, &ierr) && strings.Contains(ierr.PublicDescription(), "internal-ca") {
		t.Errorf("error_description = %q leaks the resolver's error", ierr.PublicDescription())
	}
	if !errors.Is(err, secret) {
		t.Error("the resolver's error isn't kept as the cause")
	}
}

func TestRequestCredential_JWTProof_X5CResolved(t *testing.T) {
	bindingKey := testP256Key(t)
	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, d *issuer.Dependencies) {
		d.ProofBindingKeys = fixedProofBindingKeyResolver{pub: &bindingKey.PublicKey}
	})
	nonce := f.issueNonce(t)
	proof, err := jose.Sign(jose.ES256, bindingKey, map[string]any{"typ": "openid4vci-proof+jwt", "x5c": []string{"AAAA"}},
		[]byte(`{"aud":"`+testIssuer+`","iat":1,"nonce":"`+nonce+`"}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	resp, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(resp.Credentials))
	}
}

func TestRequestCredential_RejectsKidAndX5CTogether(t *testing.T) {
	bindingKey := testP256Key(t)
	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, d *issuer.Dependencies) {
		d.ProofBindingKeys = fixedProofBindingKeyResolver{pub: &bindingKey.PublicKey}
	})
	nonce := f.issueNonce(t)
	proof, err := jose.Sign(jose.ES256, bindingKey, map[string]any{
		"typ": "openid4vci-proof+jwt", "kid": "some-kid", "x5c": []string{"AAAA"},
	}, []byte(`{"aud":"`+testIssuer+`","iat":1,"nonce":"`+nonce+`"}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsKidWhenResolverErrors(t *testing.T) {
	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, d *issuer.Dependencies) {
		d.ProofBindingKeys = fixedProofBindingKeyResolver{err: errors.New("kid is not a recognized key identifier")}
	})
	nonce := f.issueNonce(t)
	proof, err := jose.Sign(jose.ES256, testP256Key(t), map[string]any{"typ": "openid4vci-proof+jwt", "kid": "unknown"},
		[]byte(`{"aud":"`+testIssuer+`","iat":1,"nonce":"`+nonce+`"}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

// tamperJWTSignature flips a character early in proof's signature
// segment, not the last one: a fixed-width R||S signature's final
// base64url character can carry unused padding bits (64 bytes % 3 ==
// 1), so changing only that character can legally decode to the same
// bytes — see internal/jose's own TestVerifyRejectsTampering for the
// same finding.
func tamperJWTSignature(t *testing.T, proof string) string {
	t.Helper()
	lastDot := len(proof) - 1
	for proof[lastDot] != '.' {
		lastDot--
	}
	sig := []rune(proof[lastDot+1:])
	if sig[0] == 'x' {
		sig[0] = 'y'
	} else {
		sig[0] = 'x'
	}
	tampered := proof[:lastDot+1] + string(sig)
	if tampered == proof {
		t.Fatalf("tamper produced identical string")
	}
	return tampered
}

func TestRequestCredential_RejectsTamperedSignature(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, tamperJWTSignature(t, proof))
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsAttestationFromUntrustedSigner(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	untrustedSigner := testP256Key(t)
	walletKey := testP256Key(t)
	nonce := f.issueNonce(t)
	att := buildAttestation(t, untrustedSigner, nonce, &walletKey.PublicKey)

	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeAttestation, att)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

// New refuses a configuration it advertises but could never issue, or
// would issue as something other than it says: Wallets would request
// it and every request would fail, or they'd expect another binding,
// algorithm or a valid signer.
func TestNew_RefusesUnissuableConfiguration(t *testing.T) {
	expired := func(t *testing.T, deps *issuer.Dependencies) {
		ca, caKey := testcert.CA(t, "test issuer CA")
		cert, key := testcert.Leaf(t, "test issuer", ca, caKey)
		deps.SDJWTSigner = &issuer.SDJWTSigner{Signer: key, Alg: jose.ES256, IssuerCertificate: cert}
		deps.Clock = fixedClock{now: cert.NotAfter.Add(time.Hour)}
	}
	for name, mutate := range map[string]func(t *testing.T, cfg *issuer.Config, deps *issuer.Dependencies){
		"no binding method": func(_ *testing.T, cfg *issuer.Config, _ *issuer.Dependencies) {
			c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
			c.CryptographicBindingMethodsSupported = nil
			cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
		},
		"an unknown format": func(_ *testing.T, cfg *issuer.Config, _ *issuer.Dependencies) {
			c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
			c.Format = "some_unknown_format"
			cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
		},
		"jwk binding for an mdoc": func(_ *testing.T, cfg *issuer.Config, _ *issuer.Dependencies) {
			c := cfg.CredentialConfigurationsSupported[testMdocConfigID]
			c.CryptographicBindingMethodsSupported = []string{"jwk"}
			cfg.CredentialConfigurationsSupported[testMdocConfigID] = c
		},
		"cose_key binding for an SD-JWT VC": func(_ *testing.T, cfg *issuer.Config, _ *issuer.Dependencies) {
			c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
			c.CryptographicBindingMethodsSupported = []string{"cose_key"}
			cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
		},
		"an SD-JWT VC alg the signer doesn't use": func(_ *testing.T, cfg *issuer.Config, _ *issuer.Dependencies) {
			c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
			c.CredentialSigningAlgValuesSupported = []string{"ES384"}
			cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
		},
		"an mdoc alg the signer doesn't use": func(_ *testing.T, cfg *issuer.Config, _ *issuer.Dependencies) {
			c := cfg.CredentialConfigurationsSupported[testMdocConfigID]
			c.CredentialSigningAlgValuesSupportedCOSE = []oid4vci.COSEAlg{cose.EdDSA}
			cfg.CredentialConfigurationsSupported[testMdocConfigID] = c
		},
		"an expired signer certificate": func(t *testing.T, _ *issuer.Config, deps *issuer.Dependencies) { expired(t, deps) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tryCredentialEndpointFixture(t, func(cfg *issuer.Config, deps *issuer.Dependencies) { mutate(t, cfg, deps) }); err == nil {
				t.Error("New accepted it")
			}
		})
	}
}

func TestRequestCredential_RejectsX5CHeader(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key := testP256Key(t)
	nonce := f.issueNonce(t)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "openid4vci-proof+jwt", "x5c": []string{"AAAA"}},
		[]byte(`{"aud":"`+testIssuer+`","iat":1,"nonce":"`+nonce+`"}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, compact)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsMissingJWKHeader(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key := testP256Key(t)
	nonce := f.issueNonce(t)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "openid4vci-proof+jwt"},
		[]byte(`{"aud":"`+testIssuer+`","iat":1,"nonce":"`+nonce+`"}`))
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, compact)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsExpiredNonce(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	if err := f.nonces.Issue(context.Background(), issuer.NonceIssuance{
		Owner: testIssuer, Nonce: "expiring-nonce", ExpiresAt: f.now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("Issue nonce: %v", err)
	}
	proof := buildJWTProof(t, testP256Key(t), testIssuer, "expiring-nonce")
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
}

func TestRequestCredential_RejectsEmptyAttestationArray(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeAttestation)
	assertIssuerError(t, err, issuer.ErrorInvalidCredentialRequest)
}

func TestRequestCredential_RejectsAttestationProofTypeWhenUnconfigured(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	att := buildAttestation(t, f.attestationSigner, nonce, &testP256Key(t).PublicKey)
	_, err := f.iss.RequestCredential(context.Background(), grantingConfiguration(testMdocConfigID), issuer.CredentialRequest{
		CredentialConfigurationID: testMdocConfigID, // this config only supports the jwt proof type
		Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att}},
		MdocClaims:                testMdocClaims(t),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidCredentialRequest)
}

func TestRequestCredential_RejectsProofTypeThisPackageDoesNotImplement(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	cfg := issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		Issuer:    mustIssuerURL(t, testIssuer),
		Endpoints: issuer.Endpoints{
			Credential: mustEndpointURL(t, testCredentialEndpoint),
			Nonce:      mustEndpointURL(t, testNonceEndpoint),
		},
		Limits: issuer.Limits{NonceLifetime: time.Minute},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"DIVPCredential": {
				Format: sdjwtvc.CredentialFormat, VCT: "https://credentials.example.com/identity_credential",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
					"di_vp": {ProofSigningAlgValuesSupported: []string{"eddsa-2022"}},
				},
			},
		},
	}
	deps := issuer.Dependencies{
		Nonces: f.nonces, Clock: fixedClock{now: f.now}, Random: rand.Reader, SDJWTSigner: f.sdjwtSigner,
	}
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = iss.RequestCredential(context.Background(), grantingConfiguration("DIVPCredential"), issuer.CredentialRequest{
		CredentialConfigurationID: "DIVPCredential",
		Proofs:                    map[string][]string{"di_vp": {"whatever"}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsMissingClaimsForFormat(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
	})
	if err == nil {
		t.Errorf("RequestCredential accepted a request with no SDJWTClaims")
	}
}

// requestSDJWTWithProof issues a Credential Request against
// testSDJWTConfigID carrying a single proof value under proofType —
// the shared shape every "malformed proof" test below builds on, only
// varying in how proof itself was constructed.
func requestSDJWTWithProof(f credentialEndpointFixture, proofType string, proofs ...string) (oid4vci.CredentialResponse, error) {
	return f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{proofType: proofs},
		SDJWTClaims:               testSDJWTClaims(),
	})
}

func assertIssuerError(t *testing.T, err error, code issuer.ErrorCode) {
	t.Helper()
	var ierr *issuer.Error
	if !errors.As(err, &ierr) {
		t.Fatalf("error = %v, want *issuer.Error with code %q", err, code)
	}
	if ierr.Code() != code {
		t.Errorf("Code = %q, want %q", ierr.Code(), code)
	}
}

// TestRequestCredential_AttestationAlgMustBeAdvertised checks a Key
// Attestation's alg must be one of the attestation proof type's
// proof_signing_alg_values_supported (OID4VCI 1.0 Appendix F.3), even
// when its signing key is trusted: an EdDSA attestation is refused
// while only ES256 is advertised, and accepted once EdDSA is too.
func TestRequestCredential_AttestationAlgMustBeAdvertised(t *testing.T) {
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	trustEd25519 := func(algs ...string) func(*issuer.Config, *issuer.Dependencies) {
		return func(cfg *issuer.Config, deps *issuer.Dependencies) {
			deps.AttestationVerifier = fixedAttestationVerifier{pub: edPub, alg: jose.EdDSA}
			cc := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
			cc.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{
				oid4vci.ProofTypeAttestation: {ProofSigningAlgValuesSupported: algs},
			}
			cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = cc
		}
	}
	edAttestation := func(t *testing.T, f credentialEndpointFixture) string {
		t.Helper()
		walletKey := testP256Key(t)
		compact, err := attestation.Issue(edKey, jose.EdDSA, attestation.Header{}, attestation.Claims{
			IssuedAt: time.Now().Unix(), AttestedKeys: []json.RawMessage{jwkJSON(t, &walletKey.PublicKey)}, Nonce: f.issueNonce(t),
		})
		if err != nil {
			t.Fatalf("attestation.Issue: %v", err)
		}
		return compact
	}

	t.Run("not advertised", func(t *testing.T) {
		f := newCredentialEndpointFixture(t, trustEd25519("ES256"))
		_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeAttestation, edAttestation(t, f))
		assertIssuerError(t, err, issuer.ErrorInvalidProof)
		if err == nil || !strings.Contains(err.Error(), "proof_signing_alg_values_supported") {
			t.Errorf("error = %v, want it to name proof_signing_alg_values_supported", err)
		}
	})
	t.Run("advertised", func(t *testing.T) {
		f := newCredentialEndpointFixture(t, trustEd25519("ES256", "EdDSA"))
		if _, err := requestSDJWTWithProof(f, oid4vci.ProofTypeAttestation, edAttestation(t, f)); err != nil {
			t.Fatalf("RequestCredential: %v", err)
		}
	})
}

// TestRequestCredential_RequiredResponseEncryption checks an issuer
// whose response encryption is Required refuses a request that asks for
// no encrypted response, with invalid_encryption_parameters (§8.3.1.2),
// and issues to one that does.
func TestRequestCredential_RequiredResponseEncryption(t *testing.T) {
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
		cfg.RequestEncryption = &issuer.RequestEncryptionSupport{
			Keys:               []issuer.RequestDecryptionKey{{KeyID: "req-1", PrivateKey: testP256Key(t)}},
			EncValuesSupported: []jwe.Enc{jwe.A128GCM},
		}
		cfg.ResponseEncryption = &issuer.ResponseEncryptionSupport{EncValuesSupported: []jwe.Enc{jwe.A128GCM}, Required: true}
	})
	walletKey := testP256Key(t)
	request := func(encryption *issuer.ResponseEncryptionRequest) error {
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, walletKey, testIssuer, f.issueNonce(t))}},
			SDJWTClaims:               testSDJWTClaims(),
			RequestWasEncrypted:       true,
			ResponseEncryption:        encryption,
		})
		return err
	}
	assertIssuerError(t, request(nil), issuer.ErrorInvalidEncryptionParameters)
	if err := request(&issuer.ResponseEncryptionRequest{JWK: encryptionJWK(t, &testP256Key(t).PublicKey), Enc: jwe.A128GCM}); err != nil {
		t.Fatalf("request with credential_response_encryption: %v", err)
	}
}

// TestRequestCredential_EnforcesKeyAttestationLevels checks a key
// attestation proof must assert one of the key_storage and
// user_authentication levels the configuration's key_attestations_required
// accepts (OID4VCI 1.0 §12.2.4, Appendix D.2) — a lower level, or none,
// is refused.
func TestRequestCredential_EnforcesKeyAttestationLevels(t *testing.T) {
	high := attestation.ISO18045High
	moderate := attestation.ISO18045Moderate
	for name, tc := range map[string]struct {
		keyStorage, userAuth []attestation.AttackPotentialResistance
		wantErr              bool
	}{
		"both accepted":                  {[]attestation.AttackPotentialResistance{high}, []attestation.AttackPotentialResistance{high}, false},
		"one of several asserted levels": {[]attestation.AttackPotentialResistance{moderate, high}, []attestation.AttackPotentialResistance{high}, false},
		"key storage too low":            {[]attestation.AttackPotentialResistance{moderate}, []attestation.AttackPotentialResistance{high}, true},
		"user authentication too low":    {[]attestation.AttackPotentialResistance{high}, []attestation.AttackPotentialResistance{moderate}, true},
		"no key storage asserted":        {nil, []attestation.AttackPotentialResistance{high}, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
				cc := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
				cc.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{
					oid4vci.ProofTypeAttestation: {
						ProofSigningAlgValuesSupported: []string{"ES256"},
						KeyAttestationsRequired: &oid4vci.KeyAttestationRequirement{
							KeyStorage: []string{string(high)}, UserAuthentication: []string{string(high)},
						},
					},
				}
				cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = cc
			})
			att, err := attestation.Issue(f.attestationSigner, jose.ES256, attestation.Header{}, attestation.Claims{
				IssuedAt: time.Now().Unix(), AttestedKeys: []json.RawMessage{jwkJSON(t, &testP256Key(t).PublicKey)},
				Nonce: f.issueNonce(t), KeyStorage: tc.keyStorage, UserAuthentication: tc.userAuth,
			})
			if err != nil {
				t.Fatalf("attestation.Issue: %v", err)
			}
			_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeAttestation, att)
			if tc.wantErr {
				assertIssuerError(t, err, issuer.ErrorInvalidProof)
				return
			}
			if err != nil {
				t.Fatalf("RequestCredential: %v", err)
			}
		})
	}
}

// TestRequestCredential_ProofAgeWithoutNonceEndpoint checks that without
// a Nonce Endpoint a jwt proof is dated by its iat instead: one outside
// Limits.MaxProofAge of Now, in either direction, is refused (OID4VCI
// 1.0 Appendix F.4), so a captured proof can't be replayed indefinitely.
func TestRequestCredential_ProofAgeWithoutNonceEndpoint(t *testing.T) {
	for name, tc := range map[string]struct {
		offset  time.Duration
		iat     int64 // an absolute iat, in place of offset
		wantErr bool
	}{
		"fresh":             {offset: 0},
		"within the age":    {offset: -30 * time.Second},
		"too old":           {offset: -2 * time.Minute, wantErr: true},
		"too far in future": {offset: 2 * time.Minute, wantErr: true},
		// A negated age used to overflow into a pass for these.
		"year 31 million": {iat: 1e15, wantErr: true},
		"int64's maximum": {iat: math.MaxInt64, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
				cfg.Endpoints.Nonce = fapi.URL{}
				cfg.Limits.NonceLifetime = 0
				cfg.Limits.MaxProofAge = time.Minute
				deps.Nonces = nil
			})
			key := testP256Key(t)
			var jwkObj map[string]any
			if err := json.Unmarshal(jwkJSON(t, &key.PublicKey), &jwkObj); err != nil {
				t.Fatal(err)
			}
			iat := f.now.Add(tc.offset).Unix()
			if tc.iat != 0 {
				iat = tc.iat
			}
			payload, err := json.Marshal(map[string]any{"aud": testIssuer, "iat": iat})
			if err != nil {
				t.Fatal(err)
			}
			proof, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "openid4vci-proof+jwt", "jwk": jwkObj}, payload)
			if err != nil {
				t.Fatal(err)
			}
			_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
			if tc.wantErr {
				assertIssuerError(t, err, issuer.ErrorInvalidProof)
				return
			}
			if err != nil {
				t.Fatalf("RequestCredential: %v", err)
			}
		})
	}
}

func TestNew_RequiresMaxProofAgeWithoutNonceEndpoint(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.Nonce = fapi.URL{}
	cfg.Limits.NonceLifetime = 0
	deps := validDependencies(t)
	deps.Nonces = nil
	if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "max_proof_age") {
		t.Fatalf("New without a Nonce Endpoint or max_proof_age: error = %v, want max_proof_age required", err)
	}
}

// TestRequestCredential_CnfJWKHasPublicMembersOnly checks the issued
// credential's cnf.jwk is the proof key's public members only: anything
// else the Wallet put in its jwk header stays out of the credential this
// issuer signs, and a jwk header carrying the private key is refused
// (OID4VCI 1.0 Appendix F.4).
func TestRequestCredential_CnfJWKHasPublicMembersOnly(t *testing.T) {
	key := testP256Key(t)
	proofWithJWK := func(f credentialEndpointFixture, jwkObj map[string]any) string {
		payload, err := json.Marshal(map[string]any{"aud": testIssuer, "iat": time.Now().Unix(), "nonce": f.issueNonce(t)})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "openid4vci-proof+jwt", "jwk": jwkObj}, payload)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	var public map[string]any
	if err := json.Unmarshal(jwkJSON(t, &key.PublicKey), &public); err != nil {
		t.Fatal(err)
	}

	t.Run("extra members are dropped", func(t *testing.T) {
		f := newCredentialEndpointFixture(t)
		withExtras := map[string]any{"kid": "chosen-by-wallet", "x-note": "not the issuer's words"}
		for k, v := range public {
			withExtras[k] = v
		}
		resp, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proofWithJWK(f, withExtras))
		if err != nil {
			t.Fatalf("RequestCredential: %v", err)
		}
		pres, err := sdjwtvc.Parse(resp.Credentials[0].Credential)
		if err != nil {
			t.Fatalf("sdjwtvc.Parse: %v", err)
		}
		_, rawPayload, err := jose.DecodeUnverified(pres.IssuerJWT)
		if err != nil {
			t.Fatalf("DecodeUnverified: %v", err)
		}
		var payload struct {
			CNF struct {
				JWK map[string]any `json:"jwk"`
			} `json:"cnf"`
		}
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.CNF.JWK) != len(public) {
			t.Errorf("cnf.jwk = %v, want only the public members %v", payload.CNF.JWK, public)
		}
		for k, v := range public {
			if payload.CNF.JWK[k] != v {
				t.Errorf("cnf.jwk[%q] = %v, want %v", k, payload.CNF.JWK[k], v)
			}
		}
	})

	t.Run("private key is refused", func(t *testing.T) {
		f := newCredentialEndpointFixture(t)
		private, err := jwk.MarshalPrivate(key)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(private)
		if err != nil {
			t.Fatal(err)
		}
		var withD map[string]any
		if err := json.Unmarshal(raw, &withD); err != nil {
			t.Fatal(err)
		}
		_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proofWithJWK(f, withD))
		assertIssuerError(t, err, issuer.ErrorInvalidProof)
	})
}

// TestRequestCredential_RejectsUnencodableBindingKeys checks a binding
// key cnf.jwk can't carry is refused as invalid_proof: a key type a
// ProofBindingKeys resolver returned that this package can't encode as a
// JWK, and an attested key given as a private JWK.
func TestRequestCredential_RejectsUnencodableBindingKeys(t *testing.T) {
	t.Run("unsupported resolved key type", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		f := newCredentialEndpointFixture(t, func(_ *issuer.Config, d *issuer.Dependencies) {
			d.ProofBindingKeys = fixedProofBindingKeyResolver{pub: &rsaKey.PublicKey}
		})
		payload, err := json.Marshal(map[string]any{"aud": testIssuer, "iat": time.Now().Unix(), "nonce": f.issueNonce(t)})
		if err != nil {
			t.Fatal(err)
		}
		proof, err := jose.Sign(jose.ES256, testP256Key(t), map[string]any{"typ": "openid4vci-proof+jwt", "kid": "did:example:wallet#1"}, payload)
		if err != nil {
			t.Fatal(err)
		}
		_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
		assertIssuerError(t, err, issuer.ErrorInvalidProof)
	})

	t.Run("attested key is a private JWK", func(t *testing.T) {
		f := newCredentialEndpointFixture(t)
		private, err := jwk.MarshalPrivate(testP256Key(t))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(private)
		if err != nil {
			t.Fatal(err)
		}
		att, err := attestation.Issue(f.attestationSigner, jose.ES256, attestation.Header{}, attestation.Claims{
			IssuedAt: time.Now().Unix(), AttestedKeys: []json.RawMessage{raw}, Nonce: f.issueNonce(t),
		})
		if err != nil {
			t.Fatalf("attestation.Issue: %v", err)
		}
		_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeAttestation, att)
		assertIssuerError(t, err, issuer.ErrorInvalidProof)
	})
}

// batchRequest is a two-credential dc+sd-jwt Credential Request (the
// fixture's batch_size is 2), returning it and the two binding keys.
func batchRequest(t *testing.T, f credentialEndpointFixture) (issuer.CredentialRequest, []*ecdsa.PublicKey) {
	t.Helper()
	nonce := f.issueNonce(t)
	keys := []*ecdsa.PrivateKey{testP256Key(t), testP256Key(t)}
	proofs := []string{buildJWTProof(t, keys[0], testIssuer, nonce), buildJWTProof(t, keys[1], testIssuer, nonce)}
	return issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: proofs},
		SDJWTClaims:               testSDJWTClaims(),
	}, []*ecdsa.PublicKey{&keys[0].PublicKey, &keys[1].PublicKey}
}

var batchAuth = issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}

func statusRef(idx int) map[string]any {
	return map[string]any{"status_list": map[string]any{"idx": idx, "uri": "https://issuer.example.com/statuslists/1"}}
}

// TestRequestCredential_PerCredentialStatus checks a batch's Credentials
// can each carry their own status reference (HAIP 1.0 §6.1: a unique
// index per Credential): PerCredential sees each Credential in turn, with
// its binding key and its own copy of the claims.
func TestRequestCredential_PerCredentialStatus(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	req, keys := batchRequest(t, f)
	var seen []int
	req.PerCredential = func(_ context.Context, c *issuer.CredentialInstance) error {
		if c.SDJWTClaims == nil || c.MdocClaims != nil {
			t.Errorf("instance %d: want only SDJWTClaims", c.Index)
		}
		if !keys[c.Index].Equal(c.BindingKey) {
			t.Errorf("instance %d: BindingKey isn't the %d-th proof's key", c.Index, c.Index)
		}
		seen = append(seen, c.Index)
		c.SDJWTClaims.Status = statusRef(100 + c.Index)
		return nil
	}
	resp, err := f.iss.RequestCredential(context.Background(), batchAuth, req)
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if !slices.Equal(seen, []int{0, 1}) {
		t.Errorf("PerCredential saw instances %v, want [0 1]", seen)
	}
	for i, c := range resp.Credentials {
		pres, err := sdjwtvc.Parse(c.Credential)
		if err != nil {
			t.Fatal(err)
		}
		_, raw, err := jose.DecodeUnverified(pres.IssuerJWT)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Status struct {
				StatusList struct {
					Idx int `json:"idx"`
				} `json:"status_list"`
			} `json:"status"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Status.StatusList.Idx != 100+i {
			t.Errorf("credential %d: status idx %d, want %d", i, payload.Status.StatusList.Idx, 100+i)
		}
	}
	if len(req.SDJWTClaims.Status) != 0 {
		t.Error("PerCredential's changes leaked into the request's shared claims")
	}
}

// TestRequestCredential_RefusesSharedStatusInBatch checks a batch whose
// Credentials would carry the same status reference is refused — from
// the shared claims, or a PerCredential that doesn't vary it — while one
// Credential with a status reference, and a hook error, behave as
// expected.
func TestRequestCredential_RefusesSharedStatusInBatch(t *testing.T) {
	t.Run("shared claims", func(t *testing.T) {
		f := newCredentialEndpointFixture(t)
		req, _ := batchRequest(t, f)
		req.SDJWTClaims.Status = statusRef(7)
		if _, err := f.iss.RequestCredential(context.Background(), batchAuth, req); err == nil || !strings.Contains(err.Error(), "same status reference") {
			t.Fatalf("error = %v, want the shared status reference refused", err)
		}
	})
	t.Run("hook that doesn't vary it", func(t *testing.T) {
		f := newCredentialEndpointFixture(t)
		req, _ := batchRequest(t, f)
		req.PerCredential = func(_ context.Context, c *issuer.CredentialInstance) error {
			c.SDJWTClaims.Status = statusRef(7)
			return nil
		}
		if _, err := f.iss.RequestCredential(context.Background(), batchAuth, req); err == nil || !strings.Contains(err.Error(), "same status reference") {
			t.Fatalf("error = %v, want the shared status reference refused", err)
		}
	})
	t.Run("hook error", func(t *testing.T) {
		f := newCredentialEndpointFixture(t)
		req, _ := batchRequest(t, f)
		req.PerCredential = func(context.Context, *issuer.CredentialInstance) error { return errors.New("status list full") }
		if _, err := f.iss.RequestCredential(context.Background(), batchAuth, req); err == nil || !strings.Contains(err.Error(), "status list full") {
			t.Fatalf("error = %v, want the hook's error", err)
		}
	})
	t.Run("one credential with a status reference", func(t *testing.T) {
		f := newCredentialEndpointFixture(t)
		claims := testSDJWTClaims()
		claims.Status = statusRef(7)
		proof := buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))
		if _, err := f.iss.RequestCredential(context.Background(), batchAuth, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID, Proofs: map[string][]string{oid4vci.ProofTypeJWT: {proof}}, SDJWTClaims: claims,
		}); err != nil {
			t.Fatalf("RequestCredential: %v", err)
		}
	})
	t.Run("mdoc shared status", func(t *testing.T) {
		f := newCredentialEndpointFixture(t)
		nonce := f.issueNonce(t)
		claims := testMdocClaims(t)
		claims.Status = &mdoc.StatusListRef{Idx: 7, URI: "https://issuer.example.com/statuslists/1"}
		_, err := f.iss.RequestCredential(context.Background(), grantingConfiguration(testMdocConfigID), issuer.CredentialRequest{
			CredentialConfigurationID: testMdocConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, nonce), buildJWTProof(t, testP256Key(t), testIssuer, nonce)}},
			MdocClaims:                claims,
		})
		if err == nil || !strings.Contains(err.Error(), "same status reference") {
			t.Fatalf("error = %v, want the shared status reference refused", err)
		}
	})
}

// attestationStatusFunc adapts a func to issuer.AttestationStatusChecker.
type attestationStatusFunc func(context.Context, issuer.VerifiedKeyAttestation) error

func (f attestationStatusFunc) CheckAttestationStatus(ctx context.Context, c issuer.VerifiedKeyAttestation) error {
	return f(ctx, c)
}

// TestRequestCredential_AttestationStatus: Dependencies.AttestationStatus
// sees each verified key attestation; a revoked one fails the proof
// (invalid_proof), and one whose status couldn't be determined is a
// server error, not a verdict on the Wallet's keys.
func TestRequestCredential_AttestationStatus(t *testing.T) {
	for name, statusErr := range map[string]error{
		"valid":   nil,
		"revoked": fmt.Errorf("status INVALID: %w", issuer.ErrKeyAttestationRevoked),
		"unknown": errors.New("status list unreachable"),
	} {
		t.Run(name, func(t *testing.T) {
			var checked []issuer.VerifiedKeyAttestation
			f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
				deps.AttestationStatus = attestationStatusFunc(func(_ context.Context, c issuer.VerifiedKeyAttestation) error {
					checked = append(checked, c)
					return statusErr
				})
			})
			key1, key2 := testP256Key(t), testP256Key(t)
			att := buildAttestation(t, f.attestationSigner, f.issueNonce(t), &key1.PublicKey, &key2.PublicKey)

			_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att}},
				SDJWTClaims:               testSDJWTClaims(),
			})
			if len(checked) != 1 || len(checked[0].Claims.AttestedKeys) != 2 {
				t.Fatalf("status checker saw %d attestations, want the one verified attestation", len(checked))
			}
			if !f.attestationSigner.PublicKey.Equal(checked[0].SignerKey) || checked[0].SignerCertificates != nil {
				t.Errorf("status checker saw signer %v and certificates %v, want the attestation's key and no x5c", checked[0].SignerKey, checked[0].SignerCertificates)
			}
			assertAttestationStatusOutcome(t, name, err)
		})
	}
}

// assertAttestationStatusOutcome checks a Credential Request's err for
// a key attestation whose status check had outcome name: "valid" is
// accepted, "revoked" is invalid_proof, and "unknown" is a server
// error (not an *issuer.Error, so WriteError answers 500 server_error).
func assertAttestationStatusOutcome(t *testing.T, name string, err error) {
	t.Helper()
	var ierr *issuer.Error
	switch name {
	case "valid":
		if err != nil {
			t.Errorf("valid attestation: %v", err)
		}
	case "revoked":
		if !errors.As(err, &ierr) || ierr.Code() != issuer.ErrorInvalidProof {
			t.Errorf("revoked attestation: err = %v, want invalid_proof", err)
		}
	default:
		if err == nil || errors.As(err, &ierr) {
			t.Fatalf("status unknown: err = %v, want a server error", err)
		}
		rec := httptest.NewRecorder()
		issuer.WriteError(rec, err)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status unknown: WriteError answered %d, want 500", rec.Code)
		}
	}
}

// The attestation proof type takes exactly one key attestation, which
// attests every key (Appendix F.3).
func TestRequestCredential_RejectsMoreThanOneAttestation(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key1, key2 := testP256Key(t), testP256Key(t)
	nonce := f.issueNonce(t)
	att1 := buildAttestation(t, f.attestationSigner, nonce, &key1.PublicKey)
	att2 := buildAttestation(t, f.attestationSigner, nonce, &key2.PublicKey)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att1, att2}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	var ierr *issuer.Error
	if !errors.As(err, &ierr) || ierr.Code() != issuer.ErrorInvalidProof {
		t.Fatalf("two attestations: %v, want invalid_proof", err)
	}
}

// New refuses key_attestations_required on the jwt proof type, whose
// key_attestation header isn't verified, rather than publishing a
// requirement every request then fails.
func TestNewRefusesKeyAttestationsOnJWTProofType(t *testing.T) {
	cfg := validConfig(t)
	cc := cfg.CredentialConfigurationsSupported["IdentityCredential"]
	cc.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{
		oid4vci.ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"ES256"},
			KeyAttestationsRequired:        &oid4vci.KeyAttestationRequirement{KeyStorage: []string{"iso_18045_moderate"}},
		},
	}
	cfg.CredentialConfigurationsSupported["IdentityCredential"] = cc
	if _, err := issuer.New(cfg, validDependencies(t)); err == nil || !strings.Contains(err.Error(), "key_attestations_required") {
		t.Errorf("New: %v, want key_attestations_required on jwt refused", err)
	}
}

// An issuer whose request encryption is Required refuses a plaintext
// Credential Request, whatever handler passes it to RequestCredential:
// the metadata says encryption_required (§10).
func TestRequestCredential_RequiredRequestEncryption(t *testing.T) {
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
		cfg.RequestEncryption = &issuer.RequestEncryptionSupport{
			Keys:               []issuer.RequestDecryptionKey{{KeyID: "req-1", PrivateKey: testP256Key(t)}},
			EncValuesSupported: []jwe.Enc{jwe.A128GCM}, Required: true,
		}
	})
	request := func(encrypted bool) error {
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
			SDJWTClaims:               testSDJWTClaims(),
			RequestWasEncrypted:       encrypted,
		})
		return err
	}
	assertIssuerError(t, request(false), issuer.ErrorInvalidEncryptionParameters)
	if err := request(true); err != nil {
		t.Errorf("an encrypted request: %v", err)
	}
}

// A replayed attestation, with a nonce this issuer never issued or
// already used, is refused before its status is checked: a status
// check costs a Status List fetch, which a replay mustn't buy.
func TestRequestCredential_AttestationNonceBeforeStatus(t *testing.T) {
	checked := 0
	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.AttestationStatus = attestationStatusFunc(func(context.Context, issuer.VerifiedKeyAttestation) error { checked++; return nil })
	})
	key := testP256Key(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {buildAttestation(t, f.attestationSigner, "never-issued", &key.PublicKey)}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
	if checked != 0 {
		t.Errorf("the status was checked %d times for a replayed attestation, want none", checked)
	}
}

// A jwt proof's iat is an RFC 7519 NumericDate, which may be
// fractional; one out of range is refused.
func TestRequestCredential_ProofIatNumericDate(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key := testP256Key(t)
	proof := func(iat any) string {
		var jwkObj map[string]any
		if err := json.Unmarshal(jwkJSON(t, &key.PublicKey), &jwkObj); err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]any{"aud": testIssuer, "iat": iat, "nonce": f.issueNonce(t)})
		raw, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "openid4vci-proof+jwt", "jwk": jwkObj}, payload)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof(float64(time.Now().UnixMilli())/1000)); err != nil {
		t.Errorf("a fractional iat: %v", err)
	}
	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof(1e300))
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

// A proof whose payload has members differing from aud only in case is
// refused: encoding/json would read the last, an exact-match parser
// "aud".
func TestRequestCredential_ProofRefusesCaseVariantMembers(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key := testP256Key(t)
	var jwkObj map[string]any
	if err := json.Unmarshal(jwkJSON(t, &key.PublicKey), &jwkObj); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"aud":"https://elsewhere.example","AUD":"` + testIssuer + `","iat":` + strconv.FormatInt(time.Now().Unix(), 10) + `,"nonce":"` + f.issueNonce(t) + `"}`)
	proof, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "openid4vci-proof+jwt", "jwk": jwkObj}, payload)
	if err != nil {
		t.Fatal(err)
	}
	_, err = requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}
