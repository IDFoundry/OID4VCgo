package issuer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/attestation"
	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/issuer"
)

const (
	testSDJWTConfigID = "IdentityCredential"
	testMdocConfigID  = "MobileDrivingLicence"
)

func testP256Key(t *testing.T) *ecdsa.PrivateKey {
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

func (r fixedProofBindingKeyResolver) ResolveProofBindingKey(context.Context, map[string]any) (crypto.PublicKey, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.pub, nil
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
func newCredentialEndpointFixture(t *testing.T, mutate ...func(cfg *issuer.Config, deps *issuer.Dependencies)) credentialEndpointFixture {
	t.Helper()
	sdjwtSigner := testSDJWTSigner(t)
	mdocSigner := testMdocSigner(t)
	attestationSigner := testP256Key(t)
	nonces := newFakeNonceStore()
	now := time.Now()

	cfg := issuer.Config{
		Issuer: mustIssuerURL(t, testIssuer),
		Endpoints: issuer.Endpoints{
			Credential: mustEndpointURL(t, testCredentialEndpoint),
			Nonce:      mustEndpointURL(t, testNonceEndpoint),
		},
		Limits:                  issuer.Limits{NonceLifetime: time.Minute},
		BatchCredentialIssuance: &issuer.BatchCredentialIssuance{BatchSize: 2},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			testSDJWTConfigID: {
				Format:                               sdjwtvc.CredentialFormat,
				Scope:                                "identity_credential",
				VCT:                                  "https://credentials.example.com/identity_credential",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT:         {ProofSigningAlgValuesSupported: []string{"ES256"}},
					oid4vci.ProofTypeAttestation: {ProofSigningAlgValuesSupported: []string{"ES256"}},
				},
			},
			testMdocConfigID: {
				Format:                                  mdoc.CredentialFormat,
				DocType:                                 "org.iso.18013.5.1.mDL",
				CryptographicBindingMethodsSupported:    []string{"cose_key"},
				CredentialSigningAlgValuesSupportedCOSE: []cose.Alg{cose.ES256},
				ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
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
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return credentialEndpointFixture{
		iss: iss, sdjwtSigner: sdjwtSigner, mdocSigner: mdocSigner,
		attestationSigner: attestationSigner, nonces: nonces, now: now,
	}
}

func (f credentialEndpointFixture) issueNonce(t *testing.T) string {
	t.Helper()
	if err := f.nonces.Issue(context.Background(), issuer.NonceIssuance{
		Nonce: "test-nonce", ExpiresAt: f.now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue nonce: %v", err)
	}
	return "test-nonce"
}

func buildJWTProof(t *testing.T, key *ecdsa.PrivateKey, aud, nonce string) string {
	t.Helper()
	k, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	rawJWK, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var jwkObj map[string]any
	if err := json.Unmarshal(rawJWK, &jwkObj); err != nil {
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
		k, err := jwk.Marshal(pub)
		if err != nil {
			t.Fatalf("jwk.Marshal: %v", err)
		}
		raw, err := json.Marshal(k)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		raws[i] = raw
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
		Signed:     signed, ValidFrom: signed, ValidUntil: signed.Add(24 * time.Hour),
	}
}

func TestRequestCredential_SDJWT_JWTProof(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	walletKey := testP256Key(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, walletKey, testIssuer, nonce)

	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
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

	_, _, err = sdjwtvc.Verify(resp.Credentials[0].Credential, &f.sdjwtSigner.Signer.(*ecdsa.PrivateKey).PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: false,
	})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
}

func TestRequestCredential_SDJWT_Batch(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	key1, key2 := testP256Key(t), testP256Key(t)
	nonce := f.issueNonce(t)
	proof1 := buildJWTProof(t, key1, testIssuer, nonce)
	proof2 := buildJWTProof(t, key2, testIssuer, nonce)

	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
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
					cfg.BatchCredentialIssuance = &issuer.BatchCredentialIssuance{BatchSize: tc.batchSize}
				}
			})
			nonce := f.issueNonce(t)
			proofs := make([]string, tc.numProofs)
			for i := range proofs {
				proofs[i] = buildJWTProof(t, testP256Key(t), testIssuer, nonce)
			}

			resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
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

func TestRequestCredential_Mdoc_JWTProof(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	walletKey := testP256Key(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, walletKey, testIssuer, nonce)

	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.CredentialRequest{
		CredentialConfigurationID: testMdocConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		MdocClaims:                testMdocClaims(t),
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
	verified, err := mdoc.Verify(signed, &f.mdocSigner.Signer.(*ecdsa.PrivateKey).PublicKey, cose.ES256, mdoc.VerifyOptions{
		Now: func() time.Time { return f.now.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	devicePub, ok := verified.DeviceKey.(*ecdsa.PublicKey)
	if !ok || !devicePub.Equal(&walletKey.PublicKey) {
		t.Errorf("DeviceKey = %v, want %v", verified.DeviceKey, &walletKey.PublicKey)
	}
}

// TestRequestCredential_AttestationProof also locks in checkBatchSize's
// own documented distinction: BatchCredentialIssuance is deliberately
// left unset here (nil caps the proofs array's own size at exactly 1 —
// see TestRequestCredential_BatchSize), yet this still succeeds, since
// the cap applies to the array's own size (one attestation JWT here,
// len(values) == 1), not to how many Credentials an attestation
// proof's own attested_keys ultimately fans out to (two, below).
func TestRequestCredential_AttestationProof(t *testing.T) {
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
		cfg.BatchCredentialIssuance = nil
	})
	key1, key2 := testP256Key(t), testP256Key(t)
	nonce := f.issueNonce(t)
	att := buildAttestation(t, f.attestationSigner, nonce, &key1.PublicKey, &key2.PublicKey)

	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
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

func TestRequestCredential_RejectsUnknownConfig(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.CredentialRequest{
		CredentialConfigurationID: "NoSuchConfig",
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorUnknownCredentialConfig)
}

func TestRequestCredential_RejectsMissingConfigID(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.CredentialRequest{})
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
			auth: issuer.AuthorizedRequest{AuthorizationDetails: []issuer.AuthorizationDetail{
				{Type: "openid_credential", CredentialConfigurationID: testSDJWTConfigID, CredentialIdentifiers: []string{identifier}},
			}},
		},
		"no authorization_details at all": {
			auth:    issuer.AuthorizedRequest{},
			wantErr: issuer.ErrorUnknownCredentialIdentifier,
		},
		"non-matching identifier": {
			auth: issuer.AuthorizedRequest{AuthorizationDetails: []issuer.AuthorizationDetail{
				{Type: "openid_credential", CredentialConfigurationID: testSDJWTConfigID, CredentialIdentifiers: []string{"SomeOtherIdentifier"}},
			}},
			wantErr: issuer.ErrorUnknownCredentialIdentifier,
		},
		"matching identifier under the wrong type": {
			auth: issuer.AuthorizedRequest{AuthorizationDetails: []issuer.AuthorizationDetail{
				{Type: "not_openid_credential", CredentialConfigurationID: testSDJWTConfigID, CredentialIdentifiers: []string{identifier}},
			}},
			wantErr: issuer.ErrorUnknownCredentialIdentifier,
		},
		"authorized config isn't supported by this issuer": {
			auth: issuer.AuthorizedRequest{AuthorizationDetails: []issuer.AuthorizationDetail{
				{Type: "openid_credential", CredentialConfigurationID: "NoSuchConfig", CredentialIdentifiers: []string{identifier}},
			}},
			wantErr: issuer.ErrorUnknownCredentialConfig,
		},
		"credential_configuration_id also present": {
			auth: issuer.AuthorizedRequest{AuthorizationDetails: []issuer.AuthorizationDetail{
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
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"other_scope"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidCredentialRequest)
}

func TestRequestCredential_RejectsWrongNumberOfProofTypes(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)

	t.Run("zero proof types", func(t *testing.T) {
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			SDJWTClaims:               testSDJWTClaims(),
		})
		assertIssuerError(t, err, issuer.ErrorInvalidProof)
	})

	t.Run("two proof types", func(t *testing.T) {
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs: map[string][]string{
				oid4vci.ProofTypeJWT:         {proof},
				oid4vci.ProofTypeAttestation: {proof},
			},
			SDJWTClaims: testSDJWTClaims(),
		})
		assertIssuerError(t, err, issuer.ErrorInvalidProof)
	})

	t.Run("empty proof array", func(t *testing.T) {
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID,
			Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {}},
			SDJWTClaims:               testSDJWTClaims(),
		})
		assertIssuerError(t, err, issuer.ErrorInvalidProof)
	})
}

func TestRequestCredential_RejectsUnsupportedProofType(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := requestSDJWTWithProof(f, "di_vp", "whatever")
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
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
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof1}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	if err != nil {
		t.Fatalf("first RequestCredential: %v", err)
	}

	proof2 := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	_, err = f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof2}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidNonce)
}

func TestRequestCredential_RejectsMismatchedNonceAcrossBatch(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	if err := f.nonces.Issue(context.Background(), issuer.NonceIssuance{Nonce: "other-nonce", ExpiresAt: f.now.Add(time.Minute)}); err != nil {
		t.Fatalf("Issue nonce: %v", err)
	}
	proof1 := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	proof2 := buildJWTProof(t, testP256Key(t), testIssuer, "other-nonce")

	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
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

func TestRequestCredential_RejectsUnboundConfig(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	cfg := issuer.Config{
		Issuer: mustIssuerURL(t, testIssuer),
		Endpoints: issuer.Endpoints{
			Credential: mustEndpointURL(t, testCredentialEndpoint),
			Nonce:      mustEndpointURL(t, testNonceEndpoint),
		},
		Limits: issuer.Limits{NonceLifetime: time.Minute},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"UnboundCredential": {Format: sdjwtvc.CredentialFormat},
		},
	}
	deps := issuer.Dependencies{
		Nonces: f.nonces, Clock: fixedClock{now: f.now}, Random: rand.Reader, SDJWTSigner: f.sdjwtSigner,
	}
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.CredentialRequest{
		CredentialConfigurationID: "UnboundCredential",
		SDJWTClaims:               testSDJWTClaims(),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidCredentialRequest)
}

func TestRequestCredential_RejectsUnsupportedFormat(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	cfg := issuer.Config{
		Issuer: mustIssuerURL(t, testIssuer),
		Endpoints: issuer.Endpoints{
			Credential: mustEndpointURL(t, testCredentialEndpoint),
			Nonce:      mustEndpointURL(t, testNonceEndpoint),
		},
		Limits: issuer.Limits{NonceLifetime: time.Minute},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"UnsupportedFormat": {
				Format: "some_unknown_format", CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
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
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	_, err = iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.CredentialRequest{
		CredentialConfigurationID: "UnsupportedFormat",
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	if err == nil {
		t.Errorf("RequestCredential accepted an unsupported format")
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
		Nonce: "expiring-nonce", ExpiresAt: f.now.Add(-time.Minute),
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
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsAttestationProofTypeWhenUnconfigured(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	att := buildAttestation(t, f.attestationSigner, nonce, &testP256Key(t).PublicKey)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.CredentialRequest{
		CredentialConfigurationID: testMdocConfigID, // this config only supports the jwt proof type
		Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att}},
		MdocClaims:                testMdocClaims(t),
	})
	assertIssuerError(t, err, issuer.ErrorInvalidProof)
}

func TestRequestCredential_RejectsProofTypeThisPackageDoesNotImplement(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	cfg := issuer.Config{
		Issuer: mustIssuerURL(t, testIssuer),
		Endpoints: issuer.Endpoints{
			Credential: mustEndpointURL(t, testCredentialEndpoint),
			Nonce:      mustEndpointURL(t, testNonceEndpoint),
		},
		Limits: issuer.Limits{NonceLifetime: time.Minute},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"DIVPCredential": {
				Format: sdjwtvc.CredentialFormat, CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
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
	_, err = iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.CredentialRequest{
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
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
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
	return f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
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
