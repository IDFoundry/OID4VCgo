package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func testRequestDecryptionKey(t *testing.T, kid string) issuer.RequestDecryptionKey {
	t.Helper()
	return issuer.RequestDecryptionKey{KeyID: kid, PrivateKey: testP256Key(t)}
}

func testWalletJWK(t *testing.T) json.RawMessage {
	t.Helper()
	k, err := jwk.Marshal(&testP256Key(t).PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return raw
}

// --- Config validation ---

func TestNewAcceptsRequestAndResponseEncryption(t *testing.T) {
	cfg := validConfig(t)
	cfg.RequestEncryption = &issuer.RequestEncryptionSupport{
		Keys:               []issuer.RequestDecryptionKey{testRequestDecryptionKey(t, "req-1")},
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
	}
	cfg.ResponseEncryption = &issuer.ResponseEncryptionSupport{
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
	}
	if _, err := issuer.New(cfg, validDependencies(t)); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsInvalidRequestEncryption(t *testing.T) {
	nonP256, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P224 key: %v", err)
	}
	cases := map[string]*issuer.RequestEncryptionSupport{
		"no keys":                 {EncValuesSupported: []jwe.Enc{jwe.A128GCM}},
		"key missing key_id":      {Keys: []issuer.RequestDecryptionKey{{PrivateKey: testP256Key(t)}}, EncValuesSupported: []jwe.Enc{jwe.A128GCM}},
		"key missing private key": {Keys: []issuer.RequestDecryptionKey{{KeyID: "k1"}}, EncValuesSupported: []jwe.Enc{jwe.A128GCM}},
		"key not P-256":           {Keys: []issuer.RequestDecryptionKey{{KeyID: "k1", PrivateKey: nonP256}}, EncValuesSupported: []jwe.Enc{jwe.A128GCM}},
		"duplicate key_id": {
			Keys:               []issuer.RequestDecryptionKey{testRequestDecryptionKey(t, "k1"), testRequestDecryptionKey(t, "k1")},
			EncValuesSupported: []jwe.Enc{jwe.A128GCM},
		},
		"no enc values": {Keys: []issuer.RequestDecryptionKey{testRequestDecryptionKey(t, "k1")}},
		"unsupported enc": {
			Keys: []issuer.RequestDecryptionKey{testRequestDecryptionKey(t, "k1")}, EncValuesSupported: []jwe.Enc{"A128CBC-HS256"},
		},
		"unsupported zip": {
			Keys: []issuer.RequestDecryptionKey{testRequestDecryptionKey(t, "k1")}, EncValuesSupported: []jwe.Enc{jwe.A128GCM},
			ZipValuesSupported: []jwe.Zip{"GZIP"},
		},
	}
	for name, re := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.RequestEncryption = re
			if _, err := issuer.New(cfg, validDependencies(t)); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

func TestNewRejectsInvalidResponseEncryption(t *testing.T) {
	cases := map[string]*issuer.ResponseEncryptionSupport{
		"no enc values":   {},
		"unsupported enc": {EncValuesSupported: []jwe.Enc{"A128CBC-HS256"}},
		"unsupported zip": {EncValuesSupported: []jwe.Enc{jwe.A128GCM}, ZipValuesSupported: []jwe.Zip{"GZIP"}},
	}
	for name, re := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.ResponseEncryption = re
			if _, err := issuer.New(cfg, validDependencies(t)); err == nil {
				t.Fatalf("New(%s) = nil error, want error", name)
			}
		})
	}
}

// --- Metadata ---

func TestMetadata_RequestAndResponseEncryption(t *testing.T) {
	cfg := validConfig(t)
	key1, key2 := testRequestDecryptionKey(t, "req-1"), testRequestDecryptionKey(t, "req-2")
	cfg.RequestEncryption = &issuer.RequestEncryptionSupport{
		Keys:               []issuer.RequestDecryptionKey{key1, key2},
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		ZipValuesSupported: []jwe.Zip{jwe.DEF},
		Required:           true,
	}
	cfg.ResponseEncryption = &issuer.ResponseEncryptionSupport{
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
		Required:           false,
	}
	iss, err := issuer.New(cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	md := iss.Metadata()
	if md.CredentialRequestEncryption == nil {
		t.Fatalf("CredentialRequestEncryption is nil")
	}
	re := md.CredentialRequestEncryption
	if len(re.JWKS.Keys) != 2 {
		t.Fatalf("JWKS.Keys has %d entries, want 2", len(re.JWKS.Keys))
	}
	kids := map[string]bool{}
	for _, k := range re.JWKS.Keys {
		kids[k.Kid] = true
		if k.Kty != "EC" || k.Crv != "P-256" {
			t.Errorf("JWK %+v has unexpected kty/crv", k)
		}
		// §10's own "The alg parameter MUST be present" — confirmed
		// live that a real client (the OIDF suite) actually enforces
		// this, not an unused metadata field.
		if k.Alg != jwe.ECDHES {
			t.Errorf("JWK %+v has alg = %q, want %q", k, k.Alg, jwe.ECDHES)
		}
	}
	if !kids["req-1"] || !kids["req-2"] {
		t.Errorf("kids = %v, want req-1 and req-2", kids)
	}
	if len(re.EncValuesSupported) != 2 || !re.EncryptionRequired {
		t.Errorf("re = %+v", re)
	}

	if md.CredentialResponseEncryption == nil {
		t.Fatalf("CredentialResponseEncryption is nil")
	}
	rs := md.CredentialResponseEncryption
	if len(rs.AlgValuesSupported) != 1 || rs.AlgValuesSupported[0] != jwe.ECDHES {
		t.Errorf("AlgValuesSupported = %v, want [ECDH-ES]", rs.AlgValuesSupported)
	}
	if rs.EncryptionRequired {
		t.Errorf("EncryptionRequired = true, want false")
	}

	raw, err := json.Marshal(md)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	wireReqEnc, ok := wire["credential_request_encryption"].(map[string]any)
	if !ok {
		t.Fatalf("wire metadata is missing credential_request_encryption")
	}
	// The wire shape matters as much as the Go struct here: §12.2.4
	// requires "jwks" to be a JSON Web Key Set — a {"keys": [...]}
	// object, not a bare JSON array. Confirmed live against the real
	// OIDF suite that this distinction is actually checked by a real
	// client (VCICheckCredentialRequestEncryptionSupported rejected an
	// earlier version of this code that serialized jwks as a bare
	// array).
	wireJWKS, ok := wireReqEnc["jwks"].(map[string]any)
	if !ok {
		t.Fatalf("credential_request_encryption.jwks = %T, want a JSON object with a \"keys\" member", wireReqEnc["jwks"])
	}
	wireKeys, ok := wireJWKS["keys"].([]any)
	if !ok || len(wireKeys) != 2 {
		t.Fatalf("credential_request_encryption.jwks.keys = %v, want an array of 2 entries", wireJWKS["keys"])
	}
	for _, k := range wireKeys {
		key, _ := k.(map[string]any)
		if key["alg"] != string(jwe.ECDHES) {
			t.Errorf("jwks.keys entry %+v has alg = %v, want %q", key, key["alg"], jwe.ECDHES)
		}
	}
	if _, ok := wire["credential_response_encryption"]; !ok {
		t.Errorf("wire metadata is missing credential_response_encryption")
	}
}

func TestMetadata_OmitsEncryptionWhenUnconfigured(t *testing.T) {
	iss, err := issuer.New(validConfig(t), validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := iss.Metadata()
	if md.CredentialRequestEncryption != nil {
		t.Errorf("CredentialRequestEncryption = %+v, want nil", md.CredentialRequestEncryption)
	}
	if md.CredentialResponseEncryption != nil {
		t.Errorf("CredentialResponseEncryption = %+v, want nil", md.CredentialResponseEncryption)
	}
}

// --- DecryptRequestBody ---

func newEncryptionIssuer(t *testing.T, mutate func(*issuer.Config)) (*issuer.Issuer, issuer.RequestDecryptionKey) {
	t.Helper()
	key := testRequestDecryptionKey(t, "req-1")
	cfg := validConfig(t)
	cfg.RequestEncryption = &issuer.RequestEncryptionSupport{
		Keys:               []issuer.RequestDecryptionKey{key},
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
		ZipValuesSupported: []jwe.Zip{jwe.DEF},
	}
	cfg.ResponseEncryption = &issuer.ResponseEncryptionSupport{
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		ZipValuesSupported: []jwe.Zip{jwe.DEF},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	iss, err := issuer.New(cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return iss, key
}

func TestDecryptRequestBody_PassesThroughPlainJSON(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	body := []byte(`{"hello":"world"}`)
	plaintext, wasEncrypted, err := iss.DecryptRequestBody(body, "application/json")
	if err != nil {
		t.Fatalf("DecryptRequestBody: %v", err)
	}
	if wasEncrypted {
		t.Errorf("wasEncrypted = true, want false")
	}
	if string(plaintext) != string(body) {
		t.Errorf("plaintext = %s, want %s", plaintext, body)
	}
}

func TestDecryptRequestBody_RejectsUnencryptedWhenRequired(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, func(cfg *issuer.Config) { cfg.RequestEncryption.Required = true })
	_, _, err := iss.DecryptRequestBody([]byte(`{}`), "application/json")
	var ierr *issuer.Error
	if !errors.As(err, &ierr) {
		t.Fatalf("error = %v, want *issuer.Error", err)
	}
	if ierr.Code() != issuer.ErrorInvalidEncryptionParameters {
		t.Errorf("Code = %q", ierr.Code())
	}
}

func TestDecryptRequestBody_RejectsEncryptedWhenUnsupported(t *testing.T) {
	iss, err := issuer.New(validConfig(t), validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := iss.DecryptRequestBody([]byte("a.b.c.d.e"), "application/jwt"); err == nil {
		t.Fatalf("DecryptRequestBody = nil error, want error")
	}
}

func TestDecryptRequestBody_RoundTrip(t *testing.T) {
	iss, key := newEncryptionIssuer(t, nil)
	payload := []byte(`{"credential_configuration_id":"IdentityCredential"}`)
	compact, err := jwe.Encrypt(&key.PrivateKey.PublicKey, jwe.A128GCM, payload, jwe.EncryptOptions{KeyID: key.KeyID})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}

	plaintext, wasEncrypted, err := iss.DecryptRequestBody([]byte(compact), "application/jwt")
	if err != nil {
		t.Fatalf("DecryptRequestBody: %v", err)
	}
	if !wasEncrypted {
		t.Errorf("wasEncrypted = false, want true")
	}
	if string(plaintext) != string(payload) {
		t.Errorf("plaintext = %s, want %s", plaintext, payload)
	}
}

func TestDecryptRequestBody_RejectsUnknownKeyID(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	otherKey := testP256Key(t)
	compact, err := jwe.Encrypt(&otherKey.PublicKey, jwe.A128GCM, []byte(`{}`), jwe.EncryptOptions{KeyID: "not-configured"})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}
	if _, _, err := iss.DecryptRequestBody([]byte(compact), "application/jwt"); err == nil {
		t.Fatalf("DecryptRequestBody = nil error, want error")
	}
}

func TestDecryptRequestBody_RejectsUnsupportedEnc(t *testing.T) {
	iss, key := newEncryptionIssuer(t, nil)
	compact, err := jwe.Encrypt(&key.PrivateKey.PublicKey, jwe.A256GCM, []byte(`{}`), jwe.EncryptOptions{KeyID: key.KeyID})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}
	if _, _, err := iss.DecryptRequestBody([]byte(compact), "application/jwt"); err == nil {
		t.Fatalf("DecryptRequestBody = nil error, want error (A256GCM is not in this issuer's enc_values_supported)")
	}
}

func TestDecryptRequestBody_RejectsMalformedJWE(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	if _, _, err := iss.DecryptRequestBody([]byte("not-a-jwe"), "application/jwt"); err == nil {
		t.Fatalf("DecryptRequestBody = nil error, want error")
	}
}

// --- EncryptResponseBody ---

func TestEncryptResponseBody_PassesThroughWhenNilRequest(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	body := []byte(`{"credentials":[]}`)
	encoded, contentType, err := iss.EncryptResponseBody(body, nil)
	if err != nil {
		t.Fatalf("EncryptResponseBody: %v", err)
	}
	if contentType != "application/json" {
		t.Errorf("contentType = %q, want application/json", contentType)
	}
	if string(encoded) != string(body) {
		t.Errorf("encoded = %s, want %s", encoded, body)
	}
}

func TestEncryptResponseBody_RejectsWhenUnsupported(t *testing.T) {
	iss, err := issuer.New(validConfig(t), validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, err = iss.EncryptResponseBody([]byte(`{}`), &issuer.ResponseEncryptionRequest{Enc: jwe.A128GCM, JWK: testWalletJWK(t)})
	if err == nil {
		t.Fatalf("EncryptResponseBody = nil error, want error")
	}
}

func TestEncryptResponseBody_RejectsMissingEnc(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	_, _, err := iss.EncryptResponseBody([]byte(`{}`), &issuer.ResponseEncryptionRequest{JWK: testWalletJWK(t)})
	if err == nil {
		t.Fatalf("EncryptResponseBody = nil error, want error")
	}
}

func TestEncryptResponseBody_RejectsUnsupportedEnc(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	_, _, err := iss.EncryptResponseBody([]byte(`{}`), &issuer.ResponseEncryptionRequest{Enc: "A128CBC-HS256", JWK: testWalletJWK(t)})
	if err == nil {
		t.Fatalf("EncryptResponseBody = nil error, want error")
	}
}

func TestEncryptResponseBody_RejectsUnsupportedZip(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	_, _, err := iss.EncryptResponseBody([]byte(`{}`), &issuer.ResponseEncryptionRequest{Enc: jwe.A128GCM, Zip: "GZIP", JWK: testWalletJWK(t)})
	if err == nil {
		t.Fatalf("EncryptResponseBody = nil error, want error")
	}
}

func TestEncryptResponseBody_RejectsMalformedJWK(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	_, _, err := iss.EncryptResponseBody([]byte(`{}`), &issuer.ResponseEncryptionRequest{Enc: jwe.A128GCM, JWK: json.RawMessage(`not-json`)})
	if err == nil {
		t.Fatalf("EncryptResponseBody = nil error, want error")
	}
}

func TestEncryptResponseBody_RejectsNonECJWK(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	k, err := jwk.Marshal(pub)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if _, _, err := iss.EncryptResponseBody([]byte(`{}`), &issuer.ResponseEncryptionRequest{Enc: jwe.A128GCM, JWK: raw}); err == nil {
		t.Fatalf("EncryptResponseBody = nil error, want error")
	}
}

func TestEncryptResponseBody_RoundTrip(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	walletKey := testP256Key(t)
	walletJWK, err := jwk.Marshal(&walletKey.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	rawJWK, err := json.Marshal(struct {
		jwk.JWK
		Kid string `json:"kid"`
	}{JWK: walletJWK, Kid: "wallet-kid"})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	body := []byte(`{"credentials":[{"credential":"c1"}]}`)
	encoded, contentType, err := iss.EncryptResponseBody(body, &issuer.ResponseEncryptionRequest{
		JWK: rawJWK, Enc: jwe.A128GCM, Zip: jwe.DEF,
	})
	if err != nil {
		t.Fatalf("EncryptResponseBody: %v", err)
	}
	if contentType != "application/jwt" {
		t.Errorf("contentType = %q, want application/jwt", contentType)
	}

	header, err := jwe.DecodeHeader(string(encoded))
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if header["kid"] != "wallet-kid" {
		t.Errorf("kid = %v, want wallet-kid", header["kid"])
	}

	decrypted, err := jwe.Decrypt(walletKey, string(encoded))
	if err != nil {
		t.Fatalf("jwe.Decrypt: %v", err)
	}
	if string(decrypted) != string(body) {
		t.Errorf("decrypted = %s, want %s", decrypted, body)
	}
}

// --- RequestCredential/RequestDeferredCredential enforcement ---

func TestRequestCredential_RejectsResponseEncryptionWithoutEncryptedRequest(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)

	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
		ResponseEncryption:        &issuer.ResponseEncryptionRequest{Enc: jwe.A128GCM, JWK: testWalletJWK(t)},
	})
	assertIssuerError(t, err, issuer.ErrorInvalidEncryptionParameters)
}

func TestRequestCredential_AcceptsResponseEncryptionWithEncryptedRequest(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)

	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
		ResponseEncryption:        &issuer.ResponseEncryptionRequest{Enc: jwe.A128GCM, JWK: testWalletJWK(t)},
		RequestWasEncrypted:       true,
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(resp.Credentials))
	}
}

// TestEncryptResponseBody_RejectsMismatchedJWKAlg confirmed live
// against the real OIDF conformance suite's own
// fail-unsupported-encryption-algorithm module: the Wallet's own
// credential_response_encryption.jwk can declare an "alg" this issuer
// doesn't implement (here, a nonsense value; the suite's own probe
// literally uses "UNSUPPORTED_ALG") while enc/kty/crv all stay valid —
// EncryptResponseBody must reject this rather than silently encrypting
// with its own ECDH-ES anyway, per §10's own "The JWE alg algorithm
// used MUST be equal to the alg value of the chosen JWK." A live run
// against the real suite caught this: RequestCredential itself doesn't
// validate credential_response_encryption at all — only
// EncryptResponseBody (called separately, by whatever HTTP handler
// wires this package to a real endpoint) does, so this exercises that
// method directly rather than through RequestCredential.
func TestEncryptResponseBody_RejectsMismatchedJWKAlg(t *testing.T) {
	cfg := validConfig(t)
	cfg.ResponseEncryption = &issuer.ResponseEncryptionSupport{
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
	}
	iss, err := issuer.New(cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	walletKey := testP256Key(t)
	walletJWK, err := jwk.Marshal(&walletKey.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	rawJWK, err := json.Marshal(struct {
		jwk.JWK
		Alg string `json:"alg"`
	}{JWK: walletJWK, Alg: "UNSUPPORTED_ALG"})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	_, _, err = iss.EncryptResponseBody([]byte(`{"credentials":[]}`), &issuer.ResponseEncryptionRequest{
		Enc: jwe.A128GCM, JWK: rawJWK,
	})
	assertIssuerError(t, err, issuer.ErrorInvalidEncryptionParameters)
}

func TestRequestDeferredCredential_RejectsResponseEncryptionWithoutEncryptedRequest(t *testing.T) {
	deferredTransactions := newFakeDeferredTransactionStore()
	deferredTransactions.put("txn-1", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionPending})
	deps := validDependencies(t)
	deps.DeferredTransactions = deferredTransactions
	iss, err := issuer.New(validConfig(t), deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = iss.RequestDeferredCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.DeferredCredentialRequest{
		TransactionID:      "txn-1",
		ResponseEncryption: &issuer.ResponseEncryptionRequest{Enc: jwe.A128GCM, JWK: testWalletJWK(t)},
	})
	assertIssuerError(t, err, issuer.ErrorInvalidEncryptionParameters)
}

// --- Full simulated-Wallet wire round trip ---

// wireResponseEncryption/wireCredentialRequest mirror the actual §8.2
// wire shape of a Credential Request's own "credential_response_encryption"
// object and its parent — issuer has no exported request-side wire
// type of its own (CredentialRequest carries signing/claims material
// that never goes on the wire), so a caller's own HTTP glue builds
// this the same way wallet's own credentialRequestBody does.
type wireResponseEncryption struct {
	JWK json.RawMessage `json:"jwk"`
	Enc string          `json:"enc"`
}

type wireCredentialRequest struct {
	CredentialConfigurationID string                  `json:"credential_configuration_id"`
	Proofs                    map[string][]string     `json:"proofs"`
	ResponseEncryption        *wireResponseEncryption `json:"credential_response_encryption,omitempty"`
}

// TestEncryptedCredentialRequestResponseRoundTrip simulates a Wallet's
// own role directly with internal/jwe (the same way buildJWTProof
// simulates one for jwt-type proofs, since wallet has no §10 support
// of its own yet): build a plaintext Credential Request carrying its
// own ephemeral response-decryption key, encrypt it to the issuer's
// own published request-encryption key from Metadata, decrypt via
// DecryptRequestBody, drive RequestCredential, then encrypt the
// Response back via EncryptResponseBody and decrypt it with the
// Wallet's own key — proving DecryptRequestBody/EncryptResponseBody's
// wire format is exactly what a real ECDH-ES-speaking Wallet would
// produce and expect.
func TestEncryptedCredentialRequestResponseRoundTrip(t *testing.T) {
	issuerSigner := testP256Key(t)
	nonces := newFakeNonceStore()
	reqKey := testRequestDecryptionKey(t, "req-1")

	cfg := validConfig(t)
	// This test only exercises the Credential/Nonce Endpoints — drop
	// the other endpoints validConfig sets up rather than also
	// supplying their own Dependencies.
	cfg.Endpoints.DeferredCredential = fapi.URL{}
	cfg.Endpoints.Notification = fapi.URL{}
	cfg.CredentialOfferEndpoint = fapi.URL{}
	cfg.Limits.DeferredIssuancePollInterval = 0
	cfg.Limits.CredentialOfferLifetime = 0
	cfg.RequestEncryption = &issuer.RequestEncryptionSupport{
		Keys:               []issuer.RequestDecryptionKey{reqKey},
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
	}
	cfg.ResponseEncryption = &issuer.ResponseEncryptionSupport{
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
	}
	deps := issuer.Dependencies{
		Nonces:      nonces,
		Clock:       issuer.ClockFunc(time.Now),
		Random:      rand.Reader,
		SDJWTSigner: &issuer.SDJWTSigner{Signer: issuerSigner, Alg: jose.ES256},
	}
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := iss.Metadata()

	walletSigningKey := testP256Key(t)
	walletDecryptionKey := testP256Key(t)

	nonceResult, err := iss.RequestNonce(context.Background())
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	proof := buildJWTProof(t, walletSigningKey, testIssuer, nonceResult.CNonce)

	walletJWK, err := jwk.Marshal(&walletDecryptionKey.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	rawWalletJWK, err := json.Marshal(walletJWK)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	plainBody, err := json.Marshal(wireCredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		ResponseEncryption:        &wireResponseEncryption{JWK: rawWalletJWK, Enc: string(jwe.A128GCM)},
	})
	if err != nil {
		t.Fatalf("json.Marshal request: %v", err)
	}

	compactRequest, err := jwe.Encrypt(&reqKey.PrivateKey.PublicKey, jwe.A128GCM, plainBody, jwe.EncryptOptions{
		KeyID: md.CredentialRequestEncryption.JWKS.Keys[0].Kid,
	})
	if err != nil {
		t.Fatalf("jwe.Encrypt request: %v", err)
	}

	decryptedBody, wasEncrypted, err := iss.DecryptRequestBody([]byte(compactRequest), "application/jwt")
	if err != nil {
		t.Fatalf("DecryptRequestBody: %v", err)
	}
	if !wasEncrypted {
		t.Fatalf("wasEncrypted = false, want true")
	}

	var parsed wireCredentialRequest
	if err := json.Unmarshal(decryptedBody, &parsed); err != nil {
		t.Fatalf("json.Unmarshal decrypted body: %v", err)
	}

	resp, err := iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: parsed.CredentialConfigurationID,
		Proofs:                    parsed.Proofs,
		SDJWTClaims:               testSDJWTClaims(),
		ResponseEncryption:        &issuer.ResponseEncryptionRequest{JWK: parsed.ResponseEncryption.JWK, Enc: jwe.Enc(parsed.ResponseEncryption.Enc)},
		RequestWasEncrypted:       wasEncrypted,
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}

	respBody, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal response: %v", err)
	}
	encryptedResponse, contentType, err := iss.EncryptResponseBody(respBody, &issuer.ResponseEncryptionRequest{
		JWK: parsed.ResponseEncryption.JWK, Enc: jwe.Enc(parsed.ResponseEncryption.Enc),
	})
	if err != nil {
		t.Fatalf("EncryptResponseBody: %v", err)
	}
	if contentType != "application/jwt" {
		t.Fatalf("contentType = %q, want application/jwt", contentType)
	}

	decryptedResponse, err := jwe.Decrypt(walletDecryptionKey, string(encryptedResponse))
	if err != nil {
		t.Fatalf("jwe.Decrypt response: %v", err)
	}
	var finalResp oid4vci.CredentialResponse
	if err := json.Unmarshal(decryptedResponse, &finalResp); err != nil {
		t.Fatalf("json.Unmarshal decrypted response: %v", err)
	}
	if len(finalResp.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(finalResp.Credentials))
	}
	if _, _, err := sdjwtvc.Verify(finalResp.Credentials[0].Credential, &issuerSigner.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: sdjwtvc.KeyBindingNotRequired,
	}); err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
}
