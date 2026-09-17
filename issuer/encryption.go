package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// jweContentType is the media type §10 requires for an encrypted
// Credential/Deferred Credential Request or Response.
const jweContentType = "application/jwt"

// RequestDecryptionKey is one EC P-256 key pair this issuer accepts an
// encrypted Credential/Deferred Credential Request under (§10),
// published (public half only) in Metadata's own
// credential_request_encryption.jwks and looked up by KeyID to decrypt
// an incoming request whose JWE header names it.
type RequestDecryptionKey struct {
	// KeyID is REQUIRED: every published JWK needs a "kid" (§12.2.4's
	// own "Each JWK in the set MUST have a kid (Key ID) parameter that
	// uniquely identifies the key").
	KeyID string

	// PrivateKey is REQUIRED — a P-256 key, matching internal/jwe's own
	// scope.
	PrivateKey *ecdsa.PrivateKey
}

func (k RequestDecryptionKey) validate() error {
	if k.KeyID == "" {
		return fmt.Errorf("key_id is required")
	}
	if k.PrivateKey == nil {
		return fmt.Errorf("private_key is required")
	}
	if k.PrivateKey.Curve != elliptic.P256() {
		return fmt.Errorf("private_key must be a P-256 key")
	}
	return nil
}

// RequestEncryptionSupport declares this issuer's own support for
// encrypted Credential/Deferred Credential Requests (§10), published as
// the credential_request_encryption Credential Issuer Metadata
// parameter (§12.2.4). The same support governs both endpoints (§9.1's
// own "credential_request_encryption parameter in the Credential
// Issuer Metadata").
type RequestEncryptionSupport struct {
	// Keys is REQUIRED: one or more decryption keys, published as
	// Metadata's own jwks (public halves only).
	Keys []RequestDecryptionKey

	// EncValuesSupported is REQUIRED: the JWE "enc" values this issuer
	// can decrypt with.
	EncValuesSupported []jwe.Enc

	// ZipValuesSupported is OPTIONAL: the JWE "zip" values this issuer
	// can decompress after decryption.
	ZipValuesSupported []jwe.Zip

	// Required, when true, rejects an unencrypted Credential/Deferred
	// Credential Request (§12.2.4's own encryption_required).
	Required bool
}

func (s *RequestEncryptionSupport) validate() error {
	if s == nil {
		return nil
	}
	if len(s.Keys) == 0 {
		return fmt.Errorf("keys must not be empty")
	}
	seen := make(map[string]bool, len(s.Keys))
	for i, k := range s.Keys {
		if err := k.validate(); err != nil {
			return fmt.Errorf("keys[%d]: %w", i, err)
		}
		if seen[k.KeyID] {
			return fmt.Errorf("keys[%d]: duplicate key_id %q", i, k.KeyID)
		}
		seen[k.KeyID] = true
	}
	if len(s.EncValuesSupported) == 0 {
		return fmt.Errorf("enc_values_supported must not be empty")
	}
	for _, e := range s.EncValuesSupported {
		if !validEnc(e) {
			return fmt.Errorf("enc_values_supported: unsupported enc %q", e)
		}
	}
	for _, z := range s.ZipValuesSupported {
		if z != jwe.DEF {
			return fmt.Errorf("zip_values_supported: unsupported zip %q", z)
		}
	}
	return nil
}

// ResponseEncryptionSupport declares this issuer's own support for
// encrypting Credential/Deferred Credential Responses (§10), published
// as the credential_response_encryption Credential Issuer Metadata
// parameter (§12.2.4). Metadata's own alg_values_supported is always
// exactly ["ECDH-ES"] — the only alg internal/jwe implements — so
// there's no field for it here.
type ResponseEncryptionSupport struct {
	// EncValuesSupported is REQUIRED: the JWE "enc" values this issuer
	// can encode a Response with.
	EncValuesSupported []jwe.Enc

	// ZipValuesSupported is OPTIONAL: the JWE "zip" values this issuer
	// can compress a Response with before encryption.
	ZipValuesSupported []jwe.Zip

	// Required, when true, means this issuer always encrypts every
	// Response (§12.2.4's own encryption_required) — enforcing that a
	// request actually supplied encryption keys is the caller's own
	// job, since "the Wallet didn't ask for encryption" isn't itself an
	// error the Credential Request/Response protocol defines a code
	// for.
	Required bool
}

func (s *ResponseEncryptionSupport) validate() error {
	if s == nil {
		return nil
	}
	if len(s.EncValuesSupported) == 0 {
		return fmt.Errorf("enc_values_supported must not be empty")
	}
	for _, e := range s.EncValuesSupported {
		if !validEnc(e) {
			return fmt.Errorf("enc_values_supported: unsupported enc %q", e)
		}
	}
	for _, z := range s.ZipValuesSupported {
		if z != jwe.DEF {
			return fmt.Errorf("zip_values_supported: unsupported zip %q", z)
		}
	}
	return nil
}

func validEnc(e jwe.Enc) bool {
	return e == jwe.A128GCM || e == jwe.A192GCM || e == jwe.A256GCM
}

// ResponseEncryptionRequest is the Wallet's own "credential_response_encryption"
// object (§8.2/§9.1): a single public key JWK to encrypt the Response
// to, plus the JWE "enc" (and optional "zip") to use. Present on
// CredentialRequest.ResponseEncryption/DeferredCredentialRequest.ResponseEncryption
// — nil means the corresponding Response isn't encrypted.
type ResponseEncryptionRequest struct {
	JWK json.RawMessage // REQUIRED
	Enc jwe.Enc         // REQUIRED
	Zip jwe.Zip         // OPTIONAL
}

// DecryptRequestBody decrypts body if contentType is "application/jwt"
// (a JWE Compact Serialization, §10), resolving which of
// Config.RequestEncryption.Keys to decrypt with from the JWE header's
// own "kid" — or returns body unchanged (as plain JSON) for any other
// contentType. Shared by both the Credential Request (§8.2) and
// Deferred Credential Request (§9.1), since the same
// Config.RequestEncryption governs both (§9.1's own "using the
// parameters from the credential_request_encryption object").
//
// The caller must pass wasEncrypted through to
// CredentialRequest.RequestWasEncrypted (or DeferredCredentialRequest's
// own field) once it decodes plaintext into one:
// RequestCredential/RequestDeferredCredential use it to enforce
// §8.2-18's own "Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included, to prevent it
// being substituted by an attacker."
func (iss *Issuer) DecryptRequestBody(body []byte, contentType string) (plaintext []byte, wasEncrypted bool, err error) {
	if contentType != jweContentType {
		if iss.cfg.RequestEncryption != nil && iss.cfg.RequestEncryption.Required {
			return nil, false, newError(ErrorInvalidEncryptionParameters, 400, "this issuer requires an encrypted request", nil)
		}
		return body, false, nil
	}
	if iss.cfg.RequestEncryption == nil {
		return nil, false, newError(ErrorInvalidEncryptionParameters, 400, "this issuer does not support encrypted requests", nil)
	}

	header, err := jwe.DecodeHeader(string(body))
	if err != nil {
		return nil, false, newError(ErrorInvalidEncryptionParameters, 400, "malformed encrypted request", err)
	}
	kid, _ := header["kid"].(string)
	key := findRequestDecryptionKey(iss.cfg.RequestEncryption.Keys, kid)
	if key == nil {
		return nil, false, newError(ErrorInvalidEncryptionParameters, 400, "unknown encryption key id", nil)
	}
	encStr, _ := header["enc"].(string)
	if !slices.Contains(iss.cfg.RequestEncryption.EncValuesSupported, jwe.Enc(encStr)) {
		return nil, false, newError(ErrorInvalidEncryptionParameters, 400, fmt.Sprintf("unsupported enc %q", encStr), nil)
	}
	if zipStr, ok := header["zip"].(string); ok && !slices.Contains(iss.cfg.RequestEncryption.ZipValuesSupported, jwe.Zip(zipStr)) {
		return nil, false, newError(ErrorInvalidEncryptionParameters, 400, fmt.Sprintf("unsupported zip %q", zipStr), nil)
	}

	plaintext, err = jwe.Decrypt(key.PrivateKey, string(body))
	if err != nil {
		return nil, false, newError(ErrorInvalidEncryptionParameters, 400, "decryption failed", err)
	}
	return plaintext, true, nil
}

func findRequestDecryptionKey(keys []RequestDecryptionKey, kid string) *RequestDecryptionKey {
	for i := range keys {
		if keys[i].KeyID == kid {
			return &keys[i]
		}
	}
	return nil
}

// EncryptResponseBody encrypts body — a marshaled Credential Response
// or Deferred Credential Response — per req, the Wallet's own
// credential_response_encryption object from the request that produced
// body, or returns it unchanged (as plain JSON) when req is nil.
// Shared by both endpoints for the same reason DecryptRequestBody is.
func (iss *Issuer) EncryptResponseBody(body []byte, req *ResponseEncryptionRequest) (encoded []byte, contentType string, err error) {
	if req == nil {
		return body, "application/json", nil
	}
	if iss.cfg.ResponseEncryption == nil {
		return nil, "", newError(ErrorInvalidEncryptionParameters, 400, "this issuer does not support encrypted responses", nil)
	}
	if req.Enc == "" {
		return nil, "", newError(ErrorInvalidEncryptionParameters, 400, "credential_response_encryption.enc is required", nil)
	}
	if !slices.Contains(iss.cfg.ResponseEncryption.EncValuesSupported, req.Enc) {
		return nil, "", newError(ErrorInvalidEncryptionParameters, 400, fmt.Sprintf("unsupported enc %q", req.Enc), nil)
	}
	if req.Zip != "" && !slices.Contains(iss.cfg.ResponseEncryption.ZipValuesSupported, req.Zip) {
		return nil, "", newError(ErrorInvalidEncryptionParameters, 400, fmt.Sprintf("unsupported zip %q", req.Zip), nil)
	}

	pub, err := jwk.ParsePublicKey(req.JWK)
	if err != nil {
		return nil, "", newError(ErrorInvalidEncryptionParameters, 400, "malformed credential_response_encryption.jwk", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", newError(ErrorInvalidEncryptionParameters, 400, "credential_response_encryption.jwk must be an EC P-256 key", nil)
	}
	// The Wallet's own jwk may optionally carry its own "kid" — if so,
	// §10-3's "If the selected public key contains a kid parameter, the
	// JWE MUST include the same value in the kid JWE Header Parameter"
	// applies to this direction too. Best-effort: jwk.ParsePublicKey
	// above already validated req.JWK is well-formed JSON.
	var jwkFields struct {
		KeyID string  `json:"kid"`
		Alg   jwe.Alg `json:"alg"`
	}
	_ = json.Unmarshal(req.JWK, &jwkFields)
	// §10's own "The alg parameter MUST be present [and] MUST be equal
	// to the alg value of the chosen JWK" — this issuer only ever
	// encrypts with ECDH-ES (internal/jwe's own sole implementation),
	// so a JWK declaring any other alg must be rejected outright rather
	// than silently encrypted with ECDH-ES anyway. An absent alg is
	// left alone: this repo's own jwk.Marshal never emits one, so
	// requiring its presence unconditionally would reject every
	// legitimate caller in this codebase, not just a genuine mismatch.
	if jwkFields.Alg != "" && jwkFields.Alg != jwe.ECDHES {
		return nil, "", newError(ErrorInvalidEncryptionParameters, 400,
			fmt.Sprintf("credential_response_encryption.jwk declares alg %q, which this issuer cannot encrypt with", jwkFields.Alg), nil)
	}

	compact, err := jwe.Encrypt(ecPub, req.Enc, body, jwe.EncryptOptions{Zip: req.Zip, KeyID: jwkFields.KeyID})
	if err != nil {
		return nil, "", fmt.Errorf("issuer: encrypt response body: %w", err)
	}
	return []byte(compact), jweContentType, nil
}
