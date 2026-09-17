package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
)

// RequestEncryption configures how RequestCredential/RequestDeferredCredential
// encrypt the outbound request body (§10) — set this when the
// Credential Issuer's own Metadata names credential_request_encryption.
// This package doesn't fetch or parse Issuer metadata itself (see the
// package doc comment); RecipientJWK is one entry of the Issuer's own
// published credential_request_encryption.jwks (§12.2.4), the caller's
// own choice among however many the Issuer offers — §10-3's own "any
// may be selected based on the information about each key, such as
// kty, use, alg."
type RequestEncryption struct {
	// RecipientJWK is REQUIRED: the Issuer's own encryption public key,
	// as published in its Metadata.
	RecipientJWK json.RawMessage

	// Enc is REQUIRED: the JWE content encryption algorithm to use —
	// must be one the Issuer's own
	// credential_request_encryption.enc_values_supported names.
	Enc jwe.Enc

	// Zip, if set, compresses the request body before encryption — must
	// be one the Issuer's own
	// credential_request_encryption.zip_values_supported names, if any.
	Zip jwe.Zip
}

// ResponseEncryption requests an encrypted Credential/Deferred
// Credential Response (§10) by attaching a fresh, per-call ephemeral
// public key to the outbound request as its own
// "credential_response_encryption" object — RequestCredential/
// RequestDeferredCredential generate this key pair internally and
// decrypt the resulting Response transparently, so the CredentialResult
// a caller receives is always plaintext regardless of whether
// ResponseEncryption was set. Setting this without also setting
// RequestEncryption on the same request is rejected: §8.2-18's own
// "Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included, to prevent it
// being substituted by an attacker."
type ResponseEncryption struct {
	// Enc is REQUIRED: the JWE content encryption algorithm to ask the
	// Issuer to use — must be one the Issuer's own
	// credential_response_encryption.enc_values_supported names.
	Enc jwe.Enc

	// Zip, if set, asks the Issuer to compress the Response before
	// encryption — must be one the Issuer's own
	// credential_response_encryption.zip_values_supported names, if
	// any.
	Zip jwe.Zip
}

// wireResponseEncryptionRequest is ResponseEncryption's own wire shape
// once resolved to an actual ephemeral public key (§8.2/§9.1's own
// "credential_response_encryption" object) — shared by
// CredentialRequest and DeferredCredentialRequest's own private wire
// bodies.
type wireResponseEncryptionRequest struct {
	JWK json.RawMessage `json:"jwk"`
	Enc string          `json:"enc"`
	Zip string          `json:"zip,omitempty"`
}

// prepareResponseEncryption generates a fresh ephemeral P-256 key pair
// for respEnc and builds the outbound wire object for it — or returns
// all zero values when respEnc is nil. The private key is returned
// alongside so the caller can decrypt the eventual Response with it.
func prepareResponseEncryption(respEnc *ResponseEncryption) (*wireResponseEncryptionRequest, *ecdsa.PrivateKey, error) {
	if respEnc == nil {
		return nil, nil, nil
	}
	if respEnc.Enc == "" {
		return nil, nil, fmt.Errorf("response_encryption.enc is required")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral response decryption key: %w", err)
	}
	pubJWK, err := jwk.Marshal(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ephemeral public key: %w", err)
	}
	// The Issuer needs this JWK's own "alg" to know which JWE key
	// management algorithm to wrap the response's content encryption
	// key with (§8.2's own "credential_response_encryption" object,
	// "jwk" member) — this package only ever performs ECDH-ES Direct
	// Key Agreement (internal/jwe's own sole supported Alg), so that's
	// always the value, not something ResponseEncryption needs its own
	// field for.
	rawJWK, err := json.Marshal(struct {
		jwk.JWK
		Alg string `json:"alg"`
	}{JWK: pubJWK, Alg: string(jwe.ECDHES)})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal ephemeral public key: %w", err)
	}
	return &wireResponseEncryptionRequest{JWK: rawJWK, Enc: string(respEnc.Enc), Zip: string(respEnc.Zip)}, priv, nil
}

// encryptRequestBody encrypts body per reqEnc (§10), returning the
// resulting bytes and the Content-Type to send them with — or body
// unchanged with "application/json" when reqEnc is nil.
func encryptRequestBody(body []byte, reqEnc *RequestEncryption) (encoded []byte, contentType string, err error) {
	if reqEnc == nil {
		return body, "application/json", nil
	}
	if reqEnc.Enc == "" {
		return nil, "", fmt.Errorf("request_encryption.enc is required")
	}
	pub, err := jwk.ParsePublicKey(reqEnc.RecipientJWK)
	if err != nil {
		return nil, "", fmt.Errorf("request_encryption.recipient_jwk: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("request_encryption.recipient_jwk must be an EC P-256 key")
	}
	// The Issuer's own published JWK carries its own "kid" (issuer's
	// RequestDecryptionKey.KeyID is REQUIRED) — §10-3's own "If the
	// selected public key contains a kid parameter, the JWE MUST
	// include the same value in the kid JWE Header Parameter."
	var withKid struct {
		KeyID string `json:"kid"`
	}
	_ = json.Unmarshal(reqEnc.RecipientJWK, &withKid)

	compact, err := jwe.Encrypt(ecPub, reqEnc.Enc, body, jwe.EncryptOptions{Zip: reqEnc.Zip, KeyID: withKid.KeyID})
	if err != nil {
		return nil, "", fmt.Errorf("encrypt request body: %w", err)
	}
	return []byte(compact), "application/jwt", nil
}

// decryptResponseBody decrypts body if contentType is "application/jwt"
// using priv (the ephemeral key prepareResponseEncryption generated),
// or returns it unchanged for any other contentType. priv is nil
// exactly when the Wallet didn't request an encrypted Response.
//
// §8.3's own "this is done regardless of the content" means the Issuer
// must always honor a requested Response encryption — so priv set but
// an unencrypted response received is treated as an error, the same as
// the reverse (an encrypted response with no key to decrypt it).
func decryptResponseBody(body []byte, contentType string, priv *ecdsa.PrivateKey) ([]byte, error) {
	encrypted := contentType == "application/jwt"
	switch {
	case priv != nil && !encrypted:
		return nil, fmt.Errorf("requested an encrypted response but the issuer returned content-type %q", contentType)
	case priv == nil && encrypted:
		return nil, fmt.Errorf("received an encrypted response but no response_encryption was requested")
	case !encrypted:
		return body, nil
	}
	plaintext, err := jwe.Decrypt(priv, string(body))
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}
	return plaintext, nil
}
