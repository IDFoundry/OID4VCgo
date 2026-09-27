package issuer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// MaxCredentialRequestBytes bounds the Credential Request body
// ParseCredentialRequest accepts. A request carries only identifiers,
// proofs (each a compact JWT) and optionally an encryption JWK, so this
// is generous.
const MaxCredentialRequestBytes = 1 << 20

// wireCredentialRequest is the Credential Request's wire shape (§8.2).
type wireCredentialRequest struct {
	CredentialConfigurationID    string                  `json:"credential_configuration_id"`
	CredentialIdentifier         string                  `json:"credential_identifier"`
	Proofs                       map[string][]string     `json:"proofs"`
	CredentialResponseEncryption *wireResponseEncryption `json:"credential_response_encryption"`
}

type wireResponseEncryption struct {
	JWK json.RawMessage `json:"jwk"`
	Enc string          `json:"enc"`
	Zip string          `json:"zip"`
}

// ParseCredentialRequest turns a Credential Endpoint request body into
// the CredentialRequest RequestCredential takes: it decrypts it first
// when it arrived as a JWE (§10, via DecryptRequestBody, as contentType
// says), then reads credential_configuration_id, credential_identifier,
// proofs and credential_response_encryption, and sets
// RequestWasEncrypted. The caller adds SDJWTClaims/MdocClaims — what to
// issue is its own business — and passes the result to
// RequestCredential, which validates it.
//
// The HTTP handler stays the caller's: authenticating the access token,
// reading the body (at most MaxCredentialRequestBytes), and writing the
// response. Unrecognized members are ignored. Errors are *Error, ready
// for WriteError.
func (iss *Issuer) ParseCredentialRequest(body []byte, contentType string) (CredentialRequest, error) {
	if len(body) > MaxCredentialRequestBytes {
		return CredentialRequest{}, newError(ErrorInvalidCredentialRequest, http.StatusBadRequest,
			fmt.Sprintf("credential request exceeds %d bytes", MaxCredentialRequestBytes), nil)
	}
	plaintext, wasEncrypted, err := iss.DecryptRequestBody(body, contentType)
	if err != nil {
		return CredentialRequest{}, err
	}
	var wire wireCredentialRequest
	if err := json.Unmarshal(plaintext, &wire); err != nil || !bytes.HasPrefix(bytes.TrimSpace(plaintext), []byte("{")) {
		return CredentialRequest{}, newError(ErrorInvalidCredentialRequest, http.StatusBadRequest, "credential request is not a JSON object", err)
	}
	req := CredentialRequest{
		CredentialConfigurationID: wire.CredentialConfigurationID,
		CredentialIdentifier:      wire.CredentialIdentifier,
		Proofs:                    wire.Proofs,
		RequestWasEncrypted:       wasEncrypted,
	}
	if e := wire.CredentialResponseEncryption; e != nil {
		req.ResponseEncryption = &ResponseEncryptionRequest{JWK: e.JWK, Enc: jwe.Enc(e.Enc), Zip: jwe.Zip(e.Zip)}
	}
	return req, nil
}
