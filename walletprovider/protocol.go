package walletprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// The HTTP protocol's paths, relative to where Handler is served. The
// version is in the path: a change a wallet built against v1 can't read
// gets a new one.
const (
	ChallengePath         = "/v1/challenge"
	InstancesPath         = "/v1/instances"
	WalletAttestationPath = "/v1/wallet-attestation"
	KeyAttestationPath    = "/v1/key-attestation"
	StatusPath            = "/v1/status"
)

// RequestHeader is the HTTP header carrying a signed request
// (SignRequest) on WalletAttestationPath and KeyAttestationPath.
const RequestHeader = "Wallet-Provider-Request"

// MaxRequestBytes bounds a request body Handler reads: room for
// Policy.MaxKeys keys with an Android Key Attestation chain each.
const MaxRequestBytes = 256 << 10

// maxResponseBytes bounds a response body Client reads.
const maxResponseBytes = 256 << 10

// maxSignedRequestBytes bounds the RequestHeader value.
const maxSignedRequestBytes = 4 << 10

// The protocol's JSON bodies. Binary values (evidence data) are
// base64url without padding; times are seconds since the Unix epoch;
// keys are public JWKs.

type challengeRequestBody struct {
	Purpose Purpose `json:"purpose"`
}

type challengeResponseBody struct {
	Challenge string  `json:"challenge"`
	Purpose   Purpose `json:"purpose"`
	ExpiresAt int64   `json:"expires_at"`
}

type evidenceBody struct {
	Kind string `json:"kind"`
	Data string `json:"data"`
}

type registerRequestBody struct {
	Challenge       string          `json:"challenge"`
	RegistrationKey json.RawMessage `json:"registration_key"`
	Evidence        evidenceBody    `json:"evidence"`
}

type registerResponseBody struct {
	InstanceID string `json:"instance_id"`
}

type walletAttestationRequestBody struct {
	ClientID    string          `json:"client_id"`
	InstanceKey json.RawMessage `json:"instance_key"`
	Challenge   string          `json:"challenge,omitempty"`
	Evidence    *evidenceBody   `json:"evidence,omitempty"`
}

type walletAttestationResponseBody struct {
	WalletAttestation string `json:"wallet_attestation"`
}

type keyAttestationRequestBody struct {
	InstanceKey json.RawMessage   `json:"instance_key"`
	Challenge   string            `json:"challenge"`
	Keys        []json.RawMessage `json:"keys"`
	Evidence    []evidenceBody    `json:"evidence"`
	Nonce       string            `json:"nonce,omitempty"`
}

type keyAttestationResponseBody struct {
	KeyAttestation string `json:"key_attestation"`
	ExpiresAt      int64  `json:"expires_at"`
}

// errorBody is every refusal's body: Error is one of the protocol's
// error codes, and Description fixed text for it, never the internal
// error.
type errorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// decodeStrict decodes the JSON object data into v, refusing members v
// has no field for, data after the object, and what strictjson refuses
// (duplicate members, names matching a field only case-insensitively,
// text that isn't UTF-8).
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the JSON object")
	}
	if err := strictjson.Unmarshal(data, v); err != nil {
		return fmt.Errorf("strict JSON: %w", err)
	}
	return nil
}
