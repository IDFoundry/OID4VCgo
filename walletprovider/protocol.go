package walletprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
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

// wireJWK is a key in a request body: the members jwk.JWK reads, and
// the other members RFC 7517 §4 registers, which it ignores. They are
// decoded as fields, not as raw JSON, so that decodeStrict refuses any
// other member, and checks the case of their names, as it does in the
// rest of the body.
type wireJWK struct {
	jwk.JWK
	Use     string   `json:"use,omitempty"`
	KeyOps  []string `json:"key_ops,omitempty"`
	Alg     string   `json:"alg,omitempty"`
	Kid     string   `json:"kid,omitempty"`
	X5U     string   `json:"x5u,omitempty"`
	X5C     []string `json:"x5c,omitempty"`
	X5T     string   `json:"x5t,omitempty"`
	X5TS256 string   `json:"x5t#S256,omitempty"`
	Ext     *bool    `json:"ext,omitempty"` // a Web Crypto export's
}

type registerRequestBody struct {
	Challenge       string       `json:"challenge"`
	RegistrationKey wireJWK      `json:"registration_key"`
	Evidence        evidenceBody `json:"evidence"`
}

type registerResponseBody struct {
	InstanceID string `json:"instance_id"`
}

type walletAttestationRequestBody struct {
	ClientID    string        `json:"client_id"`
	InstanceKey wireJWK       `json:"instance_key"`
	Challenge   string        `json:"challenge,omitempty"`
	Evidence    *evidenceBody `json:"evidence,omitempty"`
}

type walletAttestationResponseBody struct {
	WalletAttestation string `json:"wallet_attestation"`
}

type keyAttestationRequestBody struct {
	InstanceKey wireJWK        `json:"instance_key"`
	Challenge   string         `json:"challenge"`
	Keys        []wireJWK      `json:"keys"`
	Evidence    []evidenceBody `json:"evidence"`
	Nonce       string         `json:"nonce,omitempty"`
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

// bodyTokens bounds the JSON tokens of a request body when a Key
// Attestation request may name maxKeys keys: a few dozen for each key
// and its evidence, and room for the rest. An honest body holds a
// fraction of it (a registration 19), so one of many small
// tokens, or of many members, is refused within a few kilobytes.
func bodyTokens(maxKeys int) int { return 128 + 64*maxKeys }

// decodeStrict decodes the JSON object data into v, refusing more than
// maxTokens tokens and what else strictjson refuses (duplicate members,
// names matching a field only case-insensitively, text that isn't
// UTF-8), then members v has no field for, and data after the object.
// strictjson's check goes first: it stops at the bound, where
// encoding/json reports each member it doesn't know as it goes.
func decodeStrict(data []byte, v any, maxTokens int) error {
	if err := strictjson.UnmarshalLimit(data, v, maxTokens); err != nil {
		return fmt.Errorf("strict JSON: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the JSON object")
	}
	return nil
}
