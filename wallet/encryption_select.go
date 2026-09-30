package wallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// encPreference is the order EncryptionFromMetadata picks a content
// encryption algorithm in, strongest first, among those internal/jwe
// supports.
var encPreference = []jwe.Enc{jwe.A256GCM, jwe.A192GCM, jwe.A128GCM}

// EncryptionFromMetadata chooses how RequestCredential and
// RequestDeferredCredential encrypt a Credential Request, and how they
// ask for an encrypted Credential Response, from the Credential
// Issuer's metadata (§10, §12.2.4) — the choice every Wallet otherwise
// makes by hand.
//
// It encrypts whenever the Issuer offers encryption, required or not:
// a Credential carries personal data. Both are nil when the Issuer
// offers neither. The request is encrypted to the first key in the
// Issuer's credential_request_encryption.jwks this package can use: an
// EC P-256 key for ECDH-ES (its alg absent or "ECDH-ES"). The
// strongest content encryption both sides support is chosen (A256GCM,
// then A192GCM, then A128GCM), and no compression is asked for.
//
// It fails when the Issuer's offer can't be honoured: response
// encryption offered without request encryption (§10 requires both
// together), no usable key, no common content encryption, or response
// encryption without ECDH-ES.
func EncryptionFromMetadata(meta oid4vci.Metadata) (*RequestEncryption, *ResponseEncryption, error) {
	req, resp := meta.CredentialRequestEncryption, meta.CredentialResponseEncryption
	if req == nil && resp == nil {
		return nil, nil, nil
	}
	if req == nil {
		return nil, nil, errors.New("wallet: the issuer offers response encryption without request encryption")
	}
	recipient, err := requestEncryptionKey(req.JWKS)
	if err != nil {
		return nil, nil, err
	}
	reqEnc, err := preferredEnc("credential_request_encryption", req.EncValuesSupported)
	if err != nil {
		return nil, nil, err
	}
	requestEncryption := &RequestEncryption{RecipientJWK: recipient, Enc: reqEnc}
	if resp == nil {
		return requestEncryption, nil, nil
	}
	if !slices.Contains(resp.AlgValuesSupported, jwe.ECDHES) {
		return nil, nil, fmt.Errorf("wallet: credential_response_encryption.alg_values_supported %v doesn't include %s", resp.AlgValuesSupported, jwe.ECDHES)
	}
	respEnc, err := preferredEnc("credential_response_encryption", resp.EncValuesSupported)
	if err != nil {
		return nil, nil, err
	}
	return requestEncryption, &ResponseEncryption{Enc: respEnc}, nil
}

// requestEncryptionKey returns the first key in jwks this package can
// encrypt to, as JSON.
func requestEncryptionKey(jwks oid4vci.JWKSet) (json.RawMessage, error) {
	for _, k := range jwks.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || (k.Alg != "" && k.Alg != jwe.ECDHES) {
			continue
		}
		if _, err := k.PublicKey(); err != nil {
			continue
		}
		raw, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("wallet: issuer request encryption key: %w", err)
		}
		return raw, nil
	}
	return nil, errors.New("wallet: credential_request_encryption.jwks has no EC P-256 ECDH-ES key")
}

func preferredEnc(field string, offered []jwe.Enc) (jwe.Enc, error) {
	for _, enc := range encPreference {
		if slices.Contains(offered, enc) {
			return enc, nil
		}
	}
	return "", fmt.Errorf("wallet: %s.enc_values_supported %v has none this wallet supports", field, offered)
}
