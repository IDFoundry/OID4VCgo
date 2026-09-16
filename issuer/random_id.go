package issuer

import (
	"encoding/base64"
	"io"
)

// randomID returns a base64url-encoded, cryptographically random
// identifier drawing n bytes of entropy from random — the shared
// generation RequestNonce (c_nonce, §7.2), issueDPoPNonce (RFC 9449
// §8), and ExchangePreAuthorizedCode's own credential_identifier
// minting (§6.2) all need, factored out rather than three inline
// copies.
func randomID(random io.Reader, n int) (string, error) {
	raw := make([]byte, n)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
