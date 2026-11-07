package appattest

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// ClientDataPrefix is the first line of the client data an attestation
// or assertion is made over.
const ClientDataPrefix = "OID4VCgo-WalletProvider-AppAttest/1"

// ClientData is the client data the app makes an attestation
// (DCAppAttestService.attestKey) or assertion (generateAssertion) over,
// as the SHA-256 of these bytes, its clientDataHash. It is UTF-8 text
// of LF-terminated lines:
//
//	OID4VCgo-WalletProvider-AppAttest/1
//	<purpose>
//	<challenge>
//	<thumbprint of keys[0]>
//	<thumbprint of keys[1]>
//	...
//
// where purpose is the challenge's (registration, instance or holder),
// challenge is the challenge as the provider issued it (Challenge.Value:
// base64url without padding), and each thumbprint is a key's RFC 7638
// JWK SHA-256 thumbprint, base64url without padding, in the order the
// request lists the keys: the registration key at registration, the
// instance key at its first Wallet Attestation, every holder key of a
// Key Attestation request. Every line, the last one included, ends
// with "\n"; no line holds a "\n" of its own, so the lines can't be
// read another way.
func ClientData(purpose walletprovider.Purpose, challenge string, keys []crypto.PublicKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, fail(ErrConfig, "client data needs at least one key")
	}
	if purpose == "" || strings.ContainsAny(string(purpose), "\r\n") || challenge == "" || strings.ContainsAny(challenge, "\r\n") {
		return nil, fail(ErrConfig, "client data needs a purpose and a challenge, each one line")
	}
	var b strings.Builder
	b.WriteString(ClientDataPrefix + "\n" + string(purpose) + "\n" + challenge + "\n")
	for i, k := range keys {
		j, err := jwk.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("%w: key %d: %w", ErrConfig, i, err)
		}
		t, err := j.Thumbprint()
		if err != nil {
			return nil, fmt.Errorf("%w: key %d: %w", ErrConfig, i, err)
		}
		b.WriteString(t + "\n")
	}
	return []byte(b.String()), nil
}

// ClientDataHash is the SHA-256 of ClientData: the clientDataHash the
// app passes to attestKey or generateAssertion.
func ClientDataHash(purpose walletprovider.Purpose, challenge string, keys []crypto.PublicKey) ([]byte, error) {
	data, err := ClientData(purpose, challenge, keys)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}
