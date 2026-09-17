package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// walletNonceEntropyBytes matches this repo's own nonce-generation
// convention elsewhere (e.g. cmd/conformance-verifier's own session
// IDs, verifier's own Authorization Request "nonce") — 256 bits,
// base64url-encoded.
const walletNonceEntropyBytes = 32

// newWalletNonce generates a fresh, cryptographically random
// "wallet_nonce" value (OID4VP §5.10: "a fresh, cryptographically
// random number with sufficient entropy") for one POST fetch of
// request_uri.
func newWalletNonce() (string, error) {
	buf := make([]byte, walletNonceEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// walletMetadataForPost is this binary's own "wallet_metadata" value
// (OID4VP §10/§5.10) sent on a POST request_uri fetch — an accurate,
// minimal declaration of the one presentation format/algorithm this
// binary actually supports (dc+sd-jwt, ES256 for both the Issuer
// signature and the Key Binding JWT — see wallet.HeldCredential's own
// HolderKeyAlg in credential.go), not a placeholder.
const walletMetadataForPost = `{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]}}}`

// fetchAndVerifyRequestObject fetches requestURI — via POST (with a
// fresh wallet_nonce, §5.10) when usePost is true, plain GET (§5)
// otherwise — and verifies/parses it via wallet.ParseAuthorizationRequest.
// This binary only ever receives the x509_hash-prefixed, signed-JAR
// shape verifier.BuildAuthorizationRequest itself builds, matching the
// one HAIP wallet plan variant this binary targets (request_uri_signed,
// x509_hash) — see wallet.ParseAuthorizationRequest's own doc comment
// for the DC API/other-client_id-prefix variants that function doesn't
// cover, and conformance/wallet-vp/README.md for this binary's own
// scope notes.
func fetchAndVerifyRequestObject(requestURI, clientID string, usePost bool) (wallet.AuthorizationRequest, error) {
	var compact, walletNonce string
	var err error
	if usePost {
		walletNonce, err = newWalletNonce()
		if err != nil {
			return wallet.AuthorizationRequest{}, fmt.Errorf("generate wallet_nonce: %w", err)
		}
		form := url.Values{"wallet_nonce": {walletNonce}, "wallet_metadata": {walletMetadataForPost}}
		compact, err = httpPostFormString(requestURI, form)
		if err != nil {
			return wallet.AuthorizationRequest{}, fmt.Errorf("fetch request_uri via POST: %w", err)
		}
	} else {
		compact, err = httpGetString(requestURI)
		if err != nil {
			return wallet.AuthorizationRequest{}, fmt.Errorf("fetch request_uri: %w", err)
		}
	}

	authReq, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: compact, ClientID: clientID, WalletNonce: walletNonce,
	})
	if err != nil {
		return wallet.AuthorizationRequest{}, err
	}
	return authReq, nil
}
