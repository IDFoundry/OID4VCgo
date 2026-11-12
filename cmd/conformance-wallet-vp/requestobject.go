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
// minimal declaration of the presentations this binary actually makes
// (dc+sd-jwt, ES256 for both the Issuer signature and the Key Binding
// JWT — see wallet.HeldCredential's own HolderKeyAlg in credential.go —
// and mso_mdoc, ES256 for IssuerAuth and DeviceSignature, see
// issueFixtureMdocCredential) and the Client Identifier Prefixes it
// accepts (x509_hash, and x509_san_dns with accept_x509_san_dns), not a
// placeholder — plus RFC 8414
// §2's required response_types_supported and the one response mode it
// answers in, as walletflow's own wallet metadata carries them. Like
// walletflow's, its issuer (also required by §2) is
// https://self-issued.me/v2, the one aud a Request Object may then
// carry (§5.8).
func walletMetadataForPost(acceptSANDNS bool) string {
	prefixes := `["x509_hash"]`
	if acceptSANDNS {
		prefixes = `["x509_hash","x509_san_dns"]`
	}
	return `{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]},` +
		`"mso_mdoc":{"issuerauth_alg_values":[-7],"deviceauth_alg_values":[-7]}},` +
		`"client_id_prefixes_supported":` + prefixes + `,` +
		`"response_types_supported":["vp_token"],"response_modes_supported":["direct_post.jwt"],` +
		`"issuer":"https://self-issued.me/v2"}`
}

// fetchAndVerifyRequestObject fetches requestURI — via POST (with a
// fresh wallet_nonce, §5.10) when usePost is true, plain GET (§5)
// otherwise — and verifies/parses it via wallet.ParseAuthorizationRequest.
// It takes the x509_hash-prefixed, signed-JAR shape
// verifier.BuildAuthorizationRequest itself builds, matching the one
// HAIP wallet plan variant this binary targets (request_uri_signed,
// x509_hash), and with acceptSANDNS an x509_san_dns one too (the EUDI
// interop run's) — see wallet.ParseAuthorizationRequest's own doc
// comment, and conformance/wallet-vp/README.md for this binary's own
// scope notes.
func fetchAndVerifyRequestObject(requestURI, clientID string, usePost bool, trust wallet.VerifierTrust, acceptSANDNS bool) (wallet.AuthorizationRequest, error) {
	var compact, walletNonce string
	var err error
	if usePost {
		walletNonce, err = newWalletNonce()
		if err != nil {
			return wallet.AuthorizationRequest{}, fmt.Errorf("generate wallet_nonce: %w", err)
		}
		form := url.Values{"wallet_nonce": {walletNonce}, "wallet_metadata": {walletMetadataForPost(acceptSANDNS)}}
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

	// trust is Config.verifierTrust: the chain is checked against the
	// configured anchors, or — with none — not at all; the signature
	// and x509_hash checks apply either way.
	authReq, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: compact, ClientID: clientID, WalletNonce: walletNonce,
		VerifierTrust: trust, AcceptX509SANDNS: acceptSANDNS,
	})
	if err != nil {
		return wallet.AuthorizationRequest{}, err
	}
	return authReq, nil
}
