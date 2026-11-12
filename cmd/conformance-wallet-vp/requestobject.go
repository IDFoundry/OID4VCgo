package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// walletNonceEntropyBytes matches this repo's own nonce-generation
// convention elsewhere (e.g. cmd/conformance-verifier's own session
// IDs, verifier's own Authorization Request "nonce") — 256 bits,
// base64url-encoded.
const walletNonceEntropyBytes = 32

// maxRequestObjectBytes bounds a fetched Request Object: one carries
// an x5c chain and a DCQL query, far below this.
const maxRequestObjectBytes = 1 << 20

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

// fetchAndVerifyRequestObject fetches link's request_uri as a wallet
// does, through wallet.Wallet.FetchAuthorizationRequest — or, for
// request_uri_method=post, FetchAuthorizationRequestPost, with a fresh
// wallet_nonce and walletMetadataForPost (§5.10) — so the fetch is the
// wallet package's own: its Content-Type checked, its body bounded, no
// redirect followed, over s.http, which verifies the Verifier's TLS
// certificate against verifier_tls_trust_anchors_pem. The Request
// Object is then verified by (*wallet.Wallet).ParseAuthorizationRequest
// against s.trust. It takes the x509_hash-prefixed, signed-JAR shape
// verifier.BuildAuthorizationRequest itself builds, matching the one
// HAIP wallet plan variant this binary targets (request_uri_signed,
// x509_hash), and with s.acceptSANDNS an x509_san_dns one too (the EUDI
// interop run's) — see conformance/wallet-vp/README.md for this
// binary's own scope notes.
//
// The fetcher may reach request_uri's host on a loopback or private
// address, as the suite's and the interop runs' Verifiers are: this
// binary fetches only what its driver points it at.
func (s *server) fetchAndVerifyRequestObject(ctx context.Context, link wallet.AuthorizationRequestLink) (wallet.AuthorizationRequest, error) {
	target, err := url.Parse(link.RequestURI)
	if err != nil {
		return wallet.AuthorizationRequest{}, fmt.Errorf("parse request_uri: %w", err)
	}
	w, err := wallet.New(wallet.Config{
		Assurance:       wallet.AssuranceDevelopment,
		ProofSigningAlg: oid4vci.ES256,
		Fetch: fapihttp.Config{
			MaxResponseBytes: maxRequestObjectBytes, RequestTimeout: 30 * time.Second,
			AllowLoopbackHosts: true, AllowedPrivateHosts: []string{target.Hostname()},
		},
		VerifierTrust:    s.trust,
		AcceptX509SANDNS: s.acceptSANDNS,
	}, wallet.Dependencies{HTTP: s.http, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader})
	if err != nil {
		return wallet.AuthorizationRequest{}, err
	}
	if link.RequestURIMethod != wallet.RequestURIMethodPost {
		return w.FetchAuthorizationRequest(ctx, link.RequestURI, link.ClientID)
	}
	walletNonce, err := newWalletNonce()
	if err != nil {
		return wallet.AuthorizationRequest{}, fmt.Errorf("generate wallet_nonce: %w", err)
	}
	return w.FetchAuthorizationRequestPost(ctx, link.RequestURI, link.ClientID, walletNonce, json.RawMessage(walletMetadataForPost(s.acceptSANDNS)))
}
