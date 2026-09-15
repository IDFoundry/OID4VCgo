package wallet

import (
	"crypto"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
)

// jwtProofTyp is the required JOSE "typ" header of a jwt-type key
// proof (Appendix F.1).
const jwtProofTyp = "openid4vci-proof+jwt" //nolint:gosec // an OID4VCI typ value, not a credential

// GenerateProof signs a jwt-type key proof (Appendix F.1) with signer,
// binding it to signer's own public key via a "jwk" header — the
// common case, embedding the key material inline rather than pointing
// at it. The iss claim (a registered client_id) isn't supported yet.
// See GenerateProofWithKeyID/GenerateProofWithX5C for the other two
// binding-key conveyances Appendix F.1 defines.
//
// credentialIssuer MUST be the Credential Issuer Identifier — the aud
// claim (Appendix F.1: "MUST be the Credential Issuer Identifier"),
// not the Credential Endpoint's own URL. nonce is the c_nonce from a
// prior RequestNonce call, or "" when the issuer has no Nonce Endpoint
// (Appendix F.1 makes nonce REQUIRED whenever one exists).
func (w *Wallet) GenerateProof(signer crypto.Signer, credentialIssuer, nonce string) (string, error) {
	pub, err := jwk.Marshal(signer.Public())
	if err != nil {
		return "", fmt.Errorf("wallet: generate proof: marshal jwk: %w", err)
	}
	return w.signJWTProof(signer, map[string]any{"jwk": pub}, credentialIssuer, nonce)
}

// GenerateProofWithKeyID signs a jwt-type key proof (Appendix F.1),
// binding it via a "kid" header instead of embedding the key material:
// kid points at a key the Credential Issuer is expected to already
// know or trust out-of-band, rather than conveying it inline. Appendix
// F.1's own example use is a DID URL into a DID Document, but this
// package takes no position on what a kid means — that's the issuer's
// own trust policy to resolve (see issuer.ProofBindingKeyResolver's
// doc comment for the corresponding server-side half of this).
// credentialIssuer/nonce are as GenerateProof's own.
func (w *Wallet) GenerateProofWithKeyID(signer crypto.Signer, kid, credentialIssuer, nonce string) (string, error) {
	if kid == "" {
		return "", fmt.Errorf("wallet: generate proof: kid is required")
	}
	return w.signJWTProof(signer, map[string]any{"kid": kid}, credentialIssuer, nonce)
}

// GenerateProofWithX5C signs a jwt-type key proof (Appendix F.1),
// binding it via an "x5c" header: a certificate chain (RFC 7515
// §4.1.6 — base64-encoded DER, leaf certificate first) whose leaf
// certificate's own public key is the key the Credential is bound to.
// This package doesn't build or validate the chain itself — x5c is
// whatever certificate(s) the caller's own PKI already issued for
// signer's public key; resolving trust in that chain is entirely the
// issuer's own policy (see issuer.ProofBindingKeyResolver's doc
// comment). credentialIssuer/nonce are as GenerateProof's own.
func (w *Wallet) GenerateProofWithX5C(signer crypto.Signer, x5c []string, credentialIssuer, nonce string) (string, error) {
	if len(x5c) == 0 {
		return "", fmt.Errorf("wallet: generate proof: x5c must not be empty")
	}
	return w.signJWTProof(signer, map[string]any{"x5c": x5c}, credentialIssuer, nonce)
}

// signJWTProof builds and signs the jwt-type key proof body (Appendix
// F.1) common to GenerateProof/GenerateProofWithKeyID/GenerateProofWithX5C,
// given only the binding-key header entry each one contributes.
func (w *Wallet) signJWTProof(signer crypto.Signer, bindingHeader map[string]any, credentialIssuer, nonce string) (string, error) {
	header := map[string]any{"typ": jwtProofTyp}
	for k, v := range bindingHeader {
		header[k] = v
	}

	body := map[string]any{"aud": credentialIssuer, "iat": w.deps.Clock.Now().Unix()}
	if nonce != "" {
		body["nonce"] = nonce
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("wallet: generate proof: marshal payload: %w", err)
	}

	proof, err := jose.Sign(w.cfg.ProofSigningAlg, signer, header, payload)
	if err != nil {
		return "", fmt.Errorf("wallet: generate proof: %w", err)
	}
	return proof, nil
}
