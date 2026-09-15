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
// binding it to signer's own public key via a "jwk" header — the only
// binding-key conveyance this package supports, matching issuer's own
// jwt proof verification (kid/x5c/key_attestation/trust_chain aren't
// offered here). The iss claim (a registered client_id) isn't
// supported yet either.
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
	header := map[string]any{"typ": jwtProofTyp, "jwk": pub}

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
