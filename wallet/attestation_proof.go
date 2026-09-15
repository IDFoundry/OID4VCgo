package wallet

import (
	"crypto"
	"fmt"

	"github.com/idfoundry/oid4vcigo/attestation"
	"github.com/idfoundry/oid4vcigo/internal/jose"
)

// GenerateAttestationProof builds and signs a Key Attestation JWT
// (Appendix D.1) for use as the attestation proof type (Appendix F.3):
// it sets claims.IssuedAt to the current time and, when nonce is
// non-empty, claims.Nonce — Appendix F.3's own "If the Credential
// Issuer has a Nonce Endpoint ... the c_nonce value provided ... MUST
// be provided in the key attestation's nonce parameter" — then
// delegates to attestation.Issue for everything else: header
// conveyance (kid/x5c/trust_chain), AttestedKeys, ExpiresAt,
// KeyStorage/UserAuthentication, and so on are entirely the caller's
// own policy, the same split attestation.Issue itself already draws.
//
// Building a Key Attestation is, in most real deployments, a secure
// element's or an OS attestation service's job, not pure application
// logic sitting in this package — GenerateAttestationProof exists for
// the cases where the caller's own signer can produce one directly
// (e.g. testing, or a software-only wallet), mirroring GenerateProof's
// role for jwt-type proofs. The resulting compact JWT is submitted as
// CredentialRequest.Attestation; unlike a jwt-type proof, RequestCredential
// doesn't build this one itself, since the nonce must already be baked
// into the signed attestation before the Credential Request is sent —
// a caller drives RequestNonce, then this method, then RequestCredential,
// in that order.
func (w *Wallet) GenerateAttestationProof(
	signer crypto.Signer, alg jose.Alg, header attestation.Header, claims attestation.Claims, nonce string,
) (string, error) {
	claims.IssuedAt = w.deps.Clock.Now().Unix()
	if nonce != "" {
		claims.Nonce = nonce
	}
	compact, err := attestation.Issue(signer, alg, header, claims)
	if err != nil {
		return "", fmt.Errorf("wallet: generate attestation proof: %w", err)
	}
	return compact, nil
}
