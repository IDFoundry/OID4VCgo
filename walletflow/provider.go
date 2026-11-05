package walletflow

import (
	"context"
	"crypto"
	"crypto/ecdsa"
)

// WalletProvider is the Wallet Provider's backend, as the wallet asks it
// for attestations (HAIP 1.0 §4.4.1, §4.5.1). A real one attests only
// after checking platform evidence that the request comes from a genuine
// instance of its wallet, holding the keys in secure hardware.
type WalletProvider interface {
	// WalletAttestation returns a Wallet Attestation binding
	// instanceKey to clientID: the wallet's client authentication at
	// the Authorization Server.
	WalletAttestation(ctx context.Context, clientID string, instanceKey crypto.PublicKey) (string, error)
	// KeyAttestation returns a Key Attestation over keys carrying the
	// Credential Issuer's nonce: the attestation proof the wallet sends
	// in a Credential Request, or the key_attestation its jwt proofs
	// carry. It must have an exp, which the jwt proof type requires
	// (OpenID4VCI 1.0 Appendix D.1). instanceKey is the instance key of
	// the issuance the keys are for, which WalletAttestation was asked to
	// attest first: a provider that records its instance keys
	// (oid4vcgo/walletprovider) gives the Key Attestation that key's
	// status, so suspending or revoking the instance withdraws it too.
	KeyAttestation(ctx context.Context, instanceKey crypto.PublicKey, keys []*ecdsa.PublicKey, nonce string) (string, error)
}
