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
	// in a Credential Request.
	KeyAttestation(ctx context.Context, keys []*ecdsa.PublicKey, nonce string) (string, error)
}
