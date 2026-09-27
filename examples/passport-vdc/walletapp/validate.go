package walletapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// validateReceived checks a credential the issuer returned before the
// wallet keeps it (wallet.VerifyIssuedCredential): its issuer signature,
// with the signing certificate chaining to issuerRoots; that it is bound
// to holder, the key the wallet proved possession of; and that it is the
// type conf describes, valid at now.
func validateReceived(ctx context.Context, conf oid4vci.CredentialConfigurationMetadata, credential string, holder *ecdsa.PrivateKey, issuerRoots *x509.CertPool, now time.Time) error {
	_, err := wallet.VerifyIssuedCredential(ctx, wallet.VerifyIssuedCredentialParams{
		Configuration: conf, Credential: credential, HolderKey: &holder.PublicKey,
		IssuerRoots: issuerRoots, Now: now,
	})
	return err
}
