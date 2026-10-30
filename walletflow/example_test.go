package walletflow_test

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// A wallet: its registration, the issuers and Verifiers it trusts, and
// where it keeps keys and credentials. A wallet holders use keeps them
// durably, and its keys in hardware (the mobile libraries' Keychain and
// Keystore stores): New refuses memory stores in production. Give each
// role its own trust anchors; where they share one, a leaf policy (an
// extended key usage) on each. Each role in use also needs a revocation
// check in production: a certrevocation.Refresher's Checker over its
// CAs' CRLs, or certrevocation.NoCheck{} to decline.
func ExampleNew() {
	var (
		issuerRoots, verifierRoots *x509.CertPool                // the ecosystem's trust anchors, one pool per role
		keys                       walletflow.KeyStore           // hardware-backed, declaring durable custody
		credentials                walletflow.CredentialStore    // durable, under the platform's data protection
		authorizations             walletflow.AuthorizationStore // durable, so an authorization survives a suspension
		provider                   walletflow.WalletProvider     // attests the wallet and its keys, for issuers that require it
		issuerCRLs, verifierCRLs   *certrevocation.Refresher     // each role's CAs' CRLs (certrevocation.NewRefresher)
	)
	// A Refresher fetches only when Refresh or Run is called, and a
	// role whose CRLs it doesn't hold fails closed: run each in the
	// background for as long as the wallet lives.
	ctx := context.Background()
	go issuerCRLs.Run(ctx)
	go verifierCRLs.Run(ctx)
	w, err := walletflow.New(walletflow.Config{
		ClientID: "https://wallet.example.com", RedirectURI: "com.example.wallet:/callback",
		IssuerRoots: issuerRoots, IssuerRevocation: issuerCRLs.Checker(), StatusRevocation: issuerCRLs.Checker(),
		VerifierTrust: wallet.X5CVerifierRoots{Roots: verifierRoots, Revocation: verifierCRLs.Checker()},
	}, walletflow.Dependencies{Keys: keys, Credentials: credentials, Authorizations: authorizations, Provider: provider})
	if err != nil {
		panic(err)
	}
	_ = w
}

// Receiving a credential from a Credential Offer: with a pre-authorized
// code, the holder enters the PIN the issuer sent; otherwise the holder
// signs in at the Authorization Server in a browser, which redirects
// back to Config.RedirectURI.
func ExampleWallet_StartIssuance() {
	var w *walletflow.Wallet // from walletflow.New
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, "openid-credential-offer://?credential_offer_uri=…")
	if err != nil {
		panic(err)
	}
	defer func() { _ = s.Close(ctx) }()
	if s.Offer().Grant == walletflow.GrantPreAuthorizedCode {
		err = s.RedeemPreAuthorizedCode(ctx, "493536") // the PIN, from the holder
	} else {
		var signIn string
		if signIn, err = s.BeginAuthorization(ctx); err == nil {
			_ = signIn // open in a browser; it redirects back with the result
			err = s.CompleteAuthorization(ctx, "com.example.wallet:/callback?code=…&state=…")
		}
	}
	if err != nil {
		panic(err)
	}
	result, err := s.RequestCredentials(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(result.Credentials), "received,", len(result.Deferred), "deferred")
}

// Answering a Verifier: show the holder who asks and what would be
// disclosed (Preview), then respond with their consent, or decline.
func ExampleWallet_StartPresentation() {
	var w *walletflow.Wallet // from walletflow.New
	ctx := context.Background()
	p, err := w.StartPresentation(ctx, "openid4vp://?client_id=…&request_uri=…")
	if err != nil {
		panic(err)
	}
	sel, err := p.DefaultSelection(ctx)
	if err != nil {
		panic(err)
	}
	disclosed, err := p.Preview(ctx, sel)
	if err != nil {
		panic(err)
	}
	fmt.Println(p.Verifier().Name, "asks for", disclosed) // and the holder decides
	if _, err := p.Respond(ctx, sel); err != nil {
		panic(err)
	}
}
