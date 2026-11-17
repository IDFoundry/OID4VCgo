package walletprovider_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"log"
	"net/http"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// A Wallet Provider for an Android wallet, run on several replicas over
// one database: sqlstore's DB gives every store, and its
// StatusListTokens has one replica sign each status list's token. The
// lists are sized for millions of wallets, and monitoring watches how
// many more instance keys the current period's lists take.
// DEPLOYING.md has the rest of the checklist.
func ExampleNew() {
	var (
		signer crypto.Signer       // the attestation key, in an HSM or KMS
		chain  []*x509.Certificate // its certificate, issued by your CA, naming the Identifier as a URI SAN
		// From sqlstore's DB: WalletProviderInstances, WalletProviderInstanceKeys,
		// WalletProviderChallenges, StatusIndices and StatusListTokens.
		instances    walletprovider.InstanceStore
		instanceKeys walletprovider.InstanceKeyStore
		challenges   walletprovider.ChallengeStore
		indices      statuslist.IndexStore
		tokens       statuslist.TokenStore
		android      *androidkey.Verifier // as androidkey's ExampleVerifier configures it
	)
	p, err := walletprovider.New(walletprovider.Config{
		Identifier: "https://wallet-provider.example.com", ClientIDs: []string{"https://wallet.example.com"},
		StatusListBaseURI: "https://wallet-provider.example.com/statuslists",
		// StatusListSize's default, 2^20, holds 64 × 2^20/2 ≈ 33.5M
		// instance keys used a week.
		Policy: walletprovider.Policy{Platforms: map[walletprovider.Platform]walletprovider.PlatformPolicy{
			walletprovider.PlatformAndroid: {
				SecurityLevels:      []walletprovider.SecurityLevel{walletprovider.SecurityLevelStrongBox, walletprovider.SecurityLevelTEE},
				RequireVerifiedBoot: true,
			},
		}},
	}, walletprovider.Dependencies{
		Signer: signer, Chain: chain,
		Instances: instances, InstanceKeys: instanceKeys, Challenges: challenges,
		StatusIndices: indices, StatusListTokens: tokens,
		Evidence: []walletprovider.EvidenceVerifier{androidkey.EvidenceVerifier{Verifier: android}},
		Random:   rand.Reader,
	})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // behind rate limiting
	// StatusLists serves /{start}/{n} under StatusListBaseURI.
	mux.Handle("/statuslists/", http.StripPrefix("/statuslists", p.StatusLists()))
	// Daily, from any instance: p.SweepStatusLists, then sqlstore's
	// DB.Sweep deletes instance keys past their retention.

	// From monitoring, every few minutes: raise StatusListSize before
	// Free runs out, as an attestation for one more instance key fails
	// until End, and alert on RecentInstanceFree falling fast early in
	// a period: many instances registered at once.
	fill, err := p.StatusListFill(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("room for %d more instance keys until %s, %d of them for recently registered instances",
		fill.Free(), fill.End, fill.RecentInstanceFree())
}
