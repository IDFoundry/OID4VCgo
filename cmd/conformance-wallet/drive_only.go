package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
)

// driveOnlyConfig bundles -drive-only's own flags — see main.go's own
// flag.StringVar/flag.IntVar/flag.BoolVar calls for each field's doc
// comment. Exactly one of offerURL/moduleURL is set: offerURL for
// issuer_initiated (a Credential Offer to resolve first), moduleURL
// for wallet_initiated (no offer exists at all — see runDriveOnly's
// own doc comment).
type driveOnlyConfig struct {
	runStatePath string
	offerURL     string
	moduleURL    string
	testName     string
	numCreds     int
	encrypted    bool
}

// runDriveOnly drives one already-created module instance's protocol
// flow (discovery/PAR/authorize/token/nonce/credential/notification)
// without ever calling the suite's own admin API (POST /api/plan,
// POST /api/runner, GET /api/info, GET /api/log) — see runstate.go's
// own package doc comment for why: those calls require a logged-in
// session this binary has no way to establish against a hosted suite
// instance, but none of the protocol endpoints driveModule actually
// calls are behind that login. The module's own base URL is derived
// from the resolved Credential Offer's own credential_issuer field
// (issuer_initiated's by_value variant carries the offer's JSON
// inline, so resolving it needs no network call either — see
// wallet.Wallet.ResolveCredentialOffer/credentialoffer.go's own doc
// comment on the identical finding for the fully-automated path).
//
// This driver can't itself tell you whether the module passed — the
// suite is still the one grading it. Check the module's own page in
// the suite's web UI once this returns.
//
// wallet_initiated carries no Credential Offer at all
// (@VariantHidesConfigurationFields in AbstractVCIWalletTest.java —
// vciConfig's own doc comment in config.go notes the same for
// vci.credential_offer_endpoint), so there's nothing to resolve: -offer-url
// is for issuer_initiated only, and -module-url instead names the
// module's own base URL directly (as shown on its own page in the
// suite's web UI) for driveModule to call BeginAuthorization against,
// with a nil offer — the same "no offer" shape run()'s own runModule
// already uses whenever cfg.issuerInitiated is false.
func runDriveOnly(cfg driveOnlyConfig) error {
	if cfg.runStatePath == "" {
		return fmt.Errorf("-drive-only requires -run-state")
	}
	if (cfg.offerURL == "") == (cfg.moduleURL == "") {
		return fmt.Errorf("-drive-only requires exactly one of -offer-url (issuer_initiated) or -module-url (wallet_initiated)")
	}

	run, err := loadRunState(cfg.runStatePath)
	if err != nil {
		return err
	}

	ctx := context.Background()
	httpClient := insecureSuiteHTTPClient()

	var module conformancesuite.SuiteModule
	var offer *oid4vci.CredentialOffer
	if cfg.moduleURL != "" {
		module = conformancesuite.SuiteModule{URL: strings.TrimSuffix(cfg.moduleURL, "/")}
	} else {
		offerWallet, err := newWallet(httpClient)
		if err != nil {
			return fmt.Errorf("build offer wallet: %w", err)
		}
		resolved, err := offerWallet.ResolveCredentialOffer(ctx, cfg.offerURL)
		if err != nil {
			return fmt.Errorf("resolve credential offer: %w", err)
		}
		moduleURL := strings.TrimSuffix(resolved.CredentialIssuer, "/")
		if moduleURL == "" {
			return fmt.Errorf("resolved credential offer carries no credential_issuer")
		}
		module = conformancesuite.SuiteModule{URL: moduleURL}
		offer = &resolved
	}
	log.Printf("driving %s at %s (numCreds=%d, encrypted=%v)", cfg.testName, module.URL, cfg.numCreds, cfg.encrypted)

	runner := moduleRunner{HTTPClient: httpClient, WalletRun: run}
	if err := runner.driveModule(ctx, module, cfg.testName, cfg.numCreds, cfg.encrypted, offer); err != nil {
		return fmt.Errorf("drive module: %w", err)
	}
	log.Printf("drove %s to completion — check the module's own page in the suite's web UI for its graded verdict", cfg.testName)
	return nil
}
