package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// runWalletflow receives the credential with walletflow, OID4VCgo's
// whole wallet, under ProfileHAIP: it negotiates the grant, the client
// authentication and the proof from the metadata itself, verifies what
// it receives against the IACA, and CheckStatus checks its status
// list. A wallet-initiated issuance is an offer the wallet makes
// itself, naming no grant, which walletflow redeems with the
// authorization code grant (OpenID4VCI 1.0 §4.1.1).
//
// -proof jwt or jwk is the jwt proof's key conveyance, should walletflow
// choose a jwt proof with a Key Attestation: jwt its default, by index,
// and jwk under Config.ProofKeyByJWK.
func runWalletflow(ctx context.Context, env *environment, res *result) {
	o := env.o
	offer := o.offer
	if offer == "" {
		raw, err := json.Marshal(map[string]any{"credential_issuer": o.issuer, "credential_configuration_ids": []string{o.configID}})
		if err != nil {
			res.fail("setup", err)
			return
		}
		offer = "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(raw))
	}
	w, err := walletflow.New(walletflow.Config{
		ClientID: o.clientID, RedirectURI: o.redirectURI,
		IssuerRoots:     env.issuerRoots,
		MdocIssuerRoots: env.issuerRoots,
		// The status list service signs the SD-JWT VC's lists as the
		// issuer's Status Issuer.
		StatusIssuers:               map[string][]string{o.issuer: {env.statusIssuer}},
		RequireIssuerName:           true,
		IssuerMetadataRoots:         env.metadataRoots,
		RequireSignedIssuerMetadata: true,
		RequireIssuerMetadataName:   true,
		IssuanceProfile:             walletflow.ProfileHAIP,
		BatchSize:                   max(1, o.batch),
		// -proof jwt leaves walletflow's default, naming the proof's
		// key by its index among the Key Attestation's attested_keys,
		// as the issuer requires; -proof jwk names it in jwk.
		ProofKeyByJWK: o.proof == "jwk",
		// Development only for the stack's loopback address. Every
		// certificate checked is checked for revocation, against the
		// CRLs of the IACA and the metadata CA (startCRL).
		Development:              true,
		IssuerRevocation:         env.revocation,
		StatusRevocation:         env.revocation,
		IssuerMetadataRevocation: env.revocation,
	}, walletflow.Dependencies{
		Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(),
		// A plain *http.Transport, not the recorder: CheckStatus's
		// fetches apply an address policy that needs one, and this
		// engine's result records no exchanges.
		Provider: env.provider, HTTP: env.statusHTTP,
	})
	if err != nil {
		res.fail("setup", err)
		return
	}
	s, err := w.StartIssuance(ctx, offer)
	if err != nil {
		res.fail("offer", err)
		return
	}
	defer func() { _ = s.Close(context.WithoutCancel(ctx)) }()
	if ids := s.Offer().Credentials; len(ids) > 0 {
		res.Configuration = ids[0].ConfigurationID
	}
	authURL, err := s.BeginAuthorization(ctx)
	if err != nil {
		res.fail("par", err)
		return
	}
	redirect, err := login(ctx, env.http, authURL, o.redirectURI, o.user, o.password)
	if err != nil {
		res.fail("login", err)
		return
	}
	if err := s.CompleteAuthorization(ctx, redirect); err != nil {
		res.fail("token", err)
		return
	}
	issued, err := s.RequestCredentials(ctx)
	if err != nil {
		res.fail("credential", err)
		return
	}
	for _, d := range issued.Deferred {
		res.Deferred = true
		c, err := d.Wait(ctx)
		if err != nil {
			res.fail("deferred", err)
			return
		}
		issued.Credentials = append(issued.Credentials, c)
	}
	for _, c := range issued.Credentials {
		for range c.Copies {
			report := credentialReport{Format: c.Format, Verified: true}
			checked, err := w.CheckStatus(ctx, c.ID)
			if err != nil {
				report.StatusError = err.Error()
			} else {
				report.Status = checked.Status.Value
				if checked.Status.Reason != "" {
					report.StatusError = checked.Status.Reason
				}
			}
			res.Credentials = append(res.Credentials, report)
		}
	}
	res.OK = len(res.Credentials) > 0
	if !res.OK {
		res.fail("credential", fmt.Errorf("received nothing"))
	}
}
