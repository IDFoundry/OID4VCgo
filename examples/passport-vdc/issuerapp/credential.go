package issuerapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/issuer/fapiresource"
)

func (a *App) handleNonce(w http.ResponseWriter, r *http.Request) {
	result, err := a.issuer.RequestNonce(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	result.WriteJSON(w)
}

// credentialHandler serves the Credential Endpoint: issuer.CredentialHandler
// checks the DPoP-bound access token, and prepareCredential decides
// what to issue.
func (a *App) credentialHandler() (http.Handler, error) {
	tokens, err := fapiresource.New(a.resourceVerifier)
	if err != nil {
		return nil, fmt.Errorf("issuerapp: access token verifier: %w", err)
	}
	h, err := a.issuer.CredentialHandler(issuer.CredentialHandlerConfig{
		URL: &a.credentialURL, Tokens: tokens, Prepare: a.prepareCredential,
	})
	if err != nil {
		return nil, fmt.Errorf("issuerapp: credential handler: %w", err)
	}
	return h, nil
}

// protectedHandlers serves the Deferred Credential Endpoint, whose
// polls resolveDeferred answers, and the Notification Endpoint, whose
// events the /status page shows. Both check the access token as the
// Credential Endpoint does.
func (a *App) protectedHandlers() (deferred, notification http.Handler, err error) {
	tokens, err := fapiresource.New(a.resourceVerifier)
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: access token verifier: %w", err)
	}
	deferred, err = a.issuer.DeferredCredentialHandler(issuer.DeferredCredentialHandlerConfig{
		ProtectedEndpointConfig: issuer.ProtectedEndpointConfig{URL: &a.deferredURL, Tokens: tokens},
		Resolve:                 a.resolveDeferred,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: deferred credential handler: %w", err)
	}
	notification, err = a.issuer.NotificationEndpointHandler(issuer.ProtectedEndpointConfig{URL: &a.notificationURL, Tokens: tokens})
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: notification handler: %w", err)
	}
	return deferred, notification, nil
}

// prepareCredential finds the passport transaction the access token's
// subject names and fills in the requested format from that passport's
// Evidence. Each credential gets its own status list index; done
// releases the reservation and the indexes if issuing fails.
func (a *App) prepareCredential(_ context.Context, grant issuer.Grant, req *issuer.CredentialRequest) (func(bool), error) {
	// Each offered credential is issued once per passport: reserve it
	// now, release it if issuing fails.
	e, review, err := a.transactions.reserve(grant.Subject, req.CredentialConfigurationID)
	switch {
	case errors.Is(err, errAlreadyIssued):
		return nil, issuer.NewError(issuer.ErrorCredentialRequestDenied, "this credential has already been issued for this passport")
	case err != nil:
		return nil, issuer.NewError(issuer.ErrorCredentialRequestDenied, "the passport transaction for this access token has expired")
	}
	var statusIdxs []int
	var reviewRef string
	done := func(issued bool) {
		if issued {
			a.transactions.done(grant.Subject)
			return
		}
		a.transactions.release(grant.Subject, req.CredentialConfigurationID)
		for _, idx := range statusIdxs {
			a.statusList.release(idx)
		}
		if reviewRef != "" {
			a.reviews.remove(reviewRef)
		}
	}

	// A passport uploaded for review is deferred: the wallet gets a
	// transaction_id to poll, and the review keeps its own copy of the
	// Evidence until an operator decides (resolveDeferred).
	if review {
		if reviewRef, err = a.reviews.add(e, req.CredentialConfigurationID); err != nil {
			a.transactions.release(grant.Subject, req.CredentialConfigurationID)
			return nil, issuer.NewError(issuer.ErrorCredentialRequestDenied, "too many issuances are awaiting review — try again later")
		}
		req.Defer = &issuer.Deferral{Reference: reviewRef}
		return done, nil
	}

	// Both formats are always built from the same Evidence;
	// RequestCredential uses whichever the requested configuration
	// needs.
	opts := credential.Options{Now: a.now()}
	mdocClaims, err := credential.MdocClaims(e, opts)
	if err == nil {
		req.SDJWTClaims, err = credential.SDJWTClaims(e, a.vct, opts)
	}
	if err != nil {
		done(false)
		return nil, issuer.NewError(issuer.ErrorCredentialRequestDenied, "this passport can't be issued: "+err.Error())
	}
	req.MdocClaims = mdocClaims

	// Each credential — every one of a batch — gets its own status list
	// index (HAIP 1.0 §6.1).
	req.PerCredential = func(_ context.Context, c *issuer.CredentialInstance) error {
		idx, err := a.statusList.allocate(credentialFormat(req.CredentialConfigurationID), !e.Checks.PassiveAuthentication, a.now())
		if err != nil {
			return err
		}
		statusIdxs = append(statusIdxs, idx)
		a.withStatus(c, idx)
		return nil
	}
	return done, nil
}

func (a *App) issuerMetadataHandler() http.HandlerFunc {
	return issuer.MetadataHandler(a.issuer, a.metadataSigner, oid4vci.ES256, a.metadataCert)
}

// handleVCTMetadata serves the SD-JWT VC type metadata document for
// this issuer's vct — display names for the credential and its claims.
func (a *App) handleVCTMetadata(w http.ResponseWriter, _ *http.Request) {
	claim := func(label string, path ...string) sdjwtvc.ClaimMetadata {
		return sdjwtvc.ClaimMetadata{Path: sdjwtvc.ClaimPath(path...), Display: []sdjwtvc.ClaimDisplay{{Locale: "en", Label: label}}}
	}
	doc := sdjwtvc.TypeMetadata{
		VCT:         a.vct,
		Name:        "Passport-derived credential (demo)",
		Description: "Identity attributes, portrait and the gmrtd passport file from a verified ePassport. Demo only.",
		Display: []sdjwtvc.TypeDisplay{{
			Locale: "en", Name: "Passport (demo)",
			Description: "Issued by the IDFoundry passport-vdc demo from a verified ePassport",
		}},
		Claims: []sdjwtvc.ClaimMetadata{
			claim("Family name", credential.FamilyName),
			claim("Given names", credential.GivenName),
			claim("Date of birth", credential.SDJWTBirthDate),
			claim("Nationality", credential.SDJWTNationalities),
			claim("Issuing country", credential.IssuingCountry),
			claim("Document number", credential.DocumentNumber),
			claim("Passport expiry", credential.ExpiryDate),
			claim("Sex", credential.Sex),
			claim("Portrait", credential.SDJWTPicture),
			claim("Passport file (gmrtd, all data groups)", credential.PassportFile),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}
