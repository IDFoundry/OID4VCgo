package issuerapp

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	fapires "github.com/idfoundry/fapigo/resource"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func (a *App) handleNonce(w http.ResponseWriter, r *http.Request) {
	result, err := a.issuer.RequestNonce(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	result.WriteJSON(w)
}

// handleCredential verifies the DPoP-bound access token, finds the
// passport transaction its subject names, and issues the requested
// format from that passport's Evidence.
func (a *App) handleCredential(w http.ResponseWriter, r *http.Request) {
	// credentialURL, not r.URL: a server-side request URL has no scheme
	// or host, which DPoP's htu comparison needs.
	authCtx, err := a.resourceVerifier.Verify(r.Context(), fapires.VerifyRequest{
		Method: r.Method, URL: &a.credentialURL, Authorization: r.Header.Get("Authorization"),
		DPoPProofs: r.Header.Values("DPoP"), PeerCertificate: fapires.PeerCertificateFromHTTP(r),
	})
	if err != nil {
		fapires.WriteError(w, err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, issuer.MaxCredentialRequestBytes+1))
	if err != nil {
		http.Error(w, "credential request is unreadable", http.StatusBadRequest)
		return
	}
	req, err := a.issuer.ParseCredentialRequest(body, r.Header.Get("Content-Type"))
	if err != nil {
		issuer.WriteError(w, err)
		return
	}
	// Each offered credential is issued once per passport: reserve it
	// now, release it if issuing fails.
	e, err := a.transactions.reserve(authCtx.Subject, req.CredentialConfigurationID)
	switch {
	case errors.Is(err, errAlreadyIssued):
		writeCredentialError(w, "this credential has already been issued for this passport")
		return
	case err != nil:
		writeCredentialError(w, "the passport transaction for this access token has expired")
		return
	}
	issued := false
	defer func() {
		if issued {
			a.transactions.done(authCtx.Subject)
		} else {
			a.transactions.release(authCtx.Subject, req.CredentialConfigurationID)
		}
	}()

	// Both formats are always built from the same Evidence;
	// RequestCredential uses whichever the requested configuration
	// needs.
	opts := credential.Options{Now: a.now()}
	mdocClaims, err := credential.MdocClaims(e, opts)
	if err != nil {
		writeCredentialError(w, "this passport can't be issued: "+err.Error())
		return
	}
	sdjwtClaims, err := credential.SDJWTClaims(e, a.vct, opts)
	if err != nil {
		writeCredentialError(w, "this passport can't be issued: "+err.Error())
		return
	}

	req.SDJWTClaims, req.MdocClaims = sdjwtClaims, mdocClaims
	result, err := a.issuer.RequestCredential(r.Context(), issuer.AuthorizedRequest{
		ClientIdentity: issuer.KnownClientID(authCtx.ClientID), Scopes: authCtx.Scopes,
	}, req)
	if err != nil {
		issuer.WriteError(w, err)
		return
	}
	issued = true
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// writeCredentialError reports an issuance failure caused by the
// passport transaction rather than the request (§8.3.1.2's
// credential_request_denied).
func writeCredentialError(w http.ResponseWriter, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "credential_request_denied", "error_description": description,
	})
}

func (a *App) issuerMetadataHandler() http.HandlerFunc {
	return issuer.MetadataHandler(a.issuer, a.metadataSigner, oid4vci.ES256, a.metadataCert)
}

// handleVCTMetadata serves the SD-JWT VC type metadata document for
// this issuer's vct — display names for the credential and its claims.
func (a *App) handleVCTMetadata(w http.ResponseWriter, _ *http.Request) {
	claim := func(label string, path ...string) sdjwtvc.ClaimMetadata {
		return sdjwtvc.ClaimMetadata{Path: sdjwtvc.ClaimPath(path...), Display: []sdjwtvc.ClaimDisplay{{Lang: "en", Label: label}}}
	}
	doc := sdjwtvc.TypeMetadata{
		VCT:         a.vct,
		Name:        "Passport-derived credential (demo)",
		Description: "Identity attributes and raw ICAO data groups from a verified ePassport. Demo only.",
		Display: []sdjwtvc.TypeDisplay{{
			Lang: "en", Name: "Passport (demo)",
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
			claim("ICAO Document Security Object (raw)", credential.ICAOSOD),
			claim("ICAO DG1 — MRZ (raw)", credential.ICAODG1),
			claim("ICAO DG2 — facial image (raw)", credential.ICAODG2),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}
