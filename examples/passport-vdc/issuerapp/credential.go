package issuerapp

import (
	"encoding/json"
	"io"
	"net/http"

	fapires "github.com/idfoundry/fapigo/resource"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// maxCredentialRequestBytes bounds a Credential Request body; a
// request only carries proofs, so this is generous.
const maxCredentialRequestBytes = 1 << 18

type wireCredentialRequest struct {
	CredentialConfigurationID string              `json:"credential_configuration_id"`
	CredentialIdentifier      string              `json:"credential_identifier"`
	Proofs                    map[string][]string `json:"proofs"`
}

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
	e, ok := a.transactions.get(authCtx.Subject)
	if !ok {
		writeCredentialError(w, "the passport transaction for this access token has expired")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxCredentialRequestBytes+1))
	if err != nil || len(body) > maxCredentialRequestBytes {
		http.Error(w, "credential request is unreadable or too large", http.StatusBadRequest)
		return
	}
	var wire wireCredentialRequest
	if err := json.Unmarshal(body, &wire); err != nil {
		http.Error(w, "malformed credential request", http.StatusBadRequest)
		return
	}

	// Both formats are always built from the same Evidence;
	// RequestCredential uses whichever the requested configuration
	// needs.
	opts := credential.Options{Now: a.now(), Issuer: a.cfg.IssuerURL}
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

	result, err := a.issuer.RequestCredential(r.Context(), issuer.AuthorizedRequest{
		ClientIdentity: issuer.KnownClientID(authCtx.ClientID), Scopes: authCtx.Scopes,
	}, issuer.CredentialRequest{
		CredentialConfigurationID: wire.CredentialConfigurationID,
		CredentialIdentifier:      wire.CredentialIdentifier,
		Proofs:                    wire.Proofs,
		SDJWTClaims:               sdjwtClaims,
		MdocClaims:                mdocClaims,
	})
	if err != nil {
		issuer.WriteError(w, err)
		return
	}
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
	claim := func(path []string, label string) map[string]any {
		pathAny := make([]any, len(path))
		for i, p := range path {
			pathAny[i] = p
		}
		return map[string]any{"path": pathAny, "display": []map[string]string{{"lang": "en", "label": label}}}
	}
	doc := map[string]any{
		"vct":         a.vct,
		"name":        "Passport-derived credential (demo)",
		"description": "Identity attributes and raw ICAO data groups from a verified ePassport. Demo only.",
		"display": []map[string]any{{
			"lang": "en", "name": "Passport (demo)",
			"description": "Issued by the IDFoundry passport-vdc demo from a verified ePassport",
		}},
		"claims": []map[string]any{
			claim([]string{credential.FamilyName}, "Family name"),
			claim([]string{credential.GivenName}, "Given names"),
			claim([]string{credential.SDJWTBirthDate}, "Date of birth"),
			claim([]string{credential.SDJWTNationalities}, "Nationality"),
			claim([]string{credential.IssuingCountry}, "Issuing country"),
			claim([]string{credential.DocumentNumber}, "Document number"),
			claim([]string{credential.ExpiryDate}, "Passport expiry"),
			claim([]string{credential.Sex}, "Sex"),
			claim([]string{credential.ICAOSOD}, "ICAO Document Security Object (raw)"),
			claim([]string{credential.ICAODG1}, "ICAO DG1 — MRZ (raw)"),
			claim([]string{credential.ICAODG2}, "ICAO DG2 — facial image (raw)"),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}
