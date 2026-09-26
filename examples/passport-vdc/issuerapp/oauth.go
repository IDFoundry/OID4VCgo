package issuerapp

import (
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// interactionLifetime bounds how long the approval page stays valid.
const interactionLifetime = 5 * time.Minute

// pendingInteraction links an approval page back to its fapigo
// interaction and the passport transaction it's for.
type pendingInteraction struct {
	handle server.InteractionHandle
	txID   string
	// scopes are the scopes the Wallet requested, recorded when the
	// approval page was shown and granted from here — never from the
	// submitted form.
	scopes []string
}

// handlePAR is the Pushed Authorization Request endpoint. On success it
// also records request_uri → transaction, from the request's
// issuer_state, since fapigo/server doesn't surface extension values
// at the authorization step.
func (a *App) handlePAR(w http.ResponseWriter, r *http.Request) {
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	result, err := a.server.PushAuthorizationRequest(r.Context(), server.PushAuthorizationRequest{
		HTTP: form, DPoPProofs: r.Header.Values("DPoP"), PeerCertificate: server.PeerCertificateFromHTTP(r),
		ClientAttestations:    r.Header.Values("OAuth-Client-Attestation"),
		ClientAttestationPoPs: r.Header.Values("OAuth-Client-Attestation-PoP"),
	})
	if err != nil {
		server.WriteError(w, err)
		return
	}
	// Only plain form parameters are read here: a wallet sending
	// issuer_state inside a signed request object isn't supported by
	// this demo (see the package doc).
	if state := form.Get(oid4vci.IssuerStateExtension.Name); state != "" {
		if _, ok := a.transactions.get(state); ok {
			a.requestURIs.put(result.RequestURI.String(), state, interactionLifetime)
		}
	}
	result.WriteJSON(w)
}

type approvalPage struct {
	Handle   string
	ClientID string
	Identity passport.Identity
	Scopes   []string
}

var approvalTemplate = template.Must(template.New("approval").Parse(pageHead + `
<h1>Issue passport credential?</h1>
<p>Wallet <code>{{.ClientID}}</code> is requesting a credential for:</p>
<table>
<tr><th>Name</th><td>{{.Identity.FamilyName}}, {{.Identity.GivenNames}}</td></tr>
<tr><th>Issuing country</th><td>{{.Identity.IssuingCountry}}</td></tr>
<tr><th>Document</th><td>{{.Identity.DocumentNumber}}</td></tr>
</table>
<p>Formats requested: {{range .Scopes}}<code>{{.}}</code> {{end}}</p>
<form method="post" action="/authorize/decision">
<input type="hidden" name="handle" value="{{.Handle}}">
<button name="decision" value="approve">Approve</button>
<button name="decision" value="deny">Deny</button>
</form>
<p class="note">Demo only: the holder is not authenticated here. Whoever holds the credential offer can redeem it.</p>
` + pageFoot))

// handleAuthorize begins authorization for a pushed request and, if
// it maps to a live transaction, shows the approval page.
func (a *App) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	action, err := a.server.BeginAuthorization(r.Context(), server.BeginAuthorizationRequest{
		RequestURI: q.Get("request_uri"), ClientID: fapi.ClientID(q.Get("client_id")),
	})
	if err != nil {
		writeHTMLError(w, http.StatusInternalServerError, "failed to begin authorization")
		return
	}
	switch action := action.(type) {
	case server.InteractionRequired:
		txID, ok := a.requestURIs.take(q.Get("request_uri"))
		if !ok {
			writeHTMLError(w, http.StatusBadRequest, "this authorization request isn't linked to a verified passport — start from a credential offer")
			return
		}
		e, ok := a.transactions.get(txID)
		if !ok {
			writeHTMLError(w, http.StatusBadRequest, "the passport transaction has expired — upload the passport again")
			return
		}
		handle := action.Handle.String()
		a.interactions.put(handle, pendingInteraction{handle: action.Handle, txID: txID, scopes: action.Interaction.Scope}, interactionLifetime)
		// Lets a headless wallet (the demo CLI, tests) approve without
		// scraping the page.
		w.Header().Set("X-Interaction-Handle", handle)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store") // shows the passport's identity
		_ = approvalTemplate.Execute(w, approvalPage{
			Handle: handle, ClientID: action.Interaction.ClientID.String(),
			Identity: e.Identity, Scopes: action.Interaction.Scope,
		})
	case server.RedirectResponse:
		http.Redirect(w, r, action.Destination.String(), http.StatusFound)
	case server.LocalErrorResponse:
		writeHTMLError(w, action.Error.HTTPStatus(), action.Error.PublicDescription())
	default:
		writeHTMLError(w, http.StatusInternalServerError, "unrecognized authorization action")
	}
}

// handleDecision completes an interaction, authorizing with the
// transaction ID as subject so the access token's sub identifies the
// passport to issue.
func (a *App) handleDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeHTMLError(w, http.StatusBadRequest, "malformed form")
		return
	}
	pending, ok := a.interactions.take(r.FormValue("handle"))
	if !ok {
		writeHTMLError(w, http.StatusBadRequest, "approval is unknown, expired or already used")
		return
	}
	txID := pending.txID

	var result server.InteractionResult
	switch r.FormValue("decision") {
	case "approve":
		subjectID, err := server.NewSubjectID(txID)
		if err != nil {
			writeHTMLError(w, http.StatusInternalServerError, "invalid subject")
			return
		}
		subject, err := server.NewAuthenticatedSubject(subjectID)
		if err != nil {
			writeHTMLError(w, http.StatusInternalServerError, "invalid subject")
			return
		}
		// No holder authentication happens in this demo, so the
		// authentication context names the demo and claims no
		// authentication method (amr).
		authCtx, err := server.NewAuthenticationContext(a.now(), "urn:idfoundry:passport-vdc:demo", nil)
		if err != nil {
			writeHTMLError(w, http.StatusInternalServerError, "invalid authentication context")
			return
		}
		result = server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: pending.scopes})
	case "deny":
		result = server.Deny("the holder declined")
	default:
		writeHTMLError(w, http.StatusBadRequest, "decision must be approve or deny")
		return
	}

	done, err := a.server.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{Handle: pending.handle, Result: result})
	if err != nil {
		writeHTMLError(w, http.StatusInternalServerError, "failed to complete authorization")
		return
	}
	switch v := done.(type) {
	case server.AuthorizationRedirect:
		http.Redirect(w, r, v.Destination().String(), http.StatusFound)
	case server.AuthorizationLocalError:
		writeHTMLError(w, v.Error.HTTPStatus(), v.Error.PublicDescription())
	default:
		writeHTMLError(w, http.StatusInternalServerError, "unrecognized authorization result")
	}
}

// handleToken is the Token Endpoint (authorization_code only; this demo
// issues no refresh tokens it would need to honor).
func (a *App) handleToken(w http.ResponseWriter, r *http.Request) {
	form, err := server.FormRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	if form.Get("grant_type") != "authorization_code" {
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "grant_type must be authorization_code").WriteJSON(w)
		return
	}
	result, err := a.server.ExchangeAuthorizationCode(r.Context(), server.AuthorizationCodeExchangeRequest{
		HTTP: form, DPoPProofs: r.Header.Values("DPoP"), PeerCertificate: server.PeerCertificateFromHTTP(r),
		ClientAttestations:    r.Header.Values("OAuth-Client-Attestation"),
		ClientAttestationPoPs: r.Header.Values("OAuth-Client-Attestation-PoP"),
	})
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

type authorizationServerMetadata struct {
	server.Metadata
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

func (a *App) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(authorizationServerMetadata{
		Metadata:                      a.server.Metadata(r.Context()),
		DPoPSigningAlgValuesSupported: server.RecommendedAlgorithmSet().Strings(),
	})
}

func (a *App) handleJWKS(w http.ResponseWriter, r *http.Request) {
	set, err := a.server.PublicJWKS(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}
