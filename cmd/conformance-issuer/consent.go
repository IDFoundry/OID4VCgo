package main

import (
	"html/template"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// consentPendingTTL bounds how long a stashed pendingAuthorization
// survives an abandoned consent page — matches FAPIgo's own
// cmd/conformance-as/authorize.go's identical constant/reasoning.
const consentPendingTTL = 5 * time.Minute

// consentHandler serves the browser-facing authorization endpoint with
// a genuine HTML consent form — mirrors FAPIgo's own
// cmd/conformance-as consentHandler, trimmed. The openid_credential
// authorization_details a request carries (Config.AuthorizationDetails)
// are granted as requested, each with a credential_identifier the
// consent mints (OpenID4VCI 1.0 §6.2).
type consentHandler struct {
	srv            *server.Server
	clients        storage.ClientRepository
	clock          server.Clock
	defaultSubject string
	pending        *pendingSet[string, pendingInteraction]
}

// pendingInteraction is what the consent form's decision completes: the
// interaction, and the authorization_details it requested.
type pendingInteraction struct {
	handle  server.InteractionHandle
	details extension.RARValues
}

func newConsentHandler(srv *server.Server, clients storage.ClientRepository, clock server.Clock, defaultSubject string) *consentHandler {
	return &consentHandler{
		srv: srv, clients: clients, clock: clock, defaultSubject: defaultSubject,
		pending: newPendingSet[string, pendingInteraction](clock),
	}
}

func (h *consentHandler) handleBegin(w http.ResponseWriter, r *http.Request) {
	// Refuses a repeated client_id or request_uri (RFC 6749 §3.1),
	// rendered here: no redirect for a request not yet tied to a client.
	req, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "malformed authorization request")
		return
	}
	q := r.URL.Query()
	action, err := h.srv.BeginAuthorization(r.Context(), req)
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to begin authorization")
		return
	}

	switch action := action.(type) {
	case server.InteractionRequired:
		h.pending.Put(action.Handle.String(), pendingInteraction{handle: action.Handle, details: action.Interaction.AuthorizationDetails}, consentPendingTTL)
		// Debug/test-support only, not security-relevant — mirrors
		// FAPIgo's own cmd/conformance-as identically: lets a smoke
		// test correlate a GET response with its interaction handle
		// without scraping the rendered HTML.
		w.Header().Set("X-Interaction-Handle", action.Handle.String())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = consentTemplate.Execute(w, consentPage{
			Handle: action.Handle.String(), ClientID: action.Interaction.ClientID.String(),
			Scopes: action.Interaction.Scope, LoginHint: string(action.Interaction.Hints.LoginHint),
			Subject: h.defaultSubject,
		})
	case server.RedirectResponse:
		http.Redirect(w, r, action.Destination.String(), http.StatusFound)
	case server.LocalErrorResponse:
		// See FAPIgo's own cmd/conformance-as/authorize.go for why a
		// trustworthy redirect_uri is preferred over a local page here
		// — the OIDF suite's own negative-test modules can only grade
		// an automated PASS on a redirected OAuth error, not a
		// rendered local page.
		clientID := fapi.ClientID(q.Get("client_id"))
		redirectURI := q.Get("redirect_uri")
		if redirectURI != "" {
			if client, resolveErr := h.clients.ResolveClient(r.Context(), clientID); resolveErr == nil && client.HasRedirectURI(redirectURI) {
				dest, buildErr := h.srv.BuildAuthorizationErrorRedirect(r.Context(), client, redirectURI, q.Get("state"),
					string(action.Error.Code()), action.Error.PublicDescription())
				if buildErr == nil {
					http.Redirect(w, r, dest.String(), http.StatusFound) // #nosec G710 -- dest is built from redirectURI only after client.HasRedirectURI matched it against the registry above, not raw user input
					return
				}
			}
		}
		writeLocalHTMLError(w, action.Error)
	default:
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "unrecognized authorization action")
	}
}

func (h *consentHandler) handleDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}
	pending, ok := h.pending.TakeOnce(r.FormValue("handle"))
	if !ok {
		writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "interaction handle is unknown, expired, or already used")
		return
	}
	subjectID, err := server.NewSubjectID(r.FormValue("subject"))
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "subject is required")
		return
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to build authenticated subject")
		return
	}
	// No real authentication happens here — this binary stands in for
	// a login/consent UI — so ACR/AMR are fixed placeholders, matching
	// FAPIgo's own identical stance.
	authCtx, err := server.NewAuthenticationContext(h.clock.Now(), "urn:mace:incommon:iap:silver", []string{"pwd"})
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to build authentication context")
		return
	}

	var result server.InteractionResult
	switch r.FormValue("decision") {
	case "approve":
		details, err := grantCredentialAuthorizationDetails(pending.details)
		if err != nil {
			writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "malformed authorization_details")
			return
		}
		result = server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: r.Form["scope"], AuthorizationDetails: details})
	case "deny":
		result = server.Deny("user denied the request")
	default:
		writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "decision must be approve or deny")
		return
	}

	authResult, err := h.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{Handle: pending.handle, Result: result})
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to complete authorization")
		return
	}
	switch v := authResult.(type) {
	case server.AuthorizationRedirect:
		// 303, not 302 or 307, after the consent form's POST (RFC 9700 §4.12).
		http.Redirect(w, r, v.Destination().String(), http.StatusSeeOther)
	case server.AuthorizationLocalError:
		writeLocalHTMLError(w, v.Error)
	default:
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "unrecognized authorization result")
	}
}

type consentPage struct {
	Handle    string
	ClientID  string
	Scopes    []string
	LoginHint string
	Subject   string
}

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html>
<head><title>Authorize {{.ClientID}}</title></head>
<body>
<h1>Authorize Access</h1>
<p>Client <strong>{{.ClientID}}</strong> is requesting access.</p>
{{if .LoginHint}}<p>The client suggested logging in as: {{.LoginHint}}</p>{{end}}
<form method="POST" action="/authorize/decision">
  <input type="hidden" name="handle" value="{{.Handle}}">
  <p><label>Subject: <input type="text" name="subject" value="{{.Subject}}"></label></p>
  <fieldset>
    <legend>Requested scopes</legend>
    {{range .Scopes}}
    <label><input type="checkbox" name="scope" value="{{.}}" checked> {{.}}</label><br>
    {{end}}
  </fieldset>
  <button type="submit" name="decision" value="approve">Approve</button>
  <button type="submit" name="decision" value="deny">Deny</button>
</form>
</body>
</html>
`))
