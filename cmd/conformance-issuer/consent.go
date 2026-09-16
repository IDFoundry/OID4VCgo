package main

import (
	"html/template"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// consentPendingTTL bounds how long a stashed pendingAuthorization
// survives an abandoned consent page — matches FAPIgo's own
// cmd/conformance-as/authorize.go's identical constant/reasoning.
const consentPendingTTL = 5 * time.Minute

// consentHandler serves the browser-facing authorization endpoint with
// a genuine HTML consent form — mirrors FAPIgo's own
// cmd/conformance-as consentHandler, trimmed: this binary's one
// CredentialConfiguration needs no Rich Authorization Requests
// support, so there's no AuthorizationDetails plumbing to carry
// through the pending set.
type consentHandler struct {
	srv            *server.Server
	clients        storage.ClientRepository
	clock          server.Clock
	defaultSubject string
	pending        *pendingSet[string, server.InteractionHandle]
}

func newConsentHandler(srv *server.Server, clients storage.ClientRepository, clock server.Clock, defaultSubject string) *consentHandler {
	return &consentHandler{
		srv: srv, clients: clients, clock: clock, defaultSubject: defaultSubject,
		pending: newPendingSet[string, server.InteractionHandle](clock),
	}
}

func (h *consentHandler) handleBegin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	action, err := h.srv.BeginAuthorization(r.Context(), server.BeginAuthorizationRequest{
		RequestURI: q.Get("request_uri"),
		ClientID:   fapi.ClientID(q.Get("client_id")),
	})
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to begin authorization")
		return
	}

	switch action := action.(type) {
	case server.InteractionRequired:
		h.pending.Put(action.Handle.String(), action.Handle, consentPendingTTL)
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
	handle, ok := h.pending.TakeOnce(r.FormValue("handle"))
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
		result = server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: r.Form["scope"]})
	case "deny":
		result = server.Deny("user denied the request")
	default:
		writeLocalHTMLErrorRaw(w, http.StatusBadRequest, "invalid_request", "decision must be approve or deny")
		return
	}

	authResult, err := h.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{Handle: handle, Result: result})
	if err != nil {
		writeLocalHTMLErrorRaw(w, http.StatusInternalServerError, "server_error", "failed to complete authorization")
		return
	}
	switch v := authResult.(type) {
	case server.AuthorizationRedirect:
		http.Redirect(w, r, v.Destination().String(), http.StatusFound)
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
