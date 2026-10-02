package issuerapp

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/server/interactioncookie"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// pendingInteraction links an approval page back to its fapigo
// interaction and the passport transaction it's for. It's read back from
// the browser's sealed interaction cookie (interactioncookie), never
// from the submitted form.
type pendingInteraction struct {
	handle server.InteractionHandle
	txID   string
	// scopes are the scopes the Wallet requested, granted from here.
	scopes []string
}

// interactionFromCookie restores the interaction this browser began:
// the handle, and the transaction from the request's issuer_state. The
// cookie is sealed, so neither can be swapped for another holder's.
func (a *App) interactionFromCookie(r *http.Request) (pendingInteraction, error) {
	handle, in, err := a.consent.Read(r, a.now())
	if err != nil {
		return pendingInteraction{}, err
	}
	txID, ok := extension.Get(in.Extensions, oid4vci.IssuerStateExtension)
	if !ok {
		return pendingInteraction{}, interactioncookie.ErrNoInteraction
	}
	return pendingInteraction{handle: handle, txID: txID, scopes: in.Scope}, nil
}

// handlePAR is the Pushed Authorization Request endpoint.
func (a *App) handlePAR(w http.ResponseWriter, r *http.Request) {
	req, err := server.PushAuthorizationRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	result, err := a.server.PushAuthorizationRequest(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

// approvalPage shows no passport data: it's reached by anyone holding
// the offer link and an attested wallet, before the confirmation code
// is checked. Whoever approves saw the passport on the offer page.
type approvalPage struct {
	ClientID string
	Scopes   []string
	Error    string
}

var approvalTemplate = template.Must(template.New("approval").Parse(pageHead + `
<h1>Issue passport credential?</h1>
<p>Wallet <code>{{.ClientID}}</code> is requesting credentials for the passport uploaded on the offer page.</p>
<p>Formats requested: {{range .Scopes}}<code>{{.}}</code> {{end}}</p>
{{if .Error}}<p class="warn">{{.Error}}</p>{{end}}
<form method="post" action="/authorize/decision">
<p><label>Confirmation code shown with the offer: <input name="code" inputmode="numeric" autocomplete="off" maxlength="6" size="8"></label></p>
<button name="decision" value="approve">Approve</button>
<button name="decision" value="deny">Deny</button>
</form>
<p class="note">Demo only: the holder is not authenticated here. The code only shows whoever approves saw the offer page.</p>
` + pageFoot))

// handleAuthorize begins authorization for a pushed request and, if
// it maps to a live transaction, shows the approval page.
func (a *App) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Refuses a repeated client_id or request_uri (RFC 6749 §3.1),
	// rendered here: no redirect for a request not yet tied to a client.
	req, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "malformed authorization request")
		return
	}
	action, err := a.server.BeginAuthorization(r.Context(), req)
	if err != nil {
		writeHTMLError(w, http.StatusInternalServerError, "failed to begin authorization")
		return
	}
	switch action := action.(type) {
	case server.InteractionRequired:
		// The Wallet echoed the offer's issuer_state — the transaction
		// ID — in its pushed request.
		txID, ok := extension.Get(action.Interaction.Extensions, oid4vci.IssuerStateExtension)
		if !ok {
			writeHTMLError(w, http.StatusBadRequest, "this authorization request isn't linked to a verified passport — start from a credential offer")
			return
		}
		if _, err := a.transactions.unclaimed(txID); err != nil {
			writeHTMLError(w, http.StatusBadRequest, transactionErrorMessage(err))
			return
		}
		// The interaction travels with this browser, sealed: the approval
		// can only be submitted from it, and nothing is kept here.
		if err := a.consent.Set(w, action.Handle, action.Interaction, a.now()); err != nil {
			writeHTMLError(w, http.StatusInternalServerError, "failed to begin authorization")
			return
		}
		pending := pendingInteraction{handle: action.Handle, txID: txID, scopes: action.Interaction.Scope}
		a.renderApproval(w, pending, action.Interaction.ClientID.String(), "")
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
	// The interaction cookie is the approval's only state, so refuse a
	// form another site posts (SameSite=Lax keeps the cookie off
	// cross-site POSTs too).
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.cfg.IssuerURL {
		writeHTMLError(w, http.StatusForbidden, "cross-origin approval refused")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeHTMLError(w, http.StatusBadRequest, "malformed form")
		return
	}
	pending, err := a.interactionFromCookie(r)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "no approval is in progress in this browser — it expired, was already used, or began in another browser")
		return
	}
	txID := pending.txID

	var result server.InteractionResult
	switch r.FormValue("decision") {
	case "approve":
		if !a.claimTransaction(w, pending, r.FormValue("code")) {
			return
		}
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

	// Whatever the outcome, this interaction is over.
	a.consent.Clear(w)
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

// claimTransaction redeems pending's transaction with code. On a wrong
// code it shows the approval page again, still pending, to retry; on
// any other failure an error page. It reports whether to go on and
// authorize.
func (a *App) claimTransaction(w http.ResponseWriter, pending pendingInteraction, code string) bool {
	err := a.transactions.claim(pending.txID, code)
	if err == nil {
		return true
	}
	if errors.Is(err, errWrongCode) {
		if _, err := a.transactions.unclaimed(pending.txID); err == nil {
			// The interaction cookie stays, for another try.
			a.renderApproval(w, pending, a.cfg.Wallet.ClientID, "That confirmation code is wrong — check the offer page and try again.")
			return false
		}
	}
	writeHTMLError(w, http.StatusBadRequest, transactionErrorMessage(err))
	return false
}

func (a *App) renderApproval(w http.ResponseWriter, pending pendingInteraction, clientID string, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = approvalTemplate.Execute(w, approvalPage{
		ClientID: clientID, Scopes: pending.scopes, Error: message,
	})
}

// transactionErrorMessage words a transactions error for the holder.
func transactionErrorMessage(err error) string {
	switch {
	case errors.Is(err, errAlreadyRedeemed):
		return "this credential offer has already been redeemed — each offer works once, for one wallet"
	case errors.Is(err, errTooManyWrongCodes):
		return "too many wrong confirmation codes — this offer is void; upload the passport again"
	default:
		return "the passport transaction has expired — upload the passport again"
	}
}

// handleToken is the Token Endpoint (authorization_code only; this demo
// issues no refresh tokens it would need to honor).
// handleASMetadata serves the Authorization Server's RFC 8414 metadata —
// server.Metadata, dpop_signing_alg_values_supported included.
func (a *App) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.server.Metadata(r.Context()))
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
