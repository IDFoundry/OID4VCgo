package issuerapp

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// Passports kept for refresh (OfferOptions.KeepForRefresh) are dropped
// at their deadline, when the wallet revokes its refresh token
// (handleTokenRevocation), or when someone forgets them on the /kept
// page (Forget).

// handleTokenRevocation is the token revocation endpoint (RFC 7009),
// where the wallet revokes its refresh token once it no longer holds a
// credential that uses it. Revoking a kept passport's token ends its
// grant, so the passport is dropped too. The wallet gets the same empty
// 200 whatever was revoked (§2.2).
func (a *App) handleTokenRevocation(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenRevocationRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	result, err := a.server.RevokeToken(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	if result.Revoked && result.GrantID != "" {
		// The grant ID is the transaction ID (grantFor,
		// issuePreAuthorizedRefreshToken).
		a.transactions.forget(result.GrantID)
	}
	w.WriteHeader(http.StatusOK)
}

// KeptEntry is a passport kept for refresh as the /kept page shows it:
// no passport data, only when it was uploaded, until when it's kept, and
// how many credentials it has issued.
type KeptEntry struct {
	Ref      string
	Uploaded time.Time
	Until    time.Time
	Issued   int
}

// Kept lists the passports kept for refresh, oldest first.
func (a *App) Kept() []KeptEntry {
	kept := a.transactions.kept()
	out := make([]KeptEntry, len(kept))
	for i, k := range kept {
		out[i] = KeptEntry{Ref: k.ref, Uploaded: k.uploaded, Until: k.until, Issued: k.issued}
	}
	return out
}

// errNotKept is returned by Forget for a reference no kept passport has.
var errNotKept = errors.New("issuerapp: no passport is kept under that reference")

// Forget drops the passport kept under ref (KeptEntry.Ref) now, revoking
// its refresh token first, so the wallet's next refresh is refused
// (invalid_grant) rather than finding no passport.
func (a *App) Forget(ctx context.Context, ref string) error {
	for _, k := range a.transactions.kept() {
		if k.ref != ref {
			continue
		}
		err := a.server.RevokeGrant(ctx, k.id)
		a.transactions.forget(k.id)
		if err != nil {
			return fmt.Errorf("issuerapp: the passport is forgotten, but revoking its refresh token failed: %w", err)
		}
		return nil
	}
	return errNotKept
}

var keptTemplate = template.Must(template.New("kept").Parse(pageHead + `
<h1>Passports kept for refresh</h1>
<p>A passport uploaded with "Keep for refresh" is kept for 24 hours after its first credential is issued, so the wallet can get fresh copies with its refresh token. It's deleted then, when the wallet deletes the credentials, or when you forget it here.</p>
{{if .}}
<table>
<tr><th>Uploaded</th><th>Kept until</th><th>Credentials issued</th><th></th></tr>
{{range .}}
<tr><td>{{.Uploaded.Format "2006-01-02 15:04:05"}}</td><td>{{.Until.Format "2006-01-02 15:04:05"}}</td><td>{{.Issued}}</td>
<td><form method="post" action="/demo/kept/forget"><input type="hidden" name="ref" value="{{.Ref}}"><button>Forget now</button></form></td></tr>
{{end}}
</table>
{{else}}
<p>No passport is kept for refresh.</p>
{{end}}
<p class="note">Demo only: anyone who can reach this page can forget a passport. It shows no names or document numbers.</p>
<p><a href="/demo/">Issue another</a> · <a href="/demo/status">Issued credentials</a></p>
` + pageFoot))

func (a *App) handleKeptPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(headerContentType, contentTypeHTML)
	w.Header().Set("Cache-Control", "no-store")
	_ = keptTemplate.Execute(w, a.Kept())
}

// handleForget forgets a kept passport. A cross-origin form post is
// refused, so another site can't forget one through a visitor's browser.
func (a *App) handleForget(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.cfg.IssuerURL {
		writeHTMLError(w, http.StatusForbidden, "cross-origin request refused")
		return
	}
	switch err := a.Forget(r.Context(), r.FormValue("ref")); {
	case errors.Is(err, errNotKept):
		writeHTMLError(w, http.StatusBadRequest, "that passport isn't kept any more")
		return
	case err != nil:
		writeHTMLError(w, http.StatusInternalServerError, "the passport is forgotten, but revoking its refresh token failed")
		return
	}
	http.Redirect(w, r, "/demo/kept", http.StatusSeeOther)
}
