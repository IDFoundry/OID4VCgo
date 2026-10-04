package verifierapp

import (
	"context"
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoqr"
)

// HTTP header names and values the pages use.
const (
	headerContentType = "Content-Type"
	contentTypeHTML   = "text/html; charset=utf-8"
)

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleHome)
	mux.HandleFunc("POST /requests", a.handleCreateRequest)
	mux.HandleFunc("GET /requests/{id}", a.handleRequestPage)
	// Each scenario's relying party has its own OpenID4VP endpoints.
	for sc, txs := range a.txs {
		base := "/s/" + string(sc)
		mux.Handle("GET "+base+"/request-objects/{id}", txs.RequestObjectHandler())
		mux.Handle("POST "+base+"/response", txs.ResponseHandler())
	}
	mux.HandleFunc("GET /s/{scenario}/continue", a.handleContinue)
	return mux
}

const pageHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Passport credential verifier (demo)</title>
<style>
body{font-family:system-ui,sans-serif;max-width:42rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
table{border-collapse:collapse}th,td{text-align:left;padding:.25rem .75rem .25rem 0;vertical-align:top}
code{word-break:break-all}.ok{color:#1a7f37}.bad{color:#cf222e}.note{color:#57606a;font-size:.9em}
.card{border:1px solid #d0d7de;border-radius:6px;padding:1rem;margin:1rem 0}
.portrait{max-width:10rem;border-radius:4px}
.scenario h2{margin:.2rem 0}.who{color:#57606a}.decision{font-size:1.4em}
.warn{border-color:#bf8700;background:#fff8c5}
</style>
`

const pageFoot = `
</body>
</html>
`

var homeTemplate = template.Must(template.New("home").Parse(pageHead + `</head><body>
<h1>Who's asking for your passport?</h1>
<p>Each card is a relying party asking a wallet for its passport-derived credential — as an <code>mso_mdoc</code> or a <code>dc+sd-jwt</code>, whichever it holds — for its own purpose. In order, they show what a verifier needs growing from one fact to the passport itself, and who is asking: a verifier the wallet trusts, or one it refuses outright.</p>
{{range .}}
<form method="post" action="/requests" class="card scenario">
<h2>{{.Icon}} {{.Title}}</h2>
<p class="who">{{.Verifier}} asks for {{.Asks}}.</p>
<p>{{.Shows}}</p>
<button name="scenario" value="{{.Scenario}}">Request</button>
</form>
{{end}}
` + pageFoot))

type requestPage struct {
	Scenario      ScenarioInfo
	Link          string // the cross-device request, for the QR code and the CLI wallet
	QR            template.URL
	WebWalletLink string // the same-device request, opened in the web wallet
	// AppLink is the cross-device request as a link a wallet app on this
	// device opens: its openid4vp: URL, which html/template won't put in
	// an href by itself.
	AppLink   template.URL
	Outcome   *Outcome
	Awaiting  bool // the same-device answer verified; waiting for the redirect back
	Closed    bool // answered and then rejected
	LastError string
	People    []personView // each credential presented
}

// personView is one presented credential, as the request page shows it.
type personView struct {
	Format, Status string
	Rows           [][2]string
	Portrait       template.URL // the disclosed portrait as a data: URL, if any
	ICAO           *ICAOResult
	ICAOPortrait   template.URL // the photo from the re-verified passport file, if any
}

var requestTemplate = template.Must(template.New("request").Parse(pageHead + `{{if not (or .Outcome .Closed)}}<meta http-equiv="refresh" content="2">{{end}}
</head><body>
<p class="who">{{.Scenario.Icon}} {{.Scenario.Title}} · <strong>{{.Scenario.Verifier}}</strong> asks for {{.Scenario.Asks}}.</p>
{{if .Closed}}
<h1 class="bad">✗ Presentation rejected</h1>
<p>{{.LastError}}.</p>
{{else if .Awaiting}}
<h1>The wallet has answered</h1>
<p>Waiting for it to bring you back here, in this browser — the answer is only accepted then.</p>
{{else if not .Outcome}}
<h1>Waiting for the wallet</h1>
{{if not .Scenario.Trusted}}<div class="card warn"><p><strong>{{.Scenario.Verifier}} isn't a verifier the demo wallets trust.</strong> It signs its requests with a certificate from a CA they don't recognise, so a wallet refuses this request without opening it — and sends nothing back. This page keeps waiting: nothing is shared.</p></div>{{end}}
{{if .WebWalletLink}}<p><a href="{{.WebWalletLink}}" target="_blank"><strong>Open in web wallet</strong></a> <span class="note">(on this device: it brings you back here)</span></p>{{end}}
{{if .AppLink}}<p><a href="{{.AppLink}}">Open in wallet app</a> <span class="note">(on this device; then come back to this page)</span></p>{{end}}
{{if .QR}}<p>On another device, scan:<br><img src="{{.QR}}" alt="QR code of the presentation request" width="296"></p>{{end}}
<p>Or give this request to the demo CLI wallet:</p>
<p><code>{{.Link}}</code></p>
{{if .LastError}}<p class="bad">✗ A response was rejected: {{.LastError}}. Still waiting for one that verifies.</p>{{end}}
<p class="note">This page refreshes until the wallet answers.</p>
{{else}}
<h1 class="decision {{if .Outcome.Decision.Approved}}ok{{else}}bad{{end}}">{{if .Outcome.Decision.Approved}}✓{{else}}✗{{end}} {{.Outcome.Decision.Text}}</h1>
<p>The wallet presented {{len .People}} {{if eq (len .People) 1}}credential{{else}}credentials{{end}}. Each issuer signature chains to the demo issuer's CA, and the holder proved possession of each credential's key.</p>
{{range .People}}
<div class="card person">
<p>As <code>{{.Format}}</code> · revocation status: {{if eq .Status "valid"}}<span class="ok">✓ valid</span> — checked against the issuer's status list{{else}}{{.Status}}{{end}}</p>
{{if .ICAO}}
<h2>Passport file re-verified</h2>
{{if .ICAO.Verified}}
<p class="ok">✓ gmrtd trusts the data: the SOD is signed by a Document Signer chaining to the issuing country's CSCA, and every data group matches its hash. The demo issuer can't have altered it.</p>
{{if .ICAOPortrait}}<p><img src="{{.ICAOPortrait}}" alt="Portrait from the passport's DG2" class="portrait"></p>{{end}}
<table>
<tr><th>Name</th><td>{{.ICAO.Identity.FamilyName}}, {{.ICAO.Identity.GivenNames}}</td></tr>
<tr><th>Nationality</th><td>{{.ICAO.Identity.Nationality}}</td></tr>
<tr><th>Issuing country</th><td>{{.ICAO.Identity.IssuingCountry}}</td></tr>
<tr><th>Passport expiry</th><td>{{.ICAO.Identity.ExpiryDate.Format "2006-01-02"}}{{if .ICAO.Expired}} <span class="bad">— expired</span>{{end}}</td></tr>
<tr><th>Chip authenticity</th><td>{{.ICAO.ChipAuthenticity}}</td></tr>
</table>
{{else}}
<p class="bad">✗ {{.ICAO.Error}}</p>
{{end}}
{{else}}
<h2>Disclosed claims</h2>
{{if .Portrait}}<p><img src="{{.Portrait}}" alt="Portrait of the credential holder" class="portrait"></p>{{end}}
<table>{{range .Rows}}<tr><th>{{index . 0}}</th><td>{{index . 1}}</td></tr>{{end}}</table>
{{end}}
</div>
{{end}}
{{if .Scenario.Evidence}}<p class="note">Re-verifying proves the passport data is authentic, not that the presenter holds the passport. Chip authenticity replays evidence recorded when the chip was read: a genuine chip answered then, not necessarily now. Tying the data to the presenter still relies on the issuer: it bound each credential's device key to its passport.</p>{{end}}
{{end}}
<p><a href="/">New request</a></p>
` + pageFoot))

func (a *App) handleHome(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(headerContentType, contentTypeHTML)
	_ = homeTemplate.Execute(w, ScenarioInfos())
}

// sessionCookie holds a browser's verifier session: the value the
// same-device redirect back must present (see handleContinue).
const sessionCookie = "passport_vdc_verifier_session"

// handleCreateRequest starts a request from the browser, bound to its
// session cookie (set here if it has none yet).
func (a *App) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	token := ""
	if c, err := r.Cookie(sessionCookie); err == nil && len(c.Value) >= 32 {
		token = c.Value
	} else if token, err = randomID(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	id, err := a.createSession(r.Context(), Scenario(r.PostForm.Get("scenario")), token)
	if err != nil {
		http.Error(w, "couldn't create a request", http.StatusBadRequest)
		return
	}
	// SameSite=Lax: the redirect back is a top-level navigation from the
	// wallet's page, on which Lax cookies are sent.
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/requests/"+id, http.StatusSeeOther) // #nosec G710 -- local path + a server-generated random ID, not user input
}

func (a *App) handleRequestPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s, ok := a.session(id)
	if !ok || !sameBrowser(r, s) {
		http.NotFound(w, r)
		return
	}
	page := a.requestPageFor(r.Context(), s)
	// The page carries the verified claims; keep it out of caches.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(headerContentType, contentTypeHTML)
	_ = requestTemplate.Execute(w, page)
}

// displayRows renders claims for the result page: raw byte values (the
// ICAO data groups) as their size, everything else as-is. The portrait
// is shown as an image instead (see requestPageFor).
func displayRows(claims map[string]any) [][2]string {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		if k == credential.Portrait || k == credential.SDJWTPicture {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([][2]string, 0, len(keys))
	for _, k := range keys {
		v := claims[k]
		switch x := v.(type) {
		case []byte:
			rows = append(rows, [2]string{k, fmt.Sprintf("%d bytes (raw)", len(x))})
		case string:
			if len(x) > 200 {
				rows = append(rows, [2]string{k, fmt.Sprintf("%d characters (raw, base64url)", len(x))})
				continue
			}
			rows = append(rows, [2]string{k, x})
		default:
			rows = append(rows, [2]string{k, fmt.Sprint(x)})
		}
	}
	return rows
}

// sameBrowser reports whether r comes from the browser that created s,
// when a browser did: the result is shown only there.
func sameBrowser(r *http.Request, s *session) bool {
	if s.browserToken == "" {
		return true
	}
	c, err := r.Cookie(sessionCookie)
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.browserToken)) == 1
}

// requestPageFor snapshots s for the request page.
func (a *App) requestPageFor(ctx context.Context, s *session) requestPage {
	st := a.state(ctx, s)
	info, _ := s.scenario.Info()
	page := requestPage{
		Scenario: info, Link: s.cross.link, Outcome: st.outcome, Awaiting: st.awaiting, Closed: st.closed, LastError: st.lastError,
		AppLink: appLink(s.cross.link),
	}
	if a.cfg.WebWalletURL != "" {
		sameDevice := s.cross.link
		if s.same.id != "" {
			sameDevice = s.same.link
		}
		page.WebWalletLink = a.cfg.WebWalletURL + "/present?request=" + url.QueryEscape(sameDevice)
	}
	if page.Outcome == nil {
		if qr, err := demoqr.DataURI(s.cross.link); err == nil {
			page.QR = qr
		}
		return page
	}
	people := page.Outcome.People
	if len(people) == 0 {
		people = []Person{{Format: page.Outcome.Format, Claims: page.Outcome.Claims, Status: page.Outcome.Status, ICAO: page.Outcome.ICAO}}
	}
	for _, p := range people {
		v := personView{Format: p.Format, Status: p.Status, Rows: displayRows(p.Claims), ICAO: p.ICAO}
		if uri, ok := credential.PortraitDataURI(p.Claims); ok {
			v.Portrait = template.URL(uri) // #nosec G203 -- built by PortraitDataURI from decoded JPEG bytes
		}
		if p.ICAO != nil && p.ICAO.Verified {
			if uri, ok := credential.PortraitDataURI(map[string]any{credential.Portrait: p.ICAO.Portrait}); ok {
				v.ICAOPortrait = template.URL(uri) // #nosec G203 -- built by PortraitDataURI from decoded JPEG bytes
			}
		}
		page.People = append(page.People, v)
	}
	return page
}

var errorTemplate = template.Must(template.New("error").Parse(pageHead + `</head><body>
<h1 class="bad">{{.}}</h1>
<p><a href="/">New request</a></p>
` + pageFoot))

func writeHTMLError(w http.ResponseWriter, status int, message string) {
	w.Header().Set(headerContentType, contentTypeHTML)
	w.WriteHeader(status)
	_ = errorTemplate.Execute(w, message)
}

// appLink is link as an href, when it's an OpenID4VP request link
// (openid4vp:): the one scheme the page links to besides https.
func appLink(link string) template.URL {
	if u, err := url.Parse(link); err != nil || u.Scheme != "openid4vp" {
		return ""
	}
	return template.URL(link) // #nosec G203 -- only an openid4vp: URL this verifier made, checked above
}
