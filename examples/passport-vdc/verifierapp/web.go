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
	// The pages people use are all under /demo/, so one access rule
	// (Cloudflare Access on the path, say) can guard them; /s/ is the
	// OpenID4VP surface wallets call, which must stay reachable.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/demo/", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /demo/{$}", a.handleHome)
	mux.HandleFunc("POST /demo/requests", a.handleCreateRequest)
	mux.HandleFunc("GET /demo/requests/{id}", a.handleRequestPage)
	mux.HandleFunc("POST /demo/requests/{id}/dcapi", a.handleDCAPIRequest)
	mux.HandleFunc("POST /demo/requests/{id}/dcapi/response", a.handleDCAPIResponse)
	// A browser can land on a form's or a page script's target with a
	// GET: Cloudflare Access, after a login, sends the visitor back to the
	// URL it interrupted. Each goes to the page it belongs to.
	mux.HandleFunc("GET /demo/requests", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/demo/", http.StatusSeeOther)
	})
	toRequest := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/demo/requests/"+url.PathEscape(r.PathValue("id")), http.StatusSeeOther)
	}
	mux.HandleFunc("GET /demo/requests/{id}/dcapi", toRequest)
	mux.HandleFunc("GET /demo/requests/{id}/dcapi/response", toRequest)
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
:root{--bg:#f6f8fa;--surface:#fff;--text:#1f2328;--muted:#57606a;--border:#d0d7de;--link:#0969da;
--btn-bg:#0969da;--btn-text:#fff;--focus:#0969da;--chip-bg:#eaeef2;--code-bg:#eaeef2;
--ok:#1a7f37;--ok-bg:#dafbe1;--bad:#cf222e;--bad-bg:#ffebe9;--warn-border:#9a6700;--warn-bg:#fff8c5}
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;max-width:48rem;margin:0 auto;padding:0 1rem 2rem;line-height:1.5;background:var(--bg);color:var(--text)}
a{color:var(--link)}h1{line-height:1.25}
table{border-collapse:collapse}th,td{text-align:left;padding:.3rem .75rem .3rem 0;vertical-align:top}
code{word-break:break-all;background:var(--code-bg);padding:0 .2em;border-radius:4px}
.ok{color:var(--ok)}.bad{color:var(--bad)}.note{color:var(--muted);font-size:.9em}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;margin:1rem 0}
.warn{border-color:var(--warn-border);background:var(--warn-bg)}
.site{display:flex;align-items:center;gap:.75rem;padding:1rem 0;margin-bottom:.5rem;border-bottom:1px solid var(--border)}
.site .rp-icon{font-size:2rem;line-height:1}.site p{margin:0}.site .rp-name{font-weight:700;font-size:1.1rem}
.site .rp-sub{color:var(--muted);font-size:.9em}.site .home-link{margin-left:auto;font-size:.9em;white-space:nowrap}
.badge{display:inline-block;border-radius:999px;padding:.05rem .6rem;font-size:.85em;font-weight:600;border:1px solid var(--border);background:var(--chip-bg);color:var(--text)}
.badge.ok{background:var(--ok-bg);color:var(--ok);border-color:transparent}.badge.bad{background:var(--bad-bg);color:var(--bad);border-color:transparent}
.chips{display:flex;flex-wrap:wrap;gap:.4rem;padding:0;margin:.5rem 0;list-style:none}
.chips li{background:var(--chip-bg);border-radius:999px;padding:.1rem .7rem;font-size:.9em}
.btn{display:inline-block;background:var(--btn-bg);color:var(--btn-text);border:1px solid var(--btn-bg);border-radius:8px;padding:.5rem 1rem;font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
.btn.secondary{background:transparent;color:var(--link);border-color:var(--border)}
.btn:disabled{opacity:.55;cursor:not-allowed}
.scenarios{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,20rem),1fr));gap:1rem}
.scenario{display:flex;flex-direction:column;margin:0}.scenario h2{margin:.1rem 0;font-size:1.2rem}
.scenario .who{margin:.2rem 0}.scenario .shows{flex:1}.scenario .btn{align-self:flex-start}
</style>
`

// pageParts are the templates every page shares: the header naming the
// scenario's relying party (or, given nil, the demo), and its trust
// badge.
const pageParts = `{{define "header"}}<header class="site">
{{if .}}<span class="rp-icon" aria-hidden="true">{{.Icon}}</span>
<div><p class="rp-name">{{.Verifier}}</p><p class="rp-sub">{{.Title}} · {{template "trust" .}}</p></div>
{{else}}<span class="rp-icon" aria-hidden="true">🛂</span>
<div><p class="rp-name">Passport credential verifier</p><p class="rp-sub">An OID4VCgo demo</p></div>{{end}}
<a class="home-link" href="/demo/">All scenarios</a>
</header>{{end}}
{{define "trust"}}{{if .Trusted}}<span class="badge ok">✓ Trusted verifier</span>{{else}}<span class="badge bad">✗ Untrusted — the wallet will refuse</span>{{end}}{{end}}`

const pageFoot = `
</body>
</html>
`

var homeTemplate = template.Must(template.New("home").Parse(pageParts + pageHead + `</head><body>
{{template "header"}}
<main>
<h1>Who's asking for your passport?</h1>
<p>Pick a business below. Each asks your wallet for something from your passport — from a single fact up to the whole passport — and decides what to do with the answer. Your wallet shows who's asking before you share anything.</p>
<div class="scenarios">
{{range .}}
<form method="post" action="/demo/requests" class="card scenario">
<h2><span aria-hidden="true">{{.Icon}}</span> {{.Title}}</h2>
<p class="who"><strong>{{.Verifier}}</strong> {{template "trust" .}}</p>
<ul class="chips" aria-label="What it asks for">{{range .Chips}}<li>{{.}}</li>{{end}}</ul>
<p class="shows">{{.Shows}}</p>
<button class="btn" name="scenario" value="{{.Scenario}}">Ask for this</button>
</form>
{{end}}
</div>
<p class="note">The wallet answers with its passport credential in whichever format it holds: <code>mso_mdoc</code> (an ISO mdoc Photo ID) or <code>dc+sd-jwt</code> (an SD-JWT VC). Each request accepts either.</p>
</main>
` + pageFoot))

type requestPage struct {
	Scenario ScenarioInfo
	Link     string // the cross-device request, for the QR code and the CLI wallet
	// DCAPI offers asking in this browser, over the Digital Credentials
	// API: not for a scenario taking several passports.
	DCAPI         bool
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

var requestTemplate = template.Must(template.New("request").Parse(pageHead + `{{if not (or .Outcome .Closed)}}<script>
// Refreshes until the wallet answers — a timer, not a meta refresh, so
// asking in this browser can stop it while the browser's prompt is up.
var refresh = setTimeout(function () { location.reload(); }, 2000);
</script>{{end}}
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
{{if .DCAPI}}<p><button type="button" id="dcapi">Verify with an ID in this browser</button> <span class="note">(the passport, over the Digital Credentials API: ISO's own protocol for Safari, OpenID4VP for Chrome)</span></p>
<p id="dcapi-status" class="note" role="status"></p>
<script>
document.getElementById("dcapi").addEventListener("click", async function () {
	var status = document.getElementById("dcapi-status");
	if (!("DigitalCredential" in window) || !navigator.credentials) {
		status.textContent = "This browser doesn't support the Digital Credentials API.";
		return;
	}
	clearTimeout(refresh);
	var base = location.pathname.replace(/\/$/, "");
	try {
		status.textContent = "Asking…";
		var r = await fetch(base + "/dcapi", {method: "POST"});
		if (!r.ok) throw new Error(await r.text());
		var offered = await r.json();
		var credential = await navigator.credentials.get({mediation: "required", digital: {requests: offered.requests}});
		var data = typeof credential.data === "string" ? JSON.parse(credential.data) : credential.data;
		if (data.error === "access_denied") throw new DOMException("declined", "AbortError");
		if (data.error) throw new Error("the wallet answered " + data.error);
		status.textContent = "Verifying…";
		var v = await fetch(base + "/dcapi/response", {
			method: "POST", headers: {"Content-Type": "application/json"},
			body: JSON.stringify({protocol: credential.protocol, response: data.response})
		});
		if (!v.ok) throw new Error(await v.text());
		location.reload();
	} catch (e) {
		// The holder declining: iOS's wallet cancels the request (an
		// AbortError, or NotAllowedError in some browsers), an OpenID4VP
		// wallet answers access_denied.
		status.textContent = (e.name === "AbortError" || e.name === "NotAllowedError")
			? "You declined, or the request was cancelled. Nothing was shared."
			: "Not verified: " + e.message;
		refresh = setTimeout(function () { location.reload(); }, 15000);
	}
});
</script>{{end}}
{{if .QR}}<p>On another device, scan:<br><img src="{{.QR}}" alt="QR code of the presentation request" width="296"></p>{{end}}
<p>Or give this request to the demo CLI wallet:</p>
<p><code>{{.Link}}</code></p>
{{if .LastError}}<p class="bad">✗ A response was rejected: {{.LastError}}. Still waiting for one that verifies.</p><p class="note">A rejected response isn't necessarily the holder's: anyone who has this request's QR code or link can send one, so it doesn't end the request.</p>{{end}}
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
<p><a href="/demo/">New request</a></p>
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
	http.Redirect(w, r, "/demo/requests/"+id, http.StatusSeeOther) // #nosec G710 -- local path + a server-generated random ID, not user input
}

func (a *App) handleRequestPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s, ok := a.session(id)
	if !ok || !sameBrowser(r, s) {
		// Expired, lost with a restart, or another browser's: the same
		// page for each, so it says nothing about other browsers'
		// requests.
		writeRequestEnded(w)
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
		AppLink: appLink(s.cross.link), DCAPI: !info.Multiple,
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
<p><a href="/demo/">New request</a></p>
` + pageFoot))

// requestEndedTemplate answers a request page that's gone, and returns
// to the home page after a few seconds.
var requestEndedTemplate = template.Must(template.New("ended").Parse(pageHead + `<meta http-equiv="refresh" content="5; url=/demo/"></head><body>
<h1>This request has ended</h1>
<p>It expired, or was opened in another browser. Start a new one from the verifier's home page.</p>
<p><a href="/demo/">Back to the verifier</a> (you'll be taken there in a few seconds)</p>
` + pageFoot))

func writeRequestEnded(w http.ResponseWriter) {
	w.Header().Set(headerContentType, contentTypeHTML)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	_ = requestEndedTemplate.Execute(w, nil)
}

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
