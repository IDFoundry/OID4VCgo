package verifierapp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"

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
	mux.HandleFunc("GET /demo/requests/{id}/status", a.handleRequestStatus)
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
.respond h2{margin-top:0;font-size:1.2rem}.options{display:flex;flex-direction:column;gap:1rem}
.option{border-top:1px solid var(--border);padding-top:.75rem}.option h3{margin:0 0 .5rem;font-size:1.05rem}
.option .actions{display:flex;flex-wrap:wrap;gap:.5rem;margin:.5rem 0}
.opt-qr{text-align:center}.opt-qr .qr{width:min(100%,296px);height:auto;background:#fff;padding:8px;border-radius:8px;border:1px solid var(--border)}
@media (hover:none) and (pointer:coarse){.opt-device{order:-1}}
.progress p{margin:.25rem 0}#live{font-weight:600}
.spinner{display:inline-block;width:1em;height:1em;vertical-align:-.15em;border:.18em solid var(--border);border-top-color:var(--link);border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.spinner{animation-duration:3s}}
details.cli summary{cursor:pointer;font-weight:600}
.verdict{display:flex;align-items:center;gap:1rem;border-radius:12px;padding:1rem 1.25rem;margin:1rem 0;border:2px solid}
.verdict.approved{background:var(--ok-bg);border-color:var(--ok)}.verdict.refused{background:var(--bad-bg);border-color:var(--bad)}
.verdict .mark{font-size:3rem;line-height:1;margin:0;font-weight:700}.verdict.approved .mark{color:var(--ok)}.verdict.refused .mark{color:var(--bad)}
.verdict h1{margin:0 0 .4rem;font-size:1.5rem}.verdict h1:focus{outline:none}.verdict h1:focus-visible{outline:3px solid var(--focus);outline-offset:4px}
.badges{display:flex;flex-wrap:wrap;gap:.4rem;margin:.25rem 0}
.person h2{margin-top:0;font-size:1.2rem}.person h3{font-size:1rem;margin:1rem 0 .4rem}
.person-body{display:flex;flex-wrap:wrap;gap:1rem;align-items:flex-start}
.portrait{width:9rem;max-width:100%;height:auto;border-radius:8px;border:1px solid var(--border)}
.claims{flex:1 1 16rem}.claims th{color:var(--muted);font-weight:600;white-space:nowrap}
.asked{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,14rem),1fr));gap:0 1rem}
.asked .missing{background:var(--warn-bg);color:var(--text)}
details.raw summary{cursor:pointer;color:var(--muted)}details.raw td{word-break:break-all}
.actions{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin:1.25rem 0}.actions form{margin:0}
.visually-hidden{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
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

	// State and Rejected are what the status endpoint reports now
	// (requestStatus): the page reloads when either changes.
	State    string
	Rejected bool
	// Polling: the page waits for the wallet, polling its status.
	Polling bool
	// ExpiresIn is how long until the request expires, in seconds, and
	// ExpiresInMinutes the same rounded up.
	ExpiresIn, ExpiresInMinutes int

	// Formats are the formats presented, each once; AllValid is whether
	// every credential's revocation status is "valid", and
	// StatusSummary the statuses otherwise.
	Formats       []string
	AllValid      bool
	StatusSummary string
}

// personView is one presented credential, as the request page shows it.
type personView struct {
	// Heading names the credential: for a scenario taking several,
	// "Person N" and, where it's known, the name.
	Heading        string
	Format, Status string
	// Rows are the holder's disclosed claims, and Raw the credential's
	// own and the raw ones, which the page collapses (displayRows).
	Rows, Raw []claimRow
	// Asked is what the scenario asked of this credential's format;
	// Received, what it disclosed; Unasked, what it disclosed unasked
	// (none: the verifier refuses an answer disclosing unrequested
	// claims).
	Asked             []requested
	Received, Unasked []string
	Portrait          template.URL // the disclosed portrait as a data: URL, if any
	ICAO              *ICAOResult
	ICAOPortrait      template.URL // the photo from the re-verified passport file, if any
}

// waitingScript polls the page's status (handleRequestStatus) every two
// seconds while it waits, reloading the page only when the request's
// state changes, and counts down to its expiry. Asking in this browser
// pauses it while the browser's prompt is up (verifierPolling).
const waitingScript = `<script>
(function () {
	var statusURL = location.pathname.replace(/\/$/, "") + "/status";
	var current = {{.State}}, rejected = {{.Rejected}};
	var live = document.getElementById("live"), expiry = document.getElementById("expiry");
	var deadline = Date.now() + {{.ExpiresIn}} * 1000;
	var paused = false, done = false, timer;
	function changed(text) {
		done = true;
		live.textContent = text;
		setTimeout(function () { location.reload(); }, 500);
	}
	function schedule() {
		clearTimeout(timer);
		if (!paused && !done) timer = setTimeout(poll, 2000);
	}
	function poll() {
		if (paused || done) return;
		fetch(statusURL, {cache: "no-store", credentials: "same-origin"}).then(function (r) {
			if (paused) return;
			if (r.status === 404) return changed("This request has ended.");
			if (!r.ok) throw new Error("status " + r.status);
			return r.json().then(function (s) {
				if (paused) return;
				if (s.state !== current) {
					return changed(s.state === "answered" ? "The wallet answered. Showing the result…"
						: s.state === "awaiting" ? "The wallet answered. Waiting for it to bring you back…"
						: "The request was closed.");
				}
				if (s.rejected !== rejected) return changed("A response was rejected.");
				if (typeof s.expires_in === "number") deadline = Date.now() + s.expires_in * 1000;
				schedule();
			});
		}).catch(schedule);
	}
	function tick() {
		var left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
		if (expiry) {
			expiry.textContent = left > 0
				? "This request expires in " + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0") + "."
				: "This request has expired.";
		}
		if (left === 0 && !paused && !done) return changed("This request has expired.");
		setTimeout(tick, 1000);
	}
	window.verifierPolling = {
		pause: function () { paused = true; clearTimeout(timer); },
		resume: function () { if (paused) { paused = false; schedule(); } }
	};
	schedule();
	tick();
})();
</script>`

// dcapiScript asks in this browser, over the Digital Credentials API,
// when it supports the API: the button stays disabled, with the reason,
// when it doesn't (or without JavaScript).
const dcapiScript = `<script>
(function () {
	var button = document.getElementById("dcapi"), status = document.getElementById("dcapi-status");
	var support = document.getElementById("dcapi-support");
	if (!("DigitalCredential" in window) || !navigator.credentials) {
		support.textContent = "Not available: this browser doesn't support the Digital Credentials API.";
		return;
	}
	button.disabled = false;
	support.textContent = "Your passport credential, over the Digital Credentials API: ISO's own protocol for Safari, OpenID4VP for Chrome.";
	button.addEventListener("click", async function () {
		window.verifierPolling && verifierPolling.pause();
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
			window.verifierPolling && verifierPolling.resume();
		}
	});
})();
</script>`

// copyScript offers copying the request link, where the browser can.
const copyScript = `<script>
(function () {
	var button = document.getElementById("copy-link");
	if (!button || !navigator.clipboard) return;
	button.hidden = false;
	button.addEventListener("click", function () {
		var status = document.getElementById("copy-status");
		navigator.clipboard.writeText(document.getElementById("cli-link").textContent).then(
			function () { status.textContent = "Copied."; },
			function () { status.textContent = "Couldn't copy: select the link instead."; });
	});
})();
</script>`

var requestTemplate = template.Must(template.New("request").Parse(pageParts + progressPart + pageHead +`{{if .Polling}}<noscript><meta http-equiv="refresh" content="2"></noscript>{{end}}
</head><body>
{{template "header" .Scenario}}
<main>
{{if .Closed}}
<h1 class="bad">✗ Presentation rejected</h1>
<p>{{.LastError}}.</p>
{{else if .Awaiting}}
<h1>The wallet has answered</h1>
<p>Waiting for it to bring you back here, in this browser — the answer is only accepted then.</p>
{{template "progress" .}}
{{else if not .Outcome}}
<h1>Waiting for the wallet</h1>
<p><strong>{{.Scenario.Verifier}}</strong> asks for {{.Scenario.Asks}}.</p>
{{if not .Scenario.Trusted}}<div class="card warn"><p><strong>{{.Scenario.Verifier}} isn't a verifier the demo wallets trust.</strong> It signs its requests with a certificate from a CA they don't recognise, so a wallet refuses this request without opening it — and sends nothing back. This page keeps waiting: nothing is shared.</p></div>{{end}}
<section class="card respond" aria-labelledby="respond-heading">
<h2 id="respond-heading">Choose how to respond</h2>
<div class="options">
{{if .QR}}<section class="option opt-qr" aria-labelledby="opt-qr">
<h3 id="opt-qr"><span aria-hidden="true">📷</span> Scan with a phone</h3>
<img src="{{.QR}}" alt="QR code of the presentation request, for a wallet on another device" class="qr" width="296" height="296">
<p class="note">Scan it with your wallet app, or the phone's camera.</p>
</section>{{end}}
{{if or .AppLink .WebWalletLink}}<section class="option opt-device" aria-labelledby="opt-device">
<h3 id="opt-device"><span aria-hidden="true">📲</span> Use a wallet on this device</h3>
<p class="actions">{{if .AppLink}}<a href="{{.AppLink}}" class="btn">Open in wallet app</a>{{end}}
{{if .WebWalletLink}}<a href="{{.WebWalletLink}}" target="_blank" class="btn secondary">Open in web wallet</a>{{end}}</p>
<p class="note">The web wallet brings you back here; after the wallet app, come back to this page.</p>
</section>{{end}}
{{if .DCAPI}}<section class="option opt-browser" aria-labelledby="opt-browser">
<h3 id="opt-browser"><span aria-hidden="true">🌐</span> Use this browser's ID</h3>
<p class="actions"><button type="button" class="btn" id="dcapi" disabled>Verify with an ID in this browser</button></p>
<p id="dcapi-support" class="note">Needs JavaScript and a browser supporting the Digital Credentials API.</p>
<p id="dcapi-status" class="note" role="status"></p>
</section>{{end}}
</div>
</section>
{{template "progress" .}}
{{if .LastError}}<div class="card error-card"><p class="bad">✗ A response was rejected: {{.LastError}}. Still waiting for one that verifies.</p><p class="note">A rejected response isn't necessarily the holder's: anyone who has this request's QR code or link can send one, so it doesn't end the request.</p></div>{{end}}
<details class="card cli">
<summary>For the demo CLI wallet</summary>
<p>Give it this request, as <code>go run ./cmd/wallet present -state .demo-state '…'</code>:</p>
<p><code id="cli-link">{{.Link}}</code></p>
<p><button type="button" class="btn secondary" id="copy-link" hidden>Copy link</button> <span id="copy-status" class="note" role="status"></span></p>
</details>
{{if .DCAPI}}` + dcapiScript + `{{end}}
` + copyScript + `
{{else}}
<section class="verdict {{if .Outcome.Decision.Approved}}approved{{else}}refused{{end}}">
<p class="mark" aria-hidden="true">{{if .Outcome.Decision.Approved}}✓{{else}}✗{{end}}</p>
<div>
<h1 id="verdict" tabindex="-1"><span class="visually-hidden">{{if .Outcome.Decision.Approved}}Approved: {{else}}Refused: {{end}}</span>{{.Outcome.Decision.Text}}</h1>
<p class="badges">{{range .Formats}}<span class="badge">{{.}}</span> {{end}}{{if .AllValid}}<span class="badge ok">✓ Not revoked</span>{{else}}<span class="badge">Revocation: {{.StatusSummary}}</span>{{end}} <span class="badge"><span aria-hidden="true">{{.Scenario.Icon}}</span> {{.Scenario.Verifier}}</span></p>
</div>
</section>
<p>The wallet presented {{len .People}} {{if eq (len .People) 1}}credential{{else}}credentials{{end}}. Each issuer signature chains to the demo issuer's CA, and the holder proved possession of each credential's key.{{if .AllValid}} None is revoked: each was checked against the issuer's status list.{{end}}</p>
{{range $i, $p := .People}}
<section class="card person" aria-labelledby="person-{{$i}}">
<h2 id="person-{{$i}}">{{.Heading}}</h2>
<p class="badges"><span class="badge">{{.Format}}</span> {{if eq .Status "valid"}}<span class="badge ok">✓ Not revoked</span>{{else}}<span class="badge">Revocation: {{.Status}}</span>{{end}}</p>
{{if .ICAO}}
<h3>Passport file re-verified</h3>
{{if .ICAO.Verified}}
<p class="ok">✓ gmrtd trusts the data: the SOD is signed by a Document Signer chaining to the issuing country's CSCA, and every data group matches its hash. The demo issuer can't have altered it.</p>
<div class="person-body">
{{if .ICAOPortrait}}<img src="{{.ICAOPortrait}}" alt="Portrait from the passport's chip (DG2)" class="portrait">{{end}}
<table class="claims">
<tr><th scope="row">Name</th><td>{{.ICAO.Identity.FamilyName}}, {{.ICAO.Identity.GivenNames}}</td></tr>
<tr><th scope="row">Nationality</th><td>{{.ICAO.Identity.Nationality}}</td></tr>
<tr><th scope="row">Issuing country</th><td>{{.ICAO.Identity.IssuingCountry}}</td></tr>
<tr><th scope="row">Passport expiry</th><td>{{.ICAO.Identity.ExpiryDate.Format "2 January 2006"}}{{if .ICAO.Expired}} <span class="bad">— expired</span>{{end}}</td></tr>
<tr><th scope="row">Chip authenticity</th><td>{{.ICAO.ChipAuthenticity}}</td></tr>
</table>
</div>
{{else}}
<p class="bad">✗ {{.ICAO.Error}}</p>
{{end}}
{{end}}
{{if .Asked}}<div class="asked">
<div><h3>Asked for</h3><ul class="chips">{{range .Asked}}<li{{if not .Received}} class="missing"{{end}}>{{if .Received}}✓{{else}}✗{{end}} {{.Label}}{{if not .Received}} — not shared{{end}}</li>{{end}}</ul></div>
<div><h3>Received</h3><ul class="chips">{{range .Received}}<li>{{.}}</li>{{else}}<li>Nothing</li>{{end}}</ul>
{{if .Unasked}}<p class="bad">✗ Also received, without asking: {{range $j, $l := .Unasked}}{{if $j}}, {{end}}{{$l}}{{end}}.</p>{{end}}</div>
</div>{{end}}
{{if or .Rows .Portrait}}
<h3>Disclosed claims</h3>
<div class="person-body">
{{if .Portrait}}<img src="{{.Portrait}}" alt="Portrait of the credential holder" class="portrait">{{end}}
<table class="claims">{{range .Rows}}<tr><th scope="row">{{.Label}}</th><td>{{.Value}}</td></tr>{{end}}</table>
</div>
{{end}}
{{if .Raw}}<details class="raw"><summary>Credential details and raw data</summary>
<table class="claims">{{range .Raw}}<tr><th scope="row">{{.Label}}</th><td>{{.Value}}</td></tr>{{end}}</table>
</details>{{end}}
</section>
{{end}}
{{if .Scenario.Evidence}}<p class="note">Re-verifying proves the passport data is authentic, not that the presenter holds the passport. Chip authenticity replays evidence recorded when the chip was read: a genuine chip answered then, not necessarily now. Tying the data to the presenter still relies on the issuer: it bound each credential's device key to its passport.</p>{{end}}
<script>document.getElementById("verdict").focus();</script>
{{end}}
{{if or .Outcome .Closed}}<div class="actions">
<form method="post" action="/demo/requests"><button class="btn" name="scenario" value="{{.Scenario.Scenario}}">Try again</button></form>
<a href="/demo/" class="btn secondary">New request</a>
</div>{{else}}<p><a href="/demo/">New request</a></p>{{end}}
</main>
{{if .Polling}}` + waitingScript + `{{end}}
` + pageFoot))

// progressPart is the waiting page's progress: a status region the
// polling script announces state changes in, and the request's expiry.
const progressPart = `{{define "progress"}}<div class="card progress">
<p id="live" role="status" aria-live="polite"><span class="spinner" aria-hidden="true"></span> {{if .Awaiting}}Waiting for the wallet to bring you back…{{else}}Waiting for the wallet…{{end}}</p>
<p id="expiry" class="note">This request expires in about {{.ExpiresInMinutes}} {{if eq .ExpiresInMinutes 1}}minute{{else}}minutes{{end}}.</p>
</div>{{end}}`

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

// A request's coarse states, as its status endpoint reports them.
const (
	stateWaiting  = "waiting"  // no answer yet
	stateAwaiting = "awaiting" // same-device: verified, waiting for the redirect back
	stateAnswered = "answered" // answered: the page shows the result
	stateClosed   = "closed"   // answered and then rejected
	stateEnded    = "ended"    // expired, unknown, or another browser's
)

// coarse is st as one of the coarse states.
func (st pageState) coarse() string {
	switch {
	case st.outcome != nil:
		return stateAnswered
	case st.closed:
		return stateClosed
	case st.awaiting:
		return stateAwaiting
	default:
		return stateWaiting
	}
}

// expiresIn is how long until s expires, in whole seconds.
func (a *App) expiresIn(s *session) int {
	return max(0, int(math.Ceil(s.expiresAt.Sub(a.now()).Seconds())))
}

// requestStatus is what the request page polls while it waits: its
// coarse state, whether a response was rejected and when it expires —
// never what the wallet disclosed, which only the page shows.
type requestStatus struct {
	State     string `json:"state"`
	Rejected  bool   `json:"rejected"`
	ExpiresIn int    `json:"expires_in"`
}

// handleRequestStatus answers the request page's polling, under the
// same session binding as the page: another browser's, an expired or
// an unknown request is "ended", with a 404, as the page itself is.
func (a *App) handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(headerContentType, "application/json")
	s, ok := a.session(r.PathValue("id"))
	if !ok || !sameBrowser(r, s) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(requestStatus{State: stateEnded})
		return
	}
	st := a.state(r.Context(), s)
	_ = json.NewEncoder(w).Encode(requestStatus{State: st.coarse(), Rejected: st.lastError != "", ExpiresIn: a.expiresIn(s)})
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
		State: st.coarse(), Rejected: st.lastError != "", ExpiresIn: a.expiresIn(s),
	}
	page.Polling = page.State == stateWaiting || page.State == stateAwaiting
	page.ExpiresInMinutes = (page.ExpiresIn + 59) / 60
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
	query, queryErr := a.query(s.scenario)
	page.AllValid = true
	var statuses []string
	for i, p := range people {
		v := personView{Heading: "Disclosed by the wallet", Format: p.Format, Status: p.Status, ICAO: p.ICAO}
		if info.Multiple {
			v.Heading = personHeading(i, p)
		}
		v.Rows, v.Raw = displayRows(p.Format, p.Claims)
		if queryErr == nil {
			v.Asked = askedFor(query, p.Format, p.Claims)
		}
		v.Received = received(p.Format, p.Claims)
		for _, l := range v.Received {
			if !slices.ContainsFunc(v.Asked, func(r requested) bool { return r.Label == l }) {
				v.Unasked = append(v.Unasked, l)
			}
		}
		if !slices.Contains(page.Formats, p.Format) {
			page.Formats = append(page.Formats, p.Format)
		}
		if p.Status != "valid" {
			page.AllValid = false
		}
		if !slices.Contains(statuses, p.Status) {
			statuses = append(statuses, p.Status)
		}
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
	page.StatusSummary = strings.Join(statuses, ", ")
	return page
}

// personHeading heads the i'th credential of a presentation taking
// several: "Person N", and the name it discloses or, failing that, its
// re-verified passport's.
func personHeading(i int, p Person) string {
	heading := fmt.Sprintf("Person %d", i+1)
	family, _ := p.Claims[credential.FamilyName].(string)
	given, _ := p.Claims[credential.GivenName].(string)
	if family == "" && given == "" && p.ICAO != nil && p.ICAO.Verified {
		family, given = p.ICAO.Identity.FamilyName, p.ICAO.Identity.GivenNames
	}
	switch {
	case family != "" && given != "":
		return heading + " — " + family + ", " + given
	case family != "" || given != "":
		return heading + " — " + family + given
	}
	return heading
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
