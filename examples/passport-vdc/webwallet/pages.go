package webwallet

import (
	"html/template"
	"net/http"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoui"
)

var pageHead = demoui.Head("Demo wallet")

const pageFoot = demoui.Foot

// header is every page's header.
var header = demoui.Header{
	Icon: "👛", Title: "Demo wallet", Subtitle: "Your passport credentials · an OID4VCgo demo",
	Nav: []demoui.Link{{Href: "/", Label: "Credentials"}}, NavLabel: "Wallet",
}

var pageFuncs = template.FuncMap{
	"header": func() demoui.Header { return header },
	"words":  func(t interface{ Format(string) string }) string { return t.Format(demoui.DateLayout) },
}

func parsePage(name, body string) *template.Template {
	return demoui.Parse(name, pageFuncs, pageHead+`</head><body>
{{template "site-header" header}}
<main>
`+body+`
</main>
`+pageFoot)
}

type homePage struct {
	Cards []card
	// Received is how many credentials the last receive stored, and
	// DeferredNow how many it left waiting for the issuer.
	Received, DeferredNow int
	// Deferred are the credentials waiting for their issuers; Waiting
	// and Denied report the last check.
	Deferred []deferredCard
	Waiting  bool
	Denied   bool
}

// deferredCard is a credential the issuer deferred, as the home page
// lists it.
type deferredCard struct {
	ID     string
	Format string
}

var homeTemplate = parsePage("home", `{{if gt .Received 0}}<section class="verdict approved">
<p class="mark" aria-hidden="true">✓</p>
<div><h1 id="banner" tabindex="-1">Received {{.Received}} {{if eq .Received 1}}credential{{else}}credentials{{end}}</h1>
<p>{{if gt .DeferredNow 0}}{{.DeferredNow}} more {{if eq .DeferredNow 1}}is{{else}}are{{end}} waiting for the issuer. {{end}}Stored in this wallet, below.</p></div>
</section>{{else if gt .DeferredNow 0}}<section class="verdict neutral">
<p class="mark" aria-hidden="true">⏳</p>
<div><h1 id="banner" tabindex="-1">Waiting for the issuer</h1>
<p>The issuer deferred {{.DeferredNow}} {{if eq .DeferredNow 1}}credential{{else}}credentials{{end}}: it's reviewing the request. Check back once it has decided.</p></div>
</section>{{end}}
{{if .Denied}}<section class="verdict refused">
<p class="mark" aria-hidden="true">✗</p>
<div><h1 id="banner" tabindex="-1">The issuer refused a credential</h1><p>It had deferred it, and decided not to issue it.</p></div>
</section>{{end}}
{{if .Waiting}}<p class="card note" role="status">Still waiting for the issuer: it hasn't decided yet.</p>{{end}}
<section class="card" aria-labelledby="paste-heading">
<h2 id="paste-heading">Paste a link</h2>
<form method="post" action="/link" id="paste-form">
<label for="link" class="code-label">An offer from an issuer, or a request from a verifier</label>
<div class="paste-row"><input type="text" id="link" name="link" required autocomplete="off" spellcheck="false" placeholder="openid-credential-offer://… or openid4vp://…" aria-describedby="link-kind">
<button type="button" class="btn secondary" id="clear-link" hidden>Clear</button></div>
<p id="link-kind" class="note" aria-live="polite"></p>
<button class="btn" id="link-go">Continue</button>
</form>
</section>
{{if .Deferred}}<h2>Waiting for the issuer</h2>
<ul class="entries">
{{range .Deferred}}<li class="card entry">
<p class="badges"><span class="badge">{{.Format}}</span> <span class="badge warn">Deferred</span></p>
<p><span class="spinner" aria-hidden="true"></span> The issuer is reviewing the request.</p>
<form method="post" action="/deferred/{{.ID}}" class="actions"><button class="btn secondary">Check now</button></form>
</li>
{{end}}</ul>{{end}}
<h2>Credentials</h2>
{{if .Cards}}<ul class="entries wide">
{{range .Cards}}<li class="card entry wallet-card">
<div class="wallet-card-head">{{if .Portrait}}<img src="{{.Portrait}}" alt="Portrait of {{if .Holder}}{{.Holder}}{{else}}the holder{{end}}" class="wc-portrait">{{end}}
<div><p class="wc-name">{{if .Holder}}{{.Holder}}{{else}}Passport credential{{end}}</p>
<p class="badges"><span class="badge">{{.Format}}</span></p>
<p class="note">Received {{words .ReceivedAt}}</p></div></div>
{{if .Error}}<p class="bad">{{.Error}}</p>{{else}}
<table class="claims">{{range .Rows}}<tr><th scope="row">{{.Label}}</th><td>{{.Value}}</td></tr>{{end}}</table>
{{if .Raw}}<details class="raw"><summary>Credential details and raw data</summary>
<table class="claims">{{range .Raw}}<tr><th scope="row">{{.Label}}</th><td>{{.Value}}</td></tr>{{end}}</table>
</details>{{end}}{{end}}
</li>
{{end}}</ul>
{{else}}<p class="card empty">No credentials yet. Paste an offer from the issuer above, or open one from the issuer's page.</p>{{end}}
<p class="note">Demo only: this wallet has no login and keeps holder keys unencrypted. It doesn't check whether a credential has been revoked.</p>
<script>
(function () {
	var banner = document.getElementById("banner");
	if (banner) banner.focus();
	var input = document.getElementById("link"), kind = document.getElementById("link-kind");
	var go = document.getElementById("link-go"), clear = document.getElementById("clear-link");
	function classify() {
		var v = input.value.trim();
		clear.hidden = v === "";
		if (v === "") { kind.textContent = ""; go.textContent = "Continue"; return; }
		if (v.indexOf("openid-credential-offer://") === 0) {
			kind.textContent = "A credential offer: receive it from its issuer.";
			go.textContent = "Receive";
		} else if (v.indexOf("openid4vp://") === 0) {
			kind.textContent = "A presentation request: review what the verifier asks for.";
			go.textContent = "Review request";
		} else {
			kind.textContent = "Not a link this wallet recognises: paste an openid-credential-offer:// or openid4vp:// link.";
			go.textContent = "Continue";
		}
	}
	input.addEventListener("input", classify);
	clear.addEventListener("click", function () { input.value = ""; classify(); input.focus(); });
	classify();
})();
</script>`)

type receivePage struct {
	Offer         string
	Issuer, Host  string
	Offered       []string // the offer's credential configuration IDs
	PreAuthorized bool
}

var confirmReceiveTemplate = parsePage("receive", `<h1>Receive a credential?</h1>
<section class="card" aria-labelledby="issuer-heading">
<h2 id="issuer-heading"><span aria-hidden="true">🏛️</span> {{if .Host}}From {{.Host}}{{else}}From an issuer{{end}}</h2>
{{if .Issuer}}<p class="note">Issuer: <code>{{.Issuer}}</code></p>{{else}}<p class="note">The offer is fetched from the issuer once you continue.</p>{{end}}
{{if .Offered}}<p>It offers:</p><ul class="chips" aria-label="Credentials offered">{{range .Offered}}<li>{{.}}</li>{{end}}</ul>{{end}}
</section>
<form method="post" action="/receive" class="card">
<input type="hidden" name="offer" value="{{.Offer}}">
{{if .PreAuthorized}}<p>This offer is pre-authorized: there's no approval at the issuer. Enter the PIN the issuer gave you.</p>
<label for="pin" class="code-label">PIN</label>
<span class="code-field"><input id="pin" name="pin" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxlength="6" required autofocus></span>
<div class="actions"><button class="btn">Receive</button> <a href="/" class="btn secondary">Cancel</a></div>
{{else}}<p>You'll be sent to the issuer to approve, with the confirmation code it showed you, then brought back here.</p>
<div class="actions"><button class="btn">Continue to the issuer</button> <a href="/" class="btn secondary">Cancel</a></div>{{end}}
</form>`)

var confirmPresentTemplate = parsePage("present", `<h1>Answer a verifier?</h1>
<form method="post" action="/present" class="card">
{{if .Host}}<p>The request is at <code>{{.Host}}</code>.</p>{{end}}
<p>The wallet will fetch it, check who signed it, and show you what it asks for. Nothing is shared until you choose.</p>
<input type="hidden" name="request" value="{{.Request}}">
<div class="actions"><button class="btn">Review the request</button> <a href="/" class="btn secondary">Cancel</a></div>
</form>`)

type consentPage struct {
	ID           string
	VerifierName string
	VerifierID   string
	ResponseHost string
	Options      []consentOption
	Several      bool
}

// consentOption is one way to answer, as the consent page shows it: its
// holder's portrait, and what it discloses by label and by claim path.
type consentOption struct {
	Ref, Holder, Format string
	Portrait            template.URL
	Labels, Paths       []string
}

var consentTemplate = parsePage("consent", `<h1>{{.VerifierName}} is asking for your passport</h1>
<section class="card" aria-labelledby="verifier-heading">
<h2 id="verifier-heading">{{.VerifierName}} <span class="badge ok">✓ Trusted verifier</span></h2>
<p class="note">Its request is signed by a certificate from a verifier CA this wallet trusts (identifier <code>{{.VerifierID}}</code>); the answer goes to <code>{{.ResponseHost}}</code>.</p>
</section>
<form method="post" action="/present/{{.ID}}">
<fieldset class="choices">
<legend>{{if .Several}}It accepts several passports: choose each one to share, all in one format.{{else}}Choose what to share{{end}}</legend>
{{range $i, $o := .Options}}<label class="choice block">{{if $o.Portrait}}<img src="{{$o.Portrait}}" alt="Portrait of {{$o.Holder}}" class="choice-portrait">{{end}}<input type="{{if $.Several}}checkbox{{else}}radio{{end}}" name="credential" value="{{$o.Ref}}" {{if eq $i 0}}checked{{end}}> Share {{if $o.Holder}}<strong>{{$o.Holder}}</strong>'s passport{{else}}a passport credential{{end}} as <span class="fmt">{{$o.Format}}</span>
<span class="choice-detail"><span class="note">It will see only:</span>
<span class="chips">{{range $o.Labels}}<span class="chip">{{.}}</span>{{end}}</span>
<span class="note claim-paths">Claim names: {{range $j, $p := $o.Paths}}{{if $j}}, {{end}}<code>{{$p}}</code>{{end}}</span></span>
</label>
{{end}}</fieldset>
<div class="actions decision">
<button class="btn" name="decision" value="share">Share</button>
<button class="btn secondary" name="decision" value="decline">Decline</button>
</div>
</form>`)

type donePage struct {
	Shared  bool
	Message string
}

var doneTemplate = parsePage("done", `<section class="verdict {{if .Shared}}approved{{else}}neutral{{end}}">
<p class="mark" aria-hidden="true">{{if .Shared}}✓{{else}}✗{{end}}</p>
<div><h1 id="banner" tabindex="-1">{{.Message}}</h1></div>
</section>
<p class="actions"><a href="/" class="btn">Back to the wallet</a></p>
<script>document.getElementById("banner").focus();</script>`)

var errorTemplate = parsePage("error", `<section class="verdict refused">
<p class="mark" aria-hidden="true">✗</p>
<div><h1 id="banner" tabindex="-1">Something went wrong</h1>
<p>{{.}}</p></div>
</section>
<p class="actions"><a href="/" class="btn">Back to the wallet</a></p>`)

// render writes a page. None is cached: they show credentials, offers
// (bearer secrets), requests and consent.
func render(w http.ResponseWriter, status int, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = t.Execute(w, data)
}

func renderError(w http.ResponseWriter, status int, message string) {
	render(w, status, errorTemplate, message)
}
