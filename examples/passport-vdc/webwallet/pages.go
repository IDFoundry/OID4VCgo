package webwallet

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

const pageHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Demo wallet</title>
<style>
body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
.card{border:1px solid #d0d7de;border-radius:10px;padding:1rem 1.25rem;margin:1rem 0}
.card h2{margin:.1rem 0 .5rem;font-size:1.1rem}.fmt{font-size:.8rem;color:#57606a;border:1px solid #d0d7de;border-radius:4px;padding:0 .35rem}
table{border-collapse:collapse}th,td{text-align:left;padding:.15rem .75rem .15rem 0;vertical-align:top}th{font-weight:500;color:#57606a}
input[type=text]{width:100%;box-sizing:border-box;padding:.4rem}code{word-break:break-all}
.ok{color:#1a7f37}.bad{color:#cf222e}.note{color:#57606a;font-size:.9em}
button{padding:.4rem .9rem;margin-right:.5rem}
</style>
</head>
<body>
`

const pageFoot = `
</body>
</html>
`

type homePage struct {
	Cards    []card
	Received string
}

var homeTemplate = template.Must(template.New("home").Parse(pageHead + `
<h1>Demo wallet</h1>
{{if .Received}}<p class="ok">✓ Received {{.Received}} credential(s).</p>{{end}}
<form method="get" action="/receive">
<label>Receive a credential — paste an offer link:<br><input type="text" name="offer" placeholder="openid-credential-offer://…" required></label>
<button>Receive</button>
</form>
<form method="get" action="/present">
<label>Answer a verifier — paste a request link:<br><input type="text" name="request" placeholder="openid4vp://…" required></label>
<button>Review request</button>
</form>
<h2>Credentials</h2>
{{range .Cards}}
<div class="card">
<h2>{{.Title}} <span class="fmt">{{.Format}}</span></h2>
{{if .Error}}<p class="bad">{{.Error}}</p>{{else}}
<table>{{range .Claims}}<tr><th>{{index . 0}}</th><td>{{index . 1}}</td></tr>{{end}}</table>
{{if .Raw}}<p class="note">Raw passport data: {{range $i, $r := .Raw}}{{if $i}}, {{end}}{{index $r 0}} ({{index $r 1}}){{end}}</p>{{end}}
{{end}}
</div>
{{else}}
<p class="note">No credentials yet.</p>
{{end}}
<p class="note">Demo only: this wallet has no login and keeps holder keys unencrypted.</p>
` + pageFoot))

var confirmReceiveTemplate = template.Must(template.New("receive").Parse(pageHead + `
<h1>Receive a credential?</h1>
{{if .Issuer}}<p>From <code>{{.Issuer}}</code>.</p>{{end}}
<p>You'll be sent to the issuer to approve, then brought back here.</p>
<form method="post" action="/receive">
<input type="hidden" name="offer" value="{{.Offer}}">
<button>Continue to the issuer</button> <a href="/">Cancel</a>
</form>
` + pageFoot))

type consentPage struct {
	ID           string
	VerifierID   string
	ResponseHost string
	Options      []walletapp.Option
}

var consentTemplate = template.Must(template.New("consent").Funcs(template.FuncMap{
	"path": func(p []string) string { return strings.Join(p, " › ") },
}).Parse(pageHead + `
<h1>A verifier is asking for your passport credential</h1>
<p>Verifier: <code>{{.VerifierID}}</code><br><span class="note">Its request is signed by the certificate this identifier names; the answer goes to <code>{{.ResponseHost}}</code>. This tells you who it is, not whether to trust it.</span></p>
<form method="post" action="/present/{{.ID}}">
{{range $i, $o := .Options}}
<div class="card">
<label><input type="radio" name="format" value="{{$o.Format}}" {{if eq $i 0}}checked{{end}}> Share as <span class="fmt">{{$o.Format}}</span></label>
<p>It will see only:</p>
<ul>{{range $o.Claims}}<li><code>{{path .}}</code></li>{{end}}</ul>
</div>
{{end}}
<button name="decision" value="share">Share</button>
<button name="decision" value="decline">Decline</button>
</form>
` + pageFoot))

var doneTemplate = template.Must(template.New("done").Parse(pageHead + `
<h1>{{.Message}}</h1>
<p><a href="/">Back to the wallet</a></p>
` + pageFoot))

var errorTemplate = template.Must(template.New("error").Parse(pageHead + `
<h1 class="bad">Something went wrong</h1>
<p>{{.}}</p>
<p><a href="/">Back to the wallet</a></p>
` + pageFoot))

func render(w http.ResponseWriter, status int, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = t.Execute(w, data)
}

func renderError(w http.ResponseWriter, status int, message string) {
	render(w, status, errorTemplate, message)
}
