package verifierapp

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
)

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleHome)
	mux.HandleFunc("POST /requests", a.handleCreateRequest)
	mux.HandleFunc("GET /requests/{id}", a.handleRequestPage)
	mux.HandleFunc("GET /request-objects/{id}", a.handleRequestObject)
	mux.HandleFunc("POST /response", a.handleResponse)
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
</style>
`

const pageFoot = `
</body>
</html>
`

var homeTemplate = template.Must(template.New("home").Parse(pageHead + `</head><body>
<h1>Verify a passport credential</h1>
<p>Ask a wallet for its passport-derived credential — as an <code>mso_mdoc</code> or a <code>dc+sd-jwt</code>, whichever it holds — and choose what to trust:</p>
<form method="post" action="/requests" class="card">
<h2>Trust the issuer</h2>
<p>Request name, nationality and an over-18 check. Accept them because the credential's issuer signature chains to the demo issuer's CA.</p>
<button name="mode" value="issuer">Request</button>
</form>
<form method="post" action="/requests" class="card">
<h2>Trust only the issuing country</h2>
<p>Request just the raw ICAO SOD and DG1 — not the photo — and re-run Passive Authentication against the ICAO CSCA master list. The demo issuer can't have altered this data.</p>
<button name="mode" value="icao">Request</button>
</form>
` + pageFoot))

type requestPage struct {
	ID      string
	Link    string
	Outcome *Outcome
	Rows    [][2]string
}

var requestTemplate = template.Must(template.New("request").Parse(pageHead + `{{if not .Outcome}}<meta http-equiv="refresh" content="2">{{end}}
</head><body>
{{if not .Outcome}}
<h1>Waiting for the wallet</h1>
<p>Give this request to the demo wallet:</p>
<p><code>{{.Link}}</code></p>
<p class="note">This page refreshes until the wallet answers.</p>
{{else if .Outcome.Error}}
<h1 class="bad">✗ Presentation rejected</h1>
<p>{{.Outcome.Error}}</p>
{{else}}
<h1 class="ok">✓ Presentation verified</h1>
<p>The wallet presented its <code>{{.Outcome.Format}}</code> credential. The issuer signature chains to the demo issuer's CA, and the holder proved possession of the credential's key.</p>
{{if eq .Outcome.Mode "icao"}}
<div class="card">
<h2>ICAO Passive Authentication over SOD + DG1</h2>
{{if .Outcome.ICAO.Verified}}
<p class="ok">✓ The SOD is signed by a Document Signer chaining to the issuing country's CSCA, and DG1 matches its hash. This data comes from the passport, whatever the demo issuer did.</p>
<table>
<tr><th>Name</th><td>{{.Outcome.ICAO.Identity.FamilyName}}, {{.Outcome.ICAO.Identity.GivenNames}}</td></tr>
<tr><th>Nationality</th><td>{{.Outcome.ICAO.Identity.Nationality}}</td></tr>
<tr><th>Issuing country</th><td>{{.Outcome.ICAO.Identity.IssuingCountry}}</td></tr>
<tr><th>Passport expiry</th><td>{{.Outcome.ICAO.Identity.ExpiryDate.Format "2006-01-02"}}</td></tr>
</table>
{{else}}
<p class="bad">✗ {{.Outcome.ICAO.Error}}</p>
{{end}}
<p class="note">This proves the data is authentic, not that the presenter holds the passport: that binding comes from the credential's device key.</p>
</div>
{{end}}
<h2>Disclosed claims</h2>
<table>{{range .Rows}}<tr><th>{{index . 0}}</th><td>{{index . 1}}</td></tr>{{end}}</table>
{{end}}
<p><a href="/">New request</a></p>
` + pageFoot))

func (a *App) handleHome(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homeTemplate.Execute(w, nil)
}

func (a *App) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	id, _, err := a.CreateRequest(Mode(r.PostForm.Get("mode")))
	if err != nil {
		http.Error(w, "couldn't create a request", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/requests/"+id, http.StatusSeeOther) // #nosec G710 -- local path + a server-generated random ID, not user input
}

func (a *App) handleRequestPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s, ok := a.session(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	page := requestPage{ID: id, Link: s.link}
	if outcome, done := a.Outcome(id); done {
		page.Outcome = outcome
		page.Rows = displayRows(outcome.Claims)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = requestTemplate.Execute(w, page)
}

// displayRows renders claims for the result page: raw byte values (the
// ICAO data groups) as their size, everything else as-is.
func displayRows(claims map[string]any) [][2]string {
	keys := make([]string, 0, len(claims))
	for k := range claims {
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
