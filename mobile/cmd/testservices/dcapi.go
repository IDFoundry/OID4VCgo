package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// A page asking over the Digital Credentials API, for the Android demo
// wallet's Credential Manager provider: GET /dcapi?format=<fmt> serves
// it, its button asks for family_name (from an SD-JWT VC, the default,
// or an mdoc with format=mso_mdoc) with a signed OpenID4VP request, and the page
// shows what the Verifier made of the answer. The request is bound to
// the page's own origin, the control endpoint's.
//
//	POST /dcapi/request?format=<fmt> → {"id", "protocol", "data"}
//	POST /dcapi/response/{id}        (the credential's data) → {"status": "done", "claims"} | {"status": "error", "error"}
//	GET  /dcapi/result/{id}          → the same, for tests
type dcapiRequests struct {
	v  *walletflowtest.Verifier
	mu sync.Mutex
	// by ID: the request, and what its answer came to once it came.
	requests map[string]*walletflowtest.DCAPIRequest
	results  map[string]map[string]any
}

func (d *dcapiRequests) routes(mux *http.ServeMux, env *walletflowtest.Env) {
	mux.HandleFunc("GET /dcapi", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, dcapiPage)
	})
	mux.HandleFunc("POST /dcapi/request", func(w http.ResponseWriter, r *http.Request) {
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "dc+sd-jwt"
		}
		q, err := query(env, format, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req, err := d.v.BeginDCAPI(q, "https://"+r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		d.mu.Lock()
		id := strconv.Itoa(len(d.requests) + 1)
		d.requests[id] = req
		d.mu.Unlock()
		writeJSON(w, map[string]any{"id": id, "protocol": req.Protocol, "data": json.RawMessage(req.Data)})
	})
	mux.HandleFunc("POST /dcapi/response/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		d.mu.Lock()
		req := d.requests[id]
		d.mu.Unlock()
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if req == nil || err != nil {
			http.Error(w, "no such request", http.StatusNotFound)
			return
		}
		out := map[string]any{"status": "done"}
		if result, err := d.v.VerifyDCAPIResponse(r.Context(), req, data); err != nil {
			out = map[string]any{"status": "error", "error": err.Error()}
		} else if len(result.Credentials) > 0 {
			out["claims"] = result.Credentials[0].Claims
		}
		d.mu.Lock()
		d.results[id] = out
		d.mu.Unlock()
		writeJSON(w, out)
	})
	mux.HandleFunc("GET /dcapi/result/{id}", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		out, ok := d.results[r.PathValue("id")]
		d.mu.Unlock()
		if !ok {
			out = map[string]any{"status": "pending"}
		}
		writeJSON(w, out)
	})
}

var dcapiPage = fmt.Sprintf(`<!doctype html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>DC API test</title></head>
<body style="font-family: sans-serif; padding: 24px">
<h1>Verify with an ID in this browser</h1>
<p>The test Verifier asks for family_name over the Digital Credentials API (%s).</p>
<button id="ask" style="font-size: 20px; padding: 12px 20px">Verify</button>
<pre id="result"></pre>
<script>
document.getElementById("ask").onclick = async () => {
  const out = document.getElementById("result");
  try {
    const format = new URLSearchParams(location.search).get("format") || "";
    const r = await (await fetch("/dcapi/request?format=" + encodeURIComponent(format), {method: "POST"})).json();
    const cred = await navigator.credentials.get({digital: {requests: [{protocol: r.protocol, data: r.data}]}, mediation: "required"});
    const answer = await (await fetch("/dcapi/response/" + r.id, {method: "POST", body: JSON.stringify(cred.data)})).json();
    out.textContent = JSON.stringify(answer, null, 2);
  } catch (e) {
    out.textContent = "error: " + e;
  }
};
</script></body></html>`, "openid4vp-v1-signed")
