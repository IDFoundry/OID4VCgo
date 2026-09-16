package main

import (
	"html/template"
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

type localErrorPage struct {
	Code        string
	Description string
}

var localErrorTemplate = template.Must(template.New("local-error").Parse(`<!doctype html>
<html>
<head><title>Authorization Error</title></head>
<body>
<h1>Authorization Error</h1>
<p><strong>{{.Code}}</strong></p>
<p>{{.Description}}</p>
</body>
</html>
`))

// writeOAuthJSONError translates err into an OAuth JSON error response
// (RFC 6749 §5.2) via server.WriteError — mirrors FAPIgo's own
// cmd/conformance-as/errors.go identically.
func writeOAuthJSONError(w http.ResponseWriter, err error) {
	server.WriteError(w, err)
}

func writeRawOAuthError(w http.ResponseWriter, status int, code server.ErrorCode, description string) {
	server.NewError(code, status, description).WriteJSON(w)
}

func writeLocalHTMLError(w http.ResponseWriter, err *server.Error) {
	writeLocalHTMLErrorRaw(w, err.HTTPStatus(), string(err.Code()), err.PublicDescription())
}

func writeLocalHTMLErrorRaw(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = localErrorTemplate.Execute(w, localErrorPage{Code: code, Description: description})
}
