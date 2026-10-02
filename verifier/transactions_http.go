package verifier

import (
	"encoding/json"
	"errors"
	"net/http"
	"path"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// requestObjectMediaType is RFC 9101 §10.2's media type for a Request
// Object.
const requestObjectMediaType = "application/oauth-authz-req+jwt"

// RequestObjectHandler serves request objects at the request_uri Begin
// puts in each link — mount it under TransactionsConfig.RequestURIBase,
// e.g. mux.Handle("GET /request-objects/{id}", t.RequestObjectHandler()).
// The request's ID is the {id} path value, or the last path segment.
// Only GET is supported: Begin's links don't ask for
// request_uri_method=post.
func (t *Transactions) RequestObjectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := r.PathValue("id")
		if id == "" {
			id = path.Base(r.URL.Path)
		}
		object, err := t.RequestObject(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", requestObjectMediaType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(object)) // #nosec G705 -- a JWT this Verifier signed, served as application/oauth-authz-req+jwt with nosniff, never HTML
	})
}

// maxResponseBodyBytes bounds a direct_post body: the encrypted
// response plus form encoding.
const maxResponseBodyBytes = 2*jwe.MaxCompactBytes + 4096

// ResponseHandler is the response_uri endpoint (OpenID4VP §8.2,
// direct_post.jwt): mount it at the Verifier's Config.ResponseURI. It
// passes the "response" form parameter to HandleResponse and replies
// with JSON — {"redirect_uri": …} for a same-device answer, {} for a
// cross-device one, or a 400 error whose description says only that
// the answer was refused: why is recorded as the request's LastError,
// for the Verifier's own display, not told to whoever sent it. A
// Wallet's error response for a pending request is processed, recorded
// as LastError, and answered with 200 and {} (OpenID4VP §8.2: "If the
// Response URI has successfully processed the Authorization Response or
// Authorization Error Response, it MUST respond with an HTTP status code
// of 200").
func (t *Transactions) ResponseHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxResponseBodyBytes)
		if err := r.ParseForm(); err != nil {
			writeResponseError(w, "the response is malformed")
			return
		}
		answered, err := t.HandleResponse(r.Context(), r.PostForm.Get("response"))
		var walletErr *ResponseError
		switch {
		case errors.As(err, &walletErr):
			answered = Answered{}
		case errors.Is(err, ErrTransactionAnswered):
			writeResponseError(w, "this request has already been answered")
			return
		case err != nil:
			writeResponseError(w, "the response was not accepted")
			return
		}
		body := map[string]string{}
		if answered.RedirectURI != "" {
			body["redirect_uri"] = answered.RedirectURI
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(body)
	})
}

func writeResponseError(w http.ResponseWriter, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": description})
}
