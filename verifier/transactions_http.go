package verifier

import (
	"encoding/json"
	"errors"
	"net/http"
	"path"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// HTTP header names and values the handlers set.
const (
	headerContentType  = "Content-Type"
	headerCacheControl = "Cache-Control"
	mediaTypeJSON      = "application/json"
	cacheNoStore       = "no-store"
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
		w.Header().Set(headerContentType, requestObjectMediaType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set(headerCacheControl, cacheNoStore)
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
// for the Verifier's own display, not told to whoever sent it. That
// 400 is the same whether the request is unknown, already answered,
// closed or expired, or the answer failed verification, so its content
// doesn't tell anyone holding the request's QR code whether the holder
// has presented; a Wallet resending an answer that already completed
// the request gets it too. Its timing can: a refused answer to a
// pending request is recorded (a store write), one to a request no
// longer pending isn't (see SECURITY.md's known limitations). A
// failure of the Verifier's own, such as its TransactionStore's, is a
// 500 server_error instead, so the Wallet isn't told its answer was
// refused. A
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
		if r.PostForm.Get("response") == "" && r.PostForm.Get("error") != "" {
			// An unencrypted error response, which a Wallet that can't
			// encrypt may send (§8.3.1): tied to its request by state.
			body := map[string]string{}
			if answered := t.HandleUnencryptedError(r.Context(), r.PostForm.Get("error"), r.PostForm.Get("state")); answered.RedirectURI != "" {
				body["redirect_uri"] = answered.RedirectURI
			}
			writeResponseJSON(w, body)
			return
		}
		answered, err := t.HandleResponse(r.Context(), r.PostForm.Get("response"))
		var walletErr *ResponseError
		switch {
		case errors.As(err, &walletErr):
			// A same-device request's Answered carries its redirect_uri.
		case errors.As(err, new(*serverFault)):
			// The Verifier's own failure, not the answer's.
			w.Header().Set(headerContentType, mediaTypeJSON)
			w.Header().Set(headerCacheControl, cacheNoStore)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "server_error"})
			return
		case err != nil:
			// The same reply whether the request is unknown, answered,
			// closed or expired, or the answer failed: anyone holding the
			// request's QR code can post to its key, and mustn't learn
			// from it whether the holder has presented (though only a
			// pending request's refusal is recorded, so the time taken
			// differs). A Wallet that resends an answer that was
			// delivered gets this too.
			writeResponseError(w, "the response was not accepted")
			return
		}
		body := map[string]string{}
		if answered.RedirectURI != "" {
			body["redirect_uri"] = answered.RedirectURI
		}
		writeResponseJSON(w, body)
	})
}

func writeResponseJSON(w http.ResponseWriter, body map[string]string) {
	w.Header().Set(headerContentType, mediaTypeJSON)
	w.Header().Set(headerCacheControl, cacheNoStore)
	_ = json.NewEncoder(w).Encode(body)
}

func writeResponseError(w http.ResponseWriter, description string) {
	w.Header().Set(headerContentType, mediaTypeJSON)
	w.Header().Set(headerCacheControl, cacheNoStore)
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": description})
}
