package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// What Multipaz sends walletflow that walletflow is lenient about
// (SPECIFICATIONS.md, "Known leniencies"): the peer records it as it
// arrives, and the driver checks it against what Multipaz sends today,
// so a change shows. Each value is one string:
//
//	verifier_jwks      a Verifier's client_metadata.jwks, one "alg=…,kid=…" per key
//	request_enc_jwks   an issuer's credential_request_encryption.jwks, the same, or "none"
//	token_type         the Token Response's token_type
//
// "alg=-" and "kid=-" are a key without them.

// recorder is an http.RoundTripper recording observations from the
// responses it carries.
type recorder struct {
	next http.RoundTripper

	mu       sync.Mutex
	observed map[string]string
}

func newRecorder(next http.RoundTripper) *recorder {
	return &recorder{next: next, observed: map[string]string{}}
}

// maxObservedBody bounds what the recorder reads of a response.
const maxObservedBody = 1 << 20

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := r.next.RoundTrip(req)
	if err != nil {
		return res, err
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxObservedBody))
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	contentType := res.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(contentType, "application/oauth-authz-req+jwt"):
		if payload, err := jwtPayload(string(body)); err == nil {
			r.set("verifier_jwks", verifierJWKs(payload))
		}
	case strings.HasPrefix(req.URL.Path, "/.well-known/openid-credential-issuer"):
		metadata := body
		if !strings.HasPrefix(contentType, "application/json") {
			if metadata, err = jwtPayload(string(body)); err != nil {
				return res, nil
			}
		}
		var m struct {
			Encryption *struct {
				JWKS json.RawMessage `json:"jwks"`
			} `json:"credential_request_encryption"`
		}
		if json.Unmarshal(metadata, &m) == nil {
			if m.Encryption == nil {
				r.set("request_enc_jwks", "none")
			} else {
				r.set("request_enc_jwks", describeJWKs(m.Encryption.JWKS))
			}
		}
	case res.StatusCode == http.StatusOK && strings.HasPrefix(contentType, "application/json") && req.Method == http.MethodPost:
		var t struct {
			AccessToken string  `json:"access_token"`
			TokenType   *string `json:"token_type"`
		}
		if json.Unmarshal(body, &t) == nil && t.AccessToken != "" {
			if t.TokenType == nil {
				r.set("token_type", "-")
			} else {
				r.set("token_type", *t.TokenType)
			}
		}
	}
	return res, nil
}

func (r *recorder) set(name, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observed[name] = value
}

// snapshot is what was recorded.
func (r *recorder) snapshot() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.observed))
	for k, v := range r.observed {
		out[k] = v
	}
	return out
}

// jwtPayload is a compact JWS's payload, unverified: walletflow
// verifies it; this only reads what it carried.
func jwtPayload(compact string) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}

// verifierJWKs describes a Request Object's client_metadata.jwks.
func verifierJWKs(payload []byte) string {
	var ro struct {
		ClientMetadata struct {
			JWKS json.RawMessage `json:"jwks"`
		} `json:"client_metadata"`
	}
	if err := json.Unmarshal(payload, &ro); err != nil || ro.ClientMetadata.JWKS == nil {
		return "none"
	}
	return describeJWKs(ro.ClientMetadata.JWKS)
}

// dcapiVerifierJWKs describes the client_metadata.jwks of a DC API
// request's data: {"request": <signed Request Object>}, or the unsigned
// request's parameters themselves.
func dcapiVerifierJWKs(data string) string {
	var d struct {
		Request string `json:"request"`
	}
	if err := json.Unmarshal([]byte(data), &d); err != nil {
		return "unreadable"
	}
	if d.Request == "" {
		return verifierJWKs([]byte(data))
	}
	payload, err := jwtPayload(d.Request)
	if err != nil {
		return "unreadable"
	}
	return verifierJWKs(payload)
}

// describeJWKs is a JWK Set's keys, each as "alg=…,kid=…" (kid only as
// present or not: its value is per run), sorted, joined by ";".
func describeJWKs(raw json.RawMessage) string {
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := strictjson.Unmarshal(raw, &set); err != nil {
		return "unreadable"
	}
	keys := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		alg, _ := k["alg"].(string)
		if alg == "" {
			alg = "-"
		}
		kid := "-"
		if s, _ := k["kid"].(string); s != "" {
			kid = "present"
		}
		keys = append(keys, "alg="+alg+",kid="+kid)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "empty"
	}
	return strings.Join(keys, ";")
}
