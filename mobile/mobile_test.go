package mobile

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestParseRequestLink(t *testing.T) {
	out, err := ParseRequestLink("openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fverifier.example%2Fr%2F1")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if got["abi"] != float64(ABIVersion) || got["client_id"] != "x509_hash:abc" || got["request_uri"] != "https://verifier.example/r/1" {
		t.Errorf("ParseRequestLink = %s", out)
	}
	if _, err := ParseRequestLink("openid4vp://?client_id=x"); code(err) != CodeInvalidInput || !strings.HasPrefix(err.Error(), "[invalid_input] ") {
		t.Errorf("a link without request_uri: %v", err)
	}
}

func TestFetch(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			select {
			case <-release:
			case <-r.Context().Done():
			}
		case "/missing":
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte("hello"))
		}
	}))
	defer srv.Close()
	defer close(release)

	if body, err := Fetch(NewOperation(0), srv.URL+"/"); err != nil || body != "hello" {
		t.Fatalf("Fetch = %q, %v", body, err)
	}
	if _, err := Fetch(NewOperation(0), srv.URL+"/missing"); code(err) != CodeNetwork {
		t.Errorf("a 404: %v", err)
	}
	op := NewOperation(0)
	go func() {
		time.Sleep(50 * time.Millisecond)
		op.Cancel()
		op.Cancel()
	}()
	if _, err := Fetch(op, srv.URL+"/slow"); code(err) != CodeCancelled {
		t.Errorf("a cancelled fetch: %v", err)
	}
	if _, err := Fetch(NewOperation(50), srv.URL+"/slow"); code(err) != CodeCancelled {
		t.Errorf("a timed-out fetch: %v", err)
	}
	if _, err := Fetch(nil, srv.URL); code(err) != CodeInvalidInput {
		t.Errorf("no operation: %v", err)
	}
	if _, err := Fetch(NewOperation(0), "://"); code(err) != CodeInvalidInput {
		t.Errorf("a malformed URL: %v", err)
	}
}
