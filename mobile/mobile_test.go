package mobile

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
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
