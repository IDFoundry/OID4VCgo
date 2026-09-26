package demoqr

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"
)

func TestDataURI_IsAPNG(t *testing.T) {
	uri, err := DataURI("openid-credential-offer://?credential_offer=%7B%7D")
	if err != nil {
		t.Fatalf("DataURI: %v", err)
	}
	b64, ok := strings.CutPrefix(string(uri), "data:image/png;base64,")
	if !ok {
		t.Fatalf("not a PNG data URI: %.40s", uri)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(raw)); err != nil {
		t.Fatalf("png: %v", err)
	}
}
