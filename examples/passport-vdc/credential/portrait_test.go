package credential

import (
	"bytes"
	"strings"
	"testing"
)

// testPortrait stands in for a JPEG: PortraitJPEG checks only the
// JPEG signature.
var testPortrait = append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, bytes.Repeat([]byte{0x42}, 4<<10)...)

func TestPortrait_BothFormatsRoundTrip(t *testing.T) {
	mdocClaims, err := MdocClaims(adult(), Options{Now: now})
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	identity := issueAndVerifyMdoc(t, mdocClaims)[ISONamespace]
	if got, ok := PortraitJPEG(identity); !ok || !bytes.Equal(got, testPortrait) {
		t.Error("mdoc portrait did not round-trip byte-for-byte")
	}

	sdClaims, err := SDJWTClaims(adult(), testVCT, Options{Now: now})
	if err != nil {
		t.Fatalf("SDJWTClaims: %v", err)
	}
	payload := issueAndVerifySDJWT(t, sdClaims)
	if got, ok := PortraitJPEG(payload); !ok || !bytes.Equal(got, testPortrait) {
		t.Error("SD-JWT picture did not round-trip byte-for-byte")
	}
	if s, _ := payload[SDJWTPicture].(string); !strings.HasPrefix(s, "data:image/jpeg;base64,") {
		t.Errorf("picture isn't a JPEG data: URL")
	}
}

func TestPortrait_OmittedWithoutOne(t *testing.T) {
	e := adult()
	e.Portrait = nil

	mdocClaims, err := MdocClaims(e, Options{Now: now})
	if err != nil {
		t.Fatalf("MdocClaims: %v", err)
	}
	if _, ok := mdocClaims.NameSpaces[ISONamespace][Portrait]; ok {
		t.Error("mdoc portrait issued without a portrait in the evidence")
	}
	sdClaims, err := SDJWTClaims(e, testVCT, Options{Now: now})
	if err != nil {
		t.Fatalf("SDJWTClaims: %v", err)
	}
	if _, ok := sdClaims.Additional[SDJWTPicture]; ok {
		t.Error("SD-JWT picture issued without a portrait in the evidence")
	}
}

func TestPortraitDataURI(t *testing.T) {
	uri, ok := PortraitDataURI(map[string]any{Portrait: testPortrait})
	if !ok || uri != portraitDataURI(testPortrait) {
		t.Errorf("PortraitDataURI = %q, %v", uri, ok)
	}
	if _, ok := PortraitDataURI(map[string]any{}); ok {
		t.Error("PortraitDataURI succeeded without a portrait")
	}
}

func TestPortraitJPEG_Rejects(t *testing.T) {
	for name, claims := range map[string]map[string]any{
		"none":                  {},
		"mdoc not bytes":        {Portrait: "text"},
		"mdoc not a JPEG":       {Portrait: []byte("<svg onload=alert(1)>")},
		"sd-jwt not a string":   {SDJWTPicture: 42},
		"sd-jwt other URL":      {SDJWTPicture: "https://example.com/me.jpg"},
		"sd-jwt other type":     {SDJWTPicture: "data:image/svg+xml;base64,PHN2Zz4="},
		"sd-jwt bad base64":     {SDJWTPicture: "data:image/jpeg;base64,!!!"},
		"sd-jwt not a JPEG":     {SDJWTPicture: "data:image/jpeg;base64,PHN2Zz4="},
		"sd-jwt injected quote": {SDJWTPicture: `data:image/jpeg;base64,/9j/" onerror="x`},
	} {
		if _, ok := PortraitJPEG(claims); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}
