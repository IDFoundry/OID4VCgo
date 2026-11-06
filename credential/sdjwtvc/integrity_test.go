package sdjwtvc

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateIntegrity(t *testing.T) {
	d256 := sha256.Sum256([]byte("x"))
	d384 := sha512.Sum384([]byte("x"))
	s256 := "sha256-" + base64.StdEncoding.EncodeToString(d256[:])
	s384 := "sha384-" + base64.StdEncoding.EncodeToString(d384[:])
	for _, ok := range []string{
		s256,
		"sha256-" + base64.RawStdEncoding.EncodeToString(d256[:]),
		s256 + " " + s384,
		s384 + "?opt",
	} {
		if err := validateIntegrity(ok); err != nil {
			t.Errorf("validateIntegrity(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "   ", "abc", "md5-" + base64.StdEncoding.EncodeToString(d256[:16]),
		"sha256-" + base64.StdEncoding.EncodeToString(d384[:]), // wrong length
		"sha256-!!!!", s256 + " sha1-abc",
	} {
		if err := validateIntegrity(bad); err == nil {
			t.Errorf("validateIntegrity(%q) = nil, want an error", bad)
		}
	}
}

func TestIntegrityChecked(t *testing.T) {
	key := testKey(t)
	if _, _, err := Issue(key, "ES256", Claims{VCT: "vc-type", VCTIntegrity: "nope"}, IssueOptions{}); err == nil || !strings.Contains(err.Error(), "VCTIntegrity") {
		t.Errorf("Issue with a bad vct#integrity = %v", err)
	}
	if err := (TypeMetadata{VCT: "v", Extends: "https://x.example/v", ExtendsIntegrity: "nope"}).Validate(); err == nil {
		t.Error("Validate accepted a bad extends#integrity")
	}
	bad := "nope"
	for name, rendering := range map[string]string{
		"simple":        `{"logo":{"uri":"https://x.example/l.png","uri#integrity":"nope"}}`,
		"svg_templates": `[{"uri":"https://x.example/t.svg","uri#integrity":"nope"}]`,
	} {
		m := TypeMetadata{VCT: "v", Display: []TypeDisplay{{Locale: "en", Name: "n", Rendering: map[string]json.RawMessage{name: json.RawMessage(rendering)}}}}
		if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "uri#integrity") {
			t.Errorf("%s with uri#integrity %q: %v", name, bad, err)
		}
	}
	d := sha256.Sum256([]byte("x"))
	good := "sha256-" + base64.StdEncoding.EncodeToString(d[:])
	m := TypeMetadata{VCT: "v", ExtendsIntegrity: good, Display: []TypeDisplay{{Locale: "en", Name: "n", Rendering: map[string]json.RawMessage{
		"simple": json.RawMessage(`{"logo":{"uri":"https://x.example/l.png","uri#integrity":"` + good + `"}}`),
	}}}}
	if err := m.Validate(); err != nil {
		t.Errorf("Validate with good integrity: %v", err)
	}
}
