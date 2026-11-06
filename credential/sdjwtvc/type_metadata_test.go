package sdjwtvc_test

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
)

func validTypeMetadata() sdjwtvc.TypeMetadata {
	return sdjwtvc.TypeMetadata{
		VCT: "https://issuer.example/vct/pid/1", Name: "PID",
		Display: []sdjwtvc.TypeDisplay{{Locale: "en", Name: "Person ID"}},
		Claims: []sdjwtvc.ClaimMetadata{
			{Path: sdjwtvc.ClaimPath("given_name"), Display: []sdjwtvc.ClaimDisplay{{Locale: "en", Label: "Given name"}}, Mandatory: true, SD: sdjwtvc.SDAlways, SvgID: "given_name"},
			{Path: []any{"nationalities", nil}},
			{Path: []any{"nationalities", 0}, SD: sdjwtvc.SDNever},
		},
	}
}

// TestTypeMetadata_RoundTripsAndValidates checks the draft-13 wire member
// names (locale, mandatory, extends#integrity) and that a document
// decoded from JSON — numeric path elements as float64 — still
// validates.
func TestTypeMetadata_RoundTripsAndValidates(t *testing.T) {
	m := validTypeMetadata()
	m.Extends, m.ExtendsIntegrity = "https://base.example/vct", "sha256-LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564="
	if err := m.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{"vct", "name", "extends", "extends#integrity", "display", "claims"} {
		if _, ok := wire[member]; !ok {
			t.Errorf("marshaled document has no %q member", member)
		}
	}
	display := wire["display"].([]any)[0].(map[string]any)
	claim := wire["claims"].([]any)[0].(map[string]any)
	if display["locale"] != "en" || claim["mandatory"] != true || claim["display"].([]any)[0].(map[string]any)["locale"] != "en" {
		t.Errorf("display %v / claim %v: want draft-13 locale and mandatory members", display, claim)
	}
	var decoded sdjwtvc.TypeMetadata
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Errorf("Validate after a JSON round trip: %v", err)
	}
}

func TestTypeMetadata_ValidateRejects(t *testing.T) {
	for name, mutate := range map[string]func(*sdjwtvc.TypeMetadata){
		"no vct":                  func(m *sdjwtvc.TypeMetadata) { m.VCT = "" },
		"display without locale":  func(m *sdjwtvc.TypeMetadata) { m.Display[0].Locale = "" },
		"display without name":    func(m *sdjwtvc.TypeMetadata) { m.Display[0].Name = "" },
		"empty claim path":        func(m *sdjwtvc.TypeMetadata) { m.Claims[0].Path = nil },
		"negative index":          func(m *sdjwtvc.TypeMetadata) { m.Claims[2].Path = []any{"nationalities", -1} },
		"path element of a bool":  func(m *sdjwtvc.TypeMetadata) { m.Claims[2].Path = []any{"nationalities", true} },
		"claim display no label":  func(m *sdjwtvc.TypeMetadata) { m.Claims[0].Display[0].Label = "" },
		"claim display no locale": func(m *sdjwtvc.TypeMetadata) { m.Claims[0].Display[0].Locale = "" },
		"unknown sd":              func(m *sdjwtvc.TypeMetadata) { m.Claims[0].SD = "sometimes" },
		"svg_id with a dash":      func(m *sdjwtvc.TypeMetadata) { m.Claims[0].SvgID = "given-name" },
		"svg_id starting digit":   func(m *sdjwtvc.TypeMetadata) { m.Claims[0].SvgID = "1name" },
		"duplicate svg_id":        func(m *sdjwtvc.TypeMetadata) { m.Claims[1].SvgID = "given_name" },
	} {
		m := validTypeMetadata()
		mutate(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A rendering uri must be an HTTPS URL or a data: URI (draft-19
// §5.5.1), for the simple method's logo and background_image and each
// svg_templates entry; another method's parameters aren't checked.
func TestTypeMetadata_RenderingURIs(t *testing.T) {
	for rendering, ok := range map[string]bool{
		`{"simple":{"logo":{"uri":"https://issuer.example/logo.png"},"background_color":"#fff"}}`:  true,
		`{"simple":{"background_image":{"uri":"data:image/png;base64,iVBORw0KGgo="}}}`:             true,
		`{"svg_templates":[{"uri":"https://issuer.example/card.svg"}]}`:                            true,
		`{"another_method":{"uri":"http://anything.example"}}`:                                     true,
		`{"simple":{"logo":{"uri":"http://issuer.example/logo.png"}}}`:                             false,
		`{"simple":{"logo":{"alt_text":"no uri"}}}`:                                                false,
		`{"simple":{"background_image":{"uri":"file:///etc/passwd"}}}`:                             false,
		`{"svg_templates":[{"uri":"https://issuer.example/a.svg"},{"uri":"javascript:alert(1)"}]}`: false,
		`{"svg_templates":[{"properties":{"orientation":"portrait"}}]}`:                            false,
		`{"svg_templates":{"uri":"https://issuer.example/card.svg"}}`:                              false,
		// A consumer matching names exactly reads the first uri: the
		// check must not read the second instead.
		`{"simple":{"logo":{"uri":"javascript:alert(1)"},"LOGO":{"uri":"https://issuer.example/a.png"}}}`: false,
		`{"svg_templates":[{"uri":"javascript:alert(1)","URI":"https://issuer.example/a.svg"}]}`:          false,
	} {
		m := validTypeMetadata()
		if err := json.Unmarshal([]byte(rendering), &m.Display[0].Rendering); err != nil {
			t.Fatal(err)
		}
		if err := m.Validate(); (err == nil) != ok {
			t.Errorf("%s: Validate = %v, want ok = %v", rendering, err, ok)
		}
	}
}
