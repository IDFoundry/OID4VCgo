package walletflow

import (
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// Only a logo an app may load is kept: https, or a data: image.
func TestLogoOf(t *testing.T) {
	for uri, keep := range map[string]bool{
		"https://issuer.example/logo.png":    true,
		"data:image/png;base64,iVBORw0KGgo=": true,
		"http://issuer.example/logo.png":     false,
		"data:text/html;base64,PHNjcmlwdD4=": false,
		"javascript:alert(1)":                false,
		"org.example.app:/logo":              false,
		"https:///no-host":                   false,
	} {
		if got := logoOf(&oid4vci.Logo{URI: uri}) != nil; got != keep {
			t.Errorf("logoOf(%q) kept = %v, want %v", uri, got, keep)
		}
	}
}

func TestBestLocale(t *testing.T) {
	locales := []string{"en", "de", ""}
	at := func(i int) string { return locales[i] }
	for prefs, want := range map[string]int{"de-AT": 1, "EN": 0, "fr": 2, "": 2} {
		var p []string
		if prefs != "" {
			p = []string{prefs}
		}
		if got := bestLocale(len(locales), at, p); got != want {
			t.Errorf("bestLocale(%q) = %d, want %d", prefs, got, want)
		}
	}
	if bestLocale(0, at, nil) != -1 {
		t.Error("no entries: want -1")
	}
}
