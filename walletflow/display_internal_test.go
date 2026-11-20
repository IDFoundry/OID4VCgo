package walletflow

import (
	"net/netip"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// Only a logo an app may load is kept: https, or a data: image.
func TestLogoOf(t *testing.T) {
	for uri, keep := range map[string]bool{
		"https://issuer.example/logo.png":    true,
		"data:image/png;base64,iVBORw0KGgo=": true,
		"http://issuer.example/logo.png":     false,
		"data:text/html;base64,PHNjcmlwdD4=": false,
		"data:image/svg+xml;base64,PHN2Zz4=": false,
		"data:IMAGE/SVG+XML,<svg/>":          false,
		"javascript:alert(1)":                false,
		"org.example.app:/logo":              false,
		"https:///no-host":                   false,
		"https://issuer.example./logo.png":   true,
		"https://cdn1.issuer.example/l.png":  true,
		// An IP address or localhost: the phone's own network.
		"https://127.0.0.1/logo.png":        false,
		"https://192.168.1.1:8443/logo.png": false,
		"https://[::1]/logo.png":            false,
		"https://[fe80::1%25en0]/logo.png":  false,
		"https://localhost/logo.png":        false,
		"https://LOCALHOST./logo.png":       false,
		"https://printer.localhost/l.png":   false,
		"https://2130706433/logo.png":       false,
		"https://0x7f.1/logo.png":           false,
		"https://10.0.0.010/logo.png":       false,
		"https://[::ffff:7f00:1]/logo.png":  false,
		// A single label or a local-only domain: names the phone's own
		// network resolves.
		"https://router/logo.png":             false,
		"https://router./logo.png":            false,
		"https://printer.local/logo.png":      false,
		"https://PRINTER.LOCAL./logo.png":     false,
		"https://nas.home.arpa/logo.png":      false,
		"https://home.arpa/logo.png":          false,
		"https://svc.corp.internal/logo.png":  false,
		"https://nas.lan/logo.png":            false,
		"https://lan/logo.png":                false,
		"https://issuer.local.example/l.png":  true,
		"https://issuer.lan.example/l.png":    true,
		"https://internal.issuer.example/l.p": true,
	} {
		if got := logoOf(&oid4vci.Logo{URI: uri}) != nil; got != keep {
			t.Errorf("logoOf(%q) kept = %v, want %v", uri, got, keep)
		}
	}
}

// A host that isn't ASCII is dropped unless its last label is, and
// under arpa the label before it too: a URL parser maps it first (IDNA,
// UTS #46), where full-width and other compatibility forms of digits,
// letters and full stops may make an IP address or a local name of it.
// A name whose deciding labels are ASCII is judged by them.
func TestLogoOf_MappedHosts(t *testing.T) {
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1}).String()
	private := netip.AddrFrom4([4]byte{192, 168, 1, 1}).String()
	// wide is s with its ASCII letters and digits in their full-width
	// forms.
	wide := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r < utf8.RuneSelf && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
				return r + 0xfee0
			}
			return r
		}, s)
	}
	// last is s with what follows its last full stop replaced by tail.
	last := func(s, tail string) string { return s[:strings.LastIndex(s, ".")] + tail }
	for host, keep := range map[string]bool{
		wide(loopback):                                      false,
		last(private, "."+wide("1")):                        false,
		last(loopback, "\u30021"):                           false, // IDEOGRAPHIC FULL STOP
		last(loopback, ".\U0001d7cf"):                       false, // MATHEMATICAL BOLD DIGIT ONE
		last(private, ".\u2460"):                            false, // CIRCLED DIGIT ONE
		"printer.local\uff61":                               false, // HALFWIDTH IDEOGRAPHIC FULL STOP
		"nas." + wide("local"):                              false,
		"issuer.loc\u00adal":                                false, // a soft hyphen, which IDNA drops
		wide("home") + ".arpa":                              false,
		"b\u00fccher.local":                                 false,
		"\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444": false, // in its A-labels below
		"xn--e1afmkfd.xn--p1ai":                             true,
		"b\u00fccher.example":                               true,
		"\u043f\u0440\u0438\u043c\u0435\u0440.example":      true,
		wide("2130706433") + ".example":                     true,
	} {
		uri := "https://" + host + "/logo.png"
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
