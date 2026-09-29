package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotls"
)

func TestChromeArgs(t *testing.T) {
	_, cert, err := demotls.PersistentCertificate(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	want := base64.StdEncoding.EncodeToString(sum[:])

	args := chromeArgs("/tmp/profile", cert, "https://a.example", "https://b.example")
	for _, a := range []string{
		"--user-data-dir=/tmp/profile",
		"--ignore-certificate-errors-spki-list=" + want,
		"https://a.example", "https://b.example",
	} {
		if !slices.Contains(args, a) {
			t.Errorf("chromeArgs is missing %q: %v", a, args)
		}
	}
	for _, a := range args {
		if a == "--ignore-certificate-errors" {
			t.Error("chromeArgs turns off certificate checking for every site")
		}
	}
}

func TestSPKIHashIsPerKey(t *testing.T) {
	_, a, err := demotls.PersistentCertificate(t.TempDir(), "a")
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := demotls.PersistentCertificate(t.TempDir(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if spkiHash(a) == spkiHash(b) || spkiHash(a) != spkiHash(&x509.Certificate{RawSubjectPublicKeyInfo: a.RawSubjectPublicKeyInfo}) {
		t.Error("spkiHash doesn't identify the certificate's key")
	}
}

func TestFindChrome_ExplicitPath(t *testing.T) {
	if got, err := findChrome("/opt/custom/chrome"); err != nil || got != "/opt/custom/chrome" {
		t.Errorf("findChrome(explicit) = %q, %v", got, err)
	}
}
