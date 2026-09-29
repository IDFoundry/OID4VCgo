package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// spkiHash is the base64 SHA-256 of cert's public key (its
// SubjectPublicKeyInfo) — the form Chrome's
// --ignore-certificate-errors-spki-list takes.
func spkiHash(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// chromeArgs opens urls in a separate Chrome profile under profileDir
// that accepts cert's key without a warning. Only that key: every other
// site is checked as usual. Chrome honours the SPKI list only with its
// own --user-data-dir, which also keeps the demo out of your normal
// profile.
func chromeArgs(profileDir string, cert *x509.Certificate, urls ...string) []string {
	args := []string{
		"--user-data-dir=" + profileDir,
		"--ignore-certificate-errors-spki-list=" + spkiHash(cert),
		"--no-first-run",
		"--no-default-browser-check",
	}
	return append(args, urls...)
}

// chromeCandidates are where Chrome (or Chromium) usually is on this OS.
func chromeCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	case "windows":
		var out []string
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if dir := os.Getenv(env); dir != "" {
				out = append(out, filepath.Join(dir, "Google", "Chrome", "Application", "chrome.exe"))
			}
		}
		return out
	default:
		return []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"}
	}
}

// findChrome returns the Chrome executable to run: path if given,
// otherwise the first of chromeCandidates that exists.
func findChrome(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	for _, c := range chromeCandidates() {
		if found, err := exec.LookPath(c); err == nil {
			return found, nil
		}
	}
	return "", errors.New("no Chrome or Chromium found in the usual places; pass its path with -chrome")
}

// openChrome starts Chrome on urls, trusting cert, with its profile in
// state/chrome-profile. It doesn't wait for Chrome to exit.
func openChrome(chromePath, state string, cert *x509.Certificate, urls ...string) error {
	path, err := findChrome(chromePath)
	if err != nil {
		return err
	}
	profile, err := filepath.Abs(filepath.Join(state, "chrome-profile"))
	if err != nil {
		return err
	}
	cmd := exec.Command(path, chromeArgs(profile, cert, urls...)...) // #nosec G204 -- the operator's own browser, with arguments built here
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
