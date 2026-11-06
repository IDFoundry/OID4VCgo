package mobile

import (
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Every NewWallet configuration key can be set from Swift and from
// Kotlin, so an option a release enforces is never one an app can't
// reach. The exceptions are deliberate: iOS answers the DC API only
// with org-iso-mdoc, and trusts development services through the
// device's own trust store; and the wrappers set status_cache_key
// themselves, from a key they keep, whenever statusCacheDir is set.
func TestConfigKeysParity(t *testing.T) {
	var goKeys []string
	ct := reflect.TypeOf(config{})
	for i := range ct.NumField() {
		if name, _, _ := strings.Cut(ct.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			goKeys = append(goKeys, name)
		}
	}
	notInSwift := []string{"require_signed_dcapi_requests", "development_roots"}
	setByWrappers := []string{"status_cache_key"}

	swift := between(t, "ios/OID4VCWallet/Sources/OID4VCWallet/Wallet.swift", "public struct WalletConfiguration", "enum CodingKeys", "\n    }\n")
	var swiftKeys []string
	for _, m := range regexp.MustCompile(`(\w+)(?:\s*=\s*"([a-z_]+)")?`).FindAllStringSubmatch(strings.Join(regexp.MustCompile(`case ([^\n]+)`).FindAllString(swift, -1), ","), -1) {
		if m[1] == "case" {
			continue
		}
		key := m[2]
		if key == "" {
			key = m[1]
		}
		swiftKeys = append(swiftKeys, key)
	}

	kotlin := between(t, "android/OID4VCWallet/src/main/kotlin/dev/idfoundry/oid4vcwallet/Wallet.kt", "data class WalletConfiguration(", "", "\n) {")
	var kotlinKeys []string
	for _, m := range regexp.MustCompile(`(?m)^\s*(?:@\w+(?:\("([a-z_]+)"\))?\s+)*val (\w+)`).FindAllStringSubmatch(kotlin, -1) {
		key := m[1]
		if key == "" {
			key = m[2]
		}
		kotlinKeys = append(kotlinKeys, key)
	}

	for _, k := range goKeys {
		if slices.Contains(setByWrappers, k) {
			continue
		}
		if !slices.Contains(swiftKeys, k) && !slices.Contains(notInSwift, k) {
			t.Errorf("Swift WalletConfiguration has no %q", k)
		}
		if !slices.Contains(kotlinKeys, k) {
			t.Errorf("Kotlin WalletConfiguration has no %q", k)
		}
	}
	for _, k := range append(swiftKeys, kotlinKeys...) {
		if !slices.Contains(goKeys, k) {
			t.Errorf("a wrapper sends %q, which NewWallet doesn't know", k)
		}
	}
}

// between is the text of file after start, then after from (when set),
// up to end.
func between(t *testing.T, file, start, from, end string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("%s: no %q", file, start)
	}
	s = s[i+len(start):]
	if from != "" {
		if i = strings.Index(s, from); i < 0 {
			t.Fatalf("%s: no %q", file, from)
		}
		s = s[i+len(from):]
	}
	if i = strings.Index(s, end); i >= 0 {
		s = s[:i]
	}
	return s
}
