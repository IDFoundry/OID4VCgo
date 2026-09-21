package mdoc

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// TestKeyAuthorizationsValidate is the regression test for the two
// §12.3.4 constraints KeyAuthorizations.validate implements — found
// unexercised by any existing test in a repo-wide coverage review:
// every prior test only exercised the reader-side CheckKeyAuthorizations,
// never this issuer-side check, so a regression here (e.g. an
// inverted condition) would have gone undetected.
func TestKeyAuthorizationsValidate(t *testing.T) {
	cases := map[string]struct {
		auth    *KeyAuthorizations
		wantErr bool
	}{
		"empty (both nil)": {
			auth:    &KeyAuthorizations{},
			wantErr: true,
		},
		"namespaces only": {
			auth:    &KeyAuthorizations{NameSpaces: []string{"org.iso.18013.5.1"}},
			wantErr: false,
		},
		"data elements only": {
			auth: &KeyAuthorizations{DataElements: map[string][]string{
				"org.iso.18013.5.1": {"family_name"},
			}},
			wantErr: false,
		},
		"disjoint namespaces and data elements": {
			auth: &KeyAuthorizations{
				NameSpaces: []string{"org.iso.18013.5.1"},
				DataElements: map[string][]string{
					"org.iso.18013.5.1.aamva": {"dhs_compliance"},
				},
			},
			wantErr: false,
		},
		"namespace listed in both": {
			auth: &KeyAuthorizations{
				NameSpaces: []string{"org.iso.18013.5.1"},
				DataElements: map[string][]string{
					"org.iso.18013.5.1": {"family_name"},
				},
			},
			wantErr: true,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.auth.validate()
			if tc.wantErr && err == nil {
				t.Errorf("validate() = nil error, want error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validate() = %v, want nil error", err)
			}
		})
	}
}

// TestIssueRejectsInvalidKeyAuthorizations proves the rejection
// actually propagates through Issue, not just KeyAuthorizations.validate
// in isolation.
func TestIssueRejectsInvalidKeyAuthorizations(t *testing.T) {
	f := newFixture(t)
	claims := f.claims
	claims.KeyAuthorizations = &KeyAuthorizations{}

	if _, err := Issue(f.issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{f.cert}}); err == nil {
		t.Error("Issue accepted an empty (but present) KeyAuthorizations")
	}
}

// TestNewDigester covers newDigester's SHA384/SHA512/unsupported
// branches — found unexercised by any existing test in a repo-wide
// coverage review: every test reaching this function used the
// default SHA256, despite Table 16/DigestAlg being caller-configurable
// to either of the other two.
func TestNewDigester(t *testing.T) {
	cases := map[string]struct {
		alg     DigestAlg
		wantErr bool
	}{
		"sha-256":     {alg: SHA256},
		"sha-384":     {alg: SHA384},
		"sha-512":     {alg: SHA512},
		"unsupported": {alg: "sha-1", wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h, err := newDigester(tc.alg)
			if tc.wantErr {
				if err == nil {
					t.Errorf("newDigester(%q) = nil error, want error", tc.alg)
				}
				return
			}
			if err != nil {
				t.Fatalf("newDigester(%q): %v", tc.alg, err)
			}
			if h == nil {
				t.Errorf("newDigester(%q) = nil hash.Hash", tc.alg)
			}
		})
	}
}
