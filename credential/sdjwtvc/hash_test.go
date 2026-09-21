package sdjwtvc

import "testing"

// TestNewHash covers newHash's SHA384/SHA512/unsupported branches —
// found unexercised by any existing test in a repo-wide coverage
// review: every test reaching this function used the default SHA256,
// despite HashAlg being caller-configurable to either of the other
// two (RFC 9901 §4.1.1).
func TestNewHash(t *testing.T) {
	cases := map[string]struct {
		alg     HashAlg
		wantErr bool
	}{
		"sha-256":     {alg: SHA256},
		"sha-384":     {alg: SHA384},
		"sha-512":     {alg: SHA512},
		"unsupported": {alg: "sha-1", wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h, err := newHash(tc.alg)
			if tc.wantErr {
				if err == nil {
					t.Errorf("newHash(%q) = nil error, want error", tc.alg)
				}
				return
			}
			if err != nil {
				t.Fatalf("newHash(%q): %v", tc.alg, err)
			}
			if h == nil {
				t.Errorf("newHash(%q) = nil hash.Hash", tc.alg)
			}
		})
	}
}
