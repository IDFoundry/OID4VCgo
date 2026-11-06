package walletflow

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

// TestCredentialIDHasNoHyphen: a new credential's ID never has a "-",
// even from random bytes whose base64url is all "-", so it can't begin
// with a prefix a store gives its other records.
func TestCredentialIDHasNoHyphen(t *testing.T) {
	hyphens := bytes.Repeat([]byte{0xfb, 0xef, 0xbe}, 6) // base64url "----"…
	if id, err := randomID(bytes.NewReader(hyphens)); err != nil || !strings.HasPrefix(id, "----") {
		t.Fatalf("randomID = %q, %v: the input should encode as hyphens", id, err)
	}
	id, err := credentialID(bytes.NewReader(hyphens))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(id, "-") || len(id) != 22 {
		t.Errorf("credentialID = %q, want 22 characters and no -", id)
	}
	for range 1000 {
		id, err := credentialID(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(id, "-") {
			t.Fatalf("credentialID = %q", id)
		}
	}
}
