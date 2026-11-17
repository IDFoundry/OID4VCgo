package statuslist

import (
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// A JWT Status List Token whose x5c includes the trust anchor is
// refused, as HAIP 1.0 §6.1 has the sender leave it out, even though
// the chain would verify.
func TestCheckX5C_RefusesTheAnchorInX5C(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	leaf, leafKey := testcert.Leaf(t, "status list signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	claims := forgedTokenClaims(t, 0)
	x5c := []string{base64.StdEncoding.EncodeToString(leaf.Raw), base64.StdEncoding.EncodeToString(ca.Raw)}
	token, err := issueToken(leafKey, jose.ES256, claims, map[string]any{"typ": TokenTyp, "x5c": x5c})
	if err != nil {
		t.Fatal(err)
	}
	ref := StatusListRef{Idx: 0, URI: x5cTestURI}
	if _, _, err := CheckX5C(token, roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil || !strings.Contains(err.Error(), "self-issued") {
		t.Errorf("CheckX5C = %v, want the included anchor refused", err)
	}
	x5c = x5c[:1]
	if token, err = issueToken(leafKey, jose.ES256, claims, map[string]any{"typ": TokenTyp, "x5c": x5c}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckX5C(token, roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil {
		t.Errorf("without the anchor: %v", err)
	}
}
