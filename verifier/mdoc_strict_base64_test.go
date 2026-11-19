package verifier_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// An mso_mdoc vp_token is decoded as strict base64url (RFC 7515 §2's):
// one DeviceResponse has one encoding, so one with a line break or a
// carriage return in it, which encoding/base64 skips, is refused as
// malformed.
func TestVerifyMdocResponse_StrictBase64URL(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	withToken := func(alter func(string) string) func(*verifier.VerifyResponseRequest) {
		return func(req *verifier.VerifyResponseRequest) {
			req.Response.VPToken["mdl"][0] = alter(req.Response.VPToken["mdl"][0])
		}
	}
	result, err := mf.verifyWith(t, mf.nonce, withToken(func(s string) string { return s }))
	testverify.RequireOneCredential(t, result, err, "mdl")

	for name, alter := range map[string]func(string) string{
		"a line break":      func(s string) string { return s[:len(s)/2] + "\n" + s[len(s)/2:] },
		"a carriage return": func(s string) string { return s[:len(s)/2] + "\r" + s[len(s)/2:] },
	} {
		_, err := mf.verifyWith(t, mf.nonce, withToken(alter))
		var vErr *verifier.Error
		if !errors.As(err, &vErr) || vErr.Reason() != verifier.ReasonMalformed || !strings.Contains(err.Error(), "decode device response") {
			t.Errorf("%s: %v; want the vp_token refused as malformed", name, err)
		}
	}
}
