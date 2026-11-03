package verifier_test

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// A request for a format the Verifier can't verify, or doesn't
// advertise in vp_formats_supported, is refused when it's built, not
// as every answer's failure.
func TestBuildRequests_RefuseFormatsTheVerifierDoesntVerify(t *testing.T) {
	cfg, deps := validConfig(t)
	cfg.VPFormatsSupported = map[string]any{"dc+sd-jwt": map[string]any{}, "vc+sd-jwt": map[string]any{}}
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	unknown := testIdentityQuery(t)
	unknown.Credentials[0].Format = "vc+sd-jwt"
	for name, c := range map[string]struct {
		query dcql.Query
		want  string
	}{
		"vc+sd-jwt": {unknown, "can't verify"},
		"mso_mdoc":  {testmdoc.Query(t), "vp_formats_supported"},
	} {
		format, query, want := name, c.query, c.want
		if _, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: BuildAuthorizationRequest: %v, want %q", format, err, want)
		}
		if _, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{Query: query, ExpectedOrigins: []string{"https://verifier.example"}}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: BuildDCAPIAuthorizationRequest: %v, want %q", format, err, want)
		}
	}
}
